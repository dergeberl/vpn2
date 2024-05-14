package pathcontroller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/gardener/vpn2/pkg/network"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const Name = "path-controller"

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   Name,
		Short: Name,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := utils.InitRun(cmd, Name)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			return run(ctx, cancel, log)
		},
	}

	return cmd
}

type config struct {
	IPFamilies     string       `env:"IP_FAMILIES" envDefault:"IPv4"`
	VPNNetwork     network.CIDR `env:"VPN_NETWORK"`
	HAVPNClients   int          `env:"HA_VPN_CLIENTS"`
	PodNetwork     network.CIDR `env:"POD_NETWORK"`
	NodeNetwork    network.CIDR `env:"NODE_NETWORK"`
	ServiceNetwork network.CIDR `env:"SERVICE_NETWORK"`
}

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		return err
	}
	if cfg.VPNNetwork.String() == "" {
		if cfg.IPFamilies == "IPv4" {
			cfg.VPNNetwork = network.CIDR(net.IPNet{
				IP:   net.ParseIP("192.168.123.0"),
				Mask: net.CIDRMask(24, 32),
			})
		}
	} else {
		cfg.VPNNetwork = network.CIDR(net.IPNet{
			IP:   net.ParseIP("fd8f:6d53:b97a:1::"),
			Mask: net.CIDRMask(120, 128),
		})
	}
	log.Info("config parsed", "config", cfg)

	vpnNetwork, err := network.ValidateCIDR(cfg.VPNNetwork.String(), cfg.IPFamilies)
	if err != nil {
		return err
	}
	checkNetwork := cfg.NodeNetwork
	if checkNetwork.String() == "" {
		checkNetwork = cfg.ServiceNetwork
	}
	if checkNetwork.String() == "" {
		return errors.New("network to check is undefined")
	}

	pingRouter := &PingRouter{
		checkedNet: (*net.IPNet)(&checkNetwork),
		goodIPs:    make(map[string]struct{}),
		log:        log.WithName("pingRouter"),
	}

	// acquired ip is not neccessary here, because we don't care about the subnet
	_, clientIPs := network.ComputeSeedAddrAndTargets(nil, vpnNetwork, cfg.HAVPNClients)
	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pingRouter.pingAllShootClients(clientIPs)
			_, ok := pingRouter.goodIPs[pingRouter.current.String()]
			if !ok {
				newIP, err := pingRouter.selectNewShootClient()
				if err != nil {
					return err
				}
				err = pingRouter.updateRouting(newIP)
				if err != nil {
					return err
				}
				pingRouter.current = newIP
			}
		}
	}
}

func (p *PingRouter) updateRouting(newIP net.IP) error {
	bondDev, err := netlink.LinkByName("bond0")
	if err != nil {
		return err
	}

	nets := []*net.IPNet{
		(*net.IPNet)(&p.cfg.ServiceNetwork),
		(*net.IPNet)(&p.cfg.PodNetwork),
	}
	if p.cfg.NodeNetwork.String() != "" {
		nets = append(nets, (*net.IPNet)(&p.cfg.NodeNetwork))
	}

	for _, net := range nets {
		route := routeForNetwork(net, newIP, bondDev)
		err := netlink.RouteReplace(&route)
		if err != nil {
			return fmt.Errorf("error replacing route for %s: %w", net, err)
		}
	}
	return nil
}

func routeForNetwork(net *net.IPNet, newIP net.IP, bondLink netlink.Link) netlink.Route {
	return netlink.Route{
		Via: &netlink.Via{
			Addr: newIP,
		},
		Dst:       net,
		LinkIndex: bondLink.Attrs().Index,
	}
}

func (p *PingRouter) selectNewShootClient() (net.IP, error) {
	// just use the first ip that is in goodIps map
	for ip := range p.goodIPs {
		return net.ParseIP(ip), nil
	}
	return nil, errors.New("no more good ips in pool")
}

type PingRouter struct {
	cfg config

	log        logr.Logger
	checkedNet *net.IPNet
	current    net.IP
	mu         sync.Mutex
	goodIPs    map[string]struct{}
}

func (p *PingRouter) pingAllShootClients(clients []net.IP) {
	var wg sync.WaitGroup
	for _, client := range clients {
		p.log.Info("pinging", "client ip", client)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pingClient(client)
			p.mu.Lock()
			defer p.mu.Unlock()
			if err != nil {
				delete(p.goodIPs, client.String())
			} else {
				p.goodIPs[client.String()] = struct{}{}
			}
		}()
	}
	wg.Wait()
}

// TODO: check if this code is neccessary
//
//	func (p *PingRouter) updateCurrentVPNIP() error {
//		filter := &netlink.Route{
//			Dst: p.checkedNet,
//		}
//		routes, err := netlink.RouteListFiltered(unix.AF_INET, filter, 0)
//		if err != nil {
//			return err
//		}
//		if len(routes) < 1 {
//			return fmt.Errorf("no route matched network %s", p.checkedNet)
//		}
//		p.current = routes[0].Src
//		return nil
//	}
const protocolICMP = 1

func pingClient(client net.IP) error {
	c, err := icmp.ListenPacket("udp4", "")
	if err != nil {
		return err
	}
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	err = c.SetReadDeadline(deadline)
	if err != nil {
		return err
	}

	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	marshaledMsg, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(marshaledMsg, &net.UDPAddr{IP: client}); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
	if err != nil {
		return err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return nil
	default:
		return err
	}
}
