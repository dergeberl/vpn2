package init

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/gardener/vpn2/pkg/config"
	"github.com/gardener/vpn2/pkg/ippool"
	"github.com/gardener/vpn2/pkg/network"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"net"
	"time"

	"github.com/gardener/vpn2/pkg/utils"
	"github.com/spf13/cobra"
	"os/exec"
)

const Name = "init"

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
			return Run(ctx, cancel, log)
		},
	}

	return cmd
}

// todo make private after subcommant moved
func Run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg, err := config.GetConfig(log)
	if err != nil {
		return err
	}

	if !cfg.DoNotConfigureKernelSettings {
		err := kernelSettings(cfg)
		if err != nil {
			return err
		}
	}

	vpnNetwork, err := network.ValidateCIDR(cfg.VPNNetwork, cfg.IPFamilies)
	if err != nil {
		return err
	}

	if cfg.ConfigureBonding {
		if cfg.IPFamilies != "IPv4" {
			return fmt.Errorf("the highly-available VPN setup is only supported for IPv4 single-stack shoots")
		}
		err = configureBonding(ctx, log, cfg, vpnNetwork)
		if err != nil {
			return err
		}
	}
	return nil
}

func kernelSettings(cfg config.Config) error {
	if err := sysctl.Enable("net.ipv4.ip_forward"); err != nil {
		return err
	}
	if err := sysctl.Enable("net.ipv6.conf.all.forwarding"); err != nil {
		return err
	}
	if err := sysctl.WriteInt("net.ipv4.tcp_keepalive_time", cfg.TCP.KeepAliveTime); err != nil {
		return err
	}
	if err := sysctl.WriteInt("net.ipv4.tcp_keepalive_intvl", cfg.TCP.KeepAliveInterval); err != nil {
		return err
	}
	if err := sysctl.WriteInt("net.ipv4.tcp_keepalive_probes", cfg.TCP.KeepAliveProbes); err != nil {
		return err
	}
	if err := sysctl.Write("net.ipv4.ping_group_range", "0 65532"); err != nil {
		return err
	}
	return nil
}

func configureBonding(ctx context.Context, log logr.Logger, cfg config.Config, vpnNetwork *net.IPNet) error {
	var addr *net.IPNet
	var targets []net.IP
	if cfg.IsShootClient {
		addr, targets = network.ComputeShootAddrAndTargets(vpnNetwork, cfg.VPNClientIndex)
	} else {
		broker, err := newIPAddressBrokerFromEnv(&cfg, vpnNetwork)
		if err != nil {
			return err
		}
		log.Info("acquiring ip address for bonding from kube-api server")
		acquiredIP, err := broker.AcquireIP(ctx)
		if err != nil {
			return err
		}
		ip := net.ParseIP(acquiredIP)
		if ip == nil {
			return fmt.Errorf("acquired ip %s is not a valid ipv6 nor ipv4", ip)
		}
		addr, targets = network.ComputeSeedAddrAndTargets(ip, vpnNetwork, cfg.HAVPNClients)
	}

	for i := range cfg.HAVPNServers {
		linkName := fmt.Sprintf("tap%d", i)
		err := deleteLinkByName(linkName)
		if err != nil {
			return err
		}

		cmd := exec.CommandContext(ctx, "openvpn", "--mktun", "--dev", linkName)
		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	// check if bond0 already exists and delete it if exists
	err := deleteLinkByName("bond0")
	if err != nil {
		return err
	}

	tab0Link, err := netlink.LinkByName("tap0")
	if err != nil {
		return err
	}

	// create bond0
	linkAttrs := netlink.NewLinkAttrs()
	bond := netlink.NewLinkBond(linkAttrs)
	// use bonding
	// - with active-backup mode
	// - activate ARP requests (but not used for monitoring as use_carrier=1 and arp_validate=none by default)
	// - using `primary tap0` to avoid ambiguity of selection if multiple devices are up (primary_reselect=always by default)
	// - using `num_grat_arp 5` as safeguard on switching device
	bond.Name = "bond0"
	bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	bond.FailOverMac = netlink.BOND_FAIL_OVER_MAC_ACTIVE
	bond.ArpInterval = 1000
	bond.ArpIpTargets = targets
	bond.ArpAllTargets = netlink.BOND_ARP_ALL_TARGETS_ANY
	bond.Primary = tab0Link.Attrs().Index // TODO check
	bond.NumPeerNotif = 5                 // no one know what this does

	err = netlink.LinkAdd(bond)
	if err != nil {
		return err
	}

	for i := range cfg.HAVPNServers {
		linkName := fmt.Sprintf("tap%d", i)

		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}

		err = netlink.LinkSetMaster(link, bond)
		if err != nil {
			return err
		}
	}

	err = netlink.LinkSetUp(bond)
	if err != nil {
		return err
	}
	err = netlink.AddrAdd(bond, &netlink.Addr{IPNet: addr})
	if err != nil {
		return err
	}

	return nil
}

// TODO: change this to use the config
//
// newIPAddressBrokerFromEnv initialises the broker with values from env and for in-cluster usage.
func newIPAddressBrokerFromEnv(cfg *config.Config, vpnNetwork *net.IPNet) (ippool.IPAddressBroker, error) {
	// podName := mustGetEnv("POD_NAME")
	// namespace := mustGetEnv("NAMESPACE")
	//
	// vpnNetworkString := optionalGetEnv("VPN_NETWORK", "192.168.123.0/24")
	// base, _, err := net.ParseCIDR(vpnNetworkString)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid VPN_NETWORK: %w", err)
	// }
	// if base.To4() == nil {
	// 	return nil, fmt.Errorf("invalid VPN_NETWORK %q, must be an IPv4 network", vpnNetworkString)
	// }
	// if base.To4()[3] != 0 {
	// 	return nil, fmt.Errorf("invalid VPN_NETWORK %q, last octet must be 0", vpnNetworkString)
	// }
	//
	manager, err := ippool.NewPodIPPoolManager(cfg.Namespace, cfg.PodLabelSelector)
	if err != nil {
		return nil, err
	}
	return ippool.NewIPAddressBroker(manager, vpnNetwork.IP, cfg.StartIndex, cfg.EndIndex, cfg.PodName, time.Duration(cfg.WaitSeconds)*time.Second)
}

func deleteLinkByName(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		_, ok := err.(netlink.LinkNotFoundError)
		if ok {
			return nil
		}
		return err
	}

	return netlink.LinkDel(link)
}
