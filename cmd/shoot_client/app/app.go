// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/gardener/vpn2/cmd/shoot_client/app/pathcontroller"
	"github.com/gardener/vpn2/pkg/ippool"
	"github.com/gardener/vpn2/pkg/network"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"k8s.io/component-base/version/verflag"
)

// Name is a const for the name of this component.
const Name = "shoot-client"

// NewCommand creates a new cobra.Command for running gardener-node-agent.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   Name,
		Short: "Launch the " + Name,
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

	flags := cmd.Flags()
	verflag.AddFlags(flags)
	cmd.AddCommand(pathcontroller.NewCommand())
	return cmd
}

type config struct {
	TCP struct {
		KeepAliveTime     int64 `env:"KEEPALIVE_TIME" envDefault:"7200"`
		KeepAliveInterval int64 `env:"KEEPALIVE_INTVL" envDefault:"75"`
		KeepAliveProbes   int64 `env:"KEEPALIVE_PROBES" envDefault:"9"`
	} `envPrefix:"TCP_"`
	IPFamilies                   string `env:"IP_FAMILIES" envDefault:"IPv4"`
	OpenVPNPort                  int    `env:"OPENVPN_PORT" envDefault:"8132"`
	VPNNetwork                   string `env:"VPN_NETWORK"`
	IsShootClient                bool   `env:"IS_SHOOT_CLIENT"`
	PodName                      string `env:"POD_NAME"`
	Namespace                    string `env:"NAMESPACE"`
	ConfigureBonding             bool   `env:"CONFIGURE_BONDING"`
	HAVPNClients                 int    `env:"HA_VPN_CLIENTS"`
	StartIndex                   int    `env:"START_INDEX" envDefault:"200"`
	EndIndex                     int    `env:"END_INDEX" envDefault:"254"`
	PodLabelSelector             string `env:"POD_LABEL_SELECTOR" envDefault:"app=kubernetes,role=apiserver"`
	WaitSeconds                  int    `env:"WAIT_SECONDS" envDefault:"2"`
	DoNotConfigureKernelSettings bool   `env:"$DO_NOT_CONFIGURE_KERNEL_SETTINGS" envDefault:"false"`
}

// TODO: change this to use the config
//
// newIPAddressBrokerFromEnv initialises the broker with values from env and for in-cluster usage.
func newIPAddressBrokerFromEnv(cfg *config, vpnNetwork *net.IPNet) (ippool.IPAddressBroker, error) {
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

func configureBonding(ctx context.Context, cfg config, vpnNetwork *net.IPNet) error {
	var addr *net.IPNet
	var targets []net.IP
	if cfg.IsShootClient {
		vpnClientIndex, err := getVpnClientIndex(cfg)
		if err != nil {
			return err
		}
		addr, targets = computeShootAddrAndTargets(vpnNetwork, vpnClientIndex)
	} else {
		broker, err := newIPAddressBrokerFromEnv(&cfg, vpnNetwork)
		if err != nil {
			return err
		}
		//log.Info("acuiring ip address for bonding from kube-api server")
		acquiredIP, err := broker.AcquireIP(ctx)
		if err != nil {
			return err
		}
		ip := net.ParseIP(acquiredIP)
		if ip == nil {
			return fmt.Errorf("acquired ip %s is not a valid ipv6 nor ipv4", ip)
		}
		addr, targets = computeSeedTargetAndAddr(ip, vpnNetwork, cfg.HAVPNClients)
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
	// - using `num_grat_arp 5` as safe-guard on switching device
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

	for i := range cfg.HAVPNClients {
		linkName := fmt.Sprintf("tab%S", i)
		err = deleteLinkByName(linkName)
		if err != nil {
			return err
		}

		cmd := exec.CommandContext(ctx, "openvpn", "--mktun", "--dev", linkName)
		err = cmd.Run()
		if err != nil {
			return err
		}

		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return err
		}

		err = netlink.LinkSetBondSlave(link, bond)
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
func kernelSettings(cfg config) error {
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
	return nil
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

func getVpnClientIndex(cfg config) (int, error) {
	podNameSlice := strings.Split(cfg.PodName, "-")
	return strconv.Atoi(podNameSlice[len(podNameSlice)-1])
}

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg, err := getConfig()
	if err != nil {
		return err
	}
	log.Info("config parsed", "config", cfg)

	return fmt.Errorf("not yet implemented")
}

func subcommandBonding(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg, err := getConfig(log)
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
		err = configureBonding(ctx, cfg, vpnNetwork)
		if err != nil {
			return err
		}
	}
	return nil
}

func getConfig(log logr.Logger) (config, error) {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		return cfg, err
	}
	if cfg.VPNNetwork == "" {
		if cfg.IPFamilies == "IPv4" {
			cfg.VPNNetwork = "192.168.123.0/24"
		} else {
			cfg.VPNNetwork = "fd8f:6d53:b97a:1::/120"
		}
	}
	log.Info("config parsed", "config", cfg)
	return cfg, nil
}
