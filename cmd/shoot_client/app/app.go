// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/gardener/vpn2/pkg/ippool"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
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

	return cmd
}

type config struct {
	TCP struct {
		KeepAliveTime     int `env:"KEEPALIVE_TIME" envDefault:"7200"`
		KeepAliveInterval int `env:"KEEPALIVE_INTVL" envDefault:"75"`
		KeepAliveProbes   int `env:"KEEPALIVE_PROBES" envDefault:"9"`
	} `envPrefix:"TCP_"`
	IPFamilies       string `env:"IP_FAMILIES" envDefault:"IPv4"`
	OpenVPNPort      int    `env:"OPENVPN_PORT" envDefault:"8132"`
	VPNNetwork       string `env:"VPN_NETWORK"`
	IsShootClient    bool   `env:"IS_SHOOT_CLIENT"`
	PodName          string `env:"POD_NAME"`
	Namespace        string `env:"NAMESPACE"`
	StartIndex       int    `env:"START_INDEX" envDefault:"200"`
	EndIndex         int    `env:"END_INDEX" envDefault:"254"`
	PodLabelSelector string `env:"POD_LABEL_SELECTOR" envDefault:"app=kubernetes,role=apiserver"`
	WaitSeconds      int    `env:"WAIT_SECONDS" envDefault:"2"`
}

func getCIDR(networkCIDR string, ipFamily string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, err
	}
	length, _ := cidr.Mask.Size()
	switch ipFamily {
	case "IPv4":
		if length != 24 {
			return nil, fmt.Errorf("ipv4 setup needs vpn network to have /24 subnet mask, got %d", length)
		}
	case "IPv6":
		if length != 120 {
			return nil, fmt.Errorf("ipv6 setup needs vpn network to have /120 subnet mask, got %d", length)
		}
	default:
		return nil, fmt.Errorf("unknown ipFamily: %s", ipFamily)
	}
	return cidr, nil
}

// please change this name omg
func computeShootTargetAndAddr(vpnNetwork *net.IPNet, vpnClientIndex int) (*net.IPNet, *net.IP, error) {
	_, addrLen := vpnNetwork.Mask.Size()

	newIP := slices.Clone(vpnNetwork.IP.To4())
	newIP[3] = byte(bondStart + 2 + vpnClientIndex)

	shootSubnet := &net.IPNet{
		IP:   newIP,
		Mask: net.CIDRMask(bondBits, addrLen),
	}

	target := slices.Clone(newIP)
	target[3] = byte(bondStart + 1)
	return shootSubnet, &target, nil
}

// please change this name omg
func computeSeedTargetAndAddr(acquiredIP net.IP, vpnNetwork *net.IPNet, haVPNClients int) (*net.IPNet, []net.IP, error) {
	subnet := &net.IPNet{
		IP:   acquiredIP,
		Mask: net.CIDRMask(bondBits, 32),
	}

	targets := make([]net.IP, 0, haVPNClients)
	for i := range haVPNClients {
		targetIP := slices.Clone(vpnNetwork.IP.To4())
		targetIP[3] = byte(bondStart + i + 2)
		targets = append(targets, targetIP)
	}
	return subnet, targets, nil

}

const (
	bondBits  = 26
	bondStart = 192
)

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

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		return err
	}
	if cfg.VPNNetwork == "" {
		if cfg.IPFamilies == "IPv4" {
			cfg.VPNNetwork = "192.168.123.0/24"
		} else {
			cfg.VPNNetwork = "fd8f:6d53:b97a:1::/120"
		}
	}
	log.Info("config parsed", "config", cfg)
	vpnNetwork, err := getCIDR(cfg.VPNNetwork, cfg.IPFamilies)
	if err != nil {
		return err
	}

	// todo compute
	// vpnClientIndex := 0
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

	return fmt.Errorf("not yet implemented")
}
