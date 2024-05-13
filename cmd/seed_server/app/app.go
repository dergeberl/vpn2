// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"

	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/component-base/version/verflag"
)

// Name is a const for the name of this component.
const Name = "seed-server"

const (
	ipV4Family            = "IPv4"
	ipV6Family            = "IPv6"
	baseConfigDir         = "/init-config"
	defaultIPFamilies     = ipV4Family
	defaultServiceNetwork = "100.64.0.0/13"
	defaultPodNetwork     = "100.96.0.0/11"
	defaultNodeNetwork    = ""
	defaultIPV4VpnNetwork = "192.168.123.0/24"
	defaultIPV6VpnNetwork = "fd8f:6d53:b97a:1::/120"
)

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

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	log.Info("TODO")

	ipFamilies, defined := os.LookupEnv("IP_FAMILIES")
	if !defined {
		ipFamilies = defaultIPFamilies
	}

	serviceNetwork := getConfigString("SERVICE_NETWORK", baseConfigDir+"/serviceNetwork", defaultServiceNetwork)
	podNetwork := getConfigString("POD_NETWORK", baseConfigDir+"/podNetwork", defaultPodNetwork)
	nodeNetwork := getConfigString("NODE_NETWORK", baseConfigDir+"/nodeNetwork", defaultNodeNetwork)
	vpnNetwork := getConfigString("VPN_NETWORK", baseConfigDir+"/vpnNetwork", "")

	isHA, vpnIndex := getHAInfo()

	var openVPNNetwork, openVPNNetworkPoolStart, openVPNNetworkPoolEnd string // FIXME we probably want these as netip.Prefix / netip.Addr instead of strings for more flexible use in template

	switch ipFamilies {
	case ipV4Family:
		if vpnNetwork == "" {
			vpnNetwork = defaultIPV4VpnNetwork
		}
		vpnNetworkPrefix, err := netip.ParsePrefix(vpnNetwork)
		if err != nil {
			return fmt.Errorf("vpn network prefix is not a valid prefix, vpn network: %s", vpnNetwork)
		}
		if !vpnNetworkPrefix.Addr().Is4() {
			return fmt.Errorf("vpn network prefix is not v4 although v4 address family was specified")
		}
		if vpnNetworkPrefix.Bits() != 24 {
			return fmt.Errorf("Invalid prefixlength of vpn network prefix, must be /24, vpn network: %s", vpnNetwork)
		}
		vpnNetworkPrefixBytes := vpnNetworkPrefix.Addr().As4()
		switch isHA {
		case true:
			vpnNetworkPrefixBytes[3] = byte(vpnIndex * 64)
			on, _ := netip.AddrFrom4(vpnNetworkPrefixBytes).Prefix(26)
			openVPNNetwork = on.String()
			vpnNetworkPrefixBytes[3] = byte(vpnIndex*64 + 8)
			openVPNNetworkPoolStart = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
			vpnNetworkPrefixBytes[3] = byte(vpnIndex*64 + 62)
			openVPNNetworkPoolEnd = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
		case false:
			openVPNNetwork = vpnNetworkPrefix.String()
			vpnNetworkPrefixBytes[3] = byte(10)
			openVPNNetworkPoolStart = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
			vpnNetworkPrefixBytes[3] = byte(254)
			openVPNNetworkPoolStart = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
		}

	case ipV6Family:
		if vpnNetwork == "" {
			vpnNetwork = defaultIPV6VpnNetwork
		}
		vpnNetworkPrefix, err := netip.ParsePrefix(vpnNetwork)
		if err != nil {
			return fmt.Errorf("vpn network prefix is not a valid prefix, vpn network: %s", vpnNetwork)
		}
		if !vpnNetworkPrefix.Addr().Is6() {
			return fmt.Errorf("vpn network prefix is not v6 although v6 address family was specified")
		}
		if vpnNetworkPrefix.Bits() != 120 {
			return fmt.Errorf("Invalid prefixlength of vpn network prefix, must be /120, vpn network: %s", vpnNetwork)
		}
		if isHA {
			return fmt.Errorf("error: the highly-available VPN setup is only supported for IPv4 single-stack shoots but IPv6 address family was specified")
		}
		openVPNNetwork = vpnNetworkPrefix.String()

	default:
		return fmt.Errorf("No valid IP address family, ip address family: %s", ipFamilies)
	}
	log.Info("using openvpn network", "openVPNNetwork", openVPNNetwork)

	return fmt.Errorf("not yet implemented")
}

func getConfigString(key, filename, fallback string) string {
	result, defined := os.LookupEnv(key)
	if defined {
		return result
	}

	if filename != "" {
		sn, _ := os.ReadFile(filename)
		if sn != nil {
			return string(sn)
		}
	}

	return fallback
}

func getHAInfo() (bool, int) {
	podName, ok := os.LookupEnv("POD_NAME")
	if !ok {
		return false, 0
	}

	re := regexp.MustCompile(`.*-([0-2])$`)
	matches := re.FindStringSubmatch(podName)
	if len(matches) > 1 {
		index, _ := strconv.Atoi(matches[1])
		return true, index
	}
	return false, 0
}

func netmaskFromPrefixBits(bits, prefixlen int) string {
	return net.CIDRMask(bits, prefixlen).String()
}
