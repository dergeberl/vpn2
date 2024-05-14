// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
	ipV4Family                = "IPv4"
	ipV6Family                = "IPv6"
	baseConfigDir             = "/init-config"
	defaultIPFamilies         = ipV4Family
	defaultServiceNetwork     = "100.64.0.0/13"
	defaultPodNetwork         = "100.96.0.0/11"
	defaultNodeNetwork        = ""
	defaultIPV4VpnNetwork     = "192.168.123.0/24"
	defaultIPV6VpnNetwork     = "fd8f:6d53:b97a:1::/120"
	defaultLocalNodeIP        = "255.255.255.255"
	openvpnConfigFile         = "/openvpn.config"
	openvpnClientConfigDir    = "/client-config-dir"
	openvpnClientConfigPrefix = "vpn-shoot-client"
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
	cmd.AddCommand(firewallCommand())

	return cmd
}

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	var cfg config
	var err error

	cfg.IPFamilies = getConfigString("IP_FAMILIES", "", defaultIPFamilies)

	serviceNetwork := getConfigString("SERVICE_NETWORK", baseConfigDir+"/serviceNetwork", defaultServiceNetwork)
	sn, err := getIPNet(serviceNetwork, "SERVICE_NETWORK")
	if err != nil {
		return err
	}
	cfg.ShootNetworks = append(cfg.ShootNetworks, sn)

	podNetwork := getConfigString("POD_NETWORK", baseConfigDir+"/podNetwork", defaultPodNetwork)
	pn, err := getIPNet(podNetwork, "POD_NETWORK")
	if err != nil {
		return err
	}
	cfg.ShootNetworks = append(cfg.ShootNetworks, pn)

	nodeNetwork := getConfigString("NODE_NETWORK", baseConfigDir+"/nodeNetwork", defaultNodeNetwork)
	if nodeNetwork != "" {
		nn, err := getIPNet(nodeNetwork, "NODE_NETWORK")
		if err != nil {
			return err
		}
		cfg.ShootNetworks = append(cfg.ShootNetworks, nn)
	}

	vpnNetwork := getConfigString("VPN_NETWORK", baseConfigDir+"/vpnNetwork", "")

	isHA, vpnIndex := getHAInfo()

	switch isHA {
	case true:
		cfg.Device = "tap0"
	case false:
		cfg.Device = "tun0"
	}
	cfg.IsHA = isHA

	cfg.StatusPath = os.Getenv("OPENVPN_STATUS_PATH")

	switch cfg.IPFamilies {
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
			return fmt.Errorf("invalid prefixlength of vpn network prefix, must be /24, vpn network: %s", vpnNetwork)
		}
		vpnNetworkPrefixBytes := vpnNetworkPrefix.Addr().As4()
		switch isHA {
		case true:
			vpnNetworkPrefixBytes[3] = byte(vpnIndex * 64)
			cfg.OpenVPNNetwork, _ = netip.AddrFrom4(vpnNetworkPrefixBytes).Prefix(26)
			vpnNetworkPrefixBytes[3] = byte(vpnIndex*64 + 8)
			cfg.IPv4PoolStartIP = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
			vpnNetworkPrefixBytes[3] = byte(vpnIndex*64 + 62)
			cfg.IPv4PoolEndIP = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
		case false:
			cfg.OpenVPNNetwork = vpnNetworkPrefix
			vpnNetworkPrefixBytes[3] = byte(10)
			cfg.IPv4PoolStartIP = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
			vpnNetworkPrefixBytes[3] = byte(254)
			cfg.IPv4PoolEndIP = netip.AddrFrom4(vpnNetworkPrefixBytes).String()
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
			return fmt.Errorf("invalid prefixlength of vpn network prefix, must be /120, vpn network: %s", vpnNetwork)
		}
		if isHA {
			return fmt.Errorf("error: the highly-available VPN setup is only supported for IPv4 single-stack shoots but IPv6 address family was specified")
		}
		cfg.OpenVPNNetwork = vpnNetworkPrefix

	default:
		return fmt.Errorf("no valid IP address family, ip address family: %s", cfg.IPFamilies)
	}
	log.Info("using openvpn network", "openVPNNetwork", cfg.OpenVPNNetwork)

	openvpnConfig, err := GenerateOpenVPNConfig(cfg)
	if err != nil {
		return fmt.Errorf("error %w: Could not generate openvpn config from %v", err, cfg)
	}
	if err := os.WriteFile(openvpnConfigFile, []byte(openvpnConfig), 0o644); err != nil {
		return err
	}

	vpnShootClientConfig, err := GenerateVPNShootClient(cfg)
	if err != nil {
		return fmt.Errorf("error %w: Could not generate shoot client config from %v", err, cfg)
	}
	if err := os.WriteFile(openvpnClientConfigDir+openvpnClientConfigPrefix, []byte(vpnShootClientConfig), 0o644); err != nil {
		return err
	}

	cfg.HAVPNClients, _ = strconv.Atoi(os.Getenv("HA_VPN_CLIENTS"))
	if cfg.IsHA {
		for i := 0; i < cfg.HAVPNClients; i++ {
			startIP := cfg.OpenVPNNetwork.Addr().As4()
			startIP[3] = byte(vpnIndex*64 + i + 2)
			vpnShootClientConfigHA, err := GenerateVPNShootClientHA(cfg, netip.AddrFrom4(startIP).String())
			if err != nil {
				return fmt.Errorf("error %w: Could not generate ha shoot client config %d from %v", err, i, cfg)
			}
			if err := os.WriteFile(fmt.Sprintf("%s%s-%d", openvpnClientConfigDir, openvpnClientConfigPrefix, i), []byte(vpnShootClientConfigHA), 0o644); err != nil {
				return err
			}
		}
	}

	cfg.LocalNodeIP = os.Getenv("LOCAL_NODE_IP")
	if cfg.LocalNodeIP == "" {
		cfg.LocalNodeIP = defaultLocalNodeIP
	}

	filterRegex, err := regexp.Compile(fmt.Sprintf(`(TCP connection established with \[AF_INET(6)?\]%s|)?%s(:[0-9]{1,5})? Connection reset, restarting`, cfg.LocalNodeIP, cfg.LocalNodeIP))
	if err != nil {
		return err
	}

	openvpnCommand := exec.Command("openvpn", "--config", openvpnConfigFile)
	openvpnStdout, err := openvpnCommand.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Could not connect to stdout of openvpn command")
	}

	err = openvpnCommand.Start()
	if err != nil {
		return fmt.Errorf("Could not start openvpn command, %w", err)
	}
	defer openvpnCommand.Wait()

	scanner := bufio.NewScanner(openvpnStdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if !filterRegex.Match(line) {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte("\n"))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
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

func getIPNet(cidr, name string) (netip.Prefix, error) {
	ipnet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("environment variable %s does not contain a valid cidr: %s", name, cidr)
	}
	return ipnet, nil
}
