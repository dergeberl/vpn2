// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/caarlos0/env/v10"
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
	defaultIPV4VpnNetwork     = "192.168.123.0/24"
	defaultIPV6VpnNetwork     = "fd8f:6d53:b97a:1::/120"
	openvpnConfigFile         = "/openvpn.config"
	openvpnClientConfigDir    = "/client-config-dir"
	openvpnClientConfigPrefix = "vpn-shoot-client"
)

type Environment struct {
	IPFamilies     string `env:"IP_FAMILIES" envDefault:"IPv4"`
	ServiceNetwork string `env:"SERVICE_NETWORK" envDefault:"100.64.0.0/13"`
	PodNetwork     string `env:"POD_NETWORK" envDefault:"100.96.0.0/11"`
	NodeNetwork    string `env:"NODE_NETWORK"`
	VPNNetwork     string `env:"VPN_NETWORK"`
	PodName        string `env:"POD_NAME"`
	StatusPath     string `env:"OPENVPN_STATUS_PATH"`
	HAVPNClients   int    `env:"HA_VPN_CLIENTS"`
	LocalNodeIP    string `env:"LOCAL_NODE_IP" envDefault:"255.255.255.255"`
}

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
	e, err := getEnvironment(log)
	if err != nil {
		return fmt.Errorf("could not parse environment")
	}
	cfg := config{
		Env: e,
	}

	sn, err := getIPNet(e.ServiceNetwork, "SERVICE_NETWORK")
	if err != nil {
		return err
	}
	cfg.ShootNetworks = append(cfg.ShootNetworks, sn)

	pn, err := getIPNet(e.PodNetwork, "POD_NETWORK")
	if err != nil {
		return err
	}
	cfg.ShootNetworks = append(cfg.ShootNetworks, pn)

	if e.NodeNetwork != "" {
		nn, err := getIPNet(e.NodeNetwork, "NODE_NETWORK")
		if err != nil {
			return err
		}
		cfg.ShootNetworks = append(cfg.ShootNetworks, nn)
	}

	isHA, vpnIndex := getHAInfo()

	switch isHA {
	case true:
		cfg.Device = "tap0"
	case false:
		cfg.Device = "tun0"
	}
	cfg.IsHA = isHA

	switch e.IPFamilies {
	case ipV4Family:
		vpnNetworkPrefix, err := netip.ParsePrefix(e.VPNNetwork)
		if err != nil {
			return fmt.Errorf("vpn network prefix is not a valid prefix, vpn network: %s", e.VPNNetwork)
		}
		if !vpnNetworkPrefix.Addr().Is4() {
			return fmt.Errorf("vpn network prefix is not v4 although v4 address family was specified")
		}
		if vpnNetworkPrefix.Bits() != 24 {
			return fmt.Errorf("invalid prefixlength of vpn network prefix, must be /24, vpn network: %s", e.VPNNetwork)
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
		vpnNetworkPrefix, err := netip.ParsePrefix(e.VPNNetwork)
		if err != nil {
			return fmt.Errorf("vpn network prefix is not a valid prefix, vpn network: %s", e.VPNNetwork)
		}
		if !vpnNetworkPrefix.Addr().Is6() {
			return fmt.Errorf("vpn network prefix is not v6 although v6 address family was specified")
		}
		if vpnNetworkPrefix.Bits() != 120 {
			return fmt.Errorf("invalid prefixlength of vpn network prefix, must be /120, vpn network: %s", e.VPNNetwork)
		}
		if isHA {
			return fmt.Errorf("error: the highly-available VPN setup is only supported for IPv4 single-stack shoots but IPv6 address family was specified")
		}
		cfg.OpenVPNNetwork = vpnNetworkPrefix

	default:
		return fmt.Errorf("no valid IP address family, ip address family: %s", e.IPFamilies)
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

	if cfg.IsHA {
		for i := 0; i < e.HAVPNClients; i++ {
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

	filterRegex, err := regexp.Compile(fmt.Sprintf(`(TCP connection established with \[AF_INET(6)?\]%s|)?%s(:[0-9]{1,5})? Connection reset, restarting`, e.LocalNodeIP, e.LocalNodeIP))
	if err != nil {
		return err
	}

	openvpnCommand := exec.CommandContext(ctx, "openvpn", "--config", openvpnConfigFile)
	openvpnStdout, err := openvpnCommand.StdoutPipe()
	if err != nil {
		return fmt.Errorf("could not connect to stdout of openvpn command")
	}

	err = openvpnCommand.Start()
	if err != nil {
		return fmt.Errorf("could not start openvpn command, %w", err)
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

func getIPNet(cidr, name string) (netip.Prefix, error) {
	ipnet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("environment variable %s does not contain a valid cidr: %s", name, cidr)
	}
	return ipnet, nil
}

func getEnvironment(log logr.Logger) (Environment, error) {
	e := Environment{}
	if err := env.Parse(&e); err != nil {
		return e, err
	}
	if e.VPNNetwork == "" {
		switch e.IPFamilies {
		case ipV4Family:
			e.VPNNetwork = defaultIPV4VpnNetwork
		case ipV6Family:
			e.VPNNetwork = defaultIPV6VpnNetwork
		}
	}
	log.Info("environment parsed", "environment", e)
	return e, nil
}
