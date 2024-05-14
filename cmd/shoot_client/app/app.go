// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/vpn2/cmd/shoot_client/app/init"
	"github.com/gardener/vpn2/cmd/shoot_client/app/pathcontroller"
	"github.com/gardener/vpn2/pkg/config"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/component-base/version/verflag"
	"os"
	"os/exec"
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
	cmd.AddCommand(init.NewCommand())
	return cmd
}

func vpnConfig(log logr.Logger, cfg config.Config) string {
	vpnSeedServer := "vpn-seed-server"
	dev := "tun0"

	if cfg.VPNServerIndex != "" {
		vpnSeedServer = fmt.Sprintf("vpn-seed-server-%s", cfg.VPNServerIndex)
		dev = fmt.Sprintf("tap%s", cfg.VPNServerIndex)
	}

	log.Info("Generate Config", "vpn-seed-sever", vpnSeedServer, "dev", dev)
	var openvpnConfig string

	// don't cache authorization information in memory
	openvpnConfig += fmt.Sprintln("auth-nocache")
	// stop process if something goes wrong
	openvpnConfig += fmt.Sprintln("remap-usr1 SIGTERM")
	// additional optimizations
	openvpnConfig += fmt.Sprintln("txqueuelen 1000")
	// get all routing information from server
	openvpnConfig += fmt.Sprintln("pull")
	openvpnConfig += fmt.Sprintln("data-ciphers AES-256-GCM")
	openvpnConfig += fmt.Sprintln("tls-client")
	openvpnConfig += fmt.Sprintln("auth SHA256")
	openvpnConfig += fmt.Sprintln("tls-auth \"/srv/secrets/tlsauth/vpn.tlsauth\" 1")
	// https://openvpn.net/index.php/open-source/documentation/howto.html#mitm
	openvpnConfig += fmt.Sprintln("remote-cert-tls server")
	openvpnConfig += fmt.Sprintln("pull-filter ignore redirect-gateway")
	openvpnConfig += fmt.Sprintln("pull-filter ignore redirect-gateway-ipv6")

	switch cfg.IPFamilies {
	case "IPv4":
		openvpnConfig += fmt.Sprintln("proto tcp4-client")
	case "IPv6":
		openvpnConfig += fmt.Sprintln("proto tcp6-client")
	}
	if cfg.VPNClientIndex == -1 {
		openvpnConfig += fmt.Sprintln("key /srv/secrets/vpn-client/tls.key")
		openvpnConfig += fmt.Sprintln("cert /srv/secrets/vpn-client/tls.crt")
		openvpnConfig += fmt.Sprintln("ca /srv/secrets/vpn-client/ca.crt")
	} else {
		openvpnConfig += fmt.Sprintf("key /srv/secrets/vpn-client-%d/tls.key\n", cfg.VPNClientIndex)
		openvpnConfig += fmt.Sprintf("cert /srv/secrets/vpn-client-%d/tls.crt\n", cfg.VPNClientIndex)
		openvpnConfig += fmt.Sprintf("ca /srv/secrets/vpn-client-%d/ca.crt\n", cfg.VPNClientIndex)
	}

	openvpnConfig += fmt.Sprintf("port %d\n", cfg.OpenVPNPort)

	if cfg.IsShootClient {
		openvpnConfig += fmt.Sprintf("http-proxy %s %d\n", cfg.Endpoint, cfg.OpenVPNPort)
		openvpnConfig += fmt.Sprintf("http-proxy-option CUSTOM-HEADER Reversed-VPN %s\n", cfg.ReversedVPNHeader)
	}
	return openvpnConfig
}

func setIPTableRules(cfg config.Config) error {
	forwardDevice := "tun0"
	if cfg.VPNServerIndex != "" {
		forwardDevice = "bond0"
	}

	iptable, err := iptables.New()
	if err != nil {
		return err
	}

	if cfg.IsShootClient {
		if cfg.IPFamilies == "IPv4" {
			err = iptable.Append("filter", "FORWARD", "--in-interface", forwardDevice, "-j", "ACCEPT")
			if err != nil {
				return err
			}
		}

		err = iptable.Append("nat", "POSTROUTING", "--out-interface", "eth0", "-j", "MASQUERADE")
		if err != nil {
			return err
		}
	} else {
		err = iptable.AppendUnique("filter", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-i", forwardDevice, "-j", "ACCEPT")
		if err != nil {
			return err
		}
		err = iptable.AppendUnique("filter", "INPUT", "-i", forwardDevice, "-j", "DROP")
		if err != nil {
			return err
		}
	}
	return nil
}

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	cfg, err := config.GetConfig(log)
	if err != nil {
		return err
	}
	log.Info("config parsed", "config", cfg)

	// TODO move to subcommand
	err = init.Run(ctx, cancel, log)
	if err != nil {
		return err
	}
	if cfg.ExitAfterKernelSettings {
		return nil
	}

	err = setIPTableRules(cfg)
	if err != nil {
		return err
	}

	openVPNConfig := vpnConfig(log, cfg)
	err = os.WriteFile("openvpn.config", []byte(openVPNConfig), 0666)
	if err != nil {
		return err
	}

	dev := "tun0"
	if cfg.VPNServerIndex != "" {
		dev = fmt.Sprintf("tap%s", cfg.VPNServerIndex)
	}

	cmd := exec.CommandContext(ctx, "openvpn", "--dev", dev, "--remote", cfg.Endpoint, "--config", "openvpn.config")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
