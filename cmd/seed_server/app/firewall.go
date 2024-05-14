package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

func firewallCommand() *cobra.Command {
	var device string
	var mode string

	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "firewall",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := utils.InitRun(cmd, Name)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			return runFirewallCommand(ctx, cancel, log, device, mode)
		},
	}

	cmd.Flags().StringVar(&device, "device", "", "device to configure")
	cmd.Flags().StringVar(&mode, "mode", "", "mode of firewall (up or down)")
	cmd.MarkFlagsRequiredTogether("device", "mode")

	return cmd
}

func runFirewallCommand(_ context.Context, _ context.CancelFunc, log logr.Logger, device, mode string) error {
	os.Setenv("PATH", "/sbin")
	iptable4, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return err
	}
	iptable6, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
	if err != nil {
		return err
	}

	var op4, op6 func(table, chain string, spec ...string) error
	var opName string
	switch mode {
	case "up":
		op4 = iptable4.Append
		op6 = iptable6.Append
		opName = "-A"
	case "down":
		op4 = iptable4.DeleteIfExists
		op6 = iptable6.DeleteIfExists
		opName = "-D"
	default:
		return errors.New("mode flag must be down or up")
	}

	for _, spec := range [][]string{
		{"-m", "state", "--state", "RELATED,ESTABLISHED", "-i", device, "-j", "ACCEPT"},
		{"-i", device, "-j", "DROP"},
	} {
		if err := op4("filter", "INPUT", spec...); err != nil {
			return err
		}
		if err := op6("filter", "INPUT", spec...); err != nil {
			return err
		}
		log.Info(fmt.Sprintf("iptables %s INPUT %s", opName, strings.Join(spec, " ")))
	}
	return nil
}
