package app

import (
	"context"
	"errors"
	"fmt"
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
		Args:  cobra.NoArgs,
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
	iptable, err := iptables.New()
	if err != nil {
		return err
	}

	var op func(table, chain string, spec ...string) error
	var opName string
	switch mode {
	case "up":
		op = iptable.Append
		opName = "-A"
	case "down":
		op = iptable.DeleteIfExists
		opName = "-D"
	default:
		return errors.New("mode flag must be down or up")
	}

	for _, spec := range [][]string{
		{"-m", "state", "--state", "RELATED,ESTABLISHED", "-i", device, "-j", "ACCEPT"},
		{"-i", device, "-j", "DROP"},
	} {
		if err := op("raw", "INPUT", spec...); err != nil {
			return err
		}
		log.Info(fmt.Sprintf("iptables %s INPUT %s", opName, strings.Join(spec, " ")))
	}
	return nil
}
