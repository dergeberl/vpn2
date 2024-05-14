package app

import (
	"context"
	"errors"

	"github.com/gardener/vpn2/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
)

var device string
var mode string

func firewallCommand() *cobra.Command {
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
			return run(ctx, cancel, log)
		},
	}

	cmd.Flags().StringVarP(&device, "device", "d", "", "device to configure")
	cmd.Flags().StringVarP(&mode, "mode", "d", "", "mode of firewall (up or down)")
	cmd.MarkFlagsRequiredTogether("device", "mode")

	return cmd
}

func runFirewallCommand(ctx context.Context, cancel context.CancelFunc, log logr.Logger) error {
	if mode != "up" && mode != "down" {
		return errors.New("mode flag must be down or up")
	}

	return nil
}
