// mark1 — the delivery-registry CLI (08 §7). This file is flag parse and
// wiring only (13 §1's cmd/main.go rule); each subcommand's logic lives in
// its internal package and returns cli.ExitError so the wire-stable exit
// codes (0/1/2/3/4/5) survive cobra. Anything cobra itself rejects (unknown
// flag, bad argument) is exit 2 by the global contract.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/doctor"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enable"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/report"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/status"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/verifyreceipts"
)

// Injected at release via -ldflags "-X main.version=..." (13 §9).
var version = "0.0.0-dev"

func main() {
	env := &cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Version: version}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := &cobra.Command{
		Use:           "mark1",
		Short:         "Omium Mark 1 delivery registry",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if env.StateDir == "" {
				dir, err := cli.DefaultStateDir()
				if err != nil {
					return cli.Failf(cli.ExitRuntime, "", "%v (pass --state-dir)", err)
				}
				env.StateDir = dir
			}
			return nil
		},
	}
	pf := root.PersistentFlags()
	pf.BoolVar(&env.JSON, "json", false, "machine output: exactly one JSON object on stdout (the contract)")
	pf.BoolVar(&env.Quiet, "quiet", false, "suppress human output")
	pf.StringVar(&env.StateDir, "state-dir", "", "state root (default ~/.omium/mark1 — must match mark1d's)")
	pf.StringVar(&env.Server, "server", "", "control-plane base URL (default from enrollment, else "+cli.DefaultServer+")")
	// --workspace is the global scope flag of 08 §7; only off consumes it
	// today — the others take explicit arguments.
	workspaceFlag := pf.String("workspace", "", "workspace scope (default: cwd's enclosing enabled root)")

	var enrollOpts enroll.Options
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device (OIDC device-code flow, 08 §7.1)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return enroll.Run(ctx, env, enrollOpts)
		},
	}
	// 08 §7.1 names this "<slug>"; until m1_tenants grows a slug column the
	// slug IS the tenant UUID your onboarding handed out (RLS routes on it).
	enrollCmd.Flags().StringVar(&enrollOpts.Tenant, "tenant", "", "tenant slug (the tenant id from onboarding)")
	enrollCmd.Flags().StringVar(&enrollOpts.Channel, "channel", "stable", "bundle channel: stable|canary")

	enableCmd := &cobra.Command{
		Use:   "enable <workspace-path>",
		Short: "Add a workspace to the capture allow-list (08 §7.2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return enable.Run(env, enable.Options{Path: args[0]})
		},
	}
	// §7.2 flags accepted for contract stability; the anchor-consent walk is
	// mark1d's anchors catalog row, so today both mean "no anchor prompts".
	enableCmd.Flags().String("anchors", "", "consent non-interactively to exactly these catalog IDs")
	enableCmd.Flags().Bool("no-anchors", false, "skip anchor consent prompts")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "The live read surface (08 §7.3)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return status.Run(env, status.Options{})
		},
	}

	var doctorFix bool
	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Consent catalog, fenced-config state, environment health (08 §7.4)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doctor.Run(env, doctor.Options{Fix: doctorFix})
		},
	}
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "re-apply FRAGMENT-DAMAGED/MISSING fragments (§8 apply)")

	var reportOpts report.Options
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "TVO report with coverage band and cost basis (08 §7.5)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.Run(ctx, env, reportOpts)
		},
	}
	reportCmd.Flags().StringVar(&reportOpts.Window, "window", "30d", "report window")
	reportCmd.Flags().StringVar(&reportOpts.Cohort, "cohort", "", "cohort filter")
	reportCmd.Flags().BoolVar(&reportOpts.GuaranteeGrade, "guarantee-grade", false, "refuse (exit 4) below the coverage floor instead of caveating")

	var offOpts off.Options
	var offDuration time.Duration
	offCmd := &cobra.Command{
		Use:   "off",
		Short: "THE kill switch: OFF marker before any gate (08 §7.6)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			offOpts.Workspace = *workspaceFlag
			offOpts.Duration = offDuration
			return off.Run(env, offOpts)
		},
	}
	offCmd.Flags().BoolVar(&offOpts.All, "all", false, "all workspaces (the default scope)")
	offCmd.Flags().DurationVar(&offDuration, "duration", 0, "off window, e.g. 2h (0 = until `mark1 on`)")

	onCmd := &cobra.Command{
		Use:   "on",
		Short: "Remove the OFF marker (inverse of `mark1 off`, 08 §7.6)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return off.On(env)
		},
	}

	var vrOpts verifyreceipts.Options
	verifyCmd := &cobra.Command{
		Use:   "verify-receipts",
		Short: "Verify the receipt chain via the standalone verifier (08 §7.7)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return verifyreceipts.Run(ctx, env, vrOpts)
		},
	}
	verifyCmd.Flags().StringVar(&vrOpts.From, "from", "", "local export.jsonl or a dir of *.jsonl (skips the fetch)")
	verifyCmd.Flags().BoolVar(&vrOpts.AgainstWitness, "against-witness", false, "cross-check chain heads against a witness snapshot")
	verifyCmd.Flags().BoolVar(&vrOpts.Offline, "offline", false, "no network: requires --from and --keys")
	verifyCmd.Flags().StringVar(&vrOpts.Keys, "keys", "", "local key-manifest snapshot (default: fetched from /api/v1/receipts/keys)")
	verifyCmd.Flags().StringVar(&vrOpts.Witness, "witness", "", "local witness snapshot file")

	root.AddCommand(enrollCmd, enableCmd, statusCmd, doctorCmd, reportCmd, offCmd, onCmd, verifyCmd)

	if err := root.Execute(); err != nil {
		var ee *cli.ExitError
		if !errors.As(err, &ee) {
			// Everything a subcommand raises is an ExitError; what is left
			// is cobra's own flag/arg rejection — usage, exit 2.
			fmt.Fprintln(os.Stderr, "mark1:", err)
			os.Exit(cli.ExitUsage)
		}
		if !ee.Emitted {
			env.EmitError(ee)
		}
		os.Exit(ee.Code)
	}
}
