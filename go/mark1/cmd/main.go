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
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/apparmor"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/corpus"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/doctor"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enable"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/report"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/selfupdate"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/service"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/status"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/verifyreceipts"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/verifyrelease"
)

// Injected at release via -ldflags "-X main.version=..." (13 §9).
var version = "0.0.0-dev"

// isTerminal: stdlib's answer, portable — a console on Windows is a char
// device too. A pipe, a file or /dev/null is not, and gets no consent prompt.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

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

	var enableOpts enable.Options
	enableCmd := &cobra.Command{
		Use:   "enable <workspace-path>",
		Short: "Add a workspace to the capture allow-list and consent to its anchors (08 §7.2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enableOpts.Path = args[0]
			// The consent prompt reads a terminal or nothing: piped stdin
			// never consents (enable.Options.TTY).
			enableOpts.Stdin, enableOpts.TTY = os.Stdin, isTerminal(os.Stdin)
			return enable.Run(env, enableOpts)
		},
	}
	enableCmd.Flags().StringSliceVar(&enableOpts.Anchors, "anchors", nil, "consent non-interactively to exactly these catalog IDs (comma-separated)")
	enableCmd.Flags().BoolVar(&enableOpts.NoAnchors, "no-anchors", false, "skip anchor consent prompts")
	enableCmd.Flags().BoolVar(&enableOpts.StopGate, "stop-gate", false, "opt in (at a terminal) to fail-closed blocking below the knee (FR-POLICY-006); `mark1 off` removes it")
	enableCmd.Flags().BoolVar(&enableOpts.NoStopGate, "no-stop-gate", false, "remove the stop-gate opt-in")
	enableCmd.MarkFlagsMutuallyExclusive("stop-gate", "no-stop-gate")
	enableCmd.Flags().BoolVar(&enableOpts.Exploration, "exploration", false, "opt in to ε>0 exploration (D-EF local half; the tenant's signed bundle must also carry it)")
	enableCmd.Flags().BoolVar(&enableOpts.NoExploration, "no-exploration", false, "remove the exploration opt-in")
	enableCmd.MarkFlagsMutuallyExclusive("exploration", "no-exploration")

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

	var corpusOpts corpus.Options
	corpusRecordCmd := &cobra.Command{
		Use:   "record",
		Short: "Record a conformance corpus from the installed agent (12 §3.2 recording lane): claude is driven, codex/gemini/opencode/copilot are harvested from disk",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return corpus.Record(ctx, env, corpusOpts)
		},
	}
	corpusRecordCmd.Flags().StringVar(&corpusOpts.Agent, "agent", "claudecode", "claudecode | codex | gemini | opencode | copilot")
	corpusRecordCmd.Flags().StringVar(&corpusOpts.Out, "out", "", "corpus root; writes v<installed-version>/ under it (default conformance/hooks/<agent>)")
	corpusRecordCmd.Flags().DurationVar(&corpusOpts.Since, "since", 24*time.Hour, "harvest: only artifacts modified within this window")
	corpusRecordCmd.Flags().StringVar(&corpusOpts.Workspace, "workspace", "", "harvest: the real workspace root to rewrite as /home/devuser/workspace/acme-app (default: cwd)")
	corpusCmd := &cobra.Command{Use: "corpus", Short: "Conformance corpus tooling"}
	corpusCmd.AddCommand(corpusRecordCmd)

	var vrelOpts verifyrelease.Options
	verifyReleaseCmd := &cobra.Command{
		Use:   "verify-release <artifact>",
		Short: "Verify a release artifact's SLSA provenance before executing it (09 §11.2, FR-POLICY-009)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vrelOpts.Artifact = args[0]
			return verifyrelease.Run(env, vrelOpts)
		},
	}
	verifyReleaseCmd.Flags().StringVar(&vrelOpts.Provenance, "provenance", "", "Sigstore bundle (default <artifact>.sigstore.json; or the .jsonl gh attestation download writes)")
	verifyReleaseCmd.Flags().StringVar(&vrelOpts.TrustedRoot, "trusted-root", "", "Sigstore trusted_root.json[l] (default: the snapshot built into this binary)")

	var svcOpts service.Options
	serviceCmd := &cobra.Command{Use: "service", Short: "Register mark1d as a login item of the current user (04 §11.4: launchd / systemd --user / Task Scheduler)"}
	serviceCmd.PersistentFlags().StringVar(&svcOpts.Daemon, "daemon", "", "mark1d binary (default: beside this executable, then PATH)")
	for _, sub := range []struct {
		use, short string
		run        func(*cli.Env, service.Options) error
	}{
		{"install", "Register mark1d to run at login and start it (idempotent)", service.Install},
		{"uninstall", "Stop mark1d and remove exactly what install wrote", service.Uninstall},
		{"status", "registered / running / pid", service.Query},
		{"start", "Start the registered mark1d", service.Start},
		{"stop", "Stop the registered mark1d", service.Stop},
	} {
		serviceCmd.AddCommand(&cobra.Command{
			Use: sub.use, Short: sub.short, Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return sub.run(env, svcOpts) },
		})
	}

	var updOpts selfupdate.Options
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Apply the release the update manifest names for this ring, SLSA-verified through verify-release (09 §11.2, FR-POLICY-009)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return selfupdate.Run(ctx, env, updOpts)
		},
	}
	updateCmd.Flags().BoolVar(&updOpts.Check, "check", false, "print the available version; apply nothing")
	updateCmd.Flags().StringVar(&updOpts.Manifest, "manifest", selfupdate.DefaultManifestURL, "update manifest URL")
	updateCmd.Flags().StringVar(&updOpts.InstallDir, "install-dir", "", "where the edge binaries live (default: this executable's directory)")
	updateCmd.Flags().StringVar(&updOpts.Ring, "ring", "", "manifest ring (default: the enrollment channel, else stable)")

	var aaDaemon string
	apparmorCmd := &cobra.Command{Use: "apparmor", Short: "The AppArmor profile that lets mark1d's anchor sandbox create a user namespace on Ubuntu >= 23.10 (10 §7.4); root only"}
	apparmorCmd.PersistentFlags().StringVar(&aaDaemon, "daemon", "", "mark1d binary (default: beside this executable, then PATH)")
	apparmorCmd.AddCommand(&cobra.Command{
		Use: "install", Short: "Write and load the userns profile for mark1d when the kernel restricts user namespaces (idempotent)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := service.DaemonPath(aaDaemon)
			if err != nil {
				return cli.Failf(cli.ExitRuntime, "", "%v", err)
			}
			ok, err := apparmor.Install(d)
			if err != nil {
				return cli.Failf(cli.ExitRuntime, "", "%v", err)
			}
			return env.Emit(map[string]any{"installed": ok, "daemon": d}, func(w io.Writer) {
				if ok {
					_, _ = fmt.Fprintf(w, "AppArmor profile %s loaded for %s\n", apparmor.Name, d)
				} else {
					_, _ = fmt.Fprintln(w, "unprivileged user namespaces are not restricted here; nothing to install")
				}
			})
		},
	}, &cobra.Command{
		Use: "uninstall", Short: "Unload and remove the profile install wrote", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apparmor.Uninstall(); err != nil {
				return cli.Failf(cli.ExitRuntime, "", "%v", err)
			}
			return env.Emit(map[string]any{"removed": true}, func(w io.Writer) { _, _ = fmt.Fprintln(w, "AppArmor profile removed") })
		},
	})

	root.AddCommand(enrollCmd, enableCmd, statusCmd, doctorCmd, reportCmd, offCmd, onCmd, verifyCmd, corpusCmd, verifyReleaseCmd, serviceCmd, updateCmd, apparmorCmd)

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
