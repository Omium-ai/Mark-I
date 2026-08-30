// Package doctor is 08 §7.4: the consented anchor catalog, the fenced-config
// manifest surface, and environment health — CI-friendly (exit 1 on any
// failure, 0 all green, 3 not enrolled). The BLAKE3 checksum verification
// inside fragments belongs to mark1d's §8 apply/revert engine (its manifests
// carry blake3: hashes and the CLI's pinned dependency set has no blake3 by
// design, 13 §3.4); doctor reports what it can PROVE from this side —
// presence, permissions, target existence — and labels the rest unverified
// rather than green.
package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	Fix    bool
	Socket string // test seam
	// ClaudeSettings overrides the transcript-retention probe target
	// (default ~/.claude/settings.json); a test seam.
	ClaudeSettings string
}

type Report struct {
	OK        bool       `json:"ok"`
	Anchors   []Anchor   `json:"anchors"`
	Fragments []Fragment `json:"fragments"`
	Health    []Check    `json:"health"`
}

type Anchor struct {
	ID        string `json:"id"`
	Consented bool   `json:"consented"`
	State     string `json:"state,omitempty"`
}

// Fragment states follow §7.4's vocabulary where provable from manifests
// alone: MISSING (target file gone) and PRESENT-UNVERIFIED (target exists;
// OK/USER-EDITED/FRAGMENT-DAMAGED need the §8 checksum walk in mark1d).
type Fragment struct {
	Manifest string `json:"manifest"`
	Target   string `json:"target"`
	State    string `json:"state"`
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func Run(env *cli.Env, opts Options) error {
	if _, err := env.LoadEnrollment(); err != nil {
		if errors.Is(err, cli.ErrNotEnrolled) {
			return cli.Failf(cli.ExitNotEnrolled, "M1E-1002", "not enrolled — run `mark1 enroll`")
		}
		return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
	}
	if opts.Fix {
		// --fix re-applies fragments via the §8 idempotent apply — that
		// engine lives in mark1d and has not landed. Refusing beats a fix
		// that rewrites bytes without the manifest discipline.
		return cli.Failf(cli.ExitRuntime, "", "--fix requires the §8 provisioning engine (mark1d row, not yet landed)")
	}

	rep := Report{OK: true}
	rep.Anchors = readAnchors(env)
	rep.Fragments = scanFragments(env)
	rep.Health = healthChecks(env, opts)

	for _, f := range rep.Fragments {
		if f.State == "MISSING" {
			rep.OK = false
		}
	}
	for _, c := range rep.Health {
		if !c.OK {
			rep.OK = false
		}
	}

	if err := env.Emit(rep, func(w io.Writer) { renderHuman(w, &rep) }); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "emit: %v", err)
	}
	if !rep.OK {
		ee := cli.Failf(cli.ExitRuntime, "", "doctor found problems")
		ee.Emitted = true
		return ee
	}
	return nil
}

// readAnchors renders <state>/anchors/catalog.json (04 §2.2's consent
// catalog, written at `mark1 enable`'s anchor walk — a mark1d anchors row).
// No catalog is a state, not an error: nothing has been derived yet.
func readAnchors(env *cli.Env) []Anchor {
	data, err := os.ReadFile(env.AnchorsCatalog())
	if err != nil {
		return nil
	}
	var catalog struct {
		Anchors []Anchor `json:"anchors"`
	}
	if json.Unmarshal(data, &catalog) != nil {
		return nil
	}
	return catalog.Anchors
}

func scanFragments(env *cli.Env) []Fragment {
	matches, _ := filepath.Glob(filepath.Join(env.ProvisionedDir(), "*", "*.manifest.json"))
	var out []Fragment
	for _, m := range matches {
		frag := Fragment{Manifest: m, State: "PRESENT-UNVERIFIED"}
		data, err := os.ReadFile(m)
		if err != nil {
			frag.State = "MISSING"
			out = append(out, frag)
			continue
		}
		var manifest struct {
			TargetPath string `json:"target_path"`
		}
		if json.Unmarshal(data, &manifest) != nil || manifest.TargetPath == "" {
			frag.State = "MISSING"
			out = append(out, frag)
			continue
		}
		frag.Target = manifest.TargetPath
		if _, err := os.Stat(manifest.TargetPath); err != nil {
			frag.State = "MISSING"
		}
		out = append(out, frag)
	}
	return out
}

func healthChecks(env *cli.Env, opts Options) []Check {
	var checks []Check

	// State-dir boundary: 0700 like the fabric socket dir (07 §5) — a
	// group/world grant on the dir holding the device key and token is a
	// failure, not a warning.
	if fi, err := os.Stat(env.StateDir); err != nil {
		checks = append(checks, Check{"state_dir", false, fmt.Sprintf("%s: %v", env.StateDir, err)})
	} else if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		checks = append(checks, Check{"state_dir", false,
			fmt.Sprintf("%s has mode %o; must be 0700", env.StateDir, fi.Mode().Perm())})
	} else {
		checks = append(checks, Check{"state_dir", true, env.StateDir})
	}

	socket := opts.Socket
	if socket == "" {
		if s, err := cli.SocketPath(); err == nil {
			socket = s
		}
	}
	if socket != "" {
		if fi, err := os.Lstat(socket); err != nil {
			// Not running is honest health, not sickness: doctor is run
			// before first start too.
			checks = append(checks, Check{"fabric_socket", true, "absent (daemon not running)"})
		} else if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			checks = append(checks, Check{"fabric_socket", false,
				fmt.Sprintf("%s has mode %o; 07 §5 requires 0600", socket, fi.Mode().Perm())})
		} else {
			checks = append(checks, Check{"fabric_socket", true, socket})
		}
	}

	checks = append(checks, retentionCheck(opts))
	return checks
}

// retentionCheck is §7.4's transcript-retention probe: warn when Claude
// Code's cleanupPeriodDays is shorter than the tailer's catch-up horizon.
// ponytail: horizon fixed at 30 days (the vendor default) until the tailer
// exports its real constant.
func retentionCheck(opts Options) Check {
	path := opts.ClaudeSettings
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Check{"transcript_retention", true, "unreadable home; skipped"}
		}
		path = filepath.Join(home, ".claude", "settings.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{"transcript_retention", true, "no claudecode settings readable; skipped"}
	}
	var settings struct {
		CleanupPeriodDays *int `json:"cleanupPeriodDays"`
	}
	if json.Unmarshal(data, &settings) != nil || settings.CleanupPeriodDays == nil {
		return Check{"transcript_retention", true, "cleanupPeriodDays unset (vendor default)"}
	}
	if *settings.CleanupPeriodDays < 30 {
		return Check{"transcript_retention", false,
			fmt.Sprintf("cleanupPeriodDays=%d is shorter than the tailer catch-up horizon (30d)", *settings.CleanupPeriodDays)}
	}
	return Check{"transcript_retention", true, fmt.Sprintf("cleanupPeriodDays=%d", *settings.CleanupPeriodDays)}
}

func renderHuman(w io.Writer, r *Report) {
	if len(r.Anchors) == 0 {
		fmt.Fprintln(w, "anchors       no catalog derived yet")
	}
	for _, a := range r.Anchors {
		fmt.Fprintf(w, "anchor        %s consented=%v %s\n", a.ID, a.Consented, a.State)
	}
	if len(r.Fragments) == 0 {
		fmt.Fprintln(w, "fragments     none provisioned")
	}
	for _, f := range r.Fragments {
		fmt.Fprintf(w, "fragment      %s -> %s [%s]\n", f.Manifest, f.Target, f.State)
	}
	for _, c := range r.Health {
		state := "OK"
		if !c.OK {
			state = "FAIL"
		}
		fmt.Fprintf(w, "health        %-22s %-4s %s\n", c.Name, state, c.Detail)
	}
}
