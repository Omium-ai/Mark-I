// Package doctor is 08 §7.4: the consented anchor catalog, the fenced-config
// state of every provisioned fragment, and environment health — CI-friendly
// (exit 1 on any failure, 0 all green, 3 not enrolled). Fragment
// classification and repair are the §8 engine itself (go/mark1d/adapters), not
// a second implementation: a doctor that re-derived what a fence looks like
// would drift from the apply that wrote it, and both sides' tests would stay
// green while they disagreed.
package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
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
	Agents    []Agent    `json:"agents"`
	Fragments []Fragment `json:"fragments"`
	Health    []Check    `json:"health"`
}

type Anchor struct {
	ID        string `json:"id"`
	Consented bool   `json:"consented"`
	State     string `json:"state,omitempty"`
}

// Agent is one of 08 §5's seven slots. Printing the unimplemented ones is the
// point: a cursor or codex user should learn Mark 1 does nothing for their
// agent from the tool, not from silence followed by an empty receipt.
type Agent struct {
	Name        string `json:"name"`
	Implemented bool   `json:"implemented"`
	Mechanism   string `json:"mechanism,omitempty"`
	Phase       string `json:"phase,omitempty"`
}

// Fragment is §7.4's row, in §7.4's own vocabulary: OK | USER-EDITED |
// FRAGMENT-DAMAGED | MISSING. Lines carries every provisioned line as it sits
// on disk, so the block we wrote is byte-for-byte diffable from the report
// itself (FR-AGENT-003) rather than only from the file.
type Fragment struct {
	Agent     string            `json:"agent"`
	Mechanism string            `json:"mechanism,omitempty"`
	Manifest  string            `json:"manifest"`
	Target    string            `json:"target"`
	State     string            `json:"state"`
	Detail    string            `json:"detail,omitempty"`
	Lines     []claudecode.Line `json:"lines,omitempty"`
	Fixed     bool              `json:"fixed,omitempty"`
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
	rep := Report{OK: true}
	rep.Anchors = readAnchors(env)
	rep.Agents = roster()
	rep.Fragments = scanFragments(env, opts)
	rep.Health = healthChecks(env, opts)

	for _, f := range rep.Fragments {
		if f.State != string(claudecode.StateOK) && f.State != string(claudecode.StateUserEdited) {
			// USER-EDITED is healthy: the fragment is intact and the user
			// changed their own bytes elsewhere, which is theirs to do.
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

func roster() []Agent {
	out := make([]Agent, 0, len(adapters.Roster))
	for _, s := range adapters.Roster {
		out = append(out, Agent{s.Name, s.Implemented, s.Mechanism, s.Phase})
	}
	return out
}

// scanFragments classifies every provisioned fragment through the §8 engine
// that wrote it. A fragment with no manifest was never provisioned and gets no
// row — silence there is accurate, whereas a MISSING row would fail doctor for
// every user who has not run `mark1 enable` yet.
func scanFragments(env *cli.Env, opts Options) []Fragment {
	var out []Fragment
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectClaudeCode(env, opts))
	}
	// Any OTHER manifest under <state>/provisioned/ belongs to an agent this
	// build cannot classify. Listing it beats hiding it: an unclassifiable
	// fragment is one `mark1 off` will also refuse to revert.
	matches, _ := filepath.Glob(filepath.Join(env.ProvisionedDir(), "*", "*.manifest.json"))
	for _, m := range matches {
		if m == claudecode.ManifestPath(env.StateDir) {
			continue
		}
		out = append(out, Fragment{
			Agent: filepath.Base(filepath.Dir(m)), Manifest: m,
			State:  string(claudecode.StateDamaged),
			Detail: "no adapter in this build can classify or revert this fragment",
		})
	}
	return out
}

func inspectClaudeCode(env *cli.Env, opts Options) Fragment {
	st, err := claudecode.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail, Lines: st.Lines,
	}
	if err != nil {
		f.State, f.Detail = string(claudecode.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" {
		return f
	}
	// §7.4: --fix re-applies MISSING and repairs FRAGMENT-DAMAGED, and touches
	// nothing else. OK and USER-EDITED are left strictly alone — rewriting a
	// healthy fragment because the user moved an unrelated key is the silent
	// overwrite the whole design refuses.
	if st.State != claudecode.StateMissing && st.State != claudecode.StateDamaged {
		return f
	}
	res, ferr := claudecode.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if after, aerr := claudecode.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail, f.Lines = string(after.State), after.Detail, after.Lines
	}
	return f
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
		_, _ = fmt.Fprintln(w, "anchors       no catalog derived yet")
	}
	for _, a := range r.Anchors {
		_, _ = fmt.Fprintf(w, "anchor        %s consented=%v %s\n", a.ID, a.Consented, a.State)
	}
	for _, a := range r.Agents {
		if a.Implemented {
			_, _ = fmt.Fprintf(w, "agent         %-12s mechanism %s\n", a.Name, a.Mechanism)
		} else {
			_, _ = fmt.Fprintf(w, "agent         %-12s not implemented (phase %s)\n", a.Name, a.Phase)
		}
	}
	if len(r.Fragments) == 0 {
		_, _ = fmt.Fprintln(w, "fragments     none provisioned")
	}
	for _, f := range r.Fragments {
		_, _ = fmt.Fprintf(w, "fragment      %s -> %s [%s] %s\n", f.Agent, f.Target, f.State, f.Detail)
		// Every provisioned line, one line each: a user must be able to see
		// exactly what we put in their file without opening it, and nine
		// pretty-printed blocks is a thing nobody reads. The --json Lines keep
		// the on-disk bytes verbatim, so the byte-for-byte diff (FR-AGENT-003)
		// is still available where a diff tool can use it.
		for _, l := range f.Lines {
			var buf bytes.Buffer
			if json.Compact(&buf, []byte(l.Value)) != nil {
				buf.Reset()
				buf.WriteString(l.Value)
			}
			_, _ = fmt.Fprintf(w, "  %-24s %s\n", l.Pointer, buf.String())
		}
	}
	for _, c := range r.Health {
		state := "OK"
		if !c.OK {
			state = "FAIL"
		}
		_, _ = fmt.Fprintf(w, "health        %-22s %-4s %s\n", c.Name, state, c.Detail)
	}
}
