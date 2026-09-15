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
	"strings"
	"time"

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
	ID          string    `json:"id"`
	Consented   bool      `json:"consented"`
	State       string    `json:"state,omitempty"`
	ConsentedAt time.Time `json:"consented_at"`
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
	Agent string `json:"agent"`
	// Fragment names which of the agent's blocks this row is. One agent has
	// more than one: claudecode's hooks and base-URL fragments share a target
	// file and are reverted in opposite situations, so two rows that differ
	// only in state would otherwise be unattributable.
	Fragment  string            `json:"fragment,omitempty"`
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
	anchors, badVersion := readAnchors(env)
	rep.Anchors = anchors
	rep.Agents = roster()
	rep.Fragments = scanFragments(env, opts)
	rep.Health = healthChecks(env, opts)
	if badVersion != nil {
		rep.Health = append(rep.Health, *badVersion)
	}

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

// readAnchors renders <state>/anchors/catalog.json: the consent store
// go/mark1d/internal/anchors/consent.go writes, not a second doctor-side
// notion of it. The on-disk shape is consent.go:22-25's consentFile
// ({"version":1,"entries":[...]}) holding consent.go:30-41's ConsentRecord
// fields (id, ..., consented_at). The daemon's own meaning of "consented" is
// presence in Entries — LoadConsent's doc comment: "a missing file is an
// empty store ... nothing has been consented" talks about the *store*, not a
// per-record flag, and Approve/Revoke only ever add or remove whole records
// — so every entry decoded here is consented, regardless of whether its
// consented_at happens to be zero.
//
// No catalog is a state, not an error: nothing has been derived yet. A
// version this reader does not recognise must not decode as an empty list —
// that is exactly what the bug this replaces looked like (the reader
// expected key "anchors", the daemon writes "entries", so anchors always
// read as none) — so an unrecognised version is reported back as its own
// doctor finding instead of silently producing zero anchors.
func readAnchors(env *cli.Env) ([]Anchor, *Check) {
	data, err := os.ReadFile(env.AnchorsCatalog())
	if err != nil {
		return nil, nil
	}
	var catalog struct {
		Version int `json:"version"`
		Entries []struct {
			ID          string    `json:"id"`
			ConsentedAt time.Time `json:"consented_at"`
		} `json:"entries"`
	}
	if json.Unmarshal(data, &catalog) != nil {
		return nil, nil
	}
	if catalog.Version != 1 {
		return nil, &Check{"anchors_catalog_version", false,
			fmt.Sprintf("catalog.json version %d unsupported", catalog.Version)}
	}
	out := make([]Anchor, 0, len(catalog.Entries))
	for _, e := range catalog.Entries {
		out = append(out, Anchor{ID: e.ID, Consented: true, ConsentedAt: e.ConsentedAt})
	}
	return out, nil
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
	classified := map[string]bool{
		claudecode.ManifestPath(env.StateDir):        true,
		claudecode.BaseURLManifestPath(env.StateDir): true,
	}
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectClaudeCode(env, opts))
	}
	if _, err := os.Stat(claudecode.BaseURLManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectBaseURL(env, opts))
	}
	// Any OTHER manifest under <state>/provisioned/ belongs to an agent this
	// build cannot classify. Listing it beats hiding it: an unclassifiable
	// fragment is one `mark1 off` will also refuse to revert.
	matches, _ := filepath.Glob(filepath.Join(env.ProvisionedDir(), "*", "*.manifest.json"))
	for _, m := range matches {
		if classified[m] {
			continue
		}
		out = append(out, Fragment{
			Agent:    filepath.Base(filepath.Dir(m)),
			Fragment: strings.TrimSuffix(filepath.Base(m), ".manifest.json"),
			Manifest: m,
			State:    string(claudecode.StateDamaged),
			Detail:   "no adapter in this build can classify or revert this fragment",
		})
	}
	return out
}

// inspectBaseURL classifies the proxy pointer through the engine that wrote it,
// and never repairs it. §7.4's --fix re-applies MISSING and repairs
// FRAGMENT-DAMAGED, but ApplyBaseURL has no force path on purpose (baseurl.go
// §8.3(d)): repairing this fragment means re-pointing an agent's API key at a
// loopback port, and that decision belongs to `mark1 enable`'s eligibility
// check — a `Detect()==apikey` credential and a proxy that answers the guard
// probe — none of which a diagnostic re-runs. So --fix names the remedy instead
// of performing it; leaving the row bare would send a user round the loop.
func inspectBaseURL(env *cli.Env, opts Options) Fragment {
	st, err := claudecode.InspectBaseURL(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail, Lines: st.Lines,
	}
	if err != nil {
		f.State, f.Detail = string(claudecode.StateDamaged), err.Error()
	}
	if opts.Fix && (f.State == string(claudecode.StateDamaged) || f.State == string(claudecode.StateMissing)) {
		f.Detail += " (--fix does not re-point an agent at the proxy: run `mark1 enable` to re-check eligibility, or `mark1 off` to detach)"
	}
	return f
}

func inspectClaudeCode(env *cli.Env, opts Options) Fragment {
	st, err := claudecode.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
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
		_, _ = fmt.Fprintf(w, "anchor        %s consented=%v %s consented_at=%s\n",
			a.ID, a.Consented, a.State, a.ConsentedAt.Format(time.RFC3339))
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
		_, _ = fmt.Fprintf(w, "fragment      %s/%s -> %s [%s] %s\n", f.Agent, f.Fragment, f.Target, f.State, f.Detail)
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
