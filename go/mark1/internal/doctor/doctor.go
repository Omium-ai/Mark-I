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
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/apparmor"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/service"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

type Options struct {
	Fix    bool
	Socket string // test seam
	// ClaudeSettings overrides the transcript-retention probe target
	// (default ~/.claude/settings.json); a test seam.
	ClaudeSettings string
	// CodexHome overrides $CODEX_HOME/~/.codex for the regime sniff (test seam).
	CodexHome string
	// Home overrides $HOME for the gemini, opencode, copilot and cursor config sniffs (test seam).
	Home string
}

type Report struct {
	OK        bool       `json:"ok"`
	Anchors   []Anchor   `json:"anchors"`
	Looked    []Looked   `json:"anchors_looked"` // per workspace: the kinds the daemon looked for and did not derive
	Agents    []Agent    `json:"agents"`
	Fragments []Fragment `json:"fragments"`
	Health    []Check    `json:"health"`
	// Reprovisioned names each agent `--fix` brought to this release's fragment (08 §8.3 c).
	Reprovisioned []string `json:"reprovisioned,omitempty"`
	version       string
	StopGate      cli.StopGate `json:"stop_gate"`
	Exploration   cli.StopGate `json:"exploration"`
}

// Anchor is one row of the FR-CLI-004 join between what mark1d can run
// (candidates.json, per workspace) and what the user consented to
// (catalog.json). State is empty for a consented, derivation-stable entry;
// otherwise "pending" (never consented), "drifted" (consented under a
// different exec_hash — disabled until re-consented, 04 §2.2) or "stale"
// (consented, no longer derivable anywhere).
type Anchor struct {
	ID          string    `json:"id"`
	Workspace   string    `json:"workspace,omitempty"`
	Consented   bool      `json:"consented"`
	State       string    `json:"state,omitempty"`
	ConsentedAt time.Time `json:"consented_at"`
}

// Looked is one workspace's miss list, straight from candidates.json.
type Looked struct {
	Workspace string           `json:"workspace"`
	Misses    []cli.AnchorMiss `json:"misses"`
}

// Agent is one of 08 §5's seven slots. Printing the unimplemented ones is the
// point: a cursor or codex user should learn Mark 1 does nothing for their
// agent from the tool, not from silence followed by an empty receipt.
type Agent struct {
	Name        string `json:"name"`
	Implemented bool   `json:"implemented"`
	Mechanism   string `json:"mechanism,omitempty"`
	Phase       string `json:"phase,omitempty"`
	// Live sniff for every built adapter but claudecode (whose rides the agent_version health row); HooksTrusted is codex's yes|no once provisioned.
	Version      string `json:"version,omitempty"`
	Regime       string `json:"regime,omitempty"`
	HooksTrusted string `json:"hooks_trusted,omitempty"`
	Note         string `json:"note,omitempty"`
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
	// ProvisionedBy is the Mark 1 release whose capture fragment is on disk (provision.Stamp); empty for pointer fragments and unstamped installs.
	ProvisionedBy string `json:"provisioned_by,omitempty"`
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
	rep := Report{OK: true, version: env.Version}
	anchors, looked, anchorChecks := readAnchors(env)
	rep.Anchors, rep.Looked = anchors, looked
	rep.Agents = roster(env, opts)
	if opts.Fix {
		for _, o := range provision.Reconcile(env.StateDir, env.Version) {
			if o.Action == "upgraded" {
				rep.Reprovisioned = append(rep.Reprovisioned, o.Agent)
			}
		}
	}
	rep.Fragments = scanFragments(env, opts)
	rep.Health = append(healthChecks(env, opts), anchorChecks...)
	rep.StopGate, rep.Exploration = env.ReadStopGate(), env.ReadExploration()

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
//
// The store alone says what was consented; candidates.json (the daemon's
// current derivation, anchors/candidates.go) says what that consent covers
// TODAY. With it, every candidate is a row carrying its state; without it
// the rows are the store's and the anchor_candidates finding says the daemon
// has not published — never an empty list that reads as "nothing to consent".
func readAnchors(env *cli.Env) ([]Anchor, []Looked, []Check) {
	var checks []Check
	var looked []Looked
	store := map[string]string{} // id → consented exec_hash
	storeAt := map[string]time.Time{}
	if data, err := os.ReadFile(env.AnchorsCatalog()); err == nil {
		var catalog struct {
			Version int `json:"version"`
			Entries []struct {
				ID          string    `json:"id"`
				ExecHash    string    `json:"exec_hash"`
				ConsentedAt time.Time `json:"consented_at"`
			} `json:"entries"`
		}
		switch {
		case json.Unmarshal(data, &catalog) != nil:
		case catalog.Version != 1:
			checks = append(checks, Check{"anchors_catalog_version", false,
				fmt.Sprintf("catalog.json version %d unsupported", catalog.Version)})
		default:
			for _, e := range catalog.Entries {
				store[e.ID], storeAt[e.ID] = e.ExecHash, e.ConsentedAt
			}
		}
	}

	var out []Anchor
	seen := map[string]bool{}
	cands, err := env.LoadAnchorCandidates()
	switch {
	case errors.Is(err, cli.ErrNoCandidates):
		checks = append(checks, Check{"anchor_candidates", true, "daemon has not published candidates (anchors/candidates.json absent — start mark1d, then `mark1 enable`)"})
	case err != nil:
		checks = append(checks, Check{"anchor_candidates", false, err.Error()})
	case len(cands.Workspaces) == 0:
		checks = append(checks, Check{"anchor_candidates", true, "no workspace enabled"})
	default:
		for _, ws := range cands.Workspaces {
			if len(ws.Looked) > 0 {
				looked = append(looked, Looked{Workspace: ws.Path, Misses: ws.Looked})
			}
			for _, c := range ws.Anchors {
				seen[c.ID] = true
				row := Anchor{ID: c.ID, Workspace: ws.Path, Consented: c.Consented, ConsentedAt: c.ConsentedAt}
				switch {
				case c.Consented:
				case store[c.ID] != "":
					row.State = "drifted"
				default:
					row.State = "pending"
				}
				out = append(out, row)
			}
		}
		checks = append(checks, Check{"anchor_candidates", true, fmt.Sprintf("%d workspace(s) published", len(cands.Workspaces))})
	}
	for _, id := range slices.Sorted(maps.Keys(store)) {
		if seen[id] {
			continue
		}
		row := Anchor{ID: id, Consented: true, ConsentedAt: storeAt[id]}
		if err == nil && len(cands.Workspaces) > 0 {
			row.State = "stale"
		}
		out = append(out, row)
	}
	return out, looked, checks
}

func roster(env *cli.Env, opts Options) []Agent {
	out := make([]Agent, 0, len(adapters.Roster))
	for _, s := range adapters.Roster {
		a := Agent{Name: s.Name, Implemented: s.Implemented, Mechanism: s.Mechanism, Phase: s.Phase}
		switch s.Name {
		case "codex":
			codexAgent(env, opts, &a)
		case "gemini":
			geminiAgent(env, opts, &a)
		case "opencode":
			opencodeAgent(env, opts, &a)
		case "copilot":
			copilotAgent(env, opts, &a)
		case "cursor":
			cursorAgent(env, opts, &a)
		}
		out = append(out, a)
	}
	return out
}

func regimeWord(r adapters.Regime) string {
	if r == adapters.RegimeAPIKey {
		return "apikey"
	}
	return "subscription"
}

func lines[L codex.Line | gemini.Line | cursor.Line](in []L) []claudecode.Line {
	out := make([]claudecode.Line, 0, len(in))
	for _, l := range in {
		out = append(out, claudecode.Line(l))
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
		codex.ManifestPath(env.StateDir):             true,
		gemini.ManifestPath(env.StateDir):            true,
		opencode.ManifestPath(env.StateDir):          true,
		copilot.ManifestPath(env.StateDir):           true,
		copilot.EnvManifestPath(env.StateDir):        true,
		cursor.ManifestPath(env.StateDir):            true,
	}
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectClaudeCode(env, opts))
	}
	if _, err := os.Stat(claudecode.BaseURLManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectBaseURL(env, opts))
	}
	if _, err := os.Stat(codex.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectCodex(env, opts))
	}
	if _, err := os.Stat(gemini.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectGemini(env, opts))
	}
	if _, err := os.Stat(opencode.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectOpenCode(env, opts))
	}
	if _, err := os.Stat(copilot.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectCopilot(env, opts))
	}
	if _, err := os.Stat(copilot.EnvManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectCopilotEnv(env, opts))
	}
	if _, err := os.Stat(cursor.ManifestPath(env.StateDir)); err == nil {
		out = append(out, inspectCursor(env, opts))
	}
	capture := map[string]string{
		"claudecode": claudecode.ManifestPath(env.StateDir), "codex": codex.ManifestPath(env.StateDir),
		"gemini": gemini.ManifestPath(env.StateDir), "opencode": opencode.ManifestPath(env.StateDir),
		"copilot": copilot.ManifestPath(env.StateDir), "cursor": cursor.ManifestPath(env.StateDir),
	}
	for i, f := range out {
		if f.Manifest == capture[f.Agent] {
			if st, err := provision.ReadStamp(env.StateDir, f.Agent); err == nil {
				out[i].ProvisionedBy = st.Version
			}
		}
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
	if err := provision.WriteStamp(env.StateDir, f.Agent, env.Version, res.Checksum); err != nil {
		f.Detail = "release stamp not written: " + err.Error()
	}
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

	checks = append(checks, retentionCheck(opts), agentVersionCheck(), rmRuntimeCheck(env.StateDir), taskDiffCheck(env.StateDir))
	if runtime.GOOS == "linux" {
		checks = append(checks, apparmorCheck())
	}
	return checks
}

// apparmorCheck is the apparmor_userns row: on a kernel that restricts unprivileged user namespaces the anchor sandbox needs the omium-mark1d profile, and doctor names the root command that loads it.
func apparmorCheck() Check {
	d, err := daemonPath("")
	if err != nil {
		return Check{"apparmor_userns", true, "mark1d not found beside this executable or on PATH"}
	}
	self, _ := os.Executable()
	ok, detail := apparmor.Check(d, self)
	return Check{"apparmor_userns", ok, detail}
}

// daemonPath is the mark1d the apparmor row inspects; a test seam like apparmor's host paths.
var daemonPath = service.DaemonPath

// taskDiffCheck reads mark1d's <state>/anchors/diff_status.json (go/mark1d/internal/anchors DiffState): a worktree whose diff cannot be read starves the reward model, the diff judge and contributions, so that fails; a read that answered outside the sandbox (10 §7.5 fallback) passes and says why.
func taskDiffCheck(stateDir string) Check {
	var f struct {
		Worktrees map[string]struct {
			Via     string `json:"via"`
			Abstain string `json:"abstain"`
			Detail  string `json:"detail"`
		} `json:"worktrees"`
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "anchors", "diff_status.json")) //nolint:gosec // G304: under the state dir
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Worktrees) == 0 {
		return Check{"task_diff", true, "no task diff read yet"}
	}
	ok, lines := true, []string{}
	for _, wt := range slices.Sorted(maps.Keys(f.Worktrees)) {
		w := f.Worktrees[wt]
		switch {
		case w.Abstain == "no_git" || w.Abstain == "not_a_repository" || w.Abstain == "git_failed" || w.Abstain == "unsafe_git_config" || w.Abstain == "unsafe_git_dir":
			ok = false
			lines = append(lines, wt+": "+w.Abstain+" "+w.Detail)
		case w.Via == "direct":
			lines = append(lines, wt+": read outside the sandbox ("+w.Detail+")")
		case w.Abstain != "":
			lines = append(lines, wt+": "+w.Abstain)
		default:
			lines = append(lines, wt+": ok")
		}
	}
	return Check{"task_diff", ok, strings.Join(lines, "; ")}
}

// rmRuntimeCheck reads mark1d's <state>/rm/status.json (go/mark1d/internal/rm Status): only a crash-looped runtime, a failed model fetch or a refused execution hash is a failure.
func rmRuntimeCheck(stateDir string) Check {
	var s struct {
		State   string `json:"state"`
		ModelID string `json:"model_id"`
		Detail  string `json:"detail"`
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "rm", "status.json")) //nolint:gosec // G304: under the state dir
	if err != nil || json.Unmarshal(b, &s) != nil {
		return Check{"rm_runtime", true, "not started (reward model off, or the daemon is not running)"}
	}
	d := s.State
	if s.ModelID != "" {
		d += " " + s.ModelID
	}
	return Check{"rm_runtime", s.State != "failed" && s.State != "download_failed" && s.State != "refused", d + ": " + s.Detail}
}

// agentVersionCheck is D-EE's admission as doctor sees it: pinned,
// compatible_unpinned (captured, unverified, receipted as a bypass window) or
// incompatible (capture inert). Informational — a developer's `claude` is
// whatever npm installed this week, and doctor's exit code is CI's.
func agentVersionCheck() Check {
	cc := &claudecode.Adapter{}
	d, _ := cc.Detect()
	if !d.Installed {
		return Check{"agent_version", true, "claude not on PATH; transcript capture inert"}
	}
	c, why := cc.Compatibility(d.Version)
	detail := fmt.Sprintf("claude %s %s", d.Version, c)
	switch c {
	case claudecode.CompatibleUnpinned:
		detail += " — structural probe passed, capture runs UNVERIFIED under an unsupported_agent_version bypass receipt; record a corpus: `mark1 corpus record`"
	case claudecode.Incompatible:
		detail += fmt.Sprintf(" — transcript capture DISABLED: %v", why)
	}
	return Check{"agent_version", true, detail}
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

// compatNote words the daemon's own admission verdict (adapters.Compat) for the roster row: the daemon tails a CompatibleUnpinned version under a receipted window, so "inert" is said only when it really is.
func compatNote(c adapters.Compat, err error, surface string) string {
	switch c {
	case adapters.Pinned:
		return ""
	case adapters.CompatibleUnpinned:
		return "no pinned fixture for this version; its artifact shape passed the probe, so " + surface + " capture proceeds under a receipted unsupported_agent_version window"
	case adapters.Unprobed:
		return "no pinned fixture for this version and nothing of it on disk yet; " + surface + " capture starts once a session exists to probe"
	default:
		why := ""
		if err != nil {
			why = ": " + err.Error()
		}
		return "no pinned fixture for this version and its artifact shape failed the probe" + why + "; " + surface + " capture inert (08 §5 rule 2)"
	}
}

func renderHuman(w io.Writer, r *Report) {
	if len(r.Anchors) == 0 {
		// Which kind of nothing: unpublished, no workspace, or nothing
		// derivable — the anchor_candidates finding already says.
		why := "no catalog derived yet"
		for _, c := range r.Health {
			if c.Name == "anchor_candidates" {
				why = c.Detail
			}
		}
		_, _ = fmt.Fprintln(w, "anchors      ", why)
	}
	for _, a := range r.Anchors {
		_, _ = fmt.Fprintf(w, "anchor        %s consented=%v %s consented_at=%s %s\n",
			a.ID, a.Consented, a.State, a.ConsentedAt.Format(time.RFC3339), a.Workspace)
	}
	for _, l := range r.Looked {
		for _, m := range l.Misses {
			_, _ = fmt.Fprintf(w, "looked for    %-12s %s  %s\n", m.Tool, m.Why, l.Workspace)
		}
	}
	for _, a := range r.Agents {
		if !a.Implemented {
			_, _ = fmt.Fprintf(w, "agent         %-12s not implemented (phase %s)\n", a.Name, a.Phase)
			continue
		}
		line := "mechanism " + a.Mechanism
		if a.Version != "" {
			line += " version " + a.Version
		}
		if a.Regime != "" {
			line += " regime " + a.Regime
		}
		if a.HooksTrusted != "" {
			line += " hooks_trusted: " + a.HooksTrusted
		}
		if a.Note != "" {
			line += " (" + a.Note + ")"
		}
		_, _ = fmt.Fprintf(w, "agent         %-12s %s\n", a.Name, line)
	}
	for _, a := range r.Reprovisioned {
		_, _ = fmt.Fprintf(w, "reprovisioned %s to %s\n", a, r.version)
	}
	if len(r.Fragments) == 0 {
		_, _ = fmt.Fprintln(w, "fragments     none provisioned")
	}
	for _, f := range r.Fragments {
		_, _ = fmt.Fprintf(w, "fragment      %s/%s -> %s [%s] %s\n", f.Agent, f.Fragment, f.Target, f.State, f.Detail)
		if f.ProvisionedBy != "" {
			stale := ""
			if f.ProvisionedBy != r.version {
				stale = " (this is " + r.version + ": mark1d re-provisions at its next start, or run `mark1 doctor --fix`)"
			}
			_, _ = fmt.Fprintf(w, "  provisioned by %s%s\n", f.ProvisionedBy, stale)
		}
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
	_, _ = fmt.Fprintf(w, "stop gate     %s\n", r.StopGate)
	_, _ = fmt.Fprintf(w, "exploration   %s\n", r.Exploration)
}
