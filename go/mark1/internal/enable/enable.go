// Package enable implements 08 §7.2: add the canonicalized path to the
// workspace allow-list the tailers consult (capture reads NOTHING outside
// enrolled roots — 04 §0.3 invariant 3), idempotently.
package enable

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

type Options struct {
	Path string
	// Home overrides $HOME for agent-config resolution (test seam). Empty is
	// the real user's home.
	Home string
	// Anchors is --anchors: consent non-interactively to exactly these catalog
	// IDs (08 §7.2). NoAnchors is --no-anchors: offer nothing.
	Anchors   []string
	NoAnchors bool
	// StopGate is --stop-gate: opt in, at a terminal only, to fail-closed
	// blocking (FR-POLICY-006). NoStopGate is --no-stop-gate: remove the opt-in.
	StopGate   bool
	NoStopGate bool
	// Profile is the ADR-0013 host profile of the session this enable acts for;
	// nil is provision.DefaultProfile (the daemon-down CLI has no session). A
	// declared host that owns the config surface is refused per adapter
	// with M1E-7105 (ADR-0014 §4) and rendered as NOT PROVISIONED.
	Profile *provision.Profile
	// Exploration is --exploration: D-EF's local half of ε>0 consent;
	// NoExploration is --no-exploration.
	Exploration   bool
	NoExploration bool
	// Stdin is where the consent prompt reads its answer; TTY says whether
	// that is a terminal. cmd/main.go wires os.Stdin and the char-device
	// check; tests simulate both. Without a TTY nothing is ever consented.
	Stdin io.Reader
	TTY   bool
	// Socket overrides the fabric socket the "is mark1d running" dial uses
	// (test seam) — the dial gates how long enable waits for the daemon to
	// publish candidates for a freshly enabled root.
	Socket string
}

// Result is §7.2's --json shape, minus the fields whose producers have not
// landed (the coverage receipt seq is minted by the receipt chain) — absent,
// never faked.
type Result struct {
	OK                bool     `json:"ok"`
	Workspace         string   `json:"workspace"`
	Changed           bool     `json:"changed"`
	AgentsProvisioned []string `json:"agents_provisioned"`
	// AnchorsConsented is §7.2's field: every candidate for this workspace
	// the consent store covers after this run, under its current exec_hash.
	AnchorsConsented []string `json:"anchors_consented"`
	// AnchorsPending is additive: candidates this run did NOT consent to.
	// Under --json or without a TTY that is all of them — a script cannot
	// consent by accident; it names IDs with --anchors or a human answers at a
	// terminal. AnchorsNote says why nothing was offered when nothing was.
	AnchorsPending []string `json:"anchors_pending"`
	AnchorsNote    string   `json:"anchors_note,omitempty"`
	// StopGate is the opt-in posture after this run; StopGatePending says
	// --stop-gate was asked and nothing was written (no terminal, or declined).
	StopGate        cli.StopGate `json:"stop_gate"`
	StopGatePending bool         `json:"stop_gate_pending,omitempty"`
	StopGateNote    string       `json:"stop_gate_note,omitempty"`
	Exploration     cli.StopGate `json:"exploration"`
	ExplorationNote string       `json:"exploration_note,omitempty"`
	// AgentsRefused is additive to §7.2's shape and deliberately not an error:
	// M1E-7101/7102 are refusals by design, and §7.2's exit table names no
	// provisioning-refusal class. Failing the enable would punish a user who
	// simply has no ~/.claude/settings.json yet; hiding it would leave them
	// enrolled with nothing capturing. So it is reported here and again in
	// `mark1 doctor`, which is the doc-named surface for both codes.
	AgentsRefused []Refusal `json:"agents_refused,omitempty"`
	// ProxyPointer is additive: it always states what happened to the base-URL
	// fragment, because "we did not point this agent at the proxy" is a legal
	// boundary (CON-001) and a boundary that is only observable by its silence
	// is one nobody can audit. "not-eligible" is the correct, common answer.
	ProxyPointer string `json:"proxy_pointer"`
	// CopilotPointer mirrors ProxyPointer for 08 §5.5's BYOK env-var pointer:
	// "provisioned" | "not-eligible" | an M1E code. CopilotSourceLine is set
	// only on "provisioned" — the one line `mark1 enable` prints and never
	// writes into a profile itself (CON-003's spirit).
	CopilotPointer    string `json:"copilot_pointer,omitempty"`
	CopilotSourceLine string `json:"copilot_source_line,omitempty"`
}

// Refusal is one agent whose fragment could not be applied, with the M1E code
// the user can look up.
type Refusal = provision.Refusal

func Run(env *cli.Env, opts Options) error {
	if _, err := env.LoadEnrollment(); err != nil {
		if errors.Is(err, cli.ErrNotEnrolled) {
			return cli.Failf(cli.ExitNotEnrolled, "M1E-1002", "not enrolled — run `mark1 enroll` first")
		}
		return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
	}

	fi, err := os.Stat(opts.Path)
	if err != nil {
		// §7.2 exit 2: path missing is a usage error, not a runtime one.
		return cli.Failf(cli.ExitUsage, "", "workspace path %s: %v", opts.Path, err)
	}
	if !fi.IsDir() {
		return cli.Failf(cli.ExitUsage, "", "workspace path %s is not a directory", opts.Path)
	}
	root, err := cli.CanonicalPath(opts.Path)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "canonicalizing %s: %v", opts.Path, err)
	}

	if optedOut(filepath.Join(root, ".mark1ignore")) {
		// §7.2 exit 4: a root .mark1ignore ignoring everything opts the repo
		// out — refused by design, no allow-list write.
		return cli.Failf(cli.ExitRefused, "", "%s/.mark1ignore opts this repository out of Mark 1", root)
	}

	ws, err := env.LoadWorkspaces()
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "reading allow-list: %v", err)
	}
	res := Result{OK: true, Workspace: root, AgentsProvisioned: []string{}}
	added := true
	for _, entry := range ws.Workspaces {
		if entry.Path == root {
			added = false
			break
		}
	}

	// §7.2: "re-running reconciles fragments/consents". This runs whether or
	// not the allow-list changed — a user who ran `mark1 off` and then
	// `mark1 enable` again must get their hooks back, and an early return on
	// an already-listed workspace would leave them permanently unprovisioned.
	// It runs BEFORE the root lands in the allow-list so the consent record
	// below can name what was provisioned, and so a provisioning I/O failure
	// (exit 1) leaves nothing half-enabled for the re-run to skip.
	pr, err := provision.Apply(provision.Options{Home: opts.Home, StateDir: env.StateDir, Profile: opts.Profile})
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	wrote := pr.Changed
	res.AgentsProvisioned, res.AgentsRefused = pr.Provisioned, pr.Refused
	res.ProxyPointer, res.CopilotPointer, res.CopilotSourceLine = pr.ProxyPointer, pr.CopilotPointer, pr.CopilotSourceLine
	res.Changed = added || wrote

	if added {
		now := time.Now().UTC()
		ws.Workspaces = append(ws.Workspaces, cli.WorkspaceEntry{Path: root, EnabledAt: now})
		if err := env.SaveWorkspaces(ws); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "writing allow-list: %v", err)
		}
		if err := env.AppendCoverageTransition(map[string]any{
			"ts": now.Format(time.RFC3339), "kind": "enable", "workspace": root,
		}); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "journaling coverage transition: %v", err)
		}
		// FR-CLI-002's consent record: who (the OS user running this command —
		// the consent authority, 03 §2), to what, when. Once per root: a re-run
		// that only reconciles fragments changes nothing about who consented.
		c := cli.Consent{TS: now.Format(time.RFC3339), Workspace: root, AgentsProvisioned: res.AgentsProvisioned}
		if u, err := user.Current(); err == nil {
			c.User, c.UID = u.Username, u.Uid
		}
		if err := env.AppendConsent(c); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "recording consent: %v", err)
		}
	}

	// The anchor consent walk (§7.2, 04 §2.2 "Consent catalog lifecycle"),
	// after the allow-list write: mark1d derives the catalog for a root only
	// once that file names it, and publishes the candidates this reads.
	if err := consentAnchors(env, opts, root, &res); err != nil {
		return err
	}
	if err := stopGate(env, opts, root, &res); err != nil {
		return err
	}
	if err := exploration(env, opts, root, &res); err != nil {
		return err
	}

	return env.Emit(res, func(w io.Writer) {
		if added {
			_, _ = fmt.Fprintf(w, "enabled %s\n", root)
		}
		for _, id := range res.AnchorsConsented {
			_, _ = fmt.Fprintf(w, "anchor        %s consented\n", id)
		}
		for _, id := range res.AnchorsPending {
			_, _ = fmt.Fprintf(w, "anchor        %s NOT consented (will not run)\n", id)
		}
		if res.AnchorsNote != "" {
			_, _ = fmt.Fprintf(w, "anchors       %s\n", res.AnchorsNote)
		}
		_, _ = fmt.Fprintf(w, "stop gate     %s\n", res.StopGate)
		if res.StopGateNote != "" {
			_, _ = fmt.Fprintf(w, "stop gate     %s\n", res.StopGateNote)
		}
		_, _ = fmt.Fprintf(w, "exploration   %s\n", res.Exploration)
		if res.ExplorationNote != "" {
			_, _ = fmt.Fprintf(w, "exploration   %s\n", res.ExplorationNote)
		}
		if wrote {
			for _, a := range res.AgentsProvisioned {
				_, _ = fmt.Fprintf(w, "provisioned   %s\n", a)
			}
		}
		for _, a := range res.AgentsProvisioned {
			switch a {
			case "codex":
				_, _ = fmt.Fprintln(w, "note          codex hooks run only after `codex` itself trusts them: run codex once and accept the hooks review (`mark1 doctor` shows hooks_trusted)")
			case "opencode":
				_, _ = fmt.Fprintln(w, "note          the opencode plugin loads at startup: restart any running opencode")
			}
		}
		if res.ProxyPointer == "provisioned" {
			_, _ = fmt.Fprintln(w, "provisioned   claudecode base URL -> mark1-proxy (API-key credential)")
		}
		switch res.CopilotPointer {
		case "provisioned":
			_, _ = fmt.Fprintln(w, "provisioned   copilot BYOK base URL -> mark1-proxy (not sourced automatically)")
			_, _ = fmt.Fprintf(w, "note          add this line to your shell profile: %s\n", res.CopilotSourceLine)
			_, _ = fmt.Fprintln(w, "note          "+copilotGuardGapNote)
		case "not-eligible":
			_, _ = fmt.Fprintln(w, "note          copilot BYOK pointer not provisioned (subscription regime, no BYOK key, or no proxy listening)")
		}
		for _, r := range res.AgentsRefused {
			_, _ = fmt.Fprintf(w, "NOT PROVISIONED %s: %s %s\n", r.Agent, r.Code, r.Detail)
		}
	})
}

// candidatesWait bounds how long enable waits for mark1d to derive and publish
// candidates for a root it just enabled: the daemon reacts to workspaces.json
// by fsnotify and runs one sandboxed `--version` per configured tool.
const candidatesWait = 5 * time.Second

// consentAnchors fills the three anchors_* fields and appends one
// approvals.jsonl line per consent given. Consent names the exact exec_hash
// the daemon published, so a candidate whose derivation changes afterwards is
// a different candidate (04 §2.2 re-consent) and this walk is re-run by the
// next `mark1 enable`. Nothing here is fatal to the enable itself except an
// explicit --anchors that cannot be honored: the workspace IS enabled; consent
// is a second act with its own surface (`mark1 doctor` shows the state).
func consentAnchors(env *cli.Env, opts Options, root string, res *Result) error {
	res.AnchorsConsented, res.AnchorsPending = []string{}, []string{}
	if opts.NoAnchors {
		res.AnchorsNote = "skipped (--no-anchors); re-run `mark1 enable` to consent"
		return nil
	}
	cands, err := candidatesFor(env, opts, root)
	if err != nil {
		if len(opts.Anchors) > 0 {
			return cli.Failf(cli.ExitRuntime, "", "--anchors: %v", err)
		}
		res.AnchorsNote = err.Error()
		return nil
	}
	if len(cands) == 0 {
		res.AnchorsNote = "none derivable here (no supported tool config with its binary on mark1d's PATH)"
		return nil
	}
	byID := map[string]cli.AnchorCandidate{}
	for _, c := range cands {
		byID[c.ID] = c
		if c.Consented {
			res.AnchorsConsented = append(res.AnchorsConsented, c.ID)
		}
	}
	approve := func(c cli.AnchorCandidate) error {
		a := cli.AnchorApproval{TS: time.Now().UTC().Format(time.RFC3339), Workspace: root, ID: c.ID, ExecHash: c.ExecHash}
		if u, err := user.Current(); err == nil {
			a.User, a.UID = u.Username, u.Uid
		}
		if err := env.AppendAnchorApproval(a); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "recording anchor consent: %v", err)
		}
		res.AnchorsConsented = append(res.AnchorsConsented, c.ID)
		return nil
	}

	// --anchors <id,…>: non-interactive, exactly the named IDs (§7.2). An ID
	// that is not a current candidate is a usage error, not a silent skip.
	if len(opts.Anchors) > 0 {
		for _, id := range opts.Anchors {
			c, ok := byID[id]
			if !ok {
				return cli.Failf(cli.ExitUsage, "", "--anchors %s: not a derived candidate for %s (see `mark1 doctor`)", id, root)
			}
			if c.Consented {
				continue
			}
			if err := approve(c); err != nil {
				return err
			}
		}
		for _, c := range cands {
			if !slices.Contains(res.AnchorsConsented, c.ID) {
				res.AnchorsPending = append(res.AnchorsPending, c.ID)
			}
		}
		return nil
	}

	interactive := opts.TTY && !env.JSON && !env.Quiet
	if !interactive {
		for _, c := range cands {
			if !c.Consented {
				res.AnchorsPending = append(res.AnchorsPending, c.ID)
			}
		}
		if len(res.AnchorsPending) > 0 {
			res.AnchorsNote = "not consented: no terminal (or --json/--quiet); run `mark1 enable` at a terminal or pass --anchors <id,…>"
		}
		return nil
	}
	in := bufio.NewReader(opts.Stdin)
	eof := false // EOF mid-walk: every remaining candidate is a "no"
	for _, c := range cands {
		if c.Consented {
			continue
		}
		answer := ""
		if !eof {
			printCandidate(env.Stdout, c)
			_, _ = fmt.Fprint(env.Stdout, "  consent? [y/N] ")
			line, rerr := in.ReadString('\n')
			eof = rerr != nil
			answer = strings.ToLower(strings.TrimSpace(line))
		}
		if answer == "y" || answer == "yes" {
			if err := approve(c); err != nil {
				return err
			}
			continue
		}
		res.AnchorsPending = append(res.AnchorsPending, c.ID)
	}
	return nil
}

// printCandidate is the consent prompt's body: what will run, as which binary,
// under which sandbox terms — the deal the user is being asked to make.
func printCandidate(w io.Writer, c cli.AnchorCandidate) {
	_, _ = fmt.Fprintf(w, "anchor        %s (%s, %s) %s\n", c.ID, c.Class, c.SideEffect, c.ToolVersion)
	_, _ = fmt.Fprintf(w, "  runs        %s\n", strings.Join(c.Argv, " "))
	_, _ = fmt.Fprintf(w, "  binary      %s blake3:%.12s\n", c.BinaryPath, c.BinaryHash)
	_, _ = fmt.Fprintln(w, "  sandboxed: no network, writes confined to the worktree; re-consent is asked if the binary, version or argv changes")
}

// stopGate is FR-POLICY-006's CLI half: the opt-in that lets mark1d BLOCK is a
// human act at a terminal, under the same TTY-only rule as anchor consent.
func stopGate(env *cli.Env, opts Options, root string, res *Result) error {
	if opts.NoStopGate {
		was := env.ReadOptIn().StopGate
		name, _ := osUser()
		if err := env.UpdateOptIn(time.Now().UTC().Format(time.RFC3339), name, func(a *cli.OptIn) { a.StopGate = false }); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "removing stop-gate opt-in: %v", err)
		}
		res.StopGate = env.ReadStopGate()
		if was {
			res.StopGateNote = "opt-in removed (--no-stop-gate)"
		}
		return nil
	}
	res.StopGate = env.ReadStopGate()
	if res.StopGate.State == "opted_in" {
		return nil
	}
	if !opts.StopGate {
		res.StopGateNote = "blocking disarmed; `mark1 off` removes the opt-in and enable never restores it — pass --stop-gate at a terminal"
		return nil
	}
	res.StopGatePending = true
	if !opts.TTY || env.JSON || env.Quiet {
		res.StopGateNote = "not opted in: no terminal (or --json/--quiet); run `mark1 enable --stop-gate` at a terminal"
		return nil
	}
	_, _ = fmt.Fprintln(env.Stdout, "stop gate     opting in lets mark1d BLOCK an agent's Stop while its verdict is violated below the knee (≤3 consecutive, hourly ceiling; `mark1 off` disarms)")
	_, _ = fmt.Fprint(env.Stdout, "  opt in? [y/N] ")
	line, _ := bufio.NewReader(opts.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		res.StopGateNote = "not opted in: declined"
		return nil
	}
	c := cli.Consent{TS: time.Now().UTC().Format(time.RFC3339), Workspace: root, AgentsProvisioned: res.AgentsProvisioned, StopGate: true}
	if u, err := user.Current(); err == nil {
		c.User, c.UID = u.Username, u.Uid
	}
	if err := env.WriteStopGateOptIn(c.TS, c.User); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "writing stop-gate opt-in: %v", err)
	}
	if err := env.AppendConsent(c); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "recording stop-gate consent: %v", err)
	}
	res.StopGate, res.StopGatePending = env.ReadStopGate(), false
	return nil
}

func osUser() (name, uid string) {
	if u, err := user.Current(); err == nil {
		return u.Username, u.Uid
	}
	return "", ""
}

// D-EF, one line: the bundle's signed half and this local half are both required.
const explorationRule = "D-EF: ε>0 applies only if the tenant's signed bundle also carries exploration_opt_in; either half absent ⇒ ε=0, propensity 1.0"

// exploration writes D-EF's local half beside the stop-gate opt-in; no terminal gate, a fleet script is its normal author.
func exploration(env *cli.Env, opts Options, root string, res *Result) error {
	if opts.Exploration || opts.NoExploration {
		ts := time.Now().UTC().Format(time.RFC3339)
		c := cli.Consent{TS: ts, Workspace: root, AgentsProvisioned: res.AgentsProvisioned, Exploration: true}
		c.User, c.UID = osUser()
		if err := env.UpdateOptIn(ts, c.User, func(a *cli.OptIn) { a.Exploration = opts.Exploration }); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "writing exploration opt-in: %v", err)
		}
		if opts.Exploration {
			if err := env.AppendConsent(c); err != nil {
				return cli.Failf(cli.ExitRuntime, "", "recording exploration consent: %v", err)
			}
		}
		res.ExplorationNote = explorationRule
	}
	res.Exploration = env.ReadExploration()
	return nil
}

// candidatesFor returns the daemon-published candidates for root. A root that
// was just enabled is derived by mark1d only after the allow-list write above,
// so — when the daemon is reachable — this waits a bounded time for the file
// to name it. Absent file ⇒ the daemon has never published (not running).
func candidatesFor(env *cli.Env, opts Options, root string) ([]cli.AnchorCandidate, error) {
	deadline := time.Now().Add(candidatesWait)
	reachable := -1 // unknown until needed
	for {
		c, err := env.LoadAnchorCandidates()
		if err != nil {
			return nil, err
		}
		for _, ws := range c.Workspaces {
			if ws.Path == root {
				return ws.Anchors, nil
			}
		}
		if reachable < 0 {
			socket := opts.Socket
			if socket == "" {
				socket, _ = cli.SocketPath()
			}
			reachable = 0
			if socket != "" && cli.DaemonReachable(socket) {
				reachable = 1
			}
		}
		if reachable == 0 || time.Now().After(deadline) {
			return nil, errors.New("mark1d has not published candidates for this workspace yet; re-run `mark1 enable` once it is running")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// copilotGuardGapNote: the guard admits the key by fingerprint now; what still fails is routing (supervise passes no --upstream).
const copilotGuardGapNote = "copilot: the proxy admits this BYOK key by fingerprint, but the sidecar forwards only to api.anthropic.com and Copilot posts /chat/completions -- do not source this yet if you need working Copilot completions"

// optedOut reports whether the root .mark1ignore ignores the whole repo —
// a bare `*` (or `**`) line in gitignore syntax. Finer-grained
// .mark1ignore evaluation belongs to the tailers/cortexd readers (04 §2.1);
// enable only honors the whole-repo opt-out §7.2 names.
func optedOut(ignorePath string) bool {
	f, err := os.Open(ignorePath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "*" || line == "**" {
			return true
		}
	}
	return false
}
