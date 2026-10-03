// Package provision is the one walk over every built adapter's 08 §8 apply and §8.4 revert: `mark1 enable`/`off` run it daemon-down, the control API runs it for the app.
package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// Names is every adapter this walk applies and reverts, in 08 §5 order.
var Names = []string{"claudecode", "codex", "gemini", "opencode", "copilot", "cursor"}

type Options struct {
	Home     string // overrides $HOME for agent-config resolution (test seam)
	StateDir string
	Only     []string // restricts the walk; nil is every adapter
	Repair   bool     // rewrite a FRAGMENT-DAMAGED fence instead of refusing it (08 §8.3(d), the `doctor --fix` bit)
	// Profile is the ADR-0013 host profile of the session this walk serves;
	// nil is hostprofile.Default (a solo developer's daemon, `mark1 enable`,
	// the control API today). Read and logged here; a later feature switches
	// on OwnsConfigSurface.
	Profile *hostprofile.Profile
	Log     *slog.Logger // nil logs nothing
}

type Refusal struct {
	Agent  string `json:"agent"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type Result struct {
	Provisioned       []string
	Refused           []Refusal
	Changed           bool
	ProxyPointer      string // provisioned | not-eligible | M1E code; "" when claudecode was not walked
	CopilotPointer    string
	CopilotSourceLine string
	// Profile is the host profile this walk resolved (ADR-0013): the
	// Options.Profile or hostprofile.Default. Reported so a caller can see
	// what provisioning read, before anything decides on it.
	Profile hostprofile.Profile
}

// Profile and DefaultProfile re-export the ADR-0013 host profile for the
// CLI module, which may import adapters/ but never mark1d/internal/.
type Profile = hostprofile.Profile

var DefaultProfile = hostprofile.Default

// CodeHostOwnsSurface is 08 §9's row for ADR-0014 §4: a declared host owns
// the agent's config surface, so provisioning writes nothing into it.
const CodeHostOwnsSurface = "M1E-7107"

// HostOwnsSurface reports whether p is a DECLARED host (host_id set) that
// owns the config surface. hostprofile.Default describes Mark 1's own posture,
// so its OwnsConfigSurface reads "the surface's owner — Mark 1 — owns it"
// and never refuses; only a declared host can be the other party.
func HostOwnsSurface(p hostprofile.Profile) bool {
	return p.HostID != "" && p.OwnsConfigSurface
}

// RefusalHostOwnsSurface is the one-line explanation every CLI surface prints
// for M1E-7107 (08 §8.3 step 0).
func RefusalHostOwnsSurface(p hostprofile.Profile) string {
	return fmt.Sprintf("%s: host owns config surface — %s %s owns its own configuration; Mark 1 is attached through the fabric and writes nothing here", CodeHostOwnsSurface, p.HostID, p.HostVersion)
}

// RevertUnless is Revert for a caller that knows the session's profile: when
// a declared host owns the surface there is nothing of ours in it, so revert
// is a no-op reported with the same reason (ADR-0014 §4); otherwise Revert.
func RevertUnless(p hostprofile.Profile, stateDir string, only ...string) (done []Reverted, notReverted []string, refused string) {
	if HostOwnsSurface(p) {
		return nil, nil, RefusalHostOwnsSurface(p)
	}
	done, notReverted = Revert(stateDir, only...)
	return done, notReverted, ""
}

// profileFor resolves and logs the walk's host profile (ADR-0013 §4).
func profileFor(opts Options) hostprofile.Profile {
	p := hostprofile.Default
	if opts.Profile != nil {
		p = *opts.Profile
	}
	if opts.Log != nil {
		opts.Log.Debug("provision: host profile", "host_id", p.HostID, "owns_config_surface", p.OwnsConfigSurface, "default", p.IsDefault())
	}
	return p
}

type Reverted struct {
	Agent        string `json:"agent"`
	Target       string `json:"target"`
	Kind         string `json:"kind"`
	ByteEquality bool   `json:"byte_equality"`
}

func pick[R any](repair bool, apply, fix func() (R, error)) func() (R, error) {
	if repair {
		return fix
	}
	return apply
}

func installed(d adapters.Detection, _ error) bool { return d.Installed }

// Apply walks the adapters: claudecode unconditionally, the rest only when installed, so no owned file is planted for an agent the user does not run and no fence refused for one they never configured.
func Apply(opts Options) (Result, error) {
	res := Result{Provisioned: []string{}, Profile: profileFor(opts)}
	for _, n := range opts.Only {
		if !slices.Contains(Names, n) {
			return res, fmt.Errorf("unknown agent %q", n)
		}
	}
	walk := func(name string) bool { return opts.Only == nil || slices.Contains(opts.Only, name) }
	// ADR-0014 §4 (08 §8.3 step 0): a declared host that owns the config
	// surface gets nothing written — every adapter in the walk is refused
	// with M1E-7107 naming it. hostprofile.Default is Mark 1's own posture
	// and never trips this.
	if HostOwnsSurface(res.Profile) {
		for _, name := range Names {
			if walk(name) {
				res.Refused = append(res.Refused, Refusal{name, CodeHostOwnsSurface, RefusalHostOwnsSurface(res.Profile)})
			}
		}
		return res, nil
	}
	note := func(name string, changed bool, err error, refusalCode func(error) string) error {
		var syntax *json.SyntaxError
		switch code := refusalCode(err); {
		case err == nil:
			res.Provisioned = append(res.Provisioned, name)
			res.Changed = res.Changed || changed
		case code != "":
			res.Refused = append(res.Refused, Refusal{name, code, err.Error()})
		case name == "gemini" && errors.As(err, &syntax):
			res.Refused = append(res.Refused, Refusal{name, "", "~/.gemini/settings.json is not strict JSON (comments?), so mechanism B cannot fence it: " + err.Error()})
		default:
			return fmt.Errorf("provisioning %s: %w", name, err)
		}
		return nil
	}

	if walk("claudecode") {
		a := &claudecode.Adapter{Home: opts.Home, StateDir: opts.StateDir}
		r, err := pick(opts.Repair, a.Apply, a.Repair)()
		if err := note(a.Name(), r.Changed, err, claudecode.RefusalCode); err != nil {
			return res, err
		}
		pointer, perr := a.ApplyProxyPointer()
		switch code := claudecode.RefusalCode(perr); {
		case perr == nil:
			res.ProxyPointer = "provisioned"
			res.Changed = res.Changed || pointer.Changed
		case errors.Is(perr, claudecode.ErrNotEligible):
			res.ProxyPointer = "not-eligible"
		case code != "":
			res.ProxyPointer = code
			res.Refused = append(res.Refused, Refusal{a.Name() + "/baseurl", code, perr.Error()})
		default:
			return res, fmt.Errorf("provisioning %s base URL: %w", a.Name(), perr)
		}
	}
	if cx := (&codex.Adapter{Home: opts.Home, StateDir: opts.StateDir}); walk(cx.Name()) && installed(cx.Detect()) {
		r, err := pick(opts.Repair, cx.Apply, cx.Repair)()
		if err := note(cx.Name(), r.Changed, err, codex.RefusalCode); err != nil {
			return res, err
		}
	}
	if gm := (&gemini.Adapter{Home: opts.Home, StateDir: opts.StateDir}); walk(gm.Name()) && installed(gm.Detect()) {
		r, err := pick(opts.Repair, gm.Apply, gm.Repair)()
		if err := note(gm.Name(), r.Changed, err, gemini.RefusalCode); err != nil {
			return res, err
		}
	}
	if oc := (&opencode.Adapter{Home: opts.Home, StateDir: opts.StateDir}); walk(oc.Name()) && installed(oc.Detect()) {
		r, err := pick(opts.Repair, oc.Apply, oc.Repair)()
		if err := note(oc.Name(), r.Changed, err, opencode.RefusalCode); err != nil {
			return res, err
		}
	}
	if cp := (&copilot.Adapter{Home: opts.Home, StateDir: opts.StateDir}); walk(cp.Name()) && installed(cp.Detect()) {
		r, err := pick(opts.Repair, cp.Apply, cp.Repair)()
		if err := note(cp.Name(), r.Changed, err, copilot.RefusalCode); err != nil {
			return res, err
		}
		// The BYOK env pointer is a separate owned file, never the user's profile (CON-003); every ineligibility is a normal outcome.
		pointer, perr := cp.ApplyEnvPointer()
		switch code := copilot.RefusalCode(perr); {
		case perr == nil:
			res.CopilotPointer = "provisioned"
			res.CopilotSourceLine = copilot.SourceLine(opts.StateDir, runtime.GOOS)
			res.Changed = res.Changed || pointer.Changed
		case errors.Is(perr, copilot.ErrNotEligible):
			res.CopilotPointer = "not-eligible"
		case code != "":
			res.CopilotPointer = code
			res.Refused = append(res.Refused, Refusal{cp.Name() + "/env", code, perr.Error()})
		default:
			return res, fmt.Errorf("provisioning %s env pointer: %w", cp.Name(), perr)
		}
	}
	if cu := (&cursor.Adapter{Home: opts.Home, StateDir: opts.StateDir}); walk(cu.Name()) && installed(cu.Detect()) {
		r, err := pick(opts.Repair, cu.Apply, cu.Repair)()
		if err := note(cu.Name(), r.Changed, err, cursor.RefusalCode); err != nil {
			return res, err
		}
	}
	return res, nil
}

// Revert is 08 §8.4 for the agents named (all of Names when none is), then lists whatever manifest is STILL on disk afterwards: a failed revert and a fragment an unknown agent wrote are the same problem to the user.
func Revert(stateDir string, only ...string) (done []Reverted, notReverted []string) {
	walk := func(name string) bool { return len(only) == 0 || slices.Contains(only, name) }
	// A retained fragment (hand-edited, D-CR) keeps its manifest and is deliberately NOT listed as done: the leftover scan reports it.
	add := func(agent string, r claudecode.RevertResult, err error) {
		if err == nil && r.Kind != "not-provisioned" && len(r.Retained) == 0 {
			done = append(done, Reverted{agent, r.Target, r.Kind, r.ByteEquality})
		}
	}
	if walk("claudecode") {
		// Base-URL before hooks: both fence one settings.json, and this order leaves the file matching the hooks manifest's post_image so the hooks revert takes its verbatim path.
		b, err := claudecode.RevertBaseURL(stateDir)
		add("claudecode/baseurl", b, err)
		r, err := claudecode.Revert(stateDir)
		if err == nil && r.Kind != "not-provisioned" {
			done = append(done, Reverted{"claudecode", r.Target, r.Kind, r.ByteEquality})
		}
	}
	if walk("codex") {
		r, err := codex.Revert(stateDir)
		add("codex", claudecode.RevertResult(r), err)
	}
	if walk("gemini") {
		r, err := gemini.Revert(stateDir)
		add("gemini", claudecode.RevertResult(r), err)
	}
	if walk("opencode") {
		r, err := opencode.Revert(stateDir)
		add("opencode", claudecode.RevertResult(r), err)
	}
	if walk("copilot") {
		r, err := copilot.Revert(stateDir)
		add("copilot", claudecode.RevertResult(r), err)
		e, err := copilot.RevertEnvPointer(stateDir)
		add("copilot/env", claudecode.RevertResult(e), err)
	}
	if walk("cursor") {
		r, err := cursor.Revert(stateDir)
		add("cursor", claudecode.RevertResult(r), err)
	}
	dirs := only
	if len(dirs) == 0 {
		dirs = []string{"*"}
	}
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(stateDir, "provisioned", d, "*.manifest.json"))
		notReverted = append(notReverted, m...)
	}
	return done, notReverted
}
