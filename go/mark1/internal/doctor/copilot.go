package doctor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
)

// copilotAgent fills the roster row; mechanism A owns $COPILOT_HOME/hooks/mark1.json but never creates $COPILOT_HOME itself.
func copilotAgent(env *cli.Env, opts Options, a *Agent) {
	cp := &copilot.Adapter{Home: opts.Home, StateDir: env.StateDir}
	d, _ := cp.Detect()
	if !d.Installed {
		a.Note = "copilot not on PATH"
		return
	}
	a.Version, a.Regime = d.Version, regimeWord(d.Regime)
	if !copilot.Supported(d.Version) {
		a.Note = "no pinned fixture for this version; session capture inert (08 §5 rule 2)"
	}
	// FR-AGENT-014's three-way row: whether the BYOK env pointer was ever
	// applied, and whether THIS process's environment — the user's shell, if
	// they sourced the printed line into it — currently carries it.
	a.Note = join(a.Note, "byok pointer "+copilot.EnvPointerLiveState(env.StateDir, nil))
	// SessionStateDir is <copilotHome>/session-state; its parent is the adapter's own resolution of $COPILOT_HOME.
	if dir, err := cp.SessionStateDir(); err == nil {
		if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
			a.Note = join(a.Note, "no ~/.copilot ($COPILOT_HOME); mechanism A cannot apply until copilot creates it (run copilot once, then `mark1 enable`)")
		}
	}
}

// inspectCopilotEnv classifies the BYOK env pointer without repairing it —
// same reasoning as inspectBaseURL: re-pointing needs a fresh eligibility
// check (`mark1 enable`: credential shape, live guard probe), not a blind
// rewrite of possibly-stale bytes by `doctor --fix`.
func inspectCopilotEnv(env *cli.Env, opts Options) Fragment {
	st, err := copilot.InspectEnvPointer(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail,
	}
	if err != nil {
		f.State, f.Detail = string(copilot.StateDamaged), err.Error()
		return f
	}
	if opts.Fix && (f.State == string(copilot.StateDamaged) || f.State == string(copilot.StateMissing)) {
		f.Detail += " (--fix does not re-point copilot at the proxy: run `mark1 enable` to re-check eligibility, or `mark1 off` to detach)"
	}
	return f
}

func inspectCopilot(env *cli.Env, opts Options) Fragment {
	st, err := copilot.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail,
	}
	if err != nil {
		f.State, f.Detail = string(copilot.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" || (st.State != copilot.StateMissing && st.State != copilot.StateDamaged) {
		return f
	}
	res, ferr := copilot.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if after, aerr := copilot.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail = string(after.State), after.Detail
	}
	return f
}
