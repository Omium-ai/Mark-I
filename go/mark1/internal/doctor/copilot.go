package doctor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
)

// copilotPointerNote: 08 §5.5's BYOK base URL is an env var, so no fenced file exists for a proxy pointer; said, not pretended.
const copilotPointerNote = "no proxy pointer: COPILOT_PROVIDER_BASE_URL is an env var with no fenced file target"

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
	a.Note = join(a.Note, copilotPointerNote)
	// SessionStateDir is <copilotHome>/session-state; its parent is the adapter's own resolution of $COPILOT_HOME.
	if dir, err := cp.SessionStateDir(); err == nil {
		if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
			a.Note = join(a.Note, "no ~/.copilot ($COPILOT_HOME); mechanism A cannot apply until copilot creates it (run copilot once, then `mark1 enable`)")
		}
	}
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
