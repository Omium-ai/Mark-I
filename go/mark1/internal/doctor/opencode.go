package doctor

import (
	"fmt"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

// opencodeAgent fills the roster row; plugins load at opencode start (config/plugin.ts), so a fresh one is inert in a running instance.
func opencodeAgent(env *cli.Env, opts Options, a *Agent) {
	oc := &opencode.Adapter{Home: opts.Home, StateDir: env.StateDir}
	d, _ := oc.Detect()
	if !d.Installed {
		a.Note = "opencode not on PATH"
		return
	}
	a.Version, a.Regime = d.Version, regimeWord(d.Regime)
	c, err := oc.Compatibility(d.Version)
	a.Note = compatNote(c, err, "usage")
	if _, err := opencode.LoadManifest(env.StateDir); err == nil {
		a.Note = join(a.Note, "plugin loads at opencode start; restart any opencode running since `mark1 enable`")
	}
}

func inspectOpenCode(env *cli.Env, opts Options) Fragment {
	st, err := opencode.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail,
	}
	if err != nil {
		f.State, f.Detail = string(opencode.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" || (st.State != opencode.StateMissing && st.State != opencode.StateDamaged) {
		return f
	}
	res, ferr := opencode.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if err := provision.WriteStamp(env.StateDir, f.Agent, env.Version, res.Checksum); err != nil {
		f.Detail = "release stamp not written: " + err.Error()
	}
	if after, aerr := opencode.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail = string(after.State), after.Detail
	}
	return f
}
