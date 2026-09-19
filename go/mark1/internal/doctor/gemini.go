package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
)

// geminiAgent fills the roster row; mechanism B never creates ~/.gemini/settings.json, so its absence is said here.
func geminiAgent(env *cli.Env, opts Options, a *Agent) {
	g := &gemini.Adapter{Home: opts.Home, StateDir: env.StateDir}
	d, _ := g.Detect()
	if !d.Installed {
		a.Note = "gemini not on PATH"
		return
	}
	a.Version, a.Regime = d.Version, regimeWord(d.Regime)
	c, err := g.Compatibility(d.Version)
	a.Note = compatNote(c, err, "chat")
	tmp, err := g.TmpDir()
	if err != nil {
		return
	}
	// TmpDir is <geminiDir>/tmp; its parent is the adapter's own resolution of ~/.gemini ($GEMINI_CLI_HOME aware).
	b, err := os.ReadFile(filepath.Join(filepath.Dir(tmp), "settings.json"))
	switch {
	case os.IsNotExist(err):
		a.Note = join(a.Note, "no ~/.gemini/settings.json; mechanism B cannot apply until gemini writes one (run gemini once, then `mark1 enable`)")
	case err == nil && !json.Valid(b):
		a.Note = join(a.Note, "~/.gemini/settings.json is not strict JSON (comments?); mechanism B cannot fence it")
	}
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func inspectGemini(env *cli.Env, opts Options) Fragment {
	st, err := gemini.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail, Lines: lines(st.Lines),
	}
	if err != nil {
		f.State, f.Detail = string(gemini.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" || (st.State != gemini.StateMissing && st.State != gemini.StateDamaged) {
		return f
	}
	res, ferr := gemini.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if after, aerr := gemini.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail, f.Lines = string(after.State), after.Detail, lines(after.Lines)
	}
	return f
}
