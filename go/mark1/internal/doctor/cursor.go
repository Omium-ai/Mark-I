package doctor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
)

// cursorClaudeNote: conformance/hooks/cursor/*/README.md — Cursor loads ~/.claude/settings.json hooks too, so the claudecode fragment fires the shim from Cursor with MARK1_AGENT unset (maps nothing, emits nothing).
const cursorClaudeNote = "cursor also runs the claudecode fragment (~/.claude/settings.json hooks) with MARK1_AGENT unset; that path maps nothing"

// cursorAgent fills the roster row; the wire proxy is a permanent NO-GO (08 §5.6), so the regime is subscription whatever key is configured.
func cursorAgent(env *cli.Env, opts Options, a *Agent) {
	cu := &cursor.Adapter{Home: opts.Home, StateDir: env.StateDir}
	d, _ := cu.Detect()
	if !d.Installed {
		a.Note = "cursor not on PATH"
		return
	}
	a.Version, a.Regime = d.Version, regimeWord(d.Regime)
	c, err := cu.Compatibility(d.Version)
	a.Note = compatNote(c, err, "hook")
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	// The vendor has no env override for ~/.cursor (cursor.go cursorDir).
	if _, err := os.Stat(filepath.Join(home, ".cursor")); home != "" && os.IsNotExist(err) {
		a.Note = join(a.Note, "no ~/.cursor; Mark 1 never creates the vendor's config directory (run cursor once, then `mark1 enable`)")
	}
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); err == nil {
		a.Note = join(a.Note, cursorClaudeNote)
	}
}

func inspectCursor(env *cli.Env, opts Options) Fragment {
	st, err := cursor.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail, Lines: lines(st.Lines),
	}
	if err != nil {
		f.State, f.Detail = string(cursor.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" || (st.State != cursor.StateMissing && st.State != cursor.StateDamaged) {
		return f
	}
	res, ferr := cursor.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if after, aerr := cursor.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail, f.Lines = string(after.State), after.Detail, lines(after.Lines)
	}
	return f
}
