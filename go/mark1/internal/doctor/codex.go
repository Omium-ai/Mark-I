package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
)

const trustAdvice = "run codex once and accept the hooks review"

// codexAgent fills the roster row; a user-layer hook is inert until the TUI's startup review records its trusted_hash (discovery.rs, rust-v0.154.0).
func codexAgent(env *cli.Env, opts Options, a *Agent) {
	cx := &codex.Adapter{CodexHome: opts.CodexHome, StateDir: env.StateDir}
	d, _ := cx.Detect()
	switch {
	case !d.Installed:
		a.Note = "codex not on PATH"
	default:
		a.Version = d.Version
		c, err := cx.Compatibility(d.Version)
		a.Note = compatNote(c, err, "rollout")
	}
	if d.Installed {
		a.Regime = regimeWord(d.Regime)
	}
	m, err := codex.LoadManifest(env.StateDir)
	if err != nil {
		return
	}
	trusted, total := codexTrust(m)
	if trusted == total {
		a.HooksTrusted = "yes"
		return
	}
	a.HooksTrusted = "no"
	a.Note = strings.TrimPrefix(a.Note+fmt.Sprintf("; %d/%d handlers trusted, %s", trusted, total, trustAdvice), "; ")
}

// codexTrust counts our hook_keys carrying a trusted_hash and not disabled; ponytail: hash equality is not re-derived, a stale hash reads as trusted where Codex says Modified.
func codexTrust(m codex.Manifest) (trusted, total int) {
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(m.TargetPath), "config.toml"))
	state := hookStates(raw)
	for _, p := range m.Pointers {
		total++
		rest, _ := strings.CutPrefix(p, "/hooks/")
		event, idx, _ := strings.Cut(rest, "/")
		key := m.TargetPath + ":" + snake(event) + ":" + idx + ":0"
		if st := state[key]; st.trustedHash != "" && !st.disabled {
			trusted++
		}
	}
	return trusted, total
}

type hookState struct {
	trustedHash string
	disabled    bool
}

var (
	quoted        = regexp.MustCompile(`^"([^"]+)"`)
	inlineTrusted = regexp.MustCompile(`trusted_hash\s*=\s*"([^"]+)"`)
	inlineEnabled = regexp.MustCompile(`enabled\s*=\s*false`)
)

// hookStates reads [hooks.state] per-key tables, dotted keys or inline tables; ponytail: a line scanner, not a TOML parser.
func hookStates(toml []byte) map[string]hookState {
	out := map[string]hookState{}
	var table []string
	for _, line := range strings.Split(string(toml), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			table = splitKey(strings.Trim(line, "[]"))
			continue
		}
		lhs, rhs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		path := append(append([]string{}, table...), splitKey(lhs)...)
		if len(path) < 3 || path[0] != "hooks" || path[1] != "state" {
			continue
		}
		rhs = strings.TrimSpace(rhs)
		st := out[path[2]]
		switch {
		case len(path) == 4 && path[3] == "trusted_hash":
			if m := quoted.FindStringSubmatch(rhs); m != nil {
				st.trustedHash = m[1]
			}
		case len(path) == 4 && path[3] == "enabled":
			st.disabled = strings.HasPrefix(rhs, "false")
		case len(path) == 3 && strings.HasPrefix(rhs, "{"):
			if m := inlineTrusted.FindStringSubmatch(rhs); m != nil {
				st.trustedHash = m[1]
			}
			st.disabled = inlineEnabled.MatchString(rhs)
		default:
			continue
		}
		out[path[2]] = st
	}
	return out
}

// splitKey splits a dotted TOML key outside quotes and unquotes each part.
func splitKey(k string) []string {
	var out []string
	var cur strings.Builder
	var q byte
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case q == '"' && c == '\\' && i+1 < len(k):
			i++
			cur.WriteByte(k[i])
		case q != 0:
			if c == q {
				q = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q = c
		case c == '.':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}

// snake is lib.rs hook_event_key_label: SessionStart -> session_start.
func snake(event string) string {
	var b strings.Builder
	for i, r := range event {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func inspectCodex(env *cli.Env, opts Options) Fragment {
	st, err := codex.Inspect(env.StateDir)
	f := Fragment{
		Agent: st.Agent, Fragment: st.Fragment, Mechanism: st.Mechanism, Manifest: st.Manifest,
		Target: st.Target, State: string(st.State), Detail: st.Detail, Lines: lines(st.Lines),
	}
	if err != nil {
		f.State, f.Detail = string(codex.StateDamaged), err.Error()
		return f
	}
	if !opts.Fix || f.Target == "" || (st.State != codex.StateMissing && st.State != codex.StateDamaged) {
		return f
	}
	res, ferr := codex.RepairFragment(f.Target, env.StateDir, "")
	if ferr != nil {
		f.Detail = fmt.Sprintf("--fix failed: %v", ferr)
		return f
	}
	f.Fixed = res.Changed
	if after, aerr := codex.Inspect(env.StateDir); aerr == nil {
		f.State, f.Detail, f.Lines = string(after.State), after.Detail, lines(after.Lines)
	}
	return f
}
