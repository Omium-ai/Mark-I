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
	"path/filepath"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
)

type Options struct {
	Path string
	// Home overrides $HOME for agent-config resolution (test seam). Empty is
	// the real user's home.
	Home string
}

// Result is §7.2's --json shape, minus the fields whose producers have not
// landed (anchors consent walks mark1d's anchors catalog; the coverage receipt
// seq is minted by the receipt chain) — absent, never faked.
type Result struct {
	OK                bool     `json:"ok"`
	Workspace         string   `json:"workspace"`
	Changed           bool     `json:"changed"`
	AgentsProvisioned []string `json:"agents_provisioned"`
	// AgentsRefused is additive to §7.2's shape and deliberately not an error:
	// M1E-7101/7102 are refusals by design, and §7.2's exit table names no
	// provisioning-refusal class. Failing the enable would punish a user who
	// simply has no ~/.claude/settings.json yet; hiding it would leave them
	// enrolled with nothing capturing. So it is reported here and again in
	// `mark1 doctor`, which is the doc-named surface for both codes.
	AgentsRefused []Refusal `json:"agents_refused,omitempty"`
}

// Refusal is one agent whose fragment could not be applied, with the M1E code
// the user can look up.
type Refusal struct {
	Agent  string `json:"agent"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

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
	if added {
		ws.Workspaces = append(ws.Workspaces, cli.WorkspaceEntry{Path: root, EnabledAt: time.Now().UTC()})
		if err := env.SaveWorkspaces(ws); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "writing allow-list: %v", err)
		}
		if err := env.AppendCoverageTransition(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "kind": "enable", "workspace": root,
		}); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "journaling coverage transition: %v", err)
		}
	}

	// §7.2: "re-running reconciles fragments/consents". This runs whether or
	// not the allow-list changed — a user who ran `mark1 off` and then
	// `mark1 enable` again must get their hooks back, and an early return on
	// an already-listed workspace would leave them permanently unprovisioned.
	wrote, err := provision(env, opts, &res)
	if err != nil {
		return err
	}
	res.Changed = added || wrote

	return env.Emit(res, func(w io.Writer) {
		if added {
			_, _ = fmt.Fprintf(w, "enabled %s\n", root)
		}
		if wrote {
			for _, a := range res.AgentsProvisioned {
				_, _ = fmt.Fprintf(w, "provisioned   %s\n", a)
			}
		}
		for _, r := range res.AgentsRefused {
			_, _ = fmt.Fprintf(w, "NOT PROVISIONED %s: %s %s\n", r.Agent, r.Code, r.Detail)
		}
	})
}

// provision applies the 08 §8 config fragments and reports whether anything
// was actually written. Only claudecode has an implementation
// (adapters.Roster carries the other six as declared-but-unbuilt, and
// `mark1 doctor` prints the whole roster); calling the one adapter directly
// beats a loop with a type switch inside it.
func provision(env *cli.Env, opts Options, res *Result) (wrote bool, err error) {
	a := &claudecode.Adapter{Home: opts.Home, StateDir: env.StateDir}
	applied, err := a.Apply()
	switch code := claudecode.RefusalCode(err); {
	case err == nil:
		res.AgentsProvisioned = append(res.AgentsProvisioned, a.Name())
		return applied.Changed, nil
	case code != "":
		res.AgentsRefused = append(res.AgentsRefused, Refusal{a.Name(), code, err.Error()})
		return false, nil
	}
	return false, cli.Failf(cli.ExitRuntime, "", "provisioning %s: %v", a.Name(), err)
}

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
