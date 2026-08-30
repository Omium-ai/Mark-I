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
)

type Options struct {
	Path string
}

// Result is §7.2's --json shape, minus the fields whose producers have not
// landed (anchors consent walks mark1d's anchors catalog; fragment
// provisioning is mark1d's §8 engine; the coverage receipt seq is minted by
// the receipt chain) — absent, never faked.
type Result struct {
	OK        bool   `json:"ok"`
	Workspace string `json:"workspace"`
	Changed   bool   `json:"changed"`
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
	for _, entry := range ws.Workspaces {
		if entry.Path == root {
			// §7.2 idempotence: unchanged state exits 0 silently.
			return env.Emit(Result{OK: true, Workspace: root, Changed: false}, func(io.Writer) {})
		}
	}
	ws.Workspaces = append(ws.Workspaces, cli.WorkspaceEntry{Path: root, EnabledAt: time.Now().UTC()})
	if err := env.SaveWorkspaces(ws); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "writing allow-list: %v", err)
	}
	if err := env.AppendCoverageTransition(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "kind": "enable", "workspace": root,
	}); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "journaling coverage transition: %v", err)
	}
	return env.Emit(Result{OK: true, Workspace: root, Changed: true}, func(w io.Writer) {
		fmt.Fprintf(w, "enabled %s\n", root)
	})
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
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "*" || line == "**" {
			return true
		}
	}
	return false
}
