package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
)

// redactKey keys the hash leg of every ⟨redacted:class:hash⟩ token in a fixture: fixed, so re-harvesting the same bytes is reproducible.
var redactKey = []byte("mark1-corpus-fixture")

// artifact is one vendor file and where it lands under transcripts/.
type artifact struct {
	src, rel string
}

// harvester names the file-based surface each adapter's tailer reads (the same globs its probe scans).
type harvester struct {
	detect func() (adapters.Detection, error)
	files  func() ([]artifact, error)
	// stamped reads the artifact's own version stamp ("" when the surface carries none): a file another build wrote is not this version's evidence.
	stamped func(b []byte) string
	// fixup runs over the sanitized tree: gemini's projectHash must hash the sanitized marker.
	fixup func(root string) error
}

// stampAt returns the JSON string at the pointer path inside the first line whose `type` is want.
func stampAt(want string, path ...string) func([]byte) string {
	return func(b []byte) string {
		for _, line := range bytes.Split(b, []byte("\n")) {
			var v map[string]any
			if json.Unmarshal(line, &v) != nil || v["type"] != want {
				continue
			}
			var cur any = v
			for _, k := range path {
				m, ok := cur.(map[string]any)
				if !ok {
					return ""
				}
				cur = m[k]
			}
			s, _ := cur.(string)
			return s
		}
		return ""
	}
}

func harvesters() map[string]harvester {
	cx, gm, oc, cp := &codex.Adapter{}, &gemini.Adapter{}, &opencode.Adapter{}, &copilot.Adapter{}
	return map[string]harvester{
		"codex": {detect: cx.Detect, files: func() ([]artifact, error) {
			dir, err := cx.SessionsDir()
			return globbed(dir, "sessions", err, "*", "*", "*", "rollout-*.jsonl")
		}, stamped: stampAt("session_meta", "payload", "cli_version")},
		"gemini": {detect: gm.Detect, files: func() ([]artifact, error) {
			dir, err := gm.TmpDir()
			chats, err := globbed(dir, "tmp", err, "*", "chats", "*.jsonl")
			if err != nil {
				return nil, err
			}
			subs, _ := globbed(dir, "tmp", nil, "*", "chats", "*", "*.jsonl")
			markers, _ := globbed(dir, "tmp", nil, "*", ".project_root")
			return append(append(chats, subs...), markers...), nil
		}, fixup: geminiHashes},
		"opencode": {detect: oc.Detect, files: func() ([]artifact, error) {
			dir, err := oc.CaptureDir()
			return globbed(dir, "capture", err, "ses_*.jsonl")
		}},
		"copilot": {detect: cp.Detect, files: func() ([]artifact, error) {
			dir, err := cp.SessionStateDir()
			return globbed(dir, "session-state", err, "*", "events.jsonl")
		}, stamped: stampAt("session.start", "data", "copilotVersion")},
	}
}

func globbed(dir, under string, err error, pattern ...string) ([]artifact, error) {
	if err != nil {
		return nil, err
	}
	paths, _ := filepath.Glob(filepath.Join(append([]string{dir}, pattern...)...))
	out := make([]artifact, 0, len(paths))
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		out = append(out, artifact{p, filepath.ToSlash(filepath.Join(under, rel))})
	}
	return out, nil
}

// Harvest copies the installed agent's on-disk artifacts of the last opts.Since into a
// fresh v<version>/transcripts tree, identity-sanitized and mark1-redact'ed, with a README
// naming what is still owed (hook bodies, expectations.json) before the version can be pinned.
func Harvest(env *cli.Env, opts Options) error {
	h, ok := harvesters()[opts.Agent]
	if !ok {
		return cli.Failf(cli.ExitUsage, "", "no recorder for %q: recorders exist for claudecode (driven) and codex, gemini, opencode, copilot (harvested); cursor has no file-based artifact", opts.Agent)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	return harvest(env, opts, h, home)
}

func harvest(env *cli.Env, opts Options, h harvester, home string) error {
	d, err := h.detect()
	if err != nil || !d.Installed || d.Version == "" {
		return cli.Failf(cli.ExitRuntime, "", "%s not installed or unsniffable (installed=%v version=%q)", opts.Agent, d.Installed, d.Version)
	}
	out := filepath.Join(opts.Out, "v"+d.Version)
	if _, err := os.Stat(out); err == nil {
		return cli.Failf(cli.ExitRefused, "", "%s exists — a recorded corpus is frozen (12 §3.2); remove it to re-record", out)
	}
	since := opts.Since
	if since <= 0 {
		since = 24 * time.Hour
	}
	files, err := h.files()
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	cutoff := time.Now().Add(-since)
	var fresh, markers []artifact
	for _, f := range files {
		if filepath.Base(f.src) == ".project_root" {
			markers = append(markers, f)
		} else if info, err := os.Stat(f.src); err == nil && info.ModTime().After(cutoff) {
			fresh = append(fresh, f)
		}
	}
	// A slug's marker rides along only with a fresh chat of its own: other projects' roots are not evidence.
	for _, m := range markers {
		for _, f := range fresh {
			if strings.HasPrefix(f.src, filepath.Dir(m.src)+string(filepath.Separator)) {
				fresh = append(fresh, m)
				break
			}
		}
	}
	if len(fresh) == 0 {
		return cli.Failf(cli.ExitRuntime, "", "no %s artifact modified in the last %s; run a session in the workspace, then harvest", opts.Agent, since)
	}
	san, err := harvestSanitizer(home, opts.Workspace)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	var notes []string
	var subs uint32
	cwds := map[string]bool{}
	kept := 0
	for _, f := range fresh {
		b, err := os.ReadFile(f.src)
		if err != nil {
			return cli.Failf(cli.ExitRuntime, "", "%v", err)
		}
		if h.stamped != nil {
			if v := h.stamped(b); v != "" && v != d.Version {
				notes = append(notes, fmt.Sprintf("skipped %s: stamped %s, not %s", filepath.Base(f.src), v, d.Version))
				continue
			}
		}
		kept++
		red, n, err := adapters.Redact(redactKey, san(b))
		if err != nil {
			_ = os.RemoveAll(out)
			return cli.Failf(cli.ExitRefused, "", "%s: %v", f.src, err)
		}
		subs += n
		for _, m := range cwdRe.FindAllSubmatch(red, -1) {
			cwds[string(m[1])] = true
		}
		if err := writeFile(filepath.Join(out, "transcripts", filepath.FromSlash(string(san([]byte(f.rel))))), red); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "%v", err)
		}
	}
	if kept == 0 {
		_ = os.RemoveAll(out)
		return cli.Failf(cli.ExitRuntime, "", "no %s artifact stamped %s among the %d fresh files (%s); run a session with the installed build", opts.Agent, d.Version, len(fresh), strings.Join(notes, "; "))
	}
	notes = append(notes, fmt.Sprintf("%d artifact files harvested (modified within %s); %d spans redacted by mark1-redact", kept, since, subs))
	if len(cwds) > 0 {
		notes = append(notes, "cwd values after sanitization, review for identities the grep cannot know: "+strings.Join(sortedKeys(cwds), ", "))
	}
	if h.fixup != nil {
		if err := h.fixup(filepath.Join(out, "transcripts")); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "%v", err)
		}
	}
	if err := identityGrep(out, home); err != nil {
		_ = os.RemoveAll(out)
		return cli.Failf(cli.ExitRefused, "", "%v", err)
	}
	if err := carrySelfcheck(opts.Out, out, d.Version); err != nil {
		notes = append(notes, "selfcheck.py not carried forward (no prior pin to copy it from)")
	}
	if err := writeFile(filepath.Join(out, "README.md"), []byte(harvestReadme(opts.Agent, d.Version, notes))); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	digest, n, err := digestCorpus(out)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "digest: %v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "harvested %s: %d evidence files\n%s\n", out, n, strings.Join(notes, "\n"))
	_, _ = fmt.Fprintf(env.Stdout, "\nstill owed before pinning: hooks/<Event>.json (transcribe or capture), transcripts/expectations.json (selfcheck.py's rules), then\n")
	_, _ = fmt.Fprintf(env.Stdout, "add to go/mark1d/adapters/%s SupportedVersions:\n\t%q: {},\n", opts.Agent, d.Version)
	_, _ = fmt.Fprintf(env.Stdout, "add to go/mark1d/adapters/%s/corpus_pin_test.go recordedCorpusDigest (recompute after the owed files land):\n\t%q: %q,\n", opts.Agent, d.Version, digest)
	return nil
}

// harvestSanitizer maps this machine's identities to the fixture placeholders, then the stable synthetic ids.
func harvestSanitizer(home, workspace string) (func([]byte) []byte, error) {
	var err error
	if workspace == "" {
		if workspace, err = os.Getwd(); err != nil {
			return nil, err
		}
	}
	if workspace, err = filepath.Abs(workspace); err != nil {
		return nil, err
	}
	fixed := [][2]string{{workspace, synthRoot}, {filepath.ToSlash(workspace), synthRoot}, {home, "/home/devuser"}, {filepath.ToSlash(home), "/home/devuser"}}
	san := sanitizer(fixed)
	u, err := user.Current()
	if err != nil || len(u.Username) <= 3 {
		return san, nil
	}
	userRe := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(u.Username))
	return func(b []byte) []byte { return userRe.ReplaceAll(san(b), []byte("devuser")) }, nil
}

var cwdRe = regexp.MustCompile(`"cwd":"([^"]*)"`)

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var hashRe = regexp.MustCompile(`"projectHash":"[^"]*"`)

// geminiHashes rewrites every chat head's projectHash (a 64-hex value mark1-redact's high-entropy rule tokenizes) to sha256 of its slug's sanitized .project_root, so the tailer's marker attribution still resolves.
func geminiHashes(root string) error {
	markers, _ := filepath.Glob(filepath.Join(root, "tmp", "*", ".project_root"))
	for _, m := range markers {
		raw, err := os.ReadFile(m)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(strings.TrimSpace(string(raw))))
		want := hex.EncodeToString(sum[:])
		chats, _ := filepath.Glob(filepath.Join(filepath.Dir(m), "chats", "*.jsonl"))
		for _, c := range chats {
			b, err := os.ReadFile(c)
			if err != nil {
				return err
			}
			b = hashRe.ReplaceAll(b, []byte(`"projectHash":"`+want+`"`))
			if err := os.WriteFile(c, b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// identityGrep is the selfcheck.py FORBIDDEN rule run before anything is frozen: the home path and user must be gone.
func identityGrep(out, home string) error {
	needles := [][]byte{[]byte(home)}
	if u, err := user.Current(); err == nil && len(u.Username) > 3 {
		needles = append(needles, []byte(strings.ToLower(u.Username)))
	}
	return filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lower := bytes.ToLower(b)
		for _, n := range needles {
			if len(n) > 0 && (bytes.Contains(b, n) || bytes.Contains(lower, n)) {
				return fmt.Errorf("%s still carries %q after sanitization; refusing to freeze", p, n)
			}
		}
		return nil
	})
}

// carrySelfcheck copies the newest pinned selfcheck.py forward with its version string swapped, like the driven recorder.
func carrySelfcheck(root, out, version string) error {
	ents, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") && e.Name() != "v"+version {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no prior pin under %s", root)
	}
	sort.Strings(names)
	prev := strings.TrimPrefix(names[len(names)-1], "v")
	b, err := os.ReadFile(filepath.Join(root, "v"+prev, "selfcheck.py"))
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(out, "selfcheck.py"), bytes.ReplaceAll(b, []byte(prev), []byte(version)))
}

func harvestReadme(agent, version string, notes []string) string {
	return fmt.Sprintf("# `%s` fixtures, agent version **%s** (HARVESTED, not yet pinned)\n\n"+
		"Harvested on %s by `mark1 corpus record --agent %s` from the installed `%s %s`: the on-disk artifacts\n"+
		"its tailer reads, copied from the recording machine after redaction. Hook bodies are NOT here (the shim\n"+
		"never persists a plaintext payload; transcribe them from the vendor bundle or capture them by hand), and\n"+
		"`transcripts/expectations.json` is still to be derived by `selfcheck.py`'s rules. Until both land and the\n"+
		"version joins `SupportedVersions`, this directory pins nothing. **Frozen once pinned** (12 §3.2).\n\n"+
		"## Redaction (normative, applied mechanically)\n\n"+
		"1. Identity substitution: the recording workspace → `%s`, the home directory → `/home/devuser`, the user\n"+
		"   name → `devuser`, e-mail addresses → `devuser@example.com`; every UUID and every `msg_`/`req_`/`toolu_`/\n"+
		"   `resp_`/`call_`/`prt_`/`ses_`/`rs_`/`fc_` id → a stable synthetic one (paths included, so file names and\n"+
		"   contents agree); gemini `projectHash` re-derived from the sanitized `.project_root`.\n"+
		"2. mark1-redact admit axis (the same rule table as `rust/mark1-redact`, via `go/mark1d/internal/redact`):\n"+
		"   every credential-shaped span becomes `⟨redacted:class:hash⟩`, hash = HMAC(fixed corpus key, span).\n"+
		"   A scanner quarantine aborts the harvest; raw bytes are never written.\n"+
		"3. The recorder greps the result for the home path and user name and refuses to freeze on a hit.\n\n"+
		"## Harvest notes\n\n- %s\n",
		agent, version, time.Now().UTC().Format("2006-01-02"), agent, agent, version, synthRoot, strings.Join(notes, "\n- "))
}
