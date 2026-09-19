// Package corpus is the recording lane (12 §3.2): drive the INSTALLED `claude`
// non-interactively through the v2.1.251 corpus's session shapes with the 08
// §8 fragment pointed at a capture command, sanitize per the corpus README,
// derive expectations.json by selfcheck.py's rules, and print the two Go
// constants that pin the result.
package corpus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
)

type Options struct {
	Agent     string        // claudecode (driven, the default) | codex | gemini | opencode | copilot (harvested)
	Out       string        // corpus root; empty is conformance/hooks/<agent>
	Since     time.Duration // harvest: only artifacts modified within this window
	Workspace string        // harvest: the real workspace root that becomes /home/devuser/workspace/acme-app
}

const (
	parentSession  = "aa000000-0000-4000-8000-000000000201"
	foreignSession = "aa000000-0000-4000-8000-000000000202"
	synthRoot      = "/home/devuser/workspace/acme-app"
	synthForeign   = "/home/devuser/workspace-acme-app"
	synthSlug      = "-home-devuser-workspace-acme-app"
)

// turns are the v2.1.251 README's parent session shapes: a plain reply, a
// multi-block response with a passing and a failing tool, a subagent, a
// compaction. Each is one `claude -p` process resumed into the same session.
var turns = []string{
	"Reply with exactly: ready",
	"In one response: write the sentence 'Running both checks.' and then call the Bash tool twice in that same response, once with `true` and once with `false`. After both return, reply with exactly: done",
	"Use the Agent tool with subagent_type general-purpose and the prompt 'Reply with exactly: 4'. Then reply with exactly what it returned.",
	"/compact",
}

var hookEvents = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop", "SubagentStop", "PreCompact", "SessionEnd"}

// Record dispatches: claude is driven through canonical turns; the file-based agents are harvested (harvest.go).
func Record(ctx context.Context, env *cli.Env, opts Options) error {
	if opts.Agent == "" {
		opts.Agent = "claudecode"
	}
	if opts.Out == "" {
		opts.Out = filepath.Join("conformance", "hooks", opts.Agent)
	}
	if opts.Agent != "claudecode" {
		return Harvest(env, opts)
	}
	return record(ctx, env, opts)
}

func record(ctx context.Context, env *cli.Env, opts Options) error {
	cc := &claudecode.Adapter{}
	d, err := cc.Detect()
	if err != nil || !d.Installed || d.Version == "" {
		return cli.Failf(cli.ExitRuntime, "", "claude not installed or unsniffable (installed=%v version=%q)", d.Installed, d.Version)
	}
	out := filepath.Join(opts.Out, "v"+d.Version)
	if _, err := os.Stat(out); err == nil {
		return cli.Failf(cli.ExitRefused, "", "%s exists — a recorded corpus is frozen (12 §3.2); remove it to re-record", out)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	tmp, err := os.MkdirTemp("", "mark1-corpus-")
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	r := &recording{env: env, tmp: tmp, home: home, ws: filepath.Join(tmp, "workspace", "acme-app"), foreign: filepath.Join(tmp, "workspace-acme-app")}
	if err := r.provision(); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "provision: %v", err)
	}
	vendorDir, err := cc.TranscriptDir(r.ws)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	defer func() { _ = os.RemoveAll(vendorDir) }()
	if fd, _ := cc.TranscriptDir(r.foreign); fd != vendorDir {
		return cli.Failf(cli.ExitRuntime, "", "munge collision lost: %s vs %s", vendorDir, fd)
	}
	for i, prompt := range turns {
		args := []string{"--session-id", parentSession}
		if i > 0 {
			args = []string{"--resume", parentSession}
		}
		if err := r.claude(ctx, r.ws, i+1, prompt, args...); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "turn %d: %v", i+1, err)
		}
	}
	if err := r.claude(ctx, r.foreign, len(turns)+1, "Reply with exactly: ok", "--session-id", foreignSession); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "foreign session: %v", err)
	}
	if err := r.write(out, vendorDir, d.Version, opts.Out); err != nil {
		if errors.Is(err, errSelfcheck) {
			// The recording is complete and sanitized; only the reference check disagrees. Keep it, so the disagreement can be read instead of re-recorded.
			return cli.Failf(cli.ExitRuntime, "", "%v; the recording is kept at %s for inspection (delete it before recording again)", err, out)
		}
		_ = os.RemoveAll(out)
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	digest, n, err := digestCorpus(out)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "digest: %v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "recorded %s: %d evidence files\n%s\n", out, n, strings.Join(r.notes, "\n"))
	_, _ = fmt.Fprintf(env.Stdout, "\nadd to go/mark1d/adapters/claudecode/claudecode.go SupportedVersions:\n\t%q: {},\n", d.Version)
	_, _ = fmt.Fprintf(env.Stdout, "add to go/mark1d/adapters/claudecode/corpus_pin_test.go recordedCorpusDigest:\n\t%q: %q,\n", d.Version, digest)
	return nil
}

type recording struct {
	env                    *cli.Env
	tmp, home, ws, foreign string
	notes                  []string
}

// provision registers the nine 08 §5.1 hooks through the real fragment, with
// the shim command replaced by a capture script that files each stdin body.
func (r *recording) provision() error {
	for _, d := range []string{r.ws, r.foreign, filepath.Join(r.tmp, "bin"), filepath.Join(r.tmp, "hooks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	capture := filepath.Join(r.tmp, "bin", "mark1-hookshim")
	script := "#!/bin/sh\ncat > \"" + filepath.Join(r.tmp, "hooks") + "/$MARK1_CORPUS_TURN.$$.json\"\n"
	if err := os.WriteFile(capture, []byte(script), 0o700); err != nil { //nolint:gosec // G306: a hook command must be executable
		return err
	}
	settings := filepath.Join(r.tmp, "settings.json")
	if err := os.WriteFile(settings, []byte("{}\n"), 0o600); err != nil {
		return err
	}
	_, err := claudecode.ApplyFragment(settings, filepath.Join(r.tmp, "state"), capture)
	return err
}

func (r *recording) claude(ctx context.Context, cwd string, turn int, prompt string, args ...string) error {
	args = append([]string{"-p", prompt, "--settings", filepath.Join(r.tmp, "settings.json"), "--setting-sources", "",
		"--strict-mcp-config", "--max-budget-usd", "3", "--allowedTools", "Bash(true),Bash(false),Agent"}, args...)
	cmd := exec.CommandContext(ctx, "claude", args...) //nolint:gosec // G204: the operator's own `claude`, args are ours
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), fmt.Sprintf("MARK1_CORPUS_TURN=%d", turn))
	var outb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outb, r.env.Stderr
	_, _ = fmt.Fprintf(r.env.Stderr, "corpus: turn %d in %s: %s\n", turn, filepath.Base(cwd), prompt)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, outb.String())
	}
	return nil
}

// write lays the version directory: hook bodies (first-seen per event),
// sanitized transcripts, expectations.json, selfcheck.py and README.md, then
// runs selfcheck.py on the result.
func (r *recording) write(out, vendorDir, version, root string) error {
	san := r.sanitizer()
	hooks := map[string][]byte{}
	names, _ := filepath.Glob(filepath.Join(r.tmp, "hooks", "*.json"))
	sort.Strings(names)
	fired := map[string]int{}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		var body struct {
			Event string `json:"hook_event_name"`
		}
		if json.Unmarshal(b, &body) != nil || body.Event == "" {
			continue
		}
		fired[body.Event]++
		if _, ok := hooks[body.Event]; !ok {
			hooks[body.Event] = b
		}
	}
	for _, ev := range hookEvents {
		b, ok := hooks[ev]
		if !ok {
			r.notes = append(r.notes, "HOOK DID NOT FIRE: "+ev)
			continue
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, san(b), "", "  "); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(out, "hooks", ev+".json"), append(pretty.Bytes(), '\n')); err != nil {
			return err
		}
	}
	r.notes = append(r.notes, fmt.Sprintf("hook bodies fired: %v", fired))

	streams, err := r.transcripts(vendorDir, san, filepath.Join(out, "transcripts", synthSlug))
	if err != nil {
		return err
	}
	exp, err := deriveExpectations(version, streams)
	if err != nil {
		return err
	}
	eb, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, "transcripts", "expectations.json"), append(eb, '\n')); err != nil {
		return err
	}
	if err := r.copySelfcheck(root, out, version); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, "README.md"), []byte(readme(version, r.notes))); err != nil {
		return err
	}
	check := exec.Command("python3", "selfcheck.py") //nolint:gosec // G204: fixed argv
	check.Dir, check.Stdout, check.Stderr = out, r.env.Stderr, r.env.Stderr
	if err := check.Run(); err != nil {
		return fmt.Errorf("%w: %v", errSelfcheck, err)
	}
	return nil
}

var errSelfcheck = errors.New("selfcheck.py failed on the recording")

// sanitizer is the corpus README's rule as byte substitutions: the recording
// machine's paths and user become the placeholders, every UUID and vendor id
// becomes a stable synthetic one (the two session ids are synthetic already).
func (r *recording) sanitizer() func([]byte) []byte {
	munge := func(p string) string {
		d, _ := (&claudecode.Adapter{Home: "/"}).TranscriptDir(p)
		return filepath.Base(d)
	}
	return sanitizer([][2]string{
		{r.ws, synthRoot}, {r.foreign, synthForeign}, {munge(r.ws), synthSlug},
		{r.tmp, "/home/devuser"}, {munge(r.tmp), "-home-devuser"},
		{r.home, "/home/devuser"}, {munge(r.home), "-home-devuser"},
		{filepath.Base(r.home), "devuser"},
	}, parentSession, foreignSession)
}

var (
	uuidRe  = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	idRe    = regexp.MustCompile(`\b(msg|req|toolu|resp|call|prt|ses|rs|fc)_[A-Za-z0-9]{6,}`)
	hexRe   = regexp.MustCompile(`\b[0-9a-f]{16,17}\b`)
	emailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+(\.[\w-]+)+`)
)

// sanitizer applies fixed substitutions first, then stable synthetic ids; keep names the UUIDs left verbatim.
func sanitizer(fixed [][2]string, keep ...string) func([]byte) []byte {
	seen, counts := map[string]string{}, map[string]int{}
	synth := func(kind, s string, mk func(n int) string) string {
		if _, ok := seen[kind+s]; !ok {
			counts[kind]++
			seen[kind+s] = mk(counts[kind])
		}
		return seen[kind+s]
	}
	return func(b []byte) []byte {
		s := string(b)
		for _, f := range fixed {
			s = strings.ReplaceAll(s, f[0], f[1])
		}
		s = emailRe.ReplaceAllString(s, "devuser@example.com")
		s = uuidRe.ReplaceAllStringFunc(s, func(u string) string {
			if slices.Contains(keep, u) {
				return u
			}
			return synth("uuid", u, func(n int) string { return fmt.Sprintf("aa000000-0000-4000-8000-%012d", n) })
		})
		s = idRe.ReplaceAllStringFunc(s, func(id string) string {
			kind, _, _ := strings.Cut(id, "_")
			return synth(kind, id, func(n int) string { return fmt.Sprintf("%s_01SynthRecorded%08d", kind, n) })
		})
		s = hexRe.ReplaceAllStringFunc(s, func(h string) string {
			if !strings.ContainsAny(h, "abcdef") {
				return h // a 16–17 digit run with no letter is a number (2.1.278's cost-state totalCostUSD fraction), not an id
			}
			return synth("hex", h, func(n int) string { return "a7f3e2d1c0b9a8765a"[:len(h)-3] + fmt.Sprintf("%03d", n) })
		})
		return []byte(s)
	}
}

type stream struct {
	rel, role string
	lines     [][]byte
}

// transcripts copies every stream under the vendor dir into dst, dropping
// `attachment` lines (vendor context injection: system prompt, tool listings,
// the user's email — not evidence about the usage contract) and sanitizing
// the rest byte-for-byte.
func (r *recording) transcripts(vendorDir string, san func([]byte) []byte, dst string) ([]stream, error) {
	var streams []stream
	dropped, kinds := 0, map[string]int{}
	err := filepath.WalkDir(vendorDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(vendorDir, p)
		if strings.Contains("/"+filepath.ToSlash(rel)+"/", "/memory/") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var kept [][]byte
		if strings.HasSuffix(p, ".jsonl") {
			for _, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
				var l struct {
					Type string `json:"type"`
				}
				_ = json.Unmarshal(line, &l)
				if l.Type == "attachment" {
					dropped++
					continue
				}
				kinds[l.Type]++
				kept = append(kept, san(line))
			}
			b = append(bytes.Join(kept, []byte("\n")), '\n')
		} else {
			b = san(b)
		}
		relSan := string(san([]byte(rel)))
		if err := writeFile(filepath.Join(dst, relSan), b); err != nil {
			return err
		}
		if strings.HasSuffix(p, ".jsonl") {
			role := "parent"
			if strings.Contains(relSan, "/subagents/") {
				role = "subagent"
			} else if strings.HasPrefix(relSan, foreignSession) {
				role = "foreign"
			}
			streams = append(streams, stream{rel: "transcripts/" + synthSlug + "/" + relSan, role: role, lines: kept})
		}
		return nil
	})
	r.notes = append(r.notes, fmt.Sprintf("transcript lines kept by type: %v; attachment lines dropped: %d", kinds, dropped))
	return streams, err
}

type usageEvent struct {
	IdemKeyInputs map[string]string `json:"idem_key_inputs"`
	Usage         map[string]any    `json:"usage"`
	Model         string            `json:"model"`
}

type neverEmit struct {
	MessageID string `json:"message_id"`
	RequestID string `json:"request_id"`
	Reason    string `json:"reason"`
}

// txLine is the slice of a transcript line selfcheck.py reads.
type txLine struct {
	Type        string `json:"type"`
	IsSidechain bool   `json:"isSidechain"`
	RequestID   string `json:"requestId"`
	Cwd         string `json:"cwd"`
	SessionID   string `json:"sessionId"`
	Message     *struct {
		ID    string         `json:"id"`
		Model string         `json:"model"`
		Usage map[string]any `json:"usage"`
	} `json:"message"`
}

// emitted is selfcheck.py's emitted_usage: one Usage per (message.id,
// requestId), last line wins, first-seen order; a parent drops sidechain lines.
func emitted(lines [][]byte, role string) (events []usageEvent, skipped []neverEmit, order [][2]string, perKey map[[2]string][]uint64) {
	perKey = map[[2]string][]uint64{}
	last, seenSkip := map[[2]string]txLine{}, map[[2]string]bool{}
	for _, raw := range lines {
		var l txLine
		if json.Unmarshal(raw, &l) != nil || l.Type != "assistant" || l.Message == nil || l.Message.Usage == nil {
			continue
		}
		key := [2]string{l.Message.ID, l.RequestID}
		if role == "parent" && l.IsSidechain {
			if !seenSkip[key] {
				skipped = append(skipped, neverEmit{key[0], key[1], "sidechain replay in the parent transcript — 08 §5.1 sidechain rule; the origin stream owns this key"})
			}
			seenSkip[key] = true
			continue
		}
		if _, ok := last[key]; !ok {
			order = append(order, key)
		}
		last[key] = l
		out, _ := l.Message.Usage["output_tokens"].(float64)
		perKey[key] = append(perKey[key], uint64(out))
	}
	for _, key := range order {
		l := last[key]
		u := map[string]any{}
		for _, k := range []string{"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "service_tier"} {
			u[k] = l.Message.Usage[k]
		}
		events = append(events, usageEvent{
			IdemKeyInputs: map[string]string{"session_id": l.SessionID, "message_id": key[0], "request_id": key[1]},
			Usage:         u,
			Model:         l.Message.Model,
		})
	}
	return events, skipped, order, perKey
}

func deriveExpectations(version string, streams []stream) (map[string]any, error) {
	var outStreams, foreign []map[string]any
	var overcount map[string]any
	for _, s := range streams {
		events, skipped, order, perKey := emitted(s.lines, "parent")
		if s.role == "subagent" {
			events, skipped, _, _ = emitted(s.lines, "subagent")
		}
		if len(events) == 0 {
			return nil, fmt.Errorf("%s: no usage lines recorded", s.rel)
		}
		if s.role == "foreign" {
			var l txLine
			for _, raw := range s.lines {
				if json.Unmarshal(raw, &l) == nil && l.Cwd != "" {
					break
				}
			}
			foreign = append(foreign, map[string]any{
				"file": s.rel, "cwd": l.Cwd, "never_emit_message_id": events[0].IdemKeyInputs["message_id"],
				"reason": "munged-dir collision: " + synthForeign + " and " + synthRoot + " map to the SAME vendor directory, so this foreign session shares the enabled workspace's transcript dir. Invariant 3 (04 §0.3) + 04 §2.1: its cwd resolves outside the enabled root, so the stream is never tailed and none of its keys ever emit.",
			})
			continue
		}
		if skipped == nil {
			skipped = []neverEmit{}
		}
		row := map[string]any{"file": s.rel, "role": s.role, "usage_events": events, "never_emit": skipped}
		if s.role == "parent" {
			outStreams = append([]map[string]any{row}, outStreams...)
			for _, key := range order {
				outs := perKey[key]
				if overcount != nil && len(outs) <= overcount["streamed_lines"].(int) {
					continue
				}
				var sum uint64
				for _, o := range outs {
					sum += o
				}
				overcount = map[string]any{
					"message_id": key[0], "request_id": key[1], "streamed_lines": len(outs),
					"naive_per_line_output_token_sum": sum, "correct_output_tokens": outs[len(outs)-1],
					"min_overcount_ratio_asserted": 2.0,
					"why":                          "NFR-CORRECTNESS-001 / 07 §7: emitting per line is the verified overcount; one Usage per (message.id, requestId), last line wins",
				}
			}
		} else {
			outStreams = append(outStreams, row)
		}
	}
	if overcount == nil || overcount["streamed_lines"].(int) < 2 {
		return nil, errors.New("no (message.id, requestId) key was written on more than one line — the overcount case did not record; re-run")
	}
	if len(foreign) == 0 || len(outStreams) < 2 {
		return nil, fmt.Errorf("recorded %d streams and %d foreign — need parent, subagent and foreign", len(outStreams), len(foreign))
	}
	return map[string]any{
		"suite": "conf_hooks_claudecode_" + version + "_replay", "agent": "claudecode", "agent_version": version,
		"idem_key_recipe":          "idem_key = HMAC_tenant(session_id, message_id, request_id) — 07 §7 / 08 §5.1; session_id is the PARENT sessionId for subagent streams too (04 §2.1)",
		"workspace_root":           synthRoot,
		"out_of_workspace_streams": foreign,
		"streams":                  outStreams,
		"overcount_case":           overcount,
	}, nil
}

// copySelfcheck carries the checker forward verbatim from the newest pinned
// version: same rules, so the new corpus is judged exactly as the old one.
func (r *recording) copySelfcheck(root, out, version string) error {
	ents, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var src string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") && e.Name() != "v"+version {
			src = filepath.Join(root, e.Name(), "selfcheck.py")
		}
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("no prior selfcheck.py to carry forward: %w", err)
	}
	prev := strings.TrimPrefix(filepath.Base(filepath.Dir(src)), "v")
	return writeFile(filepath.Join(out, "selfcheck.py"), bytes.ReplaceAll(b, []byte(prev), []byte(version)))
}

func readme(version string, notes []string) string {
	return fmt.Sprintf(`# `+"`claudecode`"+` hook + transcript fixtures — pinned agent version **%s**

RECORDED (not transcribed) on %s by `+"`mark1 corpus record`"+` from the installed `+"`claude %s`"+`:
the nine 08 §5.1 hooks registered through the real fragment (`+"`claudecode.ApplyFragment`"+`) with the
shim command replaced by a capture script, so every `+"`hooks/*.json`"+` is the exact stdin body the
vendor sent; transcripts are the on-disk `+"`~/.claude/projects/<munged-cwd>/`"+` files the sessions
wrote. Session shapes follow the v2.1.251 README: a parent (plain reply, multi-block response with
a passing and a failing Bash call, a subagent turn, `+"`/compact`"+`), the subagent's own stream, and a
munge-colliding foreign-workspace session. **Frozen** per 12 §3.2.

## Sanitization (the v2.1.251 rule, applied mechanically)

Recording-machine paths and user → `+"`/home/devuser`"+` / `+"`acme-app`"+`; every UUID, `+"`msg_`"+`/`+"`req_`"+`/`+"`toolu_`"+`
id and agent id → a stable synthetic one; `+"`attachment`"+` transcript lines (vendor context injection:
system prompt snapshot, tool/skill listings, session context) are dropped — they are not evidence
about the usage contract and carry the recording machine's identity. Every other line is kept
byte-for-byte after substitution. `+"`selfcheck.py`"+` is carried forward verbatim and passed on this tree.

## Recording notes

%s
`, version, time.Now().UTC().Format("2006-01-02"), version, "- "+strings.Join(notes, "\n- "))
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// digestCorpus mirrors corpus_pin_test.digestCorpus: sha256 over sorted
// (relative path, file sha256) pairs, README.md and selfcheck.py exempt.
func digestCorpus(dir string) (string, int, error) {
	var rels []string
	sums := map[string][sha256.Size]byte{}
	err := fs.WalkDir(os.DirFS(dir), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "README.md" || d.Name() == "selfcheck.py" {
			return err
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		rels = append(rels, rel)
		sums[rel] = sha256.Sum256(b)
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(rels)
	h := sha256.New()
	for _, rel := range rels {
		_, _ = fmt.Fprintf(h, "%s\n%x\n", rel, sums[rel])
	}
	return hex.EncodeToString(h.Sum(nil)), len(rels), nil
}
