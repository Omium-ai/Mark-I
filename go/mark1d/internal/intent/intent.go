// Package intent is the task's own text, read locally from the agent's on-disk transcript of an enabled workspace (Claude Code here; Codex, Gemini, Copilot and opencode add their Source from their adapter), redacted and capped; it lives in memory only and never reaches the wire or the spool.
package intent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

const (
	MaxBytes = 4 << 10
	// openSlack absorbs the gap between the hook's event reaching the daemon and Claude Code writing the prompt line.
	openSlack = 5 * time.Second
	maxTasks  = 4096
	keepFor   = 24 * time.Hour
	tailBytes = 1389
)

type opened struct {
	session [16]byte
	at      time.Time
}

// Source is one agent's transcript: Find names the session's file (with the cwd its location already attests, else ""); Line reads one line's cwd, human prompt and time (zero values when absent).
type Source struct {
	Find func(session uuid.UUID) (path, cwd string, ok bool)
	Line func(line []byte) (cwd, prompt string, at time.Time)
}

type Provider struct {
	// Sources are tried in order (Claude Code's first); Allowed is the enabled-workspace oracle over a transcript's own cwd; Scanner redacts (nil ⇒ no intent, never raw text).
	Sources []Source
	Allowed func(cwd string) bool
	Scanner *redact.Scanner

	mu    sync.Mutex
	tasks map[[16]byte]opened
}

// New reads Claude Code transcripts under projects (~/.claude/projects); callers append the other agents' Sources before the first Observe.
func New(projects string, allowed func(string) bool, sc *redact.Scanner) *Provider {
	return &Provider{Sources: []Source{ClaudeCode(projects)}, Allowed: allowed, Scanner: sc, tasks: map[[16]byte]opened{}}
}

// ClaudeCode is the Source over ~/.claude/projects/<slug>/<session>.jsonl.
func ClaudeCode(projects string) Source {
	return Source{
		Find: func(session uuid.UUID) (string, string, bool) {
			m, _ := filepath.Glob(filepath.Join(projects, "*", session.String()+".jsonl"))
			if len(m) == 0 {
				return "", "", false
			}
			return m[0], "", true
		},
		Line: func(b []byte) (string, string, time.Time) {
			var l line
			if json.Unmarshal(b, &l) != nil {
				return "", "", time.Time{}
			}
			t, _ := l.human()
			return l.Cwd, t, l.Timestamp
		},
	}
}

// Observe records each TaskOpen's session and time: the task boundary the opening prompt is read against.
func (p *Provider) Observe(ev *m1pv1.Event) {
	if ev.GetTaskOpen() == nil || len(ev.GetTaskId()) != 16 || len(ev.GetSessionId()) != 16 || ev.GetOccurredAt() == nil {
		return
	}
	var task [16]byte
	o := opened{at: ev.GetOccurredAt().AsTime()}
	copy(task[:], ev.GetTaskId())
	copy(o.session[:], ev.GetSessionId())
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.tasks) >= maxTasks {
		for k, v := range p.tasks {
			if time.Since(v.at) > keepFor {
				delete(p.tasks, k)
			}
		}
		if len(p.tasks) >= maxTasks {
			clear(p.tasks)
		}
	}
	p.tasks[task] = o
}

// Intent is the prompt that opened task (session zero ⇒ the session recorded at TaskOpen): the last human prompt written at or before the task opened.
func (p *Provider) Intent(session, task [16]byte) (string, bool) {
	p.mu.Lock()
	o, ok := p.tasks[task]
	p.mu.Unlock()
	if !ok || p.Scanner == nil || p.Allowed == nil {
		return "", false
	}
	if session != ([16]byte{}) && session != o.session {
		return "", false
	}
	raw, ok := p.read(o)
	if !ok {
		return "", false
	}
	out, outcome, _ := p.Scanner.Admit([]byte(raw))
	if outcome == redact.Quarantine {
		return "", false
	}
	return capBytes(string(out)), true
}

func (p *Provider) read(o opened) (string, bool) {
	for _, src := range p.Sources {
		if path, cwd, ok := src.Find(uuid.UUID(o.session)); ok {
			return p.readFile(src, path, cwd, o.at.Add(openSlack))
		}
	}
	return "", false
}

// readFile is the last human prompt at or before cut; the first cwd seen (or the one Find attested) must be an enabled workspace, or nothing is read.
func (p *Provider) readFile(src Source, path, cwd string, cut time.Time) (string, bool) {
	checked := cwd != ""
	if checked && !p.Allowed(cwd) {
		return "", false
	}
	f, err := os.Open(path) //nolint:gosec // G304: the session's own transcript, named by its agent's Source
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	task := ""
	for sc.Scan() {
		c, prompt, at := src.Line(sc.Bytes())
		if !checked && c != "" {
			if !p.Allowed(c) {
				return "", false
			}
			checked = true
		}
		if at.After(cut) {
			break
		}
		if prompt != "" {
			task = prompt
		}
	}
	return task, checked && task != ""
}

type line struct {
	Type        string          `json:"type"`
	Cwd         string          `json:"cwd"`
	IsMeta      bool            `json:"isMeta"`
	IsSidechain bool            `json:"isSidechain"`
	Timestamp   time.Time       `json:"timestamp"`
	ToolResult  json.RawMessage `json:"toolUseResult"`
	Message     struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

// human is the person's own prompt text: tool results, injected meta turns and subagent lines are never intent.
func (l line) human() (string, bool) {
	if l.Type != "user" || l.IsMeta || l.IsSidechain || len(l.ToolResult) > 0 {
		return "", false
	}
	var s string
	if json.Unmarshal(l.Message.Content, &s) == nil {
		return s, s != ""
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(l.Message.Content, &blocks) != nil || len(blocks) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		if b.Type != "text" {
			return "", false
		}
		parts = append(parts, b.Text)
	}
	return strings.Join(parts, "\n"), true
}

// capBytes keeps head and tail (the shape rm-input/v1 truncates to) within MaxBytes, cut on rune boundaries.
func capBytes(s string) string {
	if len(s) <= MaxBytes {
		return s
	}
	const mark = "\n[...]\n"
	head := s[:MaxBytes-tailBytes-len(mark)]
	for !utf8.ValidString(head) {
		head = head[:len(head)-1]
	}
	tail := s[len(s)-tailBytes:]
	for !utf8.ValidString(tail) {
		tail = tail[1:]
	}
	return head + mark + tail
}
