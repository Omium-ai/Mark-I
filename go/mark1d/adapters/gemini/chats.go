package gemini

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// chatsFormat is the Usage reader over the CLI's chat recordings
// (core/src/services/chatRecordingService.ts at the pin): one JSON record per
// line — a metadata head `{sessionId, projectHash, …}`, then MessageRecords. A
// `gemini` message carries `tokens` (TokensSummary) once its response
// completed and is re-appended whole under the same `id` when tool calls
// attach, so the key is (message id, session) with last line wins — the
// streaming-rewrite rule the tailer already enforces. Layout:
// ~/.gemini/tmp/<slug>/chats/session-<ts>-<id8>.jsonl for the main agent and
// chats/<parentSessionId>/<agentId>.jsonl for subagents; the slug's
// .project_root marker names the project root verbatim (projectRegistry.ts).
func chatsFormat(root string) tailers.Format {
	c := &chats{root: root, hashes: map[string]string{}, heads: map[string]uuid.UUID{}}
	return tailers.Format{Discover: c.discover, Cwd: c.cwd, NewParser: newChatParser}
}

type chats struct {
	root   string
	hashes map[string]string    // sha256(marker) → marker, for every slug whose marker is root
	heads  map[string]uuid.UUID // stream path → its metadata sessionId
}

// discover admits only slugs whose .project_root is the enabled root: Gemini
// keeps ONE tmp tree for every project, so the marker is the containment
// evidence a directory name cannot be.
func (c *chats) discover(dir string, open func(path string, role tailers.Role, session uuid.UUID)) {
	slugs(dir, func(marker, chatsDir string) {
		if !sameDir(marker, c.root) {
			return
		}
		c.hashes[projectHash(marker)] = marker
		parents, _ := filepath.Glob(filepath.Join(chatsDir, "session-*.jsonl"))
		for _, p := range parents {
			if id, ok := c.head(p); ok {
				open(p, tailers.RoleParent, id)
			}
		}
		subs, _ := filepath.Glob(filepath.Join(chatsDir, "*", "*.jsonl"))
		for _, s := range subs {
			if parent, err := uuid.Parse(filepath.Base(filepath.Dir(s))); err == nil {
				open(s, tailers.RoleSubagent, parent)
			}
		}
	})
}

// slugs visits every project slug under the tmp tree that carries a .project_root marker.
func slugs(dir string, visit func(marker, chatsDir string)) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		slug := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(filepath.Join(slug, ".project_root"))
		if err != nil {
			continue
		}
		visit(strings.TrimSpace(string(raw)), filepath.Join(slug, "chats"))
	}
}

// recentProjects reads every slug's marker into one hash table, then resolves each main chat's projectHash through it, newest chat first.
func recentProjects(tmp string, limit int) []string {
	c := &chats{hashes: map[string]string{}}
	var paths []string
	slugs(tmp, func(marker, chatsDir string) {
		c.hashes[projectHash(marker)] = marker
		p, _ := filepath.Glob(filepath.Join(chatsDir, "session-*.jsonl"))
		paths = append(paths, p...)
	})
	return tailers.RecentCwds(paths, c.cwd, limit)
}

// projectHash is utils/paths.ts getProjectHash: sha256 hex of the root string.
func projectHash(root string) string {
	s := sha256.Sum256([]byte(root))
	return hex.EncodeToString(s[:])
}

func sameDir(a, b string) bool { return normDir(a) == normDir(b) }

func normDir(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

const headMaxLine = 1 << 20

// head reads a main stream's metadata line for its full sessionId (the file
// name carries only 8 characters of it); a torn head is retried next sweep.
func (c *chats) head(path string) (uuid.UUID, bool) {
	if id, ok := c.heads[path]; ok {
		return id, true
	}
	f, err := os.Open(path)
	if err != nil {
		return uuid.UUID{}, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4<<10), headMaxLine)
	if !sc.Scan() {
		return uuid.UUID{}, false
	}
	var meta struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(sc.Bytes(), &meta) != nil {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(meta.SessionID)
	if err != nil {
		return uuid.UUID{}, false
	}
	c.heads[path] = id
	return id, true
}

// cwd attributes a stream by its metadata projectHash: only a hash of a
// marker discover admitted resolves, so a stream filed under the right slug
// with the wrong hash stays unattributable rather than assumed.
func (c *chats) cwd(line []byte) string {
	var meta struct {
		SessionID   string `json:"sessionId"`
		ProjectHash string `json:"projectHash"`
	}
	if json.Unmarshal(line, &meta) != nil || meta.SessionID == "" {
		return ""
	}
	return c.hashes[meta.ProjectHash]
}

type chatLine struct {
	SessionID string `json:"sessionId"` // metadata head only
	ID        string `json:"id"`
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Model     string `json:"model"`
	Tokens    *struct {
		Input    uint64 `json:"input"`
		Output   uint64 `json:"output"`
		Cached   uint64 `json:"cached"`
		Thoughts uint64 `json:"thoughts"`
	} `json:"tokens"`
}

// newChatParser keeps the head's sessionId: this surface has no per-request
// id, so request_id is "chat:<sessionId>" (the exec-stream precedent) and the
// vendor message id is the unique half of the key. Gemini's input count
// INCLUDES cached tokens (mapped verbatim, like OpenAI's); thoughts are
// billed as output and folded into output_tokens.
func newChatParser() func(line []byte) (tailers.Line, bool) {
	session := ""
	return func(line []byte) (tailers.Line, bool) {
		var l chatLine
		if json.Unmarshal(line, &l) != nil {
			return tailers.Line{}, false
		}
		if l.ID == "" {
			if l.SessionID != "" {
				session = l.SessionID
			}
			return tailers.Line{}, false
		}
		if l.Type != "gemini" || l.Tokens == nil || session == "" {
			return tailers.Line{}, false
		}
		return tailers.Line{
			MessageID: l.ID, RequestID: "chat:" + session,
			Model: l.Model, Timestamp: l.Timestamp,
			InputTokens: l.Tokens.Input, OutputTokens: l.Tokens.Output + l.Tokens.Thoughts,
			CacheReadTokens: l.Tokens.Cached,
		}, true
	}
}
