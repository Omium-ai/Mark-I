package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

const maxBody = 1 << 16

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.agents()) })
	mux.HandleFunc("POST /v1/agents/{name}/provision", s.provisionAgent)
	mux.HandleFunc("POST /v1/agents/{name}/disable", s.disableAgent)
	mux.HandleFunc("POST /v1/agents/{name}/pause", func(w http.ResponseWriter, r *http.Request) { s.setAgentOff(w, r, true) })
	mux.HandleFunc("POST /v1/agents/{name}/resume", func(w http.ResponseWriter, r *http.Request) { s.setAgentOff(w, r, false) })
	mux.HandleFunc("GET /v1/projects", s.getProjects)
	mux.HandleFunc("POST /v1/projects", s.postProject)
	mux.HandleFunc("DELETE /v1/projects", s.deleteProject)
	mux.HandleFunc("GET /v1/anchors", s.getAnchors)
	mux.HandleFunc("POST /v1/anchors/consent", s.postConsent)
	mux.HandleFunc("GET /v1/optins", s.getOptIns)
	mux.HandleFunc("PUT /v1/optins", s.putOptIns)
	mux.HandleFunc("POST /v1/pause", func(w http.ResponseWriter, _ *http.Request) { s.setOff(w, true) })
	mux.HandleFunc("POST /v1/resume", func(w http.ResponseWriter, _ *http.Request) { s.setOff(w, false) })
	mux.HandleFunc("GET /v1/doctor", s.doctor)
	mux.HandleFunc("GET /v1/plan", s.plan)
	mux.HandleFunc("POST /v1/shutdown", s.postShutdown)
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("GET /v1/receipts", s.receipts)
	mux.HandleFunc("POST /v1/receipts/verify", s.verifyReceipts)
	mux.HandleFunc("GET /v1/verify/events", s.verifyEvents)
	mux.HandleFunc("POST /v1/enroll/keygen", s.keygen)
	mux.HandleFunc("POST /v1/enroll", s.postEnroll)
	mux.HandleFunc("GET /v1/enroll", s.getEnroll)
	mux.HandleFunc("DELETE /v1/enroll", s.deleteEnroll)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		refuse(w, http.StatusNotFound, "M1E-2001", "no such control route")
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "body: "+err.Error())
		return false
	}
	return true
}

func internal(w http.ResponseWriter, err error) {
	refuse(w, http.StatusInternalServerError, "M1E-9500", err.Error())
}

func osUser() (name, uid string) {
	if u, err := user.Current(); err == nil {
		return u.Username, u.Uid
	}
	return "", ""
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	roots, _ := s.workspaces()
	spoolBytes := int64(0)
	if entries, err := os.ReadDir(s.cfg.SpoolDir); err == nil {
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && !e.IsDir() && filepath.Ext(e.Name()) == ".m1s" {
				spoolBytes += fi.Size()
			}
		}
	}
	enabled := make([]string, 0, len(roots.Workspaces))
	for _, e := range roots.Workspaces {
		enabled = append(enabled, e.Path)
	}
	writeJSON(w, map[string]any{
		"running":          true,
		"paused":           off.Off(s.cfg.StateDir),
		"version":          s.cfg.Version,
		"since":            s.since.UTC().Format(time.RFC3339),
		"agents_live":      s.markPaused(s.hub.live(s.projectOf(enabled))),
		"projects_enabled": enabled,
		"spool":            map[string]any{"bytes": spoolBytes, "cap": s.cfg.SpoolCap, "hard_stop": s.hardStop.Load()},
	})
}

// plan is the Claude plan tier and rate-limit windows, from local files only (adapters/claudecode/plan.go).
func (s *Server) plan(w http.ResponseWriter, _ *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		internal(w, err)
		return
	}
	p, err := claudecode.ReadPlan(home, s.cfg.StateDir)
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, p)
}

// projectOf is the hub's fallback after its session resolver (tailers.Resolve): it joins a live session to the enabled root whose Claude Code transcript names it, since that session id IS the transcript file name and the head carries the cwd the hookshim's SessionStart does not (08 §5.1). The other adapters derive session ids, so only their tailers can attribute them.
func (s *Server) projectOf(roots []string) func(agent string, sid [16]byte) string {
	return func(agent string, sid [16]byte) string {
		if agent != "claudecode" {
			return ""
		}
		name := uuid.UUID(sid).String() + ".jsonl"
		for _, root := range roots {
			dir, err := (&claudecode.Adapter{}).TranscriptDir(root)
			if err != nil {
				continue
			}
			if cwd, ok := streamCwd(filepath.Join(dir, name)); ok && within(root, cwd) {
				return root
			}
		}
		return ""
	}
}

// LocateClaude finds a session's transcript under any ~/.claude/projects/* dir (an unwatched session lives outside every enabled root, so the tailers never met it) and answers its first cwd: the session's own root, which the hook's shell cwd is not.
func LocateClaude(sid [16]byte) (agent, cwd string, ok bool) {
	dir, err := (&claudecode.Adapter{}).TranscriptDir("/")
	if err != nil {
		return "", "", false
	}
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		return "", "", false
	}
	name := uuid.UUID(sid).String() + ".jsonl"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if cwd, ok := streamCwd(filepath.Join(filepath.Dir(dir), e.Name(), name)); ok {
			return "claudecode", cwd, true
		}
	}
	return "", "", false
}

// isWSLShare: a Windows path into a WSL distro's filesystem (\\wsl.localhost\… or \\wsl$\…).
func isWSLShare(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, "/", "\\"))
	return strings.HasPrefix(l, `\\wsl.localhost\`) || strings.HasPrefix(l, `\\wsl$\`)
}

// within is the tailer's own containment oracle (enabled root + .mark1ignore), so attribution never claims a stream capture would refuse.
func within(root, cwd string) bool {
	set, err := tailers.NewWorkspaceSet(root)
	return err == nil && set.Allowed(cwd)
}

// streamCwd reads a transcript head for its first cwd, as tailers.peekCwd does for discovery.
func streamCwd(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 0; sc.Scan() && n < 64; n++ {
		var l struct {
			Cwd string `json:"cwd"`
		}
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Cwd != "" {
			return l.Cwd, true
		}
	}
	return "", false
}

// sessionTrees are the vendor session trees whose stream heads name a cwd, by agent; cursor's is always empty (hooks only).
func (s *Server) sessionTrees() map[string]func(limit int) []string {
	d := s.cfg.StateDir
	return map[string]func(int) []string{
		"codex":    (&codex.Adapter{StateDir: d}).RecentProjects,
		"gemini":   (&gemini.Adapter{StateDir: d}).RecentProjects,
		"opencode": (&opencode.Adapter{StateDir: d}).RecentProjects,
		"copilot":  (&copilot.Adapter{StateDir: d}).RecentProjects,
		"cursor":   (&cursor.Adapter{StateDir: d}).RecentProjects,
	}
}

// agentsSeen is what the daemon has observed working in root: live sessions attributed there, plus every on-disk session tree (Claude Code's per-root transcripts, the other vendors' shared trees) naming a cwd the root's oracle admits. Never inferred from provisioning.
// ponytail: one full tree scan per vendor per project row; memoize per request if GET /v1/projects ever reads slow.
func (s *Server) agentsSeen(root string) []string {
	seen := map[string]bool{}
	for _, ls := range s.hub.live(s.projectOf([]string{root})) {
		if ls.Project == root {
			seen[ls.Agent] = true
		}
	}
	if dir, err := (&claudecode.Adapter{}).TranscriptDir(root); err == nil {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
				continue
			}
			if cwd, ok := streamCwd(filepath.Join(dir, e.Name())); ok && within(root, cwd) {
				seen["claudecode"] = true
				break
			}
		}
	}
	for name, recent := range s.sessionTrees() {
		if seen[name] {
			continue
		}
		for _, cwd := range recent(0) {
			if within(root, cwd) {
				seen[name] = true
				break
			}
		}
	}
	out := slices.Sorted(maps.Keys(seen))
	if out == nil {
		out = []string{}
	}
	return out
}

type fragment struct {
	Agent     string            `json:"agent"`
	Fragment  string            `json:"fragment"`
	Mechanism string            `json:"mechanism"`
	Manifest  string            `json:"manifest"`
	Target    string            `json:"target"`
	State     string            `json:"state"`
	Detail    string            `json:"detail"`
	Lines     []json.RawMessage `json:"lines"`
}

// fragments classifies every provisioned fragment through the adapter engine that wrote it (08 §7.4).
func (s *Server) fragments() []fragment {
	var out []fragment
	add := func(manifest string, inspect func() (any, error)) {
		if _, err := os.Stat(manifest); err != nil {
			return
		}
		st, err := inspect()
		b, _ := json.Marshal(st)
		var f fragment
		_ = json.Unmarshal(b, &f)
		if err != nil {
			f.State, f.Detail = "FRAGMENT-DAMAGED", err.Error()
		}
		if f.Lines == nil {
			f.Lines = []json.RawMessage{}
		}
		out = append(out, f)
	}
	d := s.cfg.StateDir
	add(claudecode.ManifestPath(d), func() (any, error) { return claudecode.Inspect(d) })
	add(claudecode.BaseURLManifestPath(d), func() (any, error) { return claudecode.InspectBaseURL(d) })
	add(codex.ManifestPath(d), func() (any, error) { return codex.Inspect(d) })
	add(gemini.ManifestPath(d), func() (any, error) { return gemini.Inspect(d) })
	add(opencode.ManifestPath(d), func() (any, error) { return opencode.Inspect(d) })
	add(copilot.ManifestPath(d), func() (any, error) { return copilot.Inspect(d) })
	add(cursor.ManifestPath(d), func() (any, error) { return cursor.Inspect(d) })
	return out
}

// ponytail: six `--version` execs per call (~3 s on a dev box, same as `mark1 doctor`); cache on PATH mtime if the app ever polls this.
func (s *Server) agents() []map[string]any {
	d := s.cfg.StateDir
	cc, cx := &claudecode.Adapter{StateDir: d}, &codex.Adapter{StateDir: d}
	gm, oc, cp := &gemini.Adapter{StateDir: d}, &opencode.Adapter{StateDir: d}, &copilot.Adapter{StateDir: d}
	detect := map[string]func() (adapters.Detection, func(string) compatVerdict){
		"claudecode": func() (adapters.Detection, func(string) compatVerdict) {
			return must(cc.Detect()), s.memoCompat("claudecode", cc.Compatibility)
		},
		"codex": func() (adapters.Detection, func(string) compatVerdict) {
			return must(cx.Detect()), s.memoCompat("codex", cx.Compatibility)
		},
		"gemini": func() (adapters.Detection, func(string) compatVerdict) {
			return must(gm.Detect()), s.memoCompat("gemini", gm.Compatibility)
		},
		"opencode": func() (adapters.Detection, func(string) compatVerdict) {
			return must(oc.Detect()), s.memoCompat("opencode", oc.Compatibility)
		},
		"copilot": func() (adapters.Detection, func(string) compatVerdict) {
			return must(cp.Detect()), s.memoCompat("copilot", cp.Compatibility)
		},
		"cursor": func() (adapters.Detection, func(string) compatVerdict) {
			cu := &cursor.Adapter{StateDir: d}
			return must(cu.Detect()), s.memoCompat("cursor", cu.Compatibility)
		},
	}
	frags := s.fragments()
	trees := s.sessionTrees()
	out := make([]map[string]any, 0, len(adapters.Roster))
	for _, slot := range adapters.Roster {
		row := map[string]any{"name": slot.Name, "installed": false, "version": nil, "compat": nil, "probe": nil, "regime": nil, "provisioned": nil, "recent_projects": []string{}, "paused": off.AgentOff(d, slot.Name)}
		det, ok := detect[slot.Name]
		if !ok {
			out = append(out, row)
			continue
		}
		dt, compat := det()
		row["installed"] = dt.Installed
		if dt.Installed {
			v := compat(dt.Version)
			row["compat"] = v.compat
			if v.probe != "" {
				row["probe"] = v.probe
			}
			if dt.Version != "" {
				row["version"] = dt.Version
			}
			if slot.Name == "claudecode" {
				row["recent_projects"] = claudeRecentProjects()
			} else if recent := trees[slot.Name]; recent != nil {
				row["recent_projects"] = recent(0)
			}
		}
		row["regime"] = "subscription"
		if dt.Regime == adapters.RegimeAPIKey {
			row["regime"] = "apikey"
		}
		var files []map[string]any
		notes := []string{}
		mechanism := ""
		for _, f := range frags {
			if f.Agent != slot.Name {
				continue
			}
			mechanism = f.Mechanism
			// byte_equal_revert is Revert's verbatim path: the post-image still matches, so the pre-image comes back byte-for-byte (08 §8.4 step 2).
			files = append(files, map[string]any{"path": f.Target, "lines_added": len(f.Lines), "byte_equal_revert": f.State == string(claudecode.StateOK)})
			if f.State != string(claudecode.StateOK) {
				notes = append(notes, f.Fragment+": "+f.State)
			}
			if f.Detail != "" {
				notes = append(notes, f.Detail)
			}
		}
		if files != nil {
			row["provisioned"] = map[string]any{"mechanism": mechanism, "files": files, "notes": notes}
		}
		out = append(out, row)
	}
	return out
}

func must(d adapters.Detection, _ error) adapters.Detection { return d }

// claudeRecentProjects reads the cwd each ~/.claude/projects/<munged> tree's transcripts name, newest tree first — the munge is lossy, so the head line is the only honest root. The other vendors' readers are their adapters' RecentProjects (sessionTrees).
func claudeRecentProjects() []string {
	out := []string{}
	home, err := os.UserHomeDir()
	if err != nil {
		return out
	}
	base := filepath.Join(home, ".claude", "projects")
	entries, _ := os.ReadDir(base)
	type dir struct {
		path string
		mod  time.Time
	}
	dirs := make([]dir, 0, len(entries))
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && e.IsDir() {
			dirs = append(dirs, dir{filepath.Join(base, e.Name()), fi.ModTime()})
		}
	}
	slices.SortFunc(dirs, func(a, b dir) int { return b.mod.Compare(a.mod) })
	for _, d := range dirs {
		files, _ := os.ReadDir(d.path)
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".jsonl" {
				continue
			}
			if cwd, ok := streamCwd(filepath.Join(d.path, f.Name())); ok && !slices.Contains(out, cwd) {
				out = append(out, cwd)
				break
			}
		}
	}
	return out
}

// compatVerdict is one agent row's compat answer: the enum plus the probe's own words when it did not say pinned (the app shows them under the chip; item 18's "why").
type compatVerdict struct{ compat, probe string }

// memoCompat memoizes per agent and version: an unpinned version costs an artifact scan (each adapter's compat.go probe), seconds on a real home dir.
// Unprobed is never memoized: "no transcript at this version yet" becomes a verdict after the user's first session.
func (s *Server) memoCompat(agent string, probe func(string) (adapters.Compat, error)) func(string) compatVerdict {
	return func(v string) compatVerdict {
		key := agent + "@" + v
		s.mu.Lock()
		c, ok := s.compat[key]
		s.mu.Unlock()
		if ok {
			return c
		}
		k, err := probe(v)
		c = compatVerdict{compat: k.String()}
		if err != nil {
			c.probe = err.Error()
		}
		if k != adapters.Unprobed {
			s.mu.Lock()
			s.compat[key] = c
			s.mu.Unlock()
		}
		return c
	}
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func (s *Server) doctor(w http.ResponseWriter, _ *http.Request) {
	rows, err := s.anchorRows("")
	if rows == nil {
		rows = []map[string]any{}
	}
	health := []check{
		{"off", true, "inactive"},
		{"disk_hard_stop", !s.hardStop.Load(), "spool below the 95 % hard stop (07 §6)"},
		{"anchor_candidates", err == nil, "daemon has published candidates"},
	}
	if off.Off(s.cfg.StateDir) {
		health[0].Detail = "ACTIVE — capture, gating and uploads parked (08 §7.6)"
	}
	if s.hardStop.Load() {
		health[1].Detail = "disk at or past the 95 % hard stop: diagnostics shed, billing-grade blocks"
	}
	if err != nil {
		health[2].Detail = "daemon has not published candidates (" + err.Error() + ")"
	}
	frags := s.fragments()
	ok := true
	for _, f := range frags {
		if f.State != string(claudecode.StateOK) && f.State != string(claudecode.StateUserEdited) {
			ok = false
		}
	}
	for _, c := range health {
		ok = ok && c.OK
	}
	writeJSON(w, map[string]any{"ok": ok, "agents": s.agents(), "fragments": frags, "anchors": rows, "health": health})
}

type workspacesFile struct {
	Version    int              `json:"version"`
	Workspaces []workspaceEntry `json:"workspaces"`
}

type workspaceEntry struct {
	Path      string    `json:"path"`
	EnabledAt time.Time `json:"enabled_at"`
}

func (s *Server) workspacesPath() string { return filepath.Join(s.cfg.StateDir, "workspaces.json") }

func (s *Server) workspaces() (workspacesFile, error) {
	ws := workspacesFile{Version: 1}
	b, err := os.ReadFile(s.workspacesPath())
	if errors.Is(err, os.ErrNotExist) {
		return ws, nil
	}
	if err != nil {
		return ws, err
	}
	if err := json.Unmarshal(b, &ws); err != nil {
		return ws, fmt.Errorf("%s is corrupt: %w", s.workspacesPath(), err)
	}
	return ws, nil
}

func (s *Server) saveWorkspaces(ws workspacesFile) error {
	b, err := json.MarshalIndent(ws, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.workspacesPath(), b)
}

func canonical(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

// optedOut is `mark1 enable`'s whole-repo .mark1ignore refusal (08 §7.2): a bare * or ** line.
func optedOut(root string) bool {
	f, err := os.Open(filepath.Join(root, ".mark1ignore"))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l == "*" || l == "**" {
			return true
		}
	}
	return false
}

func (s *Server) project(e workspaceEntry) map[string]any {
	_, ignErr := os.Stat(filepath.Join(e.Path, ".mark1ignore"))
	workspaceID := ""
	if s.WorkspaceID != nil {
		if id := s.WorkspaceID(e.Path); len(id) == 32 && !bytes.Equal(id, make([]byte, 32)) {
			workspaceID = hex.EncodeToString(id)
		}
	}
	return map[string]any{
		"path":           e.Path,
		"workspace_id":   workspaceID, // hex(HMAC_tenant(path)) — what cloud session rows carry as `project`; "" before enrollment
		"enabled_at":     e.EnabledAt.UTC().Format(time.RFC3339),
		"agents_seen":    s.agentsSeen(e.Path),
		"tests_enabled":  anchors.TestsOptedIn(e.Path),
		"ignore_present": ignErr == nil,
		"anchors_looked": s.anchorsLooked(e.Path),
	}
}

// anchorsLooked is candidates.json's miss list for one root: what the last derivation looked for there and why each kind did not derive. Empty until the daemon has published.
func (s *Server) anchorsLooked(root string) []anchors.Miss {
	c, err := s.candidates()
	if err != nil {
		return []anchors.Miss{}
	}
	for _, ws := range c.Workspaces {
		if ws.Path == root && ws.Looked != nil {
			return ws.Looked
		}
	}
	return []anchors.Miss{}
}

func (s *Server) getProjects(w http.ResponseWriter, _ *http.Request) {
	ws, err := s.workspaces()
	if err != nil {
		internal(w, err)
		return
	}
	out := make([]map[string]any, 0, len(ws.Workspaces))
	for _, e := range ws.Workspaces {
		out = append(out, s.project(e))
	}
	writeJSON(w, out)
}

type projectBody struct {
	Path   string   `json:"path"`
	Agents []string `json:"agents,omitempty"`
}

func refusals(r []provision.Refusal) []provision.Refusal {
	if r == nil {
		return []provision.Refusal{}
	}
	return r
}

// postProject is `mark1 enable` (08 §7.2): the same provision.Apply walk, run BEFORE the allow-list write so the consent line names what was written and an I/O failure leaves nothing half-enabled; a re-POST of an enabled root reconciles the fragments and records no second consent.
func (s *Server) postProject(w http.ResponseWriter, r *http.Request) {
	var body projectBody
	if !decode(w, r, &body) {
		return
	}
	fi, err := os.Stat(body.Path)
	if err != nil || !fi.IsDir() {
		refuse(w, http.StatusBadRequest, "M1E-2001", "path is not a directory")
		return
	}
	if isWSLShare(body.Path) {
		// the founder's host daemon crawled his WSL workspace over the 9P bridge: every read is a network round trip, the index took the CPU, and the WSL lane exists for exactly this folder
		refuse(w, http.StatusBadRequest, "M1E-2001", "this folder lives in WSL; run Mark 1's daemon in WSL (Settings → Advanced → Daemon runs in) and add it there")
		return
	}
	root, err := canonical(body.Path)
	if err != nil {
		internal(w, err)
		return
	}
	if optedOut(root) {
		refuse(w, http.StatusConflict, "M1E-2001", root+"/.mark1ignore opts this repository out of Mark 1")
		return
	}
	for _, a := range body.Agents {
		if !slices.Contains(provision.Names, a) {
			refuse(w, http.StatusBadRequest, "M1E-2001", "agents: no such provisionable agent "+a)
			return
		}
	}
	s.files.Lock()
	defer s.files.Unlock()
	ws, err := s.workspaces()
	if err != nil {
		internal(w, err)
		return
	}
	pr, err := provision.Apply(provision.Options{StateDir: s.cfg.StateDir, Only: body.Agents})
	if err != nil {
		internal(w, err)
		return
	}
	respond := func(e workspaceEntry) {
		out := s.project(e)
		out["agents_provisioned"], out["agents_refused"] = pr.Provisioned, refusals(pr.Refused)
		writeJSON(w, out)
	}
	for _, e := range ws.Workspaces {
		if e.Path == root {
			respond(e)
			return
		}
	}
	ts := time.Now().UTC()
	e := workspaceEntry{Path: root, EnabledAt: ts}
	ws.Workspaces = append(ws.Workspaces, e)
	if err := s.saveWorkspaces(ws); err != nil {
		internal(w, err)
		return
	}
	name, uid := osUser()
	if err := errors.Join(
		appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": ts.Format(time.RFC3339), "kind": "enable", "reason": coverage.ReasonUserEnable, "workspace": root}),
		appendJSONL(filepath.Join(s.cfg.StateDir, "consent.jsonl"), map[string]any{"ts": ts.Format(time.RFC3339), "user": name, "uid": uid, "workspace": root, "agents_provisioned": pr.Provisioned}),
	); err != nil {
		internal(w, err)
		return
	}
	respond(e)
}

func agentName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if !slices.Contains(provision.Names, name) {
		refuse(w, http.StatusNotFound, "M1E-2001", "no such provisionable agent")
		return "", false
	}
	return name, true
}

// provisionAgent is the app's repair / re-provision action (desktop spec §5.9): the enable walk for one agent with the `doctor --fix` bit set, so a FRAGMENT-DAMAGED fence is rewritten and a MISSING one re-applied; the pre-image already on file is never re-snapshotted (08 §8.3).
func (s *Server) provisionAgent(w http.ResponseWriter, r *http.Request) {
	name, ok := agentName(w, r)
	if !ok {
		return
	}
	s.files.Lock()
	pr, err := provision.Apply(provision.Options{StateDir: s.cfg.StateDir, Only: []string{name}, Repair: true})
	s.files.Unlock()
	if err != nil {
		internal(w, err)
		return
	}
	if len(pr.Provisioned) == 0 && len(pr.Refused) == 0 {
		refuse(w, http.StatusConflict, "M1E-2001", name+" is not installed (binary not on mark1d's PATH)")
		return
	}
	frags := []fragment{}
	for _, f := range s.fragments() {
		if f.Agent == name {
			frags = append(frags, f)
		}
	}
	writeJSON(w, map[string]any{"agent": name, "provisioned": len(pr.Provisioned) > 0, "changed": pr.Changed, "refused": refusals(pr.Refused), "fragments": frags})
}

// disableAgent is `mark1 off` step 2 (08 §7.6, §8.4) for one agent: its fragments come out byte-equal where the post-image still matches, surgically otherwise; the workspace allow-list is untouched.
func (s *Server) disableAgent(w http.ResponseWriter, r *http.Request) {
	name, ok := agentName(w, r)
	if !ok {
		return
	}
	s.files.Lock()
	done, notReverted := provision.Revert(s.cfg.StateDir, name)
	s.files.Unlock()
	writeJSON(w, revertReport(map[string]any{"agent": name}, done, notReverted))
}

func revertReport(out map[string]any, done []provision.Reverted, notReverted []string) map[string]any {
	eq := len(notReverted) == 0
	for _, d := range done {
		eq = eq && d.ByteEquality
	}
	if done == nil {
		done = []provision.Reverted{}
	}
	if notReverted == nil {
		notReverted = []string{}
	}
	out["reverted"], out["not_reverted"], out["byte_equality"] = done, notReverted, eq
	return out
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	var body projectBody
	if !decode(w, r, &body) {
		return
	}
	root, err := canonical(body.Path)
	if err != nil {
		internal(w, err)
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
	ws, err := s.workspaces()
	if err != nil {
		internal(w, err)
		return
	}
	kept := ws.Workspaces[:0]
	removed := false
	for _, e := range ws.Workspaces {
		if e.Path == root {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		refuse(w, http.StatusNotFound, "M1E-2001", "project is not enabled")
		return
	}
	ws.Workspaces = kept
	if err := s.saveWorkspaces(ws); err != nil {
		internal(w, err)
		return
	}
	if err := appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": now(), "kind": "disable", "reason": coverage.ReasonMark1Off, "workspace": root}); err != nil {
		internal(w, err)
		return
	}
	// Fragments are user-scoped, not per-root: they come out (08 §8.4, as `mark1 off` step 2) only when this was the last enabled project, or the others would go silently uncaptured.
	var done []provision.Reverted
	var notReverted []string
	if len(kept) == 0 {
		done, notReverted = provision.Revert(s.cfg.StateDir)
	}
	// receipted_transition_id is null: the journal line is receipted by the daemon's coverage drain (cmd/main.go drainCoverageJournal), not at response time.
	writeJSON(w, revertReport(map[string]any{"removed": true, "path": root, "receipted_transition_id": nil}, done, notReverted))
}

// anchorRow renders one candidate; worktree is the repository below the project it was derived in, "" for the project itself.
func anchorRow(c anchors.Candidate, worktree string, lastRun, lastCode map[string]string) map[string]any {
	row := map[string]any{
		"id": c.ID, "tool": c.Tool, "version": c.ToolVersion, "side_effect": c.SideEffect,
		"consented": c.Consented, "exec_hash": c.ExecHash, "latency_class": c.Class, "last_run": nil, "worktree": worktree,
	}
	if c.Drift != "" {
		row["drift"] = c.Drift
	}
	if at, ok := lastRun[c.ID]; ok {
		row["last_run"] = at
	}
	if code := lastCode[c.ID]; code != "" {
		row["last_code"] = code // the newest vote's diagnostic_code (sandbox_denied, tool_error, TS2304, …): why a run did not simply pass
	}
	return row
}

func (s *Server) candidates() (anchors.Candidates, error) {
	var c anchors.Candidates
	b, err := os.ReadFile(anchors.CandidatesPath(s.cfg.StateDir))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("candidates.json is corrupt: %w", err)
	}
	return c, nil
}

func (s *Server) anchorRows(project string) ([]map[string]any, error) {
	c, err := s.candidates()
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	lastRun, lastCode := s.hub.lastRuns(), s.hub.lastCodes()
	for _, ws := range c.Workspaces {
		if project != "" && !anchors.Within(project, ws.Path) {
			continue
		}
		worktree := ""
		if project != "" && ws.Path != project {
			worktree, _ = filepath.Rel(project, ws.Path)
		}
		for _, a := range ws.Anchors {
			rows = append(rows, anchorRow(a, worktree, lastRun, lastCode))
		}
	}
	return rows, nil
}

func (s *Server) getAnchors(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if project != "" {
		if p, err := canonical(project); err == nil {
			project = p
		}
	}
	rows, err := s.anchorRows(project)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, []any{})
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, rows)
}

type consentBody struct {
	Project   string `json:"project"`
	ID        string `json:"id"`
	ExecHash  string `json:"exec_hash"`
	Consented *bool  `json:"consented"`
	// AllStatic consents every side-effect-free anchor of Project at once (the app's "Watch & verify"); tests stay opt-in. Waits for a just-enabled root's candidates.
	AllStatic bool `json:"all_static"`
}

// candidatesAwait is how long a consent-all waits for a just-enabled root to appear in candidates.json (watchAnchors derives it within a wsReloadTick plus the tool sniffs) — under the app's 10 s request timeout, so a slow derivation answers 409 and the app's "Turn on N checks" covers it rather than a timed-out call.
const candidatesAwait = 8 * time.Second

// postConsentAllStatic approves every static candidate of one project in a single approvals.jsonl pass and answers the project's rows.
func (s *Server) postConsentAllStatic(w http.ResponseWriter, project string) {
	if project == "" {
		refuse(w, http.StatusBadRequest, "M1E-2001", "project is required with all_static")
		return
	}
	var wss []anchors.WorkspaceCandidates
	for deadline := time.Now().Add(candidatesAwait); len(wss) == 0; time.Sleep(250 * time.Millisecond) {
		if c, err := s.candidates(); err == nil {
			for _, ws := range c.Workspaces {
				if anchors.Within(project, ws.Path) {
					wss = append(wss, ws)
				}
			}
		}
		if len(wss) == 0 && time.Now().After(deadline) {
			refuse(w, http.StatusConflict, "M1E-2001", "daemon has not published candidates for "+project+" yet; re-read GET /v1/anchors")
			return
		}
	}
	name, uid := osUser()
	s.files.Lock()
	var err error
	for _, ws := range wss {
		for _, a := range ws.Anchors {
			if a.SideEffect != anchors.SideEffectStatic || a.Consented {
				continue
			}
			err = errors.Join(err, appendJSONL(anchors.ApprovalsPath(s.cfg.StateDir), anchors.Approval{TS: now(), User: name, UID: uid, Workspace: ws.Path, ID: a.ID, ExecHash: a.ExecHash}))
		}
	}
	s.files.Unlock()
	if err != nil {
		internal(w, err)
		return
	}
	s.mu.Lock()
	step := s.reconcile
	s.mu.Unlock()
	if step != nil {
		step()
	}
	rows, err := s.anchorRows(project)
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, rows)
}

// postConsent appends the same approvals.jsonl line `mark1 enable` writes and the daemon's reconcile step applies it; consented:false revokes in the store directly.
// ponytail: a revoke races the daemon's own Approve on catalog.json (both tmp+rename); a lost approve replays from approvals.jsonl at the next boot.
func (s *Server) postConsent(w http.ResponseWriter, r *http.Request) {
	var body consentBody
	if !decode(w, r, &body) {
		return
	}
	project := ""
	if body.Project != "" {
		project, _ = canonical(body.Project)
	}
	if body.AllStatic {
		s.postConsentAllStatic(w, project)
		return
	}
	if body.ID == "" {
		refuse(w, http.StatusBadRequest, "M1E-2001", "id is required")
		return
	}
	c, err := s.candidates()
	if err != nil {
		refuse(w, http.StatusConflict, "M1E-2001", "daemon has not published candidates: "+err.Error())
		return
	}
	execHash := ""
	for _, ws := range c.Workspaces {
		for _, a := range ws.Anchors {
			if a.ID == body.ID && (body.ExecHash == "" || a.ExecHash == body.ExecHash) && (project == "" || anchors.Within(project, ws.Path)) && execHash == "" {
				execHash = a.ExecHash
			}
		}
	}
	if execHash == "" {
		refuse(w, http.StatusConflict, "M1E-2001", "no current candidate binds this (id, exec_hash); consent binds to the exact exec_hash")
		return
	}
	s.files.Lock()
	if body.Consented != nil && !*body.Consented {
		err = anchors.Revoke(anchors.ConsentPath(s.cfg.StateDir), body.ID)
	} else {
		name, uid := osUser()
		err = appendJSONL(anchors.ApprovalsPath(s.cfg.StateDir), anchors.Approval{TS: now(), User: name, UID: uid, Workspace: project, ID: body.ID, ExecHash: execHash})
	}
	s.files.Unlock()
	if err != nil {
		internal(w, err)
		return
	}
	s.mu.Lock()
	step := s.reconcile
	s.mu.Unlock()
	if step != nil {
		step()
	}
	rows, err := s.anchorRows(project)
	if err != nil {
		internal(w, err)
		return
	}
	for _, row := range rows {
		if row["id"] == body.ID && row["exec_hash"] == execHash {
			writeJSON(w, row)
			return
		}
	}
	refuse(w, http.StatusConflict, "M1E-2001", "candidate vanished during reconcile; re-read GET /v1/anchors")
}

type optIn struct {
	StopGate    bool   `json:"stop_gate"`
	Exploration bool   `json:"exploration"`
	TS          string `json:"ts,omitempty"`
	User        string `json:"user,omitempty"`
}

func (s *Server) readOptIn() (a optIn) {
	if b, err := os.ReadFile(fabric.OptInPath(s.cfg.StateDir)); err != nil || json.Unmarshal(b, &a) != nil {
		return optIn{}
	}
	return a
}

func (s *Server) optIns() (map[string]any, error) {
	ws, err := s.workspaces()
	if err != nil {
		return nil, err
	}
	tests := map[string]bool{}
	for _, e := range ws.Workspaces {
		tests[e.Path] = anchors.TestsOptedIn(e.Path)
	}
	a := s.readOptIn()
	_, offErr := os.Stat(claudecode.StatusLineOffPath(s.cfg.StateDir))
	return map[string]any{"stop_gate": a.StopGate, "exploration": a.Exploration, "tests_by_project": tests, "consents": consents.Read(s.cfg.StateDir), "statusline": offErr != nil}, nil
}

func (s *Server) getOptIns(w http.ResponseWriter, _ *http.Request) {
	out, err := s.optIns()
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, out)
}

type consentsPatch struct {
	E1         *bool `json:"e1"`
	CloudJudge *bool `json:"cloud_judge"`
	Training   *bool `json:"training"`
}

type optInBody struct {
	StopGate       *bool           `json:"stop_gate"`
	Exploration    *bool           `json:"exploration"`
	TestsByProject map[string]bool `json:"tests_by_project"`
	Consents       *consentsPatch  `json:"consents"`
	StatusLine     *bool           `json:"statusline"` // Mark 1's own line in Claude Code's footer; off = the marker file the shim honours
}

// setConsents merges a partial consents object into gates/consents.json and journals the change in consent.jsonl like every other consent this API records.
func (s *Server) setConsents(patch *consentsPatch) error {
	if patch == nil {
		return nil
	}
	was := consents.Read(s.cfg.StateDir)
	c := was
	for _, f := range []struct {
		dst *bool
		src *bool
	}{{&c.E1, patch.E1}, {&c.CloudJudge, patch.CloudJudge}, {&c.Training, patch.Training}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if c == was {
		return nil
	}
	if err := consents.Write(s.cfg.StateDir, c); err != nil {
		return err
	}
	name, uid := osUser()
	return appendJSONL(filepath.Join(s.cfg.StateDir, "consent.jsonl"), map[string]any{
		"ts": now(), "user": name, "uid": uid, "workspace": "", "agents_provisioned": []string{}, "consents": c,
	})
}

// setTestsOptIn read-modify-writes <root>/.mark1/anchors.json, the file anchors.TestsOptedIn reads (FR-VERIFY-003); only an enabled root may be written.
func (s *Server) setTestsOptIn(root string, on bool) error {
	ws, err := s.workspaces()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(ws.Workspaces, func(e workspaceEntry) bool { return e.Path == root }) {
		return fmt.Errorf("%s is not an enabled project", root)
	}
	doc := map[string]any{}
	if b, err := os.ReadFile(anchors.RepoOptInPath(root)); err == nil && json.Unmarshal(b, &doc) != nil {
		return fmt.Errorf("%s is corrupt; fix it by hand", anchors.RepoOptInPath(root))
	}
	doc["tests"] = on
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(anchors.RepoOptInPath(root), append(b, '\n'))
}

// putOptIns writes gates/opt-in.json exactly as cli.UpdateOptIn does: both false removes the file.
func (s *Server) putOptIns(w http.ResponseWriter, r *http.Request) {
	var body optInBody
	if !decode(w, r, &body) {
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
	if err := s.setConsents(body.Consents); err != nil {
		internal(w, err)
		return
	}
	if body.Consents != nil {
		go s.relayNow()
	}
	for p, on := range body.TestsByProject {
		root, err := canonical(p)
		if err == nil {
			err = s.setTestsOptIn(root, on)
		}
		if err != nil {
			refuse(w, http.StatusBadRequest, "M1E-2001", "tests_by_project: "+err.Error())
			return
		}
	}
	if body.StatusLine != nil {
		off := claudecode.StatusLineOffPath(s.cfg.StateDir)
		var err error
		if *body.StatusLine {
			if err = os.Remove(off); errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		} else if err = os.MkdirAll(filepath.Dir(off), 0o700); err == nil {
			err = writeAtomic(off, []byte("off\n"))
		}
		if err != nil {
			internal(w, err)
			return
		}
	}
	was := s.readOptIn()
	a := was
	if body.StopGate != nil {
		a.StopGate = *body.StopGate
	}
	if body.Exploration != nil {
		a.Exploration = *body.Exploration
	}
	path := fabric.OptInPath(s.cfg.StateDir)
	name, uid := osUser()
	a.TS, a.User = now(), name
	var err error
	if !a.StopGate && !a.Exploration {
		if err = os.Remove(path); errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else {
		var b []byte
		if b, err = json.Marshal(a); err == nil {
			err = writeAtomic(path, b)
		}
		if turnedOn := (a.StopGate && !was.StopGate) || (a.Exploration && !was.Exploration); err == nil && turnedOn {
			err = appendJSONL(filepath.Join(s.cfg.StateDir, "consent.jsonl"), map[string]any{
				"ts": a.TS, "user": name, "uid": uid, "workspace": "", "agents_provisioned": []string{},
				"stop_gate": a.StopGate, "exploration": a.Exploration,
			})
		}
	}
	if err != nil {
		internal(w, err)
		return
	}
	s.getOptIns(w, r)
}

// setOff is `mark1 off` / `mark1 on` steps 1 and 4 (08 §7.6): the marker every gate checks first, and the journalled CoverageTransition the daemon receipts.
func (s *Server) setOff(w http.ResponseWriter, paused bool) {
	marker := off.Marker(s.cfg.StateDir)
	ts := now()
	var err error
	if paused {
		b, _ := json.Marshal(map[string]string{"scope": "all", "written_at": ts})
		if err = writeAtomic(marker, b); err == nil {
			err = appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": ts, "kind": "disable", "reason": coverage.ReasonMark1Off, "scope": "all"})
		}
	} else {
		err = os.Remove(marker)
		switch {
		case errors.Is(err, os.ErrNotExist):
			err = nil
		case err == nil:
			err = appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": ts, "kind": "enable", "reason": coverage.ReasonUserEnable, "scope": "all"})
		}
	}
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, map[string]any{"paused": off.Off(s.cfg.StateDir), "receipted_transition_id": nil})
}

func (s *Server) postShutdown(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	stop := s.shutdown
	s.mu.Unlock()
	if stop == nil {
		refuse(w, http.StatusServiceUnavailable, "M1E-9500", "shutdown not wired: this daemon was started without a stop hook")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush() // the answer leaves before the stop path closes this listener
	}
	stop()
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		internal(w, errors.New("streaming unsupported"))
		return
	}
	ch, cancel := s.hub.subscribe()
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case f := <-ch:
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", f.family, f.data); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// ponytail: ?project= is accepted but unapplied — no wire event carries a workspace id yet (hookshim emit.rs sends it empty, capture does not stamp it).
func (s *Server) verifyEvents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.hub.verifyEvents())
}

// receipts is the local chain view: the last head the sealer persisted plus every checkpoint this boot admitted (newest first, ?before=<seq> pages back). Countersignatures and witnesses are the server's to show.
func (s *Server) receipts(w http.ResponseWriter, r *http.Request) {
	head := map[string]any{"seq": 0, "hash": "", "checkpoint_seq": 0}
	b, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "receipt", "last-head"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		internal(w, err)
		return
	default:
		if err := json.Unmarshal(b, &head); err != nil {
			internal(w, err)
			return
		}
	}
	status := "not_started"
	if seq, _ := head["seq"].(float64); seq > 0 {
		status = "sealed"
	}
	before, _ := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64)
	writeJSON(w, map[string]any{"status": status, "head": head, "checkpoints": s.hub.checkpointsBefore(before)})
}

type verifyBody struct {
	Chain   string `json:"chain"`
	Keys    string `json:"keys"`
	Witness string `json:"witness"`
}

// verifyReceipts runs rust/verifier exactly as `mark1 verify-receipts` does (08 §7.7): local snapshots when the body names them, else the enrolled server's export + key manifest fetched with the device token; its --json stdout is the result, exit 5 the defect verdict.
func (s *Server) verifyReceipts(w http.ResponseWriter, r *http.Request) {
	var body verifyBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		refuse(w, http.StatusBadRequest, "M1E-2001", "body: "+err.Error())
		return
	}
	verifier := os.Getenv("MARK1_VERIFIER") // an operator's path is taken verbatim; a wrong one fails at run, as before
	if verifier == "" {
		var verr error
		if verifier, verr = supervise.FindVerifier(); verr != nil {
			refuse(w, http.StatusServiceUnavailable, "M1E-9500", "mark1-verifier is not beside mark1d and not on PATH; set MARK1_VERIFIER to name one")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if body.Chain == "" || body.Keys == "" {
		tmp, err := os.MkdirTemp("", "mark1-verify-*")
		if err != nil {
			internal(w, err)
			return
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		if body.Chain, body.Keys, err = s.fetchChain(ctx, tmp); err != nil {
			refuse(w, http.StatusBadGateway, "M1E-1002", "fetching the chain export with the device token: "+err.Error())
			return
		}
	}
	args := []string{"verify", "--chain", body.Chain, "--keys", body.Keys, "--json"}
	if body.Witness != "" {
		args = append(args, "--witness", body.Witness)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, verifier, args...) //nolint:gosec // G204: MARK1_VERIFIER or LookPath, args as a slice, no shell
	procattr.Hide(cmd)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var xe *exec.ExitError
	switch {
	case err == nil, errors.As(err, &xe) && xe.ExitCode() == 5:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, &stdout)
	case errors.As(err, &xe):
		refuse(w, http.StatusBadRequest, "M1E-2001", fmt.Sprintf("mark1-verifier exit %d: %s", xe.ExitCode(), strings.TrimSpace(stderr.String())))
	default:
		internal(w, fmt.Errorf("running mark1-verifier: %w", err))
	}
}

const exportPage = 5000

// fetchChain lands GET /api/v1/receipts/export (paged, since_seq exclusive) and /api/v1/receipts/keys as the verifier's two input files, bytes verbatim — the same default network path verifyreceipts.fetchChain takes.
func (s *Server) fetchChain(ctx context.Context, dir string) (chain, keys string, err error) {
	doc, err := s.readEnrollment()
	if err != nil {
		return "", "", fmt.Errorf("not enrolled: %w", err)
	}
	get := func(url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+doc.DeviceToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		}
		return b, err
	}
	chain, keys = filepath.Join(dir, "chain.jsonl"), filepath.Join(dir, "keys.json")
	var out bytes.Buffer
	for since := uint64(0); ; {
		page, err := get(fmt.Sprintf("%s/api/v1/receipts/export?since_seq=%d&limit=%d", doc.Server, since, exportPage))
		if err != nil {
			return "", "", err
		}
		lines := bytes.Split(bytes.TrimSpace(page), []byte{'\n'})
		if len(bytes.TrimSpace(page)) == 0 {
			break
		}
		out.Write(page)
		if page[len(page)-1] != '\n' {
			out.WriteByte('\n')
		}
		var row struct {
			Seq json.Number `json:"seq"`
		}
		last, perr := uint64(0), json.Unmarshal(lines[len(lines)-1], &row)
		if perr == nil {
			last, perr = strconv.ParseUint(row.Seq.String(), 10, 64)
		}
		if len(lines) < exportPage {
			break
		}
		if perr != nil || last <= since {
			return "", "", fmt.Errorf("export page made no seq progress (since_seq=%d)", since)
		}
		since = last
	}
	if err := os.WriteFile(chain, out.Bytes(), 0o600); err != nil {
		return "", "", err
	}
	kb, err := get(doc.Server + "/api/v1/receipts/keys")
	if err != nil {
		return "", "", err
	}
	return chain, keys, os.WriteFile(keys, kb, 0o600)
}
