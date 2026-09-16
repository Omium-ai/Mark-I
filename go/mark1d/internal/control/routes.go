package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

const maxBody = 1 << 16

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.agents()) })
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
	writeJSON(w, map[string]any{
		"running":          true,
		"paused":           off.Off(s.cfg.StateDir),
		"version":          s.cfg.Version,
		"since":            s.since.UTC().Format(time.RFC3339),
		"agents_live":      s.hub.live(),
		"projects_enabled": len(roots.Workspaces),
		"spool":            map[string]any{"bytes": spoolBytes, "cap": s.cfg.SpoolCap, "hard_stop": s.hardStop.Load()},
	})
}

type fragment struct {
	Agent     string            `json:"agent"`
	Fragment  string            `json:"fragment,omitempty"`
	Mechanism string            `json:"mechanism,omitempty"`
	Manifest  string            `json:"manifest"`
	Target    string            `json:"target"`
	State     string            `json:"state"`
	Detail    string            `json:"detail,omitempty"`
	Lines     []json.RawMessage `json:"lines,omitempty"`
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
	cc := &claudecode.Adapter{StateDir: d}
	detect := map[string]func() (adapters.Detection, func(string) string){
		"claudecode": func() (adapters.Detection, func(string) string) { return must(cc.Detect()), s.claudeCompat(cc) },
		"codex": func() (adapters.Detection, func(string) string) {
			return must((&codex.Adapter{StateDir: d}).Detect()), pinned(codex.Supported)
		},
		"gemini": func() (adapters.Detection, func(string) string) {
			return must((&gemini.Adapter{StateDir: d}).Detect()), pinned(gemini.Supported)
		},
		"opencode": func() (adapters.Detection, func(string) string) {
			return must((&opencode.Adapter{StateDir: d}).Detect()), pinned(opencode.Supported)
		},
		"copilot": func() (adapters.Detection, func(string) string) {
			return must((&copilot.Adapter{StateDir: d}).Detect()), pinned(copilot.Supported)
		},
		"cursor": func() (adapters.Detection, func(string) string) {
			return must((&cursor.Adapter{StateDir: d}).Detect()), pinned(cursor.Supported)
		},
	}
	frags := s.fragments()
	out := make([]map[string]any, 0, len(adapters.Roster))
	for _, slot := range adapters.Roster {
		row := map[string]any{"name": slot.Name, "installed": false}
		det, ok := detect[slot.Name]
		if !ok {
			out = append(out, row)
			continue
		}
		dt, compat := det()
		row["installed"] = dt.Installed
		if dt.Installed {
			row["version"] = dt.Version
			row["compat"] = compat(dt.Version)
		}
		row["regime"] = "subscription"
		if dt.Regime == adapters.RegimeAPIKey {
			row["regime"] = "apikey"
		}
		var files []map[string]any
		var notes []string
		mechanism := ""
		for _, f := range frags {
			if f.Agent != slot.Name {
				continue
			}
			mechanism = f.Mechanism
			file := map[string]any{"path": f.Target}
			if f.Lines != nil {
				file["lines_added"] = len(f.Lines)
			}
			files = append(files, file)
			if f.State != string(claudecode.StateOK) {
				notes = append(notes, f.Fragment+": "+f.State)
			}
			if f.Detail != "" {
				notes = append(notes, f.Detail)
			}
		}
		if files != nil {
			prov := map[string]any{"mechanism": mechanism, "files": files}
			if notes != nil {
				prov["notes"] = notes
			}
			row["provisioned"] = prov
		}
		out = append(out, row)
	}
	return out
}

func must(d adapters.Detection, _ error) adapters.Detection { return d }

// claudeCompat memoizes per version: an unpinned version costs a transcript scan (compat.go probe), seconds on a real ~/.claude.
func (s *Server) claudeCompat(cc *claudecode.Adapter) func(string) string {
	return func(v string) string {
		s.mu.Lock()
		c, ok := s.compat[v]
		s.mu.Unlock()
		if ok {
			return c
		}
		k, _ := cc.Compatibility(v)
		c = k.String()
		s.mu.Lock()
		s.compat[v] = c
		s.mu.Unlock()
		return c
	}
}

func pinned(supported func(string) bool) func(string) string {
	return func(v string) string {
		if supported(v) {
			return "pinned"
		}
		return "incompatible"
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
	return map[string]any{
		"path":           e.Path,
		"enabled_at":     e.EnabledAt.UTC().Format(time.RFC3339),
		"tests_enabled":  anchors.TestsOptedIn(e.Path),
		"ignore_present": ignErr == nil,
	}
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
	Path string `json:"path"`
}

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
	root, err := canonical(body.Path)
	if err != nil {
		internal(w, err)
		return
	}
	if optedOut(root) {
		refuse(w, http.StatusConflict, "M1E-2001", root+"/.mark1ignore opts this repository out of Mark 1")
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
	ws, err := s.workspaces()
	if err != nil {
		internal(w, err)
		return
	}
	for _, e := range ws.Workspaces {
		if e.Path == root {
			writeJSON(w, s.project(e))
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
		appendJSONL(filepath.Join(s.cfg.StateDir, "consent.jsonl"), map[string]any{"ts": ts.Format(time.RFC3339), "user": name, "uid": uid, "workspace": root, "agents_provisioned": []string{}}),
	); err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, s.project(e))
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
	w.WriteHeader(http.StatusNoContent)
}

func anchorRow(c anchors.Candidate) map[string]any {
	return map[string]any{
		"id": c.ID, "tool": c.Tool, "version": c.ToolVersion, "side_effect": c.SideEffect,
		"consented": c.Consented, "exec_hash": c.ExecHash, "latency_class": c.Class,
	}
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
	for _, ws := range c.Workspaces {
		if project != "" && ws.Path != project {
			continue
		}
		for _, a := range ws.Anchors {
			rows = append(rows, anchorRow(a))
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
	Project  string `json:"project"`
	ID       string `json:"id"`
	ExecHash string `json:"exec_hash"`
}

// postConsent appends the same approvals.jsonl line `mark1 enable` writes; the daemon's reconcile step applies it.
func (s *Server) postConsent(w http.ResponseWriter, r *http.Request) {
	var body consentBody
	if !decode(w, r, &body) {
		return
	}
	if body.ID == "" || body.ExecHash == "" {
		refuse(w, http.StatusBadRequest, "M1E-2001", "id and exec_hash are required")
		return
	}
	project, _ := canonical(body.Project)
	c, err := s.candidates()
	if err != nil {
		refuse(w, http.StatusConflict, "M1E-2001", "daemon has not published candidates: "+err.Error())
		return
	}
	found := false
	for _, ws := range c.Workspaces {
		for _, a := range ws.Anchors {
			found = found || (a.ID == body.ID && a.ExecHash == body.ExecHash && (project == "" || ws.Path == project))
		}
	}
	if !found {
		refuse(w, http.StatusConflict, "M1E-2001", "no current candidate binds this (id, exec_hash); consent binds to the exact exec_hash")
		return
	}
	name, uid := osUser()
	a := anchors.Approval{TS: now(), User: name, UID: uid, Workspace: project, ID: body.ID, ExecHash: body.ExecHash}
	if err := appendJSONL(anchors.ApprovalsPath(s.cfg.StateDir), a); err != nil {
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
		if row["id"] == body.ID && row["exec_hash"] == body.ExecHash {
			writeJSON(w, row)
			return
		}
	}
	writeJSON(w, map[string]any{"id": body.ID, "exec_hash": body.ExecHash, "consented": false})
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
	return map[string]any{"stop_gate": a.StopGate, "exploration": a.Exploration, "tests_by_project": tests}, nil
}

func (s *Server) getOptIns(w http.ResponseWriter, _ *http.Request) {
	out, err := s.optIns()
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, out)
}

type optInBody struct {
	StopGate    *bool `json:"stop_gate"`
	Exploration *bool `json:"exploration"`
}

// putOptIns writes gates/opt-in.json exactly as cli.UpdateOptIn does: both false removes the file.
func (s *Server) putOptIns(w http.ResponseWriter, r *http.Request) {
	var body optInBody
	if !decode(w, r, &body) {
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
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
	writeJSON(w, map[string]any{"paused": off.Off(s.cfg.StateDir)})
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
	rows := s.hub.verifyEvents()
	out := make([]json.RawMessage, 0, len(rows))
	for _, f := range rows {
		out = append(out, f.data)
	}
	writeJSON(w, out)
}

func (s *Server) receipts(w http.ResponseWriter, _ *http.Request) {
	b, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "receipt", "last-head"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, map[string]any{})
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	var head map[string]any
	if err := json.Unmarshal(b, &head); err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, head)
}

type verifyBody struct {
	Chain   string `json:"chain"`
	Keys    string `json:"keys"`
	Witness string `json:"witness"`
}

// verifyReceipts runs tools/verifier exactly as `mark1 verify-receipts --offline` does (08 §7.7): its --json stdout is the result, exit 5 the defect verdict.
func (s *Server) verifyReceipts(w http.ResponseWriter, r *http.Request) {
	var body verifyBody
	if !decode(w, r, &body) {
		return
	}
	if body.Chain == "" || body.Keys == "" {
		refuse(w, http.StatusBadRequest, "M1E-2001", "chain and keys (local snapshots) are required; the verifier is offline by design")
		return
	}
	verifier := os.Getenv("MARK1_VERIFIER")
	if verifier == "" {
		var err error
		if verifier, err = exec.LookPath("mark1-verifier"); err != nil {
			refuse(w, http.StatusServiceUnavailable, "M1E-9500", "mark1-verifier not on PATH — install it (tools/verifier) or set MARK1_VERIFIER")
			return
		}
	}
	args := []string{"verify", "--chain", body.Chain, "--keys", body.Keys, "--json"}
	if body.Witness != "" {
		args = append(args, "--witness", body.Witness)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, verifier, args...) //nolint:gosec // G204: MARK1_VERIFIER or LookPath, args as a slice, no shell
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
