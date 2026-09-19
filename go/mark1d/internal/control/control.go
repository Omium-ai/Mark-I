// Package control is mark1d's local control API (desktop spec §7.1) behind the 08 §4.5 loopback wall.
package control

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const readHeaderTimeout = 5 * time.Second

type Config struct {
	StateDir string
	SpoolDir string
	SpoolCap int64
	Version  string
	Log      *slog.Logger
}

type Server struct {
	cfg   Config
	l     net.Listener
	http  *http.Server
	host  string
	token string
	since time.Time
	hub   *Hub

	hardStop  atomic.Bool
	mu        sync.Mutex
	reconcile func()
	enrolled  func()
	shutdown  func()
	compat    map[string]string // "<agent>@<version>" -> verdict
	files     sync.Mutex        // ponytail: serializes this process's read-modify-writes only; a concurrent `mark1 enable` races exactly as two CLIs do today
}

func Path(stateDir string) string { return filepath.Join(stateDir, "run", "control.json") }

type discovery struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

// ErrAlreadyServing: a live mark1d owns <state>/run/control.json. A second boot must leave that file alone — v0.1.1 on
// Windows overwrote it, lost the spool lock, and deleted it on exit, orphaning a healthy daemon nobody could reach.
var ErrAlreadyServing = errors.New("control: another mark1d is already serving this state dir")

// Alive answers whether the daemon named by <state>/run/control.json still serves; a stale file is a dead daemon's.
func Alive(stateDir string) (addr string, ok bool) {
	b, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return "", false
	}
	var d discovery
	if json.Unmarshal(b, &d) != nil || d.Port <= 0 || d.Token == "" {
		return "", false
	}
	addr = "127.0.0.1:" + strconv.Itoa(d.Port)
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/status", nil)
	if err != nil {
		return addr, false
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	// A refused connection answers at once; the budget only matters for a daemon whose status walk hits a cold or scanned disk.
	res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return addr, false
	}
	defer func() { _ = res.Body.Close() }()
	var st struct {
		Running bool `json:"running"`
	}
	return addr, res.StatusCode == http.StatusOK && json.NewDecoder(res.Body).Decode(&st) == nil && st.Running
}

func Listen(cfg Config) (*Server, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("control: StateDir required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if addr, ok := Alive(cfg.StateDir); ok {
		return nil, fmt.Errorf("%w (%s answers /v1/status; stop it or let the app adopt it)", ErrAlreadyServing, addr)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		_ = l.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, l: l, host: l.Addr().String(), token: hex.EncodeToString(raw[:]), since: time.Now(), hub: NewHub(), compat: map[string]string{}}
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: readHeaderTimeout}
	port := l.Addr().(*net.TCPAddr).Port
	b, _ := json.Marshal(discovery{Port: port, Token: s.token})
	if err := writeAtomic(Path(cfg.StateDir), b); err != nil {
		_ = l.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Addr() string  { return s.host }
func (s *Server) Token() string { return s.token }
func (s *Server) Hub() *Hub     { return s.hub }

// SetHardStop mirrors the spool's 95 % disk hard stop (07 §6) for /v1/status.
func (s *Server) SetHardStop(entered bool) { s.hardStop.Store(entered) }

// SetReconcile: the session's anchor reconcile step; nil (parked) leaves a posted consent to fsnotify.
func (s *Server) SetReconcile(fn func()) {
	s.mu.Lock()
	s.reconcile = fn
	s.mu.Unlock()
}

// SetEnrolled: run after POST/DELETE /v1/enroll rewrites the enrollment document; nil (parked) leaves the next boot to adopt it.
func (s *Server) SetEnrolled(fn func()) {
	s.mu.Lock()
	s.enrolled = fn
	s.mu.Unlock()
}

// SetShutdown: the graceful stop SIGTERM takes, for the app on Windows where no SIGTERM exists (desktop spec §2); nil (unwired) refuses the route.
func (s *Server) SetShutdown(fn func()) {
	s.mu.Lock()
	s.shutdown = fn
	s.mu.Unlock()
}

func (s *Server) Serve() error {
	stop := make(chan struct{})
	defer close(stop)
	go s.relayLoop(stop)
	if err := s.http.Serve(s.l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Close() error {
	err := s.http.Close()
	_ = s.l.Close()
	var d discovery // only this boot's file: a later boot's discovery is theirs to keep
	if b, rerr := os.ReadFile(Path(s.cfg.StateDir)); rerr == nil && json.Unmarshal(b, &d) == nil && d.Token == s.token {
		_ = os.Remove(Path(s.cfg.StateDir))
	}
	return err
}

// The three 08 §4.5 walls run in order, before any route match.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != s.host {
		refuse(w, http.StatusForbidden, "M1E-4004", "Host is not the bound loopback literal")
		return
	}
	if _, ok := r.Header[http.CanonicalHeaderKey("Origin")]; ok {
		refuse(w, http.StatusForbidden, "M1E-4005", "loopback requests carry no Origin; a local process is not a browser page")
		return
	}
	if !s.authorized(r.Header.Get("Authorization")) {
		refuse(w, http.StatusUnauthorized, "M1E-1002", "missing or wrong control bearer token")
		return
	}
	s.routes().ServeHTTP(w, r)
}

func (s *Server) authorized(header string) bool {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func appendJSONL(path string, rec any) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}
