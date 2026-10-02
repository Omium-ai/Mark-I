package tailers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
)

// The partner JSONL file-tail transport (08 §4.6.2, 07 "Partner event files"):
// an external writer appends one protojson m1p.v1.Event per line to
// <name>.jsonl beside <name>.manifest.json, and the daemon tails it into the
// SAME admission door the socket uses. The sidecar is the file's Hello: it
// binds the file to a session the daemon mints once and persists in the
// cursor, so the two transports resolve identical input to identical streams.

// ManifestSuffix replaces ".jsonl" to name a file's sidecar.
const ManifestSuffix = ".manifest.json"

// AcceptedSchemaVersions is the set a sidecar's schema_version must be in:
// the current m1p.v1 revision. Additive within the major, so one entry.
var AcceptedSchemaVersions = []string{"m1p.v1"}

// Manifest is <name>.manifest.json — the file-tail's Hello (08 §4.6.2).
type Manifest struct {
	Component         string `json:"component"`
	HostCorrelationID string `json:"host_correlation_id,omitempty"`
	SchemaVersion     string `json:"schema_version"`
}

// maxHostCorrelationID mirrors fabric's bound on Hello.host_correlation_id.
const maxHostCorrelationID = 256

// ReadManifest loads and validates a sidecar under the same rules the fabric
// applies to an ext: Hello (ADR-0012): ext: component, bounded correlation
// id, an accepted schema_version. The error text carries M1E-4003, the code a
// refused Hello closes with.
func ReadManifest(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%s: sidecar is not JSON: %w", fabric.CodeHandshake, err)
	}
	if !strings.HasPrefix(m.Component, fabric.ExtPrefix) {
		return m, fmt.Errorf("%s: sidecar component %q is not an external writer (want %q prefix)", fabric.CodeHandshake, m.Component, fabric.ExtPrefix)
	}
	if n := len(m.HostCorrelationID); n > maxHostCorrelationID {
		return m, fmt.Errorf("%s: host_correlation_id is %d bytes, over the %d-byte bound", fabric.CodeHandshake, n, maxHostCorrelationID)
	}
	if !slices.Contains(AcceptedSchemaVersions, m.SchemaVersion) {
		return m, fmt.Errorf("%s: schema_version %q not in the accepted set %v", fabric.CodeHandshake, m.SchemaVersion, AcceptedSchemaVersions)
	}
	return m, nil
}

// PartnerConfig wires the file-tail transport to the admission door.
type PartnerConfig struct {
	Paths    []string // --partner-events: explicit files
	Dir      string   // the well-known drop directory: <state>/partner
	StateDir string   // cursor store, shared with the transcript tailers
	// Emit is the admission door — cmd/admit.go's event, the same function
	// the socket's decoded events reach.
	Emit func(context.Context, *m1pv1.Event) error
	// OnBind observes each file's Hello-equivalent: the session (minted or
	// resumed from the cursor), component and host correlation id — the
	// same signature as fabric.Server.OnExtHello, so one daemon hook serves
	// both transports. nil is legal.
	OnBind func(session [16]byte, component, hostCorrelationID string)
	// Drop accounts one quarantined line (undecodable, or naming a foreign
	// session): the file analogue of 08 §4.3 step 4a, where there is no
	// connection to close. nil is legal.
	Drop         func()
	Log          *slog.Logger
	PollInterval time.Duration
	Now          func() time.Time
}

// Partner discovers and follows every partner file. One goroutine sweeps all
// files on a tick, exactly as Manager does for transcripts.
type Partner struct {
	cfg    PartnerConfig
	ts     map[string]*Tailer // by path
	warned map[string]string  // path → the refusal already logged
}

func NewPartner(cfg PartnerConfig) (*Partner, error) {
	if cfg.Emit == nil {
		return nil, errors.New("tailers: Partner needs Emit")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Partner{cfg: cfg, ts: map[string]*Tailer{}, warned: map[string]string{}}, nil
}

// Run sweeps until ctx ends, then drains every file to EOF and persists
// cursors. Polling only: a partner file is appended by a foreign process at
// its own pace, and the tick is the correctness path anyway (04 §2.1).
func (p *Partner) Run(ctx context.Context) error {
	tick := time.NewTicker(p.cfg.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return p.CloseFlush(context.WithoutCancel(ctx))
		case <-tick.C:
			p.Sweep(ctx)
		}
	}
}

// Sweep is one discovery + poll pass. Fail-open per file: one file's error
// logs and never stops its siblings.
func (p *Partner) Sweep(ctx context.Context) {
	p.discover()
	now := p.cfg.Now()
	for path, t := range p.ts {
		if err := t.poll(now, p.emitAll(ctx)); err != nil {
			p.cfg.Log.Error("partner: poll failed", "path", path, "err", err)
		}
		if t.gone {
			t.close()
			delete(p.ts, path)
		}
	}
}

// CloseFlush drains every file (read to EOF, persist cursors) and closes.
func (p *Partner) CloseFlush(ctx context.Context) error {
	p.discover()
	now := p.cfg.Now()
	var firstErr error
	for _, t := range p.ts {
		if err := t.readLines(now, p.emitAll(ctx)); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := t.flushAndSave(p.emitAll(ctx)); err != nil && firstErr == nil {
			firstErr = err
		}
		t.close()
	}
	p.ts = map[string]*Tailer{}
	return firstErr
}

func (p *Partner) emitAll(ctx context.Context) func([]*m1pv1.Event) error {
	return func(evs []*m1pv1.Event) error {
		for _, ev := range evs {
			if err := p.cfg.Emit(ctx, ev); err != nil {
				return err
			}
		}
		return nil
	}
}

// discover opens every explicit path and every *.jsonl in Dir. A refused or
// not-yet-ready file is re-tried on every sweep, logged once per reason.
func (p *Partner) discover() {
	paths := slices.Clone(p.cfg.Paths)
	if p.cfg.Dir != "" {
		if entries, err := os.ReadDir(p.cfg.Dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
					paths = append(paths, filepath.Join(p.cfg.Dir, e.Name()))
				}
			}
		}
	}
	for _, path := range paths {
		p.open(path)
	}
}

func (p *Partner) open(path string) {
	if _, ok := p.ts[path]; ok {
		return
	}
	base, ok := strings.CutSuffix(path, ".jsonl")
	if !ok {
		p.refuse(path, "not a .jsonl file")
		return
	}
	m, err := ReadManifest(base + ManifestSuffix)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.refuse(path, err.Error())
		}
		return // no sidecar yet: the host writes it first; re-peeked next sweep
	}
	t, err := newTailer(path, p.cfg.StateDir, stream{}, p.cfg.Now(), 0)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.refuse(path, err.Error())
		}
		return
	}
	// The file's session: resumed from the cursor the way a restarted
	// connection cannot be, else minted here exactly as fabric mints one for
	// an ext: Hello without a session_id, and persisted BEFORE any line is
	// admitted so a crash between the mint and the first save cannot split
	// the stream across two sessions.
	var sid [16]byte
	if c, ok := loadCursor(p.cfg.StateDir, t.id); ok && len(c.SessionIDHex) == 32 {
		if b, err := hex.DecodeString(c.SessionIDHex); err == nil {
			copy(sid[:], b)
		}
	}
	if sid == ([16]byte{}) {
		id, err := uuid.NewV7()
		if err != nil {
			t.close()
			p.refuse(path, "minting session: "+err.Error())
			return
		}
		sid = id
	}
	t.sessionHex = hex.EncodeToString(sid[:])
	t.src = &partnerSource{session: sid, drop: p.cfg.Drop}
	if err := t.save(p.cfg.Now()); err != nil {
		t.close()
		p.refuse(path, "persisting session: "+err.Error())
		return
	}
	delete(p.warned, path)
	p.ts[path] = t
	p.cfg.Log.Info("partner: file bound", "path", path, "component", m.Component, "session", t.sessionHex)
	if p.cfg.OnBind != nil {
		p.cfg.OnBind(sid, m.Component, m.HostCorrelationID)
	}
}

func (p *Partner) refuse(path, reason string) {
	if p.warned[path] == reason {
		return
	}
	p.warned[path] = reason
	p.cfg.Log.Warn("partner: file not tailed (08 §4.6.2)", "path", path, "reason", reason)
}

// partnerSource is the lineSource for an ext JSONL file: one protojson Event
// per line, stamped with the bound session. Nothing is buffered, so idle is
// always true and the cursor lands after every emitted line.
type partnerSource struct {
	session [16]byte
	drop    func()
}

func (s *partnerSource) consume(line []byte, _ time.Time) []*m1pv1.Event {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	ev := &m1pv1.Event{}
	// DiscardUnknown: a field this build does not know is additive within
	// the major (08 §1.1 external writer), never a reason to drop the line.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(line, ev); err != nil {
		s.quarantine()
		return nil
	}
	if sid := ev.GetSessionId(); len(sid) != 0 && !bytes.Equal(sid, s.session[:]) {
		s.quarantine() // names a session this file is not bound to (08 §4.3 step 4a, file form)
		return nil
	}
	ev.SessionId = s.session[:]
	ev.Seq, ev.SessionEpoch = 0, 0 // the daemon's at admission (07 §2), never the writer's
	return []*m1pv1.Event{ev}
}

func (s *partnerSource) quarantine() {
	if s.drop != nil {
		s.drop()
	}
}

func (s *partnerSource) quiet(time.Time) []*m1pv1.Event { return nil }
func (s *partnerSource) flush() []*m1pv1.Event          { return nil }
func (s *partnerSource) idle() bool                     { return true }
