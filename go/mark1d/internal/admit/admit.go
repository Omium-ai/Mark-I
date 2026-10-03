// Package admit is the ONE admission path every transport shares (04 §2.0):
// the socket (fabric.Server's handle), the §4.5 loopback door (through the
// same Server) and the partner JSONL tailer. It was the fabric handler
// closure in cmd/main.go, then cmd/admit.go; it is its own package so a
// transport can enter the door without reaching into the daemon's main, and
// so the per-session context a decision needs — who the writer is, what it
// declared it owns (ADR-0013) — travels with the event instead of being
// re-derived by each consumer. The transcript tailers deliberately stay on
// their direct Emit/Observe path (cmd/main.go tailWorkspaces).
//
// Pure lift, twice over: cmd's TestSocketStreamGolden pins the stream.
package admit

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/cortex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/route"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
)

// Session is the per-session context a transport binds at its Hello (or
// sidecar) and admission carries: the writer's identity as it introduced
// itself, the host's own reference (ADR-0012), and the resolved host profile
// (ADR-0013). A session no transport bound — every first-party writer
// today — reads as the zero Session with hostprofile.Default.
type Session struct {
	ID                [16]byte
	Component         string
	HostCorrelationID string
	Profile           hostprofile.Profile
	// Transport is how the session reached the door: "fabric" (socket
	// Hello) or "jsonl" (file-tail manifest); ADR-0017's receipts carry it.
	Transport string
	// Ext marks an external-writer session (component has fabric.ExtPrefix):
	// the set that gets Usage.idem_key stamped here.
	Ext bool
}

// Path is the door. Every field is a collaborator the daemon's main wires;
// none is optional except Log.
type Path struct {
	Adm    *capture.Admitter
	Cx     *cortex.Plane
	Cov    *coverage.Emitter
	Seg    *taskseg.Segmenter
	Sched  *anchors.Scheduler
	Router *route.Emitter
	Votes  *anchors.Votes
	// SessionCwd is session → the writer's Hello.cwd, for SessionStart.workspace_id.
	SessionCwd *sync.Map
	// EnabledRoot maps a cwd to the enabled workspace root containing it.
	EnabledRoot func(cwd string) (root string, ok bool)
	// IdemKey is the tenant usage-idem key (tailers.DeriveUsageIdemKey); it
	// never leaves the daemon, which is why the daemon stamps for ext writers.
	IdemKey []byte
	// Profiles is the per-session host-profile registry (ADR-0013); Bind
	// fills it, provisioning/gate/memory read it.
	Profiles *hostprofile.Registry
	// PerEvent declares which Adm errors are an accounted per-event loss.
	PerEvent func(error) bool
	Log      *slog.Logger

	mu       sync.Mutex
	sessions map[[16]byte]*Session
	warned   map[[16]byte]bool // idem_key overwrite logged once per session
}

// Bind records a bound session: the fabric's OnExtHello/OnHostProfile and the
// partner tailer's OnBind end here. Idempotent per session; a later Bind for
// the same id replaces the earlier (a Hello re-sent on a new connection).
func (p *Path) Bind(s Session) {
	p.mu.Lock()
	if p.sessions == nil {
		p.sessions = map[[16]byte]*Session{}
	}
	cp := s
	p.sessions[s.ID] = &cp
	p.mu.Unlock()
	if p.Profiles != nil {
		p.Profiles.Set(s.ID, s.Profile)
	}
}

// SessionFor returns the bound context for id, or the zero Session (with
// hostprofile.Default) when no transport bound it.
func (p *Path) SessionFor(id [16]byte) Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.sessions[id]; ok {
		return *s
	}
	return Session{ID: id, Profile: hostprofile.Default}
}

// Bytes is the fabric.Server handle shape: the INNER Event bytes of one
// FabricFrame in (D-U), the same pipeline.
func (p *Path) Bytes(ctx context.Context, payload []byte) error {
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(payload, ev); err != nil {
		// Capture owns the quarantine ledger for an undecodable payload;
		// re-entering through its own door keeps that accounting single-site.
		return p.Adm.AdmitBytes(ctx, payload)
	}
	return p.Event(ctx, ev)
}

// Event admits one decoded Event: idem_key stamp for ext sessions, cortex
// observation, workspace stamp, segmentation, the PostToolUse trigger, then
// the route or verdict door.
func (p *Path) Event(ctx context.Context, ev *m1pv1.Event) error {
	// ADR-0012 §4 first: the idem_key must be the daemon's before anything
	// downstream (segmentation, the ledger) reads the Usage. A no-op for
	// every non-ext session, so first-party streams are untouched.
	p.stampIdemKey(ev)
	// The cortex plane watches every decoded event: session start/end
	// publishes or retires the session file cortexd Hellos with, and an
	// admitted CortexInjection's root_hash reaches the anchor runner.
	p.Cx.Observe(ev)
	// SessionStart.workspace_id (events.proto): the shim sends it empty — the tenant path key is the daemon's — and the daemon stamps it from the Hello's cwd when that cwd sits inside an enabled workspace; the app names the project from the same HMAC (GET /v1/projects). A session started outside every enabled root stays unattributed, honestly.
	if ss := ev.GetSessionStart(); ss != nil && len(ss.GetWorkspaceId()) == 0 && len(ev.GetSessionId()) == 16 {
		var sid [16]byte
		copy(sid[:], ev.GetSessionId())
		if cwd, ok := p.SessionCwd.Load(sid); ok {
			if root, ok := p.EnabledRoot(cwd.(string)); ok {
				ss.WorkspaceId = p.Cov.WorkspaceID(root)
			}
		}
	}
	// Segmentation runs BEFORE admission so a vote or gate query riding the
	// same connection already resolves to the task this event opened, and
	// TaskOpen precedes the event that opened it in the spool.
	// ponytail: nil files — no wire body carries tool paths into the daemon
	// (ToolUse has no path field), so R2's overlap predicate cannot fire yet.
	for _, te := range p.Seg.Observe(ev, nil) {
		if err := p.Adm.Admit(ctx, te); err != nil && !p.PerEvent(err) {
			return err
		}
	}
	// The PostToolUse trigger (04 §2.2), keyed by the task the segmenter
	// just resolved: a run whose vote could not be filed against a real
	// task would be evidence D-AA drops on arrival, so an unresolved
	// session schedules nothing rather than running an anchor for nobody.
	if ev.GetToolUse() != nil && len(ev.GetSessionId()) == 16 {
		var sid [16]byte
		copy(sid[:], ev.GetSessionId())
		if task, ok := p.Seg.TaskFor(sid, [16]byte{}); ok {
			p.Sched.NoteToolUse(sid, task)
		}
	}
	if ev.GetModelRequest() != nil {
		return p.Router.Emit(ctx, ev)
	}
	return p.Votes.Admit(ctx, ev)
}

// stampIdemKey is ADR-0012 §4: for an ext: session the daemon computes
// Usage.idem_key per the events.proto recipe, overwriting any writer value
// and saying so once per session at debug.
func (p *Path) stampIdemKey(ev *m1pv1.Event) {
	u := ev.GetUsage()
	if u == nil || len(ev.GetSessionId()) != 16 || len(p.IdemKey) == 0 {
		return
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	s := p.SessionFor(sid)
	if !s.Ext {
		return
	}
	if len(u.GetIdemKey()) != 0 {
		p.mu.Lock()
		if p.warned == nil {
			p.warned = map[[16]byte]bool{}
		}
		first := !p.warned[sid]
		p.warned[sid] = true
		p.mu.Unlock()
		if first && p.Log != nil {
			p.Log.Debug("ext writer sent Usage.idem_key; overwritten with the daemon's (ADR-0012 §4)", "session", hex.EncodeToString(sid[:]), "component", s.Component)
		}
	}
	u.IdemKey = tailers.IdemKey(p.IdemKey, uuid.UUID(sid), u.GetMessageId(), u.GetRequestId())
}
