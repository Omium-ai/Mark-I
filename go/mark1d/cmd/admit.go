package main

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
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/route"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
)

// admitPath is the ONE admission path every transport shares (04 §2.0): the
// socket (fabric.Server's handle), the §4.5 loopback door (through the same
// Server) and the partner JSONL tailer. It was the fabric handler closure in
// run(); it is a named type so a second transport can enter the same door
// instead of growing a second copy of the decorations below. The transcript
// tailers deliberately stay on their direct Emit/Observe path (tailWorkspaces).
//
// Pure lift: TestSocketStreamGolden pins the stream before and after.
type admitPath struct {
	adm    *capture.Admitter
	cx     *cortex.Plane
	cov    *coverage.Emitter
	seg    *taskseg.Segmenter
	sched  *anchors.Scheduler
	router *route.Emitter
	votes  *anchors.Votes
	// sessionCwd is session → the writer's Hello.cwd, for SessionStart.workspace_id.
	sessionCwd *sync.Map
	stateDir   string
	workspace  string

	// ext is session → extHost for every ADR-0012 external-writer session on
	// either transport (fabric.Server.OnExtHello, tailers.Partner.OnBind):
	// the set that gets Usage.idem_key stamped here, and the host reference
	// stored beside the session for later receipt echo.
	ext *sync.Map
	// idemKey is the tenant usage-idem key (tailers.DeriveUsageIdemKey); it
	// never leaves the daemon, which is why the daemon stamps for ext writers.
	idemKey []byte
	log     *slog.Logger
}

// extHost is what an ext: Hello (or sidecar) declared, kept beside the session.
type extHost struct {
	component, hostCorrelationID string
	idemWarned                   bool
}

// bindExt records an external-writer session. It is the fabric's OnExtHello
// and the partner tailer's OnBind: one hook, two transports.
func (p *admitPath) bindExt(session [16]byte, component, hostCorrelationID string) {
	p.ext.Store(session, &extHost{component: component, hostCorrelationID: hostCorrelationID})
}

// stampIdemKey is ADR-0012 §4: for an ext: session the daemon computes
// Usage.idem_key per the events.proto recipe, overwriting any writer value
// and saying so once per session at debug.
func (p *admitPath) stampIdemKey(ev *m1pv1.Event) {
	u := ev.GetUsage()
	if u == nil || len(ev.GetSessionId()) != 16 || len(p.idemKey) == 0 {
		return
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	h, ok := p.ext.Load(sid)
	if !ok {
		return
	}
	if host := h.(*extHost); len(u.GetIdemKey()) != 0 && !host.idemWarned {
		host.idemWarned = true
		p.log.Debug("ext writer sent Usage.idem_key; overwritten with the daemon's (ADR-0012 §4)", "session", hex.EncodeToString(sid[:]), "component", host.component)
	}
	u.IdemKey = tailers.IdemKey(p.idemKey, uuid.UUID(sid), u.GetMessageId(), u.GetRequestId())
}

// bytes is the fabric.Server handle shape: the INNER Event bytes of one
// FabricFrame in (D-U), the same pipeline.
func (p *admitPath) bytes(ctx context.Context, payload []byte) error {
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(payload, ev); err != nil {
		// Capture owns the quarantine ledger for an undecodable payload;
		// re-entering through its own door keeps that accounting single-site.
		return p.adm.AdmitBytes(ctx, payload)
	}
	return p.event(ctx, ev)
}

// event admits one decoded Event: cortex observation, workspace stamp,
// segmentation, the PostToolUse trigger, then the route or verdict door.
func (p *admitPath) event(ctx context.Context, ev *m1pv1.Event) error {
	// ADR-0012 §4 first: the idem_key must be the daemon's before anything
	// downstream (segmentation, the ledger) reads the Usage. A no-op for
	// every non-ext session, so first-party streams are untouched.
	p.stampIdemKey(ev)
	// The cortex plane watches every decoded event: session start/end
	// publishes or retires the session file cortexd Hellos with, and an
	// admitted CortexInjection's root_hash reaches the anchor runner.
	p.cx.Observe(ev)
	// SessionStart.workspace_id (events.proto): the shim sends it empty — the tenant path key is the daemon's — and the daemon stamps it from the Hello's cwd when that cwd sits inside an enabled workspace; the app names the project from the same HMAC (GET /v1/projects). A session started outside every enabled root stays unattributed, honestly.
	if ss := ev.GetSessionStart(); ss != nil && len(ss.GetWorkspaceId()) == 0 && len(ev.GetSessionId()) == 16 {
		var sid [16]byte
		copy(sid[:], ev.GetSessionId())
		if cwd, ok := p.sessionCwd.Load(sid); ok {
			if root, ok := enabledRootFor(p.stateDir, p.workspace, cwd.(string)); ok {
				ss.WorkspaceId = p.cov.WorkspaceID(root)
			}
		}
	}
	// Segmentation runs BEFORE admission so a vote or gate query riding the
	// same connection already resolves to the task this event opened, and
	// TaskOpen precedes the event that opened it in the spool.
	// ponytail: nil files — no wire body carries tool paths into the daemon
	// (ToolUse has no path field), so R2's overlap predicate cannot fire yet.
	for _, te := range p.seg.Observe(ev, nil) {
		if err := p.adm.Admit(ctx, te); err != nil && !perEventLoss(err) {
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
		if task, ok := p.seg.TaskFor(sid, [16]byte{}); ok {
			p.sched.NoteToolUse(sid, task)
		}
	}
	if ev.GetModelRequest() != nil {
		return p.router.Emit(ctx, ev)
	}
	return p.votes.Admit(ctx, ev)
}
