package main

import (
	"context"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/cortex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/route"
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
