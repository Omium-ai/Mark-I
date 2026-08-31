// Package chproj is stage 10 of the ingest pipeline: the post-ack,
// asynchronous protobuf → mark1.m1p_events projection (05 §2.1). It NEVER
// affects the ack — the landing object is the truth and this is a view; any
// failure here is retried from S3 (05 §2.5), not surfaced to the edge.
//
// The insert path borrows querychoke/chconn — the one sanctioned wiring
// exception (05 §6: INSERT-shaped, no SELECT surface); this package holds no
// ClickHouse client of its own.
package chproj

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/encoding/protojson"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// Inserter is what chconn.Conn satisfies; unit tests fake it.
type Inserter interface {
	InsertRows(ctx context.Context, table string, columns []string, rows [][]any) error
}

// Table is fixed by migrations/m1_ch_001_events.sql.
const Table = "m1p_events"

// Columns is the projected subset of m1p_events. Omitted on purpose:
// ingested_at (DEFAULT now64 — the ReplacingMergeTree version column, latest
// server ingest wins), payload_json_close_reason (MATERIALIZED), cost_usd /
// cost_basis and task_seg_version (stamped by later pipeline rows, not C4),
// inclusion_path (arrives with checkpoints).
var Columns = []string{
	"tenant_id", "occurred_at", "session_id", "event_id", "seq", "session_epoch",
	"device_id", "task_id",
	"event_type", "event_class", "agent", "model",
	"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "idem_key",
	"verdict", "verdict_stage", "p_satisfied", "p_violated", "p_refused", "p_error", "noise_cert_id",
	"propensity", "fidelity", "bundle_seq",
	"checkpoint_seq", "coverage_kind", "coverage_duration_ms",
	"dropped_reason", "dropped_durability_class", "dropped_quantity",
	"payload",
}

var (
	projectSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controld_ingest_ch_project_seconds",
		Help: "ClickHouse projection duration per landed batch (05 §2.1 stage 10)",
	})
	projectLag = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "controld_ingest_ch_project_lag_seconds",
		Help: "Newest landed batch vs newest projected (05 §2.1 stage 10)",
	})
	projectFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_ch_project_failures_total",
		Help: "Batches parked after exhausting projection retries (05 §9 poison-batch row)",
	})
	projectDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_ch_project_queue_dropped_total",
		Help: "Projection jobs dropped on queue overflow — recovered only by replay (05 §2.5)",
	})
)

// ---------------------------------------------------------------------------
// Pure projection: Batch → rows. Unit-testable, replay-deterministic.
// ---------------------------------------------------------------------------

// RowsFromBatch projects a decoded batch. tenant/device are the STAGE-3 STAMP
// from verified token claims (05 §2.1 stage 3) — by the time a batch reaches
// projection its envelope identity fields have already been rejected or
// verified equal, so the stamp is the only identity written.
func RowsFromBatch(b *m1pv1.Batch, tenant, device uuid.UUID, receivedAt time.Time) [][]any {
	rows := make([][]any, 0, len(b.GetEvents())+len(b.GetDropped()))
	batchID, err := uuid.FromBytes(b.GetBatchId())
	if err != nil {
		batchID = uuid.Nil // stage 6 guarantees this cannot happen post-ack
	}
	sessionID := uuidOrNil(b.GetSessionId())
	agent := b.GetSdk().GetAgent()

	// Replay determinism: client-stamped times only, falling back to sent_at,
	// so a §2.5 re-projection produces byte-equal ordering keys and the
	// ReplacingMergeTree collapses replays instead of duplicating them.
	fallbackAt := receivedAt
	if ts := b.GetSentAt(); ts != nil {
		fallbackAt = ts.AsTime()
	}

	for _, ev := range b.GetEvents() {
		rows = append(rows, eventRow(ev, tenant, device, sessionID, agent, fallbackAt))
	}
	for i, d := range b.GetDropped() {
		rows = append(rows, droppedRow(d, i, batchID, tenant, device, sessionID, agent, fallbackAt))
	}
	return rows
}

func eventRow(ev *m1pv1.Event, tenant, device, batchSession uuid.UUID, agent string, fallbackAt time.Time) []any {
	occurred := fallbackAt
	if ts := ev.GetOccurredAt(); ts != nil {
		occurred = ts.AsTime()
	}
	session := uuidOrNil(ev.GetSessionId())
	if session == uuid.Nil {
		session = batchSession
	}

	eventType := BodyTypeName(ev)
	row := []any{
		tenant, occurred, session, uuidOrNil(ev.GetEventId()), ev.GetSeq(), ev.GetSessionEpoch(),
		device, uuidOrNil(ev.GetTaskId()),
		eventType, eventClass(eventType), agent, "",
		uint64(0), uint64(0), uint64(0), uint64(0), fixed32(nil),
		"", "", float32(0), float32(0), float32(0), float32(0), uuid.Nil,
		float64(0), "", uint64(0),
		uint64(0), "", uint64(0),
		"", "", uint64(0),
		payloadJSON(ev),
	}

	switch body := ev.GetBody().(type) {
	case *m1pv1.Event_Usage:
		u := body.Usage
		row[11] = u.GetModel()
		row[12], row[13] = u.GetInputTokens(), u.GetOutputTokens()
		row[14], row[15] = u.GetCacheCreationInputTokens(), u.GetCacheReadInputTokens()
		row[16] = fixed32(u.GetIdemKey())
	case *m1pv1.Event_VerdictEvent:
		v := body.VerdictEvent
		row[17] = enumSuffix(v.GetVerdict().String(), "VERDICT_")
		row[18] = enumSuffix(v.GetStage().String(), "VERDICT_STAGE_")
		if p := v.GetPosterior(); len(p) == 4 {
			// posterior[4] order frozen: [satisfied, violated, refused, error]
			row[19], row[20], row[21], row[22] = float32(p[0]), float32(p[1]), float32(p[2]), float32(p[3])
		}
		if id, err := uuid.Parse(v.GetNoiseCertId()); err == nil {
			row[23] = id
		}
	case *m1pv1.Event_RouteDecision:
		r := body.RouteDecision
		row[24] = r.GetPropensity()
		row[25] = enumSuffix(r.GetFidelity().String(), "ROUTE_FIDELITY_")
		row[26] = r.GetBundleSeq()
	case *m1pv1.Event_ReceiptCheckpoint:
		row[27] = body.ReceiptCheckpoint.GetCheckpointSeq()
	case *m1pv1.Event_CoverageTransition:
		c := body.CoverageTransition
		row[28] = enumSuffix(c.GetKind().String(), "COVERAGE_KIND_")
		row[29] = c.GetDurationMs()
	}
	return row
}

// droppedRow: a Dropped{} entry becomes an event_type='Dropped' row (07 §MV:
// sumStateIf(dropped_quantity, event_type = 'Dropped' ...)). Dropped carries
// no event_id of its own, so one is DERIVED deterministically from
// (batch_id, index) — a replayed batch re-derives the same id and the
// ReplacingMergeTree collapses it instead of double-counting the loss ledger.
func droppedRow(d *m1pv1.Dropped, idx int, batchID, tenant, device, session uuid.UUID, agent string, at time.Time) []any {
	eventID := uuid.NewSHA1(batchID, []byte("dropped/"+itoa(idx)))
	reason := enumSuffix(d.GetReason().String(), "DROP_REASON_")
	return []any{
		tenant, at, session, eventID, uint64(0), uint32(0),
		device, uuid.Nil,
		"Dropped", "diagnostic", agent, "",
		uint64(0), uint64(0), uint64(0), uint64(0), fixed32(nil),
		"", "", float32(0), float32(0), float32(0), float32(0), uuid.Nil,
		float64(0), "", uint64(0),
		uint64(0), "", uint64(0),
		reason, enumSuffix(d.GetDurabilityClass().String(), "DURABILITY_CLASS_"), d.GetQuantity(),
		"{}",
	}
}

// SecurityEventRow is the M1E-8003 "security event" (08 §9 reading rules:
// lands in the ledger as a GuardDecision-class event). The event_id derives
// from the offending batch_id so a replayed attack does not multiply rows.
func SecurityEventRow(tenant, device, batchID uuid.UUID, detail string, at time.Time) []any {
	payload, _ := json.Marshal(map[string]string{
		"reason_code": "identity_disagreement",
		"error_code":  "M1E-8003",
		"batch_id":    batchID.String(),
		"detail":      detail,
	})
	return []any{
		tenant, at, uuid.Nil, uuid.NewSHA1(batchID, []byte("m1e-8003")), uint64(0), uint32(0),
		device, uuid.Nil,
		"GuardDecision", "diagnostic", "", "",
		uint64(0), uint64(0), uint64(0), uint64(0), fixed32(nil),
		"", "", float32(0), float32(0), float32(0), float32(0), uuid.Nil,
		float64(0), "", uint64(0),
		uint64(0), "", uint64(0),
		"", "", uint64(0),
		string(payload),
	}
}

// eventClass maps family → the closed Enum8 (m1_ch_001: {billing, verdict,
// receipt} are the billing-grade three; {route, diagnostic} are not).
func eventClass(eventType string) string {
	switch eventType {
	case "Usage":
		return "billing"
	case "VerdictEvent":
		return "verdict"
	case "ReceiptCheckpoint":
		return "receipt"
	case "RouteDecision":
		return "route"
	default:
		return "diagnostic"
	}
}

// BodyTypeName reads the oneof case's message name ("Usage", "TaskOpen", …) —
// the exact event_type vocabulary 07's rollup MVs filter on. Exported: the
// pipeline's rate-limit categories key on the same vocabulary (05 §2.4).
func BodyTypeName(ev *m1pv1.Event) string {
	ref := ev.ProtoReflect()
	od := ref.Descriptor().Oneofs().ByName("body")
	if od == nil {
		return ""
	}
	fd := ref.WhichOneof(od)
	if fd == nil {
		return ""
	}
	return string(fd.Message().Name())
}

// payloadJSON is the "canonical JSON remainder" column: the body message in
// proto field names (snake_case), so payload_json_close_reason's
// JSONExtractString(payload, 'close_reason') finds TaskClose.close_reason.
func payloadJSON(ev *m1pv1.Event) string {
	ref := ev.ProtoReflect()
	od := ref.Descriptor().Oneofs().ByName("body")
	if od == nil {
		return "{}"
	}
	fd := ref.WhichOneof(od)
	if fd == nil {
		return "{}"
	}
	body := ref.Get(fd).Message().Interface()
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(body)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func uuidOrNil(b []byte) uuid.UUID {
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// fixed32 pads to the idem_key FixedString(32) width; zero bytes = "absent",
// matching the column's implicit default.
func fixed32(b []byte) string {
	out := make([]byte, 32)
	copy(out, b)
	return string(out)
}

// enumSuffix maps proto enum names to the CH Enum8 vocabulary: strip the
// prefix, lowercase; UNSPECIFIED (the proto zero) becomes the CH ” = 0.
func enumSuffix(name, prefix string) string {
	s := strings.TrimPrefix(name, prefix)
	if s == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(s)
}

func itoa(i int) string {
	// strconv-free tiny helper to keep the deterministic-id derivation
	// dependency-light; batches cap at 1,000 dropped entries (05 §2.1 stage 5).
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// ---------------------------------------------------------------------------
// The async projector (stage 10's worker pool, 05 §8.1)
// ---------------------------------------------------------------------------

type job struct {
	rows     [][]any
	landedAt time.Time
}

// Projector drains landed batches into ClickHouse. Post-ack by construction:
// the only way in is Enqueue, and ingest calls it after the response is
// licensed by the S3 landing.
type Projector struct {
	ins    Inserter
	queue  chan job
	wg     sync.WaitGroup
	closed sync.Once
}

// New spawns the worker pool (05 §8.1: 16 workers, 1,000-deep queue at prod
// defaults; parameters injected so tests shrink them).
func New(ins Inserter, workers, depth int) *Projector {
	p := &Projector{ins: ins, queue: make(chan job, depth)}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

// Enqueue never blocks the caller: the ack already happened, so overflow
// backpressures onto nothing (05 §8.1). A dropped job is recoverable ONLY via
// §2.5 replay from the landing prefix.
// ponytail: no durable projection cursor yet — the cursor table is not in the
// frozen migrations; until it exists, restart recovery = operator-run replay.
func (p *Projector) Enqueue(rows [][]any, landedAt time.Time) bool {
	select {
	case p.queue <- job{rows: rows, landedAt: landedAt}:
		return true
	default:
		projectDropped.Inc()
		return false
	}
}

func (p *Projector) worker() {
	defer p.wg.Done()
	for j := range p.queue {
		start := time.Now()
		// 3 attempts then park (05 §9 poison-batch row: retried ≤3 then
		// parked; a projector crashloop over one bad batch is the outage
		// mode this bound exists to prevent).
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // §8.3 CH insert budget
			err = p.ins.InsertRows(ctx, Table, Columns, j.rows)
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
		if err != nil {
			projectFailures.Inc()
			log.Printf("chproj: batch parked after 3 attempts (replay per 05 §2.5): %v", err)
			continue
		}
		projectSeconds.Observe(time.Since(start).Seconds())
		projectLag.Set(time.Since(j.landedAt).Seconds())
	}
}

// Close drains and stops the pool (05 §1.5 step 4: abort at the next
// iteration boundary; everything here is idempotent-resumable via replay).
func (p *Projector) Close() {
	p.closed.Do(func() { close(p.queue) })
	p.wg.Wait()
}
