package ingest

// FR-SPINE-023 (02 §FR-SPINE-023, acceptance 02:428): out-of-window
// M1P-Schema ⇒ the structured upgrade hint of 08 §10.2; unknown event type
// within a major ⇒ retained, not dropped. The registry is faked here; the
// Postgres implementation and its RLS wall are registry/integration_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// failingRegistry is the outage: every read errors.
type failingRegistry struct{ err error }

func (f failingRegistry) Window(context.Context, querychoke.TenantID) (registry.Window, error) {
	return registry.Window{}, f.err
}

// upgradeBody is 08 §10.2's 426 shape, verbatim.
type upgradeBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Upgrade struct {
		Presented    string   `json:"presented"`
		Accepted     []string `json:"accepted"`
		MinEdge      *string  `json:"min_edge"`
		WindowCloses *string  `json:"window_closes"`
		NotesURI     string   `json:"notes_uri"`
	} `json:"upgrade"`
}

func counterValue(t *testing.T, name string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("%s is not registered; a delta on it would always be 0", name)
	return 0
}

// A tenant pinned past v1: v1's window closed, v2 is what it accepts. Every
// field of the hint has a distinct value so a hardcoded body cannot pass.
func v2OnlyWindow() registry.Window {
	closed := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return registry.Window{
		Accepted: []string{"m1p.v2"},
		MinEdge:  map[string]string{"m1p.v2": "2.0.0"},
		Closes:   map[string]*time.Time{"m1p.v1": &closed},
		NotesURI: map[string]string{
			"m1p.v1": "https://docs.omium.ai/mark1/upgrade/m1p-v1",
			"m1p.v2": "https://docs.omium.ai/mark1/upgrade/m1p-v2",
		},
	}
}

func TestOutOfWindowSchemaGetsStructuredUpgradeHint(t *testing.T) {
	h := newHarnessWithRegistry(t, registry.Static(v2OnlyWindow()))
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil) // presents m1p.v1
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("want 426, got %d: %s", rec.Code, rec.Body.String())
	}
	var body upgradeBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not the 08 §10.2 body: %v: %s", err, rec.Body.String())
	}
	u := body.Upgrade
	switch {
	case body.Error.Code != "M1E-2007":
		t.Fatalf("code: %q", body.Error.Code)
	case u.Presented != "m1p.v1":
		t.Fatalf("presented: %q", u.Presented)
	case len(u.Accepted) != 1 || u.Accepted[0] != "m1p.v2":
		t.Fatalf("accepted: %v", u.Accepted)
	case u.MinEdge == nil || *u.MinEdge != "2.0.0":
		t.Fatalf("min_edge: %v (want the successor's)", u.MinEdge)
	case u.WindowCloses == nil || *u.WindowCloses != "2026-09-01T00:00:00Z":
		t.Fatalf("window_closes: %v", u.WindowCloses)
	case u.NotesURI != "https://docs.omium.ai/mark1/upgrade/m1p-v2":
		t.Fatalf("notes_uri: %q (want the successor's)", u.NotesURI)
	}
	// Refused before the body was touched: nothing landed, nothing projected.
	h.drain()
	if len(h.store.keys()) != 0 || h.ins.count() != 0 {
		t.Fatalf("a refused schema still landed/projected: keys=%v rows=%d", h.store.keys(), h.ins.count())
	}
}

func TestInWindowSchemaIsAccepted(t *testing.T) {
	w := v2OnlyWindow()
	w.Accepted = []string{"m1p.v1", "m1p.v2"} // same registry, tenant still in v1's window
	h := newHarnessWithRegistry(t, registry.Static(w))
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	h.drain()
	if len(h.store.keys()) != 1 || h.ins.count() != 1 {
		t.Fatalf("in-window batch did not land+project: keys=%v rows=%d", h.store.keys(), h.ins.count())
	}
}

// The registry's m1_063 semantics at the Window level: no tenant rows ⇒ every
// unretired schema; a retired schema ⇒ 426. (registry/integration_test.go
// proves the SQL derives these windows from the real tables.)
func TestEmptyWindowMeansEveryUnretiredSchema(t *testing.T) {
	// A fresh database: v1 released, nothing retired, no tenant rows.
	h := newHarnessWithRegistry(t, registry.Static(registry.Compiled))
	b, id := testBatch(t)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("unnarrowed tenant refused: %d %s", rec.Code, rec.Body.String())
	}

	// v1 retired fleet-wide, v2 the only unretired schema, still no tenant rows.
	retired := registry.Window{
		Accepted: []string{"m1p.v2"},
		NotesURI: map[string]string{"m1p.v1": "u1", "m1p.v2": "u2"},
	}
	h2 := newHarnessWithRegistry(t, registry.Static(retired))
	b2, id2 := testBatch(t)
	rec := h2.post(t, id2, encodeBatch(t, b2), nil)
	if rec.Code != http.StatusUpgradeRequired || errCode(t, rec) != "M1E-2007" {
		t.Fatalf("retired schema accepted: %d %s", rec.Code, rec.Body.String())
	}
	var body upgradeBody
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Upgrade.MinEdge != nil || body.Upgrade.WindowCloses != nil || body.Upgrade.NotesURI != "u2" {
		t.Fatalf("hint with no min_edge/window on record must carry nulls, not inventions: %+v", body.Upgrade)
	}
}

func TestRegistryOutageFallsStatic(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	h := newHarnessWithRegistry(t, failingRegistry{err: errors.New("pg: connection refused")})
	before := counterValue(t, "controld_ingest_schema_registry_fallbacks_total")

	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil) // m1p.v1 — in the compiled-in window
	if rec.Code != http.StatusOK {
		t.Fatalf("registry outage stopped capture (want 200, fail-static): %d %s", rec.Code, rec.Body.String())
	}
	if got := counterValue(t, "controld_ingest_schema_registry_fallbacks_total") - before; got != 1 {
		t.Fatalf("fallback counter moved by %v, want 1", got)
	}
	if !strings.Contains(logs.String(), "WARN ingest: schema registry unavailable") ||
		!strings.Contains(logs.String(), "connection refused") {
		t.Fatalf("no WARN with the error: %q", logs.String())
	}
	// The static window is the COMPILED one, not "accept anything": v9 is
	// still refused during the outage.
	rec = h.post(t, id, encodeBatch(t, b), func(r *http.Request) { r.Header.Set("M1P-Schema", "m1p.v9") })
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("outage widened the window: %d", rec.Code)
	}
	h.drain()
	if len(h.store.keys()) != 1 {
		t.Fatalf("want exactly the v1 landing, got %v", h.store.keys())
	}
}

// unknownTypeEvent hand-encodes an Event whose body oneof uses a field number
// this binary's m1p.v1 was not generated with (a family a NEWER edge added
// within the major). protoc-gen-go decodes it with Body == nil and the bytes
// in unknownFields; proto.Marshal re-emits them, so the batch carries it to
// the wire unchanged. Returns the event and its raw bytes.
func unknownTypeEvent(t *testing.T, session uuid.UUID, seq uint64) (*m1pv1.Event, []byte) {
	t.Helper()
	id := mustV7(t)
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.BytesType) // event_id
	raw = protowire.AppendBytes(raw, id[:])
	raw = protowire.AppendTag(raw, 2, protowire.VarintType) // seq
	raw = protowire.AppendVarint(raw, seq)
	raw = protowire.AppendTag(raw, 3, protowire.BytesType) // session_id
	raw = protowire.AppendBytes(raw, session[:])
	raw = protowire.AppendTag(raw, 49, protowire.BytesType) // body: a v1.x family at the top of the intelligence range
	raw = protowire.AppendBytes(raw, []byte("\x0a\x0bfuture-kind"))
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	if ev.GetBody() != nil || len(ev.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("test premise: the crafted event must decode to Body==nil with unknown fields")
	}
	return ev, raw
}

func TestUnknownEventTypeIsRetainedNotDropped(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	known := usageEvent(t, session, 1)
	unknown, rawUnknown := unknownTypeEvent(t, session, 2)
	b, id := testBatch(t, known, unknown)
	body := encodeBatch(t, b)
	before := counterValue(t, "controld_ingest_ch_project_unknown_event_types_total")

	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown event type was an error (want 200 ack): %d %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ack)
	if ack.Accepted != 2 {
		t.Fatalf("ack accepted=%d; the unknown event must be acked, not dropped", ack.Accepted)
	}

	// Retained: the landing object holds the unknown event byte-for-byte
	// (stage 8 lands the received bytes; the event's encoding is a verbatim
	// length-delimited substring of the batch's).
	keys := h.store.keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "/ingest/v1/") {
		t.Fatalf("want one ingest landing, got %v", keys)
	}
	landed, _, _ := h.store.Get(context.Background(), keys[0])
	decoded, err := decodeZstdBounded(landed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decoded, rawUnknown) {
		t.Fatal("landed object does not contain the unknown event's bytes — not retained")
	}

	// Skipped in projection, counted, and the KNOWN sibling still projects.
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row (the known event), got %d", h.ins.count())
	}
	if got := chproj.BodyTypeName(unknown); got != "" {
		t.Fatalf("premise: BodyTypeName of an unknown type is %q", got)
	}
	if got := counterValue(t, "controld_ingest_ch_project_unknown_event_types_total") - before; got != 1 {
		t.Fatalf("unknown-type counter moved by %v, want 1", got)
	}
	// And it is a leaf of the device's next checkpoint like every other
	// landed event (sidefx.EffectsFromBatch): the device's Merkle tree spans
	// everything it uploaded, unknown families included.
	if n := h.sfx.PendingLeafCount(mustTenant(t, h.tenant), h.device); n != 2 {
		t.Fatalf("pending leaves: want 2 (known + unknown), got %d", n)
	}
}

func mustTenant(t *testing.T, id uuid.UUID) querychoke.TenantID {
	t.Helper()
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}
