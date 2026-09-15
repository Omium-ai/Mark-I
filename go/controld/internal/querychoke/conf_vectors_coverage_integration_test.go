//go:build integration

package querychoke

// TestConfVectorsCoverageStore is the coverage family's store-backed leg. The
// fold TestConfVectorsCoverage restates in Go is, in production, a SQL
// predicate: dropped_by_tenant_day's sumIf on dropped_durability_class =
// 'billing_grade' (templates.go; m1_ch_002 mv_tvo_session). Here each case's
// Batch.dropped rows are projected the way ingest does (chproj.RowsFromBatch →
// droppedRow: enum suffix lowercased, '' for UNSPECIFIED), inserted through the
// INSERT principal into the scratch m1p_events, and read back through the real
// template as the case's tenant — dropped_billing must equal the vector's fold.
// events_billing_ingested is seeded as that many Usage rows through the same
// projection, so the template's second column is asserted too and every case
// returns exactly one day row (the zero-drop case included) rather than passing
// on an empty result.
//
// Gate: M1_TEST_CH_DSN — absent ⇒ skip, unless M1_REQUIRE_STORES=1 ⇒ fail
// (setupQC). Runs under `just test-integration`.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func TestConfVectorsCoverageStore(t *testing.T) {
	rig := setupQC(t)
	ctx := context.Background()
	m := loadCoverageManifest(t)

	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := reg.Lookup("dropped_by_tenant_day")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)

	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			tenant, device := uuid.New(), uuid.New()
			session, batchID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
			batch := &m1pv1.Batch{
				BatchId:   batchID[:],
				SessionId: session[:],
				Dropped:   decodeDropped(t, c.Dropped),
			}
			for i := uint64(0); i < c.Rollup.EventsBillingIngested; i++ {
				id := uuid.Must(uuid.NewV7())
				batch.Events = append(batch.Events, &m1pv1.Event{
					EventId: id[:], Seq: i + 1, SessionId: session[:], SessionEpoch: 1,
					Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{Model: "m", InputTokens: 1}},
				})
			}
			rows := chproj.RowsFromBatch(batch, tenant, device, at)
			if err := rig.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, rows); err != nil {
				t.Fatalf("project rows: %v", err)
			}

			q, err := Build(mustTenant(t, tenant), tpl, Params{"from": "2026-08-28", "to": "2026-08-28"})
			if err != nil {
				t.Fatal(err)
			}
			out, err := rig.runner.Run(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Rows) != 1 {
				t.Fatalf("dropped_by_tenant_day returned %d rows, want the one seeded day: %v", len(out.Rows), out.Rows)
			}
			want := foldDroppedBilling(batch.Dropped)
			if want != c.Expect.DroppedBilling {
				t.Fatalf("Go fold %d disagrees with the manifest %d", want, c.Expect.DroppedBilling)
			}
			if got := asU64(out.Rows[0]["dropped_billing"]); got != want {
				t.Fatalf("SQL dropped_billing = %d, Go fold %d — the template predicate and the vector fold disagree", got, want)
			}
			if got := asU64(out.Rows[0]["events_billing_ingested"]); got != c.Rollup.EventsBillingIngested {
				t.Fatalf("SQL events_billing_ingested = %d, want %d", got, c.Rollup.EventsBillingIngested)
			}
		})
	}
}
