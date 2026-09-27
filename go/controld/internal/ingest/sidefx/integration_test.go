//go:build integration

package sidefx_test

// DSN-gated Postgres integration (house style, 12 / 05 §7.5): a scratch
// database gets the real migrations, a NOBYPASSRLS login role stands in for
// controld_app, and the tests prove the two walls independently — the
// tenant-GUC discipline (05 §7.2) and RLS-with-NULLIF (05 §7.1) — plus the R2
// posture that pg.Open REFUSES a bypass-capable role.
//
// Gate: M1_MIGRATE_PG_DSN (privileged DSN for scratch setup). Absent ⇒ skip,
// unless M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// The vectors' TEST-ONLY seeds (conformance/vectors/receipt/README.md):
// anything signed by these keys is by definition worthless outside tests.
var (
	deviceSeed = bytes.Repeat([]byte{0x11}, 32)
	serverSeed = bytes.Repeat([]byte{0x22}, 32)
)

// The privileged DSN: this harness creates its own scratch database and applies
// the full migration tree, and m1_060 mints a BYPASSRLS role — which PG16 permits
// only to a role that already holds it. The tests themselves run as the
// unprivileged role minted below, never as this one — which is also what makes
// this DSN the honest input to TestIntegrationOpenRefusesBypassCapableRole.
func pgDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("M1_MIGRATE_PG_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_MIGRATE_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_MIGRATE_PG_DSN unset; skipping Postgres-backed test")
	}
	return v
}

type pgHarness struct {
	admin   *pgx.Conn // superuser, connected to the scratch db
	db      *pg.TenantDB
	tenantA querychoke.TenantID
	tenantB querychoke.TenantID
	deviceA uuid.UUID
	deviceB uuid.UUID
	// The real receipt writer, so the coverage inserts at sidefx.go:388-398 run
	// inside an actual AppendCheckpoint transaction rather than a fake's
	// discarded callback (sidefx_test.go:45-47).
	deviceKey *receipts.Signer
	store     *receipts.Store
	// appPoolQuery queries the raw app pool with NO tenant GUC — the
	// unset-GUC-matches-nothing probe (05 §7.1).
	appPoolQuery func(ctx context.Context, sql string, args ...any) (int64, error)
}

func setupPG(t *testing.T) *pgHarness {
	t.Helper()
	ctx := context.Background()
	dsn := pgDSN(t)

	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}

	scratch := fmt.Sprintf("controld_c4_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("c4app_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = bootstrap.Exec(cctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = bootstrap.Exec(cctx, "DROP ROLE IF EXISTS "+role)
		_ = bootstrap.Close(cctx)
	})

	scratchCfg := adminCfg.Copy()
	scratchCfg.Database = scratch
	admin, err := pgx.ConnectConfig(ctx, scratchCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	// The real migrations, in filename order — the tests run against exactly
	// what prod will execute (05 §7.4). m1_060's GRANTs touch cluster-GLOBAL
	// role tuples, so concurrent scratch setups across test packages collide
	// ("tuple concurrently updated"); the migration+role phase serializes on
	// a cluster advisory lock held on the shared bootstrap session (a Fatal
	// path releases it when Cleanup closes the session).
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "..", "migrations", "m1_[0-9]*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v (%d)", err, len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		if strings.Contains(filepath.Base(f), "m1_ch_") {
			continue
		}
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(f), err)
		}
	}

	// A login stand-in for controld_app (which is passwordless by design —
	// m1_060: credentials are injected at cutover, never committed). It
	// INHERITS controld_app's grants but keeps its own NOBYPASSRLS attribute,
	// which is the one that matters (BYPASSRLS does not inherit).
	_, err = admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'c4test' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	// Seed two tenants + one device each, as superuser (RLS bypassed by
	// attribute — which is exactly why the app path must never run as one).
	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('c4-it', 'c4-it.example') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	mkTenant := func(name string) (uuid.UUID, uuid.UUID) {
		var tid, did uuid.UUID
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, name,
		).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
			tid, make([]byte, 32),
		).Scan(&did); err != nil {
			t.Fatal(err)
		}
		return tid, did
	}
	tA, dA := mkTenant("tenant-a")
	tB, dB := mkTenant("tenant-b")

	deviceKey, err := receipts.NewSigner(deviceSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) VALUES ($1, $2, $3, $4)`,
		tA, dA, deviceKey.KeyID(), []byte(deviceKey.Public())); err != nil {
		t.Fatal(err)
	}

	appDSN := fmt.Sprintf("postgres://%s:c4test@%s:%d/%s?sslmode=disable",
		role, adminCfg.Host, adminCfg.Port, scratch)
	pool, err := pg.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)

	chainKey, err := receipts.NewSigner(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	// Boot step, exactly as cmd runs it: publish before the first countersign.
	if err := receipts.RegisterServerKey(ctx, pool, chainKey); err != nil {
		t.Fatalf("RegisterServerKey: %v", err)
	}

	claimsA := auth.Claims{TenantID: tA, DeviceID: dA}
	claimsB := auth.Claims{TenantID: tB, DeviceID: dB}
	tenantA, err := querychoke.FromClaims(claimsA)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := querychoke.FromClaims(claimsB)
	if err != nil {
		t.Fatal(err)
	}

	db := pg.NewTenantDB(pool)
	return &pgHarness{
		admin: admin, db: db,
		tenantA: tenantA, tenantB: tenantB, deviceA: dA, deviceB: dB,
		deviceKey: deviceKey, store: receipts.NewStore(db, chainKey),
		appPoolQuery: func(ctx context.Context, sql string, args ...any) (int64, error) {
			var n int64
			err := pool.QueryRow(ctx, sql, args...).Scan(&n)
			return n, err
		},
	}
}

// sealCheckpoint plays the edge: read the head as a device would (08 §3.4),
// build the payload at seq+1/checkpoint_seq+1, origin-sign it. Sealing against
// the CURRENT head is what makes each seal fresh — a second seal built this way
// carries its own checkpoint_seq and its own signature bytes, which is why it
// reaches the append instead of being refused as stale.
func (h *pgHarness) sealCheckpoint(t *testing.T, device uuid.UUID, leaves []uuid.UUID, issuedAt time.Time) receipts.CheckpointEvent {
	t.Helper()
	seq, head, ckpt, err := h.store.Head(context.Background(), h.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([][]byte, len(leaves))
	for i := range leaves {
		id := leaves[i]
		raw[i] = id[:]
	}
	root, err := receipts.MerkleRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	cp := receipts.Checkpoint{
		TenantID: h.tenantA.String(), DeviceID: device.String(),
		Seq: seq + 1, PrevReceiptHash: head, IssuedAt: receipts.IssuedAtString(issuedAt),
		CheckpointSeq: ckpt + 1, MerkleRoot: root, LeafCount: len(leaves),
	}
	signed, err := receipts.OriginSign(h.deviceKey, cp.Payload(h.deviceKey.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return receipts.CheckpointEvent{
		EventID: id, DeviceID: device, DeviceKeyID: h.deviceKey.KeyID(),
		ClaimedCheckpointSeq: ckpt + 1, MerkleRoot: root, LeafCount: len(leaves),
		FirstEventID: leaves[0], LastEventID: leaves[len(leaves)-1],
		OriginSig: signed.DeviceSig, IssuedAt: issuedAt,
	}
}

// The wedge the span read exists for: a seal the chain refused (here: a stale checkpoint_seq) leaves its leaves unconsumed at the head; the device moves on and its next seal names only its own batch's leaves. Read as "the oldest N", every later window would start at the orphans and never match; read as the span the seal names, it seals.
func TestIntegrationOrphanedLeavesAtTheHeadNeverShiftALaterSeal(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	s := sidefx.New(h.db, h.store, nil, 1, 8)
	t.Cleanup(s.Close)

	orphanBatch := uuid.Must(uuid.NewV7())
	orphans := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: orphans[0], BatchID: orphanBatch, Index: 0},
		{EventID: orphans[1], BatchID: orphanBatch, Index: 1},
	})
	stale := h.sealCheckpoint(t, h.deviceA, orphans, at.Add(time.Second))
	stale.ClaimedCheckpointSeq += 1000 // the founder's device: a chain the server never advanced
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{{EventID: stale.EventID, BatchID: uuid.Must(uuid.NewV7()), Index: 0, Checkpoint: &stale}})
	if n := s.PendingLeafCount(h.tenantA, h.deviceA); n != 2 {
		t.Fatalf("the refused seal's leaves must stay (a re-seal may still claim them): %d pending", n)
	}

	liveBatch := uuid.Must(uuid.NewV7())
	live := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: live[0], BatchID: liveBatch, Index: 0},
		{EventID: live[1], BatchID: liveBatch, Index: 1},
		{EventID: live[2], BatchID: liveBatch, Index: 2},
	})
	seal := h.sealCheckpoint(t, h.deviceA, live, at.Add(2*time.Second))
	var paged []string
	s2 := sidefx.New(h.db, h.store, func(_, _, _ uuid.UUID, detail string, _ time.Time) { paged = append(paged, detail) }, 1, 8)
	t.Cleanup(s2.Close)
	s2.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{{EventID: seal.EventID, BatchID: uuid.Must(uuid.NewV7()), Index: 0, Checkpoint: &seal}})
	if len(paged) != 0 {
		t.Fatalf("the live seal paged security: %q", paged)
	}
	var receipts int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("m1_receipts holds %d row(s), want 1: the orphans at the head shifted the live seal's window", receipts)
	}
	if n := s.PendingLeafCount(h.tenantA, h.deviceA); n != 2 {
		t.Fatalf("%d pending, want the 2 orphans alone", n)
	}
}

// coverageRowsTotal reads controld_ingest_coverage_rows_total off the default
// registry. It is the ONLY observable of the tag.RowsAffected() at
// sidefx.go:398, and a delta of 0 across a call whose insert loop provably ran
// is the direct evidence that ON CONFLICT ... DO NOTHING — not an earlier
// dedupe layer — is what absorbed the duplicate.
func coverageRowsTotal(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() != "controld_ingest_coverage_rows_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			return m.GetCounter().GetValue()
		}
	}
	t.Fatal("controld_ingest_coverage_rows_total is not registered; the delta below would always be 0")
	return 0
}

// R2, continuously: pg.Open must REFUSE a superuser/BYPASSRLS DSN — the
// RLS-inert-via-rds_superuser failure made structurally unrepeatable.
func TestIntegrationOpenRefusesBypassCapableRole(t *testing.T) {
	dsn := pgDSN(t)
	if _, err := pg.Open(context.Background(), dsn); err == nil {
		t.Fatal("pg.Open accepted a superuser role (R2 must refuse, 05 §1.2/§7.2)")
	}
}

func TestIntegrationSidefxAndRLS(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	s := sidefx.New(h.db, nil, nil, 1, 8)
	t.Cleanup(s.Close)

	t1 := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)

	t.Run("last_seen_upsert_idempotent", func(t *testing.T) {
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceA, t1, "1.2.3"); err != nil {
			t.Fatal(err)
		}
		var got time.Time
		var edge *string
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at, edge_version FROM m1_devices WHERE id = $1`, h.deviceA).Scan(&got, &edge); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(t1) {
			t.Fatalf("last_seen_at: want %v got %v", t1, got)
		}
		if edge == nil || *edge != "1.2.3" {
			t.Fatalf("edge_version not stamped from the header (m1_061): %v", edge)
		}
		// Replaying an OLDER batch must not move the timestamp backwards, and
		// replay's empty edge version ("" — the header died with the original
		// request) must not erase the recorded one.
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceA, t1.Add(-time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at, edge_version FROM m1_devices WHERE id = $1`, h.deviceA).Scan(&got, &edge); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(t1) {
			t.Fatalf("replay moved last_seen_at backwards: %v", got)
		}
		if edge == nil || *edge != "1.2.3" {
			t.Fatalf("replay erased edge_version: %v", edge)
		}
	})

	t.Run("cross_tenant_read_denied", func(t *testing.T) {
		var n int64
		err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM m1_devices`).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("tenant A sees %d devices; RLS wall is decorative", n)
		}
	})

	t.Run("cross_tenant_write_matches_nothing", func(t *testing.T) {
		// Tenant A's GUC + tenant B's device: the UPDATE must touch 0 rows —
		// the exact ingest-arm shape of the tenant-isolation suite (05 §9).
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceB, t1, "9.9.9"); err != nil {
			t.Fatal(err)
		}
		var seen *time.Time
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at FROM m1_devices WHERE id = $1`, h.deviceB).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			t.Fatalf("cross-tenant write landed: %v", *seen)
		}
	})

	t.Run("unset_guc_matches_nothing", func(t *testing.T) {
		// Raw pool, no WithTenant: the NULLIF policy form must return zero
		// rows, never all rows (05 §7.1).
		n, err := h.appPoolQuery(ctx, `SELECT count(*) FROM m1_devices`)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("unset GUC saw %d rows; the NULLIF floor failed", n)
		}
	})
}

// FR-SPINE-014 layer 2: the ON CONFLICT (event_id) DO NOTHING at sidefx.go:392,
// reached for real.
//
// Two dedupe layers sit IN FRONT of it and short-circuit the obvious test, so a
// "deliver the checkpoint twice" case proves one of them and leaves line 392 as
// dead as it was: the in-memory seen map (sidefx.go:311-317) drops the replayed
// leaf, and re-delivering the SAME seal never reaches the callback at all —
// store.go:197-203 refuses it as broken_link (its checkpoint_seq no longer
// extends the chain) before AppendCheckpoint ever inserts a receipt, and
// sidefx.go:429 then absorbs it as a proven duplicate. That is what
// TestIntegrationSidefxCheckpointAndCoverage (receipts/integration_test.go:573)
// exercises, and why its covCount==1 is not evidence about line 392.
//
// The state that DOES reach it is a restart, which 05 §2.5 makes routine:
// process dies, `seen` and `pending` die with it, replay from the landing
// objects re-admits leaves the chain already sealed, and the device — which
// re-reads the head before every seal (08 §3.4) — seals them again under a
// FRESH checkpoint_seq and fresh signature bytes. Nothing about that seal is
// stale, so it appends, and its coverage insert meets a row that already exists.
// m1_043:48 names this exact case ("UNIQUE = at-least-once ingest cannot
// double-count a gap"); line 392 is the code that makes the constraint a no-op
// instead of a crash.
func TestIntegrationCoverageInsertSurvivesAResealAfterRestart(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)
	covID := uuid.Must(uuid.NewV7())
	cov := &sidefx.Coverage{
		Kind: "bypass_start", WorkspaceDigest: make([]byte, 32),
		OccurredAt: at, Reason: "proxy_bypass",
	}

	// ── First delivery: the row is INSERTED. Counting it is what keeps the
	// final "still one row" from being satisfied by "nothing ever happened".
	before := coverageRowsTotal(t)
	s1 := sidefx.New(h.db, h.store, nil, 1, 8)
	seal1 := h.sealCheckpoint(t, h.deviceA, []uuid.UUID{covID}, at)
	s1.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: covID, Coverage: cov},
		{EventID: seal1.EventID, Checkpoint: &seal1},
	})
	s1.Close() // the restart

	if inserted := coverageRowsTotal(t) - before; inserted != 1 {
		t.Fatalf("first delivery inserted %v coverage row(s), want 1 — with nothing inserted, "+
			"every dedupe assertion below is vacuous", inserted)
	}
	var firstReceipt uuid.UUID
	if err := h.admin.QueryRow(ctx,
		`SELECT receipt_id FROM coverage_transitions WHERE event_id = $1`, covID).Scan(&firstReceipt); err != nil {
		t.Fatalf("first delivery left no coverage row: %v", err)
	}

	// ── Restart + 05 §2.5 replay. The leaf set is m1_083 now: a restart forgets
	// nothing, the re-delivered batch (same leaf, same seal bytes) is a duplicate
	// the chain answers, and a FRESH seal over the already-sealed leaf finds no
	// window and is refused — one leaf is sealed exactly once, so the coverage
	// row is inserted exactly once and keeps the receipt that sealed it.
	s2 := sidefx.New(h.db, h.store, nil, 1, 8)
	t.Cleanup(s2.Close)
	before = coverageRowsTotal(t)
	s2.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: covID, Coverage: cov},
		{EventID: seal1.EventID, Checkpoint: &seal1},
	})
	seal2 := h.sealCheckpoint(t, h.deviceA, []uuid.UUID{covID}, at.Add(time.Minute))
	if bytes.Equal(seal2.OriginSig, seal1.OriginSig) {
		t.Fatal("the re-seal reuses the first seal's signature bytes: this is a re-delivery, not the fresh seal the test needs")
	}
	s2.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: seal2.EventID, Checkpoint: &seal2},
	})

	var receipts2 int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_receipts`).Scan(&receipts2); err != nil {
		t.Fatal(err)
	}
	if receipts2 != 1 {
		t.Fatalf("m1_receipts holds %d row(s), want 1 — a leaf sealed once is sealed once; the replayed leaf stayed consumed (m1_083)", receipts2)
	}
	if n := s2.PendingLeafCount(h.tenantA, h.deviceA); n != 0 {
		t.Fatalf("%d leaf/leaves pending: the replayed, already-consumed leaf re-entered the set", n)
	}
	if again := coverageRowsTotal(t) - before; again != 0 {
		t.Fatalf("the replay inserted %v coverage row(s); at-least-once ingest just double-counted a gap (m1_043:48)", again)
	}

	var rows int64
	var receiptNow string // min(uuid) has no aggregate in PG16; ::text does
	if err := h.admin.QueryRow(ctx,
		`SELECT count(*), coalesce(min(receipt_id::text), '') FROM coverage_transitions WHERE event_id = $1`,
		covID).Scan(&rows, &receiptNow); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("coverage_transitions holds %d rows for one event_id, want 1", rows)
	}
	if receiptNow != firstReceipt.String() {
		t.Fatalf("the coverage row now names receipt %s, not the %s that sealed it", receiptNow, firstReceipt)
	}
}

// The bug m1_083 exists for: controld runs replicas: 2, a device's batch N lands on one pod and the
// checkpoint sealing it arrives on the other. With the leaf set in each pod's memory every checkpoint
// refused as merkle_mismatch (555 security rows on one tenant in a day; "Server pending" on every
// receipt in the app). Two Sidefx over one database are two pods.
func TestIntegrationCheckpointSealsLeavesAnotherReplicaLanded(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 19, 23, 0, 0, 0, time.UTC)
	podA := sidefx.New(h.db, h.store, nil, 1, 8)
	t.Cleanup(podA.Close)
	podB := sidefx.New(h.db, h.store, nil, 1, 8)
	t.Cleanup(podB.Close)

	batch1 := uuid.Must(uuid.NewV7())
	ids := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	podA.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: ids[0], BatchID: batch1, Index: 0},
		{EventID: ids[1], BatchID: batch1, Index: 1},
		{EventID: ids[2], BatchID: batch1, Index: 2},
	})
	seal := h.sealCheckpoint(t, h.deviceA, ids, at.Add(time.Second))
	seal.LastEventID = ids[2]
	var paged []string
	podB = sidefx.New(h.db, h.store, func(_, _, _ uuid.UUID, detail string, _ time.Time) { paged = append(paged, detail) }, 1, 8)
	t.Cleanup(podB.Close)
	podB.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: seal.EventID, BatchID: uuid.Must(uuid.NewV7()), Index: 0, Checkpoint: &seal},
	})
	if len(paged) != 0 {
		t.Fatalf("the other pod's leaves paged security: %q", paged)
	}
	var receipts int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("m1_receipts holds %d row(s), want 1: the checkpoint did not seal leaves the other replica landed", receipts)
	}
	if n := podA.PendingLeafCount(h.tenantA, h.deviceA); n != 0 {
		t.Fatalf("%d leaf/leaves still pending on pod A after pod B sealed them", n)
	}
}
