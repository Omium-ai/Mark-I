//go:build integration

package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// quarantinePG is the house scratch-database harness (sidefx/integration_test.go setupPG, trimmed): the real migration
// tree, a NOBYPASSRLS stand-in for controld_app, two tenants, one device, the chain key published.
type quarantinePG struct {
	admin   *pgx.Conn
	db      *pg.TenantDB
	tenantA querychoke.TenantID
	tenantB querychoke.TenantID
	deviceA uuid.UUID
	chain   *receipts.Store
}

func setupQuarantinePG(t *testing.T) *quarantinePG {
	t.Helper()
	ctx := context.Background()
	dsn := svcRequire(t, "M1_MIGRATE_PG_DSN")
	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	scratch := fmt.Sprintf("controld_qs_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("qsapp_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = bootstrap.Exec(bg, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = bootstrap.Exec(bg, "DROP ROLE IF EXISTS "+role)
		_ = bootstrap.Close(bg)
	})
	scratchCfg := adminCfg.Copy()
	scratchCfg.Database = scratch
	admin, err := pgx.ConnectConfig(ctx, scratchCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_[0-9]*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v (%d)", err, len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(f), err)
		}
	}
	_, err = admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD 'qstest' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	var orgID uuid.UUID
	if err := admin.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ('qs-it', 'qs-it.example') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	mkTenant := func(name string) (uuid.UUID, uuid.UUID) {
		var tid, did uuid.UUID
		if err := admin.QueryRow(ctx, `INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, name).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`, tid, make([]byte, 32)).Scan(&did); err != nil {
			t.Fatal(err)
		}
		return tid, did
	}
	tA, dA := mkTenant("tenant-a")
	tB, _ := mkTenant("tenant-b")
	pool, err := pg.Open(ctx, fmt.Sprintf("postgres://%s:qstest@%s:%d/%s?sslmode=disable", role, adminCfg.Host, adminCfg.Port, scratch))
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)
	chainKey, err := receipts.NewSigner(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.RegisterServerKey(ctx, pool, chainKey); err != nil {
		t.Fatal(err)
	}
	tenantA, err := querychoke.FromClaims(auth.Claims{TenantID: tA, DeviceID: dA})
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := querychoke.FromClaims(auth.Claims{TenantID: tB})
	if err != nil {
		t.Fatal(err)
	}
	db := pg.NewTenantDB(pool)
	return &quarantinePG{admin: admin, db: db, tenantA: tenantA, tenantB: tenantB, deviceA: dA, chain: receipts.NewStore(db, chainKey)}
}

type tombstoneRow struct {
	key       string
	events    int
	at        time.Time
	deletedAt *time.Time
	receiptID *uuid.UUID
}

func (q *quarantinePG) tombstone(t *testing.T, batch uuid.UUID) (tombstoneRow, bool) {
	t.Helper()
	var r tombstoneRow
	err := q.admin.QueryRow(context.Background(),
		`SELECT object_key, event_count, quarantined_at, deleted_at, receipt_id FROM m1_quarantined_batches WHERE batch_id = $1`, batch).
		Scan(&r.key, &r.events, &r.at, &r.deletedAt, &r.receiptID)
	if err == pgx.ErrNoRows {
		return r, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return r, true
}

func (q *quarantinePG) deletionRecords(t *testing.T, batch uuid.UUID) []map[string]any {
	t.Helper()
	rows, err := q.admin.Query(context.Background(),
		`SELECT id, payload FROM m1_receipts WHERE record_type = 'quarantine_deletion' AND subject_id = $1 ORDER BY seq`, batch)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(payload), &m); err != nil {
			t.Fatal(err)
		}
		m["_id"] = id
		out = append(out, m)
	}
	return out
}

type quarantineRig struct {
	*quarantinePG
	store  *s3land.Client
	direct *s3.Client
	bucket string
	ins    *fakeInserter
	now    time.Time
	url    string
	token  string
	mod    *Module
}

func setupQuarantineRig(t *testing.T, rs *scanner.Ruleset) *quarantineRig {
	t.Helper()
	r := &quarantineRig{quarantinePG: setupQuarantinePG(t), ins: &fakeInserter{}, now: time.Now().UTC().Truncate(time.Millisecond)}
	r.store, r.direct, r.bucket = svcS3Direct(t)
	proj := chproj.New(r.ins, 1, 64)
	t.Cleanup(proj.Close)
	sfx := sidefx.New(&fakeDB{}, nil, nil, 1, 64)
	sfx.SetLeafStore(sidefx.NewMemoryLeafStore())
	t.Cleanup(sfx.Close)
	r.mod = New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-qs-it"},
		PG:       fakeReady{}, Store: r.store, Proj: proj, Sidefx: sfx, Security: &fakeSecurity{},
		DB: r.db, Scanner: rs, PoolSize: 4,
		Now: func() time.Time { return r.now },
	})
	mux := http.NewServeMux()
	r.mod.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r.url, r.token = srv.URL, auth.Mint(testKey, r.tenantA.UUID(), r.deviceA, time.Hour)
	return r
}

func (r *quarantineRig) post(t *testing.T, id uuid.UUID, body []byte) int {
	t.Helper()
	code, _ := svcPost(t, r.url, "/m1p/v1/ingest", r.token, nil, id, body)
	return code
}

func (r *quarantineRig) objectExists(t *testing.T, key string) bool {
	t.Helper()
	out, err := r.store.Probe(context.Background(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out != s3land.NotLanded
}

func (r *quarantineRig) sweepAt(t *testing.T, at time.Time, tenant uuid.UUID) int {
	t.Helper()
	j := NewQuarantineSweep(r.db, r.store, r.chain, receipts.StaticTenants([]uuid.UUID{tenant}))
	j.Clock(func() time.Time { return at }, nil)
	n, err := j.SweepTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("sweep at %s: %v", at, err)
	}
	return n
}

// The whole cloud half against real stores: the landing writes the tombstone and the tagged twin; 29 d 23 h keeps
// both; 30 d deletes the MinIO object and, in one transaction, appends the origin=cloud receipt and closes the
// tombstone with its id; a twin the lifecycle already removed is receipted as lifecycle_backstop; tenant B sees none
// of it.
func TestIntegrationQuarantineTombstoneAndCloudSweep(t *testing.T) {
	r := setupQuarantineRig(t, nil)
	ctx := context.Background()

	b, id := leakyBatch(t)
	body := encodeBatch(t, b)
	if code := r.post(t, id, body); code != http.StatusAccepted {
		t.Fatalf("leaky batch: want 202, got %d", code)
	}
	key := s3land.QuarantineKey(r.tenantA.UUID(), id)
	row, ok := r.tombstone(t, id)
	if !ok || row.key != key || row.events != len(b.GetEvents()) || row.deletedAt != nil || !row.at.Equal(r.now) {
		t.Fatalf("tombstone after landing: ok=%v %+v (want key %s, %d events, at %s)", ok, row, key, len(b.GetEvents()), r.now)
	}
	tags, err := r.direct.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{Bucket: aws.String(r.bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("twin missing or untagged: %v", err)
	}
	if len(tags.TagSet) != 1 || aws.ToString(tags.TagSet[0].Key) != "class" || aws.ToString(tags.TagSet[0].Value) != "quarantine" {
		t.Fatalf("09's lifecycle rule filters on class=quarantine; the twin carries %v", tags.TagSet)
	}
	// The 08 §2.5 retry re-POSTs the same bytes: duplicate ack, one tombstone.
	if code := r.post(t, id, body); code != http.StatusAccepted {
		t.Fatalf("re-POST: want 202, got %d", code)
	}
	var n int
	if err := r.admin.QueryRow(ctx, `SELECT count(*) FROM m1_quarantined_batches`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tombstones after re-POST = %d (%v), want 1", n, err)
	}

	quarantinedAt := r.now
	if got := r.sweepAt(t, quarantinedAt.Add(29*24*time.Hour+23*time.Hour), r.tenantA.UUID()); got != 0 {
		t.Fatalf("29 d 23 h: sweep closed %d, want 0", got)
	}
	if !r.objectExists(t, key) {
		t.Fatal("29 d 23 h: the twin must still exist")
	}
	if recs := r.deletionRecords(t, id); len(recs) != 0 {
		t.Fatalf("29 d 23 h: %d receipts, want none", len(recs))
	}

	deleteAt := quarantinedAt.Add(30 * 24 * time.Hour)
	if got := r.sweepAt(t, deleteAt, r.tenantA.UUID()); got != 1 {
		t.Fatalf("30 d: sweep closed %d, want 1", got)
	}
	if r.objectExists(t, key) {
		t.Fatal("30 d: the twin must be gone from the bucket")
	}
	recs := r.deletionRecords(t, id)
	if len(recs) != 1 {
		t.Fatalf("30 d: %d receipts, want 1", len(recs))
	}
	rec := recs[0]
	for k, v := range map[string]any{
		"origin": "cloud", "reason": "retention_30d", "event_count": float64(len(b.GetEvents())),
		"quarantined_at": sidefx.MillisString(quarantinedAt), "deleted_at": sidefx.MillisString(deleteAt),
		"subject_id": id.String(), "tenant_id": r.tenantA.String(),
	} {
		if rec[k] != v {
			t.Fatalf("receipt[%s] = %v, want %v (%v)", k, rec[k], v, rec)
		}
	}
	row, _ = r.tombstone(t, id)
	if row.deletedAt == nil || !row.deletedAt.Equal(deleteAt) || row.receiptID == nil || *row.receiptID != rec["_id"].(uuid.UUID) {
		t.Fatalf("tombstone must close with the receipt that closed it: %+v vs receipt %v", row, rec["_id"])
	}
	if got := r.sweepAt(t, deleteAt.Add(24*time.Hour), r.tenantA.UUID()); got != 0 {
		t.Fatalf("a closed tombstone must not be swept again: %d", got)
	}
	if recs := r.deletionRecords(t, id); len(recs) != 1 {
		t.Fatalf("second sweep re-receipted: %d", len(recs))
	}
	// Two replicas: the loser reaches receipt() after the winner closed the row; the FOR UPDATE no-row branch is what
	// keeps it from minting a second receipt for one deletion.
	loser := NewQuarantineSweep(r.db, r.store, r.chain, receipts.StaticTenants([]uuid.UUID{r.tenantA.UUID()}))
	if err := loser.receipt(ctx, r.tenantA, expiredTombstone{batchID: id, key: key, quarantinedAt: quarantinedAt, events: row.events}, "retention_30d", deleteAt.Add(time.Hour)); err != nil {
		t.Fatalf("losing replica must skip quietly, got %v", err)
	}
	if recs := r.deletionRecords(t, id); len(recs) != 1 {
		t.Fatalf("a losing replica re-receipted a closed tombstone: %d receipts", len(recs))
	}

	// Lifecycle backstop: the object is already gone when the sweep arrives.
	r.now = r.now.Add(time.Minute)
	b2, id2 := leakyBatch(t)
	if code := r.post(t, id2, encodeBatch(t, b2)); code != http.StatusAccepted {
		t.Fatalf("second leaky batch: %d", code)
	}
	key2 := s3land.QuarantineKey(r.tenantA.UUID(), id2)
	if _, err := r.direct.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(r.bucket), Key: aws.String(key2)}); err != nil {
		t.Fatal(err)
	}
	if got := r.sweepAt(t, r.now.Add(30*24*time.Hour), r.tenantA.UUID()); got != 1 {
		t.Fatalf("backstop sweep closed %d, want 1", got)
	}
	recs2 := r.deletionRecords(t, id2)
	if len(recs2) != 1 || recs2[0]["reason"] != "lifecycle_backstop" || recs2[0]["origin"] != "cloud" {
		t.Fatalf("an already-gone twin must be receipted naming the backstop: %v", recs2)
	}
	if row2, _ := r.tombstone(t, id2); row2.deletedAt == nil || row2.receiptID == nil {
		t.Fatalf("backstop tombstone not closed: %+v", row2)
	}

	// Tenancy: tenant B's session sees no tombstone of tenant A's, and its sweep has nothing to close.
	var seen int
	if err := r.db.WithTenant(ctx, r.tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM m1_quarantined_batches`).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Fatalf("tenant B sees %d of tenant A's tombstones (%v)", seen, err)
	}
	if got := r.sweepAt(t, r.now.Add(60*24*time.Hour), r.tenantB.UUID()); got != 0 {
		t.Fatalf("tenant B's sweep closed %d of tenant A's batches", got)
	}
}

// Replay refuses a tombstoned batch even after its twin is gone — the regression the tombstone exists to close: a
// batch quarantined after landing (Rescan) used to be replayable the day the lifecycle removed its twin.
func TestIntegrationReplayRefusesTombstonedBatchAfterTheTwinIsGone(t *testing.T) {
	editionA, err := scanner.Compile("A", map[string]string{plantedAWSClass: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`})
	if err != nil {
		t.Fatal(err)
	}
	r := setupQuarantineRig(t, editionA)
	ctx := context.Background()

	session := mustV7(t)
	gh := usageEvent(t, session, 1)
	gh.GetUsage().RequestId = plantedGHToken
	dirty, dirtyID := testBatch(t, gh)
	clean, cleanID := testBatch(t, usageEvent(t, session, 2))
	for _, p := range []struct {
		id   uuid.UUID
		body []byte
	}{{dirtyID, encodeBatch(t, dirty)}, {cleanID, encodeBatch(t, clean)}} {
		if code := r.post(t, p.id, p.body); code != http.StatusOK {
			t.Fatalf("landing under edition A: want 200, got %d", code)
		}
	}
	day := time.Now().UTC()
	r.mod.scanner = scanner.Default
	if flagged, err := r.mod.Rescan(ctx, r.tenantA, day, day); err != nil || flagged != 1 {
		t.Fatalf("rescan: flagged=%d err=%v", flagged, err)
	}
	if _, ok := r.tombstone(t, dirtyID); !ok {
		t.Fatal("Rescan must tombstone the batch it quarantines")
	}
	if got := r.sweepAt(t, r.now.Add(30*24*time.Hour), r.tenantA.UUID()); got != 1 {
		t.Fatalf("sweep closed %d, want the rescanned twin", got)
	}
	if r.objectExists(t, s3land.QuarantineKey(r.tenantA.UUID(), dirtyID)) {
		t.Fatal("twin must be gone before replay is asked")
	}

	ins := &fakeInserter{}
	replayed, err := Replay(ctx, r.db, r.store, ins, nil, r.tenantA, day, day)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != 1 {
		t.Fatalf("replayed %d objects, want exactly the clean batch", replayed)
	}
	for _, row := range ins.rows {
		if strings.Contains(fmt.Sprint(row), plantedGHToken) {
			t.Fatal("the tombstoned batch's secret re-entered the ledger through replay")
		}
	}
	// The belt-and-braces OR still holds for a twin with no tombstone (pre-m1_080 objects): plant one directly.
	if _, err := r.admin.Exec(ctx, `DELETE FROM m1_quarantined_batches WHERE batch_id = $1`, dirtyID); err == nil {
		t.Fatal("tombstones must be undeletable (m1_append_only)")
	}
	legacy, legacyID := testBatch(t, usageEvent(t, session, 3))
	legacyBody := encodeBatch(t, legacy)
	if code := r.post(t, legacyID, legacyBody); code != http.StatusOK {
		t.Fatalf("legacy landing: %d", code)
	}
	if out, err := r.store.Land(ctx, s3land.QuarantineKey(r.tenantA.UUID(), legacyID), legacyBody, r.tenantA.UUID(), r.deviceA); err != nil || out != s3land.Landed {
		t.Fatalf("planting a legacy twin: %v %v", out, err)
	}
	ins2 := &fakeInserter{}
	if replayed, err := Replay(ctx, r.db, r.store, ins2, nil, r.tenantA, day, day); err != nil || replayed != 1 {
		t.Fatalf("legacy twin without a tombstone must still block replay: replayed=%d err=%v", replayed, err)
	}
}
