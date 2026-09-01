//go:build integration

// DSN-gated Postgres integration for the receipt spine (house style, 12 /
// 05 §7.5): a scratch database gets the real migrations, a NOBYPASSRLS login
// role stands in for controld_app, and the tests prove the chain properties
// the migrations state — gap-free seq under the head lock, refusal typology,
// witness publish-then-insert — plus the C7 exit shape end to end: a chain
// built through the server writer, exported over the HTTP surface, verified
// by the ACTUAL mark1-verifier binary (exit 0), then one flipped byte (exit
// 5, the named defect).
//
// Gates: M1_MIGRATE_PG_DSN (privileged DSN for scratch setup); the verifier e2e
// additionally needs cargo. Absent ⇒ skip, unless M1_REQUIRE_STORES=1 ⇒ fail.

package receipts_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
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
// unprivileged role minted below, never as this one.
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

type harness struct {
	admin     *pgx.Conn
	pool      *pgxpool.Pool
	db        *pg.TenantDB
	appRole   string
	tenantA   querychoke.TenantID
	tenantB   querychoke.TenantID
	deviceA   uuid.UUID
	deviceB   uuid.UUID
	deviceKey *receipts.Signer // deviceA's origin key, registered in m1_device_keys
	chainKey  *receipts.Signer // the server chain key, registered in m1_server_signing_keys
	store     *receipts.Store
}

func setup(t *testing.T) *harness {
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

	scratch := fmt.Sprintf("controld_c6_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("c6app_%d", time.Now().UnixNano())
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
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_0*.sql"))
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

	_, err = admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'c6test' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('c6-it', 'c6-it.example') RETURNING id`,
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

	appDSN := fmt.Sprintf("postgres://%s:c6test@%s:%d/%s?sslmode=disable",
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

	tenantA, err := querychoke.FromClaims(auth.Claims{TenantID: tA, DeviceID: dA})
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := querychoke.FromClaims(auth.Claims{TenantID: tB, DeviceID: dB})
	if err != nil {
		t.Fatal(err)
	}
	db := pg.NewTenantDB(pool)
	return &harness{
		admin: admin, pool: pool, db: db, appRole: role,
		tenantA: tenantA, tenantB: tenantB, deviceA: dA, deviceB: dB,
		deviceKey: deviceKey, chainKey: chainKey,
		store: receipts.NewStore(db, chainKey),
	}
}

// sealCheckpointErr plays the edge: read the head (as a device would via
// 08 §3.4), build the checkpoint payload at seq+1/checkpoint_seq+1, and
// origin-sign it — producing the wire-side CheckpointEvent the ingest path
// hands the store. Error-returning so worker goroutines can use it (t.Fatal
// is test-goroutine-only).
func (h *harness) sealCheckpointErr(tenant querychoke.TenantID, device uuid.UUID, key *receipts.Signer, leaves [][]byte, issuedAt time.Time) (receipts.CheckpointEvent, error) {
	seq, head, ckpt, err := h.store.Head(context.Background(), tenant)
	if err != nil {
		return receipts.CheckpointEvent{}, err
	}
	root, err := receipts.MerkleRoot(leaves)
	if err != nil {
		return receipts.CheckpointEvent{}, err
	}
	cp := receipts.Checkpoint{
		TenantID:        tenant.String(),
		DeviceID:        device.String(),
		Seq:             seq + 1,
		PrevReceiptHash: head,
		IssuedAt:        receipts.IssuedAtString(issuedAt),
		CheckpointSeq:   ckpt + 1,
		MerkleRoot:      root,
		LeafCount:       len(leaves),
	}
	signed, err := receipts.OriginSign(key, cp.Payload(key.KeyID()))
	if err != nil {
		return receipts.CheckpointEvent{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return receipts.CheckpointEvent{}, err
	}
	return receipts.CheckpointEvent{
		EventID:              id,
		DeviceID:             device,
		DeviceKeyID:          key.KeyID(),
		ClaimedCheckpointSeq: ckpt + 1,
		MerkleRoot:           root,
		LeafCount:            len(leaves),
		OriginSig:            signed.DeviceSig,
		IssuedAt:             issuedAt,
	}, nil
}

func (h *harness) sealCheckpoint(t *testing.T, tenant querychoke.TenantID, device uuid.UUID, key *receipts.Signer, leaves [][]byte, issuedAt time.Time) receipts.CheckpointEvent {
	t.Helper()
	ev, err := h.sealCheckpointErr(tenant, device, key, leaves, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func leavesOf(ids ...uuid.UUID) [][]byte {
	out := make([][]byte, len(ids))
	for i := range ids {
		id := ids[i]
		out[i] = id[:]
	}
	return out
}

func v7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIntegrationAppendGenesisLinkageAndRefusals(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 29, 10, 0, 1, 0, time.UTC)

	ev1 := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t), v7(t), v7(t)), at)
	r1, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev1, nil)
	if err != nil {
		t.Fatalf("genesis append: %v", err)
	}
	if r1.Seq != 1 || r1.CheckpointSeq != 1 {
		t.Fatalf("genesis landed at seq %d / ckpt %d, want 1/1", r1.Seq, r1.CheckpointSeq)
	}

	ev2 := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), at.Add(time.Second))
	r2, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev2, nil)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if r2.Seq != 2 {
		t.Fatalf("second append seq %d, want 2", r2.Seq)
	}
	// prev linkage: row 2's payload embeds row 1's hash.
	if !strings.Contains(r2.PayloadText, hex.EncodeToString(r1.ReceiptHash[:])) {
		t.Fatal("second payload does not link the first receipt's hash")
	}

	// Tampered origin signature ⇒ bad_signature refusal, nothing appended.
	ev3 := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), at.Add(2*time.Second))
	ev3.OriginSig[0] ^= 0xff
	_, err = h.store.AppendCheckpoint(ctx, h.tenantA, ev3, nil)
	if ref, ok := receipts.AsRefusal(err); !ok || ref.Code != receipts.DefectBadSignature {
		t.Fatalf("tampered origin signature: want bad_signature refusal, got %v", err)
	}

	// The server chain key answering the ORIGIN leg ⇒ unknown_key (the
	// vectors' S1: role binding via the table split — the chain key is not in
	// m1_device_keys, so it cannot mint device history).
	ev4 := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.chainKey, leavesOf(v7(t)), at.Add(3*time.Second))
	_, err = h.store.AppendCheckpoint(ctx, h.tenantA, ev4, nil)
	if ref, ok := receipts.AsRefusal(err); !ok || ref.Code != receipts.DefectUnknownKey {
		t.Fatalf("server key as device origin: want unknown_key refusal, got %v", err)
	}

	// A stale seal (device behind the head) ⇒ broken_link refusal naming the
	// retry semantic, not a bare signature failure.
	stale := ev2
	_, err = h.store.AppendCheckpoint(ctx, h.tenantA, stale, nil)
	if ref, ok := receipts.AsRefusal(err); !ok || ref.Code != receipts.DefectBrokenLink {
		t.Fatalf("stale checkpoint replay: want broken_link refusal, got %v", err)
	}

	// Nothing from the refusals reached the table (RLS-scoped count via the
	// admin superuser, deliberately outside the app role).
	var n int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_receipts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("m1_receipts holds %d rows, want 2", n)
	}

	// A key registered to deviceA refuses to answer for deviceB — the
	// impersonation direction.
	ev5 := h.sealCheckpoint(t, h.tenantA, h.deviceB, h.deviceKey, leavesOf(v7(t)), at.Add(4*time.Second))
	_, err = h.store.AppendCheckpoint(ctx, h.tenantA, ev5, nil)
	if ref, ok := receipts.AsRefusal(err); !ok || ref.Code != receipts.DefectUnknownKey {
		t.Fatalf("wrong device for key: want unknown_key refusal, got %v", err)
	}

	// Tenant B's chain cannot see tenant A's key at all (RLS wall).
	evB := h.sealCheckpoint(t, h.tenantB, h.deviceB, h.deviceKey, leavesOf(v7(t)), at)
	_, err = h.store.AppendCheckpoint(ctx, h.tenantB, evB, nil)
	if ref, ok := receipts.AsRefusal(err); !ok || ref.Code != receipts.DefectUnknownKey {
		t.Fatalf("cross-tenant key: want unknown_key refusal, got %v", err)
	}
}

// FR-SPINE-017's negative, which 02's Verification column asks for by name.
// m1_002 makes m1_receipts append-only three INDEPENDENT ways (grants, a row
// trigger, a TRUNCATE trigger), so a migration that drops one while leaving
// the others would keep every other test in this file green. Each mechanism
// is therefore made to refuse ON ITS OWN: the grant layer first, then the
// triggers — reachable only once the grant that would otherwise answer first
// is handed back.
func TestIntegrationReceiptsAppendOnly(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	ev := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), time.Now())
	r1, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Every attempt runs on the connection shape a REQUEST uses — the
	// NOBYPASSRLS app role with the tenant GUC set — never the migration
	// superuser, which bypasses privilege checks and would prove nothing.
	attempt := func(sql string) error {
		return h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
	}
	// RLS filters UPDATE/DELETE targets BEFORE any row trigger runs, so a row
	// this role cannot see turns every statement below into a zero-row
	// SUCCESS: the test would observe nothing and still pass. Visibility is
	// the precondition that makes the refusals mean something.
	var visible int64
	if err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM m1_receipts`).Scan(&visible)
	}); err != nil {
		t.Fatal(err)
	}
	if visible != 1 {
		t.Fatalf("app role sees %d receipts, want 1 — the writes below would refuse nothing", visible)
	}

	// Ordered, not a map: whichever statement runs first is the only one whose
	// escape is observed cleanly, because a leak that empties the table makes
	// the rest refuse nothing. TRUNCATE last, so a broken mechanism is named
	// by the one line that fails rather than by all three.
	stmts := []struct{ op, sql string }{
		{"UPDATE", `UPDATE m1_receipts SET payload = '{"rewritten":true}'`},
		{"DELETE", `DELETE FROM m1_receipts`},
		{"TRUNCATE", `TRUNCATE m1_receipts`},
	}
	// (a) The grant layer: controld holds SELECT+INSERT on the chain, nothing
	// more (m1_002 §5). This is the leg that answers in production.
	for _, s := range stmts {
		err := attempt(s.sql)
		if err == nil || !strings.Contains(err.Error(), "permission denied for table m1_receipts") {
			t.Errorf("%s as the app role: want permission denied, got %v", s.op, err)
		}
	}

	// (b)+(c) The triggers, which are the leg that HOLDS. Granting the app
	// role exactly what m1_002 revoked disarms the grant layer, so a silent
	// pass here can only mean the trigger is gone. Both raise SQLSTATE 42501,
	// so the message — not the code — is what tells the two legs apart.
	if _, err := h.admin.Exec(ctx,
		`GRANT UPDATE, DELETE, TRUNCATE ON m1_receipts TO `+h.appRole); err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		err := attempt(s.sql)
		if err == nil || !strings.Contains(err.Error(), "append-only; "+s.op+" is not permitted") {
			t.Errorf("%s with the privilege granted back: want the append-only trigger, got %v", s.op, err)
		}
	}

	// The chain is byte-identical: a refusal that still mutated would be the
	// worst outcome of the three.
	var count int64
	var payload string
	if err := h.admin.QueryRow(ctx,
		`SELECT count(*), coalesce(max(payload), '') FROM m1_receipts`).Scan(&count, &payload); err != nil {
		t.Fatal(err)
	}
	if count != 1 || payload != r1.PayloadText {
		t.Fatalf("the chain moved under a refused write: %d row(s), payload %q", count, payload)
	}
}

// The head lock serializes concurrent appends for one tenant: no gap, no
// duplicate seq, ever — losers refuse (stale seal) and re-seal against the
// fresh head, exactly the edge's retry semantic.
func TestIntegrationConcurrentAppendsGapFreeSeq(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	const workers, perWorker = 8, 5

	var mu sync.Mutex // guards the results slice only — sealing races on purpose
	var landed []int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < perWorker; k++ {
				for {
					id, err := uuid.NewV7()
					if err != nil {
						t.Errorf("uuid: %v", err)
						return
					}
					ev, err := h.sealCheckpointErr(h.tenantA, h.deviceA, h.deviceKey,
						leavesOf(id), time.Now())
					if err != nil {
						t.Errorf("seal failed: %v", err)
						return
					}
					r, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev, nil)
					if err == nil {
						mu.Lock()
						landed = append(landed, r.Seq)
						mu.Unlock()
						break
					}
					if _, isRefusal := receipts.AsRefusal(err); isRefusal {
						continue // lost the race: re-seal against the fresh head
					}
					t.Errorf("append failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if len(landed) != workers*perWorker {
		t.Fatalf("landed %d checkpoints, want %d", len(landed), workers*perWorker)
	}
	sort.Slice(landed, func(i, j int) bool { return landed[i] < landed[j] })
	for i, s := range landed {
		if s != int64(i+1) {
			t.Fatalf("seq sequence has a gap or duplicate at index %d: %v", i, landed)
		}
	}
	var maxSeq, count int64
	if err := h.admin.QueryRow(ctx,
		`SELECT max(seq), count(*) FROM m1_receipts`).Scan(&maxSeq, &count); err != nil {
		t.Fatal(err)
	}
	if maxSeq != int64(workers*perWorker) || count != int64(workers*perWorker) {
		t.Fatalf("table shows max=%d count=%d, want both %d", maxSeq, count, workers*perWorker)
	}
}

// Stage 11 end to end: leaves + coverage events + the checkpoint that seals
// them, through the sidefx machinery against the real writer — the
// coverage_transitions row lands in the SAME tx with the receipt's id.
func TestIntegrationSidefxCheckpointAndCoverage(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	var securityEvents []string
	sec := func(_, _, _ uuid.UUID, detail string, _ time.Time) {
		securityEvents = append(securityEvents, detail)
	}
	s := sidefx.New(h.db, h.store, sec, 1, 8)
	t.Cleanup(s.Close)

	at := time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)
	covID, plainID := v7(t), v7(t)
	seal := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(covID, plainID), at)
	effects := []sidefx.Effect{
		{EventID: covID, Coverage: &sidefx.Coverage{
			Kind: "bypass_start", WorkspaceDigest: make([]byte, 32),
			OccurredAt: at, Reason: "proxy_bypass"}},
		{EventID: plainID},
		{EventID: seal.EventID, Checkpoint: &seal},
	}
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", effects)

	var receiptID uuid.UUID
	var kind, reason string
	if err := h.admin.QueryRow(ctx,
		`SELECT receipt_id, kind::text, reason FROM coverage_transitions WHERE event_id = $1`,
		covID).Scan(&receiptID, &kind, &reason); err != nil {
		t.Fatalf("coverage row missing: %v", err)
	}
	if kind != "bypass_start" || reason != "proxy_bypass" {
		t.Fatalf("coverage row wrong: kind=%s reason=%s", kind, reason)
	}
	var receiptType string
	if err := h.admin.QueryRow(ctx,
		`SELECT record_type FROM m1_receipts WHERE id = $1`, receiptID).Scan(&receiptType); err != nil {
		t.Fatalf("coverage receipt_id names no receipt: %v", err)
	}
	if receiptType != "checkpoint" {
		t.Fatalf("receipt_id names a %s, want the sealing checkpoint", receiptType)
	}
	if got := s.PendingLeafCount(h.tenantA, h.deviceA); got != 0 {
		t.Fatalf("pending leaves after seal: %d", got)
	}

	// Replay of the same effects: leaf dedupe holds, the stale checkpoint is
	// a logged no-op (broken_link), and no security event fires.
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", effects)
	var covCount int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM coverage_transitions`).Scan(&covCount); err != nil {
		t.Fatal(err)
	}
	if covCount != 1 {
		t.Fatalf("replay double-counted coverage: %d rows", covCount)
	}
	if len(securityEvents) != 0 {
		t.Fatalf("replay must not page: %v", securityEvents)
	}

	// A tampered origin signature through the same path IS a security event.
	bad := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), at.Add(time.Minute))
	bad.OriginSig[10] ^= 0x01
	leafID := v7(t)
	// The pending set must contain the tampered seal's leaf for the merkle
	// check to pass and the signature check to be what refuses.
	badLeaves := leavesOf(leafID)
	root, err := receipts.MerkleRoot(badLeaves)
	if err != nil {
		t.Fatal(err)
	}
	bad.MerkleRoot = root
	bad.LeafCount = 1
	s.Apply(ctx, h.tenantA, h.deviceA, at, "", []sidefx.Effect{
		{EventID: leafID},
		{EventID: bad.EventID, Checkpoint: &bad},
	})
	if len(securityEvents) != 1 || !strings.Contains(securityEvents[0], "origin signature") {
		t.Fatalf("tampered origin signature must emit a security event, got %v", securityEvents)
	}
}

type fakePublisher struct {
	calls int
	fail  bool
}

func (f *fakePublisher) Publish(_ context.Context, tenant uuid.UUID, statement, sig []byte, keyID string) (receipts.Destination, error) {
	f.calls++
	if f.fail {
		return receipts.Destination{}, errors.New("bucket down")
	}
	uri := fmt.Sprintf("s3://witness-test/%s/%d", tenant, f.calls)
	etag := "etag-1"
	retain := time.Now().Add(24 * time.Hour)
	return receipts.Destination{BucketURI: &uri, ETag: &etag, RetainUntil: &retain}, nil
}

func TestIntegrationWitnessJobPublishThenInsert(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	// Seed a one-receipt chain so there is a head to witness.
	ev := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), time.Now())
	if _, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev, nil); err != nil {
		t.Fatal(err)
	}

	pub := &fakePublisher{}
	tenants := receipts.StaticTenants([]uuid.UUID{h.tenantA.UUID(), h.tenantB.UUID()})
	job := receipts.NewWitnessJob(h.db, h.chainKey, pub, tenants, time.Hour)

	if err := job.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var rows int64
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_witness_heads`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	// Tenant A witnessed; tenant B has an empty chain — nothing to witness
	// (m1_003's witnessed_seq > 0).
	if rows != 1 || pub.calls != 1 {
		t.Fatalf("witness rows=%d publishes=%d, want 1/1", rows, pub.calls)
	}

	// Within the interval: idempotent skip, no duplicate publication.
	if err := job.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_witness_heads`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || pub.calls != 1 {
		t.Fatalf("witness re-ran within the hour: rows=%d publishes=%d", rows, pub.calls)
	}

	// The row records a COMPLETED publication: statement verifies under the
	// chain key in the witness domain, and the witnessed facts match the head.
	var statement string
	var sig, hash []byte
	var seq int64
	if err := h.admin.QueryRow(ctx,
		`SELECT statement, server_signature, witnessed_hash, witnessed_seq FROM m1_witness_heads`).
		Scan(&statement, &sig, &hash, &seq); err != nil {
		t.Fatal(err)
	}
	if !receipts.Verify(h.chainKey.Public(), sig, append([]byte(receipts.WitnessDomainPrefix), statement...)) {
		t.Fatal("witness statement signature does not verify under the chain key")
	}
	headSeq, headHash, _, err := h.store.Head(ctx, h.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if seq != headSeq || !bytes.Equal(hash, headHash[:]) {
		t.Fatal("witnessed facts do not match the chain head")
	}

	// Publish failure ⇒ NO row: a failed hour is a missing row, never a row
	// recording a publication that did not happen (m1_003 header).
	pub.fail = true
	ev2 := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), time.Now())
	if _, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev2, nil); err != nil {
		t.Fatal(err)
	}
	failJob := receipts.NewWitnessJob(h.db, h.chainKey, pub, tenants, time.Nanosecond)
	if err := failJob.RunOnce(ctx); err != nil {
		t.Fatal(err) // per-tenant failures are contained, not fatal to the tick
	}
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_witness_heads`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("a failed publication inserted a row: %d", rows)
	}
}

// The C7 exit shape against THIS server's writer and export surface: build a
// chain through the API-path machinery, export it over HTTP, and the shipped
// mark1-verifier binary must pass it offline (exit 0); flip one byte and the
// verdict must be a named defect with exit 5 (08 §7.7's exit contract).
func TestIntegrationVerifierE2EExportRoundTrip(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	if _, err := exec.LookPath("cargo"); err != nil {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("cargo required (M1_REQUIRE_STORES=1) but not found")
		}
		t.Skip("cargo not found; skipping verifier e2e")
	}

	// Build the verifier binary the customer actually runs.
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("cargo", "build", "--locked", "-p", "mark1-verifier")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build: %v\n%s", err, out)
	}
	verifierBin := filepath.Join(repoRoot, "target", "debug", "mark1-verifier")

	// Chain of three checkpoints via the stage-11 path (odd/single/even leaf
	// counts — the same batch shapes the frozen Merkle vectors exercise).
	s := sidefx.New(h.db, h.store, nil, 1, 16)
	t.Cleanup(s.Close)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for i, n := range []int{3, 1, 2} {
		ids := make([]uuid.UUID, n)
		effects := make([]sidefx.Effect, 0, n+1)
		for j := range ids {
			ids[j] = v7(t)
			effects = append(effects, sidefx.Effect{EventID: ids[j]})
		}
		seal := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(ids...), at.Add(time.Duration(i)*time.Second))
		effects = append(effects, sidefx.Effect{EventID: seal.EventID, Checkpoint: &seal})
		s.Apply(ctx, h.tenantA, h.deviceA, at, "", effects)
	}
	headSeq, _, _, err := h.store.Head(ctx, h.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if headSeq != 3 {
		t.Fatalf("chain head at %d, want 3 — the e2e chain did not build", headSeq)
	}

	// Witness the head so the verifier's --witness cross-check runs.
	job := receipts.NewWitnessJob(h.db, h.chainKey, &fakePublisher{}, receipts.StaticTenants([]uuid.UUID{h.tenantA.UUID()}), time.Hour)
	if err := job.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Export over the real HTTP surface (auth middleware included).
	mux := http.NewServeMux()
	verifier := auth.NewHMACVerifier([]byte("e2e-test-key"), auth.StaticRevocations{})
	receipts.NewModule(receipts.ModuleDeps{
		DB: h.db, PG: h.db, Verifier: verifier,
		ObsCfg: obs.Config{ServiceName: "controld-e2e"},
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	token := auth.Mint([]byte("e2e-test-key"), h.tenantA.UUID(), h.deviceA, time.Hour)
	fetch := func(path string) []byte {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		return body
	}

	// The amended 08 §3.4 list shape (D-O ruling): every paginated row names
	// the countersigning server key so a verifier can resolve signatures
	// across rotations — additive next to the pre-ruling device key_id alias.
	var list struct {
		Receipts []struct {
			ReceiptSeq  int64   `json:"receipt_seq"`
			ServerKeyID string  `json:"server_key_id"`
			KeyID       *string `json:"key_id"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(fetch("/api/v1/receipts"), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Receipts) != 3 {
		t.Fatalf("list rows = %d, want 3", len(list.Receipts))
	}
	for _, r := range list.Receipts {
		if r.ServerKeyID != h.chainKey.KeyID() {
			t.Fatalf("row %d server_key_id = %q, want %q (08 §3.4)", r.ReceiptSeq, r.ServerKeyID, h.chainKey.KeyID())
		}
		if r.KeyID == nil || *r.KeyID != h.deviceKey.KeyID() {
			t.Fatalf("row %d key_id = %v, want the device origin key", r.ReceiptSeq, r.KeyID)
		}
	}

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.jsonl")
	if err := os.WriteFile(chainPath, fetch("/api/v1/receipts/export"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), fetch("/api/v1/receipts/keys"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "witness.json"), fetch("/api/v1/receipts/witness"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func() (int, string) {
		cmd := exec.Command(verifierBin, "verify",
			"--chain", "chain.jsonl", "--keys", "keys.json", "--witness", "witness.json", "--json")
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}

	if code, out := run(); code != 0 {
		t.Fatalf("verifier rejected the server's own export (exit %d):\n%s", code, out)
	}

	// Flip one byte INSIDE a signed payload (a leaf_count digit): the stored
	// hash no longer matches, and the verdict must be the named defect with
	// exit 5 — never a silent pass, never a bare I/O error.
	tampered, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\\"leaf_count\\":3`)
	if !re.Match(tampered) {
		t.Fatalf("expected a leaf_count:3 payload to tamper with:\n%s", tampered)
	}
	tampered = re.ReplaceAll(tampered, []byte(`\"leaf_count\":4`))
	if err := os.WriteFile(chainPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := run()
	if code != 5 {
		t.Fatalf("tampered export: want exit 5, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, string(receipts.DefectPayloadMismatch)) {
		t.Fatalf("tampered export must name payload_mismatch:\n%s", out)
	}
}

// TestIntegrationChainHeadIsSealableOverHTTP grades GET /api/v1/receipts on the
// only thing its chain_head is FOR: whether a device that has never seen this
// database can seal against it.
//
// The device-signed checkpoint payload carries `seq` and `prev_receipt_hash`,
// which are per-TENANT server facts, and `checkpoint_seq`, which the head lock
// assigns — so an edge sealer's inputs are three numbers it cannot compute and
// must be told (store.go:196-217). Every other test in this file seals through
// h.sealCheckpoint, which reads them straight out of Postgres via store.Head:
// a path no edge daemon has. This test deliberately does NOT call store.Head.
// It takes only what the HTTP surface published and, if that is a number short
// or a byte wrong, AppendCheckpoint refuses — which is the assertion. Checking
// that the JSON merely CONTAINS a checkpoint_seq field would pass on a field
// that was always zero.
func TestIntegrationChainHeadIsSealableOverHTTP(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)

	// A non-genesis head, so a sealer that ignored the published numbers and
	// assumed 1/1 would be caught. Two of the three published numbers only
	// diverge from their genesis values once something is already on the chain.
	first := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t), v7(t)), at)
	if _, err := h.store.AppendCheckpoint(ctx, h.tenantA, first, nil); err != nil {
		t.Fatalf("seeding the chain: %v", err)
	}

	mux := http.NewServeMux()
	receipts.NewModule(receipts.ModuleDeps{
		DB: h.db, PG: h.db,
		Verifier: auth.NewHMACVerifier([]byte("head-test-key"), auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-head-test"},
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/receipts?limit=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+auth.Mint([]byte("head-test-key"), h.tenantA.UUID(), h.deviceA, time.Hour))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/receipts: %d %s", resp.StatusCode, body)
	}
	var published struct {
		ChainHead struct {
			Seq           int64  `json:"seq"`
			Hash          string `json:"hash"`
			CheckpointSeq int64  `json:"checkpoint_seq"`
		} `json:"chain_head"`
	}
	if err := json.Unmarshal(body, &published); err != nil {
		t.Fatal(err)
	}

	prev, err := hex.DecodeString(published.ChainHead.Hash)
	if err != nil || len(prev) != 32 {
		t.Fatalf("chain_head.hash = %q (%d bytes decoded, err %v), want 32 hex-encoded bytes",
			published.ChainHead.Hash, len(prev), err)
	}
	leaves := leavesOf(v7(t), v7(t), v7(t))
	root, err := receipts.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	issued := at.Add(time.Minute)
	cp := receipts.Checkpoint{
		TenantID:        h.tenantA.String(),
		DeviceID:        h.deviceA.String(),
		Seq:             published.ChainHead.Seq + 1,
		PrevReceiptHash: [32]byte(prev),
		IssuedAt:        receipts.IssuedAtString(issued),
		CheckpointSeq:   published.ChainHead.CheckpointSeq + 1,
		MerkleRoot:      root,
		LeafCount:       len(leaves),
	}
	signed, err := receipts.OriginSign(h.deviceKey, cp.Payload(h.deviceKey.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	landed, err := h.store.AppendCheckpoint(ctx, h.tenantA, receipts.CheckpointEvent{
		EventID:              v7(t),
		DeviceID:             h.deviceA,
		DeviceKeyID:          h.deviceKey.KeyID(),
		ClaimedCheckpointSeq: published.ChainHead.CheckpointSeq + 1,
		MerkleRoot:           root,
		LeafCount:            len(leaves),
		OriginSig:            signed.DeviceSig,
		IssuedAt:             issued,
	}, nil)
	if err != nil {
		t.Fatalf("a checkpoint sealed against the PUBLISHED head was refused: %v\n"+
			"chain_head was %+v — the edge sealer has no other source for these numbers, so this "+
			"refusal means GET /api/v1/receipts cannot be sealed against at all", err, published.ChainHead)
	}
	if landed.Seq != 2 || landed.CheckpointSeq != 2 {
		t.Fatalf("landed at seq %d / ckpt %d, want 2/2", landed.Seq, landed.CheckpointSeq)
	}
}
