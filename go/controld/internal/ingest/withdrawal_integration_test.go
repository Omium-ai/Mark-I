//go:build integration

package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

const allOn = `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":true,"local_rm":true,"cloud_rm":true}`

func (q *quarantinePG) newDevice(t *testing.T, tenant querychoke.TenantID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := q.admin.QueryRow(context.Background(), `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
		tenant.UUID(), make([]byte, 32)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// enroll records who approved device, the way enroll.approveEnrollment leaves the row (revokeDevice flips status to revoked).
func (q *quarantinePG) enroll(t *testing.T, tenant querychoke.TenantID, device uuid.UUID, subject, kind, status string) {
	t.Helper()
	h := func(s string) []byte { b := sha256.Sum256([]byte(s + device.String())); return b[:] }
	if _, err := q.admin.Exec(context.Background(), `
		INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, token_hash, device_pubkey, oidc_subject, status, token_expires_at, approval_kind)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour', $8)`,
		tenant.UUID(), device, h("code"), h("token"), h("key"), subject, status, kind); err != nil {
		t.Fatal(err)
	}
}

func (q *quarantinePG) consentAllOn(t *testing.T, tenant querychoke.TenantID, device uuid.UUID) {
	t.Helper()
	if _, err := q.admin.Exec(context.Background(), `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm)
		VALUES ($1, $2, true, true, true, true, true, true, true)`, tenant.UUID(), device); err != nil {
		t.Fatal(err)
	}
}

// latestConsent is the device's m1_082 state as every reader takes it: the last row written.
func (q *quarantinePG) latestConsent(t *testing.T, device uuid.UUID) string {
	t.Helper()
	var e1, judge, training, team, contrib, local, rm bool
	if err := q.admin.QueryRow(context.Background(), `SELECT e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm
		FROM m1_device_consents WHERE device_id = $1 ORDER BY row_seq DESC LIMIT 1`, device).Scan(&e1, &judge, &training, &team, &contrib, &local, &rm); err != nil {
		t.Fatal(err)
	}
	b := func(v bool) string { return map[bool]string{true: "1", false: "0"}[v] }
	return "e1=" + b(e1) + " judge=" + b(judge) + " training=" + b(training) + " team=" + b(team) + " contrib=" + b(contrib) + " local_rm=" + b(local) + " cloud_rm=" + b(rm)
}

// liveRows runs intel's export read (python/intel/app/corpus/contributions.py LIVE_ROWS, read from the file so it cannot drift) under the tenant GUC.
func liveRows(t *testing.T, q *quarantinePG) int {
	t.Helper()
	src, err := os.ReadFile("../../../../python/intel/app/corpus/contributions.py")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)LIVE_ROWS = """(.*?)"""`).FindSubmatch(src)
	if m == nil {
		t.Fatal("contributions.py has no LIVE_ROWS")
	}
	n := 0
	if err := q.db.WithTenant(context.Background(), q.tenantA, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), string(m[1]))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			n++
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// effective PUTs body and returns the answered effective row in latestConsent's shape.
func (r *attachRig) effective(t *testing.T, token, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := r.h.serve(req)
	var got struct {
		Consents consentsRow `json:"consents"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("consent %s: %d %s", body, rec.Code, rec.Body.String())
	}
	c := got.Consents
	b := func(v bool) string { return map[bool]string{true: "1", false: "0"}[v] }
	return "e1=" + b(c.E1) + " judge=" + b(c.CloudJudge) + " training=" + b(c.Training) + " team=" + b(c.Team) + " contrib=" + b(c.ContributeOutcomes) + " local_rm=" + b(c.LocalRM) + " cloud_rm=" + b(c.CloudRM)
}

// contribute lands one outcome contribution of device's and returns its batch.
func (q *quarantinePG) contribute(t *testing.T, device uuid.UUID) uuid.UUID {
	t.Helper()
	batch := mustV7(t)
	if _, err := q.admin.Exec(context.Background(), `INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id, device_id, session_id, task_id, object_key)
		SELECT tenant_id, $2, $3, id, $4, $5, 'k' FROM m1_devices WHERE id = $1`, device, uuid.New(), batch, uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	return batch
}

func (q *quarantinePG) contributionWithdrawn(t *testing.T, batch uuid.UUID) bool {
	t.Helper()
	var out bool
	if err := q.admin.QueryRow(context.Background(), `SELECT withdrawn_at IS NOT NULL FROM m1_outcome_contributions WHERE batch_id = $1`, batch).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

const everything = "e1=1 judge=1 training=1 team=1 contrib=1 local_rm=1 cloud_rm=1"

// H5: the re-enrolled device turns e1/contribute_outcomes from on to off, so the old device's rows, part and contribution are withdrawn and swept; others untouched, and the old device's offs stay held until it sends them false.
func TestIntegrationWithdrawalIsPerPerson(t *testing.T) {
	r := newAttachRig(t)
	q, ctx := r.q, context.Background()
	const alice = "omium:alice"
	q.enroll(t, q.tenantA, q.deviceA, alice, "omium_user", "approved")
	r.consent(t, r.h.token, allOn)
	task := mustV7(t)
	r.own(t, q.deviceA, task)
	rec, receipt := r.send(t, r.h.token, task, "old device\x00diff --git a/o b/o\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("old-device attach: %d %s", rec.Code, rec.Body.String())
	}
	r.bind(t, task, receipt)
	batch := mustV7(t)
	key := s3land.ContributionKey(q.tenantA.UUID(), batch)
	if _, err := r.store.Land(ctx, key, []byte("contribution"), q.tenantA.UUID(), q.deviceA); err != nil {
		t.Fatal(err)
	}
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id, device_id, session_id, task_id, object_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, q.tenantA.UUID(), uuid.New(), batch, q.deviceA, uuid.New(), uuid.New(), key); err != nil {
		t.Fatal(err)
	}

	reenrolled := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, reenrolled, alice, "omium_user", "approved")
	newTok := auth.Mint(testKey, q.tenantA.UUID(), reenrolled, time.Hour)
	team := q.newDevice(t, q.tenantB)
	q.enroll(t, q.tenantB, team, alice, "omium_user", "approved")
	q.consentAllOn(t, q.tenantB, team)
	bob := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, bob, "omium:bob", "omium_user", "approved")
	q.consentAllOn(t, q.tenantA, bob)

	r.consent(t, newTok, allOn)
	if n := liveRows(t, q); n != 1 {
		t.Fatalf("before the withdrawal intel exports %d rows, want 1", n)
	}
	if rec := r.read(q.tenantA.UUID(), task, "judge"); rec.Code != http.StatusOK {
		t.Fatalf("before the withdrawal the old part is served: %d %s", rec.Code, rec.Body.String())
	}

	r.consent(t, newTok, `{"e1":false,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":false,"local_rm":false,"cloud_rm":true}`)

	const withdrawn = "e1=0 judge=1 training=1 team=1 contrib=0 local_rm=1 cloud_rm=1"
	if got := q.latestConsent(t, q.deviceA); got != withdrawn {
		t.Errorf("old device latest consent %q, want %q (withdrawn fields off, the rest and on-device local_rm kept)", got, withdrawn)
	}
	for name, d := range map[string]uuid.UUID{"another person": bob, "the person's device in another tenant": team} {
		if got := q.latestConsent(t, d); got != everything {
			t.Errorf("%s was withdrawn: %q", name, got)
		}
	}
	var evidenceOut, contribOut bool
	if err := q.admin.QueryRow(ctx, `SELECT (SELECT withdrawn_at IS NOT NULL FROM m1_evidence_attachments WHERE task_id = $1),
		(SELECT withdrawn_at IS NOT NULL FROM m1_outcome_contributions WHERE batch_id = $2)`, task, batch).Scan(&evidenceOut, &contribOut); err != nil || !evidenceOut || !contribOut {
		t.Fatalf("old device rows not withdrawn in the PUT: evidence=%v contribution=%v %v", evidenceOut, contribOut, err)
	}
	if n := liveRows(t, q); n != 0 {
		t.Fatalf("intel still exports %d of the old device's rows", n)
	}
	if rec := r.read(q.tenantA.UUID(), task, "judge"); rec.Code != http.StatusNotFound {
		t.Fatalf("the old device's part is still served: %d", rec.Code)
	}
	if n := r.sweep(t, time.Now()); n != 1 {
		t.Fatalf("evidence sweep closed %d, want 1", n)
	}
	if n, err := NewQuarantineSweep(q.db, r.store, q.chain, receipts.StaticTenants([]uuid.UUID{q.tenantA.UUID()})).SweepContributions(ctx, q.tenantA.UUID()); err != nil || n != 1 {
		t.Fatalf("contribution sweep deleted %d, %v", n, err)
	}
	if keys := r.store.keys(); len(keys) != 0 {
		t.Fatalf("withdrawn objects survived the sweeps: %v", keys)
	}
	var reason string
	if err := q.admin.QueryRow(ctx, `SELECT r.payload FROM m1_receipts r JOIN m1_evidence_attachments e ON e.deletion_receipt_id = r.id
		WHERE r.record_type = 'evidence_deletion' AND r.subject_id = $1`, task).Scan(&reason); err != nil || !strings.Contains(reason, `"reason":"withdrawn"`) {
		t.Fatalf("no withdrawn evidence_deletion receipt: %q %v", reason, err)
	}

	for i := 1; i <= 2; i++ {
		if got := r.effective(t, r.h.token, allOn); got != withdrawn {
			t.Errorf("stale relay %d from the old device was answered %q, want the person-wide offs held: %q", i, got, withdrawn)
		}
	}
	if got := r.effective(t, r.h.token, `{"e1":false,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":false,"local_rm":true,"cloud_rm":true}`); got != withdrawn {
		t.Errorf("the adopted offs sent back: %q", got)
	}
	if got := r.effective(t, r.h.token, allOn); got != everything {
		t.Errorf("once released by an explicit false, an explicit true re-grants the old device: %q", got)
	}
	if got := q.latestConsent(t, reenrolled); got != "e1=0 judge=1 training=1 team=1 contrib=0 local_rm=0 cloud_rm=1" {
		t.Errorf("a grant from the old device reached the new one: %q", got)
	}
	if err := q.db.WithTenant(ctx, q.tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT m1_withdraw_person_consents($1, '{e1}')`, team)
		return err
	}); err == nil || !strings.Contains(err.Error(), "not in the session tenant") {
		t.Fatalf("the function acted on a device outside the session tenant: %v", err)
	}
}

// A device whose latest enrollment is revoked can never relay again, so the person's explicit false reaches it even when the sender never had the field on.
func TestIntegrationRevokedDeviceTakesAnExplicitOff(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	const alice = "omium:alice"
	q.enroll(t, q.tenantA, q.deviceA, alice, "omium_user", "approved")
	revoked, sibling := q.newDevice(t, q.tenantA), q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, revoked, alice, "omium_user", "revoked")
	q.enroll(t, q.tenantA, sibling, alice, "omium_user", "approved")
	q.consentAllOn(t, q.tenantA, revoked)
	q.consentAllOn(t, q.tenantA, sibling)
	gone, kept := q.contribute(t, revoked), q.contribute(t, sibling)

	r.consent(t, r.h.token, `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":false,"local_rm":true,"cloud_rm":true}`)
	if got := q.latestConsent(t, revoked); got != "e1=1 judge=1 training=1 team=1 contrib=0 local_rm=1 cloud_rm=1" || !q.contributionWithdrawn(t, gone) {
		t.Errorf("revoked device: %q, contribution withdrawn=%v", got, q.contributionWithdrawn(t, gone))
	}
	if got := q.latestConsent(t, sibling); got != everything || q.contributionWithdrawn(t, kept) {
		t.Errorf("an approved device lost a field the sender never had on: %q, contribution withdrawn=%v", got, q.contributionWithdrawn(t, kept))
	}
}

// CRITICAL-1: onboarding with only cloud_judge on, a tenant switch's contribute_outcomes=false and the post-upgrade re-send withdraw nothing; a true→false does.
func TestIntegrationOnlyATransitionWithdrawsPersonWide(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	const alice = "omium:alice"
	q.enroll(t, q.tenantA, q.deviceA, alice, "omium_user", "approved")
	r.consent(t, r.h.token, allOn)
	task := mustV7(t)
	r.own(t, q.deviceA, task)
	if rec, receipt := r.send(t, r.h.token, task, "kept\x00diff --git a/k b/k\n"); rec.Code != http.StatusOK {
		t.Fatalf("attach: %d %s", rec.Code, rec.Body.String())
	} else {
		r.bind(t, task, receipt)
	}
	batch := q.contribute(t, q.deviceA)
	untouched := func(when string) {
		t.Helper()
		if got := q.latestConsent(t, q.deviceA); got != everything {
			t.Errorf("%s: the first device reads %q", when, got)
		}
		if q.contributionWithdrawn(t, batch) {
			t.Errorf("%s: the first device's contribution was withdrawn", when)
		}
		if rec := r.read(q.tenantA.UUID(), task, "judge"); rec.Code != http.StatusOK {
			t.Errorf("%s: the first device's E1 part is no longer served: %d", when, rec.Code)
		}
	}

	second := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, second, alice, "omium_user", "approved")
	secondTok := auth.Mint(testKey, q.tenantA.UUID(), second, time.Hour)
	r.consent(t, secondTok, `{"e1":false,"cloud_judge":true,"training":false,"team":false,"contribute_outcomes":false,"local_rm":false,"cloud_rm":false}`)
	untouched("a second device onboarding with only cloud_judge")

	switched := q.newDevice(t, q.tenantB)
	q.enroll(t, q.tenantB, switched, alice, "omium_user", "approved")
	desk := q.newDevice(t, q.tenantB)
	q.enroll(t, q.tenantB, desk, alice, "omium_user", "approved")
	q.consentAllOn(t, q.tenantB, desk)
	deskBatch := q.contribute(t, desk)
	r.consent(t, auth.Mint(testKey, q.tenantB.UUID(), switched, time.Hour), `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":false,"local_rm":true,"cloud_rm":true}`)
	if got := q.latestConsent(t, desk); got != everything || q.contributionWithdrawn(t, deskBatch) {
		t.Errorf("a tenant switch's contribute_outcomes=false withdrew the person's other device there: %q", got)
	}
	untouched("a tenant switch")

	upgraded := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, upgraded, alice, "omium_user", "approved")
	upTok := auth.Mint(testKey, q.tenantA.UUID(), upgraded, time.Hour)
	r.consent(t, upTok, `{"e1":true,"cloud_judge":false,"training":true}`)
	r.consent(t, upTok, `{"e1":true,"cloud_judge":false,"training":true,"team":false,"contribute_outcomes":false,"local_rm":false,"cloud_rm":false}`)
	untouched("the post-upgrade full-body re-send")

	r.consent(t, secondTok, `{"e1":false,"cloud_judge":true,"training":false,"team":false,"contribute_outcomes":true,"local_rm":false,"cloud_rm":false}`)
	r.consent(t, secondTok, `{"e1":false,"cloud_judge":true,"training":false,"team":false,"contribute_outcomes":false,"local_rm":false,"cloud_rm":false}`)
	if got := q.latestConsent(t, q.deviceA); got != "e1=1 judge=1 training=1 team=1 contrib=0 local_rm=1 cloud_rm=1" || !q.contributionWithdrawn(t, batch) {
		t.Errorf("a true→false transition did not withdraw person-wide: %q, contribution withdrawn=%v", got, q.contributionWithdrawn(t, batch))
	}
	if rec := r.read(q.tenantA.UUID(), task, "judge"); rec.Code != http.StatusOK {
		t.Errorf("a contribute_outcomes transition withdrew the E1 part: %d", rec.Code)
	}
}

// H3: a three-field body lands cloud_judge and training off and holds them through the upgraded edge's relays until it sends them false; m1_107 resets every earlier grant of either, once.
func TestIntegrationLegacyCopyGrantsAreReset(t *testing.T) {
	r := newAttachRig(t)
	q, ctx := r.q, context.Background()
	if got := r.effective(t, r.h.token, `{"e1":true,"cloud_judge":true,"training":true}`); got != "e1=1 judge=0 training=0 team=0 contrib=0 local_rm=0 cloud_rm=0" {
		t.Errorf("a legacy body's cloud_judge/training: %q", got)
	}
	if got := r.effective(t, r.h.token, `{"e1":true,"cloud_judge":false,"training":false}`); got != "e1=1 judge=0 training=0 team=0 contrib=0 local_rm=0 cloud_rm=0" {
		t.Errorf("a legacy body's explicit falses: %q", got)
	}
	r.consent(t, r.h.token, `{"e1":true,"cloud_judge":true,"training":true}`)
	for i := 1; i <= 2; i++ {
		if got := r.effective(t, r.h.token, allOn); got != "e1=1 judge=0 training=0 team=1 contrib=1 local_rm=1 cloud_rm=1" {
			t.Errorf("upgraded relay %d re-granted an old-copy grant: %q", i, got)
		}
	}
	r.consent(t, r.h.token, `{"e1":true,"cloud_judge":false,"training":false,"team":true,"contribute_outcomes":true,"local_rm":true,"cloud_rm":true}`)
	if got := r.effective(t, r.h.token, allOn); got != everything {
		t.Errorf("grants under the new copy: %q", got)
	}

	prior := q.newDevice(t, q.tenantA)
	q.consentAllOn(t, q.tenantA, prior)
	trainingOnly := q.newDevice(t, q.tenantA)
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training) VALUES ($1, $2, true, false, true)`, q.tenantA.UUID(), trainingOnly); err != nil {
		t.Fatal(err)
	}
	neither := q.newDevice(t, q.tenantA)
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training) VALUES ($1, $2, true, false, false)`, q.tenantA.UUID(), neither); err != nil {
		t.Fatal(err)
	}
	count := func() (n int) {
		if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_device_consents`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for run := 1; run <= 2; run++ {
		before := count()
		q.rerunM1107(t)
		if want := map[int]int{1: 3, 2: 0}[run]; count()-before != want {
			t.Fatalf("m1_107 run %d appended %d rows, want %d", run, count()-before, want)
		}
	}
	for d, want := range map[uuid.UUID]string{
		prior:        "e1=1 judge=0 training=0 team=1 contrib=1 local_rm=1 cloud_rm=1",
		trainingOnly: "e1=1 judge=0 training=0 team=0 contrib=0 local_rm=0 cloud_rm=0",
		neither:      "e1=1 judge=0 training=0 team=0 contrib=0 local_rm=0 cloud_rm=0",
	} {
		if got := q.latestConsent(t, d); got != want {
			t.Errorf("device %s after m1_107: %q, want %q", d, got, want)
		}
	}
}

func (q *quarantinePG) rerunM1107(t *testing.T) {
	t.Helper()
	src, err := os.ReadFile("../../../../migrations/m1_107_consent_transitions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.admin.Exec(context.Background(), string(src)); err != nil {
		t.Fatalf("m1_107: %v", err)
	}
}

// The edge's one-shot copy reset relays cloud_judge/training false: on a device m1_107 already reset that only releases the hold, so a new-copy training grant made on the person's other device after the cut stays on.
func TestIntegrationCopyResetRelayWithdrawsNothing(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	b := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, q.deviceA, "omium:alice", "omium_user", "approved")
	q.enroll(t, q.tenantA, b, "omium:alice", "omium_user", "approved")
	q.consentAllOn(t, q.tenantA, b)
	q.rerunM1107(t)
	r.consent(t, r.h.token, allOn)
	bTok := auth.Mint(testKey, q.tenantA.UUID(), b, time.Hour)
	if got := r.effective(t, bTok, `{"e1":true,"cloud_judge":false,"training":false,"team":true,"contribute_outcomes":true,"local_rm":true,"cloud_rm":true}`); got != "e1=1 judge=0 training=0 team=1 contrib=1 local_rm=1 cloud_rm=1" {
		t.Errorf("B after its copy-reset relay: %q", got)
	}
	if got := q.latestConsent(t, q.deviceA); got != everything {
		t.Errorf("B's copy reset reached A's post-cut grant: %q", got)
	}
	if got := r.effective(t, bTok, allOn); got != everything {
		t.Errorf("the copy-reset relay released B's holds, so a new-copy grant lands: %q", got)
	}
}

// M1: a withdrawal in flight holds the device's lock; an attach that passed the early consent check waits for it and then refuses, so no part lands after e1 is off.
func TestIntegrationAttachSerialisesWithAWithdrawal(t *testing.T) {
	r := newAttachRig(t)
	q, ctx := r.q, context.Background()
	r.consent(t, r.h.token, allOn)
	task := mustV7(t)
	r.own(t, q.deviceA, task)

	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- q.db.WithTenant(ctx, q.tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT m1_withdraw_person_consents($1, '{e1}')`, q.deviceA); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training) VALUES ($1, $2, false, true, true)`, q.tenantA.UUID(), q.deviceA); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	attached := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec, _ := r.send(t, r.h.token, task, "racing\x00diff --git a/r b/r\n")
		attached <- rec
	}()
	select {
	case rec := <-attached:
		t.Fatalf("attach finished while the withdrawal held the device lock: %d %s", rec.Code, rec.Body.String())
	case <-time.After(500 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rec := <-attached
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "e1_consent") {
		t.Fatalf("attach after the withdrawal committed: want 422 e1_consent, got %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_evidence_attachments WHERE task_id = $1`, task).Scan(&n); err != nil || n != 0 || len(r.store.keys()) != 0 {
		t.Fatalf("a part raced past the withdrawal: rows=%d objects=%v %v", n, r.store.keys(), err)
	}
}

// Attach binds the task to the device that ran it: unbound waits (503, the edge retries), another device is refused (403).
func TestIntegrationAttachOnlyFromTheTasksDevice(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	r.consent(t, r.h.token, allOn)
	other := q.newDevice(t, q.tenantA)
	otherToken := auth.Mint(testKey, q.tenantA.UUID(), other, time.Hour)
	r.consent(t, otherToken, allOn)
	part := "mine\x00diff --git a/m b/m\n"

	task := mustV7(t)
	if rec, _ := r.send(t, r.h.token, task, part); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before the task's TaskOpen lands: want 503, got %d %s", rec.Code, rec.Body.String())
	}
	r.own(t, q.deviceA, task)
	r.own(t, other, task)
	if rec, _ := r.send(t, otherToken, task, part); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "e1_task_device") {
		t.Fatalf("a teammate's device attaching my task: want 403 e1_task_device, got %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := r.send(t, r.h.token, task, part); rec.Code != http.StatusOK {
		t.Fatalf("the task's own device: %d %s", rec.Code, rec.Body.String())
	}
}

// M1: the E1 read serves only while the device's latest consent keeps e1 and the purpose's own consent (judge: cloud_judge, rm: cloud_rm).
func TestIntegrationEvidenceReadNeedsThePurposeConsent(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	r.consent(t, r.h.token, allOn)
	task := mustV7(t)
	r.own(t, q.deviceA, task)
	rec, receipt := r.send(t, r.h.token, task, "purpose\x00diff --git a/p b/p\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("attach: %d %s", rec.Code, rec.Body.String())
	}
	r.bind(t, task, receipt)
	for _, c := range []struct {
		body        string
		judge, rmOK bool
	}{
		{allOn, true, true},
		{`{"e1":true,"cloud_judge":false,"training":true,"cloud_rm":true}`, false, true},
		{`{"e1":true,"cloud_judge":true,"training":true,"cloud_rm":false}`, true, false},
	} {
		r.consent(t, r.h.token, c.body)
		for purpose, want := range map[string]bool{"judge": c.judge, "rm": c.rmOK} {
			code := map[bool]int{true: http.StatusOK, false: http.StatusNotFound}[want]
			if rec := r.read(q.tenantA.UUID(), task, purpose); rec.Code != code {
				t.Errorf("consent %s, purpose %s: got %d, want %d", c.body, purpose, rec.Code, code)
			}
		}
	}
}

// Tri-state later fields (08 §3.7a): absent keeps the device's value and withdraws nothing, a true→false withdraws for the person, a true grants only the sender.
func TestIntegrationAbsentLaterConsentFieldsWithdrawNothing(t *testing.T) {
	q := setupQuarantinePG(t)
	r := &attachRig{q: q, h: &harness{mux: http.NewServeMux()}}
	New(Deps{Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}), PG: fakeReady{}, Store: newFakeStore(), DB: q.db}).RegisterRoutes(r.h.mux)
	ctx := context.Background()
	const alice = "omium:alice"
	oldEdge, newEdge := q.deviceA, q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, oldEdge, alice, "omium_user", "approved")
	q.enroll(t, q.tenantA, newEdge, alice, "omium_user", "approved")
	oldTok, newTok := auth.Mint(testKey, q.tenantA.UUID(), oldEdge, time.Hour), auth.Mint(testKey, q.tenantA.UUID(), newEdge, time.Hour)

	r.consent(t, oldTok, allOn)
	r.consent(t, newTok, allOn)
	batch := mustV7(t)
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id, device_id, session_id, task_id, object_key)
		VALUES ($1, $2, $3, $4, $5, $6, 'k')`, q.tenantA.UUID(), uuid.New(), batch, newEdge, uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	r.consent(t, oldTok, `{"e1":true,"cloud_judge":true,"training":true}`)
	for d, want := range map[uuid.UUID]string{oldEdge: "e1=1 judge=0 training=0 team=1 contrib=1 local_rm=1 cloud_rm=1", newEdge: everything} {
		if got := q.latestConsent(t, d); got != want {
			t.Errorf("after a three-field body, device %s reads %q, want %q", d, got, want)
		}
	}
	var withdrawn bool
	if err := q.admin.QueryRow(ctx, `SELECT withdrawn_at IS NOT NULL FROM m1_outcome_contributions WHERE batch_id = $1`, batch).Scan(&withdrawn); err != nil || withdrawn {
		t.Fatalf("an absent field withdrew a contribution: %v %v", withdrawn, err)
	}

	fresh := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, fresh, "omium:bob", "omium_user", "approved")
	r.consent(t, auth.Mint(testKey, q.tenantA.UUID(), fresh, time.Hour), `{"e1":true,"cloud_judge":true,"training":true}`)
	if got := q.latestConsent(t, fresh); got != "e1=1 judge=0 training=0 team=0 contrib=0 local_rm=0 cloud_rm=0" {
		t.Errorf("a device that never had the later fields: %q, want them off", got)
	}

	r.consent(t, newTok, `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":false,"local_rm":true,"cloud_rm":false}`)
	const off = "e1=1 judge=0 training=0 team=1 contrib=0 local_rm=1 cloud_rm=1"
	for d, want := range map[uuid.UUID]string{newEdge: "e1=1 judge=1 training=1 team=1 contrib=0 local_rm=1 cloud_rm=0", oldEdge: off} {
		if got := q.latestConsent(t, d); got != want {
			t.Errorf("after a true→false, device %s reads %q, want %q", d, got, want)
		}
	}
	if err := q.admin.QueryRow(ctx, `SELECT withdrawn_at IS NOT NULL FROM m1_outcome_contributions WHERE batch_id = $1`, batch).Scan(&withdrawn); err != nil || !withdrawn {
		t.Fatalf("an explicit false did not withdraw the contribution: %v %v", withdrawn, err)
	}

	r.consent(t, newTok, `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":true,"local_rm":true,"cloud_rm":true}`)
	if got := q.latestConsent(t, newEdge); got != everything {
		t.Errorf("explicit true on the sender: %q", got)
	}
	if got := q.latestConsent(t, oldEdge); got != off {
		t.Errorf("a grant reached the person's other device: %q, want %q", got, off)
	}
}

// A leaver's device token lives up to 24 h; ingest, attach and consents refuse it as appapi does (teams.Participant), a member's device passes.
func TestIntegrationLeaversDeviceIsRefusedOnDeviceRoutes(t *testing.T) {
	q := setupQuarantinePG(t)
	h := &harness{mux: http.NewServeMux()}
	New(Deps{Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}), PG: fakeReady{}, Store: newFakeStore(), DB: q.db, Members: q.db}).RegisterRoutes(h.mux)
	ctx := context.Background()
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_team_members (tenant_id, subject, role, left_at) VALUES ($1, 'omium:carol', 'member', now()), ($1, 'omium:dan', 'member', NULL)`, q.tenantA.UUID()); err != nil {
		t.Fatal(err)
	}
	q.enroll(t, q.tenantA, q.deviceA, "omium:carol", "omium_user", "approved")
	member := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, member, "omium:dan", "omium_user", "approved")
	leaver := auth.Mint(testKey, q.tenantA.UUID(), q.deviceA, time.Hour)
	for _, route := range []struct{ method, path string }{{http.MethodPut, "/api/v1/consents"}, {http.MethodPost, "/api/v1/attach"}, {http.MethodPost, "/m1p/v1/ingest"}} {
		req := httptest.NewRequest(route.method, route.path, strings.NewReader(allOn))
		req.Header.Set("Authorization", "Bearer "+leaver)
		if rec := h.serve(req); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "M1E-1007") {
			t.Errorf("%s %s from a leaver's device: %d %s", route.method, route.path, rec.Code, rec.Body.String())
		}
	}
	if rec := h.putConsents(t, auth.Mint(testKey, q.tenantA.UUID(), member, time.Hour), allOn); rec.Code != http.StatusOK {
		t.Fatalf("an active member's device: %d %s", rec.Code, rec.Body.String())
	}
}

// MEDIUM-3: where the reward model scores is a per-device choice, so B choosing "this computer" leaves A's cloud_rm alone.
func TestIntegrationCloudRMIsPerDevice(t *testing.T) {
	r := newAttachRig(t)
	q := r.q
	q.enroll(t, q.tenantA, q.deviceA, "omium:alice", "omium_user", "approved")
	b := q.newDevice(t, q.tenantA)
	q.enroll(t, q.tenantA, b, "omium:alice", "omium_user", "approved")
	bTok := auth.Mint(testKey, q.tenantA.UUID(), b, time.Hour)
	r.consent(t, r.h.token, allOn)
	r.consent(t, bTok, allOn)
	r.consent(t, bTok, `{"e1":true,"cloud_judge":true,"training":true,"team":true,"contribute_outcomes":true,"local_rm":true,"cloud_rm":false}`)
	if got := q.latestConsent(t, q.deviceA); got != everything {
		t.Errorf("B's cloud_rm reached A: %q", got)
	}
}

// landHook runs before in the gap between the attach's committed index row and its object landing.
type landHook struct {
	*fakeStore
	before func()
}

func (l *landHook) Land(ctx context.Context, key string, body []byte, tenant, device uuid.UUID) (s3land.Outcome, error) {
	if l.before != nil {
		l.before()
	}
	return l.fakeStore.Land(ctx, key, body, tenant, device)
}

// LOW-8: a withdrawal (and a sweep that found no object) between the index row and the landing leaves no orphan: attach deletes the late object and receipts it.
func TestIntegrationAWithdrawalBeforeTheLandingLeavesNoObject(t *testing.T) {
	r := newAttachRig(t)
	q, ctx := r.q, context.Background()
	r.consent(t, r.h.token, allOn)
	hook := &landHook{fakeStore: r.store}
	r.h.mux = http.NewServeMux()
	New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		PG:       fakeReady{}, Store: hook, Sidefx: r.sfx, Security: r.sec, DB: q.db, Chain: q.chain, EvidenceToken: testEvidenceToken,
	}).RegisterRoutes(r.h.mux)
	withdraw := func() {
		if err := q.db.WithTenant(ctx, q.tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT m1_withdraw_person_consents($1, '{e1}')`, q.deviceA); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training) VALUES ($1, $2, false, true, true)`, q.tenantA.UUID(), q.deviceA)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, object string
		sweep        bool
	}{{"withdrawn, not yet swept", `"object":"deleted"`, false}, {"withdrawn and swept", `"object":"lifecycle_backstop"`, true}} {
		r.consent(t, r.h.token, allOn)
		task := mustV7(t)
		r.own(t, q.deviceA, task)
		hook.before = func() {
			hook.before = nil
			withdraw()
			if c.sweep {
				r.sweep(t, time.Now())
			}
		}
		rec, _ := r.send(t, r.h.token, task, "late\x00diff --git a/l b/l\n")
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "e1_consent") {
			t.Errorf("%s: want 422 e1_consent, got %d %s", c.name, rec.Code, rec.Body.String())
		}
		if keys := r.store.keys(); len(keys) != 0 {
			t.Errorf("%s: an orphan object survived: %v", c.name, keys)
		}
		var payload string
		if err := q.admin.QueryRow(ctx, `SELECT r.payload FROM m1_receipts r JOIN m1_evidence_attachments e ON e.deletion_receipt_id = r.id
			WHERE r.record_type = 'evidence_deletion' AND r.subject_id = $1 AND e.deleted_at IS NOT NULL`, task).Scan(&payload); err != nil || !strings.Contains(payload, `"reason":"withdrawn"`) || !strings.Contains(payload, c.object) {
			t.Errorf("%s: deletion receipt %q %v", c.name, payload, err)
		}
	}
}
