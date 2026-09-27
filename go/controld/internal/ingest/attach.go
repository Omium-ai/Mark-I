package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

const (
	// MaxAttachPart is the edge's excerpt ceiling (mark1d internal/excerpt MaxPart); the body adds the receipt and multipart framing.
	MaxAttachPart = 64 << 10
	maxAttachBody = MaxAttachPart + 16<<10
	// EvidenceRetention is the founder's 30 d ruling applied to E1 objects: past it the read route stops serving and the sweep deletes, receipted.
	EvidenceRetention = 30 * 24 * time.Hour
)

var (
	attachPartName = regexp.MustCompile(`^attach\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.e1$`)
	attachOutcomes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_attach_total",
		Help: "E1 attach uploads by outcome: landed, duplicate, quarantined, divergent, refused (08 §2.1)",
	}, []string{"outcome"})
	evidenceSweep = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_evidence_sweep_total",
		Help: "E1 evidence deletions by reason: retention_30d, withdrawn, error",
	}, []string{"reason"})
)

// redactionFile is the receipt part the edge ships beside the sanitized part (mark1d receipt.RedactionFile).
type redactionFile struct {
	Payload         string `json:"payload"`
	DeviceKeyID     string `json:"device_key_id"`
	DeviceSignature string `json:"device_signature"`
}

func errAttach(status int, code, kind, msg string) apiErr {
	attachOutcomes.WithLabelValues("refused").Inc()
	return apiErr{status, code, msg, map[string]any{"kinds": []string{kind}}}
}

// handleAttach is POST /api/v1/attach (08 §2.1): one receipt part and one attach.<task>.e1 part per request, under the device's live e1 consent; the receipt is verified and stored (m1_077), the second ruleset quarantines, the index row lands before the object.
func (m *Module) handleAttach(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeErr(w, errServer("auth middleware did not run"))
		return
	}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil || claims.DeviceID == uuid.Nil {
		writeErr(w, apiErr{http.StatusForbidden, "M1E-1001", "a device token is required: evidence is receipted per device", nil})
		return
	}
	if m.db == nil || m.sfx == nil {
		writeErr(w, errServer("evidence store not configured"))
		return
	}
	ctx, device := r.Context(), claims.DeviceID
	r.Body = http.MaxBytesReader(w, r.Body, maxAttachBody)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, errMediaType("attach is multipart/form-data"))
		return
	}
	var rf *redactionFile
	var name string
	var part []byte
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, errMalformed("multipart body unreadable or over the attach bound"))
			return
		}
		b, err := io.ReadAll(io.LimitReader(p, MaxAttachPart+1))
		switch {
		case err != nil:
			writeErr(w, errMalformed("multipart part unreadable"))
			return
		case p.FormName() == "receipt" && rf == nil:
			rf = &redactionFile{}
			if json.Unmarshal(b, rf) != nil {
				writeErr(w, errMalformed("receipt part is not a redaction receipt file"))
				return
			}
		case attachPartName.MatchString(p.FormName()) && part == nil:
			name, part = p.FormName(), b
		default:
			writeErr(w, errMalformed("attach takes exactly one receipt part and one attach.<task>.e1 part"))
			return
		}
	}
	switch {
	case rf == nil || part == nil:
		writeErr(w, errMalformed("attach takes exactly one receipt part and one attach.<task>.e1 part"))
		return
	case len(part) == 0 || len(part) > MaxAttachPart || bytes.Count(part, []byte{0}) != 1:
		writeErr(w, errAttach(http.StatusRequestEntityTooLarge, "M1E-2004", "e1_part_shape", "the E1 part is intent NUL hunks, 1 byte to 64 KiB"))
		return
	}
	task := uuid.MustParse(attachPartName.FindStringSubmatch(name)[1])
	postHash := sha256.Sum256(part)
	var claim struct {
		Subject  string `json:"subject_id"`
		PostHash string `json:"post_hash"`
	}
	if json.Unmarshal([]byte(rf.Payload), &claim) != nil || claim.Subject != task.String() || claim.PostHash != hex.EncodeToString(postHash[:]) {
		writeErr(w, errAttach(http.StatusUnprocessableEntity, "M1E-2006", "e1_receipt_mismatch", "the receipt does not attest this part for this task"))
		return
	}
	if on, err := m.e1Consented(ctx, tenant, device); err != nil {
		writeErr(w, errServer("consent store unavailable"))
		return
	} else if !on {
		writeErr(w, errAttach(http.StatusUnprocessableEntity, "M1E-2006", "e1_consent", "no live e1 consent for this device (m1_082)"))
		return
	}
	switch owner, err := m.taskDevice(ctx, tenant, task); {
	case err != nil:
		writeErr(w, errServer("task binding unavailable"))
		return
	case owner == uuid.Nil:
		attachOutcomes.WithLabelValues("refused").Inc()
		writeErr(w, errServer("this task's TaskOpen/TaskClose has not landed yet; retry"))
		return
	case owner != device:
		log.Printf("SECURITY ingest attach: tenant=%s device=%s task=%s: the task belongs to device %s", tenant, device, task, owner)
		writeErr(w, errAttach(http.StatusForbidden, "M1E-1001", "e1_task_device", "only the device that ran this task may attach its evidence"))
		return
	}
	sig, _ := hex.DecodeString(rf.DeviceSignature)
	receiptID, err := m.sfx.AdmitRedactionReceipt(ctx, tenant, device, rf.Payload, sig)
	if refusal, ok := receipts.AsRefusal(err); ok {
		log.Printf("SECURITY ingest attach: tenant=%s device=%s task=%s: redaction receipt refused (%s)", tenant, device, task, refusal.Code)
		writeErr(w, errAttach(http.StatusUnprocessableEntity, "M1E-2006", "e1_receipt_"+string(refusal.Code), refusal.Detail))
		return
	}
	if err != nil {
		writeErr(w, errServer("receipt store unavailable"))
		return
	}
	now := m.now()
	if classes := m.scanner.ScanBytes(part); len(classes) > 0 {
		m.quarantineAttach(w, r, tenant, device, task, receiptID, part, classes, now)
		return
	}
	key := s3land.EvidenceKey(tenant.UUID(), task)
	var heldHash []byte
	var closed, withdrawn bool
	err = m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, consentLockShared, device); err != nil {
			return err
		}
		on, err := latestE1(ctx, tx, device)
		if withdrawn = !on; err != nil || withdrawn {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO m1_evidence_attachments (tenant_id, task_id, attachment_name, receipt_id, post_hash, device_id, object_key, size_bytes, received_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id, task_id) DO NOTHING`,
			tenant.UUID(), task, name, receiptID[:], postHash[:], device, key, len(part), now.UTC()); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT post_hash, deleted_at IS NOT NULL FROM m1_evidence_attachments WHERE task_id = $1`, task).Scan(&heldHash, &closed)
	})
	if err != nil {
		writeErr(w, errServer("evidence index unavailable"))
		return
	}
	if withdrawn {
		writeErr(w, errAttach(http.StatusUnprocessableEntity, "M1E-2006", "e1_consent", "e1 was withdrawn while this part was in flight (m1_082)"))
		return
	}
	if closed || !bytes.Equal(heldHash, postHash[:]) {
		attachOutcomes.WithLabelValues("divergent").Inc()
		writeErr(w, apiErr{http.StatusConflict, "M1E-2003", "this task's E1 part already landed with different bytes, or was deleted", nil})
		return
	}
	outcome, err := m.store.Land(ctx, key, part, tenant.UUID(), device)
	switch {
	case err != nil:
		s3LandFailures.Inc()
		writeErr(w, errServer("landing store unavailable"))
		return
	case outcome == s3land.Divergent:
		attachOutcomes.WithLabelValues("divergent").Inc()
		writeErr(w, errDivergentBatch())
		return
	}
	if gone, err := m.closeLateLanding(ctx, tenant, task, key, now); err != nil || gone {
		if err != nil {
			writeErr(w, errServer("evidence index unavailable"))
			return
		}
		writeErr(w, errAttach(http.StatusUnprocessableEntity, "M1E-2006", "e1_consent", "e1 was withdrawn while this part was in flight (m1_082)"))
		return
	}
	status := "landed"
	if outcome == s3land.Duplicate {
		status = "duplicate"
	}
	attachOutcomes.WithLabelValues(status).Inc()
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": status, "attachment": name, "receipt_id": hex.EncodeToString(receiptID[:])})
}

// quarantineAttach is 05 §2.3 for a part: tombstone first, then the twin under the quarantine prefix, then 202 and the tenant alert; no index row, so nothing ever serves it.
func (m *Module) quarantineAttach(w http.ResponseWriter, r *http.Request, tenant querychoke.TenantID, device, task uuid.UUID, receiptID [32]byte, part []byte, classes []string, now time.Time) {
	for _, c := range classes {
		scannerHits.WithLabelValues(c).Inc()
	}
	id := uuid.NewSHA1(task, receiptID[:])
	key := s3land.EvidenceQuarantineKey(tenant.UUID(), task, now)
	if err := m.tombstone(r.Context(), tenant, id, key, 1, now); err != nil {
		tombstoneFailures.Inc()
		writeErr(w, errServer("quarantine marker unavailable"))
		return
	}
	if _, err := m.store.Land(r.Context(), key, part, tenant.UUID(), device); err != nil {
		s3LandFailures.Inc()
		writeErr(w, errServer("landing store unavailable"))
		return
	}
	m.security.RecordQuarantine(tenant.UUID(), device, id, classes, now)
	attachOutcomes.WithLabelValues("quarantined").Inc()
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "quarantined", "classes": classes})
}

func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// consentLockShared is attach's half of m1_106's per-device lock: a consent PUT holds it exclusively from its withdrawal to its commit.
const consentLockShared = `SELECT pg_advisory_xact_lock_shared(hashtextextended('m1_consent:' || $1::text, 0))`

// e1Consented reads the device's latest m1_082 row: no row or no store is no consent.
func (m *Module) e1Consented(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID) (bool, error) {
	on := false
	err := m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) (err error) {
		on, err = latestE1(ctx, tx, device)
		return err
	})
	return on, err
}

func latestE1(ctx context.Context, tx pgx.Tx, device uuid.UUID) (bool, error) {
	on := false
	err := tx.QueryRow(ctx, `SELECT e1 FROM m1_device_consents WHERE device_id = $1 ORDER BY row_seq DESC LIMIT 1`, device).Scan(&on)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return on, err
}

// taskDevice is the task's own device (m1_106, bound at stage 11 by its first TaskOpen/TaskClose); uuid.Nil while unbound.
func (m *Module) taskDevice(ctx context.Context, tenant querychoke.TenantID, task uuid.UUID) (uuid.UUID, error) {
	owner := uuid.Nil
	err := m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT device_id FROM m1_task_devices WHERE task_id = $1`, task).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return owner, err
}

// evidencePurposes maps the read's ?purpose= to the device consent it needs beside e1 (08 §3.8).
var evidencePurposes = map[string]string{"judge": "cloud_judge", "rm": "cloud_rm"}

// handleEvidence is GET /internal/v1/evidence/{task}?purpose=judge|rm: the adjudicator's E1 read under its own credential (EVIDENCE_READ_TOKEN, not the shared service token) + M1P-Tenant-Id, served only while the part is live, unwithdrawn, under 30 days, bound to a landed excerpt, byte-identical to its receipt, and its device's latest consent still has e1 and the purpose's consent.
func (m *Module) handleEvidence(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	cred, err := querychoke.VerifyServiceCredential(m.evidenceToken, bearer)
	if !ok || err != nil {
		writeErr(w, apiErr{http.StatusForbidden, "M1E-1001", "service credential required", nil})
		return
	}
	tenantUUID, err := uuid.Parse(r.Header.Get(TenantHeader))
	if err != nil {
		writeErr(w, errMalformed(TenantHeader+" must be a UUID"))
		return
	}
	tenant, err := querychoke.FromServiceJob(cred, tenantUUID)
	if err != nil {
		writeErr(w, errMalformed(err.Error()))
		return
	}
	task, err := uuid.Parse(r.PathValue("task"))
	if err != nil || m.db == nil {
		writeErr(w, errMalformed("task must be a UUID"))
		return
	}
	consent, ok := evidencePurposes[r.URL.Query().Get("purpose")]
	if !ok {
		writeErr(w, errMalformed("purpose must be judge or rm"))
		return
	}
	var key, name string
	var receiptID, post []byte
	err = m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			SELECT e.object_key, e.attachment_name, e.receipt_id, e.post_hash FROM m1_evidence_attachments e
			 WHERE e.task_id = $1 AND e.withdrawn_at IS NULL AND e.deleted_at IS NULL AND e.received_at > $2
			   AND EXISTS (SELECT 1 FROM m1_redaction_receipts rr WHERE rr.tenant_id = e.tenant_id AND rr.subject_id = e.task_id
			               AND rr.post_hash = e.post_hash AND rr.excerpt_event_id IS NOT NULL)
			   AND coalesce((SELECT d.e1 AND CASE $3 WHEN 'cloud_judge' THEN d.cloud_judge WHEN 'cloud_rm' THEN d.cloud_rm END
			                  FROM m1_device_consents d WHERE d.device_id = e.device_id ORDER BY d.row_seq DESC LIMIT 1), false)`,
			task, m.now().Add(-EvidenceRetention).UTC(), consent).Scan(&key, &name, &receiptID, &post)
	})
	notHeld := apiErr{http.StatusNotFound, "M1E-2013", "no E1 evidence held for this task", nil}
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, notHeld)
		return
	}
	if err != nil {
		writeErr(w, errServer("evidence index unavailable"))
		return
	}
	body, _, _, err := m.store.Get(r.Context(), key)
	if err != nil {
		writeErr(w, errServer("landing store unavailable"))
		return
	}
	intent, hunks, ok := bytes.Cut(body, []byte{0})
	if sum := sha256.Sum256(body); !ok || !bytes.Equal(sum[:], post) {
		log.Printf("SECURITY ingest evidence: tenant=%s task=%s: landed part does not match its receipt; not served", tenant, task)
		writeErr(w, notHeld)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"task_id": task.String(), "tier": "E1", "attachment": name,
		"receipt_id": hex.EncodeToString(receiptID), "post_hash": hex.EncodeToString(post),
		"intent": string(intent), "hunks": string(hunks),
	})
}

type dueEvidence struct {
	task      uuid.UUID
	key, why  string
	received  time.Time
	withdrawn bool
}

// SweepEvidence is the E1 half of the daily sweep: parts past 30 days, or withdrawn (a device whose latest consent turned e1 off), lose their object and gain an evidence_deletion receipt in the transaction that closes the row.
func (j *QuarantineSweep) SweepEvidence(ctx context.Context, id uuid.UUID) (int, error) {
	tenant, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		return 0, err
	}
	now := j.now()
	var due []dueEvidence
	err = j.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE m1_evidence_attachments e SET withdrawn_at = $1
			 WHERE withdrawn_at IS NULL AND deleted_at IS NULL AND NOT coalesce((SELECT d.e1 FROM m1_device_consents d
			   WHERE d.device_id = e.device_id ORDER BY d.row_seq DESC LIMIT 1), false)`, now.UTC()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT task_id, object_key, received_at, withdrawn_at IS NOT NULL FROM m1_evidence_attachments
			 WHERE deleted_at IS NULL AND (withdrawn_at IS NOT NULL OR received_at <= $1) ORDER BY received_at`, now.Add(-EvidenceRetention).UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d dueEvidence
			if err := rows.Scan(&d.task, &d.key, &d.received, &d.withdrawn); err != nil {
				return err
			}
			d.why = "retention_30d"
			if d.withdrawn {
				d.why = "withdrawn"
			}
			due = append(due, d)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, d := range due {
		if j.closeEvidence(ctx, tenant, d, now) {
			closed++
		}
	}
	return closed, nil
}

// closeEvidence deletes one part's object, then receipts it and closes the row; a failure is logged and left for the next sweep.
func (j *QuarantineSweep) closeEvidence(ctx context.Context, tenant querychoke.TenantID, d dueEvidence, now time.Time) bool {
	object, err := j.deleteObject(ctx, d.key)
	if object == sidefx.DeletionReason {
		object = "deleted"
	}
	if err != nil {
		evidenceSweep.WithLabelValues("error").Inc()
		log.Printf("ingest: evidence sweep: %s not deleted, next sweep retries: %v", d.key, err)
		return false
	}
	if j.chain == nil {
		return false
	}
	if err := j.receiptEvidence(ctx, tenant, d, object, now); err != nil {
		evidenceSweep.WithLabelValues("error").Inc()
		log.Printf("ingest: evidence sweep: %s deleted but not receipted, next sweep names the backstop: %v", d.key, err)
		return false
	}
	evidenceSweep.WithLabelValues(d.why).Inc()
	return true
}

// closeLateLanding re-reads the index row after the object landed: a withdrawal (and maybe a sweep that found nothing to delete) that committed in between leaves the object orphaned, so it is deleted now and receipted as the sweep would.
func (m *Module) closeLateLanding(ctx context.Context, tenant querychoke.TenantID, task uuid.UUID, key string, now time.Time) (bool, error) {
	d := dueEvidence{task: task, key: key, why: "withdrawn", withdrawn: true}
	var gone bool
	if err := m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT withdrawn_at IS NOT NULL OR deleted_at IS NOT NULL, received_at FROM m1_evidence_attachments WHERE task_id = $1`, task).Scan(&gone, &d.received)
	}); err != nil || !gone {
		return false, err
	}
	(&QuarantineSweep{db: m.db, store: m.store, chain: m.chain, now: m.now}).closeEvidence(ctx, tenant, d, now)
	return true, nil
}

func (j *QuarantineSweep) receiptEvidence(ctx context.Context, tenant querychoke.TenantID, d dueEvidence, object string, now time.Time) error {
	return j.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var one int
		switch err := tx.QueryRow(ctx, `SELECT 1 FROM m1_evidence_attachments WHERE task_id = $1 AND deleted_at IS NULL FOR UPDATE`, d.task).Scan(&one); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		rec, err := j.chain.AppendServerRecordTx(ctx, tx, tenant, receipts.ServerRecord{
			RecordType: "evidence_deletion",
			SubjectID:  d.task,
			IssuedAt:   now,
			Fields: map[string]any{
				"origin": "cloud", "tier": "E1", "reason": d.why, "object": object,
				"received_at": sidefx.MillisString(d.received), "deleted_at": sidefx.MillisString(now),
			},
			IdempotencyKey: "evidence:" + d.task.String(),
		})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE m1_evidence_attachments SET deleted_at = $2, deletion_receipt_id = $3 WHERE task_id = $1 AND deleted_at IS NULL`,
			d.task, now.UTC(), rec.ReceiptID)
		return err
	})
}
