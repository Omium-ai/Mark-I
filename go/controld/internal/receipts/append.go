package receipts

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// InternalRecordTypes is what an intelligence service may request over the internal route (m1_002 §5, 07 C13); key_rotation stays controld's own act.
var InternalRecordTypes = map[string]bool{
	"noise_certificate":  true,
	"memory_admission":   true,
	"bundle_publication": true,
	"corpus_export":      true,
	"verifier_promotion": true,
}

type appendRequest struct {
	TenantID       string         `json:"tenant_id"`
	RecordType     string         `json:"record_type"`
	SubjectID      string         `json:"subject_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	Payload        map[string]any `json:"payload"`
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// handleAppend is POST /internal/v1/receipts/append: the service credential is asserted before the body is read, and the tenant comes from the body only because the verified principal is a trusted internal service (ADR-0010 §2.2 seam). A repeat under the same (tenant, record_type, idempotency_key) answers the existing receipt.
func (m *Module) handleAppend(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		writeErr(w, http.StatusForbidden, "M1E-1001", "service credential required")
		return
	}
	cred, err := querychoke.VerifyServiceCredential(m.serviceToken, bearer)
	if err != nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "service credential rejected")
		return
	}
	var req appendRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed append request")
		return
	}
	tenantUUID, err := uuid.Parse(req.TenantID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "tenant_id: not a UUID")
		return
	}
	tenant, err := querychoke.FromServiceJob(cred, tenantUUID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	if !InternalRecordTypes[req.RecordType] {
		writeErr(w, http.StatusBadRequest, "M1E-2001", fmt.Sprintf("record_type %q is not an internal-service receipt class", req.RecordType))
		return
	}
	subject, err := uuid.Parse(req.SubjectID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "subject_id: not a UUID")
		return
	}
	if req.IdempotencyKey == "" || len(req.IdempotencyKey) > 200 {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "idempotency_key: required, at most 200 bytes (m1_072)")
		return
	}
	rec := ServerRecord{RecordType: req.RecordType, SubjectID: subject, IssuedAt: time.Now(), Fields: req.Payload, IdempotencyKey: req.IdempotencyKey}
	if err := rec.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	if _, err := CanonicalJSON(rec.Fields); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	if m.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "receipt append surface not wired")
		return
	}
	var out Appended
	err = m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		var hash []byte
		err := tx.QueryRow(r.Context(),
			`SELECT id, seq, receipt_hash, payload FROM m1_receipts WHERE tenant_id = $1 AND record_type = $2 AND idempotency_key = $3`,
			tenant.UUID(), rec.RecordType, rec.IdempotencyKey).Scan(&out.ReceiptID, &out.Seq, &hash, &out.PayloadText)
		if err == nil {
			// ponytail: a repeat under one key returns the first receipt whatever its fields; refuse-on-mismatch when a caller can act on it.
			out.ReceiptHash = [32]byte(hash)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out, err = m.store.AppendServerRecordTx(r.Context(), tx, tenant, rec)
		return err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "chain append failed")
		return
	}
	writeJSON(w, map[string]any{
		"receipt_id":   out.ReceiptID.String(),
		"seq":          out.Seq,
		"receipt_hash": hex.EncodeToString(out.ReceiptHash[:]),
		"payload":      out.PayloadText,
	})
}
