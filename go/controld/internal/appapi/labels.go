package appapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// Human gold labels (06 §5.1's third strong-label source): the developer confirms a completed task's outcome and the row lands in the tenant's open gold set with label_source = 'human'. Post-hoc by construction — the ledger must already hold the task's TaskClose — so a label can never touch the run it describes. The digest is m1_021's task_digest = HMAC-SHA256(tenant root, session_id ‖ task_id), the one definition (intel corpus/export.py, adjudicator nightly.py _ledger_pairs).

const (
	goldBootstrapMin = 50  // adjudicator certs/state_machine.py GOLD_BOOTSTRAP_MIN
	goldSizeGate     = 200 // D15
)

var labelWords = map[string]bool{"satisfied": true, "violated": true, "refused": true, "error": true}

func taskDigest(root []byte, session, task uuid.UUID) []byte {
	mac := hmac.New(sha256.New, root)
	mac.Write(session[:])
	mac.Write(task[:])
	return mac.Sum(nil)
}

// POST /api/v1/verify/labels {session_id, task_id, label}
func (m *Module) handleLabel(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if m.deps.TenantRoot == nil {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "labels need the tenant HMAC root (TENANT_HMAC_PEPPER)")
		return
	}
	var wire struct {
		SessionID string `json:"session_id"`
		TaskID    string `json:"task_id"`
		Label     string `json:"label"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "label body: want {session_id, task_id, label} and nothing else")
		return
	}
	session, err1 := uuid.Parse(wire.SessionID)
	task, err2 := uuid.Parse(wire.TaskID)
	wire.Label = strings.ToLower(strings.TrimSpace(wire.Label))
	if err1 != nil || err2 != nil || task == uuid.Nil || !labelWords[wire.Label] {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "label: want session_id and task_id as UUIDs and label in satisfied|violated|refused|error")
		return
	}
	rows, ok := m.query(w, r, tid, "task_for_label", querychoke.Params{"session_id": session, "task_id": task})
	if !ok {
		return
	}
	agent := ""
	var closed uint64
	if len(rows.Rows) == 1 {
		agent, closed = asStr(rows.Rows[0]["agent"]), asU64(rows.Rows[0]["closed"])
	}
	if agent == "" {
		writeErr(w, http.StatusNotFound, "M1E-4004", "no such task for this tenant")
		return
	}
	if closed == 0 {
		writeErr(w, http.StatusConflict, "M1E-4009", "the task is still open; confirm it once it has closed")
		return
	}
	root, err := m.deps.TenantRoot(tid.UUID())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "tenant root unavailable")
		return
	}
	digest := taskDigest(root, session, task)
	var device *uuid.UUID
	if claims.DeviceID != uuid.Nil {
		d := claims.DeviceID
		device = &d
	}
	var setID uuid.UUID
	err = m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		// The tenant's open set for this agent (gold labels do not transfer across hook vocabularies, m1_021); created on the first label.
		err := tx.QueryRow(r.Context(), `SELECT id FROM gold_sets WHERE tenant_id = $1 AND agent = $2 AND frozen_at IS NULL ORDER BY created_at DESC LIMIT 1`, tid.UUID(), agent).Scan(&setID)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(r.Context(), `INSERT INTO gold_sets (tenant_id, agent) VALUES ($1, $2) RETURNING id`, tid.UUID(), agent).Scan(&setID)
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO gold_set_members (gold_set_id, tenant_id, task_digest, true_label, label_source, labeled_by_device)
			VALUES ($1, $2, $3, $4::verdict, 'human', $5)
			ON CONFLICT (gold_set_id, task_digest) DO UPDATE
			   SET true_label = EXCLUDED.true_label, label_source = 'human', labeled_by_device = EXCLUDED.labeled_by_device, labeled_at = now()`,
			setID, tid.UUID(), digest, wire.Label, device)
		return err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "label not recorded")
		return
	}
	progress, ok := m.labelProgress(w, r, tid)
	if !ok {
		return
	}
	progress["recorded"] = true
	progress["label"] = wire.Label
	writeJSON(w, progress)
}

// GET /api/v1/verify/labels — how far the tenant's gold set has formed.
func (m *Module) handleLabels(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	progress, ok := m.labelProgress(w, r, tid)
	if !ok {
		return
	}
	writeJSON(w, progress)
}

func (m *Module) labelProgress(w http.ResponseWriter, r *http.Request, tid querychoke.TenantID) (map[string]any, bool) {
	var total, human, open, frozenN int64
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `SELECT count(*), count(*) FILTER (WHERE label_source = 'human'),
			count(*) FILTER (WHERE s.frozen_at IS NULL)
			FROM gold_set_members g JOIN gold_sets s ON s.id = g.gold_set_id WHERE g.tenant_id = $1`, tid.UUID()).Scan(&total, &human, &open); err != nil {
			return err
		}
		// The latest frozen snapshot is what a certificate cites (adjudicator nightly.py certs_recompute).
		return tx.QueryRow(r.Context(), `SELECT coalesce((SELECT count(*) FROM gold_set_members g WHERE g.gold_set_id = s.id), 0)
			FROM gold_sets s WHERE s.tenant_id = $1 AND s.frozen_at IS NOT NULL ORDER BY s.frozen_at DESC LIMIT 1`, tid.UUID()).Scan(&frozenN)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "label progress lookup failed")
		return nil, false
	}
	return map[string]any{
		"labels": total, "human": human, "open": open, "frozen": frozenN,
		"bootstrap_at": goldBootstrapMin, "certify_at": goldSizeGate,
	}, true
}
