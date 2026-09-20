package appapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// GET|PUT /api/v1/verify/cloud-judge — the m1_065 consent row (06 §6.5's admission precondition 1).

const (
	cloudJudgeID           = "judge:grounded-rubric@1"
	cloudJudgeSubprocessor = "anthropic"
	cloudJudgeRegion       = "us"
	cloudJudgeMaxTier      = "E1"
)

type cloudJudgeState struct {
	Enabled      bool    `json:"enabled"`
	JudgeID      string  `json:"judge_id"`
	Subprocessor string  `json:"subprocessor"`
	Region       string  `json:"region"`
	MaxTier      string  `json:"max_tier"`
	ConsentedAt  *string `json:"consented_at"`
	ConsentedBy  *string `json:"consented_by"`
}

func disclosedCloudJudge() cloudJudgeState {
	return cloudJudgeState{
		JudgeID: cloudJudgeID, Subprocessor: cloudJudgeSubprocessor,
		Region: cloudJudgeRegion, MaxTier: cloudJudgeMaxTier,
	}
}

// cloudJudgeRow is the tenant's live consent row, or the judge's static disclosure with enabled=false when none exists.
func cloudJudgeRow(r *http.Request, tx pgx.Tx, tid querychoke.TenantID) (cloudJudgeState, error) {
	s := disclosedCloudJudge()
	var consentedBy string
	var consentedAt time.Time
	err := tx.QueryRow(r.Context(), `
		SELECT subprocessor, region, max_tier, consented_by, consented_at
		  FROM m1_cloud_judge_consents
		 WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL`,
		tid.UUID(), cloudJudgeID).Scan(&s.Subprocessor, &s.Region, &s.MaxTier, &consentedBy, &consentedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return cloudJudgeState{}, err
	}
	s.Enabled = true
	at := consentedAt.UTC().Format(time.RFC3339Nano)
	s.ConsentedAt, s.ConsentedBy = &at, &consentedBy
	return s, nil
}

func (m *Module) handleCloudJudge(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	var state cloudJudgeState
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		var err error
		state, err = cloudJudgeRow(r, tx, tid)
		return err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "cloud judge consent lookup failed")
		return
	}
	writeJSON(w, state)
}

func (m *Module) handleCloudJudgeUpdate(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	var wire struct {
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || wire.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "cloud judge body: want {enabled: bool} and nothing else")
		return
	}
	var state cloudJudgeState
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		var werr error
		if *wire.Enabled {
			// Idempotent: m1_065's partial unique index refuses a second live row, so a re-enable is a no-op.
			_, werr = tx.Exec(r.Context(), `
				INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, max_tier, consented_by)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (tenant_id, judge_id) WHERE revoked_at IS NULL DO NOTHING`,
				tid.UUID(), cloudJudgeID, cloudJudgeSubprocessor, cloudJudgeRegion, cloudJudgeMaxTier, who(claims))
		} else {
			_, werr = tx.Exec(r.Context(), `
				UPDATE m1_cloud_judge_consents SET revoked_at = now(), revoked_reason = 'settings'
				 WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL`,
				tid.UUID(), cloudJudgeID)
		}
		if werr != nil {
			return werr
		}
		var err error
		state, err = cloudJudgeRow(r, tx, tid)
		return err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "cloud judge consent update failed")
		return
	}
	writeJSON(w, state)
}
