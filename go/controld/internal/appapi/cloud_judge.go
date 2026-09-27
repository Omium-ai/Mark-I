package appapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// GET|PUT /api/v1/verify/cloud-judge, /api/v1/verify/cloud-rm and /api/v1/memory/extract-consent: one m1_065 register row each (06 §6.5 precondition 1; 16 §L1/§L6).

// consentKey is what a register row discloses: the key, the subprocessor and region the service calls, the highest evidence tier it reads.
type consentKey struct{ id, subprocessor, region, maxTier string }

var (
	cloudJudgeConsent    = consentKey{"judge:grounded-rubric@2", "nebius", "global", "E1"}
	memoryExtractConsent = consentKey{"mem:extract@1", "nebius", "global", "E0"}
	cloudRMConsent       = consentKey{"rm:mark1-rm-a@1", "baseten", "us", "E1"}
)

// RegisterEntry is one row of the subprocessor register (10 §10.4): every path by which Mark 1 data reaches a third party, who processes it, where, the most it reads, and how long that processor keeps it (0 = kept only while processed: zero data retention for inference, deleted when a training run ends; null = the processor's own schedule, stated in the row's copy). A consent whose data reaches a second processor has a second row keyed "<consent>:compute".
type RegisterEntry struct {
	Key           string `json:"key"`
	Subprocessor  string `json:"subprocessor"`
	Region        string `json:"region"`
	MaxTier       string `json:"max_tier"`
	RetentionDays *int   `json:"retention_days"`
}

// Register is the single source the consent routes, the app's consent copy (Mark1-GUI settings/register.ts), mark.omium.ai/legal/subprocessors and doc 10's table are held to. e1 is the device's E1 part in the ingest bucket, swept at 30 d with an evidence_deletion receipt; training is corpus.export's typed E0 rows (no text) in the corpus bucket (lifecycle corpus-default-ttl 400 d); contribute_outcomes is the device's consented contribution under t/<tenant>/contributions/v1/ (lifecycle contribution-ttl 365 d); the two :compute rows are the training plane's GPU jobs on Nebius AI Cloud (eu-north1), which read those rows for the run and keep nothing after it; Nebius Token Factory runs with org-wide Zero Data Retention on; Baseten keeps no synchronous inference input or output; email is Customer.io (helm email.customerioRegion), sent untracked with message retention off, which still keeps the recipient's profile and delivery record.
var Register = []RegisterEntry{
	{"e1", "aws-s3", "us-east-1", "E1", days(30)},
	registerRow(cloudJudgeConsent),
	registerRow(cloudRMConsent),
	registerRow(memoryExtractConsent),
	{"training", "aws-s3", "us-east-1", "E0", days(400)},
	{"training:compute", "nebius-ai-cloud", "eu-north1", "E0", days(0)},
	{"contribute_outcomes", "aws-s3", "us-east-1", "contribution", days(365)},
	{"contribute_outcomes:compute", "nebius-ai-cloud", "eu-north1", "contribution", days(0)},
	{"email", "customer.io", "us", "account", nil},
}

func days(n int) *int { return &n }

func registerRow(k consentKey) RegisterEntry {
	return RegisterEntry{k.id, k.subprocessor, k.region, k.maxTier, days(0)}
}

type consentState struct {
	Enabled      bool    `json:"enabled"`
	JudgeID      string  `json:"judge_id"`
	Subprocessor string  `json:"subprocessor"`
	Region       string  `json:"region"`
	MaxTier      string  `json:"max_tier"`
	ConsentedAt  *string `json:"consented_at"`
	ConsentedBy  *string `json:"consented_by"`
}

// consentRow is the tenant's live row, or the key's static disclosure with enabled=false when none exists.
func consentRow(r *http.Request, tx pgx.Tx, tid querychoke.TenantID, k consentKey) (consentState, error) {
	s := consentState{JudgeID: k.id, Subprocessor: k.subprocessor, Region: k.region, MaxTier: k.maxTier}
	var consentedBy string
	var consentedAt time.Time
	err := tx.QueryRow(r.Context(), `
		SELECT subprocessor, region, max_tier, consented_by, consented_at
		  FROM m1_cloud_judge_consents
		 WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL`,
		tid.UUID(), k.id).Scan(&s.Subprocessor, &s.Region, &s.MaxTier, &consentedBy, &consentedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return consentState{}, err
	}
	s.Enabled = true
	at := consentedAt.UTC().Format(time.RFC3339Nano)
	s.ConsentedAt, s.ConsentedBy = &at, &consentedBy
	return s, nil
}

func (m *Module) consentGet(k consentKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid, _, ok := principal(w, r)
		if !ok {
			return
		}
		var state consentState
		err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
			var err error
			state, err = consentRow(r, tx, tid, k)
			return err
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "M1E-9500", "consent lookup failed")
			return
		}
		writeJSON(w, state)
	}
}

func (m *Module) consentPut(k consentKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid, claims, ok := principal(w, r)
		if !ok {
			return
		}
		var wire struct {
			Enabled *bool  `json:"enabled"`
			JudgeID string `json:"judge_id"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&wire); err != nil || wire.Enabled == nil {
			writeErr(w, http.StatusBadRequest, "M1E-2001", "consent body: want {enabled: bool, judge_id?: string} and nothing else")
			return
		}
		// consent is to the key the caller's copy described: an app that shows another processor (v0.1.14's "Anthropic, US") never enables this one
		if *wire.Enabled && wire.JudgeID != k.id {
			writeTeamErr(w, teamErr{http.StatusConflict, "M1E-2014", "consent_copy_outdated", "this app describes a different processor for this setting; update Mark 1 to turn it on"}, "")
			return
		}
		var state consentState
		err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
			// in a team one person's click would send every teammate's evidence to the subprocessor: the owner decides (15-teams ruling 4)
			if err := ownerOfTeam(r.Context(), tx, tid.UUID(), claims); err != nil {
				return err
			}
			var werr error
			if *wire.Enabled {
				// Idempotent: m1_065's partial unique index refuses a second live row, so a re-enable is a no-op.
				_, werr = tx.Exec(r.Context(), `
					INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, max_tier, consented_by)
					VALUES ($1, $2, $3, $4, $5, $6)
					ON CONFLICT (tenant_id, judge_id) WHERE revoked_at IS NULL DO NOTHING`,
					tid.UUID(), k.id, k.subprocessor, k.region, k.maxTier, who(claims))
			} else {
				_, werr = tx.Exec(r.Context(), `
					UPDATE m1_cloud_judge_consents SET revoked_at = now(), revoked_reason = 'settings'
					 WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL`,
					tid.UUID(), k.id)
			}
			if werr != nil {
				return werr
			}
			var err error
			state, err = consentRow(r, tx, tid, k)
			return err
		})
		if err != nil {
			writeTeamErr(w, err, "consent update failed")
			return
		}
		writeJSON(w, state)
	}
}
