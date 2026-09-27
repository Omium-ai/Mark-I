package ingest

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// consentsBody is the device's Step-4 record (desktop spec §3.2, mark1d gates/consents.json); the later four are tri-state: absent keeps this device's previous value (false if it never had one).
type consentsBody struct {
	E1                 *bool `json:"e1"`
	CloudJudge         *bool `json:"cloud_judge"`
	Training           *bool `json:"training"`
	Team               *bool `json:"team"`                // 15-teams: share memory with the team
	ContributeOutcomes *bool `json:"contribute_outcomes"` // 16 L8: contribute task outcomes
	LocalRM            *bool `json:"local_rm"`            // 16 L6: the reward model scores on the device
	CloudRM            *bool `json:"cloud_rm"`            // 16 L6: the reward model may score this device's E1 hunks in Omium's cloud
}

// consentsRow is the device's effective latest row, the PUT's answer (08 §3.7a).
type consentsRow struct {
	E1                 bool `json:"e1"`
	CloudJudge         bool `json:"cloud_judge"`
	Training           bool `json:"training"`
	Team               bool `json:"team"`
	ContributeOutcomes bool `json:"contribute_outcomes"`
	LocalRM            bool `json:"local_rm"`
	CloudRM            bool `json:"cloud_rm"`
}

const maxConsentsBody = 4 << 10

// explicitOff names the fields this body sets false that m1_107 may withdraw person-wide (on a true→false) and that release a hold; cloud_rm and local_rm stay per device.
func (b consentsBody) explicitOff() []string {
	off := []string{}
	for name, on := range map[string]*bool{"e1": b.E1, "cloud_judge": b.CloudJudge, "training": b.Training, "team": b.Team, "contribute_outcomes": b.ContributeOutcomes} {
		if on != nil && !*on {
			off = append(off, name)
		}
	}
	return off
}

// legacy: only an edge older than this release sends the three first fields alone, and its app granted cloud_judge and training under their old copy, so a true lands off and held.
func (b consentsBody) legacy() bool {
	return b.Team == nil && b.ContributeOutcomes == nil && b.LocalRM == nil && b.CloudRM == nil
}

// handleConsents is PUT /api/v1/consents (08 §3.7a): m1_107 withdraws the person-wide transitions under the device locks, then the sender's row is appended with every held field off until the body sends it false, and the effective row is answered.
func (m *Module) handleConsents(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeErr(w, errServer("auth middleware did not run"))
		return
	}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil || claims.DeviceID == uuid.Nil {
		writeErr(w, apiErr{http.StatusForbidden, "M1E-1001", "a device token is required: consent is recorded per device", nil})
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConsentsBody))
	dec.DisallowUnknownFields()
	var body consentsBody
	if err := dec.Decode(&body); err != nil || body.E1 == nil || body.CloudJudge == nil || body.Training == nil {
		writeErr(w, errMalformed("body must be {e1, cloud_judge, training}, all booleans"))
		return
	}
	if m.db == nil {
		writeErr(w, errServer("consent store not configured"))
		return
	}
	var row consentsRow
	var at time.Time
	err = m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		off := body.explicitOff()
		if _, err := tx.Exec(r.Context(), `SELECT m1_withdraw_person_consents($1, $2)`, claims.DeviceID, off); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), `
			INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm, person_off)
			SELECT $1, $2, $3 AND NOT ('e1' = ANY (h.s)), $4 AND NOT $10 AND NOT ('cloud_judge' = ANY (h.s)), $5 AND NOT $10 AND NOT ('training' = ANY (h.s)),
			       coalesce($6::boolean, p.team, false) AND NOT ('team' = ANY (h.s)),
			       coalesce($7::boolean, p.contribute_outcomes, false) AND NOT ('contribute_outcomes' = ANY (h.s)),
			       coalesce($8::boolean, p.local_rm, false), coalesce($9::boolean, p.cloud_rm, false),
			       nullif(ARRAY(SELECT DISTINCT x FROM unnest(h.s || array_remove(ARRAY[CASE WHEN $10 AND $4 THEN 'cloud_judge' END, CASE WHEN $10 AND $5 THEN 'training' END], NULL)) x
			                     WHERE NOT x = ANY ($11::text[]) ORDER BY x), '{}')
			  FROM (SELECT 1) one LEFT JOIN LATERAL (SELECT team, contribute_outcomes, local_rm, cloud_rm, person_off FROM m1_device_consents
			                                          WHERE device_id = $2 ORDER BY row_seq DESC LIMIT 1) p ON true
			  CROSS JOIN LATERAL (SELECT coalesce(p.person_off, '{}') AS s) h
			RETURNING e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm, recorded_at`,
			tenant.UUID(), claims.DeviceID, *body.E1, *body.CloudJudge, *body.Training, body.Team, body.ContributeOutcomes, body.LocalRM, body.CloudRM, body.legacy(), off).
			Scan(&row.E1, &row.CloudJudge, &row.Training, &row.Team, &row.ContributeOutcomes, &row.LocalRM, &row.CloudRM, &at)
	})
	if err != nil {
		writeErr(w, errServer("consent store unavailable"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"recorded_at": at.UTC().Format(time.RFC3339), "consents": row})
}
