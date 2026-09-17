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

// consentsBody is the device's whole Step-4 record (desktop spec §3.2, mark1d gates/consents.json); every field is required so a partial write can never read as a revocation or a grant of the fields it left out.
type consentsBody struct {
	E1         *bool `json:"e1"`
	CloudJudge *bool `json:"cloud_judge"`
	Training   *bool `json:"training"`
}

const maxConsentsBody = 4 << 10

// handleConsents is PUT /api/v1/consents: the device token's (tenant, device) stamps the row, the body is the state, and m1_082 keeps it append-only so the latest row per device is that device's consent and the history stays answerable.
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
	var at time.Time
	err = m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training)
			VALUES ($1, $2, $3, $4, $5) RETURNING recorded_at`,
			tenant.UUID(), claims.DeviceID, *body.E1, *body.CloudJudge, *body.Training).Scan(&at)
	})
	if err != nil {
		writeErr(w, errServer("consent store unavailable"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"recorded_at": at.UTC().Format(time.RFC3339)})
}
