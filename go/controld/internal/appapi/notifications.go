package appapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/teams"
)

// GET/PUT /api/v1/me/notifications: the signed-in person's opt-in to the weekly savings email (m1_091), in the tenant they work in now; off until they turn it on.

type notificationPrefs struct {
	WeeklyDigest bool    `json:"weekly_digest"`
	Email        *string `json:"email"`
}

func readPrefs(ctx context.Context, tx pgx.Tx, tid querychoke.TenantID, c auth.Claims) (notificationPrefs, error) {
	p := notificationPrefs{Email: emailOf(c)}
	var stored *string
	err := tx.QueryRow(ctx, `SELECT weekly_digest, email FROM m1_notification_prefs WHERE tenant_id = $1 AND subject = $2`, tid.UUID(), teams.Subject(c.Subject)).Scan(&p.WeeklyDigest, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	if p.Email == nil {
		p.Email = stored
	}
	return p, err
}

func (m *Module) handleNotifications(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	var p notificationPrefs
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) (err error) {
		p, err = readPrefs(r.Context(), tx, tid, claims)
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "notification settings unreadable")
		return
	}
	writeJSON(w, p)
}

func (m *Module) handleNotificationsUpdate(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	var wire struct {
		WeeklyDigest *bool `json:"weekly_digest"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || wire.WeeklyDigest == nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "notifications body: want {weekly_digest: bool} and nothing else")
		return
	}
	if *wire.WeeklyDigest && claims.Email == "" {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "this sign-in carries no email address to send the digest to")
		return
	}
	ctx := r.Context()
	var p notificationPrefs
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO m1_notification_prefs (tenant_id, subject, email, weekly_digest) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, subject) DO UPDATE SET weekly_digest = EXCLUDED.weekly_digest,
			  email = COALESCE(EXCLUDED.email, m1_notification_prefs.email), updated_at = now()`,
			tid.UUID(), teams.Subject(claims.Subject), emailOf(claims), *wire.WeeklyDigest); err != nil {
			return err
		}
		var err error
		p, err = readPrefs(ctx, tx, tid, claims)
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "notification settings not saved")
		return
	}
	writeJSON(w, p)
}
