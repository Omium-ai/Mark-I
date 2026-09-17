package appapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// GET /api/v1/memory/injections?window=&limit=

type injectionRow struct {
	ID         string  `json:"id"`
	ArtifactID string  `json:"artifact_id"`
	At         string  `json:"at"`
	SessionID  string  `json:"session_id"`
	TaskID     *string `json:"task_id"`
	Channel    string  `json:"channel"`
	TokensUsed uint32  `json:"tokens_used"`
	Outcome    string  `json:"outcome"`
}

// ponytail: one app_session_events window scan (the session-detail read) folded here; add an app_injections template when a tenant's month outgrows its row limit.
func (m *Module) handleInjections(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	qs := r.URL.Query()
	from, to, err := parseWindow(qs.Get("window"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	limit, err := parseLimit(qs.Get("limit"), 200, 1000)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.query(w, r, tid, "app_session_events", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	injections := foldInjections(rows.Rows)
	if len(injections) > limit {
		injections = injections[:limit]
	}
	h, ok := m.honesty(w, r, from, to)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"window": windowJSON(from, to), "injections": injections, "honesty": h})
}

// foldInjections is one row per delivered artifact, newest first; outcome is the task's stage-final verdict at close (the last one in causal order), "pending" until it has one.
func foldInjections(rows []map[string]any) []injectionRow {
	final := map[string]string{}
	for _, row := range rows {
		if asStr(row["event_type"]) == "VerdictEvent" && isFinal(asStr(row["verdict_stage"])) {
			final[asStr(row["task_id"])] = asStr(row["verdict"])
		}
	}
	out := []injectionRow{}
	for _, row := range rows {
		if asStr(row["event_type"]) != "MemoryInjection" {
			continue
		}
		var p injectionPayload
		_ = json.Unmarshal([]byte(asStr(row["payload"])), &p)
		at := asTime(row["occurred_at"])
		base := injectionRow{At: at.Format(time.RFC3339Nano), SessionID: asStr(row["session_id"]), Channel: enumSuffix(p.Channel, "INJECTION_CHANNEL_"), TokensUsed: p.TokensUsed, Outcome: "pending"}
		if id := asStr(row["task_id"]); id != uuid.Nil.String() {
			base.TaskID = &id
			if v, ok := final[id]; ok {
				base.Outcome = v
			}
		}
		eventID := asStr(row["event_id"])
		for i, raw := range p.ArtifactIDs {
			ir := base
			ir.ID, ir.ArtifactID = eventID+"/"+strconv.Itoa(i), artifactID(raw)
			out = append(out, ir)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// artifactID decodes protojson's base64 of the 16 id bytes (MemoryInjection.artifact_ids); anything else is shown as hex rather than dropped.
func artifactID(raw string) string {
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return raw
	}
	if id, err := uuid.FromBytes(b); err == nil {
		return id.String()
	}
	return hex.EncodeToString(b)
}

// GET /api/v1/team

const inviteBase = "https://app.omium.ai/invite/"

type member struct {
	ID       string  `json:"id"`
	Name     *string `json:"name"`
	Email    *string `json:"email"`
	Role     string  `json:"role"`
	JoinedAt string  `json:"joined_at"`
	Status   string  `json:"status"`
}

// who is the principal a row records: the user token's subject, else the device.
func who(c auth.Claims) string {
	if c.Subject != "" {
		return c.Subject
	}
	return "device:" + c.DeviceID.String()
}

// handleTeam: members are the tenant's principals as the schema knows them (m1_078 owner_subject, the approvers of m1_device_enrollments, the caller) plus live invites as status "invited"; no users table exists, so name/email are null. invite_link is null: the raw token is answered once by POST /team/invites (m1_081 stores its hash).
func (m *Module) handleTeam(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	var owner *string
	var shared bool
	var created time.Time
	members := []member{}
	seen := map[string]bool{}
	add := func(id string, role string, joined time.Time, email *string, status string) {
		if seen[id] {
			return
		}
		seen[id] = true
		members = append(members, member{ID: id, Email: email, Role: role, JoinedAt: joined.UTC().Format(time.RFC3339Nano), Status: status})
	}
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `SELECT owner_subject, shared_memory, created_at FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&owner, &shared, &created); err != nil {
			return err
		}
		if owner != nil {
			add(*owner, "owner", created, nil, "active")
		}
		rows, err := tx.Query(r.Context(), `SELECT oidc_subject, min(started_at) FROM m1_device_enrollments WHERE tenant_id = $1 AND status = 'approved' AND oidc_subject IS NOT NULL GROUP BY oidc_subject ORDER BY 2, 1`, tid.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sub string
			var joined time.Time
			if err := rows.Scan(&sub, &joined); err != nil {
				return err
			}
			add(sub, "member", joined, nil, "active")
		}
		if err := rows.Err(); err != nil {
			return err
		}
		add(who(claims), "member", created, nil, "active")
		invites, err := tx.Query(r.Context(), `SELECT id, invited_email, created_at FROM m1_team_invites WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > now() ORDER BY created_at, id`, tid.UUID())
		if err != nil {
			return err
		}
		defer invites.Close()
		for invites.Next() {
			var id uuid.UUID
			var email *string
			var at time.Time
			if err := invites.Scan(&id, &email, &at); err != nil {
				return err
			}
			add("invite:"+id.String(), "member", at, email, "invited")
		}
		return invites.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusForbidden, "M1E-1001", "tenant not visible")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "team lookup failed")
		return
	}
	var tvo any
	from, to, _ := parseWindow("")
	if full, rec := m.tvoReport(r, from, to); rec.code == http.StatusOK && full != nil {
		tvo = pick(full, "tvo", "coverage_band", "cost_basis", "guarantee_grade", "refusal")
	}
	writeJSON(w, map[string]any{"members": members, "invite_link": nil, "shared_memory": shared, "tvo": tvo, "fleet_status": nil})
}

// PUT /api/v1/team {shared_memory}

func (m *Module) handleTeamUpdate(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	var wire struct {
		SharedMemory *bool `json:"shared_memory"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || wire.SharedMemory == nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "team body: want {shared_memory: bool} and nothing else")
		return
	}
	var n int64
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE m1_tenants SET shared_memory = $2 WHERE id = $1`, tid.UUID(), *wire.SharedMemory)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "team update failed")
		return
	}
	if n != 1 {
		writeErr(w, http.StatusForbidden, "M1E-1001", "tenant not visible")
		return
	}
	writeJSON(w, map[string]any{"shared_memory": *wire.SharedMemory})
}

// POST /api/v1/team/invites {email?}: mints a 7-day invite (m1_081, hash stored) and answers the link once; nothing is emailed.

func (m *Module) handleTeamInvite(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	var wire struct {
		Email string `json:"email"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "invite body: want {email?} and nothing else")
		return
	}
	wire.Email = strings.TrimSpace(wire.Email)
	if wire.Email != "" && (len(wire.Email) > 254 || !strings.Contains(wire.Email, "@")) {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "email: not an address")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "entropy unavailable")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	var email *string
	if wire.Email != "" {
		email = &wire.Email
	}
	var expires time.Time
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `INSERT INTO m1_team_invites (tenant_id, token_hash, invited_email, invited_by, expires_at) VALUES ($1, $2, $3, $4, now() + interval '7 days') RETURNING expires_at`,
			tid.UUID(), hash[:], email, who(claims)).Scan(&expires)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "invite not recorded")
		return
	}
	writeJSON(w, map[string]any{
		"sent": true, "invite_link": inviteBase + tid.String() + "/" + token, "invited_email": email,
		"status": "sent", "expires_at": expires.UTC().Format(time.RFC3339Nano),
	})
}
