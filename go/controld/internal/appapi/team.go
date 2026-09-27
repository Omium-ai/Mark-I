package appapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/mail"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/teams"
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

const inviteBase = "https://mark.omium.ai/join#"

type member struct {
	ID         string  `json:"id"`
	Name       *string `json:"name"`
	Email      *string `json:"email"`
	Role       string  `json:"role"`
	JoinedAt   string  `json:"joined_at"`
	LastActive *string `json:"last_active"`
	Status     string  `json:"status"`
	Totals     *totals `json:"totals"`
}

// who is the principal a row records: the user token's subject, else the device.
func who(c auth.Claims) string {
	if c.Subject != "" {
		return c.Subject
	}
	return "device:" + c.DeviceID.String()
}

// teamErr is a refusal with the 15-teams reason string beside its M1E code.
type teamErr struct {
	status            int
	code, reason, msg string
}

func (e teamErr) Error() string { return e.reason }

func (m *Module) maxMembers() int {
	if m.deps.TeamMaxMembers <= 0 {
		return 10
	}
	return m.deps.TeamMaxMembers
}

var (
	errNotOwner         = teamErr{http.StatusForbidden, "M1E-1007", "not_owner", "only the team owner can do this"}
	errNotMember        = teamErr{http.StatusForbidden, "M1E-1007", "not_member", "you are not a member of this team"}
	errUserToken        = teamErr{http.StatusForbidden, "M1E-1007", "user_token_required", "sign in: this needs the Mark 1 user token"}
	errTeamFull         = teamErr{http.StatusConflict, "M1E-2011", "team_full", "the team is full"}
	errInviteInvalid    = teamErr{http.StatusNotFound, "M1E-2012", "invite_invalid", "this invite is unknown, expired or already used"}
	errEmailMismatch    = teamErr{http.StatusForbidden, "M1E-1007", "invite_email_mismatch", "this invite is for a different email address"}
	errAlreadyInTeam    = teamErr{http.StatusConflict, "M1E-2011", "already_in_team", "you are already in a team; leave it first"}
	errOwnTeam          = teamErr{http.StatusConflict, "M1E-2011", "own_team", "this invite is to your own team"}
	errOwnerOfTeam      = teamErr{http.StatusConflict, "M1E-2011", "owner_of_team", "you own a team with members; remove them before joining another team"}
	errOwnerCannotLeave = teamErr{http.StatusConflict, "M1E-2011", "owner_cannot_leave", "the owner cannot leave their own team"}
	errMemberNotFound   = teamErr{http.StatusNotFound, "M1E-2012", "member_not_found", "no such member in this team"}
	errInviteRate       = teamErr{http.StatusTooManyRequests, "M1E-9001", "invite_rate_limited", "too many invites today; try again tomorrow"}
)

func writeTeamErr(w http.ResponseWriter, err error, fallback string) {
	var te teamErr
	switch {
	case errors.As(err, &te):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(te.status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": te.code, "message": te.msg, "reason": te.reason}})
	case errors.Is(err, pgx.ErrNoRows):
		writeErr(w, http.StatusForbidden, "M1E-1001", "tenant not visible")
	default:
		slog.Error("appapi: team", "err", err)
		writeErr(w, http.StatusInternalServerError, "M1E-9500", fallback)
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// subjectOf is the caller's principal: the user token's, else the subject that enrolled the calling device ("" when none did).
func subjectOf(ctx context.Context, tx pgx.Tx, c auth.Claims) (string, error) {
	if c.Subject != "" {
		return teams.Subject(c.Subject), nil
	}
	var s string
	err := tx.QueryRow(ctx, `SELECT oidc_subject FROM m1_device_enrollments WHERE device_id = $1 AND oidc_subject IS NOT NULL AND status = 'approved' ORDER BY row_seq DESC LIMIT 1`, c.DeviceID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return s, err
}

// participant is teams.Participant with the team error shape.
func (m *Module) participant(next http.Handler) http.Handler {
	return teams.Participant(m.deps.PG, func(w http.ResponseWriter, err error) {
		if errors.Is(err, teams.ErrNotMember) {
			writeTeamErr(w, errNotMember, "")
			return
		}
		writeTeamErr(w, err, "team membership lookup failed")
	})(next)
}

// ownerOfTeam gates tenant-wide settings: in a team only the owner, signed in as a person, may change them; a solo tenant is unchanged.
func ownerOfTeam(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, c auth.Claims) error {
	var team bool
	var owner *string
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM m1_team_members WHERE tenant_id = $1 AND role = 'member'),
		(SELECT owner_subject FROM m1_tenants WHERE id = $1)`, tenant).Scan(&team, &owner); err != nil {
		return err
	}
	switch {
	case !team:
		return nil
	case c.Subject == "":
		return errUserToken
	case owner == nil || teams.Subject(c.Subject) != *owner:
		return errNotOwner
	}
	return nil
}

func emailOf(c auth.Claims) *string {
	if c.Email == "" {
		return nil
	}
	e := c.Email
	return &e
}

// upsertOwner gives the owner its member row (joined at the tenant's creation); an email only ever fills or refreshes it.
func upsertOwner(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, subject string, email *string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO m1_team_members (tenant_id, subject, email, role, joined_at)
		SELECT $1, $2, $3, 'owner', created_at FROM m1_tenants WHERE id = $1
		ON CONFLICT (tenant_id, subject) DO UPDATE SET email = EXCLUDED.email
		 WHERE EXCLUDED.email IS NOT NULL AND m1_team_members.email IS DISTINCT FROM EXCLUDED.email`, tenant, subject, email)
	return err
}

// roomFor refuses when owner + active members + live invites + adding exceeds the cap; callers hold the m1_tenants row lock.
func (m *Module) roomFor(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, adding int) error {
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT 1 + (SELECT count(*) FROM m1_team_members WHERE tenant_id = $1 AND role = 'member' AND left_at IS NULL)
		         + (SELECT count(*) FROM m1_team_invites WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > now())`, tenant).Scan(&n); err != nil {
		return err
	}
	if n+adding > m.maxMembers() {
		return errTeamFull
	}
	return nil
}

// handleTeam: the owner row, active members and live invites (15-teams); ids are GET /me's user.id, last_active the latest device heartbeat of that subject in this tenant. invite_link is null: the raw token is answered once by POST /team/invites.
func (m *Module) handleTeam(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var shared bool
	role := "member"
	members := []member{}
	var owners map[string]string
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var owner *string
		if err := tx.QueryRow(ctx, `SELECT owner_subject, shared_memory FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&owner, &shared); err != nil {
			return err
		}
		me, err := subjectOf(ctx, tx, claims)
		if err != nil {
			return err
		}
		if owner != nil {
			var email *string
			if me == *owner {
				role, email = "owner", emailOf(claims)
			}
			if err := upsertOwner(ctx, tx, tid.UUID(), *owner, email); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `
			SELECT m.subject, m.email, m.role, m.joined_at,
			       (SELECT max(d.last_seen_at) FROM m1_devices d JOIN m1_device_enrollments e ON e.device_id = d.id WHERE e.oidc_subject = m.subject)
			  FROM m1_team_members m
			 WHERE m.tenant_id = $1 AND m.left_at IS NULL
			 ORDER BY m.role = 'owner' DESC, m.joined_at, m.subject`, tid.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sub string
			var mb member
			var joined time.Time
			var seen *time.Time
			if err := rows.Scan(&sub, &mb.Email, &mb.Role, &joined, &seen); err != nil {
				return err
			}
			mb.ID, mb.JoinedAt, mb.Status = strings.TrimPrefix(sub, "omium:"), joined.UTC().Format(time.RFC3339Nano), "active"
			if seen != nil {
				s := seen.UTC().Format(time.RFC3339Nano)
				mb.LastActive = &s
			}
			members = append(members, mb)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if owners, err = deviceOwners(ctx, tx, tid.UUID()); err != nil {
			return err
		}
		invites, err := tx.Query(ctx, `SELECT id, invited_email, created_at FROM m1_team_invites WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > now() ORDER BY created_at, id`, tid.UUID())
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
			members = append(members, member{ID: "invite:" + id.String(), Email: email, Role: "member", JoinedAt: at.UTC().Format(time.RFC3339Nano), Status: "invited"})
		}
		return invites.Err()
	})
	if err != nil {
		writeTeamErr(w, err, "team lookup failed")
		return
	}
	var tvo any
	from, to, _ := parseWindow("")
	wide := r.WithContext(querychoke.TenantWide(r.Context()))
	if full, rec := m.tvoReport(wide, from, to); rec.code == http.StatusOK && full != nil {
		tvo = pick(full, "tvo", "coverage_band", "cost_basis", "guarantee_grade", "refusal", "trend")
	}
	var sums any
	if byDevice, err := m.deviceTotals(wide.Context(), tid, from, to); err != nil {
		slog.Error("appapi: team totals", "err", err)
	} else {
		sums = foldTotals(members, owners, byDevice, from, to)
	}
	writeJSON(w, map[string]any{"members": members, "you": map[string]string{"role": role}, "max_members": m.maxMembers(), "invite_link": nil, "shared_memory": shared, "tvo": tvo, "totals": sums, "fleet_status": nil})
}

// totals is one person's (or the team's) aggregate over the window; never a session or a device.
type totals struct {
	Sessions      int64 `json:"sessions"`
	TasksVerified int64 `json:"tasks_verified"`
	Tokens        int64 `json:"tokens"`
	TokensSaved   int64 `json:"tokens_saved"`
}

func (t *totals) add(o totals) {
	t.Sessions += o.Sessions
	t.TasksVerified += o.TasksVerified
	t.Tokens += o.Tokens
	t.TokensSaved += o.TokensSaved
}

// deviceOwners maps each device of this tenant to the subject of its latest enrollment (revoked kept: a removed laptop's history stays its owner's).
func deviceOwners(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (device_id) device_id::text, oidc_subject FROM m1_device_enrollments
		WHERE tenant_id = $1 AND device_id IS NOT NULL AND oidc_subject IS NOT NULL AND status IN ('approved', 'revoked')
		ORDER BY device_id, row_seq DESC`, tenant)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for rows.Next() {
		var device, subject string
		if err := rows.Scan(&device, &subject); err != nil {
			return nil, err
		}
		out[device] = subject
	}
	return out, rows.Err()
}

// deviceTotals runs team_device_totals.v2 tenant-wide (ctx must carry TenantWide: the viewer filter refuses a deviceless template).
func (m *Module) deviceTotals(ctx context.Context, tid querychoke.TenantID, from, to time.Time) (map[string]totals, error) {
	tpl, err := m.deps.Registry.Lookup("team_device_totals")
	if err != nil {
		return nil, err
	}
	q, err := querychoke.Build(tid, tpl, querychoke.Params{"from": from, "to": to})
	if err != nil {
		return nil, err
	}
	rows, err := m.deps.Runner.Run(ctx, q)
	if err != nil {
		return nil, err
	}
	out := map[string]totals{}
	for _, row := range rows.Rows {
		out[asStr(row["device_id"])] = totals{
			Sessions: asI64(row["sessions"]), TasksVerified: asI64(row["tasks_verified"]),
			Tokens: asI64(row["tokens"]), TokensSaved: asI64(row["tokens_saved"]),
		}
	}
	return out, nil
}

// foldTotals credits each device to its member's row; devices of no listed member (a leaver, an unenrolled one) land in unattributed, and team is the sum of all.
func foldTotals(members []member, owners map[string]string, byDevice map[string]totals, from, to time.Time) map[string]any {
	idx := map[string]int{}
	for i := range members {
		if members[i].Status == "active" {
			members[i].Totals = &totals{}
			idx["omium:"+members[i].ID] = i
		}
	}
	var team, unattributed totals
	for device, t := range byDevice {
		team.add(t)
		if i, ok := idx[owners[device]]; ok {
			members[i].Totals.add(t)
		} else {
			unattributed.add(t)
		}
	}
	return map[string]any{"window": windowJSON(from, to), "team": team, "unattributed": unattributed}
}

// PUT /api/v1/team {shared_memory}

func (m *Module) handleTeamUpdate(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
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
		if err := ownerOfTeam(r.Context(), tx, tid.UUID(), claims); err != nil {
			return err
		}
		tag, err := tx.Exec(r.Context(), `UPDATE m1_tenants SET shared_memory = $2 WHERE id = $1`, tid.UUID(), *wire.SharedMemory)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "team update failed")
		return
	}
	if n != 1 {
		writeErr(w, http.StatusForbidden, "M1E-1001", "tenant not visible")
		return
	}
	writeJSON(w, map[string]any{"shared_memory": *wire.SharedMemory})
}

// POST /api/v1/team/invites {email?}: owner only, capped, mints a 7-day invite (m1_081, hash stored) and answers the link once; with an email and a mailer the link is also emailed after commit, and `sent` says whether it was.

func (m *Module) handleTeamInvite(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
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
	if wire.Email = strings.TrimSpace(wire.Email); wire.Email != "" {
		addr, err := inviteAddress(wire.Email)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "M1E-2001", "email: want exactly one address")
			return
		}
		wire.Email = addr
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
	ctx := r.Context()
	var expires time.Time
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var owner *string
		if err := tx.QueryRow(ctx, `SELECT owner_subject FROM m1_tenants WHERE id = $1 FOR UPDATE`, tid.UUID()).Scan(&owner); err != nil {
			return err
		}
		me, err := subjectOf(ctx, tx, claims)
		if err != nil {
			return err
		}
		if owner == nil || me != *owner {
			return errNotOwner
		}
		if err := upsertOwner(ctx, tx, tid.UUID(), me, emailOf(claims)); err != nil {
			return err
		}
		if err := m.roomFor(ctx, tx, tid.UUID(), 1); err != nil {
			return err
		}
		var today int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM m1_team_invites WHERE tenant_id = $1 AND created_at > now() - interval '1 day'`, tid.UUID()).Scan(&today); err != nil {
			return err
		}
		if today >= m.invitesPerDay() {
			return errInviteRate
		}
		return tx.QueryRow(ctx, `INSERT INTO m1_team_invites (tenant_id, token_hash, invited_email, invited_by, expires_at) VALUES ($1, $2, $3, $4, now() + interval '7 days') RETURNING expires_at`,
			tid.UUID(), hash[:], email, me).Scan(&expires)
	})
	if err != nil {
		writeTeamErr(w, err, "invite not recorded")
		return
	}
	sent := false
	if email != nil && m.deps.Mail != nil {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := m.deps.Mail(sctx, inviteMail(*email, claims.Email, inviteBase+token, expires, m.deps.EmailPostal))
		cancel()
		if err != nil {
			slog.Error("appapi: invite email not sent; the invite stands", "err", err)
		}
		sent = err == nil
	}
	writeJSON(w, map[string]any{
		"sent": sent, "invite_link": inviteBase + token, "invited_email": email,
		"status": "invited", "expires_at": expires.UTC().Format(time.RFC3339Nano),
	})
}

// inviteAddress is the one bare address an invite may name, lowercased: a display name, a list or a group is refused, so the mailer is handed exactly one recipient.
func inviteAddress(raw string) (string, error) {
	a, err := netmail.ParseAddress(raw)
	if err != nil || a.Name != "" || len(a.Address) > 254 || a.Address != raw {
		return "", errors.New("not one bare address")
	}
	return strings.ToLower(a.Address), nil
}

// invitesPerDay caps invites minted per tenant per rolling 24 h, cancelled ones included (cancel frees the seat, not the quota); the ledger is m1_team_invites itself, so a restart forgets nothing.
func (m *Module) invitesPerDay() int { return 2 * m.maxMembers() }

// inviteMail is the invite's text and HTML; the link carries the token in its fragment, so a mail client that follows it never sends the token to a server.
func inviteMail(to, from, link string, expires time.Time, postal string) mail.Message {
	who := strings.TrimSpace(from)
	if who == "" {
		who = "A teammate"
	}
	day := expires.UTC().Format("2 January 2006")
	text := who + " invited you to their team on Mark 1.\n\nOpen Mark 1, choose \"Have a team invite?\" and paste this link:\n" + link +
		"\n\nOnly " + to + " can use it. It works until " + day + ".\nNo Mark 1 yet? Get it at https://mark.omium.ai\n"
	e := html.EscapeString
	body := `<p>` + e(who) + ` invited you to their team on Mark 1.</p><p>Open Mark 1, choose <b>Have a team invite?</b> and paste this link:</p><p><a href="` + e(link) + `">` + e(link) + `</a></p><p>Only ` + e(to) + ` can use it. It works until ` + e(day) + `.<br>No Mark 1 yet? Get it at <a href="https://mark.omium.ai">mark.omium.ai</a>.</p>`
	if postal != "" {
		text += "\n" + postal + "\n"
		body += `<p style="color:#888;font-size:12px">` + e(postal) + `</p>`
	}
	return mail.Message{To: to, Subject: who + " invited you to a Mark 1 team", Text: text, HTML: body}
}

// DELETE /api/v1/team/invites/{id}: owner only, user token; a live invite stops working (expires_at = now()), which also frees its seat.

func (m *Module) handleTeamCancelInvite(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	id, err := uuid.Parse(strings.TrimPrefix(r.PathValue("id"), "invite:"))
	if err != nil {
		writeTeamErr(w, errInviteInvalid, "")
		return
	}
	ctx := r.Context()
	err = m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var owner *string
		if err := tx.QueryRow(ctx, `SELECT owner_subject FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&owner); err != nil {
			return err
		}
		if owner == nil || teams.Subject(claims.Subject) != *owner {
			return errNotOwner
		}
		tag, err := tx.Exec(ctx, `UPDATE m1_team_invites SET expires_at = now() WHERE id = $1 AND tenant_id = $2 AND accepted_at IS NULL AND expires_at > now()`, id, tid.UUID())
		if err == nil && tag.RowsAffected() == 0 {
			return errInviteInvalid
		}
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "invite not cancelled")
		return
	}
	writeJSON(w, map[string]any{"id": "invite:" + id.String(), "status": "cancelled"})
}

// inviteToken takes the raw token or the whole link: what follows '#' (the join link) or the last '/' (the pre-teams link).
func inviteToken(raw string) string {
	raw = strings.TrimSpace(raw)
	return raw[strings.LastIndexAny(raw, "#/")+1:]
}

// POST /api/v1/team/invites/accept {token}: the trust boundary. The hash finds the invite across tenants (m1_090's definer lookup answers id and tenant, nothing else); everything after runs under the team's GUC with the tenant row locked for the cap.

func (m *Module) handleTeamAccept(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	var wire struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil || inviteToken(wire.Token) == "" {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "accept body: want {token} and nothing else")
		return
	}
	hash := sha256.Sum256([]byte(inviteToken(wire.Token)))
	ctx := r.Context()
	var inviteID, team uuid.UUID
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var ownsTeam bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM m1_tenants t JOIN m1_team_members m ON m.tenant_id = t.id
			 WHERE t.id = $1 AND t.owner_subject = $2 AND m.role = 'member' AND m.left_at IS NULL)`, tid.UUID(), teams.Subject(claims.Subject)).Scan(&ownsTeam); err != nil {
			return err
		}
		if ownsTeam {
			return errOwnerOfTeam
		}
		err := tx.QueryRow(ctx, `SELECT invite_id, invite_tenant FROM m1_team_invite_lookup($1)`, hash[:]).Scan(&inviteID, &team)
		if errors.Is(err, pgx.ErrNoRows) {
			return errInviteInvalid
		}
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "invite lookup failed")
		return
	}
	teamTID, err := querychoke.FromClaims(auth.Claims{TenantID: team})
	if err != nil {
		writeTeamErr(w, errInviteInvalid, "")
		return
	}
	me := teams.Subject(claims.Subject)
	err = m.deps.PG.WithTenant(ctx, teamTID, func(tx pgx.Tx) error {
		var owner *string
		var active, live bool
		var stored []byte
		var invited *string
		err := tx.QueryRow(ctx, `SELECT owner_subject, status = 'active' FROM m1_tenants WHERE id = $1 FOR UPDATE`, team).Scan(&owner, &active)
		if err == nil {
			err = tx.QueryRow(ctx, `SELECT token_hash, invited_email, accepted_at IS NULL AND expires_at > now() FROM m1_team_invites WHERE id = $1 FOR UPDATE`, inviteID).Scan(&stored, &invited, &live)
		}
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!active || !live || subtle.ConstantTimeCompare(stored, hash[:]) != 1)) {
			return errInviteInvalid
		}
		if err != nil {
			return err
		}
		if owner != nil && *owner == me {
			return errOwnTeam
		}
		if owner != nil {
			var away *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT m1_team_effective_tenant($1)`, *owner).Scan(&away); err != nil {
				return err
			}
			if away != nil && *away != team {
				return errInviteInvalid // the owner has joined another team: this one is not being run
			}
		}
		if invited != nil && !strings.EqualFold(strings.TrimSpace(*invited), strings.TrimSpace(claims.Email)) {
			return errEmailMismatch
		}
		if err := m.roomFor(ctx, tx, team, 0); err != nil {
			return err
		}
		var joined bool
		err = tx.QueryRow(ctx, `
			INSERT INTO m1_team_members (tenant_id, subject, email, role) VALUES ($1, $2, $3, 'member')
			ON CONFLICT (tenant_id, subject) DO UPDATE SET left_at = NULL, joined_at = now(), email = EXCLUDED.email
			 WHERE m1_team_members.left_at IS NOT NULL AND m1_team_members.role = 'member'
			RETURNING true`, team, me, emailOf(claims)).Scan(&joined)
		if errors.Is(err, pgx.ErrNoRows) || isUniqueViolation(err) {
			return errAlreadyInTeam
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE m1_team_invites SET accepted_at = now(), accepted_by = $2 WHERE id = $1`, inviteID, me)
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "invite not accepted")
		return
	}
	teams.Forget(me)
	// the caller's own team is not being run while they are away: its unused invites stop working
	if err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE m1_team_invites SET expires_at = now() WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > now()
			AND (SELECT owner_subject FROM m1_tenants WHERE id = $1) = $2`, tid.UUID(), me)
		return err
	}); err != nil {
		slog.Error("appapi: expire invites after accept", "err", err)
	}
	writeJSON(w, map[string]any{"tenant_id": team.String(), "role": "member"})
}

// POST /api/v1/team/leave: a member's row closes; the answer is the token's own tenant, which the app re-enrolls into.

func (m *Module) handleTeamLeave(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	ctx := r.Context()
	me := teams.Subject(claims.Subject)
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var owner *string
		if err := tx.QueryRow(ctx, `SELECT owner_subject FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&owner); err != nil {
			return err
		}
		if owner != nil && *owner == me {
			return errOwnerCannotLeave
		}
		tag, err := tx.Exec(ctx, `UPDATE m1_team_members SET left_at = now() WHERE tenant_id = $1 AND subject = $2 AND role = 'member' AND left_at IS NULL`, tid.UUID(), me)
		if err == nil && tag.RowsAffected() == 0 {
			return errNotMember
		}
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "leave not recorded")
		return
	}
	teams.Forget(me)
	writeJSON(w, map[string]any{"tenant_id": claims.TokenTenantID.String()})
}

// DELETE /api/v1/team/members/{id}: owner only; the member's row closes, then enroll's revocation path revokes their devices in this tenant. A failed revocation answers 503 and the retry is idempotent.

func (m *Module) handleTeamRemove(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	if claims.Subject == "" {
		writeTeamErr(w, errUserToken, "")
		return
	}
	if m.deps.RevokeSubject == nil {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "device revocation not wired; nobody was removed")
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	target := teams.Subject(id)
	var me string
	err := m.deps.PG.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var owner *string
		if err := tx.QueryRow(ctx, `SELECT owner_subject FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&owner); err != nil {
			return err
		}
		var err error
		if me, err = subjectOf(ctx, tx, claims); err != nil {
			return err
		}
		if owner == nil || me != *owner {
			return errNotOwner
		}
		if target == me {
			return errOwnerCannotLeave
		}
		var removed bool
		err = tx.QueryRow(ctx, `UPDATE m1_team_members SET left_at = COALESCE(left_at, now()) WHERE tenant_id = $1 AND subject = $2 AND role = 'member' RETURNING true`, tid.UUID(), target).Scan(&removed)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMemberNotFound
		}
		return err
	})
	if err != nil {
		writeTeamErr(w, err, "member not removed")
		return
	}
	teams.Forget(target)
	n, err := m.deps.RevokeSubject(ctx, tid.UUID(), target, me)
	if err != nil {
		slog.Error("appapi: team member device revocation", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "member removed; device revocation failed, retry")
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": "removed", "revoked_devices": n})
}
