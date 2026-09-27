// Package appapi is the desktop app's read surface (mark1-desktop-app-spec §5, §7.2): tenant-token verified like the public memory routes, every ClickHouse read a querychoke template built for the token's tenant, every Postgres read under the tenant GUC, and the honesty fields lifted from GET /reports/tvo rather than recomputed. Response shapes are the JSON Schemas under schema/.
package appapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/mail"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

type Deps struct {
	// Verifier is the principal seam: today the device-token verifier the public memory routes accept; lane B3's user-session verifier replaces it here and nowhere else.
	Verifier auth.Verifier
	ObsCfg   obs.Config
	Registry *querychoke.Registry
	Runner   querychoke.Runner
	// Reports is the querychoke module: GET /reports/tvo is served in-process so band, basis and grade are computed in exactly one place.
	Reports interface{ RegisterRoutes(*http.ServeMux) }
	PG      querychoke.TenantDB
	// Regimes resolves the m1_075 row for /me; nil answers regime null.
	Regimes querychoke.RegimeSource
	// TenantRoot is enroll's HKDF tenant root (04 §2.9): human gold labels digest (session, task) under it; nil refuses labels.
	TenantRoot func(uuid.UUID) ([]byte, error)
	// TeamMaxMembers is TEAM_MAX_MEMBERS (owner + members + live invites); 0 ⇒ 10.
	TeamMaxMembers int
	// RevokeSubject is enroll.Module.RevokeSubjectDevices: DELETE /team/members/{id} revokes the removed member's devices; nil refuses the route.
	RevokeSubject func(ctx context.Context, tenant uuid.UUID, subject, by string) (int, error)
	// Mail sends one transactional email (mail.CustomerIO.Send); nil ⇒ nothing is emailed and invites answer sent:false.
	Mail func(context.Context, mail.Message) (string, error)
	// EmailPostal is EMAIL_POSTAL_ADDRESS, the footer of every email controld sends.
	EmailPostal string
}

type Module struct {
	deps    Deps
	reports *http.ServeMux
	bundles bundleMemo
}

func New(d Deps) *Module {
	m := &Module{deps: d, reports: http.NewServeMux()}
	d.Reports.RegisterRoutes(m.reports)
	return m
}

func (m *Module) Name() string { return "appapi" }

func (m *Module) Ready(ctx context.Context) error {
	if p, ok := m.deps.Runner.(interface{ Ready(context.Context) error }); ok {
		return p.Ready(ctx)
	}
	return nil
}

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	verified := server.Chain(m.deps.Verifier, m.deps.ObsCfg, nil)
	chain := func(h http.Handler) http.Handler { return verified(m.participant(h)) }
	mux.Handle("GET /api/v1/sessions", chain(http.HandlerFunc(m.handleSessions)))
	mux.Handle("GET /api/v1/sessions/{id}", chain(http.HandlerFunc(m.handleSessionDetail)))
	mux.Handle("GET /api/v1/moments", chain(http.HandlerFunc(m.handleMoments)))
	mux.Handle("GET /api/v1/verify/certificates", chain(http.HandlerFunc(m.handleCertificates)))
	mux.Handle("GET /api/v1/verify/labels", chain(http.HandlerFunc(m.handleLabels)))
	mux.Handle("POST /api/v1/verify/labels", chain(http.HandlerFunc(m.handleLabel)))
	mux.Handle("GET /api/v1/verify/cloud-judge", chain(m.consentGet(cloudJudgeConsent)))
	mux.Handle("PUT /api/v1/verify/cloud-judge", chain(m.consentPut(cloudJudgeConsent)))
	mux.Handle("GET /api/v1/verify/cloud-rm", chain(m.consentGet(cloudRMConsent)))
	mux.Handle("PUT /api/v1/verify/cloud-rm", chain(m.consentPut(cloudRMConsent)))
	mux.Handle("GET /api/v1/memory/extract-consent", chain(m.consentGet(memoryExtractConsent)))
	mux.Handle("PUT /api/v1/memory/extract-consent", chain(m.consentPut(memoryExtractConsent)))
	mux.Handle("GET /api/v1/route/decisions", chain(http.HandlerFunc(m.handleRouteDecisions)))
	mux.Handle("GET /api/v1/route/bundle", chain(http.HandlerFunc(m.handleRouteBundle)))
	mux.Handle("GET /api/v1/me", chain(http.HandlerFunc(m.handleMe)))
	mux.Handle("GET /api/v1/memory/injections", chain(http.HandlerFunc(m.handleInjections)))
	mux.Handle("GET /api/v1/team", chain(http.HandlerFunc(m.handleTeam)))
	mux.Handle("PUT /api/v1/team", chain(http.HandlerFunc(m.handleTeamUpdate)))
	mux.Handle("POST /api/v1/team/invites", chain(http.HandlerFunc(m.handleTeamInvite)))
	mux.Handle("POST /api/v1/team/invites/accept", chain(http.HandlerFunc(m.handleTeamAccept)))
	mux.Handle("POST /api/v1/team/leave", chain(http.HandlerFunc(m.handleTeamLeave)))
	mux.Handle("DELETE /api/v1/team/members/{id}", chain(http.HandlerFunc(m.handleTeamRemove)))
	mux.Handle("DELETE /api/v1/team/invites/{id}", chain(http.HandlerFunc(m.handleTeamCancelInvite)))
	mux.Handle("GET /api/v1/me/notifications", chain(http.HandlerFunc(m.handleNotifications)))
	mux.Handle("PUT /api/v1/me/notifications", chain(http.HandlerFunc(m.handleNotificationsUpdate)))
	// public: the token in the path is the credential (a digest's List-Unsubscribe link); no bearer, no auth chain
	public := m.deps.ObsCfg.HTTPMiddleware(nil) // labelled by pattern, never the token
	mux.Handle("GET /api/v1/unsubscribe/{token}", public(http.HandlerFunc(m.handleUnsubscribePage)))
	mux.Handle("POST /api/v1/unsubscribe/{token}", public(http.HandlerFunc(m.handleUnsubscribe)))
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func principal(w http.ResponseWriter, r *http.Request) (querychoke.TenantID, auth.Claims, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "auth middleware missing")
		return querychoke.TenantID{}, auth.Claims{}, false
	}
	tid, err := querychoke.FromClaims(claims)
	if err != nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "token carries no tenant")
		return querychoke.TenantID{}, auth.Claims{}, false
	}
	return tid, claims, true
}

var windowRe = regexp.MustCompile(`^([0-9]{1,3})d$`)

// parseWindow is querychoke's ?window=<n>d: a closed [from, to] day range ending today (UTC), 1..365 days.
func parseWindow(raw string) (from, to time.Time, err error) {
	if raw == "" {
		raw = "30d"
	}
	match := windowRe.FindStringSubmatch(raw)
	if match == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("window %q: want <days>d", raw)
	}
	n, _ := strconv.Atoi(match[1])
	if n < 1 || n > 365 {
		return time.Time{}, time.Time{}, fmt.Errorf("window %q outside 1d..365d", raw)
	}
	to = time.Now().UTC().Truncate(24 * time.Hour)
	return to.AddDate(0, 0, -(n - 1)), to, nil
}

func windowJSON(from, to time.Time) map[string]string {
	return map[string]string{"from": from.Format(time.DateOnly), "to": to.Format(time.DateOnly)}
}

// query builds and runs a registry template for the token's tenant; every ClickHouse read in this package goes through here.
func (m *Module) query(w http.ResponseWriter, r *http.Request, tid querychoke.TenantID, name string, p querychoke.Params) (*querychoke.Rows, bool) {
	tpl, err := m.deps.Registry.Lookup(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return nil, false
	}
	q, err := querychoke.Build(tid, tpl, p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return nil, false
	}
	rows, err := m.deps.Runner.Run(r.Context(), q)
	if err != nil {
		if errors.Is(err, querychoke.ErrBusy) {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "query concurrency limit; retry")
			return nil, false
		}
		slog.Error("appapi: query failed", "template", name, "err", err)
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "query execution failed")
		return nil, false
	}
	return rows, true
}

// honesty lifts coverage band, cost basis and guarantee grade from the in-process GET /reports/tvo for the same window (08 §3.3); a refused report passes its status and code through untouched.
func (m *Module) honesty(w http.ResponseWriter, r *http.Request, from, to time.Time) (map[string]any, bool) {
	full, rec := m.tvoReport(r, from, to)
	if rec.code != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.code)
		_, _ = w.Write(rec.body.Bytes())
		return nil, false
	}
	if full == nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "report unreadable")
		return nil, false
	}
	return pick(full, "coverage_band", "cost_basis", "guarantee_grade", "task_seg_version", "price_table_version", "refusal"), true
}

// tvoReport runs the in-process GET /reports/tvo for [from, to] (08 §3.3): the recorder carries status and body; the map decodes only on 200.
func (m *Module) tvoReport(r *http.Request, from, to time.Time) (map[string]any, *memWriter) {
	days := int(to.Sub(from).Hours()/24) + 1
	req := r.Clone(r.Context())
	req.Method = http.MethodGet
	req.URL = &url.URL{Path: "/api/v1/reports/tvo", RawQuery: "window=" + strconv.Itoa(days) + "d"}
	req.RequestURI = ""
	rec := &memWriter{header: http.Header{}, code: http.StatusOK}
	m.reports.ServeHTTP(rec, req)
	if rec.code != http.StatusOK {
		return nil, rec
	}
	var full map[string]any
	if err := json.Unmarshal(rec.body.Bytes(), &full); err != nil {
		return nil, rec
	}
	return full, rec
}

func pick(full map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := full[k]; ok {
			out[k] = v
		}
	}
	return out
}

type memWriter struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (m *memWriter) Header() http.Header         { return m.header }
func (m *memWriter) Write(b []byte) (int, error) { return m.body.Write(b) }
func (m *memWriter) WriteHeader(code int)        { m.code = code }

func parseLimit(raw string, def, max int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("limit %q: want 1..%d", raw, max)
	}
	return n, nil
}

// GET /api/v1/sessions?window=&agent=&project=&cursor=&limit=

func (m *Module) handleSessions(w http.ResponseWriter, r *http.Request) {
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
	limit, err := parseLimit(qs.Get("limit"), 50, 500)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	var cursor uuid.UUID
	if c := qs.Get("cursor"); c != "" {
		if cursor, err = uuid.Parse(c); err != nil {
			writeErr(w, http.StatusBadRequest, "M1E-2001", "cursor: not a session id")
			return
		}
	}
	rows, ok := m.query(w, r, tid, "app_sessions", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	agent, project := qs.Get("agent"), qs.Get("project")
	page := []sessionRow{}
	var next *string
	for _, row := range rows.Rows {
		s := sessionFromRow(row)
		if (agent != "" && s.Agent != agent) || (project != "" && s.Project != project) {
			continue
		}
		if cursor != uuid.Nil && s.SessionID >= cursor.String() {
			continue
		}
		if len(page) == limit {
			id := page[limit-1].SessionID
			next = &id
			break
		}
		page = append(page, s)
	}
	h, ok := m.honesty(w, r, from, to)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"window": windowJSON(from, to), "sessions": page, "next_cursor": next, "honesty": h})
}

// GET /api/v1/sessions/{id}?window=

func (m *Module) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	sid, err := uuid.Parse(r.PathValue("id"))
	if err != nil || sid == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "session id: not a UUID")
		return
	}
	from, to, err := detailWindow(sid, r.URL.Query().Get("window"), time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	sessions, ok := m.query(w, r, tid, "app_sessions", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	var session *sessionRow
	for _, row := range sessions.Rows {
		if s := sessionFromRow(row); s.SessionID == sid.String() {
			session = &s
			break
		}
	}
	if session == nil {
		writeErr(w, http.StatusNotFound, "M1E-2009", "session not found in window")
		return
	}
	events, ok := m.query(w, r, tid, "app_session_events", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	tasks := foldTasks(events.Rows, sid)
	h, ok := m.honesty(w, r, from, to)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"window": windowJSON(from, to), "session": session, "tasks": tasks,
		"checkpoint_seq": session.CheckpointSeq, "honesty": h,
	})
}

// detailWindow scans the explicit ?window= when given, else the day around a UUIDv7 session id (ADR-0001 ±1 day), else 30d.
func detailWindow(sid uuid.UUID, raw string, now time.Time) (time.Time, time.Time, error) {
	if raw != "" || sid.Version() != 7 {
		return parseWindow(raw)
	}
	sec, nsec := sid.Time().UnixTime()
	day := time.Unix(sec, nsec).UTC().Truncate(24 * time.Hour)
	to := day.AddDate(0, 0, 1)
	if today := now.Truncate(24 * time.Hour); to.After(today) {
		to = today
	}
	return day.AddDate(0, 0, -1), to, nil
}

// GET /api/v1/moments?since=&limit=

func (m *Module) handleMoments(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	qs := r.URL.Query()
	since := time.Now().UTC().Add(-24 * time.Hour)
	if s := qs.Get("since"); s != "" {
		var err error
		if since, err = time.Parse(time.RFC3339, s); err != nil {
			writeErr(w, http.StatusBadRequest, "M1E-2001", "since: want RFC 3339")
			return
		}
		since = since.UTC()
	}
	limit, err := parseLimit(qs.Get("limit"), 100, 1000)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	to := time.Now().UTC().Truncate(24 * time.Hour)
	from := since.Truncate(24 * time.Hour)
	if from.After(to) {
		from = to
	}
	if to.Sub(from) > 365*24*time.Hour {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "since: more than 365 days ago")
		return
	}
	rows, ok := m.query(w, r, tid, "app_moments", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	moments := []moment{}
	var newest *time.Time
	for _, row := range rows.Rows {
		mo, keep := momentFromRow(row, since)
		if !keep {
			continue
		}
		if newest == nil {
			at := mo.At
			newest = &at
		}
		if len(moments) == limit {
			break
		}
		moments = append(moments, mo)
	}
	h, ok := m.honesty(w, r, from, to)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"since": since.Format(time.RFC3339Nano), "moments": moments, "next_since": newest, "honesty": h})
}

// GET /api/v1/route/decisions?window=

func (m *Module) handleRouteDecisions(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	from, to, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.query(w, r, tid, "ope_route_decisions", querychoke.Params{"from": from, "to": to})
	if !ok {
		return
	}
	decisions := []routeDecision{}
	for _, row := range rows.Rows {
		decisions = append(decisions, routeDecisionFromRow(row))
	}
	h, ok := m.honesty(w, r, from, to)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"window": windowJSON(from, to), "decisions": decisions, "honesty": h})
}
