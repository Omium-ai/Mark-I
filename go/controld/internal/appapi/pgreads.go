package appapi

import (
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/policydist"
)

// GET /api/v1/me

func (m *Module) handleMe(w http.ResponseWriter, r *http.Request) {
	tid, claims, ok := principal(w, r)
	if !ok {
		return
	}
	var name, region, status string
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT name, region, status FROM m1_tenants WHERE id = $1`, tid.UUID()).Scan(&name, &region, &status)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusForbidden, "M1E-1001", "tenant not visible")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "tenant lookup failed")
		return
	}
	var regime any
	if m.deps.Regimes != nil {
		reg, err := m.deps.Regimes.Regime(r.Context(), tid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "M1E-9500", "tenant regime lookup failed")
			return
		}
		if reg != nil {
			var model *string
			if reg.PriceModelID != "" {
				model = &reg.PriceModelID
			}
			regime = map[string]any{"cost_basis": reg.CostBasis, "price_model_id": model}
		}
	}
	user := map[string]any{"id": claims.DeviceID.String(), "kind": "device"}
	if claims.Subject != "" {
		user = map[string]any{"id": claims.Subject, "kind": "user"}
	}
	writeJSON(w, map[string]any{
		"user":   user,
		"tenant": map[string]any{"id": tid.String(), "name": name, "region": region, "status": status},
		"plan":   nil,
		"regime": regime,
		"region": region,
	})
}

// GET /api/v1/verify/certificates

type certificate struct {
	ID           string   `json:"id"`
	Verifier     verifier `json:"verifier"`
	Status       string   `json:"status"`
	RhoPlus      *float64 `json:"rho_plus"`
	RhoMinus     *float64 `json:"rho_minus"`
	NatarajanLCB *float64 `json:"natarajan_lcb"`
	GoldN        *int32   `json:"gold_n"`
	Identifiable bool     `json:"identifiable"`
	IssuedAt     *string  `json:"issued_at"`
	ExpiresAt    *string  `json:"expires_at"`
	ReceiptID    *string  `json:"receipt_id"`
	Active       bool     `json:"active"`
}

type verifier struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Kind        string `json:"kind"`
	Version     int32  `json:"version"`
	DisplayName string `json:"display_name"`
}

func (m *Module) handleCertificates(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	certs := []certificate{}
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT c.id, c.verifier_id, v.verifier_key, v.kind, v.version, v.display_name, c.status::text,
			       c.rho_plus::float8, c.rho_minus::float8, c.natarajan_lcb::float8, c.gold_n, c.identifiable,
			       c.issued_at, c.expires_at, c.receipt_id
			  FROM noise_certificates c
			  JOIN m1_verifiers v ON v.id = c.verifier_id
			 WHERE c.tenant_id = $1
			 ORDER BY c.issued_at DESC NULLS LAST, c.id`, tid.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c certificate
			var id, vid uuid.UUID
			var issued, expires *time.Time
			var receipt *uuid.UUID
			if err := rows.Scan(&id, &vid, &c.Verifier.Key, &c.Verifier.Kind, &c.Verifier.Version, &c.Verifier.DisplayName, &c.Status,
				&c.RhoPlus, &c.RhoMinus, &c.NatarajanLCB, &c.GoldN, &c.Identifiable, &issued, &expires, &receipt); err != nil {
				return err
			}
			c.ID, c.Verifier.ID = id.String(), vid.String()
			c.IssuedAt, c.ExpiresAt = rfc3339(issued), rfc3339(expires)
			if receipt != nil {
				s := receipt.String()
				c.ReceiptID = &s
			}
			// mark1_assert_certified's read-time rule (m1_021): certified AND unexpired.
			c.Active = c.Status == "certified" && expires != nil && expires.After(now)
			certs = append(certs, c)
		}
		return rows.Err()
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "certificate lookup failed")
		return
	}
	writeJSON(w, map[string]any{"certificates": certs})
}

func rfc3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

// GET /api/v1/route/bundle?channel=

type bundleSummary struct {
	Channel           string      `json:"channel"`
	Seq               int64       `json:"seq"`
	IssuedAt          string      `json:"issued_at"`
	PublishedAt       string      `json:"published_at"`
	MaxAgeS           uint64      `json:"max_age_s"`
	SigningKeyID      string      `json:"signing_key_id"`
	Ladders           []ladder    `json:"ladders"`
	Knee              knee        `json:"knee"`
	Epsilon           float64     `json:"epsilon"`
	ExplorationOptIn  bool        `json:"exploration_opt_in"`
	PriceTableVersion *string     `json:"price_table_version"`
	CPVS              []cpvsEntry `json:"cpvs"`
}

type ladder struct {
	LadderID string `json:"ladder_id"`
	Rungs    []rung `json:"rungs"`
}

type rung struct {
	ModelID    string `json:"model_id"`
	KeepPrefix bool   `json:"keep_prefix"`
}

type knee struct {
	CostBasis string    `json:"cost_basis"`
	VDefault  float64   `json:"v_default"`
	Rows      []kneeRow `json:"rows"`
}

type kneeRow struct {
	N    uint64   `json:"n"`
	CN   float64  `json:"c_n"`
	PLCB *float64 `json:"p_lcb"`
}

type cpvsEntry struct {
	TaskClass string  `json:"task_class"`
	ModelID   string  `json:"model_id"`
	PPass     float64 `json:"p_pass"`
	TokensEst uint64  `json:"tokens_est"`
}

// bundleMemo holds one decoded summary per published (tenant, channel, seq): the catalog row is immutable, so the strict reference decode runs once per bundle per process, never per request.
type bundleMemo struct{ m sync.Map }

var channelClass = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// ponytail: pricedBy parses the compiler's knee_note stamp (policy_compiler/jobs.py "; priced by <version>") until bundle_drafts grows a price_table_version column.
var pricedBy = regexp.MustCompile(`; priced by (\S+)$`)

func (m *Module) handleRouteBundle(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := principal(w, r)
	if !ok {
		return
	}
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	if !channelClass.MatchString(channel) {
		writeErr(w, http.StatusNotFound, "M1E-3004", "unknown channel")
		return
	}
	var (
		seq       int64
		body      []byte
		keyID     string
		published time.Time
		note      *string
	)
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		err := tx.QueryRow(r.Context(), `
			SELECT seq, body_cbor, signing_key_id, published_at FROM policy_bundles
			 WHERE tenant_id = $1 AND channel = $2 ORDER BY seq DESC LIMIT 1`, tid.UUID(), channel).
			Scan(&seq, &body, &keyID, &published)
		if err != nil {
			return err
		}
		err = tx.QueryRow(r.Context(), `SELECT knee_note FROM bundle_drafts WHERE tenant_id = $1 AND channel = $2 AND published_seq = $3`,
			tid.UUID(), channel, seq).Scan(&note)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "M1E-3004", "no bundle published on this channel")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "catalog read failed")
		return
	}
	key := tid.String() + "|" + channel + "|" + policydist.ETag(tid, channel, seq)
	cached, hit := m.bundles.m.Load(key)
	if !hit {
		b, err := policydist.Unmarshal(body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "M1E-9500", "catalog row does not decode")
			return
		}
		cached, _ = m.bundles.m.LoadOrStore(key, summarize(b, channel, seq, keyID, published, note))
	}
	writeJSON(w, cached)
}

func summarize(b *policydist.Bundle, channel string, seq int64, keyID string, published time.Time, note *string) *bundleSummary {
	s := &bundleSummary{
		Channel: channel, Seq: seq, IssuedAt: b.IssuedAt.UTC().Format(time.RFC3339Nano),
		PublishedAt: published.UTC().Format(time.RFC3339Nano), MaxAgeS: b.MaxAge, SigningKeyID: keyID,
		Ladders: []ladder{}, CPVS: []cpvsEntry{},
		Knee: knee{CostBasis: b.Sections.Route.Knee.CostBasis, VDefault: b.Sections.Route.Knee.VDefault, Rows: []kneeRow{}},
	}
	for _, l := range b.Sections.Route.Ladders {
		rungs := make([]rung, 0, len(l.Rungs))
		for _, r := range l.Rungs {
			rungs = append(rungs, rung{ModelID: r.ModelID, KeepPrefix: r.KeepPrefix})
		}
		s.Ladders = append(s.Ladders, ladder{LadderID: l.LadderID, Rungs: rungs})
	}
	for _, row := range b.Sections.Route.Knee.Rows {
		s.Knee.Rows = append(s.Knee.Rows, kneeRow{N: row.N, CN: row.CN, PLCB: row.PLCB})
	}
	for _, c := range b.Sections.Route.CPVS {
		s.CPVS = append(s.CPVS, cpvsEntry{TaskClass: c.TaskClass, ModelID: c.ModelID, PPass: c.PPass, TokensEst: c.TokensEst})
	}
	if e := b.Sections.Route.Exploration; e != nil {
		s.Epsilon = e.Epsilon
	}
	if o := b.Sections.Route.ExplorationOptIn; o != nil {
		s.ExplorationOptIn = *o
	}
	if note != nil {
		if m := pricedBy.FindStringSubmatch(*note); m != nil {
			s.PriceTableVersion = &m[1]
		}
	}
	return s
}
