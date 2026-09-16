// Package memory serves the two edge-facing memory routes (06 §9.4-9.5, FR-REMEMBER-004): device-token verified, tenant stamped from claims, proxied to mark1-intel over the ADR-0010 §2.2 service seam.
package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

const (
	intelArtifacts = "/v1/memory/artifacts"
	intelMatch     = "/v1/memory/match"
	// maxMatchBody: intel caps error at 4096 chars; JSON-escaped that is under 32 KiB.
	maxMatchBody = 64 << 10
	// maxIntelBody is the edge cache's own read ceiling (mark1d/memory bodyLimit).
	maxIntelBody = 8 << 20
)

// matchDeadline bounds the intel hop to the edge's fuzz budget (mark1d/memory matchBudget, 06 §9.5 D29).
var matchDeadline = 1500 * time.Millisecond

type Deps struct {
	Verifier auth.Verifier
	ObsCfg   obs.Config
	// IntelBaseURL and IntelServiceToken are the ADR-0010 §2.2 seam; an empty URL answers 503, never a guess.
	IntelBaseURL      string
	IntelServiceToken string
}

type Module struct {
	deps Deps
	http *http.Client
}

func New(d Deps) *Module {
	return &Module{deps: d, http: &http.Client{Timeout: 10 * time.Second}}
}

func (m *Module) Name() string { return "memory" }

// Ready: nothing to probe. Intel down is a 502 on two routes and the edge fails static on last-known-good; it must never take ingest off the LB.
func (m *Module) Ready(context.Context) error { return nil }

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// ponytail: unmetered; 05 §8.2 has no memory row yet, add a per-device bucket when one lands.
	chain := server.Chain(m.deps.Verifier, m.deps.ObsCfg, nil)
	mux.Handle("GET /api/v1/memory/artifacts", chain(http.HandlerFunc(m.handleArtifacts)))
	mux.Handle("POST /api/v1/memory/match", chain(http.HandlerFunc(m.handleMatch)))
}

func (m *Module) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	body, ok := m.proxy(w, r, http.MethodGet, intelArtifacts+"?tenant_id="+tenant.String(), nil)
	if !ok {
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// matchWire is the edge's body (mark1d/memory fuzz). Unknown fields, tenant_id included, are refused: the tenant slot exists only on the internal wire.
type matchWire struct {
	Error string `json:"error"`
	Limit int    `json:"limit,omitempty"`
}

func (m *Module) handleMatch(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	var wire matchWire
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMatchBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		writeError(w, http.StatusBadRequest, "M1E-2001", "match body missing, malformed, or too large")
		return
	}
	upstream, err := json.Marshal(struct {
		TenantID string `json:"tenant_id"`
		matchWire
	}{tenant.String(), wire})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "M1E-9500", "match request encoding failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), matchDeadline)
	defer cancel()
	body, ok := m.proxy(w, r.WithContext(ctx), http.MethodPost, intelMatch, upstream)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// proxy is the one internal hop: service bearer on, edge version forwarded, 2xx passed through byte-for-byte, intel's own 4xx a 400, everything else a 502 with no upstream bytes.
func (m *Module) proxy(w http.ResponseWriter, r *http.Request, method, path string, body []byte) ([]byte, bool) {
	if m.deps.IntelBaseURL == "" {
		writeError(w, http.StatusServiceUnavailable, "M1E-9500", "memory service not configured")
		return nil, false
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), method, strings.TrimRight(m.deps.IntelBaseURL, "/")+path, rd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "M1E-9500", "memory service request failed")
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+m.deps.IntelServiceToken)
	if v := r.Header.Get("X-Mark1-Edge-Version"); v != "" && len(v) <= 128 {
		req.Header.Set("X-Mark1-Edge-Version", v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.http.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "M1E-9500", "memory service unavailable")
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		writeError(w, http.StatusBadRequest, "M1E-2001", "memory service refused the request")
		return nil, false
	default:
		writeError(w, http.StatusBadGateway, "M1E-9500", "memory service failed")
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxIntelBody+1))
	if err != nil || len(out) > maxIntelBody {
		writeError(w, http.StatusBadGateway, "M1E-9500", "memory service response unreadable or too large")
		return nil, false
	}
	return out, true
}

func matchesETag(header, etag string) bool {
	for _, c := range strings.Split(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(c), "W/") == etag {
			return true
		}
	}
	return false
}

func tenantFrom(w http.ResponseWriter, r *http.Request) (querychoke.TenantID, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "M1E-9500", "auth middleware missing")
		return querychoke.TenantID{}, false
	}
	tid, err := querychoke.FromClaims(claims)
	if err != nil {
		writeError(w, http.StatusForbidden, "M1E-1001", "token carries no tenant")
		return querychoke.TenantID{}, false
	}
	return tid, true
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
