package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

// Chain is the 05 §0.3 middleware order: auth → tenancy stamp → obs, in that
// order. Rate limiting is the fourth link but is category-shaped (05 §2.4
// buckets debit per-event counts, which only exist after protobuf decode), so
// the module's pipeline owns it; the coarse pre-decompression shed lives
// there too (§2.4: 503 before stage-4 decompression spend).
//
// onAuthFailure lets the owning module count failures in ITS metric namespace
// (05 §2.1 stage 2: controld_ingest_auth_failures_total{reason}) without the
// substrate importing a module — the substrate stays metric-agnostic.
func Chain(v auth.Verifier, obsCfg obs.Config, onAuthFailure func(reason string)) func(http.Handler) http.Handler {
	obsMW := obsCfg.HTTPMiddleware(nil)
	return func(next http.Handler) http.Handler {
		// obs wraps the handler; auth wraps obs? No — the doc's order is
		// auth → stamp → obs → handler: an unauthenticated request is
		// refused before it costs a metrics observation on the route.
		metered := obsMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || bearer == "" {
				if onAuthFailure != nil {
					onAuthFailure("missing")
				}
				writeAuthError(w, http.StatusUnauthorized, "M1E-1002", "device token missing")
				return
			}
			claims, err := v.Verify(r.Context(), bearer)
			if err != nil {
				// The 08 §9 mapping: revoked is terminal 403 M1E-1003;
				// everything else (bad signature, expired, stale revocation
				// state — fail-closed) is 401 M1E-1002, retryable only
				// after re-auth.
				if errors.Is(err, auth.ErrRevoked) {
					if onAuthFailure != nil {
						onAuthFailure("revoked")
					}
					writeAuthError(w, http.StatusForbidden, "M1E-1003", "device revoked")
					return
				}
				if onAuthFailure != nil {
					onAuthFailure("bad_token")
				}
				writeAuthError(w, http.StatusUnauthorized, "M1E-1002", "device token invalid or expired")
				return
			}
			// The tenancy stamp (05 §2.1 stage 3): claims — never the
			// envelope — travel the request context from here on.
			Stamp(r.Context(), claims.TenantID, claims.DeviceID)
			metered.ServeHTTP(w, r.WithContext(auth.WithClaims(r.Context(), claims)))
		})
	}
}

func writeAuthError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
