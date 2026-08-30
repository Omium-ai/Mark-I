// Package auth is the shared token-verification seam (05 §0.1 point 2: one
// binary, one verification middleware, one revocation posture).
//
// The TOKEN is the only identity source in controld: tenant_id and device_id
// come from verified claims, never from a path, body, or envelope value
// (05 §2.1 stage 3; 08 §2.1). Everything downstream — the S3 landing key, the
// Postgres tenant GUC, the ClickHouse rows — is stamped from what Verify
// returns.
//
// Two implementations share the Verifier seam:
//   - Ed25519Verifier (token.go) — PRODUCTION, the cmd default: stateless
//     verification of enroll-minted server-signed tokens (05 §3.3), revocation
//     through enroll's ≤60 s fail-closed cache (05 §3.4) via the
//     TenantRevocations seam.
//   - HMACVerifier (verify.go) — the dev seam, reachable only behind an
//     explicit AUTH_DEV_MODE=1 with a loud boot log. Same error taxonomy
//     (M1E-1002 / M1E-1003), same ≤24 h ceiling, same fail-closed posture, so
//     the two seams teach identical contracts.
package auth
