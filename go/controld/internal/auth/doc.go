// Package auth is the shared token-verification seam (05 §0.1 point 2: one
// binary, one verification middleware, one revocation posture).
//
// The TOKEN is the only identity source in controld: tenant_id and device_id
// come from verified claims, never from a path, body, or envelope value
// (05 §2.1 stage 3; 08 §2.1). Everything downstream — the S3 landing key, the
// Postgres tenant GUC, the ClickHouse rows — is stamped from what Verify
// returns.
//
// C4 SCOPE. This package ships the Verifier interface plus an HMAC-signed dev
// implementation. The production token scheme — Ed25519 server-key tokens
// (stateless verification, 05 §3.3), the OIDC device-code enrollment that
// mints them (05 §3.1–3.2), and the ≤60 s revocation cache with fail-closed
// staleness (05 §3.4) — arrives with `enroll` in its own delivery row
// (WS-6, 14 §Phase-1 row 1.4). The RevocationChecker seam below is where that
// cache plugs in; the interface, the error taxonomy mapping (M1E-1002 /
// M1E-1003), and the fail-closed posture are already fixed here so the swap
// changes an implementation, not a contract.
package auth
