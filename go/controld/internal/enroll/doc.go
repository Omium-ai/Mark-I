// Package enroll will own device identity: the OIDC device-code state machine
// against the tenant's own IdP, ≤24 h Ed25519 device tokens, proof-of-
// possession refresh, revocation with the ≤60 s fail-closed cache, and the
// enrollment credential fingerprints the proxy guard matches (05 §3).
//
// C4 STUB. Built in the control-plane workstream WS-6 (14 §2; plan row 1.4:
// "controld.enroll + device identity"). Until then the auth package's dev
// HMAC verifier is the token seam (internal/auth/doc.go), and its Verifier /
// RevocationChecker interfaces are the contract this module implements.
package enroll
