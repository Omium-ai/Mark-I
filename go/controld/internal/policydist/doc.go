// Package policydist will own bundle distribution: the monotonic-seq catalog,
// ETag poll + SSE push, the ACK ledger, the canary widen/halt controller, the
// transparency log, and KMS section-split signing (05 §4).
//
// C4 STUB. Built in the control-plane workstream WS-6 (14 §2:
// `controld.{enroll,policydist,querychoke}`), gated on ADR-0004 (the key
// ceremony — bundle-key split is boot refusal R5's premise). Nothing in C4
// serves or signs a bundle; R5 is asserted when the first signing key exists.
package policydist
