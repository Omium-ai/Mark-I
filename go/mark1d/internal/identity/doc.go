// Package identity is mark1d's key custody and origin-signing package
// (04 §2.9): the device Ed25519 key, the canonical receipt bytes it signs,
// and the checkpoint Merkle construction whose root is what gets signed.
//
// It is the Go mirror of the receipt discipline (04 §7.2: "one signing
// discipline product-wide") — vendored from the estate's
// core-services/recovery-orchestrator/app/receipts (canonical.py, keys.py,
// chain.py; copied 2026-08-29) with the mark1 extensions from 07's receipts
// section and migrations/m1_002_receipt_chain.sql: the "mark1-label-v1\0"
// domain prefix, checkpoint_seq + inclusion_path, and the server
// countersignature over the same signing input. The byte contract is frozen
// by conformance/vectors/receipt/ and locked across Rust, Go and Python by
// tools/ci/conformance_crosslang.sh — these files must never drift from the
// vectors, and the vectors never move to accommodate these files.
//
// Key custody: Custody is the seam of 04 §2.9's ladder (macOS Keychain →
// Windows TPM/DPAPI → Linux secret-service/TPM2 → 0600 file). Only the
// floor — FileCustody, the 0600 file under ~/.omium/mark1/ — exists today;
// the keychain/TPM rungs arrive with the enroll flow (they are provisioning
// concerns, and there is no enrollment to provision for yet). No library is
// pinned ahead of that row: one was, and since nothing imported it, it was
// not a pin at all — `go mod tidy` deleted it the first time it ran (D-CF).
// Whichever library serves the rung is chosen when the rung is built.
//
// Whatever the rung, the private key never leaves custody: Sign() is the
// only operation a DeviceKey exposes (04 §2.9, table §8: "key bytes never
// cross a package boundary").
//
// Token refresh, revocation handling (OnRevoked, M1E-1003) and the HMAC /
// X25519 spill key material named by 04 §2.9 belong to the uplink/enroll
// rows and are deliberately absent here.
package identity
