// Package policydist owns bundle distribution (05 §4): the monotonic-seq
// catalog, ETag poll + SSE push, the ACK ledger, the canary widen/halt
// arithmetic, the transparency log, and section-split signing.
//
// THE ONE PROPERTY. The sequence is monotonic per (tenant, channel) and the
// chain is append-only. A rollback is a FORWARD publication under a higher
// seq — the edge's anti-rollback check is used, never fought — so there is no
// unpublish verb in this package because there is none in the system. The
// enforcement is the database's: m1_042's trigger admits exactly head_seq + 1
// with a matching prev_hash under a row lock it takes itself, and three
// append-only layers (row trigger, statement trigger, REVOKE) stand between a
// published body and any edit. Go computes the same values; if the two ever
// disagree the INSERT fails, which is the safe direction.
//
// FILE MAP
//
//	bundle.go   07's CDDL as Go types + the publish-side reference decoder
//	sign.go     the six section keys; one key per section, no key in two
//	tlog.go     RFC 6962 / SHA-256 Merkle log + signed heads (05 §4.4)
//	store.go    the one-transaction publication, catalog serving, ACKs, coverage
//	sse.go      the bounded hint fan-out
//	canary.go   pure widen/halt/hold arithmetic over an ACK coverage snapshot
//	module.go   08 §3.2's three routes
//	limits.go   05 §8.2's per-device buckets for those routes
//
// KEY CUSTODY. Boot refusal R5 (KMS DescribeKey on the bundle key) is NOT
// asserted here: DeriveKeyring builds six distinct Ed25519 keys from one root
// seed via HKDF, which buys the section split (six key ids, a leaked verify
// key cannot sign routes) but not KMS-resident custody. SectionSigner is the
// seam a KMS signer implements with no other change in this package — the same
// deferral receipts.go already records for the chain key.
package policydist
