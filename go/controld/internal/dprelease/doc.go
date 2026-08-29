// Package dprelease will own the differential-privacy release path: the
// (k,m)-anonymity gate, intersection-reconstruction, the integer DP
// mechanisms, the ε ledger, and the human review queue (05 §5). It is the
// ONLY path by which anything derived from more than one tenant's data
// becomes visible to anyone.
//
// C4 STUB. Built in the intelligence workstream WS-7 (14 §2:
// `controld.dprelease`), shipping Phase 5. It rides in the binary from day
// one as registered-but-inert (05 §5: retrofitting a legality boundary is how
// legality boundaries get holes); its BYPASSRLS Postgres pool opens against
// the `mark1_federation_worker` role (migrations/m1_060) in its own row.
package dprelease
