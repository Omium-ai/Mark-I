// Package querychoke will be the only ClickHouse read principal — the
// construction proof of 05 §6: a query without a tenant predicate cannot be
// constructed, because the only executable value comes from a builder whose
// constructor requires a TenantID and whose template registry is closed and
// boot-validated (refusal R4).
//
// C4 SCOPE. This delivery row (13 §11 C4) ships only:
//   - the TenantID newtype (tenantid.go) — needed NOW because pg.TenantDB's
//     tenant-GUC discipline (05 §7.2) takes it, and ingest's stage-3 stamp
//     produces it;
//   - the chconn subpackage — the ONLY ClickHouse client handle in the
//     codebase (05 §0.3), which ingest/chproj borrows for its INSERT path
//     (05 §6: "the one wiring exception, INSERT-shaped, no SELECT surface").
//
// The builder, the closed template registry, the Runner extraction seam, and
// the fuzz/negative suites (05 §6.2–6.5, 12) arrive with the control-plane
// workstream WS-6 (14 §2 row WS-6: `controld.{enroll,policydist,querychoke}`).
package querychoke
