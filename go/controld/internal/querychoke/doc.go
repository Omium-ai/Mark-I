// Package querychoke is the only ClickHouse read principal — the
// construction proof of 05 §6: a query without a tenant predicate cannot be
// constructed, because the only executable value (Query) comes from a
// builder whose constructor requires a TenantID, the only renderable bodies
// are members of the closed, boot-validated template registry (refusal R4),
// and the only client handle lives in the sealed chconn subpackage.
//
// Layout (05 §0.3):
//   - tenantid.go   — the TenantID newtype (verified claims → identity)
//   - templates.go  — the closed registry + R4 boot validation
//   - builder.go    — Build/BuildWrite: predicate by construction
//   - runner.go     — the exported Runner extraction seam (05 §0.2)
//   - service.go    — the intel-driver service-credential seam (ADR-0010)
//   - module.go     — the 08 §3.3 routes + the internal rollup write route
//   - chconn/       — the ONLY ClickHouse client handle in the codebase
//
// The two write-shaped carve-outs (offboard_delete_tenant,
// tvo_rollup_tenant_day) are Build-constructed like every read and carry the
// same mandatory {{tenant_pred}} marker (05 §6.3). ADR-0001/ADR-0010 are
// unsigned: production writes are blocked; the rollup route is flag-gated
// (module.go's WHY header).
package querychoke
