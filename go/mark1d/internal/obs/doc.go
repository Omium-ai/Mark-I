// Package obs owns mark1d self-observation: the in-process counter/gauge
// table of 11 §3.1, drained into an EdgeHealth event once per successful
// uploader cycle and at most once per 15 minutes per device (11 §2.3).
//
// The edge exposes no metrics port — a laptop daemon with a scrape port is
// attack surface with no scraper (04 §2.11) — so health leaves the machine
// the only way anything does: as a diagnostic-class M1P event through the
// same admission pipeline, spool and uplink as captured product telemetry.
// Diagnostic class is the point: health sheds first under pressure and never
// blocks a developer's session, and the shed is itself accounted as
// Dropped{spool_shed, diagnostic}, so shed diagnostics stay COUNTED.
//
// Zero OpenTelemetry, ever (CON-005/ADR-0005): Prometheus exposition is a
// cloud-side (controld) concern, and no_otel_test.go is the module-graph
// guard that keeps it that way.
package obs
