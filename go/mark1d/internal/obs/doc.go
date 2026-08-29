// Package obs will own mark1d self-observation: slog structured logging plus
// atomic counters drained into EdgeHealth and Dropped{} emissions (04 §2,
// doc 11). The edge self-reports over M1P only — zero OpenTelemetry, ever
// (CON-005/ADR-0005); Prometheus is a cloud-side (controld) concern.
//
// C3 STUB (13 §11 row C3 ships the skeleton). Filled when cmd's run loop and
// the uplink land (WS-1/WS-2, 14 §2) — the first consumers of a counter.
package obs
