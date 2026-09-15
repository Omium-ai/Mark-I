package ingest

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The 05 §2.1 stage-table metrics, by their doc names, registered with
// promauto at package init (05 §1.7: module-scoped controld_<module>_*;
// chproj/sidefx own their stage-10/11 metrics in their packages).
var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_requests_total",
		Help: "Ingest requests by pipeline stage reached (05 §2.1 stage 1)",
	}, []string{"stage"})

	authFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_auth_failures_total",
		Help: "Device-token verification failures (05 §2.1 stage 2)",
	}, []string{"reason"})

	identityDisagreements = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_identity_disagreements_total",
		Help: "Envelope identity disagreed with verified token claims — any nonzero value pages (05 §2.1 stage 3, 11)",
	})

	zstdBombTrips = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_zstd_bomb_trips_total",
		Help: "Decompression bound trips: ratio or window (05 §2.1 stage 4)",
	})

	decodeFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_decode_failures_total",
		Help: "Protobuf decode or size/count bound failures (05 §2.1 stage 5)",
	})

	invariantViolations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_invariant_violations_total",
		Help: "Batch invariant violations by kind (05 §2.1 stage 6)",
	}, []string{"kind"})

	scannerHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_scanner_hits_total",
		Help: "Pre-egress secret scanner hits by class (05 §2.1 stage 7)",
	}, []string{"class"})

	scannerScanSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controld_ingest_scanner_scan_seconds",
		Help: "Pre-egress scan duration (05 §2.1 stage 7)",
	})

	s3LandSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controld_ingest_s3_land_seconds",
		Help: "S3 conditional-PUT landing duration (05 §2.1 stage 8)",
	})

	s3LandFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_s3_land_failures_total",
		Help: "Landing failures — each one is a withheld ack, never a lost batch (05 §2.1 stage 8)",
	})

	ackSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "controld_ingest_ack_seconds",
		Help:    "Stage-1 entry to response write — THE ingest SLI (05 §2.1 stage 9, §2.7)",
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 6.4},
	})

	quarantinesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_quarantines_total",
		Help: "Batches landed under the quarantine prefix (05 §2.3)",
	})

	schemaRefusals = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_schema_refusals_total",
		Help: "426 M1E-2007: M1P-Schema outside the tenant's registry window (08 §10.2)",
	})

	schemaRegistryFallbacks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_schema_registry_fallbacks_total",
		Help: "Registry reads that failed and were served from the compiled-in window — fail-static, capture continues (08 §9)",
	})

	// Distinct from chproj's queue_dropped_total, whose help text says
	// "recovered only by replay" — true for a landed batch's rows and FALSE
	// for these: an M1E-8003 batch never landed and the quarantine prefix is
	// never auto-replayed, so a security row dropped here is gone. Counted
	// under its own name so the loss is priced, never silent (11 §10.1).
	securityEventsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_security_events_dropped_total",
		Help: "Security-event rows (M1E-8003 / M1E-7002) dropped on projector queue overflow — NO replay path; any nonzero value pages (05 §2.1 stage 3; 11 §10.1)",
	}, []string{"code"})
)
