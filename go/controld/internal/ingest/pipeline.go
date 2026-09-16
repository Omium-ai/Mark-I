package ingest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// schemaSyntax is the shape of a well-formed M1P-Schema (07 §1: the package
// name is the wire name). Anything else is malformed, not out-of-window —
// refused as 400 before the registry is consulted.
var schemaSyntax = regexp.MustCompile(`^m1p\.v[1-9][0-9]*$`)

// The 05 §2.1 bounds, all normative.
const (
	maxCompressed     = 8 << 20  // stage 1: compressed-size cap
	maxDecoded        = 32 << 20 // stage 4: decoded-size cap (08 §2.1)
	maxExpansionRatio = 100      // stage 4: a 1 KiB body expanding to 32 MiB is an attack
	maxDecoderWindow  = 64 << 20 // stage 4: decoder window bound
	maxEvents         = 10_000   // stage 5
	maxEventBytes     = 1 << 20  // stage 5: mirrors the M1PL frame bound
	maxDroppedEntries = 1_000    // stage 5
)

// principal is the stage-3 stamp: verified claims for a device, the service credential plus the named tenant for service.go.
type principal struct {
	tenant  querychoke.TenantID
	device  uuid.UUID
	service bool
}

// handleIngest runs the 05 §2.1 stages strictly in order. Stages 1–9 are
// synchronous and stateless; stages 10–11 are post-ack and asynchronous —
// the response is licensed by the S3 landing alone (05 §2.2).
func (m *Module) handleIngest(w http.ResponseWriter, r *http.Request) {
	// Stage 2 ran in the middleware (server.Chain); stage 3's stamp is the
	// verified claims — the ONLY identity source from here on (08 §2.1).
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeErr(w, errServer("auth middleware did not run")) // a bug, not a request problem
		return
	}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil {
		writeErr(w, errServer("verified claims carry no tenant"))
		return
	}
	m.ingest(w, r, principal{tenant: tenant, device: claims.DeviceID})
}

func (m *Module) ingest(w http.ResponseWriter, r *http.Request, p principal) {
	// §2.4 in-process shed: when the bounded pool is saturated, refuse BEFORE
	// stage 4's decompression spend — a fast honest 503 beats a slow timeout
	// because the edge's backoff automaton handles it correctly.
	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeErr(w, errServer("ingest pool saturated"))
		return
	}

	start := m.now()
	requestsTotal.WithLabelValues("admit").Inc()
	tenant, tenantID, deviceID := p.tenant, p.tenant.UUID(), p.device

	// ---- Stage 1: transport admission -----------------------------------
	if r.ContentLength < 0 {
		writeErr(w, errMalformed("Content-Length required"))
		return
	}
	if r.ContentLength > maxCompressed {
		writeErr(w, errTooLarge())
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-m1p-protobuf" {
		writeErr(w, errMediaType("Content-Type must be application/x-m1p-protobuf"))
		return
	}
	if ce := r.Header.Get("Content-Encoding"); ce != "zstd" {
		writeErr(w, errMediaType("Content-Encoding must be zstd"))
		return
	}
	schema := r.Header.Get("M1P-Schema")
	if !schemaSyntax.MatchString(schema) {
		writeErr(w, errMalformed("M1P-Schema must be m1p.v<n>"))
		return
	}
	headerBatchID, err := uuid.Parse(r.Header.Get("M1P-Batch-Id"))
	if err != nil || headerBatchID.Version() != 7 {
		writeErr(w, errMalformed("M1P-Batch-Id must be a uuidv7"))
		return
	}

	// ---- Schema window (FR-SPINE-023; 08 §10.2) ---------------------------
	// Per-TENANT, so it needs the stage-3 stamp above and sits after every
	// header check that needs no lookup — but before the body is read: a
	// batch the window refuses is refused before stage 4 spends on it. A
	// registry read failure is fail-STATIC (08 §9: capture is fail-open for
	// availability): the compiled-in window applies and capture continues.
	win, err := m.registry.Window(r.Context(), tenant)
	if err != nil {
		schemaRegistryFallbacks.Inc()
		log.Printf("WARN ingest: schema registry unavailable, serving the compiled-in window (fail-static): %v", err)
		win = registry.Compiled
	}
	if !win.Accepts(schema) {
		schemaRefusals.Inc()
		writeUpgradeRequired(w, schema, win)
		return
	}

	compressed, err := io.ReadAll(io.LimitReader(r.Body, maxCompressed+1))
	if err != nil {
		writeErr(w, errMalformed("body read failed"))
		return
	}
	if len(compressed) > maxCompressed {
		writeErr(w, errTooLarge())
		return
	}

	// ---- Stage 4: zstd with bomb guard -----------------------------------
	decoded, err := decodeZstdBounded(compressed)
	switch {
	case errors.Is(err, errZstdBomb):
		zstdBombTrips.Inc()
		writeErr(w, errMalformed("decompression bound tripped"))
		return
	case errors.Is(err, errDecodedTooLarge):
		writeErr(w, errTooLarge())
		return
	case err != nil:
		writeErr(w, errMalformed("zstd decode failed"))
		return
	}

	// ---- Stage 5: protobuf decode with size/count bounds -----------------
	var batch m1pv1.Batch
	if err := proto.Unmarshal(decoded, &batch); err != nil {
		decodeFailures.Inc()
		writeErr(w, errMalformed("protobuf decode failed"))
		return
	}
	if len(batch.GetEvents()) > maxEvents || len(batch.GetDropped()) > maxDroppedEntries {
		decodeFailures.Inc()
		writeErr(w, errMalformed("batch exceeds event/dropped count bounds"))
		return
	}
	for _, ev := range batch.GetEvents() {
		if proto.Size(ev) > maxEventBytes {
			decodeFailures.Inc()
			writeErr(w, errMalformed("event exceeds 1 MiB bound"))
			return
		}
	}

	// ---- Stage 3's reject half: identity disagreement (decision D-K) -----
	// The stamp came from the token at the top; here the envelope's advisory
	// fields and the server-stamped band (900–999) are checked against it.
	// Any client-asserted identity ⇒ 403 M1E-8003 + security event — the
	// client cannot assert its own identity (08 §2.1).
	if detail, bad := identityDisagreement(&batch, tenantID, deviceID); bad {
		identityDisagreements.Inc()
		m.security.RecordIdentityDisagreement(tenantID, deviceID, headerBatchID, detail, m.now())
		writeErr(w, errIdentityDisagreement())
		return
	}

	// ---- Stage 6: invariant checks ---------------------------------------
	if e, violated := m.checkInvariants(r.Context(), &batch, headerBatchID, p.service, tenant, deviceID); violated {
		writeErr(w, e)
		return
	}

	// ---- §2.4 rate limiting (needs the decoded category counts) ----------
	types := make([]string, len(batch.GetEvents()))
	for i, ev := range batch.GetEvents() {
		types[i] = chproj.BodyTypeName(ev)
	}
	if wait, allowed := m.limiter.Debit(tenantID, deviceID, categoryCounts(types)); !allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(wait))
		w.Header().Set("M1P-Rate-Limits", RateLimitsHeader)
		writeErr(w, errRateLimited())
		return
	}

	// ---- Stage 7: independent second redaction scan ----------------------
	scanStart := m.now()
	hits := m.scanner.Scan(&batch)
	scannerScanSeconds.Observe(m.now().Sub(scanStart).Seconds())
	for _, h := range hits {
		scannerHits.WithLabelValues(h.Class).Inc()
	}
	flagged := len(hits) > 0

	// ---- Stage 8: S3-first landing ---------------------------------------
	// The object is the RECEIVED bytes, byte-identical to what the device
	// sent (05 §2.1 stage 8) — never a re-encoding, never post-strip: a
	// flagged batch lands whole under the quarantine prefix instead of the
	// (mechanically replayed) ingest prefix (05 §2.3). Keys are pure
	// functions of (tenant, batch_id) so the 08 §2.5 retry automaton always
	// re-PUTs the SAME key and the conditional write can detect it (08 §2.3).
	receivedAt := m.now()
	key := s3land.IngestKey(tenantID, headerBatchID)
	if flagged {
		key = s3land.QuarantineKey(tenantID, headerBatchID)
		// A batch that first landed CLEAN under the ingest prefix (ack lost
		// in transit, 08 §2.5) and is flagged on the re-POST — a scanner
		// ruleset changed between attempts — is already in the replay log:
		// quarantining the retry would double-land it under both prefixes
		// and turn the acked 200 into a 202. Probe the ingest key first; the
		// extra HEAD rides only the rare flagged path, never the clean one.
		// The reverse flip (first quarantined, retry now clean) is deliberately
		// NOT probed: it would put a HEAD on every clean batch's hot path
		// (05 §2.7 ack budget), and landing a batch the CURRENT ruleset deems
		// clean is exactly 05 §2.3's fail-closed judgment applied at re-POST
		// time — the stale quarantine object ages out under the 90-day
		// lifecycle and is never auto-replayed.
		switch prior, perr := m.store.Probe(r.Context(), s3land.IngestKey(tenantID, headerBatchID), compressed); {
		case perr != nil:
			s3LandFailures.Inc()
			writeErr(w, errServer("landing store unavailable"))
			return
		case prior == s3land.Duplicate:
			// Re-ack as the duplicate it is (200, all duplicates) with NO new
			// landing and NO side effects — the first landing owns stages 10–11.
			m.writeAck(w, start, &batch, headerBatchID, nil, true)
			return
		case prior == s3land.Divergent:
			writeErr(w, errDivergentBatch())
			return
		}
		// The never-replay marker lands before the twin (quarantine.go); without it the batch is not durably held.
		if err := m.tombstone(r.Context(), tenant, headerBatchID, key, len(batch.GetEvents()), receivedAt); err != nil {
			tombstoneFailures.Inc()
			log.Printf("ingest: quarantine tombstone for batch %s not written: %v", headerBatchID, err)
			writeErr(w, errServer("quarantine marker unavailable"))
			return
		}
	}
	landStart := m.now()
	outcome, err := m.store.Land(r.Context(), key, compressed, tenantID, deviceID)
	s3LandSeconds.Observe(m.now().Sub(landStart).Seconds())
	if err != nil {
		// The batch has NOT landed; withholding the ack IS the durability
		// promise (05 §9: no ack is ever sent for an unlanded batch).
		s3LandFailures.Inc()
		writeErr(w, errServer("landing store unavailable"))
		return
	}

	switch outcome {
	case s3land.Divergent:
		writeErr(w, errDivergentBatch())
		return
	case s3land.Duplicate:
		// Re-POST of an acked batch (08 §2.3): ack again cheaply, run NO
		// side effects — the first landing already owns stages 10–11.
		m.writeAck(w, start, &batch, headerBatchID, hits, true)
		return
	}

	// ---- Stage 9: ack — and only now stages 10–11 ------------------------
	if flagged {
		quarantinesTotal.Inc()
		// CON-008's "+ tenant alert" (08 §9 M1E-7002). quarantinesTotal is
		// ops-visible and not tenant-visible, the quarantine object is not
		// tenant-queryable, and the 202's quarantined[] dies with a device
		// that has already parked — so the ONE surface the tenant owns, its
		// ledger, gets a GuardDecision-class row. Identity is the stage-3
		// stamp from verified claims, never the envelope. Reached only on the
		// LANDING path: a duplicate re-POST returned above, so one landed
		// quarantine records exactly one event, and the event_id is derived
		// from batch_id so even a replay collapses instead of multiplying.
		m.security.RecordQuarantine(tenantID, deviceID, headerBatchID, hitClasses(hits), receivedAt)
		// 05 §2.3: nothing from a flagged batch is projected; the 202 is
		// still a durability promise (the quarantine object holds it all).
		m.writeAck(w, start, &batch, headerBatchID, hits, false)
		return
	}
	m.writeAck(w, start, &batch, headerBatchID, nil, false)

	// Stage 10 (ClickHouse projection) + stage 11 (Postgres side-effects):
	// post-ack, asynchronous, idempotent on event_id — failure here is
	// replayed from the landing object, never surfaced to the edge.
	rows := chproj.RowsFromBatch(&batch, tenantID, deviceID, receivedAt)
	m.proj.Enqueue(rows, receivedAt)
	if p.service {
		return // no device row to touch, no chain to leaf into (service.go)
	}
	// X-Mark1-Edge-Version is recorded, never rejected on (08 §10.1): it
	// stamps m1_devices.edge_version alongside last_seen_at (m1_061).
	m.sfx.Enqueue(tenant, deviceID, receivedAt, r.Header.Get("X-Mark1-Edge-Version"),
		sidefx.EffectsFromBatch(&batch, receivedAt))
}

// hitClasses is the ONLY thing a stage-7 hit is allowed to carry out of the
// scan: the rule classes that fired, deduped and sorted (deterministic so a
// replayed batch produces a byte-equal event). scanner.Hit deliberately holds
// no matched text to leak — see chproj.QuarantineEventRow for why nothing
// derived from the content may ride along either.
func hitClasses(hits []scanner.Hit) []string {
	seen := make(map[string]bool, len(hits))
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if !seen[h.Class] {
			seen[h.Class] = true
			out = append(out, h.Class)
		}
	}
	sort.Strings(out)
	return out
}

// identityDisagreement applies 08 §2.1's constraint + the envelope's
// server-stamped-band rule (proto envelope.proto fields 900–903).
func identityDisagreement(b *m1pv1.Batch, tenant, device uuid.UUID) (string, bool) {
	if t := b.GetAdvisoryTenantId(); len(t) > 0 && !bytes.Equal(t, tenant[:]) {
		return "advisory_tenant_id disagrees with token", true
	}
	if d := b.GetAdvisoryDeviceId(); len(d) > 0 && !bytes.Equal(d, device[:]) {
		return "advisory_device_id disagrees with token", true
	}
	for _, ev := range b.GetEvents() {
		// The server-stamped band (900–999) MUST be unset on the client
		// wire — ANY client-set value rejects, even one matching the token
		// (envelope.proto band note; decision D-K). The batch-level advisory
		// fields above are the sanctioned cross-check slots, where equal
		// values are legal and only disagreement rejects.
		if len(ev.GetTenantId()) > 0 || len(ev.GetDeviceId()) > 0 ||
			ev.GetReceivedAt() != nil || ev.GetClockSkewMs() != 0 {
			return "server-stamped band field set by client", true
		}
	}
	return "", false
}

// checkInvariants is stage 6: violations name the offending event_ids
// (08 §2.4: named events quarantine at edge, remainder re-sent once).
func (m *Module) checkInvariants(ctx context.Context, b *m1pv1.Batch, headerBatchID uuid.UUID, service bool, tenant querychoke.TenantID, device uuid.UUID) (apiErr, bool) {
	batchID, err := uuid.FromBytes(b.GetBatchId())
	if err != nil || batchID != headerBatchID {
		invariantViolations.WithLabelValues("batch_id_mismatch").Inc()
		return errInvariant(nil, []string{"batch_id_mismatch"}), true
	}
	var badIDs, kinds []string
	// FR-VERIFY-004: the device's live origin key, resolved at most once per
	// batch (constant for every vote in it) and only if a vote actually
	// carries a signature to check -- an all-unsigned batch (or no votes)
	// never touches m1_device_keys.
	var pubLooked, pubOK bool
	var pub ed25519.PublicKey
	for _, ev := range b.GetEvents() {
		id, err := uuid.FromBytes(ev.GetEventId())
		if err != nil || id.Version() != 7 {
			invariantViolations.WithLabelValues("event_id").Inc()
			badIDs, kinds = append(badIDs, id.String()), append(kinds, "event_id")
			continue
		}
		if ev.GetSeq() == 0 {
			invariantViolations.WithLabelValues("seq").Inc()
			badIDs, kinds = append(badIDs, id.String()), append(kinds, "seq")
		}
		// The ~2.5× streaming-overcount defense is ENFORCED here, not
		// trusted (05 §2.1 stage 6; events.proto: "Ingest rejects a Usage
		// without it").
		if u := ev.GetUsage(); u != nil && len(u.GetIdemKey()) != 32 {
			invariantViolations.WithLabelValues("usage_idem_key").Inc()
			badIDs, kinds = append(badIDs, id.String()), append(kinds, "usage_idem_key")
		}
		// FR-VERIFY-020, same posture as the idem_key row: verify.proto says a
		// receiver MUST reject a posterior whose length is not 4, and a stage
		// outside the enum (UNSPECIFIED included) is not a verdict. Refused
		// here so a billing-grade event never lands as a null projection.
		if v := ev.GetVerdictEvent(); v != nil {
			if len(v.GetPosterior()) != 4 {
				invariantViolations.WithLabelValues("verdict_posterior").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "verdict_posterior")
			}
			// Descriptor lookup, not a hand-list: a stage added to the proto is
			// admitted by regeneration alone; the zero value never is.
			if st := v.GetStage(); st.Number() == 0 || st.Descriptor().Values().ByNumber(st.Number()) == nil {
				invariantViolations.WithLabelValues("verdict_stage").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "verdict_stage")
			} else if st == foreignStage[service] {
				invariantViolations.WithLabelValues("verdict_stage_origin").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "verdict_stage_origin")
			}
		}
		// FR-ROUTE-001, same posture: a RouteDecision is the OPE logging row
		// (06 §11.1), and a propensity outside (0, 1] — the zero a missing
		// producer lands, NaN included — a fidelity the descriptor does not
		// know (06 §11.2 filters on it), or an empty action is a row no
		// estimator can read. Refused so it never lands as a null projection.
		if r := ev.GetRouteDecision(); r != nil {
			if p := r.GetPropensity(); !(p > 0 && p <= 1) {
				invariantViolations.WithLabelValues("route_propensity").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "route_propensity")
			}
			if f := r.GetFidelity(); f.Number() == 0 || f.Descriptor().Values().ByNumber(f.Number()) == nil {
				invariantViolations.WithLabelValues("route_fidelity").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "route_fidelity")
			}
			if r.GetAction() == "" {
				invariantViolations.WithLabelValues("route_action").Inc()
				badIDs, kinds = append(badIDs, id.String()), append(kinds, "route_action")
			}
		}
		// FR-VERIFY-004: an empty signature is admitted (pre-ruling producers,
		// or a device with no enrolled key -- receipt sealing degrades the same
		// way) and marked unsigned downstream (chproj.unsignedAnchorVotes); a
		// NON-empty signature that fails to verify is refused here, never
		// silently dropped to unsigned -- that would let a forged vote pass as
		// merely uncertified.
		if av := ev.GetAnchorVote(); av != nil {
			if sig := av.GetSignature(); len(sig) > 0 {
				if !pubLooked {
					pubLooked = true
					if m.deviceKeys != nil {
						if p, ok, kerr := m.deviceKeys.PublicKey(ctx, tenant, device); kerr == nil {
							pub, pubOK = p, ok
						}
					}
				}
				if !pubOK || !verifyAnchorVoteSignature(pub, av, sig) {
					invariantViolations.WithLabelValues("anchor_vote_signature").Inc()
					badIDs, kinds = append(badIDs, id.String()), append(kinds, "anchor_vote_signature")
				}
			}
		}
	}
	if len(badIDs) > 0 || len(kinds) > 0 {
		return errInvariant(badIDs, kinds), true
	}
	return apiErr{}, false
}

// verifyAnchorVoteSignature reproduces verify.proto's signing input --
// deterministic proto marshal of av with signature cleared, no domain prefix
// (that's the receipt chain's JSON scheme, not this one) -- and checks it
// against the enrolled device key. av is cloned so the caller's copy (which
// still needs its real signature for the wire/payload column) is untouched.
func verifyAnchorVoteSignature(pub ed25519.PublicKey, av *m1pv1.AnchorVote, sig []byte) bool {
	clone, ok := proto.Clone(av).(*m1pv1.AnchorVote)
	if !ok {
		return false
	}
	clone.Signature = nil
	canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return false
	}
	return receipts.Verify(pub, sig, canon)
}

// foreignStage[service] is the stage that principal never authors (verify.proto VerdictStage: PROVISIONAL is the edge fusion, CERTIFIED is adjudicator-emitted; REVISED is both, 04 §2 slow anchors).
var foreignStage = map[bool]m1pv1.VerdictStage{
	false: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED,
	true:  m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
}

// ---------------------------------------------------------------------------
// Stage 4: bounded zstd
// ---------------------------------------------------------------------------

var (
	errZstdBomb        = errors.New("ingest: zstd expansion/window bound tripped")
	errDecodedTooLarge = errors.New("ingest: decoded size bound tripped")
)

// decodeZstdBounded enforces the three simultaneous stage-4 bounds: decoded
// ≤ 32 MiB (hard stop MID-STREAM via the limit reader, not after), expansion
// ratio ≤ 100:1, decoder window ≤ 64 MiB. WHY ratio AND size: a token-dense
// 300 KiB body legally approaches the size cap; a 1 KiB body reaching it is
// an attack (05 §2.1 stage 4).
func decodeZstdBounded(compressed []byte) ([]byte, error) {
	dec, err := zstd.NewReader(bytes.NewReader(compressed),
		zstd.WithDecoderMaxWindow(maxDecoderWindow),
		zstd.WithDecoderConcurrency(1),
	)
	if err != nil {
		return nil, err
	}
	defer dec.Close()

	sizeLimit := int64(maxDecoded)
	ratioLimit := int64(len(compressed)) * maxExpansionRatio
	limit := sizeLimit
	if ratioLimit < limit {
		limit = ratioLimit
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(dec, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		if limit == ratioLimit && ratioLimit < sizeLimit {
			return nil, errZstdBomb
		}
		return nil, errDecodedTooLarge
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Stage 9: the ack body (08 §2.4 / §2.6)
// ---------------------------------------------------------------------------

type ackBody struct {
	BatchID     string   `json:"batch_id"`
	Accepted    int      `json:"accepted"`
	Duplicates  int      `json:"duplicates"`
	Quarantined []string `json:"quarantined"`
	ServerTime  string   `json:"server_time"`
	// checkpoint_hint is advisory (08 §2.6) and absent until the checkpoint
	// builder ships with the receipt machinery (C6) — additive later, per
	// 08 §10.2's response discipline.
}

func (m *Module) writeAck(w http.ResponseWriter, start time.Time, b *m1pv1.Batch, batchID uuid.UUID, hits []scanner.Hit, replay bool) {
	body := ackBody{
		BatchID:     batchID.String(),
		Quarantined: []string{},
		ServerTime:  m.now().UTC().Format(time.RFC3339Nano),
	}
	status := http.StatusOK
	switch {
	case len(hits) > 0:
		// 202: durably held, nothing projected (08 §2.4). quarantined[]
		// names the flagged event_ids; recomputed deterministically on a
		// replayed POST, so the replay ack matches the original.
		status = http.StatusAccepted
		seen := map[string]bool{}
		for _, h := range hits {
			id := h.EventID.String()
			if !seen[id] {
				seen[id] = true
				body.Quarantined = append(body.Quarantined, id)
			}
		}
	case replay:
		// Same M1P-Batch-Id, same bytes, already landed: every event is a
		// duplicate by definition (M1E-2002 is informational, in the 200).
		body.Duplicates = len(b.GetEvents())
	default:
		body.Accepted = len(b.GetEvents())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("M1P-Rate-Limits", RateLimitsHeader)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
	ackSeconds.Observe(m.now().Sub(start).Seconds())
}

func retryAfterSeconds(wait time.Duration) string {
	secs := int(wait / time.Second)
	if wait%time.Second != 0 || secs == 0 {
		secs++ // ceil: Retry-After is a floor for the edge (08 §2.5)
	}
	return itoa(secs)
}

func itoa(i int) string {
	if i <= 0 {
		return "1"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
