package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// The 05 §2.1 bounds, all normative.
const (
	schemaV1          = "m1p.v1"
	maxCompressed     = 8 << 20  // stage 1: compressed-size cap
	maxDecoded        = 32 << 20 // stage 4: decoded-size cap (08 §2.1)
	maxExpansionRatio = 100      // stage 4: a 1 KiB body expanding to 32 MiB is an attack
	maxDecoderWindow  = 64 << 20 // stage 4: decoder window bound
	maxEvents         = 10_000   // stage 5
	maxEventBytes     = 1 << 20  // stage 5: mirrors the M1PL frame bound
	maxDroppedEntries = 1_000    // stage 5
)

// handleIngest runs the 05 §2.1 stages strictly in order. Stages 1–9 are
// synchronous and stateless; stages 10–11 are post-ack and asynchronous —
// the response is licensed by the S3 landing alone (05 §2.2).
func (m *Module) handleIngest(w http.ResponseWriter, r *http.Request) {
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
	if schema := r.Header.Get("M1P-Schema"); schema != schemaV1 {
		writeUpgradeRequired(w, schema)
		return
	}
	headerBatchID, err := uuid.Parse(r.Header.Get("M1P-Batch-Id"))
	if err != nil || headerBatchID.Version() != 7 {
		writeErr(w, errMalformed("M1P-Batch-Id must be a uuidv7"))
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
	if detail, bad := identityDisagreement(&batch, claims); bad {
		identityDisagreements.Inc()
		m.security.RecordIdentityDisagreement(claims.TenantID, claims.DeviceID, headerBatchID, detail, m.now())
		writeErr(w, errIdentityDisagreement())
		return
	}

	// ---- Stage 6: invariant checks ---------------------------------------
	if e, violated := checkInvariants(&batch, headerBatchID); violated {
		writeErr(w, e)
		return
	}

	// ---- §2.4 rate limiting (needs the decoded category counts) ----------
	types := make([]string, len(batch.GetEvents()))
	for i, ev := range batch.GetEvents() {
		types[i] = chproj.BodyTypeName(ev)
	}
	if wait, allowed := m.limiter.Debit(claims.TenantID, claims.DeviceID, categoryCounts(types)); !allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(wait))
		w.Header().Set("M1P-Rate-Limits", RateLimitsHeader)
		writeErr(w, errRateLimited())
		return
	}

	// ---- Stage 7: independent second redaction scan ----------------------
	scanStart := m.now()
	hits := scanner.ScanBatch(&batch)
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
	key := s3land.IngestKey(claims.TenantID, headerBatchID)
	if flagged {
		key = s3land.QuarantineKey(claims.TenantID, headerBatchID)
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
		switch prior, perr := m.store.Probe(r.Context(), s3land.IngestKey(claims.TenantID, headerBatchID), compressed); {
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
	}
	landStart := m.now()
	outcome, err := m.store.Land(r.Context(), key, compressed, claims.TenantID, claims.DeviceID)
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
		// 05 §2.3: nothing from a flagged batch is projected; the 202 is
		// still a durability promise (the quarantine object holds it all).
		m.writeAck(w, start, &batch, headerBatchID, hits, false)
		return
	}
	m.writeAck(w, start, &batch, headerBatchID, nil, false)

	// Stage 10 (ClickHouse projection) + stage 11 (Postgres side-effects):
	// post-ack, asynchronous, idempotent on event_id — failure here is
	// replayed from the landing object, never surfaced to the edge.
	rows := chproj.RowsFromBatch(&batch, claims.TenantID, claims.DeviceID, receivedAt)
	m.proj.Enqueue(rows, receivedAt)
	// X-Mark1-Edge-Version is recorded, never rejected on (08 §10.1): it
	// stamps m1_devices.edge_version alongside last_seen_at (m1_061).
	m.sfx.Enqueue(tenant, claims.DeviceID, receivedAt, r.Header.Get("X-Mark1-Edge-Version"),
		sidefx.EffectsFromBatch(&batch, receivedAt))
}

// identityDisagreement applies 08 §2.1's constraint + the envelope's
// server-stamped-band rule (proto envelope.proto fields 900–903).
func identityDisagreement(b *m1pv1.Batch, c auth.Claims) (string, bool) {
	if t := b.GetAdvisoryTenantId(); len(t) > 0 && !bytes.Equal(t, c.TenantID[:]) {
		return "advisory_tenant_id disagrees with token", true
	}
	if d := b.GetAdvisoryDeviceId(); len(d) > 0 && !bytes.Equal(d, c.DeviceID[:]) {
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
func checkInvariants(b *m1pv1.Batch, headerBatchID uuid.UUID) (apiErr, bool) {
	batchID, err := uuid.FromBytes(b.GetBatchId())
	if err != nil || batchID != headerBatchID {
		invariantViolations.WithLabelValues("batch_id_mismatch").Inc()
		return errInvariant(nil, []string{"batch_id_mismatch"}), true
	}
	var badIDs, kinds []string
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
	}
	if len(badIDs) > 0 || len(kinds) > 0 {
		return errInvariant(badIDs, kinds), true
	}
	return apiErr{}, false
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
