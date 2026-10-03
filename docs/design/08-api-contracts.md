# 08 — API Contracts

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`) and the architecture spec v2.0 (`docs/spec/architecture-spec.md`). Where this document and either of those disagree, they win. Glossary terms are used exactly as defined in `01-introduction.md` §9 and are not redefined here.
**Audience:** anyone integrating anything with anything — an edge component with the cloud, an agent with the edge, a customer's verifier with our receipts.
**Normative language:** MUST/MUST NOT/SHOULD per RFC 2119. Contracts appear in fenced blocks; prose exists only where a constraint or a WHY needs stating.

Claude Code hook and settings facts in §5.1 were verified against the vendor documentation (`code.claude.com/docs/en/hooks`, `/settings`, `/settings-reference`) on 2026-08-28 and against on-disk transcripts. Every other agent's surface is marked verified or `UNVERIFIED` explicitly — a wrong contract is worse than a flagged gap.

---

## 1. Contract inventory and stability policy

### 1.1 Stability classes

| Class | Meaning | Who may change it, and how |
|---|---|---|
| **wire-stable** | Byte-level compatibility contract. Consumed by binaries we do not control the rollout of (edges in the field, the open-source verifier, customer scripts). | Additive changes only within a major. Breaking change ⇒ a new major namespace served **in parallel** (`m1p.v2`, `/api/v2/…`) — never an in-place change. `buf breaking` at `WIRE_JSON` gates protobuf in CI; deleted fields are `reserved` forever. |
| **config-stable** | Shape is versioned data distributed through PolicyBundle sections (`agent_maps`, verify matrices, knee tables) or fenced config fragments. | A format change is a **bundle push, not a release**. Edges skip-and-retain unknown sections/keys within a bundle major (§10.3). |
| **internal** | Both ends ship in the same signed package and upgrade atomically (M1PL framing, spool segment layout, `mark1d`↔CLI local IPC). | May change on any release. Still versioned (frame `ver` byte, segment header) so a partially-upgraded host fails loudly, not silently. |
| **externally-owned** | Defined by an agent vendor, not by us (hook payloads, transcript line format, settings file schemas). | We absorb drift: field maps and parser rules live in `agent_maps` bundle data; unrecognized shapes emit `Dropped{unsupported_agent_version}` and never fabricate values. |
| **external writer** | The subset of the local fabric a third-party host integrates against (§4.6, ADR-0012, 2026-10-02): endpoint discovery, M1PL framing, `Hello`/`HelloAck` with `ext:` session binding, the `Event` envelope and the five-event minimum, the JSONL file-tail mode and its sidecar manifest. Consumed by binaries we do not ship. | **Public and versioned.** Additive only within `m1p.v1`: a new field, a new optional event, a new control arm. Nothing an integrated host sends today may stop being accepted within the major; a breaking change is `m1p.v2`, served in parallel. The M1PL `ver` byte and the sidecar `schema_version` are the two version carriers. `buf breaking` at `WIRE_JSON` and the `ext` conformance vectors (12 §3.4) gate it in CI. |

### 1.2 Inventory

| # | Interface | Producer → Consumer | Class | Defined in |
|---|---|---|---|---|
| I-1 | `m1p.v1` protobuf schema (all event families) | edge components → `controld.ingest` | wire-stable | 07 §protobuf; this doc §2 |
| I-2 | M1P/1 ingest transport (`POST /m1p/v1/ingest`) | `mark1d` uploader → `controld.ingest` | wire-stable | §2 |
| I-3 | Control-plane REST (enroll, policy, receipts, reports, DP) | `mark1` CLI + `mark1d` → `controld` | wire-stable | §3 |
| I-4 | Public-key + transparency-log read surface | anyone (incl. the standalone verifier, offline) | wire-stable, **public** | §3.5 |
| I-5 | Receipt/checkpoint format + chain rules | `controld`/`mark1d` → `rust/verifier` | wire-stable, **public** | 07 §receipts; §3.4 |
| I-6 | PolicyBundle v1 (canonical CBOR, six sections) | `mark1-intel.policy-compiler` → edges | config-stable | 07 §bundle; §10.3 |
| I-7 | M1PL local fabric (UDS / named pipe framing) | hookshim, proxy, cortexd, tailers → `mark1d` | internal | §4 |
| I-8 | Loopback fallback listener | agents that cannot exec the shim → `mark1d` | internal | §4.5 |
| I-9 | Per-agent hook payloads + transcript formats | agent vendors → hookshim/tailers | externally-owned | §5 |
| I-10 | Agent-facing hook *responses* (context injection, block/allow) | hookshim → agent | externally-owned (vendor schema), our content config-stable | §5 |
| I-11 | cortexd MCP tools | cortexd → agents (MCP clients) | wire-stable (schema additive within a version) | §6 |
| I-12 | `mark1` CLI surface (`--json` output shapes, exit codes) | `mark1` → humans, MDM, CI scripts | wire-stable for `--json` and exit codes; human text is not a contract | §7 |
| I-13 | Fenced config fragments + provisioning manifest | `mark1d` → agent config files | config-stable | §8 |
| I-14 | Error taxonomy (`M1E-*` codes) | everything → everything | wire-stable | §9 |
| I-15 | Spool segment binary layout | `mark1d` → `mark1d` | internal | 07 §spool |
| I-16 | Corpus export formats (Parquet + KTO JSONL/manifest) | `mark1-intel.corpus` → data-refinery | wire-stable within the estate | 07 §corpus |
| I-17 | External-writer contract (socket + JSONL file-tail) | third-party hosts (`ext:` writers) → `mark1d` | external writer, **public** | §4.6; `docs/integrating-a-host.md` |

### 1.3 Deprecation policy per class

- **wire-stable.** A deprecated major keeps being served for **≥ 180 days** after its successor GAs, and for as long as any enrolled, non-revoked device is still pinned to it — the `m1p-registry` records per-tenant accepted windows, and a major is retired per tenant only when that tenant's window closes. Out-of-window requests receive the structured upgrade hint of §10.2, never a silent drop. Public interfaces (I-4, I-5) are **never** retired: the verifier must validate historical chains forever, so old receipt formats remain decodable in `rust/verifier` permanently.
- **config-stable.** No deprecation window is needed: the bundle carries the shape and the data together. Removing a section is a bundle push that old edges treat as "section absent ⇒ built-in default" (fail-static ladder, §10.3).
- **internal.** No external deprecation obligations. The version byte/field MUST still change on any layout change so that mixed-version state on disk (e.g. spool segments across an upgrade) is detected and drained, not misparsed.
- **externally-owned.** We deprecate nothing; vendors do. When a vendor breaks a surface, the response is: bump `agent_maps` (bundle push) if the break is absorbable; otherwise the adapter emits `Dropped{reason: unsupported_agent_version}` and the conformance fixture for the pinned version is updated. The adapter slot's go/no-go spike artifact (plan, Phase 1) is re-run on major vendor releases.

One rule spans all classes: **nothing negotiates silently.** Every version decision an edge or server makes is observable — in a response header, an ACK ledger row, or a `Dropped{}` event.

---

## 2. M1P/1 ingest

The single event-upload endpoint. Plain HTTPS POST — **never gRPC to the edge** (middleboxes; the Cursor/Sentry/PostHog/Tailscale convergence). Delivery is at-least-once; the server makes it exactly-once-effective by idempotent upsert.

### 2.1 Request

```
POST /m1p/v1/ingest HTTP/1.1
Host: ingest.mark1.omium.ai
Authorization: Bearer <device token, ≤24 h, from enrollment (§3.1)>
Content-Type: application/x-m1p-protobuf
Content-Encoding: zstd
M1P-Schema: m1p.v1
M1P-Batch-Id: <uuidv7, equals Batch.batch_id>
X-Mark1-Edge-Version: <semver of mark1d>
Content-Length: <n>          # decoded size MUST be ≤ 32 MiB; frames inside are individually bounded

Body (zstd-compressed m1p.v1.Batch):
  Batch {
    batch_id:    uuidv7        # idempotency key for the whole POST
    session_id:  uuidv7
    sdk:         { component, version }        # "mark1d", semver
    sent_at:     timestamp     # stamped at send time; server computes clock skew
    events:      Event[]       # final, redaction-admitted events; each carries event_id (uuidv7) + seq
    dropped:     Dropped[]     # accounting for everything shed since the last successful batch
  }
```

Constraints, all normative:

- `tenant_id` and `device_id` **do not appear in the envelope trust path**. `controld.ingest` stamps both onto every stored row from the verified token claims. If the envelope carries either field and it disagrees with the token, the batch is **rejected (403, `M1E-8003`) and a security event is recorded**. The client cannot assert its own identity — that is the anti-`rds_superuser` lesson applied to ingest.
- Every event in `events[]` MUST already have passed the edge's admit-to-upload redaction axis (fail-closed, no off switch). Ingest runs an **independent second scanner** with its own ruleset; a high-confidence secret hit quarantines the batch (202 + `quarantined[]`, below) and alerts the tenant — client-side redaction never gets to be the last line.
- `Usage` events MUST carry `idem_key = HMAC_tenant(session_id, message.id, request_id)`. This is a protocol invariant (the verified ~2.5× streaming-overcount defense), not parser etiquette; ingest enforces its presence.
- Large artifacts (opt-in evidence blobs) do not ride this endpoint; they upload as multipart `attach.{event_id}.{name}` to the S3 attachment path named in the enrollment document.

### 2.2 The S3-first landing rule

**Ingest acknowledges nothing it has not durably landed.** The response is written only after the raw (post-scan) batch object is confirmed in S3 under the tenant prefix (`s3://…/<tenant>/ingest/<yyyy-mm-dd>/<batch_id>.m1p.zst`, per-tenant KMS key). The S3 object *is* the replay log: ClickHouse insertion (`async_insert=1, wait_for_async_insert=1`) and the Postgres side-effects happen from that object and can be replayed from it after any downstream failure. A `200`/`202` therefore means "this data can no longer be lost by Omium," which is what lets the edge delete spool segments on ack (whole-file ack-then-delete).

### 2.3 Idempotency

Three layers, one key: transcript `(message.id, requestId)` at the edge → `event_id` (and `idem_key` for `Usage`) idempotent upsert at ingest → ClickHouse `ReplacingMergeTree` on `event_id`. Re-POSTing an identical batch — same `M1P-Batch-Id` — is safe and cheap: the server detects the already-landed S3 object and returns the original response. Re-sending individual events inside a new batch is also safe: duplicates count in `duplicates`, not in `accepted`, and are not double-stored.

### 2.4 Response statuses

| Status | Meaning | Edge behavior |
|---|---|---|
| `200 OK` | Batch landed in S3; all events accepted or deduplicated. | Delete acked spool segments. |
| `202 Accepted` | Batch landed, but ≥1 event was quarantined by the pre-egress scanner or held for schema review. Body lists `quarantined[]`. | Delete acked segments; surface quarantine via `mark1 status`; a `Dropped{reason: quarantined}` for the affected events goes in the next batch. |
| `400 Bad Request` | Malformed: zstd/protobuf decode failure, missing `M1P-Batch-Id`, unbounded frame. `M1E-2001`. | **Quarantine-and-report** (4xx rule). Never retried. |
| `401 Unauthorized` | Token missing/expired/unparseable. `M1E-1002`. | Refresh token via §3.1; if refresh succeeds, the same batch is re-sent (this is a new attempt, not a 4xx quarantine — 401 with a refreshable token is the one 4xx the uploader may retry **after** re-auth; with no refresh path it parks). |
| `403 Forbidden` | Device revoked (`M1E-1003`) or envelope/token identity disagreement (`M1E-8003`, + security event). | Quarantine-and-report; `mark1d` drops to capture-local-only and surfaces re-enrollment. |
| `409 Conflict` | `M1P-Batch-Id` already landed with different content bytes. `M1E-2003`. | Quarantine-and-report — this indicates local spool corruption; never overwrite a landed batch. |
| `413 Payload Too Large` | Decoded batch > 32 MiB. `M1E-2004`. | Split the batch and re-send halves (deterministic split; not a "retry" in the backoff sense). |
| `415 Unsupported Media Type` | Wrong `Content-Type`/`Content-Encoding`. `M1E-2005`. | Quarantine-and-report. |
| `422 Unprocessable Entity` | Schema-valid envelope, invariant-violating events (e.g. `Usage` without `idem_key`). Body names the offending `event_id`s. `M1E-2006`. | Quarantine the named events, re-send the remainder once, report. |
| `426 Upgrade Required` | `M1P-Schema` outside the tenant's accepted window. Body is the structured upgrade hint (§10.2). `M1E-2007`. | Quarantine-and-report; surface upgrade via `mark1 doctor`. |
| `429 Too Many Requests` | Rate limited. Carries `Retry-After` and `M1P-Rate-Limits` (per-category, Sentry grammar: `<category>:<limit>:<window>;…`). | **Retry** with backoff, honoring `Retry-After` as the floor and per-category limits for future batch composition. |
| `5xx` | Server fault. Nothing landed unless a later replay proves otherwise — idempotency makes blind re-send safe. | **Retry** with backoff. |

### 2.5 Retry policy (normative, exact)

Retry **only** on network errors, `5xx`, and `429`.

```
attempt n (1-based):  delay = min(cap, base · 2^(n−1)) · U(0,1)     # full jitter
base = 6 s     cap = 30 min     max attempts ≈ 10 (i.e. give up after the 10th failure)
then: PARK — batch stays in the spool, uploader moves on; parked work is re-queued
      on daemon restart, on network-change signal, and every 6 h.
429: delay additionally ≥ Retry-After.
4xx (except the 401-with-refresh case): QUARANTINE-AND-REPORT — batch moves to
      ~/.omium/mark1/quarantine/ (0600, encrypted), a Dropped{reason, durability_class,
      quantity} entry rides the next successful batch, and `mark1 status` shows it.
      Quarantined data is never silently discarded and never auto-retried.
```

Parking (not dropping) after exhaustion is deliberate: usage/verdict/receipt-checkpoint classes are billing-grade and **block on full** in the spool rather than shed, so a long outage degrades diagnostics first and billing-grade data never.

### 2.6 Worked example

```
>>> POST /m1p/v1/ingest
>>> Authorization: Bearer eyJhbGciOiJFZERTQSJ9…
>>> Content-Type: application/x-m1p-protobuf
>>> Content-Encoding: zstd
>>> M1P-Schema: m1p.v1
>>> M1P-Batch-Id: 0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01
>>> X-Mark1-Edge-Version: 1.4.2
>>> [zstd(Batch{ batch_id: 0191c2f3-…9e01, session_id: 0191c2f0-…, sent_at: …,
>>>   events: [ Usage{event_id: 0191c2f3-…, seq: 41, idem_key: hmac…,
>>>              input_tokens: 2113, output_tokens: 388,
>>>              cache_creation_input_tokens: 0, cache_read_input_tokens: 19244,
>>>              service_tier: "standard"},
>>>            VerdictEvent{event_id: 0191c2f3-…, seq: 42, stage: PROVISIONAL,
>>>              posterior: [0.86, 0.09, 0.03, 0.02], noise_cert_id: ""} ],
>>>   dropped: [ Dropped{reason: SPOOL_SHED, durability_class: DIAGNOSTIC, quantity: 17} ] })]

<<< HTTP/1.1 200 OK
<<< Content-Type: application/json
<<< M1P-Rate-Limits: usage:10000:60;diagnostic:2000:60
<<<
<<< { "batch_id": "0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01",
<<<   "accepted": 2, "duplicates": 0, "quarantined": [],
<<<   "server_time": "2026-08-28T14:03:11.402Z",
<<<   "checkpoint_hint": { "checkpoint_seq": 5121, "pending_leaves": 1834 } }
```

`posterior[4]` is ordered exactly `[satisfied, violated, refused, error]` — the four-verdict vocabulary, verbatim, everywhere. `checkpoint_hint` is advisory (which receipt checkpoint these leaves will fold into); the authoritative binding arrives later as a `ReceiptCheckpoint` event and a chain row retrievable via §3.4.

---

## 3. Control-plane REST

All under `https://api.mark1.omium.ai/api/v1/…` unless noted. JSON request/response bodies except where stated. Two token kinds: **device token** (issued by §3.1, identifies `(tenant, device)`, ≤24 h) and **operator token** (a tenant-admin OIDC access token, for revocation/report/DP endpoints). Every authenticated endpoint stamps tenancy from the verified token; a tenant identifier in a path or body is never trusted (`M1E-8003` on disagreement). All list endpoints paginate with `?limit=&cursor=` and return `next_cursor`.

### 3.1 Enrollment (OIDC device-code)

Device enrollment state machine — states are stored per device in Postgres and every transition is receipted:

```
                 start                    user approves at IdP        first token issued
  (none) ────────────────▶ PENDING ─────────────────────────▶ APPROVED ─────────────▶ ACTIVE
                              │  device-code expires (15 min)                            │
                              ▼                                                          │ operator revoke / offboard
                           EXPIRED  (terminal; re-run start)                             ▼
                                                                                      REVOKED  (terminal)
  ACTIVE ──(token expiry, ≤24 h)──▶ ACTIVE            # refresh with proof-of-possession; no state change
  ACTIVE ──(refresh fails 30 d)───▶ DORMANT ──(refresh succeeds)──▶ ACTIVE     # bookkeeping only
```

`REVOKED` is fail-closed and immediate: the token-verification path checks a revocation list that is **never served from cache older than 60 s**; a revoked device's next request — ingest, policy, anything — gets `403 M1E-1003`. There is no un-revoke; re-enrollment creates a new `device_id` and a new device key, and the old receipt chain remains attributable to the old identity.

```
POST /api/v1/enroll/device/start                         auth: none (rate-limited by IP)
  { "client": "mark1-cli", "client_version": "1.4.2",
    "device_pubkey": "ed25519:BASE64…",                  # the device origin-signing key, generated
    "platform": "linux-x86_64", "hostname_hash": "hmac…" }  # in keychain/TPM; 0600 file floor
→ 200
  { "device_code": "…", "user_code": "WDJB-MJHT",
    "verification_uri": "https://idp.customer.example/activate",
    "expires_in": 900, "interval": 5 }
Errors: 400 M1E-2001 (malformed), 429 M1E-9001.

POST /api/v1/enroll/device/poll                          auth: none (device_code is the secret)
  { "device_code": "…" }
→ 202 { "status": "pending" }                            # keep polling at `interval`
→ 200 { "status": "active",
        "device_id": "0191…", "tenant_id": "0191…",     # informational; never trusted from client later
        "device_token": "…", "expires_in": 86400,        # ≤ 24 h, always
        "server_min_edge": "1.2.0",                      # §10.1 minimum-version handshake
        "endpoints": { "ingest": "https://ingest.…", "attach": "https://…", "policy_stream": "…" },
        "key_manifest_uri": "/.well-known/mark1-keys",
        "tenant_root_hex": "…" }                         # 04 §2.9's per-tenant HMAC root (idem_key salt); only on an ACTIVE body,
                                                        # never in a list; absent (not empty) when the server holds no pepper
Errors: 400 M1E-1004 (unknown/expired device_code → state EXPIRED),
        403 M1E-1005 (user denied at IdP), 429 M1E-9001 (poll faster than `interval`).

POST /api/v1/enroll/token                                auth: none (proof-of-possession)
  { "device_id": "0191…", "signed_nonce": { "nonce_from": "/api/v1/enroll/nonce",
      "sig": "ed25519 over (nonce ‖ device_id ‖ requested_at)" } }
→ 200 { "device_token": "…", "expires_in": 86400, "tenant_root_hex": "…" }   # the root rides every PoP refresh too
Errors: 401 M1E-1002 (bad signature), 403 M1E-1003 (REVOKED — terminal; body says re-enroll).

POST /api/v1/enroll/revoke                               auth: operator token
  { "device_id": "0191…", "reason": "offboarding" }
→ 200 { "device_id": "0191…", "state": "revoked", "receipt_seq": 812 }   # per-event receipted
Errors: 404 M1E-1006, 403 M1E-1001 (not a tenant admin).

GET /api/v1/enroll/devices                               auth: operator token
→ 200 { "devices": [ { "device_id", "state", "platform", "enrolled_at",
                       "last_seen_at", "edge_version" } … ], "next_cursor": … }
```

WHY the ≤24 h ceiling: a stolen device token has a bounded lifetime even if revocation propagation fails entirely; the daily refresh is also the natural checkpoint at which `server_min_edge` and key-manifest changes reach every edge.

### 3.2 Policy distribution

Bundles are canonical CBOR, signed with section-split KMS-resident keys, sequenced monotonically per `(tenant, channel)`, carrying `max_age` and `prev_hash`. The edge verifies **signature + monotonic seq + transparency-log inclusion proof** before applying anything, persists last-known-good, and is fail-static. Channels: `stable` (default), `canary` (server-assigned cohorts; canary cohorts double as OPE randomization units).

```
GET /api/v1/policy/bundle?channel=stable                 auth: device token
  If-None-Match: "<etag of currently-applied bundle>"
→ 200
  Content-Type: application/cbor          ETag: "t7-stable-000482"
  X-Mark1-Bundle-Seq: 482                 X-Mark1-Bundle-Sig: <echo of the in-map sigs>
  X-Mark1-Tlog-Proof: <echo of the in-map inclusion proof; log head in /.well-known/mark1-keys>
  [canonical-CBOR PolicyBundle v1: verify | route | memory | cortex | gates | agent_maps]

The signatures and the inclusion proof live INSIDE the bundle map (07's CDDL:
`signatures`, `inclusion`), and the in-map copies are the ONLY ones the edge
verifies. These three headers are transport-level echoes for cache keying,
proxy logging, and cheap `seq` triage. A header participates in NO verification
step: each section signature is over the D-Q signing structure (07), whose every
field is read from the map, so an edge that trusted a header would be trusting a
value nothing signed. A header
disagreeing with the map is therefore ignored rather than an error — it is
unauthenticated either way. This is what the frozen bundle vectors encode. The
bundle BODY that `prev_hash` and the tlog leaf commit to is the canonical map
minus its `inclusion` entry: a leaf cannot commit to the proof of its own
inclusion.
→ 304 Not Modified                        # ETag matches; nothing to do
Errors: 401/403 as usual; 404 M1E-3004 (unknown channel).
Edge rejection is local, not an HTTP error: bad signature (M1E-3001), non-monotonic seq
(M1E-3002), missing/invalid inclusion proof (M1E-3003), any command string in `verify`
(M1E-3005, decode-time) — each keeps last-known-good and reports via the next ACK.

GET /api/v1/policy/stream?channel=stable                 auth: device token
  Accept: text/event-stream
→ 200, SSE. Events:
  event: bundle        data: {"seq":483,"etag":"t7-stable-000483"}     # a hint; edge then GETs §above
  event: revocation    data: {"revocation_epoch":91}                   # fail-closed class: re-check now
  event: ping          data: {}                                        # every 30 s
  event: judge_request data: <protojson m1p.v1.JudgeRequest>            # ADR-0008 edge half (D-EI): adjudicator-svc posts it to
                                                                        # POST /internal/v1/judge-requests (service token); the daemon
                                                                        # runs the judge with the customer's own key for a task it owns
                                                                        # and answers with JudgeVote{locus: CLIENT_SIDE} in its next batch;
                                                                        # no replay — the adjudicator reposts under the same request_id
The stream is advisory push; the poll (with jittered 5-min interval) is the correctness
path. A dead stream degrades latency, never correctness.

POST /api/v1/policy/ack                                  auth: device token
  { "channel": "stable", "seq": "483", "bundle_hash": "sha256:…",
    "result": "applied" | "rejected" | "partial",
    "sections_skipped": ["cortex"],                      # §10.3 — unknown-section negotiation
    "reject_code": "M1E-3001" }                          # absent when result is "applied"
→ 200 { "recorded": true }
`"seq": "483"` is quoted, not a typo: proto3 JSON encodes `uint64` as a string by
spec, and this body is the JSON projection of `m1p.v1.BundleAck`. The SSE hint above
carries `"seq":483` unquoted because it projects no protobuf message.
The ACK ledger is what canary-widening reads: fleet promotion widens only on ACK
evidence plus ledger-observed TVO, and `sections_skipped` counts as non-adoption
for the skipped section.
```

**This body is `m1p.v1.BundleAck` in proto3 canonical JSON, and the mapping is exact except where tabulated below.** `result`, `sections_skipped` and `reject_code` carry free text in the proto for exactly this reason: they are the fields a human reads in an incident, and an enum that projects as `BUNDLE_ACK_RESULT_APPLIED` costs a translation table on both sides to say `applied`. Every remaining divergence is enumerated here rather than discovered — **three, and no fourth**. Two more were raised and are now closed; both are kept below struck through rather than deleted, because a reader who finds the old spelling in a stale branch needs to see that it was considered and which way it went:

| # | Field | Proto | This document | WHY the two differ |
|---|---|---|---|---|
| 1 | `seq` | `uint64` | JSON string `"483"` | proto3 JSON spec: 64-bit integers are strings, because JSON numbers are IEEE-754 doubles and lose precision past 2⁵³. A `uint32` would project as a bare number, but the sequence is per-`(tenant, channel)` and monotonic forever — narrowing the type to flatter a JSON example is the wrong trade |
| 2 | `bundle_hash` | `bytes` (32, raw) | `"sha256:…"` | proto3 JSON renders `bytes` as base64, so the algorithm-prefixed form here is a **presentation** of the same 32 bytes. The prefix is out-of-band metadata the proto deliberately does not carry, so the ACK cannot disagree with `policy_bundles.body_sha256` about encoding |
| ~~3~~ | ~~`bundle_hash` algorithm label~~ | (none — bytes) | `sha256:` | **CLOSED — the label moved, as this row said it would.** It read `blake3:` while 07 and 05 §4.4 both specify SHA-256 over the bundle's canonical bytes, and this row named itself as the side that must move. It has: rows 2 and the §3.2 example above, and `bundle/client.go`'s `hashLabel`, all say `sha256:` now. Resolved while no server counterpart exists to coordinate with, which is the cheapest this change will ever be. Note the neighbouring §8 hashes are **genuinely** BLAKE3 (`fragment.go:116`) — this was one mislabelled field, not a repo-wide convention |
| 4 | `device_id` / `tenant_id` | absent by design | absent | Server-derived from the verified token, never client-asserted — the same rule as §2's envelope (`M1E-8003` on disagreement). There is no field for an edge to assert its own identity into |
| ~~5~~ | ~~`result` vocabulary~~ | `applied` / `rejected` / `partial` | same | **CLOSED — not a divergence any more.** `07`'s `bundle_acks.result` used to store a second three-value vocabulary (`verified_active` / `verify_failed` / `stale_rejected`) with the note that "the ledger stores its mapping" — but no mapping was ever written down, in this document or anywhere else, so the reconciliation was a promise rather than a specification. 05 §4.2 assigns the ACK contract to this section, so the ledger now stores **this** vocabulary verbatim and there is nothing left to map. Nothing was lost: `verify_failed` vs `stale_rejected` is `reject_code` (`M1E-3001`/`3003`/`3005` vs `M1E-3002`), which is finer than the collapsed pair, and the old vocabulary could not express `partial` at all — the one value 05 §4.3(b)'s halt rule reads |

**Gate-direction constraint (normative, from the spec):** a bundle's `gates` section may downgrade a posture closed→open only; anything fail-closed requires a local on-disk tenant opt-in artifact — the control plane cannot remotely tighten an edge into blocking a developer.

### 3.3 Report and query endpoints — the query chokepoint

Every read below is generated and executed exclusively by `controld.query-choke`, the only ClickHouse principal; the builder provably appends the tenant predicate to every query (fuzz + negative tests on every PR). No other component — including other `controld` modules — holds ClickHouse credentials.

```
GET /api/v1/reports/tvo?window=30d&cohort=all&cost_basis=auto     auth: operator token
→ 200 { "tvo": …, "trend": […], "coverage_band": {"observed_fraction": 0.94, "floor": 0.85},
        "cost_basis": "usd" | "quota",                  # never mixed; `auto` splits cohorts
        "task_seg_version": "task_seg.v1",
        "waste": { "retry_loop_tokens": …, "re_exploration_tokens": …, "over_model_tokens": … },
        "price_table_version": "model_prices.v1@sha256:…",   # usd only: the pinned price table the figures were priced under (06 §8.4)
        "guarantee_grade": true | false }
→ 200 with "guarantee_grade": false and "refusal": "M1E-5004 coverage below floor"
        # the number still renders, the guarantee is refused — refused outright, not footnoted
Errors: 400 M1E-2001 (bad window), 403 M1E-1001.

GET /api/v1/reports/interventions?window=…               auth: operator token
→ 200 { "knee_arrests": [ {task_id, tokens_saved_estimate, verdict, bundle_seq} … ] }

POST /api/v1/query                                        auth: operator token
  { "template": "usage_by_session", "params": { … } }     # named templates only — no raw SQL
→ 200 { "rows": […], "template_version": "…" }
Errors: 400 M1E-2008 (unknown template — the chokepoint refuses, it does not improvise).

POST /internal/v1/query                                   auth: intel service credential (ADR-0010 §2.2)
  { "tenant_id": "…", "template": "tvo_task_window", "params": { … } }
→ 200 { "rows": […], "template_version": "…" }            # same registry, same write refusal; the tenant is
                                                          # named in the body because the caller is the driver,
                                                          # not a tenant (never routed through Kong)
Errors: 403 M1E-1001 (credential), 400 M1E-2001 (tenant_id), 400 M1E-2008.
```

WHY templates, not SQL: arbitrary SQL cannot be tenant-predicate-proven by construction; a closed template set can.

### 3.4 Receipt and checkpoint retrieval

```
GET /api/v1/receipts?since_seq=800&limit=500              auth: device or operator token
→ 200 { "receipts": [ { "receipt_seq": 801, "kind": "checkpoint" | "noise_cert" |
          "memory_admission" | "bundle_publication" | "corpus_export" |
          "coverage_transition" | "guard_contamination",
          "payload": "<canonical-json text, verbatim as signed>",
          "device_sig": "ed25519:…", "server_sig": "ed25519:…",
          "key_id": "ed25519:…", "server_key_id": "ed25519:…",
          "prev_hash": "…", "this_hash": "…" } … ],
        "chain_head": { "seq": 5121, "hash": "…", "checkpoint_seq": 412 } }
`server_key_id` was added additively (§10.2) once the verifier existed to consume this
surface: `key_id` names the DEVICE origin key (it rides inside the signed payload) and
the countersigning server key is a row fact the verifier must resolve per-receipt across
rotations — one key_id cannot name two keys, and a verifier that guesses which role a
key served is the S1 the receipt vectors exist to forbid.

`chain_head.checkpoint_seq` was added additively on the same rule, once the EDGE SEALER
existed to consume it (D-CX). This object is the edge's only source for the three numbers
a checkpoint signature covers but a device cannot compute: 07 §checkpoint-model has the
device sign a payload carrying `seq` and `prev_receipt_hash` — per-tenant chain facts that
advance from other devices and from server-written receipt kinds — and `checkpoint_seq`,
which the head lock assigns. The sealer claims `seq+1` / `checkpoint_seq+1` against
`prev_receipt_hash = hash` and the server verifies its signature over exactly that
reconstruction, so a head stating two of the three is a head no device can seal against.
It follows that the head must be re-read before **every** seal rather than cached: a
cached head is stale the moment anything else in the tenant writes a receipt, and the
stale-head failure is a `bad_signature` refusal, not a retryable error.

GET /api/v1/receipts/checkpoints/{checkpoint_seq}         auth: device or operator token
→ 200 { "checkpoint_seq": 5121, "merkle_root": "…", "leaf_count": 4096,
        "first_event_id": "0191…", "last_event_id": "0191…", "receipt_seq": 801 }

GET /api/v1/receipts/inclusion/{event_id}                 auth: device or operator token
→ 200 { "event_id": "0191…", "checkpoint_seq": 5121,
        "inclusion_path": ["blake3:…", "blake3:…", …], "index": 1834 }
Errors: 404 M1E-2009 (event not yet checkpointed — retry after next checkpoint interval).
```

Receipt payloads are returned as the exact canonical text that was signed (`text`, not re-serialized JSON — the vendored `canonical.py` discipline) so the verifier checks bytes, not interpretations.

**Checkpoint payload v2 (ADR-0017, host-bound receipts).** A checkpoint payload is `v` 1 — the eleven keys the receipt vectors freeze — unless the sealed batch holds a leaf of a bound `ext:` session (§4.3 step 2b), in which case it is `v` 2: the same eleven keys plus `hosts` (one entry per session in the batch, sorted by `session_id`: `transport` `fabric`|`jsonl`|`native`, `host_id`, `host_version`, `profile_hash` = sha256 of the ADR-0013 canonical profile, `host_correlation_id`, `tasks[]` of `task_id` with `identity_hash` iff the host declared `supplies_identity`), `arrests_acted` (task-bearing `GuardDecision` leaves — the ACT-only count of §3.3) and `arrests_recommended` (`ArrestRecommendation` leaves). All of it is inside the signed text: the device sends the same facts on `ReceiptCheckpoint.hosts` with `payload_version = 2`, controld rebuilds exactly these bytes to verify the origin signature and countersigns them, and `m1_090` restates the block as `host_bindings`/`arrests_acted`/`arrests_recommended` columns. Verifiers read payload keys by name and hash the stored text, so a v1 verifier accepts a v2 chain; `conformance/vectors/hostchain` locks the bytes across Go, Rust and Python.

### 3.5 Public, unauthenticated-by-design endpoints

```
GET /.well-known/mark1-keys                               auth: NONE, by design
→ 200 { "server_chain_keys":  [ {"key_id","pubkey","not_before","not_after","cross_sig"} … ],
        "bundle_section_keys": [ … ],                    # section-split; update key ≠ bundle key
        "update_keys":         [ … ],
        "tlog": { "uri": "https://tlog.mark1.omium.ai", "head": {"size":…, "root":"…","sig":"…"} } }

GET https://tlog.mark1.omium.ai/v1/{head | entries?start=&count= | proof?leaf=} auth: NONE
GET /healthz  /readyz                                     auth: NONE
```

WHY unauthenticated is safe here — and required: these endpoints serve only public verification material (public keys, log heads, inclusion proofs) and liveness bits. The standalone verifier and any customer script MUST be able to check the chain **without an Omium credential and without Omium's cooperation** — authenticating the verification surface would reintroduce "trust Omium" at exactly the point whose purpose is removing it. Substitution attacks (serving a victim different keys) are what the external witness closes: chain heads and key manifests are anchored hourly in the transparency log and/or the customer's object-lock bucket, so a forked view is detectable by comparison, not prevented by auth. Nothing tenant-identifying is served on any of these paths.

### 3.6 DP-release surface

```
GET /api/v1/federation/releases?since=…                   auth: operator token
→ 200 { "releases": [ { "release_id", "artifact_kind": "workflow_template" |
          "pitfall_remedy" | "routing_hint",             # `invariant` is excluded by schema
          "k": 31, "m": 6, "epsilon_spent": 0.25,
          "receipt_seq": …, "review_status": "approved" } … ] }

GET /api/v1/federation/epsilon                            auth: operator token
→ 200 { "budget": 4.0, "spent": 1.75, "entries": [ {ts, mechanism, epsilon, release_id} … ] }
        # the ε ledger; exhaustion blocks further release, never further capture

POST /api/v1/federation/optout                            auth: operator token
  { "scope": "all" | "artifact_kind:…" }
→ 200 { "effective_at": …, "receipt_seq": … }
```

There is no endpoint that returns another tenant's contribution, pre-DP aggregate, or membership fact — the (k,m)-intersection gate and the DP release layer run inside `controld.dp-release`, and only their outputs have a route.

### 3.7 Memory delivery (06 §9.4–9.5; edge consumer `mark1d/internal/memory`)

**Edge-side memory modes (ADR-0016).** The two endpoints below serve the daemon's cache for every session. What the daemon does with a match is selected by the session's host profile (§4.3 step 2b): for `hostprofile.Default` and a declared host with `owns_memory: false` it injects and records (`MemoryInjection`, `ArtifactOutcome` at close — 06 §9.5); for a **declared host that owns memory** it is in PROPOSE mode — it injects nothing, records neither, **never calls `POST /api/v1/memory/match` for that session** (the reactive tier serves exact cached digests only), and emits one `MemoryProposal` per candidate (§4.2's frame on the host's connection, `<state-dir>/run/proposals/<session-hex>.jsonl`, the ledger). A PROPOSE session contributes nothing to ADMIT-LCB.

```
GET /api/v1/memory/artifacts                              auth: device token
  X-Mark1-Edge-Version: mark1d/<semver>                    # recorded/forwarded, never a rejection axis (§10.1)
  If-None-Match: "<etag>"                                  # optional
→ 200 { "artifacts": [ { "artifact_id", "kind": "pitfall" | "fix_pattern" | "invariant",
          "trigger", "guidance", "utility_lcb", "error_sig_digest"? } … ] }
  ETag: "<sha256 of the body>"   Cache-Control: no-cache
→ 304 Not Modified                                        # exact ETag match; no body
```
The admitted, injectable set for the token's tenant, LCB-ordered (06 §9.4 with d̂ = 0); routing hints (DB kind `preference`) are never served. The body carries no tenant field: the tenant is stamped from the verified token and forwarded to mark1-intel on the internal seam (ADR-0010 §2.2, `INTEL_BASE_URL` + `INTEL_SERVICE_TOKEN`, which intel verifies in turn), never read from the request. Errors: 401 M1E-1002 · 403 M1E-1003 · 502 M1E-9500 (intel unavailable/5xx/deadline; the edge keeps last-known-good) · 503 M1E-9500 (memory service not configured).

```
POST /api/v1/memory/match                                 auth: device token
  { "error": "<PostToolUseFailure text, ≤4096 chars>", "limit": 3 }   # exactly these fields; ≤64 KiB
→ 200 { "artifacts": [ { …as above…, "distance": 0.05 } … ], "signature_digest": "<sha256 of the normalized signature>" }
```
The reactive fuzz tier (06 §9.5 D29): admitted `pitfall` artifacts within cosine 0.15 over the one halfvec HNSW column, at most `limit` ≤ m_inject = 3. The server hop is deadline-bounded at 1.5 s, the edge's own budget. A `tenant_id` (or any unknown field) in the body is refused, not ignored. Errors: 400 M1E-2001 (malformed/oversize body, unknown field, or intel refused the request) · 401 M1E-1002 · 403 M1E-1003 · 502 M1E-9500 · 503 M1E-9500. No §8.2 rate-limit row exists yet for these two routes.

### 3.7a Device consents (desktop onboarding Step 4; 04 §2.7, 07 `m1_082`)

```
PUT /api/v1/consents                                      auth: device token (a user token is refused)
  { "e1": bool, "cloud_judge": bool, "training": bool }   # exactly these three, all present; ≤4 KiB, unknown field refused
→ 200 { "recorded_at": "<RFC 3339>" }
```
The body is the device's whole consent state, not a patch: each PUT appends one `m1_device_consents` row stamped with the token's `(tenant, device)`, and the latest row per device is that device's consent (the table is append-only; history stays answerable). The edge relays the same record it wrote to `<state>/gates/consents.json` and keeps it pending until acknowledged, so the cloud's view never runs ahead of the local one. Consumers: `e1` gates `EmitExcerpt`'s E1 case on the edge (a `Dropped{e1_consent_absent}` row when absent); `cloud_judge` is the §3.8 judge path's precondition; `training` gates `corpus.export` — the job runs only when every device of the tenant that has ever recorded consent currently consents (`bool_and` over latest rows; a tenant with no rows is refused, never assumed). Errors: 400 M1E-2001 (shape) · 401 M1E-1002 · 403 M1E-1001 (no device claim) · 503 M1E-9500 (store unavailable or unconfigured).

### 3.8 Internal service surface (never public; service credential, ADR-0010 §2.2)

```
POST /internal/v1/receipts/append                         auth: Bearer <INTEL_SERVICE_TOKEN>
  { "tenant_id", "record_type": "noise_certificate" | "memory_admission" | "bundle_publication"
                              | "corpus_export" | "verifier_promotion",
    "subject_id", "idempotency_key", "payload": { …integers and strings only… } }
→ 200 { "receipt_id", "seq", "receipt_hash", "payload" }
```
The one chain writer (m1_002 §5): the intelligence services hold no chain key and no `m1_receipts` INSERT grant; they request their per-event rare-class receipts here and commit their own row in the same local transaction AFTER the receipt id returns. The credential is asserted before the body is decoded; the tenant comes from the body only because the verified principal is the service. Idempotency is keyed on the caller's attempt — `(tenant, record_type, idempotency_key)`, m1_072 — never on `subject_id` (re-admission and cert re-issue legitimately repeat a subject); a repeat answers the existing receipt. Errors: 401/403 on the credential, 400 on a class outside the set above or a payload the canonical form refuses.

---

## 4. The local fabric (UDS / Windows named pipe)

Class: **internal** (all endpoints ship in one signed package), but fully specified because it crosses the Rust/Go language boundary and is fuzzed in CI.

### 4.1 Endpoint and permissions

```
Linux/macOS:  ~/.omium/mark1/mark1d.sock         mode 0600, owned by the enrolling user;
                                                 parent dir ~/.omium/mark1/ mode 0700
Windows:      \\.\pipe\omium-mark1d              DACL: current user SID only (no Everyone,
                                                 no NETWORK), created by mark1d
```

- `mark1d` creates the socket at startup (unlink-then-bind; refuse to start if the path is a symlink — `M1E-4001`).
- On connect, `mark1d` verifies the peer: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) UID must equal the daemon's UID; named-pipe impersonation-level check on Windows. UID mismatch ⇒ immediate close + a `GuardDecision`-class security event. Filesystem permissions are the first wall; peer-cred verification is the second — neither alone is trusted.
- **Writers:** `mark1-hookshim`, `mark1-proxy`, `cortexd`, and the transcript tailers (in-process in `mark1d`, listed for completeness). **`mark1d` is the only spool writer.** No other process opens, appends to, or truncates a spool segment, ever — single-writer is what makes "one durability implementation" true and is why the cgo boundary was deleted.

### 4.2 The `M1PL` frame contract

```
offset  size  field
0       4     magic     = ASCII "M1PL" (0x4D 0x31 0x50 0x4C)
4       1     ver       = 0x01
5       4     len       = u32, little-endian, length of payload in bytes
                          BOUNDED: 0 < len ≤ M1PL_MAX_FRAME = 4_194_304 (4 MiB).
                          len == 0 or len > M1PL_MAX_FRAME is a protocol error: the
                          reader closes the connection (M1E-4002) and the writer
                          spills locally.
9       len   payload   = one serialized m1p.v1.FabricFrame — a oneof carrying
                          an Event or a control message from the set below.
                          D-U: the oneof IS the Event-vs-control discriminator
                          this line used to leave implicit (proto3 bytes are
                          not self-describing); 07 §5 owns the ruling.
```

**`M1PL_MAX_FRAME` is stated here exactly once and referenced everywhere else in this document.** Its normative definition is doc 07 §5, which owns the framing bytes; 07 §6 derives the spool record bound `20 < len ≤ 4_194_324` from it, so a second copy that drifts silently invalidates the spool's bound too. The conformance vectors freeze the value (doc 12 §3.4), which makes drift a build failure rather than a field incident.

Both halves of the bound are load-bearing, and the lower half is the one a decoder written as `if len > MAX` quietly omits: a zero-length frame is not an empty `Event`, it is a desynchronized stream, and continuing to read from it is how a decoder starts interpreting payload bytes as headers. The upper half caps the allocation any single corrupt or hostile length prefix can demand at 4 MiB instead of 4 GiB.

No checksum in the frame — the transport is a reliable local byte stream; integrity-at-rest is the spool's crc32c, integrity-in-flight is the kernel's. The decoder (both the Rust encoder in `m1p-wire` and the Go decoder in `mark1d`) is fuzzed in CI against shared conformance vectors; a Go/Rust disagreement on any vector fails the build, and the `m1pl` rejection vectors (12 §3.4) cover `len == 0` and `len == M1PL_MAX_FRAME + 1` explicitly.

Control messages (defined in `m1p.v1`, doc 07; they never reach the spool or the wire):

| Message | Direction | Purpose |
|---|---|---|
| `Hello{component, pid, version, session_id, cwd, host_correlation_id}` | writer → mark1d | First frame on every connection. `cwd` (2026-09-20) is the writer's working directory — a hook process runs in the agent's project root — and stays on this socket: mark1d maps it to an enabled workspace and stamps `SessionStart.workspace_id` (the HMAC) from it; the path itself never enters an event. `host_correlation_id` (ADR-0012, 2026-10-02) is an external host's own session reference, ≤ 256 bytes, opaque: stored beside the Mark 1 session for later receipt echo, never used as a Mark 1 identity; empty from first-party writers. `mark1d` replies `HelloAck{accepted: true, max_frame: M1PL_MAX_FRAME, session_id}` or closes. The symbol, not a re-typed literal — §4.2 is the only place the value appears. `max_frame` is the daemon telling the writer which build it is talking to, **not a negotiated ceiling**: a writer that reads a smaller value may send smaller frames, never a larger bound than §4.2's. `HelloAck.session_id` is set only when the daemon minted the session for an `ext:` writer (§4.3 step 2a); empty otherwise. |
| `GateQuery{task_id, gate: STOP\|TOOL, deadline_ms}` | hookshim → mark1d | Read the cached `VerdictEvent{PROVISIONAL}` and knee state for a gate decision. |
| `GateVerdict{decision: ALLOW\|BLOCK, verdict, posterior[4], reason, evidence_ref, system_message, recommendation}` | mark1d → hookshim / `ext:` writer | The reply. **The gate reads the cache; it never computes** — this round-trip is a map lookup, budgeted ≤ 5 ms. `recommendation` (ADR-0015, §4.7) is set only for a session in `ARREST_MODE_RECOMMEND` where ACT would have blocked or arrested; the decision is then `ALLOW`. |
| `ArrestRecommendation{kind, reason, k_star_estimate, projected_cost, task_id, turn, session_id, evidence_ref}` | mark1d → `ext:` writer | ADR-0015, §4.7. An unsolicited daemon→writer frame: pushed to the bound `ext:` connection of a session in `ARREST_MODE_RECOMMEND` when the gate's judgement would have acted. Never sent to a first-party writer. The same message is the `Event.body.arrest_recommendation` family in the ledger. |
| `MemoryProposal{artifact_id, category, candidate_trigger, candidate_guidance, evidence, channel, session_id, task_id}` | mark1d → `ext:` writer | ADR-0016, §3.7. The other unsolicited daemon→writer frame: pushed to the bound `ext:` connection of a session whose declared host owns memory, once per candidate memory would have injected. Never sent to a first-party writer. The same message is the `Event.body.memory_proposal` family in the ledger. |
| `Flush{}` / `FlushAck{drained: n}` | writer → mark1d → writer | Mandatory drain barrier on SessionEnd/shutdown. |

### 4.3 Handshake

1. Writer connects; OS-level peer checks run (§4.1).
2. Writer sends `Hello` as its first frame. Any other first frame ⇒ close (`M1E-4003`). `Hello.session_id` is REQUIRED, 16 bytes, non-zero (D-AT): a missing, wrong-length or all-zero id ⇒ close (`M1E-4003`).
   - 2a. **External writers (ADR-0012).** A `Hello` whose `component` starts with `ext:` MAY carry an **empty** `session_id`. `mark1d` then mints a UUIDv7 session and returns it in `HelloAck.session_id`; the writer echoes it in `Event.session_id` on every frame of that connection. An `ext:` writer that sends a 16-byte id is bound to that id and nothing is minted. A wrong-length or all-zero id is the ordinary D-AT refusal — minting is for an empty field only, never a repair.
   - 2b. **Host profile manifest (ADR-0013).** After binding, `mark1d` reads `Hello.host_manifest` (`m1p.v1.HostManifest`, fabric.proto). **Absent ⇒ the session's profile is `hostprofile.Default`** — today's behaviour, exactly: Mark 1 owns the config surface and memory, acts on an arrest, the writer does not own execution. **Present on an `ext:` connection ⇒ validated:** `host_id` and `host_version` non-empty; `arrest_mode` is `ARREST_MODE_ACT` or `ARREST_MODE_RECOMMEND` (`UNSPECIFIED` is an error when a manifest is present); `owns_execution` is `true` (an `ext:` writer owns its loop by definition); `schema_version` is in the accepted set, currently `{"m1p.v1"}`. Any failure ⇒ close with **`M1E-4007`**, logged once. **Present on a non-`ext:` connection ⇒ close `M1E-4007`**: hookshim and cortexd never send one, so its presence there is a bug, not a request. The resolved profile is stored on the session and reaches provisioning, the gate and memory through the admission session context; in this revision they log it and decide nothing on it. The file-tail transport carries the same message as the sidecar's `host_manifest` block (07 "Partner event files") through the same validator. The handshake also logs whether `host_id` is a known host (the informational registry, ADR-0013 §5); unknown hosts are not refused.

     ```
     Hello{component: "ext:cem888/runner@2.0.1", host_correlation_id: "run-7781",
           host_manifest: {host_id: "cem888", host_version: "2.0.1",
                           owns_execution: true, owns_config_surface: true, owns_memory: true,
                           arrest_mode: ARREST_MODE_RECOMMEND, supplies_identity: true,
                           schema_version: "m1p.v1"}}
     ```
3. `mark1d` replies `HelloAck`. Version negotiation is the single `ver` byte: `mark1d` accepts exactly the versions its release ships; a mismatch closes with `HelloAck{accepted:false, want_ver}` — possible only mid-upgrade, and loud.
4. After `HelloAck`, the connection is a unidirectional event stream (plus `GateQuery`/`Flush` request-reply where the component uses them). Event frames are **fire-and-forget: no per-event ack.** Durability is the spool's job, not the fabric's.
   - 4a. **Session echo, `ext:` connections only (ADR-0012).** On an `ext:` connection every decodable `Event` must carry `session_id` equal to the bound session; any other value ⇒ close (`M1E-4003`) before admission. First-party writers (hookshim, proxy, cortexd) and the §4.5 loopback door are **not** checked by this rule: their events are attributed by their own `session_id` exactly as before, and widening the rule is a separate decision (ADR-0012 §"Not decided here").

### 4.4 Backpressure and deadlines

| Parameter | Value | WHY |
|---|---|---|
| Connect timeout | 100 ms | A hook process has a 50 ms fire-and-forget budget; if the daemon is absent, spill immediately rather than stall the agent. |
| Event write deadline | 250 ms | Bounded by the writer, enforced with socket write timeouts. |
| `GateQuery` deadline | carried in the frame; ≤ the agent hook's own budget minus 10 ms | The shim, not the daemon, owns the agent-facing deadline. |
| Read-side buffer in `mark1d` | 4 MiB per connection, then TCP-style backpressure (stop reading) | When a billing-grade spool class blocks-on-full, backpressure propagates to writers by design — blocking beats silent loss for billing-grade classes. |

Writer behavior when a deadline trips or the daemon is unreachable, per component:

- **hookshim:** never blocks the agent past its budget. It appends the event to its **sanitized spill file** (`~/.omium/mark1/spill/hookshim.ring`, 0600, device-key-encrypted, ≤24 h TTL with receipted expiry). The shim links `mark1-redact`, so even emergency spill is post-redaction. On next successful connect it replays the ring, then truncates. For a `GateQuery` timeout the shim returns **allow** to the agent (capture and gating are fail-open for availability) and emits `Dropped{reason: gate_timeout}`.
- **proxy:** uses its own Rust tee spill ring (same rules: post-redaction, 0600, encrypted, TTL'd); the client-facing byte stream is never held by fabric backpressure — the tee is structurally unable to hold a client write.
- **cortexd:** drops push-map refreshes (recomputable) and counts `Dropped{reason: fabric_unavailable, durability_class: DIAGNOSTIC}`.

### 4.5 Fallback loopback listener

Where an agent surface cannot exec the shim (it can only call HTTP), `mark1d` exposes a loopback listener. It is OFF unless an enabled adapter requires it.

```
Bind:      127.0.0.1:<random high port>, chosen per boot; never 0.0.0.0, never ::
Discovery: port + token written to ~/.omium/mark1/loopback.json   (0600)
Auth:      Authorization: Bearer <per-session token from that file> — REQUIRED
Host:      MUST be literally "127.0.0.1:<bound port>" (the exact bound literal).
           Anything else — "localhost", a hostname, a mismatched port — ⇒ 403 M1E-4004.
           WHY literal: DNS-rebinding sends a browser to attacker.example resolving to
           127.0.0.1; the Host header then carries the attacker's name. Literal matching
           makes rebinding structurally inert.
Origin:    ANY Origin header present ⇒ 403 M1E-4005. No CORS, no preflight answer.
           A legitimate caller is a local process, never a browser page.
Routes:    POST /m1pl        body: one m1p.v1 event (JSON encoding), same semantics as a frame
           POST /m1pl/gate   body: GateQuery JSON → GateVerdict JSON, same 5 ms cache-read budget
Responses: 204 (event accepted), 200 (gate verdict), 400 M1E-2001, 401 M1E-1002,
           403 M1E-4004/4005, 429 M1E-9001 (per-session rate cap).
```

The loopback listener accepts events **only** for sessions whose token it issued; it is a constrained door into the same single-writer spool path, not a second fabric. **It is not an external-writer transport** (§4.6): it has no `Hello`, so no `ext:` identity, no session binding and no `host_correlation_id`. A third-party host uses the socket or the file-tail mode.

### 4.6 External writers — the `ext:` contract

Class: **external writer** (§1.1) — public, versioned, additive-only within `m1p.v1`. ADR-0012 is the decision record; `docs/integrating-a-host.md` is the partner-facing walkthrough of exactly this section. An *external writer* is a third-party agent runtime that owns its own execution loop and hands Mark 1 events it did not harvest itself. Two transports carry the same contract; downstream of admission nothing can tell them apart.

**Scope rule.** Everything below is additive to §4.1–§4.4. Nothing here changes what `mark1-hookshim`, `mark1-proxy`, `cortexd` or the transcript tailers send or receive; the `ext:` branches are keyed on the `component` prefix and are inert for every other writer.

#### 4.6.1 Transport A — the socket

| Item | Contract |
|---|---|
| Endpoint discovery | `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`, else `~/.omium/mark1/m1p.sock` (07 §5; `fabric.SocketPath`). Windows: `\\.\pipe\omium-mark1-<user-SID>` where the SID is the calling user's. Owner-only on both; a host runs as the same OS user as the daemon or it cannot connect, by design (§4.1). |
| Framing | §4.2 verbatim: `M1PL` \| `ver=0x01` \| `len` (u32 LE, `0 < len ≤ M1PL_MAX_FRAME`) \| one serialized `m1p.v1.FabricFrame`. Reference codecs: `rust/m1p-wire/src/framing.rs`, `go/mark1d/internal/fabric/framing.go`; vectors in `conformance/vectors/m1pl/`. |
| `Hello.component` | `ext:<vendor>/<product>@<version>`, e.g. `ext:acme/runner@1.2.3`. The `ext:` prefix is the switch for everything below; the rest is free text carried for `mark1 doctor`. |
| Session binding | §4.3 step 2a: `session_id` empty ⇒ the daemon mints a UUIDv7 and returns it in `HelloAck.session_id`; the host echoes it in `Event.session_id` on every frame. A host that does hold a 16-byte id may send it and is bound to it. |
| `Hello.host_correlation_id` | Optional, ≤ 256 bytes, the host's own run or thread reference. Stored beside the session; never a Mark 1 identity (ADR-0012 §3). |
| `Hello.cwd` | Optional. When set to the project root the daemon stamps `SessionStart.workspace_id` from it exactly as for a hook process; the path never enters an event. |
| Session echo | §4.3 step 4a: a decodable `Event` naming any session other than the bound one ⇒ close `M1E-4003`, before admission. |
| Drain | `Flush`/`FlushAck` as §4.2: send `Flush` after `SessionEnd` and wait for the ack before exiting; `drained` counts this connection's admitted events. |
| Not available to `ext:` writers | `ContextQuery`, `ContaminationAlert`. These arms answer exactly as for any writer but carry no contract for hosts. `GateQuery` IS available to an `ext:` session in `ARREST_MODE_RECOMMEND` (§4.7, ADR-0015): the reply's `recommendation` is the gate's judgement for the host's own loop; in `ARREST_MODE_ACT` a host that queries is gated like a shim. |

#### 4.6.2 Transport B — the JSONL file-tail mode

For integration and phase-one testing without a socket client. The host appends to a file; `mark1d` tails it through the **same admission door** the socket uses (`admitPath`, cmd/admit.go).

```
File:        <name>.jsonl            append-only; one m1p.v1.Event per line, protojson
Sidecar:     <name>.manifest.json    written BEFORE the first event line; this is the file's Hello
             {"component": "ext:acme/runner@1.2.3",
              "host_correlation_id": "run-7781",         optional, ≤ 256 bytes
              "schema_version": "m1p.v1"}                required, exactly "m1p.v1"
Discovery:   mark1d --partner-events <path>[,<path>...]  explicit files, plus every *.jsonl under
             <state-dir>/partner/                         (~/.omium/mark1/partner/, 0700)
```

- **Sidecar ≡ `Hello`.** The daemon reads the sidecar on first open and binds the file the way §4.3 step 2a binds a connection: `component` must carry the `ext:` prefix, the session is minted once, and the minted id is persisted in the file's tailer cursor so a daemon restart resumes the SAME session. A missing or unreadable sidecar, a non-`ext:` component or a `schema_version` outside the accepted set ⇒ the file is not tailed, logged once (`M1E-4003`, the same code as a refused `Hello`), re-checked on the next discovery tick.
- **Lines.** `Event.session_id` is left empty (the host does not know the minted id) and the daemon stamps it; a line that names a different, non-empty session is quarantined and accounted (`Dropped{LOCAL_QUARANTINE}`) and the tail continues — the file analogue of §4.3 step 4a, where there is no connection to close. An undecodable line is quarantined and accounted the same way. Unknown fields are ignored, as protojson's `DiscardUnknown` permits within a major.
- **Offsets, rotation, resume** follow the transcript tailers' rules (04 §2.1): the cursor is keyed by file identity, advances only over whole `\n`-terminated lines (a torn last line waits for the next poll), rotation drains the old inode then follows the new file from offset 0, and truncation re-scans from 0. **Set `event_id` yourself** (a UUIDv7 per line): ingest dedupes on it, so a re-scan is idempotent server-side; without it a truncation replay duplicates diagnostic-class events.

#### 4.6.3 The `Event` envelope from an external writer (both transports)

| Field | Rule |
|---|---|
| `event_id` | 16 bytes, UUIDv7, RECOMMENDED. Minted by the daemon when empty. |
| `seq`, `session_epoch` | MUST be zero. Assigned at admission (07 §2); a non-zero value is overwritten, never trusted. |
| `session_id` | Socket: the bound session, every frame. File: empty. |
| `task_id` | SHOULD be empty. The daemon segments under `task_seg.v1` (ADR-0002) from your `Turn` events — see the minimum set. |
| `occurred_at` | Your wall clock at the event. Display and skew analysis only; **lines/frames must be in causal order and `occurred_at` must be non-decreasing** within a session. `seq` is the daemon's, not yours. |
| `tenant_id`, `device_id`, `received_at`, `clock_skew_ms` | MUST be unset (server-stamped band); cleared at admission. |
| `Usage.idem_key` | **Stamped by the daemon** for every `ext:` session, per the events.proto recipe over `(session_id, message_id, request_id)`. A non-empty writer value is overwritten and the overwrite is logged once per session at debug (ADR-0012 §4). Send `message_id` and `request_id`; leave `idem_key` empty. |

**Minimum event set** an external host emits, in the order they occur:

| Event | When | Notes |
|---|---|---|
| `Turn{initiator: INITIATOR_HUMAN}` | each new user intent | **This is what opens a Mark 1 task** (task_seg.v1 R1). Emit one per intent; the daemon mints `TaskOpen`. |
| `TaskOpen` | when your own loop opens a unit of work | Recorded as your declared boundary: `task_seg_version` is your string (e.g. `ext:acme/runner.v1`), `task_id` as you set it or empty. The daemon's receipted denominator remains the `task_seg.v1` task it mints from your `Turn`s; host-declared boundaries become authoritative only under a later host-profile feature. |
| `Turn{initiator: INITIATOR_AGENT}` | each attempt your loop makes | counted into `TaskClose.turn_count`. |
| `ToolUse` | each tool call, with `status` and `duration_ms` | optional but expected; built-in names pass literally, anything else is HMAC'd (events.proto). |
| `Usage` | each model response, with `message_id`, `request_id`, `model`, token counts | billing-grade: blocks on a full spool, never shed. |
| `ArtifactOutcome` | when you claim an outcome for the unit of work | `task_verdict` from the one `Verdict` vocabulary (artifacts.proto). |
| `TaskClose` | when your loop closes the unit of work | as `TaskOpen`: your declared boundary, recorded. |
| `SessionStart` / `SessionEnd` | lifecycle, first and last | RECOMMENDED. `SessionStart.agent` is your product name; `capture_paths` empty. `SessionEnd` closes the daemon's open task (`RESOLUTION_UNRESOLVED_SESSION_END` unless a verdict closed it) and triggers the drain. |

The five-event floor `conformance/vectors/ext/` pins is `TaskOpen`, `TaskClose`, `Turn`, `Usage`, `ArtifactOutcome`; `mark1 validate-events` (§7.8) checks the ordering above on a file before you ever connect.

#### 4.6.4 What the daemon does on bad input

| Input | Socket | File-tail |
|---|---|---|
| Framing violation (`len` out of bound, bad magic) | close, `M1E-4002` (§4.2) | n/a |
| Duplicate oneof arm, unknown arm, non-`Hello` first frame | close, `M1E-4003` | n/a |
| `Hello` without `ext:` and without a session; malformed session; `host_correlation_id` > 256 bytes | close, `M1E-4003` | file not tailed, logged once |
| `Event` naming the wrong session | close, `M1E-4003` | line quarantined, accounted, tail continues |
| Undecodable `Event` payload / line | quarantined and accounted (`Dropped{LOCAL_QUARANTINE}`), connection lives | same |
| Event over the 1 MiB admission bound (07 §6) | quarantined and accounted | same |
| Billing-grade event under a full spool | the read stalls (backpressure, §4.4); the host's write blocks | the tail stalls at that line |

A quarantine is never silent: it rides the next batch's `Dropped{}` (07 §3) and `mark1 doctor` counts it.

### 4.7 Arrest modes (ADR-0015)

The session's host profile (§4.3 step 2b) selects what happens **after** the gate's judgement. Detection — task resolution, the cached verdict, the knee state — is the same in both modes.

| Mode | Who | At a block / cap / knee stop |
|---|---|---|
| `ARREST_MODE_ACT` | every session that declared nothing (`hostprofile.Default`: hookshim, cortexd, tailers, loopback) and any `ext:` session that chose it | today's path, unchanged: `GateVerdict.decision = BLOCK` below the knee and at the cap; the knee stop's `system_message` to the human; `GuardDecision{BLOCKED \| ARRESTED}` in the ledger; the control API's `arrest` row and SSE event. |
| `ARREST_MODE_RECOMMEND` | an `ext:` session that declared it | `decision` stays `ALLOW` and **no `GuardDecision` is recorded**. One `ArrestRecommendation` (`kind`: `stop_gate_block` \| `knee_arrest` \| `block_cap`; `reason`; `k_star_estimate`; `projected_cost`; `task_id`; `turn`; `session_id`; `evidence_ref`) is delivered on four paths: the `GateVerdict.recommendation` reply, a `FabricFrame{arrest_recommendation}` pushed to the bound `ext:` connection, one protojson `Event` line appended to `<state-dir>/run/recommendations/<session-hex>.jsonl` (for file-tail hosts), and the control API's SSE stream (`event: recommendation`) — and it is admitted as a ledger `Event` (`Event.body.arrest_recommendation`, diagnostic class). |

**Counting.** The arrest and block counts and the `tokens_saved` sum behind receipts, §3.3 reports and the desktop session row read `GuardDecision` rows and therefore count ACT only. Recommendations are counted from their own family: the edge's verify ring (`type: recommendation`) and `mark1.arrest_recommendations` (migration `m1_ch_003`), a materialized view over `m1p_events` rows of that type. A recommendation the host ignored saved nothing and claims nothing.

**projected_cost** is the daemon's estimate of what the next attempt would spend — the same figure an acted arrest records as `tokens_saved_estimate` — so a host can weigh the recommendation in the daemon's own units.

---

## 5. Per-agent hook contracts

Rules common to all seven adapters:

1. **Field maps live in bundle data, not code.** The mapping from each agent's JSON payload to `m1p.v1` events ships in the `agent_maps` section of PolicyBundle v1. A vendor format break is a bundle push, not a release.
2. **Version sniffing, typed drops.** Every adapter sniffs the agent version at session start; an unmapped version emits `Dropped{reason: unsupported_agent_version}` and captures nothing speculative. Adapters never guess a field.
3. **Spike gating.** An adapter slot opens only when its go/no-go spike artifact lands in `conformance/` (recorded fixtures per pinned agent version). Where a payload below is marked `UNVERIFIED — spike gates this adapter slot`, that is the contract: the spike produces the fixture; the fixture produces the field map; nothing is authored from memory.
4. **Hook payloads carry no token usage on any surface verified so far.** Usage comes from transcripts or the wire (API-key regime), never from hook JSON.
5. **Timing.** The shim's observer budget is 50 ms fire-and-forget (frame the event, hand off or spill, exit 0). Gate hooks — and the two context pulls, `UserPromptSubmit` (the pack) and, since D-EI, `PostToolUse` (the next-turn `CORRECTION`) — carry a bounded deadline (the 250 ms pack budget minus the 10 ms margin) and fail-open to *allow* / print nothing on timeout — Mark 1's absence must never block a developer.

### 5.1 claudecode (Claude Code) — verified 2026-08-28 against vendor docs and on-disk transcripts

**Registration.** Hook entries of `type: "command"` invoking `mark1-hookshim`, provisioned per §8 into Claude Code settings (`~/.claude/settings.json` scope by default). Hook config levels merge; a duplicated handler runs once. Claude Code strips `OTEL_*` exporter variables from every hook subprocess — irrelevant to Mark 1 (zero OpenTelemetry anywhere), noted so nobody "fixes" it.

**Events Mark 1 registers, what it reads, what it may return:**

| Hook event | Matcher | Fields read (exact vendor names) | Mark 1 returns | Deadline set in fragment |
|---|---|---|---|---|
| `SessionStart` | `*` | `session_id`, `transcript_path`, `cwd`, `source` (`startup\|resume\|clear\|compact\|fork`), `model` (optional — the only event that may carry it) | `hookSpecificOutput.additionalContext`: the budgeted cortex ranked map + memory pack (1–8k tokens, budget-binary-search). Emits `SessionStart` + `CortexInjection`/`MemoryInjection` events | 10 s (map is precomputed; this is a read) |
| `UserPromptSubmit` | n/a (no matcher support) | common fields + `prompt` | `hookSpecificOutput.additionalContext` (map/memory refresh when the index clock moved); never `decision:"block"` — Mark 1 does not veto prompts | 5 s (vendor default here is 30 s; a stuck hook stalls the session, so we undercut it) |
| `PreToolUse` | `*` | common + `tool_name`, `tool_input`, `tool_use_id`, `permission_mode` | Nothing (observer; emits `ToolUse` open). Mark 1 does not use `permissionDecision` — it is not a permission product | 5 s |
| `PostToolUse` | `*` | above + `tool_response`, `duration_ms` | `hookSpecificOutput.additionalContext` only when a slow anchor produced a `REVISED` verdict since the last turn (the next-turn correction path). Fast anchors refresh the fusion cache on the debounce this event drives | 5 s |
| `PostToolUseFailure` | `*` | common + `tool_name`, `tool_input`, `tool_use_id`, `error`, `is_interrupt`, `duration_ms` | `hookSpecificOutput.additionalContext`: reactive pitfall–remedy injection (C8). Keys on `tool_name`, `is_interrupt`, and the `Exit code N` first line of `error`; the rest of `error` is display text, not a stable format | 5 s |
| `Stop` | n/a | common + `stop_hook_active`, `last_assistant_message` (use this, not the transcript — the transcript is written asynchronously and may lag the turn) | **The stop-gate.** Reads the cached `GateVerdict` (§4.2) and: below the knee ⇒ `{"decision":"block","reason":"<verdict + failure evidence as continuation reason>"}`; at the knee ⇒ exit 0 with no decision (Claude stops) plus `systemMessage` surfacing verdict + evidence to the human. Hard caps checked **before** the gate: `MARK1_DISABLE=1`/`mark1 off`, `stop_hook_active`, ≤3 consecutive blocks per task, hourly block ceiling. (Claude Code's own cap is 8 consecutive blocks; ours is tighter and hits first.) Never `continue:false` | 30 s |
| `SubagentStop` | `*` | common + `stop_hook_active`, `agent_id`, `agent_type`, `agent_transcript_path`, `last_assistant_message` | Observer only in v1 (emits lifecycle events; subagent gating is not a v1 surface) | 5 s |
| `PreCompact` | `manual,auto` | common + `trigger`, `custom_instructions` | Nothing (emits a context-lifecycle event so TVO attribution can see compaction boundaries) | 5 s |
| `SessionEnd` | `*` | common + `reason` (`clear\|resume\|logout\|prompt_input_exit\|other`) | Nothing returnable (vendor discards JSON output on this event). Triggers `Flush{}` — the mandatory spool drain. Vendor budget: 1.5 s default, raised to the highest configured `timeout` up to 60 s; the fragment sets 30 s | 30 s |

Payload shape notes (vendor-verified): common fields on every event are `session_id`, `transcript_path`, `cwd`, `hook_event_name`, plus `permission_mode` and `prompt_id` where the event carries them, and `agent_id`/`agent_type` inside subagents. Exit-code semantics: exit 0 + JSON stdout is the only mode the shim uses; exit 2 is never used (its blocking semantics duplicate `decision`, and exit 1 does not block). Hook output strings, including `additionalContext`, are capped by the vendor at 10,000 characters. **DECISION D-AF (lead, binding, 2026-08-30): the previous sentence here — "which the 8k-token map budget already guarantees" — was false, and false in the dangerous direction.** The cap counts *characters*; the budget counts *tokens*, estimated as `ceil(len/4)` (`cortexd::map::estimate_tokens`). A rendering that satisfies an 8k-token budget may therefore run to **32,000 characters — 3.2× over the vendor cap**. The documented ceiling did not guarantee compliance; it guaranteed violation. The largest token budget that provably fits is **2,500**, and the 2k default leaves only ~2,000 characters for the memory pack and the JSON envelope *combined*, so even the default is tight rather than comfortable. Three binding consequences: (1) the token budget remains the product knob and the bundle-tunable field, because it is what a tenant reasons about and what the map and memory pack share, but the render fit predicate gains a **second ceiling** — a candidate fits only if it is under the token budget **and** under the character cap; (2) the **clamp lives at the shim's serialization boundary**, applied to the *concatenated* injection, because the map and the memory pack have different producers and only the shim sees the string the vendor will actually receive — a per-producer budget cannot enforce a shared cap; (3) truncation is **flagged, never silent** — `MapRender.truncated` already exists but `CortexInjection` has no field to carry it, so one is added (`bool truncated = 6`, additive, alongside D-AE's oneof arms as a Phase 4 build row). This is not bookkeeping. `CortexInjection.tokens_used` is stated in this document as "the join key for TVO's `reexploration_tokens` term, which is claimable only where a `CortexInjection` exists" — and the character clamp fires at the **shim**, downstream of cortexd, which is the process that reports `tokens_used`. Without a truncation signal the ledger therefore **over-attributes reexploration tokens to map content the model never received**, silently corrupting an input to the product's own headline metric. An injection the vendor discarded and an injection Mark 1 never built are indistinguishable to a developer; they must not be indistinguishable to us, and above all they must not be indistinguishable to TVO. Truncation cuts on a whole-file block boundary — a ranked map ending mid-symbol signature is worse than a shorter honest one. `additionalContext` is delivered as a system reminder; on `--resume` the saved text is replayed rather than the hook re-run, so injected content MUST be safe when stale (facts, not imperatives). **No hook payload carries token usage** — the transcript tail below is the sole `Usage` source in the subscription regime.

**Transcript-tail contract (the `Usage` source):**

```
Path:        primary — the transcript_path field delivered in every hook payload.
             fallback derivation (tailer discovery without a hook event):
             ~/.claude/projects/<munged-cwd>/<session-id>.jsonl
             where <munged-cwd> = absolute cwd with '/' replaced by '-'
             (e.g. /home/anurag/workspace/Omium → -home-anurag-workspace-Omium).
             Subagent transcripts: <same dir>/<session-id>/subagents/agent-<agent_id>.jsonl
             (path taken verbatim from SubagentStop.agent_transcript_path when available).

Line format: JSONL. The tailer reads ONLY lines whose message carries usage; assistant
             lines carry BOTH `requestId` and `message.id`, plus
             message.usage = { input_tokens, output_tokens,
                               cache_creation_input_tokens, cache_read_input_tokens,
                               service_tier }.

Dedupe rule (protocol invariant, not parser etiquette):
             one Usage event per unique (message.id, requestId), last-write-wins —
             streaming appends multiple partial assistant lines under the same pair
             with cumulative usage; emitting per line is the verified ~2.5× overcount.
             idem_key = HMAC_tenant(session_id, message.id, request_id) makes the rule
             enforceable end-to-end: ingest upserts on idem_key, so even a tailer bug
             cannot double-count.

Sidechain rule:
             a Usage event is attributed to the transcript in which the API call
             originated. Sidechain (sub-agent) content replayed into the parent
             transcript is NOT re-emitted; because the replay carries the same
             (message.id, requestId), the idem_key collapses it by construction even
             if a tailer misclassifies. Subagent transcripts are tailed as their own
             streams under the parent session_id.

Scope:       tailers run only inside `mark1 enable`d workspaces, honor `.mark1ignore`,
             and read transcript files only — never `file-history/` snapshots unless
             tenant-enabled (and then only local diff stats compute).

Retention (vendor): transcripts auto-delete after `cleanupPeriodDays` (default 30,
             minimum 1, 0 invalid) via a background sweep after session start.
             IMPLICATION FOR BACKFILL: the transcript is a live capture surface, not
             an archive. At enrollment, backfill recovers at most the trailing
             retention window, is labeled as backfill in coverage accounting, and is
             never guarantee-grade (pre-enrollment CoverageTransition receipts do not
             exist, so the coverage band cannot certify those sessions). Mark 1 MUST
             NOT depend on any transcript older than capture onset, and MUST tail
             promptly — a tailer offline for longer than the retention window loses
             data the vendor deleted, which surfaces as a coverage gap, never as a
             silent hole.
```

**Capability unavailable on this surface:** no wire access in the subscription regime (regime table, 01 §4.2) — routing decisions are `ADVISORY`/`CONFIG_STEERED`, never `WIRE_ENFORCED`; no per-request model rewrite; no authoritative model identity except the optional `SessionStart.model`; no token usage in hook payloads; cost basis is `quota`.

### 5.2 codex (OpenAI Codex CLI)

Phase 2 adapter (~80% hook-vocabulary reuse from Claude Code per the research pass). Spike target: the `TokenCountEvent` usage surface — whether it is emitted per request, per turn, and with what dedupe key. Field map ships in `agent_maps` once the spike fixture lands.
Spike landed 2026-09-15 (`docs/spikes/codex-token-count-event.md`, GO-WITH-CONDITIONS, from `openai/codex` source): Codex ships a hooks system modeled on Claude Code's field for field — `SessionStart`/`SessionEnd`, `PreToolUse`/`PostToolUse`, `PreCompact`/`PostCompact`, `UserPromptSubmit`, `SubagentStart`/`SubagentStop`, `Stop`/`Interrupt`; configured in `~/.codex/hooks.json` or `[[hooks.<Event>]]` tables in `config.toml`; the same exit-code semantics and `hookSpecificOutput.additionalContext` shape (`codex-rs/hooks/src/schema.rs`). `TokenCountEvent` is real (`codex-rs/protocol/src/protocol.rs`: `TokenUsage{input, cached_input, cache_write_input, output, reasoning_output, total}`) and rides the `codex exec --json` / app-server event stream. **Still unverified, and it gates the slot:** whether usage is persisted to the on-disk rollout JSONL (`$CODEX_HOME/sessions/…/rollout-*.jsonl`; a `TokenUsageRecord` variant exists but issue #3201 closed "not planned") — if not, the Usage source is the event stream, an architectural branch from the file-tail design; issue #14489 re-emits `last_token_usage` on rate-limit refreshes (the overcount class FR-SPINE-003 defeats); ~4,400 published npm versions make per-version fixture pinning load-bearing. Field map ships in `agent_maps` once one recorded session settles the persistence question.

### 5.3 gemini (Gemini CLI)

Landed 2026-09-16 at pin `v0.59.0` (`go/mark1d/adapters/gemini`, `conformance/hooks/gemini/v0.59.0/`, shim map `maps/gemini.json`). Spike verdict GO with a two-source design (`docs/spikes/gemini-cli-beforemodel-oauth.md`). **Usage source is the CLI's chat recording** (`~/.gemini/tmp/<slug>/chats/*.jsonl`; `MessageRecord.tokens` carries the full `usageMetadata` breakdown in every auth mode), keyed `(MessageRecord.id, "chat:"+sessionId)` — there is no per-request id on this surface; `output_tokens = output + thoughts`, `input` includes cached, `cache_creation = 0`. Containment: a slug is offered only when its `.project_root` marker equals the enabled root and a stream only when its `projectHash == sha256(marker)`. Hooks: mechanism B into `~/.gemini/settings.json` (user file; absent ⇒ M1E-7101; JSONC ⇒ a plain parse refusal with no M1E code), seven registrations from `hooks/types.ts HookEventName` — SessionStart, BeforeAgent (turn_human), BeforeTool/AfterTool, PreCompress (none), AfterAgent (the stop gate: `decision:"block"` + reason continues the turn with `stop_hook_active`), SessionEnd; timeouts in **ms**; `MARK1_AGENT=gemini` rides the hook entry's `env`. BeforeModel/AfterModel are deliberately not registered (AfterModel fires per streamed chunk; no shim kind answers `llm_request`). Regime mirrors `validateNonInterActiveAuth` + `getAuthTypeFromEnv`: only `gemini-api-key` is API-key; OAuth is capture-only, never proxied.

### 5.4 opencode

Landed 2026-09-16 at pin `v1.18.31` (`go/mark1d/adapters/opencode`, `conformance/hooks/opencode/v1.18.31/`, shim map `maps/opencode.json`). Spike verdict GO-WITH-CONDITIONS (`docs/spikes/opencode-adapter.md`). Plugins are in-process (`default export {id, server}`) and persistence is SQLite-only, so the adapter is mechanism A: an owned plugin file `$XDG_CONFIG_HOME/opencode/plugins/mark1.js` that execs the shim for lifecycle hooks (fire-and-forget, JSON on stdin) and appends `step-finish` parts + assistant `message.updated` verbatim to `~/.omium/mark1/capture/opencode/<sessionID>.jsonl`, which mark1d tails as a `tailers.Format`. Dedupe key `(StepFinishPart.messageID, StepFinishPart.id)` (one step-finish per LLM call; `AssistantMessage.tokens` is the LAST step's count and never counts). `output_tokens = output + reasoning`, `cache_read/creation = cache.read/write`. Session identity: `m1p session_id = UUIDv5(NameSpaceURL, "opencode:"+sessionID)`, computed identically in mark1.js, Go and the selfcheck. No SessionEnd or gate exists on this surface (`session.idle` is observation only). Regime from `opencode.json` `model` else `model.json recent[0]`; a stored `auth.json` `type:"api"` or a `provider.<id>.options.apiKey` ⇒ API-key, everything else subscription.

### 5.5 copilot (GitHub Copilot CLI)

Landed 2026-09-16 at pin `@github/copilot@1.0.85` (`go/mark1d/adapters/copilot`, `conformance/hooks/copilot/v1.0.85/` — **recorded** offline in BYOK mode against a loopback fake provider, shim map `maps/copilot.json`). The spike's finding holds: `assistant.usage` is `ephemeral: true` and never written; only the `session.shutdown.data.modelMetrics` rollup exists, so `events.jsonl` is **DIAGNOSTIC** class (SessionStart/SessionEnd only, never Usage) and Usage rides the BYOK wire path (`Authorization: Bearer $COPILOT_PROVIDER_API_KEY` to `<base>/chat/completions`, OpenAI-chat dialect). Hooks: mechanism A, owned `$COPILOT_HOME/hooks/mark1.json`, PascalCase Claude-compatible bodies; **`PreToolUse` command hooks fail CLOSED at the pin** (a missing shim binary denies every tool call), so the fragment writes `bash: "<shim> || true"` to restore fail-open (rule 5). Stop gate `decision:"block"` → continuation with `stop_hook_active:true`; `SessionEnd` fires after every `agentStop` in `-p` mode. Regime: `providers.json` (entries must all be plain keys) else `COPILOT_PROVIDER_BASE_URL` + `COPILOT_PROVIDER_API_KEY` with no bearer token / key command ⇒ API-key; GitHub-billed ⇒ subscription, capture-only. `WireCredential()` yields a credential only for a plain env key; a `gho_` token is refused on the wire regardless (gateway tripwire). Context injection is inert on this surface (the shim renders Claude's nested `hookSpecificOutput`, which the PascalCase format is not documented to read).

### 5.6 cursor (Cursor)

Landed 2026-09-16 (`go/mark1d/adapters/cursor`, `conformance/hooks/cursor/v2026.09.10-fd3934a/` — transcribed from the pinned `cursor-agent` CLI bundle `2026.09.10-fd3934a` and IDE 3.20.21, not recorded: Cursor has no offline or BYOK path, so a live fixture needs an account). Observe/gate only; the wire proxy and model rewrite are a **permanent NO-GO** in every regime (typed `ErrWireNoGo`, M1E-7105) and `Detect()` is subscription unconditionally. Hooks: A/B fence into `~/.cursor/hooks.json` (owned `{"version":1}` when absent, fenced `_mark1` entries when present; the validator rejects unknown event names for the whole file and requires a numeric `version`). The CLI dispatches ten hook steps; `stop` is wired and carries `loop_count` (vendor cap `loop_limit` 5), no `stop_hook_active`; Cursor's normalizer converts `{decision:"block", reason}` into `followup_message` on every command hook, so the shim's block output works unchanged; `sessionStart/sessionEnd/beforeShell*` are IDE-only at the pin. Cursor also loads `~/.claude/settings.json` hooks translated (`Stop→stop`), so the claudecode fragment is exec'd by Cursor with `MARK1_AGENT` unset and maps nothing. Context injection is inert (Cursor reads top-level `additionalContext`, the shim renders the nested Claude shape). No durable local usage surface is GO, so the daemon runs no cursor tailer.

### 5.7 crush (Charm Crush)

Roadmap slot only. Extension surface entirely `UNVERIFIED — spike gates this adapter slot`. Listed so the adapter registry, the capability matrix (03), and this document stay in one-to-one correspondence.

---

## 6. MCP tool schemas (`cortexd`)

`cortexd` serves MCP natively in Rust over the loopback transport (§4.5 rules: per-session bearer token, literal-loopback `Host`, `Origin` rejection). Registered into agents by name `mark1-cortex` via the §8 provisioning path. Style follows the estate's FastMCP convention (one tool = one narrowly-typed callable with a docstring naming exactly what it calls); the schemas below are the wire truth in any implementation language.

**Session scoping (applies to every tool).** A tool call is served only for the enrolled workspace bound to the calling session's loopback token. Every `path` argument is canonicalized and MUST resolve inside that workspace root after symlink resolution; anything else — traversal, absolute paths outside the root, `.mark1ignore`d paths — is **refused** (`refused: true`, `reason_code: "M1E-6402"`), never partially answered. Results are computed from the local index only; no tool call leaves the machine, and every call emits a `CortexInjection`-family ledger event carrying `root_hash` + `index_clock`.

**Budget limits.** Every response carries `budget` accounting and is hard-capped at `max_tokens` (default 2,000 per call, 8,000 per session turn across calls, bundle-tunable via the `cortex` section). When a full answer exceeds budget, the tool returns the highest-ranked subset with `truncated: true` — ranked truncation, never mid-record cuts.

**Refusal beats fabrication (normative).** A tool that cannot answer *correctly* — index stale beyond `index_clock` tolerance, grammar unavailable for a language (L1 miss), graph shard missing — returns the refusal envelope instead of degrading silently. This copies the estate's probe-registry rule: unimplemented kinds are refused, never faked.

```json
// Refusal envelope — a valid, schema-conforming SUCCESS result (not an MCP error),
// so agents read the reason instead of retry-looping:
{ "refused": true,
  "reason_code": "M1E-6401 | M1E-6402 | M1E-6403 | M1E-6404",
  "reason": "index for 3 files is behind the working tree; re-run after save",
  "retry_after_ms": 1500 }
```

Common output preamble on every non-refused result:

```json
{ "refused": false,
  "root_hash": "blake3:…",          // L0 merkle root the answer was computed against
  "index_clock": 48211,             // monotonic index generation
  "budget": { "max_tokens": 2000, "used_tokens": 1240, "truncated": false } }
```

### 6.1 `repo_map` — the ranked repository map

```json
// input
{ "type": "object",
  "properties": {
    "focus":      { "type": "array", "items": { "type": "string" },
                    "description": "Optional file paths or symbol names to personalize PageRank toward" },
    "max_tokens": { "type": "integer", "minimum": 256, "maximum": 8000, "default": 2000 } },
  "additionalProperties": false }

// output (merged with the common preamble)
{ "type": "object",
  "properties": {
    "map": { "type": "string",
             "description": "Ranked, budgeted map: files with their key symbol signatures, ordered by personalized PageRank over the L2 graph" },
    "files_ranked": { "type": "integer" } },
  "required": ["map"] }
```

### 6.2 `find_definition` — symbol lookup

```json
// input
{ "type": "object",
  "properties": {
    "symbol": { "type": "string", "minLength": 1 },
    "hint_path": { "type": "string", "description": "Optional path to disambiguate collisions" } },
  "required": ["symbol"], "additionalProperties": false }

// output
{ "type": "object",
  "properties": {
    "definitions": { "type": "array", "items": { "type": "object",
      "properties": {
        "path": { "type": "string" }, "line": { "type": "integer" },
        "kind": { "type": "string", "enum": ["function","method","class","struct","enum","trait","interface","type","const","var","module"] },
        "signature": { "type": "string" },
        "confidence": { "type": "string", "enum": ["scip","tags"],
                        "description": "scip = L3 precise; tags = L1 tree-sitter heuristic" } },
      "required": ["path","line","kind","confidence"] } } },
  "required": ["definitions"] }
// Empty `definitions` means "indexed and absent". An unindexable query is a refusal, not [].
```

### 6.3 `find_references` — symbol lookup, inverse direction

```json
// input
{ "type": "object",
  "properties": {
    "symbol": { "type": "string", "minLength": 1 },
    "defined_at": { "type": "object", "properties": { "path": {"type":"string"}, "line": {"type":"integer"} },
                    "description": "Optional anchor from a prior find_definition result" },
    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 } },
  "required": ["symbol"], "additionalProperties": false }

// output
{ "type": "object",
  "properties": {
    "references": { "type": "array", "items": { "type": "object",
      "properties": { "path": {"type":"string"}, "line": {"type":"integer"},
                      "context": {"type":"string","description":"the referencing line, verbatim"},
                      "confidence": {"type":"string","enum":["scip","tags"]} },
      "required": ["path","line","confidence"] } },
    "total": { "type": "integer", "description": "count before limit/budget truncation" } },
  "required": ["references","total"] }
```

### 6.4 `deps` — dependency neighborhood of a file or symbol

```json
// input
{ "type": "object",
  "properties": {
    "path": { "type": "string" },
    "symbol": { "type": "string" },
    "direction": { "type": "string", "enum": ["out","in","both"], "default": "both" },
    "depth": { "type": "integer", "minimum": 1, "maximum": 3, "default": 1 } },
  "oneOf": [ { "required": ["path"] }, { "required": ["symbol"] } ],
  "additionalProperties": false }

// output
{ "type": "object",
  "properties": {
    "nodes": { "type": "array", "items": { "type": "object",
      "properties": { "id": {"type":"string"}, "path": {"type":"string"}, "kind": {"type":"string"} },
      "required": ["id","path"] } },
    "edges": { "type": "array", "items": { "type": "object",
      "properties": { "from": {"type":"string"}, "to": {"type":"string"},
                      "kind": {"type":"string","enum":["imports","calls","implements","references"]} },
      "required": ["from","to","kind"] } } },
  "required": ["nodes","edges"] }
```

### 6.5 `ranked_files` — ranked-file retrieval for a task description

```json
// input
{ "type": "object",
  "properties": {
    "query": { "type": "string", "minLength": 3,
               "description": "Natural-language task description or error text" },
    "limit": { "type": "integer", "minimum": 1, "maximum": 30, "default": 10 } },
  "required": ["query"], "additionalProperties": false }

// output
{ "type": "object",
  "properties": {
    "files": { "type": "array", "items": { "type": "object",
      "properties": { "path": {"type":"string"},
                      "score": {"type":"number","minimum":0,"maximum":1},
                      "why": {"type":"string","description":"graph evidence: matched symbols, recent-edit adjacency — never a fabricated rationale"} },
      "required": ["path","score"] } } },
  "required": ["files"] }
// Ranking is graph-guided (PPR over L2, seeded by tag matches and the live recent-edit
// set) — not embeddings; that choice is load-bearing (spec §2, LocAgent evidence).
```

### 6.6 `memory_recall` — typed experience artifacts for the task at hand

Served by `cortexd` from the locally-synced, tenant-scoped artifact cache that `mark1-intel.memory` maintains (delivery is receipted upstream; recall is local). This is the *pull* complement of the push path (C8); both emit `MemoryInjection` events, and `ArtifactOutcome` at task close feeds ADMIT-LCB.

```json
// input
{ "type": "object",
  "properties": {
    "query": { "type": "string", "minLength": 3 },
    "kinds": { "type": "array",
               "items": { "type": "string", "enum": ["workflow_template","pitfall_remedy","invariant"] },
               "description": "routing_hint is structurally absent: routing hints compile into bundles and are never injected as text" },
    "limit": { "type": "integer", "minimum": 1, "maximum": 10, "default": 3 } },
  "required": ["query"], "additionalProperties": false }

// output
{ "type": "object",
  "properties": {
    "artifacts": { "type": "array", "items": { "type": "object",
      "properties": {
        "artifact_id": { "type": "string" },
        "kind": { "type": "string", "enum": ["workflow_template","pitfall_remedy","invariant"] },
        "body": { "type": "string" },
        "utility_lcb": { "type": "number", "description": "the ADMIT-LCB lower confidence bound at admission" },
        "scope": { "type": "string", "enum": ["tenant","federated"] } },
      "required": ["artifact_id","kind","body","scope"] } } },
  "required": ["artifacts"] }
// Empty cache, unsynced cache, or a query with no artifact above the injection
// threshold returns { "artifacts": [] } — an honest empty, not a refusal; refusals
// are reserved for "cannot answer correctly" (stale index, scope violation).
```

---

### 6.7 `mark1.send_manifest` — declare the host, open the external-writer session (ADR-0018)

The three `mark1.*` tools make an MCP client an **external writer** (ADR-0012/0013): `cortexd` is the transport, the daemon is the authority. They bypass the index-state gates above, spend no budget and emit no `CortexInjection`; their refusal envelope is §6's with fabric reason codes.

```json
// input
{ "client": "cem888",                      // ^[A-Za-z0-9._-]{1,64}$ → fabric component "ext:mcp/cem888"
  "host_manifest": { "host_id": "cem888", "host_version": "2.0.1", "owns_execution": true,
                     "owns_config_surface": true, "owns_memory": true, "arrest_mode": "recommend",
                     "supplies_identity": true, "schema_version": "m1p.v1" },   // m1p.v1.HostManifest, §4.3 step 2b
  "host_correlation_id": "run-7f3a" }      // optional, ≤ 256 bytes; kept on the session, never a Mark 1 session id
// output
{ "refused": false, "session_id": "<32 hex>", "component": "ext:mcp/cem888" }
// refusals: M1E-4007 (the daemon closed the handshake: manifest or version refused — its log names which),
//           M1E-4008 (mark1d not reachable). Never retried.
```

The Hello carries no `session_id`, so the daemon mints one (ADR-0012) and `cortexd` keeps it, with the manifest and correlation id, for the life of its process: every later Hello for this `client` presents the same three, so the daemon binds the same session and §4.3 step 4a's echo check holds. One session per client per `cortexd` process; a second `send_manifest` is a new declaration and a new session.

### 6.8 `mark1.emit_event` — forward one Event as the host's session

```json
// input: one m1p.v1.Event in protojson (§4.6.2's line format; proto or lowerCamelCase names)
{ "client": "cem888",
  "event": { "task_id": "<base64 or 32 hex>", "occurred_at": "2026-10-03T12:34:56.789Z",
             "usage": { "model": "claude-sonnet-5-5", "input_tokens": "812", "output_tokens": 95,
                        "source": "USAGE_SOURCE_TRANSCRIPT" } } }
// output
{ "refused": false, "session_id": "<32 hex>", "delivered": 1 }
```

Exactly one of `task_open`, `task_close`, `turn`, `usage`, `artifact_outcome` (the external-writer vocabulary, §4.6); anything else is an invalid-params error, not a refusal. `event_id`, `seq` and `session_id` are ignored — the daemon stamps them, and `Usage.idem_key` is the daemon's (ADR-0012 §4); `occurred_at` defaults to now. A client that never called `send_manifest` gets a session minted under `hostprofile.Default` on its first event, as any `ext:` Hello without a manifest does. Refusals: `M1E-4003` / `M1E-4007` / `M1E-4008` as in §6.7.

### 6.9 `mark1.get_recommendations` — what the daemon left for the session

```json
// input
{ "client": "cem888" }
// output
{ "refused": false, "session_id": "<32 hex>",
  "recommendations": [ { "sessionId": "…", "arrestRecommendation": { "kind": "knee_arrest", … } } ],   // §4.7
  "proposals":       [ { "sessionId": "…", "memoryProposal": { "category": "PROPOSAL_CATEGORY_PITFALL", … } } ],  // §3.7
  "unparsed_lines": 0 }
```

Read from `<state>/run/recommendations/<session-hex>.jsonl` and `<state>/run/proposals/<session-hex>.jsonl` — the file-tail host's path, which needs no connection to be open when the gate decides. `<state>` is `MARK1_STATE_DIR`, else `$HOME/.omium/mark1`. An absent file is an empty list; a malformed line is counted in `unparsed_lines`, never fatal. Refused with `M1E-4003` when the client has no session yet.

## 7. CLI surface (`mark1`)

Global contract, all subcommands:

```
Exit codes (wire-stable — scripts and MDM key on these):
  0  success
  1  runtime failure (network, daemon unreachable where required, I/O)
  2  usage error (unknown flag, bad argument)
  3  not enrolled / authentication required (M1E-1xxx class)
  4  refused by design (coverage floor, consent absent, guarantee-grade refusal — M1E-5xxx)
  5  verification failure (verify-receipts found a chain defect)
Global flags: --json (machine output on stdout; the --json shape is the contract,
  human text is not), --quiet, --workspace <path> (defaults to cwd's enclosing
  enabled root). Human output goes to stdout, diagnostics to stderr; --json output
  is exactly one JSON object on stdout, always with {"ok": bool, "error": {code, message}?}.
```

### 7.1 `mark1 enroll`

```
mark1 enroll --tenant <tenant-uuid> [--channel stable|canary]
  --tenant is REQUIRED on a fresh enrollment and is the tenant UUID string verbatim:
  m1_tenants has no slug column and RLS routes on the UUID, so a human-friendly alias
  would be a second name for the same row that some mapping must own — nothing does.
  A re-run on an already-enrolled device needs no flag (idempotent, local-only).
Side effects: generates the device Ed25519 keypair (OS keychain/TPM where available,
  0600 file floor), runs the OIDC device-code flow (§3.1: prints user_code +
  verification_uri, polls at `interval`), persists the enrollment document under
  ~/.omium/mark1/ (0600), starts/adopts mark1d.
stdout (human): the user_code, the URI, then per-step progress and final device_id.
stdout (--json): { "ok": true, "device_id": "…", "tenant_id": "…", "state": "active",
                   "expires_in": 86400 }
Exit: 0; 1 network; 3 IdP denial (M1E-1005); 4 device-code expired (M1E-1004 — rerun).
Idempotent: an already-ACTIVE device re-prints its identity and exits 0.
```

### 7.2 `mark1 enable`

```
mark1 enable <workspace-path> [--anchors <id,…>] [--no-anchors]
Side effects: adds the canonicalized path to the workspace allow-list (capture reads
  NOTHING outside enrolled roots); walks the local anchor catalog and prompts for
  consent per anchor (skipped with --no-anchors; --anchors consents non-interactively
  to exactly the named catalog IDs); provisions agent config fragments per §8;
  starts cortexd indexing for the root; emits a receipted CoverageTransition{enable}.
stdout (--json): { "ok": true, "workspace": "/abs/path",
                   "anchors_consented": ["ruff@cat-3","tsc-incremental@cat-7"],
                   "agents_provisioned": ["claudecode"], "coverage_receipt_seq": 91 }
Exit: 0; 1; 2 (path missing); 3 (not enrolled); 4 (path outside the user's home and
  policy forbids it, or .mark1ignore at root opts the repo out).
Idempotent: re-running reconciles fragments/consents; unchanged state exits 0 silently.
```

### 7.3 `mark1 status` — the live read surface

```
mark1 status [--json]
Read-only. Shows, live: enrollment state and token freshness; every enabled workspace
  and what is being read from it right now (transcript paths tailed, artifact dirs
  watched, proxy attached or not, cortex index clock); regime per agent
  (subscription | apikey) and cost basis; spool depth by class; parked/quarantined
  batches (§2.5); last-applied bundle (channel, seq, age vs max_age); active off/bypass
  windows.
stdout (--json): { "ok": true, "enrollment": {...}, "workspaces": [ { "path": …,
  "reading": { "transcripts": […], "artifact_dirs": […], "proxy": "attached|off",
  "index_clock": … }, "agents": [ {"name":"claudecode","regime":"subscription",
  "adapter":"active|dropped:unsupported_agent_version"} ] } ],
  "spool": { "depth_by_class": {...}, "parked": 0, "quarantined": 0 },
  "bundle": { "channel":"stable", "seq":483, "age_s":1200, "stale": false },
  "off": { "active": false } }
Exit: 0 even when the daemon is degraded (status must always answer); 3 not enrolled.
WHY: this command is the product's transparency promise — the §5 scope rules are
  auditable here, not asserted in a doc.
```

### 7.4 `mark1 doctor`

```
mark1 doctor [--json] [--fix]
Read-only unless --fix. Shows:
  1. The consented anchor catalog: every locally-derived anchor, its catalog ID,
     consent state and date, re-consent-needed flag (catalog changed since consent),
     and the bundle-enabled subset (bundles enable by ID only — any command string
     in a bundle fails decode upstream, M1E-3005).
  2. Fenced-config diffs: for every provisioned agent file, the §8 manifest entry vs
     the bytes on disk — OK (post-image matches) | USER-EDITED (fragment intact,
     surrounding file changed) | FRAGMENT-DAMAGED (checksum mismatch inside our
     markers) | MISSING. Byte-level diff on request.
  3. Environment health: fabric socket perms, keychain reachability, clock skew vs
     server, transcript retention setting if readable (warns when cleanupPeriodDays
     is shorter than the tailer's catch-up horizon).
--fix re-applies only FRAGMENT-DAMAGED/MISSING fragments via the §8 idempotent apply;
  it never touches user bytes outside our markers.
Exit: 0 all green; 1 any FRAGMENT-DAMAGED/MISSING or health failure (CI-friendly);
  3 not enrolled.
```

### 7.5 `mark1 report`

```
mark1 report [--window 30d] [--cohort …] [--json]
Calls GET /api/v1/reports/tvo (§3.3) with the operator or device identity available.
stdout: TVO with — always — its coverage band and cost basis; the waste taxonomy
  triple; knee-arrest count and token deltas. If coverage < floor, the command prints
  the numbers WITH the refusal notice and exits 4 when --guarantee-grade was requested:
  a guarantee-grade report below the coverage floor is refused outright, not caveated.
Exit: 0; 1; 3; 4 (guarantee-grade refusal, M1E-5004).
```

### 7.6 `mark1 off` — the uncircumventable kill switch

```
mark1 off [--workspace <path> | --all] [--duration 2h]
Side effects, in order:
  1. Writes the off-marker file ~/.omium/mark1/OFF (or per-workspace marker).
     EVERY gate evaluation in every component checks this marker (and MARK1_DISABLE=1)
     BEFORE reading any policy, bundle, or verdict cache — the check precedes the
     gate, so no bundle, server, or config state can re-enable gating while off.
  2. Reverts every provisioned fragment via the §8 revert algorithm — the agent's
     config returns to byte-equality (verified: the revert re-hashes the restored file
     against the §8 manifest pre-image and prints the verdict).
  3. Stops tailers, detaches the proxy, idles cortexd for the scope.
  4. Emits a receipted CoverageTransition{disable} — off windows are attributable,
     which is what lets TVO reports carry an honest coverage band.
stdout (--json): { "ok": true, "scope": "all", "byte_equality": true,
                   "coverage_receipt_seq": 92, "until": "2026-08-28T18:00:00Z" }
Exit: 0; 1 (partial — anything not fully reverted is listed and doctor shows it).
There is no server round-trip on the critical path: off works with the network down.
`mark1 on` (alias: `enable` re-run) is the inverse; it re-provisions and re-receipts.
```

### 7.7 `mark1 verify-receipts`

```
mark1 verify-receipts [--from <export.jsonl|dir>] [--against-witness] [--offline] [--json]
Wraps the standalone open-source verifier (rust/verifier) — same code, same verdicts.
Default network path: GET /api/v1/receipts/export + /api/v1/receipts/keys — the export
is DEFINED as byte-loadable by the verifier with no translation layer, so the CLI's
job is fetch + orchestrate + honest exit codes, never a fourth crypto implementation.
(The paginated §3.4 rows serve dashboards and drilldowns; the export serves auditors.)
/.well-known/mark1-keys arrives with policydist's key ceremony and is NOT this path's
dependency.
Validates: hash-chain continuity (per-tenant gap-free seq), both signatures per
  receipt (device origin + server countersign) against the key manifest with key_id
  rotation/cross-signing rules, checkpoint Merkle roots against sampled event
  inclusion paths, and (--against-witness) chain heads against the transparency log
  or the customer's object-lock bucket. --offline requires a local key-manifest and
  witness snapshot and touches no network — the "Omium's servers are unreachable"
  guarantee, executable.
  Accepts checkpoint payload v1 and v2 alike (ADR-0017): the host block is verified as
  signed bytes and carried in the row, never interpreted — judging a host is the
  auditor's job; conformance/vectors/hostchain runs through it end to end.
stdout (--json): { "ok": true|false, "checked": {receipts, checkpoints, leaves_sampled},
  "intact_prefix_seq": 5121, "last_good_seq": 5121,
  "defects": [ {"seq": …, "kind": "hash_mismatch|sig_invalid|gap|fork|witness_mismatch",
                "detail": "…"} ] }
Exit: 0 chain valid; 5 any defect (defects are enumerated, never summarized away);
  2 usage; 1 I/O.
```

### 7.8 `mark1 validate-events`

```
mark1 validate-events [<file.jsonl> | -] [--json]
Checks a JSONL file of m1p.v1 Events (one protojson Event per line — the file-tail
format of §4.6.2, and what a socket host would frame) against the external-writer
contract BEFORE the host connects. Pure: no daemon, no network, no state dir; reads
stdin with "-" or no argument.
Checks, per line and per session (session_id, or the one empty session of a file):
  parses as an m1p.v1.Event with exactly one body arm; event_id 16 bytes or empty
  (empty is a WARNING: the daemon mints one, but a re-scan then duplicates at ingest);
  session_id 16 bytes or empty; seq and session_epoch zero; the server-stamped band
  unset; Usage carries message_id and request_id (idem_key set is a WARNING: the
  daemon overwrites it, ADR-0012 §4); occurred_at present and non-decreasing;
  causal order — TaskClose only after its TaskOpen, no nested TaskOpen, Turn only
  inside an open task, Usage and ArtifactOutcome only after a Turn in that task;
  SessionEnd with a task still open is a WARNING.
  Unknown fields are WARNINGS, never errors (§1.1 external writer: additive within
  the major). seq is deliberately NOT checked: it is the daemon's (07 §2).
stdout (--json): { "ok": true|false, "lines": N,
  "errors":   [ {"line": n, "message": "…"} ],
  "warnings": [ {"line": n, "message": "…"} ] }
  Human form: one "line n: error|warning: …" per finding, then a summary line.
Exit: 0 valid (warnings allowed); 5 any error, M1E-4006, after the report is printed
  (findings are enumerated, never summarized away); 2 unreadable path; 1 I/O.
```

---

## 8. Agent configuration provisioning

The rule, restated from the frozen plan because everything here derives from it: **Mark 1 uses only native include/extension mechanisms and never rewrites a file it does not exclusively own.** Two mechanisms implement it, chosen per file:

- **Mechanism A — owned file (preferred).** Where the agent natively discovers config from a directory or extension point (a plugin dir, a `hooks.d`, an MCP-server registry entry), Mark 1 writes a file it exclusively owns (`…/mark1.*`). Apply = write file; revert = delete file. Byte-equality of the *user's* files is trivially preserved because they are never opened for write.
- **Mechanism B — fenced fragment (only when A does not exist).** Where the agent reads exactly one user-owned file with no include mechanism, Mark 1 inserts one fenced, checksummed fragment into that file, under the algorithm in §8.3.

Which mechanism each agent uses is recorded in `agent_maps` (config-stable) and shown by `mark1 doctor`. For claudecode, hook entries and the `mark1-cortex` MCP registration go into the agent's settings scope chosen at `mark1 enable` time; the shape of what is inserted is fixed here, the destination file is `agent_maps` data.

**Where this lives, and why there is exactly one copy of it** (D-AY). The mechanism is implemented once, in `go/mark1d/adapters/<agent>/fragment.go` — inside the daemon's module but deliberately **outside `internal/`**, which doc 13 §3.2 sanctions for `cmd/` and `adapters/` and nothing else. `go/mark1` imports it (`ApplyFragment`, `RepairFragment`, `Revert`, `ManifestPath`) rather than carrying its own copy, because all three CLI callers must work **with the daemon down** — `enable` applies, `doctor` classifies, `off` reverts, none of them over the socket (§7.6). A revert implemented twice is the failure this arrangement exists to prevent: it silently *under*-reverts, and the drift is invisible to exactly the test written to catch it, since each copy's own byte-equality test keeps passing while the two disagree about what a fence is. Duplication is safe only when something fails the moment the twins diverge; stateful mutation of a user-owned file has no such pin.

**Ordering is normative, not incidental** (D-BK). §8.3's apply writes the §8.2 manifest **before** the target file, mirroring §8.4 step 4's "deleted LAST" — the manifest brackets the mutation. `Revert` keys off the manifest alone and reports `not-provisioned` without ever opening the target, so the other order strands our handlers in a user's file permanently if the process dies between the two writes. The inverse crash is benign by construction: §8.4's surgical path is tag-driven, never index-driven, so a manifest whose `post_image` matches nothing is a no-op.

### 8.1 Fence markers (exact, normative)

For comment-capable formats — the comment leader `#` is replaced by the host format's line-comment token (`//`, `--`, `;`) per `agent_maps`:

```
# >>> MARK1 MANAGED BLOCK v1 agent=claudecode fragment=hooks DO NOT EDIT >>>
# mark1: applied-by=mark1d/1.4.2 applied-at=2026-08-28T14:03:11Z
# mark1: checksum=blake3:9f2c…e1     # BLAKE3 of the payload lines, exact bytes,
#                                    # excluding all `# mark1:` header lines
<payload lines>
# <<< MARK1 MANAGED BLOCK v1 agent=claudecode fragment=hooks <<<
```

For strict-JSON files (no comments possible — Claude Code settings among them), the fence is a reserved key namespace plus a sibling checksum object; Mark 1 owns exactly the JSON Pointers it records and nothing else:

```json
{
  "hooks": {
    "Stop": [ { "matcher": "", "hooks": [ { "type": "command",
      "command": "~/.omium/mark1/bin/mark1-hookshim", "timeout": 30 } ],
      "_mark1": "v1" } ]
  },
  "_mark1_managed": {
    "version": 1, "agent": "claudecode", "fragment": "hooks",
    "pointers": [ "/hooks/Stop/0", "/hooks/SessionStart/0", "…" ],
    "checksum": "blake3:…"          // BLAKE3 over the canonical-JSON of the pointed-to values
  }
}
```

Every managed JSON entry carries the `"_mark1": "v1"` tag so an entry is identifiable even if `_mark1_managed` is damaged. Mark 1 never sets, merges, or reorders any key it does not list in `pointers`.

### 8.2 The manifest

Every apply records, in `~/.omium/mark1/provisioned/<agent>/<fragment>.manifest.json` (0600):

```json
{ "target_path": "/home/u/.claude/settings.json",
  "mechanism": "A|B",
  "pre_image_hash": "blake3:…",  "pre_image": "<zstd+base64 of the ORIGINAL bytes>",
  "post_image_hash": "blake3:…", "post_image": "<zstd+base64 of the bytes WE WROTE (ADR-0014)>",
  "fragment_checksum": "blake3:…",
  "applied_at": "…", "applied_by": "mark1d/1.4.2" }
```

Storing the original bytes, not just their hash, is what makes byte-equality restoration a guarantee rather than a hope. Storing the bytes we wrote (`post_image`, additive, ADR-0014) is what lets §8.4 tell a reformat from an edit and an edit outside our fence from one inside it; a manifest without it reverts under the pre-ADR-0014 rule (whole-file hash equal ⇒ verbatim, else surgical).

### 8.3 Idempotent apply

```
apply(target, fragment):
  0. if the session's host profile (ADR-0013) is a DECLARED host (host_id set) with
     owns_config_surface = true → refuse the whole walk, every adapter: M1E-7107
     "host owns config surface" naming host_id; write nothing (ADR-0014 §4).
     hostprofile.Default is Mark 1's own posture and never refuses.
  1. read target (missing file: mechanism A creates; mechanism B refuses — we do not
     invent a user file to fence into. M1E-7101).
  2. locate an existing MARK1 block/pointer set.
     a. none      → snapshot pre_image; insert fragment (B: append at the position
                    agent_maps names — default end-of-file; JSON: set pointers);
                    write atomically (temp file + rename, preserve mode/owner);
                    write manifest.
     b. found, checksum matches desired fragment → no-op. exit unchanged.
     c. found, checksum differs (stale fragment) → replace payload BETWEEN OUR
        MARKERS ONLY (JSON: replace pointed-to values only); update manifest
        (pre_image is NOT overwritten — it remains the original pre-Mark1 bytes).
     d. found, checksum invalid vs its own payload (user edited inside our fence)
        → STOP. no write. flag FRAGMENT-DAMAGED in doctor (M1E-7102). Repair only
        via explicit `mark1 doctor --fix` — silently overwriting a human's edit,
        even inside our fence, is a rewrite of bytes we no longer exclusively own.
  3. verify: re-read, re-checksum, record post_image_hash.
Re-running apply with an unchanged desired fragment is a byte-for-byte no-op — that
is the idempotence contract, and CI asserts it (apply ∘ apply ≡ apply).
```

### 8.4 Revert — and how `mark1 off` restores byte-equality

```
revert(target, manifest):                                          (drift-aware, ADR-0014)
  0. if the session's host profile is a DECLARED host with owns_config_surface = true
     → no-op, reason M1E-7107: nothing of ours is in a surface the host owns.
  1. read target. Classify drift with ONE shared pure function,
     fence.Classify(pre_image, post_image, current) — for strict JSON "outside the
     fence" is the document with our keys removed and "inside" is our entries
     (array elements tagged "_mark1", the _mark1_managed object), both compared
     STRUCTURALLY, so a reformat (CRLF, indentation, trailing newline) is not drift:
       DriftNone          current is what we wrote, structurally
       DriftOutsideFence  our entries intact; something else in the document changed
                          (a second writer before or after our entries, a key of theirs)
       DriftInsideFence   our entries present but not what we wrote
       FenceMissing       none of our entries present
     A manifest with no post_image (pre-ADR-0014) classifies by whole-file hash:
     equal ⇒ DriftNone, else DriftOutsideFence.
  2. DriftNone → restore manifest.pre_image VERBATIM (atomic write). Result is
     byte-identical to the pre-Mark1 file. Report kind `verbatim`, byte_equality: true.
     (Also when blake3(target) == pre_image_hash: a previous run restored it and
     died before step 4.)
  3. DriftOutsideFence → surgical removal: delete exactly our entries (JSON: the
     "_mark1"-tagged entries and the _mark1_managed object; a key we created that is
     now empty goes too, a key they had stays), write atomically, preserving
     everything else — their entries, their order, their line endings. Report kind
     `surgical`; doctor retains the diff summary. The pre-image is NOT restored:
     it would delete a second writer's lines.
     3b. DriftInsideFence, FenceMissing → the existing §7.4 handling, unchanged:
         what we cannot verify is FRAGMENT-DAMAGED / MISSING. Where the block no
         longer verifies against its own checksum → write NOTHING, report kind
         `fragment-damaged` and list, in `retained`, which of our pointers are still
         set; the safe response to "I cannot tell what is in there" is the one
         that refuses to write.
  4. delete manifest last (so a crash mid-revert is re-runnable: revert is also
     idempotent — a target with no block and no manifest is a successful no-op),
     and NOT AT ALL when step 3b retained anything.
Mechanism A revert: delete the owned file. byte_equality: true by construction.
```

**Why 3b writes nothing and keeps the manifest** (D-CR). The checksum covers a fragment's pointers *jointly*, so the moment it stops matching we can no longer say which pointer the user took ownership of — and a partial removal there is the worst of the three options. The base-URL fragment makes the cost concrete: its two pointers are the user's own `ANTHROPIC_BASE_URL` and *our* `M1-Cred-Ref` header, and removing the `_mark1_managed` object while leaving that header deletes the only record in the file that the header is ours. Deleting the manifest on top of that ends not the exposure but our ability to see it: `mark1 off` globs for manifests and `doctor` reads them, so every subsequent run reports `not-provisioned` at a machine still routing an agent's API key to a loopback port. `retained` is therefore reported separately from `byte_equality` — "their bytes differ from the pre-image" and "our pointer is still live" are both a bare `false`, and only the second is an unfinished revert. `mark1 off` does not count a retained fragment as done; it falls to the leftover scan and exits 1.

`mark1 off` runs `revert` for every manifest in scope and prints the aggregated verdict; the `12`-suite test for this is the byte-equality snapshot check named in the frozen plan (apply → off → `cmp` original). Because gates check the off-marker **before** any policy read (§7.6), reverting fragments is defense in depth, not the off mechanism itself — an agent that caches its config and keeps invoking the shim hits the off-marker check inside the shim and gets a no-op exit 0.

---

## 9. Error taxonomy

Normative. Later documents (04, 05, 11, 12) cite these codes; they do not invent new ones — a new failure mode gets a new row here first. Code blocks: `1xxx` auth/enroll · `2xxx` request/ingest · `3xxx` policy/bundle · `4xxx` local fabric · `5xxx` gates/verdicts/reports · `6xxx` cortex/MCP · `7xxx` redaction/egress/provisioning · `8xxx` credential guard/tenancy · `9xxx` rate/quota. Postures are the frozen matrix: **fail-open for availability (capture, hooks), fail-static for policy, fail-closed for legality and secrets.**

| Class | Code | Condition | HTTP | Retryable? | User-visible? | Failure posture |
|---|---|---|---|---|---|---|
| auth | `M1E-1001` | caller lacks operator role | 403 | no | yes (CLI exit 3) | fail-closed |
| auth | `M1E-1002` | device token missing/expired/bad signature | 401 | after re-auth only | on repeat (status) | fail-closed |
| auth | `M1E-1003` | device REVOKED | 403 | no (terminal) | yes — re-enroll prompt | **fail-closed** (revocation class) |
| auth | `M1E-1004` | device_code unknown/expired | 400 | no (restart flow) | yes | fail-closed |
| auth | `M1E-1005` | user denied enrollment at IdP | 403 | no | yes | fail-closed |
| auth | `M1E-1006` | device not found | 404 | no | yes | — |
| request | `M1E-2001` | malformed request/body | 400 | **no — quarantine-and-report** | via `mark1 status` | fail-open (capture continues locally) |
| request | `M1E-2002` | duplicate batch/event (informational, in 200 body) | 200 | n/a | no | — |
| ingest | `M1E-2003` | batch_id landed with different bytes | 409 | no — quarantine | yes (spool corruption warning) | fail-open |
| ingest | `M1E-2004` | batch > 32 MiB decoded | 413 | split & re-send | no | fail-open |
| ingest | `M1E-2005` | wrong content type/encoding | 415 | no — quarantine | via status | fail-open |
| ingest | `M1E-2006` | invariant-violating events (e.g. `Usage` sans `idem_key`) | 422 | remainder once; named events quarantine | via status | fail-open |
| ingest | `M1E-2007` | `M1P-Schema` out of accepted window | 426 | no — quarantine + upgrade hint | yes (doctor) | fail-open |
| query | `M1E-2008` | unknown query template | 400 | no | yes | fail-closed (chokepoint refuses, never improvises) |
| receipts | `M1E-2009` | event not yet checkpointed | 404 | yes, after checkpoint interval | no | — |
| ingest | `M1E-2010` | an `AnchorVote` carrying a non-empty `signature` that does not verify under the device's live enrolled key (FR-VERIFY-004, D-EI); a batch whose only violations are of this kind | 422 | remainder once; named events quarantine | via status | fail-closed (a forged vote never lands) |
| policy | `M1E-3001` | bundle signature invalid | local | next poll | doctor | **fail-static** (keep last-known-good) |
| policy | `M1E-3002` | bundle seq non-monotonic | local | next poll | doctor | fail-static |
| policy | `M1E-3003` | transparency-log inclusion proof missing/invalid | local | next poll | doctor | fail-static |
| policy | `M1E-3004` | unknown channel | 404 | no | yes | fail-static |
| policy | `M1E-3005` | command string in a bundle section | local decode | no — bundle rejected whole | doctor + ACK `rejected` | fail-static (and the compiler bug is a P1) |
| policy | `M1E-3006` | bundle past `max_age`, control plane unreachable | local | keeps polling | status (`stale: true`) | fail-static → conservative built-in defaults; verdicts flagged `stale_cert` |
| fabric | `M1E-4001` | socket path is a symlink / bad perms | local | no — daemon refuses start | yes | fail-closed (start refusal) |
| fabric | `M1E-4002` | frame `len` outside `0 < len ≤ M1PL_MAX_FRAME` (§4.2) | local | no — connection closed | no | fail-open (writer spills) |
| fabric | `M1E-4003` | first frame not `Hello` / version mismatch / `Hello` without a session (D-AT) / an `ext:` writer's `Event` naming a session other than its bound one (ADR-0012, §4.3 step 4a) | local | no | no | fail-open |
| fabric | `M1E-4004` | loopback `Host` not the bound literal | 403 | no | security event | **fail-closed** |
| fabric | `M1E-4005` | loopback request carries `Origin` | 403 | no | security event | **fail-closed** |
| fabric | `M1E-4006` | `mark1 validate-events` found an error in an external writer's JSONL (§7.8): a line that the daemon would quarantine or an ordering the contract forbids (§4.6.3) | CLI exit 5 | n/a | no | n/a — a pre-connect check; the file is the host's to fix |
| fabric | `M1E-4007` | host manifest invalid (§4.3 step 2b, ADR-0013): empty `host_id`/`host_version`, `arrest_mode` unspecified, `owns_execution` false on an `ext:` connection, `schema_version` outside the accepted set, or a manifest from a non-`ext:` writer | local | no — connection closed / file not tailed | no | fail-closed for that writer; nothing else is affected |
| fabric | `M1E-4008` | mark1d not reachable from the MCP surface (§6.7–6.9, ADR-0018): the socket or pipe refused the connection or timed out. Reported in the tool's refusal envelope, never retried. | n/a |
| gate | `M1E-5001` | gate query timeout / verdict cache unavailable | local | n/a | no | **fail-open — gate answers allow**; `Dropped{gate_timeout}` |
| gate | `M1E-5002` | local hard cap hit (≤3 consecutive blocks, hourly ceiling) | local | n/a | transcript feedback | fail-open (stop allowed) |
| gate | `M1E-5003` | verdict is `uncertified/bootstrapping` where certification required | local/API | n/a | labeled honestly | refusal to gate memory/corpus, never a fake cert |
| report | `M1E-5004` | guarantee-grade report below coverage floor | 200 body / CLI exit 4 | no | yes — the refusal IS the message | refusal-by-design |
| cortex | `M1E-6401` | index stale beyond tolerance | MCP refusal | yes (`retry_after_ms`) | agent-visible | refusal beats fabrication |
| cortex | `M1E-6402` | path outside session workspace / traversal / `.mark1ignore` | MCP refusal | no | agent-visible + security event | **fail-closed** |
| cortex | `M1E-6403` | grammar unavailable (L1 miss) | MCP refusal | no | agent-visible | refusal |
| cortex | `M1E-6404` | graph shard missing/corrupt | MCP refusal | after reindex | agent-visible | refusal |
| egress | `M1E-7001` | span flagged by admit-to-upload axis | local | n/a | no (span becomes `⟨redacted:class:hash⟩`) | **fail-closed, no off switch** |
| egress | `M1E-7002` | ingest pre-egress scanner quarantine | 202 body | no | tenant alert | fail-closed |
| provision | `M1E-7101` | fence target absent (mechanism B) | local | no | doctor | refusal — we do not create user files |
| provision | `M1E-7102` | user edit inside our fence (checksum broken) | local | via `doctor --fix` only | doctor | refusal — no silent overwrite |
| provision | `M1E-7103` | duplicate key in the settings object | local | no | doctor | refusal — legal JSON that every decoder collapses differently, so a rewrite would silently delete one of the user's values |
| provision | `M1E-7107` | host owns config surface (ADR-0014 §4, §8.3 step 0): the session's declared host set `owns_config_surface`, so provisioning writes nothing and revert is a no-op; `enable`/`off`/`doctor` say the active host owns its own configuration and Mark 1 is attached through the fabric | local | no | enable/off/doctor | refusal — never a write into a surface another party owns |
| provision | `M1E-7104` | provisioning manifest unreadable | local | no | doctor | refusal — the manifest's `pre_image` is the only byte-equality revert target, so apply refuses rather than re-snapshot over an unknown prior state |
| provision | `M1E-7105` | base-URL fragment requested without a detected API-key credential | local | no | doctor | **fail-closed — the CON-001 boundary.** Every non-affirmative answer collapses here (no key, a subscription credential, a detection that errored, no proxy listening): on this path "I could not tell" and "no" must be the same answer, and there is no force path |
| provision | `M1E-7106` | the agent's settings already set this variable | local | no | doctor | refusal — Mark 1 never overwrites a base URL or header the user set |
| guard | `M1E-8001` | request without valid `M1-Cred-Ref` at the proxy | 403 | no — **no override path exists in the binary** | receipted (sampled `GuardDecision`) | **fail-closed** |
| guard | `M1E-8002` | upstream subscription-marker detected (`oauth_contamination`) | local P0 | no | yes — session killed, config rolled back, receipted | **fail-closed** |
| guard | `M1E-8003` | envelope identity disagrees with verified token claims | 403 | no | security event | **fail-closed** |
| rate | `M1E-9001` | rate limited | 429 | yes — backoff, honor `Retry-After` | no | fail-open |
| server | `M1E-9500` | internal server error (generic 5xx wrapper) | 500/502/503 | yes — §2.5 backoff | on persistence (status) | fail-open |

Reading rules: *Retryable* means the §2.5 automaton may retry without human action — everything else is quarantine, refusal, or terminal. *User-visible* names the surface (`mark1 status`, `mark1 doctor`, transcript feedback, tenant alert); anything marked "security event" additionally lands in the ledger as a `GuardDecision`-class event. HTTP responses carry the code machine-readably: `{"error": {"code": "M1E-2006", "message": "…", "detail": {…}}}`, and locally-raised codes appear identically in `--json` CLI output — one taxonomy, every surface.

---

## 10. Versioning and negotiation

Three version axes, deliberately independent: the **schema** (`m1p.v1` — what events mean), the **edge release** (`mark1d` semver — what code runs), and the **bundle seq** (what policy applies). Negotiation never conflates them.

### 10.1 The minimum-version handshake

- The enrollment/refresh response (§3.1) carries `server_min_edge`. An edge below it keeps capturing (fail-open) but surfaces the upgrade in `mark1 status`/`doctor` and refuses to *enable new adapters* until upgraded — capture continuity is never held hostage to an upgrade.
- Every **edge** request carries `X-Mark1-Edge-Version` — ingest (§2.1) and every control-plane call in §3, the policy ACK included. It is written "edge" and not "ingest" because `bundle_acks.edge_version` is `NOT NULL` and is stamped from this header on the ACK POST: a rule scoped to ingest alone would leave the ACK ledger's own version column with no source, which is exactly the join the next clause names. The server records it (fleet visibility, ACK ledger joins) but never hard-rejects on it alone — rejection authority belongs to the schema axis (`M1P-Schema`), because an old *release* speaking an in-window *schema* is by definition still correct.
- There is **no daemon self-update on managed fleets by default**; when self-update is on, updates verify SLSA provenance under the update key (which is a different key from the bundle key; both are in the transparency log).

### 10.2 New edge vs old server, old edge vs new server

**Old edge → new server (the common case).** Additive-only discipline within a major means the server always decodes an in-window `m1p.v1` batch. Fields the old edge doesn't send are absent-with-defaults; the server MUST NOT infer them. Server responses add fields but never rename or re-type — the edge ignores unknown response keys.

**New edge → old server** (rolling deploys, self-host lag). The edge sends `M1P-Schema: m1p.v1` as long as it emits only v1; new *event types* within v1 that an older server binary doesn't know are **skip-and-retain**: stored raw in the S3 landing object (which precedes decoding — §2.2), skipped in ClickHouse projection, and re-projected on server upgrade. Nothing is lost; it is deferred. This is WHY S3-first is also the compatibility mechanism, not just the durability one.

**Out-of-window schema.** When a tenant's accepted window (per `m1p-registry`) excludes the presented `M1P-Schema`, the server answers `426` with the structured upgrade hint:

```json
{ "error": { "code": "M1E-2007", "message": "schema out of accepted window" },
  "upgrade": { "presented": "m1p.v1", "accepted": ["m1p.v2"],
               "min_edge": "2.0.0", "window_closes": null,
               "notes_uri": "https://docs.omium.ai/mark1/upgrade/m1p-v2" } }
```

`window_closes` is the close of the **presented** schema's window for this tenant (`m1_tenant_schema_windows.window_closes`; `null` when the tenant has no explicit row, i.e. the schema is retired globally or was never opened for them). `min_edge` and `notes_uri` come from the registry rows of the schemas in `accepted`. *(Pinned 2026-09-15: the field had no stated subject; FR-SPINE-023 built it as the presented schema's.)*

4xx rule applies: quarantine-and-report, never a retry loop. A major bump is a **new package served in parallel** (`/m1p/v2/ingest` beside `/m1p/v1/ingest`); the tenant window is the retirement instrument, per-tenant, never a fleet-wide flag day.

### 10.3 Bundles an old edge cannot fully parse

PolicyBundle v1 is a CBOR map of sections (`verify | route | memory | cortex | gates | agent_maps`), each independently versioned as `(section_name, section_version)` and independently signed (section-split keys). The edge's `mark1-policy` crate (and the parallel Go decoder — shared conformance vectors keep them bit-identical in verdict) applies this ladder per section:

```
for each section in a signature-, seq-, and inclusion-proof-valid bundle:
  1. section_version known               → decode to typed eval structs; apply.
  2. section_version unknown (newer)     → SKIP-AND-RETAIN: keep the raw bytes,
       keep running the LAST-KNOWN-GOOD version of that section (fail-static per
       section, not per bundle); ACK with sections_skipped: ["<name>"] so the ACK
       ledger sees partial adoption and canary widening treats it as non-adoption.
  3. section absent from the bundle      → conservative built-in default for that
       section (single-rung ladder, knee=1, detect-only redaction, gates open).
  4. section fails validation (e.g. a command string anywhere in `verify`)
                                         → M1E-3005: the WHOLE bundle is rejected,
       not just the section — a bundle that violates a security invariant is not
       trusted piecewise. Last-known-good bundle stays in force; ACK `rejected`.
```

Rule 2 vs rule 4 is the load-bearing distinction: *unknown* is a compatibility event (tolerated, reported, fail-static); *invalid* is a security event (rejected whole). A server that needs an edge to actually adopt a new section version therefore watches `sections_skipped` in the ACK ledger and gates the rollout on edge upgrades — policy can never silently outrun the code that evaluates it.

Monotonic seq interacts with skipping: an edge that skipped section `cortex@v3` in seq 483 and later receives seq 484 with `cortex@v2` content applies it normally — **rollback is previous content under a higher seq**, so serving old sections to stragglers requires no seq exception and reintroduces no replay surface.

### 10.4 Everything else, one line each

- **M1PL frames:** single `ver` byte; both ends ship together; mismatch is loud (`M1E-4003`), possible only mid-upgrade (§4.3).
- **Spool segments:** header carries the layout version; an upgraded `mark1d` drains old-layout segments read-only before writing new ones; it never mixes layouts within a segment.
- **MCP tools (§6):** additive schema evolution only; a renamed or re-typed field is a new tool name. Agents cache tool schemas per session, so in-place mutation is a lying contract.
- **CLI `--json`:** additive keys only; removed keys require a major CLI version and a release note. Exit codes are frozen forever — MDM scripts key on them.
- **Receipts:** never versioned away (§1.3); new receipt kinds are new `kind` values, and `rust/verifier` treats an unknown `kind` as opaque-but-chain-checked — the chain verifies even where the payload semantics are newer than the verifier.
- **Hook payloads:** vendor-versioned, absorbed by `agent_maps` (§5 rule 1); an unabsorbable break is `Dropped{unsupported_agent_version}` plus a conformance-fixture update, never a guess.

---

*End of 08 — API Contracts. Schema DDL and binary layouts this document references live in 07; component internals in 04/05/06; the tests that hold every contract here live in 12.*
