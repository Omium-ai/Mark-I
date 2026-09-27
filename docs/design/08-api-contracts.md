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
- `RmScore` (16 L6a) is refused at stage 6 (422 `M1E-2006`, named events) as `rm_score_model_id` (not `^rm:[a-z0-9-]+@[1-9][0-9]*$`), `rm_score_range` (`score` is the uncalibrated P(yes) = σ(logit("yes") − logit("no")); NaN or outside [0, 1]), `rm_score_locus` (`CLOUD` is the adjudicator's alone, via service ingest and unsigned; a device speaks only `CLIENT_SIDE`) `rm_score_unsigned` (a device's `CLIENT_SIDE` score with an empty `signature`: an edge with no enrolled key has no score to send) or `rm_score_signature` (a device's `signature` that does not verify under its live key, the `AnchorVote` scheme). The 422 remainder flow quarantines only the named score on the edge.
- `GuardDecision` (ADR-0013) is refused at stage 6 (422 `M1E-2006`, named events) as `guard_basis` when `knee_basis` is not one of `""`, `prior`, `anchor_grounded`, `certified`, `unknown`, or `cost_basis` is not one of `""`, `usd`, `quota` (`""` = an edge that predates the field).
- `OutcomeContribution` (16 L8) travels alone: stage 6 refuses it (422 `M1E-2006`, named events) as `contribution_shape` (`task_id` not 16 bytes or ≠ `Event.task_id`, `redaction_receipt_ref` not 32 bytes, empty `diff_redacted`), `contribution_not_alone` (batched with any other event or with `dropped[]` rows) or `contribution_consent` (the device's latest `m1_device_consents` row lacks `contribute_outcomes`, a service principal, or no store); a consent-store read error is 503 `M1E-9500`. An admitted batch lands at `t/<tenant>/contributions/v1/…` (07 S3 layout) after its `m1_outcome_contributions` index row, never under `ingest/`; its `m1p_events` row carries no text.
- Large artifacts (opt-in evidence blobs) do not ride this endpoint; they upload as multipart `attach.{event_id}.{name}` to the attach endpoint named in the enrollment document (`endpoints.attach`, below).

**The attach upload (E1, 16 L10; built 2026-09-26).**

```
POST /api/v1/attach                                       auth: device token (a user token is refused)
Content-Type: multipart/form-data                         # body ≤ 80 KiB
  part "receipt"               the edge's redaction receipt file {payload, device_key_id, device_signature (hex), receipt_hash}
  part "attach.<task_id>.e1"   the sanitized part: task intent (≤ 1 KiB) NUL unified diff hunks; ≤ 64 KiB, exactly one NUL
→ 200 { "status": "landed" | "duplicate", "attachment", "receipt_id" }
→ 202 { "status": "quarantined", "classes": [...] }       # the second ruleset hit; nothing is indexed or served
```
One part per task: `evidence_event_id` = `task_id`, and the receipt's `subject_id` must name it and its `post_hash` must equal sha256(part), else 422 `e1_receipt_mismatch`. Order: the device's latest `m1_082` row must say `e1` (else 422 `e1_consent`, nothing lands) → the task must be this device's: `m1_task_devices` (07 m1_106) binds a task to the device whose TaskOpen/TaskClose landed first (ingest stage 11); unbound is 503 M1E-9500 (the edge retries until its batch lands), another device's task is 403 M1E-1001 `e1_task_device` → the receipt is verified under the enrolled key and stored in `m1_redaction_receipts` (idempotent) → the ingest scanner's independent ruleset scans the part (a hit: `m1_quarantined_batches` tombstone, the twin at `t/<tenant>/quarantine/v1/dt=…/e1-<task>.bin`, the M1E-7002 tenant alert, 202) → the `m1_evidence_attachments` index row (m1_099) lands before the object, in a transaction that first takes the device's consent lock shared (`pg_advisory_xact_lock_shared(hashtextextended('m1_consent:' ‖ device, 0))`, held exclusively by every consent PUT, §3.7a) and re-reads the latest `e1` (off: 422 `e1_consent`, nothing indexed or landed) → conditional PUT to `t/<tenant>/evidence/v1/<task>.e1` under the tenant's KMS key. A re-upload of the same bytes answers `duplicate`; different bytes for a landed (or deleted) task is 409 M1E-2003. After a 200 the edge admits the `EvidenceExcerpt{tier: E1, evidence_event_id: task, attachment_name, redaction_receipt_id}` event, and stage 11 binds the receipt to it; only a bound receipt's part is ever read. The edge retries 5xx/401/429 from a local pending part (post-redaction bytes only) and waits while its consent record is not yet relayed; any other answer settles the part. Errors: 400 M1E-2001 (shape) · 401 M1E-1002 · 403 M1E-1001 (`e1_task_device`) · 403 M1E-1007 (a leaver's device) · 413 M1E-2004 (part size or shape) · 415 M1E-2005 · 422 M1E-2006 (`e1_consent`, `e1_receipt_mismatch`, `e1_receipt_<defect>`) · 409 M1E-2003 · 503 M1E-9500 (store, or the task not yet bound).

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
| `403 Forbidden` | Device revoked (`M1E-1003`), envelope/token identity disagreement (`M1E-8003`, + security event), or the device's enrolling subject has left its team tenant (`M1E-1007`, the token's last ≤24 h; attach and §3.7a answer the same). | Quarantine-and-report; `mark1d` drops to capture-local-only and surfaces re-enrollment. |
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
        "tenant_root_hex": "…",                          # 04 §2.9's per-tenant HMAC root (idem_key salt); only on an ACTIVE body,
                                                        # never in a list; absent (not empty) when the server holds no pepper
        "contribute_outcomes_default": true,            # only for Omium staff enrolling into a DOGFOOD_TENANTS tenant (16 L8):
        "contribute_outcomes_default_reason": "omium_staff" }  # a STAFF_SUBJECTS entry, or an @omium.ai email the issuer marks
                                                        # email_verified; both fields or neither (an invited non-staff teammate
                                                        # gets neither, and so does a refresh body). mark1d applies the default
                                                        # once, only with that reason, unless the person already set it
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
  X-Mark1-Bundle-Features: knee_basis      # ADR-0013: optional keys this edge decodes; absent ⇒ none. controld never serves a head
                                           # carrying route.knee.basis to a poll without the word (it republishes without it first)
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
        "cost_basis": "usd" | "quota",                  # never mixed; `auto` is the tenant's m1_075 row, else quota (ADR-0013 §10: the bootstrap bundle's rule)
        "task_seg_version": "task_seg.v1",
        "waste": { "retry_loop_tokens": …, "re_exploration_tokens": …, "over_model_tokens": … },
        "price_table_version": "model_prices.v1@sha256:…",   # usd only: the pinned price table the figures were priced under (06 §8.4)
        "tokens_saved": { "label": "estimated", "version": "savings.v3", "total": ±…,   # net vs plain Claude Code (doc 16 ruling 4); may be negative
                          "blocks": …, "block_count": …, "blocks_resolved": …, "debit": …,
                          "arrests": …, "arrest_count": …,                        # forced retries avoided, never in total
                          "certified": ± …,                                       # the net over certified tasks decided under this report's cost_basis; 0 until certification
                          "by_cost_basis": { "usd"|"quota"|"unknown": {"total": ±…, "block_count": …, "arrest_count": …} },  # ADR-0013: total split by the basis each decision was priced under; "unknown" = an edge that predates GuardDecision.cost_basis
                          "restated": { "tasks": …, "total": ±… } },               # ADR-0013: the part of total that verdicts/usage dated after a closed decision day moved
        "closed": { "tvo": …|null, "guarantee_grade": …, "days": …, "refusal"? }, # the rolled-up days graded apart from today's live day (absent for a team member)
        "guarantee_grade": true | false }
# "tvo" is null when the window has zero verified outcomes — an unmeasured denominator, never 0; a day with zero verified outcomes has no trend point at all (absent, never null: app releases before v0.2 parse trend[].tvo as a number)
# tokens_saved (ADR-0013): a task is in the window when its verify-plane decision is dated inside it; its verdict and post-block usage are read through today, so late verdicts count, and a closed day whose net moved after it closed is counted in "restated", never changed silently
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
PUT /api/v1/consents                                      auth: device token (a user token is refused; a leaver's device 403 M1E-1007)
  { "e1": bool, "cloud_judge": bool, "training": bool }   # all three present, every edge generation; ≤4 KiB, unknown field refused
  + tri-state "team", "contribute_outcomes",              # 15-teams, 16 L8, 16 L6a (07 m1_097): absent (or null) = unchanged
              "local_rm", "cloud_rm": bool                #   for this device; explicit false = off for this device, and person-wide
                                                          #   only on a true→false transition (below); explicit true = this device only
→ 200 { "recorded_at": "<RFC 3339>",
        "consents": { "e1": bool, "cloud_judge": bool, "training": bool, "team": bool,
                      "contribute_outcomes": bool, "local_rm": bool, "cloud_rm": bool } }   # this device's EFFECTIVE latest row, all seven
```

**The response is the effective row (m1_107).** `consents` is exactly the `m1_device_consents` row this PUT appended, all seven fields, never absent. It differs from the body in one direction only: a field the body sends `true` can come back `false`, never the reverse (an explicit false is always stored false; an absent later field comes back as the carried value). A `true` → `false` difference means the field is **held** in the row's `person_off`, for one of two reasons: (1) **person-wide off**: another device of the same person withdrew the field (a transition, below) and wrote this device's row with `person_off` naming it; (2) **old copy**: `cloud_judge` and `training` were both re-worded this release. A three-field body (only an edge older than this release sends one) cannot carry new-copy consent, so it stores either field `false` and holds it when it asks for true; an explicit false is stored as sent. m1_107 resets every pre-cut grant of either the same way, and the edge's one-shot local copy reset relays both `false`, which only releases those holds (the row is already false: no transition, nothing person-wide). **A hold lasts until this device sends THAT field explicitly `false`**: every PUT stores `person_off` = the previous holds minus the body's explicit falses (plus the legacy `cloud_judge` hold), and a held field is stored off whatever the body says, so a racing relay or one whose answer was lost cannot re-grant it with a stale true. An explicit false on a held field is never a transition (its row is already false), so the release withdraws nothing. After the release, an explicit true re-grants this device only. **Edge contract (X2):** on every 2xx the edge MUST adopt each field that is `true` in its sent body and `false` in `consents` into `<state>/gates/consents.json` as off (journalled with reason `cloud_withdrawal`), then PUT the adopted record once (it carries those fields `false`, which releases the holds), and only then treat the record as acknowledged; a later grant is an ordinary relay. It must never adopt a `false` → `true` difference (there is none by construction; treat one as a server fault and keep the local off). The edge serializes every relay (the loop, the boot and session-start syncs, the `/v1/optins` and enroll kicks) so no relay reads the record before another's adoption and PUTs a stale true after its release. **`contribute_outcomes` while undecided:** a tenant switch resets it to undecided (neither the person's stamp nor a staff default), and the edge then sends it ABSENT, never `false`: returning to a tenant whose device row still holds `true` would otherwise read as a true → false transition and sweep the person's contributions. When a 2xx row says `true` for an undecided `contribute_outcomes`, the edge restores it locally as the person's own choice in that tenant (it is this device's prior choice there, carried; journalled `restored_prior_choice`); every other `false` → `true` difference is still never adopted. **Copy reset (edge-local, one-shot):** a `gates/consents.json` never stamped with consent copy 2 (`gates/consents_copy`) has `cloud_judge` and `training` turned off at mark1d's boot (journalled `copy_reset`, relayed as ordinary offs), then is stamped; grants from then on pass the `X-Mark1-Consent-Copy: 2` gate below. An edge that ignores the body (≤ v0.1.19) keeps sending the stale true, so its holds never lift: it cannot re-grant a person-wide off, and its `cloud_judge` and `training` stay off. The legacy fallback ack (`legacy_cloud`, 16) predates the field and carries no `consents`. **Rollback:** controld at f85bff9 predates `person_off` and writes rows without it, so rolling controld back past m1_107 drops every hold (the next stale true re-grants on that device). That is accepted because the rollout is cloud-first and no edge depends on holds before X2 ships. Do not roll controld back past m1_107 without re-applying the holds afterwards (re-run the one-shot `cloud_judge`/`training` reset and redo the person-wide offs from `m1_device_consents` history).
The body is the device's consent state. **Tri-state later fields:** `e1`, `cloud_judge` and `training` are sent by every edge generation and are always the device's new value (except the held offs above). `team`, `contribute_outcomes`, `local_rm` and `cloud_rm` are decoded as absent / false / true: absent (an edge that predates the field, or the legacy three-field body the current edge falls back to when a legacy cloud 400s) carries this device's previous latest value into the new row (a device that never had it stays false) and withdraws nothing, on this device or any other; an explicit false turns it off for this device; an explicit true turns it on for this device only. The current edge always sends all seven explicitly. **A withdrawal is a transition, per person** (07 m1_106, m1_107): every edge sends every field on every relay (a toggle, onboarding, a tenant switch's `contribute_outcomes: false`, the post-upgrade re-send), so an explicit false alone says nothing. A field among `e1`, `cloud_judge`, `training`, `team`, `contribute_outcomes` is withdrawn person-wide only when the body sends it false AND this device's own previous latest row had it true. Those moved fields are then turned off, in the same transaction, on every other device of this tenant whose latest enrollment carries this device's subject, by appending a row that copies that device's latest state with them off and names them in `person_off`. **Ruling (MEDIUM-4, privacy first):** a device of the person whose latest enrollment is not `approved` (revoked, or re-enrolled away) can never relay again, so it takes every explicit false in the body, transition or not. The person's current visible setting governs data from their revoked devices, so after a team removal and re-invite, the new device's current consent governs the old device's data. E1 parts (`e1`) and contributions (`contribute_outcomes`) are marked withdrawn only on the devices whose field went true → false in this PUT, the sender included. Every re-enroll with a new key mints a new device id, so without this a re-enrolled person's old device kept exporting. Not across tenants: consent follows the tenant (16 L8) and a tenant switch resets `contribute_outcomes` to undecided, so an off in a team tenant says nothing about what the person granted in their personal one. Grants stay per device. `local_rm` and `cloud_rm` never propagate: where the reward model scores is a per-device choice, and `e1` stays the person-wide kill switch for E1 data (a cloud RM read needs `e1` too). The PUT always holds the sender's consent lock and each person-device's (`m1_consent:<device>`, ascending) until commit, so a concurrent withdrawal can't be lost under the sender's carried fields, and an attach in flight on any of them either commits first (and is withdrawn by this PUT) or waits and is refused. Identity is the enrollment's `oidc_subject` as stored: an `omium_user` approval stores `omium:<sub>`, an `idp_device_code` approval the IdP's raw subject, and no mapping between the two exists, so one human enrolled both ways in one tenant is two people here (a missed propagation, never a wrong withdrawal). each PUT appends one `m1_device_consents` row stamped with the token's `(tenant, device)`, and the latest row per device (the last written, `row_seq` (m1_105), never the newest `recorded_at`: a withdrawal stamped by a stepped-back clock still wins) is that device's consent (the table is append-only; history stays answerable). The edge relays the same record it wrote to `<state>/gates/consents.json` and keeps it pending until acknowledged, so the cloud's view never runs ahead of the local one. Consumers: `e1` gates `EmitExcerpt`'s E1 case on the edge (a `Dropped{e1_consent_absent}` row when absent) and the attach upload (§2.1); a PUT whose `e1` goes true → false stamps `withdrawn_at` on the live `m1_evidence_attachments` rows of every device it turned off in the same transaction, the internal read stops serving them at once, and the daily sweep deletes them with an `evidence_deletion` receipt; `cloud_judge` is the §3.8 judge path's precondition; `training` gates `corpus.export` — the job runs only when every device of the tenant that has ever recorded consent currently consents (`bool_and` over latest rows; a tenant with no rows is refused, never assumed). `contribute_outcomes` (07 `m1_096`) is per device: ingest admits an `OutcomeContribution` only under a latest row saying true, and a true → false transition stamps `withdrawn_at` on the past contributions of every device it turned off in the same transaction (the daily sweep deletes their objects). The edge sets it through the local control API, `PUT /v1/optins {"consents": {"contribute_outcomes": bool}}` (a partial patch; off also purges `<state>/contrib`). `local_rm` / `cloud_rm` (07 `m1_097`) are the Settings choice "Reward model: On this computer | In Omium's cloud | Off", set the same way (`PUT /v1/optins {"consents": {"local_rm": bool, "cloud_rm": bool}}`); `local_rm` arms mark1d's supervised `mark1-rm` child (no cloud call), `cloud_rm` is read by the adjudicator's cloud scorer beside `e1`. `PUT /v1/optins` turns `cloud_judge`, `cloud_rm` or `training` on only for a request carrying `X-Mark1-Consent-Copy: 2` (the app showing the current register copy); without it such an enable is 409 `{"error":{"code":"M1E-2014","reason":"consent_copy_outdated","message"}}` and nothing is written, while offs and the other fields need no header. `GET /v1/optins` and the PUT's echo carry two optional lists beside `consents`, each absent when empty, persisted beside `gates/consents.json` (`consents_<name>.json`) across restarts, cleared per key when the person sets that key here again, and refused in a PUT body (400 M1E-2001, unknown field): `cloud_withdrawal: string[]`, the keys mark1d turned off adopting another device's withdrawal (journal reason `cloud_withdrawal`), and `copy_reset: string[]`, the keys turned off because they were granted under the outdated copy — the edge's one-shot copy reset, or controld's m1_107 reset of pre-cut `cloud_judge`/`training` grants when it arrives as an adoption on a record not yet stamped copy 2. Errors: 400 M1E-2001 (shape) · 401 M1E-1002 · 403 M1E-1001 (no device claim) · 403 M1E-1007 (the device's enrolling subject has left the team tenant; ingest and attach answer the same, `teams.Participant`) · 503 M1E-9500 (store unavailable or unconfigured, or the membership lookup failed).

### 3.7b Tenant register consents (06 §6.5, §9.1; 07 `m1_065`, `m1_073`, `m1_092`; 16 §L1/§L6)

```
GET /api/v1/verify/cloud-judge                            auth: user or device token
GET /api/v1/verify/cloud-rm
GET /api/v1/memory/extract-consent
→ 200 { "enabled": bool, "judge_id", "subprocessor", "region", "max_tier", "consented_at": <RFC 3339>|null, "consented_by": str|null }
PUT /api/v1/verify/cloud-judge                            auth: user or device token; team owner only in a team
PUT /api/v1/verify/cloud-rm
PUT /api/v1/memory/extract-consent
  { "enabled": true,  "judge_id": "<the route's key>" }  # enable: judge_id is REQUIRED and must equal the key the caller's consent copy describes
  { "enabled": false }                                    # disable: judge_id optional and ignored; always allowed
                                                          # nothing else; ≤4 KiB, unknown field refused
→ 200 (the GET body)
→ 409 M1E-2014 reason consent_copy_outdated               # enable with judge_id absent or not the route's current key; nothing written
```
The keys to send today: `judge:grounded-rubric@2` (cloud-judge), `rm:mark1-rm-a@1` (cloud-rm), `mem:extract@1` (extract-consent). A client sends the key its own compiled consent copy describes, never the `judge_id` it just read from GET: consent is to the processor the person was shown. Why: v0.1.14 shows "Anthropic, US" for the cloud judge and PUTs a bare `{"enabled":true}`; the route's key is now Nebius/global, and a bare enable would record consent to a processor the person never saw. A bare enable is 409, a bare disable still works, so an old app can always turn a consent off.
One `m1_cloud_judge_consents` row per route: the cloud judge `judge:grounded-rubric@2` (`nebius`, `global`, `max_tier` E1), the cloud reward model `rm:mark1-rm-a@1` (`baseten`, `us`, E1; the app writes it with the Settings choice "Reward model: In Omium's cloud", and the adjudicator scores only devices whose own record also says `cloud_rm` and `e1`) and memory extraction `mem:extract@1` (`nebius`, `global`, E0) — "Learn from my sessions" in Settings, off by default. Each key's processor, region and retention is a row of the subprocessor register (`appapi.Register`, 10 §10.4), which the app's consent copy renders. Absent a live row GET answers `enabled:false` with the static disclosure; PUT true inserts the row (idempotent under the partial unique index), PUT false revokes it (`revoked_reason='settings'`, never a DELETE). `judge_id` is the register key column for both. Schemas: `go/controld/internal/appapi/schema/{cloud_judge,cloud_rm,memory_extract_consent}.json`. Errors: 400 M1E-2001 (shape) · 403 M1E-1001 (no tenant) · 403 M1E-1007 `not_owner` (a team member) · 409 M1E-2014 `consent_copy_outdated` · 500 M1E-9500.

### 3.7c Team rounded and the weekly email (15-teams; 16 §L3; 07 `m1_091`)

```
GET    /api/v1/team                                        auth: user or device token
→ 200 { …15-teams…, "members": [ { …, "totals": {sessions, tasks_verified, tokens, tokens_saved} | null } ],
        "totals": { "window": {from, to}, "team": {…}, "unattributed": {…} } | null }
POST   /api/v1/team/invites          { "email"? }          auth: user token; owner
→ 200 { "sent": bool, "invite_link", "invited_email", "status": "invited", "expires_at" }
DELETE /api/v1/team/invites/{id}                           auth: user token; owner   ({id} = invite:<uuid> or <uuid>)
→ 200 { "id": "invite:<uuid>", "status": "cancelled" }
GET    /api/v1/me/notifications                            auth: user token
PUT    /api/v1/me/notifications      { "weekly_digest": bool }   # exactly this field; ≤4 KiB
→ 200 { "weekly_digest": bool, "email": str|null }
GET    /api/v1/unsubscribe/{token}                         auth: NONE, the path token is the credential
POST   /api/v1/unsubscribe/{token}   (form body ignored; RFC 8058 one-click posts List-Unsubscribe=One-Click)
→ 200|404|503 text/html (no-store, no-referrer, CSP default-src 'none')
```
Totals are 30 d aggregates from `team_device_totals.v2` read under `querychoke.TenantWide`; controld maps each device to the subject of its latest enrollment in Postgres and answers no device id and no session; devices of no listed member land in `unattributed`, and `team` sums everything. `tokens_saved` is savings.v3's net estimate and may be negative (blocks inside the window, resolved by every verdict through today, ADR-0013). An invite with an email is sent after the commit through Customer.io (5 s timeout, click tracking and message retention off so the `#token` never passes a tracking redirect); a failed or unconfigured send keeps the invite and answers `sent:false`. Cancel sets `expires_at = now()` (the seat frees). `email` is exactly one bare address (`net/mail`; a list, a display name, a group or `<…>` is 400), stored and mailed lowercased; the mailer itself refuses any other recipient. At most 2 × `TEAM_MAX_MEMBERS` invites per tenant per rolling 24 h, cancelled ones included (cancel frees the seat, not the quota), counted from `m1_team_invites.created_at`, so a restart forgets nothing: over it, 429 M1E-9001 `invite_rate_limited`. Every app route (this section and §3.7b, sessions, reports, `/me`) refuses a device token whose enrolling subject is neither the tenant's owner nor an active member of a team tenant with 403 M1E-1007 `not_member`: a leaver's device keeps its token up to 24 h and reads nothing of the team with it. The digest opt-in is per (tenant, subject) in the tenant the person works in now, off until turned on; PUT true needs an email on the sign-in. GET on the unsubscribe path only renders a confirm form (link scanners change nothing); POST turns the digest off. Unknown or malformed tokens answer the same 404 page. Kong routes `/api/v1/unsubscribe` (prefix) and `~/api/v1/me/notifications$` to controld. Schemas: `go/controld/internal/appapi/schema/{team,team_invite,team_invite_cancel,notifications}.json`. Errors: 400 M1E-2001 (shape) · 403 M1E-1007 (`not_owner`, `not_member`, `user_token_required`) · 404 M1E-2012 `invite_invalid` · 429 M1E-9001 `invite_rate_limited` · 500 M1E-9500.

### 3.8 Internal service surface (never public; service credential, ADR-0010 §2.2)

```
POST /internal/v1/receipts/append                         auth: Bearer <INTEL_SERVICE_TOKEN>
  { "tenant_id", "record_type": "noise_certificate" | "memory_admission" | "bundle_publication"
                              | "corpus_export" | "verifier_promotion",
    "subject_id", "idempotency_key", "payload": { …integers and strings only… } }
→ 200 { "receipt_id", "seq", "receipt_hash", "payload" }
```
```
GET /internal/v1/evidence/{task_id}?purpose=judge|rm      auth: Bearer <EVIDENCE_READ_TOKEN>, M1P-Tenant-Id: <tenant>
→ 200 { "task_id", "tier": "E1", "attachment", "receipt_id", "post_hash", "intent", "hunks" }
→ 404 M1E-2013                                            # none uploaded, not yet bound, withdrawn, deleted, past 30 d, or the purpose's consent is off
```
The adjudicator's E1 read (16 L10): the cloud judge `judge:grounded-rubric@2` reads it by default (`app/judges/evidence.py`, absent ⇒ the E0 fallback) and the cloud RM through `rm_input_reader`. Served only under the tenant GUC from a live, unwithdrawn index row under 30 days whose receipt is bound to a landed excerpt, only while the part's device's latest `m1_082` row (by `row_seq`) still says `e1` **and** the purpose's consent — `purpose=judge` needs `cloud_judge`, `purpose=rm` needs `cloud_rm` — and only when the object's sha256 still equals that receipt's `post_hash`. The credential is the adjudicator's own `EVIDENCE_READ_TOKEN` (SM `omium/prod/mark1-evidence-token`, k8s Secret `mark1-evidence-token` key `token`; controld env `EVIDENCE_READ_TOKEN`, adjudicator env `ADJ_EVIDENCE_TOKEN`), never the shared `INTEL_SERVICE_TOKEN` intel also holds; compared in constant time, and an unset token refuses every caller (controld refuses to boot when it equals `INTEL_SERVICE_TOKEN`). Errors: 403 M1E-1001 (credential) · 400 M1E-2001 (tenant header, task id, `purpose` absent or not `judge`/`rm`) · 404 M1E-2013 · 503 M1E-9500.

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
| `Hello{component, pid, version, session_id, cwd}` | writer → mark1d | First frame on every connection. `cwd` (2026-09-20) is the writer's working directory — a hook process runs in the agent's project root — and stays on this socket: mark1d maps it to an enabled workspace and stamps `SessionStart.workspace_id` (the HMAC) from it; the path itself never enters an event. `mark1d` replies `HelloAck{accepted: true, max_frame: M1PL_MAX_FRAME}` or closes. The symbol, not a re-typed literal — §4.2 is the only place the value appears. `max_frame` is the daemon telling the writer which build it is talking to, **not a negotiated ceiling**: a writer that reads a smaller value may send smaller frames, never a larger bound than §4.2's. |
| `GateQuery{task_id, gate: STOP\|TOOL, deadline_ms}` | hookshim → mark1d | Read the cached `VerdictEvent{PROVISIONAL}` and knee state for a gate decision. |
| `GateVerdict{decision: ALLOW\|BLOCK, verdict, posterior[4], reason, evidence_ref}` | mark1d → hookshim | The reply. **The gate reads the cache; it never computes** — this round-trip is a map lookup, budgeted ≤ 5 ms. |
| `Flush{}` / `FlushAck{drained: n}` | writer → mark1d → writer | Mandatory drain barrier on SessionEnd/shutdown. |

### 4.3 Handshake

1. Writer connects; OS-level peer checks run (§4.1).
2. Writer sends `Hello` as its first frame. Any other first frame ⇒ close (`M1E-4003`).
3. `mark1d` replies `HelloAck`. Version negotiation is the single `ver` byte: `mark1d` accepts exactly the versions its release ships; a mismatch closes with `HelloAck{accepted:false, want_ver}` — possible only mid-upgrade, and loud.
4. After `HelloAck`, the connection is a unidirectional event stream (plus `GateQuery`/`Flush` request-reply where the component uses them). Event frames are **fire-and-forget: no per-event ack.** Durability is the spool's job, not the fabric's.

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

The loopback listener accepts events **only** for sessions whose token it issued; it is a constrained door into the same single-writer spool path, not a second fabric.

### 4.6 Local control API (app ↔ daemon)

The desktop app's `/v1/...` routes sit behind the same three walls as §4.5 (literal Host, no Origin, bearer from `<state>/run/control.json`). Their shapes are held to `desktop/mock/fixtures/*/local-*.json` by `internal/control/conformance_test.go`; the mock README lists them. One route is specified here because it is the only one that runs anchors on request:

```
POST /v1/anchors/probe   body: {"project": "<enabled root>"}      (16 §L4, first run)
202  {"project", "anchors": n}   n consented static anchors will run once, one after another, in the background
400  M1E-2001  missing project / unknown field (strict decoder)
404  M1E-2001  not an enabled project
409  M1E-2001  no catalog armed for it yet, or a probe of it is already running (one at a time per project)
503  M1E-2001  the anchor plane is not running
```

Each run takes `RunOne`'s path (consent + binary-hash gates, sandbox, the kind's handler) under a 2-minute per-anchor timeout, but emits **no AnchorVote and no ledger event** and stores no evidence: the result lands only as `last_run`/`last_code` on `GET /v1/anchors`, which the app polls. Test-class anchors never run here. The app frames the result as "checks ready", never "verified".

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
  "off": { "active": false },
  "reward_model": null | { "state": <worst served model's>, "detail": …, "models": [
    { "model_id": "rm:mark1-rm-a@1", "state": "starting|downloading|verifying|ready|
      no_runtime|download_failed|failed|refused|not_served", "detail": …, "size_bytes": … } ],
    "rm_backlog": <closed tasks dropped unscored, oldest first> } }
  (reward_model is <state>/rm/status.json, 16 §L6: one row per model, so a down RM-B is
  named while RM-A keeps scoring; null until the daemon has reached the reward model.)
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
     markers) | MISSING. Byte-level diff on request. Each capture fragment also names
     the Mark 1 release whose bytes are on disk (`provisioned_by`, from
     provisioned/<agent>/release.json, §8.3.1), flagged when it is not this release.
  3. Environment health: fabric socket perms, keychain reachability, clock skew vs
     server, transcript retention setting if readable (warns when cleanupPeriodDays
     is shorter than the tailer's catch-up horizon); `rm_runtime`, failing only when a
     reward model crash-looped, its pinned download failed or its execution hash was refused
     (16 §L6); the app's `GET /v1/doctor` also carries `reward_models` (the §7.3 object, or null).
--fix re-applies only FRAGMENT-DAMAGED/MISSING fragments via the §8 idempotent apply,
  and runs the §8.3.1 release reconcile first (a stale OK/USER-EDITED fragment is
  brought to this release's bytes; `reprovisioned` names each); it never touches user
  bytes outside our markers.
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
stdout (--json): { "ok": true|false, "checked": {receipts, checkpoints, leaves_sampled},
  "intact_prefix_seq": 5121, "last_good_seq": 5121,
  "defects": [ {"seq": …, "kind": "hash_mismatch|sig_invalid|gap|fork|witness_mismatch",
                "detail": "…"} ] }
Exit: 0 chain valid; 5 any defect (defects are enumerated, never summarized away);
  2 usage; 1 I/O.
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
  "post_image_hash": "blake3:…",
  "fragment_checksum": "blake3:…",
  "applied_at": "…", "applied_by": "mark1d/1.4.2" }
```

Storing the original bytes, not just their hash, is what makes byte-equality restoration a guarantee rather than a hope.

### 8.3 Idempotent apply

```
apply(target, fragment):
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

#### 8.3.1 Release upgrades reach existing installs

A release that changes a capture fragment's bytes (a new hook, a new `mark1.js`) must reach users who enabled an earlier one without asking them to re-run `mark1 enable`. `provision.Reconcile` (go/mark1d/adapters/provision/reconcile.go) is step 2(c) driven by what is already on disk:

- **When:** every mark1d on-window start while at least one workspace is enabled — so the first start after `mark1 update` restarts the daemon — on `POST /v1/agents/{name}/resume` for that agent, and on `mark1 doctor --fix`. `mark1 enable` and the app's re-provision action already run the full §8.3 apply.
- **Which fragments:** only an agent's capture fragment whose §8.2 manifest exists and whose classification is OK or USER-EDITED, re-applied at the `target_path` the manifest recorded (never a path re-derived from the daemon's own environment). The apply is non-forcing: a current fragment is not opened for write (2b); a stale one has only our payload replaced (2c), atomically, with the pre-image untouched.
- **Never:** Mark 1 off (§7.6) or `MARK1_DISABLE=1` — nothing runs; a paused agent — skipped until resume; a reverted agent (no manifest) — nothing re-added; a fence the user edited (FRAGMENT-DAMAGED) — refused, M1E-7102, logged at WARN, left for `doctor --fix`; a fragment the user removed (MISSING) — not re-added. The base-URL and Copilot env pointers are not reconciled: re-pointing an agent at the proxy is `mark1 enable`'s eligibility decision.
- **Record:** each successful apply or reconcile writes `provisioned/<agent>/release.json` (`{version, fragment_checksum, at}`, 0600) — the release whose fragment is on disk; revert deletes it with the manifest. mark1d logs every upgrade at INFO; `mark1 doctor` and `GET /v1/agents` (`provisioned.provisioned_by`) show it per agent.

### 8.4 Revert — and how `mark1 off` restores byte-equality

```
revert(target, manifest):
  1. read target.
  2. if blake3(target) == manifest.post_image_hash:
       → the file is exactly as we left it: restore manifest.pre_image VERBATIM
         (atomic write). Result is byte-identical to the pre-Mark1 file. Report
         byte_equality: true.
  3. else (the user edited the file after we did — their bytes, their ownership):
       → surgical removal: delete exactly our block (B: markers inclusive, plus the
         one trailing newline we added; JSON: remove exactly manifest.pointers and
         the _mark1_managed object, touching nothing else).
       → report byte_equality: "surgical" with a diff summary; doctor retains it.
     3b. UNLESS the block itself no longer verifies (the recorded checksum does not
         describe what is at the pointers, or the _mark1_managed object is gone):
         → write NOTHING. Report kind `fragment-damaged` and list, in `retained`,
           which of our pointers are still set. §7.4 already fixes this reading:
           what we cannot verify is FRAGMENT-DAMAGED, and the safe response to
           "I cannot tell what is in there" is the one that refuses to write.
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
| auth | `M1E-1007` | team role does not permit this (`reason`: not_owner, not_member, invite_email_mismatch, user_token_required) — 15-teams | 403 | no | yes | fail-closed |
| auth | `M1E-1008` | sharing to the team needs the author's team consent (`reason`: consent_required) — 15-teams | 403 | no | yes | fail-closed |
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
| team | `M1E-2011` | team state conflict (`reason`: already_in_team, own_team, owner_of_team, team_full, owner_cannot_leave) — 15-teams | 409 | no | yes | fail-closed |
| team | `M1E-2012` | invite or member not found (`reason`: invite_invalid, member_not_found) — 15-teams | 404 | no | yes | — |
| evidence | `M1E-2013` | no E1 evidence held for the task (none uploaded, unbound, withdrawn, deleted, past 30 d, or the device's consent for the read's purpose is off) — 16 L10 | 404 | no | no | fail-closed (the judge falls back to E0) |
| consent | `M1E-2014` | a register consent enable whose `judge_id` is absent or not the route's current key: the caller's copy describes another processor (`reason`: consent_copy_outdated) — §3.7b | 409 | no — update the app | yes | fail-closed (nothing written) |
| policy | `M1E-3001` | bundle signature invalid | local | next poll | doctor | **fail-static** (keep last-known-good) |
| policy | `M1E-3002` | bundle seq non-monotonic | local | next poll | doctor | fail-static |
| policy | `M1E-3003` | transparency-log inclusion proof missing/invalid | local | next poll | doctor | fail-static |
| policy | `M1E-3004` | unknown channel | 404 | no | yes | fail-static |
| policy | `M1E-3005` | command string in a bundle section | local decode | no — bundle rejected whole | doctor + ACK `rejected` | fail-static (and the compiler bug is a P1) |
| policy | `M1E-3006` | bundle past `max_age`, control plane unreachable | local | keeps polling | status (`stale: true`) | fail-static → conservative built-in defaults; verdicts flagged `stale_cert` |
| fabric | `M1E-4001` | socket path is a symlink / bad perms | local | no — daemon refuses start | yes | fail-closed (start refusal) |
| fabric | `M1E-4002` | frame `len` outside `0 < len ≤ M1PL_MAX_FRAME` (§4.2) | local | no — connection closed | no | fail-open (writer spills) |
| fabric | `M1E-4003` | first frame not `Hello` / version mismatch | local | no | no | fail-open |
| fabric | `M1E-4004` | loopback `Host` not the bound literal | 403 | no | security event | **fail-closed** |
| fabric | `M1E-4005` | loopback request carries `Origin` | 403 | no | security event | **fail-closed** |
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
- **Desktop app (Mark1-GUI) vs a newer cloud:** a released app parses every response with its own zod schemas, so a cloud response never re-types, nulls or drops a field a released app requires. Held by `appapi/testdata/app-v0.1.14/` (v0.1.14's schemas, transcribed) and `releasedApp` in every appapi response test, plus `TestTVOReportParsesInTheReleasedApp`. What that bought in this release: a trend day with no verified outcome is absent rather than `tvo: null`; a session's `tokens_saved` is floored at 0 (v0.1.14 reads a count) and the signed savings.v3 net rides the new `tokens_saved_net`; a register consent enable without the key the app's copy describes is 409 (§3.7b).
- **Hook payloads:** vendor-versioned, absorbed by `agent_maps` (§5 rule 1); an unabsorbable break is `Dropped{unsupported_agent_version}` plus a conformance-fixture update, never a guess.

---

*End of 08 — API Contracts. Schema DDL and binary layouts this document references live in 07; component internals in 04/05/06; the tests that hold every contract here live in 12.*
