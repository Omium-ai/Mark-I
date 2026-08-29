# Reconciliation ledger

**Status:** open. Compiled 2026-08-28 during the design-documentation phase, from findings
reported by the document authors as they wrote. This file is the input to the reconciliation
pass and to the four founder-decision ADRs.

**Resolution rule:** the frozen plan (`spec/execution-plan-v2.md`) wins over the architecture
spec; the spec wins over any design document. Where reality contradicts the plan, that is a
finding raised to the founder, **not** a document quietly amended and **not** an edit to the plan.

Severity:
- **S1** — a real design decision is missing or two decisions are incompatible. Needs a
  founder or an ADR before code.
- **S2** — two documents state different numbers or names for the same thing. Mechanical fix,
  but it must be picked and applied everywhere.
- **S3** — a typo or a stale sentence in a source document. Fix in place, no decision needed.

---

## S1 — decisions that must be made before code

### R-01 — AWS KMS does not support Ed25519
*Found by `09`. Affects: the plan's receipt section, `07` part 2a, `04` (`mark1-receipt`), `10` §9.*

The plan says two things that cannot both hold: receipts use **Ed25519 chain primitives**
(vendored from `recovery-orchestrator/app/receipts/keys.py`) **and** bundle/server signing keys
are **KMS-resident**. KMS offers RSA and ECDSA (P-256/P-384/P-521); it does not offer Ed25519.

`09` proposes: P-256 in KMS for the server chain key, bundle signing keys and the update key;
Ed25519 retained on devices where the private key is locally held; `key_id` carries an algorithm
prefix, which the vendored `keys.py` scheme (`"ed25519:" + sha256(pub)[:16]`) already
accommodates. The offline verifier must then implement both.

**Decision needed** — goes into **ADR-0004 (key ceremony)**. Alternatives: (a) `09`'s split,
(b) Ed25519 everywhere with server keys in CloudHSM or a self-managed KMS, (c) P-256 everywhere
including devices, dropping the vendored Ed25519 reuse.

### R-02 — the verdict → KTO label mapping does not exist anywhere
*Found by `07` part 3. Affects: `06` §12, `07` part 3 §7, the corpus exporter.*

Mark 1's vocabulary is four-valued (`satisfied | violated | refused | error`). The trainer's
`KtoRow` wire shape is binary (`desirable | undesirable`, reward 1 | 0). Neither the plan nor the
spec says what happens to `refused` and `error` rows at export.

`07` resolved it in-document by **excluding both from KTO**, citing Paper II's argument that
infrastructure failure is not a quality signal. That reasoning is sound, but it is a decision
being made by a document author, not a recorded one.

**Decision needed** — new **ADR-0009 (verdict→label mapping for corpus export)**. Note the
second-order effect: excluding `error` rows silently biases the corpus toward environments where
the toolchain works, which is exactly the population where verification is cheapest.

### R-03 — `VerifiedTrajectory` has no `completion` field
*Found by `06`. Affects: `06` §12, `07` part 3 §7, `omium-training-plane`.*

`07` assumes the Mark 1 KTO seam works without touching the trainer, because `rows.jsonl` is the
`VerifiedTrajectory` wire shape. But the Rust `VerifiedTrajectory` in `omium-vrr-common` — as
constructed throughout `data-refinery/src/corpus/mod.rs` — **has no `completion` field**; only the
Python `KtoRow` mirror carries it, as an extension. Mark 1 rows have no `jsonl_ref` to deref, so a
Mark 1 row round-tripped through the refinery loses its inlined completion and the trainer falls
back to `render_completion(fix_class)` or drops the row — potentially the entire Mark 1 corpus.

`06` §12.2 resolves it normatively: one additive, serde-defaulted `completion: Option<String>` on
`VerifiedTrajectory`, plus a round-trip conformance test.

**This is the one change Mark 1 needs in another repo.** It is additive and backward-compatible,
but it is a training-plane commit, and the standing constraint is that Mark 1 changes nothing
outside its own repo. **Founder call: authorize the one-field training-plane change, or have the
Mark 1 exporter write the trainer's expected shape directly and skip the refinery.**

### R-04 — Phase 6 has no gate
*Found by `02`. Affects: `02` §10, `12` §12.*

Every assembly phase in the plan ends with a bold **Gate:** sentence except Phase 6, in both the
plan and spec §8. `02` derived one and marked it clearly as non-verbatim; `12` adopts it.

**Decision needed:** founder either ratifies the derived gate or writes the real one. Low urgency
— Phase 6 is far out — but it should not be forgotten, because an ungated phase is where scope
quietly returns.

### R-05 — staging is internally contradictory in the estate
*Found by `09`. Affects: `09` §9, and anything that assumes a staging environment exists.*

`envs/staging/providers.tf` and `deploy-prod.yml` say the staging account is "TBD", while
`values.staging.yaml` and the whole `argocd/omium-staging-*` tree pin account `910900236780` with
live-looking RDS and Redis endpoints. `09` targets prod-only for Phase 1 and flags this.

**Someone must establish which is true.** Not a Mark 1 decision, but Mark 1 cannot plan a
promotion path across an environment whose existence is ambiguous.

---

## S2 — same thing, two values; pick one and apply everywhere

### R-06 — M1PL frame length bound: 4 MiB or 1 MiB
*Found by `04`. `07` part 1 says ≤4 MiB; `08` §4.2 says ≤1 MiB with `HelloAck{max_frame: 1048576}`.*
Pick one. The larger bound accommodates a big tool-result payload; the smaller one is a tighter
memory-safety envelope. Whichever wins must appear in `07`, `08`, `04` and the fuzz target's
corpus policy.

### R-07 — local fabric endpoint paths differ
*Found by `04`.* `07` says `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock` with a SID-qualified Windows
pipe; `08` says `~/.omium/mark1/mark1d.sock` and `\\.\pipe\omium-mark1d`. `07`'s form is the
better one (XDG is correct on Linux, and SID-qualification is a real security property), but `08`
is the interface document, so the value must be picked and both updated.

### R-08 — who stamps `seq`
*Found by `04`.* The plan and spec say the hookshim "stamps UUIDv7 + seq"; `07` assigns `seq` at
`mark1d` admission. `04` followed `07` — correctly, since per-session monotonicity is only
well-defined at the single writer, and multiple shim invocations cannot coordinate a counter.
**Recommend ratifying `07`'s placement** (shim stamps `event_id` only) and treating the plan's
phrasing as loose rather than normative.

### R-09 — cortexd MCP tool names
*Found by `08`, `04`, `06`.* Spec C6 names five tools including `expand`, and omits
`ranked_files` and `memory_recall`. `08` documents six: `repo_map / find_definition /
find_references / deps / ranked_files / memory_recall`, and `04` and `06` follow `08`.
**Recommend ratifying `08`'s set** — it is the interface document and the names are better — and
correcting the spec.

### R-10 — client crate count
*Found by `01`, `03`, `07` part 1.* The plan says "9 deployables + **4** client crates" and lists
four. Spec §2's heading says "+ **2** client crates-as-binaries" while its body lists three or
four. **The plan wins: four crates** (`mark1-redact`, `mark1-receipt`, `mark1-policy`,
`m1p-wire`), with `mark1-frames` a fifth, proxy-internal crate listed separately. Fix the spec
heading.

### R-11 — proxy and gateway phase numbers
*Found by `02`, `03`.* Spec §0's C1.7 disposition places the proxy in Phase 2 and the gateway in
Phase 4. The plan and spec §8 both place them in Phase 3 and Phase 5. **The plan wins.** Fix
spec §0.

### R-12 — `buf breaking` target
*Found by `07` part 1.* The estate's `buf.yaml` uses `breaking: FILE`; the plan mandates
`WIRE_JSON` for `m1p`. **The plan wins** — `m1p` is an external wire contract, not an internal
one, and WIRE_JSON is the correct strictness for it. Divergence from the estate is deliberate and
is recorded in `07` §1 and `13` §5.

### R-13 — Python protobuf plugin
*Found by `07` part 1.* The plan names `betterproto`; the estate pins
`buf.build/protocolbuffers/python:v29.3`. `07` followed the plan and recorded the estate plugin
as the ADR fallback. Low stakes, but pick one before the first `buf generate`.

### R-14 — is `querychoke` really the only ClickHouse principal
*Found by `07` part 3.* The plan says query-choke is "the only ClickHouse principal", while the
same plan has `controld.ingest` doing ClickHouse async-insert. `07` reconciled it as **two
credentials — INSERT-only and SELECT-only — both held solely by `controld`, with all reads
exclusively through the choke**. That preserves the security property the sentence was protecting.
Ratify the wording.

### R-15 — enrollment fingerprint registration has no endpoint
*Found by `05`.* The spec's OAuth guard requires credentials "HMAC-fingerprint-matched to
enrollment", but `08` §3.1 defines no endpoint that registers a fingerprint. `05` §3.6 specifies
`POST /api/v1/enroll/fingerprints` and flags it as an additive row `08` must adopt. **Adopt it.**

---

## S3 — stale or wrong in a source document

### R-16 — AWS account IDs have drifted in three places
*Found by `09`.* `Omium-platform/terraform/README.md` disagrees with the live backends, and the
platform chart's default `values.yaml` carries a **third** prod account ID (`650790810654`). The
live values are mgmt `169805602430` and prod `965384155704`. `09` cites the live values. The
platform-side files are not ours to fix under the no-platform-changes constraint — raise it.

### R-17 — prod has no monitoring kustomization
*Found in the estate scan; carried by `09` and `11`.* Staging has one, prod does not. Mark 1 must
land its own rather than inherit an absence. Alertmanager is likewise a comment.

### R-18 — spec §9 lists ten compliance points, the plan lists seven
*Found by `02`.* The spec's list is a superset, adding evidence typing, training and
auditability. Not a contradiction — `02` covered the extras and `10` carries all ten in its
control matrix. Recorded so nobody later "fixes" the plan to match.

### R-19 — `filter_by_sigs` drops signature-less rows
*Found by `06`.* In `data-refinery`, `filter_by_sigs` drops rows without signatures when the
signature set is non-empty. This is **correct** for Mark 1 (every Mark 1 row is receipted and
signed), but it is surprising enough that it is worth stating so nobody later "fixes" it into a
pass-through and silently admits unsigned rows.

### R-20 — `scan_worm` is HTTP today, not S3
*Found by `06`.* The current `CorpusReader::scan_worm` is the Option-A HTTP path against the
orchestrator. `scan_mark1` revives the S3 decode path and puts the currently-dead `fold_report`
helper back into use. Consistent with the plan; no conflict. Recorded because a reader of
`corpus/mod.rs` will otherwise think the S3 path is dead code and delete it.

---

---

## Second pass — findings raised during the operational-envelope documents

R-01…R-20 were compiled from the contract and design documents. These six surfaced later, from
`09`/`11`/`12`/`13`, and were each **verified against the live estate by the lead on 2026-08-28**
rather than taken on an author's report.

### R-21 — `EdgeHealth` is load-bearing in `11` and does not exist in `m1p.v1` — **S1**
*Found by the lead. Affects: `07` §3–§4, `08` §2, `11` §2.3/SLO-7/A-14.*

`11` refers to `EdgeHealth` thirteen times: it is the transport for the edge's low-cadence
diagnostic self-metrics (§2.3), the source of the `gate_read_seconds` p99 digests behind **SLO-7**,
and the cohort signal behind alert **A-14 (EdgeFleetRegression)**. It appears **zero times in `07`**
and **zero times in `08`**. The plan's event-family list does not contain it either.

This is not a naming drift — the message does not exist. Because the edge deliberately exposes no
metrics endpoint ("a laptop daemon exposing a metrics port is attack surface with no scraper",
`04` §2.11), `EdgeHealth` is the *only* channel by which fleet health reaches us. Without it, three
of `11`'s commitments are unimplementable and the edge is unobservable in production.

**Decision needed:** add `EdgeHealth` to `m1p.v1` as a **diagnostic-class** event (so it is
drop-newest on a full spool and never blocks, per ADR-0007), with its field set drawn from `11`
§2.3, and add the corresponding row to `08` §2. It must be defined **before the first
`buf generate`** — adding an event family later is a wire-compatible addition, but `11`'s Phase 1
SLOs assume it exists at Phase 1.

### R-22 — pod-annotation scraping may be scraped by nothing — **S1 (estate)**
*Found by `11` (recorded there as gap G-3); verified by the lead. Affects: `09`, `11` §12, `12`.*

Verified in the live estate:
- `infrastructure/terraform/modules/observability/main.tf` deploys **kube-prometheus-stack** via
  `helm_release`, with `serviceMonitorSelectorNilUsesHelmValues = false` and
  `podMonitorSelectorNilUsesHelmValues = false`, and **no `additionalScrapeConfigs`** — the string
  does not occur anywhere in `Omium-platform/` or `omium-gitops/`.
- **Zero** `ServiceMonitor`, `PodMonitor` or `ScrapeConfig` objects exist in either repo.
- A **second, hand-rolled Prometheus** lives in `Omium-platform/monitoring/` (a
  `docker-compose.monitoring.yml` with its own `prometheus/`, `alertmanager/`, `grafana/` trees).

The prometheus-operator does not honour `prometheus.io/scrape` annotations; it discovers targets
only through those CRDs. So the estate's universal annotation convention is, as deployed, scraped
by nothing — while both selectors are wide open and would happily consume CRDs that no one has
written.

This is the training-plane failure shape at the observability layer: perfectly-configured pods, a
green control plane, and no data. Mark 1 must not inherit it. **`09` adds an annotation-based
`additionalScrapeConfigs` job (or a PodMonitor) for its own namespace, and `12` adds the smoke
test `11` G-3 specifies — after deploy, assert `controld_ingest_requests_total` is actually
queryable in Prometheus.** Readiness-truth applied to monitoring itself.

The platform-side half is not ours to fix under the no-platform-changes constraint — **raise it**.

### R-23 — `checkpoint-manager` builds on `alpine:latest` — **S3 (estate)**
*Found by `13`; verified by the lead. Affects: nothing in Mark 1; recorded to prevent inheritance.*

`Omium-platform/core-services/checkpoint-manager/Dockerfile:45` is `FROM alpine:latest`. That is a
floating tag *and* a musl base, both of which the estate's own Rust convention rejected
(`rust:1.91-slim-bookworm` → `gcr.io/distroless/cc-debian12:nonroot`, glibc not musl) and which the
2026-08-13 `latest`-retirement decision rejected for images. Mark 1's Go images follow the
distroless convention in `13` §4 and pin by digest. No action for Mark 1; **raise the platform
instance** rather than silently diverging from a convention that has one live violator.

### R-24 — estate Python is 3.11, Mark 1 specifies 3.12 — **S2**
*Found by `13`; verified by the lead. Affects: `13` §3, `12` §9, the two Python services.*

Verified: `Omium-platform/.github/workflows/ci.yml` sets `PYTHON_VERSION: '3.11'` and every
`setup-python` in the estate consumes it; `enforcement-gates.yml` and `sdk-publish.yml` hardcode
`'3.11'`; `recovery-orchestrator/Dockerfile:2` is `FROM python:3.11-slim`.

Mark 1 is a **separate repo with its own CI**, so a version split is legal rather than a conflict —
but it is only free while nothing is shared. The moment `python/shared/mark1_receipts/` is vendored
from `recovery-orchestrator/app/receipts/`, a 3.12-only construct in the vendored copy makes the two
trees silently non-interchangeable, and the vendoring is a Phase 1 deliverable.

**Pick one and write it down:** 3.12 for Mark 1 with a rule that the vendored receipt module stays
3.11-compatible (recommended — the vendored code is small, pure-stdlib, and diff-checked against its
origin), or 3.11 for Mark 1 to match. Either way `13` §3 must state it explicitly instead of
assuming.

### R-25 — "kill -9 loses nothing" vs. the fsync torn-tail — **S2, resolved; wording must be fixed**
*Found by `04` (F-20) against the plan's verification line. Affects: the plan §Verification, `04`
F-20, `12` §6.2, ADR-0007.*

The plan's Phase 1 verification says "deliberate kill -9 mid-batch loses nothing in the
billing-grade classes." `04`'s failure catalog F-20 correctly notes that with a 250–500 ms fsync
cadence, a **power loss** can leave a torn tail and drop up to one fsync window of events.

These are different failures and both statements are true: `kill -9` terminates the process but
leaves the page cache intact, so the OS still writes the pages — nothing is lost. Power loss and
kernel panic are the lossy cases. ADR-0007 reasons the cadence by crash-loss class on exactly this
distinction, and `12` §6.2 states the testable form: **zero loss of *acknowledged* events**.

No decision needed; the design is coherent. **But the plan's sentence is loose enough to be read as
a durability guarantee against power loss, which we do not make and must never make to a customer.**
Every restatement outside the plan uses `12` §6.2's wording. Recorded so the looser sentence is not
propagated into a datasheet.

### R-26 — root `migrations/` vs. the estate's per-service trees — **S3, resolved**
*Found by `13`. Affects: `13` §2, `07` §8.*

The plan's repo layout shows a single root `migrations/`. The estate's convention is strictly
per-service (`core-services/*/migrations/` with service-prefixed `ro_0NN_*.sql`; **no root
`migrations/` exists in `Omium-platform`**).

`13` resolves this as root **plus** per-service: root `migrations/m1_0NN_*.sql` is the
**`controld`-owned core schema** (tenants/devices, receipt chain, bundles, ε ledger — the tables
`controld` is the sole writer for), while `adjudicator` and `intel` keep their own
`adj_0NN_*.sql` / `in_0NN_*.sql` trees. That is the estate convention applied honestly: one tree per
owning service, and `controld` happens to own the core.

No conflict with the plan — the root tree it drew is `controld`'s. Recorded so nobody later
"corrects" `13` back to a single tree and gives three services write access to one migration
sequence.

---

## Third pass — adversarial security/compliance review (2026-08-28)

A hostile external reader was given `10` in full, `07`'s privacy-bearing sections, `08` §§2–4,
`05` §§2/3/5/6/7/10, `04` §§3/4/9.6, and the frozen plan's compliance section, told the 20 known
findings were out of scope, and instructed to attack the seven product claims and audit whether
`10` §12's `compile-time`/`runtime`/`receipted` labels are honest.

It returned fifteen findings. **The lead independently verified SEC-01, SEC-02 and SEC-04 against
the actual document lines before recording them**; the rest are recorded with the reviewer's
citations and are marked unverified where they are. Verification status is stated per finding
because a reviewer's claim is not a finding until someone has read the line.

The reviewer's own summary of the set is worth keeping: *"These are not 'you forgot defense in
depth.' They are places where a specific sentence claims a property the specified mechanism does
not deliver."*

### SEC-01 — the off-switch is the compiled-in override the OAuth guard says does not exist — **S1, verified**
*Breaks claim 1 (never intercepts subscription traffic). Affects: `04` §3.1/§9.6, `10` §3.4/§3.8-A9/C-02/§3.9, `02` CON-013.*

Verified by the lead. `10` C-02 (`10:531`) asserts *"No override: no env var, flag, config, or
bundle path forwards an unprovisioned credential"*, and §3.9 (`10:215`) builds the legal position on
*"Omium's shipped binaries contain no path that forwards subscription traffic, no override to enable
one."* `04:527` and the §9.6 state machine (`04:952`) specify the opposite:

> `RECEIVED --> NOOP_FORWARD : off-marker present / pass through untouched`

`NOOP_FORWARD` is a **forwarding** state reached *before* the `M1-Cred-Ref` branch, before the
fingerprint check, before the shape tripwire, and it emits no `GuardDecision`.

**In fairness to `04`, it is not blind to this** — both lines scope it to a race window and note the
compensating control (*"`mark1 off` detaches the proxy (reverts the base-URL fragment), so in
practice traffic no longer arrives"*). The reviewer's rebuttal is the correct one and it holds: the
compensating control lives in **a different process**. Creating the off-marker directly
(`touch ~/.omium/mark1/OFF`) without running `mark1 off` never executes the fragment revert, so the
proxy stays attached and stays listening — and forwards untouched. `02` CON-013 (P0) then *mandates*
the marker be honoured "before any gate evaluation," so the behaviour is required, not incidental.

**The fix is smaller than the finding.** Off must mean **detach, never pass through**. Delete
`NOOP_FORWARD`: with the marker present the proxy refuses and closes (`403` +
`CoverageTransition{BYPASS}`). Being out of the request path means not answering, not answering
transparently. Then C-02 becomes true, A9 becomes true, and `12/guard-no-forward-path` becomes
provable. CON-013's "uncircumventable off" must be re-scoped in the same change to **gating and
capture, explicitly not the provenance guard** — the guard is a legality control and legality is
fail-closed, which is exactly what the failure-posture matrix already says.

### SEC-02 — the corpus exporter writes plaintext prompts and completions to an Omium bucket — **S1, verified**
*Breaks claim 3 / non-negotiable #3 (raw sessions and customer code stay client-side by default). Affects: `06` §12.1, `07` §Corpus schemas, `10` (absent entirely), R-03.*

Verified by the lead, and it is the most serious finding in the set.

`07:3384` is normative: Mark 1's exporter **inlines `completion`** into `rows.jsonl`, and the KTO
row schema carries `prompt str required`. `07:3396` names the destination:
**`s3://omium-mark1-corpus-prod`** — an Omium-owned bucket, not the customer's.

Every other document says this cannot happen. `07:3340`, *one page earlier in the same document*:
*"No paths, no excerpts, no diffs — the default-tier evidence rule holds in the corpus too; digests
only."* `05` §10.2: `controld` holds *"no raw code or prompts."* `10` §10.5: raw sessions live
client-side *"per the frozen plan's hard constraint."* And `10` mentions `completion` exactly
**once** in 110 KB — there is no control row, no test, and no §13 residual for what is, as
specified, the largest raw-content egress in the system. By `10` §12.11's own rule, *a control
absent from the matrix does not exist for compliance purposes.*

There is also a second-order impossibility the reviewer is right to name: the exporter runs
**server-side** (`mark1-intel.corpus-exporter`), and under E0 the server holds only typed records
and salted digests. So either the exporter cannot be built as specified — and the Phase 5–6 moat is
empty — or an unspecified raw-content upload path must exist that no document designs and no
scanner covers. There is no third option.

**This is adjacent to R-03 but is not R-03, and it inverts R-03's disposition.** R-03 asked whether
the Rust `VerifiedTrajectory` needs an additive `completion` field — a schema-compatibility
question. Nobody asked what it means that the field carries the customer's code into Omium's
bucket. **R-03's proposed resolution makes this privacy problem load-bearing across two repos, so
R-03 must not be authorized until SEC-02 is decided.**

**Founder decision, before Phase 5, and it is a product decision not an engineering one:**
- **(a) Preferred — the corpus stays digest-only and the KTO pair is written client-side** into the
  customer's own bucket (the E2 posture), with only the manifest and the export receipt reaching
  Omium. The constraint holds, the claim stays true, and the moat survives: we still get the labels,
  the lineage and the receipt, and per-tenant training runs where the data already is.
- **(b) Corpus contribution becomes an explicit E1-class, per-tenant, contractual, receipted
  opt-in**, with the admit-to-upload scanner running over `prompt`/`completion` on the export path,
  a new `10` §12.9 control row, a §13 residual, and DPA language. **The marketing claim then must
  change** from "your code stays client-side" to "…unless you opt into corpus contribution."

Doing (b) silently is the one option that is not available.

### SEC-03 — the erasure story over-claims, and the schema forbids the deletion the deletion path mandates — **S1, unverified by the lead**
*Breaks claim 6. Affects: `07` §Retention steps 3–5, `07` §Federation FKs, `10` §13.*

Two parts. **(a)** `07` §Retention step 5 says key destruction *"is the backstop that makes steps
2–3 not need to be perfect."* Step 2 is S3 and is genuinely crypto-erasable. Step 3 is ClickHouse
and step 4 is Postgres, and **neither is encrypted under the per-tenant key** — that key is bound to
the S3 prefix by bucket policy and nothing else. The ClickHouse step is an async `ALTER … DELETE`
mutation with no completion signal in the receipt set and no reach into backups; RDS PITR retains
deleted rows under an account-level key that the tenant HMAC salt has nothing to do with.

**(b)** `publication_span_producers.contribution_id` and `artifact_publications.artifact_id` are
`REFERENCES … ON DELETE RESTRICT`. Step 4 says *"delete memory artifacts, artifact contributions."*
For any tenant that ever contributed to a published artifact, the offboarding transaction **aborts**
— and `artifact_contributions` is tenant-attributable by construction, since it is the table the
(k,m) gate counts `DISTINCT tenant_id` over. The "deliberately does not delete" list names witness
heads, the receipt chain, the ε ledger and published artifacts; it does **not** name these, so this
is an unacknowledged, schema-enforced refusal to erase, discovered when the job first runs.

**Fix:** scope step 5's sentence to what it covers ("S3 objects and backups under the tenant
prefix"), state the enumeration-based residual for CH/PG with its backup-window bound in `10` §13,
gate the offboarding receipt on `system.mutations … is_done=1`, and decide explicitly whether
`artifact_contributions` survives as legitimate-interest audit evidence (then say so in the list and
defend it) or is tombstoned with the org-count frozen at publication. Silently colliding is the only
option that fails.

### SEC-04 — two incompatible Postgres role inventories, and the NOBYPASSRLS test checks one role by name — **S1, verified**
*Breaks claim 4. Affects: `05` §7.1/§7.3/§7.5, `07` §Roles and grants, `10` §6.2/C-29/C-30.*

Verified by the lead. `05:198`/`05:574` define `controld_app`, `controld_worker` (BYPASSRLS) and
`controld_migrate`. `07` grants extensively to **`adjudicator_app` and `intel_app`**
(`07:1094–1099`, `07:1380–1381`) and names `mark1_federation_worker` as the single BYPASSRLS worker.
`controld_worker` appears **nowhere in `07`**; `intel_app`, `adjudicator_app` and
`mark1_federation_worker` appear **nowhere in `10`**.

These disagree on substance, not naming: `05` §7.3 lists `dprelease/epsledger.go` as a BYPASSRLS
path; `07` says the DP release runs under `set_local_tenant` and needs no bypass. **Which jobs are
cross-tenant by specification is a design decision, and two documents answer it differently.**

**The reviewer's second claim — that the test set is name-scoped and misses this — is mostly
wrong, and the lead's verification is the reason it is recorded that way.** The reviewer read
`05` §7.5 and `10` §12.5 but not `12`'s isolation suite, which is stronger than either:

- `12` §isolation broadens the assertion to *"`rolbypassrls = false AND rolsuper = false` for
  `controld_app` **and every `*_app` role in the migration set**"* — not one hard-coded name.
- `neg_bypassrls_role_connection_refused` already **is** the boot refusal the reviewer proposed: a
  scratch BYPASSRLS role's DSN handed to the pool constructor must fail `AfterConnect` with
  `errBypassRLSRole`, checking `rolbypassrls OR rolsuper` for `current_user` **on the live
  connection, where inheritance has already resolved**.
- `neg_bypassrls_inherited_membership` covers the exact estate failure — privilege arriving via
  role *membership* rather than the role's own attribute.
- `test_rls_cross_tenant_denied` is table-list-driven from `pg_policies`, so a new tenant-scoped
  table without a policy fails by omission.

That is a better answer to the decorative-RLS incident than the reviewer credited. **What survives
is the inventory contradiction, which is the S1**, plus one genuine test gap: `*_app` is a naming
convention, not a predicate, so a *worker* role holding `BYPASSRLS` under a name that does not end
in `_app` is outside the static assertion's scope. The runtime boot refusal still catches it at
connect time, so this is defence-in-depth rather than a hole.

**Fix:** reconcile the inventory across `05`/`07`/`10` — that is a design decision about which jobs
are cross-tenant by specification, and it is the part that actually blocks code. Then make the
static assertion allow-list-driven rather than convention-driven (`SELECT rolname FROM pg_roles
WHERE rolcanlogin AND (rolbypassrls OR rolsuper)` must equal a hard-coded list) so it stops
depending on a naming habit, and add the missing roles to `10` §6.2 and C-29/C-30.

*Related, and it will bite on first use:* `trg_epsilon_budget` runs `SELECT … FOR UPDATE` on
`tenant_privacy_budgets`, but `07` grants `intel_app` only `SELECT` on that table. Postgres requires
`UPDATE` privilege for `SELECT … FOR UPDATE`. The gate fails with a permission error, and the
natural under-deadline fix — `SECURITY DEFINER` — makes the trigger run as owner and **bypass RLS
inside the trigger body**. Grant `UPDATE` now and test the trigger under the granted role.

### SEC-05 — ClickHouse `payload String` is unbounded free text, and skip-and-retain routes around both scanners — **S2/S1, unverified**
*Breaks claims 2 and 3. Affects: `07` §ClickHouse, `05` §2.1 stages 5 and 7, `10` §5.4.*

`mark1.m1p_events` carries `payload String CODEC(ZSTD(3))` — a per-event, 760-day-retained,
arbitrary JSON column — while `10` §5.4's compensating control is that the scanner sits *"behind a
wire format that mostly has no field for a secret to ride in."* `payload` is that field, and `10`
never mentions it.

The bypass is the worse half: `05` §2.1 stage 5 retains unknown event types raw, and stage 7's
independent server scanner *"scans every string field of every event"* — which an undecoded unknown
type does not have. A compromised device (in scope per `10` §0.4) emits an unknown `event_type`
within `m1p.v1` carrying arbitrary bytes; they land in the **S3 replay log**, the prefix `05` §2.3
exists to keep secrets out of *because it is replayed mechanically forever*. Separately,
`EvidenceRecord.tool` and `.diagnostic_code` are unbounded proto `string`s whose "finite public
vocabulary" is a comment, not a validator.

**Fix:** the second scanner runs over **raw bytes** for anything the decoder classified as unknown;
`payload` gets a typed per-event-type registry or a hard byte cap with scanner coverage; length and
charset validators for `tool`/`diagnostic_code` at ingest stage 6; a `10` §12.3 control row; and a
`12` negative test planting a secret in an unknown-type event and asserting quarantine.

### SEC-06 — ClickHouse has no *write*-side tenant isolation — **S2, unverified**
*Breaks claim 4. Affects: `05` §6, `10` §6.2/§6.3/§2.3.*

The `querychoke` construction proof is a proof about **reads**, and an excellent one. The `INSERT`
path is the acknowledged wiring exception, and the projector runs post-ack and asynchronously from
the S3 landing object — with nothing structural binding the `tenant_id` it writes to the token
claims that landed the object. No row policy, no per-tenant key (S3-only), no `CHECK`, no `Build()`
marker, and no negative test: `10` §6.3 admits the S3 arm is missing but the ClickHouse *write* arm
is not even named as missing, and §2.3's cross-tenant-write row covers only S3.

A projector or replay-listing bug therefore writes tenant A's events into rows labelled B, after
which `querychoke` faithfully serves them to B, *correctly tenant-predicated on the wrong label.*
**Fix:** store `tenant_id` inside the landing object's canonical bytes and have the projector read
it from the object, never from the key path; add a live two-tenant cross-**write** negative; add the
`10` §12.5 row; and state in §6.2 that ClickHouse isolation is read-side with the write-side control
named separately.

### SEC-07 — witness statements may publish per-tenant hourly activity to a permanent public log — **S2, unverified**
*Breaks claims 4 and 6. Affects: `07` §Witness heads, `05` §4.4, `08` §3.5.*

`07` publishes, hourly and **per tenant**, a signed statement containing `tenant_id, seq, hash,
checkpoint_seq, witnessed_at` to *"a public transparency log and/or the customer's own object-lock
S3 bucket"*, with `log_backend` exampled as `'rekor'`. `08` §3.5 states of the public endpoints:
*"Nothing tenant-identifying is served on any of these paths."* Whether the tlog leaf is the
statement or its hash is **never specified**, and `05` §4.4 implies a different answer than `07`.

Under the Rekor reading, any observer can enumerate each customer's hourly engineering-activity
volume forever — crunch periods, incident nights, the week a team was laid off — and one leaked
`tenant_id` de-anonymises the whole history retroactively. It is also **unerasable by construction**:
witness heads are excluded from offboarding and the customer bucket is COMPLIANCE-locked.

**Fix, and it is the obvious one:** leaves are `SHA-256(statement)`; the statement itself goes only
to the customer's own object-lock bucket; the tenant identifier inside it is per-tenant salted. The
customer can verify; the public log anchors a hash and reveals nothing; `08` §3.5's sentence becomes
true. Residual for the aggregate leaf-count signal (which leaks Omium's customer count, not the
customer's data). **This must be decided inside ADR-0004 while witness selection is still open** —
it is precisely the kind of thing that gets defaulted under time pressure on ceremony day.

### SEC-08 — exact un-noised `k`/`m` are released to every tenant — **S2, unverified**
*Breaks claim 5. Affects: `05` §5.4 step 6, `08` §3.6, `07` §Federation.*

`05` §5.4.6 is normative that the exact counts *"are never released."* `08` §3.6's
`GET /api/v1/federation/releases` returns `"k": 31, "m": 6` — exact, noiseless, zero ε charged,
because k/m are classified as gate inputs rather than statistics.

That is a differencing oracle. A tenant observes `k` with its contribution present, opts out via
`POST /federation/optout`, observes `k` again, and reads an exact answer to "how many other tenants
produce this pattern" — repeatable across kinds and clusters until it holds a census of the
population's engineering practices. The design rejects thresholding on noisy counts *specifically
because the threshold test leaks partition existence*, then publishes the count.

**Fix:** return `"k_gate": "passed"` and drop the numbers — nothing a customer needs is lost. Also
make opt-out one-way within an accounting window so the toggle is not a repeatable oracle.

### SEC-09 — ε is a lifetime sum in the trigger and "per calendar year" in prose — **S2, unverified**
*Breaks claim 5. Affects: `07` `trg_epsilon_budget`, `05` §5.2/§5.6, `10` §10.3, `08` §3.6.*

The trigger sums `epsilon_ledger` with **no window predicate** and the ledger is append-only, so as
implemented the cap is a **lifetime** cap. `10` §10.3 and `05` §5.2 both say *"ε = 4.0 per calendar
year"* and `05` §5.6 offers *"budget renewal at the window boundary"* as an unblock.

Both readings have a problem. Lifetime: the guarantee is strong and real, but the promised renewal
cannot happen and tenants will hit a permanent wall while being told otherwise. Annual: composition
is linear across renewals, so cumulative loss is ε = 20 after five years and ε = 40 after ten —
`e^40` is a number, not a privacy guarantee, and nothing bounds lifetime loss or tells the customer
the ε they were sold is per-year rather than per-relationship. **A reviewer with DP background asks
"ε over what horizon?" in the first ten minutes.** Decide, make the trigger and the API agree, and
if annual, add a second lifetime cap.

### SEC-10 — a tenant can veto the federation by exhausting its own ε — **S2, unverified**
*Affects: `05` §5.5/§5.6, `10` §11, §13.*

`05` §5.5 charges every contributing tenant the full `ε_release`, and §5.6 correctly refuses the
whole release rather than dropping an over-budget tenant (dropping would let budget pressure reshape
published content — a real side channel, rightly closed). But a tenant that spends its own budget
early then **permanently blocks every candidate artifact its data touches** for the rest of the
window, at zero marginal cost and with no privileged access. At k = 25, a high-volume tenant is in a
large fraction of all clusters. The federation is the Phase 5 moat; one adversarial or merely-heavy
tenant stalls it at zero.

**Fix, and it preserves §5.6's reasoning exactly:** exclude exhausted tenants at **candidate
selection**, before any content-dependent computation — a decision made upstream of intersection
counting cannot reshape published content. Residual for the mid-window case.

### SEC-11 — the canary controller is a live cross-tenant channel; B-T claims an absolute — **S3, unverified**
*Affects: `10` §1 (B-T), §6, §11.4; `05` §4.3/§7.3.*

`10` §1's B-T row says *"nothing crosses except `dprelease` outputs"*, restated four times. `05`
§7.3 justifies `policydist/canary.go` as BYPASSRLS precisely because *"cohort-vs-control comparisons
span tenants"*, and §4.3 has those cross-tenant baselines **drive an automatic control action** —
halting a rollout. So tenant B's metrics determine whether tenant A's bundle widens; a tenant that
inflates its own `Dropped{}` rate moves the fleet baseline for everyone, and because halts are
observable via bundle `seq` and `mark1 status`, two colluding tenants have a low-bandwidth covert
channel across a boundary stated as carrying nothing.

**Fix:** scope the baseline per-tenant (which is what you actually want for a per-tenant rollout
anyway), or amend B-T to name the exception and add a §13 residual. Do not leave the absolute
standing next to `05` §7.3.

### SEC-12 — the sock-puppet defence is a reviewer's judgment with a fail-open default — **S2, unverified**
*Affects: `07` §Federation `collusion_group_id`, `10` §12.6 C-38, §11.2, §13 R-3.*

`collusion_group_id uuid NOT NULL DEFAULT gen_random_uuid()` — every org is its own group until a
human enrollment reviewer merges it. The schema comment argues *against its own default*: it says
fail-toward-more-distinct would inflate `m`, then picks the default that does exactly that
(maximising `count(DISTINCT collusion_group_id)` makes `m` **easier**, not harder, to satisfy).

C-38 is labelled **`runtime`**. The two verification predicates are genuinely runtime; **collusion
collapse is not** — it is discretionary human judgment with a fail-open default, and
`12/federation-collusion-collapse` can only assert that *given* a shared group id the count
collapses. That tests the `GROUP BY`, not the control. Consequently §11.2 and §13 R-3 price the
sock-puppet attack at *"four real, distinct, paying corporate identities maintained convincingly"*
when the true price is four shell entities that clear a payment check and a DNS challenge without a
reviewer connecting them — under a thousand dollars, not four real companies.

**Fix:** split C-38 into `runtime` (verification predicates) and **`policy`** (collapse) with a §13
residual; re-price R-3 honestly; and **invert the default** — group automatically on billing
instrument fingerprint, payment-processor account, NS ASN, WHOIS registrant or shared IdP issuer,
and require a reviewer to *split* rather than to merge. That inversion is one line of DDL and a job,
and it is the whole fix.

### SEC-13 — three §12 rows claim a stronger enforcement class than the mechanism supports — **S2, unverified**
*This is the honesty audit `10` §12 was asked to survive. Affects: `10` §12.*

- **C-16** (admit axis, `compile-time`): true of the **Rust** crate, whose API cannot express a
  bypass. But `10` §5.2 has `mark1d` carrying a **Go** admit implementation validated bit-identical
  by conformance vectors — and `mark1d` is the *only spool writer*, so the Go path, not the Rust
  one, is the last line before the only upload source. Vector equality is a **CI** property over a
  finite set; it proves agreement on the vectors, not absence of a bypass in the Go code. Correct
  labels: `compile-time` (Rust) + `CI` (equivalence) + a new `runtime` row for "the Go admit path is
  unconditionally invoked in capture stage order," which has no test of its own today.
- **C-49** (E0 no free text, `compile-time`): `EvidenceRecord.tool` and `.diagnostic_code` are proto
  `string`s, and a protobuf string has no compile-time content constraint in any of the three
  languages. Correct label `runtime` — and the validator it implies **does not exist in any
  document** (see SEC-05).
- **C-05** ("provable refusal", `receipted`): honestly labelled, but §3.7's word *provable* is not.
  `GuardDecision` is **sampled**. Sampling proves *some* refusals happened; the compliance claim is a
  universal (*no* forward happened) and sampling cannot support a universal. Either receipt refusals
  per-event — they are rare, a refusal means something is misconfigured — or state in §3.7 and §13
  that the receipts evidence the guard *operating*, and the absence-of-forward claim rests on the
  binary audit in §3.9.

The reviewer credited §12.11's matrix-lint (fail the build on a non-`policy` row naming no test, and
a `policy` row with no §13 residual) as *"a genuinely good idea I have not seen elsewhere"* — with
the caveat that it checks **presence** of a test, not **fitness** of the class, so the enforcement
column needs one human audit pass. This finding is that pass's first output.

### SEC-14 — "fingerprints orphaned atomically" has no edge mechanism — **S3, unverified**
*Affects: `10` §9.1, `05` §3.4/§3.6, `04` §3.1.*

`10` §9.1 claims operator revoke *"orphans fingerprints atomically (guard forwards nothing)"*. But
the guard's check is explicitly **edge-local** against a registry recorded at provisioning, and
`05` §3.4's edge-side revocation contract — stop uploading, stop requesting bundles, purge
secret-bearing deliveries — **does not include clearing the proxy's provision registry**. Server-side
orphaning therefore reaches the proxy only on daemon restart, so a revoked device keeps forwarding
against its cached table.

Direct harm is small (the customer's own key, their own traffic, their own vendor — we simply stop
observing). The problems are that §9.1 states a control that does not exist, in the table an auditor
reads most carefully, and that `07`'s deletion path leans on revocation meaning *"edges stop
capturing immediately."* **Fix:** purge the registry from the existing `event: revocation` SSE
handler, add `12/guard-registry-purged-on-revoke`, or soften §9.1 until it exists.

### SEC-15 — four smaller items — **S3, unverified**
- **The receipt `payload` is unconstrained text and is never deleted.** The only constraint is that
  it parses as JSON, yet `07` asserts the chain stores *"never content"*, and the table is
  triple-protected append-only and excluded from offboarding. Any receipt class that ever puts a
  hostname, path or workspace name in a payload has made it permanently undeletable. A per-
  `record_type` payload schema validated at append is cheap now and impossible later.
- **A single device token reads the whole tenant receipt chain** (`08` §3.4: *"device or operator
  token"*), so a compromised laptop reads every `memory_admission`, `corpus_export` and
  `bundle_publication` for the tenant — while `10` §6.4 claims a compromised device *"cannot read the
  ledger at operator scope."* Scope device tokens to their own `device_key_id`.
- **`05` §5.1 and §5.7 disagree on whether ε is spent before or after human review.** §5.1 orders
  ε-commit → review; §5.7 has approval execute the commit; `07`'s `trg_km_publication_gate` requires
  `approved` first, which implies §5.7. This decides whether a reviewer's "no" costs a tenant real
  budget — a customer-facing fact. The trigger is right; fix §5.1.
- **`10` §2.1 claims "no-network in cortexd"** with no mechanism named anywhere in `04` §6; the
  network-deny primitive is the *anchor sandbox's*, and cortexd is a long-running daemon, not a
  sandboxed anchor. Name the mechanism or drop the claim.

### What the reviewer could not break

Recorded because it is as useful as the findings, and because these are what we lead with in a
security review: the **`querychoke` construction proof** (*"the best thing in the estate"* — a
tenant-less query cannot be *constructed*, and the `OpsScope` type split means *"'forgot the tenant'
and 'meant fleet-wide' are different types, not different intentions"*) on the read side; the
**receipt chain schema** (genesis *equivalence* not implication; `seq` from a locked head so a gap
unambiguously means deletion; `payload` as `text` because `jsonb` re-renders bytes under a signature;
the `discontinuity` record type — *"the erasure is defensible, the silence is not"* — which the
reviewer had not seen done before); the **`M1-Cred-Ref` → credential-bytes fingerprint binding**,
which defeats both the stolen-ref attack and the realistic misconfiguration case at step 3 without
needing the shape classifier at all; **S3-first ack** (*"the ack is the durability claim"*); the
**quarantine-prefix decision**; and `10` §13's sixteen residuals with cost-to-close, which the
reviewer called *"the strongest single signal in the corpus."*

---

## Fourth pass — adversarial staff-engineer review (2026-08-28)

A hostile staff engineer was given `03`, `04`, `05`, `06`, `08`, `11`, `12`, `13`, `14` and the
known findings, told "we start coding Monday," and asked to attack eight axes: concurrency and
ownership, hot-path budgets without arithmetic, unreachable state-machine states, the three-language
boundary tax, build-order impossibilities, untestable test claims, operability without tracing, and
"the thing nobody planned for."

Thirteen findings. **The lead verified ENG-01, ENG-04, ENG-05, ENG-06 and ENG-08 against document
lines**; the rest carry the reviewer's citations. Its "checked and holds" list is recorded at the
end because a design that survives a hostile read on eight axes is worth knowing about precisely.

### ENG-01 — Phase 2's gate needs the bundle plane Phase 3 delivers — **S1, verified**
*Axis E (sequencing). Affects: `14` §2/§4, `04` §2.3/§2.6/§5, `12` §12 Phase 2.*

Fusion is *"pure math over bundle data … nothing here is edge-invented"* (`04` §2.3); the knee runs
on the bundle's knee table and `cost_basis`; the shim's field maps load *"from the daemon-materialized
cache of the bundle's `agent_maps` section"* (`04` §5). **But PolicyBundle v1, its signing, its
distribution, the transparency log and the compiler are all Phase 3** — and `14`'s own dependency
graph draws the edge `FUSE → BUND`. With no bundle, `04` §2.3's declared posture is conservative
built-ins (*gates answer allow, knee = 1*), under which Phase 2's gate — *"retry loops demonstrably
arrested at the knee on live sessions"* — **is unreachable by the shipped mechanism.**

Phase 1 has the same inversion in miniature: W6 builds the hookshim on bundle-supplied field maps
two phases before a bundle exists, and no built-in default for `agent_maps` is specified anywhere.

**This is the most consequential finding of either review** because it is not a contradiction to fix
in prose — it is a build order that does not close. And the danger is specific: under deadline
pressure the team will invent a side-channel map/matrix loading path (a local file `mark1d` reads)
that **bypasses the signature, seq and inclusion-proof verification the entire security story rests
on**, and that path will survive into production.

**Fix is sequencing, not scope:** define a Phase 1 **"bundle zero"** — a statically signed, locally
installed bundle file verified by the same `mark1-policy` decoder (signature + seq, with the tlog
proof waived by an explicit `seq = 0` rule) carrying `agent_maps` plus initial `verify` and knee
sections. Distribution and the transparency log stay in Phase 3. One new artifact, recorded in
`04` §2.6/§5, `07`'s bundle section, and `14`'s graph — and the bypass path never gets invented
because the legitimate path exists on day one.

### ENG-02 — model rewrite breaks the no-buffering invariant, and ≤1 ms has no arithmetic for it — **S1, unverified**
*Axis B (hot-path budgets). Affects: `04` §3.2/§3.4, `12` §7.1.*

`04` §3.2 asserts both *"no full-message buffering"* and that model rewrite *"parses only the JSON
prefix needed to rewrite `\"model\"`, streams the rest."* **JSON key order is not contractual.** A
client that serializes `model` after a multi-hundred-KB `messages` array forces the proxy to buffer
the entire body before the first upstream byte — you cannot forward bytes you may still need to
rewrite. No buffer bound, no fallback, no RSS accounting exists for that path, against a ≤35 MB
ceiling asserted at 64 concurrent streams.

The budget's provenance is also thinner than it reads: the linkerd2-proxy citation covers a
*byte-forwarding* proxy, not one doing body mutation plus optional redact-in-transit — and at the
redact crate's own ~100 MB/s worst case, one 64 KiB chunk scan is ~0.65 ms of the 1 ms budget.
`12` §7.1 does not state whether redact-in-transit is enabled in the gated load.

**Fix:** bound the rewrite window in `04` §3.2 — rewrite iff `model` appears within N KiB of body
start, else forward unmodified and log the decision as degraded fidelity, `Dropped{}`-accounted.
Add a key-order-adversarial fixture to the golden set (the chaos suite cannot catch this today
because no fixture varies key order), and state the bench's rewrite/redaction configuration in
`12` §7.1.

### ENG-03 — `12` and `13` disagree on how CI runs stores, and `13`'s entrypoint re-creates the estate's excluded-tests failure — **S1, verified**
*Axis D/F. Affects: `12` §0.3/§11.4, `13` §6.2/§6.3.*

Verified by the lead, and it is the one that would have bitten in week one.

`12:513` decides: *"real stores on every PR, provisioned as native binaries on the Linux runner — no
Docker required, no testcontainers, and no skip-if-absent,"* with `M1_REQUIRE_STORES=1` **inverting**
the estate's `skipif` idiom so a missing DSN is a hard error and the job asserts zero skips. The
reasoning at `12:516` is exactly right: *"the decorative-RLS incident was invisible precisely because
nothing executed against a real Postgres with the real role."*

`13` says three different things. `13:663`: *"real-Postgres suites gated on an env DSN via
`pytest.mark.skipif` — no testcontainers; CI has no Docker."* `13:825–826`: *"Integration suites gate
on env DSNs… e.g. from `just dev-up`"* — which is `docker compose`. `13:921`: *"DSN-gated services
via **GH service containers**"* — also Docker. And `13`'s `ci` recipe, *"everything a PR must pass,"*
is `gen-check lint test fuzz` — **`test-integration` is not in it**, while integration and chaos
suites are build-tag-gated and so excluded from the bare `go test ./...` that `12` §0.3 claims has
"no exclusions."

**So the isolation suite — the required PR check the entire tenancy story rests on — is not in the
repo's canonical CI entrypoint.** That is byte-for-byte the estate failure `12` §0.3 exists to
prevent, shipped in the scaffold document. **`12` §11.4 wins.** Rewrite `13`'s justfile comment and
`ci` recipe to include `test-integration` and isolation under `M1_REQUIRE_STORES=1` with a
`just stores-up` native-binary recipe, delete the service-container wording, unify the env-var
names, and have `12` §0.3 acknowledge tag-gated suites and how skip-accounting covers them.

### ENG-04 — the per-session `seq` counter does not survive a daemon restart — **S1, verified**
*Axis A (concurrency/ownership). Affects: `04` §2.0, `07` §2, `03` §8.4, `11` §0.3, R-08.*

Verified by the lead, and this is the subtlest finding in either review — nobody caught it in the
design pass, including me.

`04:172`: *"`seq` is assigned here (one authority, per R-4) from a **per-session atomic counter**."*
`07:154` makes it load-bearing: *"the causal-order source of truth: developer clocks drift, so
wall-clock…"* — `seq` is what the system uses **everywhere it distrusts wall clocks**.

Sessions outlive the daemon. `04` §11.4 calls launchd killing `mark1d` during sleep *"not an edge
case but a routine,"* and `04` F-02 has a crash-loop restart path. **Acked spool segments are
deleted, so the high-water mark is not reconstructible from disk.** A restarted `mark1d` therefore
re-issues `seq` 1, 2, 3… for a session that is still live — duplicate `(session_id, seq)` pairs.
Spill-ring replay compounds it: events spilled pre-crash drain *after* post-restart live events and
receive later seqs, **inverting causal order in exactly the window where ordering matters most.**

The consequence is silent: causal-order corruption on every daemon restart, poisoning `task_seg.v1`
denominators and attempt-indexed knee fitting (γ̂) — the numbers we quote to customers. The
skew-invariance test replays fixtures, so it does not catch this.

**Note this does not disturb R-08** — `07`'s placement of `seq` at `mark1d` admission remains
correct, because a shim-local counter cannot be session-monotonic across many short-lived processes.
The placement is right; the **recovery** was never specified.

**Fix, one decision recorded in `07` and `04` §2.0:** either persist a per-session `seq` high-water
in the tailer-cursor store (fsync'd on the spool cadence) and drain spill rings before admitting new
fabric events for that session, or add a `session_epoch` component that bumps per daemon boot so
ordering is `(epoch, seq)`. The epoch form is cheaper and strictly more robust. Add the assertion to
`chaos_daemon_kill9`: **no duplicate `(session_id, seq)` after recovery.**

### ENG-05 — nobody builds tenant onboarding — **S1, verified**
*Axis H ("the thing nobody planned for"). Affects: `05` §3.2, `08` §1.2, `14` all phases.*

Verified by the lead. Every flow presupposes a fully provisioned tenant: `05:321` has the registry
row carrying `{issuer, client_id, jwks_uri, …}` *"discovered from the issuer's OIDC metadata **at
tenant onboarding**"*; `05:744` pins the JWKS *"at onboarding"*; `05:347` chooses a directory-lookup
contract *"at onboarding."* Ingest needs a per-tenant KMS alias whose **absence is boot refusal R6's
bucket-policy premise**; `04` §2.9 needs per-tenant HMAC material *"delivered at enrollment"*; the ε
budget, coverage floors and operator-token semantics all need rows.

**No `controld` module owns tenant lifecycle** — the five are ingest/enroll/policydist/dprelease/
querychoke. `08` has **no `/tenants` surface at all**. `14` has no task for it in any phase.
**Even the Phase 1 dogfood cannot enroll device #1 without a hand-crafted tenant row.**

The failure is predictable and ugly: week 3 of Phase 1, enrollment stalls on "where does the tenant
come from," and the answer becomes untracked `psql`-by-hand provisioning — **unreceipted
identity-plane mutations in a product whose entire pitch is that identity changes are receipted.**

**Fix:** one small explicit Phase 1 deliverable — a tenant admin surface (Omium-operator scoped,
receipted; a CLI over migrations is fine at pilot) that creates the row, provisions the KMS alias
and its bucket-policy statement, mints tenant HMAC material, and defines operator-token
verification. One `05` section, one `08` inventory row, ~1 engineer-week in `14`.

### ENG-06 — A-04 pages on loss the design explicitly permits as routine — **S2, verified**
*Axis G (operability). Affects: `11` §7 SLO-3 / §8 A-04, `04` §11.4/F-20, `12` §6.2.*

A-04 pages on `increase(intel_dropped_billing_events_total[1h]) > 0` and SLO-3 declares zero
tolerance. But `04` defines torn-tail `Dropped{CRC_LOSS}` in billing categories as the **designed,
bounded, accounted** outcome of any unclean shutdown, and `04` §11.4 calls launchd killing the
daemon during sleep *"not an edge case but a routine."* `12` §6.2 already reconciles the two as
"zero loss of *acknowledged* events" (this is **R-25**) — but the **alert expression never got the
memo**. The ledger-derived metric cannot distinguish permitted pre-ack loss from forbidden post-ack
loss, so at fleet scale it pages every time a laptop lid closes on the wrong 250 ms.

**This is how a pager dies:** a 3am page factory in week one of dogfood, then the alert gets
silenced, taking the one genuine product-integrity pager with it.

**Fix:** label the signal `{scope="post_ack"|"pre_ack_bounded"}` (CRC_LOSS from recovery is pre-ack);
page on any post-ack occurrence, ticket on pre-ack rate exceeding the fsync-window expectation. One
label, one expression. **Recorded as the operational half of R-25.**

### ENG-07 — the disk hard-stop's `CoverageTransition` needs the spool that just refused it — **S2, unverified**
*Axis A/C. Affects: `04` §2.4/§2.7, `07` §6.*

`CoverageTransition` is a billing-grade, per-event-receipted class, and billing-grade appends
**block** at spool-full. At the 95%-disk hard stop the pre-append statfs check refuses all appends —
**including the event that records the stop.** The same self-reference exists at spool-cap-full: the
transition event's own append participates in the backpressure it is reporting.

So the coverage band — the number that gates guarantee-grade reporting — silently misses the two
failure modes it most needs to record. Or an implementer "fixes" it by appending past the hard stop
and quietly voids the disk promise.

**Fix:** a reserved accounting quota — accounting-class events may append until a second, higher
threshold (≈97%); below that, the persisted tracker window replays into an event on resume. One
paragraph, and `spool_disk_hardstop` gains an assertion that the transition event itself lands.

### ENG-08 — four state-machine states you can enter and never leave — **S2, verified**
*Axis C. Affects: `04` §9.1/§9.2/§9.4, `05` §3.1.*

1. `04` §9.1 `DISCOVERED` (tailers started, cortex map served) **has no exit** — idle-timeout and
   crash-detection edges exist only from `ACTIVE`, so a session that dies before its first admitted
   event **leaks tailers forever**.
2. `04` §9.2 `OPEN` reaches a closed state only via `ACTIVE`, so a task with no subsequent events at
   session end never emits `TaskClose` — contradicting *"a first-class denominator class, never
   excluded."* That is a hole in the TVO denominator.
3. `04` §9.4 `RUNNING_PARTIAL` has **no outgoing edge at all** — no poll back to `FETCHED`, no
   `max_age` path to `BUILTINS`. A policy state clearable only by restart.
4. `05` §3.1 `APPROVED` has no expiry, while `PENDING` expires at 15 minutes. A CLI that dies after
   IdP approval parks an approved enrollment with a registered pubkey indefinitely.

**Fix:** four edges — `DISCOVERED → CLOSED` on idle/tailer-observed death; `OPEN → CLOSED_UNRESOLVED`
at session end; `RUNNING_PARTIAL → FETCHED` (poll) and `→ BUILTINS` (max_age); `APPROVED → EXPIRED`
after a bounded unclaimed window. Diagram edits plus four unit cases.

### ENG-09 — query-time PageRank has no latency budget — **S2, unverified**
*Axis B. Affects: `04` §6.1/§6.4, `08` §6, `12` §7.1.*

The only benched cortex latency is the **precomputed** session-start map, which is off the serving
path. But `ranked_files` — and `repo_map` with a `focus` seed — run PPR **lazily, per novel seed
set, at query time, inside a blocking agent MCP call**. On the 100k-file fixture a cold evaluation
is seconds of graph work. No time budget, no iteration cap, no refuse-past-deadline rule; the
`M1E-64xx` refusal taxonomy covers staleness and scope, not time.

`04` §0.2's own rule is *"a budget without an enforcement point is a wish, so none appears here
without one."* Here there is **no budget at all** — and the consequence is risk #8 (UX blowback →
permanent `mark1 off`) triggered by the plane whose whole job is to *save* tokens.

**Fix:** a per-call wall budget (≈500 ms) enforced by bounded power-iteration steps with a coarse
global-PageRank fallback, a time-budget refusal carrying `retry_after_ms`, and a bench on the large
fixture.

### ENG-10 — `12` and `13` disagree on the entire `conformance/` layout — **S2, verified**
*Axis D. Affects: `12` §1.1/§3/§10.2, `13` §1.*

`12` places suites at `conformance/{sse, hooks/<agent>/<version>, canary/oauth, vectors/{m1p,bundle,
receipt}, isolation, integration, e2e, cli, fuzz-corpus}` and makes **`conformance/traceability.yaml`
the enforced artifact of the whole quality system** — `tools/trace-check` fails CI when any of the
181 requirement IDs has no mapped test.

`13`'s tree — declared *"byte-for-byte where a pin is stated"* — uses `conformance/{frames/<dialect>/
<vendor-version>, hooks/<agent>@<pinned-version>, canary/token-shapes, vectors/{m1pl,redact,receipt,
bundle}, tenancy}`. Different names for essentially every directory (`tenancy` vs `isolation`,
`frames` vs `sse`, `m1pl` vs `m1p`), and **no `traceability.yaml`, no `integration/`, no `e2e/`, no
`cli/`, no `fuzz-corpus/` anywhere** — verified: the string `traceability.yaml` appears in `12` and
never in `13`.

So `tools/trace-check`, `12`'s teeth, points at a file the scaffold never creates, and every adopted
slug's `source:` path is wrong on day one. **Fix:** one reconciliation pass declaring `13` §1
canonical for paths, regenerating `12`'s path references, and adding the five missing entries to
`13`'s tree.

### ENG-11 — the ingest ack bench gate contradicts the SLO it protects — **S2, unverified**
*Axis F/B. Affects: `12` §7.1, `05` §2.7, `11` SLO-2.*

`05` §2.7 sets p99 ≤ **800 ms**, *"dominated by the S3 PUT + KMS encrypt (~150–400 ms)"*, and SLO-2
adopts it verbatim. `12`'s merge-blocking bench threshold is **500 ms** at 1,000 ev/s, and neither
cites the other. Worse, the bench runs against **MinIO**, whose PUT latency shares nothing with
S3+KMS — so the 500 ms figure does not measure the term that dominates the 800 ms budget.

Either an unpassable gate or false confidence, and per `12` §7.3's own rule (*thresholds are
requirements*) someone will edit one under pressure. **Fix:** state explicitly that the CI bench
gates *pipeline-minus-S3* (stage 1 → stage 8 entry) with its own number, and that 800 ms end-to-end
is SLO-2's, validated nightly against real S3.

### ENG-12 — the merge-blocking bench runner is infrastructure nobody is tasked to build — **S2, unverified**
*Axis F. Affects: `12` §7.2/§11.5, `13` §6.3, `14` WS-8, `11` §12.*

`12` makes benchmarks on *"one self-hosted runner class (c7i.2xlarge-equivalent, frozen in
`bench/RUNNER.md`)"* a merge-blocking stage **with no perf-waiver path**. The estate has no
self-hosted runners, and provisioning, securing and keeping one alive appears nowhere — not in
WS-8's charter, not in `11` §12's gap list, not in `13`. `13` §6.3 also contradicts `12` on when it
gates (*"required: yes from Phase 3"* vs benchmarks blocking every PR, when `bench_shim_dispatch`
and `bench_redact_throughput` are Phase 1–2 budgets).

So either every merge blocks the day an unowned runner dies — a single point of failure for the
whole repo — or the stage quietly becomes report-only, which `12` §7.3 provides no sanctioned way to
do. **Fix:** name the runner as a WS-8 Phase 1 deliverable, write an availability fallback into
`12` §7.2 (runner offline ⇒ deferred to a mandatory pre-release run, **never silently skipped**),
and reconcile `13` §6.3's phase column.

### ENG-13 — the weekly canary couples repo-wide CI to a live vendor account — **S3, unverified**
*Axis F. Affects: `12` §3.3/§1.3, `10`, `09`.*

The token-shape canary's corpus refresh needs a **live Anthropic fixture account** holding both
OAuth and API-key credentials, exercised from CI weekly, where *"one miss = job red = repo-wide CI
red."* A vendor outage, suspension, rate limit or login-flow change is **indistinguishable in effect
from a classifier miss**. And recording credential *shapes* from live credentials inside CI is
itself a credential-custody operation with no stated handling — whose account, what custody, what
redaction; fixtures are sanitized at record time, but the recorder holds live tokens.

Recurrent false-red weeks train the team to override **the loudest legal alarm in the system**.
**Fix:** split the lanes — the gating classifier check runs against the committed corpus only
(deterministic; red means a real miss), while the live recording lane files a PR on new shapes and
*alerts* rather than reds on infrastructure failure. Name the fixture account's custody in `10`/`09`.

### What the staff engineer could not break

Recorded precisely, because it is the other half of the review's value:

- **Spool-full cannot deadlock an agent.** Traced end to end: billing-grade backpressure propagates
  fabric-read-stop → 250 ms writer deadline → sanitized spill → exit 0; `GateQuery` reads a
  lock-free `atomic.Pointer` cache and **never touches the spool or the admission path**; the shim's
  45 ms abandon timer plus gate-deadline-minus-10 ms bounds every wait. *"Fail-open-for-availability
  survives every full-spool interleaving described."*
- **The single-writer invariant is enforceable as described** — the spool write handle is a
  possession *moved into* `capture.Admitter` at construction, and restart-with-in-flight-clients is
  fully specified (spill rings sealed to a key only `mark1d` holds, pidfile+hash adoption, cursor
  resume, idem-key dedupe backstop). Except for ENG-04.
- **OPE sequencing is correct and honest** — propensity/fidelity logging lands before OPE consumes
  it, `WIRE_ENFORCED`-only filtering holds, and the ε = 0 limits are stated without overselling
  (*"non-regression on overlap is the strongest emittable claim"*).
- **Fusion vs confusion-matrix *estimation* ordering is handled.** The Phase 2 gap is bundle
  *distribution* (ENG-01), not estimation.
- **The uplink, spool-segment and bundle-apply machines close** — `PARKED` has three named re-queue
  triggers, every `SEALED`/`UPLOADING`/`QUARANTINED` path terminates, and rollback-by-append
  eliminates the seq-exception replay hole.
- **Every other hot-path budget has real arithmetic and an enforcement point** — gate ≤5 ms is a map
  lookup with an instrumented no-compute test; shim ≤10 ms cold start is structurally argued and
  benched; ingest 800 ms is decomposed into its dominant term.
- **The SLIs are computable as written** — every SLO row cites an expression that exists in the
  catalog, the ledger→Prometheus exporter dependency is flagged as Phase 1 critical path, and the
  no-OTel correlation story is concretely specified (identity-tuple joins, a six-step executable
  runbook) **with its weakest link self-declared rather than hand-waved.**
- **The codegen story is internally coherent** — committed gen, no `build.rs`, pinned remote plugins,
  a freshness gate, one Rust include-owner, and frozen cross-language vectors *including rejection
  vectors*. `13`, `04` and `12` agree.
- **The guard's no-override-path is testable as described** — `trybuild` compile-fail for
  `Secret<T>`, a grep gate for override-pattern flags, call-graph plus runtime negative, and a
  canary meta-test asserting the test-only seam is absent from release builds.

---

## Fifth pass — mechanical verification of the built foundation (2026-08-28)

The first four passes read documents. This one **executed** the foundation the documents
specify: `buf lint`/`buf build` against the real toolchain, all 12 migrations against a live
Postgres 15.19 + pgvector 0.8.6 and a live ClickHouse 26.7.5.10, and the build/CI scaffold
against `uv`, `cargo`, `just` and the shell.

That distinction is the finding. Every defect below sits in a file that reads correctly. Three
of them are the same failure the estate has already paid for once — **a gate that reports
success by never executing** — and none of them was in any agent's self-report. Reading is not
verification.

All thirteen are **fixed and re-verified**; they are recorded because the classes recur.

| ID | Sev | Defect | What it would have cost |
|---|---|---|---|
| BUILD-01 | S1 | `Verdict` declared in both `artifacts.proto` and `verify.proto` (two authors, one enum) | `buf` refuses the package; nothing in three languages compiles. Fixed by deleting verify.proto's copy — artifacts.proto is the import leaf, so the alternative placement is `PACKAGE_NO_IMPORT_CYCLE`. |
| BUILD-02 | S1 | `m1_ch_002_rollups.sql`: `agent` was a plain `LowCardinality(String)` in an `AggregatingMergeTree`, neither in `ORDER BY` nor an aggregate | ClickHouse rejects it outright *because* the plain form "silently produces wrong results" after a merge — in the **TVO rollups**, where a silently-wrong number is the worst failure this product has. Now `SimpleAggregateFunction(any, …)`; changing `ORDER BY` was rejected as effectively irreversible (ADR-0001). |
| BUILD-03 | S1 | `just build-py` ran `uv sync --frozen` against a virtual workspace root with no dependencies of its own | Resolves to "no changes", installs **nothing**, so `ruff` is absent and the **ruff banned-api no-OTel gate (CON-005) passes by never running**. `--all-packages` → 80 packages incl. ruff 0.16.5, pytest 9.1.1. |
| BUILD-04 | S1 | `scripts/migrate-db.sh` globbed `*.sql` and sent every file to `psql` | `just migrate` hands ClickHouse DDL to Postgres and aborts the whole run. Now dispatches on the filename rule the SQL files themselves declare, one Postgres ledger for both engines. |
| BUILD-05 | S1 | the same runner read its file list on **stdin** | Any body command that reads stdin swallows the rest of the list; observed live — 12 files found, **1 applied, exit 0, "done: 1 applied"**. A runner that applies a prefix of the schema and calls it success. Now reads on fd 3. |
| BUILD-06 | S1 | `just stores-up` starts ClickHouse (native port **9000**) then MinIO on `127.0.0.1:9000`; both wait loops `break`-only | MinIO can never bind, and the recipe reports success anyway — CI then runs `M1_REQUIRE_STORES=1` against a store that never started, surfacing as a connection error inside an unrelated test. MinIO → 9002 (ClickHouse's port is the one tools assume); both loops now fail loudly. |
| BUILD-07 | S2 | `tools/ci/gen_fresh.sh` had zero callers; `just gen-check` re-implemented its `git diff` but not its `git ls-files --others` check | A new `.proto` whose generated output was never `git add`ed passes the freshness gate silently. `gen-check` now delegates. |
| BUILD-08 | S2 | `tools/ci/conformance_crosslang.sh` hard-fails when no vectors exist | Correct intent ("a run that executes zero vector tests is a FAILED run"), wrong at C0: the scaffold commit lands red, which trains people to ignore red. Now driven by a committed `conformance/vectors/EXPECTED` manifest — "no vectors yet" is a reviewable claim, "the vectors vanished" still fails. |
| BUILD-09 | S2 | `just ci` omitted `gates` and `conformance`, both of which ci.yml runs | The local canonical entrypoint was a *weaker* check than CI while claiming to be the same one — the estate's excluded-suite failure, in the recipe whose own comment warns about it. Closes the remaining half of **ENG-03**. |
| BUILD-10 | S2 | `mark1-verifier` is Apache-2.0 and published; its only workspace dependency `mark1-receipt` inherited `UNLICENSED` | The customer cannot build the verifier and crates.io cannot accept it — "a standalone verifier validates the chain offline with our server unreachable" becomes marketing. `mark1-receipt` is now Apache-2.0: the receipt format **is** the public contract, and the moat is the corpus, not canonical-JSON. Founder-visible consequence, flagged. |
| BUILD-11 | S2 | no crate set `publish = false`, and `deny.toml` had no `private` rule | `cargo deny check licenses` fails on our own crates (`UNLICENSED` is not valid SPDX), and any `cargo publish` in the wrong directory pushes proprietary source to an append-only registry. The 7 proprietary crates are now unpublishable; the 2 Apache crates stay inside the gate. |
| BUILD-12 | S2 | `09` §3.3 names the service roles `mark1_controld_app`/`…`; `07` and all 10 migrations use `controld_app`/`…` (200+ refs vs 5) | `09` is what the migrate Job's `ALTER ROLE … PASSWORD` heredoc and the ExternalSecret keys get authored from — the injection would target a role that does not exist, leaving the real one password-less and unusable. `09` corrected to the migrations' spelling. |
| BUILD-13 | S3 | no `.python-version` (uv resolved 3.13.13 against a 3.12 pin that `>=3.12` permitted silently); compose file named `docker-compose.yml` against the justfile's `compose.yaml` | Toolchain drift and a `just dev-up` that cannot find its file. Both fixed. |

### What the foundation got right, proven by execution

- **All 12 migrations apply, and re-apply as no-ops** — 10 Postgres + 2 ClickHouse, from a wiped
  schema: 12 applied → re-run 0 applied / 12 already present, 31 tables + 6 ClickHouse objects.
  The 31 is **30 domain tables + `schema_migrations`**, which `migrate-db.sh` creates and which is
  therefore absent when the `.sql` files are applied directly with `psql`. Stated because 22
  policied + 8 global = 30, and the missing row otherwise reads as an audit that lost a table.
- **RLS is real, not decorative** — **22 of 22** tenant-scoped tables carry all four controls
  (`ENABLE` + `FORCE` + `DROP POLICY IF EXISTS` + `tenant_isolation` in the `NULLIF`/two-arg
  `current_setting` form), and **zero** tables carrying a `tenant_id` column lack a policy. The
  8 un-policied tables are all legitimately global: `m1_organizations`, `m1_verifiers`,
  `m1_server_signing_keys`, `org_verification`, and the four federation publication tables
  (`artifact_publications`, `publication_spans`, `publication_span_producers`,
  `publication_review_queue`) whose entire purpose is to hold what survived cross-tenant
  aggregation.
  > **Written as 22, not 21, and the difference is the interesting part.** An audit that
  > enumerates *tables carrying a `tenant_id` column* finds 21 and calls the set complete. The
  > 22nd is **`m1_tenants`**, whose tenant key is `id` — it is the root of the tenancy graph and
  > it is policied (`USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`), but
  > a column-name scan classifies it as global and moves on. The property is *better* than the
  > earlier claim of "21 of 21"; the claim was low because the query behind it was looking for a
  > column name rather than for a tenancy predicate. Recorded because the next person to write
  > that audit query will write the same one.
- **Exactly one `BYPASSRLS` role exists** — `mark1_federation_worker`, the one SEC-04 permits and
  names; `controld_app`/`adjudicator_app`/`intel_app` are all `NOBYPASSRLS NOSUPERUSER`. The
  `rds_superuser` scar is not reopened.
- **ADR-0001's ordering key is byte-exact on the live server** —
  `tenant_id, toDate(occurred_at), session_id, event_id`, `ReplacingMergeTree(ingested_at)`,
  split TTL (90 d diagnostics / 760 d), bloom filter on `idem_key`. *Still unsigned — no
  production ClickHouse write may happen until it is.*
- **The M1P contract compiles** — `buf lint` and `buf build` both exit 0; 88,179-byte descriptor
  set. `session_epoch` (ENG-04) and `EdgeHealth` (R-21) are both present in the wire types.

---

## Sixth pass — line-level sweep of the repaired foundation (2026-08-28)

The fifth pass executed the foundation and fixed thirteen defects. This pass read every line of
what survived — CI workflows, gate scripts, all 12 migrations, all 6 `.proto` files, the justfile
and the bootstrap script — and found **37 more**, six of them S1. All were verified against
current file contents before being recorded; one alleged S1 (a claimed `AggregateFunction` type
mismatch in `m1_ch_002_rollups.sql`) was **disproved** by reproducing it against the live
ClickHouse 26.7 and is deliberately not listed, so it is not re-raised.

**The lesson of this pass is BUILD-03.** It was reported against `just build-py`, fixed there,
and re-verified there — genuinely green. But `--all-packages` was missing from **nine other**
`uv run --frozen` call sites, so `lint-py`, `test-py`, `test-integration`, `test-isolation` and
`fmt` all stayed broken, and the ruff banned-api no-OTel gate (CON-005) still passed by never
running. A fix verified against the command it was reported on, rather than against the class of
defect, leaves the bug everywhere it was not reported. Grep every caller before declaring a fix.

Two findings from the fifth pass's own tail were already stale by the time this pass ran
(`proto/gen/` was empty; `proto/gen/go/go.sum` absent) — codegen has since been unblocked and all
three languages generate.

### The six S1s

| ID | Defect | What it would have cost |
|---|---|---|
| BUILD-14 | nine `uv run --frozen` sites still target the dependency-less virtual root | Every Python lane re-syncs the venv down to empty and fails tool-not-found; the no-OTel ruff gate never executes. The unfixed remainder of BUILD-03. |
| BUILD-15 | `ci.yml` and `release.yml` still set `M1_TEST_S3_ENDPOINT` to port **9000** | BUILD-06 moved MinIO to 9002 in the justfile; the two CI workflows did not follow. MinIO cannot bind (ClickHouse holds 9000), the now-hard wait loop exits 1, and every integration run and every release dies at `just stores-up`. Same class as BUILD-14: one call site fixed, the siblings missed. |
| BUILD-16 | neither workflow sets `CLICKHOUSE_*`, and `stores-up` ships no `clickhouse-client` | BUILD-04's two-dialect dispatch hard-requires `CLICKHOUSE_HOST`, so `just migrate` aborts in CI and the ledger tables are never created. A fix's own precondition, unpropagated. |
| BUILD-17 | `m1_060:188` grants `UPDATE` on `tenant_privacy_budgets` to `intel_app` | The DP-**spending** role can raise its own privacy **cap**. RLS cannot stop it — it updates its own tenant's row, so `USING` and `WITH CHECK` both pass. `m1_060` sorts last, so it wins. The justification comment describes a `SELECT … FOR UPDATE` lock that `m1_041` replaced with `pg_advisory_xact_lock`, and `m1_041:314` states in terms "Deliberately NO UPDATE". **A stale comment kept a revoked grant alive.** |
| BUILD-18 | `epsilon_ledger` has no `BEFORE TRUNCATE` statement trigger | Row triggers do not fire on `TRUNCATE`, and `REVOKE … FROM PUBLIC` never binds the owner. `TRUNCATE epsilon_ledger` as `mark1_owner` erases the entire spent-privacy record the file itself calls "a legal record; it survives everything". `m1_042` and `m1_043` have the identical hole while their comments claim append-only "three ways" — **they ship two.** |
| BUILD-19 | `release.yml`'s bench-runner guard sits inside the job it guards | `runs-on: [self-hosted, "${{ vars.MARK1_BENCH_RUNNER }}"]` is resolved by the scheduler *before* any step runs, so an unset variable queues the job for GitHub's 24 h timeout instead of failing fast — the exact opposite of what the step's comment claims. `ci.yml`'s bench trio already does this correctly; the release lane copied the intent, not the mechanism. |

Two further S2s deserve naming because they are the pass's recurring theme in its purest form:
`otel_gate.sh`'s non-vacuity guard is a single global "did we scan anything", satisfied by any one
file — so with `Cargo.lock` and three `go.sum` files absent it reports OK having enforced the
zero-OTel rule for Python alone. And `secret_type_gate.sh`'s rule 3 was narrowed from `\.0\b` to
`[Ss]ecret[A-Za-z0-9_]*\.0`, so it fires only when the receiver identifier literally contains
"secret" — `token.0`, `cred.0`, `k.0` all pass. That gate guards **credential custody**; a false
green there is a leak CI blessed. Narrowing a pattern to silence a false positive, without
recording that the coverage shrank, is how a control becomes decoration.

### The eleven cross-document decisions (lead, binding)

Eight of the 37 were contradictions between frozen documents, which cannot be fixed by editing
one side. They were decided before repair began so that no two agents could resolve the same
contradiction two different ways:

| # | Decision | Why this side won |
|---|---|---|
| D-A | M1PL frame `len` bound = **4 MiB** (`4_194_304`); `08`'s 1 MiB and `HelloAck{max_frame}` are corrected | `04` §42 R-1 had already ruled: `07` owns the framing bytes. `07` §6 also *derives* the spool record bound (`20 < len ≤ 4_194_324`) from it, so `07` is internally consistent across two sections and `08` is not. Conformance vectors freeze this number in the next commit. |
| D-B | Six additive `DropReason` values; `string category` → `DurabilityClass durability_class` (field 2 `reserved`) | The edge could not encode drops `04` and `08` normatively require it to emit, so they collapsed to `UNSPECIFIED` and the loss ledger stopped being attributable. `08`:149 sends `category: DIAGNOSTIC` — a durability class, not an event family — and the spool record byte [16] already carries exactly `{1=billing, 2=diagnostic}` outside the payload, so a drop stays attributable without decoding protobuf. Enum values 1 and 2 deliberately equal that byte. |
| D-C | `CoverageTransition` is **diagnostic** class, per-event receipted | `07` §6 closes the billing-grade set at exactly three classes. The proto comment claiming block-on-full would have made an implementer stamp class byte 1 and get backpressure `07` never authorized. |
| D-D | `BundleAck`: `result`/`sections_skipped`/`reject_code` become strings; `seq` stays `uint64` and `08`'s example becomes `"483"` | `buf.yaml` pins `breaking: WIRE_JSON`, so the JSON projection is a frozen surface. Four of five divergences are fixed in the proto; the fifth is proto3's specified uint64-as-string mapping, and changing the field's type to flatter a JSON example would be the tail wagging the dog. |
| D-E | `session_epoch` and `EdgeHealth` ratified into `07` | Closes **ENG-04** and **R-21**. `11` §2.3 already specifies `EdgeHealth` completely and says in terms that `07` must ratify it; the proto had shipped both while claiming a ratification the tracker recorded as open. |
| D-F | The `tvo_tenant_day` writer becomes **ADR-0010** | The author's four reasons why an insert-block MV cannot produce this rollup are correct. The defect is that a real `07`-internal contradiction was settled in a SQL comment — invisible to the doc set, no alternatives, no consequences, no signature. |
| D-G | Test-store env vars are `M1_TEST_*`; `13` §6.2 is corrected | Three files (justfile + both workflows) against one doc line, and `M1_` matches the `M1P`/`M1E` prefix family. |
| D-H | trivy runs at **release**, on built images | `12` §11.3/§11.5 and `ci.yml` already agree; `13` §6.3 is the outlier. Scanning locally-built images in the PR lane buys no signal the release scan does not already give. |
| D-I | Drop `13` §1's `.github/CODEOWNERS` mirror claim | The root file resolves; a later mirror would silently shadow it. |
| D-J | `GateHealth`: drop `read_p50_us`, keep `read_p99_us` and add it to `11` §2.3 | `11` §2.3 closes the gate field set at `{reads, allows, blocks, timeouts}` and claims conformance asserts that closure — while SLO-7 depends on a p99 the closed set omits. The test and the SLO contradicted each other. |
| D-K | Advisory identity mismatch = **403 / M1E-8003**, not 400 | A well-formed batch asserting the wrong identity is Forbidden, not malformed. `08` §2.1 is right; `07` §2 is corrected. |

**Still not signed, and still blocking:** ADRs 0001/0002/0004/0009; SEC-01; SEC-02 (which gates
R-03); ENG-01 and ENG-05 scope. No production ClickHouse write may occur before ADR-0001 is
signed. BUILD-10's licensing consequence (`mark1-receipt` becoming Apache-2.0) remains a lead
decision flagged for founder visibility, not a founder approval.

---

## Seventh pass — repairing the sixth pass's findings, executed against live stores (2026-08-28)

The sixth pass *found* 22 defects. This pass *fixed* all 22 and then ran the result against a live
PostgreSQL 15 and a live ClickHouse 24.8.14.39 — the pinned version — rather than reading the SQL
and believing it.

**The organizing observation: the doc set predicted its own defect and the SQL beside it did the
wrong thing anyway.** `07` §3107 says, verbatim, that the `dropped_billing` predicate reads
`dropped_durability_class`, *not* `event_class`, and that filtering the loss ledger on
`event_class` "would sum to zero forever — a coverage band that never narrows, which is the exact
failure `Dropped{}` exists to prevent." Both materialized views did exactly that. A `Dropped{}` row
is *itself* a diagnostic-class event; `event_class` describes the row while
`dropped_durability_class` describes the thing that was lost. Executed on the live server, before
and after, on the same three seeded rows:

| predicate | `dropped_billing` |
|---|---|
| `dropped_durability_class = 'billing_grade'` (now) | **7** |
| `event_class = 'billing'` (as it shipped) | **0** |

Zero, for every tenant, for all time — and silently, because a coverage band that never narrows
looks exactly like a fleet that never loses anything.

### Method: fix the class, not the citation

Every finding named one line. Before editing any of them, the whole **class** of the defect was
grepped for and every sibling fixed in the same commit. That is the discipline BUILD-03 and
BUILD-14/15/16 exist to enforce — *a fix verified against the command it was reported on rather
than against the class of defect* — and applying it surfaced **eight defects nobody reported**,
including: `02` had no requirement mandating `session_epoch` at all, so the normative causal-order
rule rested on a field no requirement demanded; `05` §6.3's template registry listed neither
write-shaped template; and `07`'s `bundle_acks` and `coverage_transitions` both referenced
`devices(id)`, a table that does not exist under any migration (every one of them says
`m1_devices`) — DDL that could not have applied.

### The four repairs of this round, and what each was hiding

| # | Defect | What it actually meant |
|---|---|---|
| 1 | **The ACK ledger stored a second vocabulary and no mapping.** `bundle_acks.result` held `verified_active`/`verify_failed`/`stale_rejected`; `08` §3.2 and `policy.proto` both asserted "the ledger column stores the mapping" | No mapping was written anywhere, by anyone. Worse, `05` §4.3(b) halts a rollout on `partial (sections_skipped) > 20%` and (a) on `reject_code = M1E-3005` — reading two columns the ledger did not have, off a `result` value the old vocabulary **could not express**. Fixed by deleting the second vocabulary, not by writing the mapping: `08` owns the contract (`05` §4.2), so the ledger stores `08`'s three values verbatim, and the verify-vs-stale distinction moves to `reject_code`, which is strictly finer. `bundle_hash`, `sections_skipped`, `reject_code`, `edge_version` added |
| 2 | **`conformance/tenancy/` was an empty directory** cited as the enforcement point by the justfile, `12` §4, and `m1_060`'s postcondition comment (SEC-04) | Three citations, zero enforcement — the recurring *gate that reports success by never executing*. Built rather than deleted: a `conftest.py` that makes a missing DSN a hard error and **fails the session on any skip**, plus the SEC-04 cluster-wide allow-list assertion m1_060 defers to |
| 3 | **`just build-go` exits 0 having compiled nothing.** `go build ./...` treats "matched no packages" as a warning | Same shape as the ruff hole BUILD-03 fixed. `test-go` had it too and was not reported. One private `_go-src` recipe, called by both, so the tripwire cannot drift between build and test |
| 4 | **`override_pattern_gate.sh` printed a clean `OK` over zero `.rs` files** | It guards `04` §3.1 step 4 — *"No override path is compiled into the binary"* — the load-bearing half of the OAuth non-interception claim. Its two sibling gates print `PARTIAL`; this one asserted a property of a binary that does not exist. Now `PARTIAL`, still green. Green and OK are different words and the difference is the entire point |

### Executed, not reviewed

- **All 10 Postgres migrations apply to a wiped database**, including the rewritten `bundle_acks`.
- **Every `bundle_acks` constraint fires, and fires for the right reason.** Six illegal shapes were
  attempted; each was rejected by its intended constraint, not by a neighbour: the old vocabulary
  (`bundle_acks_result`), `applied` carrying a `reject_code`, `partial` skipping nothing, and
  `rejected` with no code (all `…_result_evidence`), an attacker-chosen section name
  `{cortex,pwn}` (`…_sections_known` — the halt-denominator poisoning), and a 2-byte hash
  (`…_hash_len`). All three legal shapes then inserted, which is what distinguishes a working
  CHECK from one that rejects everything.
- **`05` §4.3's halt rules compute for the first time**: `partial_ratio = 0.333` against the 20%
  threshold, and the `M1E-3005` tripwire resolves to an `Index Only Scan using
  ix_acks_command_string` — the 5-minute cross-tenant tick costs the number of hits, which in a
  healthy fleet is zero.
- **Both ClickHouse migrations apply**; 6 objects; the `dropped_billing` table above.
- **`(session_epoch, seq)` ordering executed** (D-E / ENG-04): a post-restart `seq = 1` event
  sorts *after* `seq = 3` of the previous epoch, which `ORDER BY seq` alone reverses.
- **The tenancy suite's own tripwires were verified by triggering them**: an injected skipping test
  turned `5 passed, 1 skipped` into **exit 1**; an empty collection printed the three citations by
  name. A zero-skip assertion nobody tested is the same class of decoration as the RLS it guards.
- **SEC-04 asserted against the live cluster and passes 5/5** — and it asks the question **twice**.
  The literal reconciliation text is an *attribute* query (`rolbypassrls OR rolsuper`); the estate's
  incident was *membership* — `rds_superuser` inherited, attributes clean, `ALTER ROLE …
  NOBYPASSRLS` repairing nothing. A test running only the literal query would rebuild the exact
  blind spot `m1_060`'s comment spends a paragraph warning about, so it runs the resolution query
  (`pg_has_role(…, 'USAGE')`) as well. `SUPERUSER` and `BYPASSRLS` are allow-listed **separately**,
  because `mark1_federation_worker` is legitimately the one and may never be the other.
- **`just gen` re-run**; all four generated targets carry the amended contract; `buf lint` clean.

**One claim was found to be understated rather than wrong** — see "RLS is real, not decorative"
above: the property is 22 of 22, not 21 of 21, because the audit query behind the older number
looked for a column named `tenant_id` and so classified `m1_tenants` — whose tenant key is `id`,
and which is the root of the tenancy graph — as global.

---

## Disposition tracker

| ID | Severity | Resolution | Owner | Status |
|---|---|---|---|---|
| R-01 | S1 | ADR-0004 | founder | open |
| R-02 | S1 | ADR-0009 (new) | founder | open |
| R-03 | S1 | founder call on the cross-repo change | founder | open |
| R-04 | S1 | ratify or write Phase 6 gate | founder | open |
| R-05 | S1 | establish staging truth | estate owner | open |
| R-06 | S2 | pick a bound, apply to 07/08/04 | lead | open |
| R-07 | S2 | adopt `07`'s paths in `08` | lead | open |
| R-08 | S2 | ratify `07` (`mark1d` stamps `seq`) | lead | open |
| R-09 | S2 | ratify `08`'s six tool names | lead | open |
| R-10 | S2 | four crates; fix spec §2 heading | lead | open |
| R-11 | S2 | Phase 3 / Phase 5; fix spec §0 | lead | open |
| R-12 | S2 | WIRE_JSON, deliberate divergence | lead | resolved |
| R-13 | S2 | pick a Python plugin | lead | open |
| R-14 | S2 | two credentials, reads via choke | lead | resolved |
| R-15 | S2 | add the fingerprint endpoint to `08` | lead | open |
| R-16 | S3 | raise the platform-side drift | founder | open |
| R-17 | S3 | Mark 1 lands its own | lead | open |
| R-18 | S3 | recorded, no action | — | closed |
| R-19 | S3 | recorded, no action | — | closed |
| R-20 | S3 | recorded, no action | — | closed |
| R-21 | S1 | define `EdgeHealth` in `07`/`08` before first `buf generate` | lead | **closed by D-E** — ratified in `07`; in scope of `conf_schema_closed_field_set` |
| R-22 | S1 | Mark 1 lands its own scrape job + smoke test; raise the platform half | lead + founder | open |
| R-23 | S3 | raise the platform `alpine:latest` instance | founder | open |
| R-24 | S2 | pick 3.12-with-3.11-compatible-vendor, state it in `13` §3 | lead | open |
| R-25 | S2 | use `12` §6.2's wording everywhere outside the plan | lead | resolved |
| R-26 | S3 | recorded, no action — `13`'s split is correct | — | closed |
| SEC-01 | S1 | off ⇒ detach/refuse, delete `NOOP_FORWARD`; re-scope CON-013 | founder | open |
| SEC-02 | S1 | **client-side corpus (a) or contractual opt-in (b)** — gates R-03 | founder | open |
| SEC-03 | S1 | scope the crypto-erasure claim; resolve the FK collision | lead | open |
| SEC-04 | S1 | **one role inventory** (the blocking half); allow-list not `*_app` convention | lead | **enforcement landed, 5/5 green** — `conformance/tenancy/test_sec04_bypassrls_allowlist.py`, allow-list on both the attribute AND membership axes, `SUPERUSER`/`BYPASSRLS` listed separately. The inventory itself is the assertion; open only for the `rds` profile's names, unverifiable until a real RDS cluster exists |
| SEC-05 | S2 | byte-scan unknown types; constrain `payload`, `tool`, `diagnostic_code` | lead | open |
| SEC-06 | S2 | tenant in the landing object; cross-**write** negative test | lead | open |
| SEC-07 | S2 | hash-only public leaves — **decide inside ADR-0004** | founder | open |
| SEC-08 | S2 | return `k_gate: passed`, not exact counts; one-way opt-out | lead | open |
| SEC-09 | S2 | pick lifetime or annual; make trigger and API agree | founder | open |
| SEC-10 | S2 | exclude exhausted tenants at candidate selection | lead | open |
| SEC-11 | S3 | per-tenant canary baseline, or amend B-T + residual | lead | open |
| SEC-12 | S2 | split C-38; invert the grouping default; re-price R-3 | lead | open |
| SEC-13 | S2 | relabel C-16 / C-49 / C-05; audit the whole enforcement column | lead | open |
| SEC-14 | S3 | purge the registry on revoke, or soften §9.1 | lead | open |
| SEC-15 | S3 | four small fixes as listed | lead | open |
| ENG-01 | S1 | **Phase 1 "bundle zero"** — statically signed local bundle, same decoder, `seq = 0` waives the tlog proof | lead | open |
| ENG-02 | S1 | bound the rewrite window in `04` §3.2 + key-order fixture + state the bench config | lead | open |
| ENG-03 | S1 | `12` §11.4 wins; rewrite `13`'s `ci` recipe to include `test-integration` under `M1_REQUIRE_STORES=1` | lead | **closed by BUILD-09** — `just ci` now runs `test-integration test-isolation gates conformance` |
| ENG-04 | S1 | add `session_epoch` (preferred) or persist a `seq` high-water; assert no dup `(session_id, seq)` in `chaos_daemon_kill9` | lead | **closed by D-E** — `m1p.v1` field 6, `m1_ch_001` column, FR-SPINE-001, epoch-bump fixture; ordering executed on the live server (seventh pass) |
| ENG-05 | S1 | **Phase 1 tenant admin surface** — row + KMS alias + HMAC material + operator-token semantics, receipted | founder | open |
| ENG-06 | S2 | label A-04 `scope="post_ack"\|"pre_ack_bounded"`; page post-ack, ticket pre-ack — operational half of R-25 | lead | open |
| ENG-07 | S2 | reserved accounting quota above the 95% hard stop + assertion in `spool_disk_hardstop` | lead | open |
| ENG-08 | S2 | add four exit edges (`DISCOVERED`, `OPEN`, `RUNNING_PARTIAL`, `APPROVED`) + four unit cases | lead | open |
| ENG-09 | S2 | per-call PPR wall budget with bounded iteration + global-PageRank fallback + time-budget refusal | lead | open |
| ENG-10 | S2 | `13` §1 canonical for paths; regenerate `12`'s refs; add the five missing dirs incl. `traceability.yaml` | lead | open |
| ENG-11 | S2 | CI bench gates pipeline-minus-S3 with its own number; 800 ms is SLO-2's, nightly vs real S3 | lead | open |
| ENG-12 | S2 | name the bench runner a WS-8 Phase 1 deliverable + availability fallback (deferred, never skipped) | lead | open |
| ENG-13 | S3 | split canary lanes — committed corpus gates, live recording alerts | lead | open |
| BUILD-01 | S1 | one `Verdict` in artifacts.proto (import leaf); verify.proto documents why | lead | **fixed, verified** |
| BUILD-02 | S1 | `SimpleAggregateFunction(any, LowCardinality(String))`; ORDER BY untouched | lead | **fixed, verified** |
| BUILD-03 | S1 | `uv sync --frozen --all-packages` | lead | **fixed, verified** |
| BUILD-04 | S1 | two-lane dispatch on the `m1_ch_*` filename rule, one Postgres ledger | lead | **fixed, verified** |
| BUILD-05 | S1 | file list read on fd 3, never stdin | lead | **fixed, verified** |
| BUILD-06 | S1 | MinIO → 9002; both store wait loops fail on timeout | lead | **fixed, verified** |
| BUILD-07 | S2 | `gen-check` delegates to `gen_fresh.sh` | lead | **fixed, verified** |
| BUILD-08 | S2 | `conformance/vectors/EXPECTED` manifest arms the gate per family | lead | **fixed, verified** |
| BUILD-09 | S2 | `just ci` gains `gates` + `conformance` (closes ENG-03's second half) | lead | **fixed, verified** |
| BUILD-10 | S2 | `mark1-receipt` → Apache-2.0 so the offline verifier is buildable and publishable | founder-visible | **fixed, flagged** |
| BUILD-11 | S2 | `publish = false` on the 7 proprietary crates + `private = { ignore = true }` | lead | **fixed** |
| BUILD-12 | S2 | `09` §3.3 corrected to `controld_app`/`adjudicator_app`/`intel_app` | lead | **fixed, verified** |
| BUILD-13 | S3 | `.python-version` = 3.12; compose renamed to `compose.yaml` | lead | **fixed, verified** |
| FIX-01 | S1 | both MV `dropped_billing` predicates read `dropped_durability_class` | lead | **fixed, executed** — 7 vs 0 on the live server |
| FIX-02 | S1 | `bundle_acks` gains `bundle_hash`/`sections_skipped`/`reject_code`/`edge_version`; one vocabulary, `08`'s | lead | **fixed, executed** — 6 illegal shapes rejected by the right constraint, 3 legal shapes admitted |
| FIX-03 | S1 | `conformance/tenancy/` conftest (hard-error on missing DSN, fail-on-skip) + SEC-04 allow-list suite | lead | **fixed, executed** — 5/5 green; both tripwires verified by triggering them |
| FIX-04 | S2 | `_go-src` tripwire on `build-go` **and** `test-go` | lead | **fixed, verified** |
| FIX-05 | S2 | `override_pattern_gate.sh` prints `PARTIAL`, not `OK`, over an empty crate | lead | **fixed** |
| FIX-06 | S2 | `gen_fresh.sh` gains a `git rev-parse --git-dir` precondition | lead | **fixed** |
| FIX-07 | S2 | `07`'s `bundle_acks`/`coverage_transitions` referenced a nonexistent `devices(id)` | lead | **fixed, executed** — unreported sibling; the DDL as written could not apply |
| FIX-08 | S3 | RLS claim corrected upward: 22 of 22, and why a `tenant_id` column scan misses `m1_tenants` | lead | **fixed, executed** |
