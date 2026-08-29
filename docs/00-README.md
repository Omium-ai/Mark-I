# Mark 1 — Design Documentation

**Status:** design phase. No production code exists yet, by intent.
**Owner:** Anurag Upadhyay (founder / principal architect), Omium.
**Started:** 2026-08-28.

This directory is the complete design record for **Mark 1**, Omium's second product line: a
layer that wraps coding agents to cut **tokens per verified outcome (TVO)** while raising
output quality, and that turns every session into outcome-labeled trajectory data.

Nothing here is a proposal. The architecture was settled by a 13-agent
research → design → adversarial-critique → synthesis pass and approved by the founder. These
documents *record* that architecture at the level of detail required to write the code, and
they fix the things that are expensive to change once code exists: message definitions, table
DDL, module boundaries, function-level contracts, failure semantics, network topology, and the
test gates that make each delivery phase objectively checkable.

---

## Sources of truth, in precedence order

When two documents disagree, the higher entry wins, and the lower one is wrong and gets fixed.

| # | Source | What it governs |
|---|---|---|
| 1 | `spec/execution-plan-v2.md` | **Frozen.** The canonical plan: component registry, assembly order, compliance enforcement, phase gates. Never edited by a design document. |
| 2 | `spec/architecture-spec.md` | The authoritative architecture spec (sections 0–11), including the normative data-contract table C1–C13 and the failure-posture matrix. |
| 3 | `07-data-model.md`, `08-api-contracts.md` | The concrete contracts. Once written, every other document cites these rather than restating them. |
| 4 | Everything else in this directory | Design detail that must conform to 1–3. |

`spec/architecture-inputs.md` is the raw evidence trail behind the spec — seven technology
research reports, three independent architectures, and two adversarial critiques. It is
retained unedited so any decision can be traced back to the argument that produced it. It is
not a source of truth; the spec is what survived it.

The theory this productizes lives outside this repo, in `Omium/mark1-research/` — three
compile-verified papers: TVO as an economic objective, oracle-free outcome adjudication, and
federated experience. `01-introduction.md` maps them onto the planes and separates what is a
theorem from what is engineering.

---

## Reading order

Read `01` first regardless of who you are. After that, follow the row that describes you.

| Doc | Title | Read this if you are… |
|---|---|---|
| `01-introduction.md` | Introduction, thesis, scope, glossary | anyone, first |
| `02-requirements.md` | Numbered requirements + acceptance criteria + phase gates | writing code, testing it, or deciding whether a phase is done |
| `03-hld.md` | High-level design: C4 context/container, the five planes, core flow diagrams | building any component, or evaluating the system as a whole |
| `04-lld-edge.md` | Low-level design: `mark1d`, `mark1-proxy`, `mark1-hookshim`, `cortexd`, the Rust crates | writing edge code |
| `05-lld-cloud.md` | Low-level design: `controld` — ingest, enroll, policy-dist, dp-release, query-choke | writing cloud code |
| `06-lld-intelligence.md` | Low-level design: `adjudicator-svc`, `mark1-intel`, the training-plane seam | implementing adjudication, TVO, memory, routing, or the corpus |
| `07-data-model.md` | Protobuf, Postgres DDL, ClickHouse DDL, PolicyBundle CBOR, spool layout, corpus schemas | touching any persisted or transmitted byte |
| `08-api-contracts.md` | M1P/1, control-plane REST, MCP tools, hook contracts, CLI, UDS framing, error taxonomy | implementing or calling any interface |
| `09-infrastructure.md` | AWS topology, EKS, RDS, ClickHouse, S3/KMS, IRSA, Helm + GitOps, capacity and cost, DR, edge distribution | deploying, sizing, or paying for it |
| `10-security-threat-model.md` | Trust boundaries, STRIDE, the OAuth guard, credential custody, tenancy, key ceremony, control matrix | reviewing us, or writing anything that touches a credential or a tenant boundary |
| `11-observability-and-slo.md` | Self-monitoring without OpenTelemetry, metrics catalog, SLIs/SLOs, alerts, runbooks | operating it |
| `12-testing-and-quality.md` | Test pyramid, conformance suites, fuzz and chaos targets, isolation negative tests, CI thresholds | writing a test, or checking a gate |
| `13-repo-scaffold.md` | File-by-file scaffold, build tooling, lint/format, versioning, release, CODEOWNERS | starting the first commit |
| `14-delivery-plan.md` | Workstreams, dependency graph, milestones, gate checklists, risk register | sequencing the build |
| `adr/` | Architecture decision records | before changing anything a record decided |
| `RECONCILIATION.md` | Every contradiction found across the set, with severity and owner | signing off the design phase, or wondering why two documents disagree |

---

## Non-negotiables

These bind every document, every component, and every future change. A design that violates one
is wrong on its face, not a trade-off to discuss.

1. **No OpenTelemetry, anywhere.** M1P is Omium's own capture fabric. Not "OTel plus
   extensions", not "OTel for internal spans" — none. The estate was checked: nothing depends
   on OTel that Mark 1 would inherit, so this costs nothing today and stays cheap only if it is
   never relaxed.
2. **Subscription traffic is never intercepted.** No proxying, no credential intermediation, no
   modification of any vendor binary. The wire proxy serves customer-owned **API-key** traffic
   only, gated on a credential provisioned after positive API-key detection, and there is no
   override path compiled into the binary. This is a legal boundary, not a policy preference.
3. **Raw sessions and customer code stay client-side by default.** Evidence is typed, never free
   text. Judges run through the customer's own key by default. Anything else is an explicit,
   receipted, per-tenant opt-in.
4. **Four verdicts, always:** `satisfied | violated | refused | error`. Collapsing infrastructure
   failure into `violated` incurs provably unavoidable excess risk; the vocabulary is a theorem,
   not a convention.
5. **Failure posture is fixed:** fail-**open** for availability (capture, hooks — Mark 1 must
   never be why an agent stopped working), fail-**static** for policy (last-known-good runs
   indefinitely if the control plane vanishes), fail-**closed** for legality and secrets (the
   OAuth guard, upload admission, revocation).
6. **Every number we quote is defensible.** A TVO figure carries its coverage band and its cost
   basis (`usd` or `quota`), and guarantee-grade reporting is refused below the coverage floor.
   "Verify Omium" is the sales claim, so the receipt chain ships with a standalone offline
   verifier from the first phase.

---

## Keeping documents and code in sync

Once code exists, the documents are not archaeology — they are the interface. The rules:

- **Contracts change here first.** A change to a proto message, a table, a bundle section, an
  error code, or a hook payload lands in `07`/`08` in the same pull request as the code, or the
  pull request is incomplete.
- **`buf breaking` is the enforcement.** Wire compatibility is checked mechanically; the document
  explains the change, CI decides whether it is allowed.
- **A requirement without a test is a bug in `02`.** Every requirement in `02` names how it is
  verified and `12` names the test. Adding a control to `10` without a corresponding row in
  `12` is not permitted.
- **Decisions go in `adr/`, not in prose.** If a design changes for a reason, the reason is an
  ADR with a status; superseded records stay, marked superseded.
- **The plan is frozen.** `spec/execution-plan-v2.md` is not edited by this documentation effort.
  If reality contradicts the plan, that is a finding to raise with the founder, not a document
  to quietly amend.

---

## Document status

All fifteen numbered documents and all nine ADRs are written. What remains is decision, not
authorship.

| Doc | Status |
|---|---|
| `00-README.md` | written |
| `01-introduction.md` | written |
| `02-requirements.md` | written — 181 requirements (15 CON, 120 FR, 46 NFR) |
| `03-hld.md` | written — 15 diagrams, all 9 core flows |
| `04-lld-edge.md` | written — 46-row failure catalog, each row naming its test |
| `05-lld-cloud.md` | written — 11-stage ingest, querychoke construction proof |
| `06-lld-intelligence.md` | written — ADJUDICATE pseudocode + worked example |
| `07-data-model.md` | written — 29 sections: protobuf, Postgres, ClickHouse, CBOR, corpus |
| `08-api-contracts.md` | written — full `M1E-*` error taxonomy |
| `09-infrastructure.md` | written — capacity model with the arithmetic shown |
| `10-security-threat-model.md` | written — 67-row control matrix (C-01…C-67) |
| `11-observability-and-slo.md` | written — 10 SLOs, 15 alerts, 10 runbooks, zero OTel |
| `12-testing-and-quality.md` | written — per-phase gate checklists |
| `13-repo-scaffold.md` | written — file-by-file scaffold, commits C0–C9 |
| `14-delivery-plan.md` | written — ≈116 engineer-weeks, staffing scenarios |
| `RECONCILIATION.md` | **open** — 104 findings (26 cross-document + 15 security review + 13 staff-engineer review + 13 build verification + 37 line-level sweep); the input to sign-off. The last 50 are the **closed** ones: they were found by *executing* the foundation and then reading every line of it, rather than reading the documents that describe it. The sixth pass also records eleven binding cross-document decisions (D-A…D-K) that no single document could have resolved alone. |

| ADR | Decision | Status |
|---|---|---|
| `0001-clickhouse-ordering-key.md` | ordering key + `ReplacingMergeTree` layout | **Proposed — founder sign-off required** |
| `0002-task-seg-v1.md` | the TVO denominator's merge rules | **Proposed — founder sign-off required** |
| `0003-shapley-game-definition.md` | players and `v(S)` | **Proposed — deferred**; the deterministic waste taxonomy ships first regardless, and no Shapley code may be written until this is signed |
| `0004-key-ceremony.md` | device / chain / bundle / update keys, rotation, witness | **Proposed — founder sign-off required**; resolves R-01 |
| `0005-no-otel-m1p.md` | zero OpenTelemetry; M1P is the sole fabric | Accepted |
| `0006-language-boundaries.md` | where Rust, Go and Python each go, and why | Accepted |
| `0007-spool-durability-classes.md` | block-on-full vs drop-newest per class | Accepted |
| `0008-client-side-first-judges.md` | judges run through the customer's key by default | Accepted |
| `0009-verdict-to-training-label.md` | four verdicts → binary KTO labels | **Proposed**; resolves R-02 |
| `0010-tvo-rollup-writer.md` | who writes `tvo_tenant_day` — a daily job-keyed batch writer, never a materialized view | **Proposed — founder sign-off required before the first `tvo_tenant_day` write**, the same gate ADR-0001 carries; resolves D-F / F37 |

**The design phase is not complete.** It closes when:

1. every `RECONCILIATION.md` finding is dispositioned — in particular the sixteen S1s. Two are not
   ours to close directly (**R-03** rides on SEC-02's outcome; **R-05**, staging truth, belongs to
   the estate owner). Two more are now **closed** by the sixth pass and are shown struck through
   below rather than deleted, because a reader needs to see that they were raised and how they
   settled: **R-21** (`EdgeHealth` ratified) and **ENG-04** (`session_epoch` ratified). The
   remaining **twelve**:

   *Cross-document reconciliation*
   - **R-01** the KMS/Ed25519 split, **R-02** the verdict→label mapping, **R-04** the missing
     Phase 6 gate;
   - **R-22** whether anything in this estate is actually scraped;
     (**R-21** — the `EdgeHealth` message `11` depended on and `07` never defined — is
     **closed**: `07` §3 ratified it as `Event.body` field 22, `11` §12 records G-5 as closed,
     and its closed-field-set control is specified as `conf_schema_closed_field_set`, `12` §3.6);

   *Security / compliance review — each falsifies a non-negotiable as written*
   - **SEC-01** the off-switch, which as specified *is* the compiled-in override the OAuth guard
     says does not exist — it must detach, not pass through;
   - **SEC-02** the corpus exporter, which as specified writes the customer's plaintext prompts and
     completions to an Omium bucket, contradicting non-negotiable 3 above. **This gates R-03** (the
     one-field training-plane change), which must not be authorized until SEC-02 is decided;
   - **SEC-03** an erasure claim scoped wider than the mechanism, plus foreign keys that forbid the
     deletion the deletion path mandates;
   - **SEC-04** two incompatible Postgres role inventories — the estate's own decorative-RLS
     failure, reproduced at design time.

   *Staff-engineer review — build-order and correctness, not policy*
   - **ENG-01** Phase 2's gate depends on the bundle plane Phase 3 delivers. The build order does
     not close, and the improvised fix is a bundle side-channel that bypasses signature verification
     permanently. Needs a Phase 1 **bundle zero**;
   - **ENG-02** model rewrite silently breaks the no-buffering invariant when a client emits `model`
     after `messages`, against an unbounded buffer and a ≤1 ms budget with no arithmetic for it;
   - **ENG-03** `12` and `13` disagree on how CI provisions stores, and `13`'s `ci` recipe **omits
     the isolation suite** — byte-for-byte the excluded-tests failure `12` §0.3 exists to prevent;
   - ~~**ENG-04** the per-session `seq` counter does not survive a daemon restart, so every restart
     silently corrupts the causal order that `07` calls the source of truth — and therefore the TVO
     numbers we quote. Does not disturb R-08: the *placement* is right, the *recovery* is missing;~~
     **closed (D-E)**: `Event.session_epoch` is ratified as `m1p.v1` field 6 — a durable
     per-device boot counter — and `07` §2 now makes the lexicographic pair `(session_epoch, seq)`
     the normative causal order, with `(session_id, session_epoch, seq)` unique where
     `(session_id, seq)` was not. The rule binds every consumer, has a ClickHouse column
     (`m1_ch_001`), a P0 requirement (FR-SPINE-001) and a test fixture with a mid-session epoch
     bump (`12` §skew-ordering-invariance) — the last of which is what would catch a regression
     back to `seq` alone, which a clock-skew fixture alone cannot;
   - **ENG-05** nobody builds tenant onboarding. Every flow presupposes a provisioned tenant; no
     module, no endpoint, no task owns creating one. Phase 1's own dogfood cannot enroll device #1
     without hand-crafted, unreceipted identity-plane rows.

   SEC-01 and SEC-02 each falsify a non-negotiable as currently written. Neither is a deep flaw —
   both fixes are small and both are recorded — but **neither may be left open into Phase 1**,
   because each is a sentence we would otherwise say to a customer that is not true. ENG-01, ENG-03
   and ENG-05 are different in kind: not wrong statements but missing work, and each would surface
   in the first three weeks of Phase 1 as improvisation under deadline. All three fixes are small
   *now* and expensive after code exists — which is precisely what this phase is for.
2. ADRs 0001, 0002 and 0004 are **signed** — 0001 before any production ClickHouse write and 0002
   before any number is quoted to a customer, because both are irreversible in practice;
3. a reader who has never seen this conversation can go from `01-introduction.md` to writing
   `proto/m1p/v1/*.proto` without asking a question.

Item 3 is the real test. Items 1 and 2 are what make item 3 honest.

### Mechanical verification — run by the lead, 2026-08-28

The plan's Appendix A names six checks for this phase. The evidence is here so the next reader does
not have to re-derive it — including where a check passes on coverage but not on accuracy, which is
the only kind of verification result worth writing down.

| Check | Result |
|---|---|
| Every registry component has an LLD section | **Pass.** `04` §§2–7 cover `mark1d`, `mark1-proxy`, `mark1-frames`, `mark1-hookshim`, `cortexd` and the four client crates; `05` §§2–6 cover `controld`'s five modules; `06` §§1–9 cover both Python services |
| Every data-store table has real DDL in `07`, and every RLS policy has a negative test in `12` | **Pass on design, not on wiring.** 14 `FORCE ROW LEVEL SECURITY` tables, 14 `CREATE POLICY tenant_isolation`; `12`'s isolation suite is *driven from `pg_policies` at runtime*, so a new tenant-scoped table without a policy fails **by omission** — the design cannot rot silently. But **ENG-03**: `13`'s `ci` recipe, "everything a PR must pass," omits `test-integration`, so the suite `12` calls a required check is not in the scaffold's CI entrypoint. Strong test, not yet wired |
| Each of the six **Gate:** lines resolves to a numbered acceptance criterion | **Pass.** `02` §9 is the acceptance table, §10 maps each gate to the requirement IDs that must be green, and `12` §12 carries the matching per-phase checklists. One caveat, already tracked: Phase 6's gate sentence is derived, not verbatim (**R-04**) |
| Each of the seven in-code compliance points has a `10` control row and a `12` test | **Pass on coverage** — 67 control rows, every one of the plan's seven points cited 5–8 times. **Not a pass on labelling**: see **SEC-13**, where three rows claim a stronger enforcement class than their mechanism delivers |
| All ADRs written with a decision recorded | **Pass.** Nine ADRs, each with a status line: four Accepted (0005–0008), four Proposed awaiting founder sign-off (0001, 0002, 0004, 0009), one Proposed-and-deferred (0003 — and no Shapley code may be written until it is superseded) |
| No document references OpenTelemetry as a dependency anywhere | **Pass.** Every occurrence across all 24 files is a rejection, a rationale, or a CI gate that bans it — `ci_lockfile_no_otel` scans the cargo, go and uv lockfiles, and ADR-0005 carries the rule forward as a repo lint on `docs/` |

Three checks passed on coverage while failing on accuracy, and all three are recorded rather than
smoothed over: the compliance matrix is complete but three of its enforcement labels overstate
(SEC-13); the isolation suite is genuinely strong while the role *inventory* it tests against is
contradictory between documents (SEC-04) and the suite is missing from the scaffold's CI entrypoint
(ENG-03). A fourth, adjacent: `tools/trace-check` is `12`'s enforcement of requirement coverage, and
the `conformance/traceability.yaml` it reads is never created by `13` (ENG-10).

**The distinction that matters for sign-off:** every one of these is a documentation defect caught
while it is still only documentation. None is a design that does not work. The two adversarial
reviews between them could not break the spool-full deadlock analysis, the single-writer invariant,
the OPE sequencing, the querychoke construction proof, the receipt chain, the `M1-Cred-Ref` binding,
the S3-first ack, the state machines outside the four missing edges, or the codegen story — which is
the result this phase was run to obtain.
