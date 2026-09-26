# 16 — Release: real savings, T2 reward model, rounded Teams, first-run and retention

Status: approved by the founder 2026-09-26. Builds on `15-teams.md` (branch `teams-v1`). This is the contract every lane builds against; a lane that must deviate says so in its report instead of improvising. Research behind every section: `Omium/scratch/release-research/README.md`, `Omium/data/rm/papers/rm-design.md`, `Omium/data/rm/papers/verifier-models.md`, `Omium/data/rm/manifests/LICENCE_AUDIT.md`.

## Founder rulings

1. **Certification by a trained T2 reward model (RM)**, not gold labels standing in. The third independent view is **both** a diff-reading judge **and** a second RM from a different model family.
2. **The RM runs on the user's machine or in our cloud — the user chooses** (Settings). Local is the default where the machine can run it; nothing leaves the machine on the local path.
3. **Cloud judging and memory extraction go through the platform llm-router (Nebius Token Factory)**, not an Anthropic key. Zero Data Retention is on (founder toggles it in the Nebius console); processing region is "global" and the consent text says so.
4. **"Tokens saved" is measured against plain Claude Code**: net estimated savings (credit blocks that led to a fixed task, debit tokens spent after blocks that did not). It can be negative. Arrests are reported separately as "forced retries avoided".
5. **Training data**: public data first (licence-clean rows only until counsel signs off on model-generated rows and unlicensed archives), then real agent PRs mined from GitHub, then self-generated execution-labelled sessions, then Mark 1 users' outcomes with consent.
6. Teams: per-member aggregate totals (sessions, verified tasks, tokens, saved) are visible to every member; never another member's sessions. Invite emails go out via Customer.io. The weekly savings email is **opt-in**.

## Independence rules (Paper II Assumption 1) — every lane obeys these

- Views: **anchors** (the project's own static checks; compile/test are the sound rejectors), **judge** (LLM), **RM-A** and **RM-B** (two trained models of different base families).
- The RM sees **only the task text and the final diff**. Never anchor output, EvidenceRecords, test output, the agent's trajectory or self-claims, or judge output. A unit test on prompt assembly enforces it.
- The judge counts as independent of anchors **only** when its input is the diff (E1 hunks or local raw diff) and its rubric rows used for estimation do not reference anchor output. An E0 judge (anchor rows as evidence) is correlation group `syntactic`.
- Correlation groups come from `m1_verifiers.definition.group`, not from the event family. Tests are their own group (architecture spec), not `syntactic`.
- Identifiability gate G4 counts only sound rejectors (compile, test) as anchors.
- RM training labels are execution- or time-grounded only (tests, merge/revert/CI/survival, human gold). Never Mark 1's fused verdicts, never LLM-judge labels.
- Every view runs on every task it can (no ambiguity-triggered running).

## Lanes

Base branches: `release-v2` in omium-mark1 and Mark1-GUI, cut from `teams-v1`. Each lane owns the files listed; the lead integrates.

### L1 — Router judging + memory extraction (adjudicator, intel, charts)
- `app/llm.py` httpx client in adjudicator and intel: `POST {LLM_ROUTER_URL}/v1/chat/completions`, header `X-Omium-Agent-Id: <MARK1_ROUTER_AGENT_ID>` + `X-Omium-Execution-Id: <uuid>`, **never a tenant header or `tenant_id`** (the router's adapter hop would route to Baseten); semaphore 4, 190 s timeout, retry 429/502/503/504 ×3 (1/2/4 s), a policy-blocked answer is counted and not retried.
- Pinned catalog ids: judge `zai-org/GLM-5.2`; memory candidate `Qwen/Qwen3-30B-A3B-Instruct-2507`; memory validate `zai-org/GLM-5.2`. Served model must equal the pinned id or the vote is refused.
- `JudgeSpec.locus` edge|cloud: `judge:grounded-rubric@1` = edge (customer key, Claude), `judge:grounded-rubric@2` = cloud GLM via router (`subprocessor=nebius`, `region=global`, `max_tier=E1`). Migration revokes live `@1` cloud consent rows (UPDATE, `revoked_reason='subprocessor_changed:anthropic->nebius'`).
- Memory extraction consent: its own register key `mem:extract@1` (nebius/global), its own toggle "Learn from my sessions" (off by default); extraction runs only for admitted tenants. CHECK rewrite + `intel_app` grant.
- Caps: `ADJ_JUDGE_MAX_TASKS_PER_DAY=60`, `INTEL_MEMORY_MAX_SESSIONS_PER_DAY=30`, `INTEL_MEMORY_MAX_INPUT_TOKENS=20000`.
- Charts: `config.llmRouterUrl`; drop the anthropic secret/flag; NetworkPolicy egress to `omium/llm-router:8005`. gitops: drop `mark1-anthropic` ExternalSecret; llm-router ingress from `omium-mark1`. Platform chart: `INTERNAL_SYSTEM_AGENT_IDS` env + prod value adding Mark 1's id (the global Shell-Injection rule `[;&|$\x60]` otherwise 403s every Mark 1 prompt).
- Remove `anthropic` deps; delete dead `CloudJudge`. Consent copy in the app names Nebius, global processing, zero retention. Docs: 02 NFR-PRIVACY-006, 06 §6.5/§9.1, 10.

### L2 — Real savings number (controld querychoke, mark1d gate, app)
- Phase 0: `tvo=null` when verified=0 (window + trend); `tokens_saved.label="estimated"`, `tokens_saved.certified`; `tokens_saved_estimate` on the local arrest SSE row; stale "knee never fires" comments; "prior p(r)" instead of p̂_LCB wording when the basis is the bootstrap prior; app: savings chip separate from the TVO pill, `estimate` read, Settings/notify through `isIndicative`, consistent zero copy, Memory tile shows hits/tokens injected (activity, not savings).
- Phase 1: `savings.v2` net estimate per ruling 4 (credit resolved blocks, debit post-block usage of unresolved; arrests separate "forced retries avoided"); certified saved = same restricted to certified tasks, 0 until certification.
- Phase 2 (ADR-0012 "Knee index is the repair round"): edge r = consecutive VIOLATED attempts whose failure signature (`tool:diagnostic_code` set) overlaps the previous; reset on non-VIOLATED or disjoint; knee reads r; n stays for the ledger. Grade closed days separately from today's live day (I2).
- `GuardDecision` gains `knee_basis` (prior|anchor_grounded|certified) and `bundle_seq` is projected (07 + proto additive).

### L3 — Teams rounded + weekly email (controld appapi, intel job, app)
- Customer.io: controld Go client + intel Python client, secret `omium/prod/customerio-credentials` (`app_api_key`) via ExternalSecret `mark1-customerio`, from `noreply@mail.omium.ai`, **click tracking off, message retention off**. Unset key ⇒ not sent.
- Invite email (send after commit, 5 s timeout, failure keeps the invite, `sent` truthful); `DELETE /api/v1/team/invites/{id}` (owner, user token; `expires_at=now()`).
- Team dashboard: `team_device_totals.v1` (m1p_events, GROUP BY device_id, aggregates only) under `TenantWide`; per-member `totals` on GET /team; unattributed bucket; never device ids or sessions.
- Per-person trend: `tvo_task_day.v1` + per-day fold in live.go; leave `tvo_task_window` untouched.
- Weekly email: migration `m1_091_notification_prefs`; `GET/PUT /api/v1/me/notifications`; public `GET/POST /api/v1/unsubscribe/{token}` (+ Kong route); intel `digest.weekly` job + weekly cadence + CronJob `0 9 * * 1`; send ledger; List-Unsubscribe headers; postal address from config `EMAIL_POSTAL_ADDRESS` (founder supplies; unset ⇒ job refuses to send).

### L4 — First run (mark1d anchors/control, app onboarding + Home)
- `POST /v1/anchors/probe {project}`: runs consented static anchors once on the worktree via `RunOne`'s handler path, **emits no AnchorVote**, records `last_run/last_code`; answers 202; app polls `GET /v1/anchors`. Framed "checks ready", never "verified".
- Onboarding: consent 409s retried and shown; recent projects ticked by default; Watching runs the probe, lists results (`AnchorRow`), then a live "Waiting for your first task…" card that flips on the first `verdict`/`arrest` event, with a copyable starter prompt.
- Home "N checks need your OK": copy `N checks need your OK · x new · y changed`, 30 s refetch, dedupe by `id+exec_hash`, surface errors, link to Verify › Anchors.

### L5 — RM training pipeline (omium-training-plane/training-jobs, data/rm)
- Objective `rm_pointwise` reusing `KtoRow/KtoDataset` (prompt = task, completion = diff, desirable/undesirable), LoRA or full FT per the bake-off, BCE on `logit("yes") − logit("no")` at the final position; optional pairwise term on same-task pass/fail pairs. `DataClass.PUBLIC`.
- Data assembly from `s3://omium-training-datasets-prod-965384155704/rm/normalized/` with the licence audit as a filter (USE + approved USE-WITH-CONDITIONS), split by task/instance across sources, time split, repo down-weighting (django), held-out sets: swe-review-bench, patch_correctness_pcc, SWE-bench Verified/Lite, a Claude-style shift set.
- `eval_rm` eval card: AUROC/AUPRC, ECE + fitted calibration (`calibration_version`), per-language, per-source, shift-set AUROC (v1 bar ≥ 0.60), latency on CPU int8.
- Export: merged weights + GGUF (int8) with HF↔GGUF parity vectors; artifacts to `s3://omium-adapters-prod-965384155704/rm/<name>@<ver>/`.
- RM-A base: Qwen family (bake-off Qwen2.5-Coder-1.5B / Qwen3-1.7B / Qwen3-0.6B); RM-B base: a different family (ModernBERT-large or a Llama/Granite/Gemma-class small model with a commercial licence).

### L6 — RM serving + adjudicator integration
- Edge (client-side): supervised child `mark1-rm` (llama-server first), model downloaded on consent and sha256-pinned in the local catalog; runs after TaskClose, niced, one at a time, 30 s timeout; `RmScore` gains `execution_hash`, `signature` (Ed25519 like AnchorVote), `locus`; consent `local_rm` on device consents; Settings choice Local | Cloud | Off.
- Cloud: Baseten scale-to-zero endpoint scoring on E1 hunks for tenants that chose Cloud and consented to E1.
- Ingest: refuse malformed RmScore (model id, score range/NaN, bad signature).
- Adjudicator: `adjudication_votes.v3` (RmScore with calibration_version; judge tier/trigger); fold RmScore in `vote_matrix`/`votes_by_task`; groups from registry; G4 sound rejectors only; shadow members enter estimation, not fusion (amends 06 §4.4); promotion pairs from gold + certified ledger (not escalations); `register` caller and the probation→shadow, canary→active edges; compiler drops `judge:`/`rm:` ids from the edge verify section instead of raising; seed `rm:` catalog rows; a structural check comparing predicted vs gold-measured agreement.

### L7 — Diff-reading judge
- Edge judge (customer's key) reads the local raw diff + task text with a rubric whose estimation rows never reference anchor output; cloud `@2` reads E1 sanitized hunks for consenting tenants. `JudgeVote` gains `tier_used` and `trigger`. E0 judge rows are group `syntactic`.

### L8 — Real data (GitHub mining, self-generated sessions, consented user data)
- GitHub agent PRs: AIDev + a GH Archive collector (Claude Code/Codex/Copilot/Devin/Cursor signatures) with labels merged/closed, CI conclusion, revert, 30-day code survival; runs as cluster Jobs writing to `rm/raw/` + `rm/normalized/`.
- Self-generated: pilot 1,000 tasks (SWE-rebench/SWE-smith images) with an open agent on Token Factory models + a Claude Code slice, hidden-test labels, flaky re-runs, reward-hack detection; then 20k.
- Consented user data (v2): a consent class "Contribute task outcomes to improve Mark 1's models" (off by default) that uploads task text + redacted diff + outcome for opted-in devices; dogfood tenants first.

## Rollout
Cloud (migrations m1_091+, controld, intel, adjudicator) → platform router config → edge release (probe, gate, RM child) → app release. Models ship behind promotion: probation → shadow → LCB → canary → active; "certified" appears only when the identifiability gate honestly passes.
