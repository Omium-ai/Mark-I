# Spike: Codex CLI `TokenCountEvent` — go/no-go for the Codex adapter slot

Gates: `03-hld.md` §6 Codex row, `08-api-contracts.md` §5.2, FR-AGENT-011. All URLs read 2026-09-15 against `openai/codex` (npm `@openai/codex`, latest stable `0.154.0`, alpha channel `0.155.0-alpha.7`).

## Verdict: GO-WITH-CONDITIONS

`TokenCountEvent` is real, typed, and carries the token breakdown we need — the surface exists and its field vocabulary tracks Claude Code's closely, so the plan's ~80% overlap assumption holds up under direct source inspection. But it is a **live protocol/event-stream artifact, not a confirmed transcript-tail artifact**: whether it (or its rollout sibling `TokenUsageRecord`) is actually persisted to the on-disk session JSONL for ordinary sessions is unconfirmed from source text, and an explicit prior request to add usage to rollout files was closed "not planned." The adapter cannot reuse the Claude Code tailer design as-is; it needs a live-event-stream capture path (wrapped `codex exec --json` or an app-server client), which is a scope change the spike proper must confirm empirically before any adapter code merges.

## Q1 — TokenCountEvent: exists, per-session cumulative + per-turn delta, two related shapes

Core protocol (`codex-rs/protocol/src/protocol.rs`): `EventMsg::TokenCount(TokenCountEvent)`, doc comment "Usage update for the current session, including totals and last turn. Optional means unknown — UIs should not display when `None`."
```rust
pub struct TokenCountEvent { pub info: Option<TokenUsageInfo>, pub rate_limits: Option<RateLimitSnapshot> }
pub struct TokenUsageInfo { pub total_token_usage: TokenUsage, pub last_token_usage: TokenUsage, pub model_context_window: Option<i64> }
pub struct TokenUsage { input_tokens, cached_input_tokens, cache_write_input_tokens, output_tokens, reasoning_output_tokens, total_tokens: i64 }
```
This existed by 2025-10-07 ([PR #4856](https://github.com/openai/codex/pull/4856), Number-vs-BigInt fix for the VS Code extension). A known defect ([issue #14489](https://github.com/openai/codex/issues/14489)) says `TokenCount` re-emits `last_token_usage` on rate-limit-only refreshes with no new usage — a tailer that treats every `TokenCount` line as a fresh delta will overcount, structurally the same failure class FR-SPINE-003 defeats for Claude. `cumulative_cost_usd` was requested but absent as of 2026-03-30 ([issue #16258](https://github.com/openai/codex/issues/16258)).

Separately, `codex exec --json` (alias `--experimental-json`) emits a purpose-built stdout JSONL stream (`codex-rs/exec/src/exec_events.rs`, `event_processor_with_jsonl_output.rs`): `thread.started/turn.started/turn.completed/turn.failed/item.*/error`. `TurnCompletedEvent.usage: Usage{input_tokens, cached_input_tokens, cache_write_input_tokens, output_tokens, reasoning_output_tokens}` (no `total_tokens` here) is the practical per-turn usage line for a wrapped exec subprocess — introduced with the `--json`/`--experimental-json` flag (`codex-rs/exec/src/cli.rs`); exact introducing version not found in fetched docs.

Not found in source as of 2026-09-15: an explicit statement of emission cadence (once per API response vs. also on other triggers) beyond the rate-limit-refresh caveat above.

## Q2 — Hooks: yes, and closely modeled on Claude Code's

Codex has a real hooks system as of today ([developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks) → [learn.chatgpt.com/docs/hooks](https://learn.chatgpt.com/docs/hooks)). Events: `SessionStart/SessionEnd`, `PreToolUse/PostToolUse`, `PreCompact/PostCompact`, `UserPromptSubmit`, `SubagentStart/SubagentStop`, `Stop/Interrupt`. Config: `~/.codex/hooks.json` or inline `[[hooks.SessionStart]]` / `[[hooks.SessionStart.hooks]]` tables in `config.toml` (`type="command"`, `command`, `timeout`), plus repo-level `.codex/hooks.json`, plugin-bundled `hooks/hooks.json`; feature-gated by `[features] hooks = true|false`; admin lock `allow_managed_hooks_only = true` in `requirements.toml`. Exact stdin schema confirmed from source (`codex-rs/hooks/src/schema.rs`, `UserPromptSubmitCommandInput`): `session_id, turn_id, agent_id, agent_type, transcript_path, cwd, hook_event_name, model, permission_mode, prompt` — field names are near-identical to Claude Code's, plus a native `turn_id`. Stdout: `{continue, stopReason, systemMessage, hookSpecificOutput:{hookEventName, additionalContext}}`; exit 0 = parse JSON, exit 2 = block (stderr reason), other = error — the same three-way contract as `08` §5.1. Output capped ~2,500 tokens (`additionalContextLimit`), overflow spills to `<temp_dir>/hook_outputs/`. This is direct confirmation, not inference, of the plan's ~80% vocabulary-overlap claim. No hook schema fetched carries token usage, consistent with (but not an explicit vendor confirmation of) Mark 1's own rule that usage never rides hook JSON.

Introduction date not pinned exactly; hooks predate a regression reported against Codex Desktop `0.129.0-alpha.15` (~spring 2026, [issue #21639](https://github.com/openai/codex/issues/21639)).

## Q3 — Persistence: rollout JSONL exists; usage-in-rollout is unconfirmed

Path: `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ISO-ts>-<thread_id>.jsonl` (`codex-rs/rollout/{lib.rs,recorder.rs,rollout_file_name.rs}`). Format: one `RolloutLine{timestamp, ordinal, #[flatten] item: RolloutItem}` per line (`codex-rs/history/src/lib.rs`). `RolloutItem` variants include `SessionMeta, ResponseItem, Compacted, TurnContext, TokenUsageRecord(TokenUsageRecord), WorldState, SecurityRiskScore, RetainedContext, EventMsg(EventMsg), RealtimeItem, InterAgentCommunication*`. `TokenUsageRecord{thread_id, turn_id, session_id, root_turn_id, response_id, usage: TokenUsage, turn_token_usage: TokenUsage, thread_token_usage: TokenUsage}` — `response_id` is the closest structural analog to Claude's `requestId`; `(thread_id, turn_id, response_id)` is a plausible idem_key composition satisfying FR-SPINE-003's dedupe class. **But**: an explicit user request to add usage/cost to rollout files was closed "not planned" ([issue #3201](https://github.com/openai/codex/pull/3201), predates this research); `TokenUsageRecord` existing as a type does not by itself prove the recorder writes it for ordinary interactive/exec sessions today rather than only for the newer `features.rollout_budget` accounting path. **Not found in source as of 2026-09-15**: confirmation that a real session's `.jsonl` actually contains `TokenUsageRecord` or `EventMsg::TokenCount` lines. This is the first empirical check the real spike must run (record a session, `grep` the file).

## Q4 — Subscription vs API-key parity

`AuthMode` (`codex-rs/protocol/src/auth.rs`) lists `ApiKey, Chatgpt, ChatgptAuthTokens, Headers, AgentIdentity, PersonalAccessToken, BedrockApiKey, BedrockAccessKeys` as orthogonal to the event/rollout layer — no auth-mode branch gating `TokenUsage` population was found in fetched source, so parity is architectural inference, not an explicit statement. Third-party corroboration (not authoritative — a downstream project, not `openai/codex` itself): [openclaw/openclaw#78760](https://github.com/openclaw/openclaw/issues/78760) reports ChatGPT-subscription-authenticated Codex sessions do populate local `usage`/cost fields even though billing is subscription-based. No ToS or technical barrier found to reading these already-on-disk, locally-written records — consistent with Mark 1's "never proxy subscription traffic, only read local writes" posture. OpenAI's ToS text itself was not independently reviewed in this pass.

## Q5 — Versioning

Pin via `npm install @openai/codex@<exact-version>` or the matching GitHub release tag/asset ([releases](https://github.com/openai/codex/releases)). Churn is fast: npm lists 4,463 published versions total ([npmjs.com/package/@openai/codex](https://www.npmjs.com/package/@openai/codex)); the alpha channel cut `0.155.0-alpha.3` through `alpha.7` within 2026-09-11–15 alone. This is materially faster than Claude Code's cadence — `08` §5's common rule 2 ("unmapped version ⇒ `Dropped{unsupported_agent_version}`") is load-bearing here, not optional.

## What the adapter slot needs

- **Hooks (capture: context/injection):** viable, confirmed field-for-field close to Claude Code's — but carries no usage, same as Claude.
- **Transcript tail:** unconfirmed for usage. Type support exists (`TokenUsageRecord`, `EventMsg` as `RolloutItem` variants) but on-disk presence for ordinary sessions is not verified from source alone, and a prior feature request for exactly this was declined.
- **Artifact dirs:** no distinct usage surface found beyond the rollout tree and the hook-output spill directory (which carries hook output, not usage).
- **Proxy (API-key regime):** viable as already scoped by the separate `openai-responses/chat dialect golden transcripts` spike (`08` §5.2) — out of this spike's scope.
- **Net:** the credible Usage source for Codex is a **live event stream**, not a file tail: either wrap `codex exec --json` and read `turn.completed.usage`, or run as an app-server JSON-RPC client consuming `EventMsg::TokenCount`. This is a real architectural branch from the Claude Code adapter, not a drop-in reuse, even though hook vocabulary reuse is confirmed high.

## Open risks

1. Rollout persistence of usage is unverified — must be confirmed empirically before any "transcript tail" design is written into the adapter.
2. `TokenCount` re-emits on rate-limit-only refreshes with unchanged usage (#14489) — naive per-line summation double-counts, same failure class as Claude's streaming overcount.
3. Extremely high release velocity (multiple alphas/day) raises the odds a pinned conformance fixture goes stale fast; per-version fixture pinning is not optional.
4. No `cumulative_cost_usd` on the wire as of 2026-03-30 — cost attribution needs local price-table math, not vendor-supplied cost.
5. App-server JSON-RPC protocol shape (needed if the live-event-stream path is chosen for interactive sessions) was not deeply investigated in this pass and needs its own read before adapter design.
