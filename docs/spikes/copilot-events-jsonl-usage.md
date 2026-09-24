# Spike: GitHub Copilot CLI `events.jsonl` usage surface

**Scope:** Copilot CLI / coding-agent surfaces (`github/copilot-cli`), not IDE inline completions. Gates the Phase 5 `copilot` adapter slot per `docs/design/03-hld.md` §6 and `docs/design/08-api-contracts.md` §5.5. All facts read 2026-09-15; every claim is sourced or marked "not found as of 2026-09-15."

## Verdict: GO-WITH-CONDITIONS — stays Phase 5, on a different primary usage path than the plan assumed

The named spike target — `events.jsonl` as the per-request `Usage` source — is **refuted for billing-grade capture**. It's real, but GitHub's own contributors call it undocumented/unstable (open issue asking them to formalize it), it has a confirmed breaking-field regression and a JSON-corruption bug in the trailing release window, and its token-usage payload is a **whole-session rollup per model**, not per-request — incompatible with Mark 1's `idem_key = HMAC_tenant(session_id, message.id, request_id)` invariant (`08-api-contracts.md` §2).

Two findings change the adapter's shape, not its phase: (1) **hooks are more mature than the matrix assumed** — a GA, documented lifecycle-hook system (14 events, JSON stdin, exit-code + JSON gating) structurally parallel to Claude Code's, closeable with a conformance fixture now; (2) **BYOK is real, first-party, and ToS-clean by structure**, giving Copilot the same wire-capture path already verified for other API-key-regime agents — BYOK traffic goes straight to the named provider, so it's billing-grade and dialect-mappable the same way.

Recommendation: keep Copilot at Phase 5, re-scope the deliverable — close **capture: hooks** and **injection** on the documented hook contract; keep **capture: transcript/usage** gated, retargeted from `events.jsonl` to the BYOK wire path (subscription-regime `events.jsonl`/OTel becomes DIAGNOSTIC-class only, never `Usage`-class).

---

## Q1 — Local event log

Confirmed real: `~/.copilot/session-state/<session-uuid>/events.jsonl` (override root via `COPILOT_HOME`). JSONL, 20+ event types (session lifecycle, tool execution, sub-agent activity, model changes). No official schema doc exists — [github/copilot-cli#3551](https://github.com/github/copilot-cli/issues/3551) (read 2026-09-15) is an **open** feature request asking GitHub to formalize it: *"external tools can watch this file and react to events without any plugin API"* but *"[w]ithout documentation or stability guarantees, these integrations are fragile."*

- Schema churn: [#3520](https://github.com/github/copilot-cli/issues/3520) reports CLI 1.0.54 dropped a previously-required `ephemeral` field, breaking a downstream consumer (read 2026-09-15).
- Corruption: [#2012](https://github.com/github/copilot-cli/issues/2012) — unescaped U+2028/U+2029 breaks `JSON.parse()` on resume (read 2026-09-15).
- Token usage: present **only as a per-session aggregate** on the `session.shutdown` event: `data.modelMetrics.<model>.{inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, reasoningTokens, requests.count}`, per [ccusage.com/guide/copilot](https://ccusage.com/guide/copilot/) (read 2026-09-15), itself labeled experimental/Beta. Model id is present (keyed by model string). Open requests for finer granularity: [#1394](https://github.com/github/copilot-cli/issues/1394), [#1152](https://github.com/github/copilot-cli/issues/1152).
- Two other usage surfaces exist: opt-in OpenTelemetry JSONL export (`${COPILOT_HOME}/otel/**/*.jsonl`, env `COPILOT_OTEL_FILE_EXPORTER_PATH`), per-span so closer to per-request but off by default; and `--usage-output-file` (added v1.0.81, 2026-08-27: "Add per-agent usage metrics to --usage-output-file JSON output"), whose schema is **not found as of 2026-09-15** anywhere, including the [CLI programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference) (read 2026-09-15).
- ACP (`Agent Client Protocol`) exposes live per-turn `usage_update` notifications since v1.0.78 (2026-08-03); schema not independently verified — flag for a follow-on spike if Mark 1 ever targets ACP clients directly.

## Q2 — Hooks / lifecycle extensibility

Real and GA. [docs.github.com/en/copilot/reference/hooks-reference](https://docs.github.com/en/copilot/reference/hooks-reference) (read 2026-09-15) lists: `sessionStart`, `sessionEnd`, `userPromptSubmitted`, `userPromptTransformed`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `preCompact`, `agentStop`, `subagentStart`, `subagentStop`, `errorOccurred`, `notification` (CLI-only), `permissionRequest` (CLI-only).

Config: repo-level `.github/hooks/NAME.json`; user-level `~/.copilot/hooks/` (`$COPILOT_HOME/hooks/`; Windows `%USERPROFILE%\.copilot\hooks\`) — [use-hooks](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks) (read 2026-09-15). Shape: `{"version":1,"hooks":{"hookName":[{"type":"command","bash":"...","cwd":".","timeoutSec":10,"env":{...}}]}}`. Default timeout 30 s.

Gating (hooks-reference, read 2026-09-15): exit 0 → stdout parsed as JSON; exit 2 → deny on `preToolUse`/`permissionRequest`; other non-zero → fail-open + logged error, **except `preToolUse`, which fails closed**; **timeout is always fail-open**, even for `preToolUse`. Outputs: `permissionDecision`, `decision:"block"|"allow"` (on `agentStop`/`subagentStop`), `additionalContext`, `modifiedArgs`/`modifiedResult`/`modifiedPrompt`. **No token-usage field anywhere in the hook schema** — consistent with `08-api-contracts.md` §5 rule 4.

Other surfaces confirmed (read 2026-09-15): MCP (built-in + custom servers), `.copilot/lsp-config.json`/`.github/lsp.json`, custom instructions (`AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/**.instructions.md`, also `CLAUDE.md`/`GEMINI.md`), custom agents/personas, "Agent Plugins 1.0" (GA ~August 2026), skills.

## Q3 — BYOK vs. subscription, ToS

Subscription model meters **premium requests**, one per prompt regardless of model. Local `/usage` slash command exists but is **documented unreliable**: [#1582](https://github.com/github/copilot-cli/issues/1582), open/unanswered — undercounts vs. the account-level quota, worse around context compaction (read 2026-09-15). Authoritative usage is github.com billing settings only.

BYOK is real, first-party: [use-byok-models](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models) and the [2026-01-15 BYOK changelog](https://github.blog/changelog/2026-01-15-github-copilot-bring-your-own-key-byok-enhancements/) (both read 2026-09-15). Providers: Anthropic, OpenAI, Azure/Foundry, Bedrock, Google AI Studio, xAI, OpenAI-compatible endpoints, Ollama, via `COPILOT_PROVIDER_TYPE` + config (`type`/`baseUrl`/`apiKey` from env). GitHub: *"Usage through BYOK is billed directly by your chosen provider and does not count against GitHub Copilot request quotas."* Same shape as the wire-proxy pattern already verified for other API-key-regime agents.

ToS: [github-copilot-product-specific-terms](https://github.com/customer-terms/github-copilot-product-specific-terms) (read 2026-09-15) has **no clause found** against local-log tailing or `/usage` reads — but it's marked deprecated 2026-03-05 in favor of "GitHub Generative AI Services Terms," **not fetched — not found as of 2026-09-15**. Reverse-engineered proxies (`copilot-api` etc.) are flagged elsewhere as unsupported/suspension risk for production use; passive local-file tailing makes no extra backend calls and is categorically different, but no GitHub-authored sentence confirms that. **Open item — needs a legal read before shipping.**

## Q4 — Version pinning and churn

Install via npm (`@github/copilot`, pin exact version), Homebrew, WinGet, or install script (`VERSION=`). GA 2026-02-25; **172 releases by 2026-09-04** (v1.0.83), roughly weekly. Churn directly relevant to this adapter within the trailing dozen releases: v1.0.79 breaking sandbox-key rename (`allowDevToolCaches`→`allowDevToolAccess`, old key silently ignored); v1.0.81 added OTel trace context to hook inputs + `--usage-output-file`; v1.0.82 removed the hooks enable/disable UI toggle "temporarily"; plus the `ephemeral`-field break (#3520) and JSONL corruption (#2012) above. **Materially higher churn than any other agent in the matrix** — the plan's default "re-run on major vendor releases" policy (§1.3) is insufficient; re-run the fixture every ~10 releases or on any changelog entry touching hooks/session-events/sandbox config (no real majors exist — breaks ship in patch versions).

## Q5 — Dedupe keys

**Not found as of 2026-09-15: an authoritative, GitHub-published dedupe key.** Field names assembled only from scattered issues (`id`, `type`, `timestamp`, `parentId`, `turnId`, `interactionId`, `messageId` — [github/copilot-sdk#1111](https://github.com/github/copilot-sdk/issues/1111), read 2026-09-15), not a spec. Worse: `session.shutdown`, the one event carrying usage, has **no per-request id at all** (a per-model rollup), so it can't support idempotent per-request upsert the way Claude Code's `(message.id, requestId)` pair does. The opt-in OTel export carries per-span ids usable as a dedupe key, but is off by default.

## What the adapter slot needs

- **Hooks:** viable now for capture (lifecycle/tool events) and stop/tool-style gating — closest of any unverified agent to Claude Code's shape. Field-map via `agent_maps` bundle data per the standing rule.
- **Transcript/events.jsonl tail:** viable only as DIAGNOSTIC-class, observe-only (session boundaries, coarse per-model totals) — **not** viable as the `Usage` source; no per-request id, unstable schema, admitted-unofficial by GitHub.
- **Wire proxy (BYOK only):** the correct billing-grade `Usage` path — same dialect-mapping as other API-key-regime agents, first-party-sanctioned, outside subscription metering entirely.
- **Artifact dirs / MCP / custom-instructions:** viable injection points (`.github/copilot-instructions.md`, MCP registration) for context/map delivery, same pattern as Claude Code's `CLAUDE.md`/MCP.

## Open risks

1. GitHub Generative AI Services Terms not yet read — ToS clearance for passive local tailing is unconfirmed.
2. `--usage-output-file` schema undocumented, too new (2026-08-27) to design against without its own micro-spike.
3. Weekly release cadence with observed breaking changes to this adapter's exact dependencies means Copilot's fixture-refresh cost is structurally higher than any Phase 1–4 agent — budget accordingly.
4. Subscription-regime usage (non-BYOK) has no billing-grade path today; without BYOK, Mark 1 can only report DIAGNOSTIC-class coarse totals, never a guarantee-grade TVO number for Copilot.
