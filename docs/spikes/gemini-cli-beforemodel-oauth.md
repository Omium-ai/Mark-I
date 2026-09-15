# Spike: Gemini CLI `BeforeModel` in OAuth mode

**Read against:** `docs/08-api-contracts.md` §5.3 (gemini adapter, `UNVERIFIED — spike gates this adapter slot`), `docs/03-hld.md` §6 (per-agent capability matrix, Gemini CLI row — all six cells `unverified`). All sources below read 2026-09-15.

## Verdict: GO, with a two-source capture design — not hooks alone

`BeforeModel`/`AfterModel` are real, documented, default-on hook events that fire at the CLI's internal turn loop, independent of which backend (Code Assist/OAuth vs. public API/key) ultimately serves the request — no vendor doc or issue found scoping either event to one auth mode. `BeforeModel` is a viable, and better-than-Claude's, injection point: it can mutate the actual request object (`hookSpecificOutput.llm_request`), not just append a context string. But `AfterModel`'s `usageMetadata` is a deliberately reduced projection carrying only `totalTokenCount` — none of `promptTokenCount`/`candidatesTokenCount`/`cachedContentTokenCount`/`thoughtsTokenCount`. The full breakdown exists only in the CLI's local OpenTelemetry log (`target: "local"`, an `outfile` on disk — no collector, no network hop), which we may tail exactly as we tail Claude Code's transcript. **Recommendation: proceed to build with hooks (injection) + local telemetry-log tail (usage) as the two capture surfaces; do not gate the whole adapter slot on hooks alone.** One live-session fixture is still needed before `agent_maps` is frozen (see Open risks).

## 1. Hook system

Eleven events: `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`, `AfterTool`, `PreCompress`, `Notification`. Source: `docs/hooks/index.md` and `docs/hooks/reference.md`, github.com/google-gemini/gemini-cli (raw, main branch).

Base stdin (every event): `{ session_id, transcript_path, cwd, hook_event_name, timestamp }`.

`BeforeModel` stdin adds `llm_request: { model, messages: [{role, content}], config: {temperature,...}, toolConfig }`. Output: `hookSpecificOutput.llm_request` (override request fields), `hookSpecificOutput.llm_response` (synthetic response — skips the LLM call entirely), `decision: "deny"` blocks the turn.

`AfterModel` stdin adds `llm_request` plus:
```
"llm_response": {
  "candidates": [{ "content": {"role":"model","parts":string[]}, "finishReason": string }],
  "usageMetadata": { "totalTokenCount": number }
}
```
— quoted verbatim from the "Stable Model API" section of `reference.md`. Fires **once per streamed chunk**, not once per turn. Output: `hookSpecificOutput.llm_response` (replace chunk), `decision:"deny"`, `continue:false`.

Exit codes (both events, and globally): `0` = success, stdout parsed as JSON, "preferred for all logic including intentional blocks"; `2` = System Block, stderr becomes the rejection reason; any other code = non-fatal warning, original params used. Stdout must be pure JSON — any stray text degrades to an allow + `systemMessage`.

Config: `settings.json` → `hooks` object, keyed by event name, each entry `{matcher, sequential, hooks:[{type:"command", command, name, timeout(default 60000ms), description}]}`. Precedence: `.gemini/settings.json` (project) > `~/.gemini/settings.json` (user) > `/etc/gemini-cli/settings.json` (system) > extension-defined hooks.

**Version/stability:** Google's own announcement states hooks are "enabled by default in Gemini CLI as of v0.26.0+" (developers.googleblog.com/tailor-gemini-cli-to-your-workflow-with-hooks, dated 2026-01-28). Feature tracked from issue #9070 "Comprehensive Hooking System" (opened 2025-09-22, closed, 34/34 sub-issues). **No "experimental" or "stable" label appears anywhere in current docs** — but the surface is still being patched: v0.35.0 shipped "fix(hooks): fix BeforeAgent/AfterAgent inconsistencies" and v0.38.0 shipped "fix(core): propagate BeforeModel hook model override end-to-end" (release changelogs, github.com/google-gemini/gemini-cli/releases). Latest stable as of read date: v0.59.0 (released 2026-09-08).

## 2. Token usage: hooks vs. local telemetry

Hook payload: only `usageMetadata.totalTokenCount`, confirmed by the schema quote above — not found: prompt/candidates/cached/thoughts breakdown in any hook payload.

Full breakdown **is** available, but only via the CLI's local telemetry file, not hooks. `docs/cli/telemetry.md` (github.com/google-gemini/gemini-cli): `.gemini/settings.json` → `{"telemetry":{"enabled":true, "target":"local", "outfile":".gemini/telemetry.log"}}` (`enabled` default `false`, `target` default `"local"`). This writes OpenTelemetry-shaped log/metric/trace records to a plain file — no collector process, no network egress required, so it is safe to tail under the "read local files, never run OTel ourselves" rule. The `gemini_cli.api_response` log record carries: `model`, `status_code`, `duration_ms`, `input_token_count`, `output_token_count`, `cached_content_token_count`, `thoughts_token_count`, `tool_token_count`, `total_token_count`, `prompt_id`, `auth_type`, `finish_reasons`. This is the direct analogue of Claude Code's transcript-tail `message.usage` block.

## 3. OAuth vs. API key

Default auth is `oauth-personal`; other values seen: `oauth`, `api-key`, `gemini-api-key`, `vertex-ai`, `google-auth-library` (ai-sdk.dev community-provider docs; geminicli.com/docs/get-started/authentication). Every `gemini_cli.api_response`/`gemini_cli.config` log record carries `auth_type`, so a telemetry-log tailer can self-classify regime without touching the network.

OAuth requests route through Code Assist at `https://cloudcode-pa.googleapis.com`, a different base URL from the public `generativelanguage.googleapis.com` (docs.cloud.google.com/gemini/docs/codeassist/gemini-cli). Confirmed structural enforcement of the no-proxy rule: GitHub issue #15430, "CLI ignores GOOGLE_GEMINI_BASE_URL and forces Cloud Auth/Endpoints" — once an OAuth/Cloud session is cached, the base-URL override is **not honored**; the vendor itself forecloses the interception path we must never take. In the API-key regime, `GEMINI_API_KEY` is the standard credential and `GOOGLE_GEMINI_BASE_URL` (implemented per PR #6380, "Support configuring Gemini API base URL via environment variable") does override the endpoint — this is the only regime a `mark1-proxy` could ever attach to, consistent with the plan.

ToS: Gemini Code Assist for individuals' terms prohibit "directly accessing the services powering Gemini Code Assist using third-party software, tools, or services" and "3rd party tools or proxies to access resources and quotas" (developers.google.com/gemini-code-assist ToS/privacy pages). This targets wire-level interception, not local reads of files the CLI itself writes (hook stdin, transcripts, telemetry log) — the same posture already taken for Claude Code's transcript tailer (08 §5.1).

## 4. Session transcripts on disk

`~/.gemini/tmp/<project_hash>/chats/session-<timestamp>-<id>.jsonl`, one file per session; checkpoints live in a sibling `checkpoints/` dir backed by a shadow git repo (GitHub issue #15292, discussion #4974). Every hook stdin payload also carries `transcript_path` directly (base input schema), mirroring Claude Code's delivery pattern. **Not found as of 2026-09-15:** whether transcript JSONL lines, or the `AfterModel` payload, carry a `message.id`/`requestId`-equivalent pair usable for our `(message.id, requestId)` idem_key construction — this needs the live fixture, not doc research.

## 5. Version churn

Hooks default-on since v0.26.0 (~2026-01-28) to current stable v0.59.0 (2026-09-08): roughly 33 minor versions in ~7.5 months, near-weekly cadence, with hook-specific bugfixes in at least two of the last ten releases. Pin the exact version for the conformance fixture, same discipline as the Claude Code adapter.

## What the adapter slot needs

- **Injection** — `BeforeModel` (`hookSpecificOutput.llm_request`), viable in both regimes; strictly more powerful than Claude's `additionalContext` string since it can mutate the request object directly.
- **Coarse usage** — `AfterModel.llm_response.usageMetadata.totalTokenCount`, per streamed chunk; dedupe strategy unverified (open risk).
- **Full usage** — local telemetry-log tail (`gemini_cli.api_response`), same shape as Claude's transcript tail; requires `telemetry.enabled=true` to be provisioned into the user's settings (it is off by default).
- **Transcript tail** — viable as a secondary source; stable dedupe id not yet confirmed.
- **Proxy** — never viable for OAuth (vendor-enforced), viable only under `GEMINI_API_KEY` + `GOOGLE_GEMINI_BASE_URL`, matching every other adapter's regime split.

## Open risks

1. `BeforeModel`/`AfterModel` firing under a live `oauth-personal` session, and whether `totalTokenCount` is populated (vs. 0/absent) specifically for Code Assist-routed responses, is inferred from doc architecture, not captured — the actual go/no-go fixture must run one real OAuth session.
2. No stable per-request dedupe key found in hook or transcript schemas (§4) — required before `idem_key` can be defined for this adapter.
3. `tools.enableHooks` as the master kill-switch key came from a secondary source; the primary `docs/get-started/configuration.md` 404'd on direct fetch today and needs re-verification.
4. Streaming `AfterModel` fires per-chunk with cumulative-vs-per-chunk `totalTokenCount` semantics unconfirmed — a Claude-style ~2.5× overcount risk exists here too if the wrong reduction is chosen.
5. Hook output size/character caps (Claude Code has one) not checked in this pass — not found as of 2026-09-15.
