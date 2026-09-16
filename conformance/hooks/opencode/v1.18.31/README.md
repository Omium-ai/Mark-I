# `opencode` plugin-hook + capture fixtures — pinned agent version **1.18.31**

The corpus that gates the opencode adapter slot (08 §5 rule 3: no fixture, no adapter; nothing is
authored from memory). Directory named per 12 §3.2 (`conformance/hooks/<agent>/<version>/`).
**Frozen** — a new opencode release gets a *new* version directory; these files are never edited.

## Provenance (what is vendor, what is synthesized)

Pin: npm `opencode-ai@1.18.31` = git tag `v1.18.31` = commit
`014614d35b397775e5d397a490fc72368c894ec2` (github.com/anomalyco/opencode, the version the spike
`docs/spikes/opencode-adapter.md` names), fetched 2026-09-16. MIT.

| Path | What it is | Source |
|---|---|---|
| `schema/plugin-index.ts` | The plugin API: `PluginInput` (`directory`, `worktree`, …), `Hooks` (`event`, `chat.message`, `tool.execute.before/after` argument shapes), `PluginModule` (`default export {id, server}`). **Verbatim vendor bytes.** | `packages/plugin/src/index.ts` at the pinned commit |
| `schema/v1-session.ts` | The V1 session/message/part schemas: `SessionInfo` (`directory`), `Assistant` (`path.cwd`, `providerID`/`modelID`, `cost`, `tokens`), `StepFinishPart` (`tokens{input,output,reasoning,cache{read,write}}`, `cost`), and the `session.created`/`message.updated`/`message.part.updated` event definitions. **Verbatim.** | `packages/schema/src/v1/session.ts` |
| `schema/session-status-event.ts` | `session.status` / `session.idle` (deprecated, still published — `session/status.ts`). **Verbatim.** | `packages/schema/src/session-status-event.ts` |
| `schema/identifier.ts` | The id format: `<prefix>_` + 12 hex time chars + 14 base62 chars (`ses_`, `msg_`, `prt_`). **Verbatim.** | `packages/schema/src/identifier.ts` |
| `schema/auth-index.ts` | `auth.json`'s credential shapes (`type: "oauth" \| "api" \| "wellknown"`) and its path (`Global.Path.data/auth.json`). **Verbatim.** | `packages/opencode/src/auth/index.ts` |
| `inputs/plugin-inputs.json` | Vendor-shaped arguments to the plugin hooks, two instances (one per project directory): `event` calls carry `{id, type, properties}` as `plugin/index.ts` builds them from the bus; trigger hooks carry `(input, output)`. Synthesized from the schemas above with synthetic identities. | `packages/opencode/src/plugin/index.ts`, `session/tools.ts`, `session/prompt.ts`, `session/processor.ts` |
| `hooks/<hook>.json` | The stdin body `mark1-hookshim` receives per registered hook — what `go/mark1d/adapters/opencode/mark1.js` composes from the inputs: `{hook_event_name, session_id, cwd, …vendor fields at top level}`. **Produced by running the real plugin** (`selfcheck.py` → `harness.mjs`), never typed. Per 08 §5 rule 4 **no hook body carries token usage**, and `tool.execute.after` drops `args`. | `mark1.js hook()` |
| `transcripts/capture/<sessionID>.jsonl` | The per-session usage stream `mark1.js record()` appends under the capture dir: assistant `message.updated` and `step-finish` `message.part.updated` events, verbatim `{type, properties}`. **Produced by running the real plugin.** | `mark1.js record()` |
| `transcripts/expectations.json` | Exactly which `Usage` events a correct tailer emits per stream: idem_key inputs, token numbers, model, plus the lines and streams that must never emit. | our reading of the vendor bytes, re-derived independently by `selfcheck.py` |
| `selfcheck.py`, `harness.mjs` | Fixture audit, not the tailer under test. `python3 selfcheck.py` (needs `node`), exit 0 = consistent: re-runs the plugin and diffs its output against `hooks/` and `transcripts/capture/` byte for byte. | — |

## Sanitization rule (normative)

Every identity is synthetic — placeholder user (`devuser`), workspace (`acme-app`),
`ses_0199a1b2c3d4SynthFixtu…` / `msg_…` / `prt_…` ids, `call_SynthFixture…` tool-call ids.
`selfcheck.py` greps every fixture byte for the recording machine's identities and fails red on a hit.

## Why the capture surface is ours, and what the vendor persists

The spike's central finding holds at the pin: plugins are in-process modules (`default export
{id, server}`, `plugin/index.ts readV1Plugin`), discovered from `{plugin,plugins}/*.{ts,js}` under
every config directory (`config/plugin.ts`, `Global.Path.config` = `$XDG_CONFIG_HOME/opencode`
first), and `mark1-hookshim`'s stdin transport does not transplant — so `mark1.js` is the transplant:
it execs the shim per lifecycle hook exactly as a Claude Code or Codex hook entry would.

Usage has no file to tail: durable events, sessions, messages and parts live in SQLite
(`core/src/event/sql.ts`, `session/sql.ts`); the `storage/` JSON tree the docs mention is the
pre-migration layout (`storage/storage.ts MIGRATIONS[0]` reads and retires it). No SQLite reader is
taken on; the plugin appends the two event kinds the tailer needs to a JSONL under the capture dir.

- `processor.ts` `step-finish`: `assistantMessage.tokens = usage.tokens` (the LAST step's count,
  overwritten per step) and `cost += usage.cost` (cumulative), then `updatePart({type:"step-finish",
  tokens, cost})` and `updateMessage(assistantMessage)`. So the per-LLM-call count is the
  **step-finish part**, keyed by its own `PartID` — which closes the spike's dedupe risk
  (`assistantMessageID` reused across steps).
- `session.ts getUsage`: `tokens.input` = provider input MINUS cache read and write;
  `tokens.output` = provider output MINUS reasoning. Mapped: `input_tokens = tokens.input`,
  `output_tokens = tokens.output + tokens.reasoning`, `cache_read = cache.read`,
  `cache_creation = cache.write`; `cost` is unmapped.
- `session.updateMessage` runs before any part of a new assistant message, so the head of every
  capture stream is a `message.updated` carrying `path.cwd` — the containment evidence — and
  `providerID`/`modelID`, the model.
- The plugin `event` hook only sees events whose `location.directory` is its instance directory
  (`plugin/index.ts events.listen`), so `cwd` on hook bodies is `PluginInput.directory`.

At the pin a bare `plugins/mark1.js` is its own entrypoint (`plugin/shared.ts
resolvePluginEntrypoint`: no `package.json` beside it → the file is the target; file plugins skip the
npm compatibility gate) and `readV1Plugin` takes the `default export {id, server}` shape.

Still owed by a LIVE session on a real `opencode 1.18.31` install: the plugin actually importing under
Bun with its `node:` builtins, the exact `message.updated` cadence during streaming, whether
`session.idle` keeps firing once `session.status` fully replaces it, and the mid-flight v1→v2 schema
migration's effect on `message.part.updated`.

## Recording-time facts pinned by these fixtures

- **Session identity**: opencode ids are `ses_<26>` strings; `m1p session_id =
  UUIDv5(NameSpaceURL, "opencode:" + sessionID)` — computed identically by `mark1.js sessionUUID`,
  `opencode.SessionUUID` (Go) and `selfcheck.py` (Python `uuid5`). Each opencode session, child
  sessions included, is its own m1p session.
- **Dedupe key** is `(StepFinishPart.messageID, StepFinishPart.id)` →
  `idem_key = HMAC_tenant(session_id, message_id := messageID, request_id := part id)`. The
  re-published `prt_…P002` counts once; `message.updated` lines never count.
- **Hooks** registered by the plugin: `session.created` (session_start), `chat.message`
  (turn_human), `tool.execute.before`/`after` (tool open/close, vendor `tool` + `callID`),
  `session.idle` (turn_agent). No SessionEnd exists on this surface; no stop-gate either —
  `session.idle` is an observation, not a decision point, and `tool.execute.before` gating (throw
  to block) is not wired. `MARK1_AGENT=opencode` rides the shim's environment from the plugin.
- **Regime**: the provider is `opencode.json`'s `model` ("provider/model"), else the newest
  `recent` entry of `$XDG_STATE_HOME/opencode/model.json` (`provider.ts defaultModel`); its
  `auth.json` entry `type: "api"` or `provider.<id>.options.apiKey` is the API-key regime; oauth,
  wellknown, env-supplied keys (a models.dev lookup) and an unresolvable provider are subscription.
  Anthropic OAuth is gone from this version (removed in 1.3.0), so the CON-001 surface here is other
  providers' OAuth (`plugin/openai/codex`, `github-copilot`, gitlab, poe).
- **Kill switch**: `mark1.js` checks `MARK1_DISABLE=1` and the `~/.omium/mark1/OFF` marker before
  every exec and every append (08 §7.6).
