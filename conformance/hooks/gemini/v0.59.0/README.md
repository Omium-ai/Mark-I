# `gemini` hook + chat-recording fixtures — pinned agent version **0.59.0**

The corpus that gates the gemini adapter slot (08 §5 rule 3: no fixture, no adapter; nothing is
authored from memory). Directory named per 12 §3.2 (`conformance/hooks/<agent>/<version>/`).
**Frozen** — a new Gemini CLI release gets a *new* version directory; these files are never edited.

## Provenance (what is vendor, what is synthesized)

Pin: npm `@google/gemini-cli@0.59.0` = git tag `v0.59.0` = commit
`fb0d535af931b27c51e87e5e6ade72905b1e8390` (github.com/google-gemini/gemini-cli, the stable the spike
`docs/spikes/gemini-cli-beforemodel-oauth.md` names), fetched 2026-09-16. Apache-2.0.

| Path | What it is | Source |
|---|---|---|
| `schema/hooks-types.ts` | The vendor's hook input/output types: `HookEventName` (11 events), `HookInput` (base stdin), one `<Event>Input` per event, the `SessionStartSource`/`SessionEndReason`/`PreCompressTrigger` enums, `CommandHookConfig` (`timeout` in ms, `env`). **Verbatim vendor bytes.** | `packages/core/src/hooks/types.ts` at the pinned commit |
| `schema/chatRecordingTypes.ts` | The on-disk chat-recording types: `ConversationRecord` (metadata head), `MessageRecord`, `TokensSummary` (`input/output/cached/thoughts/tool/total`, each annotated with the `usageMetadata` field it copies). **Verbatim vendor bytes.** | `packages/core/src/services/chatRecordingTypes.ts` |
| `hooks/<HookEventName>.json` | The stdin body `mark1-hookshim` receives per registered event: `HookInput` (`hookEventHandler.ts createBaseInput`) plus that event's own fields, with synthetic identities and enum values verbatim. `selfcheck.py` checks every field against the `<Event>Input` interface in `schema/hooks-types.ts` and every enum value against its enum. Per 08 §5 rule 4 **no hook body carries token usage.** | `packages/core/src/hooks/{types,hookEventHandler}.ts` |
| `transcripts/tmp/<slug>/.project_root` | The ownership marker `projectRegistry.ts` writes beside every project's temp dir: the project root, verbatim. Containment evidence for the whole slug. | `packages/core/src/config/projectRegistry.ts` (`ensureOwnershipMarkers`) |
| `transcripts/tmp/<slug>/chats/session-<YYYY-MM-DDTHH-MM>-<sessionId[:8]>.jsonl` | Main-agent chat recordings in the real layout (`chatRecordingService.ts initialize`), one JSON record per line (`appendRecord`): the metadata head `{sessionId, projectHash, startTime, lastUpdated}`, `MessageRecord`s, `{$set: …}` updates. Synthesized from the vendor types and write paths, not recorded from a live install — see "persistence" below. | `packages/core/src/services/chatRecordingService.ts`, `chatRecordingTypes.ts`, `packages/core/src/config/storage.ts` |
| `transcripts/tmp/<slug>/chats/<parentSessionId>/<agentId>.jsonl` | A subagent recording (`kind: "subagent"`, nested under the parent session id, `directories` stamped). | same |
| `transcripts/expectations.json` | Exactly which `Usage` events a correct tailer emits per stream: idem_key inputs, token numbers, model, plus the streams and lines that must never emit. | our reading of the vendor bytes, re-derived independently by `selfcheck.py` |
| `selfcheck.py` | Fixture audit, not the tailer under test. `python3 selfcheck.py`, exit 0 = consistent. | — |

## Sanitization rule (normative)

Every identity is synthetic — placeholder user (`devuser`), workspace (`acme-app`), `6f1e2d3c-…`
session ids, `7a1c0001-…` message ids, `call_SynthFixture…` tool-call ids. `selfcheck.py` greps every
fixture byte for the recording machine's identities and fails red on a hit.

## Persistence: what the vendor source says, what a live recording still owes

The spike read the docs and concluded the full token breakdown lives only in the local telemetry
outfile. At the pinned commit the source says otherwise, and it changes the Usage source:

- `chatRecordingService.ts::recordMessageTokens` copies the response's `usageMetadata` —
  `promptTokenCount`, `candidatesTokenCount`, `cachedContentTokenCount`, `thoughtsTokenCount`,
  `toolUsePromptTokenCount`, `totalTokenCount` — onto the `gemini` `MessageRecord` as `tokens`, and
  `geminiChat.ts` calls it on every successfully completed stream **before** `recordMessage` writes the
  response line, so the line carries `tokens` (and `model`) from its first append. Recording is on by
  default and independent of auth mode.
- The telemetry outfile (`telemetry.target: "local"`) is **not** JSONL: `file-exporters.ts` writes each
  OpenTelemetry `ReadableLogRecord` as `safeJsonStringify(record, 2) + "\n"` — pretty-printed,
  multi-line objects — and is off by default. It is not a Usage source here.
- `recordToolCalls` re-appends the whole `gemini` message (same `id`) when tool calls attach; the
  parent fixture carries that duplicate and it counts zero times. A `gemini` message created by
  `recordToolCalls` *before* its tokens arrived (the `queuedTokens` path) is appended once without
  `tokens` and again with them; the subagent fixture carries that pair and it counts once.

Still owed by a LIVE recording on a real `gemini 0.59.0` install: whether `totalTokenCount` (and the
breakdown) is populated for Code Assist–routed (`oauth-personal`) responses, the exact `thoughts`/
`toolCalls` noise a real turn writes, the hook `session_id` ↔ transcript `sessionId` correspondence on
`--resume`, and the `SessionEnd` firing order at exit.

## Recording-time facts pinned by these fixtures

- **Dedupe key** is `(MessageRecord.id, "chat:" + sessionId)` → `idem_key = HMAC_tenant(session_id,
  message_id, request_id)` with `session_id` := the PARENT stream's `sessionId` (a subagent under
  `chats/<parent>/` is tailed under the parent, as Claude Code's are), `message_id` := the message's
  `randomUUID()` id, `request_id` := `chat:<the stream's own sessionId>` — this surface carries no
  per-request id, so the codex exec-stream precedent applies.
- **Containment**: `~/.gemini/tmp/` is ONE tree for every project. A slug is admitted only when its
  `.project_root` is the enabled root; a stream inside it is admitted only when its metadata
  `projectHash` equals `sha256(.project_root)` (`utils/paths.ts getProjectHash` over
  `config.getProjectRoot()`, the same `path.resolve`d string the marker holds). The `other-app` slug is
  never offered; the mis-hashed stream inside `acme-app` is never attributed.
- **Field semantics**: `tokens.input` is `promptTokenCount`, which INCLUDES cached tokens (mapped
  verbatim, OpenAI-style); `tokens.output` EXCLUDES `thoughts`, so `output_tokens = output + thoughts`;
  no cache-write count exists on this surface (`cache_creation_input_tokens = 0`); `tokens.tool` and
  `tokens.total` are unmapped.
- **Hooks**: `hook_event_name` and `session_id` (`config.getSessionId()`, a `randomUUID`) on every
  body; `transcript_path` is the recording file; `AfterAgent` carries `stop_hook_active` and
  `decision:"block"` + `reason` continues the turn with it set (`core/client.ts`), so it is the
  stop-gate; `BeforeTool`/`AfterTool` carry `tool_name` but **no tool-call id** at this version;
  `AfterTool` has no failure marker; hook `timeout` is milliseconds; `CommandHookConfig.env` is merged
  into the handler's environment (`hookRunner.ts`), which is how `MARK1_AGENT=gemini` travels.
- **Regime**: `security.auth.selectedType` in `~/.gemini/settings.json` wins, else
  `getAuthTypeFromEnv()` (`GOOGLE_GENAI_USE_GCA`, `GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_GEMINI_BASE_URL`,
  `GEMINI_API_KEY`, Cloud Shell/ADC in that order); `enforcedType` must agree or the CLI refuses to
  run. Only `gemini-api-key` is the API-key regime.
- `BeforeModel`/`AfterModel`/`BeforeToolSelection`/`Notification` are real and not registered:
  `AfterModel` fires per streamed chunk with `usageMetadata.totalTokenCount` only.
