# `copilot` hook + `events.jsonl` fixtures — pinned agent version **1.0.85**

The corpus that gates the copilot adapter slot (08 §5 rule 3: no fixture, no adapter; nothing is
authored from memory). Directory named per 12 §3.2 (`conformance/hooks/<agent>/<version>/`).
**Frozen** — a new Copilot CLI release gets a *new* version directory; these files are never edited.

RECORDED (not transcribed) on 2026-09-16 from the vendor binary running **offline in BYOK mode**
against a fake OpenAI-compatible provider on loopback (`COPILOT_OFFLINE=true`,
`COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:<port>/v1`, `COPILOT_PROVIDER_API_KEY=<synthetic>`), so no
GitHub account, network, or real model was involved: every `hooks/*.json` is the exact stdin body the
CLI sent to a capture script registered through a `$COPILOT_HOME/hooks/*.json` file, and every
`transcripts/session-state/<uuid>/events.jsonl` is the on-disk file the session wrote.

## Provenance (what is vendor, what is recorded)

Pin: npm `@github/copilot@1.0.85` (loader tarball sha256
`d26e3c15310bdcdcc910ed223285bed8d68aaebce0d344f97224b5cfdaeeee36`) whose platform package
`@github/copilot-linux-x64@1.0.85` (tarball sha256
`4a0081b1b615639c8101ccd39c71bbef4f194e86a1be81fd03962a59daae1026`, `buildMetadata.gitCommit`
`4848e944`) is a Node SEA embedding `copilot.tgz`; the CLI is closed source (github/copilot-cli holds
issues and releases only), so "source" here is the shipped bundle. Docs pinned at github/docs
`b87a8cfb5931ae735ff4dc3d936ccbc2a4c0b1e7` (`content/copilot/reference/hooks-reference.md`, 2026-09-01)
and `1765b5624b3ec9a2841b385345757140cd29eb7c` (`use-byok-models.md`, 2026-09-14). Spike:
`docs/spikes/copilot-events-jsonl-usage.md`.

| Path | What it is | Source |
|---|---|---|
| `schema/session-events.subset.schema.json` | The vendor's JSON Schema for `events.jsonl` lines, **verbatim definitions** for the fifteen types the reader and this README cite (`StartEvent`/`StartData`/`WorkingDirectoryContext`, `ShutdownEvent`/`ShutdownData`/`ShutdownModelMetric*`, `AssistantUsageEvent`/`AssistantUsageData`, `HookStart*`/`HookEnd*`). The full file is 856 KB, sha256 `20e13b3f689f554814142d3467fa1dd68469ddf16533954bd29ff89cbd8e805d`. | `schemas/session-events.schema.json` inside the pinned bundle |
| `schema/hooks-types.d.ts` | The SDK's hook input/output typings, `BaseHookInput` through `SessionHooks`, **verbatim slice** of `copilot-sdk/types.d.ts` (sha256 `2911ecb4aac830b7c129f2accf01086ae47a5250700dc050e95dfa33def862c4`). These are the camelCase callback shapes; the PascalCase stdin bodies below are their snake_case rendering per the docs. | pinned bundle |
| `hooks/<Event>.json` | The stdin body of each registered event, recorded. | live CLI run, sanitized |
| `transcripts/session-state/<sid>/events.jsonl` | Three recorded session logs: `aa01` (bash tool call + reply), `aa02` (failing `view` → `PostToolUseFailure`), `ff01` (a foreign workspace whose `Stop` was answered with `decision:"block"` once — it carries the `stop_hook_active:true` re-entry). | live CLI runs, sanitized |
| `transcripts/expectations.json` | Exactly which DIAGNOSTIC events a correct reader emits per stream, and that it emits **zero Usage**. | our reading of the vendor schema + recordings, re-derived independently by `selfcheck.py` |
| `selfcheck.py` | Fixture audit, not the reader under test. `python3 selfcheck.py`, exit 0 = consistent. | — |

## Sanitization rule (normative)

Recording-machine paths → `/home/devuser/acme-app` (workspace), `/home/devuser/other-app` (foreign),
`/home/devuser/.copilot` (`$COPILOT_HOME`); the capture script path → the shim path; every UUID → a
stable synthetic `c0910000-…` id (session ids `…aa01`/`…aa02`/`…ff01`); `system.message` lines (the
vendor's system prompt, which embeds the environment) are dropped, every other line is kept
byte-for-byte after substitution. `selfcheck.py` greps every fixture byte for the recording machine's
identities and fails red on a hit.

## Recording-time facts pinned by these fixtures

- **Hook config format**: `{"version":1,"hooks":{"<Event>":[{"type":"command","bash":"…","env":{…},"timeoutSec":N}]}}`
  in `$COPILOT_HOME/hooks/<name>.json` (`~/.copilot/hooks/` by default) — a directory of files, so the
  adapter owns `mark1.json` outright (08 §8 mechanism A). **PascalCase event names select the
  Claude-compatible payload** (`hook_event_name`, `session_id`, ISO `timestamp`, `cwd`), which is what
  the shim's maps key on; camelCase names deliver `sessionId`/epoch-ms with **no event-name field**, so
  they are unusable by a stateless per-exec shim. `session_id` is a UUID (`--session-id` "set the UUID for
  a new session"; the runtime resolves "a UUID prefix to a unique session ID").
- **Events that fired** in `-p` mode: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
  `PostToolUseFailure`, `Stop`, `SessionEnd`. Order quirk: `UserPromptSubmit` fired **before**
  `SessionStart` (24.546 Z vs 24.562 Z). `SubagentStop`, `PreCompact`, `ErrorOccurred` were registered
  and never fired; they are not in the corpus and the adapter does not register them.
- **Stop gate**: `Stop` carries `stop_hook_active`; answering `{"decision":"block","reason":R}` enqueued R
  as the next `UserPromptSubmit` and re-fired `Stop` with `stop_hook_active:true` (stream `ff01`, the
  `hook.start` lines carry both inputs). Vendor runaway cap: 8 consecutive blocks.
- **`SessionEnd` fires per completion, not per process**: in stream `ff01` it fired after the first
  `Stop` (before the block-forced continuation) and again at the true end, both `reason:"complete"`.
- **`PreToolUse` command hooks fail CLOSED**: with the hook command pointing at a missing binary the CLI
  denied the tool call ("Denied by preToolUse hook … (hook errored)"); the same entry with `|| true`
  appended let it run. Timeouts are fail-open (docs). The adapter therefore writes `bash: "<shim> || true"`
  so a missing or unexecutable shim can never block a developer (08 §5 rule 5).
- **`tool_name` is the Claude name** under PascalCase (`Bash`, `Read`); **no tool-call id** on
  `PreToolUse`/`PostToolUse`/`PostToolUseFailure` at this version (`tool_use_id` empty, never guessed).
  `PostToolUseFailure` fired only for a real tool failure (`Path does not exist`); a permission-denied
  tool fired neither `PostToolUse` nor `PostToolUseFailure`.
- **`events.jsonl`**: `$COPILOT_HOME/session-state/<session-uuid>/events.jsonl`, one
  `{type,data,id,timestamp,parentId}` per line. `session.start.data.context.cwd` is the containment
  evidence; `session.shutdown.data.{shutdownType,sessionStartTime,modelMetrics}` closes the session.
  **Per-request usage is never persisted**: `assistant.usage` is `ephemeral: true` (a schema `const`)
  and no such line exists in any recording; the only token numbers on disk are the per-session,
  per-model rollup on `session.shutdown`, which has no per-request id and can never satisfy the
  `idem_key` invariant (08 §2) — DIAGNOSTIC class, never `Usage`. `assistant.message` lines carry
  `apiCallId` and `model` but no counts. `hook.start.data.input` keeps the camelCase form of each hook
  input regardless of the configured format.
- **BYOK wire**: with `COPILOT_PROVIDER_BASE_URL` set the CLI POSTs `<base>/chat/completions`
  (`stream:true`, OpenAI chat dialect, user-agent `OpenAI/JS 5.20.1`) with
  `Authorization: Bearer $COPILOT_PROVIDER_API_KEY` — the same wire the gateway's OpenAI-chat dialect
  already carries. BYOK is activated by `COPILOT_PROVIDER_BASE_URL` alone ("GitHub authentication is not
  required"); `COPILOT_PROVIDER_API_KEY_COMMAND` and `COPILOT_PROVIDER_BEARER_TOKEN` take precedence over
  the key, and `$COPILOT_PROVIDERS_CONFIG` / `$COPILOT_HOME/providers.json` (`{"providers":[…],"models":[…]}`)
  takes precedence over every `COPILOT_PROVIDER_*` variable (bundle `e0t`: config wins when either array
  is non-empty). `COPILOT_PROVIDER_GHES_HOST` is GitHub-billed, not BYOK.

## Still owed by a LIVE recording on a real GitHub-billed install

Whether `events.jsonl` and the hook bodies are byte-identical under a GitHub-authenticated
(subscription) session — this corpus was recorded BYOK-offline, the only mode that needs no account;
whether `SubagentStop`/`PreCompact`/`ErrorOccurred` bodies match the docs; the `providers.json`
entry schema (read only from bundle strings: `type`, `baseUrl`, `apiKey`, `bearerToken`,
`apiKeyCommand`); Windows (`powershell`) command handling.
