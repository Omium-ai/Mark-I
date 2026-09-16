# `cursor` hook fixtures — pinned CLI build **2026.09.10-fd3934a** (IDE 3.20.21)

The corpus that gates the cursor observe/gate slot (08 §5 rule 3: no fixture, no adapter; nothing is
authored from memory). Directory named per 12 §3.2 (`conformance/hooks/<agent>/<version>/`), keyed
by the CLI build because the CLI (`cursor-agent`) is the surface the spike names as the enterprise
target and the one whose hook-payload builders are readable. **Frozen** — a new build gets a *new*
version directory; these files are never edited.

TRANSCRIBED (not recorded) on 2026-09-16 from the vendor bundles: Cursor is closed source and the
client talks only to Cursor's backend (no BYOK/offline path exists, `docs/spikes/cursor-observe-gate.md`
§Q3), so a session cannot be driven without an account and network. Every hook body below is composed
field-for-field from the CLI's own payload builder at this build; **no live session confirms them**,
on either surface — that is the spike's standing condition and this corpus's residual.

## Provenance (what is vendor, what is composed)

| Pin | Artifact |
|---|---|
| CLI | `cursor-agent 2026.09.10-fd3934a`, `https://downloads.cursor.com/lab/2026.09.10-fd3934a/linux/x64/agent-cli-package.tar.gz` (sha256 `27997c8391ad853a5a732b1845db8ef82a8ba6afb0f7829cc739464f8966e96e`; `index.js` `3f26b0fe…6a80`, `190.index.js` `07d06c80…0715`) |
| IDE | Cursor 3.20.21, commit `f09fca384ceca23f7bf21f9c23655b162641d740` (2026-09-13), `extensions/cursor-agent-exec/dist/main.js` sha256 `7a62b0b8…4e2a` |
| Docs | `https://cursor.com/docs/hooks.md` fetched 2026-09-16, sha256 `7294a2d6…5d39` |

| Path | What it is | Source |
|---|---|---|
| `schema/hooks-module.js` | The vendor's hooks module, pretty-printed (prettier 3, no semantic change): the event vocabulary `r`, the Claude-Code → Cursor event table `s` (`Stop→stop`, `PreToolUse→preToolUse`, `UserPromptSubmit→beforeSubmitPrompt`, …), the tool-name table, the per-event output validators `Q`, the response merge `O`, and `z()` — the normalizer that turns `{decision:"block",reason}` into `followup_message`. | `index.js` module `../hooks/dist/index.js` |
| `schema/cli-hook-dispatch.js` | The agent-runtime hook request switch: the **ten** steps the CLI dispatches at this build and the exact snake_case object each builds (`stop` carries `status`, `loop_count` and four token fields when the runtime sets them; `postToolUse`/`postToolUseFailure` render `duration`, not `duration_ms`). | `index.js` |
| `schema/cli-hook-runner.js` | `executeHookForStep`: adds `session_id` (`session_id ?? conversation_id`), `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`, `transcript_path`; config sources (`/etc/cursor/hooks.json`, `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json`, team, plus `~/.claude/settings.json` and `.claude/settings*.json`) and their run order. | `190.index.js` |
| `schema/hooks_pb.fields.json` | The `agent.v1.*RequestQuery` proto field lists as registered in the IDE build — the runtime side of the same contract. | IDE `cursor-agent-exec` bundle |
| `schema/hooks-docs-reference.md` | Verbatim slice (Configuration → Reference) of the vendor docs: the `hooks.json` format, per-script options, matcher rules, and the per-event input/output shapes including the two IDE-only events. | cursor.com/docs |
| `hooks/<event>.json` | One composed stdin body per registered event: the dispatch switch's object + the runner's base fields (CLI-dispatched events), or the docs' input + base fields (`sessionStart`, `sessionEnd`). | composed, checked by `selfcheck.py` against the vendor lists |
| `expectations.json` | Registrations, the gate contract, the NO-GO clauses, and the pins. | — |
| `selfcheck.py` | Fixture audit. `python3 selfcheck.py`, exit 0 = consistent. | — |

## Sanitization rule (normative)

Synthetic identities only — workspace `/home/devuser/acme-app`, conversation `cc0e0000-…aa01`,
generation `…aa02`, `call_SynthFixture…` tool ids, `user_email: null`. `selfcheck.py` greps every
fixture byte for the recording machine's identities and fails red on a hit.

## Facts pinned by these fixtures

- **Config**: `~/.cursor/hooks.json` `{"version":1,"hooks":{"<event>":[{"command":…,"timeout":s,"loop_limit":n|null,"failClosed":bool,"matcher":re}]}}`
  — flat entries, no matcher groups. The validator rejects an **unknown event name** for the whole file
  and checks only the known keys on an entry, so a `"_mark1":"v1"` tag on our entries is tolerated.
  JSONC comments are stripped before parsing. Commands run through the shell with the payload on stdin
  (`<<'CURSOR_HOOK_EOF'` heredoc or a direct stdin pipe), default timeout 60 s, `failClosed` default
  false; exit 2 = deny where a permission applies.
- **The CLI runs Claude Code's hooks too**: `~/.claude/settings.json` (and the project `.claude/settings*.json`)
  are loaded, translated through table `s`, and executed — so a machine with the claudecode fragment
  provisioned already spawns the shim from Cursor with `MARK1_AGENT` unset; the claudecode map then sees
  `hook_event_name:"stop"` (Cursor's spelling), matches nothing, and emits nothing. Cursor dedupes a
  Claude-sourced entry against a Cursor-sourced one only when the command strings are identical.
- **Ten steps dispatched by the CLI at this build**: `preCompact`, `subagentStart`, `subagentStop`,
  `beforeSubmitPrompt`, `afterAgentResponse`, `afterAgentThought`, `stop`, `preToolUse`, `postToolUse`,
  `postToolUseFailure`. `sessionStart`/`sessionEnd`/`beforeShellExecution`/`afterShellExecution`/
  `beforeReadFile`/`afterFileEdit`/`before|afterMCPExecution`/`workspaceOpen` have **no** dispatch in
  the CLI bundle and no `agent.v1` query message: IDE-only here. The forum-reported "CLI discards
  `stop`" gap is therefore not what the bundle shows — `stop` is wired — but wired is not fired:
  unconfirmed live.
- **Stop gate**: `stop` input is `{status, loop_count, …}` with **no `stop_hook_active`**; the vendor's
  per-script `loop_limit` (default 5) makes the runner skip the hook once `loop_count` reaches it, so the
  runaway cap is vendor-side. Output: the shim's Claude-shaped `{"decision":"block","reason":R}` is
  accepted verbatim — `z()` sets `followup_message = R.trim()` for `stop` and `subagentStop` on every
  command hook, not only Claude-sourced ones — and Cursor auto-submits R as the next user message.
- **Tool ids exist**: `preToolUse`/`postToolUse`/`postToolUseFailure` carry `tool_use_id` (unlike
  Copilot and Gemini at their pins); `tool_name` is Cursor's vocabulary (`Shell`, `Read`, `Write`, `Grep`,
  `Delete`, `Task`, `MCP:<tool>`).
- **Token fields on hooks**: `stop` and `afterAgentResponse` builders render `input_tokens`/`output_tokens`/
  `cache_read_tokens`/`cache_write_tokens` **only when the runtime sets them**; the fixture bodies omit
  them and the map never reads them — DIAGNOSTIC-at-best, unconfirmed live, never a `Usage`
  (08 §5 rule 4 stands for Mark 1's purposes).
- **Ids are UUIDs**: the CLI mints `agentId: crypto.randomUUID()` (the conversation id) and
  `generationUUID ?? crypto.randomUUID()`; `session_id` is the conversation id unless the payload carries
  its own — the shim's `session_id_field` parses either.
- **NO-GO, permanent**: wire proxy and model rewrite — every request, BYOK or not, transits Cursor's
  backend where the final prompt is built; no customer-machine vantage sees the provider hop. The adapter
  reports the subscription regime unconditionally and refuses the wire path with `M1E-7105`.

## Still owed by a LIVE session

One `cursor-agent` and one IDE Agent-Chat session with these hooks registered: that the ten CLI steps
fire with these shapes, that `sessionStart`/`sessionEnd` fire in the IDE as the docs describe, whether
the token fields populate, and the `cursor_version` string each surface stamps.
