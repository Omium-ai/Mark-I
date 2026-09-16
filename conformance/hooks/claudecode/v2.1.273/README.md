# `claudecode` hook + transcript fixtures — pinned agent version **2.1.273**

RECORDED (not transcribed) on 2026-09-16 by `mark1 corpus record` from the installed `claude 2.1.273`:
the nine 08 §5.1 hooks registered through the real fragment (`claudecode.ApplyFragment`) with the
shim command replaced by a capture script, so every `hooks/*.json` is the exact stdin body the
vendor sent; transcripts are the on-disk `~/.claude/projects/<munged-cwd>/` files the sessions
wrote. Session shapes follow the v2.1.251 README: a parent (plain reply, multi-block response with
a passing and a failing Bash call, a subagent turn, `/compact`), the subagent's own stream, and a
munge-colliding foreign-workspace session. **Frozen** per 12 §3.2.

## Sanitization (the v2.1.251 rule, applied mechanically)

Recording-machine paths and user → `/home/devuser` / `acme-app`; every UUID, `msg_`/`req_`/`toolu_`
id and agent id → a stable synthetic one; `attachment` transcript lines (vendor context injection:
system prompt snapshot, tool/skill listings, session context) are dropped — they are not evidence
about the usage contract and carry the recording machine's identity. Every other line is kept
byte-for-byte after substitution. `selfcheck.py` is carried forward verbatim and passed on this tree.

## Recording notes

- hook bodies fired: map[PostToolUse:2 PostToolUseFailure:1 PreCompact:1 PreToolUse:3 SessionEnd:5 SessionStart:6 Stop:4 SubagentStop:2 UserPromptSubmit:4]
- transcript lines kept by type: map[ai-title:5 assistant:9 atis-latch:7 last-prompt:7 mode:2 queue-operation:10 system:5 user:12]; attachment lines dropped: 45

## Shape deltas vs v2.1.251 (the finding — every one observed on this recording)

Hook bodies (all nine fired; nothing the `agent_maps` field map reads moved):
- `SessionStart` (source `startup`) LOST `model` and `permission_mode`; a `source: "compact"` SessionStart
  (fired after `/compact`) carries `model` and `prompt_id`.
- `Stop`, `SubagentStop` GAINED `prompt_id`, `permission_mode`, `effort{level}`, `background_tasks`, `session_crons`.
- `PreToolUse`, `PostToolUse`, `PostToolUseFailure` GAINED `effort{level}`; `PreCompact`, `SessionEnd` GAINED `prompt_id`.
- `PreCompact.custom_instructions` is `null` (was `""`); `SessionEnd.reason` is `other` under `-p` (was `prompt_input_exit`).
- `/compact` also fires a `SubagentStop` (the summarizer runs as a subagent) before the `compact` SessionStart.

Transcripts (the tailer's replay suite passes unchanged against this tree):
- Streams now LEAD with unversioned, cwd-less meta lines (`queue-operation`, `atis-latch`, `last-prompt`,
  `ai-title`, `mode`); `version`/`cwd`/`sessionId` are stamped on every message line, not every line.
- The 2.5× rewrite is now **one line per content block** under one `(message.id, requestId)`, stamped
  `apiBlockIndex` 0..n with identical cumulative usage (turn 2: text + 2 tool_use = 3 lines, naive 438 vs correct 146).
- Assistant lines LOST the duplicate `session_id` sibling; GAINED `apiBlockIndex`, `perTurnEffort`,
  `usage.iterations[]` (populated), `message.container`, `message.diagnostics`, `message.context_management`.
- The parent transcript carries **no sidechain replay** of the subagent's lines (`never_emit` is empty);
  the subagent stream is the only copy, alongside a new `subagents/agent-<id>.meta.json` sibling.
- `/compact` writes a `system/compact_boundary` line and a `user` line with `isCompactSummary: true`.
- Under `-p`, `promptSource` is `sdk` and `entrypoint` is `sdk-cli` (interactive sessions stamp `typed`/`cli`).
