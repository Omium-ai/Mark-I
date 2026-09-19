# `claudecode` hook + transcript fixtures — pinned agent version **2.1.278**

RECORDED (not transcribed) on 2026-09-19 by `mark1 corpus record` from the installed `claude 2.1.278`:
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
- transcript lines kept by type: map[assistant:9 atis-latch:7 cost-state:5 last-prompt:7 mode:2 queue-operation:10 system:5 user:12]; attachment lines dropped: 45

## Shape deltas vs v2.1.273 (every one observed on this recording)

Hook bodies: no key gained or lost in any of the nine events — the `agent_maps` field map reads exactly what it read at 2.1.273.

Transcripts (the tailer's replay suite passes unchanged against this tree):
- New `cost-state` line type (5 per parent stream): cumulative `totalCostUSD` (a 17-digit float — the sanitizer's hex-id rule now leaves pure-digit runs alone), API/tool durations, `modelUsage`. Unversioned meta, not a usage line; the tailer skips it like the other meta types.
- `ai-title` lines are gone from this recording (titles were not generated for `-p` sessions).
- Assistant lines GAINED `advisorModel` and `message.input_transformations`; nothing the dedupe key or usage read moved.
