# `claudecode` hook + transcript fixtures — pinned agent version **2.1.251**

The recorded corpus that gates the claudecode adapter slot (08 §5 rule 3: no fixture, no
adapter; nothing is authored from memory). Directory named per 12 §3.2's convention
`conformance/hooks/<agent>/<version>/`; the pin is the `claude --version` of the machine the
shapes were recorded from, 2026-08-29. **Frozen** — per 12 §3.2's refresh policy a new Claude
Code release gets a *new* version directory via the recording lane; these files are never
edited, and the old pin documents the supported window.

## Sanitization rule (normative for every fixture in this tree)

Shapes are transcribed from live v2.1.251 on-disk transcripts and the vendor-verified hook
table (08 §5.1); every identity is synthetic — placeholder user (`devuser`), placeholder
workspace (`acme-app`), placeholder prompts/code/paths, `aa000000-…` UUIDs, `…SynthFixture…`
message/request/tool ids. Zero real workspace content, enforced mechanically: `selfcheck.py`
greps every fixture payload byte for the recording machine's identities and fails red on a
hit, so a future re-recording cannot leak quietly.

## Contents

| Path | What it is |
|---|---|
| `hooks/<HookEventName>.json` | The exact stdin body `mark1-hookshim` receives for each of the nine events 08 §5.1 registers (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`, `SubagentStop`, `PreCompact`, `SessionEnd`). Filename == `hook_event_name`. Per 08 §5 rule 4, **no hook body carries token usage** — selfcheck asserts it. |
| `transcripts/-home-devuser-workspace-acme-app/<session>.jsonl` | Parent-session transcript in the real on-disk layout (`~/.claude/projects/<munged-cwd>/<session-id>.jsonl`, 08 §5.1), exercising: (a) the ~2.5× overcount case — one assistant message rewritten across 4 streaming lines under one `(message.id, requestId)` with cumulative usage (naive per-line sum 2562 output tokens vs the correct last-line 1042 ≈ 2.46×); (b) sidechain replay lines (`isSidechain:true`) that must never emit from this stream; (c) a normal multi-turn tail with tool use, non-usage noise lines (`system`, `tool_result`), and a verbatim-repeated finished line (observed v2.1.251 behavior) that must still yield one event. |
| `transcripts/…/<session>/subagents/agent-<id>.jsonl` | The subagent's own stream — the *origin* of the sidechain key replayed in the parent. Tailed as its own stream under the **parent** `session_id` (04 §2.1); its lines emit here and only here. |
| `transcripts/expectations.json` | Exactly which `Usage` events a correct tailer emits per stream, in first-seen-key order: `idem_key` inputs (`session_id`, `message_id`, `request_id` — 07 §7's HMAC recipe), token numbers, plus the keys that must never emit and the overcount arithmetic. |
| `selfcheck.py` | Fixture audit, not the tailer under test: re-derives the expected events from 08 §5.1's dedupe + sidechain rules, checks the overcount corpus still overcounts (≥2×), enforces the sanitization tripwire and the nine-event hook inventory. `python3 selfcheck.py`, exit 0 = consistent. Mutation-tested: flattening the rewrite, flipping `isSidechain`, or leaking a real path all go red. |

## How the replay suite consumes this (12 §3.2)

- `conf_hooks_claudecode_2.1.251_replay` — replay every `hooks/*.json` body through the
  hookshim field maps + adapter and every transcript stream through `mark1d.tailers`, assert
  the exact `m1p.v1` event sequence; for `Usage`, `expectations.json` is the oracle.
- `conf_adapter_fieldmap_bundle_push` — a renamed-field variant of these bodies under a new
  `agent_maps` bundle must parse with **no binary change** (FR-AGENT-001).
- `adapter_version_sniff_drop` — any version without a green directory here is
  `Dropped{UNSUPPORTED_AGENT_VERSION}` and zero parsed events (F-12, FR-AGENT-002).

The expected `m1p.v1` sequences for the hook bodies live with the field maps (the `agent_maps`
bundle those tests load), not here — this directory pins the *vendor* side of the contract.

## Recording-time observations pinned by these fixtures

- v2.1.251 assistant lines carry **both** `sessionId` and a distinct `session_id`; the hook
  payload's `session_id`, the transcript filename, and `idem_key`'s session input are all the
  former. `expectations.json` uses `sessionId`.
- On disk, v2.1.251's streaming rewrites repeat the key with *identical* cumulative usage
  (up to 6 lines observed); 08 §5.1's contract also covers *evolving* cumulative usage, which
  this corpus exhibits deliberately — last-write-wins is correct for both, and per-line
  emission is the verified ~2.5× overcount either way (NFR-CORRECTNESS-001, 07 §7).
- The parent's sidechain replay carries the same `(message.id, requestId)` as the subagent's
  own stream, so even a misclassifying tailer collapses at ingest on `idem_key` — the backstop
  07 §7 promises, demonstrated by construction here (`msg_…DDDDDDDD`).
- Usage blocks include vendor fields Mark 1 does not map (`output_tokens_details`,
  `cache_creation`, `inference_geo`, …) on purpose: the tailer must tolerate unknown fields.
