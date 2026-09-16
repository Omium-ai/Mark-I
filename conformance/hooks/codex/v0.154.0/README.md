# `codex` hook + rollout fixtures — pinned agent version **0.154.0**

The corpus that gates the codex adapter slot (08 §5 rule 3: no fixture, no adapter; nothing is
authored from memory). Directory named per 12 §3.2 (`conformance/hooks/<agent>/<version>/`).
**Frozen** — a new Codex release gets a *new* version directory; these files are never edited.

## Provenance (what is vendor, what is synthesized)

Pin: npm `@openai/codex@0.154.0` = git tag `rust-v0.154.0` = commit
`6b9826e3aa83b1a5947db50f4332cb9c65f1b340` (tagged 2026-09-09T21:43:48Z), fetched 2026-09-16.

| Path | What it is | Source |
|---|---|---|
| `schema/*.command.input.schema.json` | The vendor's own generated JSON schema for each hook's stdin body (11 of the 12 events; `PermissionRequest` is not registered — Mark 1 is not a permission product). **Verbatim vendor bytes.** | `codex-rs/hooks/schema/generated/` at the pinned commit (written by `codex-rs/hooks/src/schema.rs::write_schema_fixtures`) |
| `hooks/<HookEventName>.json` | The stdin body `mark1-hookshim` receives per registered event. Synthesized from the schema for that event (every `required` field, `const`/`enum` values verbatim, `additionalProperties: false` respected) with synthetic identities. `selfcheck.py` validates each body against its schema. Per 08 §5 rule 4 **no hook body carries token usage**. | `codex-rs/hooks/src/schema.rs` (`*CommandInput` structs) |
| `transcripts/sessions/2026/09/16/rollout-<ts>-<thread_id>.jsonl` | Rollout files in the real on-disk layout `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<YYYY-MM-DDTHH-MM-SS>-<thread_id>.jsonl`. Line shape `{timestamp, ordinal, type, payload}` (`RolloutLine` + `RolloutItemWire`). Synthesized from the vendor types, not recorded from a live install — see "persistence" below. | `codex-rs/history/src/{lib.rs,rollout_payload.rs}`, `codex-rs/rollout/src/{recorder.rs,rollout_file_name.rs,policy.rs}`, `codex-rs/protocol/src/protocol.rs` (`TokenUsageRecord`, `TokenUsage`, `TokenCountEvent`, `SessionMeta`, `TurnContextItem`) |
| `exec/codex-exec.jsonl` | A `codex exec --json` stdout stream (`ThreadEvent` JSONL) — reader (b) of the adapter. Synthesized from the vendor types. | `codex-rs/exec/src/exec_events.rs` |
| `transcripts/expectations.json` | Exactly which `Usage` events a correct tailer emits per stream: idem_key inputs, token numbers, model, plus the lines that must never emit and the #14489 re-emit arithmetic. | our reading of the vendor bytes, re-derived independently by `selfcheck.py` |
| `selfcheck.py` | Fixture audit, not the tailer under test. `python3 selfcheck.py`, exit 0 = consistent. | — |

## Sanitization rule (normative)

Every identity is synthetic — placeholder user (`devuser`), workspace (`acme-app`), UUIDv7-shaped
`019965a0-…` thread/turn ids, `resp_SynthFixture…` response ids, `call_SynthFixture…` tool ids.
`selfcheck.py` greps every fixture byte for the recording machine's identities and fails red on a hit.

## Persistence: what the vendor source says, what a live recording still owes

The spike (`docs/spikes/codex-token-count-event.md`) left "is usage persisted to the rollout
JSONL?" unconfirmed. At the pinned commit the source answers it directly:

- `codex-rs/rollout/src/policy.rs::is_persisted_rollout_item` returns `true` for
  `RolloutItem::TokenUsageRecord(_)`; `should_persist_event_msg` returns `true` for
  `EventMsg::TokenCount(_)`.
- `codex-rs/core/tests/suite/token_usage_rollout.rs::observed_response_usage_accumulates_per_turn_and_thread`
  runs a session against a mock Responses API and asserts the rollout file holds **one
  `token_usage_record` per completed response** (`response_id`, per-response `usage`, cumulative
  `turn_token_usage`/`thread_token_usage`), across a shutdown + resume, and **no record for a
  response that reported no usage**.

So the rollout tail is the primary Usage source (reader (a)); `codex exec --json` is reader (b).
Still owed by a LIVE recording on a real `codex 0.154.0` install: the exact `session_meta`
noise-field set, whether `token_usage_record` lines are ever re-logged verbatim (Claude Code's
observed post-compaction re-log has no confirmed Codex analogue — the dedupe defends it anyway),
and the reverted-thread (`rollout-…-<thread>_<rollout>.jsonl`) replay contents.

## Recording-time facts pinned by these fixtures

- **Dedupe key** is `(thread_id, turn_id, response_id)` → `idem_key = HMAC_tenant(thread_id, turn_id, response_id)`
  through the same recipe Claude Code uses (`session_id := thread_id`, `message_id := turn_id`,
  `request_id := response_id`). Each Codex thread — root or spawned sub-agent — is its own m1p
  session; the record's `session_id` names the root thread for a parent join.
- **`token_count` snapshots never count.** `TokenCountEvent{info:{total_token_usage, last_token_usage},
  rate_limits}` is a UI snapshot re-emitted on rate-limit-only refreshes with unchanged usage
  (openai/codex#14489). The parent fixture carries three snapshots whose `last_token_usage` equals
  `resp_SynthFixtureBBBBBBBB`'s usage against one `token_usage_record` — a per-line summer over
  `token_count` reports 3×; the tailer reads `token_usage_record` lines only, so it cannot.
- A `compacted` line nests `latest_token_usage_record` (a copy of `resp_SynthFixtureCCCCCCCC`);
  it is not a top-level record and never emits.
- **Field semantics differ from Anthropic's**: OpenAI `input_tokens` INCLUDES `cached_input_tokens`,
  and `output_tokens` INCLUDES `reasoning_output_tokens`. Mapped verbatim (`cached_input_tokens →
  cache_read_input_tokens`, `cache_write_input_tokens → cache_creation_input_tokens`); cost math
  downstream must key on the model string, not assume Anthropic subtraction rules.
- `model` is not on the record; it is the last preceding `turn_context.payload.model` in the stream.
- **Containment**: Codex keeps ONE `sessions/` tree for every workspace, so every project's
  rollouts share the enabled workspace's directory. The foreign stream's `session_meta.cwd`
  resolves outside the enabled root; it is never tailed (04 §0.3 invariant 3, 04 §2.1).
- Hook payloads carry a native `turn_id` on every turn-scoped event; `SessionEnd.reason` is
  `const "other"` at this version; `PostToolUse` has no `duration_ms` and there is no
  `PostToolUseFailure` (failure rides `tool_response`).
- Hooks are discovered from `~/.codex/hooks.json` (`HooksFile{description?, hooks}` —
  `deny_unknown_fields` at the root, so no `_mark1_managed` sibling can live there; the per-entry
  `_mark1` tag on a matcher group is tolerated) and are **trust-gated**: a user-layer handler runs
  only once its `trusted_hash` is recorded under `[hooks.state]` in `config.toml`
  (`codex-rs/hooks/src/engine/discovery.rs`), which the Codex TUI's startup hooks review writes
  on "Trust all and continue". Mark 1 registers; the user trusts. `mark1 doctor` should say so.
