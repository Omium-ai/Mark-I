# Mark 1 desktop mock server

Dependency-free (Node ≥ 20, stdlib `http` only). Serves the data contracts in
`mark1-desktop-app-spec.md` §7 against static fixtures, so the desktop app
can be built before the real `mark1d`/`controld` endpoints exist.

## Run it

```
node server.mjs --scenario active [--local-port 4001] [--cloud-port 4002]
```

Two HTTP servers start: the local control API (default `:4001`, `/v1/...`)
and the cloud API (default `:4002`, `/api/v1/...`). It prints `READY
<localPort> <cloudPort>` once listening, and writes `control.json` (port +
a random per-boot `token`, the daemon's own field name) next to `server.mjs` — what a real app reads from
`<state>/run/control.json`. Any non-empty `Authorization` header is accepted
on the cloud API (real auth is an OAuth session, not simulated here).

`--scenario` is one of: `first-run | active | paused | offline | below-floor`.

## Scenarios

- **first-run** — onboarding just finished. Agents/projects are configured,
  nothing has run yet: empty sessions, empty events, no report (`guarantee_
  grade: false` with a "not enough sessions yet" `refusal` string).
- **active** — steady state. Live session on the tray, arrests, injections,
  route decisions, a guarantee-grade TVO report.
- **paused** — `status.paused: true`, no live agents, no new SSE events;
  cloud data still returns (show it as last-synced, not an error).
- **offline** — the cloud port never binds (connection refused); the local
  port answers exactly as in `active`. This is how the app should tell "the
  daemon is fine, the network isn't."
- **below-floor** — `GET /reports/tvo` has `coverage_band.observed_fraction:
  0.82` under a `0.95` floor, `guarantee_grade: false`, and a `refusal`
  string explaining why, the exact case §5.3 describes. Grade and refusal
  are controld's own spelling (08 §3.3 honesty fields: a boolean and the
  stated refusals joined by `; `); `trend` is `[{day, tvo}]`, one point per
  rollup day.

## Fixtures

`fixtures/<scenario>/<endpoint>.json`, one file per row of §7.1/§7.2 (`local-*`
for the control API, `cloud-*` for the cloud API). Storybook/design can read
these directly without running the server. `GET /v1/events` fixtures are
arrays of `{delayMs, event, data}`, replayed as SSE on a timer, looping.

The sign-in handoff (§3.2 step 1) is four local rows: `POST /v1/enroll/keygen`
(the device public key the app sends to controld's `/enroll/device/approve`),
`POST /v1/enroll` (the ACTIVE body handed back verbatim; the real daemon 409s
one minted for another device key or another live tenant), `GET /v1/enroll`
(`enrolled` is true only while the device token is live; `state` is
`active|expired|revoked`; `key_id` is present once a key exists) and
`DELETE /v1/enroll` (device sign-out — returns the GET shape). Every scenario
here is post-onboarding, so `GET` is enrolled; the not-enrolled shape is the
`DELETE` fixture. Static fixtures do not flip state.

Numbers are internally consistent: `tokens_saved.total` = the sum of its
`arrests`/`re_exploration_avoided`/`routing` parts, and `tvo` = tokens ÷
verified outcomes.

Ids join across the two sides byte-for-byte: the live session is
`0191c7a0-5b1e-7c2d-9e4f-0123456789a0` (ids are dashed UUID strings on every
app-facing surface, local and cloud) in `local-status.agents_live`,
`local-verify-events`, `cloud-sessions`, `cloud-sessions/{id}` (the route
literal in `CLOUD_ROUTES`), `cloud-moments` and `cloud-memory-injections`;
its tasks are `…89a1` (the arrest, also `reports-interventions.knee_arrests[0]`),
`…89a2` (the injection) and `…89a3` (the route decision). Agent names are the
daemon's catalog vocabulary on both sides (`claudecode`, never `claude-code`).
Receipt seqs join too: `local-receipts` numbers checkpoints 1..3 with head
`{seq: 1042, checkpoint_seq: 3}`, and `cloud-receipts-export` is controld's
real export shape — `application/x-ndjson`, one signed receipt per line
(`tools/verifier` `ExportRow`: `seq, payload, receipt_hash_hex,
device_key_id, device_signature_hex, server_key_id, server_signature_hex`),
the fixture holding the lines as an array. Chain seq 1042 is checkpoint 3 and
its `receipt_hash_hex` is the local `head.hash`; `merkle_root`, `key_id`
(`device_key_id`) and `leaf_count` sit inside each line's canonical
`payload`. Witness heads are their own route, `GET /api/v1/receipts/witness`
(`{heads:[{witnessed_seq, witnessed_hash_hex, witnessed_at, statement,
server_key_id, signature_hex, object_bucket_uri?, log_backend?}]}`), as on
controld. Signatures and hashes here are shaped, not verifiable.

`POST /v1/shutdown` answers `{ok: true}` and is how the app stops the daemon
where no SIGTERM exists (Windows); the daemon then takes the same graceful
stop path a signal does.

## What the local fixtures are held to

`go/mark1d/internal/control/conformance_test.go` runs every `local-*.json`
row of `LOCAL_ROUTES` against the real daemon and fails on any structural
difference (key sets, JSON types, first array element), so these shapes are
the daemon's, not a sketch of §7.1:

- Agent names are the daemon's catalog names (`claudecode`, `codex`,
  `gemini`, `opencode`, `copilot`, `cursor`, `crush`), the same strings
  `SessionStart.agent` carries on the wire. Every `/v1/agents` row has all
  keys; `version`/`compat`/`provisioned` are `null` until known, `regime` is
  `null` for an unimplemented slot. `byte_equal_revert` is true iff the
  fragment's target is byte-identical to what Mark 1 wrote (state `OK`).
  `recent_projects` are the cwds an agent's own session trees name (every adapter with a session tree: Claude Code transcripts, codex rollouts, gemini chats, opencode captures, copilot events; cursor has none and is always `[]`).
- `receipted_transition_id` on `pause`/`resume`/`DELETE /v1/projects` is
  `null`: the daemon journals the transition and its coverage drain receipts
  it a few seconds later, so no id exists at response time.
- `POST /v1/projects` is `mark1 enable`: it provisions every installed
  agent's hook fragment (08 §8) before the root lands in the allow-list, and
  answers the project row plus `agents_provisioned:[name…]` and
  `agents_refused:[{agent, code, detail}]` (M1E-7101 when the agent's
  settings file does not exist — mechanism B never creates one). The body
  may carry `agents:[name…]` to restrict the walk; a re-POST of an enabled
  root re-verifies the fragments and records no second consent.
  `DELETE /v1/projects` adds `reverted:[{agent, target, kind, byte_equality}]`,
  `not_reverted:[manifest…]` and `byte_equality`: fragments are user-scoped,
  so they come out only when the last enabled project is removed.
- `POST /v1/agents/{name}/provision` (`local-agents-provision`, the route
  literal names `claudecode`) is repair / re-provision for one agent — the
  same walk with the `doctor --fix` bit, so a `FRAGMENT-DAMAGED` fence is
  rewritten and a `MISSING` one re-applied; it answers `{agent, provisioned,
  changed, refused, fragments}` with the agent's doctor fragment rows, `404`
  for a name outside the six built adapters and `409` for one not installed.
  `POST /v1/agents/{name}/disable` (`local-agents-disable`) reverts that
  agent's fragments byte-equal (08 §8.4) and keeps the workspace:
  `{agent, reverted, not_reverted, byte_equality}`.
  `POST /v1/agents/{name}/pause` · `/resume` (`local-agents-pause`,
  `local-agents-resume`) is `/v1/pause` for one agent: the hookshim gate
  answers allow for that agent's sessions and its tailers admit nothing
  until resume, journalled as an `agent_pause` / `agent_resume` coverage
  transition; `{agent, paused, receipted_transition_id}` (null, drain-minted).
  `GET /v1/agents` rows and `status.agents_live` rows carry `paused` for
  it; the global switch stays `status.paused` and wins.
- Anchors carry `side_effect: static|test` (the FR-VERIFY-003 tier axis)
  and no `tier`; `last_run` is the newest anchor vote this daemon boot saw,
  `null` before one.
- `/v1/optins.consents` is the Step-4 record (`e1`, `cloud_judge`,
  `training`), all `false` until the user consents; `PUT` merges a partial
  object. `tests_by_project` is writable the same way.
- `/v1/receipts` is the local chain view: `{status: not_started|sealed,
  head:{seq, hash, checkpoint_seq}, checkpoints:[{seq, time,
  events_covered, merkle_root, key_id}]}` newest first, `?before=<seq>`
  pages back. Countersignatures and witnesses are the cloud export's.
- `POST /v1/receipts/verify` relays the offline verifier's own `Report`
  (`tools/verifier`). An empty body verifies the enrolled server's export
  with its key manifest; `{chain, keys, witness?}` names local snapshots.
- `/v1/verify/events` rows are `{type: arrest|verdict|tamper, id, time,
  task_id, session_id, …}`: arrests add `attempt, p_lcb, v, c_n,
  inequality, evidence_ref` (numbers `null` when the knee was not
  evaluable), verdicts `verdict, state, certificate_id`, tampers
  `anchor_id`.
- `GET /v1/events` data objects are the daemon's frames: protojson
  `m1p.v1.Event` with `event_id`/`session_id`/`task_id` re-spelled as dashed
  UUIDs (the body under its family key, uint64 counts as strings, enums as
  their prefixed names), except `arrest`, which is the same row
  `/v1/verify/events` holds.

## What the memory-action and team fixtures are held to

controld now serves these routes (`internal/memory` proxies the actions and
`GET /memory/outcomes` to mark1-intel; `internal/appapi` serves
`GET /memory/injections` and the team rows; response shapes are the JSON
Schemas in `go/controld/internal/appapi/schema/`), so the fixtures here mirror
that backend where the mock can and differ where the mock's static ids cannot:

- `POST /api/v1/memory/artifacts/{id}/retire` (body `{reason}`, 1..1024
  chars) answers `{artifact_id, state: "retired", receipt_id}` — the retire is
  chained as a `memory_admission` receipt whose payload carries `act: retire`,
  the reason and the actor; `…/pin` · `…/unpin` answer `{artifact_id, pinned}`;
  `…/share` · `…/unshare` answer `{artifact_id, scope}`. The route literal is
  `art_pit_7`; the real backend takes a UUID and answers `404 M1E-2009` for a
  malformed, unknown or another tenant's id (never 403). Artifact rows carry
  `pinned` alongside `scope`; a pinned artifact is never auto-retired by the
  nightly ADMIT-LCB pass (a user retire still may).
- `GET /api/v1/memory/injections` is one row per artifact delivered by a
  `MemoryInjection` event; `outcome` is the task's stage-final verdict at
  close, `pending` until it has one. `GET /api/v1/memory/outcomes` is the
  stored ADMIT-LCB evidence per artifact (`uplift_lcb` = the stored lcb,
  `n` = `verified_outcomes` = the certified sample count). Both real routes
  wrap their arrays (`{window, injections, honesty}` / `{outcomes}`), as do
  the fixtures; `GET /api/v1/memory/artifacts` is `{artifacts: [{artifact_id,
  …}]}` (08 §3.7). Injection `outcome` is `pending | satisfied | violated |
  refused | error` and `channel` the six-value INJECTION_CHANNEL suffix.
  `fixtures/controld/cloud-*.json` are goldens written by controld's own
  handlers (`go test ./internal/appapi -run TestAppAPIMatchesDesktopFixtures -update`) and
  parsed by the GUI's contract test; the mock server does not serve them.
- `GET /api/v1/team` members are the tenant's principals as the schema knows
  them (the m1_078 owner, the approvers of device enrollments, the caller)
  plus live invites as `status: "invited"`; there is no users table, so the
  real backend sends `name: null, email: null` on a principal, and `invite_link:
  null` (the raw token is answered exactly once by `POST /team/invites`, whose
  hash is what `m1_team_invites` keeps for 7 days). `PUT /api/v1/team`
  `{shared_memory}` answers `{shared_memory}`. `POST /api/v1/team/invites`
  `{email?}` answers `{sent: true, invite_link, invited_email, status: "sent",
  expires_at}`; nothing is emailed.

TBD shapes (spec marks these unfrozen) are listed in `TBD.md`.

## Test it

```
node desktop/mock/check.mjs
```

Starts the server once per scenario, hits every endpoint with the real
bearer, asserts `200` + parseable JSON (or one JSON document per line on an
`application/x-ndjson` reply; `401` without a bearer on the local API;
connection refused on the cloud port for `offline`), reads one replayed SSE
event where the fixture has any. Exits non-zero on any failure. It binds
`4501`/`4502`; `MOCK_CHECK_LOCAL_PORT`/`MOCK_CHECK_CLOUD_PORT` move it when
another mock holds them.
