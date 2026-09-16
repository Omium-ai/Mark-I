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
a random per-boot bearer) next to `server.mjs` — what a real app reads from
`<state>/run/control.json`. Any non-empty `Authorization` header is accepted
on the cloud API (real auth is an OAuth session, not simulated here).

`--scenario` is one of: `first-run | active | paused | offline | below-floor`.

## Scenarios

- **first-run** — onboarding just finished. Agents/projects are configured,
  nothing has run yet: empty sessions, empty events, no report (`guarantee_
  grade: "indicative"` with an "not enough sessions yet" refusal).
- **active** — steady state. Live session on the tray, arrests, injections,
  route decisions, a guarantee-grade TVO report.
- **paused** — `status.paused: true`, no live agents, no new SSE events;
  cloud data still returns (show it as last-synced, not an error).
- **offline** — the cloud port never binds (connection refused); the local
  port answers exactly as in `active`. This is how the app should tell "the
  daemon is fine, the network isn't."
- **below-floor** — `GET /reports/tvo` has `coverage_band.observed_fraction:
  0.82` under a `0.95` floor, `guarantee_grade: "indicative"`, and a
  `refusal.reason` explaining why — the exact case §5.3 describes.

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

TBD shapes (spec marks these unfrozen) are listed in `TBD.md`.

## Test it

```
node desktop/mock/check.mjs
```

Starts the server once per scenario, hits every endpoint with the real
bearer, asserts `200` + parseable JSON (`401` without a bearer on the local
API; connection refused on the cloud port for `offline`), reads one replayed
SSE event where the fixture has any. Exits non-zero on any failure.
