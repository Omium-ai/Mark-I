# Endpoints the spec marks *TBD* (mark1-desktop-app-spec.md §7.2)

Shapes below are this mock's best guess, chosen for the simplest plausible
shape from what the screens in §5 say they need. The backend should freeze
(or replace) these before the frontend treats them as contract.

- `GET /api/v1/sessions`, `GET /api/v1/sessions/{id}` — list uses the columns
  §5.2 names (agent, project, tokens split, verified outcomes, arrests,
  injections, route decisions, coverage); detail adds the task/attempt knee
  curve, verdict trail, typed evidence, injections, receipt checkpoint seq.
- `GET /api/v1/moments?since=` — `{type: arrest|injection|route, id, time,
  task_id, project, agent, summary, tokens_saved}`, one shape for all three
  kinds since Home's feed renders them as one list.
- `GET /api/v1/memory/artifacts` · `/memory/injections` · `/memory/outcomes`
  — user-facing versions of routes that exist internally; fields taken
  directly from §5.5's prose (kind/trigger/guidance/utility_lcb/state/scope
  for artifacts; channel/tokens_used/outcome for injections; uplift_lcb/n
  for outcomes).
- `GET /api/v1/verify/certificates` — `{id, status, project, issued_at,
  epsilon}`; epsilon is null until certified.
- `GET /api/v1/route/decisions`, `GET /api/v1/route/bundle` — decisions per
  §5.6's list; bundle holds ladders/knee_table/cost_basis/exploration_epsilon
  /price_table_version/gateway_status as one config object.
- `GET /api/v1/team`, `POST /api/v1/team/invites` — members/invite_link/
  shared_memory/tvo/fleet_status; invite POST just echoes back a sent status.
- `GET /api/v1/me` — `{user, tenant, plan, regime, region}`.

Also simplified, not spec-TBD but worth flagging: every tenant in these
fixtures is single-regime (apikey/usd). §5.3 says a mixed-regime tenant gets
two separate reports, never one — that split isn't modeled here.
