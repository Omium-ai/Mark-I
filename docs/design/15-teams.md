# 15 — Teams (v1)

Status: approved by the founder 2026-09-26. This is the contract every lane builds against; a lane that needs to deviate says so in its report instead of improvising.

## Founder rulings

1. **Visibility: own work + team totals.** A member sees only their own sessions, tasks, verdicts, receipts, labels, injections and memory, plus memory a teammate explicitly shared. The Team page shows the member list and team-wide TVO totals (aggregates only). The owner has no extra read rights over members' work.
2. **One active workspace.** Accepting an invite moves the person's *new* work into the team tenant. Their personal history stays in their personal tenant and is what they see again if they leave. No workspace switcher.
3. **Seats: free, capped at 10 members per team** (owner included), one config value `TEAM_MAX_MEMBERS` (default 10). Live unaccepted invites count against the cap.
4. The team `consent` is real: sharing an artifact requires it, and a teammate only receives a shared artifact while its author still consents.

## Vocabulary

- **subject**: the principal string already stored by enrollment, `"omium:" + <user token sub>` (`m1_tenants.owner_subject`, `m1_device_enrollments.oidc_subject`).
- **personal tenant**: `m1_tenants.kind='personal'`, owner = `owner_subject` (m1_078). A personal tenant *becomes a team* the moment it has one active member row. There is no separate team tenant.
- **effective tenant** of a subject: the tenant of its active `member` row if one exists, else the tenant in its user token.
- **owner**: `m1_tenants.owner_subject` of the effective tenant. **member**: an active `m1_team_members` row with `role='member'`.

## Schema — `migrations/m1_090_teams.sql` (lane A owns the file; everyone else reads this section)

```sql
CREATE TABLE IF NOT EXISTS m1_team_members (
  tenant_id  uuid NOT NULL REFERENCES m1_tenants(id),
  subject    text NOT NULL,                      -- "omium:<sub>"
  email      text,                               -- from the user token at accept/refresh time
  role       text NOT NULL CHECK (role IN ('owner','member')),
  joined_at  timestamptz NOT NULL DEFAULT now(),
  left_at    timestamptz,
  PRIMARY KEY (tenant_id, subject)
);
-- one active workspace: a subject is an active *member* of at most one tenant
CREATE UNIQUE INDEX IF NOT EXISTS ux_m1_team_members_one_active
  ON m1_team_members (subject) WHERE left_at IS NULL AND role = 'member';

ALTER TABLE m1_team_invites  ADD COLUMN IF NOT EXISTS accepted_by text;
ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS team boolean NOT NULL DEFAULT false;
ALTER TABLE memory_artifacts ADD COLUMN IF NOT EXISTS owner_subject text;
-- backfill: the enrollment subject of the provenance device, else the tenant owner
```

- The owner gets a row (`role='owner'`) the first time they mint an invite or read `GET /team`, carrying their email; the owner row is never "left".
- Re-joining after leaving reuses the primary key: `UPDATE ... SET left_at = NULL, joined_at = now()`.
- House style: idempotent, `BEGIN/COMMIT`, ENABLE + FORCE RLS with the two-arg `NULLIF(current_setting('app.tenant_id', true), '')::uuid` policy, grants to `controld_app` (rw) and `intel_app` (read on `m1_team_members`, `m1_device_consents`; rw on the new `memory_artifacts` column via the existing table grant). The two lookups that must cross tenants (effective tenant by subject; invite by token hash) go through `SECURITY DEFINER` functions owned by the migration role with a pinned `search_path`, returning only the columns they need — the same way the repo already handles pre-tenant lookups (read how enroll does it and follow that pattern).

`memory_artifacts.owner_subject` backfill (in the migration): `UPDATE memory_artifacts a SET owner_subject = COALESCE(e.oidc_subject, t.owner_subject) FROM ...` using `a.body->'provenance'->>'device_id'` → the latest approved `m1_device_enrollments` row for that device → `oidc_subject`; fallback `m1_tenants.owner_subject`. Rows that resolve to neither stay NULL; NULL owner means "visible to the tenant owner only".

## Cloud API (controld) — additive, all under the user token unless stated

| Route | Who | Behaviour |
|---|---|---|
| `GET /api/v1/team` (exists) | any member | members = owner row + active members + live invites (`status:"invited"`); each `{id, name:null, email, role, joined_at, last_active, status}`; `id` is in the **same format as `GET /api/v1/me` → `user.id`** so the app's "(you)" works; `last_active` = max `last_seen_at` of that subject's devices in this tenant. Also `role` of the caller at top level: `"you": {"role": "owner"|"member"}`. `tvo` = team-wide totals (aggregate). `invite_link` stays null. |
| `POST /api/v1/team/invites` (exists) | owner only (403 `M1E-2003` otherwise) | refuses with 409 `M1E-2409` `team_full` when active members + owner + live invites ≥ `TEAM_MAX_MEMBERS`. Upserts the owner row with the caller's email. **Stop claiming `sent: true`** — no email is sent in v1; answer `sent: false`. Link format changes to `https://mark.omium.ai/join#<token>` (fragment: never reaches a server log). |
| `POST /api/v1/team/invites/accept` `{token}` | any signed-in person | token is the raw token or the full link (take what follows `#` or the last `/`). 404 `invite_invalid` (unknown/expired/accepted), 403 `invite_email_mismatch` (invited_email set and ≠ token email, case-insensitive), 409 `already_in_team` (caller is an active member elsewhere), 409 `own_team` (caller is that tenant's owner), 409 `team_full` (cap re-checked under `SELECT ... FOR UPDATE` on the `m1_tenants` row). Success: insert/reactivate the member row with email, set `accepted_at`/`accepted_by`, answer `{"tenant_id", "role":"member"}`. The app then re-enrolls the device. |
| `POST /api/v1/team/leave` | member | sets `left_at`; owner gets 400 `owner_cannot_leave`. Answer `{"tenant_id": <personal tenant from token>}`; the app re-enrolls. |
| `DELETE /api/v1/team/members/{id}` | owner | sets `left_at` for that member; the removed person's next token/enroll resolves back to personal. Their devices in the team tenant are revoked (existing revocation path) so they stop uploading into the team. |
| `PUT /api/v1/consents` (exists, device token, ingest) | device | body gains optional `team` (default false) → `m1_device_consents.team`. |

Error bodies use the existing `{code, message}` shape plus a `reason` field; clients match on `reason`. Codes (08 §9): 403 `M1E-1007` role does not permit (not_owner, not_member, invite_email_mismatch, user_token_required), 403 `M1E-1008` consent_required, 409 `M1E-2011` conflict (already_in_team, own_team, owner_of_team, team_full, owner_cannot_leave), 404 `M1E-2012` not found (invite_invalid, member_not_found). An owner whose team has active members cannot accept another team's invite (409 owner_of_team).

### Effective tenant — one chokepoint

`userauth.tenantVerifier.Verify` (the read-surface user-token verifier) and `enroll.handleApprove` both resolve the tenant through **one** function: `teams.EffectiveTenant(ctx, db, subject, tokenTenant) (uuid.UUID, error)` in a new package `go/controld/internal/teams`. A short in-process cache (30 s) is fine (`ponytail:` marker). A removed/left member's reads fall back to the token tenant on the next cache miss.

### Per-person visibility (lane B)

- A tenant **is a team** once it has ever had a `member` row (active or left): a leaver's last token must never fall back to tenant-wide reads. Tenants that never had a member are unchanged (no filter) — existing users see exactly what they see today. A device whose enrolling subject is neither the owner nor an active member gets no new token (`M1E-1003`); tenant-wide settings (shared memory, cloud judge) in a team are the owner's, under the user token.
- In a team, every read in `appapi` that returns per-session/task/verdict/receipt/label/injection data is filtered to the **viewer's devices**: devices of this tenant whose approved enrollment `oidc_subject` = viewer subject. Device-token callers (the daemon) are scoped to their own subject's devices the same way.
- ClickHouse reads go through `querychoke` templates: add a `device_ids Array(UUID)` parameter and an `AND device_id IN {device_ids}` predicate to every per-tenant template the app reads, applied only when the caller passes it (an empty array must mean "no rows", never "no filter"; "no filter" is the parameter being absent). The chokepoint still asserts the tenant predicate.
- Team TVO on `GET /team` stays tenant-wide (aggregate). The Reports page shows the viewer's own TVO.
- Receipts: the chain head, witness and verification stay tenant-wide (hashes only). Receipt *rows/checkpoints* listed to the app are the viewer's devices'.

### Memory (lane C, intel; lane B wires controld's memory module)

- controld's memory module passes `viewer_subject` (resolved from the user token, or from the device's enrollment for device tokens) to every intel memory call.
- intel serving predicate for `GET /v1/memory/artifacts`, `POST /v1/memory/match`, and the app list: `owner_subject = viewer` OR (`scope='team'` AND tenant `shared_memory` AND the owner's **latest** consent row on any of their devices in this tenant has `team=true`) OR (`owner_subject IS NULL` AND viewer is the tenant owner). Non-team tenants: unchanged behaviour (the predicate reduces to "everything" because the viewer owns everything; keep it cheap).
- New artifacts are stamped with `owner_subject` = enrollment subject of the provenance device. Admission/merging never folds evidence from different owners into one artifact inside a team tenant (the merge key includes `owner_subject`).
- `share`: only the owner of the artifact, and only while the caller's latest team consent is true (403 `consent_required` otherwise). `unshare`, `pin`, `unpin`, `retire`: owner of the artifact only (403 `not_owner`).

## Edge (mark1d)

- `consents.Consents` gains `Team bool \`json:"team"\``; `consentsPatch` gains `Team *bool`; `GET /v1/optins` returns it; the relay to `PUT /api/v1/consents` sends it. The strict decoder stays strict.
- Re-enrollment into a different tenant (after accept/leave): the daemon's `enroll` local route must accept a new identity whose `tenant_id` differs from the current one. Before swapping it drains the spool under the old identity (bounded wait; whatever cannot drain is kept and uploaded under the old token until that token expires, never under the new one), then swaps identity, bundle LKG and tenant root. Events are never re-stamped into the new tenant.

## App (Mark1-GUI, branch `teams`, on top of Fazil's PR #2)

- `features.team = true`.
- Sign-in "Have a team invite?" field keeps the invite; after sign-in + enrollment the app calls `teamInviteAccept`, then re-enrolls, then refetches everything. Errors from the table above render as plain sentences.
- Team page: owner sees invite controls, member list with a remove action per member, shared-memory switch; a member sees the list and a **Leave team** action (confirm dialog: "Your personal history comes back; your team work stays with the team.").
- Invite form: with an email it says **Create invite** (not "Send"), and shows the link to copy with the note that only that email can use it.
- Memory: "Share to team" is disabled with a one-line reason when the team consent is off, and absent on artifacts the viewer does not own.
- Settings consent row as in PR #2.
- Mock scenarios and contract fixtures under `omium-mark1/desktop/mock/` cover: solo owner, owner with members, member, full team, and every accept error.
- `npm run check` must pass, including the two e2e failures on PR #2 and the date-dependent e2e (pin the clock or make fixtures relative).

## Invite landing page (mark-1--web)

`/join` on mark.omium.ai: reads the token from the fragment client-side, never sends it anywhere, and tells the person to open Mark 1 and paste the link (with the download buttons for people who don't have it yet).

## Rollout order

1. Cloud (controld + intel + migration) — additive and backward compatible; ships first.
2. Edge release (mark1d with the `team` consent and tenant-switch re-enroll).
3. App release pinned to that edge, `features.team = true`.
