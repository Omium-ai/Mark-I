-- m1_081_memory_actions_team.sql
-- Desktop spec §5.5 memory actions + §5.10 team (v1 minimal). (1) memory_artifacts
-- grows `pinned` (the ADMIT-LCB retire branch in memory/admit.py never auto-retires a
-- pinned row; a user retire still may) and `scope` ('mine' | 'team', the app's share
-- toggle -- a label the artifact carries, not a serving predicate: no per-user artifact
-- ownership exists, so the tenant's admitted set is what the edge syncs either way).
-- (2) m1_tenants.shared_memory, the team-level on/off the app reads and writes.
-- (3) m1_team_invites: one row per minted invite link, hash only (the raw token lives
-- in the link the POST answered with, once); 7-day TTL as a schema fact like
-- m1_001's ck_m1_enroll_token_ttl; accepted_at is reserved for the dashboard's
-- accept flow, which does not exist yet. controld_app owns the table; intel_app owns
-- the artifact columns through m1_040's table-level grant.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE memory_artifacts ADD COLUMN IF NOT EXISTS pinned boolean NOT NULL DEFAULT false;
ALTER TABLE memory_artifacts ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'mine';
ALTER TABLE memory_artifacts DROP CONSTRAINT IF EXISTS ck_memory_artifacts_scope;
ALTER TABLE memory_artifacts ADD CONSTRAINT ck_memory_artifacts_scope CHECK (scope IN ('mine', 'team'));

ALTER TABLE m1_tenants ADD COLUMN IF NOT EXISTS shared_memory boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS m1_team_invites (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  token_hash     bytea NOT NULL UNIQUE,
  invited_email  text,
  invited_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  accepted_at    timestamptz,
  CONSTRAINT ck_m1_team_invites_hash_len CHECK (octet_length(token_hash) = 32),
  CONSTRAINT ck_m1_team_invites_ttl CHECK (expires_at <= created_at + interval '7 days')
);

CREATE INDEX IF NOT EXISTS ix_m1_team_invites_live
  ON m1_team_invites (tenant_id, expires_at) WHERE accepted_at IS NULL;

ALTER TABLE m1_team_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_team_invites FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_team_invites;
CREATE POLICY tenant_isolation ON m1_team_invites
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_team_invites FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE (accepted_at) ON m1_team_invites TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_team_invites;
--   ALTER TABLE m1_tenants DROP COLUMN IF EXISTS shared_memory;
--   ALTER TABLE memory_artifacts DROP CONSTRAINT IF EXISTS ck_memory_artifacts_scope;
--   ALTER TABLE memory_artifacts DROP COLUMN IF EXISTS scope;
--   ALTER TABLE memory_artifacts DROP COLUMN IF EXISTS pinned;
-- COMMIT;
