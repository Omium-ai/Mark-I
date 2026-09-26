-- m1_090_teams.sql
-- Teams v1 (docs/design/15-teams.md): membership, invite acceptance, the team consent,
-- artifact ownership, and device keys unique per tenant so one daemon key re-enrolls
-- into its team tenant and back (the receipt FKs follow the key to (tenant_id, key_id)).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_team_members (
  tenant_id  uuid NOT NULL REFERENCES m1_tenants(id),
  subject    text NOT NULL,
  email      text,
  role       text NOT NULL CHECK (role IN ('owner', 'member')),
  joined_at  timestamptz NOT NULL DEFAULT now(),
  left_at    timestamptz,
  PRIMARY KEY (tenant_id, subject)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_m1_team_members_one_active
  ON m1_team_members (subject) WHERE left_at IS NULL AND role = 'member';

ALTER TABLE m1_team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_team_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_team_members;
CREATE POLICY tenant_isolation ON m1_team_members
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE m1_team_invites ADD COLUMN IF NOT EXISTS accepted_by text;
ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS team boolean NOT NULL DEFAULT false;
ALTER TABLE memory_artifacts ADD COLUMN IF NOT EXISTS owner_subject text;

-- the enrollment subject of the provenance device (revoked devices keep who enrolled them), else the tenant owner; NULL = owner-only
UPDATE memory_artifacts a
   SET owner_subject = COALESCE((
         SELECT e.oidc_subject FROM m1_device_enrollments e
          WHERE e.tenant_id = a.tenant_id AND e.oidc_subject IS NOT NULL
            AND e.device_id::text = a.body->'provenance'->>'device_id'
          ORDER BY e.started_at DESC LIMIT 1), t.owner_subject)
  FROM m1_tenants t
 WHERE t.id = a.tenant_id AND a.owner_subject IS NULL;

ALTER TABLE m1_receipts DROP CONSTRAINT IF EXISTS fk_m1_receipts_device_key;
ALTER TABLE m1_redaction_receipts DROP CONSTRAINT IF EXISTS fk_m1_redaction_receipts_device_key;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.conrelid::regclass AS tbl, c.conname FROM pg_constraint c
            WHERE c.contype = 'f' AND c.confrelid = 'm1_device_keys'::regclass
              AND c.conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = c.conrelid AND attname = 'device_key_id')]::int2[] LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.tbl, r.conname);
  END LOOP;
END $$;
ALTER TABLE m1_device_keys DROP CONSTRAINT IF EXISTS uq_m1_dkeys_tenant_key_id;
ALTER TABLE m1_device_keys ADD CONSTRAINT uq_m1_dkeys_tenant_key_id UNIQUE (tenant_id, key_id);
ALTER TABLE m1_receipts ADD CONSTRAINT fk_m1_receipts_device_key
  FOREIGN KEY (tenant_id, device_key_id) REFERENCES m1_device_keys (tenant_id, key_id);
ALTER TABLE m1_redaction_receipts ADD CONSTRAINT fk_m1_redaction_receipts_device_key
  FOREIGN KEY (tenant_id, device_key_id) REFERENCES m1_device_keys (tenant_id, key_id);
ALTER TABLE m1_device_keys DROP CONSTRAINT IF EXISTS uq_m1_dkeys_key_id;

CREATE OR REPLACE FUNCTION m1_team_effective_tenant(p_subject text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT tenant_id FROM m1_team_members WHERE subject = p_subject AND role = 'member' AND left_at IS NULL
$$;

CREATE OR REPLACE FUNCTION m1_team_invite_lookup(p_hash bytea)
RETURNS TABLE (invite_id uuid, invite_tenant uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT id, tenant_id FROM m1_team_invites WHERE token_hash = p_hash AND accepted_at IS NULL AND expires_at > now()
$$;

REVOKE ALL ON m1_team_members FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION m1_team_effective_tenant(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION m1_team_invite_lookup(bytea) FROM PUBLIC;
DO $$
BEGIN
  -- the definers' own read path: FORCE RLS binds the owner too, so the two lookups must not hinge on the migration role's BYPASSRLS
  EXECUTE format('DROP POLICY IF EXISTS definer_lookup ON m1_team_members; CREATE POLICY definer_lookup ON m1_team_members FOR SELECT TO %I USING (true)', current_user);
  EXECUTE format('DROP POLICY IF EXISTS definer_lookup ON m1_team_invites; CREATE POLICY definer_lookup ON m1_team_invites FOR SELECT TO %I USING (true)', current_user);
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_team_members TO controld_app;
    GRANT UPDATE (accepted_at, accepted_by, expires_at) ON m1_team_invites TO controld_app; -- expires_at: an owner who joins another team retires their unused invites
    GRANT EXECUTE ON FUNCTION m1_team_effective_tenant(text), m1_team_invite_lookup(bytea) TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_team_members TO intel_app;
    GRANT SELECT (tenant_id, device_id, oidc_subject, status, started_at) ON m1_device_enrollments TO intel_app; -- device -> owner_subject
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; the global key_id unique refuses while one key backs two tenants):
-- BEGIN;
--   DROP FUNCTION IF EXISTS m1_team_invite_lookup(bytea);
--   DROP FUNCTION IF EXISTS m1_team_effective_tenant(text);
--   ALTER TABLE m1_device_keys ADD CONSTRAINT uq_m1_dkeys_key_id UNIQUE (key_id);
--   ALTER TABLE m1_redaction_receipts DROP CONSTRAINT IF EXISTS fk_m1_redaction_receipts_device_key;
--   ALTER TABLE m1_redaction_receipts ADD FOREIGN KEY (device_key_id) REFERENCES m1_device_keys(key_id);
--   ALTER TABLE m1_receipts DROP CONSTRAINT IF EXISTS fk_m1_receipts_device_key;
--   ALTER TABLE m1_receipts ADD FOREIGN KEY (device_key_id) REFERENCES m1_device_keys(key_id);
--   ALTER TABLE m1_device_keys DROP CONSTRAINT IF EXISTS uq_m1_dkeys_tenant_key_id;
--   DROP POLICY IF EXISTS definer_lookup ON m1_team_invites;
--   ALTER TABLE memory_artifacts DROP COLUMN IF EXISTS owner_subject;
--   ALTER TABLE m1_device_consents DROP COLUMN IF EXISTS team;
--   ALTER TABLE m1_team_invites DROP COLUMN IF EXISTS accepted_by;
--   DROP TABLE IF EXISTS m1_team_members;
-- COMMIT;
