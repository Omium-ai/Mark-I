-- m1_091_notification_prefs.sql
-- Opt-in weekly savings email (16-release L3): prefs + unsubscribe token (definer lookup by token), and the digest send ledger.
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_notification_prefs (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id),
  subject       text NOT NULL,
  email         text,
  weekly_digest boolean NOT NULL DEFAULT false,
  unsub_token   text NOT NULL DEFAULT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_m1_notification_prefs_unsub ON m1_notification_prefs (unsub_token);

CREATE TABLE IF NOT EXISTS m1_notification_sends (
  tenant_id    uuid NOT NULL REFERENCES m1_tenants(id),
  subject      text NOT NULL,
  kind         text NOT NULL CHECK (kind IN ('weekly_digest')),
  period_start date NOT NULL,
  outcome      text NOT NULL CHECK (outcome IN ('sending', 'sent', 'failed')),
  delivery_id  text,
  error        text,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject, kind, period_start)
);

ALTER TABLE m1_notification_prefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_notification_prefs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_notification_prefs;
CREATE POLICY tenant_isolation ON m1_notification_prefs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE m1_notification_sends ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_notification_sends FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_notification_sends;
CREATE POLICY tenant_isolation ON m1_notification_sends
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE OR REPLACE FUNCTION m1_notification_unsub_lookup(p_token text)
RETURNS TABLE (pref_tenant uuid, pref_subject text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT tenant_id, subject FROM m1_notification_prefs WHERE unsub_token = p_token
$$;

REVOKE ALL ON m1_notification_prefs FROM PUBLIC;
REVOKE ALL ON m1_notification_sends FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION m1_notification_unsub_lookup(text) FROM PUBLIC;
DO $$
BEGIN
  -- FORCE RLS binds the definer too: its lookup must not hinge on the migration role's BYPASSRLS
  EXECUTE format('DROP POLICY IF EXISTS definer_lookup ON m1_notification_prefs; CREATE POLICY definer_lookup ON m1_notification_prefs FOR SELECT TO %I USING (true)', current_user);
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_notification_prefs TO controld_app;
    GRANT UPDATE (email, weekly_digest, updated_at) ON m1_notification_prefs TO controld_app;
    GRANT EXECUTE ON FUNCTION m1_notification_unsub_lookup(text) TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_notification_prefs TO intel_app;
    GRANT SELECT, INSERT, UPDATE ON m1_notification_sends TO intel_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   DROP FUNCTION IF EXISTS m1_notification_unsub_lookup(text);
--   DROP TABLE IF EXISTS m1_notification_sends;
--   DROP TABLE IF EXISTS m1_notification_prefs;
-- COMMIT;
