-- m1_084_tenant_directory.sql
-- The job schedulers enumerate tenants from the database, not from a static list.
--
-- WHY. The intel and adjudicator CronJobs took every tenant as a `--tenant`
-- argument rendered from a Helm value (05 §7.3's pilot list). Every tenant a
-- desktop sign-in creates after that list was written got no rollup, no memory
-- job, no adjudication — 50 testers, three rows on the list. m1_tenants cannot
-- be enumerated at runtime: FORCE RLS admits exactly the id in the GUC, for the
-- owner too. So the lifecycle facts of every tenant — id, status, kind — are
-- mirrored into a GLOBAL directory (the m1_organizations / m1_schema_versions
-- posture: not tenant-scoped, holds no tenant data) by a trigger on
-- m1_tenants, and the schedulers read that.
--
-- The trigger function is SECURITY DEFINER (runs as this file's role, the table
-- owner) so the request-path role that inserts a personal tenant needs no
-- write grant on the directory. The backfill below runs as the migration role
-- (the RDS master, which bypasses RLS); in a cluster whose migration role does
-- not, the directory fills as tenants are next touched.

CREATE TABLE IF NOT EXISTS m1_tenant_directory (
  tenant_id   uuid PRIMARY KEY,
  status      text NOT NULL,
  kind        text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION trg_m1_tenant_directory() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  INSERT INTO m1_tenant_directory (tenant_id, status, kind, updated_at)
  VALUES (NEW.id, NEW.status, NEW.kind, now())
  ON CONFLICT (tenant_id) DO UPDATE SET status = EXCLUDED.status, kind = EXCLUDED.kind, updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS m1_tenant_directory_sync ON m1_tenants;
CREATE TRIGGER m1_tenant_directory_sync
  AFTER INSERT OR UPDATE OF status, kind ON m1_tenants
  FOR EACH ROW EXECUTE FUNCTION trg_m1_tenant_directory();

INSERT INTO m1_tenant_directory (tenant_id, status, kind)
SELECT id, status, kind FROM m1_tenants
ON CONFLICT (tenant_id) DO UPDATE SET status = EXCLUDED.status, kind = EXCLUDED.kind, updated_at = now();

REVOKE ALL ON m1_tenant_directory FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_tenant_directory TO intel_app;       -- `app.jobs run --tenant all`
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_tenant_directory TO adjudicator_app; -- its jobs twin
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON m1_tenant_directory TO controld_app;    -- the witness's tenant set, later
  END IF;
END $$;
