-- m1_082_device_consents.sql
-- The Step-4 consent record (desktop spec §3.2: e1, cloud_judge, training) lives on the
-- device in gates/consents.json; this is its cloud twin, one append-only row per change,
-- relayed by mark1d under the device token (PUT /api/v1/consents, controld ingest). A
-- device speaks for itself only: the latest row per device is that device's state, and
-- the training exporter (intel corpus.export) reads the TENANT as consented only when
-- every device that ever recorded a row currently consents and at least one did -- the
-- fail-closed reading, since corpus_candidates carries no device_id to separate one
-- device's tasks from another's. History rows stay so "was training consented on
-- <date>" is answerable, as m1_065 keeps for the cloud judge.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_device_consents (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES m1_tenants(id),
  device_id    uuid NOT NULL REFERENCES m1_devices(id),
  e1           boolean NOT NULL,
  cloud_judge  boolean NOT NULL,
  training     boolean NOT NULL,
  recorded_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_m1_device_consents_latest
  ON m1_device_consents (tenant_id, device_id, recorded_at DESC);

ALTER TABLE m1_device_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_device_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_device_consents;
CREATE POLICY tenant_isolation ON m1_device_consents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS trg_m1_device_consents_no_update ON m1_device_consents;
CREATE TRIGGER trg_m1_device_consents_no_update
  BEFORE UPDATE ON m1_device_consents
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_device_consents_no_delete ON m1_device_consents;
CREATE TRIGGER trg_m1_device_consents_no_delete
  BEFORE DELETE ON m1_device_consents
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_device_consents_no_truncate ON m1_device_consents;
CREATE TRIGGER trg_m1_device_consents_no_truncate
  BEFORE TRUNCATE ON m1_device_consents
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

REVOKE ALL ON m1_device_consents FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_device_consents TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_device_consents TO intel_app;      -- corpus.export's training gate
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_device_consents TO adjudicator_app; -- the cloud_judge flag beside m1_065
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; drops consent history -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_device_consents;
-- COMMIT;
