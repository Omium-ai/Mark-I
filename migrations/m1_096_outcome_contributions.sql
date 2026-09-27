-- m1_096_outcome_contributions.sql
-- 16 L8: the contribute_outcomes device consent (off by default) and the index of consented uploads; content stays in the t/<tenant>/contributions/v1/ landing object.

BEGIN;

ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS contribute_outcomes boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS m1_outcome_contributions (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  event_id      uuid NOT NULL,
  batch_id      uuid NOT NULL,
  device_id     uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT,
  session_id    uuid NOT NULL,
  task_id       uuid NOT NULL,
  object_key    text NOT NULL CHECK (object_key <> ''),
  received_at   timestamptz NOT NULL DEFAULT now(),
  withdrawn_at  timestamptz,
  deleted_at    timestamptz,
  PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS ix_m1_outcome_contributions_device
  ON m1_outcome_contributions (tenant_id, device_id) WHERE withdrawn_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_m1_outcome_contributions_sweep
  ON m1_outcome_contributions (tenant_id, withdrawn_at) WHERE withdrawn_at IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE m1_outcome_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_outcome_contributions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_outcome_contributions;
CREATE POLICY tenant_isolation ON m1_outcome_contributions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_outcome_contributions FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_outcome_contributions TO controld_app;
    GRANT UPDATE (withdrawn_at, deleted_at) ON m1_outcome_contributions TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_outcome_contributions TO intel_app;
    GRANT SELECT ON m1_quarantined_batches TO intel_app;  -- a rescanned contribution batch is never exported
    GRANT SELECT ON gold_sets, gold_set_members TO intel_app;  -- the human label (m1_086)
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; export the index first, the objects outlive it):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_outcome_contributions;
--   ALTER TABLE m1_device_consents DROP COLUMN IF EXISTS contribute_outcomes;
-- COMMIT;
