-- m1_083_checkpoint_leaves.sql
-- The per-device set of landed leaves a checkpoint seals (05 §2.1 stage 11), durable and shared.
-- It lived in controld memory (sidefx pending[]); at replicas: 2 each pod held half of every
-- device's leaves and every checkpoint refused as merkle_mismatch (555 security rows on the
-- founder's tenant in one day, "Server pending" on every receipt in the app). Order is the
-- device's spool order: batch_id is the device-minted UUIDv7 of the upload (monotonic per
-- device) and idx the event's place in it — arrival order across pods is not spool order.
-- A leaf stays after its seal with consumed_seq set so a replayed batch cannot re-enter it.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_checkpoint_leaves (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id),
  device_id     uuid NOT NULL,
  batch_id      uuid NOT NULL,
  idx           integer NOT NULL CHECK (idx >= 0),
  event_id      uuid NOT NULL,
  coverage      jsonb,
  deletion      jsonb,
  landed_at     timestamptz NOT NULL DEFAULT now(),
  consumed_seq  bigint,
  PRIMARY KEY (tenant_id, device_id, event_id)
);

CREATE INDEX IF NOT EXISTS ix_m1_checkpoint_leaves_window
  ON m1_checkpoint_leaves (tenant_id, device_id, batch_id, idx)
  WHERE consumed_seq IS NULL;

CREATE INDEX IF NOT EXISTS ix_m1_checkpoint_leaves_sweep
  ON m1_checkpoint_leaves (landed_at)
  WHERE consumed_seq IS NOT NULL;

ALTER TABLE m1_checkpoint_leaves ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_checkpoint_leaves FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_checkpoint_leaves;
CREATE POLICY tenant_isolation ON m1_checkpoint_leaves
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_checkpoint_leaves FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON m1_checkpoint_leaves TO controld_app;
  END IF;
END $$;

COMMIT;
