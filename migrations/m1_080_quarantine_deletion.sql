-- m1_080_quarantine_deletion.sql
-- Founder ruling 2026-09-16 (D-EI; NFR-OPERABILITY-003): quarantine retention is 30 days,
-- then delete, receipted in the chain. (1) The `quarantine_deletion` receipt class: a server
-- act whose subject_id is the batch_id, written by controld twice over -- stage 11 persists
-- the edge's device-signed on-disk receipt (QuarantineDeletion, envelope arm 23) after
-- verifying the signature, origin='edge'; the daily cloud sweep receipts its own S3
-- deletion, origin='cloud'. Additive CHECK rewrite in m1_069's style. (2) The tombstone
-- m1_quarantined_batches, inserted in the request path that lands the S3 twin (05 §2.3), so
-- the never-replay marker is a row and not the object's existence (07 §S3 layout); closed
-- exactly once, in the same transaction as the receipt.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
DECLARE def text;
BEGIN
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'm1_receipts_record_type_check';
  IF def NOT LIKE '%quarantine_deletion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT m1_receipts_record_type_check';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT m1_receipts_record_type_check ' ||
      replace(def, '''corpus_export''::text', '''corpus_export''::text, ''quarantine_deletion''::text');
  END IF;
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'ck_m1_receipts_record_shape';
  IF def NOT LIKE '%quarantine_deletion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT ck_m1_receipts_record_shape';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT ck_m1_receipts_record_shape ' ||
      replace(def, '''corpus_export''::text', '''corpus_export''::text, ''quarantine_deletion''::text');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS m1_quarantined_batches (
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  batch_id       uuid NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now(),
  object_key     text NOT NULL CHECK (object_key <> ''),
  event_count    int NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  deleted_at     timestamptz,
  receipt_id     uuid,                          -- the quarantine_deletion receipt; logical key like m1_043/m1_069 (an FK would pre-empt m1_receipts' append-only trigger)
  PRIMARY KEY (tenant_id, batch_id),
  -- A deletion is recorded only with its receipt; neither half alone.
  CONSTRAINT ck_m1_qb_deletion_receipted CHECK ((deleted_at IS NULL) = (receipt_id IS NULL))
);

CREATE INDEX IF NOT EXISTS ix_m1_quarantined_batches_pending
  ON m1_quarantined_batches (tenant_id, quarantined_at) WHERE deleted_at IS NULL;

ALTER TABLE m1_quarantined_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_quarantined_batches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_quarantined_batches;
CREATE POLICY tenant_isolation ON m1_quarantined_batches
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- The tombstone is written once and closed once: only deleted_at/receipt_id may change,
-- and only from NULL.
CREATE OR REPLACE FUNCTION m1_quarantined_batches_close_once()
RETURNS trigger AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'm1_quarantined_batches: a receipted deletion is final'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.batch_id, NEW.quarantined_at, NEW.object_key, NEW.event_count)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.batch_id, OLD.quarantined_at, OLD.object_key, OLD.event_count) THEN
    RAISE EXCEPTION 'm1_quarantined_batches is append-only outside deleted_at/receipt_id'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1_quarantined_batches_close_once ON m1_quarantined_batches;
CREATE TRIGGER trg_m1_quarantined_batches_close_once
  BEFORE UPDATE ON m1_quarantined_batches
  FOR EACH ROW EXECUTE FUNCTION m1_quarantined_batches_close_once();

DROP TRIGGER IF EXISTS trg_m1_quarantined_batches_no_delete ON m1_quarantined_batches;
CREATE TRIGGER trg_m1_quarantined_batches_no_delete
  BEFORE DELETE ON m1_quarantined_batches
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_quarantined_batches_no_truncate ON m1_quarantined_batches;
CREATE TRIGGER trg_m1_quarantined_batches_no_truncate
  BEFORE TRUNCATE ON m1_quarantined_batches
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

REVOKE ALL ON m1_quarantined_batches FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE (deleted_at, receipt_id) ON m1_quarantined_batches TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; the tombstones are the never-replay markers -- export them first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_quarantined_batches;
--   DROP FUNCTION IF EXISTS m1_quarantined_batches_close_once();
--   -- the receipt class stays: m1_receipts is append-only and rows may already cite it
-- COMMIT;
