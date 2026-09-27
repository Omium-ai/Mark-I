-- m1_099_evidence_attachments.sql
-- 16 L10 E1 evidence path (FR-VERIFY-016, 08 §2.1): the per-task attach index (row before object) and the evidence_deletion receipt class for the 30 d / withdrawal sweep.

BEGIN;

DO $$
DECLARE def text;
BEGIN
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'm1_receipts_record_type_check';
  IF def NOT LIKE '%evidence_deletion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT m1_receipts_record_type_check';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT m1_receipts_record_type_check ' ||
      replace(def, '''quarantine_deletion''::text', '''quarantine_deletion''::text, ''evidence_deletion''::text');
  END IF;
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'ck_m1_receipts_record_shape';
  IF def NOT LIKE '%evidence_deletion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT ck_m1_receipts_record_shape';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT ck_m1_receipts_record_shape ' ||
      replace(def, '''quarantine_deletion''::text', '''quarantine_deletion''::text, ''evidence_deletion''::text');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS m1_evidence_attachments (
  tenant_id           uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  task_id             uuid NOT NULL,
  attachment_name     text NOT NULL CHECK (attachment_name = 'attach.' || task_id::text || '.e1'),
  receipt_id          bytea NOT NULL,
  post_hash           bytea NOT NULL CHECK (octet_length(post_hash) = 32),
  device_id           uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT,
  object_key          text NOT NULL CHECK (object_key <> ''),
  size_bytes          int NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 65536),
  received_at         timestamptz NOT NULL DEFAULT now(),
  withdrawn_at        timestamptz,
  deleted_at          timestamptz,
  deletion_receipt_id uuid,                      -- the evidence_deletion receipt; logical key like m1_080's
  PRIMARY KEY (tenant_id, task_id),
  FOREIGN KEY (tenant_id, receipt_id) REFERENCES m1_redaction_receipts (tenant_id, receipt_id) ON DELETE RESTRICT,
  CONSTRAINT ck_m1_ea_deletion_receipted CHECK ((deleted_at IS NULL) = (deletion_receipt_id IS NULL))
);

CREATE INDEX IF NOT EXISTS ix_m1_evidence_attachments_live
  ON m1_evidence_attachments (tenant_id, received_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_m1_evidence_attachments_device
  ON m1_evidence_attachments (tenant_id, device_id) WHERE withdrawn_at IS NULL AND deleted_at IS NULL;

ALTER TABLE m1_evidence_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_evidence_attachments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_evidence_attachments;
CREATE POLICY tenant_isolation ON m1_evidence_attachments
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE OR REPLACE FUNCTION m1_evidence_attachments_close_once()
RETURNS trigger AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'm1_evidence_attachments: a receipted deletion is final'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.task_id, NEW.attachment_name, NEW.receipt_id, NEW.post_hash, NEW.device_id,
      NEW.object_key, NEW.size_bytes, NEW.received_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.task_id, OLD.attachment_name, OLD.receipt_id, OLD.post_hash, OLD.device_id,
      OLD.object_key, OLD.size_bytes, OLD.received_at) THEN
    RAISE EXCEPTION 'm1_evidence_attachments is append-only outside withdrawn_at/deleted_at/deletion_receipt_id'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1_evidence_attachments_close_once ON m1_evidence_attachments;
CREATE TRIGGER trg_m1_evidence_attachments_close_once
  BEFORE UPDATE ON m1_evidence_attachments
  FOR EACH ROW EXECUTE FUNCTION m1_evidence_attachments_close_once();

DROP TRIGGER IF EXISTS trg_m1_evidence_attachments_no_delete ON m1_evidence_attachments;
CREATE TRIGGER trg_m1_evidence_attachments_no_delete
  BEFORE DELETE ON m1_evidence_attachments
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

REVOKE ALL ON m1_evidence_attachments FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_evidence_attachments TO controld_app;
    GRANT UPDATE (withdrawn_at, deleted_at, deletion_receipt_id) ON m1_evidence_attachments TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; the rows index live evidence objects -- delete those first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_evidence_attachments;
--   DROP FUNCTION IF EXISTS m1_evidence_attachments_close_once();
--   -- the receipt class stays: m1_receipts is append-only and rows may already cite it
-- COMMIT;
