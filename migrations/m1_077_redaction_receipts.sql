-- m1_077_redaction_receipts.sql
-- The redaction receipt behind every E1 excerpt (FR-VERIFY-016; 10 §10.4 C-50 "every
-- excerpt upload receipted"). One row per receipt the device signed over
-- {pre_hash, post_hash, classes, span_digests} for one evidence event: payload is the
-- exact canonical bytes the device signature covers (DomainPrefix || payload, the
-- m1_002 signing input), receipt_id is sha256 over that input and is what
-- EvidenceExcerpt.redaction_receipt_id carries on the wire. Rows are written by
-- controld when the attach upload (08 §2.1) presents the receipt beside the sanitized
-- part, and bound once -- excerpt_event_id -- when the excerpt naming the receipt
-- lands (ingest stage 11). An excerpt whose receipt is absent, belongs to another
-- device, or names a different subject is refused there and stays unbound; the
-- adjudicator's readers serve only bound receipts.
--
-- Not a chain link: 07's per-event classes are rare by design and a device-origin
-- per-event link has no server writer yet (coverage_transition, guard_contamination
-- are in the same state). The receipt is still verifiable offline under the
-- published device key exactly like a checkpoint's origin half.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_redaction_receipts (
  tenant_id         uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  receipt_id        bytea NOT NULL CHECK (octet_length(receipt_id) = 32),
  device_id         uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT,
  device_key_id     text NOT NULL REFERENCES m1_device_keys(key_id),
  device_signature  bytea NOT NULL CHECK (octet_length(device_signature) = 64),
  subject_id        uuid NOT NULL,                -- the evidence event the excerpt expands
  payload           text NOT NULL CHECK (payload::jsonb IS NOT NULL),
  pre_hash          bytea NOT NULL CHECK (octet_length(pre_hash) = 32),
  post_hash         bytea NOT NULL CHECK (octet_length(post_hash) = 32),
  excerpt_event_id  uuid,                         -- bound once, at ingest, to the EvidenceExcerpt event
  received_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, receipt_id)
);

CREATE INDEX IF NOT EXISTS ix_m1_redaction_receipts_excerpt
  ON m1_redaction_receipts (tenant_id, excerpt_event_id) WHERE excerpt_event_id IS NOT NULL;

ALTER TABLE m1_redaction_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_redaction_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_redaction_receipts;
CREATE POLICY tenant_isolation ON m1_redaction_receipts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- The binding is write-once; everything else on the row is the signed record.
CREATE OR REPLACE FUNCTION m1_redaction_receipts_bind_once()
RETURNS trigger AS $$
BEGIN
  IF OLD.excerpt_event_id IS NOT NULL AND NEW.excerpt_event_id IS DISTINCT FROM OLD.excerpt_event_id THEN
    RAISE EXCEPTION 'm1_redaction_receipts.excerpt_event_id is bound once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.receipt_id, NEW.device_id, NEW.device_key_id, NEW.device_signature,
      NEW.subject_id, NEW.payload, NEW.pre_hash, NEW.post_hash, NEW.received_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.receipt_id, OLD.device_id, OLD.device_key_id, OLD.device_signature,
      OLD.subject_id, OLD.payload, OLD.pre_hash, OLD.post_hash, OLD.received_at) THEN
    RAISE EXCEPTION 'm1_redaction_receipts is append-only outside excerpt_event_id'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1_redaction_receipts_bind_once ON m1_redaction_receipts;
CREATE TRIGGER trg_m1_redaction_receipts_bind_once
  BEFORE UPDATE ON m1_redaction_receipts
  FOR EACH ROW EXECUTE FUNCTION m1_redaction_receipts_bind_once();

DROP TRIGGER IF EXISTS trg_m1_redaction_receipts_no_delete ON m1_redaction_receipts;
CREATE TRIGGER trg_m1_redaction_receipts_no_delete
  BEFORE DELETE ON m1_redaction_receipts
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_redaction_receipts_no_truncate ON m1_redaction_receipts;
CREATE TRIGGER trg_m1_redaction_receipts_no_truncate
  BEFORE TRUNCATE ON m1_redaction_receipts
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

REVOKE ALL ON m1_redaction_receipts FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE (excerpt_event_id) ON m1_redaction_receipts TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_redaction_receipts TO adjudicator_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; drops the only proof the scrub ran -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_redaction_receipts;
--   DROP FUNCTION IF EXISTS m1_redaction_receipts_bind_once();
-- COMMIT;
