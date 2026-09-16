-- m1_072_receipt_idempotency_key.sql
-- The caller's attempt identity for receipts requested over controld's internal append
-- route (m1_002 §5: adjudicator/intel REQUEST receipts). A retried job presents the same
-- key and gets the same receipt; a NEW act on an old subject (re-admission after retire,
-- a cert re-issued after demotion) presents a new key and gets a new link. A row fact
-- like server_key_id, never inside the signed payload; NULL on every pre-existing row.

BEGIN;

ALTER TABLE m1_receipts ADD COLUMN IF NOT EXISTS idempotency_key text
  CONSTRAINT ck_m1_receipts_idem_key
    CHECK (idempotency_key IS NULL OR (idempotency_key <> '' AND octet_length(idempotency_key) <= 200));

CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_receipts_idempotency
  ON m1_receipts (tenant_id, record_type, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP INDEX IF EXISTS uq_m1_receipts_idempotency;
--   ALTER TABLE m1_receipts DROP COLUMN IF EXISTS idempotency_key;
-- COMMIT;
