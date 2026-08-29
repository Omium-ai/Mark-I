-- m1_003_witness_heads.sql
-- WHY: this table is Omium's OWN record of what it published where. It is not
-- the evidence — the evidence is the copy in the log and in the customer's
-- bucket, which is the point: those are the two places Omium cannot edit. The
-- row exists so support and the verifier can find the external copies, and so
-- a publication gap is a queryable fact rather than a silent one. The witness
-- job publishes FIRST and inserts AFTER, so every row records a completed
-- publication; a failed hour is a missing row, which the hourly cadence makes
-- visible. Rows are append-only for the same reason receipts are.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_witness_heads (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES m1_tenants(id),

  -- The witnessed facts: head (seq, hash) and checkpoint counter at the
  -- moment of signing. seq > 0 because an empty chain has nothing to witness.
  witnessed_seq         bigint NOT NULL CHECK (witnessed_seq > 0),
  witnessed_hash        bytea  NOT NULL,
  witnessed_checkpoint_seq bigint NOT NULL CHECK (witnessed_checkpoint_seq >= 0),
  witnessed_at          timestamptz NOT NULL DEFAULT now(),

  -- The exact canonical bytes that were signed and published — text, not
  -- jsonb, for the same signature-over-bytes reason as m1_receipts.payload.
  -- Contains tenant_id, seq, hash, checkpoint_seq, witnessed_at; domain
  -- prefix "mark1-witness-v1\0" so a witness statement can never be replayed
  -- as a receipt or vice versa.
  statement             text NOT NULL,
  server_key_id         text NOT NULL REFERENCES m1_server_signing_keys(key_id),
  server_signature      bytea NOT NULL,

  -- Destination 1: the transparency log. Index + the log's inclusion proof,
  -- stored as the log returns it (text: proof formats are the log's contract,
  -- not ours — parsing it into columns would break on the log's next version).
  log_backend           text,      -- e.g. 'rekor'; names which log to ask
  log_entry_index       bigint,
  log_inclusion_proof   text,

  -- Destination 2: the customer's object-lock bucket. URI + etag + the
  -- retention horizon the object was locked under; retain_until is what turns
  -- "we uploaded it" into "nobody, including the bucket owner, can remove it
  -- before this date".
  object_bucket_uri     text,
  object_etag           text,
  object_retain_until   timestamptz,

  CONSTRAINT ck_m1_wh_hash_len CHECK (octet_length(witnessed_hash) = 32),
  CONSTRAINT ck_m1_wh_sig_len  CHECK (octet_length(server_signature) = 64),
  CONSTRAINT ck_m1_wh_statement_json CHECK (statement::jsonb IS NOT NULL),
  -- Each destination is all-or-nothing, and at least one must be present: a
  -- witness row that witnesses to nowhere is a log line, not a control.
  CONSTRAINT ck_m1_wh_log_shape
    CHECK ((log_backend IS NULL) = (log_entry_index IS NULL)
           AND (log_backend IS NULL) = (log_inclusion_proof IS NULL)),
  CONSTRAINT ck_m1_wh_object_shape
    CHECK ((object_bucket_uri IS NULL) = (object_etag IS NULL)
           AND (object_bucket_uri IS NULL) = (object_retain_until IS NULL)),
  CONSTRAINT ck_m1_wh_some_destination
    CHECK (log_backend IS NOT NULL OR object_bucket_uri IS NOT NULL)
);

ALTER TABLE m1_witness_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_witness_heads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_witness_heads;
CREATE POLICY tenant_isolation ON m1_witness_heads
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- "latest witness for this tenant" and "witness history around timestamp T"
-- are the verifier's two queries.
CREATE INDEX IF NOT EXISTS ix_m1_wh_tenant_time
  ON m1_witness_heads (tenant_id, witnessed_at DESC);

-- Append-only, same three layers as m1_receipts, reusing m1_002's function.
DROP TRIGGER IF EXISTS trg_m1wh_append_only ON m1_witness_heads;
CREATE TRIGGER trg_m1wh_append_only
  BEFORE UPDATE OR DELETE ON m1_witness_heads
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1wh_no_truncate ON m1_witness_heads;
CREATE TRIGGER trg_m1wh_no_truncate
  BEFORE TRUNCATE ON m1_witness_heads
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

REVOKE UPDATE, DELETE, TRUNCATE ON m1_witness_heads FROM PUBLIC;
DO $$
BEGIN
  EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON m1_witness_heads FROM %I', current_user);
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_witness_heads TO controld_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON m1_witness_heads FROM controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_witness_heads TO intel_app;  -- reports cite witness coverage
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; the external copies survive regardless,
-- which is the design working):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_witness_heads CASCADE;
-- COMMIT;
