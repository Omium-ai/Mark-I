-- m1_002_receipt_chain.sql
-- WHY: every number Mark 1 quotes to a customer (TVO, coverage, verified
-- labels) must be backed by a record we provably cannot rewrite. The design is
-- ro_012's, adopted with its reasoning intact:
--   * per-tenant chain, gap-free seq — a gap MEANS deletion, never "an abort
--     happened", because seq comes from a locked row, not a sequence;
--   * payload is text, NOT jsonb — jsonb is a parsed representation that
--     re-orders keys and re-renders numbers, each harmless to a reader and
--     fatal to a signature over bytes;
--   * append-only three ways — trigger, TRUNCATE trigger, REVOKE — because a
--     control that survives only when a second control catches it has failed;
--   * a discontinuity is a LINK, never a repair.
-- What is new is WHO signs. The device that captured the events signs the
-- checkpoint (origin), and the server countersigns on ingest. Device-only
-- would let Omium disown a receipt ("a device made that up"); server-only
-- would let Omium mint history. Dual signatures close both directions.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- (1) m1_server_signing_keys — the server chain key, with rotation.
-- ---------------------------------------------------------------------------
-- Global, not tenant-scoped: the key signs for Omium, not for a tenant, and
-- every tenant's verifier needs to read it. Rotation inserts a new row and
-- stamps retired_at on the old; retired keys stop signing NEW receipts and are
-- NEVER unpublished — a receipt signed under an unpublished key is a receipt
-- nobody can verify, i.e. one we never issued (ro_012's rule).
CREATE TABLE IF NOT EXISTS m1_server_signing_keys (
  key_id         text PRIMARY KEY,   -- "ed25519:" + first 16 hex of SHA-256(pub); derived, so it cannot lie
  key_algorithm  text NOT NULL DEFAULT 'ed25519' CHECK (key_algorithm = 'ed25519'),
  public_key     bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  retired_at     timestamptz,
  CONSTRAINT ck_m1_skeys_pub_len CHECK (octet_length(public_key) = 32)
);

-- ---------------------------------------------------------------------------
-- (2) m1_receipts — the chain.
-- ---------------------------------------------------------------------------
-- One table for all receipt classes, because one table is what keeps the chain
-- a single unbroken per-tenant sequence. The CHAIN columns are NOT NULL on
-- every row; the class-specific columns are nullable and held to
-- all-or-nothing shapes by ck_m1_receipts_record_shape.
CREATE TABLE IF NOT EXISTS m1_receipts (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES m1_tenants(id),

  -- ---- chain columns: present on every row --------------------------------
  seq                bigint NOT NULL,          -- per-tenant, starts at 1, gap-free (locked head row, see below)
  prev_receipt_hash  bytea NOT NULL,           -- 32 zero bytes at genesis; carried INSIDE the signed payload as hex
  receipt_hash       bytea NOT NULL,           -- SHA-256 of the signing input
  -- The exact bytes canonicalised and signed. text, NOT jsonb — see header.
  payload            text NOT NULL,
  record_type        text NOT NULL CHECK (record_type IN (
                       'checkpoint',
                       'noise_certificate', 'memory_admission',
                       'bundle_publication', 'corpus_export',
                       'coverage_transition', 'guard_contamination',
                       'discontinuity')),
  issued_at          timestamptz NOT NULL DEFAULT now(),

  -- ---- signatures: server always, device on device-originated classes -----
  -- Both signatures are over the SAME signing input (domain prefix ||
  -- canonical payload), so the offline verifier needs one canonicalisation
  -- and two public keys, not two encodings.
  server_key_id      text NOT NULL REFERENCES m1_server_signing_keys(key_id),
  server_signature   bytea NOT NULL,
  device_key_id      text REFERENCES m1_device_keys(key_id),
  device_signature   bytea,

  -- ---- checkpoint columns: present iff record_type = 'checkpoint' ---------
  -- A checkpoint seals a batch of N events / T seconds into a Merkle root.
  -- checkpoint_seq is the tenant's checkpoint counter (also gap-free, advanced
  -- under the same head lock); merkle_root commits to the leaves, which are
  -- the events' UUIDv7 ids + content hashes in spool order.
  checkpoint_seq     bigint,
  merkle_root        bytea,
  event_count        int,

  -- ---- per-event columns: present on the six per-event classes ------------
  -- subject_id is what this receipt attests: the M1P event_id for edge-side
  -- classes, or the registry-row id (cert, artifact, bundle, export) for
  -- server-side acts. Edge-side classes ALSO carry the Merkle inclusion proof
  -- tying the subject event into an already-sealed, device-signed checkpoint:
  -- checkpoint_seq names it, inclusion_path is the concatenated 32-byte
  -- sibling hashes leaf-to-root, leaf_index disambiguates left/right. bytea
  -- rather than bytea[] so octet_length can police it and the verifier reads
  -- one contiguous buffer.
  subject_id         uuid,
  inclusion_path     bytea,
  leaf_index         bigint,

  CONSTRAINT ck_m1_receipts_seq        CHECK (seq > 0),
  -- Length checks rather than domains: a truncated hash that is still "a
  -- bytea" fails verification years later, off-line, indistinguishable from
  -- forgery. Reject it at write time, where the cause is knowable.
  CONSTRAINT ck_m1_receipts_prev_len   CHECK (octet_length(prev_receipt_hash) = 32),
  CONSTRAINT ck_m1_receipts_hash_len   CHECK (octet_length(receipt_hash) = 32),
  CONSTRAINT ck_m1_receipts_ssig_len   CHECK (octet_length(server_signature) = 64),
  CONSTRAINT ck_m1_receipts_dsig_len   CHECK (device_signature IS NULL OR octet_length(device_signature) = 64),
  CONSTRAINT ck_m1_receipts_root_len   CHECK (merkle_root IS NULL OR octet_length(merkle_root) = 32),
  CONSTRAINT ck_m1_receipts_path_len   CHECK (inclusion_path IS NULL OR octet_length(inclusion_path) % 32 = 0),
  CONSTRAINT ck_m1_receipts_leaf_idx   CHECK (leaf_index IS NULL OR leaf_index >= 0),
  CONSTRAINT ck_m1_receipts_count      CHECK (event_count IS NULL OR event_count > 0),
  CONSTRAINT ck_m1_receipts_payload_json CHECK (payload::jsonb IS NOT NULL),
  -- Genesis equivalence, verbatim from ro_012: seq 1 is the only row that MAY
  -- point at nothing and the only row ALLOWED to. The one-way implication
  -- would permit a mid-chain row claiming to start a chain — the exact shape
  -- a truncation leaves when the surviving tail should look like a whole
  -- history.
  CONSTRAINT ck_m1_receipts_genesis
    CHECK ((seq = 1) = (prev_receipt_hash = '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)),
  -- Dual-signing shape: the three classes that ORIGINATE on the device carry
  -- the device signature; the rest are server acts. Equivalence, not
  -- implication, so a server act cannot dress up as device-attested.
  CONSTRAINT ck_m1_receipts_origin
    CHECK ((record_type IN ('checkpoint', 'coverage_transition', 'guard_contamination'))
           = (device_key_id IS NOT NULL AND device_signature IS NOT NULL)),
  -- All-or-nothing record shapes, one arm per class family, explicit column
  -- lists so nothing can wear half of another class's clothes.
  CONSTRAINT ck_m1_receipts_record_shape CHECK (
    (record_type = 'checkpoint'
      AND checkpoint_seq IS NOT NULL AND checkpoint_seq > 0
      AND merkle_root IS NOT NULL AND event_count IS NOT NULL
      AND subject_id IS NULL AND inclusion_path IS NULL AND leaf_index IS NULL)
    OR
    (record_type IN ('coverage_transition', 'guard_contamination')
      AND subject_id IS NOT NULL AND checkpoint_seq IS NOT NULL
      AND inclusion_path IS NOT NULL AND leaf_index IS NOT NULL
      AND merkle_root IS NULL AND event_count IS NULL)
    OR
    (record_type IN ('noise_certificate', 'memory_admission',
                     'bundle_publication', 'corpus_export')
      AND subject_id IS NOT NULL
      AND checkpoint_seq IS NULL AND inclusion_path IS NULL AND leaf_index IS NULL
      AND merkle_root IS NULL AND event_count IS NULL)
    OR
    (record_type = 'discontinuity'
      AND subject_id IS NULL AND checkpoint_seq IS NULL AND inclusion_path IS NULL
      AND leaf_index IS NULL AND merkle_root IS NULL AND event_count IS NULL)
  ),

  -- Two receipts claiming one position is the ambiguity the structure exists
  -- to exclude; refused by the database, not merely by the head lock.
  CONSTRAINT uq_m1_receipts_tenant_seq UNIQUE (tenant_id, seq),
  -- Globally unique: payload contains tenant_id and seq, so a collision is a
  -- canonicalisation bug or SHA-256 breaking. Both should stop the write.
  CONSTRAINT uq_m1_receipts_hash       UNIQUE (receipt_hash)
);

ALTER TABLE m1_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_receipts;
CREATE POLICY tenant_isolation ON m1_receipts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Checkpoint numbering is unique per tenant (gap-freedom comes from the head
-- lock; uniqueness is proven here), and it is the witness/inclusion lookup.
CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_receipts_checkpoint
  ON m1_receipts (tenant_id, checkpoint_seq)
  WHERE record_type = 'checkpoint';
-- "find the receipt for this cert / artifact / bundle / export / event".
CREATE INDEX IF NOT EXISTS ix_m1_receipts_subject
  ON m1_receipts (tenant_id, subject_id)
  WHERE subject_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- (3) m1_receipt_chain_head — the per-tenant serialization point.
-- ---------------------------------------------------------------------------
-- ro_012's locked row, with checkpoint_seq added so BOTH counters advance
-- under the one lock. NOT a cache of MAX(seq): it is the lock itself. Append =
-- SELECT ... FOR UPDATE, build+sign at seq+1, INSERT, UPDATE head, COMMIT.
CREATE TABLE IF NOT EXISTS m1_receipt_chain_head (
  tenant_id       uuid PRIMARY KEY REFERENCES m1_tenants(id),
  -- 0-with-genesis-hash rather than NULL, so the first append — the path
  -- least tested and most exercised for a brand-new customer — has no
  -- special case.
  seq             bigint NOT NULL DEFAULT 0,
  head_hash       bytea  NOT NULL
                    DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
  checkpoint_seq  bigint NOT NULL DEFAULT 0,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_m1_head_seq      CHECK (seq >= 0),
  CONSTRAINT ck_m1_head_ckpt     CHECK (checkpoint_seq >= 0),
  CONSTRAINT ck_m1_head_hash_len CHECK (octet_length(head_hash) = 32)
);

ALTER TABLE m1_receipt_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_receipt_chain_head FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_receipt_chain_head;
CREATE POLICY tenant_isolation ON m1_receipt_chain_head
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- (4) Append-only enforcement — ro_012's three layers, verbatim in intent.
-- ---------------------------------------------------------------------------
-- (a) REVOKE from PUBLIC and from the migration's own role (a speed bump);
-- (b) BEFORE UPDATE/DELETE row trigger (the one that holds);
-- (c) BEFORE TRUNCATE statement trigger, because row triggers do not fire on
--     TRUNCATE and TRUNCATE is the one-statement eraser.
-- The head is deliberately NOT append-only: advancing it is an UPDATE, and
-- that is its entire job; it is a pointer recomputable from the chain, not a
-- record. Compelled erasure must DISABLE TRIGGER out loud and then append a
-- record_type='discontinuity' receipt naming the last known-good (seq, hash) —
-- the erasure is defensible, the silence is not.
-- The function is generic on purpose: m1_003 reuses it for witness heads.
CREATE OR REPLACE FUNCTION m1_append_only()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION
    '% is append-only; % is not permitted', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege',
          HINT = 'Erasure must DISABLE TRIGGER explicitly and then append a discontinuity receipt (m1_002 header).';
  RETURN NULL;  -- unreachable; keeps plpgsql from reporting a missing RETURN
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1r_append_only ON m1_receipts;
CREATE TRIGGER trg_m1r_append_only
  BEFORE UPDATE OR DELETE ON m1_receipts
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1r_no_truncate ON m1_receipts;
CREATE TRIGGER trg_m1r_no_truncate
  BEFORE TRUNCATE ON m1_receipts
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

REVOKE UPDATE, DELETE, TRUNCATE ON m1_receipts FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON m1_receipt_chain_head FROM PUBLIC;

DO $$
BEGIN
  EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON m1_receipts FROM %I', current_user);
  EXECUTE format('REVOKE DELETE, TRUNCATE ON m1_receipt_chain_head FROM %I', current_user);
END $$;

-- ---------------------------------------------------------------------------
-- (5) Grants. ONE writer: every append flows through controld, which holds
-- the head lock and the server key. adjudicator/intel REQUEST receipts over
-- controld's internal API and only ever read this table — a service that
-- could append receipts about its own output could certify itself.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT         ON m1_receipts           TO controld_app;
    GRANT SELECT, INSERT, UPDATE ON m1_receipt_chain_head TO controld_app;
    GRANT SELECT, INSERT, UPDATE ON m1_server_signing_keys TO controld_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON m1_receipts           FROM controld_app;
    REVOKE DELETE, TRUNCATE         ON m1_receipt_chain_head FROM controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_receipts, m1_server_signing_keys TO adjudicator_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_receipts, m1_server_signing_keys TO intel_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- Dropping these tables destroys every attestation ever issued and is NOT
-- recoverable by re-capture: receipts are signed statements about moments
-- that have passed. Export every tenant's chain first.
-- BEGIN;
--   DROP TABLE IF EXISTS m1_receipts CASCADE;
--   DROP TABLE IF EXISTS m1_receipt_chain_head CASCADE;
--   DROP TABLE IF EXISTS m1_server_signing_keys CASCADE;
--   DROP FUNCTION IF EXISTS m1_append_only();
-- COMMIT;
