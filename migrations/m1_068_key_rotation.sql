-- m1_068_key_rotation.sql
-- ADR-0004's rotation cross-sign chain, as schema: (1) a server chain key may
-- carry its predecessor's endorsement and a retirement stamp; (2) the retiring
-- key's LAST receipt on a tenant chain is a `key_rotation` record naming the
-- successor; (3) the key manifest is a transparency-log leaf kind
-- (m1_062 already admits 'key_manifest') whose logged bytes are kept here so
-- the leaf hash is matchable to a document. Numbered after m1_060 for the
-- reason m1_062's header gives: grants must land after the roles exist.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- ---------------------------------------------------------------------------
-- (1) m1_server_signing_keys: the cross-sign chain.
-- ---------------------------------------------------------------------------
-- cross_signature is the retiring key's Ed25519 signature over
-- "mark1-key-rotation-v1\0" || 'server_chain' || 0x00 || successor public key
-- (receipts.CrossSignInput). Both columns or neither; a key never endorses
-- itself. The first key of a deployment has no predecessor and stays NULL.
ALTER TABLE m1_server_signing_keys
  ADD COLUMN IF NOT EXISTS cross_signed_by text REFERENCES m1_server_signing_keys(key_id),
  ADD COLUMN IF NOT EXISTS cross_signature bytea;
ALTER TABLE m1_server_signing_keys DROP CONSTRAINT IF EXISTS ck_m1_skeys_cross_sign;
ALTER TABLE m1_server_signing_keys ADD CONSTRAINT ck_m1_skeys_cross_sign CHECK (
  (cross_signed_by IS NULL) = (cross_signature IS NULL)
  AND (cross_signature IS NULL OR octet_length(cross_signature) = 64)
  AND (cross_signed_by IS NULL OR cross_signed_by <> key_id)
);

-- ---------------------------------------------------------------------------
-- (2) m1_receipts: the key_rotation record class (server act, subject = the
--     successor key's UUIDv5, payload carries successor_key_id).
-- ---------------------------------------------------------------------------
ALTER TABLE m1_receipts DROP CONSTRAINT IF EXISTS m1_receipts_record_type_check;
ALTER TABLE m1_receipts ADD CONSTRAINT m1_receipts_record_type_check CHECK (record_type IN (
  'checkpoint',
  'noise_certificate', 'memory_admission',
  'bundle_publication', 'corpus_export', 'key_rotation',
  'coverage_transition', 'guard_contamination',
  'discontinuity'));

ALTER TABLE m1_receipts DROP CONSTRAINT IF EXISTS ck_m1_receipts_record_shape;
ALTER TABLE m1_receipts ADD CONSTRAINT ck_m1_receipts_record_shape CHECK (
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
                   'bundle_publication', 'corpus_export', 'key_rotation')
    AND subject_id IS NOT NULL
    AND checkpoint_seq IS NULL AND inclusion_path IS NULL AND leaf_index IS NULL
    AND merkle_root IS NULL AND event_count IS NULL)
  OR
  (record_type = 'discontinuity'
    AND subject_id IS NULL AND checkpoint_seq IS NULL AND inclusion_path IS NULL
    AND leaf_index IS NULL AND merkle_root IS NULL AND event_count IS NULL)
);

-- ---------------------------------------------------------------------------
-- (3) key_manifests: the logged bytes behind every 'key_manifest' leaf.
-- ---------------------------------------------------------------------------
-- body is canonical JSON (receipts.CanonicalJSON) and body_sha256 is the
-- tlog leaf preimage, exactly as policy_bundles.body_sha256 is for bundles.
-- Per tenant because the log is (m1_062); one manifest is appended to every
-- tenant's log at publication.
CREATE TABLE IF NOT EXISTS key_manifests (
  tenant_id    uuid   NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  tlog_index   bigint NOT NULL,
  body         text   NOT NULL,
  body_sha256  bytea  NOT NULL CHECK (octet_length(body_sha256) = 32),
  tlog_proof   jsonb  NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, tlog_index),
  FOREIGN KEY (tenant_id, tlog_index) REFERENCES tlog_leaves(tenant_id, leaf_index)
);

DROP TRIGGER IF EXISTS key_manifests_no_update_delete ON key_manifests;
CREATE TRIGGER key_manifests_no_update_delete
  BEFORE UPDATE OR DELETE ON key_manifests
  FOR EACH ROW EXECUTE FUNCTION trg_tlog_append_only();
DROP TRIGGER IF EXISTS key_manifests_no_truncate ON key_manifests;
CREATE TRIGGER key_manifests_no_truncate
  BEFORE TRUNCATE ON key_manifests
  FOR EACH STATEMENT EXECUTE FUNCTION trg_tlog_append_only();

ALTER TABLE key_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_manifests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON key_manifests;
CREATE POLICY tenant_isolation ON key_manifests
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- (4) Grants -- m1_062's pattern, restated by name for the new table.
-- ---------------------------------------------------------------------------
REVOKE ALL ON key_manifests FROM PUBLIC;
DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON key_manifests TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON key_manifests TO intel_app;
  END IF;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON key_manifests FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS key_manifests;
--   ALTER TABLE m1_server_signing_keys DROP CONSTRAINT IF EXISTS ck_m1_skeys_cross_sign;
--   ALTER TABLE m1_server_signing_keys DROP COLUMN IF EXISTS cross_signature, DROP COLUMN IF EXISTS cross_signed_by;
--   -- the two m1_receipts CHECKs revert to m1_002's text once no key_rotation row exists
-- COMMIT;
