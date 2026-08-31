-- m1_062_transparency_log.sql
-- The transparency log 05 §4.4 names and 07 never DDL'd: "an append-only
-- Merkle log (RFC 6962 shape: leaves are SHA-256(bundle canonical bytes), plus
-- key-manifest snapshots and hourly receipt chain heads -- one log, three leaf
-- kinds, kind-tagged). Backing store is Postgres (a `tlog_leaves` table with a
-- dense `leaf_index`), with the current signed head (size, root, sig)
-- recomputed on append."
--
-- WHY IT MATTERS. m1_042 makes `policy_bundles.tlog_index` and `tlog_proof`
-- NOT NULL and says why: "an unlogged bundle must be unpublishable, because a
-- bundle outside the log is invisible to split-view detection." Those two
-- columns had nothing to reference. This file is what they reference.
--
-- ---------------------------------------------------------------------------
-- WHY 062 AND NOT 044 -- read this before "renumbering it into the table block"
-- ---------------------------------------------------------------------------
-- m1_060_roles_and_grants.sql's own header states the trap: every GRANT in
-- m1_001-m1_043 is wrapped in `IF EXISTS (SELECT 1 FROM pg_roles ...)`, and on
-- a fresh database built in filename order those guards are ALL FALSE, because
-- the roles do not exist until m1_060 creates them. m1_060 therefore restates
-- the complete matrix -- but it cannot restate grants for a table that did not
-- exist when it was frozen. A `m1_044` here would ship its tables with ZERO
-- runtime privileges on every fresh build, and the first publication in a new
-- environment would fail on `permission denied for table tlog_leaves`.
--
-- Numbering AFTER the roles file is what makes the grants at the bottom
-- actually take. m1_061_device_edge_version.sql already set that precedent.
-- The cost is that m1_060's narrowing REVOKE sweep (`... ON ALL TABLES IN
-- SCHEMA public`) ran before these tables existed, so section (5) restates it
-- for them by name. Absence is the control; it has to be re-established, not
-- assumed.
--
-- ---------------------------------------------------------------------------
-- THE GRANT WIDENING IN SECTION (5), STATED PLAINLY BECAUSE IT IS A DEVIATION
-- ---------------------------------------------------------------------------
-- m1_060 gives controld_app SELECT on policy_bundles and gives intel_app the
-- INSERT. Neither role can execute the publication transaction 05 §4.1 and
-- 06 §10.4(3) specify, because that transaction is ONE transaction and must
-- write BOTH the catalog row AND the per-event `bundle_publication` receipt:
--
--   * controld_app  holds INSERT on m1_receipts, SELECT-only on policy_bundles.
--   * intel_app     holds INSERT on policy_bundles, SELECT-only on m1_receipts.
--
-- One of the two must widen. This file widens controld_app on the CATALOG
-- rather than intel_app on the RECEIPT CHAIN, for three reasons:
--   1. m1_002's single-writer rule ("m1_002 receipt chain: ONE writer") is a
--      stronger invariant than the catalog's writer identity. Widening
--      intel_app onto m1_receipts would break it; widening controld_app onto
--      policy_bundles breaks nothing -- the append-only triggers and m1_060's
--      REVOKE of UPDATE on policy_bundles both still bind.
--   2. m1_060's own section header already names controld_app as "the request
--      path of ingest / enroll / POLICYDIST, plus the receipt and checkpoint
--      side-effects". The publication receipt is precisely a receipt side
--      effect of policydist.
--   3. 05 §4.1 places the publication path in `policydist`, i.e. in controld:
--      "mark1-intel.policy-compiler -> policydist's internal publication path
--      (in-repo, not a public route)". intel_app's INSERT is for the
--      compiler-submits-sections story; the process that takes the head lock
--      and writes the row is controld.
-- intel_app keeps everything m1_060 gave it. Nothing is revoked from anyone.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- ---------------------------------------------------------------------------
-- (1) tlog_heads -- the fixed-key lock row. Size only; no root.
-- ---------------------------------------------------------------------------
-- The bundle_channel_heads pattern from m1_042, and it is a FIXED key
-- (tenant_id alone) for the reason that pattern exists: two publishers must
-- contend on THE SAME row. Locking "the newest signed head" instead would let
-- the loser of a race hold a lock on a row that is no longer newest, and both
-- would compute the same next leaf_index.
--
-- No root_hash column. The Merkle root is not computable in SQL, so a root
-- here would be a value the database cannot check and the application could
-- silently desync -- exactly the kind of decorative column this schema avoids.
-- Roots live in tlog_signed_heads, where a signature makes them accountable.
CREATE TABLE IF NOT EXISTS tlog_heads (
  tenant_id  uuid PRIMARY KEY REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  tree_size  bigint NOT NULL DEFAULT 0 CHECK (tree_size >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- (2) tlog_leaves -- the log itself. Dense leaf_index, append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tlog_leaves (
  tenant_id   uuid   NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  -- 0-based and DENSE (05 §4.4). Dense, not merely unique: an inclusion proof
  -- is computed against a tree of size N, and a gap makes every proof past the
  -- gap prove membership in a tree nobody else can reconstruct.
  leaf_index  bigint NOT NULL CHECK (leaf_index >= 0),
  -- 05 §4.4's three leaf kinds, kind-tagged so one log serves all three and a
  -- consumer can tell what it is looking at without decoding the preimage.
  kind        text   NOT NULL CHECK (kind IN ('policy_bundle', 'key_manifest', 'receipt_chain_head')),
  -- The LEAF PREIMAGE HASH: SHA-256 over the committed bytes (for a bundle,
  -- its canonical CBOR minus `inclusion` -- 07's CDDL: "a transparency-log
  -- leaf cannot commit to the proof of its own inclusion"). NOT the RFC 6962
  -- leaf hash: the 0x00 domain prefix is applied by the tree code, so storing
  -- the prefixed form would make the same bundle hash unequal to
  -- policy_bundles.body_sha256 and break the one comparison that matters.
  leaf_hash   bytea  NOT NULL CHECK (octet_length(leaf_hash) = 32),
  appended_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, leaf_index)
);

-- WHY THE LOG IS PER TENANT, since 05 §4.4 says "one log".
-- 05 §4.4's "one log" is a statement about LEAF KINDS ("one log, three leaf
-- kinds"), not about tenancy, and it says nothing either way about the latter.
-- This schema resolves the silence toward tenancy because the alternative is
-- the estate's own scar: a table with no tenant_id is a table with no RLS, and
-- a bundle leaf correlates one-to-one with a tenant's published policy. Every
-- property 05 §4.4 asks of the log survives the split -- append-only,
-- dense-index, log(n) inclusion proofs, and split-view detection by comparing
-- a published head against the witness copy, which is a per-head comparison
-- and does not care how many trees exist. What does NOT survive is a single
-- global root; the public `tlog.mark1.omium.ai` surface (08 §3.5, "nothing
-- tenant-identifying") therefore cannot serve one root for everybody, and
-- whoever builds that surface must serve per-tenant heads to authenticated
-- callers or a tenant-blind aggregate. Recorded here rather than discovered
-- there.
CREATE OR REPLACE FUNCTION trg_tlog_leaf_dense() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE h tlog_heads;
BEGIN
  INSERT INTO tlog_heads (tenant_id) VALUES (NEW.tenant_id)
  ON CONFLICT (tenant_id) DO NOTHING;                     -- first append creates the head at 0
  SELECT * INTO h FROM tlog_heads WHERE tenant_id = NEW.tenant_id FOR UPDATE;
  -- No visible head row (RLS, or a deleted head) leaves h NULL and every
  -- comparison below evaluates NULL -- the gate would admit an arbitrary
  -- leaf_index with no density check at all. Same refusal as m1_042's.
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tlog head for tenant % is not visible: append refused', NEW.tenant_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.leaf_index <> h.tree_size THEN
    RAISE EXCEPTION 'tlog leaf_index must be % for tenant %, got % -- gaps and rewrites are unrepresentable',
      h.tree_size, NEW.tenant_id, NEW.leaf_index USING ERRCODE = 'check_violation';
  END IF;
  UPDATE tlog_heads SET tree_size = NEW.leaf_index + 1, updated_at = now()
   WHERE tenant_id = NEW.tenant_id;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS tlog_leaf_dense ON tlog_leaves;
CREATE TRIGGER tlog_leaf_dense
  BEFORE INSERT ON tlog_leaves
  FOR EACH ROW EXECUTE FUNCTION trg_tlog_leaf_dense();

-- Append-only, three ways, m1_042's function shape. An editable transparency
-- log is a claim about history, not a record of it.
CREATE OR REPLACE FUNCTION trg_tlog_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'the transparency log is append-only: history is superseded by a later leaf, never edited'
    USING ERRCODE = 'check_violation';
END $$;

DROP TRIGGER IF EXISTS tlog_leaves_no_update_delete ON tlog_leaves;
CREATE TRIGGER tlog_leaves_no_update_delete
  BEFORE UPDATE OR DELETE ON tlog_leaves
  FOR EACH ROW EXECUTE FUNCTION trg_tlog_append_only();
-- Way three: row triggers do not fire on TRUNCATE, and the REVOKE below does
-- not bind the owner.
DROP TRIGGER IF EXISTS tlog_leaves_no_truncate ON tlog_leaves;
CREATE TRIGGER tlog_leaves_no_truncate
  BEFORE TRUNCATE ON tlog_leaves
  FOR EACH STATEMENT EXECUTE FUNCTION trg_tlog_append_only();

-- ---------------------------------------------------------------------------
-- (3) tlog_signed_heads -- the signed (size, root) history.
-- ---------------------------------------------------------------------------
-- One row per append: 05 §4.4's "current signed head (size, root, sig)
-- recomputed on append". History, not a single current row, because split-view
-- detection is a COMPARISON -- "the head was X at size N" has to still be on
-- record when the witness copy is checked against it an hour later.
CREATE TABLE IF NOT EXISTS tlog_signed_heads (
  tenant_id uuid   NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  tree_size bigint NOT NULL CHECK (tree_size >= 1),   -- an empty tree has no root worth signing
  root_hash bytea  NOT NULL CHECK (octet_length(root_hash) = 32),
  -- 05 §4.4: "Signing the head uses the update/log key class, not a bundle
  -- section key -- a bundle-key compromise must not allow rewriting log
  -- history." The FK to m1_server_signing_keys is what makes the key public,
  -- and therefore what makes the signature checkable by someone outside Omium.
  key_id    text   NOT NULL REFERENCES m1_server_signing_keys(key_id),
  signature bytea  NOT NULL CHECK (octet_length(signature) = 64),
  signed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, tree_size)
);

DROP TRIGGER IF EXISTS tlog_signed_heads_no_update_delete ON tlog_signed_heads;
CREATE TRIGGER tlog_signed_heads_no_update_delete
  BEFORE UPDATE OR DELETE ON tlog_signed_heads
  FOR EACH ROW EXECUTE FUNCTION trg_tlog_append_only();
DROP TRIGGER IF EXISTS tlog_signed_heads_no_truncate ON tlog_signed_heads;
CREATE TRIGGER tlog_signed_heads_no_truncate
  BEFORE TRUNCATE ON tlog_signed_heads
  FOR EACH STATEMENT EXECUTE FUNCTION trg_tlog_append_only();

-- "the newest signed head for this tenant" is the serving query.
CREATE INDEX IF NOT EXISTS ix_tlog_signed_heads_latest
  ON tlog_signed_heads (tenant_id, tree_size DESC);

-- ---------------------------------------------------------------------------
-- (4) RLS -- canonical form, all three. The NULLIF is what makes an unset GUC
--     match nothing rather than everything.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tlog_heads', 'tlog_leaves', 'tlog_signed_heads'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- (5) Grants -- and m1_060's narrowing REVOKEs, restated for these tables.
-- ---------------------------------------------------------------------------
REVOKE ALL ON tlog_heads, tlog_leaves, tlog_signed_heads FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    -- policydist publishes (append leaf + sign head) and serves (read leaves
    -- to recompute an inclusion proof). UPDATE on tlog_heads is the trigger's
    -- own head advance, nothing else -- the same carve-out m1_060 spells out
    -- for intel_app on bundle_channel_heads.
    GRANT SELECT, INSERT         ON tlog_leaves, tlog_signed_heads TO controld_app;
    GRANT SELECT, INSERT, UPDATE ON tlog_heads                     TO controld_app;
    -- The publication-transaction widening argued in the header. INSERT only:
    -- m1_060's REVOKE of UPDATE on policy_bundles still binds, and m1_042's
    -- append-only triggers outrank every grant in this file.
    GRANT INSERT                 ON policy_bundles                 TO controld_app;
    GRANT INSERT, UPDATE         ON bundle_channel_heads           TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    -- The compiler reads what was logged to cite it in reports; it never
    -- appends -- appending is the act that must stay with one writer.
    GRANT SELECT ON tlog_leaves, tlog_signed_heads, tlog_heads TO intel_app;
  END IF;

  -- m1_060 §(6): no runtime role holds DELETE or TRUNCATE on anything, and
  -- nothing holds UPDATE on an append-only table. Its `ALL TABLES IN SCHEMA
  -- public` sweep predates these tables, so it is restated by name here.
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE DELETE, TRUNCATE ON tlog_heads, tlog_leaves, tlog_signed_heads FROM %I', r);
      EXECUTE format('REVOKE UPDATE ON tlog_leaves, tlog_signed_heads FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS tlog_signed_heads;
--   DROP TABLE IF EXISTS tlog_leaves;
--   DROP TABLE IF EXISTS tlog_heads;
--   DROP FUNCTION IF EXISTS trg_tlog_leaf_dense();
--   DROP FUNCTION IF EXISTS trg_tlog_append_only();
--   REVOKE INSERT ON policy_bundles FROM controld_app;
--   REVOKE INSERT, UPDATE ON bundle_channel_heads FROM controld_app;
-- COMMIT;
