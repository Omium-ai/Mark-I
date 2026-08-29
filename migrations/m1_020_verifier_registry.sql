-- m1_020_verifier_registry.sql
-- WHY: an anchor is a command that runs on a customer's machine against their
-- repo. The user consented to a SPECIFIC execution -- this binary content,
-- these args, this env allow-list -- summarized as one 32-byte
-- effective_execution_hash (the anti-tamper envelope: a PATH-shimmed ruff or
-- an edited argv changes the hash). Consent to "ruff" in the abstract would
-- mean a catalog edit silently re-scopes what runs; consent to a hash cannot
-- be re-scoped, only re-asked. The catalog is GLOBAL (no tenant_id, no RLS):
-- bundles enable anchors by catalog id, and confusion matrices key on
-- (verifier, version), so every tenant must read the same rows. Consent is
-- tenant-scoped and carries the standard policy.
--
-- NUMBERING NOTE: 07-data-model.md prints this file as m1_004_verifier_registry.sql.
-- It is m1_020 here so the tenancy/receipt files can occupy 001..0NN without a
-- collision; nothing in the content depends on the number, only on running
-- after m1_001_tenancy_devices.sql (m1_tenants, m1_devices).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- (0) verdict -- the four-valued vocabulary, adopted verbatim from the
-- platform's sweep_verdict enum (migration 008). Defined here, in the verifier
-- plane's own file, because it is the verifier plane's vocabulary; the
-- certificate and gold-set tables in m1_021 use it unqualified.
--
-- 'refused' is load-bearing and is why this is an ENUM and not a text column:
-- the estate's probe-registry rule (recovery-orchestrator/app/verify/probes.py)
-- is that a kind with no handler produces NO synthetic vote and NO silent drop
-- -- it is recorded as a refusal. A refusal is a statement about Mark 1's own
-- verifier plane; 'violated' is a statement about the customer's code; the two
-- must never be confusable in the record, so both are first-class stored
-- values and neither can be spelled by accident. The same discipline runs the
-- other way in the catalog below: kind's CHECK list is exactly the set of
-- kinds this build can interpret, so an unimplemented kind cannot be
-- registered at all -- it is refused at write time rather than catalogued and
-- faked at read time.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'verdict') THEN
    CREATE TYPE verdict AS ENUM ('satisfied', 'violated', 'refused', 'error');
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- (1) m1_verifiers -- the catalog. One row per (verifier, version), immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_verifiers (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Stable human key: 'ruff', 'tsc-incremental', 'cargo-check-warm',
  -- 'judge:e1-default'. text, not enum: the catalog grows with every adapter.
  verifier_key             text NOT NULL,
  kind                     text NOT NULL
                             CHECK (kind IN ('anchor', 'judge', 'reward_model', 'consistency')),
  -- int, not semver text: versions here order catalog rows, they do not
  -- describe the tool. The tool's own version string lives in definition.
  version                  int  NOT NULL CHECK (version > 0),
  display_name             text NOT NULL,
  -- The full definition the hash commits to (resolved binary digest, argv,
  -- env allow-list, sandbox preconditions). jsonb here -- unlike a receipt
  -- payload this is DATA to query, not bytes to re-sign; the hash below is
  -- computed over its canonical form at publication and stored, not derived.
  definition               jsonb NOT NULL,
  -- Anchors only (equivalence CHECK below): SHA-256 over the canonical
  -- definition. THE anti-tamper value: the edge recomputes it from what it
  -- actually resolved and refuses to run on mismatch.
  effective_execution_hash bytea,
  created_at               timestamptz NOT NULL DEFAULT now(),
  -- Retirement stops NEW consents and bundle references; old consents and old
  -- receipts still resolve, because the row never goes away.
  retired_at               timestamptz,
  CONSTRAINT ck_m1_verifiers_hash_len
    CHECK (effective_execution_hash IS NULL OR octet_length(effective_execution_hash) = 32),
  -- Equivalence: every anchor has a hash, only anchors have one. A judge's
  -- identity is its definition (model id, prompt hash); it does not execute
  -- on customer machines, so it has no execution to consent to.
  CONSTRAINT ck_m1_verifiers_anchor_hash
    CHECK ((kind = 'anchor') = (effective_execution_hash IS NOT NULL)),
  CONSTRAINT uq_m1_verifiers_key_version UNIQUE (verifier_key, version)
);

-- Immutability: a catalog row may only ever gain retired_at. Any other change
-- is a NEW VERSION -- that is the whole re-consent mechanism, so it gets a
-- trigger, not a convention. The jsonb-minus-key comparison covers every
-- column including ones added later, so a future ALTER TABLE cannot quietly
-- open a mutability hole.
CREATE OR REPLACE FUNCTION m1_verifier_immutable()
RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM (to_jsonb(OLD) - 'retired_at') THEN
    RAISE EXCEPTION
      'm1_verifiers rows are immutable except retired_at; publish a new version'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1v_immutable ON m1_verifiers;
CREATE TRIGGER trg_m1v_immutable
  BEFORE UPDATE ON m1_verifiers
  FOR EACH ROW EXECUTE FUNCTION m1_verifier_immutable();

REVOKE DELETE, TRUNCATE ON m1_verifiers FROM PUBLIC;

-- "current version of each verifier" -- the policy compiler's scan.
CREATE INDEX IF NOT EXISTS ix_m1_verifiers_key
  ON m1_verifiers (verifier_key, version DESC) WHERE retired_at IS NULL;

-- ---------------------------------------------------------------------------
-- (2) m1_anchor_consents -- per-workspace consent, hash-pinned.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_anchor_consents (
  id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                 uuid NOT NULL REFERENCES m1_tenants(id),
  device_id                 uuid NOT NULL REFERENCES m1_devices(id),
  -- Per-tenant HMAC of the workspace root, never the path: paths are exactly
  -- what the wire contract keeps off the server. 32 bytes, length-checked.
  workspace_fingerprint     bytea NOT NULL,
  verifier_id               uuid NOT NULL REFERENCES m1_verifiers(id),
  -- The hash the user SAW in `mark1 doctor` and said yes to. Stored even
  -- though it must equal the catalog's (trigger below) so that if a catalog
  -- row were ever tampered with, the consent still states what was consented
  -- to -- the two agreeing is a checkable fact, not a foreign key's assumption.
  consented_execution_hash  bytea NOT NULL,
  consented_by              text  NOT NULL,   -- OIDC subject; consent has an author
  consented_at              timestamptz NOT NULL DEFAULT now(),
  -- Withdrawal is an UPDATE of these, never a DELETE: "was this anchor
  -- consented on 2026-06-01" must stay answerable for receipt disputes.
  revoked_at                timestamptz,
  revoked_reason            text,
  CONSTRAINT ck_m1_consent_ws_len   CHECK (octet_length(workspace_fingerprint) = 32),
  CONSTRAINT ck_m1_consent_hash_len CHECK (octet_length(consented_execution_hash) = 32)
);

-- At most one LIVE consent per (workspace, verifier version); history rows
-- (revoked, or pointing at superseded versions) accumulate freely.
CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_consent_live
  ON m1_anchor_consents (tenant_id, workspace_fingerprint, verifier_id)
  WHERE revoked_at IS NULL;

-- Insert-time validation: the consent must name an ANCHOR and must name its
-- CURRENT hash. This is what makes a stale consent dialog (hash changed
-- between display and click) a refused write instead of a silent mis-consent.
CREATE OR REPLACE FUNCTION m1_consent_matches_catalog()
RETURNS trigger AS $$
DECLARE
  v m1_verifiers%ROWTYPE;
BEGIN
  SELECT * INTO v FROM m1_verifiers WHERE id = NEW.verifier_id;
  IF v.kind IS DISTINCT FROM 'anchor' THEN
    RAISE EXCEPTION 'consent is only defined for anchors; % is %', v.verifier_key, v.kind
      USING ERRCODE = 'check_violation';
  END IF;
  IF v.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'cannot consent to retired verifier %', v.verifier_key
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.consented_execution_hash IS DISTINCT FROM v.effective_execution_hash THEN
    RAISE EXCEPTION
      'consent hash does not match catalog for % v%; re-display and re-ask',
      v.verifier_key, v.version
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1_consent_matches ON m1_anchor_consents;
CREATE TRIGGER trg_m1_consent_matches
  BEFORE INSERT ON m1_anchor_consents
  FOR EACH ROW EXECUTE FUNCTION m1_consent_matches_catalog();

ALTER TABLE m1_anchor_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_anchor_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_anchor_consents;
CREATE POLICY tenant_isolation ON m1_anchor_consents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- The runnability check's exact access path: live consents for one workspace.
CREATE INDEX IF NOT EXISTS ix_m1_consent_workspace
  ON m1_anchor_consents (tenant_id, workspace_fingerprint)
  WHERE revoked_at IS NULL;

-- THE RUNNABILITY INVARIANT, recorded here so every consumer spells it the
-- same way. An anchor version V is runnable in workspace W iff:
--
--   SELECT EXISTS (
--     SELECT 1
--     FROM m1_anchor_consents c
--     JOIN m1_verifiers v ON v.id = c.verifier_id
--     WHERE c.tenant_id             = NULLIF(current_setting('app.tenant_id', true), '')::uuid
--       AND c.workspace_fingerprint = $1        -- W
--       AND v.id                    = $2        -- V
--       AND c.revoked_at IS NULL
--       AND v.retired_at IS NULL
--       AND c.consented_execution_hash = v.effective_execution_hash
--   );
--
-- Re-consent on change needs no machinery beyond the above: a changed
-- effective execution is, by the immutability trigger, a NEW catalog row with
-- a new id, which no existing consent references, so this returns false
-- everywhere until each workspace consents again through `mark1 doctor`. The
-- final equality predicate looks redundant (the insert trigger enforced it)
-- and is kept deliberately: it is the read-side check that still holds if a
-- catalog row were altered with triggers disabled.

-- ---------------------------------------------------------------------------
-- (3) Grants. The policy compiler (intel) publishes catalog versions; consent
-- arrives through controld from the edge; nobody deletes anything.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_verifiers TO intel_app;  -- UPDATE = retired_at only, trigger-policed
    GRANT SELECT ON m1_anchor_consents TO intel_app;            -- the compiler refuses to enable unconsented anchors
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON m1_verifiers TO controld_app;
    GRANT SELECT, INSERT, UPDATE ON m1_anchor_consents TO controld_app;  -- UPDATE = revocation
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_verifiers TO adjudicator_app;  -- confusion matrices key on catalog rows
  END IF;
END $$;

REVOKE DELETE, TRUNCATE ON m1_verifiers, m1_anchor_consents FROM PUBLIC;

COMMIT;

-- ROLLBACK (run manually if needed; drops the consent history that receipt
-- disputes cite -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_anchor_consents CASCADE;
--   DROP TABLE IF EXISTS m1_verifiers CASCADE;
--   DROP FUNCTION IF EXISTS m1_consent_matches_catalog();
--   DROP FUNCTION IF EXISTS m1_verifier_immutable();
--   DROP TYPE IF EXISTS verdict;
-- COMMIT;
