-- m1_021_noise_certs_gold_sets.sql
-- Noise certificates (C5) + gold sets. A verifier's verdicts are worthless as
-- training labels until its noise is measured; this migration stores the
-- measurement and makes "certified" a constraint-checked fact, not a flag.
-- The rule "a non-certified verdict must not gate memory extraction or corpus
-- admission" is mark1_assert_certified(), attached here to corpus_admissions
-- and in m1_040 to memory-artifact admission -- one function, both gates.
--
-- Gold-set membership is server-selected and EDGE-INDISTINGUISHABLE BY
-- CONSTRUCTION: membership exists only in gold_set_members, which no
-- edge-facing surface reads; tasks and events carry no membership marker
-- anywhere in m1p.v1 or in any PolicyBundle section, and selection is a
-- server-side join on task_digest, the per-tenant HMAC the ledger already
-- carries, so the edge cannot even test membership by hashing. Selection is
-- also post-hoc (06 §5.1): at execution time gold tasks do not yet exist.
--
-- NUMBERING NOTE: 07-data-model.md prints this file as
-- m1_006_noise_certs_gold_sets.sql; it is m1_021 here to leave 001..0NN to the
-- tenancy/receipt files. It runs after m1_020_verifier_registry.sql, which
-- defines the verdict enum and m1_verifiers.
--
-- NAMING NOTE (deviation from the printed DDL in 07-data-model.md, recorded
-- rather than silently absorbed): the doc's part-3 listings write the FKs as
-- tenants(id) and verifier_registry(id), but the only DDL that creates those
-- tables -- m1_001_tenancy_devices.sql and the verifier-registry file above,
-- both in the same document -- names them m1_tenants and m1_verifiers. The FKs
-- below name what those files actually create, matching m1_040/m1_041.
--
-- TWO COLUMNS ADDED beyond the printed DDL, both required in prose by
-- 06-lld-intelligence.md and both load-bearing for the C5 claim; recorded here
-- so the addition is auditable:
--   * gold_set_members.label_source -- 06 §1.3 and §5.1: "the strong label's
--     source is recorded on the row" (t3 | human | batch-readjudication).
--   * noise_certificates.natarajan_lcb -- 06 §5.2: the checkable condition is
--     NATARAJAN_OK <=> LCB95(1 - (rho+ + rho-)) > 0, i.e. provably at 95%, NOT
--     the point-estimate inequality alone. Without the LCB in the row, a
--     certificate measured on a barely-sufficient window could satisfy the
--     point-estimate CHECK while the interval straddles 1. Both conjuncts are
--     kept: the point estimate is the doc's printed constraint, the LCB is the
--     theorem's actual condition.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cert_status') THEN
    -- 'bootstrapping' is distinct from 'uncertified' because it is an honest
    -- public answer ("we are measuring") rather than an absence; C5 requires
    -- reports to say which one it is. Both are below-threshold states, and a
    -- verdict in either state gates NOTHING: not memory extraction, not corpus
    -- admission (mark1_assert_certified() below is the enforcement).
    CREATE TYPE cert_status AS ENUM ('uncertified', 'bootstrapping', 'certified');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS gold_sets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  agent       text NOT NULL,             -- claudecode|codex|...: gold labels do not transfer across hook vocabularies
  -- NULL = still accepting members. A certificate may only cite a frozen set:
  -- rho measured against a moving target is not a measurement.
  frozen_at   timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gold_set_members (
  gold_set_id  uuid NOT NULL REFERENCES gold_sets(id) ON DELETE CASCADE,  -- members are meaningless without their set
  tenant_id    uuid NOT NULL,            -- denormalized so RLS holds on this table without a join
  -- Per-tenant HMAC of (session_id, task_id): joins to ledger events without
  -- naming them, and is the ONLY membership record anywhere -- bytea, not uuid,
  -- because it is a digest, not an identity we mint.
  task_digest  bytea NOT NULL CHECK (octet_length(task_digest) = 32),
  true_label   verdict NOT NULL,         -- adjudicated ground truth, four-valued like every verdict
  -- Where the strong label came from (06 §5.1). Recorded per row because the
  -- three sources have different trust: a T3 certified re-run and a residue
  -- human label are not interchangeable evidence, and an auditor asking "how
  -- was this ground truth established" must get an answer from the row.
  label_source text NOT NULL
                 CHECK (label_source IN ('t3', 'human', 'batch-readjudication')),
  labeled_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gold_set_id, task_digest) -- one label per task per set; relabeling is an UPDATE, not a duplicate
);

-- Freshness (06 D16/D17) is computed over labeled_at within a set; rotation is
-- oldest-out. This is that scan.
CREATE INDEX IF NOT EXISTS ix_gold_members_fresh
  ON gold_set_members (gold_set_id, labeled_at DESC);

CREATE TABLE IF NOT EXISTS noise_certificates (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  verifier_id  uuid NOT NULL REFERENCES m1_verifiers(id) ON DELETE RESTRICT, -- a cert about a retired verifier is still evidence
  gold_set_id  uuid REFERENCES gold_sets(id) ON DELETE RESTRICT,  -- NULL only while uncertified/bootstrapping
  status       cert_status NOT NULL DEFAULT 'uncertified',
  -- numeric(7,6), not float: rho is a stored measurement compared in constraints,
  -- and float equality in a CHECK is a latent lie.
  rho_plus     numeric(7,6) CHECK (rho_plus  >= 0 AND rho_plus  < 1),
  rho_minus    numeric(7,6) CHECK (rho_minus >= 0 AND rho_minus < 1),
  -- LCB95( 1 - (rho+ + rho-) ) -- the Natarajan margin's lower confidence
  -- bound. Signed: a negative margin is a real, storable measurement and the
  -- honest reason a cert stays below 'certified'.
  natarajan_lcb numeric(7,6) CHECK (natarajan_lcb >= -1 AND natarajan_lcb <= 1),
  gold_n       int CHECK (gold_n >= 0),  -- size of the frozen set AT ISSUE; the set can grow later, the cert's basis cannot
  identifiable boolean NOT NULL DEFAULT false,  -- spectral Dawid-Skene identifiability gate passed
  diagnostics  jsonb NOT NULL DEFAULT '{}'::jsonb, -- spectral gap, condition number, per-class support, Wilson CIs; jsonb because the diagnostic set evolves with the estimator
  issued_at    timestamptz,
  expires_at   timestamptz,              -- the freshness gate; enforced at read time by mark1_assert_certified()
  receipt_id   uuid,                     -- C13: certification is one of the six per-event-receipted actions; logical key, no cross-service FK
  -- THE STATUS IS EARNED. A row cannot claim 'certified' unless the Natarajan
  -- condition, the identifiability diagnostic, the size gate and a frozen set
  -- are all present in the row itself. Below any of these, the honest status
  -- is 'uncertified'/'bootstrapping' -- exactly what C5 demands.
  CONSTRAINT certified_is_earned CHECK (
    status <> 'certified' OR (
      rho_plus IS NOT NULL AND rho_minus IS NOT NULL
      AND rho_plus + rho_minus < 1        -- Natarajan condition, stored as a checkable fact
      AND natarajan_lcb IS NOT NULL
      AND natarajan_lcb > 0               -- ...and PROVABLY so at 95% (06 §5.2 NATARAJAN_OK)
      AND identifiable
      AND gold_n >= 200                   -- size gate: Paper II sample-complexity floor (D15); changing it is deliberately a migration
      AND gold_set_id IS NOT NULL
      AND issued_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at > issued_at
    )
  )
  -- A cert may only cite a FROZEN, same-tenant set: trigger below, because
  -- that predicate reads another table.
);

-- One live certificate per (tenant, verifier): the fusion bundle compiler must
-- never have two answers for "what is this verifier's noise".
CREATE UNIQUE INDEX IF NOT EXISTS uq_cert_live
  ON noise_certificates (tenant_id, verifier_id)
  WHERE status = 'certified';

-- A certificate's basis must be reconstructible, which means the set it cites
-- must have stopped moving before it was cited, and must belong to the same
-- tenant (a cross-tenant gold set would be measurement laundering that RLS
-- alone does not catch under a BYPASSRLS maintenance role).
CREATE OR REPLACE FUNCTION trg_cert_gold_set_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE g gold_sets%ROWTYPE;
BEGIN
  IF NEW.status = 'certified' THEN
    SELECT * INTO g FROM gold_sets WHERE id = NEW.gold_set_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'certified cert % cites gold set % that does not exist', NEW.id, NEW.gold_set_id
        USING ERRCODE = 'check_violation';
    END IF;
    IF g.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
      RAISE EXCEPTION 'gold set % belongs to another tenant; a cert may only cite its own tenant''s basis', g.id
        USING ERRCODE = 'check_violation';
    END IF;
    IF g.frozen_at IS NULL THEN
      RAISE EXCEPTION 'gold set % is not frozen; rho measured against a moving target is not a measurement', g.id
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS cert_gold_set_frozen ON noise_certificates;
CREATE TRIGGER cert_gold_set_frozen
  BEFORE INSERT OR UPDATE OF status, gold_set_id, tenant_id ON noise_certificates
  FOR EACH ROW EXECUTE FUNCTION trg_cert_gold_set_frozen();

-- THE GATE. Both consumers of certification (memory extraction, corpus
-- admission) call this in a BEFORE trigger. Freshness lives here and not in a
-- sweeper: the moment expires_at passes, the gate fails closed, whether or not
-- any job has run. STABLE, not IMMUTABLE -- it reads a table and the clock.
CREATE OR REPLACE FUNCTION mark1_assert_certified(p_cert uuid) RETURNS uuid
LANGUAGE plpgsql STABLE AS $$
DECLARE ok boolean;
BEGIN
  SELECT (status = 'certified' AND expires_at > now()) INTO ok
    FROM noise_certificates WHERE id = p_cert;
  IF ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'cert % is not currently certified: non-certified verdicts do not gate admission (C5)', p_cert
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN p_cert;
END $$;

-- Corpus admission: the Postgres-side row the corpus-exporter joins before a
-- trajectory may enter the training corpus. One row per admitted task.
CREATE TABLE IF NOT EXISTS corpus_admissions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  task_digest  bytea NOT NULL CHECK (octet_length(task_digest) = 32),  -- same per-tenant HMAC key as gold members: joinable in-tenant only
  label        verdict NOT NULL,
  cert_id      uuid NOT NULL REFERENCES noise_certificates(id) ON DELETE RESTRICT, -- the label's warrant; deleting the warrant would orphan the label
  admitted_at  timestamptz NOT NULL DEFAULT now(),
  receipt_id   uuid,                     -- corpus export is per-event receipted (C13); logical key, no cross-service FK
  CONSTRAINT uq_corpus_admission UNIQUE (tenant_id, task_digest)  -- re-admission overwrites, never double-counts
);

CREATE OR REPLACE FUNCTION trg_corpus_requires_cert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM mark1_assert_certified(NEW.cert_id);
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS corpus_admission_cert_gate ON corpus_admissions;
CREATE TRIGGER corpus_admission_cert_gate
  BEFORE INSERT OR UPDATE OF cert_id ON corpus_admissions
  FOR EACH ROW EXECUTE FUNCTION trg_corpus_requires_cert();

-- RLS: canonical form. All four tables take writes, so WITH CHECK is symmetric.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['gold_sets','gold_set_members','noise_certificates','corpus_admissions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;

-- Grants: adjudicator-svc owns certification; intel's exporter only reads certs
-- and writes admissions. Guarded so a cluster without the roles file still applies.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT, UPDATE ON gold_sets, gold_set_members, noise_certificates TO adjudicator_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON noise_certificates TO intel_app;
    GRANT SELECT, INSERT, UPDATE ON corpus_admissions TO intel_app;
  END IF;
END $$;

REVOKE DELETE, TRUNCATE ON gold_sets, gold_set_members, noise_certificates,
                           corpus_admissions FROM PUBLIC;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS corpus_admissions;
--   DROP FUNCTION IF EXISTS trg_corpus_requires_cert();
--   DROP FUNCTION IF EXISTS mark1_assert_certified(uuid);
--   DROP FUNCTION IF EXISTS trg_cert_gold_set_frozen();
--   DROP TABLE IF EXISTS noise_certificates;
--   DROP TABLE IF EXISTS gold_set_members;
--   DROP TABLE IF EXISTS gold_sets;
--   DROP TYPE  IF EXISTS cert_status;
-- COMMIT;
