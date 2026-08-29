-- m1_040_memory_artifacts.sql
-- REMEMBER plane storage: distilled artifacts, the LCB admission ladder, the
-- single halfvec column for error-signature fuzz, and the contribution rows
-- the federation (k,m) gate aggregates. Admission is gated on a live noise
-- certificate via mark1_assert_certified() -- an uncertified verdict can label
-- nothing that enters memory.
--
-- THE ONE pgvector COLUMN IN MARK 1 LIVES HERE, AND ONLY HERE. Error-signature
-- matching is the single genuine fuzzy-match problem in the schema: two stack
-- traces from the same pitfall differ in paths, line numbers and generated
-- names, so no exact key exists to join them, and the whole value of a pitfall
-- artifact is firing on the PARAPHRASE of an error it has seen. Everything else
-- that looks like a vector problem is not one: memory retrieval by task context
-- is tag/kind filtering plus LCB ranking (relational); code localization is
-- cortexd's graph problem, decided at the edge; dedupe and gold membership are
-- exact HMAC equality; federation spans must match EXACTLY or the m-count is
-- fiction. A second vector column would buy recall nowhere and cost an ANN
-- index plus an unauditable similarity predicate.
--
-- NAMING NOTE (deviation from the printed DDL in 07-data-model.md, recorded
-- rather than silently absorbed): the doc's part-2 listings write the tenancy
-- FKs as tenants(id) / organizations(id) / devices(id), but the only DDL that
-- creates those tables -- m1_001_tenancy_devices.sql, in the same document --
-- names them m1_tenants / m1_organizations / m1_devices. The FKs below name
-- what m1_001 actually creates, because a migration that cannot resolve its
-- own references is not a migration.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE EXTENSION IF NOT EXISTS vector;   -- pgvector >= 0.7 for halfvec; ships with RDS PG15

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_abstraction') THEN
    -- 'instance': one observed episode. 'pattern': generalized across episodes,
    -- content-scrubbed. 'invariant': a fact about THIS tenant's codebase --
    -- publishable never (see the CHECKs in m1_041).
    CREATE TYPE artifact_abstraction AS ENUM ('instance', 'pattern', 'invariant');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_kind') THEN
    CREATE TYPE artifact_kind AS ENUM ('pitfall', 'fix_pattern', 'preference', 'invariant');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'admission_state') THEN
    -- ADMIT-LCB ladder: extracted -> shadow (retrieved, never injected) ->
    -- admitted (injected) -> retired. States are one-directional except
    -- admitted->retired; the trigger below enforces the cert gate on the
    -- transition INTO 'admitted', which is the only transition that changes
    -- what a customer session sees.
    CREATE TYPE admission_state AS ENUM ('extracted', 'shadow', 'admitted', 'retired');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS memory_artifacts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  abstraction     artifact_abstraction NOT NULL,
  kind            artifact_kind NOT NULL,
  -- The distilled body: typed sections (trigger, guidance, evidence refs),
  -- already redaction-admitted before it ever reaches this table. jsonb, not
  -- text, because retrieval filters on typed fields inside it.
  body            jsonb NOT NULL,
  -- THE vector column. halfvec, not vector: 2 bytes/dim halves the HNSW
  -- footprint and recall loss is unmeasurable at this dimensionality; 1024 dims
  -- matches the embedding model fixed in 06-lld-intelligence. NULLable: only
  -- pitfall-class artifacts carry an error signature.
  error_signature halfvec(1024),
  state           admission_state NOT NULL DEFAULT 'extracted',
  -- Tenant-scope LCB admission facts (ADMIT-LCB): the lower confidence bound on
  -- uplift, and the observation count it was computed from. numeric, not float,
  -- because the promotion comparison (lcb > 0) is a constraint-adjacent read.
  lcb             numeric(8,6),
  n_obs           int NOT NULL DEFAULT 0 CHECK (n_obs >= 0),
  cert_id         uuid REFERENCES noise_certificates(id) ON DELETE RESTRICT, -- the warrant for the labels behind lcb
  admitted_at     timestamptz,
  receipt_id      uuid,                  -- memory admission is per-event receipted (C13)
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  -- 'invariant' the kind and 'invariant' the abstraction must agree, or the
  -- publication CHECK in m1_041 could be dodged by mislabeling.
  CONSTRAINT invariant_kinds_agree CHECK ((kind = 'invariant') = (abstraction = 'invariant')),
  -- Admitted rows must carry their evidence: an LCB, observations, and a cert.
  CONSTRAINT admitted_is_earned CHECK (
    state <> 'admitted' OR (lcb IS NOT NULL AND lcb > 0 AND n_obs > 0 AND cert_id IS NOT NULL AND admitted_at IS NOT NULL)
  ),
  -- FK target for the composite publication FK: (id, abstraction) is trivially
  -- unique given the PK; declaring it lets publication tables bind the
  -- abstraction value they CHECK against, instead of trusting a copy.
  CONSTRAINT uq_artifact_id_abstraction UNIQUE (id, abstraction)
);

-- The gate on the only transition a customer can feel. INSERTs arrive as
-- 'extracted' (extraction itself is also cert-gated -- the extractor only reads
-- corpus_admissions rows, which the noise-cert migration already gates -- so
-- this trigger is the second, independent enforcement of the same C5 rule).
CREATE OR REPLACE FUNCTION trg_admission_requires_cert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state = 'admitted' AND (TG_OP = 'INSERT' OR OLD.state IS DISTINCT FROM 'admitted') THEN
    PERFORM mark1_assert_certified(NEW.cert_id);
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS artifact_admission_cert_gate ON memory_artifacts;
CREATE TRIGGER artifact_admission_cert_gate
  BEFORE INSERT OR UPDATE OF state ON memory_artifacts
  FOR EACH ROW EXECUTE FUNCTION trg_admission_requires_cert();

-- THE HNSW INDEX -- the only ANN structure in the schema. m=16/ef_construction=64
-- are pgvector defaults, correct at this scale (artifacts are distilled, not
-- raw events; even a large tenant holds thousands, not millions). Partial on
-- signature-bearing rows so preference/invariant artifacts cost nothing here.
-- Cosine ops because signature embeddings are length-normalized by convention
-- and the retrieval threshold in 06 is stated in cosine distance.
CREATE INDEX IF NOT EXISTS ix_artifacts_error_signature
  ON memory_artifacts USING hnsw (error_signature halfvec_cosine_ops)
  WITH (m = 16, ef_construction = 64)
  WHERE error_signature IS NOT NULL;

-- Retrieval's relational path: injectable artifacts for a tenant, by kind.
CREATE INDEX IF NOT EXISTS ix_artifacts_injectable
  ON memory_artifacts (tenant_id, kind)
  WHERE state = 'admitted';

-- Contribution rows: one per (artifact, tenant, span). This is the table the
-- federation (k,m) gate GROUPs -- the k-count and the per-span m-count are both
-- computed from here, never asserted.
CREATE TABLE IF NOT EXISTS artifact_contributions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id  uuid NOT NULL REFERENCES memory_artifacts(id) ON DELETE RESTRICT, -- contributions are the publication audit trail; they outlive nothing
  tenant_id    uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  org_id       uuid NOT NULL REFERENCES m1_organizations(id) ON DELETE RESTRICT, -- denormalized: the m-count collapses on org, and a join at gate time is a join inside a trigger
  -- Digest of the NORMALIZED span content under the per-tenant HMAC key.
  -- Deliberately NOT globally joinable: cross-tenant span identity is
  -- established only by the worker re-normalizing content, downstream of this table.
  span_digest  bytea NOT NULL CHECK (octet_length(span_digest) = 32),
  produced_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_contribution UNIQUE (artifact_id, tenant_id, span_digest)  -- one tenant contributes a span once; re-observation is not re-production
);

CREATE INDEX IF NOT EXISTS ix_contributions_by_artifact ON artifact_contributions (artifact_id);

-- RLS. memory_artifacts and artifact_contributions take writes -> symmetric
-- WITH CHECK. The federation worker (BYPASSRLS) reads across tenants here;
-- that is the named justification for its existence.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['memory_artifacts','artifact_contributions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT, INSERT, UPDATE ON memory_artifacts, artifact_contributions TO intel_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mark1_federation_worker') THEN
    GRANT SELECT ON memory_artifacts, artifact_contributions TO mark1_federation_worker;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS artifact_contributions;
--   DROP TRIGGER IF EXISTS artifact_admission_cert_gate ON memory_artifacts;
--   DROP FUNCTION IF EXISTS trg_admission_requires_cert();
--   DROP TABLE IF EXISTS memory_artifacts;
--   DROP TYPE IF EXISTS admission_state;
--   DROP TYPE IF EXISTS artifact_kind;
--   DROP TYPE IF EXISTS artifact_abstraction;
-- COMMIT;
