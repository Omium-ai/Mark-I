-- m1_041_federation.sql
-- The cross-tenant boundary: org verification + collusion collapse, the (k,m)
-- publication gate, intersection-reconstruction bookkeeping, the human review
-- queue, and the epsilon ledger. Everything above this boundary is
-- tenant-scoped; everything below it has provably shed tenant identity.
--
-- The (k,m) gate is enforced TWICE on purpose: once as the HAVING clause the
-- candidate query is built from -- so the worker can only FIND artifacts that
-- pass -- and once as a constraint trigger on the publication table -- so a bug
-- in the worker cannot PUBLISH one that doesn't. Counting is collusion-
-- collapsed: tenants roll up to their org's collusion_group_id, so five tenants
-- of one holding company count once toward m.
--
-- Publication tables carry no tenant_id and no RLS BY DESIGN: every row in them
-- has already crossed the k,m/intersection/DP/review pipeline, and the absence
-- of a tenant column is itself the guarantee that nothing tenant-attributable
-- can be stored there. Decorative RLS on a table with nothing to isolate is the
-- estate failure this schema exists to not repeat.
--
-- The epsilon ledger is the opposite: strictly tenant-scoped, append-only, with
-- budget exhaustion enforced by trigger -- an over-budget release fails at
-- INSERT, before any bytes leave.
--
-- NAMING NOTE: tenancy FKs name m1_tenants / m1_organizations, the tables that
-- m1_001_tenancy_devices.sql actually creates. See the same note in m1_040.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- ---------------------------------------------------------------------------
-- (1) Verification facts about organizations. Control-plane rows, no tenant_id:
-- these are Omium's facts about a customer, not customer data.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS org_verification (
  org_id              uuid PRIMARY KEY REFERENCES m1_organizations(id) ON DELETE RESTRICT, -- verification history is audit evidence
  billing_verified_at timestamptz,      -- a real payment method cleared; NULL = not verified
  domain_verified_at  timestamptz,      -- DNS challenge on the org's claimed domain; NULL = not verified
  -- COLLUSION COLLAPSE. Orgs sharing a billing root, a corporate parent, or a
  -- domain root are assigned the same group id by the enrollment reviewer; the
  -- m-count is over DISTINCT groups. uuid with a per-org default so an org is
  -- its own group until someone proves otherwise -- fail-toward-more-distinct
  -- would inflate m, so the default is the honest singleton.
  collusion_group_id  uuid NOT NULL DEFAULT gen_random_uuid(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- (2) Human review queue. Nothing publishes without a named human approving it.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'review_state') THEN
    CREATE TYPE review_state AS ENUM ('pending', 'approved', 'rejected');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS publication_review_queue (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id  uuid NOT NULL,
  abstraction  artifact_abstraction NOT NULL CHECK (abstraction <> 'invariant'), -- the schema-level exclusion, first of three
  -- Composite FK: the abstraction value is BOUND to the artifact row, not copied
  -- by hand -- a mislabeled queue row is a constraint violation, not a review error.
  FOREIGN KEY (artifact_id, abstraction) REFERENCES memory_artifacts (id, abstraction) ON DELETE RESTRICT,
  -- The k,m-gated, DP-noised, redacted body AS THE REVIEWER SEES IT. text, not
  -- jsonb: reviewers approve exact bytes, and jsonb normalization would let the
  -- published bytes differ from the approved ones.
  candidate_body text NOT NULL,
  state        review_state NOT NULL DEFAULT 'pending',
  reviewer     text,                     -- IdP subject of the human; NULL only while pending
  decided_at   timestamptz,
  CONSTRAINT decided_is_attributed CHECK (state = 'pending' OR (reviewer IS NOT NULL AND decided_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- (3) Publications. Global rows: no tenant_id -- structurally nothing to leak.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS artifact_publications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id  uuid NOT NULL,
  abstraction  artifact_abstraction NOT NULL CHECK (abstraction <> 'invariant'), -- exclusion, second of three
  FOREIGN KEY (artifact_id, abstraction) REFERENCES memory_artifacts (id, abstraction) ON DELETE RESTRICT,
  review_id    uuid NOT NULL REFERENCES publication_review_queue(id) ON DELETE RESTRICT, -- who approved this is permanent record
  body         text NOT NULL,            -- must byte-equal the approved candidate_body; asserted by the trigger below
  epsilon_spent numeric(8,6) NOT NULL CHECK (epsilon_spent >= 0), -- the DP cost of this release, mirrored per-tenant in the epsilon ledger
  published_at timestamptz NOT NULL DEFAULT now(),
  receipt_id   uuid NOT NULL,            -- bundle/artifact publication is per-event receipted (C13)
  CONSTRAINT uq_publication_per_artifact UNIQUE (artifact_id) -- an artifact publishes once; a revision is a new artifact
);

-- ---------------------------------------------------------------------------
-- (4) Intersection-reconstruction bookkeeping. The published body is REBUILT
-- from spans, and each span's independent producers are recorded row-by-row --
-- the m-count is an aggregate over evidence, never a stored assertion.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS publication_spans (
  publication_id uuid NOT NULL REFERENCES artifact_publications(id) ON DELETE RESTRICT,
  span_index     int  NOT NULL CHECK (span_index >= 0),  -- position in the reconstructed body
  span_sha256    bytea NOT NULL CHECK (octet_length(span_sha256) = 32), -- PLAIN hash, not HMAC: this content is post-gate and globally joinable by design
  PRIMARY KEY (publication_id, span_index)
);

CREATE TABLE IF NOT EXISTS publication_span_producers (
  publication_id  uuid NOT NULL,
  span_index      int  NOT NULL,
  contribution_id uuid NOT NULL REFERENCES artifact_contributions(id) ON DELETE RESTRICT, -- the proof rows must outlive everything they prove
  FOREIGN KEY (publication_id, span_index) REFERENCES publication_spans (publication_id, span_index) ON DELETE RESTRICT,
  PRIMARY KEY (publication_id, span_index, contribution_id)
);

-- ---------------------------------------------------------------------------
-- (5) THE GATE, form one: the HAVING clause. This is the exact shape the
-- worker's candidate query is generated from; constants k=25, m=5 are the
-- plan's Phase-5 gate values and live in ONE place (this comment and the
-- trigger below) so they cannot drift apart silently.
--
--   SELECT c.artifact_id
--     FROM artifact_contributions c
--     JOIN org_verification v
--       ON v.org_id = c.org_id
--      AND v.billing_verified_at IS NOT NULL
--      AND v.domain_verified_at  IS NOT NULL
--    GROUP BY c.artifact_id
--   HAVING count(DISTINCT c.tenant_id)          >= 25   -- k: independent producing tenants
--      AND count(DISTINCT v.collusion_group_id) >=  5;  -- m: collusion-collapsed verified orgs
--
-- THE GATE, form two: the trigger. Recomputes the same counts at publish time
-- and additionally enforces the per-span rule (each span independently produced
-- by >= m collusion groups), review approval, and body byte-equality. A worker
-- bug can now only fail to publish, never over-publish.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_km_publication_gate() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  k_count int; m_count int; bad_spans int; approved_body text;
BEGIN
  SELECT count(DISTINCT c.tenant_id), count(DISTINCT v.collusion_group_id)
    INTO k_count, m_count
    FROM artifact_contributions c
    JOIN org_verification v
      ON v.org_id = c.org_id
     AND v.billing_verified_at IS NOT NULL
     AND v.domain_verified_at  IS NOT NULL
   WHERE c.artifact_id = NEW.artifact_id;
  IF k_count < 25 OR m_count < 5 THEN
    RAISE EXCEPTION '(k,m) gate: artifact % has k=%, m=% (need k>=25, m>=5)', NEW.artifact_id, k_count, m_count
      USING ERRCODE = 'check_violation';
  END IF;

  -- Per-span: every span of the reconstructed body was independently produced
  -- by >= 5 collusion-collapsed groups. Runs AFTER because producer rows insert
  -- in the same transaction as the publication (constraint trigger, deferred).
  SELECT count(*) INTO bad_spans FROM (
    SELECT p.span_index
      FROM publication_spans p
      LEFT JOIN publication_span_producers pp
        ON (pp.publication_id, pp.span_index) = (p.publication_id, p.span_index)
      LEFT JOIN artifact_contributions c ON c.id = pp.contribution_id
      LEFT JOIN org_verification v ON v.org_id = c.org_id
     WHERE p.publication_id = NEW.id
     GROUP BY p.span_index
    HAVING count(DISTINCT v.collusion_group_id) < 5
  ) s;
  IF bad_spans > 0 THEN
    RAISE EXCEPTION 'intersection-reconstruction: % span(s) of publication % lack >=5 independent producers', bad_spans, NEW.id
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT candidate_body INTO approved_body
    FROM publication_review_queue WHERE id = NEW.review_id AND state = 'approved';
  IF approved_body IS NULL THEN
    RAISE EXCEPTION 'publication % cites review % which is not approved', NEW.id, NEW.review_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF approved_body <> NEW.body THEN
    RAISE EXCEPTION 'publication % body differs from the reviewed bytes', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS km_publication_gate ON artifact_publications;
CREATE CONSTRAINT TRIGGER km_publication_gate
  AFTER INSERT ON artifact_publications
  DEFERRABLE INITIALLY DEFERRED   -- deferred so spans+producers can land in the same tx and still be checked
  FOR EACH ROW EXECUTE FUNCTION trg_km_publication_gate();

-- ---------------------------------------------------------------------------
-- (6) The epsilon ledger. Tenant-scoped, append-only; composition is basic
-- sequential (a provable upper bound -- advanced composition can only lower
-- spend, so the trigger fails safe), and exhaustion blocks the INSERT itself.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_privacy_budgets (
  tenant_id   uuid PRIMARY KEY REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  epsilon_cap numeric(8,4) NOT NULL CHECK (epsilon_cap > 0),  -- contractual, per tenant; changing it is a contract change, so an UPDATE here is auditable
  delta_cap   numeric(12,10) NOT NULL DEFAULT 1e-6 CHECK (delta_cap > 0),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS epsilon_ledger (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT, -- spent budget is a legal record; it survives everything
  publication_id uuid REFERENCES artifact_publications(id) ON DELETE RESTRICT, -- NULL for non-publication releases (DP rollup exports)
  mechanism      text NOT NULL,           -- 'laplace_int' | 'gaussian_int' | ... (Google DP Go integer mechanisms)
  epsilon        numeric(8,6) NOT NULL CHECK (epsilon > 0),
  delta          numeric(12,10) NOT NULL DEFAULT 0 CHECK (delta >= 0),
  composed_at    timestamptz NOT NULL DEFAULT now(),
  receipt_id     uuid NOT NULL             -- every spend is receipted; an unreceipted spend is indistinguishable from a leak
);

CREATE INDEX IF NOT EXISTS ix_epsilon_ledger_tenant ON epsilon_ledger (tenant_id);

-- BUDGET EXHAUSTION, encoded. Serializes concurrent spends for one tenant
-- (correct: two half-budget releases racing must not both pass), sums under
-- basic sequential composition, and refuses the spend that would cross the cap.
-- No budget row = no spending at all: fail-closed for tenants nobody
-- provisioned, and fail-closed for a caller whose app.tenant_id GUC does not
-- match NEW.tenant_id, because RLS on tenant_privacy_budgets then returns no
-- row at all.
--
-- SEC-04 (RECONCILIATION.md) RESOLVED HERE -- THE MUTUAL EXCLUSION IS AN
-- ADVISORY LOCK, NOT `SELECT ... FOR UPDATE`.
-- The printed design took the budget row with FOR UPDATE. Postgres requires the
-- UPDATE privilege for any row-locking SELECT, and intel_app -- the role that
-- performs the DP release -- holds SELECT only on tenant_privacy_budgets, so
-- the gate would have failed with a permission error on first use. The two
-- obvious repairs are both wrong:
--   * GRANT UPDATE on tenant_privacy_budgets to intel_app -- that hands the
--     spending role the power to raise the very cap that is meant to bind it,
--     inside its own tenant, which RLS cannot prevent because it IS its tenant.
--     The budget stops being a budget.
--   * SECURITY DEFINER on the trigger -- that runs the body as mark1_owner and
--     therefore reads tenant_privacy_budgets and epsilon_ledger with the
--     owner's visibility, i.e. it bypasses the very RLS this schema exists to
--     make non-decorative. A privacy control must not be built on an RLS hole.
-- pg_advisory_xact_lock needs no table privilege at all, is transaction-scoped
-- (released on commit AND on rollback, so a refused spend leaks no lock), and
-- gives exactly the serialization FOR UPDATE was there for. The cap and the
-- running sum are then read with plain SELECTs under the caller's own RLS --
-- SECURITY INVOKER, no bypass, no widened grant.
-- The lock key is derived with md5 (a documented function; hashtext is not) and
-- namespaced by a literal so it cannot collide with another subsystem's key.
-- Correct at READ COMMITTED, which is what the release job runs at: a higher
-- isolation level would hold a snapshot taken before the lock was granted and
-- could miss a just-committed spend.
CREATE OR REPLACE FUNCTION trg_epsilon_budget() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE cap numeric; dcap numeric; spent numeric; dspent numeric;
BEGIN
  PERFORM pg_advisory_xact_lock(
    ('x' || substr(md5('m1.epsilon_ledger:' || NEW.tenant_id::text), 1, 16))::bit(64)::bigint);

  SELECT epsilon_cap, delta_cap INTO cap, dcap
    FROM tenant_privacy_budgets WHERE tenant_id = NEW.tenant_id;
  IF cap IS NULL THEN
    RAISE EXCEPTION 'no privacy budget provisioned for tenant %: DP release refused', NEW.tenant_id
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT coalesce(sum(epsilon),0), coalesce(sum(delta),0) INTO spent, dspent
    FROM epsilon_ledger WHERE tenant_id = NEW.tenant_id;
  IF spent + NEW.epsilon > cap OR dspent + NEW.delta > dcap THEN
    RAISE EXCEPTION 'privacy budget exhausted for tenant %: spent e=% of %, this release needs e=%',
      NEW.tenant_id, spent, cap, NEW.epsilon
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS epsilon_budget_gate ON epsilon_ledger;
CREATE TRIGGER epsilon_budget_gate
  BEFORE INSERT ON epsilon_ledger
  FOR EACH ROW EXECUTE FUNCTION trg_epsilon_budget();

-- The ledger is append-only at BOTH layers (the ro_012 lesson: a control that
-- holds only because a trigger caught it has already failed -- and a control
-- that holds only by grant does not bind the owner).
CREATE OR REPLACE FUNCTION trg_epsilon_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'epsilon_ledger is append-only: spent privacy budget is never edited or erased'
    USING ERRCODE = 'check_violation';
END $$;
DROP TRIGGER IF EXISTS epsilon_no_update_delete ON epsilon_ledger;
CREATE TRIGGER epsilon_no_update_delete
  BEFORE UPDATE OR DELETE ON epsilon_ledger
  FOR EACH ROW EXECUTE FUNCTION trg_epsilon_append_only();

-- Row triggers do not fire on TRUNCATE, so without this statement trigger the
-- one-statement eraser walks past both other layers -- and it is the layer that
-- matters most here, because the REVOKE below does not bind the owner (m1_002 (c)).
DROP TRIGGER IF EXISTS epsilon_no_truncate ON epsilon_ledger;
CREATE TRIGGER epsilon_no_truncate
  BEFORE TRUNCATE ON epsilon_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION trg_epsilon_append_only();

REVOKE UPDATE, DELETE, TRUNCATE ON epsilon_ledger FROM PUBLIC;

-- RLS on the tenant-scoped pair. The DP release job runs per tenant under
-- set_local_tenant -- it composes one tenant's budget, so it HAS a tenant
-- context and gets no bypass. Publication tables carry no tenant_id: RLS on
-- them would be decorative, and decorative RLS is the estate failure this
-- schema exists to not repeat.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_privacy_budgets','epsilon_ledger'] LOOP
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
    GRANT SELECT, INSERT ON epsilon_ledger TO intel_app;          -- the per-tenant DP release path; append-only by grant
    GRANT SELECT ON tenant_privacy_budgets, artifact_publications, publication_spans TO intel_app;
    -- Deliberately NO UPDATE on tenant_privacy_budgets: see the SEC-04 note above.
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mark1_federation_worker') THEN
    GRANT SELECT ON org_verification TO mark1_federation_worker;
    GRANT SELECT, INSERT, UPDATE ON publication_review_queue TO mark1_federation_worker;   -- UPDATE: recording the human's decision
    GRANT SELECT, INSERT ON artifact_publications, publication_spans, publication_span_producers TO mark1_federation_worker;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TRIGGER IF EXISTS epsilon_no_truncate ON epsilon_ledger;
--   DROP TRIGGER IF EXISTS epsilon_no_update_delete ON epsilon_ledger;
--   DROP TRIGGER IF EXISTS epsilon_budget_gate ON epsilon_ledger;
--   DROP FUNCTION IF EXISTS trg_epsilon_append_only();
--   DROP FUNCTION IF EXISTS trg_epsilon_budget();
--   DROP TABLE IF EXISTS epsilon_ledger;
--   DROP TABLE IF EXISTS tenant_privacy_budgets;
--   DROP TRIGGER IF EXISTS km_publication_gate ON artifact_publications;
--   DROP FUNCTION IF EXISTS trg_km_publication_gate();
--   DROP TABLE IF EXISTS publication_span_producers;
--   DROP TABLE IF EXISTS publication_spans;
--   DROP TABLE IF EXISTS artifact_publications;
--   DROP TABLE IF EXISTS publication_review_queue;
--   DROP TYPE IF EXISTS review_state;
--   DROP TABLE IF EXISTS org_verification;
-- COMMIT;
