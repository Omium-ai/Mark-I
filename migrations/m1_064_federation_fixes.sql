-- m1_064_federation_fixes.sql
-- Closes the six m1_041 divergences the federation integration suite recorded
-- (CON-011 ledger entry, findings 1-3 and 6, plus the opt-out FR-FED-006 owes)
-- and couples the epsilon debit to the publication row (05 §5.5, FR-FED-005).
--
--   (a) ONE verification truth. org_verification becomes a VIEW over
--       m1_organizations: verified_at columns are m1_001's own, and
--       collusion_group_id is DERIVED -- the transitive closure of "shares a
--       billing_customer_id or a registrable domain root" -- so five orgs of
--       one payer collapse to one group without a reviewer typing a uuid.
--   (b) The per-span m-count joins the same verified + opted-in row source as
--       the artifact-level count (the federation_contributions view).
--   (c) A publication with zero spans is refused.
--   (d) artifact_publications, publication_spans and publication_span_producers
--       are append-only at the trigger layer, like the ledger.
--   (e) collusion_group_id: see (a).
--   (f) m1_tenants.federation_opted_out_at: an opted-out tenant's contributions
--       are absent from the gate's row source, so they count toward nothing and
--       are charged nothing.
--   (g) The gate trigger debits the epsilon ledger ITSELF, for every tenant it
--       counted, through a SECURITY DEFINER function that sets the tenant GUC
--       per row: a publication row cannot commit without its debits, a debit
--       with a publication_id cannot exist without its publication (FK), and a
--       budget refusal rolls the publication back. FORCE RLS binds the owner
--       too, so the definer sees exactly what the GUC admits -- no bypass.
--
-- DEFERRED-AT-COMMIT SEMANTICS (finding 4, kept on purpose). km_publication_gate
-- is an AFTER INSERT constraint trigger, DEFERRABLE INITIALLY DEFERRED: the
-- spans and producer rows that the per-span rule counts land in the same
-- transaction as the publication row, so the gate can only run once all three
-- are present -- at COMMIT. Consequence for any writer: a successful INSERT
-- means nothing; only a successful COMMIT means published, and a worker that
-- emits bytes between the two has been lied to. dprelease.Publish returns the
-- COMMIT error for exactly this reason.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- (f) tenant opt-out ----------------------------------------------------------
ALTER TABLE m1_tenants ADD COLUMN IF NOT EXISTS federation_opted_out_at timestamptz;

-- (a)+(e) org_verification: table -> derived view -----------------------------
-- ponytail: last-two-labels domain root, not the PSL -- over-collapses (*.co.uk is one group), the safe direction; add a PSL table when a real customer trips it.
CREATE OR REPLACE FUNCTION fed_domain_root(d text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT lower(regexp_replace(d, '^.*?([^.]+\.[^.]+)$', '\1'))
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'org_verification' AND relkind = 'r') THEN
    DROP TABLE org_verification;
  END IF;
END $$;

-- ponytail: whole-graph closure per evaluation; materialize per component when org count makes the gate slow (releases take days, so not yet).
CREATE OR REPLACE VIEW org_verification AS
WITH RECURSIVE edge AS (
  SELECT a.id AS src, b.id AS dst
    FROM m1_organizations a JOIN m1_organizations b
      ON a.id <> b.id AND a.billing_customer_id = b.billing_customer_id
  UNION
  SELECT a.id, b.id
    FROM m1_organizations a JOIN m1_organizations b
      ON a.id <> b.id AND fed_domain_root(a.primary_domain) = fed_domain_root(b.primary_domain)
), reach AS (
  SELECT id AS org_id, id AS peer FROM m1_organizations
  UNION
  SELECT r.org_id, e.dst FROM reach r JOIN edge e ON e.src = r.peer
)
SELECT o.id AS org_id, o.billing_verified_at, o.domain_verified_at,
       g.collusion_group_id
  FROM m1_organizations o
  JOIN (SELECT org_id, min(peer::text)::uuid AS collusion_group_id FROM reach GROUP BY org_id) g
    ON g.org_id = o.id;

-- (b)+(f) the gate's ONE row source: verified org, opted-in tenant ------------
-- security_invoker: the worker's BYPASSRLS reaches the two FORCE-RLS tables; org_verification stays an owner view (no grant on m1_organizations).
CREATE OR REPLACE VIEW federation_contributions WITH (security_invoker = true) AS
SELECT c.id, c.artifact_id, c.tenant_id, c.org_id, v.collusion_group_id
  FROM artifact_contributions c
  JOIN org_verification v
    ON v.org_id = c.org_id
   AND v.billing_verified_at IS NOT NULL
   AND v.domain_verified_at  IS NOT NULL
  JOIN m1_tenants t ON t.id = c.tenant_id AND t.federation_opted_out_at IS NULL;

-- (g) the debit, callable only with the gate's own inputs ---------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_epsilon_ledger_publication
  ON epsilon_ledger (tenant_id, publication_id) WHERE publication_id IS NOT NULL;

CREATE OR REPLACE FUNCTION fed_debit_epsilon(pub uuid, tenants uuid[], eps numeric, receipt uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE t uuid;
BEGIN
  IF coalesce(cardinality(tenants), 0) = 0 THEN
    RAISE EXCEPTION 'publication % charges no tenant', pub USING ERRCODE = 'check_violation';
  END IF;
  FOREACH t IN ARRAY tenants LOOP
    PERFORM set_config('app.tenant_id', t::text, true);
    INSERT INTO epsilon_ledger (tenant_id, publication_id, mechanism, epsilon, receipt_id)
    VALUES (t, pub, 'laplace_int', eps, receipt);
  END LOOP;
  PERFORM set_config('app.tenant_id', '', true);
END $$;

-- The gate, form two, rewritten over federation_contributions -----------------
--   SELECT artifact_id FROM federation_contributions
--    GROUP BY artifact_id
--   HAVING count(DISTINCT tenant_id) >= 25 AND count(DISTINCT collusion_group_id) >= 5;
CREATE OR REPLACE FUNCTION trg_km_publication_gate() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  k_count int; m_count int; span_count int; bad_spans int; approved_body text; tenants uuid[];
BEGIN
  SELECT count(DISTINCT tenant_id), count(DISTINCT collusion_group_id), array_agg(DISTINCT tenant_id)
    INTO k_count, m_count, tenants
    FROM federation_contributions WHERE artifact_id = NEW.artifact_id;
  IF k_count < 25 OR m_count < 5 THEN
    RAISE EXCEPTION '(k,m) gate: artifact % has k=%, m=% (need k>=25, m>=5)', NEW.artifact_id, k_count, m_count
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT count(*) INTO span_count FROM publication_spans WHERE publication_id = NEW.id;
  IF span_count = 0 THEN
    RAISE EXCEPTION 'intersection-reconstruction: publication % has no spans', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;

  SELECT count(*) INTO bad_spans FROM (
    SELECT p.span_index
      FROM publication_spans p
      LEFT JOIN publication_span_producers pp
        ON (pp.publication_id, pp.span_index) = (p.publication_id, p.span_index)
      LEFT JOIN federation_contributions c ON c.id = pp.contribution_id AND c.artifact_id = NEW.artifact_id
     WHERE p.publication_id = NEW.id
     GROUP BY p.span_index
    HAVING count(DISTINCT c.collusion_group_id) < 5
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

  PERFORM fed_debit_epsilon(NEW.id, tenants, NEW.epsilon_spent, NEW.receipt_id);
  RETURN NEW;
END $$;

-- (d) append-only publication evidence ---------------------------------------
CREATE OR REPLACE FUNCTION trg_fed_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: published evidence is never edited or erased', TG_TABLE_NAME
    USING ERRCODE = 'check_violation';
END $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['artifact_publications','publication_spans','publication_span_producers'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS fed_no_update_delete ON %I', t);
    EXECUTE format('CREATE TRIGGER fed_no_update_delete BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION trg_fed_append_only()', t);
    EXECUTE format('DROP TRIGGER IF EXISTS fed_no_truncate ON %I', t);
    EXECUTE format('CREATE TRIGGER fed_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION trg_fed_append_only()', t);
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM PUBLIC', t);
  END LOOP;
END $$;

-- Grants: the dropped table took m1_041/m1_060's with it -----------------------
DO $$
BEGIN
  REVOKE EXECUTE ON FUNCTION fed_debit_epsilon(uuid, uuid[], numeric, uuid) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mark1_federation_worker') THEN
    GRANT SELECT ON org_verification, federation_contributions TO mark1_federation_worker;
    GRANT SELECT (id, org_id, federation_opted_out_at) ON m1_tenants TO mark1_federation_worker;
    GRANT EXECUTE ON FUNCTION fed_debit_epsilon(uuid, uuid[], numeric, uuid) TO mark1_federation_worker;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; org_verification returns as m1_041's table
-- only by re-applying m1_041 after this):
-- BEGIN;
--   DROP TRIGGER IF EXISTS fed_no_update_delete ON artifact_publications;
--   DROP TRIGGER IF EXISTS fed_no_truncate ON artifact_publications;
--   DROP TRIGGER IF EXISTS fed_no_update_delete ON publication_spans;
--   DROP TRIGGER IF EXISTS fed_no_truncate ON publication_spans;
--   DROP TRIGGER IF EXISTS fed_no_update_delete ON publication_span_producers;
--   DROP TRIGGER IF EXISTS fed_no_truncate ON publication_span_producers;
--   DROP FUNCTION IF EXISTS trg_fed_append_only();
--   DROP FUNCTION IF EXISTS fed_debit_epsilon(uuid, uuid[], numeric, uuid);
--   DROP INDEX IF EXISTS uq_epsilon_ledger_publication;
--   DROP VIEW IF EXISTS federation_contributions;
--   DROP VIEW IF EXISTS org_verification;
--   DROP FUNCTION IF EXISTS fed_domain_root(text);
--   ALTER TABLE m1_tenants DROP COLUMN IF EXISTS federation_opted_out_at;
-- COMMIT;
