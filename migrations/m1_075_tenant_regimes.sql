-- m1_075_tenant_regimes.sql
-- The per-tenant regime source (06 §8.4; 02 FR-ROUTE-004 / FR-VERIFY-009): what the
-- ledger rows do not carry and the compiler and the TVO report cannot proceed without.
-- One row per tenant, exactly one cost basis (CON-014: never mixed):
--   usd    -> price_model_id, the model whose pinned app/pricing row prices the tenant's
--             attempts (the versioned model_prices table ships in the intel repo as data;
--             the report stamps its digest);
--   quota  -> window_limit_tokens fitted from transcript-observed rate-limit events and
--             shadow_price_usd, the tenant-CONFIRMED S (D22's $200 is a placeholder the
--             code refuses to treat as confirmed -- it is never a row default here);
--   both   -> v_default, V(task)'s fallback (06 §8.1).
-- The basis-inputs CHECK mirrors report.py: a field of the other basis on a row is a
-- constructor error, not a stray.
--
-- Every set is recorded: an AFTER INSERT OR UPDATE trigger mirrors the new row into an
-- append-only history (m1_002's three-way pattern: trigger, TRUNCATE trigger, REVOKE), so
-- "who set S to what, when" is evidence, not a log line. A tenant with no row cannot
-- compile and cannot earn guarantee-grade -- the honest state, by design.
-- intel_app: SELECT/INSERT/UPDATE on the settings row, SELECT/INSERT on the history
-- (the trigger inserts as the caller); DELETE and TRUNCATE revoked from every *_app role.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_tenant_regimes (
  tenant_id            uuid PRIMARY KEY REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  cost_basis           text NOT NULL CHECK (cost_basis IN ('usd', 'quota')),
  price_model_id       text,                 -- usd: the pinned app/pricing row's model_id
  window_limit_tokens  bigint,               -- quota: fitted, never assumed (06 §8.4)
  shadow_price_usd     numeric(12, 4),       -- quota: S, tenant-confirmed (D22)
  v_default            numeric(14, 4) NOT NULL CHECK (v_default > 0),  -- V(task) fallback (06 §8.1)
  set_by               text NOT NULL CHECK (set_by <> ''),
  set_at               timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT m1_tenant_regimes_basis_inputs CHECK (
    CASE cost_basis
      WHEN 'usd'   THEN price_model_id IS NOT NULL AND window_limit_tokens IS NULL AND shadow_price_usd IS NULL
      WHEN 'quota' THEN price_model_id IS NULL AND COALESCE(window_limit_tokens, 0) > 0 AND COALESCE(shadow_price_usd, -1) >= 0
    END
  )
);

CREATE TABLE IF NOT EXISTS m1_tenant_regime_history (
  id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id            uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  cost_basis           text NOT NULL,
  price_model_id       text,
  window_limit_tokens  bigint,
  shadow_price_usd     numeric(12, 4),
  v_default            numeric(14, 4) NOT NULL,
  set_by               text NOT NULL,
  set_at               timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_m1_tenant_regime_history_tenant
  ON m1_tenant_regime_history (tenant_id, set_at);

CREATE OR REPLACE FUNCTION m1_tenant_regime_record() RETURNS trigger AS $$
BEGIN
  INSERT INTO m1_tenant_regime_history
    (tenant_id, cost_basis, price_model_id, window_limit_tokens, shadow_price_usd, v_default, set_by, set_at)
  VALUES
    (NEW.tenant_id, NEW.cost_basis, NEW.price_model_id, NEW.window_limit_tokens, NEW.shadow_price_usd,
     NEW.v_default, NEW.set_by, NEW.set_at);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_m1_tenant_regimes_record ON m1_tenant_regimes;
CREATE TRIGGER trg_m1_tenant_regimes_record
  AFTER INSERT OR UPDATE ON m1_tenant_regimes
  FOR EACH ROW EXECUTE FUNCTION m1_tenant_regime_record();

-- History is append-only three ways (m1_002): m1_append_only() holds even for the owner.
DROP TRIGGER IF EXISTS trg_m1_tenant_regime_history_append_only ON m1_tenant_regime_history;
CREATE TRIGGER trg_m1_tenant_regime_history_append_only
  BEFORE UPDATE OR DELETE ON m1_tenant_regime_history
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_tenant_regime_history_no_truncate ON m1_tenant_regime_history;
CREATE TRIGGER trg_m1_tenant_regime_history_no_truncate
  BEFORE TRUNCATE ON m1_tenant_regime_history
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

ALTER TABLE m1_tenant_regimes ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_tenant_regimes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_tenant_regimes;
CREATE POLICY tenant_isolation ON m1_tenant_regimes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE m1_tenant_regime_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_tenant_regime_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_tenant_regime_history;
CREATE POLICY tenant_isolation ON m1_tenant_regime_history
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_tenant_regimes, m1_tenant_regime_history FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_tenant_regimes TO intel_app;
    GRANT SELECT, INSERT ON m1_tenant_regime_history TO intel_app;
  END IF;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE DELETE, TRUNCATE ON m1_tenant_regimes FROM %I', r);
      EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON m1_tenant_regime_history FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (manual; loses every tenant's regime and its history -- compiles and
-- guarantee-grade reports stop until the rows are re-set):
-- BEGIN;
--   DROP TRIGGER IF EXISTS trg_m1_tenant_regimes_record ON m1_tenant_regimes;
--   DROP FUNCTION IF EXISTS m1_tenant_regime_record();
--   DROP TABLE IF EXISTS m1_tenant_regime_history;
--   DROP TABLE IF EXISTS m1_tenant_regimes;
-- COMMIT;
