-- m1_085_personal_quota_regime.sql
-- A personal tenant reads in quota basis by default.
--
-- WHY. A personal tenant is one developer on a subscription (the desktop
-- sign-in path, m1_078): there is no per-token bill, so its TVO is tokens
-- per outcome and its cost basis is quota. m1_075 seeded no row for it ("a
-- cost basis is a founder-visible fact, not a default"), so every personal
-- report defaulted to usd, found no pinned price and refused the guarantee
-- for a reason that could never apply.
--
-- The row is the honest minimum: shadow_price_usd = 0 states the report is
-- in tokens (no dollar shadow price is claimed — D22's confirmation is what a
-- tenant supplies when it wants one); window_limit_tokens = 1 is the "not
-- yet fitted" sentinel the fitting job overwrites (06 §8.4). set_by names
-- the default so the history row reads as one.
--
-- controld's enroll writes the same row for every personal tenant it
-- creates from here on (INSERT granted below); this backfills the ones that
-- exist.

INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, window_limit_tokens, shadow_price_usd, v_default, set_by)
SELECT t.id, 'quota', NULL, 1, 0, 1, 'm1_085:personal-default'
  FROM m1_tenants t
 WHERE t.kind = 'personal'
   AND NOT EXISTS (SELECT 1 FROM m1_tenant_regimes r WHERE r.tenant_id = t.id);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT INSERT ON m1_tenant_regimes TO controld_app;         -- enroll's personal default
    GRANT INSERT ON m1_tenant_regime_history TO controld_app;  -- the record trigger inserts as the caller
  END IF;
END $$;
