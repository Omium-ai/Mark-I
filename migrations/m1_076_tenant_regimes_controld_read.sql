-- m1_076_tenant_regimes_controld_read.sql
-- controld's GET /api/v1/reports/tvo (08 §3.3) resolves the tenant's cost basis from
-- its m1_075 row (06 §8.4/§8.5: guarantee grade needs the regime set and, for usd, the
-- pinned model). m1_075 granted the table to intel_app only; controld_app reads it,
-- under FORCE RLS + the tenant GUC, and never writes it -- intel stays the sole setter.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON m1_tenant_regimes TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   REVOKE SELECT ON m1_tenant_regimes FROM controld_app;
-- COMMIT;
