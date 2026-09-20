-- m1_087_spectral_runs_intel_read.sql
-- The nightly compiler (python/intel/app/policy_compiler/jobs.py) reads the tenant's newest
-- spectral_runs row (adj_001_spectral_runs.sql, adjudicator-owned, FORCE RLS + tenant GUC) to
-- build the `verify` section: an identifiable run's fitted confusion/prior, or else the
-- `stable` head carried forward -- never the zero-verifier default (06 §4). intel already
-- reads noise_certificates (m1_021) and policy_bundles (m1_042); this is the same reader grant
-- on the estimator's own table.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON spectral_runs TO intel_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   REVOKE SELECT ON spectral_runs FROM intel_app;
-- COMMIT;
