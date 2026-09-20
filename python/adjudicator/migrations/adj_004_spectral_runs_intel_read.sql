-- adj_004_spectral_runs_intel_read.sql
-- The nightly policy compiler (intel app/policy_compiler/jobs.py) reads the tenant's newest
-- spectral_runs row to compile the bundle's verify section: an identifiable run's fitted
-- confusion and prior, else the stable head carried forward. The grant lives in this tree
-- because the table does (adj_001): the m1 tree runs first in prod and alone in the Go
-- harness, where a grant on a table that does not exist yet fails.
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
