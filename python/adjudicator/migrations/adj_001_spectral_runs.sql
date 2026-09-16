-- adj_001_spectral_runs.sql
-- The nightly spectral_estimate output (06 §1.2 batch table; §4.3 "the diagnostics
-- are computed and stored with every run either way"). One row per (tenant, window):
-- the §4.3 gate verdict, all six diagnostics, and — only when the gate passed — the
-- per-verifier confusion laws and the class prior. certs.recompute (runs_after) reads
-- the row for its window and copies passed/diagnostics onto the certificate
-- (identifiable, diagnostics), so a `certified` status can cite the run that earned it.
-- Idempotent upsert keyed by the job identity (06 §7.3): a re-run recomputes the same
-- window into the same row.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS spectral_runs (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  window_start  timestamptz NOT NULL,   -- the nightly closed UTC day (job_runs.window_start)
  window_days   int NOT NULL CHECK (window_days >= 1),  -- trailing vote window ending that day
  n_tasks       int NOT NULL CHECK (n_tasks >= 0),
  passed        boolean NOT NULL,       -- spectral.identifiability.Diagnostics.passed, verbatim
  diagnostics   jsonb NOT NULL,         -- the six §4.3 diagnostics + failed gates, NaN as null
  confusion     jsonb NOT NULL DEFAULT '{}'::jsonb,  -- verifier_id -> [satisfied, violated] x [accept, reject, abstain]; {} unless passed
  prior         jsonb,                  -- [pi_satisfied, pi_violated]; null unless passed
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, window_start)
);

ALTER TABLE spectral_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE spectral_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON spectral_runs;
CREATE POLICY tenant_isolation ON spectral_runs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON spectral_runs FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT, UPDATE ON spectral_runs TO adjudicator_app;
    REVOKE DELETE, TRUNCATE ON spectral_runs FROM adjudicator_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses only estimator history -- the next
-- nightly recomputes its window):
-- BEGIN;
--   DROP TABLE IF EXISTS spectral_runs;
-- COMMIT;
