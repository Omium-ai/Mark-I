-- m1_067_job_runs.sql
-- The job ledger (06 §7.3 idempotency layer 1; ADR-0010 layer 1 that tvo/rollup.py
-- defers to "the scheduler wave"). One row per (job, tenant, window): a retry is the
-- SAME row with attempts+1, a re-run of a succeeded window is a no-op that only
-- bumps `requested`, so the row itself says "asked twice, ran once". Every
-- registered job is per-tenant, hence tenant_id NOT NULL under the canonical RLS
-- form; a global job is a later migration, not a nullable column that RLS would
-- hide from every app role.
--
-- Written by BOTH intel_app (memory/policy_compiler/ope/corpus/tvo jobs) and
-- adjudicator_app (gold/certs jobs); the job name carries the owning service.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS job_runs (
  job           text NOT NULL,
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  window_start  timestamptz NOT NULL,   -- nightly: the closed UTC day; hourly: the closed UTC hour
  outcome       text NOT NULL
                  CHECK (outcome IN ('running', 'succeeded', 'failed', 'parked',
                                     'skipped_prereq_failed')),
  attempts      int NOT NULL DEFAULT 0 CHECK (attempts >= 0),   -- times the callable actually ran
  requested     int NOT NULL DEFAULT 1 CHECK (requested >= 1),  -- times the runner was asked
  receipt_id    uuid,                   -- the job's receipted output, when it emits one (C13)
  error         text,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  PRIMARY KEY (job, tenant_id, window_start),
  CONSTRAINT job_runs_finished CHECK ((outcome = 'running') = (finished_at IS NULL))
);

ALTER TABLE job_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON job_runs;
CREATE POLICY tenant_isolation ON job_runs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON job_runs FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['intel_app', 'adjudicator_app'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT SELECT, INSERT, UPDATE ON job_runs TO %I', r);
    END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE DELETE, TRUNCATE ON job_runs FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses only run history -- every job is
-- idempotent on its own outputs, so the next run recomputes, never double-counts):
-- BEGIN;
--   DROP TABLE IF EXISTS job_runs;
-- COMMIT;
