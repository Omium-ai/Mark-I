-- m1_074_certified_runs.sql
-- T3 certified runs (06 §2.5 tier T3; 14 task 6.5 "rent E2B/Daytona first"). One row
-- per (task, attempt, anchor) run of a declared test anchor inside a rented microVM.
-- The sandbox is a cloud subprocessor, so the run is admitted through the SAME
-- register as cloud judging (m1_065, 06 §6.5 preconditions 1-4): consent_id is the
-- row the run cites. E0 carries no code (nothing to materialise) and E2 never leaves
-- the customer boundary, so evidence_tier is E1 by CHECK, not by convention.
--
-- The edge's T0 vote for the same anchor is the reward-hacking surface (10 §11.3);
-- `divergence` is the signed anchor-vs-T3 comparison per run (+1 = the edge accepted
-- what the certified environment rejects, -1 = the reverse, 0 = agreement or an
-- infra failure on either side) and `tenant_divergence` the tenant's running mean at
-- insert time -- the per-tenant adversarial-ML metric, readable off the row.
--
-- task_id/attempt_id are ledger identities (m1p.v1.Event); no Postgres task or
-- session table exists to reference. receipt_id stays NULL: no certified_run receipt
-- class exists (m1_002 record shape, controld ServerRecordTypes); the row is the
-- durable fact a future receipt cites.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- The register keys on judge_id; a certified run is not a judge and must not be
-- consented under a judge's name. Additive rewrite of m1_065's inline CHECK (the
-- m1_069 precedent): 't3:<provider>@<v>' joins 'judge:<name>@<v>' and m1_073's
-- 'rm:<model>@<v>'. The last rewrite wins, so every rewrite of this CHECK must
-- carry the full set.
ALTER TABLE m1_cloud_judge_consents DROP CONSTRAINT IF EXISTS m1_cloud_judge_consents_judge_id_check;
ALTER TABLE m1_cloud_judge_consents ADD CONSTRAINT m1_cloud_judge_consents_judge_id_check
  CHECK (judge_id ~ '^(judge|rm|t3):[a-z0-9-]+@[1-9][0-9]*$');

CREATE TABLE IF NOT EXISTS m1_certified_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  consent_id        uuid NOT NULL REFERENCES m1_cloud_judge_consents(id) ON DELETE RESTRICT,
  task_id           uuid NOT NULL,
  attempt_id        uuid NOT NULL,
  anchor_id         text NOT NULL,                -- the edge's catalog id ("pytest@cat-1")
  provider          text NOT NULL CHECK (provider IN ('e2b')),
  sandbox_id        text,                         -- NULL when create() itself failed
  evidence_tier     text NOT NULL CHECK (evidence_tier = 'E1'),
  execution_hash    bytea NOT NULL CHECK (octet_length(execution_hash) = 32),
  exit_code         int,                          -- NULL when the run never returned
  verdict           verdict NOT NULL,             -- the certified result
  edge_verdict      verdict NOT NULL,             -- the edge's T0 vote for anchor_id
  provisional       verdict NOT NULL,             -- the edge's fused PROVISIONAL verdict
  divergence        smallint NOT NULL CHECK (divergence IN (-1, 0, 1)),
  tenant_divergence numeric(7,6) NOT NULL CHECK (tenant_divergence BETWEEN -1 AND 1),
  receipt_id        uuid,
  started_at        timestamptz NOT NULL,
  finished_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_m1_certified_runs_ordered CHECK (finished_at >= started_at)
);

CREATE INDEX IF NOT EXISTS ix_m1_certified_runs_tenant_time
  ON m1_certified_runs (tenant_id, finished_at DESC);

ALTER TABLE m1_certified_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_certified_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_certified_runs;
CREATE POLICY tenant_isolation ON m1_certified_runs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_certified_runs FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT ON m1_certified_runs TO adjudicator_app;  -- append-only: a run happened
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON m1_certified_runs TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; drops the only record that evidence was sent to
-- a subprocessor -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_certified_runs;
--   ALTER TABLE m1_cloud_judge_consents DROP CONSTRAINT IF EXISTS m1_cloud_judge_consents_judge_id_check;
--   ALTER TABLE m1_cloud_judge_consents ADD CONSTRAINT m1_cloud_judge_consents_judge_id_check
--     CHECK (judge_id ~ '^(judge|rm):[a-z0-9-]+@[1-9][0-9]*$');
-- COMMIT;
