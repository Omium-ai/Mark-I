-- m1_101_llm_spend_days.sql
-- 16 §L1/§L6: the paid cloud calls (cloud judge and memory extraction on Nebius through the llm-router, the
-- cloud RM on Baseten) are capped per tenant per UTC day, not per run. One row per (tenant, UTC day, spend
-- key) counts the units RESERVED before any call (app/llm.py reserve_today): a rerun, a retry after a crash or
-- a second window on the same day draws on the same row, so no schedule can multiply spend. A reservation is
-- never returned (a refused call still spent its slot): the ledger can under-spend a cap, never exceed it.
-- The day is the database clock's UTC date, one clock for every pod.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_llm_spend_days (
  tenant_id   uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  day         date NOT NULL,
  spend_key   text NOT NULL CHECK (spend_key ~ '^(judge|rm|mem):[a-z0-9-]+@[1-9][0-9]*$'),
  units       int  NOT NULL DEFAULT 0 CHECK (units >= 0),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, day, spend_key)
);

ALTER TABLE m1_llm_spend_days ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_llm_spend_days FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_llm_spend_days;
CREATE POLICY tenant_isolation ON m1_llm_spend_days
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON m1_llm_spend_days FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['intel_app', 'adjudicator_app'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT SELECT, INSERT, UPDATE ON m1_llm_spend_days TO %I', r);
      EXECUTE format('REVOKE DELETE, TRUNCATE ON m1_llm_spend_days FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; the caps then fall back to the per-run bound only):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_llm_spend_days;
-- COMMIT;
