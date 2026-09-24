-- adj_003_judge_dispatches.sql
-- The nightly judge_batch output (06 §1.2 batch table; §6.2 step 1 selects the tasks:
-- ambiguous under D18 and carrying no vote from the judge). One row per (tenant, task,
-- judge): the request_id the edge dedupes on (client-side, the C4 default: vote stays
-- NULL here because it lands in the ledger from the customer's own key) or, under an
-- m1_065 consent row, the cloud vote the Anthropic Batch returned with the token counts
-- 06 §6.4 books as verifier spend v and §6.3's cache_read SLO reads. A cloud row with a
-- vote is a spent call: a retried job re-posts it to the ledger and never re-calls the
-- model (06 §7.3.5). No judge_batch receipt class exists (m1_002 record shape, controld
-- ServerRecordTypes); the row is the durable fact a future receipt cites (m1_074 precedent).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS judge_dispatches (
  tenant_id                   uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  task_id                     uuid NOT NULL,
  judge_id                    text NOT NULL CHECK (judge_id ~ '^judge:[a-z0-9-]+@[1-9][0-9]*$'),
  request_id                  uuid NOT NULL,          -- specs.request_id_for; one vote per id at the edge
  window_start                timestamptz NOT NULL,   -- the nightly closed UTC day (job_runs.window_start)
  locus                       text NOT NULL CHECK (locus IN ('client_side', 'cloud')),
  vote                        verdict,                -- cloud only; NULL = dispatched, vote lands from the edge
  model                       text,
  batch_id                    text,                   -- the vendor's msgbatch id
  input_tokens                bigint CHECK (input_tokens >= 0),
  output_tokens               bigint CHECK (output_tokens >= 0),
  cache_creation_input_tokens bigint CHECK (cache_creation_input_tokens >= 0),
  cache_read_input_tokens     bigint CHECK (cache_read_input_tokens >= 0),
  dispatched_at               timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id, judge_id),
  CONSTRAINT ck_judge_dispatches_cloud CHECK (
    (locus = 'cloud') = (vote IS NOT NULL AND model IS NOT NULL AND input_tokens IS NOT NULL
                         AND output_tokens IS NOT NULL)
  )
);

ALTER TABLE judge_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE judge_dispatches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON judge_dispatches;
CREATE POLICY tenant_isolation ON judge_dispatches
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON judge_dispatches FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT, UPDATE ON judge_dispatches TO adjudicator_app;
    REVOKE DELETE, TRUNCATE ON judge_dispatches FROM adjudicator_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses the spent-call record, so the next nightly
-- re-calls the model for any cloud vote the ledger did not receive):
-- BEGIN;
--   DROP TABLE IF EXISTS judge_dispatches;
-- COMMIT;
