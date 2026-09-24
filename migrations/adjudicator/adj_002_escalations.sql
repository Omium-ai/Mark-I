-- adj_002_escalations.sql
-- The nightly readjudicate output (06 §1.2 batch table; §6.2 step 1 selects the tasks:
-- fused |eta - band edges| < D18 margin). One row per (tenant, task): the provisional eta
-- that selected it, the escalated VerdictEvent (adjudicate(..., escalation=True): stage,
-- verdict, posterior, provenance, cert), the consistency-vote facts FR-VERIFY-017 scopes to
-- this stage, the T3 run it cited (or why none ran), and the T2 reward model's shadow vote
-- against the escalated verdict -- the 06 §12.4 row-2 pair promotion.step measures.
-- No ingest path exists from this service to the ledger, so the REVISED verdict lives
-- here, not on m1p_events. Idempotent upsert keyed by (tenant, task) (06 §7.3): a re-run
-- recomputes the same task into the same row.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS escalations (
  tenant_id            uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  task_id              uuid NOT NULL,
  window_start         timestamptz NOT NULL,   -- the nightly closed UTC day (job_runs.window_start)
  eta                  numeric(7,6) NOT NULL CHECK (eta BETWEEN 0 AND 1),  -- provisional posterior[satisfied]
  provisional          verdict NOT NULL,       -- the provisional-stage verdict the eta produced
  verdict              verdict NOT NULL,       -- escalated
  stage                text NOT NULL CHECK (stage IN ('CERTIFIED', 'bootstrapping', 'uncertified')),
  posterior            double precision[] NOT NULL CHECK (array_length(posterior, 1) = 4),
  provenance           text NOT NULL CHECK (provenance IN ('prior', 'shrunk-global', 'spectral')),
  noise_cert_id        uuid REFERENCES noise_certificates(id) ON DELETE RESTRICT,
  vote_count           int NOT NULL CHECK (vote_count >= 0),
  consistency_fused    int NOT NULL DEFAULT 0 CHECK (consistency_fused >= 0),
  consistency_excluded int NOT NULL DEFAULT 0 CHECK (consistency_excluded >= 0),
  agreement_rate       numeric(7,6) CHECK (agreement_rate BETWEEN 0 AND 1),  -- ConsistencyVote.agreement_rate; NULL = no T3 run
  certified_run_id     uuid REFERENCES m1_certified_runs(id) ON DELETE RESTRICT,
  t3_skipped           text,                   -- why no T3 run happened; NULL iff certified_run_id set
  rm_verifier_id       text,                   -- the shadow member; NULL = no RM vote this run
  rm_vote              text CHECK (rm_vote IN ('accept', 'reject', 'abstain')),
  rm_skipped           text,                   -- counted refusal reason; NULL iff rm_vote set
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id),
  CONSTRAINT ck_escalations_t3 CHECK ((certified_run_id IS NULL) = (t3_skipped IS NOT NULL)),
  CONSTRAINT ck_escalations_rm CHECK ((rm_vote IS NULL) = (rm_skipped IS NOT NULL)),
  CONSTRAINT ck_escalations_rm_id CHECK ((rm_vote IS NULL) = (rm_verifier_id IS NULL))
);

ALTER TABLE escalations ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON escalations;
CREATE POLICY tenant_isolation ON escalations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON escalations FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT, UPDATE ON escalations TO adjudicator_app;
    REVOKE DELETE, TRUNCATE ON escalations FROM adjudicator_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses the escalated verdicts and the shadow pairs
-- promotion.step measures -- the next nightly re-escalates tasks still in its window):
-- BEGIN;
--   DROP TABLE IF EXISTS escalations;
-- COMMIT;
