-- m1_070_bundle_drafts.sql
-- The compiler → policydist hand-off (05 §4.1 "policydist's internal publication
-- path (in-repo, not a public route)"; 06 §10.4). mark1-intel's policy compiler
-- INSERTs one draft per (tenant, channel, compile window): the six canonical
-- section byte strings, their map hash, and the knee sanity gate's verdict.
-- controld's draft publisher (policydist/drafts.go) claims pending drafts,
-- re-runs the strict reference decode, and either publishes through
-- Module.Publish (state 'published', published_seq, canary_plan attached) or
-- records why it refused (state 'refused'). The compiler holds no signing key
-- and no publish verb: it can only ask.
--
-- The primary key is the job identity (06 §7.3): a re-run of the same window
-- is the same row, so a retried compile cannot mint a second publication.
-- intel_app INSERT/SELECT only; controld_app SELECT/UPDATE only; DELETE and
-- TRUNCATE revoked from every *_app role by name (m1_060's narrowing sweep).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS bundle_drafts (
  tenant_id       uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  channel         text NOT NULL,
  window_start    timestamptz NOT NULL,       -- the compile job's closed window (job_runs.window_start)
  -- Canonical CBOR per section (07 PolicyBundle v1; 06 §10.4 rule 2: the compiler
  -- submits canonical section bytes, signing happens in controld).
  verify_cbor     bytea NOT NULL,
  route_cbor      bytea NOT NULL,
  memory_cbor     bytea NOT NULL,
  cortex_cbor     bytea NOT NULL,
  gates_cbor      bytea NOT NULL,
  agent_maps_cbor bytea NOT NULL,
  draft_hash      bytea NOT NULL CHECK (octet_length(draft_hash) = 32),  -- sha256 of the six-section canonical map
  max_age         interval NOT NULL,
  knee_gate_ok    boolean NOT NULL,           -- 06 §10.3: implied knee within ±1 of k*(ρ̂, γ̂); false blocks publication
  knee_note       text NOT NULL,
  state           text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'published', 'refused')),
  refusal_reason  text,
  published_seq   bigint,
  canary_plan     jsonb,                      -- 06 §10.4 rule 4, attached by controld at publication
  claimed_at      timestamptz,                -- the publisher's lease; a crashed publish is reclaimable
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, channel, window_start),
  FOREIGN KEY (tenant_id, channel, published_seq) REFERENCES policy_bundles (tenant_id, channel, seq) ON DELETE RESTRICT,
  CONSTRAINT bundle_drafts_state_evidence CHECK (
    CASE state
      WHEN 'pending'   THEN refusal_reason IS NULL     AND published_seq IS NULL
      WHEN 'published' THEN refusal_reason IS NULL     AND published_seq IS NOT NULL
      WHEN 'refused'   THEN refusal_reason IS NOT NULL AND published_seq IS NULL
    END
  )
);

CREATE INDEX IF NOT EXISTS ix_bundle_drafts_pending ON bundle_drafts (tenant_id, window_start)
  WHERE state = 'pending';

ALTER TABLE bundle_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bundle_drafts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bundle_drafts;
CREATE POLICY tenant_isolation ON bundle_drafts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON bundle_drafts FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT, INSERT ON bundle_drafts TO intel_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, UPDATE ON bundle_drafts TO controld_app;
  END IF;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE DELETE, TRUNCATE ON bundle_drafts FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses only unpublished drafts and the
-- plan attachments -- published bundles, receipts and the log are untouched):
-- BEGIN;
--   DROP TABLE IF EXISTS bundle_drafts;
-- COMMIT;
