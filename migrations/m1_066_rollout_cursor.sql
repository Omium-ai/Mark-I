-- m1_066_rollout_cursor.sql
-- The canary controller's cursor (05 §4.3; §1.5 "cursors live in Postgres,
-- not memory"): one row per (tenant, channel) naming the rollout under
-- control (seq), the step it is serving (cohort_percent), when that step
-- began (the soak clock), the consecutive-regressed-tick count for the 2σ
-- rule, and -- once halted -- why and which seq carried the rollback.
--
-- A halt is sticky: the row stays halted until a NEW publication moves the
-- channel head past both seq and rollback_seq, at which point the controller
-- resets the row for the new rollout. Nobody unhalts a row in place; the
-- fix for a halted rollout is a forward publication, never a cursor edit.
--
-- controld_app holds SELECT/INSERT/UPDATE: this is a cursor, not a ledger.
-- DELETE and TRUNCATE are revoked from every *_app role by name, restating
-- m1_060's narrowing sweep for a table that postdates it.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS rollout_cursor (
  tenant_id       uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  channel         text NOT NULL,
  seq             bigint NOT NULL CHECK (seq >= 1),
  cohort_percent  int NOT NULL CHECK (cohort_percent BETWEEN 0 AND 100),
  step_started_at timestamptz NOT NULL DEFAULT now(),
  health_ticks    int NOT NULL DEFAULT 0 CHECK (health_ticks >= 0),
  halted_at       timestamptz,
  halt_reason     text,
  rollback_seq    bigint,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, channel),
  FOREIGN KEY (tenant_id, channel, seq) REFERENCES policy_bundles (tenant_id, channel, seq) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, channel, rollback_seq) REFERENCES policy_bundles (tenant_id, channel, seq) ON DELETE RESTRICT,
  CONSTRAINT rollout_cursor_halt_evidence CHECK ((halted_at IS NULL) = (halt_reason IS NULL)),
  CONSTRAINT rollout_cursor_rollback_is_forward CHECK (rollback_seq IS NULL OR (halted_at IS NOT NULL AND rollback_seq > seq))
);

ALTER TABLE rollout_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_cursor FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON rollout_cursor;
CREATE POLICY tenant_isolation ON rollout_cursor
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON rollout_cursor FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE ON rollout_cursor TO controld_app;
  END IF;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE DELETE, TRUNCATE ON rollout_cursor FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; loses only rollout position -- the next
-- tick re-seeds every channel at the first step from its current head):
-- BEGIN;
--   DROP TABLE IF EXISTS rollout_cursor;
-- COMMIT;
