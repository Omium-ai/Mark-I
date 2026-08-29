-- m1_043_coverage.sql
-- Coverage transitions + the derived band every TVO report must carry
-- (plan compliance point 7). The transition log is the ground truth; bands
-- are arithmetic over it, recomputable by anyone holding the receipts.
--
-- A TVO number computed over a window where capture was off for an afternoon is
-- a lie with a decimal point. Coverage makes every gap attributable: the raw
-- store mirrors the receipted CoverageTransition M1P events one-to-one, so
-- ledger and Postgres can be reconciled row-by-row, and the coverage state of
-- any instant is derivable -- covered iff the last transition on that
-- (device, workspace) surface is 'enable' or 'bypass_end'. Time before a
-- surface's first 'enable' is uncovered AND attributed; there is deliberately
-- no "assumed covered" state, for the same reason the sweeper has no "assumed
-- clean" one.
--
-- NAMING NOTE: tenancy/device FKs name m1_tenants / m1_devices, the tables that
-- m1_001_tenancy_devices.sql actually creates. See the same note in m1_040.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'coverage_kind') THEN
    -- Four kinds, not a boolean: 'disable' (mark1 off / workspace un-enrolled)
    -- and 'bypass_start' (MARK1_DISABLE=1, kill-switch) are different facts
    -- with different contractual weight, even though both open a gap.
    CREATE TYPE coverage_kind AS ENUM ('enable', 'disable', 'bypass_start', 'bypass_end');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'coverage_band') THEN
    -- 'A' >= 0.98, 'B' >= 0.90, 'C' >= 0.75, else 'insufficient'. An enum, not
    -- text, because the guarantee CHECK below compares against it and a typo'd
    -- band must be unrepresentable.
    CREATE TYPE coverage_band AS ENUM ('A', 'B', 'C', 'insufficient');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS coverage_transitions (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- bigint identity, not uuid: the band query orders by (occurred_at, id) and an insertion-ordered tiebreaker is the point
  tenant_id        uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  device_id        uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT, -- a revoked device's gaps still count against its tenant's band
  -- Per-tenant HMAC of the workspace root path: identifies the surface without
  -- storing a path (evidence carries no paths).
  workspace_digest bytea NOT NULL CHECK (octet_length(workspace_digest) = 32),
  kind             coverage_kind NOT NULL,
  occurred_at      timestamptz NOT NULL,
  event_id         uuid NOT NULL UNIQUE,  -- the M1P CoverageTransition event this row mirrors; UNIQUE = at-least-once ingest cannot double-count a gap
  -- Mirrors CoverageTransition.reason_code VERBATIM. This row and that event are
  -- reconciled one-by-one on event_id, so the two vocabularies must be the same
  -- vocabulary or the reconciliation compares strings that can never match.
  -- The set is 04 §2.7's, and 04 §2.7 is its only authority:
  --   'mark1_off' | 'disk_hard_stop' | 'user_enable' | 'proxy_bypass'
  --   | 'proxy_failed' | 'unsupported_agent_version' | 'transcript_retention_gap'
  -- Deliberately NOT a CHECK or an enum: reason_code is a proto `string` for the
  -- same reason dropped_reason is LowCardinality and not Enum8 -- codes grow
  -- additively inside m1p.v1, and a new one must land as data, not as a
  -- migration that a running edge cannot wait for.
  reason           text NOT NULL DEFAULT '', -- '' not NULL so it can sit in indexes without NULL surprises
  receipt_id       uuid NOT NULL           -- coverage transitions are per-event receipted (C13): every gap is attributable AND provable
);

CREATE INDEX IF NOT EXISTS ix_coverage_surface
  ON coverage_transitions (tenant_id, device_id, workspace_digest, occurred_at, id);

-- TVO reports: the Postgres row a customer-facing report is issued from (the
-- numbers themselves come from ClickHouse through the query choke; this row is
-- the receipted issuance record).
CREATE TABLE IF NOT EXISTS tvo_reports (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  window_start    timestamptz NOT NULL,
  window_end      timestamptz NOT NULL CHECK (window_end > window_start),
  cost_basis      text NOT NULL CHECK (cost_basis IN ('usd', 'quota')),  -- C9/knee: a number without its basis is not a number
  coverage_ratio  numeric(6,5) NOT NULL CHECK (coverage_ratio >= 0 AND coverage_ratio <= 1),
  -- THE BAND, derived -- generated, not written, so a report cannot claim a band
  -- its own stored ratio contradicts.
  coverage_band   coverage_band NOT NULL GENERATED ALWAYS AS (
    CASE
      WHEN coverage_ratio >= 0.98 THEN 'A'::coverage_band
      WHEN coverage_ratio >= 0.90 THEN 'B'::coverage_band
      WHEN coverage_ratio >= 0.75 THEN 'C'::coverage_band
      ELSE 'insufficient'::coverage_band
    END
  ) STORED,
  guarantee_grade boolean NOT NULL DEFAULT false,
  body            jsonb NOT NULL,          -- the report as issued: TVO, waste taxonomy, per-task rollups
  issued_at       timestamptz NOT NULL DEFAULT now(),
  receipt_id      uuid NOT NULL,
  -- THE FLOOR. Guarantee-grade issuance below band A is unrepresentable -- the
  -- plan's "refuse issuance below the floor" as a constraint, not a policy.
  CONSTRAINT guarantee_needs_band_a CHECK (NOT guarantee_grade OR coverage_ratio >= 0.98)
);

-- THE BAND QUERY. Computes coverage_ratio for tenant $1 over [$2, $3).
-- Semantics, stated once: a surface is covered from an 'enable'/'bypass_end'
-- until its next transition; the denominator is the union of each surface's
-- [first_enable, window_end) clamped to the window -- so a surface enabled on
-- Wednesday does not owe coverage for Monday, but a surface that went dark
-- Wednesday owes every second until window_end. Runs under the tenant GUC;
-- RLS bounds it even if the WHERE clause were dropped.
--
--   WITH tx AS (
--     SELECT device_id, workspace_digest, occurred_at,
--            kind IN ('enable', 'bypass_end') AS covered,
--            lead(occurred_at, 1, $3)
--              OVER (PARTITION BY device_id, workspace_digest
--                    ORDER BY occurred_at, id)               AS next_at
--       FROM coverage_transitions
--      WHERE tenant_id = $1 AND occurred_at < $3             -- includes pre-window rows: they carry state INTO the window
--   ),
--   clamped AS (
--     SELECT covered,
--            greatest(occurred_at, $2) AS s,
--            least(next_at, $3)        AS e
--       FROM tx
--      WHERE next_at > $2                                    -- intervals ending before the window contribute nothing
--   )
--   SELECT coalesce(
--            sum(extract(epoch FROM e - s)) FILTER (WHERE covered)
--            / nullif(sum(extract(epoch FROM e - s)), 0),
--          0)::numeric(6,5) AS coverage_ratio
--     FROM clamped
--    WHERE e > s;
--
-- A zero-row result (no transitions ever) yields ratio 0 via the coalesce:
-- "never enabled" is band 'insufficient', not a division error and never a pass.

-- RLS: canonical form; both tables take writes.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['coverage_transitions','tvo_reports'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;

-- Transitions are evidence: append-only at BOTH layers. The privilege layer
-- binds the runtime roles; the trigger layer binds mark1_owner too -- a control
-- that holds only through the other has already failed.
CREATE OR REPLACE FUNCTION trg_coverage_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'coverage_transitions is append-only: a gap is corrected by a later transition, never by editing history'
    USING ERRCODE = 'check_violation';
END $$;
DROP TRIGGER IF EXISTS coverage_no_update_delete ON coverage_transitions;
CREATE TRIGGER coverage_no_update_delete
  BEFORE UPDATE OR DELETE ON coverage_transitions
  FOR EACH ROW EXECUTE FUNCTION trg_coverage_append_only();

-- Row triggers do not fire on TRUNCATE and the REVOKE below does not bind the
-- owner, so this statement trigger is the whole of what "binds mark1_owner too"
-- means against the one statement that erases the band evidence outright.
DROP TRIGGER IF EXISTS coverage_no_truncate ON coverage_transitions;
CREATE TRIGGER coverage_no_truncate
  BEFORE TRUNCATE ON coverage_transitions
  FOR EACH STATEMENT EXECUTE FUNCTION trg_coverage_append_only();

REVOKE UPDATE, DELETE, TRUNCATE ON coverage_transitions FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON coverage_transitions TO controld_app;  -- ingest mirrors CoverageTransition events; append-only by grant
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON coverage_transitions TO intel_app;
    GRANT SELECT, INSERT ON tvo_reports TO intel_app;              -- reports are issued, never edited; a correction is a new report
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS tvo_reports;
--   DROP TRIGGER IF EXISTS coverage_no_truncate ON coverage_transitions;
--   DROP TRIGGER IF EXISTS coverage_no_update_delete ON coverage_transitions;
--   DROP FUNCTION IF EXISTS trg_coverage_append_only();
--   DROP TABLE IF EXISTS coverage_transitions;
--   DROP TYPE IF EXISTS coverage_band;
--   DROP TYPE IF EXISTS coverage_kind;
-- COMMIT;
