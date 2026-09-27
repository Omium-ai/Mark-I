-- m1_105_row_seq.sql
-- Latest-row reads ordered by a now()-stamped column trust the wall clock across transactions, and a
-- clock stepped backwards (NTP, a VM resync: measured 2.5-2.7 s steps every ~30 s on a WSL2 host) makes
-- an older row look newer: a consent withdrawn seconds after it was granted reads as granted again. Every
-- table whose "latest" matters gets `row_seq`, a GENERATED ALWAYS identity drawn at insert (and re-drawn
-- by the writes that make a row newer: a relabel, a freeze, a re-armed enrollment), and its readers order
-- by it. Existing rows are numbered in the order today's readers already use, so no current answer moves.
--
--   m1_device_consents                  latest consent per device (withdrawal must win)
--   m1_device_enrollments               latest enrollment per device (who owns it)
--   bundle_acks                         latest ACK per device (rollout coverage and halts)
--   gold_sets                           latest open / frozen set (bumped on freeze)
--   gold_set_members                    latest label per task (bumped on relabel)
--   noise_certificates                  the tenant's current certificate
--   m1_verifier_promotion_transitions   the promotion ledger's order
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;
SET LOCAL jit = off;  -- a one-shot backfill; JIT compile time only, and some hosts ship no llvmjit
SET LOCAL row_security = off;  -- the backfill must see every row: a role that FORCE RLS would filter errors here instead of numbering nothing

CREATE OR REPLACE FUNCTION pg_temp.m1_105_row_seq(tbl regclass, backfill_order text) RETURNS void AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = tbl AND attname = 'row_seq' AND NOT attisdropped) THEN
    RETURN;
  END IF;
  EXECUTE format('ALTER TABLE %s ADD COLUMN row_seq bigint', tbl);
  EXECUTE format('ALTER TABLE %s DISABLE TRIGGER USER', tbl);
  EXECUTE format(
    'UPDATE %1$s t SET row_seq = o.n FROM (SELECT ctid AS c, row_number() OVER (ORDER BY %2$s) AS n FROM %1$s) o WHERE t.ctid = o.c',
    tbl, backfill_order);
  EXECUTE format('ALTER TABLE %s ENABLE TRIGGER USER', tbl);
  EXECUTE format('ALTER TABLE %s ALTER COLUMN row_seq SET NOT NULL, ALTER COLUMN row_seq ADD GENERATED ALWAYS AS IDENTITY', tbl);
  EXECUTE format('SELECT setval(pg_get_serial_sequence(%L, ''row_seq''), coalesce((SELECT max(row_seq) FROM %s), 0) + 1, false)', tbl::text, tbl);
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I UNIQUE (row_seq)', tbl, 'uq_' || tbl::text || '_row_seq');
END;
$$ LANGUAGE plpgsql;

SELECT pg_temp.m1_105_row_seq('m1_device_consents', 'recorded_at, id');
SELECT pg_temp.m1_105_row_seq('m1_device_enrollments', 'started_at, id');
SELECT pg_temp.m1_105_row_seq('bundle_acks', 'acked_at, seq, device_id');
SELECT pg_temp.m1_105_row_seq('gold_sets', 'coalesce(frozen_at, created_at), id');
SELECT pg_temp.m1_105_row_seq('gold_set_members', 'labeled_at, gold_set_id, task_digest');
SELECT pg_temp.m1_105_row_seq('noise_certificates', 'issued_at NULLS FIRST, id');
SELECT pg_temp.m1_105_row_seq('m1_verifier_promotion_transitions', 'at, from_state, id');

CREATE INDEX IF NOT EXISTS ix_m1_device_consents_row_seq ON m1_device_consents (device_id, row_seq DESC);
CREATE INDEX IF NOT EXISTS ix_m1_device_enrollments_row_seq ON m1_device_enrollments (device_id, row_seq DESC);
CREATE INDEX IF NOT EXISTS ix_bundle_acks_row_seq ON bundle_acks (tenant_id, channel, device_id, row_seq DESC);

-- a column grant never covers a later column: intel_app's m1_090 grant is the only one on these tables, and digest.weekly / memory.extract order by row_seq
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT (row_seq) ON m1_device_enrollments TO intel_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual): ALTER TABLE <each table above> DROP COLUMN IF EXISTS row_seq; (the readers then need
-- their recorded_at / started_at / acked_at / created_at / frozen_at / labeled_at / issued_at / at order back).
