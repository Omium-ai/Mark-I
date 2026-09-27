-- adj_005_judge_dispatches_tier.sql
-- 16 §L1/§L7: the cloud diff judge reads E1 hunks when receipted ones exist and falls back to E0
-- anchor facts otherwise, so a spent row records the tier its vote was cast on and a re-post
-- carries the same tier_used. NULL = a row written before this column (every one of them E0).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE judge_dispatches ADD COLUMN IF NOT EXISTS evidence_tier text
  CHECK (evidence_tier IN ('E0', 'E1'));

COMMIT;
