-- m1_092_router_judge_consents.sql
-- 16 §L1: the cloud judge moves from Anthropic to Nebius behind the platform llm-router as the new
-- judge:grounded-rubric@2, so live @1 rows naming Anthropic are revoked (UPDATE, never DELETE); memory
-- extraction gets its own register key mem:extract@1, read by intel. The CHECK carries the full prefix set.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_cloud_judge_consents DROP CONSTRAINT IF EXISTS m1_cloud_judge_consents_judge_id_check;
ALTER TABLE m1_cloud_judge_consents ADD CONSTRAINT m1_cloud_judge_consents_judge_id_check
  CHECK (judge_id ~ '^(judge|rm|t3|mem):[a-z0-9-]+@[1-9][0-9]*$');

UPDATE m1_cloud_judge_consents
   SET revoked_at = now(), revoked_reason = 'subprocessor_changed:anthropic->nebius'
 WHERE judge_id = 'judge:grounded-rubric@1' AND subprocessor = 'anthropic' AND revoked_at IS NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_cloud_judge_consents TO intel_app;  -- memory.extract's mem:extract@1 admission
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; the revoked rows stay revoked -- a consent to a
-- subprocessor that no longer runs is not restored):
-- BEGIN;
--   REVOKE SELECT ON m1_cloud_judge_consents FROM intel_app;
--   ALTER TABLE m1_cloud_judge_consents DROP CONSTRAINT IF EXISTS m1_cloud_judge_consents_judge_id_check;
--   ALTER TABLE m1_cloud_judge_consents ADD CONSTRAINT m1_cloud_judge_consents_judge_id_check
--     CHECK (judge_id ~ '^(judge|rm|t3):[a-z0-9-]+@[1-9][0-9]*$');
-- COMMIT;
