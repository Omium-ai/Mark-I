-- m1_097_local_rm_consent.sql
-- 16 L6: the reward-model choice on the device consent record. local_rm = scores on the device (nothing leaves);
-- cloud_rm = the device's E1 hunks may be scored in Omium's cloud (the tenant row in m1_cloud_judge_consents still gates it).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS local_rm boolean NOT NULL DEFAULT false;
ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS cloud_rm boolean NOT NULL DEFAULT false;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   ALTER TABLE m1_device_consents DROP COLUMN IF EXISTS cloud_rm;
--   ALTER TABLE m1_device_consents DROP COLUMN IF EXISTS local_rm;
-- COMMIT;
