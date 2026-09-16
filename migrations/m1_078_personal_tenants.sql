-- m1_078_personal_tenants.sql
-- Personal tenants for Omium-account sign-in: kind='personal' rows have no org
-- (biconditional with org_id, so neither kind can drift into the other), carry the
-- owning subject 'omium:<users.id>', and use the platform tenants.id as their id.
-- ck_m1_tenants_onboarded is untouched (never set for personal tenants; nothing
-- reads it); artifact_contributions.org_id NOT NULL keeps them out of federation.
-- m1_device_enrollments records the approval path; user_code_hash is reserved for
-- the headless omium_device_code lane.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_tenants ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'org';
ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_kind;
ALTER TABLE m1_tenants ADD CONSTRAINT ck_m1_tenants_kind CHECK (kind IN ('org', 'personal'));

ALTER TABLE m1_tenants ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_org_kind;
ALTER TABLE m1_tenants ADD CONSTRAINT ck_m1_tenants_org_kind CHECK ((kind = 'personal') = (org_id IS NULL));

ALTER TABLE m1_tenants ADD COLUMN IF NOT EXISTS owner_subject text;
ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_owner;
ALTER TABLE m1_tenants ADD CONSTRAINT ck_m1_tenants_owner CHECK (kind <> 'personal' OR owner_subject IS NOT NULL);

ALTER TABLE m1_device_enrollments ADD COLUMN IF NOT EXISTS approval_kind text NOT NULL DEFAULT 'idp_device_code';
ALTER TABLE m1_device_enrollments DROP CONSTRAINT IF EXISTS ck_m1_enroll_approval_kind;
ALTER TABLE m1_device_enrollments ADD CONSTRAINT ck_m1_enroll_approval_kind
  CHECK (approval_kind IN ('idp_device_code', 'omium_user', 'omium_device_code'));

ALTER TABLE m1_device_enrollments ADD COLUMN IF NOT EXISTS user_code_hash bytea;
ALTER TABLE m1_device_enrollments DROP CONSTRAINT IF EXISTS ck_m1_enroll_user_code_len;
ALTER TABLE m1_device_enrollments ADD CONSTRAINT ck_m1_enroll_user_code_len
  CHECK (user_code_hash IS NULL OR octet_length(user_code_hash) = 32);

COMMIT;

-- ROLLBACK (manual; the org_id NOT NULL restore refuses while any personal tenant
-- row exists -- close those tenants first, never DELETE them):
-- BEGIN;
--   ALTER TABLE m1_device_enrollments DROP CONSTRAINT IF EXISTS ck_m1_enroll_user_code_len;
--   ALTER TABLE m1_device_enrollments DROP COLUMN IF EXISTS user_code_hash;
--   ALTER TABLE m1_device_enrollments DROP CONSTRAINT IF EXISTS ck_m1_enroll_approval_kind;
--   ALTER TABLE m1_device_enrollments DROP COLUMN IF EXISTS approval_kind;
--   ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_owner;
--   ALTER TABLE m1_tenants DROP COLUMN IF EXISTS owner_subject;
--   ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_org_kind;
--   ALTER TABLE m1_tenants ALTER COLUMN org_id SET NOT NULL;
--   ALTER TABLE m1_tenants DROP CONSTRAINT IF EXISTS ck_m1_tenants_kind;
--   ALTER TABLE m1_tenants DROP COLUMN IF EXISTS kind;
-- COMMIT;
