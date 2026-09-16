-- m1_073_rm_consent.sql
-- The T2 reward model (app/rm) is a second cloud path with the judge consent shape (06 §6.5), so a
-- tenant's E1 consent may name an rm:<model>@<v> member as well as a judge:<name>@<v> one. The
-- rest of the row (subprocessor, region, max_tier) is unchanged and still fail-closed on mismatch.
ALTER TABLE m1_cloud_judge_consents DROP CONSTRAINT IF EXISTS m1_cloud_judge_consents_judge_id_check;
ALTER TABLE m1_cloud_judge_consents ADD CONSTRAINT m1_cloud_judge_consents_judge_id_check
  CHECK (judge_id ~ '^(judge|rm):[a-z0-9-]+@[1-9][0-9]*$');
