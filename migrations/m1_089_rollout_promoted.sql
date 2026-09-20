-- m1_089_rollout_promoted.sql
-- rollout_cursor gains promoted_seq: 05 §4.3 item 1's rollout completion,
-- concretely -- once a canary rollout's cohort_percent reaches 100 and holds
-- clean through one more soak, the controller forward-publishes the canary
-- head's content onto the STABLE channel and records the stable seq it
-- landed at here, so a re-tick never promotes the same rollout twice.
--
-- No FK: m1_066's rollback_seq can reference policy_bundles(tenant_id,
-- channel, seq) because a rollback always lands on the SAME channel as the
-- cursor row. A promotion does not -- a canary row's promoted_seq names a
-- seq on the STABLE channel, and policy_bundles has no (tenant_id, seq) key
-- to hang a cross-channel FK off. Nullable, no CHECK, same posture as
-- m1_061's edge_version: an unset value means "not promoted yet", not
-- "unknown".
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE rollout_cursor ADD COLUMN IF NOT EXISTS promoted_seq bigint;

COMMIT;

-- ROLLBACK (run manually if needed; the controller re-derives promotion
-- state from cohort_percent and step_started_at, so losing this column only
-- risks one duplicate forward-publish on the next tick):
-- BEGIN;
--   ALTER TABLE rollout_cursor DROP COLUMN IF EXISTS promoted_seq;
-- COMMIT;
