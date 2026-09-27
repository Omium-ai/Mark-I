-- m1_095_diff_judge_verifier.sql
-- 16 §L7: the anchor-blind edge judge, judge:diff-rubric@1. It reads ONLY the task text and the local raw
-- diff through the customer's own key (go/mark1d/internal/judge/diff.go), runs on every closed task it can
-- (JudgeVote.trigger = ALWAYS, tier_used = E1_LOCAL), and its rubric binds no verifier output, so it is its
-- own correlation group `judge` (16 §Independence). judge:grounded-rubric@1 (m1_088) stays the E0 judge in
-- group `syntactic`; its row is immutable (m1_020 trigger), so a reader takes an E0 judge row without a
-- "group" key as `syntactic`.
--
-- Deliberately NOT in app/judges/specs.py JUDGE_SPECS: judge_batch dispatches every spec there on ambiguous
-- tasks, and an ambiguity-triggered run of this judge would break the trigger rule. The edge refuses a
-- JudgeRequest naming it.
--
-- rubric_sha256 = sha256(diff.go diffRubric); judge/diff_test.go pins it to this file. A rubric edit is a new
-- version (06 §6.3), never an UPDATE of this row.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, effective_execution_hash)
VALUES (
  'judge:diff-rubric', 'judge', 1, 'Diff-reading judge (Claude Sonnet 5, customer key)',
  '{"judge_id":"judge:diff-rubric@1","kind":"judge","group":"judge","locus":"edge","rubric_sha256":"113cae74a359581432a1336a19f3d4f41e65160b5dc3a56730ba2c8af955fe00","rubric_version":1,"model":"claude-sonnet-5","subprocessor":"anthropic","evidence_tier":"E1_LOCAL","trigger":"always"}'::jsonb,
  NULL
)
ON CONFLICT (verifier_key, version) DO NOTHING;

-- ROLLBACK (run manually if needed; catalog rows are retired, never deleted):
-- UPDATE m1_verifiers SET retired_at = now() WHERE verifier_key = 'judge:diff-rubric' AND version = 1;
