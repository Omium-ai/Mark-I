-- m1_100_cloud_judge_verifier.sql
-- 16 §L1/§L7: the cloud judge judge:grounded-rubric@2 (zai-org/GLM-5.2 on Nebius Token Factory through the
-- platform llm-router, register key nebius/global/E1) gets its catalog row, so registry_by_wire_id resolves
-- its votes and certs.recompute writes it a certificate. It reads E1 sanitized hunks + task text on a rubric
-- that binds no verifier output: its own correlation group `judge` (16 §Independence). A task with no E1
-- part falls back to the E0 anchor facts on the @1 rubric; those votes (tier_used = E0) are a derived view
-- of the anchors, so votes.groups_of files them as the separate estimation column
-- "judge:grounded-rubric@2/E0" in group `syntactic` (definition.e0_fallback).
--
-- rubric_sha256 = sha256(app/judges/specs.py JUDGE_SPECS["judge:grounded-rubric@2"].rubric), and
-- e0_fallback.rubric_sha256 = sha256(its e0_rubric); tests/test_judges.py pins both to this file. A rubric
-- edit is a new version (06 §6.3), never an UPDATE of this row (m1_020's trigger refuses it).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, effective_execution_hash)
VALUES (
  'judge:grounded-rubric', 'judge', 2, 'Cloud diff judge (GLM-5.2 on Nebius Token Factory)',
  '{"judge_id":"judge:grounded-rubric@2","kind":"judge","group":"judge","locus":"cloud","rubric_sha256":"c76a3762668c846fc54cc91ce4a51a7b8bbf3b7f68c5abaf8d4cf6e05c7c9336","rubric_version":2,"model":"zai-org/GLM-5.2","subprocessor":"nebius","region":"global","max_tier":"E1","evidence_tier":"E1","trigger":"always","e0_fallback":{"group":"syntactic","evidence_tier":"E0","rubric_sha256":"9eeafe310e423552240e2529422022a6e9b6d4bce26f7670f657e53cd01098f7"}}'::jsonb,
  NULL
)
ON CONFLICT (verifier_key, version) DO NOTHING;

-- ROLLBACK (run manually if needed; catalog rows are retired, never deleted):
-- UPDATE m1_verifiers SET retired_at = now() WHERE verifier_key = 'judge:grounded-rubric' AND version = 2;
