-- m1_088_verifier_catalog_seed.sql
-- m1_verifiers (m1_020) has never carried a production row: certs_recompute
-- (adjudicator nightly.py) iterates zero verifiers and writes no certificate
-- at all, and judge_batch.py's registry_by_wire_id has no judge to dispatch
-- to. This seeds the nine anchors go/controld/internal/policydist/bootstrap.go
-- already bundles by wire id (bootstrapAnchors: cargo-check/compile,
-- cargo-test/test, eslint/lint, go-test/test, go-vet/typecheck, npm-test/test,
-- pytest/test, ruff/lint, tsc/typecheck) plus the one registered T1 judge
-- (app/judges/specs.py JUDGE_SPECS, judge:grounded-rubric@1).
--
-- Anchor verifier_key IS the wire id ("<tool>@cat-1", not "<tool>"): no
-- catalog publisher has pinned anchor keys yet (readjudicate.py
-- registry_by_wire_id's own comment), and votes arrive keyed that way. The
-- judge's verifier_key is the bare name ("judge:grounded-rubric"); pairing
-- it with version=1 reconstructs registry_by_wire_id's other form,
-- "<key>@<version>" = "judge:grounded-rubric@1", the exact wire judge_id.
--
-- effective_execution_hash is m1_020's own definition of itself: SHA-256
-- over the canonical form of `definition`. Computed here over the literal
-- text authored below (never over the jsonb column's reformatting, which
-- postgres does not promise byte-stable) so the stored hash is reproducible
-- from this file alone. A judge has no execution to hash (m1_020's
-- equivalence CHECK): NULL.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, effective_execution_hash)
SELECT v.verifier_key, 'anchor', 1, v.display_name, v.definition::jsonb,
       digest(convert_to(v.definition, 'UTF8'), 'sha256')
  FROM (VALUES
    ('cargo-check@cat-1', 'cargo check', '{"tool":"cargo-check","kind":"compile","catalog_id":"cargo-check@cat-1"}'),
    ('cargo-test@cat-1',  'cargo test',  '{"tool":"cargo-test","kind":"test","catalog_id":"cargo-test@cat-1"}'),
    ('eslint@cat-1',      'eslint',      '{"tool":"eslint","kind":"lint","catalog_id":"eslint@cat-1"}'),
    ('go-test@cat-1',     'go test',     '{"tool":"go-test","kind":"test","catalog_id":"go-test@cat-1"}'),
    ('go-vet@cat-1',      'go vet',      '{"tool":"go-vet","kind":"typecheck","catalog_id":"go-vet@cat-1"}'),
    ('npm-test@cat-1',    'npm test',    '{"tool":"npm-test","kind":"test","catalog_id":"npm-test@cat-1"}'),
    ('pytest@cat-1',      'pytest',      '{"tool":"pytest","kind":"test","catalog_id":"pytest@cat-1"}'),
    ('ruff@cat-1',        'ruff',        '{"tool":"ruff","kind":"lint","catalog_id":"ruff@cat-1"}'),
    ('tsc@cat-1',         'tsc',         '{"tool":"tsc","kind":"typecheck","catalog_id":"tsc@cat-1"}')
  ) AS v(verifier_key, display_name, definition)
ON CONFLICT (verifier_key, version) DO NOTHING;

-- rubric_sha256 = sha256(app/judges/specs.py JUDGE_SPECS["judge:grounded-rubric@1"].rubric); a
-- rubric edit is a new version (06 §6.3), never an UPDATE of this row (m1_020's trigger refuses it).
INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, effective_execution_hash)
VALUES (
  'judge:grounded-rubric', 'judge', 1, 'Grounded rubric judge (Claude Sonnet 5)',
  '{"judge_id":"judge:grounded-rubric@1","kind":"judge","rubric_sha256":"9eeafe310e423552240e2529422022a6e9b6d4bce26f7670f657e53cd01098f7","rubric_version":1,"model":"claude-sonnet-5","subprocessor":"anthropic","region":"us","evidence_tier":"E0"}'::jsonb,
  NULL
)
ON CONFLICT (verifier_key, version) DO NOTHING;
