-- m1_090: ADR-0017 host-bound receipts. A v2 checkpoint payload carries the
-- batch's host bindings and its acted/recommended arrest counts INSIDE the
-- signed text; these columns restate them for queries (estate rule: a column
-- restates a signed claim, it never replaces it). NULL on every v1 row.
ALTER TABLE m1_receipts
  ADD COLUMN IF NOT EXISTS host_bindings       jsonb,
  ADD COLUMN IF NOT EXISTS arrests_acted       integer,
  ADD COLUMN IF NOT EXISTS arrests_recommended integer;

COMMENT ON COLUMN m1_receipts.host_bindings IS
  'ADR-0017: the checkpoint payload''s "hosts" array as signed (v2 rows only); payload text is the truth';
COMMENT ON COLUMN m1_receipts.arrests_acted IS
  'ADR-0017: GuardDecision leaves with a task in the sealed batch (ACT only; v2 rows only)';
COMMENT ON COLUMN m1_receipts.arrests_recommended IS
  'ADR-0017: ArrestRecommendation leaves in the sealed batch (never summed with arrests_acted)';
