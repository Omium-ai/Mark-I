-- m1_086_human_gold_labels.sql
-- A person can confirm an outcome; the confirmation is a gold label.
--
-- WHY. 06 §5.1 names three strong-label sources (t3 | human |
-- batch-readjudication) and gold_set_members.label_source records which.
-- None had a producer: gold/select.py's add_members has no caller, so no
-- tenant ever formed a set, gold.refresh never froze one and no certificate
-- row exists anywhere. The desktop app now lets the developer confirm a
-- completed task's outcome (POST /api/v1/verify/labels, controld appapi);
-- the row lands here with label_source = 'human' and the device that
-- labeled it, so "how was this ground truth established" has an answer per
-- row (m1_021's own audit rule). Selection stays post-hoc by construction:
-- the route refuses a task the ledger has not closed.

ALTER TABLE gold_set_members ADD COLUMN IF NOT EXISTS labeled_by_device uuid;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON gold_sets TO controld_app;                 -- the tenant's open set, created on first label
    GRANT SELECT, INSERT, UPDATE ON gold_set_members TO controld_app;  -- relabeling is an UPDATE (the PK), never a duplicate
  END IF;
END $$;
