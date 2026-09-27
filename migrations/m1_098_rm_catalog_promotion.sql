-- m1_098_rm_catalog_promotion.sql
-- 16 §L6: a reward_model row may carry an execution hash; rm:mark1-rm-{a,b}@1 seeded with a pending artifact that
-- publish seals once (07 §m1_098 has the seal statement); promotion may rest on >= 200 human/T3 gold overlaps
-- instead of a certified cert (rm-design §4.4), and canary -> active needs 48 h.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_verifiers DROP CONSTRAINT IF EXISTS ck_m1_verifiers_anchor_hash;
ALTER TABLE m1_verifiers ADD CONSTRAINT ck_m1_verifiers_anchor_hash
  CHECK (CASE kind
           WHEN 'anchor' THEN effective_execution_hash IS NOT NULL
           WHEN 'reward_model' THEN true
           ELSE effective_execution_hash IS NULL
         END);

CREATE OR REPLACE FUNCTION m1_verifier_immutable()
RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM (to_jsonb(OLD) - 'retired_at') THEN
    IF OLD.kind = 'reward_model'
       AND OLD.definition #>> '{artifact,status}' = 'pending'
       AND NEW.definition #>> '{artifact,status}' = 'sealed'
       AND (NEW.definition - 'artifact') = (OLD.definition - 'artifact')
       AND (to_jsonb(NEW) - 'retired_at' - 'definition' - 'effective_execution_hash')
           = (to_jsonb(OLD) - 'retired_at' - 'definition' - 'effective_execution_hash')
       AND OLD.effective_execution_hash IS NULL
       AND NEW.effective_execution_hash IS NOT NULL
       AND NEW.effective_execution_hash = decode(NEW.definition #>> '{artifact,execution_sha256}', 'hex')
    THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION
      'm1_verifiers rows are immutable except retired_at (and one pending->sealed RM artifact); publish a new version'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, effective_execution_hash)
VALUES
  ('rm:mark1-rm-a', 'reward_model', 1, 'Mark 1 reward model A (Qwen family)',
   '{"model_id":"rm:mark1-rm-a@1","kind":"rm","group":"rm-a","scope":"global","base_family":"qwen","loci":["client_side","cloud"],"inputs":["task_text","diff"],"artifact":{"status":"pending","manifest_uri":"s3://omium-adapters-prod-965384155704/rm/mark1-rm-a@1/manifest.json","model_sha256":null,"gguf_sha256":null,"template_sha256":null,"calibration":null,"eval_card":null,"execution_sha256":null}}'::jsonb,
   NULL),
  ('rm:mark1-rm-b', 'reward_model', 1, 'Mark 1 reward model B (non-Qwen family)',
   '{"model_id":"rm:mark1-rm-b@1","kind":"rm","group":"rm-b","scope":"global","base_family":"non-qwen","loci":["client_side","cloud"],"inputs":["task_text","diff"],"artifact":{"status":"pending","manifest_uri":"s3://omium-adapters-prod-965384155704/rm/mark1-rm-b@1/manifest.json","model_sha256":null,"gguf_sha256":null,"template_sha256":null,"calibration":null,"eval_card":null,"execution_sha256":null}}'::jsonb,
   NULL)
ON CONFLICT (verifier_key, version) DO NOTHING;

ALTER TABLE m1_verifier_promotions ADD COLUMN IF NOT EXISTS gold_n int NOT NULL DEFAULT 0;
ALTER TABLE m1_verifier_promotions DROP CONSTRAINT IF EXISTS ck_m1_promotion_gold_n;
ALTER TABLE m1_verifier_promotions ADD CONSTRAINT ck_m1_promotion_gold_n CHECK (gold_n >= 0);
ALTER TABLE m1_verifier_promotions DROP CONSTRAINT IF EXISTS promoted_is_earned;
ALTER TABLE m1_verifier_promotions ADD CONSTRAINT promoted_is_earned CHECK (
  state NOT IN ('lcb_promoted', 'canary', 'active') OR (
    shadow_n >= 500                                  -- D38
    AND lcb IS NOT NULL AND bar IS NOT NULL AND lcb > bar
    AND (cert_id IS NOT NULL OR gold_n >= 200)       -- a live certified cert, or D15 gold overlaps
    AND measured_at IS NOT NULL
  )
);

CREATE OR REPLACE FUNCTION m1_promotion_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE h m1_verifier_promotions%ROWTYPE;
BEGIN
  SELECT * INTO h FROM m1_verifier_promotions
   WHERE id = NEW.promotion_id AND tenant_id = NEW.tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'promotion % is not in tenant %', NEW.promotion_id, NEW.tenant_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF NEW.from_state <> h.state THEN
    RAISE EXCEPTION 'stale transition: promotion % is %, not %', h.id, h.state, NEW.from_state
      USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (
    NEW.from_state::text || '>' || NEW.to_state::text = ANY (ARRAY[
      'probation>shadow', 'shadow>lcb_promoted', 'lcb_promoted>canary', 'canary>active',
      'lcb_promoted>shadow', 'canary>shadow', 'active>shadow'])
    OR (NEW.to_state = 'retired' AND NEW.from_state <> 'retired')
  ) THEN
    RAISE EXCEPTION 'illegal promotion transition % -> %', NEW.from_state, NEW.to_state
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.to_state = 'lcb_promoted' THEN
    IF h.shadow_n < 500 OR h.lcb IS NULL OR h.bar IS NULL OR h.lcb <= h.bar
       OR h.measured_at IS NULL OR h.measured_at < h.state_since
       OR (h.cert_id IS NULL AND h.gold_n < 200) THEN
      RAISE EXCEPTION
        'insufficient_evidence: promotion % has shadow_n=%, lcb=%, bar=%, measured_at=% (state_since %), gold_n=%',
        h.id, h.shadow_n, h.lcb, h.bar, h.measured_at, h.state_since, h.gold_n
        USING ERRCODE = 'check_violation';
    END IF;
    IF h.cert_id IS NOT NULL THEN
      PERFORM mark1_assert_certified(h.cert_id);
    END IF;
    NEW.evidence := NEW.evidence || jsonb_build_object(
      'shadow_n', h.shadow_n, 'lcb', h.lcb, 'bar', h.bar, 'cert_id', h.cert_id, 'gold_n', h.gold_n);
  END IF;
  IF NEW.from_state = 'canary' AND NEW.to_state = 'active'
     AND h.state_since > now() - interval '48 hours' THEN
    RAISE EXCEPTION 'canary_hold: promotion % has been canary only since %', h.id, h.state_since
      USING ERRCODE = 'check_violation';
  END IF;
  UPDATE m1_verifier_promotions
     SET state = NEW.to_state, state_since = now(), updated_at = now()
   WHERE id = h.id;
  RETURN NEW;
END $$;

COMMIT;

-- ROLLBACK (manual): retire the two rm rows (never delete), drop ck_m1_promotion_gold_n and gold_n, and re-create
-- promoted_is_earned, m1_promotion_transition() and m1_verifier_immutable() and the anchor-hash CHECK from m1_069/m1_020.
