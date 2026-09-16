-- m1_069_verifier_promotion.sql
-- 06 §12.4 promotion pipeline for learned ensemble members (FR-LEARN-004, C12):
-- probation -> shadow -> lcb_promoted -> canary -> active, demotion to shadow,
-- retirement from anywhere. Per tenant, because the labels a candidate is measured
-- against are a tenant's certified verdicts (06 §5.4). The head row is mutable only
-- through the append-only transition ledger, whose trigger is the state machine.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'promotion_state') THEN
    CREATE TYPE promotion_state AS ENUM
      ('probation', 'shadow', 'lcb_promoted', 'canary', 'active', 'retired');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS m1_verifier_promotions (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  verifier_id           uuid NOT NULL REFERENCES m1_verifiers(id) ON DELETE RESTRICT,
  incumbent_verifier_id uuid REFERENCES m1_verifiers(id) ON DELETE RESTRICT,  -- NULL = abstain-always baseline (06 §4.4)
  state                 promotion_state NOT NULL DEFAULT 'probation',
  state_since           timestamptz NOT NULL DEFAULT now(),
  -- Shadow evidence (06 §12.4 rows 2-3): certified-pair count, empirical-Bernstein LCB
  -- of the Youden discrimination, the incumbent's point Youden it must beat, and the
  -- cert warranting the labels. Written by the measure step, read by the gate below.
  shadow_n              int NOT NULL DEFAULT 0 CHECK (shadow_n >= 0),
  lcb                   numeric(8,6),
  bar                   numeric(8,6),
  cert_id               uuid REFERENCES noise_certificates(id) ON DELETE RESTRICT,
  measured_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_m1_promotion_candidate UNIQUE (tenant_id, verifier_id),
  CONSTRAINT ck_m1_promotion_not_self CHECK (incumbent_verifier_id IS DISTINCT FROM verifier_id),
  CONSTRAINT promoted_is_earned CHECK (
    state NOT IN ('lcb_promoted', 'canary', 'active') OR (
      shadow_n >= 500                    -- D38
      AND lcb IS NOT NULL AND bar IS NOT NULL AND lcb > bar
      AND cert_id IS NOT NULL AND measured_at IS NOT NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS m1_verifier_promotion_transitions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  promotion_id  uuid NOT NULL REFERENCES m1_verifier_promotions(id) ON DELETE RESTRICT,
  from_state    promotion_state NOT NULL,
  to_state      promotion_state NOT NULL,
  reason        text NOT NULL CHECK (reason <> ''),
  evidence      jsonb NOT NULL DEFAULT '{}'::jsonb,
  receipt_id    uuid NOT NULL,          -- C13 rare class 'verifier_promotion'; logical key, no cross-service FK
  at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_m1_promotion_transitions_promotion
  ON m1_verifier_promotion_transitions (promotion_id, at);

-- A candidate is born in probation; nothing is registered already promoted.
CREATE OR REPLACE FUNCTION m1_promotion_born_in_probation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state <> 'probation' THEN
    RAISE EXCEPTION 'a learned member registers in probation, not %', NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_m1_promotion_born ON m1_verifier_promotions;
CREATE TRIGGER trg_m1_promotion_born
  BEFORE INSERT ON m1_verifier_promotions
  FOR EACH ROW EXECUTE FUNCTION m1_promotion_born_in_probation();

-- The head's state moves only from inside the ledger trigger (depth 2); a direct UPDATE
-- (depth 1) is a bypass of the state machine and is refused.
CREATE OR REPLACE FUNCTION m1_promotion_state_via_ledger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state AND pg_trigger_depth() = 1 THEN
    RAISE EXCEPTION 'promotion state changes only through m1_verifier_promotion_transitions'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_m1_promotion_state_via_ledger ON m1_verifier_promotions;
CREATE TRIGGER trg_m1_promotion_state_via_ledger
  BEFORE UPDATE ON m1_verifier_promotions
  FOR EACH ROW EXECUTE FUNCTION m1_promotion_state_via_ledger();

-- THE STATE MACHINE. Legal edges, the stale-write refusal, the shadow gate (D38 count,
-- LCB over the bar, evidence measured in THIS shadow period, live certified cert via
-- mark1_assert_certified -- C5), then the head advances. One row per edge, forever.
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
       OR h.measured_at IS NULL OR h.measured_at < h.state_since THEN
      RAISE EXCEPTION
        'insufficient_evidence: promotion % has shadow_n=%, lcb=%, bar=%, measured_at=% (state_since %)',
        h.id, h.shadow_n, h.lcb, h.bar, h.measured_at, h.state_since
        USING ERRCODE = 'check_violation';
    END IF;
    PERFORM mark1_assert_certified(h.cert_id);
    NEW.evidence := NEW.evidence || jsonb_build_object(
      'shadow_n', h.shadow_n, 'lcb', h.lcb, 'bar', h.bar, 'cert_id', h.cert_id);
  END IF;
  UPDATE m1_verifier_promotions
     SET state = NEW.to_state, state_since = now(), updated_at = now()
   WHERE id = h.id;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_m1_promotion_transition ON m1_verifier_promotion_transitions;
CREATE TRIGGER trg_m1_promotion_transition
  BEFORE INSERT ON m1_verifier_promotion_transitions
  FOR EACH ROW EXECUTE FUNCTION m1_promotion_transition();

DROP TRIGGER IF EXISTS trg_m1_promotion_transitions_append_only ON m1_verifier_promotion_transitions;
CREATE TRIGGER trg_m1_promotion_transitions_append_only
  BEFORE UPDATE OR DELETE ON m1_verifier_promotion_transitions
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

DROP TRIGGER IF EXISTS trg_m1_promotion_transitions_no_truncate ON m1_verifier_promotion_transitions;
CREATE TRIGGER trg_m1_promotion_transitions_no_truncate
  BEFORE TRUNCATE ON m1_verifier_promotion_transitions
  FOR EACH STATEMENT EXECUTE FUNCTION m1_append_only();

-- The receipt class (C13). Additive rewrite of m1_receipts' two CHECKs rather than a
-- restated list: sibling migrations add classes too, and a restated list would drop
-- whichever landed first.
DO $$
DECLARE def text;
BEGIN
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'm1_receipts_record_type_check';
  IF def NOT LIKE '%verifier_promotion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT m1_receipts_record_type_check';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT m1_receipts_record_type_check ' ||
      replace(def, '''corpus_export''::text', '''corpus_export''::text, ''verifier_promotion''::text');
  END IF;
  SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
   WHERE conrelid = 'm1_receipts'::regclass AND conname = 'ck_m1_receipts_record_shape';
  IF def NOT LIKE '%verifier_promotion%' THEN
    EXECUTE 'ALTER TABLE m1_receipts DROP CONSTRAINT ck_m1_receipts_record_shape';
    EXECUTE 'ALTER TABLE m1_receipts ADD CONSTRAINT ck_m1_receipts_record_shape ' ||
      replace(def, '''corpus_export''::text', '''corpus_export''::text, ''verifier_promotion''::text');
  END IF;
END $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['m1_verifier_promotions', 'm1_verifier_promotion_transitions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
  END LOOP;
END $$;

-- adjudicator-svc owns promotion; intel's policy compiler reads which members are active.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_verifier_promotions TO adjudicator_app;
    GRANT SELECT, INSERT ON m1_verifier_promotion_transitions TO adjudicator_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_verifier_promotions, m1_verifier_promotion_transitions TO intel_app;
  END IF;
END $$;

REVOKE UPDATE, DELETE, TRUNCATE ON m1_verifier_promotion_transitions FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON m1_verifier_promotions FROM PUBLIC;

COMMIT;

-- ROLLBACK (manual; drops the promotion history receipts cite -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_verifier_promotion_transitions CASCADE;
--   DROP TABLE IF EXISTS m1_verifier_promotions CASCADE;
--   DROP FUNCTION IF EXISTS m1_promotion_transition();
--   DROP FUNCTION IF EXISTS m1_promotion_state_via_ledger();
--   DROP FUNCTION IF EXISTS m1_promotion_born_in_probation();
--   DROP TYPE IF EXISTS promotion_state;
-- COMMIT;
