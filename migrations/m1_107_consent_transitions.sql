-- m1_107_consent_transitions.sql: a person-wide withdrawal is a true→false transition, rows written for the person carry person_off (held until the device sends the field false), cloud_rm stays per device, and pre-release cloud_judge and training grants (old copy) are reset (07 m1_107, 08 §3.7a). Idempotent + re-runnable.

BEGIN;
SET LOCAL row_security = off;  -- the one-shot row must see every tenant's devices

ALTER TABLE m1_device_consents ADD COLUMN IF NOT EXISTS person_off text[];

CREATE OR REPLACE FUNCTION m1_withdraw_person_consents(p_device uuid, p_off text[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
DECLARE
  v_tenant  uuid := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_subject text;
  v_devices uuid[];
  v_device  uuid;
  v_moved   text[];
  v_e1      uuid[];
  v_contrib uuid[];
BEGIN
  IF v_tenant IS NULL OR NOT EXISTS (SELECT 1 FROM m1_devices WHERE id = p_device AND tenant_id = v_tenant) THEN
    RAISE EXCEPTION 'm1_withdraw_person_consents: device % is not in the session tenant', p_device
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_off IS NULL OR NOT p_off <@ ARRAY['e1', 'cloud_judge', 'training', 'team', 'contribute_outcomes'] THEN  -- cloud_rm and local_rm are per-device choices
    RAISE EXCEPTION 'm1_withdraw_person_consents: unknown consent field in %', p_off
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  SELECT e.oidc_subject INTO v_subject
    FROM m1_device_enrollments e
   WHERE e.tenant_id = v_tenant AND e.device_id = p_device AND e.oidc_subject IS NOT NULL
   ORDER BY e.row_seq DESC LIMIT 1;

  SELECT array_agg(d ORDER BY d) INTO v_devices FROM (
    SELECT p_device AS d
    UNION
    SELECT e.device_id FROM m1_device_enrollments e
     WHERE v_subject IS NOT NULL AND e.tenant_id = v_tenant AND e.oidc_subject = v_subject AND e.device_id IS NOT NULL
       AND e.row_seq = (SELECT max(x.row_seq) FROM m1_device_enrollments x
                         WHERE x.device_id = e.device_id AND x.oidc_subject IS NOT NULL)
  ) s;

  FOREACH v_device IN ARRAY v_devices LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('m1_consent:' || v_device::text, 0));
  END LOOP;

  SELECT ARRAY(SELECT f FROM unnest(p_off) f WHERE coalesce((to_jsonb(c) ->> f)::boolean, false)) INTO v_moved
    FROM (SELECT 1) one LEFT JOIN LATERAL (SELECT * FROM m1_device_consents d WHERE d.tenant_id = v_tenant AND d.device_id = p_device
                                           ORDER BY d.row_seq DESC LIMIT 1) c ON true;

  WITH latest AS (
    SELECT DISTINCT ON (e.device_id) e.device_id, e.status FROM m1_device_enrollments e
     WHERE e.tenant_id = v_tenant AND e.device_id = ANY (v_devices) AND e.device_id <> p_device AND e.oidc_subject IS NOT NULL
     ORDER BY e.device_id, e.row_seq DESC
  ), cur AS (
    SELECT DISTINCT ON (d.device_id) d.* FROM m1_device_consents d
     WHERE d.tenant_id = v_tenant AND d.device_id = ANY (v_devices) AND d.device_id <> p_device
     ORDER BY d.device_id, d.row_seq DESC
  ), flip AS (
    SELECT c.*, ARRAY(SELECT f FROM unnest(CASE WHEN l.status = 'approved' THEN v_moved ELSE p_off END) f
                       WHERE (to_jsonb(c) ->> f)::boolean) AS off
      FROM cur c JOIN latest l USING (device_id)
  ), ins AS (
    INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm, person_off)
    SELECT tenant_id, device_id,
           e1 AND NOT ('e1' = ANY (off)),
           cloud_judge AND NOT ('cloud_judge' = ANY (off)),
           training AND NOT ('training' = ANY (off)),
           team AND NOT ('team' = ANY (off)),
           contribute_outcomes AND NOT ('contribute_outcomes' = ANY (off)),
           local_rm,
           cloud_rm,
           ARRAY(SELECT DISTINCT x FROM unnest(coalesce(person_off, '{}') || off) x ORDER BY x)
      FROM flip WHERE cardinality(off) > 0
  )
  SELECT array_agg(device_id) FILTER (WHERE 'e1' = ANY (off)), array_agg(device_id) FILTER (WHERE 'contribute_outcomes' = ANY (off))
    INTO v_e1, v_contrib FROM flip;

  IF 'e1' = ANY (v_moved) THEN
    v_e1 := array_append(v_e1, p_device);
  END IF;
  IF 'contribute_outcomes' = ANY (v_moved) THEN
    v_contrib := array_append(v_contrib, p_device);
  END IF;
  IF v_e1 IS NOT NULL THEN
    UPDATE m1_evidence_attachments SET withdrawn_at = now()
     WHERE tenant_id = v_tenant AND device_id = ANY (v_e1) AND withdrawn_at IS NULL AND deleted_at IS NULL;
  END IF;
  IF v_contrib IS NOT NULL THEN
    UPDATE m1_outcome_contributions SET withdrawn_at = now()
     WHERE tenant_id = v_tenant AND device_id = ANY (v_contrib) AND withdrawn_at IS NULL;
  END IF;
END;
$$;

DO $$
DECLARE
  v_cut timestamptz := now();
BEGIN
  IF to_regclass('schema_migrations') IS NOT NULL THEN
    EXECUTE $q$SELECT coalesce(min(applied_at), now()) FROM schema_migrations WHERE version LIKE '%m1\_107\_consent\_transitions.sql'$q$ INTO v_cut;
  END IF;
  INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm, person_off)
  SELECT c.tenant_id, c.device_id, c.e1, false, false, c.team, c.contribute_outcomes, c.local_rm, c.cloud_rm,
         ARRAY(SELECT DISTINCT x FROM unnest(coalesce(c.person_off, '{}')
                 || array_remove(ARRAY[CASE WHEN c.cloud_judge THEN 'cloud_judge' END, CASE WHEN c.training THEN 'training' END], NULL)) x ORDER BY x)
    FROM (SELECT DISTINCT ON (d.device_id) d.* FROM m1_device_consents d ORDER BY d.device_id, d.row_seq DESC) c
   WHERE (c.cloud_judge OR c.training) AND c.recorded_at < v_cut;
END $$;

REVOKE EXECUTE ON FUNCTION m1_withdraw_person_consents(uuid, text[]) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT EXECUTE ON FUNCTION m1_withdraw_person_consents(uuid, text[]) TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; the rows it wrote stay, m1_082 is append-only): re-apply m1_106's function body, then
-- BEGIN;
--   ALTER TABLE m1_device_consents DROP COLUMN IF EXISTS person_off;
-- COMMIT;
