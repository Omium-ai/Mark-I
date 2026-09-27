-- m1_106_person_withdrawal.sql
-- Two bindings the E1 and contribution paths were missing.
--
--   m1_task_devices                  the task's own device, bound once by the first TaskOpen/TaskClose that
--                                    lands (ingest stage 11); attach admits a part only from that device
--   m1_withdraw_person_consents()    a consent turned off is turned off for the PERSON in this tenant: every
--                                    device whose latest enrollment carries the caller device's subject gets a
--                                    new m1_082 row with those fields off, and its E1 parts / contributions are
--                                    marked withdrawn, so every latest-row-per-device reader agrees. Not across
--                                    tenants: consent follows the tenant (16 L8), and a tenant switch resets
--                                    contribute_outcomes to undecided, so an off in the team tenant is not a
--                                    withdrawal of what the person granted in their personal one (15-teams)
--
-- Invoker's rights: FORCE RLS on every table it touches keeps it inside the session tenant, and it refuses a
-- device outside it outright. It locks each device of the person (xact advisory lock 'm1_consent:<device>',
-- ascending id); attach takes the same lock shared before its consent check and index insert, so a
-- withdrawal and an upload of the same device serialise. Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_task_devices (
  tenant_id  uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  task_id    uuid NOT NULL,
  device_id  uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT,
  bound_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id)
);

ALTER TABLE m1_task_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_task_devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_task_devices;
CREATE POLICY tenant_isolation ON m1_task_devices
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS trg_m1_task_devices_no_update ON m1_task_devices;
CREATE TRIGGER trg_m1_task_devices_no_update
  BEFORE UPDATE ON m1_task_devices
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();
DROP TRIGGER IF EXISTS trg_m1_task_devices_no_delete ON m1_task_devices;
CREATE TRIGGER trg_m1_task_devices_no_delete
  BEFORE DELETE ON m1_task_devices
  FOR EACH ROW EXECUTE FUNCTION m1_append_only();

CREATE INDEX IF NOT EXISTS ix_m1_device_enrollments_subject
  ON m1_device_enrollments (tenant_id, oidc_subject) WHERE oidc_subject IS NOT NULL AND device_id IS NOT NULL;

CREATE OR REPLACE FUNCTION m1_withdraw_person_consents(p_device uuid, p_off text[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
DECLARE
  v_tenant  uuid := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_subject text;
  v_devices uuid[];
  v_device  uuid;
BEGIN
  IF v_tenant IS NULL OR NOT EXISTS (SELECT 1 FROM m1_devices WHERE id = p_device AND tenant_id = v_tenant) THEN
    RAISE EXCEPTION 'm1_withdraw_person_consents: device % is not in the session tenant', p_device
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_off IS NULL OR NOT p_off <@ ARRAY['e1', 'cloud_judge', 'training', 'team', 'contribute_outcomes', 'cloud_rm'] THEN
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

  INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, team, contribute_outcomes, local_rm, cloud_rm)
  SELECT c.tenant_id, c.device_id,
         c.e1 AND NOT ('e1' = ANY (p_off)),
         c.cloud_judge AND NOT ('cloud_judge' = ANY (p_off)),
         c.training AND NOT ('training' = ANY (p_off)),
         c.team AND NOT ('team' = ANY (p_off)),
         c.contribute_outcomes AND NOT ('contribute_outcomes' = ANY (p_off)),
         c.local_rm,
         c.cloud_rm AND NOT ('cloud_rm' = ANY (p_off))
    FROM (SELECT DISTINCT ON (d.device_id) d.* FROM m1_device_consents d
           WHERE d.tenant_id = v_tenant AND d.device_id = ANY (v_devices) AND d.device_id <> p_device
           ORDER BY d.device_id, d.row_seq DESC) c
   WHERE (c.e1 AND 'e1' = ANY (p_off)) OR (c.cloud_judge AND 'cloud_judge' = ANY (p_off))
      OR (c.training AND 'training' = ANY (p_off)) OR (c.team AND 'team' = ANY (p_off))
      OR (c.contribute_outcomes AND 'contribute_outcomes' = ANY (p_off)) OR (c.cloud_rm AND 'cloud_rm' = ANY (p_off));

  IF 'e1' = ANY (p_off) THEN
    UPDATE m1_evidence_attachments SET withdrawn_at = now()
     WHERE tenant_id = v_tenant AND device_id = ANY (v_devices) AND withdrawn_at IS NULL AND deleted_at IS NULL;
  END IF;
  IF 'contribute_outcomes' = ANY (p_off) THEN
    UPDATE m1_outcome_contributions SET withdrawn_at = now()
     WHERE tenant_id = v_tenant AND device_id = ANY (v_devices) AND withdrawn_at IS NULL;
  END IF;
END;
$$;

REVOKE ALL ON m1_task_devices FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION m1_withdraw_person_consents(uuid, text[]) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT ON m1_task_devices TO controld_app;
    GRANT EXECUTE ON FUNCTION m1_withdraw_person_consents(uuid, text[]) TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual; the consent rows it wrote stay, m1_082 is append-only):
-- BEGIN;
--   DROP FUNCTION IF EXISTS m1_withdraw_person_consents(uuid, text[]);
--   DROP INDEX IF EXISTS ix_m1_device_enrollments_subject;
--   DROP TABLE IF EXISTS m1_task_devices;
-- COMMIT;
