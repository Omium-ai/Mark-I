-- m1_079_noise_certs_controld_read.sql
-- controld's GET /api/v1/verify/certificates (desktop spec §5.4 / §7.2) lists the tenant's
-- noise certificates with their status. m1_021 granted the table to adjudicator_app (owner)
-- and intel_app (reader); controld_app reads it too, under FORCE RLS + the tenant GUC, and
-- never writes it -- certification stays the adjudicator's alone. m1_verifiers, which the
-- route joins for the verifier's key/kind/name, is already controld_app-readable (m1_020).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON noise_certificates TO controld_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual):
-- BEGIN;
--   REVOKE SELECT ON noise_certificates FROM controld_app;
-- COMMIT;
