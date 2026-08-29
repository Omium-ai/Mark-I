-- =============================================================================
-- m1_060_roles_and_grants.sql
--
-- The runtime role matrix for the Mark 1 Postgres schema. Runs LAST, on
-- purpose (07 §"Postgres — conventions and migration ordering": the roles file
-- is "deliberately last so its narrowing REVOKEs outrank every blanket grant").
--
-- NUMBERING. 07's prose calls this file `m1_011_roles_grants.sql`. In this repo
-- m1_001-m1_039 and m1_040-m1_059 are allocated to the table/trigger/policy
-- migrations, so the roles file lands at m1_060. Filename-order execution keeps
-- 07's "roles last" property, which is the property that actually matters.
--
-- WHY THE GRANTS ARE RESTATED HERE IN FULL. Every grant in m1_001-m1_043 is
-- wrapped in `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ...)`, per the
-- house style. On a fresh database built in filename order those guards are ALL
-- false, because the roles do not exist until this file creates them -- so a
-- first-run database would end with four login roles and zero table privileges.
-- This file therefore carries the complete matrix, not just the tables that have
-- no earlier grant. Restating also makes the two build orders (roles-first from
-- a restore, roles-last from a fresh apply) converge on the same matrix.
--
-- -----------------------------------------------------------------------------
-- WHY THIS FILE IS THE MOST CONSEQUENTIAL ONE IN THE SET
-- -----------------------------------------------------------------------------
-- The estate's lesson, verbatim (07 §"Roles and grants"): 61 FORCE-RLS tables
-- were decorative because every service connected as the RDS master user, which
-- inherits rds_superuser and therefore BYPASSRLS. Correct policies, privileged
-- connection, zero enforcement.
--
-- The fix is structural, not procedural: migrations run as the owner
-- (mark1_owner), runtime never does; every request-path role is NOBYPASSRLS and
-- NOSUPERUSER by attribute; the grant surface is per-table, never schema-wide;
-- and this file asserts its own postcondition at the bottom, so a database that
-- somehow converged to a privileged runtime role rolls the migration back
-- instead of shipping.
--
-- -----------------------------------------------------------------------------
-- RECONCILIATION OF RECONCILIATION.md FINDING SEC-04 (S1, verified)
-- -----------------------------------------------------------------------------
-- 05 and 07 carried two incompatible role inventories:
--   * 05 §7.1/§7.3: controld_app, controld_worker (BYPASSRLS), controld_migrate.
--   * 07 §Roles and grants: controld_app, adjudicator_app, intel_app, and
--     mark1_federation_worker as the single BYPASSRLS worker. controld_worker
--     appears nowhere in 07; 07's three names appear nowhere in 10.
--
-- Resolution rule applied: 07 is the data-model authority and wins on schema
-- objects (role names, grant matrix); 05 wins on which process does what. One
-- inventory results. `controld_worker` is DISSOLVED: it was a process-shaped
-- name for a capability that 07 already partitions by capability, and four of
-- its five justifying paths turn out not to be cross-tenant at all.
--
--   ROLE                     | COMPONENT THAT CONNECTS AS IT        | BYPASSRLS | WHY
--   -------------------------+--------------------------------------+-----------+-----
--   mark1_owner              | the migration Sync-hook Job only     | no        | Table owner, holds DDL. Never present in a runtime pod's environment. This is 05's `controld_migrate` under 07's name; 07 wins on the name. Not created here -- this file RUNS as it.
--   controld_app             | controld: ingest, enroll, policydist,| no        | Request path. FORCE RLS + the NULLIF two-arg GUC policy is the whole isolation control, so a bypass here would re-create the estate failure exactly.
--                            | receipt/checkpoint side-effects      |           |
--   adjudicator_app          | adjudicator-svc (06 §schema owner    | no        | Certification and nothing else. Cannot read memory_artifacts: a certifier that can see what its certificates admit can be gamed toward admitting it.
--                            | list)                                |           |
--   intel_app                | mark1-intel (memory, tvo-engine,     | no        | 07 names DP release under intel_app; 03/05 place the DP-release *process* inside controld. Both hold: 07's roles are CAPABILITY-scoped, not process-scoped, so `controld.dprelease`'s epsilon-ledger path connects on the intel_app pool. No new role, no widened grant.
--                            | policy-compiler, corpus-exporter)    |           |
--                            | + controld.dprelease/epsledger.go    |           |
--   mark1_federation_worker  | controld.dprelease/intersect.go      | YES       | THE one bypass. Nameable cross-tenant jobs, cross-tenant BY MATHEMATICAL DEFINITION: the (k,m) candidate GROUP BY over artifact_contributions, the org collusion collapse over org_verification, and the span reconstruction read over memory_artifacts. A per-tenant GUC loop cannot compute count(DISTINCT tenant_id). Its cross-tenant privilege is SELECT-only; its write surface is entirely tenant-less tables.
--
-- THE epsledger DISAGREEMENT, RESOLVED IN FAVOUR OF 07 (the safer reading).
-- 05 §7.3 lists `dprelease/epsledger.go` alongside `intersect.go` as a
-- BYPASSRLS path. 07 §Federation and privacy is explicit and gives a mechanism:
-- "The DP release job runs per tenant under set_local_tenant -- it composes one
-- tenant's budget, so it HAS a tenant context and gets no bypass." That is
-- correct on the arithmetic: basic sequential composition sums ONE tenant's
-- epsilon_ledger rows against ONE tenant's cap. Nothing in 05 supplies a
-- mechanism that makes a tenant context impossible there. 05's grouping of the
-- two files was convenience (same package), not specification. ADOPTED: 07.
-- epsledger runs on intel_app under set_local_tenant, NOBYPASSRLS.
--
-- THE OTHER THREE 05 §7.3 PATHS, likewise resolved to no-bypass:
--   * `policydist/canary.go` -- 05 §7.3 says "cohort-vs-control comparisons span
--     tenants", but 05 §4.3 (the same document, more detail) says the controller
--     drives rollout "per (tenant, bundle seq)" and compares a cohort against
--     "the un-widened remainder" of the SAME tenant; the health signals come
--     from querychoke templates (ClickHouse), not Postgres. Per-tenant loop.
--   * `enroll`'s daily reconciliation sweep -- re-validating approved_by per
--     device is embarrassingly per-tenant; iterate tenants, set the GUC, sweep.
--   * `ingest/sidefx` checkpoint builder -- 05 §7.3 itself says "each write is
--     still tenant-keyed", and 07's m1_002 already grants exactly that write set
--     (m1_receipts INSERT, m1_receipt_chain_head UPDATE) to the NOBYPASSRLS
--     controld_app. Per-tenant loop.
--   * the offboarding/deletion job -- needs DELETE, which NO runtime role holds
--     (see the deliberate-absence list below). It runs as mark1_owner under dual
--     control, per tenant, with the GUC set (FORCE RLS binds the owner too).
--
-- SEC-04's named follow-on defect, RESOLVED IN m1_041 AND NOT HERE:
-- trg_epsilon_budget() serializes with pg_advisory_xact_lock, not with
-- `SELECT ... FOR UPDATE`, so the budget gate needs no UPDATE privilege on
-- tenant_privacy_budgets at all. intel_app therefore holds SELECT only, and (6)
-- revokes UPDATE besides: the DP-SPENDING role must not be able to raise the
-- very cap that binds it, and RLS cannot stop it if it can -- it would be
-- editing its OWN tenant's row, so USING and WITH CHECK both pass.
--
-- -----------------------------------------------------------------------------
-- Roles are created WITHOUT passwords: a LOGIN role with no password cannot
-- authenticate. Credentials are injected from Secrets Manager
-- (omium/prod/mark1-db-service-credentials) at cutover, never committed.
--
-- Idempotent, safe to re-run under ON_ERROR_STOP=1.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- (1) Roles.
-- -----------------------------------------------------------------------------
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB', r);
    ELSE
      -- NOSUPERUSER omitted on the converge path: RDS's master is not a true
      -- superuser and rejects ALTER ROLE ... NOSUPERUSER (same reasoning as
      -- platform 07/100a/200a). The postcondition in (7) still verifies it.
      EXECUTE format('ALTER ROLE %I LOGIN NOBYPASSRLS NOCREATEROLE NOCREATEDB', r);
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
  END LOOP;

  -- THE one BYPASSRLS role. The bar: somebody can NAME the cross-tenant job.
  -- Named above. Cross-tenant privilege is SELECT-only.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mark1_federation_worker') THEN
    CREATE ROLE mark1_federation_worker LOGIN BYPASSRLS NOSUPERUSER NOCREATEROLE NOCREATEDB;
  ELSE
    ALTER ROLE mark1_federation_worker LOGIN BYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  GRANT USAGE ON SCHEMA public TO mark1_federation_worker;
END $$;

-- -----------------------------------------------------------------------------
-- (2) controld_app -- the request path of ingest / enroll / policydist, plus the
--     receipt and checkpoint side-effects. Per-table, never schema-wide.
-- -----------------------------------------------------------------------------
-- m1_001 identity registry: controld owns enrollment and revocation.
GRANT SELECT, INSERT, UPDATE ON m1_organizations, m1_tenants, m1_devices,
                                m1_device_enrollments, m1_device_keys,
                                m1_device_credential_fingerprints
  TO controld_app;
-- m1_002 receipt chain: ONE writer. Append-only at the privilege layer too.
GRANT SELECT, INSERT         ON m1_receipts            TO controld_app;
GRANT SELECT, INSERT, UPDATE ON m1_receipt_chain_head  TO controld_app;
GRANT SELECT, INSERT, UPDATE ON m1_server_signing_keys TO controld_app;
-- m1_003 witness heads: append-only.
GRANT SELECT, INSERT ON m1_witness_heads TO controld_app;
-- m1_020 verifier registry: consent arrives through controld from the edge.
GRANT SELECT                 ON m1_verifiers       TO controld_app;
GRANT SELECT, INSERT, UPDATE ON m1_anchor_consents TO controld_app;  -- UPDATE = revocation
-- m1_042 bundle distribution + the ACK ledger.
GRANT SELECT         ON policy_bundles, bundle_channel_heads TO controld_app;
GRANT SELECT, INSERT ON bundle_acks                          TO controld_app;
-- m1_043 coverage: ingest mirrors CoverageTransition events; append-only by grant.
GRANT SELECT, INSERT ON coverage_transitions TO controld_app;

-- -----------------------------------------------------------------------------
-- (3) adjudicator_app -- certification and nothing else.
-- -----------------------------------------------------------------------------
GRANT SELECT ON m1_tenants, m1_devices, m1_device_keys TO adjudicator_app;
GRANT SELECT ON m1_receipts, m1_server_signing_keys    TO adjudicator_app;
GRANT SELECT ON m1_verifiers                           TO adjudicator_app;  -- confusion matrices key on catalog rows
GRANT SELECT, INSERT, UPDATE ON gold_sets, gold_set_members, noise_certificates
  TO adjudicator_app;

-- -----------------------------------------------------------------------------
-- (4) intel_app -- memory, DP release, policy compiler, TVO, corpus exporter.
-- -----------------------------------------------------------------------------
GRANT SELECT ON m1_organizations, m1_tenants, m1_devices, m1_device_keys TO intel_app;
GRANT SELECT ON m1_receipts, m1_server_signing_keys                      TO intel_app;
GRANT SELECT ON m1_witness_heads                                         TO intel_app;  -- reports cite witness coverage
GRANT SELECT, INSERT, UPDATE ON m1_verifiers TO intel_app;  -- UPDATE = retired_at only, trigger-policed
GRANT SELECT ON m1_anchor_consents           TO intel_app;  -- the compiler refuses to enable unconsented anchors
GRANT SELECT ON noise_certificates, coverage_transitions,
                artifact_publications, publication_spans TO intel_app;
GRANT SELECT, INSERT, UPDATE ON memory_artifacts, artifact_contributions,
                                corpus_admissions        TO intel_app;
GRANT SELECT, INSERT ON epsilon_ledger, tvo_reports, policy_bundles TO intel_app;
GRANT SELECT, INSERT, UPDATE ON bundle_channel_heads TO intel_app;  -- UPDATE: the head advance inside the publish trigger
GRANT SELECT ON tenant_privacy_budgets TO intel_app;  -- SELECT only: the spender never holds its own cap

-- -----------------------------------------------------------------------------
-- (5) mark1_federation_worker -- cross-tenant READS, tenant-less writes.
-- -----------------------------------------------------------------------------
GRANT SELECT ON memory_artifacts, artifact_contributions, org_verification
  TO mark1_federation_worker;
GRANT SELECT, INSERT, UPDATE ON publication_review_queue TO mark1_federation_worker;  -- UPDATE: recording the human's decision
GRANT SELECT, INSERT ON artifact_publications, publication_spans,
                        publication_span_producers      TO mark1_federation_worker;

-- -----------------------------------------------------------------------------
-- (6) The narrowing REVOKEs. This is why the file runs last: a REVOKE here
--     outranks any blanket grant an earlier file (or a human at a psql prompt)
--     left behind. Absence is the control.
--
--     * NO role has DELETE or TRUNCATE on ANYTHING. Retirement is a state
--       change; erasure is the offboarding runbook run as mark1_owner under
--       dual control; everything else is evidence.
--     * The append-only tables lose UPDATE as well, at the privilege layer,
--       independently of the trigger layer -- the ro_012 discipline: a control
--       that holds only because the other one caught it has already failed.
--     * tenant_privacy_budgets loses UPDATE too, though it is not append-only:
--       raising a cap is a contract change made by the owner, never by the role
--       that spends against it.
--     * adjudicator_app is not named on memory_artifacts anywhere above; the
--       REVOKE makes that explicit rather than incidental.
--     * mark1_federation_worker holds NOTHING on epsilon_ledger, policy_bundles,
--       gold_set_members, tvo_reports or the receipt chain -- its bypass is
--       scoped to the federation read set, so compromising the worker leaks
--       contributions, not budgets, bundles, gold labels or money-adjacent rows.
-- -----------------------------------------------------------------------------
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app',
                           'mark1_federation_worker'] LOOP
    EXECUTE format('REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM %I', r);
    EXECUTE format(
      'REVOKE UPDATE ON m1_receipts, m1_witness_heads, epsilon_ledger, '
      'policy_bundles, coverage_transitions, tenant_privacy_budgets FROM %I', r);
  END LOOP;
END $$;

REVOKE ALL ON memory_artifacts, artifact_contributions, corpus_admissions,
              epsilon_ledger, tenant_privacy_budgets
  FROM adjudicator_app;

-- -----------------------------------------------------------------------------
-- (7) POSTCONDITION. The migration proves its own security property or rolls
--     back. This is the direct, structural answer to the rds_superuser
--     incident: privilege is checked as it RESOLVES (own attribute OR arriving
--     through role membership), because the estate's failure arrived through
--     membership, not through an attribute anyone had set.
--
--     pg_has_role(member, grantee, 'USAGE') is true when privileges are
--     actually inherited, and is true for a role against itself -- so one
--     predicate covers both the attribute case and the membership case.
--
--     Deliberately NOT enforced here: that current_user (the migration role) is
--     unprivileged. On RDS the bootstrap apply legitimately runs as the master.
--     conformance/tenancy/ owns the allow-list assertion over the whole cluster
--     (RECONCILIATION SEC-04: `SELECT rolname FROM pg_roles WHERE rolcanlogin
--     AND (rolbypassrls OR rolsuper)` must equal a hard-coded list) -- an
--     allow-list, not the `*_app` naming convention, which is a habit and not a
--     predicate.
--
--     Note what (a) actually catches, since step (1) above just ran
--     `ALTER ROLE ... NOBYPASSRLS` and would have repaired a plain attribute:
--     the cases the ALTER cannot repair. Privilege arriving through role
--     MEMBERSHIP (the estate's exact failure -- rds_superuser inherited, not
--     set), and a SUPERUSER attribute that the ALTER could not clear because
--     NOSUPERUSER was omitted on the converge path. Both are silent otherwise.
-- -----------------------------------------------------------------------------
DO $$
DECLARE bad text;
BEGIN
  -- (a) No request-path role may reach BYPASSRLS or SUPERUSER by any route.
  SELECT string_agg(r.rolname, ', ') INTO bad
    FROM pg_roles r
   WHERE r.rolname IN ('controld_app', 'adjudicator_app', 'intel_app')
     AND EXISTS (SELECT 1 FROM pg_roles g
                  WHERE (g.rolbypassrls OR g.rolsuper)
                    AND pg_has_role(r.oid, g.oid, 'USAGE'));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION
      'RLS would be decorative: request-path role(s) [%] hold or inherit BYPASSRLS/SUPERUSER. '
      'This is the 61-table estate failure. Migration refused.', bad
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- (b) The one bypass role must hold exactly that and no more.
  SELECT string_agg(r.rolname, ', ') INTO bad
    FROM pg_roles r
   WHERE r.rolname = 'mark1_federation_worker'
     AND (NOT r.rolbypassrls
          OR EXISTS (SELECT 1 FROM pg_roles g
                      WHERE g.rolsuper AND pg_has_role(r.oid, g.oid, 'USAGE')));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION
      'mark1_federation_worker must be BYPASSRLS and must not hold or inherit SUPERUSER. '
      'Migration refused.'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
END $$;

COMMIT;

-- ROLLBACK (manual, after repointing every service DSN back to the owner --
-- which is itself the failure this file exists to prevent, so do not):
-- BEGIN;
--   REVOKE ALL ON ALL TABLES IN SCHEMA public FROM controld_app, adjudicator_app,
--     intel_app, mark1_federation_worker;
--   REVOKE USAGE ON SCHEMA public FROM controld_app, adjudicator_app,
--     intel_app, mark1_federation_worker;
--   DROP ROLE IF EXISTS controld_app;
--   DROP ROLE IF EXISTS adjudicator_app;
--   DROP ROLE IF EXISTS intel_app;
--   DROP ROLE IF EXISTS mark1_federation_worker;
-- COMMIT;
