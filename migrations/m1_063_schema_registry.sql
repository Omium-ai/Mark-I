-- m1_063_schema_registry.sql
-- The `m1p-registry` FR-SPINE-023 names and no migration ever DDL'd: released
-- schema versions plus per-tenant accepted windows. Until this file, ingest
-- exact-matched `M1P-Schema` against a compiled-in "m1p.v1" and the 426 body
-- hardcoded accepted=[m1p.v1] with min_edge/window_closes null — there was no
-- window, so the "tenant window is the retirement instrument, per-tenant,
-- never a fleet-wide flag day" sentence of 08 §10.2 had nothing to stand on.
--
-- SEMANTICS (the part ingest/registry implements; stated here so the two
-- cannot drift apart silently):
--   * m1_schema_versions is GLOBAL, not tenant-scoped — the same posture as
--     m1_organizations (07). A schema is released once; retired_at closes it
--     fleet-wide only for tenants with NO explicit window.
--   * A tenant with NO rows in m1_tenant_schema_windows accepts every schema
--     whose retired_at IS NULL. The registry NARROWS; it never has to be
--     populated for the fleet to work, and a fresh database ingests m1p.v1
--     the moment this file has run (the seed row below).
--   * A tenant WITH rows accepts exactly the schemas it has rows for whose
--     window_closes IS NULL OR window_closes > now(). A tenant row for a
--     globally retired schema keeps that tenant on it — per-tenant retirement
--     is the point (08 §1.3: "≥ 180 days after its successor GAs, and for as
--     long as any enrolled, non-revoked device is still pinned to it").
--
-- WHO WRITES. Nobody at runtime. controld_app gets SELECT only, on both
-- tables; no *_app role gets INSERT/UPDATE. Windows are set by Omium
-- operations against the tenant's contract, not by the tenant and not by the
-- daemon — a device that could widen its own window would make the 426 a
-- suggestion. RESIDUAL, stated plainly: no ops surface for setting windows
-- exists yet; until one does, a window is an owner-role INSERT.
--
-- Numbered after m1_060 for the reason m1_062's header spells out: the grants
-- at the bottom only take once the roles exist, and m1_060's narrowing REVOKE
-- sweep predates these tables, so it is restated by name here.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

-- ---------------------------------------------------------------------------
-- (1) m1_schema_versions — the released-schema catalog. NOT tenant-scoped.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_schema_versions (
  -- The customer-visible protocol name that rides M1P-Schema (07 §1). The
  -- CHECK is the same syntactic gate ingest applies before any lookup.
  schema      text PRIMARY KEY CHECK (schema ~ '^m1p\.v[1-9][0-9]*$'),
  released_at timestamptz NOT NULL,
  retired_at  timestamptz NULL,
  -- The mark1d semver that first speaks this schema; the 426 hint's min_edge
  -- names the SUCCESSOR schema's value (08 §10.2's example). NULL for v1:
  -- there is nothing older to upgrade from.
  min_edge    text NULL,
  notes_uri   text NOT NULL
);

INSERT INTO m1_schema_versions (schema, released_at, retired_at, min_edge, notes_uri)
VALUES ('m1p.v1', now(), NULL, NULL, 'https://docs.omium.ai/mark1/upgrade/m1p-v1')
ON CONFLICT (schema) DO NOTHING;

-- ---------------------------------------------------------------------------
-- (2) m1_tenant_schema_windows — the per-tenant narrowing.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_tenant_schema_windows (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  schema        text NOT NULL REFERENCES m1_schema_versions(schema),
  -- NULL = open indefinitely; a past instant = closed (the 426 hint reports
  -- it as window_closes so the edge can say WHEN it fell out of window).
  window_closes timestamptz NULL,
  PRIMARY KEY (tenant_id, schema)
);

-- ---------------------------------------------------------------------------
-- (3) RLS — canonical form. The NULLIF is what makes an unset GUC match
--     nothing rather than everything. m1_schema_versions carries none: it is
--     global by design, like m1_organizations.
-- ---------------------------------------------------------------------------
ALTER TABLE m1_tenant_schema_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_tenant_schema_windows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_tenant_schema_windows;
CREATE POLICY tenant_isolation ON m1_tenant_schema_windows
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- (4) Grants — SELECT only, and m1_060's narrowing REVOKEs restated by name.
-- ---------------------------------------------------------------------------
REVOKE ALL ON m1_schema_versions, m1_tenant_schema_windows FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON m1_schema_versions, m1_tenant_schema_windows TO controld_app;
  END IF;
  FOREACH r IN ARRAY ARRAY['controld_app', 'adjudicator_app', 'intel_app', 'mark1_federation_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON m1_schema_versions, m1_tenant_schema_windows FROM %I', r);
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; ingest falls back to its compiled-in
-- [m1p.v1] window the moment the tables are gone — fail-static, 08 §9):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_tenant_schema_windows;
--   DROP TABLE IF EXISTS m1_schema_versions;
-- COMMIT;
