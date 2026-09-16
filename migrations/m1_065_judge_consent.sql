-- m1_065_judge_consent.sql
-- WHY: the cloud-judge path (06 §6.5) sends evidence to a model vendor. It is
-- admissible ONLY under four machine-checked preconditions: (1) a tenant consent
-- row, (2) the subprocessor named in that row, (3) the region pinned on the call,
-- (4) evidence tier <= the consented cloud tier -- and E2 never, structurally.
-- This table is (1)+(2)+(3)+(4) as one revocable row per (tenant, judge version).
-- No row means client-side execution through the customer's own key
-- (FR-VERIFY-015 / NFR-PRIVACY-006): absence is the default, never a fallback.
--
-- Shape mirrors m1_anchor_consents (m1_020): revocation is an UPDATE, never a
-- DELETE, so "was cloud judging consented on <date>" stays answerable. Keyed by
-- the wire judge_id text ("judge:<name>@<version>", verify.proto JudgeVote) --
-- a rubric/model change is a new version (06 §6.3), which no existing consent
-- names, so re-consent needs no machinery beyond the key.
--
-- RECEIPTING (06 §6.5 "a receipted, revocable settings row") is the ledger's
-- concern and is not wired here; the row is the durable fact the receipt cites.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS m1_cloud_judge_consents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES m1_tenants(id),
  judge_id        text NOT NULL CHECK (judge_id ~ '^judge:[a-z0-9-]+@[1-9][0-9]*$'),
  -- The model vendor disclosed to the tenant (the subprocessor register entry).
  subprocessor    text NOT NULL,
  -- The vendor-side inference geography pinned on every call (Anthropic:
  -- 'us' | 'global'). Compared verbatim against the judge's registry entry.
  region          text NOT NULL,
  -- E2 is VPC/self-host only and never leaves the customer boundary: the CHECK
  -- is the "job builder has no E2 branch" of 06 §6.5, enforced where a code
  -- regression cannot reach it.
  max_tier        text NOT NULL CHECK (max_tier IN ('E0', 'E1')),
  consented_by    text NOT NULL,   -- OIDC subject; consent has an author
  consented_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  revoked_reason  text
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_cloud_judge_consent_live
  ON m1_cloud_judge_consents (tenant_id, judge_id)
  WHERE revoked_at IS NULL;

ALTER TABLE m1_cloud_judge_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_cloud_judge_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_cloud_judge_consents;
CREATE POLICY tenant_isolation ON m1_cloud_judge_consents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Consent arrives through controld from the tenant's admin surface; the
-- adjudicator only ever reads it at job admission. Nobody deletes anything.
REVOKE ALL ON m1_cloud_judge_consents FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_cloud_judge_consents TO controld_app;  -- UPDATE = revocation
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_cloud_judge_consents TO adjudicator_app;
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed; drops consent history that receipt
-- disputes cite -- export it first):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_cloud_judge_consents CASCADE;
-- COMMIT;
