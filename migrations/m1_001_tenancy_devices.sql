-- m1_001_tenancy_devices.sql
-- WHY: everything downstream keys on tenant_id, and the federation (k,m) gate
-- keys on ORGANIZATIONS whose verification is provable from this table alone.
-- Devices exist because receipts are dual-signed: the device origin key is an
-- identity we must be able to enroll, rotate, and revoke without ever losing
-- the ability to verify what an old key already signed. Nothing here is ever
-- DELETEd — enrollment and key history is evidence, so retirement is an UPDATE
-- of a timestamp, and the grants below hand out no DELETE to anyone.
--
-- ENG-05 (RECONCILIATION S1, "nobody builds tenant onboarding"): every flow in
-- 04/05/08 presupposes a fully provisioned tenant, and no module created one.
-- The m1_tenants block below carries the onboarding-only columns that make a
-- tenant row *expressible* rather than hand-crafted in psql — the tenant IdP
-- metadata discovered at onboarding (05 §3.2), the pinned JWKS (05 §10.1 B2),
-- the per-tenant KMS alias whose absence is boot refusal R6's premise
-- (05 §1.2), the per-tenant HMAC salt reference (10 §9), the coverage floor,
-- and the operator-token verification rule. `onboarding_completed_at` is
-- guarded by a CHECK over all of them, so "provisioned" is a database fact and
-- a half-onboarded tenant cannot claim to be finished.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- (1) m1_organizations — the federation trust registry. NOT tenant-scoped.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_organizations (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                     text NOT NULL,
  -- The domain the org proved control of. Verification method recorded so an
  -- auditor can ask "proved HOW" — dns_txt is the strong answer, email the weak.
  primary_domain           text NOT NULL,
  domain_verified_at       timestamptz,
  domain_verification_method text
    CHECK (domain_verification_method IN ('dns_txt', 'email')),
  -- Stripe customer id, text because it is Stripe's key, not ours. A billing
  -- relationship is the second, independent leg of "verified": domains are
  -- cheap, invoices are not, and the (k,m) gate needs both legs so that m
  -- sock-puppet orgs collapse to zero rather than to m.
  billing_customer_id      text,
  billing_verified_at      timestamptz,
  created_at               timestamptz NOT NULL DEFAULT now(),
  -- A method without a timestamp (or vice versa) is a half-claim; refuse it.
  CONSTRAINT ck_m1_org_domain_pair
    CHECK ((domain_verified_at IS NULL) = (domain_verification_method IS NULL)),
  CONSTRAINT uq_m1_org_domain UNIQUE (primary_domain)
);

-- The federation gate's exact predicate, named here so every consumer counts
-- "verified" the same way:  domain_verified_at IS NOT NULL AND
-- billing_verified_at IS NOT NULL.  Partial index so the gate's org count is
-- an index-only scan.
CREATE INDEX IF NOT EXISTS ix_m1_org_verified
  ON m1_organizations (id)
  WHERE domain_verified_at IS NOT NULL AND billing_verified_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- (2) m1_tenants — the isolation boundary everything else FKs to.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m1_tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES m1_organizations(id),
  name        text NOT NULL,
  -- text + CHECK rather than an enum: tenant lifecycle states will grow
  -- (trial, suspended-for-billing, ...) and ALTER TYPE ADD VALUE cannot run
  -- inside the transactional migration style this repo uses.
  status      text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'closed')),
  -- Region pinning for the cloud-judge path (contract C4); recorded at the
  -- tenant, enforced at the services.
  region      text NOT NULL DEFAULT 'us-east-1',
  created_at  timestamptz NOT NULL DEFAULT now(),

  -- ---- ENG-05 (a): tenant IdP, discovered at onboarding -------------------
  -- 05 §3.2: enroll runs the OIDC device-authorization grant against the
  -- TENANT's IdP, not ours, so these five endpoints must exist before device
  -- #1 can enroll. Discovered from the issuer's OIDC metadata at onboarding
  -- and refreshed daily (oidc_refreshed_at); oidc_discovered_at is the
  -- onboarding fact, oidc_refreshed_at is the liveness fact, and they are
  -- separate because a stale refresh must not look like a missing onboarding.
  oidc_issuer                        text,
  oidc_client_id                     text,
  -- The IdP client secret itself never lands in Postgres: this is the AWS
  -- Secrets Manager path External Secrets resolves (09 §secrets). Storing the
  -- secret here would make this table a credential vault without the vault.
  oidc_client_secret_ref             text,
  oidc_jwks_uri                      text,
  -- The JWKS document pinned at onboarding (05 §10.1 B2). Pinned, not fetched
  -- on demand: an IdP whose JWKS URI is hijacked would otherwise be able to
  -- mint approvals for this tenant. Rotation is an explicit re-pin.
  oidc_jwks_pinned                   text,
  oidc_device_authorization_endpoint text,
  oidc_token_endpoint                text,
  oidc_discovered_at                 timestamptz,
  oidc_refreshed_at                  timestamptz,
  -- 05 §3.5 abuse case 3: the daily reconciliation sweep re-validates every
  -- ACTIVE device's approver against the tenant IdP. WHICH contract to use is
  -- chosen at onboarding, because IdPs differ and the sweep cannot guess.
  -- 'none' is a legitimate, recorded choice — it costs the tenant nothing but
  -- <=24 h of token life past offboarding, and the row says so out loud.
  directory_lookup_mode              text NOT NULL DEFAULT 'none'
    CHECK (directory_lookup_mode IN ('introspection', 'scim', 'directory', 'none')),

  -- ---- ENG-05 (b): per-tenant KMS + bucket policy -------------------------
  -- 07 S3 layout: every object under t/<tenant_uuid>/ is SSE-KMS'd under this
  -- tenant's dedicated key, and the bucket policy DENIES any PutObject whose
  -- key id does not match the prefix. Boot refusal R6 asserts that deny
  -- statement exists; onboarding is what puts it there, and
  -- bucket_policy_applied_at is the record that it did. The alias is recorded
  -- rather than derived because its prefix is deployment config
  -- (KMS_TENANT_ALIAS_PREFIX, 05 §1.3) — a derived value would silently drift
  -- when that env changes, and an SSE-KMS PUT under a drifted alias is a
  -- write failure at 3am with no row to explain it.
  kms_key_alias                      text,
  kms_key_arn                        text,
  bucket_policy_applied_at           timestamptz,

  -- ---- ENG-05 (c): per-tenant HMAC salt material --------------------------
  -- 04 §2.9 needs this "delivered at enrollment"; 10 §9 makes its destruction
  -- the crypto-erasure lever at offboarding. Reference only — the salt lives
  -- in Secrets Manager, derived from the mark1-hmac-pepper root (09). The
  -- version is what digests carry, so rotation does not orphan old digests.
  hmac_salt_secret_ref               text,
  hmac_salt_version                  int NOT NULL DEFAULT 1
                                       CHECK (hmac_salt_version >= 1),

  -- ---- ENG-05 (d): operator-token verification ----------------------------
  -- 08 §1: an operator token is a tenant-admin OIDC access token. WHICH
  -- audience and which claim makes a subject an admin is a per-tenant fact
  -- that must be decided at onboarding; without it every operator endpoint
  -- (revoke, reports, DP) has no admission rule at all.
  operator_audience                  text,
  operator_admin_claim               text,
  operator_admin_value               text,

  -- ---- ENG-05 (e): coverage floor -----------------------------------------
  -- 06 §5 D23: guarantee-grade issuance is refused below 0.95. Per-tenant so a
  -- contract can demand MORE; the CHECK is what stops it demanding less, which
  -- would turn the refusal rule into a negotiable one.
  coverage_floor                     numeric(4,3) NOT NULL DEFAULT 0.950
    CHECK (coverage_floor >= 0.950 AND coverage_floor <= 1.000),

  -- 05 §3.4: the revocation authority is the device row PLUS this monotonic
  -- per-tenant epoch, bumped on every revoke. It is what policydist pushes on
  -- live SSE streams and what the <=60 s fail-closed revocation cache compares
  -- against; a cache with no epoch cannot tell "nothing changed" from "I have
  -- not refreshed".
  revocation_epoch                   bigint NOT NULL DEFAULT 0
                                       CHECK (revocation_epoch >= 0),

  -- The single fact that says a tenant is usable. Set once, by the onboarding
  -- path, only when every provisioned dependency above is recorded.
  onboarding_completed_at            timestamptz,

  -- Onboarding is a checklist, so make it one the database enforces. Without
  -- this a tenant row can be INSERTed with nothing but a name and every
  -- downstream refusal (R6, the sweep, operator auth, the salt) fails far from
  -- the cause. NOTE: the ε budget is deliberately NOT here — it lives in
  -- tenant_privacy_budgets (companion part) and a CHECK cannot reach another
  -- table; the onboarding path must seed that row and the (k,m) gate refuses
  -- without it.
  CONSTRAINT ck_m1_tenants_onboarded CHECK (
    onboarding_completed_at IS NULL
    OR (oidc_issuer IS NOT NULL
        AND oidc_client_id IS NOT NULL
        AND oidc_jwks_uri IS NOT NULL
        AND oidc_jwks_pinned IS NOT NULL
        AND oidc_device_authorization_endpoint IS NOT NULL
        AND oidc_token_endpoint IS NOT NULL
        AND oidc_discovered_at IS NOT NULL
        AND kms_key_alias IS NOT NULL
        AND kms_key_arn IS NOT NULL
        AND bucket_policy_applied_at IS NOT NULL
        AND hmac_salt_secret_ref IS NOT NULL
        AND operator_audience IS NOT NULL
        AND operator_admin_claim IS NOT NULL
        AND operator_admin_value IS NOT NULL)
  )
);

ALTER TABLE m1_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_tenants;
-- The PK IS the tenant id, so the policy keys on id directly.
CREATE POLICY tenant_isolation ON m1_tenants
  USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE INDEX IF NOT EXISTS ix_m1_tenants_org ON m1_tenants (org_id);

-- ---------------------------------------------------------------------------
-- (3) m1_devices — one row per enrolled machine.
-- ---------------------------------------------------------------------------
-- 05 §3.1's DORMANT state has no column here on purpose: it is "refresh absent
-- 30 d", derivable from last_seen_at, and it changes no trust decision. A
-- stored state that nothing reads is a state that drifts.
CREATE TABLE IF NOT EXISTS m1_devices (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id),
  -- 'linux' | 'darwin' | 'windows'; free text because OS strings drift and a
  -- CHECK here would reject the first Windows-on-ARM machine for no benefit.
  platform       text NOT NULL,
  -- Per-tenant HMAC of the hostname, never the hostname: the wire contract
  -- says no raw identifiers leave the edge, and this table must not be the
  -- exception. 32 bytes = HMAC-SHA-256; length-checked like every digest.
  hostname_hmac  bytea NOT NULL,
  enrolled_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz,
  -- Revocation is columns, not a table: the record IS the device row, and a
  -- revoked device must keep existing so its historical receipts stay
  -- attributable. revoked_by is the OIDC subject that ordered it.
  revoked_at     timestamptz,
  revoked_by     text,
  revoked_reason text,
  CONSTRAINT ck_m1_devices_hostname_len CHECK (octet_length(hostname_hmac) = 32),
  CONSTRAINT ck_m1_devices_revoked_shape
    CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL)
);

ALTER TABLE m1_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_devices;
CREATE POLICY tenant_isolation ON m1_devices
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- "list this tenant's live devices" is the console's and the revocation
-- sweep's only access pattern.
CREATE INDEX IF NOT EXISTS ix_m1_devices_tenant
  ON m1_devices (tenant_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- (4) m1_device_enrollments — one row per OIDC device-code grant.
-- ---------------------------------------------------------------------------
-- Kept as its own table (not columns on m1_devices) because enrollment is an
-- audit event that can fail, expire, or be denied, and each attempt is a fact
-- worth keeping; a device may re-enroll after revocation and both grants must
-- survive.
CREATE TABLE IF NOT EXISTS m1_device_enrollments (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES m1_tenants(id),
  device_id         uuid REFERENCES m1_devices(id),   -- NULL until approved
  -- Hashes only. The raw device_code and the bearer device token are
  -- credentials; a table that stored them verbatim would be a credential
  -- vault without the vault. SHA-256, length-checked.
  device_code_hash  bytea NOT NULL,
  token_hash        bytea,                            -- set on approval
  -- 05 §3.1/§3.5 abuse case 2: the device's Ed25519 public key is registered
  -- HERE, at /enroll/device/start, BEFORE the user approves, and the eventual
  -- device identity binds to exactly this key. That binding is the whole
  -- defense against a replayed device_code — an attacker replaying the code
  -- gets a device they hold no key for. It cannot live on m1_device_keys
  -- because no device row exists yet at PENDING.
  device_pubkey     bytea NOT NULL,
  oidc_subject      text,                             -- who approved, from the IdP
  status            text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked')),
  started_at        timestamptz NOT NULL DEFAULT now(),
  token_expires_at  timestamptz,
  CONSTRAINT ck_m1_enroll_code_len   CHECK (octet_length(device_code_hash) = 32),
  CONSTRAINT ck_m1_enroll_token_len  CHECK (token_hash IS NULL OR octet_length(token_hash) = 32),
  CONSTRAINT ck_m1_enroll_pubkey_len CHECK (octet_length(device_pubkey) = 32),
  -- The plan's ≤24h token lifetime is a schema fact, not an app promise: a
  -- code path that mints a longer token fails here, loudly, at write time.
  CONSTRAINT ck_m1_enroll_token_ttl
    CHECK (token_expires_at IS NULL OR token_expires_at <= started_at + interval '24 hours'),
  -- An approved grant without a token or a device is not a grant.
  CONSTRAINT ck_m1_enroll_approved_shape
    CHECK (status <> 'approved'
           OR (device_id IS NOT NULL AND token_hash IS NOT NULL
               AND token_expires_at IS NOT NULL AND oidc_subject IS NOT NULL)),
  CONSTRAINT uq_m1_enroll_code UNIQUE (device_code_hash)
);

ALTER TABLE m1_device_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_device_enrollments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_device_enrollments;
CREATE POLICY tenant_isolation ON m1_device_enrollments
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Ingest's per-request auth lookup: token hash -> live grant. Partial, because
-- expired/denied grants are history, not lookups.
CREATE UNIQUE INDEX IF NOT EXISTS ix_m1_enroll_token
  ON m1_device_enrollments (token_hash) WHERE status = 'approved';

-- The daily reconciliation sweep's access pattern: "who approved this live
-- device, and is that subject still at the IdP".
CREATE INDEX IF NOT EXISTS ix_m1_enroll_device
  ON m1_device_enrollments (device_id) WHERE status = 'approved';

-- ---------------------------------------------------------------------------
-- (5) m1_device_keys — the device origin-signing keys, with rotation.
-- ---------------------------------------------------------------------------
-- Rotation NEVER deletes or overwrites: a receipt signed under a key we
-- stopped publishing is a receipt nobody can verify, which is the same as
-- never having issued it (ro_012's rule, adopted verbatim). Rotation inserts
-- the new key and stamps superseded_at on the old one; revocation stamps
-- revoked_at. Both old rows remain readable forever.
CREATE TABLE IF NOT EXISTS m1_device_keys (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id),
  device_id      uuid NOT NULL REFERENCES m1_devices(id),
  -- "ed25519:" + first 16 hex of SHA-256(pubkey) — derived, so key_id and
  -- public_key cannot disagree; the receipt table joins on this.
  key_id         text NOT NULL,
  key_algorithm  text NOT NULL DEFAULT 'ed25519' CHECK (key_algorithm = 'ed25519'),
  public_key     bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  superseded_at  timestamptz,       -- set by rotation; the successor row exists
  revoked_at     timestamptz,       -- set on compromise; verification of PAST
                                    -- receipts still uses the key, but nothing
                                    -- new signed under it is accepted
  revoked_reason text,
  CONSTRAINT ck_m1_dkeys_pub_len CHECK (octet_length(public_key) = 32),
  CONSTRAINT uq_m1_dkeys_key_id  UNIQUE (key_id)
);

ALTER TABLE m1_device_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_device_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_device_keys;
CREATE POLICY tenant_isolation ON m1_device_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Exactly one live key per device: rotation is an ordered handover, not a
-- pool. Enforced structurally so a racing double-rotation cannot leave two.
CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_dkeys_live
  ON m1_device_keys (device_id)
  WHERE superseded_at IS NULL AND revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- (6) m1_device_credential_fingerprints — the proxy guard's server anchor.
-- ---------------------------------------------------------------------------
-- 05 §3.6: the OAuth-non-interception guard forwards only credentials named by
-- an M1-Cred-Ref that mark1d provisioned after Detect()==apikey, HMAC-
-- fingerprint-matched to enrollment. The match is edge-local; this table is
-- the authoritative set the edge re-verifies against after a restart, and it
-- is what makes "revoking a device orphans its fingerprints" true — a revoked
-- device's proxy has no valid provision set and therefore forwards nothing.
-- fingerprint = HMAC-SHA256(k_device, credential_bytes): keyed by the device
-- key, so it reveals nothing about the credential and does not correlate
-- across devices. De-provisioning stamps revoked_at; rows are never deleted,
-- because "what could this device forward, when" is an audit question.
CREATE TABLE IF NOT EXISTS m1_device_credential_fingerprints (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES m1_tenants(id),
  device_id      uuid NOT NULL REFERENCES m1_devices(id),
  fingerprint    bytea NOT NULL,
  -- 'anthropic' | 'openai' | ... — the upstream class the credential is for,
  -- so a fingerprint cannot be honoured against the wrong destination.
  upstream_class text NOT NULL,
  provisioned_at timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  CONSTRAINT ck_m1_fp_len CHECK (octet_length(fingerprint) = 32)
);

ALTER TABLE m1_device_credential_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE m1_device_credential_fingerprints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON m1_device_credential_fingerprints;
CREATE POLICY tenant_isolation ON m1_device_credential_fingerprints
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- One live fingerprint per (device, upstream class, value); re-provisioning
-- the same credential must not silently double the authoritative set.
CREATE UNIQUE INDEX IF NOT EXISTS uq_m1_fp_live
  ON m1_device_credential_fingerprints (device_id, upstream_class, fingerprint)
  WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- (7) Grants. controld owns enrollment and revocation (UPDATEs, no DELETEs);
-- the intelligence services only ever read identity.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT, INSERT, UPDATE ON m1_organizations, m1_tenants, m1_devices,
                                    m1_device_enrollments, m1_device_keys,
                                    m1_device_credential_fingerprints
      TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adjudicator_app') THEN
    GRANT SELECT ON m1_tenants, m1_devices, m1_device_keys TO adjudicator_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT ON m1_organizations, m1_tenants, m1_devices, m1_device_keys
      TO intel_app;  -- the federation gate reads org verification state
  END IF;
END $$;

REVOKE DELETE, TRUNCATE ON m1_organizations, m1_tenants, m1_devices,
                           m1_device_enrollments, m1_device_keys,
                           m1_device_credential_fingerprints
  FROM PUBLIC;

COMMIT;

-- ROLLBACK (run manually if needed; destroys the identity registry, and with
-- it the ability to attribute any existing receipt to a device):
-- BEGIN;
--   DROP TABLE IF EXISTS m1_device_credential_fingerprints CASCADE;
--   DROP TABLE IF EXISTS m1_device_keys CASCADE;
--   DROP TABLE IF EXISTS m1_device_enrollments CASCADE;
--   DROP TABLE IF EXISTS m1_devices CASCADE;
--   DROP TABLE IF EXISTS m1_tenants CASCADE;
--   DROP TABLE IF EXISTS m1_organizations CASCADE;
-- COMMIT;
