-- m1_042_policy_bundles.sql
-- The bundle catalog + per-(tenant,channel) heads + the device ACK ledger.
-- PolicyBundle v1 bodies are canonical CBOR, signed section-split, carrying
-- NO command strings and NO code (decode-time rejection at the edge); this
-- schema stores, sequences and proves them -- it never interprets them.
--
-- The edge's anti-rollback check (monotonic seq, mark1-policy crate) is only as
-- good as the server's promise never to mint a regression. That promise is a
-- table shape: the catalog is append-only, the per-(tenant,channel) head is a
-- locked row (the receipt_chain_head pattern from ro_012, reused because it
-- already survived production), and the publishing trigger admits exactly
-- head_seq + 1. A regression or a gap is not a bug to detect -- it is an INSERT
-- that cannot commit.
--
-- NAMING NOTE: tenancy/device FKs name m1_tenants / m1_devices, the tables that
-- m1_001_tenancy_devices.sql actually creates. See the same note in m1_040.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE TABLE IF NOT EXISTS policy_bundles (
  tenant_id     uuid NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  -- 'canary' | 'stable' | agent-specific channels. text, not enum: adding a
  -- channel is a rollout decision, not a schema migration.
  channel       text NOT NULL,
  seq           bigint NOT NULL CHECK (seq >= 1),   -- 1-based; the head row's 0 means "nothing published yet"
  -- The exact signed bytes. bytea, not jsonb-of-decoded-CBOR: the edge verifies
  -- a signature over BYTES, and storing anything but those bytes invites a
  -- canonicalization mismatch between what we signed and what we serve.
  body_cbor     bytea NOT NULL,
  body_sha256   bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
  prev_hash     bytea NOT NULL CHECK (octet_length(prev_hash) = 32),  -- chains to seq-1's body_sha256; genesis chains to 32 zero bytes
  max_age       interval NOT NULL,                  -- past this, a fail-static edge falls to conservative built-in defaults
  -- Section-split signatures: one per bundle section so a verify-only key
  -- cannot sign routes. jsonb {section: {sig, key_id}} because the section set
  -- is the bundle format's to grow, not this table's.
  signatures    jsonb NOT NULL,
  signing_key_id text NOT NULL,                     -- the primary key id, denormalized for rotation queries
  -- Transparency-log inclusion: the log's index plus the audit path the edge
  -- verifies. NOT NULL both -- an unlogged bundle must be unpublishable, because
  -- a bundle outside the log is invisible to split-view detection.
  tlog_index    bigint NOT NULL CHECK (tlog_index >= 0),
  tlog_proof    jsonb  NOT NULL,
  published_at  timestamptz NOT NULL DEFAULT now(),
  receipt_id    uuid NOT NULL,                      -- bundle publication is per-event receipted (C13)
  PRIMARY KEY (tenant_id, channel, seq)             -- THE uniqueness that makes one (tenant,channel,seq) mean one bundle forever
);

-- The head: one locked row per (tenant, channel) -- ro_012's chain-head pattern.
-- Not a sequence: a sequence survives rollback (gaps) and cannot be read
-- transactionally with the row it guards.
CREATE TABLE IF NOT EXISTS bundle_channel_heads (
  tenant_id  uuid   NOT NULL REFERENCES m1_tenants(id) ON DELETE RESTRICT,
  channel    text   NOT NULL,
  head_seq   bigint NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
  head_hash  bytea  NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
             CHECK (octet_length(head_hash) = 32),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, channel)
);

-- THE CONSTRAINT THAT MAKES A SEQ REGRESSION IMPOSSIBLE. FOR UPDATE serializes
-- publishers per channel; NEW.seq must be exactly head+1 (no regressions AND no
-- gaps -- a gap is a regression the edge cannot distinguish from censorship);
-- prev_hash must chain to the recorded head. The head row advances in the same
-- transaction, so there is no window in which two publishers both see head N.
-- Monotonicity is therefore a database fact, never a writer's discipline.
-- (FOR UPDATE is legitimate here, unlike in the epsilon gate: the publisher
-- role holds UPDATE on this table because advancing the head IS its job. See
-- the SEC-04 note in m1_041 for the case where it is not.)
CREATE OR REPLACE FUNCTION trg_bundle_seq_monotonic() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE h bundle_channel_heads;
BEGIN
  INSERT INTO bundle_channel_heads (tenant_id, channel)
       VALUES (NEW.tenant_id, NEW.channel)
  ON CONFLICT (tenant_id, channel) DO NOTHING;          -- first publish creates the head at 0
  SELECT * INTO h FROM bundle_channel_heads
   WHERE tenant_id = NEW.tenant_id AND channel = NEW.channel FOR UPDATE;
  -- No head row visible (RLS, or a deleted head) leaves h NULL, and every
  -- comparison below then evaluates NULL and takes the FALSE branch -- the gate
  -- would admit an arbitrary seq with no chain check at all.
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bundle head for (%,%) is not visible: publish refused', NEW.tenant_id, NEW.channel
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.seq <> h.head_seq + 1 THEN
    RAISE EXCEPTION 'bundle seq must be % for (%,%), got % -- regressions and gaps are unrepresentable',
      h.head_seq + 1, NEW.tenant_id, NEW.channel, NEW.seq USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.prev_hash <> h.head_hash THEN
    RAISE EXCEPTION 'bundle prev_hash does not chain to head for (%,%)', NEW.tenant_id, NEW.channel
      USING ERRCODE = 'check_violation';
  END IF;
  UPDATE bundle_channel_heads
     SET head_seq = NEW.seq, head_hash = NEW.body_sha256, updated_at = now()
   WHERE tenant_id = NEW.tenant_id AND channel = NEW.channel;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS bundle_seq_monotonic ON policy_bundles;
CREATE TRIGGER bundle_seq_monotonic
  BEFORE INSERT ON policy_bundles
  FOR EACH ROW EXECUTE FUNCTION trg_bundle_seq_monotonic();

-- Published bundles are immutable evidence: append-only three ways, like ro_012.
CREATE OR REPLACE FUNCTION trg_bundles_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'policy_bundles is append-only: a bad bundle is superseded by seq+1, never edited'
    USING ERRCODE = 'check_violation';
END $$;
DROP TRIGGER IF EXISTS bundles_no_update_delete ON policy_bundles;
CREATE TRIGGER bundles_no_update_delete
  BEFORE UPDATE OR DELETE ON policy_bundles
  FOR EACH ROW EXECUTE FUNCTION trg_bundles_append_only();
-- Way three. Row triggers do not fire on TRUNCATE and the REVOKE does not bind
-- the owner, so this is the only layer standing between `TRUNCATE policy_bundles`
-- and a bundle_channel_heads row chaining to bundles that no longer exist.
DROP TRIGGER IF EXISTS bundles_no_truncate ON policy_bundles;
CREATE TRIGGER bundles_no_truncate
  BEFORE TRUNCATE ON policy_bundles
  FOR EACH STATEMENT EXECUTE FUNCTION trg_bundles_append_only();
REVOKE UPDATE, DELETE, TRUNCATE ON policy_bundles FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- (2) The ACK ledger: which device verified-and-activated which seq. One row
-- per (device, channel, seq) -- a device re-ACKing after restart upserts, never
-- double-counts.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bundle_acks (
  tenant_id   uuid NOT NULL,
  channel     text NOT NULL,
  seq         bigint NOT NULL,
  device_id   uuid NOT NULL REFERENCES m1_devices(id) ON DELETE RESTRICT,  -- ACK history proves what a revoked device was running
  acked_at    timestamptz NOT NULL DEFAULT now(),
  -- 08 §3.2's vocabulary VERBATIM. A failed verify is an ACK too -- silence and
  -- refusal must be distinguishable to the canary -- but the distinction this
  -- column used to draw itself ('verified_active' | 'verify_failed' |
  -- 'stale_rejected') is now `reject_code`, which is strictly more expressive:
  -- M1E-3001/3003/3005 are the verify failures and M1E-3002 is the stale one,
  -- while 'partial' had no representation in the old vocabulary at all. Two
  -- vocabularies would need a mapping, and 05 §4.2 assigns the ACK contract to
  -- 08 -- so the ledger stores 08's, and there is nothing left to map.
  result           text NOT NULL,
  -- BundleAck.bundle_hash: 32 raw bytes, SHA-256 over the bundle's canonical
  -- bytes (05 §4.4), comparable to policy_bundles.body_sha256. Stored, not
  -- discarded, because an ACK claiming a seq whose body it never saw is only
  -- detectable against the hash it reports.
  bundle_hash      bytea NOT NULL,
  -- 08 §10.3 skip-and-retain. 05 §4.3(b) counts `partial` off THIS column, so
  -- it is a rollout-control input, not diagnostics.
  sections_skipped text[] NOT NULL DEFAULT '{}',
  -- 08 §9 policy error codes. NULL unless result = 'rejected'. 05 §4.3(a) halts
  -- an entire rollout on a single 'M1E-3005' -- a command string that reached an
  -- edge decoder -- which is why it is a column and not a log line.
  reject_code      text,
  -- 05 §4.3: "the ledger row adds device_id, edge_version, acked_at". A section
  -- skipped by one build and applied by the next is a version story, not a
  -- bundle story, and without this column the two are indistinguishable.
  edge_version     text NOT NULL,
  PRIMARY KEY (tenant_id, channel, device_id, seq),
  FOREIGN KEY (tenant_id, channel, seq) REFERENCES policy_bundles (tenant_id, channel, seq) ON DELETE RESTRICT, -- an ACK of a nonexistent bundle is an attack signal, not a row
  CONSTRAINT bundle_acks_hash_len CHECK (octet_length(bundle_hash) = 32),
  CONSTRAINT bundle_acks_result   CHECK (result IN ('applied', 'rejected', 'partial')),
  -- Each result asserts the presence or absence of its own evidence. Without
  -- this, an 'applied' row carrying a reject_code and a 'partial' row skipping
  -- nothing both store cleanly, and 05 §4.3's halt arithmetic counts them.
  CONSTRAINT bundle_acks_result_evidence CHECK (
    CASE result
      WHEN 'applied'  THEN reject_code IS NULL     AND cardinality(sections_skipped) = 0
      WHEN 'rejected' THEN reject_code IS NOT NULL AND cardinality(sections_skipped) = 0
      WHEN 'partial'  THEN reject_code IS NULL     AND cardinality(sections_skipped) > 0
    END
  ),
  -- Fail-closed second layer beneath ingest's own vocabulary check on
  -- BundleAck.sections_skipped: a typo'd or attacker-chosen section name cannot
  -- perturb the >20% halt denominator, because it cannot be stored. The six are
  -- the PolicyBundle sections, fixed by 07's CDDL.
  CONSTRAINT bundle_acks_sections_known CHECK (
    sections_skipped <@ ARRAY['verify','route','memory','cortex','gates','agent_maps']::text[]
  )
);

CREATE INDEX IF NOT EXISTS ix_acks_rollout ON bundle_acks (tenant_id, channel, seq, result);

-- The 05 §4.3(a) tripwire: "one occurrence is one too many", evaluated every
-- 5-minute tick across every tenant. A partial index makes that scan cost
-- proportional to the number of hits, which in a healthy fleet is zero.
CREATE INDEX IF NOT EXISTS ix_acks_command_string ON bundle_acks (tenant_id, channel, seq)
  WHERE reject_code = 'M1E-3005';

-- THE CANARY QUERY. policy-dist promotes canary -> stable on this and nothing
-- else. Denominator = devices seen in 24h (a dark device can't ACK and must not
-- count against the rollout); numerator = distinct devices whose LATEST ack on
-- the channel is the head AND applied. Promotion rule in controld (05 §4.3
-- step 2): head_ratio >= 0.9 AND rejected = 0, sustained for the soak window.
-- `partial` is deliberately absent from the numerator: 05 §4.3(b) makes a
-- skipped section count as NON-adoption, so a partial ACK must not widen a
-- rollout even though it is a successful verify.
--
--   WITH latest AS (
--     SELECT DISTINCT ON (a.device_id) a.device_id, a.seq, a.result
--       FROM bundle_acks a
--      WHERE a.tenant_id = $1 AND a.channel = 'canary'
--      ORDER BY a.device_id, a.acked_at DESC
--   )
--   SELECT h.head_seq,
--          count(d.id)                                                            AS active_devices,
--          count(l.device_id) FILTER (WHERE l.seq = h.head_seq
--                                       AND l.result = 'applied')                 AS on_head,
--          count(l.device_id) FILTER (WHERE l.result = 'rejected')                AS rejected,
--          count(l.device_id) FILTER (WHERE l.result = 'partial')                 AS partial,
--          round(count(l.device_id) FILTER (WHERE l.seq = h.head_seq
--                                       AND l.result = 'applied')::numeric
--                / nullif(count(d.id), 0), 4)                                     AS head_ratio
--     FROM bundle_channel_heads h
--     JOIN m1_devices d ON d.tenant_id = h.tenant_id
--                      AND d.revoked_at IS NULL
--                      AND d.last_seen_at > now() - interval '24 hours'
--     LEFT JOIN latest l ON l.device_id = d.id
--    WHERE h.tenant_id = $1 AND h.channel = 'canary'
--    GROUP BY h.head_seq;

-- RLS: canonical form on all three; bundles and acks take writes.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['policy_bundles','bundle_channel_heads','bundle_acks'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
  END LOOP;
END $$;

DO $$
BEGIN
  -- controld.policy-dist serves and ACKs under the request tenant's GUC;
  -- intel's policy-compiler publishes the same way. Nobody gets UPDATE/DELETE
  -- on the catalog -- the append-only REVOKE above outranks these.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'controld_app') THEN
    GRANT SELECT ON policy_bundles, bundle_channel_heads TO controld_app;
    GRANT SELECT, INSERT ON bundle_acks TO controld_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'intel_app') THEN
    GRANT SELECT, INSERT ON policy_bundles TO intel_app;
    GRANT SELECT, INSERT, UPDATE ON bundle_channel_heads TO intel_app;  -- UPDATE: the head advance inside the publish trigger
  END IF;
END $$;

COMMIT;

-- ROLLBACK (run manually if needed):
-- BEGIN;
--   DROP TABLE IF EXISTS bundle_acks;
--   DROP TRIGGER IF EXISTS bundles_no_truncate ON policy_bundles;
--   DROP TRIGGER IF EXISTS bundles_no_update_delete ON policy_bundles;
--   DROP TRIGGER IF EXISTS bundle_seq_monotonic ON policy_bundles;
--   DROP FUNCTION IF EXISTS trg_bundles_append_only();
--   DROP FUNCTION IF EXISTS trg_bundle_seq_monotonic();
--   DROP TABLE IF EXISTS policy_bundles;
--   DROP TABLE IF EXISTS bundle_channel_heads;
-- COMMIT;
