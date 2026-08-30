-- m1_061_device_edge_version.sql
-- m1_devices gains edge_version: 08 §3.1 lists it in every GET /enroll/devices
-- row, but m1_001 never created the column — the handler served a JSON null
-- and the contradiction sat in the build report. This closes it.
--
-- The value is the semver mark1d announces in X-Mark1-Edge-Version (08 §10.1:
-- every edge request carries it; the server RECORDS it for fleet visibility
-- and never hard-rejects on it — rejection authority belongs to the schema
-- axis, M1P-Schema). It is stamped by ingest stage 11 alongside last_seen_at
-- (sidefx.ApplyLastSeen) with the same idempotent posture: replay stamps
-- nothing (the header died with the original request), live traffic is
-- last-write-wins. Nullable text, no CHECK: a device that has never ingested
-- has no known version, and version strings drift like platform strings do
-- (m1_001's own rationale for free-text platform).
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_devices ADD COLUMN IF NOT EXISTS edge_version text;

COMMIT;

-- ROLLBACK (run manually if needed; loses only derived fleet telemetry —
-- the next ingest per device re-stamps it):
-- BEGIN;
--   ALTER TABLE m1_devices DROP COLUMN IF EXISTS edge_version;
-- COMMIT;
