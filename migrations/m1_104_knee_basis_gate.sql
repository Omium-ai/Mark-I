-- m1_104_knee_basis_gate.sql
-- ADR-0013 §8: no edge may ever be handed a bundle it cannot decode. An edge that decodes the
-- optional route.knee.basis says so on every bundle poll (X-Mark1-Bundle-Features: knee_basis);
-- m1_devices.bundle_features keeps the latest word per device, and controld publishes a bundle WITH
-- the key only when no non-revoked device of the tenant is known not to decode it — and never serves
-- a head carrying it to a poll that did not advertise it (the head is republished without it first). policy_bundles records both
-- halves of that decision: knee_basis_intended (what the producer stamped — the bootstrap's prior,
-- the compiler's certified; NULL on rows published before this migration) and knee_basis (what the
-- signed bytes carry; NULL when withheld), so a later fleet change republishes the head with the
-- key added or withheld, never guessing the producer's word.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_devices ADD COLUMN IF NOT EXISTS bundle_features text[];
-- NULL = a device that has not polled since it enrolled (nothing known against it); '{}' = one that
-- polled and advertised nothing. Every device enrolled before this migration runs is an edge that
-- predates the key, so it is marked known-old here; a re-run only re-marks devices that never
-- polled, which withholds the key until their first poll — the safe direction.
UPDATE m1_devices SET bundle_features = '{}' WHERE bundle_features IS NULL;

ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS knee_basis_intended text
  CHECK (knee_basis_intended IN ('prior', 'anchor_grounded', 'certified'));
ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS knee_basis text
  CHECK (knee_basis IN ('prior', 'anchor_grounded', 'certified'));

COMMIT;

-- ROLLBACK (run manually if needed; every bundle is then published without the key):
-- BEGIN;
--   ALTER TABLE policy_bundles DROP COLUMN IF EXISTS knee_basis;
--   ALTER TABLE policy_bundles DROP COLUMN IF EXISTS knee_basis_intended;
--   ALTER TABLE m1_devices DROP COLUMN IF EXISTS bundle_features;
-- COMMIT;
