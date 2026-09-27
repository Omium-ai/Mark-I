-- m1_103_rm_execution_hash.sql
-- 16 §L6: a reward model's execution identity is rm-exec/v1, one recipe on the device, in the export and in
-- the seal: BLAKE3-256(GGUF bytes || 0x00 || 'llama.cpp b<build>' || 0x00 || template_sha hex). The export
-- writes it into manifest.json as `execution_hash`; publish copies it into the sealed artifact as
-- `artifact.execution_hash` and into effective_execution_hash, which a client-side RmScore must equal to vote.
-- Supersedes m1_098's `artifact.execution_sha256` (a sha256 over calibration/gguf/template that no device can
-- compute); nothing has been sealed under it.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

CREATE OR REPLACE FUNCTION m1_verifier_immutable()
RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - 'retired_at') IS DISTINCT FROM (to_jsonb(OLD) - 'retired_at') THEN
    IF OLD.kind = 'reward_model'
       AND OLD.definition #>> '{artifact,status}' = 'pending'
       AND NEW.definition #>> '{artifact,status}' = 'sealed'
       AND (NEW.definition - 'artifact') = (OLD.definition - 'artifact')
       AND (to_jsonb(NEW) - 'retired_at' - 'definition' - 'effective_execution_hash')
           = (to_jsonb(OLD) - 'retired_at' - 'definition' - 'effective_execution_hash')
       AND OLD.effective_execution_hash IS NULL
       AND NEW.effective_execution_hash IS NOT NULL
       AND NEW.definition #>> '{artifact,execution_hash}' ~ '^[0-9a-f]{64}$'
       AND NEW.effective_execution_hash = decode(NEW.definition #>> '{artifact,execution_hash}', 'hex')
    THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION
      'm1_verifiers rows are immutable except retired_at (and one pending->sealed RM artifact); publish a new version'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;

-- ROLLBACK (manual): re-create m1_verifier_immutable() from m1_098 (the execution_sha256 form).
