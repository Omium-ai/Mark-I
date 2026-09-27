-- m1_102_digest_sent_figure.sql
-- ADR-0013 §late verdicts: a sent weekly digest is the one savings figure that cannot be restated in
-- place — the email is gone. The send ledger therefore keeps the tokens-saved figure it mailed, so the
-- next week's digest can recompute that week through today and, when a verdict that landed after the
-- email moved it, say so on its own line ("restated: X, was Y") instead of letting the two emails
-- silently disagree. NULL on rows sent before this column existed: nothing to restate against.
--
-- Idempotent + re-runnable, house style, safe under ON_ERROR_STOP=1.

BEGIN;

ALTER TABLE m1_notification_sends ADD COLUMN IF NOT EXISTS tokens_saved bigint;

COMMIT;

-- ROLLBACK (run manually if needed; digests then stop restating the previous week):
-- BEGIN;
--   ALTER TABLE m1_notification_sends DROP COLUMN IF EXISTS tokens_saved;
-- COMMIT;
