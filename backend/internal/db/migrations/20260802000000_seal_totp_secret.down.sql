-- Reverses the sealed-secret migration. Note what this cannot do: sealed
-- secrets are not recoverable here, because the master key that would open them
-- lives in internal/custody and never reaches Postgres. Rolling back therefore
-- restores the *column*, not the enrollments — every device must re-enroll, and
-- the ever-enrolled count resets to zero.
--
-- That reset reopens the token-enrollment gate (see the up migration's guard for
-- why that matters). Rolling back is an operator decision to be made with that
-- in mind, not a routine undo.
ALTER TABLE reviewer_tokens DROP COLUMN totp_secret_enc;
ALTER TABLE reviewer_tokens ADD COLUMN totp_secret TEXT;

DROP TABLE data_keys;
