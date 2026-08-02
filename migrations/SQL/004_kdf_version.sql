-- ============================================================================
-- Migration 004: KDF Parameter Versioning
-- ============================================================================
--
-- Adds kdf_version to users so the client knows which Argon2id parameter set
-- was used to derive the account's auth verifier (and master key / wrapped
-- vault key). The parameters themselves live ONLY in the client
-- (src/crypto/constants.ts) — the server merely stores and returns the number.
--
-- Existing accounts default to version 1 (the original parameter set).
-- New registrations send the version they used (the current version).
-- PUT /auth/kdf-upgrade bumps an account to a newer version by re-deriving
-- the auth key and re-wrapping the (unchanged) vault key under the new
-- master-key parameters, all client-side.
-- ============================================================================

ALTER TABLE users ADD COLUMN kdf_version INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN users.kdf_version IS
  'Argon2id parameter-table version this account was derived with. Returned by login step 1; bumped by password change / recovery / PUT /auth/kdf-upgrade.';
