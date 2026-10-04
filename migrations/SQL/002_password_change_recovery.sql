-- ============================================================================
-- Migration 002: Password Change + Account Recovery
-- ============================================================================
--
-- PASSWORD CHANGE:
--   Reuses the EXISTING vault key (VK) — only re-wraps it under a new
--   master key derived from the new password. Vault entries are NOT
--   re-encrypted. This is the key hierarchy advantage from Prompt 0.
--
--   FRESH SALTS justification:
--     When the password changes, NEW salts are generated for both the master
--     key and auth key derivations. Rationale:
--     1. The OLD salts are on the compromised server. If we reused them, an
--        attacker who captures the new auth_verifier can run an offline
--        brute-force attack against the new password using the known old
--        salts. With fresh salts, any precomputed tables are useless.
--     2. The old salts+verifier pair is invalidated on the server atomically
--        with the new one being written, so there's no window where both are
--        valid.
--     3. Argon2id's memory-hardness makes each new derivation ~$1-5 of GPU
--        time in production (256 MiB / 4 rounds). The marginal cost of
--        fresh salts is zero — it's the same computation that already
--         happens on every login.
--
-- ACCOUNT RECOVERY:
--   Recovery is implemented via a client-generated 128-bit recovery code
--   that wraps a copy of the vault key. The server stores the wrapped blob;
--   the code itself is shown to the user ONCE and never transmitted again.
--
--   TRADE-OFF (explicit, for the UI copy):
--     - TRUE ZERO-KNOWLEDGE (option B in the spec): the server cannot reset
--       a forgotten password. A lost master password = permanently
--       inaccessible vault. This is the strongest security guarantee.
--     - RECOVERY CODE (option A, implemented here): the user trades some
--       security surface (a second path to the vault key) for recoverability.
--       The 128-bit code offline means an attacker must physically steal it.
--       A compromised server CANNOT recover the vault without the code.
--
--   The recovery columns store the vaultKey re-wrapped under
--   SHA-256(recovery_code || "zkm-recovery-key-v1"). This blob is useless
--   without the code, so the server breach does not compromise recovery.
-- ============================================================================

-- Password change: no new columns needed — the existing salt_enc, salt_auth,
-- auth_verifier, wrapped_vk, wrapped_vk_iv, wrapped_vk_tag columns are
-- updated in-place. See PUT /auth/password route.

-- Account recovery: three new nullable columns on users.
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk      BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk_iv   BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk_tag  BYTEA;

-- Comment on new columns for documentation.
COMMENT ON COLUMN users.recovery_wrapped_vk IS
  'Vault key re-wrapped under SHA-256(recovery_code || domain_sep). NULL = no recovery option. Useless without the 128-bit code.';
COMMENT ON COLUMN users.recovery_wrapped_vk_iv IS
  'GCM nonce for the recovery wrap. 12 bytes.';
COMMENT ON COLUMN users.recovery_wrapped_vk_tag IS
  'GCM auth tag for the recovery wrap. 16 bytes.';
