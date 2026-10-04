-- Migration 003: TOTP-based 2FA support
--
-- ADDS:
--   1. TOTP secret + enabled flag on users table
--   2. Backup codes table (one-time-use recovery codes)
--
-- DESIGN DECISIONS:
--   - TOTP secret is stored via APPLICATION-LEVEL ENVELOPE ENCRYPTION
--     (AES-256-GCM under TOTP_ENCRYPTION_KEY from server env vars), split
--     across three columns: totp_secret_enc (ciphertext), totp_secret_iv
--     (12-byte GCM nonce), totp_secret_tag (16-byte auth tag). This provides
--     defense-in-depth: a database compromise alone does not expose the
--     TOTP secrets. NEVER stored in plaintext logs or returned in API
--     responses after setup. All NULL = 2FA not set up.
--
--   - totp_enabled: BOOLEAN flag. 2FA setup has two phases:
--     (a) setup: generates secret + shows QR → totp_enabled = false
--     (b) enable: user verifies a code → totp_enabled = true
--     This prevents a user from being locked out by a failed setup.
--
--   - backup_codes: separate table (not JSONB on users) because:
--     (a) individual codes can be marked as used independently
--     (b) proper indexing for lookup by code hash
--     (c) follows relational normalization
--
--   - code_hash: SHA-256 of the backup code with domain separator.
--     Fast to compute (backup codes are high-entropy + rate-limited,
--     so Argon2id is unnecessary overhead).
--
--   - used: BOOLEAN flag. After successful verification, mark as true.
--     One-time use: prevents replay if backup code is intercepted.
--
-- COLUMN JUSTIFICATIONS:
--   totp_secret_enc / totp_secret_iv / totp_secret_tag BYTEA:
--     - Envelope-encrypted TOTP secret (20 bytes / 160 bits per RFC 4226).
--     - AES-256-GCM ciphertext + 12-byte nonce + 16-byte tag, keyed by
--       TOTP_ENCRYPTION_KEY (32 bytes, hex) from server env.
--     - Split across three columns for explicit schema clarity.
--
--   totp_enabled BOOLEAN DEFAULT false:
--     - Two-phase setup: generate → verify → enable.
--     - False by default: user must explicitly enable after setup.
--
--   backup_codes.id UUID:
--     - Primary key for individual code records.
--     - UUID v4 prevents enumeration of backup code IDs.
--
--   backup_codes.code_hash VARCHAR(64):
--     - SHA-256 hex output is exactly 64 characters.
--     - Indexed for efficient lookup during verification.
--
--   backup_codes.used BOOLEAN DEFAULT false:
--     - Set to true after successful use.
--     - Cannot be reset without regenerating all backup codes.
--
--   backup_codes.created_at TIMESTAMPTZ:
--     - Audit trail: when was this set of backup codes generated?
--     - Used for cleanup policies (e.g., expire codes after 1 year).

-- 1. Add TOTP columns to users (envelope-encrypted secret, 3 columns)
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS totp_secret_enc  BYTEA,
  ADD COLUMN IF NOT EXISTS totp_secret_iv   BYTEA,
  ADD COLUMN IF NOT EXISTS totp_secret_tag  BYTEA,
  ADD COLUMN IF NOT EXISTS totp_enabled     BOOLEAN NOT NULL DEFAULT false;

-- 2. Create backup_codes table
CREATE TABLE IF NOT EXISTS backup_codes (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  code_hash   VARCHAR(64) NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id ON backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_backup_codes_code_hash ON backup_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user_used ON backup_codes(user_id, used);
