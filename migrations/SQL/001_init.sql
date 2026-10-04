-- ============================================================================
-- Zero-Knowledge Password Manager — Initial Schema
-- Database: PostgreSQL 15+
-- ============================================================================
--
-- COLUMN JUSTIFICATION:
--
-- Every column in this schema is justified below. The principle: store only
-- what the server MUST store to (a) authenticate the user and (b) return
-- encrypted blobs the client cannot decrypt without the master password.
--
-- COLUMNS THE SERVER MUST NEVER STORE:
--   - Master password (MP) — never transmitted, never stored.
--   - Master Key (MK) — derived client-side, never leaves the client.
--   - Vault Key (VK) in plaintext — only stored wrapped (encrypted under MK).
--   - Any plaintext vault entry content.
--   - The authKey / auth_verifier in a form that can be replayed without
--     the master password (SRP eliminates this; the Argon2id-verifier
--     fallback accepts this trade-off, mitigated by rate limiting).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- users — one row per registered account
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  -- Opaque identifier. UUIDv4 prevents enumeration via sequential IDs.
  user_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Email used as the login identifier. Stored as-is (not hashed) because
  -- the server needs to look it up during login. The email is NOT secret
  -- (it's on business cards, etc.), but we never reveal whether it exists
  -- in responses (generic "invalid credentials" everywhere).
  email         VARCHAR(255) UNIQUE NOT NULL,

  -- Random 32-byte salt for the MASTER KEY derivation (client-side Argon2id).
  -- Stored so the client can re-derive MK on subsequent logins.
  -- NOT secret — salts are public per Kerckhoffs's principle.
  salt_enc      BYTEA       NOT NULL,

  -- Random 32-byte salt for the AUTH KEY derivation (client-side Argon2id).
  -- Independent from salt_enc so that compromising the auth path does not
  -- help derive the encryption path, and vice versa.
  salt_auth     BYTEA       NOT NULL,

  -- The 32-byte auth verifier produced by the client's deriveAuthKey():
  --   authKey = SHA-256(Argon2id(MP, salt_auth || "zkm-auth-key-v1"))
  -- The server stores this and compares (constant-time) on login.
  -- WARNING — This field is a password-equivalent for the auth path.
  --   An attacker who steals this AND bypasses rate-limiting can authenticate.
  --   The Argon2id cost (256 MiB / 4 rounds in production) makes offline
  --   brute-force expensive. Rate limiting + account lockout protect online.
  --   SRP-6a (planned upgrade) eliminates this property entirely.
  auth_verifier BYTEA       NOT NULL,

  -- The Vault Key wrapped (encrypted) under the Master Key using AES-256-GCM.
  -- Three components stored separately for explicit schema clarity:
  wrapped_vk      BYTEA     NOT NULL,  -- ciphertext (32 bytes for 256-bit VK)
  wrapped_vk_iv   BYTEA     NOT NULL,  -- 12-byte random GCM nonce
  wrapped_vk_tag  BYTEA     NOT NULL,  -- 16-byte GCM authentication tag
  -- The server CANNOT unwrap this without MK, which requires MP.

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- vault_entries — encrypted blobs, one per password/note stored by user
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_entries (
  -- Opaque identifier. UUIDv4 prevents enumeration via sequential IDs.
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Foreign key to owning user. CASCADE delete: when a user is removed,
  -- all their vault entries are removed too.
  user_id     UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

  -- AES-256-GCM nonce (12 bytes). Unique per entry per encryption call.
  -- Stored in the clear — nonces are not secret.
  nonce       BYTEA       NOT NULL,

  -- Encrypted vault entry content. The server cannot read this.
  ciphertext  BYTEA       NOT NULL,

  -- GCM authentication tag (16 bytes). Tamper detection.
  auth_tag    BYTEA       NOT NULL,

  -- Category label stored in PLAINTEXT for server-side filtering/search.
  -- Must NEVER contain secret data. E.g. "login", "secure-note", "ssh-key".
  -- This is the ONLY metadata the server can see about an entry's purpose.
  entry_type  VARCHAR(50) NOT NULL,

  -- Monotonically increasing version counter. Client increments on each
  -- update. Used as AAD (Additional Authenticated Data) in AES-GCM to
  -- prevent ciphertext transplantation between versions.
  version     INTEGER     NOT NULL DEFAULT 1,

  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- auth_sessions — server-side session records (optional; JWT is stateless)
-- ---------------------------------------------------------------------------
-- We store session records for the ability to revoke sessions server-side
-- (e.g. on password change, on detected compromise). The JWT itself is
-- self-contained; this table is the revocation list.
CREATE TABLE IF NOT EXISTS auth_sessions (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

  -- SHA-256 hash of the JWT token. We never store the raw token.
  -- The raw token exists only in the client's Authorization header.
  token_hash    BYTEA       NOT NULL,

  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- audit_log — immutable append-only security event log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        REFERENCES users(user_id) ON DELETE SET NULL,

  -- Event classification. Controlled vocabulary enforced at application layer.
  event_type  VARCHAR(50) NOT NULL,

  -- Client IP. Truncated to 45 chars to accommodate IPv6 (::ffff:...).
  ip_address  VARCHAR(45),

  -- Raw User-Agent string for forensic correlation.
  user_agent  TEXT,

  -- Free-form JSONB for event-specific context.
  -- LINT-CHECK ENFORCEMENT (see audit.ts):
  --   This field MUST NEVER contain any of:
  --     password, secret, key, authKey, masterKey, vaultKey,
  --     wrappedVk, plaintext, credential, token (raw value)
  --   Use code review + ESLint rule to enforce at development time.
  details     JSONB,

  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
-- Vault entries: lookup by owner is the dominant query pattern.
CREATE INDEX IF NOT EXISTS idx_vault_entries_user_id    ON vault_entries(user_id);

-- Sessions: lookup by owner (for revocation) and by token hash (for auth).
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id    ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions(token_hash);

-- Audit: time-range queries for incident investigation, user-specific queries.
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
