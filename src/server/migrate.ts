/**
 * Database schema migration helper.
 *
 * Runs all initial DDL migrations using Prisma's connection pool.
 * All statements are written with IF NOT EXISTS to be strictly idempotent:
 * they run safely on fresh databases (creating all tables and indexes)
 * and no-op safely when redeploying or restarting against existing databases.
 */

import { prisma } from "./db.js";

export async function runMigrations(): Promise<void> {
  console.log("[zkm] Checking and updating database schema…");

  try {
    // 001_init.sql
    await prisma.$executeRawUnsafe(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS users (
        user_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        email         VARCHAR(255) UNIQUE NOT NULL,
        salt_enc      BYTEA       NOT NULL,
        salt_auth     BYTEA       NOT NULL,
        auth_verifier BYTEA       NOT NULL,
        wrapped_vk      BYTEA     NOT NULL,
        wrapped_vk_iv   BYTEA     NOT NULL,
        wrapped_vk_tag  BYTEA     NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS vault_entries (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        nonce       BYTEA       NOT NULL,
        ciphertext  BYTEA       NOT NULL,
        auth_tag    BYTEA       NOT NULL,
        entry_type  VARCHAR(50) NOT NULL,
        version     INTEGER     NOT NULL DEFAULT 1,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id       UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        token_hash    BYTEA       NOT NULL,
        expires_at    TIMESTAMPTZ NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     UUID        REFERENCES users(user_id) ON DELETE SET NULL,
        event_type  VARCHAR(50) NOT NULL,
        ip_address  VARCHAR(45),
        user_agent  TEXT,
        details     JSONB,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_vault_entries_user_id ON vault_entries(user_id);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions(token_hash);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);`);

    // 002_password_change_recovery.sql
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk BYTEA;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk_iv BYTEA;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_wrapped_vk_tag BYTEA;`);

    // 003_2fa.sql
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc BYTEA;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_iv BYTEA;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_tag BYTEA;`);
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;`);

    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS backup_codes (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        code_hash   VARCHAR(64) NOT NULL,
        used        BOOLEAN NOT NULL DEFAULT false,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_backup_codes_user_id ON backup_codes(user_id);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_backup_codes_code_hash ON backup_codes(code_hash);`);
    await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_backup_codes_user_used ON backup_codes(user_id, used);`);

    // 004_kdf_version.sql
    await prisma.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS kdf_version INTEGER NOT NULL DEFAULT 1;`);

    // 005_sessions.sql
    await prisma.$executeRawUnsafe(`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);`);
    await prisma.$executeRawUnsafe(`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;`);

    console.log("[zkm] Database schema is verified and up-to-date.");
  } catch (error) {
    console.error("[zkm] Error running automated database schema updates:", error);
    throw error;
  }
}
