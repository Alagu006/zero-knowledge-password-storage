/**
 * Server integration tests.
 *
 * These tests run the REAL Express application (via supertest, no network
 * socket) against the REAL PostgreSQL test database (zkm_test).
 *
 * REQUIREMENTS:
 *   1. Local PostgreSQL running on localhost:5555 (see .env).
 *   2. A dedicated `zkm_test` database with all migrations applied:
 *        psql -U zkm -h localhost -p 5555 -c "CREATE DATABASE zkm_test;"
 *        psql -U zkm -h localhost -p 5555 -d zkm_test -f migrations/SQL/001_init.sql
 *        ... (002, 003, 004, 005)
 *   3. Run via:  npm run test:integration
 *
 * The suite is gated behind INTEGRATION_TESTS=1 so `npm test` (pure unit
 * tests) does not require a live database. The vitest.integration.config.ts
 * sets that flag.
 *
 * NOTE ON "CLIENT CRYPTO":
 *   The server NEVER derives keys — it only stores opaque hex blobs. These
 *   tests therefore use fixed hex strings for salts/authKey/wrappedVk. They
 *   exercise the server's real validation, persistence, and flow logic.
 */

import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import type { Express } from "express";
import type { PrismaClient } from "@prisma/client";

const ENABLED = process.env.INTEGRATION_TESTS === "1";

// ---------------------------------------------------------------------------
// Request body shape for registration (hex-encoded, client-generated values).
// ---------------------------------------------------------------------------

interface RegisterBody {
  email: string;
  saltEnc: string;
  saltAuth: string;
  authKey: string;
  wrappedVk: string;
  wrappedVkIv: string;
  wrappedVkTag: string;
  kdfVersion: number;
  recoveryWrappedVk?: string;
  recoveryWrappedVkIv?: string;
  recoveryWrappedVkTag?: string;
}

describe.runIf(ENABLED)("Server integration tests", () => {
  let app: Express;
  let prisma: PrismaClient;
  let totp: typeof import("../utils/totp.js");

  // -------------------------------------------------------------------------
  // Environment + server bootstrap. Env MUST be set before importing the
  // server modules (config.ts reads env at module load).
  // -------------------------------------------------------------------------

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.DATABASE_URL =
      "postgresql://zkm:root@localhost:5555/zkm_test?schema=public";
    process.env.JWT_SECRET =
      "integration-test-jwt-secret-0123456789abcdefghijklmnopqrstuvwxyz";
    process.env.TEMP_TOKEN_SECRET =
      "integration-test-temp-secret-0123456789abcdefghijklmnopqrstuvwxyz";
    process.env.TOTP_ENCRYPTION_KEY =
      "4a8f3e2b1c9d0e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f";
    // Raise per-IP rate limits so the full suite doesn't trip them.
    process.env.AUTH_RATE_LIMIT_MAX = "1000";
    process.env.TOTP_RATE_LIMIT_MAX = "1000";

    const appModule = await import("../app.js");
    const dbModule = await import("../db.js");
    totp = await import("../utils/totp.js");
    app = appModule.createApp();
    prisma = dbModule.prisma;

    // Expected errors (401/409/etc.) are logged by the error handler; silence
    // them so the test output is readable. Restored in afterAll.
    vi.spyOn(console, "error").mockImplementation(() => {});

    await prisma.$connect();
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    if (prisma) {
      await prisma.$disconnect();
    }
  });

  // Clean slate between tests — each test creates its own unique users.
  beforeEach(async () => {
    await prisma.$executeRawUnsafe(
      `TRUNCATE TABLE users, vault_entries, auth_sessions, backup_codes, audit_log CASCADE;`,
    );
  });

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  let seq = 0;
  function makeUser(overrides: Partial<RegisterBody> = {}): RegisterBody {
    seq += 1;
    return {
      email: `it-${Date.now()}-${seq}-${randomUUID().slice(0, 8)}@example.com`,
      saltEnc: "11".repeat(32),
      saltAuth: "22".repeat(32),
      authKey: "33".repeat(32),
      wrappedVk: "44".repeat(32),
      wrappedVkIv: "55".repeat(12),
      wrappedVkTag: "66".repeat(16),
      kdfVersion: 1,
      ...overrides,
    };
  }

  const register = (body: RegisterBody) =>
    request(app).post("/auth/register").send(body);

  const loginStep1 = (email: string) =>
    request(app).post("/auth/login").send({ email });

  const loginStep2 = (email: string, authKey: string) =>
    request(app).post("/auth/login/verify").send({ email, authKey });

  /** Register + login (no 2FA) → session JWT. */
  async function loginToken(user: RegisterBody): Promise<string> {
    await register(user).expect(201);
    const res = await loginStep2(user.email, user.authKey);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTypeOf("string");
    return res.body.token as string;
  }

  const authHeader = (token: string) => ({ Authorization: `Bearer ${token}` });

  function totpSecretFromUri(uri: string): Uint8Array {
    const match = /secret=([A-Z2-7]+)/.exec(uri);
    if (!match) throw new Error("No base32 secret found in otpauth URI");
    return totp.base32Decode(match[1]!);
  }

  const currentTotp = (secret: Uint8Array) => totp.generateTotpCode(secret);

  const newCredentials = (overrides: Partial<RegisterBody> = {}) => ({
    saltEnc: "77".repeat(32),
    saltAuth: "88".repeat(32),
    authKey: "99".repeat(32),
    wrappedVk: "aa".repeat(32),
    wrappedVkIv: "bb".repeat(12),
    wrappedVkTag: "cc".repeat(16),
    kdfVersion: 1,
    ...overrides,
  });

  // -------------------------------------------------------------------------
  // Health + registration
  // -------------------------------------------------------------------------

  describe("health + registration", () => {
    it("GET /health returns ok", async () => {
      const res = await request(app).get("/health");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "ok" });
    });

    it("registers a new account", async () => {
      const res = await register(makeUser());
      expect(res.status).toBe(201);
    });

    it("rejects duplicate email registration", async () => {
      const user = makeUser();
      await register(user).expect(201);
      const res = await register(user);
      expect(res.status).toBe(409);
    });

    it("rejects a malformed body with 400", async () => {
      const res = await register(makeUser({ authKey: "not-hex!" }));
      expect(res.status).toBe(400);
    });

    it("rejects unknown fields (mass-assignment protection)", async () => {
      const body = { ...makeUser(), totpEnabled: true } as unknown as RegisterBody;
      const res = await register(body);
      expect(res.status).toBe(400);
    });

    it("rejects an out-of-range kdfVersion", async () => {
      const res = await register(makeUser({ kdfVersion: 11 }));
      expect(res.status).toBe(400);
    });

    it("returns a generic 400 message for validation errors", async () => {
      const res = await register(makeUser({ authKey: "not-hex!" }));
      expect(res.body.error).toBe("Invalid input");
    });
  });

  // -------------------------------------------------------------------------
  // Login
  // -------------------------------------------------------------------------

  describe("login", () => {
    it("step 1 returns salts + wrapped vault key", async () => {
      const user = makeUser();
      await register(user).expect(201);

      const res = await loginStep1(user.email);
      expect(res.status).toBe(200);
      expect(res.body.saltEnc).toBe(user.saltEnc);
      expect(res.body.saltAuth).toBe(user.saltAuth);
      expect(res.body.wrappedVk).toBe(user.wrappedVk);
      expect(res.body.kdfVersion).toBe(1);
    });

    it("step 1 for an unknown email returns dummy values (anti-enumeration)", async () => {
      const res = await loginStep1(`ghost-${randomUUID()}@example.com`);
      expect(res.status).toBe(200);
      expect(res.body.saltEnc).toMatch(/^[0-9a-f]{64}$/);
      expect(res.body.saltAuth).toMatch(/^[0-9a-f]{64}$/);
      expect(res.body.wrappedVk).toMatch(/^[0-9a-f]+$/);
      expect(typeof res.body.kdfVersion).toBe("number");
    });

    it("step 2 with the correct authKey issues a JWT", async () => {
      const user = makeUser();
      await register(user).expect(201);
      const res = await loginStep2(user.email, user.authKey);
      expect(res.status).toBe(200);
      expect(res.body.token).toBeTypeOf("string");
    });

    it("step 2 with the wrong authKey returns generic 401", async () => {
      const user = makeUser();
      await register(user).expect(201);
      const res = await loginStep2(user.email, "99".repeat(32));
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Invalid credentials");
    });

    it("step 2 for an unknown email returns the SAME generic 401", async () => {
      const res = await loginStep2(`ghost-${randomUUID()}@example.com`, "33".repeat(32));
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Invalid credentials");
    });

    it("a valid session token is accepted on protected routes", async () => {
      const user = makeUser();
      await register(user).expect(201);
      const res = await loginStep2(user.email, user.authKey);
      const token = res.body.token as string;

      const vault = await request(app)
        .get("/vault/entries")
        .set(authHeader(token));
      expect(vault.status).toBe(200);
    });

    it("protected routes reject a missing token", async () => {
      const res = await request(app).get("/vault/entries");
      expect(res.status).toBe(401);
    });

    it("protected routes reject a garbage token", async () => {
      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader("not-a-real-token"));
      expect(res.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // Vault CRUD
  // -------------------------------------------------------------------------

  describe("vault CRUD", () => {
    const entryBody = () => ({
      entryType: "password" as const,
      nonce: "ab".repeat(12),
      ciphertext: "cd".repeat(16),
      authTag: "ef".repeat(16),
    });

    const updateBody = (version: number) => {
      const { entryType: _ignored, ...rest } = entryBody();
      return { ...rest, version };
    };

    it("creates an entry", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send(entryBody());
      expect(res.status).toBe(201);
      expect(res.body.version).toBe(1);
      expect(res.body.id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it("lists entries for the authenticated user only", async () => {
      const userA = makeUser();
      const userB = makeUser();
      const tokenA = await loginToken(userA);
      const tokenB = await loginToken(userB);

      await request(app)
        .post("/vault/entries")
        .set(authHeader(tokenA))
        .send(entryBody())
        .expect(201);

      const resB = await request(app).get("/vault/entries").set(authHeader(tokenB));
      expect(resB.status).toBe(200);
      expect(resB.body.entries).toHaveLength(0);

      const resA = await request(app).get("/vault/entries").set(authHeader(tokenA));
      expect(resA.body.entries).toHaveLength(1);
      expect(resA.body.entries[0]!.entryType).toBe("password");
    });

    it("updates an entry with a matching version", async () => {
      const token = await loginToken(makeUser());
      const created = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send(entryBody())
        .expect(201);

      const res = await request(app)
        .put(`/vault/entries/${created.body.id}`)
        .set(authHeader(token))
        .send(updateBody(1));
      expect(res.status).toBe(200);
      expect(res.body.version).toBe(2);
    });

    it("rejects an update with a stale version (optimistic concurrency)", async () => {
      const token = await loginToken(makeUser());
      const created = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send(entryBody())
        .expect(201);

      const res = await request(app)
        .put(`/vault/entries/${created.body.id}`)
        .set(authHeader(token))
        .send(updateBody(99));
      expect(res.status).toBe(404);
    });

    it("deletes an entry", async () => {
      const token = await loginToken(makeUser());
      const created = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send(entryBody())
        .expect(201);

      const del = await request(app)
        .delete(`/vault/entries/${created.body.id}`)
        .set(authHeader(token));
      expect(del.status).toBe(204);

      const list = await request(app).get("/vault/entries").set(authHeader(token));
      expect(list.body.entries).toHaveLength(0);
    });

    it("cross-user access to an entry returns 404 (no IDOR leak)", async () => {
      const tokenA = await loginToken(makeUser());
      const tokenB = await loginToken(makeUser());

      const created = await request(app)
        .post("/vault/entries")
        .set(authHeader(tokenA))
        .send(entryBody())
        .expect(201);

      const read = await request(app)
        .get("/vault/entries")
        .set(authHeader(tokenB));
      expect(read.body.entries).toHaveLength(0);

      const update = await request(app)
        .put(`/vault/entries/${created.body.id}`)
        .set(authHeader(tokenB))
        .send(updateBody(1));
      expect(update.status).toBe(404);

      const del = await request(app)
        .delete(`/vault/entries/${created.body.id}`)
        .set(authHeader(tokenB));
      expect(del.status).toBe(404);
    });

    it("rejects an invalid entryType", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send({ ...entryBody(), entryType: "drop-table" });
      expect(res.status).toBe(400);
    });
  });

  // -------------------------------------------------------------------------
  // Password change + KDF upgrade
  // -------------------------------------------------------------------------

  describe("password change + KDF upgrade", () => {
    it("changes the password with the correct old authKey", async () => {
      const user = makeUser();
      const token = await loginToken(user);

      const res = await request(app)
        .put("/auth/password")
        .set(authHeader(token))
        .send({ oldAuthKey: user.authKey, ...newCredentials() });
      expect(res.status).toBe(200);

      // Old session is revoked.
      const old = await request(app).get("/vault/entries").set(authHeader(token));
      expect(old.status).toBe(401);

      // New authKey works; old authKey does not.
      const newLogin = await loginStep2(user.email, "99".repeat(32));
      expect(newLogin.status).toBe(200);
      const oldLogin = await loginStep2(user.email, user.authKey);
      expect(oldLogin.status).toBe(401);
    });

    it("rejects a password change with the wrong old authKey", async () => {
      const user = makeUser();
      const token = await loginToken(user);

      const res = await request(app)
        .put("/auth/password")
        .set(authHeader(token))
        .send({ oldAuthKey: "00".repeat(32), ...newCredentials() });
      expect(res.status).toBe(401);
    });

    it("requires a valid session for a password change", async () => {
      const res = await request(app)
        .put("/auth/password")
        .send({ oldAuthKey: "33".repeat(32), ...newCredentials() });
      expect(res.status).toBe(401);
    });

    it("upgrades KDF parameters to a newer version", async () => {
      const user = makeUser({ kdfVersion: 1 });
      const token = await loginToken(user);

      const res = await request(app)
        .put("/auth/kdf-upgrade")
        .set(authHeader(token))
        .send({ oldAuthKey: user.authKey, ...newCredentials({ kdfVersion: 2 }) });
      expect(res.status).toBe(200);

      // New login reflects the new version.
      const step1 = await loginStep1(user.email);
      expect(step1.body.kdfVersion).toBe(2);
    });

    it("rejects a KDF downgrade", async () => {
      const user = makeUser({ kdfVersion: 2 });
      const token = await loginToken(user);

      const res = await request(app)
        .put("/auth/kdf-upgrade")
        .set(authHeader(token))
        .send({ oldAuthKey: user.authKey, ...newCredentials({ kdfVersion: 1 }) });
      expect(res.status).toBe(409);
    });

    it("rejects a KDF upgrade with the wrong old authKey", async () => {
      const user = makeUser();
      const token = await loginToken(user);

      const res = await request(app)
        .put("/auth/kdf-upgrade")
        .set(authHeader(token))
        .send({ oldAuthKey: "00".repeat(32), ...newCredentials({ kdfVersion: 2 }) });
      expect(res.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // 2FA / TOTP + backup codes
  // -------------------------------------------------------------------------

  describe("2FA (TOTP + backup codes)", () => {
    async function setup2Fa(token: string) {
      const res = await request(app).post("/auth/2fa/setup").set(authHeader(token));
      expect(res.status).toBe(200);
      expect(res.body.backupCodes).toHaveLength(10);
      return {
        secret: totpSecretFromUri(res.body.totpUri as string),
        backupCodes: res.body.backupCodes as string[],
      };
    }

    it("setup returns a TOTP URI and 10 backup codes", async () => {
      const token = await loginToken(makeUser());
      const { secret, backupCodes } = await setup2Fa(token);
      expect(currentTotp(secret)).toMatch(/^\d{6}$/);
      for (const code of backupCodes) {
        expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
      }
    });

    it("enables 2FA with a correct TOTP code", async () => {
      const token = await loginToken(makeUser());
      const { secret } = await setup2Fa(token);

      const res = await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) });
      expect(res.status).toBe(200);

      const status = await request(app).get("/auth/2fa/status").set(authHeader(token));
      expect(status.body).toEqual({ totpEnabled: true, backupCodesRemaining: 10 });
    });

    it("rejects enabling 2FA with a wrong code", async () => {
      const token = await loginToken(makeUser());
      await setup2Fa(token);

      const res = await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: "000000" });
      expect(res.status).toBe(401);

      const status = await request(app).get("/auth/2fa/status").set(authHeader(token));
      expect(status.body.totpEnabled).toBe(false);
    });

    it("does not allow a second setup once 2FA is enabled", async () => {
      const token = await loginToken(makeUser());
      const { secret } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const res = await request(app).post("/auth/2fa/setup").set(authHeader(token));
      expect(res.status).toBe(409);
    });

    it("login with 2FA requires a TOTP code (two-step token flow)", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      // Password auth now returns a temp token, not a session token.
      const step2 = await loginStep2(user.email, user.authKey);
      expect(step2.status).toBe(200);
      expect(step2.body.twoFactorRequired).toBe(true);
      expect(step2.body.tempToken).toBeTypeOf("string");
      expect(step2.body.token).toBeUndefined();

      // Wrong code → 401.
      const bad = await request(app)
        .post("/auth/2fa/verify")
        .send({ tempToken: step2.body.tempToken, code: "000000" });
      expect(bad.status).toBe(401);

      // Correct code → full session token.
      const good = await request(app)
        .post("/auth/2fa/verify")
        .send({ tempToken: step2.body.tempToken, code: currentTotp(secret) });
      expect(good.status).toBe(200);
      expect(good.body.token).toBeTypeOf("string");
    });

    it("login works with a one-time backup code", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret, backupCodes } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const step2 = await loginStep2(user.email, user.authKey);
      const res = await request(app)
        .post("/auth/2fa/backup-verify")
        .send({ tempToken: step2.body.tempToken, code: backupCodes[0] });
      expect(res.status).toBe(200);
      expect(res.body.token).toBeTypeOf("string");
    });

    it("a backup code can only be used once", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret, backupCodes } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const step2 = await loginStep2(user.email, user.authKey);
      await request(app)
        .post("/auth/2fa/backup-verify")
        .send({ tempToken: step2.body.tempToken, code: backupCodes[0] })
        .expect(200);

      const step2b = await loginStep2(user.email, user.authKey);
      const reuse = await request(app)
        .post("/auth/2fa/backup-verify")
        .send({ tempToken: step2b.body.tempToken, code: backupCodes[0] });
      expect(reuse.status).toBe(401);
    });

    it("disables 2FA with the current TOTP code", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const res = await request(app)
        .post("/auth/2fa/disable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) });
      expect(res.status).toBe(200);

      // Login no longer requires 2FA.
      const step2 = await loginStep2(user.email, user.authKey);
      expect(step2.body.twoFactorRequired).toBeUndefined();
      expect(step2.body.token).toBeTypeOf("string");
    });

    it("regenerates backup codes with a fresh TOTP code", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret, backupCodes } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const res = await request(app)
        .post("/auth/2fa/backup-codes/regenerate")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) });
      expect(res.status).toBe(200);
      expect(res.body.backupCodes).toHaveLength(10);

      // Old codes are gone; new codes work for login.
      const step2 = await loginStep2(user.email, user.authKey);
      const oldCode = await request(app)
        .post("/auth/2fa/backup-verify")
        .send({ tempToken: step2.body.tempToken, code: backupCodes[0] });
      expect(oldCode.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // Account recovery
  // -------------------------------------------------------------------------

  describe("account recovery", () => {
    it("returns the recovery blob + session token for a recovery-enabled account", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      await register(user).expect(201);

      const res = await request(app).post("/auth/recovery").send({ email: user.email });
      expect(res.status).toBe(200);
      expect(res.body.recoverySessionToken).toBeTypeOf("string");
      expect(res.body.recoveryWrappedVk).toBe("12".repeat(32));
    });

    it("returns dummy values for an account without recovery (anti-enumeration)", async () => {
      const user = makeUser();
      await register(user).expect(201);

      const res = await request(app).post("/auth/recovery").send({ email: user.email });
      expect(res.status).toBe(200);
      expect(res.body.recoverySessionToken).toBeTypeOf("string");
      expect(res.body.recoveryWrappedVk).toMatch(/^[0-9a-f]+$/);
    });

    it("completes recovery and rotates credentials", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      await register(user).expect(201);

      const initiate = await request(app)
        .post("/auth/recovery")
        .send({ email: user.email });
      const complete = await request(app)
        .post("/auth/recovery/complete")
        .send({
          recoverySessionToken: initiate.body.recoverySessionToken,
          ...newCredentials(),
        });
      expect(complete.status).toBe(200);

      // Old credentials no longer work; new ones do.
      const oldLogin = await loginStep2(user.email, user.authKey);
      expect(oldLogin.status).toBe(401);
      const newLogin = await loginStep2(user.email, "99".repeat(32));
      expect(newLogin.status).toBe(200);
    });

    it("recovery session tokens are single-use", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      await register(user).expect(201);

      const initiate = await request(app)
        .post("/auth/recovery")
        .send({ email: user.email });
      await request(app)
        .post("/auth/recovery/complete")
        .send({
          recoverySessionToken: initiate.body.recoverySessionToken,
          ...newCredentials(),
        })
        .expect(200);

      // The recovery blob is cleared → same token cannot complete again.
      const again = await request(app)
        .post("/auth/recovery/complete")
        .send({
          recoverySessionToken: initiate.body.recoverySessionToken,
          ...newCredentials({ authKey: "77".repeat(32) }),
        });
      expect(again.status).toBe(401);
    });

    it("regenerates the recovery code with proof of the current password", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      const token = await loginToken(user);

      const res = await request(app)
        .post("/auth/recovery/regenerate")
        .set(authHeader(token))
        .send({
          oldAuthKey: user.authKey,
          recoveryWrappedVk: "ab".repeat(32),
          recoveryWrappedVkIv: "cd".repeat(12),
          recoveryWrappedVkTag: "ef".repeat(16),
        });
      expect(res.status).toBe(200);

      const initiate = await request(app).post("/auth/recovery").send({ email: user.email });
      expect(initiate.body.recoveryWrappedVk).toBe("ab".repeat(32));
    });

    it("rejects recovery-code regeneration with the wrong password", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      const token = await loginToken(user);

      const res = await request(app)
        .post("/auth/recovery/regenerate")
        .set(authHeader(token))
        .send({
          oldAuthKey: "00".repeat(32),
          recoveryWrappedVk: "ab".repeat(32),
          recoveryWrappedVkIv: "cd".repeat(12),
          recoveryWrappedVkTag: "ef".repeat(16),
        });
      expect(res.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // Session management
  // -------------------------------------------------------------------------

  describe("session management", () => {
    it("lists the current session", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app).get("/auth/sessions").set(authHeader(token));
      expect(res.status).toBe(200);
      expect(res.body.sessions).toHaveLength(1);
      expect(res.body.sessions[0]!.current).toBe(true);
      expect(res.body.sessions[0]!.active).toBe(true);
      expect(res.body.sessions[0]!.id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it("revokes every other session", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app).delete("/auth/sessions").set(authHeader(token));
      expect(res.status).toBe(200);
      // The current session is kept.
      const list = await request(app).get("/auth/sessions").set(authHeader(token));
      expect(list.body.sessions).toHaveLength(1);
    });

    it("revoking the current session invalidates the token", async () => {
      const token = await loginToken(makeUser());
      const list = await request(app).get("/auth/sessions").set(authHeader(token));
      const sessionId = list.body.sessions[0]!.id as string;

      const del = await request(app)
        .delete(`/auth/sessions/${sessionId}`)
        .set(authHeader(token));
      expect(del.status).toBe(200);

      const after = await request(app).get("/vault/entries").set(authHeader(token));
      expect(after.status).toBe(401);
    });

    it("cannot revoke another user's session (404)", async () => {
      const tokenA = await loginToken(makeUser());
      const tokenB = await loginToken(makeUser());

      const listA = await request(app).get("/auth/sessions").set(authHeader(tokenA));
      const sessionAId = listA.body.sessions[0]!.id as string;

      const res = await request(app)
        .delete(`/auth/sessions/${sessionAId}`)
        .set(authHeader(tokenB));
      expect(res.status).toBe(404);
    });

    it("returns 404 for an unknown session id", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app)
        .delete(`/auth/sessions/${randomUUID()}`)
        .set(authHeader(token));
      expect(res.status).toBe(404);
    });
  });

  // -------------------------------------------------------------------------
  // Lockout (account + TOTP)
  // -------------------------------------------------------------------------

  describe("lockout", () => {
    it("locks an account after repeated failed logins", async () => {
      const user = makeUser();
      await register(user).expect(201);

      // 5 wrong passwords → failures recorded.
      for (let i = 0; i < 5; i++) {
        const res = await loginStep2(user.email, "00".repeat(32));
        expect(res.status).toBe(401);
      }

      // 6th attempt — even with the correct authKey — is refused (421).
      const res = await loginStep2(user.email, user.authKey);
      expect(res.status).toBe(421);
      expect(res.headers["retry-after"]).toBeDefined();
      expect(res.body.error).toBe("Invalid credentials");
    });

    it("a non-existent email also accumulates failures without leaking existence", async () => {
      const email = `ghost-${randomUUID()}@example.com`;
      for (let i = 0; i < 5; i++) {
        await loginStep2(email, "00".repeat(32)).expect(401);
      }
      const res = await loginStep2(email, "00".repeat(32));
      expect(res.status).toBe(421);
    });

    it("locks TOTP verification after repeated wrong codes", async () => {
      const token = await loginToken(makeUser());
      const setup = await request(app).post("/auth/2fa/setup").set(authHeader(token));
      const secret = totpSecretFromUri(setup.body.totpUri as string);

      // 5 wrong codes on /2fa/enable.
      for (let i = 0; i < 5; i++) {
        const res = await request(app)
          .post("/auth/2fa/enable")
          .set(authHeader(token))
          .send({ code: "000000" });
        expect(res.status).toBe(401);
      }

      // 6th attempt — even with the correct code — is refused (421).
      const res = await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) });
      expect(res.status).toBe(421);
    });
  });

  // -------------------------------------------------------------------------
  // Security headers
  // -------------------------------------------------------------------------

  describe("security headers", () => {
    it("sets strict security headers on every response", async () => {
      const res = await request(app).get("/health");
      expect(res.status).toBe(200);

      expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
      expect(res.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
      expect(res.headers["x-content-type-options"]).toBe("nosniff");
      expect(res.headers["x-frame-options"]).toBe("DENY");
      expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
      expect(res.headers["permissions-policy"]).toContain("camera=()");
      expect(res.headers["strict-transport-security"]).toContain("max-age=31536000");
    });

    it("does not leak error details in validation failures", async () => {
      const res = await register(makeUser({ authKey: "bad" }));
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).not.toContain("bad");
    });
  });
});
