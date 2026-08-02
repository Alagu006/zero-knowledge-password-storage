/**
 * Adversarial / security tests.
 *
 * These probe the REAL server (via supertest) with hostile inputs: forged and
 * tampered JWTs, algorithm-confusion attempts, token scope confusion, recovery
 * token binding, session revocation on credential changes, and injection
 * sanity checks. They run against the zkm_test database and are gated behind
 * INTEGRATION_TESTS=1 (see vitest.integration.config.ts).
 *
 * NOTE ON "CLIENT CRYPTO":
 *   The server never derives keys — it stores opaque hex blobs. These tests
 *   use fixed hex strings for salts/authKey/wrappedVk and focus on the server's
 *   authentication + authorization boundaries.
 */

import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import type { Express } from "express";
import type { PrismaClient } from "@prisma/client";

const ENABLED = process.env.INTEGRATION_TESTS === "1";

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

interface SigningSecrets {
  jwtSecret: string;
  jwtSecretPrev: string;
  tempTokenSecret: string;
}

describe.runIf(ENABLED)("Adversarial security tests", () => {
  let app: Express;
  let prisma: PrismaClient;
  let totp: typeof import("../utils/totp.js");
  let secrets: SigningSecrets;

  // -------------------------------------------------------------------------
  // Environment + server bootstrap. Env MUST be set before importing the
  // server modules (config.ts reads env at module load). JWT_SECRET_PREV is
  // set here so the key-rotation path can be exercised.
  // -------------------------------------------------------------------------

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.DATABASE_URL =
      "postgresql://zkm:root@localhost:5555/zkm_test?schema=public";
    process.env.JWT_SECRET =
      "security-test-jwt-secret-0123456789abcdefghijklmnopqrstuvwxyz";
    process.env.JWT_SECRET_PREV =
      "security-test-jwt-prev-secret-0123456789abcdefghijklmnopqrstuvwxyz";
    process.env.TEMP_TOKEN_SECRET =
      "security-test-temp-secret-0123456789abcdefghijklmnopqrstuvwxyz";
    process.env.TOTP_ENCRYPTION_KEY =
      "4a8f3e2b1c9d0e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f";
    // Raise per-IP rate limits so the suite doesn't trip them.
    process.env.AUTH_RATE_LIMIT_MAX = "1000";
    process.env.TOTP_RATE_LIMIT_MAX = "1000";

    const appModule = await import("../app.js");
    const dbModule = await import("../db.js");
    const configModule = await import("../config.js");
    totp = await import("../utils/totp.js");
    app = appModule.createApp();
    prisma = dbModule.prisma;
    secrets = {
      jwtSecret: configModule.config.jwtSecret,
      jwtSecretPrev: configModule.config.jwtSecretPrev!,
      tempTokenSecret: configModule.config.tempTokenSecret,
    };

    vi.spyOn(console, "error").mockImplementation(() => {});

    await prisma.$connect();
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    if (prisma) {
      await prisma.$disconnect();
    }
  });

  // Clean slate between tests.
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
      email: `sec-${Date.now()}-${seq}-${randomUUID().slice(0, 8)}@example.com`,
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

  /** Enable 2FA for a logged-in user; returns the TOTP secret + backup codes. */
  async function setup2Fa(token: string) {
    const res = await request(app).post("/auth/2fa/setup").set(authHeader(token));
    expect(res.status).toBe(200);
    expect(res.body.backupCodes).toHaveLength(10);
    return {
      secret: totpSecretFromUri(res.body.totpUri as string),
      backupCodes: res.body.backupCodes as string[],
    };
  }

  /** Manually insert a session record for an arbitrary token (rotation test). */
  async function insertSession(userId: string, token: string): Promise<void> {
    const tokenHash = createHash("sha256").update(token).digest();
    await prisma.authSession.create({
      data: {
        userId,
        tokenHash,
        expiresAt: new Date(Date.now() + 20 * 60 * 1000),
        ipAddress: "127.0.0.1",
        userAgent: "security-test",
      },
    });
  }

  // -------------------------------------------------------------------------
  // JWT integrity & algorithm attacks
  // -------------------------------------------------------------------------

  describe("JWT integrity & algorithm attacks", () => {
    const payload = (userId = randomUUID()) => ({ userId, email: "a@b.com" });

    it("rejects a token signed with a different secret", async () => {
      const attackerToken = jwt.sign(
        payload(),
        "attacker-chosen-secret-that-is-at-least-32-bytes",
        { algorithm: "HS256", expiresIn: "15m" } as jwt.SignOptions,
      );
      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(attackerToken));
      expect(res.status).toBe(401);
    });

    it("rejects a token whose payload was tampered with", async () => {
      const user = makeUser();
      const valid = await loginToken(user);
      const [header, body, sig] = valid.split(".");
      const tamperedPayload = {
        ...JSON.parse(Buffer.from(body!, "base64url").toString()),
        userId: randomUUID(),
      };
      const tampered = [
        header,
        Buffer.from(JSON.stringify(tamperedPayload)).toString("base64url"),
        sig,
      ].join(".");

      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(tampered));
      expect(res.status).toBe(401);
    });

    it("rejects an 'alg: none' token (signature omission)", async () => {
      const b64 = (o: unknown) =>
        Buffer.from(JSON.stringify(o)).toString("base64url");
      const noneToken = [
        b64({ alg: "none", typ: "JWT" }),
        b64(payload()),
        "",
      ].join(".");

      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(noneToken));
      expect(res.status).toBe(401);
    });

    it("rejects an HS256 token signed with a non-secret value (key/algorithm confusion)", async () => {
      // Simulates the classic confusion attack where the attacker uses a
      // well-known value (e.g. a public key) as the HMAC secret. The server
      // pins `algorithms: ["HS256"]` AND verifies against the real secret,
      // so this must fail.
      const fakePublicKey =
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMx\n-----END PUBLIC KEY-----";
      const confusedToken = jwt.sign(payload(), fakePublicKey, {
        algorithm: "HS256",
      });

      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(confusedToken));
      expect(res.status).toBe(401);
    });

    it("rejects an expired token", async () => {
      const expired = jwt.sign(
        { ...payload(), exp: Math.floor(Date.now() / 1000) - 60 },
        secrets.jwtSecret,
        { algorithm: "HS256" },
      );
      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(expired));
      expect(res.status).toBe(401);
    });

    it("rejects a validly-signed token for a non-existent user (no session)", async () => {
      const ghost = jwt.sign(payload(), secrets.jwtSecret, {
        algorithm: "HS256",
        expiresIn: "15m",
      } as jwt.SignOptions);
      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(ghost));
      expect(res.status).toBe(401);
    });

    it("accepts a token signed with the previous key during rotation", async () => {
      const user = makeUser();
      await register(user).expect(201);

      // Get the real user id from the DB.
      const dbUser = await prisma.user.findUniqueOrThrow({
        where: { email: user.email },
      });

      const prevToken = jwt.sign(
        { userId: dbUser.id, email: dbUser.email },
        secrets.jwtSecretPrev,
        { algorithm: "HS256", expiresIn: "15m" } as jwt.SignOptions,
      );

      // The session check requires a matching row; create it directly since
      // the login flow only ever signs with the current key.
      await insertSession(dbUser.id, prevToken);

      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(prevToken));
      expect(res.status).toBe(200);
    });
  });

  // -------------------------------------------------------------------------
  // Token scope separation
  // -------------------------------------------------------------------------

  describe("token scope separation", () => {
    it("a full session JWT cannot be used as a 2FA temp token", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app)
        .post("/auth/2fa/verify")
        .send({ tempToken: token, code: "000000" });
      expect(res.status).toBe(401);
    });

    it("a 2FA temp token cannot access protected routes", async () => {
      const user = makeUser();
      const token = await loginToken(user);
      const { secret } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const step2 = await loginStep2(user.email, user.authKey);
      expect(step2.body.tempToken).toBeTypeOf("string");

      const res = await request(app)
        .get("/vault/entries")
        .set(authHeader(step2.body.tempToken as string));
      expect(res.status).toBe(401);
    });

    it("a recovery session token cannot be used as a 2FA temp token", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      await register(user).expect(201);

      const recovery = await request(app)
        .post("/auth/recovery")
        .send({ email: user.email });
      expect(recovery.status).toBe(200);

      const res = await request(app)
        .post("/auth/2fa/verify")
        .send({ tempToken: recovery.body.recoverySessionToken, code: "000000" });
      expect(res.status).toBe(401);
    });

    it("a 2FA temp token cannot be used as a recovery session token", async () => {
      const user = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      const token = await loginToken(user);
      const { secret } = await setup2Fa(token);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(token))
        .send({ code: currentTotp(secret) })
        .expect(200);

      const step2 = await loginStep2(user.email, user.authKey);
      const res = await request(app)
        .post("/auth/recovery/complete")
        .send({
          recoverySessionToken: step2.body.tempToken as string,
          ...newCredentials(),
        });
      expect(res.status).toBe(401);
    });

    it("a full session JWT cannot be used as a recovery session token", async () => {
      const token = await loginToken(makeUser());
      const res = await request(app)
        .post("/auth/recovery/complete")
        .send({ recoverySessionToken: token, ...newCredentials() });
      expect(res.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // Recovery hardening
  // -------------------------------------------------------------------------

  describe("recovery hardening", () => {
    it("rejects recovery/complete with a garbage token", async () => {
      const res = await request(app)
        .post("/auth/recovery/complete")
        .send({ recoverySessionToken: "not-a-real-token", ...newCredentials() });
      expect(res.status).toBe(401);
    });

    it("binds recovery/complete to the token's user (a token for A cannot modify B)", async () => {
      const userA = makeUser({
        recoveryWrappedVk: "12".repeat(32),
        recoveryWrappedVkIv: "34".repeat(12),
        recoveryWrappedVkTag: "56".repeat(16),
      });
      const userB = makeUser();
      await register(userA).expect(201);
      await register(userB).expect(201);

      const initiate = await request(app)
        .post("/auth/recovery")
        .send({ email: userA.email });
      expect(initiate.status).toBe(200);

      // Complete recovery for A using A's token.
      const complete = await request(app)
        .post("/auth/recovery/complete")
        .send({
          recoverySessionToken: initiate.body.recoverySessionToken,
          ...newCredentials(),
        });
      expect(complete.status).toBe(200);

      // A was rotated: old creds dead, new creds work.
      const oldA = await loginStep2(userA.email, userA.authKey);
      expect(oldA.status).toBe(401);
      const newA = await loginStep2(userA.email, "99".repeat(32));
      expect(newA.status).toBe(200);

      // B is untouched: A's recovery could not be repointed at B.
      const oldB = await loginStep2(userB.email, userB.authKey);
      expect(oldB.status).toBe(200);
    });
  });

  // -------------------------------------------------------------------------
  // Session lifecycle (revocation on credential change)
  // -------------------------------------------------------------------------

  describe("session lifecycle (revocation)", () => {
    it("a password change invalidates the active session token", async () => {
      const user = makeUser();
      const token = await loginToken(user);

      const change = await request(app)
        .put("/auth/password")
        .set(authHeader(token))
        .send({ oldAuthKey: user.authKey, ...newCredentials() });
      expect(change.status).toBe(200);

      const res = await request(app).get("/vault/entries").set(authHeader(token));
      expect(res.status).toBe(401);
    });

    it("a KDF upgrade invalidates the active session token", async () => {
      const user = makeUser();
      const token = await loginToken(user);

      const upgrade = await request(app)
        .put("/auth/kdf-upgrade")
        .set(authHeader(token))
        .send({ oldAuthKey: user.authKey, ...newCredentials({ kdfVersion: 2 }) });
      expect(upgrade.status).toBe(200);

      const res = await request(app).get("/vault/entries").set(authHeader(token));
      expect(res.status).toBe(401);
    });
  });

  // -------------------------------------------------------------------------
  // Cross-user isolation in the 2FA path
  // -------------------------------------------------------------------------

  describe("cross-user isolation", () => {
    it("a backup code from one user cannot log into another user", async () => {
      const userA = makeUser();
      const userB = makeUser();
      const tokenA = await loginToken(userA);
      const tokenB = await loginToken(userB);

      const a2fa = await setup2Fa(tokenA);
      const b2fa = await setup2Fa(tokenB);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(tokenA))
        .send({ code: currentTotp(a2fa.secret) })
        .expect(200);
      await request(app)
        .post("/auth/2fa/enable")
        .set(authHeader(tokenB))
        .send({ code: currentTotp(b2fa.secret) })
        .expect(200);

      // B's temp token combined with A's backup code must fail.
      const step2B = await loginStep2(userB.email, userB.authKey);
      expect(step2B.body.tempToken).toBeTypeOf("string");

      const res = await request(app)
        .post("/auth/2fa/backup-verify")
        .send({
          tempToken: step2B.body.tempToken as string,
          code: a2fa.backupCodes[0],
        });
      expect(res.status).toBe(401);

      // B's own code still works (the failed attempt did not consume it).
      const ok = await request(app)
        .post("/auth/2fa/backup-verify")
        .send({
          tempToken: step2B.body.tempToken as string,
          code: b2fa.backupCodes[0],
        });
      expect(ok.status).toBe(200);
    });
  });

  // -------------------------------------------------------------------------
  // Injection sanity
  // -------------------------------------------------------------------------

  describe("injection sanity", () => {
    it("SQL injection strings in email are rejected by validation (no 500)", async () => {
      const evilEmail = "' OR '1'='1' --";

      const reg = await request(app)
        .post("/auth/register")
        .send(makeUser({ email: evilEmail }));
      expect(reg.status).toBe(400);

      const login = await loginStep2(evilEmail, "33".repeat(32));
      expect(login.status).toBe(400);
    });

    it("non-hex / script ciphertext is rejected (XSS cannot be stored)", async () => {
      const token = await loginToken(makeUser());

      const evil = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send({
          entryType: "password",
          nonce: "ab".repeat(12),
          ciphertext: "<script>alert('xss')</script>",
          authTag: "ef".repeat(16),
        });
      expect(evil.status).toBe(400);

      const evilType = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send({
          entryType: "<script>alert(1)</script>",
          nonce: "ab".repeat(12),
          ciphertext: "cd".repeat(16),
          authTag: "ef".repeat(16),
        });
      expect(evilType.status).toBe(400);

      // Control: a legitimate hex entry is still accepted.
      const ok = await request(app)
        .post("/vault/entries")
        .set(authHeader(token))
        .send({
          entryType: "password",
          nonce: "ab".repeat(12),
          ciphertext: "cd".repeat(16),
          authTag: "ef".repeat(16),
        });
      expect(ok.status).toBe(201);
    });
  });
});
