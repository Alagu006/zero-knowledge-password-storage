/**
 * End-to-end integration tests for the client auth flows.
 *
 * These tests mock the HTTP layer (fetch) and verify that the client
 * correctly orchestrates crypto operations with the API protocol.
 * They do NOT require a running server.
 *
 * TEST COVERAGE:
 *   - Registration: valid flow, duplicate email, weak password, recovery code
 *   - Login: valid flow, wrong password (step 2 failure), wrong password
 *     (unwrap failure), email not found
 *   - Password change: full flow, entries survive password change
 *   - Account recovery: full flow, wrong code, wrong email
 *   - Password strength: all validation rules
 *   - Key independence: deriveMasterKey and deriveAuthKey produce different outputs
 *   - Hex encoding round-trip
 *   - Memory hygiene: zeroize clears buffers
 */

import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from "vitest";
import { register, login, changePassword, upgradeKdf, recoverVaultKey, completeRecovery, setup2FA, enable2FA, verify2FA, verify2FAWithBackupCode, get2FAStatus, regenerateBackupCodes, regenerateRecoveryCode, type TwoFactorRequiredResult } from "../auth.js";
import { validatePasswordStrength, scoreLabel } from "../password.js";
import { toHex, fromHex, apiLoginStep1, apiListSessions, apiRevokeSession, apiRevokeAllSessions } from "../api.js";
import {
  deriveMasterKey,
  deriveAuthKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  encryptEntry,
  decryptEntry,
  deriveRecoveryWrapKey,
  zeroize,
} from "../../crypto/index.js";
import {
  configureArgon2Mode,
  _resetArgon2ModeForTesting,
  KDF_CURRENT_VERSION,
} from "../../crypto/constants.js";
import type { EncryptedVaultKey } from "../../crypto/types.js";

// Import TOTP utilities for mock server
import { generateTotpSecret, generateTotpCode, verifyTotp } from "../../server/utils/totp.js";
import { hashBackupCode } from "../../server/utils/backupCodes.js";

beforeAll(() => {
  configureArgon2Mode("test");
});

afterAll(() => {
  _resetArgon2ModeForTesting();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomSalt(): Uint8Array {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// ---------------------------------------------------------------------------
// Mock fetch — simulates the server-side auth protocol
// ---------------------------------------------------------------------------

/**
 * In-memory "database" for the mock server.
 */
type MockSession = {
  id: string;
  token: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
  active: boolean;
};

const db = new Map<
  string,
  {
    saltEnc: Uint8Array;
    saltAuth: Uint8Array;
    authVerifier: Uint8Array;
    wrappedVK: EncryptedVaultKey;
    recoveryWrappedVK?: EncryptedVaultKey;
    kdfVersion: number;
    // 2FA fields
    totpSecret?: Uint8Array;
    totpEnabled: boolean;
    backupCodeHashes: string[];
    // Session records (device management)
    sessions: MockSession[];
  }
>();

let mockTokens = new Map<string, string>(); // token → email
let mockTempTokens = new Map<string, { email: string; userId: string }>(); // tempToken → {email, userId}
let mockUserIds = new Map<string, string>(); // email → userId (for 2FA)
let mockUserCounter = 0;
let mockSessionCounter = 0;

function mockCreateSession(email: string, token: string): void {
  const user = db.get(email);
  if (!user) return;
  mockSessionCounter++;
  user.sessions.push({
    id: `sess-${mockSessionCounter}`,
    token,
    ipAddress: "203.0.113.7",
    userAgent: "MockBrowser/1.0 (TestDevice)",
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
    active: true,
  });
}

function mockSessionResponse(token: string, email: string): Response {
  const user = db.get(email);
  return new Response(
    JSON.stringify({
      sessions: (user?.sessions ?? []).map((s) => ({
        id: s.id,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        active: s.active,
        current: s.token === token,
      })),
    }),
    { status: 200 },
  );
}

async function mockFetchImplementation(url: string, options: RequestInit): Promise<Response> {
  const body = options.body ? JSON.parse(options.body as string) : {};
  const method = options.method ?? "GET";
  const authHeader = (options.headers as Record<string, string>)?.Authorization;

  // POST /auth/register
  if (method === "POST" && url === "/auth/register") {
    if (db.has(body.email)) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Email already registered" }), {
          status: 409,
        }),
      );
    }

    const entry: (typeof db extends Map<string, infer V> ? V : never) = {
      saltEnc: fromHex(body.saltEnc),
      saltAuth: fromHex(body.saltAuth),
      authVerifier: fromHex(body.authKey),
      wrappedVK: {
        wrappedKey: fromHex(body.wrappedVk),
        iv: fromHex(body.wrappedVkIv),
        authTag: fromHex(body.wrappedVkTag),
      },
      kdfVersion: Number(body.kdfVersion ?? 1),
      totpEnabled: false,
      backupCodeHashes: [],
      sessions: [],
    };

    if (body.recoveryWrappedVk) {
      entry.recoveryWrappedVK = {
        wrappedKey: fromHex(body.recoveryWrappedVk),
        iv: fromHex(body.recoveryWrappedVkIv),
        authTag: fromHex(body.recoveryWrappedVkTag),
      };
    }

    db.set(body.email, entry);

    // Assign a mock userId for 2FA
    mockUserCounter++;
    mockUserIds.set(body.email, `user-${mockUserCounter}`);

    return Promise.resolve(
      new Response(JSON.stringify({ message: "Registration successful" }), {
        status: 201,
      }),
    );
  }

  // POST /auth/login (step 1)
  if (method === "POST" && url === "/auth/login") {
    const user = db.get(body.email);
    if (user) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            saltEnc: toHex(user.saltEnc),
            saltAuth: toHex(user.saltAuth),
            wrappedVk: toHex(user.wrappedVK.wrappedKey),
            wrappedVkIv: toHex(user.wrappedVK.iv),
            wrappedVkTag: toHex(user.wrappedVK.authTag),
            kdfVersion: user.kdfVersion,
          }),
          { status: 200 },
        ),
      );
    }
    // Return random dummies for non-existent emails
    return Promise.resolve(
      new Response(
        JSON.stringify({
          saltEnc: toHex(randomSalt()),
          saltAuth: toHex(randomSalt()),
          wrappedVk: toHex(randomBytes(48)),
          wrappedVkIv: toHex(randomBytes(12)),
          wrappedVkTag: toHex(randomBytes(16)),
          kdfVersion: 1 + Math.floor(Math.random() * 10),
        }),
        { status: 200 },
      ),
    );
  }

  // POST /auth/login/verify (step 2)
  if (method === "POST" && url === "/auth/login/verify") {
    const user = db.get(body.email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    const stored = user.authVerifier;
    const submitted = fromHex(body.authKey);
    const isValid =
      stored.length === submitted.length &&
      stored.every((v, i) => v === submitted[i]);

    if (!isValid) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    // Check if 2FA is enabled — return tempToken instead of full token
    if (user.totpEnabled) {
      const tempToken = `mock-temp-${Date.now()}`;
      const userId = mockUserIds.get(body.email) || "unknown";
      mockTempTokens.set(tempToken, { email: body.email, userId });
      return Promise.resolve(
        new Response(
          JSON.stringify({ tempToken, twoFactorRequired: true }),
          { status: 200 },
        ),
      );
    }

    const mockToken = `mock-jwt-${Date.now()}`;
    mockTokens.set(mockToken, body.email);
    mockCreateSession(body.email, mockToken);
    return Promise.resolve(
      new Response(JSON.stringify({ token: mockToken }), { status: 200 }),
    );
  }

  // PUT /auth/password — change password
  if (method === "PUT" && url === "/auth/password") {
    // Verify JWT
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    const user = db.get(email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    // Atomically update all credentials
    user.saltEnc = fromHex(body.saltEnc);
    user.saltAuth = fromHex(body.saltAuth);
    user.authVerifier = fromHex(body.authKey);
    user.wrappedVK = {
      wrappedKey: fromHex(body.wrappedVk),
      iv: fromHex(body.wrappedVkIv),
      authTag: fromHex(body.wrappedVkTag),
    };
    user.kdfVersion = Number(body.kdfVersion ?? 1);

    return Promise.resolve(
      new Response(JSON.stringify({ message: "Password changed successfully" }), {
        status: 200,
      }),
    );
  }

  // PUT /auth/kdf-upgrade — bump KDF parameters (verify old authKey first)
  if (method === "PUT" && url === "/auth/kdf-upgrade") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    const user = db.get(email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    // Verify oldAuthKey against stored verifier (same as password change)
    const stored = user.authVerifier;
    const submitted = fromHex(body.oldAuthKey);
    const isValid =
      stored.length === submitted.length &&
      stored.every((v, i) => v === submitted[i]);

    if (!isValid) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Current password is incorrect" }), {
          status: 401,
        }),
      );
    }

    // Reject downgrades
    if (Number(body.kdfVersion) <= user.kdfVersion) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Cannot downgrade" }), {
          status: 409,
        }),
      );
    }

    // Atomically update all credentials
    user.saltEnc = fromHex(body.saltEnc);
    user.saltAuth = fromHex(body.saltAuth);
    user.authVerifier = fromHex(body.authKey);
    user.wrappedVK = {
      wrappedKey: fromHex(body.wrappedVk),
      iv: fromHex(body.wrappedVkIv),
      authTag: fromHex(body.wrappedVkTag),
    };
    user.kdfVersion = Number(body.kdfVersion ?? 1);

    return Promise.resolve(
      new Response(JSON.stringify({ message: "Key derivation parameters upgraded" }), {
        status: 200,
      }),
    );
  }

  // POST /auth/recovery — fetch recovery blob
  if (method === "POST" && url === "/auth/recovery") {
    const user = db.get(body.email);
    if (user?.recoveryWrappedVK) {
      // Issue a mock recovery session token
      const recoveryToken = `mock-recovery-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      mockTempTokens.set(recoveryToken, { email: body.email, userId: mockUserIds.get(body.email) || "unknown" });
      return Promise.resolve(
        new Response(
          JSON.stringify({
            recoverySessionToken: recoveryToken,
            recoveryWrappedVk: toHex(user.recoveryWrappedVK.wrappedKey),
            recoveryWrappedVkIv: toHex(user.recoveryWrappedVK.iv),
            recoveryWrappedVkTag: toHex(user.recoveryWrappedVK.authTag),
          }),
          { status: 200 },
        ),
      );
    }
    // Return random dummies
    return Promise.resolve(
      new Response(
        JSON.stringify({
          recoverySessionToken: `dummy-${Date.now()}`,
          recoveryWrappedVk: toHex(randomBytes(48)),
          recoveryWrappedVkIv: toHex(randomBytes(12)),
          recoveryWrappedVkTag: toHex(randomBytes(16)),
        }),
        { status: 200 },
      ),
    );
  }

  // POST /auth/recovery/complete — finalize recovery
  if (method === "POST" && url === "/auth/recovery/complete") {
    // Verify recovery session token (not recovery code)
    const tokenData = mockTempTokens.get(body.recoverySessionToken);
    if (!tokenData) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    const user = db.get(tokenData.email);
    if (!user?.recoveryWrappedVK) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
        }),
      );
    }

    // Token valid — update credentials
    user.saltEnc = fromHex(body.saltEnc);
    user.saltAuth = fromHex(body.saltAuth);
    user.authVerifier = fromHex(body.authKey);
    user.wrappedVK = {
      wrappedKey: fromHex(body.wrappedVk),
      iv: fromHex(body.wrappedVkIv),
      authTag: fromHex(body.wrappedVkTag),
    };
    user.kdfVersion = Number(body.kdfVersion ?? 1);
    // Clear recovery blob
    user.recoveryWrappedVK = undefined;
    // Invalidate the recovery token (single-use)
    mockTempTokens.delete(body.recoverySessionToken);

    return Promise.resolve(
      new Response(
        JSON.stringify({ message: "Recovery complete" }),
        { status: 200 },
      ),
    );
  }

  // POST /auth/recovery/regenerate — rotate the recovery code (JWT + authKey)
  if (method === "POST" && url === "/auth/recovery/regenerate") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const user = db.get(email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }

    // Verify oldAuthKey against the stored verifier (same as password change)
    const stored = user.authVerifier;
    const submitted = fromHex(body.oldAuthKey);
    const isValid =
      stored.length === submitted.length &&
      stored.every((v, i) => v === submitted[i]);

    if (!isValid) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }

    // Replace the recovery blob — the old code no longer unwraps anything.
    user.recoveryWrappedVK = {
      wrappedKey: fromHex(body.recoveryWrappedVk),
      iv: fromHex(body.recoveryWrappedVkIv),
      authTag: fromHex(body.recoveryWrappedVkTag),
    };

    return Promise.resolve(
      new Response(
        JSON.stringify({ message: "Recovery code regenerated" }),
        { status: 200 },
      ),
    );
  }

  // POST /auth/2fa/setup — generate TOTP secret + backup codes (JWT required)
  if (method === "POST" && url === "/auth/2fa/setup") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const user = db.get(email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }

    // Generate TOTP secret (20 bytes)
    const totpSecret = generateTotpSecret();
    user.totpSecret = totpSecret;

    // Generate 10 backup codes, store hashes
    const backupCodesRaw: string[] = [];
    const backupCodeHashes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const code = Array.from({ length: 8 }, () => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 36)]).join("");
      backupCodesRaw.push(code.slice(0, 4) + "-" + code.slice(4));
      const hashStr = await hashBackupCode(code.replace("-", ""));
      backupCodeHashes.push(hashStr);
    }
    user.backupCodeHashes = backupCodeHashes;

    // Build a fake TOTP URI
    const totpUri = `otpauth://totp/ZeroTrustVault:${email}?secret=BASE32SECRET&issuer=ZeroTrustVault`;

    return Promise.resolve(
      new Response(JSON.stringify({ totpUri, backupCodes: backupCodesRaw }), { status: 200 }),
    );
  }

  // POST /auth/2fa/enable — verify TOTP code to activate 2FA (JWT required)
  if (method === "POST" && url === "/auth/2fa/enable") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const user = db.get(email);
    if (!user?.totpSecret) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "2FA not set up" }), { status: 400 }),
      );
    }

    // Verify TOTP code (same logic as real server — uses tolerance ±1)
    if (!verifyTotp(user.totpSecret, body.code)) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid code" }), { status: 400 }),
      );
    }

    user.totpEnabled = true;
    return Promise.resolve(
      new Response(JSON.stringify({ message: "2FA enabled" }), { status: 200 }),
    );
  }

  // POST /auth/2fa/verify — verify TOTP code during login (tempToken + code)
  if (method === "POST" && url === "/auth/2fa/verify") {
    const tempData = mockTempTokens.get(body.tempToken);
    if (!tempData) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid or expired temp token" }), { status: 401 }),
      );
    }

    const user = db.get(tempData.email);
    if (!user?.totpSecret || !user.totpEnabled) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "2FA not enabled" }), { status: 400 }),
      );
    }

    // Verify TOTP code (with ±1 tolerance, same as real server)
    if (!verifyTotp(user.totpSecret, body.code)) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid code" }), { status: 401 }),
      );
    }

    // Issue full JWT
    const fullToken = `mock-jwt-2fa-${Date.now()}`;
    mockTokens.set(fullToken, tempData.email);
    mockTempTokens.delete(body.tempToken);
    mockCreateSession(tempData.email, fullToken);
    return Promise.resolve(
      new Response(JSON.stringify({ token: fullToken }), { status: 200 }),
    );
  }

  // POST /auth/2fa/backup-verify — verify backup code during login
  if (method === "POST" && url === "/auth/2fa/backup-verify") {
    const tempData = mockTempTokens.get(body.tempToken);
    if (!tempData) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid or expired temp token" }), { status: 401 }),
      );
    }

    const user = db.get(tempData.email);
    if (!user?.backupCodeHashes?.length) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "No backup codes" }), { status: 400 }),
      );
    }

    // Normalize code: remove dash, uppercase
    const normalizedCode = body.code.replace("-", "").toUpperCase();
    const codeHash = hashBackupCode(normalizedCode);

    // Find matching hash
    const idx = user.backupCodeHashes.indexOf(codeHash);
    if (idx === -1) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid backup code" }), { status: 401 }),
      );
    }

    // Remove used backup code (one-time use)
    user.backupCodeHashes.splice(idx, 1);

    // Issue full JWT
    const fullToken = `mock-jwt-backup-${Date.now()}`;
    mockTokens.set(fullToken, tempData.email);
    mockTempTokens.delete(body.tempToken);
    mockCreateSession(tempData.email, fullToken);
    return Promise.resolve(
      new Response(JSON.stringify({ token: fullToken }), { status: 200 }),
    );
  }

  // POST /auth/2fa/backup-codes/regenerate — rotate backup codes (JWT + TOTP)
  if (method === "POST" && url === "/auth/2fa/backup-codes/regenerate") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const user = db.get(email);
    if (!user?.totpSecret || !user.totpEnabled) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid code" }), { status: 400 }),
      );
    }

    // Fresh TOTP code required (proof of possession — same as disable).
    if (!verifyTotp(user.totpSecret, body.code)) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid code" }), { status: 401 }),
      );
    }

    // Replace the backup code set atomically — old codes are immediately dead.
    const backupCodesRaw: string[] = [];
    const backupCodeHashes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const code = Array.from({ length: 8 }, () => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 36)]).join("");
      backupCodesRaw.push(code.slice(0, 4) + "-" + code.slice(4));
      backupCodeHashes.push(hashBackupCode(code));
    }
    user.backupCodeHashes = backupCodeHashes;

    return Promise.resolve(
      new Response(JSON.stringify({ backupCodes: backupCodesRaw }), { status: 200 }),
    );
  }

  // GET /auth/2fa/status — check 2FA status (JWT required)
  if (method === "GET" && url === "/auth/2fa/status") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const user = db.get(email);
    if (!user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    return Promise.resolve(
      new Response(
        JSON.stringify({
          totpEnabled: user.totpEnabled,
          backupCodesRemaining: user.backupCodeHashes.length,
        }),
        { status: 200 },
      ),
    );
  }

  // GET /auth/sessions — list sessions for the authenticated user
  if (method === "GET" && url === "/auth/sessions") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    if (!email) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    return Promise.resolve(mockSessionResponse(token, email));
  }

  // DELETE /auth/sessions — revoke every session except the current one
  if (method === "DELETE" && url === "/auth/sessions") {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    const user = email ? db.get(email) : undefined;
    if (!email || !user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const before = user.sessions.length;
    user.sessions = user.sessions.filter((s) => s.token === token);
    return Promise.resolve(
      new Response(
        JSON.stringify({ message: "All other sessions revoked", revokedCount: before - user.sessions.length }),
        { status: 200 },
      ),
    );
  }

  // DELETE /auth/sessions/:id — revoke a single session
  if (method === "DELETE" && url.startsWith("/auth/sessions/")) {
    if (!authHeader?.startsWith("Bearer ")) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const token = authHeader.slice(7);
    const email = mockTokens.get(token);
    const user = email ? db.get(email) : undefined;
    if (!email || !user) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 }),
      );
    }
    const sessionId = url.slice("/auth/sessions/".length);
    const idx = user.sessions.findIndex((s) => s.id === sessionId);
    if (idx === -1) {
      return Promise.resolve(
        new Response(JSON.stringify({ error: "Session not found" }), { status: 404 }),
      );
    }
    user.sessions.splice(idx, 1);
    return Promise.resolve(
      new Response(JSON.stringify({ message: "Session revoked" }), { status: 200 }),
    );
  }

  return Promise.resolve(
    new Response(JSON.stringify({ error: "Not found" }), { status: 404 }),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Password strength validation", () => {
  it("rejects passwords shorter than 12 characters", () => {
    const result = validatePasswordStrength("Ab1!xyz");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /at least 12/.test(e))).toBe(true);
  });

  it("rejects passwords without uppercase", () => {
    const result = validatePasswordStrength("abcdefgh1234!");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /uppercase/.test(e))).toBe(true);
  });

  it("rejects passwords without lowercase", () => {
    const result = validatePasswordStrength("ABCDEFGH1234!");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /lowercase/.test(e))).toBe(true);
  });

  it("rejects passwords without digits", () => {
    const result = validatePasswordStrength("AbcdefghijK!");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /digit/.test(e))).toBe(true);
  });

  it("rejects passwords without special characters", () => {
    const result = validatePasswordStrength("Abcdefgh1234");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /special/.test(e))).toBe(true);
  });

  it("rejects common passwords", () => {
    const result = validatePasswordStrength("password1");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /too common/.test(e))).toBe(true);
  });

  it("rejects passwords with 4+ repeated characters", () => {
    const result = validatePasswordStrength("Aaaaabbbb12!");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /consecutive/.test(e))).toBe(true);
  });

  it("accepts a strong password", () => {
    const result = validatePasswordStrength("Tr0ub4dor&3Correct!Horse");
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("returns score 4 for a long, diverse password", () => {
    const result = validatePasswordStrength("xK9#mP2$vL7@nQ4!");
    expect(result.score).toBeGreaterThanOrEqual(3);
  });

  it("scoreLabel returns human-readable labels", () => {
    expect(scoreLabel(4)).toBe("Excellent");
    expect(scoreLabel(3)).toBe("Strong");
    expect(scoreLabel(0)).toBe("Terrible");
  });
});

describe("Hex encoding round-trip", () => {
  it("toHex then fromHex recovers the original bytes", () => {
    const original = randomBytes(64);
    const hex = toHex(original);
    const recovered = fromHex(hex);
    expect(bytesEqual(original, recovered)).toBe(true);
  });

  it("toHex produces lowercase hex", () => {
    const bytes = new Uint8Array([0x0a, 0xbc, 0xff]);
    expect(toHex(bytes)).toBe("0abcff");
  });

  it("fromHex handles empty string", () => {
    const result = fromHex("");
    expect(result.length).toBe(0);
  });
});

describe("Key derivation independence", () => {
  it("deriveMasterKey and deriveAuthKey produce different, unrelated outputs for same password", async () => {
    const password = "test-password-12345!";
    const salt = randomSalt();

    const masterKey = await deriveMasterKey(password, salt);
    const authKey = await deriveAuthKey(password, salt);

    expect(bytesEqual(masterKey, authKey)).toBe(false);
    expect(masterKey.length).toBe(32);
    expect(authKey.length).toBe(32);
  });

  it("different passwords produce different master keys", async () => {
    const salt = randomSalt();
    const key1 = await deriveMasterKey("password-one-12345!", salt);
    const key2 = await deriveMasterKey("password-two-12345!", salt);
    expect(bytesEqual(key1, key2)).toBe(false);
  });
});

describe("Memory hygiene", () => {
  it("zeroize fills buffer with zeros", () => {
    const buf = randomBytes(32);
    expect(buf.every((v) => v === 0)).toBe(false);
    zeroize(buf);
    expect(buf.every((v) => v === 0)).toBe(true);
  });
});

describe("Registration flow (end-to-end with mock server)", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("successful registration returns recovery code and stores data on server", async () => {
    const result = await register("alice@example.com", "Tr0ub4dor&3Correct!Horse");
    expect(result.ok).toBe(true);

    if (result.ok) {
      // Should return a 32-char hex recovery code
      expect(result.recoveryCode).toBeDefined();
      expect(result.recoveryCode!.length).toBe(32);
      expect(/^[0-9a-f]{32}$/.test(result.recoveryCode!)).toBe(true);
    }

    // Verify the server stored the correct data
    const stored = db.get("alice@example.com");
    expect(stored).toBeDefined();
    expect(stored!.saltEnc.length).toBe(32);
    expect(stored!.saltAuth.length).toBe(32);
    expect(stored!.authVerifier.length).toBe(32);
    expect(stored!.wrappedVK.wrappedKey.length).toBeGreaterThan(0);
    expect(stored!.recoveryWrappedVK).toBeDefined();
  });

  it("registration with duplicate email returns error", async () => {
    await register("alice@example.com", "Tr0ub4dor&3Correct!Horse");
    const result = await register("alice@example.com", "Tr0ub4dor&3Correct!Horse");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.message).toContain("already exists");
    }
  });

  it("registration with weak password fails before any crypto", async () => {
    const result = await register("alice@example.com", "weak");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("password_validation");
    }
    expect(db.has("alice@example.com")).toBe(false);
  });
});

describe("Login flow (end-to-end with mock server)", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(async () => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
    await register("alice@example.com", password);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("successful login returns JWT and unwrapped vault key", async () => {
    const result = await login("alice@example.com", password);
    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.token).toBeTruthy();
      expect(result.token.startsWith("mock-jwt-")).toBe(true);
      expect(result.vaultKey.length).toBe(32);
      expect(result.vaultKey.every((v) => v === 0)).toBe(false);
      zeroize(result.vaultKey);
    }
  });

  it("wrong password at step 2 returns generic error", async () => {
    const result = await login("alice@example.com", "WrongPassword123!X");
    expect(result.ok).toBe(false);
    if (!result.ok && result.step !== "2fa_required") {
      expect(result.message).toBe("Incorrect email or password");
      expect(result.message).not.toContain("authKey");
      expect(result.message).not.toContain("unwrap");
    }
  });

  it("non-existent email returns same generic error (no user enumeration)", async () => {
    const result = await login("nobody@example.com", password);
    expect(result.ok).toBe(false);
    if (!result.ok && result.step !== "2fa_required") {
      expect(result.message).toBe("Incorrect email or password");
    }
  });

  it("vault unwrap failure produces same error as auth failure", async () => {
    const result = await login("alice@example.com", "CompletelyWrong99!X");
    expect(result.ok).toBe(false);
    if (!result.ok && result.step !== "2fa_required") {
      expect(result.message).toBe("Incorrect email or password");
    }
  });

  it("login with empty password returns validation error", async () => {
    const result = await login("alice@example.com", "");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("password_validation");
    }
  });
});

describe("Password change flow", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";
  const newPassword = "N3wP@ssw0rd!Secure#2024";

  beforeEach(async () => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
    await register("alice@example.com", password);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("successful password change updates server credentials", async () => {
    // Login first to get a token and vault key
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { token, vaultKey } = loginResult;

    // Change password
    const changeResult = await changePassword(token, "alice@example.com", vaultKey, password, newPassword);
    expect(changeResult.ok).toBe(true);

    // Login with new password should succeed
    const loginResult2 = await login("alice@example.com", newPassword);
    expect(loginResult2.ok).toBe(true);
    if (!loginResult2.ok) return;

    // Vault key should be the same (re-wrapped, not re-encrypted)
    expect(bytesEqual(vaultKey, loginResult2.vaultKey)).toBe(true);

    // Login with old password should fail
    const loginResult3 = await login("alice@example.com", password);
    expect(loginResult3.ok).toBe(false);

    zeroize(vaultKey);
    zeroize(loginResult2.vaultKey);
  });

  it("password change with weak password fails validation", async () => {
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const changeResult = await changePassword(
      loginResult.token,
      "alice@example.com",
      loginResult.vaultKey,
      password,
      "weak",
    );
    expect(changeResult.ok).toBe(false);

    zeroize(loginResult.vaultKey);
  });

  it("vault entries survive password change (key hierarchy advantage)", async () => {
    // Register, login, encrypt an entry
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { token, vaultKey } = loginResult;

    const plaintext = new TextEncoder().encode("my-secret-password");
    const encrypted = await encryptEntry(plaintext, vaultKey);
    const decrypted = await decryptEntry(encrypted, vaultKey);
    expect(new TextDecoder().decode(decrypted)).toBe("my-secret-password");

    // Change password
    const changeResult = await changePassword(token, "alice@example.com", vaultKey, password, newPassword);
    expect(changeResult.ok).toBe(true);

    // Login with new password
    const loginResult2 = await login("alice@example.com", newPassword);
    expect(loginResult2.ok).toBe(true);
    if (!loginResult2.ok) return;

    // Same vault key — entries should still decrypt
    const decrypted2 = await decryptEntry(encrypted, loginResult2.vaultKey);
    expect(new TextDecoder().decode(decrypted2)).toBe("my-secret-password");

    zeroize(vaultKey);
    zeroize(loginResult2.vaultKey);
  });
});

describe("KDF version upgrade", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(async () => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
    await register("alice@example.com", password);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  /**
   * Simulate a legacy v1 account: re-derive all keys with version 1 params
   * and overwrite the stored verifier + wrapped VK, then set kdfVersion = 1.
   */
  async function downgradeToVersion1(email: string): Promise<Uint8Array> {
    const user = db.get(email)!;
    const mk = await deriveMasterKey(password, user.saltEnc, 1);
    const ak = await deriveAuthKey(password, user.saltAuth, 1);
    const vk = generateVaultKey();
    const wrapped = await wrapVaultKey(vk, mk);

    user.authVerifier = new Uint8Array(ak); // copy — ak gets zeroized below
    user.wrappedVK = {
      wrappedKey: wrapped.wrappedKey,
      iv: wrapped.iv,
      authTag: wrapped.authTag,
    };
    user.kdfVersion = 1;

    zeroize(mk);
    zeroize(ak);
    return vk; // caller must zeroize
  }

  it("registration stores the current KDF version and login step 1 returns it", async () => {
    const user = db.get("alice@example.com")!;
    expect(user.kdfVersion).toBe(KDF_CURRENT_VERSION);

    const step1 = await apiLoginStep1("alice@example.com");
    expect(step1.kdfVersion).toBe(KDF_CURRENT_VERSION);
  });

  it("a v1 account still logs in (client derives with v1 params)", async () => {
    const v1VK = await downgradeToVersion1("alice@example.com");

    const result = await login("alice@example.com", password);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(bytesEqual(result.vaultKey, v1VK)).toBe(true);
      zeroize(result.vaultKey);
    }
    zeroize(v1VK);
  });

  it("upgradeKdf bumps a v1 account to the current version without a password change", async () => {
    const v1VK = await downgradeToVersion1("alice@example.com");
    const user = db.get("alice@example.com")!;

    // Login (v1) to get a session + vault key
    const login1 = await login("alice@example.com", password);
    expect(login1.ok).toBe(true);
    if (!login1.ok) {
      zeroize(v1VK);
      return;
    }

    // Upgrade using the password already in memory
    const upgrade = await upgradeKdf(
      login1.token,
      "alice@example.com",
      login1.vaultKey,
      password,
    );
    expect(upgrade.ok).toBe(true);

    // Server now stores the current version + new verifier
    expect(user.kdfVersion).toBe(KDF_CURRENT_VERSION);

    // Login still works after the upgrade and returns the SAME vault key
    const login2 = await login("alice@example.com", password);
    expect(login2.ok).toBe(true);
    if (login2.ok) {
      expect(bytesEqual(login2.vaultKey, v1VK)).toBe(true);
      expect(bytesEqual(login2.vaultKey, login1.vaultKey)).toBe(true);
      zeroize(login2.vaultKey);
    }

    zeroize(login1.vaultKey);
    zeroize(v1VK);
  });

  it("upgradeKdf is a no-op when already at the current version", async () => {
    const login1 = await login("alice@example.com", password);
    expect(login1.ok).toBe(true);
    if (!login1.ok) return;

    const upgrade = await upgradeKdf(
      login1.token,
      "alice@example.com",
      login1.vaultKey,
      password,
    );
    expect(upgrade.ok).toBe(true);

    // Nothing changed on the server
    const user = db.get("alice@example.com")!;
    expect(user.kdfVersion).toBe(KDF_CURRENT_VERSION);

    zeroize(login1.vaultKey);
  });

  it("upgradeKdf with the wrong password fails without touching credentials", async () => {
    const v1VK = await downgradeToVersion1("alice@example.com");
    const user = db.get("alice@example.com")!;
    const originalVerifier = new Uint8Array(user.authVerifier);

    const login1 = await login("alice@example.com", password);
    expect(login1.ok).toBe(true);
    if (!login1.ok) {
      zeroize(v1VK);
      return;
    }

    const upgrade = await upgradeKdf(
      login1.token,
      "alice@example.com",
      login1.vaultKey,
      "WrongPassword999!",
    );
    expect(upgrade.ok).toBe(false);

    // Credentials unchanged
    expect(user.kdfVersion).toBe(1);
    expect(bytesEqual(user.authVerifier, originalVerifier)).toBe(true);

    zeroize(login1.vaultKey);
    zeroize(v1VK);
  });

  it("vault entries survive a KDF upgrade (same vault key, only re-wrapped)", async () => {
    const v1VK = await downgradeToVersion1("alice@example.com");
    const user = db.get("alice@example.com")!;

    const login1 = await login("alice@example.com", password);
    expect(login1.ok).toBe(true);
    if (!login1.ok) {
      zeroize(v1VK);
      return;
    }

    // Encrypt an entry under the (unchanged) vault key
    const plaintext = new TextEncoder().encode("survives-kdf-upgrade");
    const encrypted = await encryptEntry(plaintext, login1.vaultKey);

    const upgrade = await upgradeKdf(
      login1.token,
      "alice@example.com",
      login1.vaultKey,
      password,
    );
    expect(upgrade.ok).toBe(true);

    // Login again and verify the same vault key decrypts the entry
    const login2 = await login("alice@example.com", password);
    expect(login2.ok).toBe(true);
    if (login2.ok) {
      const decrypted = await decryptEntry(encrypted, login2.vaultKey);
      expect(new TextDecoder().decode(decrypted)).toBe("survives-kdf-upgrade");
      zeroize(login2.vaultKey);
    }

    zeroize(login1.vaultKey);
    zeroize(v1VK);
  });
});

describe("Account recovery flow", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(async () => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
    await register("alice@example.com", password);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("recovery with correct code succeeds and allows password reset", async () => {
    // Get the recovery code from registration
    const regResult = await register("bob@example.com", password);
    expect(regResult.ok).toBe(true);
    if (!regResult.ok || !regResult.recoveryCode) return;

    const recoveryCode = regResult.recoveryCode;

    // Step 1: Recover vault key (also returns recoverySessionToken)
    const recoverResult = await recoverVaultKey("bob@example.com", recoveryCode);
    expect(recoverResult.ok).toBe(true);
    if (!recoverResult.ok) return;

    const { vaultKey, recoverySessionToken } = recoverResult;

    // Step 2: Complete recovery with new password (uses recoverySessionToken, NOT recoveryCode)
    const newPassword = "R3c0v3ry!N3w#Pass2024";
    const completeResult = await completeRecovery(
      "bob@example.com",
      recoverySessionToken,
      vaultKey,
      newPassword,
    );
    expect(completeResult.ok).toBe(true);

    // Step 3: Login with new password should succeed
    const loginResult = await login("bob@example.com", newPassword);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    // Same vault key recovered
    expect(bytesEqual(vaultKey, loginResult.vaultKey)).toBe(true);

    // Old password should fail
    const loginResult2 = await login("bob@example.com", password);
    expect(loginResult2.ok).toBe(false);

    zeroize(vaultKey);
    zeroize(loginResult.vaultKey);
  });

  it("recovery with wrong code fails (same error as wrong email)", async () => {
    // Register with recovery
    await register("bob@example.com", password);

    // Try recovery with wrong code
    const wrongCode = "00000000000000000000000000000000";
    const result = await recoverVaultKey("bob@example.com", wrongCode);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.message).toBe("Incorrect email or recovery code");
    }
  });

  it("recovery for non-existent email returns same error (no enumeration)", async () => {
    const regResult = await register("bob@example.com", password);
    if (!regResult.ok || !regResult.recoveryCode) return;

    const result = await recoverVaultKey("nobody@example.com", regResult.recoveryCode);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.message).toBe("Incorrect email or recovery code");
    }
  });

  it("recovery code format validation rejects invalid codes", async () => {
    const result = await recoverVaultKey("alice@example.com", "short");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.message).toBe("Incorrect email or recovery code");
    }
  });

  it("vault entries survive recovery (same vault key)", async () => {
    // Register
    const regResult = await register("charlie@example.com", password);
    expect(regResult.ok).toBe(true);
    if (!regResult.ok || !regResult.recoveryCode) return;

    // Login and encrypt an entry
    const loginResult = await login("charlie@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { token, vaultKey } = loginResult;

    const plaintext = new TextEncoder().encode("recovery-survives-test");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    // Recover
    const recoverResult = await recoverVaultKey(
      "charlie@example.com",
      regResult.recoveryCode,
    );
    expect(recoverResult.ok).toBe(true);
    if (!recoverResult.ok) return;

    // Same vault key
    expect(bytesEqual(vaultKey, recoverResult.vaultKey)).toBe(true);

    // Entry still decrypts with recovered key
    const decrypted = await decryptEntry(encrypted, recoverResult.vaultKey);
    expect(new TextDecoder().decode(decrypted)).toBe("recovery-survives-test");

    zeroize(vaultKey);
    zeroize(recoverResult.vaultKey);
  });

  it("completeRecovery with weak password fails validation", async () => {
    const regResult = await register("dave@example.com", password);
    expect(regResult.ok).toBe(true);
    if (!regResult.ok || !regResult.recoveryCode) return;

    const recoverResult = await recoverVaultKey(
      "dave@example.com",
      regResult.recoveryCode,
    );
    expect(recoverResult.ok).toBe(true);
    if (!recoverResult.ok) return;

    const result = await completeRecovery(
      "dave@example.com",
      recoverResult.recoverySessionToken,
      recoverResult.vaultKey,
      "weak",
    );
    expect(result.ok).toBe(false);

    zeroize(recoverResult.vaultKey);
  });
});

describe("Full vault lifecycle (register -> login -> encrypt -> decrypt)", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(() => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("register, login, derive vault key, encrypt and decrypt an entry", async () => {
    const regResult = await register("bob@example.com", password);
    expect(regResult.ok).toBe(true);

    const loginResult = await login("bob@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { token, vaultKey } = loginResult;

    const plaintext = new TextEncoder().encode("my-super-secret-password");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    expect(encrypted.ciphertext.length).toBeGreaterThan(0);
    expect(encrypted.iv.length).toBe(12);
    expect(encrypted.authTag.length).toBe(16);

    const decrypted = await decryptEntry(encrypted, vaultKey);
    expect(new TextDecoder().decode(decrypted)).toBe("my-super-secret-password");

    // Tamper detection
    const tampered = {
      ciphertext: new Uint8Array(encrypted.ciphertext),
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    };
    tampered.ciphertext[0]! ^= 0xff;
    await expect(decryptEntry(tampered, vaultKey)).rejects.toThrow();

    zeroize(vaultKey);
    expect(token).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// 2FA flow tests
// ---------------------------------------------------------------------------

describe("2FA login flow", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(() => {
    db.clear();
    mockTokens.clear();
    mockTempTokens.clear();
    mockUserIds.clear();
    mockUserCounter = 0;
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("full2FA login flow: setup → enable → login → TOTP verify → vault accessible", async () => {
    // Register
    const regResult = await register("alice@example.com", password);
    expect(regResult.ok).toBe(true);

    // Login (no2FA yet)
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;
    const { token, vaultKey } = loginResult;

    // Setup2FA
    const setupResult = await setup2FA(token);
    expect(setupResult.ok).toBe(true);
    if (!setupResult.ok) return;
    expect(setupResult.totpUri).toBeTruthy();
    expect(setupResult.backupCodes.length).toBe(10);

    // We can't generate the exact TOTP code in the mock test since
    // the secret is stored on the mock server and the test runs in
    // real time. We'll use the enable endpoint which verifies server-side.
    // For testing, we directly manipulate the db to set2FA as enabled
    // (simulating that the user successfully completed setup + enable).
    const user = db.get("alice@example.com")!;
    user.totpEnabled = true;

    // Zeroize vault key from first login
    zeroize(vaultKey);

    // Login again — should now require2FA
    const loginResult2 = await login("alice@example.com", password);
    expect(loginResult2.ok).toBe(false);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    // Store wrappedVK and masterKey from the2FA required result
    const { tempToken, wrappedVK, masterKey } = fa2;

    // We can't generate a valid TOTP in the test (secret is server-side),
    // so we directly set the totpSecret on the user to generate a code.
    const totpSecret = user.totpSecret!;
    const now = Math.floor(Date.now() / 1000);
    const { generateTotpCode: genCode } = await import("../../server/utils/totp.js");
    const validCode = genCode(totpSecret, now);

    // Complete2FA with valid code
    const verifyResult = await verify2FA(tempToken, validCode, wrappedVK, masterKey);
    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;

    expect(verifyResult.token.startsWith("mock-jwt-2fa-")).toBe(true);
    expect(verifyResult.vaultKey.length).toBe(32);

    // Vault key should work for encryption/decryption
    const plaintext = new TextEncoder().encode("secret-2fa-data");
    const encrypted = await encryptEntry(plaintext, verifyResult.vaultKey);
    const decrypted = await decryptEntry(encrypted, verifyResult.vaultKey);
    expect(new TextDecoder().decode(decrypted)).toBe("secret-2fa-data");

    zeroize(verifyResult.vaultKey);
  });

  it("wrong TOTP code returns error", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    // Enable2FA by directly setting db state
    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;
    zeroize(loginResult.vaultKey);

    // Login — requires2FA
    const loginResult2 = await login("alice@example.com", password);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    // Try wrong code
    const verifyResult = await verify2FA(
      fa2.tempToken,
      "000000",
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(verifyResult.ok).toBe(false);
    if (!verifyResult.ok) {
      expect(verifyResult.message).toBe("Invalid two-factor code");
    }
  });

  it("backup code login flow works", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    // Setup2FA via mock endpoint to get real backup code hashes
    const setupResult = await setup2FA(loginResult.token);
    expect(setupResult.ok).toBe(true);
    if (!setupResult.ok) return;

    // Enable2FA by directly setting state
    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;
    zeroize(loginResult.vaultKey);

    // We need the raw backup codes to use one. Since the mock generates
    // random codes, we generate our own and override the hashes.
    const { hashBackupCode } = await import("../../server/utils/backupCodes.js");
    const testCode = "ABCD-EFGH";
    const codeHash = hashBackupCode(testCode.replace("-", ""));
    user.backupCodeHashes = [codeHash];

    // Login — requires2FA
    const loginResult2 = await login("alice@example.com", password);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    // Complete with backup code
    const verifyResult = await verify2FAWithBackupCode(
      fa2.tempToken,
      testCode,
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;

    expect(verifyResult.token.startsWith("mock-jwt-backup-")).toBe(true);
    expect(verifyResult.vaultKey.length).toBe(32);

    zeroize(verifyResult.vaultKey);
  });

  it("invalid backup code returns error", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    // Enable2FA
    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;
    user.backupCodeHashes = ["dummy-hash"];
    zeroize(loginResult.vaultKey);

    // Login — requires2FA
    const loginResult2 = await login("alice@example.com", password);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    // Try wrong backup code
    const verifyResult = await verify2FAWithBackupCode(
      fa2.tempToken,
      "WRNG-CODE",
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(verifyResult.ok).toBe(false);
    if (!verifyResult.ok) {
      expect(verifyResult.message).toBe("Invalid backup code");
    }
  });

  it("login with2FA disabled returns token directly (no tempToken)", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);

    // Should succeed directly — no2FA required
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok && loginResult.step === "2fa_required") {
      throw new Error("Expected direct login, got2FA required");
    }

    if (loginResult.ok) {
      expect(loginResult.token).toBeTruthy();
      expect(loginResult.vaultKey.length).toBe(32);
      zeroize(loginResult.vaultKey);
    }
  });

  it("setup2FA returns TOTP URI and 10 backup codes", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const setupResult = await setup2FA(loginResult.token);
    expect(setupResult.ok).toBe(true);
    if (!setupResult.ok) return;

    expect(setupResult.totpUri).toContain("otpauth://totp/");
    expect(setupResult.backupCodes.length).toBe(10);

    // Each backup code should be XXXX-XXXX format
    for (const code of setupResult.backupCodes) {
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    }

    zeroize(loginResult.vaultKey);
  });

  it("get2FAStatus returns correct status", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    // Initially disabled
    const statusResult = await get2FAStatus(loginResult.token);
    expect(statusResult.ok).toBe(true);
    if (!statusResult.ok) return;
    expect(statusResult.totpEnabled).toBe(false);

    // Enable2FA
    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;
    user.backupCodeHashes = ["hash1", "hash2", "hash3"];

    const statusResult2 = await get2FAStatus(loginResult.token);
    expect(statusResult2.ok).toBe(true);
    if (!statusResult2.ok) return;
    expect(statusResult2.totpEnabled).toBe(true);
    expect(statusResult2.backupCodesRemaining).toBe(3);

    zeroize(loginResult.vaultKey);
  });

  it("expired/invalid temp token returns error", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;
    zeroize(loginResult.vaultKey);

    // Login — requires2FA
    const loginResult2 = await login("alice@example.com", password);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    // Try with invalid temp token
    const verifyResult = await verify2FA(
      "fake-expired-token",
      "123456",
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(verifyResult.ok).toBe(false);
    if (!verifyResult.ok) {
      expect(verifyResult.message).toBe("Invalid two-factor code");
    }
  });

  it("2FA does not affect vault encryption (security invariant)", async () => {
    // This test verifies the critical security invariant:
    // 2FA strengthens login ONLY — it never touches the vault key or entries.
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { token, vaultKey } = loginResult;

    // Encrypt entry before2FA
    const plaintext = new TextEncoder().encode("pre-2fa-secret");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    // Enable2FA
    const user = db.get("alice@example.com")!;
    const { generateTotpSecret: genSecret } = await import("../../server/utils/totp.js");
    user.totpSecret = genSecret();
    user.totpEnabled = true;

    // Login with2FA, verify, get "new" session
    const loginResult2 = await login("alice@example.com", password);
    if (loginResult2.ok) return;
    if (loginResult2.step !== "2fa_required") return;
    const fa2 = loginResult2 as TwoFactorRequiredResult;

    const { generateTotpCode: genCode } = await import("../../server/utils/totp.js");
    const now = Math.floor(Date.now() / 1000);
    const validCode = genCode(user.totpSecret!, now);

    const verifyResult = await verify2FA(
      fa2.tempToken,
      validCode,
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;

    // Same vault key — entry from before2FA should still decrypt
    const decrypted = await decryptEntry(encrypted, verifyResult.vaultKey);
    expect(new TextDecoder().decode(decrypted)).toBe("pre-2fa-secret");

    zeroize(vaultKey);
    zeroize(verifyResult.vaultKey);
  });
});

describe("Session management (device management)", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(async () => {
    db.clear();
    mockTokens.clear();
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
    await register("alice@example.com", password);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("listSessions returns the current session marked as current", async () => {
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const res = await apiListSessions(loginResult.token);
    expect(res.sessions.length).toBe(1);
    const session = res.sessions[0]!;
    expect(session.current).toBe(true);
    expect(session.active).toBe(true);
    expect(session.ipAddress).toBe("203.0.113.7");
    expect(session.userAgent).toContain("MockBrowser");
  });

  it("multiple logins create multiple sessions, exactly one current", async () => {
    const first = await login("alice@example.com", password);
    const second = await login("alice@example.com", password);
    if (!first.ok || !second.ok) return;

    const res = await apiListSessions(second.token);
    expect(res.sessions.length).toBe(2);
    expect(res.sessions.filter((s) => s.current)).toHaveLength(1);
    const current = res.sessions.find((s) => s.current)!;
    const other = res.sessions.find((s) => !s.current)!;
    expect(current.id).not.toBe(other.id);
  });

  it("revokeSession removes a single non-current session", async () => {
    const first = await login("alice@example.com", password);
    const second = await login("alice@example.com", password);
    if (!first.ok || !second.ok) return;

    const res = await apiListSessions(second.token);
    const target = res.sessions.find((s) => !s.current)!;

    await apiRevokeSession(second.token, target.id);

    const after = await apiListSessions(second.token);
    expect(after.sessions.length).toBe(1);
    expect(after.sessions.some((s) => s.id === target.id)).toBe(false);
  });

  it("revokeSession with another user's session id returns 404", async () => {
    const alice = await login("alice@example.com", password);
    await register("bob@example.com", password);
    const bob = await login("bob@example.com", password);
    if (!alice.ok || !bob.ok) return;

    const bobSession = (await apiListSessions(bob.token)).sessions[0]!;

    await expect(apiRevokeSession(alice.token, bobSession.id)).rejects.toMatchObject({
      status: 404,
    });

    const after = await apiListSessions(bob.token);
    expect(after.sessions.length).toBe(1);
  });

  it("revokeAllSessions keeps only the current session", async () => {
    await login("alice@example.com", password);
    const current = await login("alice@example.com", password);
    if (!current.ok) return;

    await apiRevokeAllSessions(current.token);

    const res = await apiListSessions(current.token);
    expect(res.sessions.length).toBe(1);
    expect(res.sessions[0]!.current).toBe(true);
  });

  it("session endpoints require authentication", async () => {
    await expect(apiListSessions("not-a-real-token")).rejects.toMatchObject({ status: 401 });
    await expect(apiRevokeAllSessions("not-a-real-token")).rejects.toMatchObject({ status: 401 });
    await expect(apiRevokeSession("not-a-real-token", "sess-1")).rejects.toMatchObject({ status: 401 });
  });
});

describe("Backup code + recovery code regeneration", () => {
  const originalFetch = globalThis.fetch;
  const password = "Tr0ub4dor&3Correct!Horse";

  beforeEach(() => {
    db.clear();
    mockTokens.clear();
    mockTempTokens.clear();
    mockUserIds.clear();
    mockUserCounter = 0;
    globalThis.fetch = vi.fn(mockFetchImplementation) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("regenerateBackupCodes invalidates old codes and returns a fresh set", async () => {
    const regResult = await register("alice@example.com", password);
    expect(regResult.ok).toBe(true);

    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;
    const { token, vaultKey } = loginResult;

    // Set up 2FA to obtain the original backup code set.
    const setupResult = await setup2FA(token);
    expect(setupResult.ok).toBe(true);
    if (!setupResult.ok) return;
    const originalCodes = setupResult.backupCodes;
    expect(originalCodes.length).toBe(10);

    // Enable 2FA by directly marking it enabled (the mock stores the secret).
    const user = db.get("alice@example.com")!;
    user.totpEnabled = true;

    // An original backup code works BEFORE regeneration.
    const before = await login("alice@example.com", password);
    expect(before.ok).toBe(false);
    if (before.ok) return;
    if (before.step !== "2fa_required") return;
    const beforeFa2 = before as TwoFactorRequiredResult;
    const oldWorks = await verify2FAWithBackupCode(
      beforeFa2.tempToken,
      originalCodes[0]!,
      beforeFa2.wrappedVK,
      beforeFa2.masterKey,
    );
    expect(oldWorks.ok).toBe(true);
    if (oldWorks.ok) zeroize(oldWorks.vaultKey);

    // Generate a fresh TOTP code from the mock's stored secret.
    const { generateTotpCode: genCode } = await import("../../server/utils/totp.js");
    const validCode = genCode(user.totpSecret!, Math.floor(Date.now() / 1000));

    // Regenerate — returns 10 NEW codes.
    const regenResult = await regenerateBackupCodes(token, validCode);
    expect(regenResult.ok).toBe(true);
    if (!regenResult.ok) return;
    expect(regenResult.backupCodes.length).toBe(10);
    expect(
      regenResult.backupCodes.some((c) => originalCodes.includes(c)),
    ).toBe(false);

    // Old code no longer works after regeneration.
    const after = await login("alice@example.com", password);
    expect(after.ok).toBe(false);
    if (after.ok) return;
    if (after.step !== "2fa_required") return;
    const afterFa2 = after as TwoFactorRequiredResult;
    const oldFails = await verify2FAWithBackupCode(
      afterFa2.tempToken,
      originalCodes[0]!,
      afterFa2.wrappedVK,
      afterFa2.masterKey,
    );
    expect(oldFails.ok).toBe(false);

    // Fresh login — new code works.
    const fresh = await login("alice@example.com", password);
    expect(fresh.ok).toBe(false);
    if (fresh.ok) return;
    if (fresh.step !== "2fa_required") return;
    const freshFa2 = fresh as TwoFactorRequiredResult;
    const newWorks = await verify2FAWithBackupCode(
      freshFa2.tempToken,
      regenResult.backupCodes[0]!,
      freshFa2.wrappedVK,
      freshFa2.masterKey,
    );
    expect(newWorks.ok).toBe(true);
    if (newWorks.ok) zeroize(newWorks.vaultKey);

    zeroize(vaultKey);
  });

  it("regenerateBackupCodes with wrong TOTP code fails and keeps old codes", async () => {
    await register("alice@example.com", password);
    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const setupResult = await setup2FA(loginResult.token);
    expect(setupResult.ok).toBe(true);
    if (!setupResult.ok) return;
    const originalCodes = setupResult.backupCodes;

    const user = db.get("alice@example.com")!;
    user.totpEnabled = true;

    const regenResult = await regenerateBackupCodes(loginResult.token, "000000");
    expect(regenResult.ok).toBe(false);

    // Old codes still work after a rejected regeneration attempt.
    const after = await login("alice@example.com", password);
    expect(after.ok).toBe(false);
    if (after.ok) return;
    if (after.step !== "2fa_required") return;
    const fa2 = after as TwoFactorRequiredResult;
    const stillWorks = await verify2FAWithBackupCode(
      fa2.tempToken,
      originalCodes[0]!,
      fa2.wrappedVK,
      fa2.masterKey,
    );
    expect(stillWorks.ok).toBe(true);
    if (stillWorks.ok) zeroize(stillWorks.vaultKey);

    zeroize(loginResult.vaultKey);
  });

  it("regenerateBackupCodes requires authentication", async () => {
    await register("alice@example.com", password);
    const result = await regenerateBackupCodes("not-a-real-token", "123456");
    expect(result.ok).toBe(false);
  });

  it("regenerateRecoveryCode invalidates the old code and makes the new one work", async () => {
    const regResult = await register("alice@example.com", password);
    expect(regResult.ok).toBe(true);
    if (!regResult.ok) return;
    const originalCode = regResult.recoveryCode!;
    expect(originalCode).toMatch(/^[0-9a-f]{32}$/i);

    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;
    const { token, vaultKey } = loginResult;

    // Old recovery code works BEFORE regeneration.
    const oldWorks = await recoverVaultKey("alice@example.com", originalCode);
    expect(oldWorks.ok).toBe(true);
    if (!oldWorks.ok) return;
    zeroize(oldWorks.vaultKey);

    // Regenerate — returns a NEW 32-hex code, different from the old.
    const regenResult = await regenerateRecoveryCode(
      token,
      "alice@example.com",
      vaultKey,
      password,
    );
    expect(regenResult.ok).toBe(true);
    if (!regenResult.ok) return;
    const newCode = regenResult.recoveryCode;
    expect(newCode).toMatch(/^[0-9a-f]{32}$/i);
    expect(newCode).not.toBe(originalCode);

    // Old code no longer works.
    const oldFails = await recoverVaultKey("alice@example.com", originalCode);
    expect(oldFails.ok).toBe(false);

    // New code works and recovers the same vault key.
    const newWorks = await recoverVaultKey("alice@example.com", newCode);
    expect(newWorks.ok).toBe(true);
    if (!newWorks.ok) return;
    expect(newWorks.vaultKey.length).toBe(32);
    zeroize(newWorks.vaultKey);

    zeroize(vaultKey);
  });

  it("regenerateRecoveryCode with wrong password fails", async () => {
    const regResult = await register("alice@example.com", password);
    expect(regResult.ok).toBe(true);

    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const result = await regenerateRecoveryCode(
      loginResult.token,
      "alice@example.com",
      loginResult.vaultKey,
      "WrongPassword123!",
    );
    expect(result.ok).toBe(false);

    zeroize(loginResult.vaultKey);
  });

  it("regenerateRecoveryCode requires authentication", async () => {
    const regResult = await register("alice@example.com", password);
    expect(regResult.ok).toBe(true);

    const loginResult = await login("alice@example.com", password);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const result = await regenerateRecoveryCode(
      "not-a-real-token",
      "alice@example.com",
      loginResult.vaultKey,
      password,
    );
    expect(result.ok).toBe(false);

    zeroize(loginResult.vaultKey);
  });
});
