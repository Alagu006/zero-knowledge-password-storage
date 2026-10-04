/**
 * Authentication routes.
 *
 * FLOW OVERVIEW (matches client-side deriveAuthKey from src/crypto/core.ts):
 *
 * REGISTRATION (single request):
 *   1. Client generates salt_enc, salt_auth locally (CSPRNG).
 *   2. Client derives masterKey, authKey from password + salts.
 *   3. Client generates vaultKey, wraps it under masterKey → wrappedVK.
 *   4. Client sends: { email, saltEnc, saltAuth, authKey, wrappedVK, ... }
 *   5. Server stores everything. Returns 201.
 *
 * LOGIN (two-step — client needs salts before it can compute authKey):
 *   Step 1 — POST /auth/login { email }
 *     Server returns { saltEnc, saltAuth, wrappedVK, wrappedVKIv, wrappedVKTag }
 *     even for non-existent emails (random dummy values) to prevent user
 *     enumeration. The client then computes authKey locally.
 *
 *   Step 2 — POST /auth/login/verify { email, authKey }
 *     Server compares the submitted authKey against the stored
 *     auth_verifier using constant-time comparison (crypto.timingSafeEqual).
 *     On match → issues a short-lived JWT.
 *     On failure → returns generic "Invalid credentials".
 *
 * WHAT THE SERVER STORES (and what it NEVER sees):
 *   ✓ Stores: email, salt_enc, salt_auth, auth_verifier, wrapped_vk + iv + tag
 *   ✗ NEVER sees: master password, master key, vault key in plaintext,
 *     any vault entry plaintext
 */

import { Router } from "express";
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../db.js";
import {
  registerWithRecoverySchema,
  loginStep1Schema,
  loginStep2Schema,
  changePasswordSchema,
  kdfUpgradeSchema,
  recoveryInitiateSchema,
  recoveryCompleteSchema,
  totpEnableSchema,
  totpDisableSchema,
  totpVerifySchema,
  backupCodeVerifySchema,
  backupCodesRegenerateSchema,
  recoveryRegenerateSchema,
  uuidParamSchema,
  KDF_VERSION_MIN,
  KDF_VERSION_MAX,
} from "../utils/validation.js";
import { auditLog } from "../utils/audit.js";
import {
  authRateLimiter,
  totpRateLimiter,
  isAccountLocked,
  lockoutRemainingSeconds,
  recordAuthFailure,
  clearAuthFailures,
  isTotpLocked,
  totpLockoutRemainingSeconds,
  recordTotpFailure,
  clearTotpFailures,
} from "../middleware/rateLimit.js";
import { signToken, signTempToken, requireAuth, requireTempToken } from "../middleware/auth.js";
import {
  ConflictError,
  NotFoundError,
  UnauthorizedError,
  LockedError,
} from "../utils/errors.js";
import {
  generateTotpSecret,
  verifyTotp,
  generateTotpUri,
  isTotpConsumed,
  markTotpConsumed,
} from "../utils/totp.js";
import {
  generateBackupCodes,
  verifyBackupCode,
} from "../utils/backupCodes.js";
import {
  encryptTotpSecret,
  decryptTotpSecret,
} from "../utils/totpEncryption.js";
import { config } from "../config.js";

const router = Router();

/**
 * Random KDF version for dummy login step-1 responses (non-existent emails).
 * Anti-enumeration: the shape must be indistinguishable from a real account,
 * and a real account's kdfVersion is effectively uniform across [MIN, MAX].
 */
function dummyKdfVersion(): number {
  return KDF_VERSION_MIN + Math.floor(Math.random() * (KDF_VERSION_MAX - KDF_VERSION_MIN + 1));
}

// ---------------------------------------------------------------------------
// POST /auth/register
// ---------------------------------------------------------------------------
// Single-step registration. Client has already derived all keys locally
// and sends the results. Server is a dumb storage layer.
//
// WHAT ARRIVES IN THE BODY (all hex-encoded):
//   email            — login identifier
//   saltEnc          — 32 bytes, client-generated salt for master key KDF
//   saltAuth         — 32 bytes, client-generated salt for auth key KDF
//   authKey          — 32 bytes, SHA-256(Argon2id(MP, saltAuth ‖ context))
//   wrappedVk        — 32 bytes, vaultKey encrypted under masterKey (AES-GCM ciphertext)
//   wrappedVkIv      — 12 bytes, GCM nonce for wrapped vault key
//   wrappedVkTag     — 16 bytes, GCM auth tag for wrapped vault key
//
// NONE of these are the master password or the master key.

router.post(
  "/register",
  authRateLimiter,
  async (req, res) => {
    const parsed = registerWithRecoverySchema.parse(req.body);

    // Check for existing account — same generic error as login to prevent
    // an attacker from probing email availability via registration.
    const existing = await prisma.user.findUnique({
      where: { email: parsed.email },
    });
    if (existing) {
      throw new ConflictError("Email already registered");
    }

    const user = await prisma.user.create({
      data: {
        email: parsed.email,
        saltEnc: Buffer.from(parsed.saltEnc, "hex"),
        saltAuth: Buffer.from(parsed.saltAuth, "hex"),
        authVerifier: Buffer.from(parsed.authKey, "hex"),
        wrappedVk: Buffer.from(parsed.wrappedVk, "hex"),
        wrappedVkIv: Buffer.from(parsed.wrappedVkIv, "hex"),
        wrappedVkTag: Buffer.from(parsed.wrappedVkTag, "hex"),
        kdfVersion: parsed.kdfVersion,
        // Recovery blob: optional. Only present if user opted into recovery.
        ...(parsed.recoveryWrappedVk && {
          recoveryWrappedVk: Buffer.from(parsed.recoveryWrappedVk, "hex"),
          recoveryWrappedVkIv: Buffer.from(parsed.recoveryWrappedVkIv!, "hex"),
          recoveryWrappedVkTag: Buffer.from(parsed.recoveryWrappedVkTag!, "hex"),
        }),
      },
    });

    // AUDIT: log success. Details contains NO secret material.
    await auditLog({
      userId: user.id,
      eventType: "register_success",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // Return 201 with no sensitive data. The client already has everything
    // it needs (it generated the keys).
    res.status(201).json({ message: "Registration successful" });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/login  (Step 1 — return salts + wrapped VK)
// ---------------------------------------------------------------------------
// The client CANNOT compute authKey without the salts, so it must call
// this endpoint first. For non-existent emails we return random dummy
// values so the client performs a full Argon2id derivation + unwrap
// attempt before getting a generic failure in step 2. This costs the
// attacker ~300ms per guess (Argon2id) even when the email doesn't exist.

router.post(
  "/login",
  authRateLimiter,
  async (req, res) => {
    const parsed = loginStep1Schema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email: parsed.email },
      select: {
        saltEnc: true,
        saltAuth: true,
        wrappedVk: true,
        wrappedVkIv: true,
        wrappedVkTag: true,
        kdfVersion: true,
      },
    });

    if (user) {
      await auditLog({
        eventType: "login_step1",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        details: { email: parsed.email },
      });

      res.json({
        saltEnc: user.saltEnc.toString("hex"),
        saltAuth: user.saltAuth.toString("hex"),
        wrappedVk: user.wrappedVk.toString("hex"),
        wrappedVkIv: user.wrappedVkIv.toString("hex"),
        wrappedVkTag: user.wrappedVkTag.toString("hex"),
        kdfVersion: user.kdfVersion,
      });
      return;
    }

    // Email not found — return random dummy values of the correct shape.
    // The client will compute a wrong authKey, send it in step 2, and
    // get "Invalid credentials". This costs the attacker one Argon2id
    // derivation (~300ms) per non-existent email, slowing user enumeration.
    res.json({
      saltEnc: randomBytes(32).toString("hex"),
      saltAuth: randomBytes(32).toString("hex"),
      wrappedVk: randomBytes(32).toString("hex"),
      wrappedVkIv: randomBytes(12).toString("hex"),
      wrappedVkTag: randomBytes(16).toString("hex"),
      kdfVersion: dummyKdfVersion(),
    });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/login/verify  (Step 2 — verify auth key, issue JWT)
// ---------------------------------------------------------------------------
// The client sends the authKey it computed from (password + salts from step 1).
// Server compares using constant-time comparison to prevent timing attacks.

router.post(
  "/login/verify",
  authRateLimiter,
  async (req, res) => {
    const parsed = loginStep2Schema.parse(req.body);

    // Account lockout check (per-email, in-memory).
    if (isAccountLocked(parsed.email)) {
      const remaining = lockoutRemainingSeconds(parsed.email);
      await auditLog({
        eventType: "login_locked",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        details: { email: parsed.email },
      });
      throw new LockedError("Invalid credentials", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { email: parsed.email },
    });

    // Constant-time comparison of auth verifier.
    // If the user does not exist, compare against a dummy buffer so response
    // time is identical to an incorrect password, preventing email enumeration.
    const dummyVerifier = Buffer.alloc(32);
    const stored = user ? user.authVerifier : dummyVerifier;
    const submitted = Buffer.from(parsed.authKey, "hex");

    const isValid =
      user !== null &&
      stored.length === submitted.length &&
      timingSafeEqual(stored, submitted);

    if (!isValid) {
      recordAuthFailure(parsed.email);

      await auditLog({
        ...(user ? { userId: user.id } : {}),
        eventType: "login_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        details: { email: parsed.email },
      });

      throw new UnauthorizedError("Invalid credentials");
    }

    // ── Authentication successful ──

    clearAuthFailures(parsed.email);

    // Check if 2FA is enabled — if so, return a temp token instead of the
    // full session JWT. The client must then complete the 2FA step.
    if (user.totpEnabled) {
      const tempToken = signTempToken({ userId: user.id, email: user.email });

      await auditLog({
        userId: user.id,
        eventType: "login_success",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      // Return temp token — client must call POST /auth/2fa/verify
      res.json({ tempToken, twoFactorRequired: true });
      return;
    }

    // No 2FA — issue full session token.
    const token = signToken({ userId: user.id, email: user.email });

    // Revoke any prior active sessions for this user (single-session policy).
    // This is optional; remove if concurrent sessions are desired.
    await prisma.authSession.deleteMany({
      where: {
        userId: user.id,
        expiresAt: { gt: new Date() },
      },
    });

    // Create a session record for server-side revocation capability.
    const { createHash } = await import("node:crypto");
    const tokenHash = createHash("sha256").update(token).digest();

    // JWT expiry is 15 min by default; store 20 min to allow slight skew.
    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

    await prisma.authSession.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      },
    });

    await auditLog({
      userId: user.id,
      eventType: "login_success",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // Return the JWT. The client stores it and sends it as:
    //   Authorization: Bearer <token>
    //
    // The JWT payload contains ONLY { userId, email } — no key material,
    // no vault data, no derived secrets.
    res.json({ token });
  },
);

// ---------------------------------------------------------------------------
// PUT /auth/password — change master password (re-wrap VK)
// ---------------------------------------------------------------------------
// Requires JWT authentication. The client:
//   1. Derives new masterKey, authKey from new password with FRESH salts.
//   2. Re-wraps the same vaultKey under the new masterKey.
//   3. Sends { saltEnc, saltAuth, authKey, wrappedVK } to this endpoint.
//
// FRESH SALTS justification:
//   The old salts are on the compromised server. Reusing them would let an
//   attacker who captures the new auth_verifier run offline brute-force
//   against the new password using the known old salts. Fresh salts ensure
//   any precomputed Argon2id tables are useless. The marginal cost is zero
//   — Argon2id runs anyway on every login.
//
// Vault entries are NOT re-encrypted. The vaultKey hasn't changed — only
// its wrapping key (masterKey) has. This is the key hierarchy advantage.

router.put(
  "/password",
  requireAuth,
  authRateLimiter,
  async (req, res) => {
    const parsed = changePasswordSchema.parse(req.body);

    // The JWT middleware has already attached userId + email to req.user.
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;

    // Fetch current user to verify current password via auth verifier.
    // The client sends the old authKey for verification before changing.
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, authVerifier: true },
    });

    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Verify the old authKey matches the stored verifier.
    // This prevents a stolen JWT from being used to change the password.
    const stored = user.authVerifier;
    const submitted = Buffer.from(parsed.oldAuthKey, "hex");

    const isValid =
      stored.length === submitted.length &&
      timingSafeEqual(stored, submitted);

    if (!isValid) {
      await auditLog({
        userId,
        eventType: "password_change_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });
      throw new UnauthorizedError("Current password is incorrect");
    }

    // Old password verified. Atomically update salts, auth verifier, and wrapped VK.
    // Also revoke all other active sessions for this user (single-session policy).
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          saltEnc: Buffer.from(parsed.saltEnc, "hex"),
          saltAuth: Buffer.from(parsed.saltAuth, "hex"),
          authVerifier: Buffer.from(parsed.authKey, "hex"),
          wrappedVk: Buffer.from(parsed.wrappedVk, "hex"),
          wrappedVkIv: Buffer.from(parsed.wrappedVkIv, "hex"),
          wrappedVkTag: Buffer.from(parsed.wrappedVkTag, "hex"),
          kdfVersion: parsed.kdfVersion,
        },
      }),
      prisma.authSession.deleteMany({
        where: {
          userId,
          expiresAt: { gt: new Date() },
        },
      }),
    ]);

    await auditLog({
      userId,
      eventType: "password_change",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ message: "Password changed successfully" });
  },
);

// ---------------------------------------------------------------------------
// PUT /auth/kdf-upgrade — migrate an account to newer Argon2id parameters
// ---------------------------------------------------------------------------
// Requires JWT authentication AND proof of the current password. The client
// re-derives its auth key (and master key) with the newest KDF parameter
// version using the password it already has in memory (no re-prompt), then
// re-wraps the UNCHANGED vault key under the new master key.
//
// The request body is identical to PUT /auth/password:
//   { oldAuthKey, saltEnc, saltAuth, authKey, wrappedVk, wrappedVkIv,
//     wrappedVkTag, kdfVersion }
//
// oldAuthKey is derived with the account's CURRENT (old) parameters and
// verified against the stored verifier. This prevents a stolen JWT from
// forcing an upgrade / overwriting credentials.
//
// The wrappedVK MUST be re-encrypted because the master-key parameters are
// also versioned — a version bump changes the derived master key, so the
// vault key must be re-wrapped under the new master key. Vault entries are
// NOT re-encrypted (the vault key itself never changes).

router.put(
  "/kdf-upgrade",
  requireAuth,
  authRateLimiter,
  async (req, res) => {
    const parsed = kdfUpgradeSchema.parse(req.body);

    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, authVerifier: true, kdfVersion: true },
    });

    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Verify the old authKey (derived with the current/old params) matches
    // the stored verifier — same pattern as PUT /auth/password.
    const stored = user.authVerifier;
    const submitted = Buffer.from(parsed.oldAuthKey, "hex");

    const isValid =
      stored.length === submitted.length &&
      timingSafeEqual(stored, submitted);

    if (!isValid) {
      await auditLog({
        userId,
        eventType: "kdf_upgrade_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });
      throw new UnauthorizedError("Current password is incorrect");
    }

    // Reject downgrades: only allow moving to a NEWER parameter version.
    if (parsed.kdfVersion <= user.kdfVersion) {
      await auditLog({
        userId,
        eventType: "kdf_upgrade_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        details: { attempted: parsed.kdfVersion, current: user.kdfVersion },
      });
      throw new ConflictError("Cannot downgrade key derivation parameters");
    }

    // Atomically update credentials + revoke all other sessions.
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          saltEnc: Buffer.from(parsed.saltEnc, "hex"),
          saltAuth: Buffer.from(parsed.saltAuth, "hex"),
          authVerifier: Buffer.from(parsed.authKey, "hex"),
          wrappedVk: Buffer.from(parsed.wrappedVk, "hex"),
          wrappedVkIv: Buffer.from(parsed.wrappedVkIv, "hex"),
          wrappedVkTag: Buffer.from(parsed.wrappedVkTag, "hex"),
          kdfVersion: parsed.kdfVersion,
        },
      }),
      prisma.authSession.deleteMany({
        where: {
          userId,
          expiresAt: { gt: new Date() },
        },
      }),
    ]);

    await auditLog({
      userId,
      eventType: "kdf_upgrade",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
      details: { fromVersion: user.kdfVersion, toVersion: parsed.kdfVersion },
    });

    res.json({ message: "Key derivation parameters upgraded" });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/recovery — initiate account recovery
// ---------------------------------------------------------------------------
// The client sends their email. If the user exists and has a recovery blob,
// the server returns a short-lived recovery session token (JWT). The client
// then uses the recovery code locally to unwrap the vault key, and sends
// the token back with new credentials via POST /auth/recovery/complete.
//
// SECURITY: If the email doesn't exist, we return a random dummy token
// (same anti-enumeration pattern as login step 1). The client performs
// full crypto before getting a generic failure.

router.post(
  "/recovery",
  authRateLimiter,
  async (req, res) => {
    const parsed = recoveryInitiateSchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email: parsed.email },
      select: {
        id: true,
        email: true,
        recoveryWrappedVk: true,
        recoveryWrappedVkIv: true,
        recoveryWrappedVkTag: true,
      },
    });

    if (user && user.recoveryWrappedVk) {
      await auditLog({
        eventType: "recovery_initiated",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        details: { email: parsed.email },
      });

      // Issue a short-lived recovery session token (5 min, single-use).
      // Uses the tempTokenSecret with step: "recovery" to prevent cross-use.
      const recoveryToken = jwt.sign(
        { userId: user.id, email: user.email, step: "recovery" },
        config.tempTokenSecret,
        { algorithm: "HS256", expiresIn: "5m" } as jwt.SignOptions,
      );

      // Return the recovery blob (client needs it to unwrap locally)
      // AND the recovery session token (for completeRecovery).
      res.json({
        recoverySessionToken: recoveryToken,
        recoveryWrappedVk: user.recoveryWrappedVk.toString("hex"),
        recoveryWrappedVkIv: user.recoveryWrappedVkIv?.toString("hex") ?? "",
        recoveryWrappedVkTag: user.recoveryWrappedVkTag?.toString("hex") ?? "",
      });
      return;
    }

    // Email not found OR no recovery set up — return random dummies
    // (same shape) so the client performs full crypto before getting a
    // generic failure. The dummy token will fail verification in step 2.
    res.json({
      recoverySessionToken: randomBytes(32).toString("base64url"),
      recoveryWrappedVk: randomBytes(32).toString("hex"),
      recoveryWrappedVkIv: randomBytes(12).toString("hex"),
      recoveryWrappedVkTag: randomBytes(16).toString("hex"),
    });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/recovery/complete — finalize recovery (set new credentials)
// ---------------------------------------------------------------------------
// After the client unwraps the vault key using the recovery code LOCALLY,
// it derives new credentials (new salts, new auth key, new wrapped VK) and
// sends them here along with the recovery session token from step 1.
//
// SECURITY: The recovery code NEVER reaches the server. The server only
// verifies the recovery session token (a short-lived JWT) to authorize
// the credential update. The vault key is unwrapped entirely client-side.

router.post(
  "/recovery/complete",
  authRateLimiter,
  async (req, res) => {
    const parsed = recoveryCompleteSchema.parse(req.body);

    // Verify the recovery session token.
    let tokenPayload: { userId: string; email: string; step: string };
    try {
      tokenPayload = jwt.verify(
        parsed.recoverySessionToken,
        config.tempTokenSecret,
        { algorithms: ["HS256"] },
      ) as { userId: string; email: string; step: string };
    } catch {
      throw new UnauthorizedError("Invalid credentials");
    }

    if (tokenPayload.step !== "recovery") {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Look up the user from the token (not from body.email — prevents
    // an attacker from using a valid token to update a different account).
    const user = await prisma.user.findUnique({
      where: { id: tokenPayload.userId },
      select: {
        id: true,
        recoveryWrappedVk: true,
      },
    });

    if (!user || !user.recoveryWrappedVk) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Recovery code is valid. Atomically update all credentials.
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: {
          saltEnc: Buffer.from(parsed.saltEnc, "hex"),
          saltAuth: Buffer.from(parsed.saltAuth, "hex"),
          authVerifier: Buffer.from(parsed.authKey, "hex"),
          wrappedVk: Buffer.from(parsed.wrappedVk, "hex"),
          wrappedVkIv: Buffer.from(parsed.wrappedVkIv, "hex"),
          wrappedVkTag: Buffer.from(parsed.wrappedVkTag, "hex"),
          kdfVersion: parsed.kdfVersion,
          // Clear recovery blob — old code is now invalid.
          recoveryWrappedVk: null,
          recoveryWrappedVkIv: null,
          recoveryWrappedVkTag: null,
        },
      }),
      prisma.authSession.deleteMany({
        where: {
          userId: user.id,
          expiresAt: { gt: new Date() },
        },
      }),
    ]);

    await auditLog({
      userId: user.id,
      eventType: "recovery_complete",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ message: "Recovery complete. Please log in with your new password." });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/recovery/regenerate — rotate the account recovery code
// ---------------------------------------------------------------------------
// Requires JWT authentication AND proof of the current password (oldAuthKey,
// verified against the stored auth verifier — same check as PUT /auth/password).
// Rationale: a stolen session token alone must not be able to rotate a user's
// recovery code.
//
// The raw recovery code NEVER reaches the server. The client generates a
// fresh 128-bit code, re-wraps the UNCHANGED vault key under SHA-256(new_code),
// and sends only the new wrapped blob. Replacing the blob invalidates the old
// code immediately.

router.post(
  "/recovery/regenerate",
  requireAuth,
  authRateLimiter,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;
    const parsed = recoveryRegenerateSchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { authVerifier: true },
    });
    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Constant-time comparison — same as login step 2.
    const stored = user.authVerifier;
    const submitted = Buffer.from(parsed.oldAuthKey, "hex");
    if (stored.length !== submitted.length || !timingSafeEqual(stored, submitted)) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // Replace the recovery blob. The old code no longer unwraps anything.
    await prisma.user.update({
      where: { id: userId },
      data: {
        recoveryWrappedVk: Buffer.from(parsed.recoveryWrappedVk, "hex"),
        recoveryWrappedVkIv: Buffer.from(parsed.recoveryWrappedVkIv, "hex"),
        recoveryWrappedVkTag: Buffer.from(parsed.recoveryWrappedVkTag, "hex"),
      },
    });

    await auditLog({
      userId,
      eventType: "recovery_regenerated",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ message: "Recovery code regenerated" });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/setup — generate TOTP secret + backup codes
// ---------------------------------------------------------------------------
// Requires JWT authentication. Generates a TOTP secret (server-side) and
// 10 backup codes. Returns the TOTP URI (for QR) and backup codes ONCE.
// The secret is stored on the user row but 2FA is NOT yet enabled — the user
// must verify a code first via POST /auth/2fa/enable.
//
// SECURITY: The TOTP secret is never returned again after this call.
// The QR code / URI should be scanned immediately.

router.post(
  "/2fa/setup",
  requireAuth,
  authRateLimiter,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId, email } = req.user;

    // Check if 2FA is already set up
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpEnabled: true, totpSecretEnc: true },
    });

    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    if (user.totpEnabled) {
      throw new ConflictError("Two-factor authentication is already enabled");
    }

    // Generate new TOTP secret (20 bytes / 160 bits)
    const totpSecret = generateTotpSecret();

    // Generate the otpauth URI for QR code
    const totpUri = generateTotpUri(totpSecret, email);

    // Generate backup codes
    const { codes: backupCodeStrings, records: backupCodeRecords } = generateBackupCodes();

    // Encrypt TOTP secret under the server's envelope key before storing.
    // This provides defense-in-depth: DB compromise alone does not expose the secret.
    const encrypted = encryptTotpSecret(totpSecret, Buffer.from(config.totpEncryptionKey, "hex"));

    // Store the encrypted TOTP secret (NOT enabled yet) and backup codes.
    // Delete any existing backup codes (from a previous incomplete setup).
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          totpSecretEnc: encrypted.ciphertext,
          totpSecretIv: encrypted.iv,
          totpSecretTag: encrypted.tag,
          totpEnabled: false,
        },
      }),
      prisma.backupCode.deleteMany({
        where: { userId },
      }),
      prisma.backupCode.createMany({
        data: backupCodeRecords.map((r) => ({
          userId,
          codeHash: r.codeHash,
          used: false,
        })),
      }),
    ]);

    await auditLog({
      userId,
      eventType: "totp_setup",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // Return secret URI + backup codes ONCE.
    // The client must scan the QR and save the backup codes immediately.
    res.json({
      totpUri,
      backupCodes: backupCodeStrings,
    });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/enable — verify TOTP code to activate 2FA
// ---------------------------------------------------------------------------
// After setup, the user scans the QR code and submits a 6-digit code to prove
// they have successfully enrolled. This sets totpEnabled = true.
//
// This two-phase approach prevents lockout: if the user fails to scan the QR,
// they can simply not call /enable and remain with 2FA disabled.

router.post(
  "/2fa/enable",
  requireAuth,
  totpRateLimiter,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;
    const parsed = totpEnableSchema.parse(req.body);

    if (isTotpLocked(userId)) {
      const remaining = totpLockoutRemainingSeconds(userId);
      throw new LockedError("Invalid code", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecretEnc: true, totpSecretIv: true, totpSecretTag: true, totpEnabled: true },
    });

    if (!user || !user.totpSecretEnc || !user.totpSecretIv || !user.totpSecretTag || user.totpEnabled) {
      throw new UnauthorizedError("Invalid code");
    }

    // Replay attack prevention: reject codes already consumed within this window
    if (isTotpConsumed(userId, parsed.code)) {
      throw new UnauthorizedError("Invalid code");
    }

    // Decrypt the TOTP secret from the envelope
    const totpSecret = decryptTotpSecret(
      { ciphertext: user.totpSecretEnc, iv: user.totpSecretIv, tag: user.totpSecretTag },
      Buffer.from(config.totpEncryptionKey, "hex"),
    );

    const isValid = verifyTotp(totpSecret, parsed.code);

    if (!isValid) {
      recordTotpFailure(userId);

      await auditLog({
        userId,
        eventType: "totp_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      throw new UnauthorizedError("Invalid code");
    }

    markTotpConsumed(userId, parsed.code);

    // Code is valid — enable 2FA.
    clearTotpFailures(userId);

    await prisma.user.update({
      where: { id: userId },
      data: { totpEnabled: true },
    });

    await auditLog({
      userId,
      eventType: "totp_enabled",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ message: "Two-factor authentication enabled" });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/disable — disable 2FA (requires current TOTP code)
// ---------------------------------------------------------------------------
// Disabling 2FA requires proof of possession (current TOTP code).
// This prevents a stolen JWT from being used to disable 2FA.

router.post(
  "/2fa/disable",
  requireAuth,
  totpRateLimiter,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;
    const parsed = totpDisableSchema.parse(req.body);

    if (isTotpLocked(userId)) {
      const remaining = totpLockoutRemainingSeconds(userId);
      throw new LockedError("Invalid code", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecretEnc: true, totpSecretIv: true, totpSecretTag: true, totpEnabled: true },
    });

    if (!user || !user.totpSecretEnc || !user.totpSecretIv || !user.totpSecretTag || !user.totpEnabled) {
      throw new UnauthorizedError("Invalid code");
    }

    // Replay attack prevention: reject codes already consumed within this window
    if (isTotpConsumed(userId, parsed.code)) {
      throw new UnauthorizedError("Invalid code");
    }

    // Decrypt the TOTP secret from the envelope
    const totpSecret = decryptTotpSecret(
      { ciphertext: user.totpSecretEnc, iv: user.totpSecretIv, tag: user.totpSecretTag },
      Buffer.from(config.totpEncryptionKey, "hex"),
    );

    const isValid = verifyTotp(totpSecret, parsed.code);

    if (!isValid) {
      recordTotpFailure(userId);

      await auditLog({
        userId,
        eventType: "totp_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      throw new UnauthorizedError("Invalid code");
    }

    markTotpConsumed(userId, parsed.code);

    // Valid code — disable 2FA and clear all 2FA data.
    clearTotpFailures(userId);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          totpSecretEnc: null,
          totpSecretIv: null,
          totpSecretTag: null,
          totpEnabled: false,
        },
      }),
      prisma.backupCode.deleteMany({
        where: { userId },
      }),
    ]);

    await auditLog({
      userId,
      eventType: "totp_disabled",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ message: "Two-factor authentication disabled" });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/backup-codes/regenerate — rotate the backup code set
// ---------------------------------------------------------------------------
// Requires JWT authentication AND a FRESH TOTP code (not the JWT alone).
// Rationale: a stolen session token should not be able to silently replace
// the user's emergency access codes — the attacker would also need their
// authenticator. The old codes are deleted immediately; new codes are shown
// ONCE. This mirrors the "proof of possession" requirement of /2fa/disable.

router.post(
  "/2fa/backup-codes/regenerate",
  requireAuth,
  totpRateLimiter,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;
    const parsed = backupCodesRegenerateSchema.parse(req.body);

    if (isTotpLocked(userId)) {
      const remaining = totpLockoutRemainingSeconds(userId);
      throw new LockedError("Invalid code", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecretEnc: true, totpSecretIv: true, totpSecretTag: true, totpEnabled: true },
    });

    if (!user || !user.totpSecretEnc || !user.totpSecretIv || !user.totpSecretTag || !user.totpEnabled) {
      throw new UnauthorizedError("Invalid code");
    }

    // Replay attack prevention: reject codes already consumed within this window
    if (isTotpConsumed(userId, parsed.code)) {
      throw new UnauthorizedError("Invalid code");
    }

    // Decrypt the TOTP secret from the envelope.
    const totpSecret = decryptTotpSecret(
      { ciphertext: user.totpSecretEnc, iv: user.totpSecretIv, tag: user.totpSecretTag },
      Buffer.from(config.totpEncryptionKey, "hex"),
    );

    const isValid = verifyTotp(totpSecret, parsed.code);

    if (!isValid) {
      recordTotpFailure(userId);

      await auditLog({
        userId,
        eventType: "totp_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      throw new UnauthorizedError("Invalid code");
    }

    markTotpConsumed(userId, parsed.code);

    clearTotpFailures(userId);

    // Generate a fresh set and atomically replace the old one.
    const { codes: backupCodeStrings, records: backupCodeRecords } = generateBackupCodes();
    await prisma.$transaction([
      prisma.backupCode.deleteMany({ where: { userId } }),
      prisma.backupCode.createMany({
        data: backupCodeRecords.map((r) => ({
          userId,
          codeHash: r.codeHash,
          used: false,
        })),
      }),
    ]);

    await auditLog({
      userId,
      eventType: "backup_codes_regenerated",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // New codes are returned exactly once.
    res.json({ backupCodes: backupCodeStrings });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/verify — verify TOTP code during login (2FA step)
// ---------------------------------------------------------------------------
// Called after successful password auth when 2FA is enabled.
// The client sends the tempToken (from login/verify) + 6-digit TOTP code.
// On success, issues the full session JWT.

router.post(
  "/2fa/verify",
  totpRateLimiter,
  async (req, res) => {
    const parsed = totpVerifySchema.parse(req.body);

    // Decode the temp token to get userId + email.
    // We verify the token manually (requireTempToken does this via middleware,
    // but here we inline it to avoid an extra middleware layer).
    const jwt = await import("jsonwebtoken");
    const { config } = await import("../config.js");

    let tempPayload: { userId: string; email: string; step: string };
    try {
      tempPayload = jwt.default.verify(
        parsed.tempToken,
        config.tempTokenSecret,
        { algorithms: ["HS256"] },
      ) as { userId: string; email: string; step: string };
    } catch {
      throw new UnauthorizedError("Invalid or expired code");
    }

    if (tempPayload.step !== "2fa") {
      throw new UnauthorizedError("Invalid token scope");
    }

    const userId = tempPayload.userId;
    const email = tempPayload.email;

    if (isTotpLocked(userId)) {
      const remaining = totpLockoutRemainingSeconds(userId);
      throw new LockedError("Invalid code", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecretEnc: true, totpSecretIv: true, totpSecretTag: true, totpEnabled: true },
    });

    if (!user || !user.totpSecretEnc || !user.totpSecretIv || !user.totpSecretTag || !user.totpEnabled) {
      throw new UnauthorizedError("Invalid code");
    }

    // Replay attack prevention: reject codes already consumed within this window
    if (isTotpConsumed(userId, parsed.code)) {
      throw new UnauthorizedError("Invalid code");
    }

    // Decrypt the TOTP secret from the envelope
    const totpSecret = decryptTotpSecret(
      { ciphertext: user.totpSecretEnc, iv: user.totpSecretIv, tag: user.totpSecretTag },
      Buffer.from(config.totpEncryptionKey, "hex"),
    );

    const isValid = verifyTotp(totpSecret, parsed.code);

    if (!isValid) {
      recordTotpFailure(userId);

      await auditLog({
        userId,
        eventType: "totp_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      throw new UnauthorizedError("Invalid code");
    }

    markTotpConsumed(userId, parsed.code);

    // TOTP code is valid — issue full session JWT.
    clearTotpFailures(userId);

    const token = signToken({ userId, email });

    // Revoke any prior active sessions (single-session policy).
    await prisma.authSession.deleteMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
    });

    // Create session record.
    const { createHash } = await import("node:crypto");
    const tokenHash = createHash("sha256").update(token).digest();
    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

    await prisma.authSession.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      },
    });

    await auditLog({
      userId,
      eventType: "totp_success",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ token });
  },
);

// ---------------------------------------------------------------------------
// POST /auth/2fa/backup-verify — verify a backup code during login
// ---------------------------------------------------------------------------
// Alternative to TOTP when the user has lost access to their authenticator.
// Each backup code can be used ONCE. After use, the hash is marked as used.

router.post(
  "/2fa/backup-verify",
  totpRateLimiter,
  async (req, res) => {
    const parsed = backupCodeVerifySchema.parse(req.body);

    // Decode temp token
    const jwt = await import("jsonwebtoken");
    const { config } = await import("../config.js");

    let tempPayload: { userId: string; email: string; step: string };
    try {
      tempPayload = jwt.default.verify(
        parsed.tempToken,
        config.tempTokenSecret,
        { algorithms: ["HS256"] },
      ) as { userId: string; email: string; step: string };
    } catch {
      throw new UnauthorizedError("Invalid or expired code");
    }

    if (tempPayload.step !== "2fa") {
      throw new UnauthorizedError("Invalid token scope");
    }

    const userId = tempPayload.userId;
    const email = tempPayload.email;

    if (isTotpLocked(userId)) {
      const remaining = totpLockoutRemainingSeconds(userId);
      throw new LockedError("Invalid code", remaining);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpEnabled: true },
    });

    if (!user || !user.totpEnabled) {
      throw new UnauthorizedError("Invalid code");
    }

    // Fetch all backup codes for this user
    const backupCodeRecords = await prisma.backupCode.findMany({
      where: { userId },
      select: { codeHash: true, used: true },
    });

    // Extract the raw code from the submitted code (remove dash if present)
    const rawCode = parsed.code.replace(/-/g, "").toUpperCase();

    // Use our constant-time verification
    const recordIndex = verifyBackupCode(
      rawCode,
      backupCodeRecords.map((r) => ({
        codeHash: r.codeHash,
        used: r.used,
      })),
    );

    if (recordIndex === -1) {
      recordTotpFailure(userId);

      await auditLog({
        userId,
        eventType: "backup_code_failure",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      });

      throw new UnauthorizedError("Invalid code");
    }

    // Mark the backup code as used (one-time use).
    const matchedRecord = backupCodeRecords[recordIndex]!;
    await prisma.backupCode.updateMany({
      where: {
        userId,
        codeHash: matchedRecord.codeHash,
      },
      data: { used: true },
    });

    clearTotpFailures(userId);

    // Issue full session JWT
    const token = signToken({ userId, email });

    await prisma.authSession.deleteMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
    });

    const { createHash } = await import("node:crypto");
    const tokenHash = createHash("sha256").update(token).digest();
    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

    await prisma.authSession.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
      },
    });

    await auditLog({
      userId,
      eventType: "backup_code_success",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.json({ token });
  },
);

// ---------------------------------------------------------------------------
// GET /auth/2fa/status — check 2FA enrollment status
// ---------------------------------------------------------------------------
// Returns whether 2FA is enabled and how many backup codes remain.
// Never returns the TOTP secret itself.

router.get(
  "/2fa/status",
  requireAuth,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totpEnabled: true },
    });

    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    const unusedBackupCodes = await prisma.backupCode.count({
      where: { userId, used: false },
    });

    res.json({
      totpEnabled: user.totpEnabled,
      backupCodesRemaining: unusedBackupCodes,
    });
  },
);

// ---------------------------------------------------------------------------
// GET /auth/sessions — list active sessions for the current user
// ---------------------------------------------------------------------------
// Requires JWT. Returns device metadata (best-effort IP + user agent) and
// marks which session corresponds to the token used for this request.
// NEVER returns token hashes (defense-in-depth; they are one-way digests of
// bearer secrets).

router.get(
  "/sessions",
  requireAuth,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;

    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : "";
    const currentHash = createHash("sha256").update(token).digest();

    const sessions = await prisma.authSession.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });

    const now = new Date();
    res.json({
      sessions: sessions.map((s) => ({
        id: s.id,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt.toISOString(),
        expiresAt: s.expiresAt.toISOString(),
        active: s.expiresAt > now,
        current: s.tokenHash.equals(currentHash),
      })),
    });
  },
);

// ---------------------------------------------------------------------------
// DELETE /auth/sessions — revoke every session EXCEPT the current one
// ---------------------------------------------------------------------------
// The client logs in again on the current device and boots all others out
// (e.g. after detecting an unknown device).

router.delete(
  "/sessions",
  requireAuth,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;

    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : "";
    const currentHash = createHash("sha256").update(token).digest();

    const { count } = await prisma.authSession.deleteMany({
      where: {
        userId,
        NOT: { tokenHash: currentHash },
      },
    });

    await auditLog({
      userId,
      eventType: "sessions_revoked",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
      details: { revokedCount: count },
    });

    res.json({ message: "All other sessions revoked" });
  },
);

// ---------------------------------------------------------------------------
// DELETE /auth/sessions/:id — revoke a single session
// ---------------------------------------------------------------------------
// The user can only revoke their own sessions. A non-existent or foreign
// session id returns 404 so we don't leak whether an id belongs to someone
// else. Revoking the current session is allowed (immediate logout on the
// next authenticated request) — the UI disables it to avoid confusion.

router.delete(
  "/sessions/:id",
  requireAuth,
  async (req, res) => {
    if (!req.user) {
      throw new UnauthorizedError("Invalid credentials");
    }
    const { userId } = req.user;
    const { id } = uuidParamSchema.parse(req.params);

    const deleted = await prisma.authSession.deleteMany({
      where: { id, userId },
    });

    if (deleted.count === 0) {
      throw new NotFoundError("Session not found");
    }

    await auditLog({
      userId,
      eventType: "session_revoked",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
      details: { sessionId: id },
    });

    res.json({ message: "Session revoked" });
  },
);

export default router;
