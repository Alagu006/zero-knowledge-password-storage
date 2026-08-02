/**
 * Rate limiting and account lockout.
 *
 * TWO layers of protection against online brute-force:
 *
 * 1. IP-level rate limiting (express-rate-limit):
 *    - 10 requests per 15-minute window per IP address.
 *    - Prevents a single attacker from flooding the auth endpoints.
 *    - Returns 429 with Retry-After header.
 *
 * 2. Per-account lockout (in-memory Map):
 *    - After 5 consecutive failed login attempts for the same email,
 *      the account is locked for 15 minutes.
 *    - Lockout is email-based, so even if the attacker uses different IPs,
 *      the target account is protected.
 *    - In-memory: resets on server restart. For multi-node deployments,
 *      replace with Redis-backed counter.
 *
 * BOTH layers use the same generic "Invalid credentials" response to prevent
 * the attacker from distinguishing between "email not found" and "wrong
 * password" and "account locked". The Retry-After header on 421/429 is the
 * only signal, and it's a standard HTTP mechanism.
 */

import rateLimit from "express-rate-limit";
import { config } from "../config.js";

// ---------------------------------------------------------------------------
// 1. IP-level rate limiter (express-rate-limit)
// ---------------------------------------------------------------------------

export const authRateLimiter = rateLimit({
  windowMs: config.authRateLimit.windowMs,
  max: config.authRateLimit.max,
  standardHeaders: true,   // RateLimit-* headers (draft-6)
  legacyHeaders: false,    // Disable X-RateLimit-* headers
  keyGenerator: (req) => {
    // Use X-Forwarded-For only when Express trust proxy is enabled
    // (i.e., running behind a reverse proxy like nginx/ALB).
    // Without trust proxy, the header is untrusted and could be spoofed.
    if (req.app.get("trust proxy")) {
      return (
        (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ??
        req.ip ??
        "unknown"
      );
    }
    return req.ip ?? "unknown";
  },
  handler: (_req, res) => {
    res.status(429).json({
      error: "Too many requests, please try again later",
    });
  },
});

// ---------------------------------------------------------------------------
// 2. Per-account lockout (in-memory)
// ---------------------------------------------------------------------------

interface LockoutRecord {
  failures: number;
  lockedUntil: number; // epoch ms; 0 = not locked
}

const lockoutStore = new Map<string, LockoutRecord>();

/** Purge expired entries periodically to prevent unbounded memory growth. */
setInterval(() => {
  const now = Date.now();
  for (const [email, record] of lockoutStore) {
    if (record.lockedUntil > 0 && now > record.lockedUntil) {
      lockoutStore.delete(email);
    } else if (record.failures === 0) {
      lockoutStore.delete(email);
    }
  }
}, 60_000).unref(); // runs every 60s, doesn't keep the event loop alive

/**
 * Check whether the given account is currently locked out.
 * Returns `true` if locked, `false` if the account can accept attempts.
 */
export function isAccountLocked(email: string): boolean {
  const record = lockoutStore.get(email);
  if (!record) return false;
  if (record.lockedUntil === 0) return false;
  if (Date.now() >= record.lockedUntil) {
    // Lockout expired — clear it.
    lockoutStore.delete(email);
    return false;
  }
  return true;
}

/** Get remaining lockout seconds (for Retry-After header). */
export function lockoutRemainingSeconds(email: string): number {
  const record = lockoutStore.get(email);
  if (!record || record.lockedUntil === 0) return 0;
  return Math.max(0, Math.ceil((record.lockedUntil - Date.now()) / 1000));
}

/** Record a failed authentication attempt. May trigger lockout. */
export function recordAuthFailure(email: string): void {
  const existing = lockoutStore.get(email) ?? { failures: 0, lockedUntil: 0 };
  existing.failures += 1;

  if (existing.failures >= config.accountLockout.maxFailures) {
    existing.lockedUntil =
      Date.now() + config.accountLockout.lockoutDurationMs;
  }

  lockoutStore.set(email, existing);
}

/** Reset failure count on successful authentication. */
export function clearAuthFailures(email: string): void {
  lockoutStore.delete(email);
}

// ---------------------------------------------------------------------------
// 3. TOTP-specific rate limiter (separate from auth rate limiter)
// ---------------------------------------------------------------------------
// TOTP attempts are rate-limited separately because:
//   - A compromised password should not allow unlimited 2FA guesses.
//   - TOTP codes are 6 digits (1M combinations) — stricter limits needed.
//   - Prevents online brute-force against the 2FA step specifically.

export const totpRateLimiter = rateLimit({
  windowMs: config.totpRateLimit.windowMs,
  max: config.totpRateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    if (req.app.get("trust proxy")) {
      return (
        (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ??
        req.ip ??
        "unknown"
      );
    }
    return req.ip ?? "unknown";
  },
  handler: (_req, res) => {
    res.status(429).json({
      error: "Too many attempts, please try again later",
    });
  },
});

// ---------------------------------------------------------------------------
// 4. Per-account TOTP lockout (in-memory)
// ---------------------------------------------------------------------------
// After 5 failed TOTP attempts for the same userId, lock out for 5 minutes.
// Separate from password lockout — a compromised password + wrong TOTP should
// not lock the account for password attempts.

interface TotpLockoutRecord {
  failures: number;
  lockedUntil: number;
}

const totpLockoutStore = new Map<string, TotpLockoutRecord>();

const TOTP_MAX_FAILURES = config.totpLockout.maxFailures;
const TOTP_LOCKOUT_MS = config.totpLockout.lockoutDurationMs;

/** Purge expired TOTP lockout entries. */
setInterval(() => {
  const now = Date.now();
  for (const [userId, record] of totpLockoutStore) {
    if (record.lockedUntil > 0 && now > record.lockedUntil) {
      totpLockoutStore.delete(userId);
    } else if (record.failures === 0) {
      totpLockoutStore.delete(userId);
    }
  }
}, 60_000).unref();

/** Check whether the user's TOTP is locked out. */
export function isTotpLocked(userId: string): boolean {
  const record = totpLockoutStore.get(userId);
  if (!record) return false;
  if (record.lockedUntil === 0) return false;
  if (Date.now() >= record.lockedUntil) {
    totpLockoutStore.delete(userId);
    return false;
  }
  return true;
}

/** Get remaining TOTP lockout seconds. */
export function totpLockoutRemainingSeconds(userId: string): number {
  const record = totpLockoutStore.get(userId);
  if (!record || record.lockedUntil === 0) return 0;
  return Math.max(0, Math.ceil((record.lockedUntil - Date.now()) / 1000));
}

/** Record a failed TOTP attempt. May trigger lockout. */
export function recordTotpFailure(userId: string): void {
  const existing = totpLockoutStore.get(userId) ?? { failures: 0, lockedUntil: 0 };
  existing.failures += 1;

  if (existing.failures >= TOTP_MAX_FAILURES) {
    existing.lockedUntil = Date.now() + TOTP_LOCKOUT_MS;
  }

  totpLockoutStore.set(userId, existing);
}

/** Reset TOTP failure count on successful verification. */
export function clearTotpFailures(userId: string): void {
  totpLockoutStore.delete(userId);
}
