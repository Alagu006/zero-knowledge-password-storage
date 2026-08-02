/**
 * Server configuration — all values from environment variables.
 * No secrets are hardcoded. Fail fast if required vars are missing.
 *
 * JWT KEY ROTATION:
 *   To rotate the JWT signing key:
 *   1. Generate a new key: openssl rand -base64 64
 *   2. Set JWT_SECRET_PREV to the current JWT_SECRET value
 *   3. Set JWT_SECRET to the new value
 *   4. Deploy — old tokens remain valid (signed with prev key)
 *   5. After max token lifetime (JWT_EXPIRES_IN), clear JWT_SECRET_PREV
 *
 *   During rotation, the server accepts tokens signed with EITHER key.
 *   New tokens are always signed with the current JWT_SECRET.
 */

function requireEnv(name: string): string {
  const val = process.env[name];
  if (!val) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return val;
}

/**
 * Require an environment variable with a minimum byte length.
 * Prevents weak/short signing secrets that could be brute-forced.
 */
function requireSecret(name: string, minLength = 32): string {
  const val = requireEnv(name);
  if (Buffer.byteLength(val, "utf8") < minLength) {
    throw new Error(
      `${name} must be at least ${minLength} bytes (got ${Buffer.byteLength(val, "utf8")}). Generate with: openssl rand -base64 64`,
    );
  }
  return val;
}

/**
 * Read an integer environment variable with a fallback.
 * Used for rate-limit / lockout tuning — e.g. integration tests raise the
 * limits so a full test suite does not trip the per-IP buckets.
 */
function intEnv(name: string, fallback: number): number {
  const val = process.env[name];
  if (val === undefined || val === "") return fallback;
  const parsed = parseInt(val, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    throw new Error(
      `${name} must be a positive integer (got "${val}")`,
    );
  }
  return parsed;
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: parseInt(process.env.PORT ?? "3000", 10),

  databaseUrl: requireEnv("DATABASE_URL"),

  /** Current JWT signing key — used for new tokens. */
  jwtSecret: requireSecret("JWT_SECRET"),
  /**
   * Previous JWT signing key — used during key rotation.
   * When set, tokens signed with this key are accepted until they expire.
   * Set JWT_SECRET_PREV to the old value before rotating JWT_SECRET.
   * Clear after all old tokens have expired.
   */
  jwtSecretPrev: process.env.JWT_SECRET_PREV || undefined,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? "15m",

  /** Secret for 2FA temporary tokens (short-lived, 5 min, scoped to 2FA step). */
  tempTokenSecret: requireSecret("TEMP_TOKEN_SECRET"),
  tempTokenExpiresIn: "5m",

  /**
   * Application-level envelope encryption key for TOTP secrets.
   * 32 bytes (256 bits), hex-encoded. Provides defense-in-depth:
   * even if the database is compromised, TOTP secrets remain encrypted.
   */
  totpEncryptionKey: requireSecret("TOTP_ENCRYPTION_KEY", 64),

  /** Per-IP rate limit for auth endpoints. */
  authRateLimit: {
    windowMs: intEnv("AUTH_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000), // 15-minute sliding window
    max: intEnv("AUTH_RATE_LIMIT_MAX", 10),                        // 10 attempts per window per IP
  },

  /**
   * Per-account lockout after repeated failures.
   * In-memory — resets on server restart. Production should use Redis or
   * a database-backed counter for multi-node deployments.
   */
  accountLockout: {
    maxFailures: intEnv("ACCOUNT_LOCKOUT_MAX_FAILURES", 5),                    // lock after 5 failures
    lockoutDurationMs: intEnv("ACCOUNT_LOCKOUT_DURATION_MS", 15 * 60 * 1000),  // 15-minute lockout
  },

  /** Per-IP rate limit for TOTP/backup-code endpoints. */
  totpRateLimit: {
    windowMs: intEnv("TOTP_RATE_LIMIT_WINDOW_MS", 5 * 60 * 1000), // 5-minute window
    max: intEnv("TOTP_RATE_LIMIT_MAX", 5),                        // 5 attempts per window per IP
  },

  /**
   * Per-account TOTP lockout after repeated failed codes.
   * Separate from the password lockout so a compromised password + wrong TOTP
   * does not lock the account for password attempts.
   */
  totpLockout: {
    maxFailures: intEnv("TOTP_LOCKOUT_MAX_FAILURES", 5),                   // lock after 5 failures
    lockoutDurationMs: intEnv("TOTP_LOCKOUT_DURATION_MS", 5 * 60 * 1000), // 5-minute lockout
  },

  corsOrigins: (process.env.CORS_ORIGINS ?? "https://localhost:3000").split(","),
} as const;
