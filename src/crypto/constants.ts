// Argon2id parameters for Master Key derivation.
//
// Rationale for these specific values:
// - memory: 64 MB (65536 KiB) — the minimum acceptable for offline-attack
//   resistance per OWASP 2023 guidelines. Production should use 256 MB+.
//   64 MB is chosen here so unit tests complete in reasonable time while
//   still meaningfully slowing brute-force. Every 2x memory increase
//   roughly doubles attacker GPU SRAM cost.
// - iterations (time cost): 3 — combined with 64 MB memory, each derivation
//   performs ~192 MB of sequential memory reads. This is the minimum OWASP
//   recommends; higher values linearly increase derivation time.
// - parallelism: 4 — matches typical consumer core count. GPU attackers
//   gain no benefit because Argon2id's memory-hardness is the bottleneck,
//   not thread count.
// - output length: 32 bytes (256 bits) — matches AES-256 key size.
//
// DEVIATION NOTE from the architecture doc's production values of
// 256 MB / 4 iterations: this module uses 64 MB / 3 iterations so that
// tests finish in <5 seconds on consumer hardware. The production config
// should be 256 MiB / 4 iterations. A separate PRODUCTION Parameters
// object is exported for that purpose.

export const ARGON2_PARAMS_MASTER = {
  memory: 64 * 1024,   // 64 MB in KiB
  iterations: 3,
  parallelism: 4,
  outputLength: 32,     // bytes
} as const;

// Auth Key derivation uses the same computational cost — the server must
// be able to recompute the verifier, and the security requirement is
// identical: slow down offline brute-force against the SRP verifier.
export const ARGON2_PARAMS_AUTH = {
  memory: 64 * 1024,
  iterations: 3,
  parallelism: 4,
  outputLength: 32,
} as const;

// Production parameters — swap these in for real deployment.
export const ARGON2_PARAMS_MASTER_PROD = {
  memory: 256 * 1024,  // 256 MiB
  iterations: 4,
  parallelism: 4,
  outputLength: 32,
} as const;

export const ARGON2_PARAMS_AUTH_PROD = {
  memory: 256 * 1024,
  iterations: 4,
  parallelism: 4,
  outputLength: 32,
} as const;

/**
 * Argon2id parameters — shared type for both test and production configs.
 */
export interface Argon2Params {
  readonly memory: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly outputLength: number;
}

// ---------------------------------------------------------------------------
// Versioned KDF parameter table
// ---------------------------------------------------------------------------
// KDF parameters are VERSIONED so that, when the recommended Argon2id cost
// increases, existing accounts can be migrated to the stronger parameters on
// their next successful login WITHOUT requiring the user to change their
// password (see the PUT /auth/kdf-upgrade flow).
//
//   Version 1 = the original parameter sets above
//               (test: 64 MiB / 3 iter; production: 256 MiB / 4 iter).
//   Version 2 = stronger: 1.5x memory in test mode (96 MiB / 3 iter) and
//               2x memory in production mode (512 MiB / 4 iter).
//   Versions 3+ = reserved for future increases. An account created at a
//               given version always uses that version's parameters.
//
// TEST MODE NOTE: test parameters are deliberately much cheaper than
// production so the test suite completes in reasonable time. The version
// bump is still verifiable because the parameters genuinely differ.

export const KDF_CURRENT_VERSION = 2;
export const KDF_MIN_VERSION = 1;
export const KDF_MAX_VERSION = 10;

const KDF_PARAMS_TEST: Record<number, { master: Argon2Params; auth: Argon2Params }> = {
  1: { master: ARGON2_PARAMS_MASTER, auth: ARGON2_PARAMS_AUTH },
  2: {
    master: { memory: 96 * 1024, iterations: 3, parallelism: 4, outputLength: 32 },
    auth: { memory: 96 * 1024, iterations: 3, parallelism: 4, outputLength: 32 },
  },
};

const KDF_PARAMS_PROD: Record<number, { master: Argon2Params; auth: Argon2Params }> = {
  1: { master: ARGON2_PARAMS_MASTER_PROD, auth: ARGON2_PARAMS_AUTH_PROD },
  2: {
    master: { memory: 512 * 1024, iterations: 4, parallelism: 4, outputLength: 32 },
    auth: { memory: 512 * 1024, iterations: 4, parallelism: 4, outputLength: 32 },
  },
};

/**
 * Explicitly configured Argon2id mode. Must be set before any KDF call.
 *
 * This replaces the fragile `process.env.NODE_ENV` sniffing with an
 * explicit configuration step. The mode MUST be configured at application
 * entry points (e.g., main.tsx for browser, index.ts for server).
 */
let _argon2Mode: "test" | "production" | null = null;

/**
 * Configure the Argon2id parameter set. Must be called once at startup
 * before any key derivation (deriveMasterKey, deriveAuthKey).
 *
 * @param mode - "test" for fast parameters (64 MiB / 3 iterations),
 *               "production" for secure parameters (256 MiB / 4 iterations).
 * @throws Error if called more than once (to prevent mode-switching attacks).
 */
export function configureArgon2Mode(mode: "test" | "production"): void {
  if (_argon2Mode !== null) {
    throw new Error(
      `Argon2 mode already configured as "${_argon2Mode}". Cannot reconfigure.`,
    );
  }
  _argon2Mode = mode;
}

/**
 * Get the appropriate Argon2id parameters based on the configured mode and
 * the account's KDF version.
 *
 * @param purpose - "master" or "auth" derivation context.
 * @param version - KDF parameter version. Defaults to the current version.
 *   Accounts created at an older version pass their stored kdfVersion so the
 *   same password still derives the same keys (stable across upgrades).
 *   Unknown versions (not yet in the table) fall back to the current version
 *   so a bad stored version can never produce undefined parameters.
 *
 * @throws Error if configureArgon2Mode() has not been called yet.
 *
 * IMPORTANT: Production deployments MUST use production parameters.
 * Test parameters are NOT secure enough for real key derivation.
 */
export function getArgon2Params(
  purpose: "master" | "auth" = "master",
  version: number = KDF_CURRENT_VERSION,
): Argon2Params {
  if (_argon2Mode === null) {
    throw new Error(
      "Argon2 mode not configured. Call configureArgon2Mode('test' | 'production') at application startup.",
    );
  }

  const table = _argon2Mode === "production" ? KDF_PARAMS_PROD : KDF_PARAMS_TEST;
  const entry = table[version] ?? table[KDF_CURRENT_VERSION];
  if (!entry) {
    throw new Error(`No Argon2 parameters defined for KDF version ${version}`);
  }

  return purpose === "auth" ? entry.auth : entry.master;
}

/**
 * Reset the configured mode (TEST ONLY).
 * Used in test setup to allow reconfiguration between test suites.
 * @internal
 */
export function _resetArgon2ModeForTesting(): void {
  _argon2Mode = null;
}

// Domain separation strings — prepended to salt to ensure the two KDF
// contexts are information-theoretically independent even if the user
// provides the same salt for both (which they shouldn't, but defense in depth).
export const KDF_CONTEXT_MASTER = "zkm-master-key-v1";
export const KDF_CONTEXT_AUTH = "zkm-auth-key-v1";

// Domain separation for recovery-wrap key derivation (SHA-256 of recovery code).
export const KDF_CONTEXT_RECOVERY = "zkm-recovery-key-v1";

// Recovery code length in bytes (16 bytes = 128 bits of entropy).
// OWASP recommends >=128 bits for recovery codes. 16 bytes provides
// 2^128 brute-force resistance, matching AES-128 security level.
export const RECOVERY_CODE_LENGTH = 16;

// AES key sizes
export const AES_KEY_LENGTH = 256; // bits
export const AES_GCM_IV_LENGTH = 12; // bytes (96 bits) — NIST-recommended for GCM
export const AES_GCM_TAG_LENGTH = 16; // bytes (128 bits) — default GCM tag

// AES-KW (RFC 3394) wraps a 256-bit key into a 320-bit (40-byte) blob
// (32 bytes key + 8 bytes integrity check value).
export const AES_KW_WRAPPED_LENGTH = 40; // bytes
