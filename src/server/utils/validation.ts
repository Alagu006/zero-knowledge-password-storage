/**
 * Input validation schemas — Zod.
 *
 * Every route handler runs its request body through one of these schemas
 * BEFORE accessing the database. This provides:
 *   1. Type-safe parsed output (no manual type assertions).
 *   2. Rejection of unexpected fields (prevents mass-assignment).
 *   3. Format enforcement (hex lengths, UUID format, etc.).
 *
 * All schemas use .strict() to reject unknown properties.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// KDF version bounds — MIRRORS src/crypto/constants.ts.
// The server never derives keys (that happens client-side), so it only needs
// the valid range to reject out-of-bounds versions, not the parameters.
// Keep these in sync with KDF_MIN_VERSION / KDF_MAX_VERSION.
// ---------------------------------------------------------------------------
export const KDF_VERSION_MIN = 1;
export const KDF_VERSION_MAX = 10;

export const kdfVersionSchema = z
  .number()
  .int()
  .min(KDF_VERSION_MIN, `kdfVersion must be >= ${KDF_VERSION_MIN}`)
  .max(KDF_VERSION_MAX, `kdfVersion must be <= ${KDF_VERSION_MAX}`);

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------

/** POST /auth/register — single-step registration. */
export const registerSchema = z
  .object({
    email: z.string().email().max(255),

    // Client-generated salts (hex-encoded 32 bytes = 64 hex chars).
    saltEnc: z.string().regex(/^[0-9a-f]{64}$/i, "saltEnc must be 64 hex chars (32 bytes)"),
    saltAuth: z.string().regex(/^[0-9a-f]{64}$/i, "saltAuth must be 64 hex chars (32 bytes)"),

    // Auth verifier from client's deriveAuthKey() (32 bytes = 64 hex chars).
    authKey: z.string().regex(/^[0-9a-f]{64}$/i, "authKey must be 64 hex chars (32 bytes)"),

    // Wrapped vault key components (hex-encoded).
    // wrappedVk: AES-256-GCM ciphertext of 32-byte vault key = 32 bytes = 64 hex chars.
    // Enforce max 128 hex chars (64 bytes) to prevent oversized payloads.
    wrappedVk: z.string().regex(/^[0-9a-f]{1,128}$/i, "wrappedVk must be hex, max 128 chars (64 bytes)"),
    wrappedVkIv: z.string().regex(/^[0-9a-f]{24}$/i, "wrappedVkIv must be 24 hex chars (12 bytes)"),
    wrappedVkTag: z.string().regex(/^[0-9a-f]{32}$/i, "wrappedVkTag must be 32 hex chars (16 bytes)"),

    // KDF parameter version the client used to derive these keys.
    kdfVersion: kdfVersionSchema,
  })
  .strict();

/** POST /auth/login — step 1: email only, to retrieve salts. */
export const loginStep1Schema = z
  .object({
    email: z.string().email().max(255),
  })
  .strict();

/** POST /auth/login/verify — step 2: email + auth key. */
export const loginStep2Schema = z
  .object({
    email: z.string().email().max(255),
    authKey: z.string().regex(/^[0-9a-f]{64}$/i, "authKey must be 64 hex chars (32 bytes)"),
  })
  .strict();

// ---------------------------------------------------------------------------
// Vault entry routes
// ---------------------------------------------------------------------------

/** Allowed entry types — validated server-side to prevent injection of unexpected categories. */
const ENTRY_TYPE_ENUM = ["password", "note", "api-key", "ssh-key", "credit-card", "other"] as const;

/** POST /vault/entries — create new entry. */
export const createEntrySchema = z
  .object({
    entryType: z.enum(ENTRY_TYPE_ENUM, {
      errorMap: () => ({ message: `entryType must be one of: ${ENTRY_TYPE_ENUM.join(", ")}` }),
    }),
    nonce: z.string().regex(/^[0-9a-f]{24}$/i, "nonce must be 24 hex chars (12 bytes)"),
    ciphertext: z.string().regex(/^[0-9a-f]+$/i, "ciphertext must be hex").min(2),
    authTag: z.string().regex(/^[0-9a-f]{32}$/i, "authTag must be 32 hex chars (16 bytes)"),
  })
  .strict();

/** PUT /vault/entries/:id — update existing entry. */
export const updateEntrySchema = z
  .object({
    entryType: z
      .enum(ENTRY_TYPE_ENUM, {
        errorMap: () => ({ message: `entryType must be one of: ${ENTRY_TYPE_ENUM.join(", ")}` }),
      })
      .optional(),
    nonce: z.string().regex(/^[0-9a-f]{24}$/i, "nonce must be 24 hex chars (12 bytes)"),
    ciphertext: z.string().regex(/^[0-9a-f]+$/i, "ciphertext must be hex").min(2),
    authTag: z.string().regex(/^[0-9a-f]{32}$/i, "authTag must be 32 hex chars (16 bytes)"),
    version: z.number().int().positive(),
  })
  .strict();

/** URL param — UUID v4. */
export const uuidParamSchema = z.object({
  id: z.string().uuid(),
});

// ---------------------------------------------------------------------------
// Password change
// ---------------------------------------------------------------------------

/** PUT /auth/password — change master password (re-wrap VK under new MK). */
export const changePasswordSchema = z
  .object({
    // Current auth key (verification that the user knows the current password).
    oldAuthKey: z.string().regex(/^[0-9a-f]{64}$/i, "oldAuthKey must be 64 hex chars (32 bytes)"),
    // New credentials.
    saltEnc: z.string().regex(/^[0-9a-f]{64}$/i, "saltEnc must be 64 hex chars (32 bytes)"),
    saltAuth: z.string().regex(/^[0-9a-f]{64}$/i, "saltAuth must be 64 hex chars (32 bytes)"),
    authKey: z.string().regex(/^[0-9a-f]{64}$/i, "authKey must be 64 hex chars (32 bytes)"),
    wrappedVk: z.string().regex(/^[0-9a-f]{1,128}$/i, "wrappedVk must be hex, max 128 chars (64 bytes)"),
    wrappedVkIv: z.string().regex(/^[0-9a-f]{24}$/i, "wrappedVkIv must be 24 hex chars (12 bytes)"),
    wrappedVkTag: z.string().regex(/^[0-9a-f]{32}$/i, "wrappedVkTag must be 32 hex chars (16 bytes)"),
    // KDF parameter version used for the NEW keys (always the current version).
    kdfVersion: kdfVersionSchema,
  })
  .strict();

/**
 * PUT /auth/kdf-upgrade — migrate an account to newer Argon2id parameters.
 * Identical request shape to changePasswordSchema: the client re-derives the
 * auth key with the new parameters (password already in memory — no re-prompt)
 * and re-wraps the unchanged vault key under the new master-key parameters.
 * The oldAuthKey is verified first, exactly like a password change, so a
 * stolen JWT alone cannot force an upgrade.
 */
export const kdfUpgradeSchema = changePasswordSchema;

// ---------------------------------------------------------------------------
// Account recovery
// ---------------------------------------------------------------------------

/** POST /auth/register — extended with optional recovery blob. */
export const registerWithRecoverySchema = registerSchema.extend({
  recoveryWrappedVk: z.string().regex(/^[0-9a-f]{1,128}$/i, "recoveryWrappedVk must be hex, max 128 chars").optional(),
  recoveryWrappedVkIv: z.string().regex(/^[0-9a-f]{24}$/i, "recoveryWrappedVkIv must be 24 hex chars (12 bytes)").optional(),
  recoveryWrappedVkTag: z.string().regex(/^[0-9a-f]{32}$/i, "recoveryWrappedVkTag must be 32 hex chars (16 bytes)").optional(),
}).strict().refine(
  (data) => {
    const hasAny = data.recoveryWrappedVk || data.recoveryWrappedVkIv || data.recoveryWrappedVkTag;
    const hasAll = data.recoveryWrappedVk && data.recoveryWrappedVkIv && data.recoveryWrappedVkTag;
    // If any recovery field is present, all three must be present.
    return !hasAny || hasAll;
  },
  {
    message: "All recovery fields (recoveryWrappedVk, recoveryWrappedVkIv, recoveryWrappedVkTag) must be provided together or all omitted",
  },
);

/** POST /auth/recovery — fetch the recovery blob for an email. */
export const recoveryInitiateSchema = z
  .object({
    email: z.string().email().max(255),
  })
  .strict();

/** POST /auth/recovery/complete — finalize recovery with new credentials. */
export const recoveryCompleteSchema = z
  .object({
    // Recovery session token from POST /auth/recovery (JWT, short-lived).
    // Proves the client initiated recovery and the email is valid.
    // The recovery code never reaches the server — vault unwrap happens client-side.
    recoverySessionToken: z.string().min(1, "recoverySessionToken is required"),
    // New credentials (same shape as registration).
    saltEnc: z.string().regex(/^[0-9a-f]{64}$/i, "saltEnc must be 64 hex chars (32 bytes)"),
    saltAuth: z.string().regex(/^[0-9a-f]{64}$/i, "saltAuth must be 64 hex chars (32 bytes)"),
    authKey: z.string().regex(/^[0-9a-f]{64}$/i, "authKey must be 64 hex chars (32 bytes)"),
    wrappedVk: z.string().regex(/^[0-9a-f]{1,128}$/i, "wrappedVk must be hex, max 128 chars (64 bytes)"),
    wrappedVkIv: z.string().regex(/^[0-9a-f]{24}$/i, "wrappedVkIv must be 24 hex chars (12 bytes)"),
    wrappedVkTag: z.string().regex(/^[0-9a-f]{32}$/i, "wrappedVkTag must be 32 hex chars (16 bytes)"),
    // KDF parameter version used for the new credentials.
    kdfVersion: kdfVersionSchema,
  })
  .strict();

/**
 * POST /auth/recovery/regenerate — rotate the account recovery code.
 *
 * The raw recovery code NEVER reaches the server. The client generates a
 * fresh 128-bit code, re-wraps the (unchanged) vault key under SHA-256(code),
 * and sends only the new wrapped blob. The server requires proof of the
 * CURRENT password (oldAuthKey, verified against the stored auth verifier)
 * so a stolen JWT alone cannot rotate a user's recovery code.
 */
export const recoveryRegenerateSchema = z
  .object({
    // Proof of current password knowledge (same check as PUT /auth/password).
    oldAuthKey: z.string().regex(/^[0-9a-f]{64}$/i, "oldAuthKey must be 64 hex chars (32 bytes)"),
    // New recovery-wrapped vault key blob (client-generated under new code).
    recoveryWrappedVk: z.string().regex(/^[0-9a-f]{1,128}$/i, "recoveryWrappedVk must be hex, max 128 chars"),
    recoveryWrappedVkIv: z.string().regex(/^[0-9a-f]{24}$/i, "recoveryWrappedVkIv must be 24 hex chars (12 bytes)"),
    recoveryWrappedVkTag: z.string().regex(/^[0-9a-f]{32}$/i, "recoveryWrappedVkTag must be 32 hex chars (16 bytes)"),
  })
  .strict();

// ---------------------------------------------------------------------------
// 2FA / TOTP
// ---------------------------------------------------------------------------

/** POST /auth/2fa/enable — verify TOTP code to enable 2FA (after setup). */
export const totpEnableSchema = z
  .object({
    code: z.string().regex(/^\d{6}$/, "code must be exactly 6 digits"),
  })
  .strict();

/** POST /auth/2fa/disable — disable 2FA (requires current TOTP code). */
export const totpDisableSchema = z
  .object({
    code: z.string().regex(/^\d{6}$/, "code must be exactly 6 digits"),
  })
  .strict();

/** POST /auth/2fa/verify — verify TOTP code during login (2FA step). */
export const totpVerifySchema = z
  .object({
    tempToken: z.string().min(1, "tempToken is required"),
    code: z.string().regex(/^\d{6}$/, "code must be exactly 6 digits"),
  })
  .strict();

/**
 * POST /auth/2fa/backup-codes/regenerate — rotate the backup code set.
 * Requires a FRESH TOTP code (not the JWT alone) so a stolen session token
 * cannot silently replace a user's emergency access codes.
 */
export const backupCodesRegenerateSchema = totpDisableSchema;

/** POST /auth/2fa/backup-verify — verify a backup code during login. */
export const backupCodeVerifySchema = z
  .object({
    tempToken: z.string().min(1, "tempToken is required"),
    code: z
      .string()
      .regex(
        /^[A-Z2-9]{4}-?[A-Z2-9]{4}$/i,
        "code must be a valid 8-character backup code (XXXX-XXXX)",
      ),
  })
  .strict();
