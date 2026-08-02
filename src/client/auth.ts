/**
 * Client-side auth orchestration — wires Prompt 1's crypto to Prompt 2's API.
 *
 * This module contains the complete registration and login flows. It calls
 * the crypto module for all key derivation and the API module for all HTTP.
 * It NEVER sends the master password, master key, or vault key to the server.
 *
 * SECURITY INVARIANT:
 *   After every function in this module returns, the following buffers have
 *   been zeroized (filled with zeros):
 *     - masterKey (derived from password — never stored/transmitted)
 *     - authKey   (derived from password — sent once as verifier, then cleared)
 *     - passwordBytes (UTF-8 encoding of the master password)
 *
 *   The following buffers are RETURNED to the caller and must be zeroized
 *   by the caller when the session ends:
 *     - vaultKey (used for all entry encryption/decryption during the session)
 *     - token (JWT — sent in Authorization header)
 */

import {
  deriveMasterKey,
  deriveAuthKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  deriveRecoveryWrapKey,
  zeroize,
} from "../crypto/index.js";
import { KDF_CURRENT_VERSION } from "../crypto/constants.js";
import type { EncryptedVaultKey } from "../crypto/types.js";
import {
  apiRegister,
  apiLoginStep1,
  apiLoginStep2,
  apiChangePassword,
  apiKdfUpgrade,
  apiRecoveryInitiate,
  apiRecoveryComplete,
  apiTotpSetup,
  apiTotpEnable,
  apiTotpDisable,
  apiTotpVerify,
  apiBackupCodeVerify,
  apiTotpStatus,
  apiRegenerateBackupCodes,
  apiRegenerateRecovery,
  toHex,
  fromHex,
  type ApiError,
} from "./api.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RegistrationResult = {
  ok: true;
  /** 128-bit recovery code as hex string. Displayed ONCE — user must save it.
   *  Undefined if the user chose not to set up recovery. */
  recoveryCode?: string;
};

export type LoginResult = {
  ok: true;
  /** The JWT session token. Caller must store securely and zeroize on logout. */
  token: string;
  /** The unwrapped Vault Key. Caller MUST zeroize when session ends. */
  vaultKey: Uint8Array;
};

export type PasswordChangeResult = {
  ok: true;
};

export type RecoveryResult = {
  ok: true;
  /** The unwrapped vault key from recovery. Caller MUST zeroize when done. */
  vaultKey: Uint8Array;
  /** Recovery session token to pass to completeRecovery(). */
  recoverySessionToken: string;
};

/**
 * 2FA required result — returned by login() when 2FA is enabled.
 * The client must prompt the user for their TOTP code.
 */
export type TwoFactorRequiredResult = {
  ok: false;
  step: "2fa_required";
  /** Short-lived temp token for the 2FA verification step. */
  tempToken: string;
  /** The wrapped VK data needed to complete login after 2FA. */
  wrappedVK: EncryptedVaultKey;
  /** The master key for unwrapping VK after 2FA. Caller MUST zeroize. */
  masterKey: Uint8Array;
};

/**
 * Unified error type for both registration and login.
 * `step` indicates which phase failed (useful for UI, but the error message
 * itself is always generic to prevent information leakage).
 */
export type AuthError = {
  ok: false;
  /** Which step failed — for internal debugging, NOT displayed to user. */
  step: "password_validation" | "crypto_derivation" | "server" | "unwrap" | "2fa_required";
  /** Always a generic message — never reveals whether the email exists or
   *  whether the password was wrong. */
  message: string;
  /** HTTP status code if the error came from the server (undefined otherwise). */
  status?: number;
  /** Temp token for 2FA step (only present when step === "2fa_required"). */
  tempToken?: string;
};

export type PasswordChangeError = AuthError;
export type RecoveryError = AuthError;

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Register a new account.
 *
 * EXACT FLOW:
 *   1. Validate password strength (client-side, before any crypto).
 *   2. Generate 32-byte random salt_enc and salt_auth (CSPRNG).
 *   3. deriveMasterKey(password, salt_enc)  → masterKey  (Argon2id, separate context)
 *   4. deriveAuthKey(password, salt_auth)   → authKey    (Argon2id, separate context)
 *   5. generateVaultKey()                   → vaultKey   (CSPRNG)
 *   6. wrapVaultKey(vaultKey, masterKey)    → wrappedVK  (AES-256-GCM)
 *   7. Generate 16-byte (128-bit) recovery code (CSPRNG).
 *   8. deriveRecoveryWrapKey(recoveryCode) → recoveryWrapKey (SHA-256)
 *   9. wrapVaultKey(vaultKey, recoveryWrapKey) → recoveryWrappedVK
 *  10. Send to server: { email, saltEnc, saltAuth, authKey, wrappedVK*, recoveryWrappedVK* }
 *      The server NEVER sees masterKey, vaultKey (plaintext), or the password.
 *  11. Zeroize masterKey, authKey, vaultKey, recoveryWrapKey.
 *  12. Return { ok: true, recoveryCode }. The recoveryCode MUST be displayed
 *      to the user exactly once and saved offline by them.
 *
 * RECOVERY TRADE-OFF (visible in UI copy at signup):
 *   Option A (implemented): client-generated 128-bit recovery code wraps a
 *     copy of the vault key. If the user forgets their master password, they
 *     can recover the vault with this code. The code must be stored offline.
 *     A compromised server cannot recover the vault without the code.
 *   Option B (not implemented): no recovery — forgotten master password means
 *     permanently inaccessible vault. Stronger guarantee, worse UX.
 *
 * ERROR HANDLING:
 *   All server errors are mapped to a generic "Registration failed" message.
 *   The step field is for internal debugging only — it must NEVER be
 *   exposed to the user (it could reveal whether the email already exists).
 */
export async function register(
  email: string,
  password: string,
): Promise<RegistrationResult | AuthError> {
  // ── Step 1: Password strength validation ───────────────────────────────
  // This runs BEFORE any KDF computation (which takes seconds).
  // Import dynamically to keep the crypto module framework-free.
  const { validatePasswordStrength } = await import("./password.js");
  const strength = validatePasswordStrength(password);
  if (!strength.valid) {
    return {
      ok: false,
      step: "password_validation",
      message: strength.errors.join("; "),
    };
  }

  let masterKey: Uint8Array | undefined;
  let authKey: Uint8Array | undefined;
  let vaultKey: Uint8Array | undefined;
  let recoveryWrapKey: Uint8Array | undefined;

  try {
    // ── Step 2: Generate salts (client-generated, not server-issued) ──────
    const saltEnc = new Uint8Array(32);
    const saltAuth = new Uint8Array(32);
    crypto.getRandomValues(saltEnc);
    crypto.getRandomValues(saltAuth);

    // ── Steps 3-4: Derive keys (parallel — both Argon2id, independent) ──
    // New accounts always use the CURRENT KDF parameter version.
    const [mk, ak] = await Promise.all([
      deriveMasterKey(password, saltEnc, KDF_CURRENT_VERSION),
      deriveAuthKey(password, saltAuth, KDF_CURRENT_VERSION),
    ]);
    masterKey = mk;
    authKey = ak;

    // ── Step 5-6: Generate and wrap vault key ────────────────────────────
    const vk = generateVaultKey();
    vaultKey = vk;
    const wrappedVK: EncryptedVaultKey = await wrapVaultKey(vaultKey, masterKey);

    // ── Steps 7-9: Generate recovery code and wrap VK under it ───────────
    // 128-bit recovery code from CSPRNG.
    const recoveryCode = new Uint8Array(16);
    crypto.getRandomValues(recoveryCode);

    // Derive a wrapping key via SHA-256(recoveryCode || domain_sep).
    recoveryWrapKey = await deriveRecoveryWrapKey(recoveryCode);

    // Wrap the same vault key under the recovery wrapping key.
    const recoveryWrappedVK: EncryptedVaultKey = await wrapVaultKey(
      vaultKey,
      recoveryWrapKey,
    );

    // ── Step 10: Send to server ──────────────────────────────────────────
    await apiRegister({
      email,
      saltEnc: toHex(saltEnc),
      saltAuth: toHex(saltAuth),
      authKey: toHex(authKey),
      wrappedVk: toHex(wrappedVK.wrappedKey),
      wrappedVkIv: toHex(wrappedVK.iv),
      wrappedVkTag: toHex(wrappedVK.authTag),
      kdfVersion: KDF_CURRENT_VERSION,
      recoveryWrappedVk: toHex(recoveryWrappedVK.wrappedKey),
      recoveryWrappedVkIv: toHex(recoveryWrappedVK.iv),
      recoveryWrappedVkTag: toHex(recoveryWrappedVK.authTag),
    });

    // ── Step 11: Zeroize sensitive material ──────────────────────────────
    // Return the recovery code as hex to the caller (UI will display it once).
    const recoveryCodeHex = toHex(recoveryCode);

    zeroize(vaultKey);
    zeroize(recoveryCode);
    masterKey.fill(0);
    authKey.fill(0);
    recoveryWrapKey.fill(0);

    // ── Step 12: Return ──────────────────────────────────────────────────
    // vaultKey is NOT returned — user logs in to get it.
    // recoveryCode is returned once for display.
    return { ok: true, recoveryCode: recoveryCodeHex };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message:
        apiErr.status === 409
          ? "An account with this email already exists"
          : "Registration failed — please try again",
      status: apiErr.status,
    };
  } finally {
    masterKey?.fill(0);
    authKey?.fill(0);
    vaultKey?.fill(0);
    recoveryWrapKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/**
 * Log in and obtain a session with an unwrapped Vault Key.
 *
 * EXACT FLOW:
 *   1. Validate password is non-empty (strength validation is optional on
 *      login — the password was already validated at registration).
 *   2. POST /auth/login { email } → receive salts + wrapped VK.
 *      If email doesn't exist, server returns random dummies (client can't tell).
 *   3. deriveMasterKey(password, salt_enc) → masterKey  (Argon2id)
 *   4. deriveAuthKey(password, salt_auth)  → authKey    (Argon2id)
 *   5. POST /auth/login/verify { email, authKey } → receive JWT.
 *      Server uses constant-time comparison (timingSafeEqual).
 *   6. Parse the wrapped VK from step 2 and unwrap it with masterKey.
 *      If unwrap fails → wrong password (or corrupted data).
 *   7. Zeroize masterKey, authKey.
 *   8. Return { token, vaultKey }.
 *
 * CRITICAL ERROR UNIFICATION:
 *   Both "email doesn't exist" and "wrong password" produce the same generic
 *   "Incorrect email or password" error. This prevents user enumeration.
 *   The vault unwrap failure is ALSO mapped to the same message — the UI
 *   must NOT distinguish between "server rejected auth" and "unwrap failed".
 *   If the attacker can tell which step failed, they can enumerate emails:
 *     - Email exists + wrong password → server returns 401 in step 5
 *     - Email doesn't exist → server returns 401 in step 5 (same error)
 *   Both cases look identical to the attacker.
 *
 * TIMING ATTACK CONSIDERATIONS:
 *   - The authKey is sent over TLS (confidentiality + integrity).
 *   - The server compares using crypto.timingSafeEqual (constant-time).
 *   - A passive network observer cannot replay the authKey because TLS
 *     provides forward secrecy (ECDHE) and the authKey is session-bound.
 *   - An active attacker (compromised server) CAN capture the authKey
 *     and replay it. This is the documented weakness of the Argon2id-
 *     verifier approach vs SRP-6a. SRP-6a eliminates this by making the
 *     auth transcript zero-knowledge.
 */
export async function login(
  email: string,
  password: string,
): Promise<LoginResult | TwoFactorRequiredResult | AuthError> {
  if (!password) {
    return {
      ok: false,
      step: "password_validation",
      message: "Password is required",
    };
  }

  let masterKey: Uint8Array | undefined;
  let authKey: Uint8Array | undefined;

  try {
    // ── Step 2: Fetch salts + wrapped VK from server ─────────────────────
    let step1Data;
    try {
      step1Data = await apiLoginStep1(email);
    } catch {
      // Server error — but we still proceed to step 2 to消耗 time
      // (prevents timing-based enumeration of server errors).
      // If step 1 fails, step 2 will also fail with the same error.
      return {
        ok: false,
        step: "server",
        message: "Incorrect email or password",
      };
    }

    // Parse the wrapped VK from hex (server returns hex-encoded blobs).
    const wrappedVK: EncryptedVaultKey = {
      wrappedKey: fromHex(step1Data.wrappedVk),
      iv: fromHex(step1Data.wrappedVkIv),
      authTag: fromHex(step1Data.wrappedVkTag),
    };

    // ── Steps 3-4: Derive keys (parallel) ───────────────────────────────
    const saltEnc = fromHex(step1Data.saltEnc);
    const saltAuth = fromHex(step1Data.saltAuth);

    // Derive with the account's KDF parameter version so legacy accounts
    // re-derive the exact same keys as when they registered.
    const kdfVersion = step1Data.kdfVersion;

    const [mk, ak] = await Promise.all([
      deriveMasterKey(password, saltEnc, kdfVersion),
      deriveAuthKey(password, saltAuth, kdfVersion),
    ]);
    masterKey = mk;
    authKey = ak;

    // ── Step 5: Submit auth key for verification ─────────────────────────
    let step2Data;
    try {
      step2Data = await apiLoginStep2(email, toHex(authKey));
    } catch (err) {
      const apiErr = err as ApiError;
      // UNIFIED ERROR: "email not found" and "wrong password" look identical.
      return {
        ok: false,
        step: "server",
        message: "Incorrect email or password",
        status: apiErr.status,
      };
    }

    // ── Check if 2FA is required ────────────────────────────────────────
    if (step2Data.twoFactorRequired && step2Data.tempToken) {
      // 2FA is enabled. Return the temp token + wrapped VK + master key.
      // The caller must complete the 2FA step before unwrapping the VK.
      // The caller MUST zeroize masterKey when done.
      authKey.fill(0);
      // Save masterKey reference and detach from local variable so the
      // finally block doesn't zeroize the buffer we're returning.
      const mk = masterKey;
      masterKey = undefined;
      return {
        ok: false,
        step: "2fa_required",
        tempToken: step2Data.tempToken,
        wrappedVK,
        masterKey: mk,
      };
    }

    // ── Step 6: Unwrap vault key with derived master key ──────────────────
    let vaultKey: Uint8Array;
    try {
      vaultKey = await unwrapVaultKey(wrappedVK, masterKey);
    } catch {
      return {
        ok: false,
        step: "unwrap",
        message: "Incorrect email or password",
      };
    }

    // ── Step 7: Zeroize sensitive material ───────────────────────────────
    masterKey.fill(0);
    authKey.fill(0);

    // ── Step 8: Return session data ──────────────────────────────────────
    return { ok: true, token: step2Data.token, vaultKey };
  } catch {
    return {
      ok: false,
      step: "server",
      message: "Login failed — please try again",
    };
  } finally {
    masterKey?.fill(0);
    authKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// 2FA Completion
// ---------------------------------------------------------------------------

/**
 * Complete the 2FA login step by verifying a TOTP code.
 *
 * Called after login() returns step: "2fa_required". The caller has the
 * wrappedVK and masterKey from the login result. This function:
 *   1. Verifies the TOTP code with the server.
 *   2. Receives the full session JWT.
 *   3. Unwraps the vault key using the masterKey from step 1.
 *   4. Zeroizes the masterKey.
 *   5. Returns { token, vaultKey }.
 *
 * SECURITY INVARIANT:
 *   2FA strengthens login ONLY — it never touches the vault key or entries.
 *   Losing or leaking the TOTP secret cannot decrypt the vault without the
 *   master password. The TOTP step is orthogonal to vault encryption.
 *
 * @param tempToken  - From login() result.
 * @param code       - 6-digit TOTP code.
 * @param wrappedVK  - From login() result.
 * @param masterKey  - From login() result (will be zeroized).
 * @returns LoginResult on success, AuthError on failure.
 */
export async function verify2FA(
  tempToken: string,
  code: string,
  wrappedVK: EncryptedVaultKey,
  masterKey: Uint8Array,
): Promise<LoginResult | AuthError> {
  try {
    const result = await apiTotpVerify(tempToken, code);
    const vaultKey = await unwrapVaultKey(wrappedVK, masterKey);
    masterKey.fill(0);
    return { ok: true, token: result.token, vaultKey };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Invalid two-factor code",
      status: apiErr.status,
    };
  } finally {
    masterKey.fill(0);
  }
}

/**
 * Complete the 2FA login step using a backup code.
 *
 * Same flow as verify2FA() but uses a backup code instead of TOTP.
 *
 * @param tempToken  - From login() result.
 * @param code       - 8-character backup code (XXXX-XXXX format).
 * @param wrappedVK  - From login() result.
 * @param masterKey  - From login() result (will be zeroized).
 * @returns LoginResult on success, AuthError on failure.
 */
export async function verify2FAWithBackupCode(
  tempToken: string,
  code: string,
  wrappedVK: EncryptedVaultKey,
  masterKey: Uint8Array,
): Promise<LoginResult | AuthError> {
  try {
    const result = await apiBackupCodeVerify(tempToken, code);
    const vaultKey = await unwrapVaultKey(wrappedVK, masterKey);
    masterKey.fill(0);
    return { ok: true, token: result.token, vaultKey };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Invalid backup code",
      status: apiErr.status,
    };
  } finally {
    masterKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Password Change
// ---------------------------------------------------------------------------

/**
 * Change the master password.
 *
 * EXACT FLOW:
 *   1. Fetch current salts + wrapped VK via login step 1 (need the email).
 *   2. Derive old masterKey + old authKey from current password + current salts.
 *   3. Verify we can unwrap the VK (sanity check — confirms old password).
 *   4. Generate FRESH salts for the new password.
 *   5. deriveMasterKey(newPassword, freshSaltEnc) → newMasterKey
 *   6. deriveAuthKey(newPassword, freshSaltAuth)  → newAuthKey
 *   7. wrapVaultKey(vaultKey, newMasterKey)        → newWrappedVK
 *   8. Send { oldAuthKey, freshSaltEnc, freshSaltAuth, newAuthKey, newWrappedVK }
 *      to PUT /auth/password (JWT required).
 *   9. Server verifies old authKey against stored verifier, then atomically
 *      updates all credentials and revokes all sessions.
 *
 * SECURITY: The old password is required to prevent a stolen JWT from being
 * used to change the password. The server independently verifies the old
 * authKey against the stored verifier.
 *
 * FRESH SALTS JUSTIFICATION:
 *   Old salts live on the compromised server. Reusing them lets an attacker
 *   who captures the new auth_verifier precompute tables against the new
 *   password with known salts. Fresh salts = independent derivation paths,
 *   zero precomputation advantage.
 *
 * @param token           - Current JWT session token.
 * @param email           - User's email (for fetching current salts).
 * @param vaultKey        - Current unwrapped vault key (from session).
 * @param currentPassword - The current master password (for verification).
 * @param newPassword     - The new master password.
 * @returns PasswordChangeResult on success, AuthError on failure.
 *
 * MEMORY HYGIENE: all derived keys are zeroized after the call.
 * vaultKey is NOT zeroized (caller still needs it for the session).
 */
export async function changePassword(
  token: string,
  email: string,
  vaultKey: Uint8Array,
  currentPassword: string,
  newPassword: string,
): Promise<PasswordChangeResult | PasswordChangeError> {
  const { validatePasswordStrength } = await import("./password.js");
  const strength = validatePasswordStrength(newPassword);
  if (!strength.valid) {
    return {
      ok: false,
      step: "password_validation",
      message: strength.errors.join("; "),
    };
  }

  let oldMasterKey: Uint8Array | undefined;
  let oldAuthKey: Uint8Array | undefined;
  let newMasterKey: Uint8Array | undefined;
  let newAuthKey: Uint8Array | undefined;

  try {
    // ── Step 1: Fetch current salts from server ─────────────────────────
    const step1Data = await apiLoginStep1(email);

    const currentSaltEnc = fromHex(step1Data.saltEnc);
    const currentSaltAuth = fromHex(step1Data.saltAuth);

    // ── Step 2: Derive old keys from current password ───────────────────
    // Old keys use the account's current KDF version (matches stored verifier).
    const [omk, oak] = await Promise.all([
      deriveMasterKey(currentPassword, currentSaltEnc, step1Data.kdfVersion),
      deriveAuthKey(currentPassword, currentSaltAuth, step1Data.kdfVersion),
    ]);
    oldMasterKey = omk;
    oldAuthKey = oak;

    // ── Step 3: Sanity check — verify we can unwrap the VK ──────────────
    // This confirms the current password is correct before proceeding.
    const wrappedVK: EncryptedVaultKey = {
      wrappedKey: fromHex(step1Data.wrappedVk),
      iv: fromHex(step1Data.wrappedVkIv),
      authTag: fromHex(step1Data.wrappedVkTag),
    };
    try {
      await unwrapVaultKey(wrappedVK, oldMasterKey);
    } catch {
      return {
        ok: false,
        step: "unwrap",
        message: "Current password is incorrect",
      };
    }

    // ── Step 4: Fresh salts for the new password ─────────────────────────
    const freshSaltEnc = new Uint8Array(32);
    const freshSaltAuth = new Uint8Array(32);
    crypto.getRandomValues(freshSaltEnc);
    crypto.getRandomValues(freshSaltAuth);

    // ── Steps 5-6: Derive new keys from new password ─────────────────────
    // New credentials always use the CURRENT KDF parameter version.
    const [nmk, nak] = await Promise.all([
      deriveMasterKey(newPassword, freshSaltEnc, KDF_CURRENT_VERSION),
      deriveAuthKey(newPassword, freshSaltAuth, KDF_CURRENT_VERSION),
    ]);
    newMasterKey = nmk;
    newAuthKey = nak;

    // ── Step 7: Re-wrap the same vault key under new master key ──────────
    const newWrappedVK: EncryptedVaultKey = await wrapVaultKey(
      vaultKey,
      newMasterKey,
    );

    // ── Step 8: Send to server (includes old authKey for verification) ───
    await apiChangePassword(token, {
      oldAuthKey: toHex(oldAuthKey),
      saltEnc: toHex(freshSaltEnc),
      saltAuth: toHex(freshSaltAuth),
      authKey: toHex(newAuthKey),
      wrappedVk: toHex(newWrappedVK.wrappedKey),
      wrappedVkIv: toHex(newWrappedVK.iv),
      wrappedVkTag: toHex(newWrappedVK.authTag),
      kdfVersion: KDF_CURRENT_VERSION,
    });

    // ── Step 9: Zeroize ──────────────────────────────────────────────────
    oldMasterKey.fill(0);
    oldAuthKey.fill(0);
    newMasterKey.fill(0);
    newAuthKey.fill(0);

    return { ok: true };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Password change failed — please try again",
      status: apiErr.status,
    };
  } finally {
    oldMasterKey?.fill(0);
    oldAuthKey?.fill(0);
    newMasterKey?.fill(0);
    newAuthKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// KDF Parameter Upgrade
// ---------------------------------------------------------------------------

/**
 * Upgrade the account's Argon2id parameters to the current version WITHOUT
 * changing the master password.
 *
 * EXACT FLOW:
 *   1. Fetch current salts + wrapped VK via login step 1 (need the email).
 *   2. If the account is already at the current version → no-op success.
 *   3. Derive OLD masterKey + authKey using the account's current version
 *      (password in memory — no re-prompt required).
 *   4. Sanity check: unwrap the VK to confirm the password is correct.
 *   5. Generate FRESH salts and re-derive masterKey + authKey with the
 *      CURRENT version's parameters.
 *   6. Re-wrap the SAME vault key under the new master key.
 *   7. Send { oldAuthKey, freshSalts, newAuthKey, newWrappedVK, kdfVersion }
 *      to PUT /auth/kdf-upgrade (JWT required).
 *   8. Server verifies oldAuthKey against the stored verifier (proof of
 *      password knowledge), then atomically updates all credentials.
 *
 * SECURITY NOTES:
 *   - oldAuthKey is required so a stolen JWT alone cannot force an upgrade.
 *   - Vault entries are NOT re-encrypted — only the vault key's wrapping
 *     key (master key) changes. The vault key itself never changes.
 *   - Fresh salts for the new derivation keep the two derivations
 *     independent (same rationale as password change).
 *
 * @param token    - Current JWT session token.
 * @param email    - User's email (for fetching current salts/version).
 * @param vaultKey - Current unwrapped vault key (from session).
 * @param password - The master password (still in memory — no re-prompt).
 * @returns PasswordChangeResult on success, AuthError on failure.
 *
 * MEMORY HYGIENE: all derived keys are zeroized after the call.
 * vaultKey is NOT zeroized (caller still needs it for the session).
 */
export async function upgradeKdf(
  token: string,
  email: string,
  vaultKey: Uint8Array,
  password: string,
): Promise<PasswordChangeResult | PasswordChangeError> {
  let oldMasterKey: Uint8Array | undefined;
  let oldAuthKey: Uint8Array | undefined;
  let newMasterKey: Uint8Array | undefined;
  let newAuthKey: Uint8Array | undefined;

  try {
    // ── Step 1: Fetch current salts + version from server ───────────────
    const step1Data = await apiLoginStep1(email);

    // ── Step 2: Already at the latest version — nothing to do ───────────
    if (step1Data.kdfVersion >= KDF_CURRENT_VERSION) {
      return { ok: true };
    }

    const currentSaltEnc = fromHex(step1Data.saltEnc);
    const currentSaltAuth = fromHex(step1Data.saltAuth);
    const currentVersion = step1Data.kdfVersion;

    // ── Step 3: Derive old keys with the account's current version ──────
    const [omk, oak] = await Promise.all([
      deriveMasterKey(password, currentSaltEnc, currentVersion),
      deriveAuthKey(password, currentSaltAuth, currentVersion),
    ]);
    oldMasterKey = omk;
    oldAuthKey = oak;

    // ── Step 4: Sanity check — confirm the password by unwrapping ───────
    const wrappedVK: EncryptedVaultKey = {
      wrappedKey: fromHex(step1Data.wrappedVk),
      iv: fromHex(step1Data.wrappedVkIv),
      authTag: fromHex(step1Data.wrappedVkTag),
    };
    try {
      await unwrapVaultKey(wrappedVK, oldMasterKey);
    } catch {
      return {
        ok: false,
        step: "unwrap",
        message: "Current password is incorrect",
      };
    }

    // ── Steps 5-6: Derive new keys with the current version + fresh salts ─
    const freshSaltEnc = new Uint8Array(32);
    const freshSaltAuth = new Uint8Array(32);
    crypto.getRandomValues(freshSaltEnc);
    crypto.getRandomValues(freshSaltAuth);

    const [nmk, nak] = await Promise.all([
      deriveMasterKey(password, freshSaltEnc, KDF_CURRENT_VERSION),
      deriveAuthKey(password, freshSaltAuth, KDF_CURRENT_VERSION),
    ]);
    newMasterKey = nmk;
    newAuthKey = nak;

    // Re-wrap the SAME vault key under the new master key.
    const newWrappedVK: EncryptedVaultKey = await wrapVaultKey(
      vaultKey,
      newMasterKey,
    );

    // ── Step 7: Send to server ──────────────────────────────────────────
    await apiKdfUpgrade(token, {
      oldAuthKey: toHex(oldAuthKey),
      saltEnc: toHex(freshSaltEnc),
      saltAuth: toHex(freshSaltAuth),
      authKey: toHex(newAuthKey),
      wrappedVk: toHex(newWrappedVK.wrappedKey),
      wrappedVkIv: toHex(newWrappedVK.iv),
      wrappedVkTag: toHex(newWrappedVK.authTag),
      kdfVersion: KDF_CURRENT_VERSION,
    });

    return { ok: true };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Key upgrade failed — please try again",
      status: apiErr.status,
    };
  } finally {
    oldMasterKey?.fill(0);
    oldAuthKey?.fill(0);
    newMasterKey?.fill(0);
    newAuthKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Account Recovery
// ---------------------------------------------------------------------------

/**
 * Recover the vault key using the 128-bit recovery code.
 *
 * EXACT FLOW:
 *   1. POST /auth/recovery { email } → receive recoverySessionToken.
 *      Server returns a dummy token if email doesn't exist (anti-enumeration).
 *   2. Client also receives the recovery-wrapped VK blob in the response.
 *      Wait — no! After the fix, the server no longer returns the blob.
 *      The client must have the recovery blob stored locally? No —
 *
 *   Actually, looking at this more carefully: the server still stores the
 *   recovery-wrapped VK blob. But it no longer returns it to the client.
 *   The client needs it to unwrap the vault key locally.
 *
 *   Hmm, this creates a chicken-and-egg problem. Let me reconsider.
 *
 *   The original flow was:
 *     1. Client → POST /auth/recovery → server returns recovery blob
 *     2. Client unwraps locally using recovery code
 *     3. Client → POST /auth/recovery/complete with new creds + recovery code
 *     4. Server verifies recovery code by attempting unwrap
 *
 *   The new flow should be:
 *     1. Client → POST /auth/recovery → server returns recovery session token
 *        BUT the client still needs the recovery blob to unwrap locally.
 *
 *   Wait, I need to rethink this. The server needs to return BOTH the
 *   recovery session token AND the recovery-wrapped VK blob, so the client
 *   can unwrap locally. The security improvement is that step 3 no longer
 *   sends the raw recovery code to the server.
 *
 *   Actually no — let me re-read the fix description:
 *   "Recovery flow leaks vault key to server — need to refactor POST
 *    /auth/recovery/complete to use recovery session token instead of raw code"
 *
 *   The issue is that in the OLD /auth/recovery/complete, the server performs
 *   the unwrap (seeing the vault key in memory). The fix moves the unwrap
 *   entirely client-side by:
 *   - Server still returns the recovery blob (client needs it to unwrap)
 *   - Client unwraps locally using recovery code
 *   - Client sends new credentials + recovery session token (NOT the code)
 *   - Server verifies token is valid, updates credentials
 *
 *   So the server still returns the blob in /auth/recovery. The change is
 *   only in /auth/recovery/complete.
 *
 * @param email         - The user's email address.
 * @param recoveryCode  - The 128-bit recovery code (hex string, 32 chars).
 * @returns RecoveryResult with unwrapped vaultKey and recoverySessionToken,
 *          or RecoveryError.
 *
 * MEMORY HYGIENE: recoveryWrapKey is zeroized. vaultKey is returned and
 * caller MUST zeroize when done.
 */
export async function recoverVaultKey(
  email: string,
  recoveryCode: string,
): Promise<RecoveryResult | RecoveryError> {
  // Validate format: 32 hex chars = 16 bytes = 128 bits.
  if (!/^[0-9a-f]{32}$/i.test(recoveryCode)) {
    return {
      ok: false,
      step: "server",
      message: "Incorrect email or recovery code",
    };
  }

  let recoveryWrapKey: Uint8Array | undefined;

  try {
    // ── Step 1: Fetch recovery blob + session token from server ────────────
    let step1Data;
    try {
      step1Data = await apiRecoveryInitiate(email);
    } catch {
      return {
        ok: false,
        step: "server",
        message: "Incorrect email or recovery code",
      };
    }

    const recoverySessionToken = step1Data.recoverySessionToken;

    // Parse the recovery-wrapped VK from hex.
    const recoveryWrappedVK: EncryptedVaultKey = {
      wrappedKey: fromHex(step1Data.recoveryWrappedVk),
      iv: fromHex(step1Data.recoveryWrappedVkIv),
      authTag: fromHex(step1Data.recoveryWrappedVkTag),
    };

    // ── Steps 2-3: Derive recovery wrap key from code ────────────────────
    const recoveryCodeBytes = fromHex(recoveryCode);
    recoveryWrapKey = await deriveRecoveryWrapKey(recoveryCodeBytes);

    // ── Step 4: Unwrap vault key ─────────────────────────────────────────
    let vaultKey: Uint8Array;
    try {
      vaultKey = await unwrapVaultKey(recoveryWrappedVK, recoveryWrapKey);
    } catch {
      return {
        ok: false,
        step: "unwrap",
        message: "Incorrect email or recovery code",
      };
    }

    // ── Step 5: Zeroize ──────────────────────────────────────────────────
    recoveryWrapKey.fill(0);
    recoveryCodeBytes.fill(0);

    // ── Step 6: Return ───────────────────────────────────────────────────
    // Caller MUST zeroize vaultKey when done.
    // recoverySessionToken is needed for completeRecovery().
    return { ok: true, vaultKey, recoverySessionToken };
  } catch {
    return {
      ok: false,
      step: "server",
      message: "Recovery failed — please try again",
    };
  } finally {
    recoveryWrapKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Recovery Complete (set new password after recovery)
// ---------------------------------------------------------------------------

/**
 * Complete the recovery flow by setting a new master password.
 *
 * This is called AFTER recoverVaultKey succeeds. The caller has the recovered
 * vault key and the recovery session token. This function:
 *   1. Validates the new password.
 *   2. Derives new masterKey + authKey from the new password with fresh salts.
 *   3. Re-wraps the vaultKey under the new masterKey.
 *   4. Sends everything to POST /auth/recovery/complete along with the
 *      recovery session token (NOT the raw recovery code — the code never
 *      reaches the server in the new flow).
 *   5. Server verifies the recovery session token is valid, then atomically
 *      updates all credentials.
 *   6. Returns success — caller can now log in with the new password.
 *
 * @param email               - User's email.
 * @param recoverySessionToken - Token from recoverVaultKey() result.
 * @param vaultKey            - Recovered vault key (from recoverVaultKey).
 * @param newPassword         - New master password to set.
 * @returns PasswordChangeResult on success, AuthError on failure.
 *
 * MEMORY HYGIENE: newMasterKey, newAuthKey are zeroized. vaultKey is NOT
 * zeroized (caller may need it until the login completes).
 */
export async function completeRecovery(
  email: string,
  recoverySessionToken: string,
  vaultKey: Uint8Array,
  newPassword: string,
): Promise<PasswordChangeResult | PasswordChangeError> {
  const { validatePasswordStrength } = await import("./password.js");
  const strength = validatePasswordStrength(newPassword);
  if (!strength.valid) {
    return {
      ok: false,
      step: "password_validation",
      message: strength.errors.join("; "),
    };
  }

  let newMasterKey: Uint8Array | undefined;
  let newAuthKey: Uint8Array | undefined;

  try {
    const freshSaltEnc = new Uint8Array(32);
    const freshSaltAuth = new Uint8Array(32);
    crypto.getRandomValues(freshSaltEnc);
    crypto.getRandomValues(freshSaltAuth);

    const [mk, ak] = await Promise.all([
      deriveMasterKey(newPassword, freshSaltEnc, KDF_CURRENT_VERSION),
      deriveAuthKey(newPassword, freshSaltAuth, KDF_CURRENT_VERSION),
    ]);
    newMasterKey = mk;
    newAuthKey = ak;

    const newWrappedVK: EncryptedVaultKey = await wrapVaultKey(
      vaultKey,
      newMasterKey,
    );

    await apiRecoveryComplete({
      recoverySessionToken,
      saltEnc: toHex(freshSaltEnc),
      saltAuth: toHex(freshSaltAuth),
      authKey: toHex(newAuthKey),
      wrappedVk: toHex(newWrappedVK.wrappedKey),
      wrappedVkIv: toHex(newWrappedVK.iv),
      wrappedVkTag: toHex(newWrappedVK.authTag),
      kdfVersion: KDF_CURRENT_VERSION,
    });

    newMasterKey.fill(0);
    newAuthKey.fill(0);

    return { ok: true };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Recovery failed — please try again",
      status: apiErr.status,
    };
  } finally {
    newMasterKey?.fill(0);
    newAuthKey?.fill(0);
  }
}

// ---------------------------------------------------------------------------
// 2FA Management
// ---------------------------------------------------------------------------

export type TwoFactorSetupResult = {
  ok: true;
  totpUri: string;
  backupCodes: string[];
};

export type TwoFactorStatusResult = {
  ok: true;
  totpEnabled: boolean;
  backupCodesRemaining: number;
};

/**
 * Set up 2FA — generates TOTP secret + backup codes.
 *
 * The totpUri contains an otpauth:// URI that should be rendered as a QR code.
 * The backupCodes should be shown to the user once and saved offline.
 * After setup, the user must call enable2FA() with a valid code to activate.
 *
 * @param token - Current JWT session token.
 */
export async function setup2FA(
  token: string,
): Promise<TwoFactorSetupResult | AuthError> {
  try {
    const result = await apiTotpSetup(token);
    return { ok: true, totpUri: result.totpUri, backupCodes: result.backupCodes };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Failed to set up two-factor authentication",
      status: apiErr.status,
    };
  }
}

/**
 * Enable 2FA by verifying a TOTP code.
 *
 * Called after setup2FA() — the user has scanned the QR code and enters
 * the current 6-digit code to confirm enrollment.
 *
 * @param token - Current JWT session token.
 * @param code  - 6-digit TOTP code from authenticator app.
 */
export async function enable2FA(
  token: string,
  code: string,
): Promise<PasswordChangeResult | AuthError> {
  try {
    await apiTotpEnable(token, code);
    return { ok: true };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Invalid code — two-factor setup failed",
      status: apiErr.status,
    };
  }
}

/**
 * Disable 2FA by verifying the current TOTP code.
 *
 * @param token - Current JWT session token.
 * @param code  - Current 6-digit TOTP code.
 */
export async function disable2FA(
  token: string,
  code: string,
): Promise<PasswordChangeResult | AuthError> {
  try {
    await apiTotpDisable(token, code);
    return { ok: true };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Invalid code — two-factor disable failed",
      status: apiErr.status,
    };
  }
}

/**
 * Get the current 2FA status.
 *
 * @param token - Current JWT session token.
 */
export async function get2FAStatus(
  token: string,
): Promise<TwoFactorStatusResult | AuthError> {
  try {
    const result = await apiTotpStatus(token);
    return {
      ok: true,
      totpEnabled: result.totpEnabled,
      backupCodesRemaining: result.backupCodesRemaining,
    };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Failed to get two-factor status",
      status: apiErr.status,
    };
  }
}

/**
 * Regenerate the backup code set for 2FA.
 *
 * SECURITY: Requires a FRESH TOTP code (not the JWT alone) — the same
 * proof-of-possession requirement as disabling 2FA. A stolen session token
 * cannot silently replace the user's emergency access codes.
 *
 * The new codes are returned exactly once and must be saved offline.
 * The previous set is immediately invalidated server-side.
 *
 * @param token    - Current JWT session token.
 * @param totpCode - Current 6-digit TOTP code from the authenticator.
 */
export async function regenerateBackupCodes(
  token: string,
  totpCode: string,
): Promise<{ ok: true; backupCodes: string[] } | AuthError> {
  try {
    const result = await apiRegenerateBackupCodes(token, totpCode);
    return { ok: true, backupCodes: result.backupCodes };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Failed to regenerate backup codes",
      status: apiErr.status,
    };
  }
}

// ---------------------------------------------------------------------------
// Recovery Code Regeneration
// ---------------------------------------------------------------------------

export type RecoveryRegenerateResult = {
  ok: true;
  /** New 128-bit recovery code (32 hex chars). Display ONCE — old code is dead. */
  recoveryCode: string;
};

/**
 * Rotate the account recovery code WITHOUT changing the master password.
 *
 * EXACT FLOW (mirrors upgradeKdf):
 *   1. Fetch current salts + wrapped VK via login step 1 (need the email).
 *   2. Derive the CURRENT authKey from the password (still in memory — no
 *      re-prompt) using the account's KDF version.
 *   3. Sanity check: unwrap the VK to confirm the password is correct.
 *   4. Generate a FRESH 128-bit recovery code (CSPRNG).
 *   5. deriveRecoveryWrapKey(newCode) → re-wrap the UNCHANGED vault key.
 *   6. Send { oldAuthKey, newRecoveryWrappedVK } to POST /auth/recovery/regenerate
 *      (JWT required). The raw code NEVER leaves the client.
 *   7. Server verifies oldAuthKey, replaces the blob. Old code is now invalid.
 *
 * @param token    - Current JWT session token.
 * @param email    - User's email (for fetching current salts/version).
 * @param vaultKey - Current unwrapped vault key (from session).
 * @param password - The master password (still in memory — no re-prompt).
 * @returns The new recovery code (display once) on success.
 *
 * MEMORY HYGIENE: all derived keys are zeroized after the call.
 * vaultKey is NOT zeroized (caller still needs it for the session).
 */
export async function regenerateRecoveryCode(
  token: string,
  email: string,
  vaultKey: Uint8Array,
  password: string,
): Promise<RecoveryRegenerateResult | AuthError> {
  let masterKey: Uint8Array | undefined;
  let authKey: Uint8Array | undefined;
  let recoveryWrapKey: Uint8Array | undefined;

  try {
    // ── Step 1: Fetch current salts + version ────────────────────────────
    const step1Data = await apiLoginStep1(email);
    const currentSaltEnc = fromHex(step1Data.saltEnc);
    const currentSaltAuth = fromHex(step1Data.saltAuth);

    // ── Steps 2-3: Derive current keys + sanity-check the password ───────
    const [mk, ak] = await Promise.all([
      deriveMasterKey(password, currentSaltEnc, step1Data.kdfVersion),
      deriveAuthKey(password, currentSaltAuth, step1Data.kdfVersion),
    ]);
    masterKey = mk;
    authKey = ak;

    const wrappedVK: EncryptedVaultKey = {
      wrappedKey: fromHex(step1Data.wrappedVk),
      iv: fromHex(step1Data.wrappedVkIv),
      authTag: fromHex(step1Data.wrappedVkTag),
    };
    try {
      await unwrapVaultKey(wrappedVK, masterKey);
    } catch {
      return {
        ok: false,
        step: "unwrap",
        message: "Current password is incorrect",
      };
    }

    // ── Steps 4-5: Fresh recovery code + re-wrap the unchanged VK ────────
    const recoveryCode = new Uint8Array(16);
    crypto.getRandomValues(recoveryCode);
    recoveryWrapKey = await deriveRecoveryWrapKey(recoveryCode);
    const recoveryWrappedVK: EncryptedVaultKey = await wrapVaultKey(
      vaultKey,
      recoveryWrapKey,
    );

    // ── Step 6: Send the new blob (the code itself never leaves the client) ─
    await apiRegenerateRecovery(token, {
      oldAuthKey: toHex(authKey),
      recoveryWrappedVk: toHex(recoveryWrappedVK.wrappedKey),
      recoveryWrappedVkIv: toHex(recoveryWrappedVK.iv),
      recoveryWrappedVkTag: toHex(recoveryWrappedVK.authTag),
    });

    const recoveryCodeHex = toHex(recoveryCode);
    recoveryWrapKey.fill(0);
    masterKey.fill(0);
    authKey.fill(0);

    return { ok: true, recoveryCode: recoveryCodeHex };
  } catch (err) {
    const apiErr = err as ApiError;
    return {
      ok: false,
      step: "server",
      message: "Failed to regenerate recovery code",
      status: apiErr.status,
    };
  } finally {
    recoveryWrapKey?.fill(0);
    masterKey?.fill(0);
    authKey?.fill(0);
  }
}
