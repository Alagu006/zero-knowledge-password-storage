/**
 * HTTP API client for the ZKM backend.
 *
 * This module handles ONLY the wire protocol — it knows nothing about
 * cryptography. It sends hex-encoded blobs and receives hex-encoded blobs.
 * All key derivation, wrapping, and encryption happens in the auth module.
 *
 * DESIGN DECISION — client-generated salts:
 *   Salts are generated client-side (crypto.getRandomValues) rather than
 *   server-issued. Rationale:
 *   1. A malicious server cannot influence salt quality (force weak salts).
 *   2. No extra round-trip at registration time.
 *   3. Salts are NOT secret (per Kerckhoffs's principle) — sending them
 *      to the server is safe. The server stores them for the login step 1
 *      retrieval.
 *
 * TIMING ATTACK NOTE:
 *   This client sends authKey to the server for comparison. The server uses
 *   crypto.timingSafeEqual (constant-time). The client cannot do the same
 *   server-side; it trusts TLS to protect the transport. This is the
 *   documented trade-off of the Argon2id-verifier approach vs SRP-6a.
 */

import type { EncryptedVaultKey } from "../crypto/types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ApiError = {
  status: number;
  message: string;
};

export type LoginStep1Response = {
  saltEnc: string;   // hex
  saltAuth: string;  // hex
  wrappedVk: string; // hex
  wrappedVkIv: string;
  wrappedVkTag: string;
  kdfVersion: number; // Argon2id parameter version used for this account
};

export type LoginStep2Response = {
  token: string; // JWT
  tempToken?: string; // short-lived 2FA token (when 2FA is enabled)
  twoFactorRequired?: boolean;
};

export type RegisterRequest = {
  email: string;
  saltEnc: string;
  saltAuth: string;
  authKey: string;       // hex — the auth verifier
  wrappedVk: string;     // hex — vault key ciphertext
  wrappedVkIv: string;
  wrappedVkTag: string;
  kdfVersion: number;    // Argon2id parameter version used to derive keys
  // Optional recovery blob: vault key wrapped under recovery code.
  recoveryWrappedVk?: string;
  recoveryWrappedVkIv?: string;
  recoveryWrappedVkTag?: string;
};

export type VaultEntryResponse = {
  id: string;
  entryType: string;
  nonce: string;
  ciphertext: string;
  authTag: string;
  version: number;
  createdAt: string;
  updatedAt: string;
};

// ---------------------------------------------------------------------------
// Internal fetch wrapper
// ---------------------------------------------------------------------------

/**
 * Low-level fetch wrapper. All API calls go through here.
 * Throws ApiError on non-2xx responses.
 */
async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let message = "Request failed";
    try {
      const err = await res.json() as { error?: string };
      message = err.error ?? message;
    } catch {
      // response body not JSON — use status text
      message = res.statusText || message;
    }
    throw { status: res.status, message } as ApiError;
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

/** POST /auth/register — store the derived auth verifier + wrapped VK. */
export function apiRegister(req: RegisterRequest): Promise<{ message: string }> {
  return request("POST", "/auth/register", req);
}

/**
 * POST /auth/login — step 1: retrieve salts + wrapped VK for the given email.
 * Returns random dummies if the email doesn't exist (prevents enumeration).
 */
export function apiLoginStep1(email: string): Promise<LoginStep1Response> {
  return request("POST", "/auth/login", { email });
}

/**
 * POST /auth/login/verify — step 2: submit the auth verifier for
 * constant-time comparison. Returns a JWT on success.
 */
export function apiLoginStep2(
  email: string,
  authKey: string,
): Promise<LoginStep2Response> {
  return request("POST", "/auth/login/verify", { email, authKey });
}

// ---------------------------------------------------------------------------
// Vault endpoints
// ---------------------------------------------------------------------------

/** GET /vault/entries — list all encrypted entries for the authenticated user. */
export function apiListEntries(
  token: string,
): Promise<{ entries: VaultEntryResponse[] }> {
  return request("GET", "/vault/entries", undefined, token);
}

/** POST /vault/entries — create a new encrypted entry. */
export function apiCreateEntry(
  token: string,
  entry: { entryType: string; nonce: string; ciphertext: string; authTag: string },
): Promise<VaultEntryResponse> {
  return request("POST", "/vault/entries", entry, token);
}

/** PUT /vault/entries/:id — update an existing entry (optimistic concurrency). */
export function apiUpdateEntry(
  token: string,
  id: string,
  entry: { entryType?: string; nonce: string; ciphertext: string; authTag: string; version: number },
): Promise<VaultEntryResponse> {
  return request("PUT", `/vault/entries/${id}`, entry, token);
}

/** DELETE /vault/entries/:id — permanently remove an entry. */
export function apiDeleteEntry(
  token: string,
  id: string,
): Promise<void> {
  return request("DELETE", `/vault/entries/${id}`, undefined, token);
}

// ---------------------------------------------------------------------------
// Helpers for hex conversion (used by auth module)
// ---------------------------------------------------------------------------

/** Convert Uint8Array to lowercase hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert hex string to Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Password change endpoint
// ---------------------------------------------------------------------------

export type ChangePasswordRequest = {
  oldAuthKey: string;
  saltEnc: string;
  saltAuth: string;
  authKey: string;
  wrappedVk: string;
  wrappedVkIv: string;
  wrappedVkTag: string;
  kdfVersion: number;
};

/** PUT /auth/password — change master password (re-wrap VK, requires JWT). */
export function apiChangePassword(
  token: string,
  req: ChangePasswordRequest,
): Promise<{ message: string }> {
  return request("PUT", "/auth/password", req, token);
}

/**
 * PUT /auth/kdf-upgrade — migrate an account to newer Argon2id parameters.
 * Request shape is identical to a password change (old auth key for proof of
 * possession + new credentials derived under the newer parameters).
 */
export function apiKdfUpgrade(
  token: string,
  req: ChangePasswordRequest,
): Promise<{ message: string }> {
  return request("PUT", "/auth/kdf-upgrade", req, token);
}

// ---------------------------------------------------------------------------
// Account recovery endpoints
// ---------------------------------------------------------------------------

export type RecoveryInitiateResponse = {
  recoverySessionToken: string;
  recoveryWrappedVk: string;  // hex
  recoveryWrappedVkIv: string;
  recoveryWrappedVkTag: string;
};

/** POST /auth/recovery — fetch recovery blob + session token for an email (anti-enumeration). */
export function apiRecoveryInitiate(
  email: string,
): Promise<RecoveryInitiateResponse> {
  return request("POST", "/auth/recovery", { email });
}

export type RecoveryCompleteRequest = {
  recoverySessionToken: string;
  saltEnc: string;
  saltAuth: string;
  authKey: string;
  wrappedVk: string;
  wrappedVkIv: string;
  wrappedVkTag: string;
  kdfVersion: number;
};

/** POST /auth/recovery/complete — finalize recovery with new credentials. */
export function apiRecoveryComplete(
  req: RecoveryCompleteRequest,
): Promise<{ message: string }> {
  return request("POST", "/auth/recovery/complete", req);
}

// ---------------------------------------------------------------------------
// 2FA endpoints
// ---------------------------------------------------------------------------

export type TwoFactorSetupResponse = {
  totpUri: string;     // otpauth:// URI for QR code
  backupCodes: string[]; // 10 formatted backup codes (XXXX-XXXX)
};

export type TwoFactorStatusResponse = {
  totpEnabled: boolean;
  backupCodesRemaining: number;
};

/** POST /auth/2fa/setup — generate TOTP secret + backup codes (JWT required). */
export function apiTotpSetup(
  token: string,
): Promise<TwoFactorSetupResponse> {
  return request("POST", "/auth/2fa/setup", undefined, token);
}

/** POST /auth/2fa/enable — verify TOTP code to activate 2FA (JWT required). */
export function apiTotpEnable(
  token: string,
  code: string,
): Promise<{ message: string }> {
  return request("POST", "/auth/2fa/enable", { code }, token);
}

/** POST /auth/2fa/disable — disable 2FA (requires current TOTP code). */
export function apiTotpDisable(
  token: string,
  code: string,
): Promise<{ message: string }> {
  return request("POST", "/auth/2fa/disable", { code }, token);
}

/** POST /auth/2fa/verify — verify TOTP code during login (tempToken + code). */
export function apiTotpVerify(
  tempToken: string,
  code: string,
): Promise<{ token: string }> {
  return request("POST", "/auth/2fa/verify", { tempToken, code });
}

/** POST /auth/2fa/backup-verify — verify backup code during login. */
export function apiBackupCodeVerify(
  tempToken: string,
  code: string,
): Promise<{ token: string }> {
  return request("POST", "/auth/2fa/backup-verify", { tempToken, code });
}

/** GET /auth/2fa/status — check 2FA enrollment status (JWT required). */
export function apiTotpStatus(
  token: string,
): Promise<TwoFactorStatusResponse> {
  return request("GET", "/auth/2fa/status", undefined, token);
}

/** POST /auth/2fa/backup-codes/regenerate — rotate backup codes (JWT + fresh TOTP code). */
export function apiRegenerateBackupCodes(
  token: string,
  code: string,
): Promise<{ backupCodes: string[] }> {
  return request("POST", "/auth/2fa/backup-codes/regenerate", { code }, token);
}

export type RecoveryRegenerateRequest = {
  oldAuthKey: string;
  recoveryWrappedVk: string;
  recoveryWrappedVkIv: string;
  recoveryWrappedVkTag: string;
};

/** POST /auth/recovery/regenerate — rotate the recovery code (JWT + current authKey). */
export function apiRegenerateRecovery(
  token: string,
  req: RecoveryRegenerateRequest,
): Promise<{ message: string }> {
  return request("POST", "/auth/recovery/regenerate", req, token);
}

// ---------------------------------------------------------------------------
// Session management endpoints
// ---------------------------------------------------------------------------

export type SessionInfo = {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
  active: boolean;
  current: boolean;
};

/** GET /auth/sessions — list the current user's sessions (JWT required). */
export function apiListSessions(
  token: string,
): Promise<{ sessions: SessionInfo[] }> {
  return request("GET", "/auth/sessions", undefined, token);
}

/** DELETE /auth/sessions/:id — revoke a single session (JWT required). */
export function apiRevokeSession(
  token: string,
  sessionId: string,
): Promise<{ message: string }> {
  return request("DELETE", `/auth/sessions/${sessionId}`, undefined, token);
}

/** DELETE /auth/sessions — revoke every session except the current one. */
export function apiRevokeAllSessions(
  token: string,
): Promise<{ message: string }> {
  return request("DELETE", "/auth/sessions", undefined, token);
}
