/**
 * Zero-Knowledge Password Manager — Client-Side Cryptographic Core
 *
 * This module is framework-free and uses only:
 *   - hash-wasm (Argon2id WASM implementation)
 *   - Web Crypto API (SubtleCrypto) for AES-256-GCM
 *   - crypto.getRandomValues for CSPRNG
 *
 * LIBRARY CHOICE — hash-wasm vs argon2-browser:
 *   hash-wasm is chosen because it works in BOTH browser and Node.js via a
 *   pure WASM build with no native bindings. argon2-browser is browser-only
 *   (relies on browser-specific WASM instantiation) and cannot be used in
 *   Node test suites without polyfills. hash-wasm wraps the reference Argon2
 *   C implementation compiled to WASM and has been widely adopted.
 *
 * KNOWN LIMITATION — JavaScript GC and key material:
 *   JS strings are immutable and cannot be zeroed. Uint8Array buffers CAN be
 *   overwritten with zeros, but the GC may have already copied them during
 *   reallocation, and the engine's string/number representation is outside
 *   our control. This is an inherent platform limitation. Mitigations:
 *   - We zeroize every Uint8Array we allocate for key/password material.
 *   - We avoid creating unnecessary intermediate copies.
 *   - We never log, serialize, or return key material unnecessarily.
 *   Residual copies in GC-managed memory remain a theoretical risk.
 */

import { argon2id } from "hash-wasm";
import {
  AES_KEY_LENGTH,
  AES_GCM_IV_LENGTH,
  AES_GCM_TAG_LENGTH,
  KDF_CONTEXT_MASTER,
  KDF_CONTEXT_AUTH,
  KDF_CONTEXT_RECOVERY,
  KDF_CURRENT_VERSION,
  getArgon2Params,
  type Argon2Params,
} from "./constants.js";
import type { EncryptedEntry, EncryptedVaultKey } from "./types.js";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Ensure a Uint8Array is backed by a plain ArrayBuffer (not SharedArrayBuffer),
 * which is required by Web Crypto API's BufferSource type under TS 5.6+.
 * Returns the same reference if already backed by ArrayBuffer.
 */
function asAB(buf: Uint8Array): Uint8Array<ArrayBuffer> {
  if (buf.buffer instanceof ArrayBuffer) {
    return buf as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(buf);
}

/**
 * Import raw AES key bytes into a non-extractable CryptoKey.
 * Non-extractable: the key cannot be exported back to raw bytes from the
 * CryptoKey object, reducing the attack surface if the key object is leaked.
 */
async function importAesGcmKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    asAB(keyBytes),
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false, // not extractable
    ["encrypt", "decrypt"],
  );
}

/**
 * Build a domain-separated salt: application_context ‖ user_salt.
 * This ensures deriveMasterKey and deriveAuthKey produce unrelated outputs
 * even if called with the same user-supplied salt (which they shouldn't be,
 * but defense in depth).
 */
function buildDomainSeparatedSalt(
  context: string,
  userSalt: Uint8Array,
): Uint8Array {
  const ctxBytes = new TextEncoder().encode(context);
  const combined = new Uint8Array(ctxBytes.length + userSalt.length);
  combined.set(ctxBytes);
  combined.set(userSalt, ctxBytes.length);
  return combined;
}

/**
 * Run Argon2id with the given parameters and return the raw hash bytes.
 * Password bytes are zeroized after use.
 */
async function runArgon2id(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
): Promise<Uint8Array> {
  const result = await argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memory,
    hashLength: params.outputLength,
    outputType: "binary",
  });
  return result;
}

/**
 * Split an AES-GCM ciphertext+tag buffer into its two components.
 * Web Crypto returns `ciphertext ‖ authTag` as a single ArrayBuffer.
 */
function splitCiphertextTag(
  combined: ArrayBuffer,
): { ciphertext: Uint8Array; authTag: Uint8Array } {
  const bytes = new Uint8Array(combined);
  const ciphertext = bytes.slice(0, bytes.length - AES_GCM_TAG_LENGTH);
  const authTag = bytes.slice(bytes.length - AES_GCM_TAG_LENGTH);
  return { ciphertext, authTag };
}

/**
 * Concatenate ciphertext and auth tag into a single buffer for Web Crypto
 * decrypt / the wire format.
 */
function concatCiphertextTag(
  ciphertext: Uint8Array,
  authTag: Uint8Array,
): Uint8Array {
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);
  return combined;
}

// ---------------------------------------------------------------------------
// 1. deriveMasterKey
// ---------------------------------------------------------------------------

/**
 * Derive a 256-bit Master Key from the master password and a user-specific
 * salt using Argon2id.
 *
 * The master password NEVER leaves the client. The returned key is used
 * solely to unwrap the Vault Key; it is never transmitted to the server.
 *
 * @param masterPassword - The user's master password (plaintext, in-memory only).
 * @param salt           - Random per-user salt (stored on server, NOT secret).
 * @param version        - KDF parameter version (defaults to the current
 *   version). Pass the account's stored kdfVersion so legacy accounts keep
 *   deriving the same key after the parameter table is upgraded.
 * @returns 32-byte Uint8Array containing the Master Key.
 *
 * MEMORY HYGIENE: The password byte array is zeroed after KDF. The returned
 * key MUST be zeroed by the caller when no longer needed.
 */
export async function deriveMasterKey(
  masterPassword: string,
  salt: Uint8Array,
  version: number = KDF_CURRENT_VERSION,
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(masterPassword);
  const domainSalt = buildDomainSeparatedSalt(KDF_CONTEXT_MASTER, salt);

  try {
    const key = await runArgon2id(
      passwordBytes,
      domainSalt,
      getArgon2Params("master", version),
    );
    return key;
  } finally {
    passwordBytes.fill(0);
  }
}

// ---------------------------------------------------------------------------
// 2. deriveAuthKey
// ---------------------------------------------------------------------------

/**
 * Derive an Auth Key from the master password using Argon2id with a
 * SEPARATE salt context, then hash the result with SHA-256 to produce
 * a fixed-format authentication verifier.
 *
 * The two KDF contexts (master vs auth) use:
 *   - Different application-level context strings (domain separation)
 *   - Different user salts (must be stored independently on server)
 *   - The same Argon2id parameters (same cost, independent outputs)
 *
 * Even if an attacker obtains the auth verifier (stored on server) and
 * the auth salt, they cannot derive the Master Key because:
 *   (a) the salt is different, and
 *   (b) the Argon2id output is further hashed with SHA-256, destroying
 *       any algebraic relationship to the MK derivation path.
 *
 * @param masterPassword - The user's master password.
 * @param authSalt       - Random per-user auth salt (stored on server).
 * @param version        - KDF parameter version (defaults to the current
 *   version). Pass the account's stored kdfVersion for stable re-derivation.
 * @returns 32-byte Uint8Array: SHA-256(Argon2id(MP, salt_auth ‖ context)).
 *
 * MEMORY HYGIENE: password bytes zeroized after KDF.
 */
export async function deriveAuthKey(
  masterPassword: string,
  authSalt: Uint8Array,
  version: number = KDF_CURRENT_VERSION,
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(masterPassword);
  const domainSalt = buildDomainSeparatedSalt(KDF_CONTEXT_AUTH, authSalt);

  try {
    const argonHash = await runArgon2id(
      passwordBytes,
      domainSalt,
      getArgon2Params("auth", version),
    );

    // SHA-256 to shape into fixed auth-verifier format and destroy any
    // potential relationship to the raw Argon2id output used for MK.
    const sha256Hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", asAB(argonHash)),
    );

    // Zeroize the intermediate Argon2id output
    argonHash.fill(0);

    return sha256Hash;
  } finally {
    passwordBytes.fill(0);
  }
}

// ---------------------------------------------------------------------------
// 3. generateVaultKey
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically secure random 256-bit Vault Key.
 *
 * The Vault Key is the symmetric key that encrypts individual vault entries.
 * It is generated once, stored encrypted (wrapped) on the server, and never
 * transmitted in plaintext.
 *
 * Uses crypto.getRandomValues which is backed by the OS CSPRNG
 * (/dev/urandom on Linux, BCryptGenRandom on Windows, arc4random on macOS).
 *
 * @returns 32-byte random Uint8Array.
 *
 * MEMORY HYGIENE: The caller MUST zero this buffer when no longer needed.
 */
export function generateVaultKey(): Uint8Array {
  const key = new Uint8Array(AES_KEY_LENGTH / 8);
  crypto.getRandomValues(key);
  return key;
}

// ---------------------------------------------------------------------------
// 4. wrapVaultKey / unwrapVaultKey
// ---------------------------------------------------------------------------

/**
 * Encrypt the Vault Key under the Master Key using AES-256-GCM.
 *
 * The wrapped key is stored on the server. The server can return it to the
 * client, but cannot unwrap it without the Master Key (which is derived from
 * the Master Password and never leaves the client).
 *
 * A fresh random 96-bit IV is generated per wrap call.
 *
 * @param vaultKey  - The 256-bit Vault Key to encrypt.
 * @param masterKey - The 256-bit Master Key (derived from password).
 * @returns EncryptedVaultKey containing {wrappedKey, iv, authTag}.
 *
 * MEMORY HYGIENE: inputs are NOT zeroed here (caller may need them);
 * the caller should zero masterKey after this call.
 */
export async function wrapVaultKey(
  vaultKey: Uint8Array,
  masterKey: Uint8Array,
): Promise<EncryptedVaultKey> {
  const iv = new Uint8Array(AES_GCM_IV_LENGTH);
  crypto.getRandomValues(iv);

  const cryptoKey = await importAesGcmKey(masterKey);
  const combined = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: AES_GCM_TAG_LENGTH * 8 },
    cryptoKey,
    asAB(vaultKey),
  );

  const { ciphertext, authTag } = splitCiphertextTag(combined);
  return { wrappedKey: ciphertext, iv, authTag };
}

/**
 * Decrypt the Vault Key using the Master Key.
 *
 * Throws a descriptive error if the Master Key is wrong or the data is
 * corrupted. NEVER returns silently with wrong data — AES-GCM's
 * authentication tag guarantees tamper detection.
 *
 * @param encrypted - The EncryptedVaultKey from the server.
 * @param masterKey - The 256-bit Master Key.
 * @returns The decrypted 256-bit Vault Key.
 * @throws Error if decryption fails (wrong key or tampered data).
 *
 * MEMORY HYGIENE: The returned Vault Key MUST be zeroed by the caller
 * when no longer needed.
 */
export async function unwrapVaultKey(
  encrypted: EncryptedVaultKey,
  masterKey: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importAesGcmKey(masterKey);
  const combined = concatCiphertextTag(encrypted.wrappedKey, encrypted.authTag);

  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asAB(encrypted.iv), tagLength: AES_GCM_TAG_LENGTH * 8 },
      cryptoKey,
      asAB(combined),
    );
    return new Uint8Array(plainBuf);
  } catch {
    throw new Error(
      "Vault key unwrap failed: wrong master key or data corrupted/tampered",
    );
  }
}

// ---------------------------------------------------------------------------
// 5. encryptEntry
// ---------------------------------------------------------------------------

/**
 * Encrypt a vault entry's plaintext using AES-256-GCM with a fresh
 * random 96-bit IV.
 *
 * IVs are NEVER derived deterministically (no counter, no hash of
 * plaintext). Each call generates a cryptographically random IV via
 * crypto.getRandomValues, making IV collision negligible up to ~2^48
 * entries per vault (birthday bound on 96-bit space).
 *
 * @param plaintext - The entry data to encrypt (arbitrary bytes).
 * @param vaultKey  - The 256-bit Vault Key.
 * @returns EncryptedEntry containing {ciphertext, iv, authTag}.
 *
 * MEMORY HYGIENE: plaintext is NOT zeroed (caller owns the buffer).
 * The caller should zero plaintext after this call.
 */
export async function encryptEntry(
  plaintext: Uint8Array,
  vaultKey: Uint8Array,
): Promise<EncryptedEntry> {
  const iv = new Uint8Array(AES_GCM_IV_LENGTH);
  crypto.getRandomValues(iv);

  const cryptoKey = await importAesGcmKey(vaultKey);
  const combined = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: AES_GCM_TAG_LENGTH * 8 },
    cryptoKey,
    asAB(plaintext),
  );

  const { ciphertext, authTag } = splitCiphertextTag(combined);
  return { ciphertext, iv, authTag };
}

// ---------------------------------------------------------------------------
// 6. decryptEntry
// ---------------------------------------------------------------------------

/**
 * Decrypt a vault entry using AES-256-GCM.
 *
 * CRITICAL: This function throws on ANY authentication failure — wrong key,
 * tampered ciphertext, or corrupted auth tag. It NEVER returns partial or
 * garbage data. This is a fundamental property of AES-GCM: the
 * authentication tag is verified BEFORE any plaintext is released.
 *
 * @param encrypted - The EncryptedEntry (ciphertext, iv, authTag).
 * @param vaultKey  - The 256-bit Vault Key.
 * @returns The decrypted plaintext as Uint8Array.
 * @throws Error if decryption fails (wrong key or tampered data).
 *
 * MEMORY HYGIENE: The returned plaintext MUST be zeroed by the caller
 * when no longer needed.
 */
export async function decryptEntry(
  encrypted: EncryptedEntry,
  vaultKey: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importAesGcmKey(vaultKey);
  const combined = concatCiphertextTag(encrypted.ciphertext, encrypted.authTag);

  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asAB(encrypted.iv), tagLength: AES_GCM_TAG_LENGTH * 8 },
      cryptoKey,
      asAB(combined),
    );
    return new Uint8Array(plainBuf);
  } catch {
    throw new Error(
      "Entry decryption failed: wrong key, tampered data, or corrupted auth tag",
    );
  }
}

// ---------------------------------------------------------------------------
// 7. deriveRecoveryWrapKey — recovery key derivation
// ---------------------------------------------------------------------------

/**
 * Derive a 256-bit wrapping key from the raw recovery code bytes using
 * SHA-256 with domain separation.
 *
 * The recovery code is 128 bits of entropy (16 bytes from CSPRNG).
 * SHA-256 stretches it to 256 bits for AES-256 wrapping.
 * The domain separator prevents the recovery wrap key from being usable
 * as a master key or auth key even if the same bytes appeared in another
 * context (defense in depth — the code bytes should never be reused, but
 * the cost of domain separation is negligible).
 *
 * SECURITY MODEL:
 *   - The recovery code is generated ONCE at registration and shown to
 *     the user exactly once. The server NEVER sees the raw code — only
 *     the wrapped-vault-key blob that requires it to unwrap.
 *   - The recovery code provides a SECOND path to the vault key, bypassing
 *     the master password. This is the explicit trade-off of recovery vs
 *     pure zero-knowledge: without it, a forgotten master password means
 *     an unrecoverable vault.
 *
 * @param recoveryCode - 16-byte CSPRNG value (128 bits).
 * @returns 32-byte Uint8Array wrapping key for vault key recovery.
 *
 * MEMORY HYGIENE: recoveryCode is NOT zeroed (caller owns the buffer).
 */
export async function deriveRecoveryWrapKey(
  recoveryCode: Uint8Array,
): Promise<Uint8Array> {
  const ctxBytes = new TextEncoder().encode(KDF_CONTEXT_RECOVERY);
  const input = new Uint8Array(ctxBytes.length + recoveryCode.length);
  input.set(ctxBytes);
  input.set(recoveryCode, ctxBytes.length);

  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", asAB(input)),
  );

  // Zeroize intermediate
  input.fill(0);

  return hash;
}

// ---------------------------------------------------------------------------
// 8. zeroize — memory hygiene
// ---------------------------------------------------------------------------

/**
 * Overwrite a Uint8Array buffer with zeros.
 *
 * This is the ONLY reliable way to scrub key material from JS heap memory.
 * It should be called on every sensitive buffer (derived keys, plaintext
 * passwords as bytes, vault keys) as soon as they are no longer needed.
 *
 * KNOWN LIMITATIONS (JavaScript GC):
 *   1. JS strings (e.g. the master password itself) are IMMUTABLE and
 *      cannot be zeroed. They persist in V8 heap until GC collects them,
 *      and V8 may keep internal copies in string tables or JIT code.
 *   2. Uint8Array backing buffers may have been COPIED by the GC during
 *      reallocation. The original memory region may still contain key bytes
 *      after we zero the current view.
 *   3. Engines may optimize out fill(0) if they detect the buffer is
 *      "dead" — though in practice V8 does not do this for live references.
 *
 * These are fundamental JavaScript platform limitations, not defects in
 * this library. A native (Rust/C) extension could use explicit_bzero or
 * Platform::SecureZeroMemory for stronger guarantees.
 *
 * @param buffer - The Uint8Array to overwrite with zeros.
 */
export function zeroize(buffer: Uint8Array): void {
  buffer.fill(0);
}
