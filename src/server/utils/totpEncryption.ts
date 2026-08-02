/**
 * Application-level envelope encryption for TOTP secrets.
 *
 * The TOTP secret is encrypted under a server-side key (TOTP_ENCRYPTION_KEY)
 * using AES-256-GCM with a fresh random IV. This provides defense-in-depth:
 * even if the database is compromised, the TOTP secrets are encrypted at
 * the application layer (in addition to any DB-level encryption).
 *
 * WHY NOT DB-ONLY ENCRYPTION?
 *   DB-level encryption (e.g., PostgreSQL pgcrypto Transparent Data Encryption)
 *   protects at rest but exposes plaintext to the application process. If the
 *   server is compromised (RCE, memory dump), DB-level encryption provides no
 *   additional protection. Application-level envelope encryption means the
 *   decryption key is separate from the database — an attacker with DB access
 *   but without the TOTP_ENCRYPTION_KEY cannot decrypt TOTP secrets.
 *
 * KEY MANAGEMENT:
 *   TOTP_ENCRYPTION_KEY is a 32-byte (256-bit) hex-encoded string loaded from
 *   environment variables. It is NEVER stored in the database or logged.
 *   Rotate by re-encrypting all TOTP secrets with the new key.
 */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96 bits — NIST-recommended for GCM
const TAG_LENGTH = 16; // 128 bits — default GCM auth tag

export interface EncryptedTOTPSecret {
  /** AES-256-GCM ciphertext. */
  ciphertext: Buffer;
  /** Random 96-bit IV. */
  iv: Buffer;
  /** GCM authentication tag. */
  tag: Buffer;
}

/**
 * Encrypt a TOTP secret using AES-256-GCM under the server's envelope key.
 *
 * @param secret    - Raw TOTP secret bytes (typically 20 bytes).
 * @param encryptionKey - 32-byte key from TOTP_ENCRYPTION_KEY env var.
 * @returns EncryptedTOTPSecret with ciphertext, iv, and tag.
 */
export function encryptTotpSecret(
  secret: Uint8Array,
  encryptionKey: Buffer,
): EncryptedTOTPSecret {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv, {
    authTagLength: TAG_LENGTH,
  });

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(secret)),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return { ciphertext, iv, tag };
}

/**
 * Decrypt a TOTP secret using AES-256-GCM under the server's envelope key.
 *
 * @param encrypted   - The encrypted TOTP secret components.
 * @param encryptionKey - 32-byte key from TOTP_ENCRYPTION_KEY env var.
 * @returns Decrypted TOTP secret bytes.
 * @throws Error if decryption fails (wrong key or tampered data).
 */
export function decryptTotpSecret(
  encrypted: EncryptedTOTPSecret,
  encryptionKey: Buffer,
): Uint8Array {
  const decipher = createDecipheriv(ALGORITHM, encryptionKey, encrypted.iv, {
    authTagLength: TAG_LENGTH,
  });
  decipher.setAuthTag(encrypted.tag);

  const plaintext = Buffer.concat([
    decipher.update(encrypted.ciphertext),
    decipher.final(),
  ]);

  return new Uint8Array(plaintext);
}
