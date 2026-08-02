/**
 * Backup codes — one-time-use recovery codes for 2FA bypass.
 *
 * SECURITY MODEL:
 *   - 10 codes generated per setup, each 8 characters (alphanumeric).
 *   - Codes are hashed (SHA-256) before storage — never stored in plaintext.
 *   - Each code can be used ONCE. After use, the stored hash is marked as used.
 *   - Codes are shown to the user ONCE at generation time. They cannot be
 *     retrieved again.
 *
 * FORMAT: 8-character alphanumeric codes (uppercase + digits), grouped as
 *   XXXX-XXXX for readability (display only, stored without dash).
 *
 * ENTROPY: 32^8 ≈ 1.1 × 10^12 combinations per code. With 10 codes, an
 *   attacker has ~10^13 attempts — sufficient for emergency access.
 *
 * IMPLEMENTATION:
 *   - Generation: crypto.randomBytes for CSPRNG.
 *   - Hashing: SHA-256 (fast, non-interactive — backup codes don't need
 *     Argon2id because they are high-entropy, one-time, and rate-limited).
 *   - Verification: iterate all stored hashes, constant-time compare each.
 */

import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of backup codes to generate per setup. */
export const BACKUP_CODE_COUNT = 10;

/** Length of each backup code in characters (before formatting). */
export const BACKUP_CODE_LENGTH = 8;

/** Characters allowed in backup codes (uppercase + digits, 32 chars = 5 bits each). */
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No I, O, 0, 1 (ambiguous)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BackupCodeRecord {
  /** SHA-256 hash of the code (hex string). */
  codeHash: string;
  /** Whether this code has been used. */
  used: boolean;
}

export interface GeneratedBackupCodes {
  /** Raw codes to display to the user once. Formatted as XXXX-XXXX. */
  codes: string[];
  /** Hashed codes to store in the database. */
  records: BackupCodeRecord[];
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/**
 * Generate a set of backup codes.
 *
 * Each code is 8 random alphanumeric characters (from a 32-char charset).
 * The codes are formatted as XXXX-XXXX for readability.
 *
 * @returns Array of formatted backup codes (display to user once).
 */
export function generateBackupCodes(): GeneratedBackupCodes {
  const codes: string[] = [];
  const records: BackupCodeRecord[] = [];

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = generateSingleCode();
    const formatted = formatCode(code);
    const hash = hashBackupCode(code);

    codes.push(formatted);
    records.push({ codeHash: hash, used: false });
  }

  return { codes, records };
}

/**
 * Generate a single random backup code.
 */
function generateSingleCode(): string {
  // We need 8 characters from a 32-char set.
  // 8 * log2(32) = 40 bits of entropy per code.
  // Use rejection sampling to avoid modulo bias.
  const bytesNeeded = Math.ceil((BACKUP_CODE_LENGTH * 5) / 8); // ~5 bytes
  let code = "";

  while (code.length < BACKUP_CODE_LENGTH) {
    const buf = randomBytes(bytesNeeded);
    for (const byte of buf) {
      if (code.length >= BACKUP_CODE_LENGTH) break;
      const charIndex = byte % CODE_CHARS.length;
      // Rejection: skip if byte >= 256 - (256 % 32) = 256 - 0 = 256 (no rejection needed for 32 chars)
      // Actually 256 % 32 = 0, so no bias — all bytes map cleanly.
      code += CODE_CHARS[charIndex]!;
    }
  }

  return code;
}

/**
 * Format a code as XXXX-XXXX for display.
 */
function formatCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * Hash a backup code using SHA-256.
 *
 * The hash includes a domain separator to prevent cross-protocol attacks
 * (though backup codes are single-use, defense in depth).
 *
 * @param code - Raw 8-character code (without dash).
 * @returns Hex-encoded SHA-256 hash.
 */
export function hashBackupCode(code: string): string {
  const normalized = code.replace(/-/g, "").toUpperCase();
  const input = `zkm-backup-code-v1:${normalized}`;
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify a submitted backup code against stored hash records.
 *
 * Uses constant-time comparison for each hash to prevent timing attacks.
 * Returns the index of the matched record (for marking as used) or -1.
 *
 * @param code          - The submitted code (may or may not have dash).
 * @param storedRecords - Array of stored hash records from the database.
 * @returns Index of the matched record, or -1 if no match.
 */
export function verifyBackupCode(
  code: string,
  storedRecords: BackupCodeRecord[],
): number {
  const normalized = code.replace(/-/g, "").toUpperCase();

  // Validate format
  if (!/^[A-Z2-9]{8}$/.test(normalized)) {
    return -1;
  }

  const submittedHash = hashBackupCode(normalized);
  const submittedBuf = Buffer.from(submittedHash, "utf8");

  for (let i = 0; i < storedRecords.length; i++) {
    const record = storedRecords[i]!;

    // Skip already-used codes
    if (record.used) continue;

    const storedBuf = Buffer.from(record.codeHash, "utf8");

    if (
      submittedBuf.length === storedBuf.length &&
      timingSafeEqual(submittedBuf, storedBuf)
    ) {
      return i;
    }
  }

  return -1;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/**
 * Format a hex-encoded hash record array for storage.
 * Used when creating the initial backup code records.
 */
export function formatRecordsForStorage(
  records: BackupCodeRecord[],
): Array<{ codeHash: string; used: boolean }> {
  return records.map((r) => ({
    codeHash: r.codeHash,
    used: r.used,
  }));
}
