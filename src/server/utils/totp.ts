/**
 * RFC 6238 — Time-based One-Time Password (TOTP) utility.
 *
 * Used server-side only. The TOTP secret is generated on the server,
 * shown once as a QR code, and stored (encrypted at rest) for verification.
 *
 * Parameters (per Google Authenticator compatibility):
 *   - Algorithm: HMAC-SHA1
 *   - Digits: 6
 *   - Time step: 30 seconds
 *   - Tolerance: ±1 time step (60-second window)
 *
 * SECURITY:
 *   - The raw secret is NEVER logged, serialized to JSON after initial setup,
 *     or returned in any API response after the setup endpoint.
 *   - All comparison with stored secrets uses timing-safe equality.
 *   - The secret is generated via crypto.randomBytes (OS CSPRNG).
 */

import { randomBytes, timingSafeEqual, createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of digits in the TOTP code. */
export const TOTP_DIGITS = 6;

/** Time step in seconds (RFC 6238 default). */
export const TOTP_PERIOD = 30;

/** Number of time steps to check before/after current (±1 = 60s window). */
export const TOTP_TOLERANCE = 1;

/** TOTP secret length in bytes (20 bytes = 160 bits, RFC 4226 recommendation). */
export const TOTP_SECRET_LENGTH = 20;

/** Issuer name for the otpauth:// URI. */
const TOTP_ISSUER = "ZKM";

// ---------------------------------------------------------------------------
// Base32 encoding (RFC 4648)
// ---------------------------------------------------------------------------

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encode a Uint8Array to a Base32 string (no padding). */
export function base32Encode(data: Uint8Array): string {
  let bits = "";
  for (const byte of data) {
    bits += byte.toString(2).padStart(8, "0");
  }
  // Pad to multiple of 5
  while (bits.length % 5 !== 0) {
    bits += "0";
  }
  let result = "";
  for (let i = 0; i < bits.length; i += 5) {
    const index = parseInt(bits.substring(i, i + 5), 2);
    result += BASE32_CHARS[index]!;
  }
  return result;
}

/** Decode a Base32 string to a Uint8Array. */
export function base32Decode(encoded: string): Uint8Array {
  const clean = encoded.replace(/[\s=]+/g, "").toUpperCase();
  let bits = "";
  for (const char of clean) {
    const index = BASE32_CHARS.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substring(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// TOTP generation and verification
// ---------------------------------------------------------------------------

/**
 * Generate a random TOTP secret.
 *
 * @returns Raw secret bytes (20 bytes / 160 bits).
 */
export function generateTotpSecret(): Uint8Array {
  return randomBytes(TOTP_SECRET_LENGTH);
}

/**
 * Compute the TOTP code for a given time counter.
 *
 * @param secret    - The raw TOTP secret bytes.
 * @param counter   - The time counter (Math.floor(timeStep / period)).
 * @returns 6-digit zero-padded code string.
 *
 * Uses Node.js crypto.createHmac (HMAC-SHA1) which is available
 * on the server side. For browser-side, Web Crypto API would be used
 * but TOTP verification is server-only.
 */
function computeHmacTotp(secret: Uint8Array, counter: number): string {
  // Convert counter to 8-byte big-endian buffer
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter & 0xffffffff, 4);

  // HMAC-SHA1
  const hmac = createHmac("sha1", secret);
  hmac.update(counterBuf);
  const hash = hmac.digest();

  // Dynamic truncation (RFC 4226)
  const offset = hash[hash.length - 1]! & 0x0f;
  const binary =
    ((hash[offset]! & 0x7f) << 24) |
    ((hash[offset + 1]! & 0xff) << 16) |
    ((hash[offset + 2]! & 0xff) << 8) |
    (hash[offset + 3]! & 0xff);

  // Truncate to 6 digits
  const otp = binary % 1_000_000;
  return otp.toString().padStart(TOTP_DIGITS, "0");
}

/**
 * Generate the current TOTP code for a given secret.
 *
 * @param secret     - The raw TOTP secret bytes.
 * @param timeStep   - Current Unix time in seconds (default: Math.floor(Date.now() / 1000)).
 * @returns 6-digit zero-padded code string.
 */
export function generateTotpCode(
  secret: Uint8Array,
  timeStep?: number,
): string {
  const now = timeStep ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / TOTP_PERIOD);
  return computeHmacTotp(secret, counter);
}

/**
 * Verify a TOTP code against a secret, allowing for clock drift.
 *
 * Checks the current time step AND ±TOTP_TOLERANCE steps.
 * This provides a 60-second window (current + previous + next).
 *
 * @param secret    - The stored raw TOTP secret bytes.
 * @param code      - The 6-digit code to verify.
 * @param timeStep  - Current Unix time in seconds (default: now).
 * @returns true if the code matches any time step in the window.
 *
 * Uses constant-time comparison (timingSafeEqual) to prevent timing attacks.
 */
export function verifyTotp(
  secret: Uint8Array,
  code: string,
  timeStep?: number,
): boolean {
  // Validate format: must be exactly 6 digits
  if (!/^\d{6}$/.test(code)) {
    return false;
  }

  const now = timeStep ?? Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(now / TOTP_PERIOD);

  // Check current step and ±TOLERANCE
  for (let offset = -TOTP_TOLERANCE; offset <= TOTP_TOLERANCE; offset++) {
    const counter = currentCounter + offset;
    if (counter < 0) continue; // no negative counters
    const expected = computeHmacTotp(secret, counter);

    // Constant-time comparison
    const expectedBuf = Buffer.from(expected, "utf8");
    const codeBuf = Buffer.from(code, "utf8");

    if (
      expectedBuf.length === codeBuf.length &&
      timingSafeEqual(expectedBuf, codeBuf)
    ) {
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// URI generation (for QR code)
// ---------------------------------------------------------------------------

/**
 * Generate an otpauth:// URI for QR code generation.
 *
 * Format: otpauth://totp/{issuer}:{email}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
 *
 * @param secret     - The raw TOTP secret bytes.
 * @param email      - The user's email (account name).
 * @param issuer     - The issuer name (default: "ZKM").
 * @returns otpauth:// URI string.
 */
export function generateTotpUri(
  secret: Uint8Array,
  email: string,
  issuer = TOTP_ISSUER,
): string {
  const base32Secret = base32Encode(secret);
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedEmail = encodeURIComponent(email);
  return `otpauth://totp/${encodedIssuer}:${encodedEmail}?secret=${base32Secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}

/**
 * Generate a data URI containing an SVG QR code image.
 *
 * This is a minimal QR code encoder that produces a valid SVG.
 * For production, a proper QR code library should be used.
 * This implementation produces a basic QR code for the otpauth:// URI.
 *
 * NOTE: This is a PLACEHOLDER that returns a simple representation.
 * In production, use a dedicated library like `qrcode` or `otpauth`.
 * The important thing is the URI format — the UI can render it as a link
 * or use any QR library.
 *
 * @param uri - The otpauth:// URI to encode.
 * @returns Data URI with the QR code (SVG format).
 */
export function generateQrDataUri(_uri: string): string {
  // Return a placeholder that indicates the QR should be generated client-side.
  // In a real implementation, this would use a QR code library.
  // The server returns the otpauth URI and the client renders it.
  return "";
}

// ---------------------------------------------------------------------------
// Replay attack prevention (RFC 6238 §5.2)
// ---------------------------------------------------------------------------

interface ConsumedTotpEntry {
  expiresAt: number;
}

const consumedCodes = new Map<string, ConsumedTotpEntry>();
const MAX_CONSUMED_CODES = 10_000;

function pruneConsumedCodes(): void {
  const now = Date.now();
  for (const [key, entry] of consumedCodes.entries()) {
    if (entry.expiresAt <= now) {
      consumedCodes.delete(key);
    }
  }
}

/**
 * Check if a TOTP code has already been consumed by a user within its validity window.
 */
export function isTotpConsumed(userId: string, code: string): boolean {
  pruneConsumedCodes();
  const key = `${userId}:${code}`;
  const entry = consumedCodes.get(key);
  if (!entry) return false;
  return entry.expiresAt > Date.now();
}

/**
 * Mark a TOTP code as consumed by a user to prevent replay attacks.
 */
export function markTotpConsumed(
  userId: string,
  code: string,
  windowSeconds = (TOTP_TOLERANCE * 2 + 1) * TOTP_PERIOD,
): void {
  pruneConsumedCodes();
  if (consumedCodes.size >= MAX_CONSUMED_CODES) {
    const oldestKey = consumedCodes.keys().next().value;
    if (oldestKey) consumedCodes.delete(oldestKey);
  }
  const key = `${userId}:${code}`;
  consumedCodes.set(key, { expiresAt: Date.now() + windowSeconds * 1000 });
}

/**
 * Clear all consumed codes (used for testing).
 */
export function clearConsumedTotpCodes(): void {
  consumedCodes.clear();
}
