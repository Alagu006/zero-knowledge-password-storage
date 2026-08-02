/**
 * Client-side password strength validation.
 *
 * WHY CLIENT-SIDE VALIDATION MUST BE PAIRED WITH HIGH ARGON2ID COST:
 *
 *   Client-side validation enforces minimum complexity (length, character
 *   classes) which raises the entropy floor of passwords accepted into the
 *   system. This makes dictionary/brute-force attacks harder because every
 *   password in the keyspace has at least N bits of entropy.
 *
 *   HOWEVER, client-side validation alone is INSUFFICIENT because:
 *
 *   1. An attacker can bypass the client entirely and submit a weak
 *      password hash (authKey) directly to the server API. The server
 *      stores whatever authKey it receives — it cannot tell whether the
 *      original password was "abc" or "correct-horse-battery-staple".
 *
 *   2. Even with validation, a 12-character password with mixed character
 *      classes has ~72 bits of entropy — feasible to brute-force if the
 *      KDF is cheap (e.g. a single SHA-256 hash).
 *
 *   3. Argon2id with high parameters (256 MiB, 4 iterations) ensures that
 *      EACH GUESS costs ~1 second of GPU/ASIC time, making even moderate-
 *      entropy passwords computationally infeasible to crack offline:
 *        - 72-bit entropy + Argon2id(256 MiB, 4 iter) ≈ 10^12 GPU-years
 *        - 40-bit entropy (weak password) + same Argon2id ≈ 10^4 GPU-years
 *
 *   The two defenses are COMPLEMENTARY:
 *     - Validation raises the entropy floor (harder to guess).
 *     - Argon2id raises the cost per guess (slower to verify).
 *     - Together they provide defense-in-depth: even if one layer is weak
 *       (e.g. user picks a borderline password that passes validation),
 *       the other layer still provides substantial protection.
 *
 *   BOTTOM LINE: Never rely on password policy alone. The KDF cost is the
 *   primary security mechanism; validation is a secondary hardening measure.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PasswordStrengthResult = {
  valid: boolean;
  /** Human-readable error messages for failed rules. Empty if valid. */
  errors: string[];
  /** 0-4 score: 0=terrible, 1=weak, 2=fair, 3=strong, 4=excellent. */
  score: number;
};

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/** Minimum password length. OWASP recommends ≥12 for user-chosen passwords. */
const MIN_LENGTH = 12;

/** Maximum password length — prevent DoS via Argon2id with huge input. */
const MAX_LENGTH = 128;

/**
 * Common passwords to reject. This is a SMALL subset for demonstration.
 * Production should use the full "Have I Been Pwned" password list or
 * the k-anonymity API. A 100k-entry list loaded at startup is typical.
 */
const COMMON_PASSWORDS = new Set([
  "password",
  "password1",
  "password123",
  "12345678",
  "123456789",
  "1234567890",
  "qwerty123",
  "admin123",
  "letmein123",
  "welcome123",
  "monkey123",
  "dragon123",
  "master123",
  "login1233",
  "abc123456",
]);

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate password strength against policy requirements.
 *
 * Returns `{ valid: true }` if all rules pass, or `{ valid: false, errors }`
 * with one message per failing rule. The UI should display all errors.
 */
export function validatePasswordStrength(
  password: string,
): PasswordStrengthResult {
  const errors: string[] = [];

  // ── Length checks ──────────────────────────────────────────────────────
  if (password.length < MIN_LENGTH) {
    errors.push(
      `Password must be at least ${MIN_LENGTH} characters (got ${password.length})`,
    );
  }
  if (password.length > MAX_LENGTH) {
    errors.push(`Password must not exceed ${MAX_LENGTH} characters`);
  }

  // ── Character class checks ─────────────────────────────────────────────
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one digit");
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }

  // ── Common password check ──────────────────────────────────────────────
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    errors.push("Password is too common — choose a more unique password");
  }

  // ── Repetition check ───────────────────────────────────────────────────
  if (/(.)\1{3,}/.test(password)) {
    errors.push("Password must not contain 4+ consecutive identical characters");
  }

  // ── Sequential pattern check ───────────────────────────────────────────
  if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
    errors.push("Password must not contain long sequential patterns");
  }

  // ── Compute entropy score ──────────────────────────────────────────────
  const score = computeEntropyScore(password);

  return {
    valid: errors.length === 0,
    errors,
    score,
  };
}

/**
 * Estimate password entropy and map to a 0-4 score.
 *
 * This is a rough heuristic. A proper entropy calculator would consider
 * the actual character set used and the length. For demonstration purposes,
 * this combines length + character diversity into a simple score.
 */
function computeEntropyScore(password: string): number {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 33;

  // Bits of entropy ≈ length × log2(poolSize)
  const entropy =
    password.length * Math.log2(Math.max(poolSize, 1));

  if (entropy >= 80) return 4; // excellent
  if (entropy >= 60) return 3; // strong
  if (entropy >= 45) return 2; // fair
  if (entropy >= 30) return 1; // weak
  return 0;                    // terrible
}

/**
 * Human-readable label for the entropy score.
 */
export function scoreLabel(score: number): string {
  switch (score) {
    case 4: return "Excellent";
    case 3: return "Strong";
    case 2: return "Fair";
    case 1: return "Weak";
    default: return "Terrible";
  }
}
