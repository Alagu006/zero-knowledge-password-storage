/**
 * HIBP Pwned Passwords breach check (k-anonymity protocol).
 *
 * Implements the k-anonymity scheme used by HaveIBeenPwned:
 *   1. Compute SHA-1(password).
 *   2. Send ONLY the first 5 hex chars (the "prefix") to HIBP.
 *   3. HIBP returns every hash suffix that matches the prefix, with the
 *      breach count for each.
 *   4. Compare the remaining suffix locally.
 *
 * The full hash NEVER leaves the client, so neither HIBP nor a passive
 * network observer can reconstruct the password (each prefix bucket contains
 * thousands of candidates). This is the recommended way to check a password
 * against Pwned Passwords without leaking it.
 *
 * FAIL-OPEN SECURITY: any network error, non-200 response, or malformed body
 * is treated as `{ status: "error" }` so the check can NEVER block account
 * registration or password change when HIBP is unreachable. The UI must
 * treat "error" the same as "not breached" (proceed), never the reverse.
 */

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";

export type BreachCheckResult =
  | { status: "ok"; breached: boolean; count: number }
  | { status: "error" };

/**
 * Check whether a password has appeared in known data breaches.
 *
 * @param password - The candidate password (plaintext, in-memory only).
 * @returns
 *   - `{ status: "ok", breached, count }` when HIBP was reachable.
 *   - `{ status: "error" }` on any failure (network, non-200, malformed).
 *     Callers MUST fail open on "error".
 */
export async function checkPasswordBreached(
  password: string,
): Promise<BreachCheckResult> {
  try {
    const hashBuffer = await crypto.subtle.digest(
      "SHA-1",
      new TextEncoder().encode(password),
    );
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    const res = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
      headers: { "Add-Padding": "true" },
    });
    if (!res.ok) {
      return { status: "error" };
    }

    const text = await res.text();

    // Response format: one "SUFFIX:COUNT" per line (case-insensitive suffix).
    let count = 0;
    for (const line of text.split("\n")) {
      const [lineSuffix, lineCount] = line.trim().split(":");
      if (
        lineSuffix &&
        lineSuffix.toUpperCase() === suffix.toUpperCase()
      ) {
        const parsed = parseInt(lineCount ?? "", 10);
        count = Number.isFinite(parsed) ? parsed : 0;
        break;
      }
    }

    return { status: "ok", breached: count > 0, count };
  } catch {
    // Fail-open: fetch rejection (network down, TLS failure, DNS), digest
    // error, etc. Never propagate — the check must not block the user.
    return { status: "error" };
  }
}
