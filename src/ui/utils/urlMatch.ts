/**
 * Strict origin-based URL matching for autofill.
 *
 * SECURITY RULE: URL matching must compare the FULL ORIGIN (scheme + host + port),
 * not a substring. This prevents an attacker from registering a domain like
 * "evil-example.com" to match entries for "example.com".
 *
 * Example:
 *   matchOrigin("https://example.com:443", "https://example.com/login") → true
 *   matchOrigin("https://example.com",     "https://evil-example.com") → false
 *   matchOrigin("https://example.com",     "http://example.com")       → false (scheme mismatch)
 */

export function matchOrigin(storedUrl: string, currentUrl: string): boolean {
  try {
    const stored = new URL(storedUrl);
    const current = new URL(currentUrl);

    return (
      stored.protocol === current.protocol &&
      stored.hostname === current.hostname &&
      stored.port === current.port
    );
  } catch {
    return false;
  }
}

/**
 * Check if a stored entry URL matches the given current page URL.
 * Returns true only if the full origin (scheme + host + port) matches.
 */
export function entryMatchesUrl(entryUrl: string, pageUrl: string): boolean {
  return matchOrigin(entryUrl, pageUrl);
}
