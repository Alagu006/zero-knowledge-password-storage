/**
 * HTML entity escaping to prevent XSS when rendering user-provided data.
 *
 * SECURITY RULE: NEVER use dangerouslySetInnerHTML on any data that could
 * contain user input. Use this function to escape all user-provided strings
 * before rendering.
 */

const ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
};

const ESCAPE_REGEX = /[&<>"'/]/g;

export function escapeHtml(str: string): string {
  return str.replace(ESCAPE_REGEX, (ch) => ESCAPE_MAP[ch] ?? ch);
}
