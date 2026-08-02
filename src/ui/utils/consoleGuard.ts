/**
 * Console stripping for production builds.
 *
 * SECURITY: In production, decrypted vault data (passwords, notes, keys)
 * must never appear in console output. Browser developer tools, console
 * logging extensions, and remote logging services can capture console
 * output. This module nullifies console.log/warn/error/info/debug in
 * production builds (when Vite sets import.meta.env.PROD to true).
 *
 * DEVELOPMENT: In dev mode, this module is a no-op — console output
 * works normally for debugging.
 *
 * This must be imported at the application entry point (main.tsx) BEFORE
 * any other module to ensure stripping is active before any decrypted
 * data could be logged.
 */

function noop(): void {
  /* intentionally empty */
}

if (import.meta.env.PROD) {
  // Preserve the original methods in case we need them for internal use
  // (e.g., the error handler re-throws). But strip user-facing output.
  console.log = noop;
  console.warn = noop;
  console.info = noop;
  console.debug = noop;

  // In highest-security mode (ZKM_HIGHEST_SECURITY=1), also strip
  // console.error to prevent any possibility of vault data leaking
  // through error handlers. Note: this may interfere with React error
  // boundaries and unhandled rejection handlers.
  //
  // Default: keep console.error for operational safety.
  if (
    typeof process !== "undefined" &&
    process.env?.ZKM_HIGHEST_SECURITY === "1"
  ) {
    console.error = noop;
  }
}
