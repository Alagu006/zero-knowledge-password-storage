/**
 * Audit logging — append-only security event record.
 *
 * CRITICAL LINT RULE:
 *   The `details` field MUST NEVER contain any of the following:
 *     - password, pass, mp, masterPassword
 *     - secret, key, authKey, masterKey, vaultKey, wrappedVk
 *     - plaintext, credential, token (raw session/JWT values)
 *     - Any Uint8Array / Buffer / Bytes values
 *
 *   Enforce this via:
 *     1. ESLint custom rule (no-secret-in-audit-details)
 *     2. Code review checklist
 *     3. CI type-check: details is typed as Record<string, string | number>
 *        NOT Record<string, unknown>
 *
 *   Audit logs are RETAINED INDEFINITELY for forensic investigation.
 *   If secret data is accidentally written, it CANNOT be retracted from
 *   the log without a destructive migration.
 */

import { prisma } from "../db.js";

type AuditEventType =
  | "register_success"
  | "register_failure"
  | "login_step1"
  | "login_success"
  | "login_failure"
  | "login_locked"
  | "password_change"
  | "password_change_failure"
  | "kdf_upgrade"
  | "kdf_upgrade_failure"
  | "recovery_initiated"
  | "recovery_failure"
  | "recovery_complete"
  | "entry_create"
  | "entry_update"
  | "entry_delete"
  | "entry_list"
  | "token_revoked"
  | "totp_setup"
  | "totp_enabled"
  | "totp_disabled"
  | "totp_success"
  | "totp_failure"
  | "backup_code_success"
  | "backup_code_failure"
  | "backup_codes_regenerated"
  | "recovery_regenerated"
  | "session_revoked"
  | "sessions_revoked";

/**
 * Record an audit event. Failures here are swallowed (audit must never
 * crash the request), but logged to stderr for operator visibility.
 */
export async function auditLog(params: {
  userId?: string;
  eventType: AuditEventType;
  ipAddress?: string;
  userAgent?: string;
  /** Safe fields only — see LINT RULE above. */
  details?: Record<string, string | number>;
}): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: params.userId ?? null,
        eventType: params.eventType,
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
        details: params.details ?? undefined,
      },
    });
  } catch (err) {
    // Audit failure is a serious operational issue — log to stderr.
    // Never swallow silently.
    console.error("[audit] FAILED to write audit record:", err);
  }
}
