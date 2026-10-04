-- ============================================================================
-- Migration 005: Session / Device Management
-- ============================================================================
--
-- Adds ip_address and user_agent to auth_sessions so the Sessions page can
-- show which devices are logged in and let the user revoke them.
--
-- SECURITY NOTE: These fields are best-effort situational awareness, not a
-- security boundary. req.ip reflects the peer/proxy address and user agents
-- are trivially spoofable. Never authenticate based on them.
--
-- Existing sessions keep NULL metadata (captured going forward on login).
-- ============================================================================

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;

COMMENT ON COLUMN auth_sessions.ip_address IS
  'Best-effort peer address at session creation (see migration note). May be NULL for pre-existing sessions.';

COMMENT ON COLUMN auth_sessions.user_agent IS
  'Best-effort User-Agent header at session creation. Trivially spoofable — informational only.';
