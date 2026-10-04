import React, { useState, useEffect, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { regenerateBackupCodes } from "../../client/auth";

type SetupPhase = "initial" | "showing_codes" | "verifying" | "enabled" | "error";

export function TwoFactorSetupPage() {
  const { token, setup2FA, enable2FA, get2FAStatus, error, clearError } = useAuth();
  const navigate = useNavigate();

  const [phase, setPhase] = useState<SetupPhase>("initial");
  const [totpUri, setTotpUri] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [statusLoading, setStatusLoading] = useState(true);
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [backupCodesRemaining, setBackupCodesRemaining] = useState(0);
  const [codesSaved, setCodesSaved] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  // Backup-code regeneration state.
  const [regenerateMode, setRegenerateMode] = useState(false);
  const [regenerateCode, setRegenerateCode] = useState("");
  const [regenerating, setRegenerating] = useState(false);
  const [newBackupCodes, setNewBackupCodes] = useState<string[] | null>(null);
  const [newCodesSaved, setNewCodesSaved] = useState(false);
  const [regenerateError, setRegenerateError] = useState<string | null>(null);

  // Check current 2FA status on mount
  useEffect(() => {
    if (!token) return;
    get2FAStatus().then((status) => {
      if (status) {
        setTotpEnabled(status.totpEnabled);
        setBackupCodesRemaining(status.backupCodesRemaining);
      }
      setStatusLoading(false);
    });
  }, [token, get2FAStatus]);

  const handleSetup = async () => {
    setLoading(true);
    clearError();
    const result = await setup2FA();
    if (result.ok && result.totpUri && result.backupCodes) {
      setTotpUri(result.totpUri);
      setBackupCodes(result.backupCodes);
      setPhase("showing_codes");
    } else {
      setPhase("error");
    }
    setLoading(false);
  };

  const handleVerify = async (e: FormEvent) => {
    e.preventDefault();
    if (verifyCode.length !== 6) return;

    setLoading(true);
    clearError();
    const ok = await enable2FA(verifyCode);
    if (ok) {
      setPhase("enabled");
      setTotpEnabled(true);
      setBackupCodesRemaining(backupCodes.length);
    } else {
      setPhase("verifying");
    }
    setLoading(false);
  };

  const handleRegenerateBackupCodes = async (e: FormEvent) => {
    e.preventDefault();
    if (!token || regenerateCode.length !== 6) return;

    setRegenerating(true);
    setRegenerateError(null);
    const result = await regenerateBackupCodes(token, regenerateCode);
    if (result.ok) {
      setNewBackupCodes(result.backupCodes);
      setNewCodesSaved(false);
      setRegenerateCode("");
      setRegenerateMode(false);
    } else {
      setRegenerateError(result.message);
    }
    setRegenerating(false);
  };

  const handleNewCodesSaved = () => {
    if (!newBackupCodes) return;
    setBackupCodesRemaining(newBackupCodes.length);
    setNewBackupCodes(null);
    setNewCodesSaved(false);
  };

  // ── Loading state ───────────────────────────────────────────────────
  if (statusLoading) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <p style={styles.loading}>Loading...</p>
        </div>
      </div>
    );
  }

  // ── 2FA already enabled ─────────────────────────────────────────────
  if (totpEnabled && phase !== "enabled") {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Two-Factor Authentication</h1>
          <p style={styles.subtitle}>Two-factor authentication is already enabled</p>

          {newBackupCodes ? (
            <>
              <p style={styles.info}>
                Your previous backup codes have been revoked. Save these new
                codes now — they won't be shown again.
              </p>
              <div style={styles.codesContainer}>
                {newBackupCodes.map((code, i) => (
                  <div key={i} style={styles.codeItem}>
                    <code style={styles.codeText}>{code}</code>
                  </div>
                ))}
              </div>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={newCodesSaved}
                  onChange={(e) => setNewCodesSaved(e.target.checked)}
                  style={styles.checkbox}
                />
                I have saved these new codes in a safe place
              </label>
              <button
                onClick={handleNewCodesSaved}
                disabled={!newCodesSaved}
                style={{
                  ...styles.button,
                  opacity: newCodesSaved ? 1 : 0.5,
                  marginTop: 16,
                }}
              >
                Done
              </button>
            </>
          ) : regenerateMode ? (
            <form onSubmit={handleRegenerateBackupCodes} style={styles.form}>
              <p style={styles.info}>
                Backups remaining: {backupCodesRemaining}. Regenerating will
                permanently invalidate your current backup codes. Enter your
                authenticator code to confirm.
              </p>
              <label style={styles.label}>
                Authenticator Code
                <input
                  type="text"
                  value={regenerateCode}
                  onChange={(e) => {
                    setRegenerateCode(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    );
                    setRegenerateError(null);
                  }}
                  placeholder="000000"
                  maxLength={6}
                  autoComplete="one-time-code"
                  style={styles.input}
                />
              </label>

              {regenerateError && (
                <div style={styles.error} role="alert">
                  {regenerateError}
                </div>
              )}

              <button
                type="submit"
                disabled={regenerating || regenerateCode.length !== 6}
                style={{
                  ...styles.button,
                  opacity:
                    regenerating || regenerateCode.length !== 6 ? 0.6 : 1,
                }}
              >
                {regenerating
                  ? "Regenerating..."
                  : "Regenerate Backup Codes"}
              </button>
              <p style={styles.footer}>
                <button
                  type="button"
                  onClick={() => {
                    setRegenerateMode(false);
                    setRegenerateCode("");
                    setRegenerateError(null);
                  }}
                  style={styles.linkButton}
                >
                  Cancel
                </button>
              </p>
            </form>
          ) : (
            <>
              <p style={styles.info}>
                Backup codes remaining: {backupCodesRemaining}
              </p>
              <button
                onClick={() => setRegenerateMode(true)}
                style={styles.button}
              >
                Regenerate Backup Codes
              </button>
            </>
          )}

          <p style={styles.footer}>
            <button onClick={() => navigate("/vault")} style={styles.linkButton}>
              Back to Vault
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ── Phase: Showing backup codes ─────────────────────────────────────
  if (phase === "showing_codes") {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Save Your Backup Codes</h1>
          <p style={styles.subtitle}>
            These codes can be used once each if you lose access to your
            authenticator app. Save them now — they won't be shown again.
          </p>

          <div style={styles.codesContainer}>
            {backupCodes.map((code, i) => (
              <div key={i} style={styles.codeItem}>
                <code style={styles.codeText}>{code}</code>
              </div>
            ))}
          </div>

          <label style={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={codesSaved}
              onChange={(e) => setCodesSaved(e.target.checked)}
              style={styles.checkbox}
            />
            I have saved these codes in a safe place
          </label>

          <button
            onClick={() => setPhase("verifying")}
            disabled={!codesSaved}
            style={{
              ...styles.button,
              opacity: codesSaved ? 1 : 0.5,
              marginTop: 16,
            }}
          >
            Continue to Verification
          </button>
        </div>
      </div>
    );
  }

  // ── Phase: Verifying TOTP code ──────────────────────────────────────
  if (phase === "verifying") {
    const secretMatch = totpUri.match(/secret=([A-Z2-7]+)/i);
    const rawSecret = secretMatch ? secretMatch[1] : "";
    const formattedSecret = rawSecret.match(/.{1,4}/g)?.join(" ") ?? rawSecret;

    const handleCopySecret = async () => {
      if (!rawSecret) return;
      try {
        await navigator.clipboard.writeText(rawSecret);
        setCopiedSecret(true);
        setTimeout(() => setCopiedSecret(false), 2000);
      } catch {
        // Fallback or ignore clipboard permission error
      }
    };

    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Add to Authenticator</h1>
          <p style={styles.subtitle}>
            Enter this secret key in your authenticator app (Google Authenticator, Authy, 1Password, etc.) or open directly:
          </p>

          {rawSecret && (
            <div style={styles.secretBox}>
              <div style={styles.secretLabel}>Manual Setup Key:</div>
              <div style={styles.secretValue}>{formattedSecret}</div>
              <div style={{ display: "flex", gap: "8px", marginTop: "10px", flexWrap: "wrap" }}>
                <button
                  type="button"
                  onClick={handleCopySecret}
                  style={styles.copyBtn}
                >
                  {copiedSecret ? "Copied!" : "Copy Setup Key"}
                </button>
                <a
                  href={totpUri}
                  style={styles.openAppBtn}
                >
                  Open in Authenticator
                </a>
              </div>
            </div>
          )}

          {error && (
            <div style={styles.error} role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleVerify} style={styles.form}>
            <label style={styles.label}>
              Enter 6-Digit Authenticator Code
              <input
                type="text"
                value={verifyCode}
                onChange={(e) => {
                  setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6));
                  clearError();
                }}
                placeholder="000000"
                maxLength={6}
                autoComplete="one-time-code"
                style={styles.input}
              />
            </label>

            <button
              type="submit"
              disabled={loading || verifyCode.length !== 6}
              style={{
                ...styles.button,
                opacity: loading || verifyCode.length !== 6 ? 0.6 : 1,
              }}
            >
              {loading ? "Verifying..." : "Enable 2FA"}
            </button>
          </form>

          <p style={styles.footer}>
            <button
              onClick={() => setPhase("showing_codes")}
              style={styles.linkButton}
            >
              Back to backup codes
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ── Phase: Enabled successfully ─────────────────────────────────────
  if (phase === "enabled") {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Two-Factor Enabled</h1>
          <p style={styles.subtitle}>
            Two-factor authentication has been enabled successfully.
            You'll need your authenticator app for future logins.
          </p>
          <button onClick={() => navigate("/vault")} style={styles.button}>
            Back to Vault
          </button>
        </div>
      </div>
    );
  }

  // ── Phase: Initial / Setup ──────────────────────────────────────────
  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <h1 style={styles.title}>Set Up Two-Factor Authentication</h1>
        <p style={styles.subtitle}>
          Add an extra layer of security to your account. You'll need an
          authenticator app like Google Authenticator or Authy.
        </p>

        {error && (
          <div style={styles.error} role="alert">
            {error}
          </div>
        )}

        <div style={styles.infoBox}>
          <p style={styles.infoTitle}>How it works:</p>
          <ul style={styles.infoList}>
            <li>Scan a QR code with your authenticator app</li>
            <li>Enter a 6-digit code to verify setup</li>
            <li>Save backup codes for emergencies</li>
          </ul>
        </div>

        <button
          onClick={handleSetup}
          disabled={loading}
          style={{
            ...styles.button,
            opacity: loading ? 0.6 : 1,
            marginTop: 16,
          }}
        >
          {loading ? "Setting up..." : "Start Setup"}
        </button>

        <p style={styles.footer}>
          <button onClick={() => navigate("/vault")} style={styles.linkButton}>
            Skip for now
          </button>
        </p>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    padding: 24,
  },
  card: {
    width: "100%",
    maxWidth: 480,
    padding: 32,
    borderRadius: 12,
    backgroundColor: "#161822",
    border: "1px solid #2a2d35",
  },
  title: {
    margin: "0 0 4px",
    fontSize: 20,
    fontWeight: 700,
    color: "#7c8aff",
    textAlign: "center",
  },
  subtitle: {
    margin: "0 0 24px",
    fontSize: 14,
    color: "#888",
    textAlign: "center",
    lineHeight: 1.5,
  },
  loading: {
    textAlign: "center",
    color: "#888",
  },
  info: {
    fontSize: 14,
    color: "#aaa",
    textAlign: "center",
    marginBottom: 16,
  },
  infoBox: {
    padding: 16,
    borderRadius: 8,
    backgroundColor: "#1a1d2e",
    border: "1px solid #2a2d35",
    marginBottom: 16,
  },
  infoTitle: {
    margin: "0 0 8px",
    fontSize: 13,
    fontWeight: 600,
    color: "#aaa",
  },
  infoList: {
    margin: 0,
    paddingLeft: 20,
    fontSize: 13,
    color: "#888",
    lineHeight: 1.8,
  },
  codesContainer: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: 8,
    marginBottom: 16,
    padding: 16,
    borderRadius: 8,
    backgroundColor: "#0f1117",
    border: "1px solid #2a2d35",
  },
  codeItem: {
    padding: "8px 12px",
    textAlign: "center",
  },
  codeText: {
    fontFamily: "monospace",
    fontSize: 14,
    color: "#7c8aff",
    letterSpacing: 1,
  },
  checkboxLabel: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontSize: 13,
    color: "#aaa",
    cursor: "pointer",
  },
  checkbox: {
    width: 16,
    height: 16,
  },
  error: {
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#3a1520",
    border: "1px solid #5c2233",
    color: "#ff6b8a",
    fontSize: 13,
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: 16,
  },
  label: {
    display: "flex",
    flexDirection: "column",
    gap: 6,
    fontSize: 13,
    color: "#aaa",
  },
  input: {
    padding: "10px 12px",
    fontSize: 14,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    outline: "none",
    fontFamily: "monospace",
    letterSpacing: 2,
    textAlign: "center",
  },
  button: {
    padding: "12px 16px",
    fontSize: 14,
    fontWeight: 600,
    border: "none",
    borderRadius: 6,
    backgroundColor: "#7c8aff",
    color: "#fff",
    cursor: "pointer",
    marginTop: 8,
  },
  footer: {
    marginTop: 20,
    fontSize: 13,
    color: "#888",
    textAlign: "center",
  },
  linkButton: {
    background: "none",
    border: "none",
    color: "#7c8aff",
    cursor: "pointer",
    fontSize: 13,
    padding: 0,
  },
  secretBox: {
    padding: "14px",
    backgroundColor: "#12141c",
    borderRadius: 8,
    border: "1px solid #282c3c",
    marginBottom: 20,
    textAlign: "left",
  },
  secretLabel: {
    fontSize: 12,
    color: "#9aa0b4",
    marginBottom: 6,
    fontWeight: 500,
  },
  secretValue: {
    fontFamily: "monospace",
    fontSize: 15,
    letterSpacing: 2,
    color: "#99a5ff",
    wordBreak: "break-all",
    fontWeight: 600,
    userSelect: "all",
  },
  copyBtn: {
    padding: "7px 14px",
    fontSize: 12,
    fontWeight: 600,
    border: "1px solid #363b4f",
    borderRadius: 6,
    backgroundColor: "#1e2233",
    color: "#e0e0e0",
    cursor: "pointer",
  },
  openAppBtn: {
    padding: "7px 14px",
    fontSize: 12,
    fontWeight: 600,
    border: "1px solid #363b4f",
    borderRadius: 6,
    backgroundColor: "#1e2233",
    color: "#7c8aff",
    textDecoration: "none",
    display: "inline-block",
  },
};
