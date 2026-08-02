import React, { useState, FormEvent, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { validatePasswordStrength, scoreLabel } from "../../client/password";
import { checkPasswordBreached } from "../../client/breachCheck";
import { regenerateRecoveryCode } from "../../client/auth";

export function ChangePasswordPage() {
  const { token, vaultKey, email, loading, error, clearError, changePassword } =
    useAuth();
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [score, setScore] = useState(0);
  const [success, setSuccess] = useState(false);
  const [breachWarning, setBreachWarning] = useState<string | null>(null);
  const breachCheckedForRef = useRef("");
  const breachAcceptedRef = useRef(false);

  // Recovery-code rotation state.
  const [regenRecoveryBusy, setRegenRecoveryBusy] = useState(false);
  const [regenRecoveryError, setRegenRecoveryError] = useState<string | null>(
    null,
  );
  const [confirmRecoveryRegen, setConfirmRecoveryRegen] = useState(false);
  const [newRecoveryCode, setNewRecoveryCode] = useState<string | null>(null);

  const handlePasswordChange = (value: string) => {
    setNewPassword(value);
    clearError();
    breachCheckedForRef.current = "";
    breachAcceptedRef.current = false;
    setBreachWarning(null);
    if (value.length > 0) {
      const result = validatePasswordStrength(value);
      setValidationErrors(result.errors);
      setScore(result.score);
    } else {
      setValidationErrors([]);
      setScore(0);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirm) {
      setValidationErrors(["Passwords do not match"]);
      return;
    }
    if (!token || !vaultKey || !email) return;
    setValidationErrors([]);

    if (breachCheckedForRef.current !== newPassword || !breachAcceptedRef.current) {
      const breach = await checkPasswordBreached(newPassword);
      if (breach.status === "ok" && breach.breached) {
        breachCheckedForRef.current = newPassword;
        breachAcceptedRef.current = false;
        setBreachWarning(
          `This password has appeared in ${breach.count.toLocaleString()} known data breaches. Using it is risky — a never-leaked password is safer. Click "Change Password" again to proceed anyway.`,
        );
        return;
      }
      // Fail-open: "error" (HIBP unreachable) and "not breached" both proceed.
      breachCheckedForRef.current = newPassword;
      breachAcceptedRef.current = true;
      setBreachWarning(null);
    }

    const ok = await changePassword(token, email, vaultKey, currentPassword, newPassword);
    if (ok) {
      setSuccess(true);
    }
  };

  const handleRecoveryRegenerate = async () => {
    if (!token || !vaultKey || !email || !currentPassword) return;
    setRegenRecoveryBusy(true);
    setRegenRecoveryError(null);
    const result = await regenerateRecoveryCode(
      token,
      email,
      vaultKey,
      currentPassword,
    );
    if (result.ok) {
      setNewRecoveryCode(result.recoveryCode);
      setConfirmRecoveryRegen(false);
    } else {
      setRegenRecoveryError(result.message);
    }
    setRegenRecoveryBusy(false);
  };

  if (success) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Password Changed</h1>
          <p style={styles.subtitle}>
            Your master password has been updated. Your vault key has been
            re-wrapped under the new password — all vault entries remain intact.
          </p>
          <Link to="/vault" style={styles.link}>
            Return to Vault
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.column}>
        <div style={styles.card}>
          <h1 style={styles.title}>Change Master Password</h1>
          <p style={styles.subtitle}>
            Your existing vault key will be re-wrapped under the new password.
            Vault entries are not re-encrypted.
          </p>

          {error && (
            <div style={styles.error} role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={styles.form}>
            <label style={styles.label}>
              Current Master Password
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => {
                  setCurrentPassword(e.target.value);
                  clearError();
                }}
                required
                autoComplete="current-password"
                style={styles.input}
              />
            </label>

            <label style={styles.label}>
              New Master Password
              <input
                type="password"
                value={newPassword}
                onChange={(e) => handlePasswordChange(e.target.value)}
                required
                autoComplete="new-password"
                style={styles.input}
              />
              {newPassword.length > 0 && (
                <div style={styles.strengthBar}>
                  <div
                    style={{
                      ...styles.strengthFill,
                      width: `${(score / 4) * 100}%`,
                      backgroundColor: scoreColor(score),
                    }}
                  />
                </div>
              )}
              {newPassword.length > 0 && (
                <span style={{ ...styles.scoreLabel, color: scoreColor(score) }}>
                  {scoreLabel(score)}
                </span>
              )}
            </label>

            <label style={styles.label}>
              Confirm New Password
              <input
                type="password"
                value={confirm}
                onChange={(e) => {
                  setConfirm(e.target.value);
                  clearError();
                }}
                required
                autoComplete="new-password"
                style={styles.input}
              />
            </label>

            {validationErrors.length > 0 && (
              <ul style={styles.errors}>
                {validationErrors.map((err, i) => (
                  <li key={i} style={styles.errorItem}>
                    {err}
                  </li>
                ))}
              </ul>
            )}

            {breachWarning && (
              <div style={styles.breachWarning} role="alert">
                {breachWarning}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || validationErrors.length > 0}
              style={{
                ...styles.button,
                opacity: loading || validationErrors.length > 0 ? 0.6 : 1,
              }}
            >
              {loading ? "Changing password..." : "Change Password"}
            </button>
          </form>

          <p style={styles.footer}>
            <Link to="/vault" style={styles.link}>
              Cancel
            </Link>
          </p>
        </div>

        <div style={styles.card}>
          <h1 style={styles.title}>Regenerate Recovery Code</h1>
          <p style={styles.subtitle}>
            Replace your 128-bit account recovery code with a fresh one. Your
            current recovery code stops working immediately. The new code is
            shown only once — save it somewhere safe.
          </p>

          {newRecoveryCode ? (
            <>
              <p style={styles.recoveryCodeLabel}>Your new recovery code</p>
              <div style={styles.recoveryCodeBox}>
                <code style={styles.codeText}>{newRecoveryCode}</code>
              </div>
              <p style={styles.warning}>
                Write this down now. It will not be shown again, and your old
                recovery code no longer works.
              </p>
              <button
                onClick={() => setNewRecoveryCode(null)}
                style={styles.button}
              >
                Done
              </button>
            </>
          ) : (
            <>
              {regenRecoveryError && (
                <div style={styles.error} role="alert">
                  {regenRecoveryError}
                </div>
              )}
              <p style={styles.info}>
                Your current master password (above) is required to prove
                ownership before the code is rotated.
              </p>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={confirmRecoveryRegen}
                  onChange={(e) => setConfirmRecoveryRegen(e.target.checked)}
                  style={styles.checkbox}
                />
                I understand my current recovery code will stop working
              </label>
              <button
                onClick={handleRecoveryRegenerate}
                disabled={
                  regenRecoveryBusy || !confirmRecoveryRegen || !currentPassword
                }
                style={{
                  ...styles.button,
                  opacity:
                    regenRecoveryBusy || !confirmRecoveryRegen || !currentPassword
                      ? 0.6
                      : 1,
                }}
              >
                {regenRecoveryBusy
                  ? "Regenerating..."
                  : "Regenerate Recovery Code"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function scoreColor(score: number): string {
  switch (score) {
    case 4:
      return "#22c55e";
    case 3:
      return "#7c8aff";
    case 2:
      return "#f59e0b";
    case 1:
      return "#f97316";
    default:
      return "#ef4444";
  }
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
    padding: "24px 0",
  },
  column: {
    display: "flex",
    flexDirection: "column",
    gap: 24,
    width: "100%",
    maxWidth: 400,
    alignItems: "stretch",
  },
  card: {
    width: "100%",
    maxWidth: 400,
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
  },
  strengthBar: {
    height: 4,
    borderRadius: 2,
    backgroundColor: "#2a2d35",
    overflow: "hidden",
  },
  strengthFill: {
    height: "100%",
    borderRadius: 2,
    transition: "width 0.2s, background-color 0.2s",
  },
  scoreLabel: {
    fontSize: 12,
    fontWeight: 600,
  },
  errors: {
    margin: 0,
    padding: "8px 12px",
    listStyle: "none",
    borderRadius: 6,
    backgroundColor: "#2a1520",
    border: "1px solid #3d2233",
  },
  errorItem: {
    fontSize: 12,
    color: "#ff6b8a",
    padding: "2px 0",
  },
  breachWarning: {
    padding: "10px 12px",
    borderRadius: 6,
    backgroundColor: "#2a1f05",
    border: "1px solid #5c4a0a",
    color: "#f5c65d",
    fontSize: 13,
    lineHeight: 1.5,
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
  link: {
    color: "#7c8aff",
    textDecoration: "none",
  },
  info: {
    fontSize: 13,
    color: "#888",
    margin: "0 0 16px",
    lineHeight: 1.5,
  },
  checkboxLabel: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontSize: 13,
    color: "#aaa",
    cursor: "pointer",
    marginBottom: 16,
  },
  checkbox: {
    width: 16,
    height: 16,
  },
  recoveryCodeLabel: {
    fontSize: 13,
    fontWeight: 600,
    color: "#aaa",
    textAlign: "center",
    margin: "0 0 8px",
  },
  recoveryCodeBox: {
    padding: 12,
    borderRadius: 6,
    backgroundColor: "#0f1117",
    border: "1px solid #2a2d35",
    textAlign: "center",
    marginBottom: 12,
  },
  codeText: {
    fontFamily: "monospace",
    fontSize: 16,
    color: "#7c8aff",
    letterSpacing: 2,
    wordBreak: "break-all",
  },
  warning: {
    fontSize: 13,
    color: "#f5c65d",
    backgroundColor: "#2a1f05",
    border: "1px solid #5c4a0a",
    padding: "10px 12px",
    borderRadius: 6,
    lineHeight: 1.5,
    margin: "0 0 16px",
  },
};
