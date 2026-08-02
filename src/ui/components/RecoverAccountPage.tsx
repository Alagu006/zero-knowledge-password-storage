import React, { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { recoverVaultKey, completeRecovery } from "../../client/auth";
import { validatePasswordStrength, scoreLabel } from "../../client/password";
import { zeroize } from "../../crypto";

type Step = "enter-code" | "set-password" | "done";

export function RecoverAccountPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>("enter-code");
  const [email, setEmail] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [score, setScore] = useState(0);
  const [recoveredVaultKey, setRecoveredVaultKey] = useState<Uint8Array | null>(null);
  const [recoverySessionToken, setRecoverySessionToken] = useState<string | null>(null);

  const handlePasswordChange = async (value: string) => {
    setNewPassword(value);
    if (value.length > 0) {
      const result = validatePasswordStrength(value);
      setValidationErrors(result.errors);
      setScore(result.score);
    } else {
      setValidationErrors([]);
      setScore(0);
    }
  };

  const handleRecover = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await recoverVaultKey(email, recoveryCode);
      if (result.ok) {
        setRecoveredVaultKey(result.vaultKey);
        setRecoverySessionToken(result.recoverySessionToken);
        setStep("set-password");
      } else {
        setError(result.message);
      }
    } catch {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleSetPassword = async (e: FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirm) {
      setValidationErrors(["Passwords do not match"]);
      return;
    }
    if (!recoveredVaultKey || !recoverySessionToken) return;

    setLoading(true);
    setError(null);
    try {
      const result = await completeRecovery(
        email,
        recoverySessionToken,
        recoveredVaultKey,
        newPassword,
      );
      if (result.ok) {
        zeroize(recoveredVaultKey);
        setRecoveredVaultKey(null);
        setRecoverySessionToken(null);
        setStep("done");
      } else {
        setError(result.message);
      }
    } catch {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  if (step === "done") {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Recovery Complete</h1>
          <p style={styles.subtitle}>
            Your master password has been reset. You can now log in with your
            new password. Your vault entries are intact.
          </p>
          <Link to="/login" style={styles.linkButton}>
            Log In
          </Link>
        </div>
      </div>
    );
  }

  if (step === "set-password") {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Set New Password</h1>
          <p style={styles.subtitle}>
            Your vault key has been recovered. Set a new master password now.
          </p>

          <div style={styles.warning}>
            The vault key is in memory. Set your new password and do not close
            this page.
          </div>

          {error && (
            <div style={styles.error} role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleSetPassword} style={styles.form}>
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
                onChange={(e) => setConfirm(e.target.value)}
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

            <button
              type="submit"
              disabled={loading || validationErrors.length > 0}
              style={{
                ...styles.button,
                opacity: loading || validationErrors.length > 0 ? 0.6 : 1,
              }}
            >
              {loading ? "Setting password..." : "Set New Password"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <h1 style={styles.title}>Account Recovery</h1>
        <p style={styles.subtitle}>
          If you forgot your master password, use your recovery code to access
          your vault and set a new password.
        </p>

        <div style={styles.warningBox}>
          <strong style={{ color: "#f59e0b" }}>Important:</strong> If you did
          not save your recovery code during registration, your vault is
          permanently inaccessible. The server cannot reset your password —
          that is the zero-knowledge security guarantee.
        </div>

        {error && (
          <div style={styles.error} role="alert">
            {error}
          </div>
        )}

        <form onSubmit={handleRecover} style={styles.form}>
          <label style={styles.label}>
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setError(null);
              }}
              required
              autoComplete="username"
              style={styles.input}
            />
          </label>

          <label style={styles.label}>
            Recovery Code (32 hex characters)
            <input
              type="text"
              value={recoveryCode}
              onChange={(e) => {
                setRecoveryCode(
                  e.target.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 32),
                );
                setError(null);
              }}
              required
              placeholder="e.g. a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
              style={styles.input}
              maxLength={32}
            />
          </label>

          <button
            type="submit"
            disabled={loading || recoveryCode.length !== 32}
            style={{
              ...styles.button,
              opacity: loading || recoveryCode.length !== 32 ? 0.6 : 1,
            }}
          >
            {loading ? "Recovering..." : "Recover Vault"}
          </button>
        </form>

        <p style={styles.footer}>
          Remember your password?{" "}
          <Link to="/login" style={styles.link}>
            Log in instead
          </Link>
        </p>
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
    margin: "0 0 16px",
    fontSize: 14,
    color: "#888",
    textAlign: "center",
  },
  warning: {
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#2a1f05",
    border: "1px solid #5c4a0a",
    color: "#f59e0b",
    fontSize: 13,
  },
  warningBox: {
    padding: "12px 14px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#1a1500",
    border: "1px solid #3d3000",
    fontSize: 13,
    color: "#aaa",
    lineHeight: 1.5,
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
  linkButton: {
    display: "block",
    textAlign: "center",
    padding: "12px 16px",
    fontSize: 14,
    fontWeight: 600,
    borderRadius: 6,
    backgroundColor: "#7c8aff",
    color: "#fff",
    textDecoration: "none",
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
};
