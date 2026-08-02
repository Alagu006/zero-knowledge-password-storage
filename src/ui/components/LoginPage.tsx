import React, { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export function LoginPage() {
  const { login, loading, error, clearError, twoFactorPending, verify2FA, verify2FAWithBackupCode, cancel2FA } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await login(email, password);
    if (ok) navigate("/vault");
  };

  const handleVerify2FA = async (e: FormEvent) => {
    e.preventDefault();
    const code = useBackupCode ? backupCode : totpCode;
    const ok = useBackupCode
      ? await verify2FAWithBackupCode(code)
      : await verify2FA(code);
    if (ok) navigate("/vault");
  };

  const handleCancel2FA = () => {
    cancel2FA();
    setTotpCode("");
    setBackupCode("");
    setUseBackupCode(false);
  };

  // ── 2FA prompt ──────────────────────────────────────────────────────
  if (twoFactorPending) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Two-Factor Authentication</h1>
          <p style={styles.subtitle}>
            {useBackupCode
              ? "Enter one of your backup codes"
              : "Enter the 6-digit code from your authenticator app"}
          </p>

          {error && (
            <div style={styles.error} role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleVerify2FA} style={styles.form}>
            {!useBackupCode ? (
              <label style={styles.label}>
                Authenticator Code
                <input
                  type="text"
                  value={totpCode}
                  onChange={(e) => {
                    setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6));
                    clearError();
                  }}
                  placeholder="000000"
                  maxLength={6}
                  autoComplete="one-time-code"
                  style={styles.input}
                />
              </label>
            ) : (
              <label style={styles.label}>
                Backup Code
                <input
                  type="text"
                  value={backupCode}
                  onChange={(e) => {
                    setBackupCode(e.target.value.toUpperCase().slice(0, 9));
                    clearError();
                  }}
                  placeholder="XXXX-XXXX"
                  maxLength={9}
                  style={styles.input}
                />
              </label>
            )}

            <button
              type="submit"
              disabled={loading || (useBackupCode ? backupCode.length < 8 : totpCode.length !== 6)}
              style={{
                ...styles.button,
                opacity: loading || (useBackupCode ? backupCode.length < 8 : totpCode.length !== 6) ? 0.6 : 1,
              }}
            >
              {loading ? "Verifying..." : "Verify"}
            </button>
          </form>

          <p style={styles.footer}>
            <button
              onClick={() => {
                setUseBackupCode(!useBackupCode);
                setTotpCode("");
                setBackupCode("");
                clearError();
              }}
              style={styles.linkButton}
            >
              {useBackupCode ? "Use authenticator code instead" : "Use a backup code"}
            </button>
          </p>

          <p style={styles.footer}>
            <button onClick={handleCancel2FA} style={styles.linkButton}>
              Back to login
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ── Normal login form ───────────────────────────────────────────────
  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <h1 style={styles.title}>Zero Knowledge Password Manager</h1>
        <p style={styles.subtitle}>Log in to your vault</p>

        {error && (
          <div style={styles.error} role="alert">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          <label style={styles.label}>
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                clearError();
              }}
              required
              autoComplete="username"
              style={styles.input}
            />
          </label>

          <label style={styles.label}>
            Master Password
            <input
              type="password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                clearError();
              }}
              required
              autoComplete="current-password"
              style={styles.input}
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            style={{
              ...styles.button,
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? "Deriving keys..." : "Unlock Vault"}
          </button>
        </form>

        <p style={styles.footer}>
          Don't have an account?{" "}
          <Link to="/register" style={styles.link}>
            Register
          </Link>
        </p>

        <p style={styles.footer}>
          <Link to="/recover" style={styles.link}>
            Forgot master password?
          </Link>
        </p>

        <p style={styles.security}>
          Your master password never leaves this device. All encryption happens
          in your browser.
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
  linkButton: {
    background: "none",
    border: "none",
    color: "#7c8aff",
    cursor: "pointer",
    fontSize: 13,
    padding: 0,
  },
  security: {
    marginTop: 16,
    fontSize: 11,
    color: "#666",
    textAlign: "center",
    lineHeight: 1.5,
  },
};
