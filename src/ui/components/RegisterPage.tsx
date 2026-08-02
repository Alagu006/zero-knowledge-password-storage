import React, { useState, FormEvent, useCallback, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { validatePasswordStrength, scoreLabel } from "../../client/password";
import { checkPasswordBreached } from "../../client/breachCheck";

export function RegisterPage() {
  const { register, loading, error, clearError } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [score, setScore] = useState(0);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [codeCopied, setCodeCopied] = useState(false);
  const [breachWarning, setBreachWarning] = useState<string | null>(null);
  const breachCheckedForRef = useRef("");
  const breachAcceptedRef = useRef(false);

  const handlePasswordChange = (value: string) => {
    setPassword(value);
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
    if (password !== confirm) {
      setValidationErrors(["Passwords do not match"]);
      return;
    }
    setValidationErrors([]);

    if (breachCheckedForRef.current !== password || !breachAcceptedRef.current) {
      const breach = await checkPasswordBreached(password);
      if (breach.status === "ok" && breach.breached) {
        breachCheckedForRef.current = password;
        breachAcceptedRef.current = false;
        setBreachWarning(
          `This password has appeared in ${breach.count.toLocaleString()} known data breaches. Using it is risky — a never-leaked password is safer. Click "Create Account" again to proceed anyway.`,
        );
        return;
      }
      // Fail-open: "error" (HIBP unreachable) and "not breached" both proceed.
      breachCheckedForRef.current = password;
      breachAcceptedRef.current = true;
      setBreachWarning(null);
    }

    const result = await register(email, password);
    if (result.ok && result.recoveryCode) {
      setRecoveryCode(result.recoveryCode);
    } else if (result.ok) {
      navigate("/login");
    }
  };

  const copyCode = useCallback(async () => {
    if (!recoveryCode) return;
    try {
      await navigator.clipboard.writeText(recoveryCode);
      setCodeCopied(true);
      setTimeout(() => setCodeCopied(false), 3000);
    } catch {
      // Fallback: select the text so user can Ctrl+C
    }
  }, [recoveryCode]);

  // Recovery code display screen
  if (recoveryCode) {
    return (
      <div style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.title}>Save Your Recovery Code</h1>
          <p style={styles.subtitle}>
            Your account has been created. Save this recovery code somewhere
            safe — you will need it if you forget your master password.
          </p>

          <div style={styles.recoveryWarning}>
            <strong style={{ color: "#f59e0b" }}>Critical:</strong> If you lose
            both your master password AND this recovery code, your vault is
            permanently inaccessible. The server cannot help you recover it.
          </div>

          <div style={styles.codeBox}>
            <code style={styles.code}>{recoveryCode}</code>
          </div>

          <button onClick={copyCode} style={styles.copyButton}>
            {codeCopied ? "Copied!" : "Copy to Clipboard"}
          </button>

          <div style={styles.securityNote}>
            <strong>Security notes:</strong>
            <ul style={styles.securityList}>
              <li>Write this code on paper and store it in a safe place</li>
              <li>Do not store it in a password manager (that is what this app is)</li>
              <li>Do not screenshot it — screen recording software may capture it</li>
              <li>This code will not be shown again</li>
            </ul>
          </div>

          <button
            onClick={() => navigate("/login")}
            style={styles.button}
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <h1 style={styles.title}>Create Account</h1>
        <p style={styles.subtitle}>
          Your vault key will be encrypted with your master password.
        </p>

        <div style={styles.recoveryInfo}>
          <strong>Account recovery:</strong> A 128-bit recovery code will be
          generated and shown once during signup. If you forget your master
          password, you can use this code to recover your vault. Without it,
          a forgotten password means permanent data loss — this is the
          zero-knowledge trade-off.
        </div>

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
              onChange={(e) => handlePasswordChange(e.target.value)}
              required
              autoComplete="new-password"
              style={styles.input}
            />
            {password.length > 0 && (
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
            {password.length > 0 && (
              <span style={{ ...styles.scoreLabel, color: scoreColor(score) }}>
                {scoreLabel(score)}
              </span>
            )}
          </label>

          <label style={styles.label}>
            Confirm Password
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
            {loading ? "Creating account..." : "Create Account"}
          </button>
        </form>

        <p style={styles.footer}>
          Already have an account?{" "}
          <Link to="/login" style={styles.link}>
            Log in
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
    maxWidth: 420,
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
  recoveryInfo: {
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#1a1520",
    border: "1px solid #2d2233",
    fontSize: 12,
    color: "#aaa",
    lineHeight: 1.5,
  },
  recoveryWarning: {
    padding: "12px 14px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#2a1f05",
    border: "1px solid #5c4a0a",
    fontSize: 13,
    color: "#ccc",
    lineHeight: 1.5,
  },
  codeBox: {
    padding: "16px",
    marginBottom: 12,
    borderRadius: 6,
    backgroundColor: "#0f1117",
    border: "1px solid #2a2d35",
    textAlign: "center",
  },
  code: {
    fontSize: 16,
    fontFamily: "'Fira Code', 'Cascadia Code', monospace",
    color: "#22c55e",
    letterSpacing: 2,
    wordBreak: "break-all",
  },
  copyButton: {
    width: "100%",
    padding: "8px 12px",
    fontSize: 13,
    fontWeight: 600,
    border: "1px solid #3a3d45",
    borderRadius: 6,
    backgroundColor: "#1a1d25",
    color: "#ccc",
    cursor: "pointer",
    marginBottom: 16,
  },
  securityNote: {
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#1a1520",
    border: "1px solid #2d2233",
    fontSize: 12,
    color: "#888",
    lineHeight: 1.5,
  },
  securityList: {
    margin: "6px 0 0",
    padding: "0 0 0 16px",
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
};
