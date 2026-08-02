import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { useAutoLock } from "../contexts/AutoLockContext";

export function Layout({ children }: { children: React.ReactNode }) {
  const { email, logout } = useAuth();
  const { remainingMs } = useAutoLock();

  const minutes = Math.floor(remainingMs / 60_000);
  const seconds = Math.floor((remainingMs % 60_000) / 1000);

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <h1 style={styles.logo}>ZKM</h1>
        </div>
        <div style={styles.headerRight}>
          <span style={styles.timer}>
            Lock in {minutes}:{seconds.toString().padStart(2, "0")}
          </span>
          <span style={styles.email}>{email}</span>
          <Link to="/change-password" style={styles.changePasswordLink}>
            Change Password
          </Link>
          <Link to="/2fa-setup" style={styles.changePasswordLink}>
            2FA Setup
          </Link>
          <Link to="/sessions" style={styles.changePasswordLink}>
            Sessions
          </Link>
          <button onClick={logout} style={styles.logoutBtn}>
            Lock &amp; Log Out
          </button>
        </div>
      </header>
      <main style={styles.main}>{children}</main>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: "100vh",
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 24px",
    borderBottom: "1px solid #2a2d35",
    backgroundColor: "#161822",
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
  },
  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: 16,
  },
  logo: {
    margin: 0,
    fontSize: 20,
    fontWeight: 700,
    color: "#7c8aff",
  },
  timer: {
    fontSize: 13,
    color: "#888",
    fontVariantNumeric: "tabular-nums",
  },
  email: {
    fontSize: 13,
    color: "#aaa",
  },
  changePasswordLink: {
    fontSize: 13,
    color: "#7c8aff",
    textDecoration: "none",
  },
  logoutBtn: {
    padding: "6px 12px",
    fontSize: 13,
    border: "1px solid #3a3d45",
    borderRadius: 6,
    backgroundColor: "transparent",
    color: "#ccc",
    cursor: "pointer",
  },
  main: {
    maxWidth: 800,
    margin: "0 auto",
    padding: 24,
  },
};
