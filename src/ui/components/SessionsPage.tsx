import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import {
  apiListSessions,
  apiRevokeSession,
  apiRevokeAllSessions,
} from "../../client/api";
import type { SessionInfo } from "../../client/api";

export function SessionsPage() {
  const { token } = useAuth();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiListSessions(token);
      setSessions(res.sessions);
    } catch {
      setError("Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const revokeOne = async (id: string) => {
    if (!token) return;
    setBusyId(id);
    setError(null);
    setMessage(null);
    try {
      await apiRevokeSession(token, id);
      setSessions((prev) => prev.filter((s) => s.id !== id));
    } catch {
      setError("Failed to revoke session");
    } finally {
      setBusyId(null);
    }
  };

  const revokeAllOthers = async () => {
    if (!token) return;
    setBusyId("all");
    setError(null);
    setMessage(null);
    try {
      await apiRevokeAllSessions(token);
      await refresh();
      setMessage("All other sessions have been revoked.");
    } catch {
      setError("Failed to revoke sessions");
    } finally {
      setBusyId(null);
    }
  };

  const formatDate = (iso: string) =>
    new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <h1 style={styles.title}>Active Sessions</h1>
        <p style={styles.subtitle}>
          Devices currently signed in to your account. Revoke any session you
          no longer recognize. IP addresses and user agents are best-effort
          metadata shown for situational awareness only.
        </p>

        {error && (
          <div style={styles.error} role="alert">
            {error}
          </div>
        )}
        {message && (
          <div style={styles.success} role="status">
            {message}
          </div>
        )}

        {loading ? (
          <p style={styles.empty}>Loading sessions…</p>
        ) : sessions.length === 0 ? (
          <p style={styles.empty}>No active sessions.</p>
        ) : (
          <ul style={styles.list}>
            {sessions.map((s) => (
              <li key={s.id} style={styles.item}>
                <div style={styles.itemBody}>
                  <div style={styles.itemRow}>
                    <span style={styles.deviceLabel}>
                      {s.userAgent ? (
                        s.userAgent.split(" ").slice(0, 4).join(" ") +
                        (s.userAgent.split(" ").length > 4 ? "…" : "")
                      ) : (
                        "Unknown device"
                      )}
                    </span>
                    {s.current && <span style={styles.currentTag}>This device</span>}
                    {!s.active && !s.current && (
                      <span style={styles.expiredTag}>Expired</span>
                    )}
                  </div>
                  <div style={styles.metaRow}>
                    <span>{s.ipAddress ?? "IP unknown"}</span>
                    <span>·</span>
                    <span>Logged in {formatDate(s.createdAt)}</span>
                    {!s.active && <span>· Expired {formatDate(s.expiresAt)}</span>}
                  </div>
                </div>
                {!s.current && (
                  <button
                    onClick={() => revokeOne(s.id)}
                    disabled={busyId !== null}
                    style={styles.revokeBtn}
                  >
                    {busyId === s.id ? "Revoking…" : "Revoke"}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}

        <div style={styles.actions}>
          <button
            onClick={revokeAllOthers}
            disabled={busyId !== null || sessions.length <= 1}
            style={{
              ...styles.revokeAllBtn,
              opacity: busyId !== null || sessions.length <= 1 ? 0.6 : 1,
            }}
          >
            {busyId === "all" ? "Revoking…" : "Revoke All Other Devices"}
          </button>
          <Link to="/vault" style={styles.link}>
            Back to Vault
          </Link>
        </div>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "center",
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    padding: "48px 16px",
  },
  card: {
    width: "100%",
    maxWidth: 560,
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
    margin: "0 0 20px",
    fontSize: 13,
    color: "#888",
    textAlign: "center",
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
  success: {
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#122a1a",
    border: "1px solid #1f5c33",
    color: "#5ddb8a",
    fontSize: 13,
  },
  empty: {
    fontSize: 13,
    color: "#888",
    textAlign: "center",
    padding: "16px 0",
  },
  list: {
    margin: 0,
    padding: 0,
    listStyle: "none",
  },
  item: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
    padding: "12px 14px",
    marginBottom: 8,
    borderRadius: 6,
    backgroundColor: "#0f1117",
    border: "1px solid #2a2d35",
  },
  itemBody: {
    minWidth: 0,
  },
  itemRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    marginBottom: 4,
  },
  deviceLabel: {
    fontSize: 14,
    fontWeight: 600,
    color: "#e0e0e0",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  currentTag: {
    fontSize: 11,
    fontWeight: 600,
    color: "#22c55e",
    border: "1px solid #1f5c33",
    borderRadius: 4,
    padding: "1px 6px",
  },
  expiredTag: {
    fontSize: 11,
    fontWeight: 600,
    color: "#888",
    border: "1px solid #3a3d45",
    borderRadius: 4,
    padding: "1px 6px",
  },
  metaRow: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    fontSize: 12,
    color: "#888",
  },
  revokeBtn: {
    padding: "6px 12px",
    fontSize: 13,
    fontWeight: 600,
    border: "1px solid #5c2233",
    borderRadius: 6,
    backgroundColor: "#3a1520",
    color: "#ff6b8a",
    cursor: "pointer",
    whiteSpace: "nowrap",
  },
  actions: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginTop: 20,
    gap: 12,
  },
  revokeAllBtn: {
    padding: "10px 14px",
    fontSize: 13,
    fontWeight: 600,
    border: "1px solid #5c4a0a",
    borderRadius: 6,
    backgroundColor: "#2a1f05",
    color: "#f5c65d",
    cursor: "pointer",
  },
  link: {
    fontSize: 13,
    color: "#7c8aff",
    textDecoration: "none",
  },
};
