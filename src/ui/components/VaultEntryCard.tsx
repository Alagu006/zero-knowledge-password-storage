import React, { useState } from "react";
import type { DecryptedEntry } from "../contexts/VaultContext";
import { useClipboard } from "../hooks/useClipboard";
import { escapeHtml } from "../utils/sanitize";

type Props = {
  entry: DecryptedEntry;
  onEdit: () => void;
  onDelete: () => void;
  /** If true, this entry matches the current page URL (autofill suggestion). */
  urlMatch?: boolean;
};

/**
 * SECURITY: This component NEVER uses dangerouslySetInnerHTML.
 * All user-provided data (label, url, username, notes, secret) is rendered
 * either as React text content (which auto-escapes) or via escapeHtml()
 * for defense-in-depth. The escapeHtml calls on text nodes are redundant
 * with React's built-in escaping but serve as a safety net against future
 * refactors that might introduce dangerouslySetInnerHTML.
 */
export function VaultEntryCard({ entry, onEdit, onDelete, urlMatch }: Props) {
  const { copyToClipboard, copied } = useClipboard();
  const [showSecret, setShowSecret] = useState(false);
  const [confirmCopy, setConfirmCopy] = useState(false);
  const [showAllFields, setShowAllFields] = useState(false);

  const { payload } = entry;
  const isDecryptionFailed = payload.secret.startsWith("[Decryption failed");

  const handleCopy = async () => {
    if (!confirmCopy) {
      setConfirmCopy(true);
      setTimeout(() => setConfirmCopy(false), 3000);
      return;
    }
    await copyToClipboard(payload.secret);
    setConfirmCopy(false);
  };

  return (
    <div
      style={{
        ...styles.card,
        ...(urlMatch ? styles.cardMatch : undefined),
      }}
    >
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.typeBadge}>{escapeHtml(entry.entryType)}</div>
          {urlMatch && <span style={styles.matchBadge}>URL Match</span>}
        </div>
        <div style={styles.actions}>
          <button onClick={onEdit} style={styles.actionBtn} title="Edit">
            Edit
          </button>
          <button onClick={onDelete} style={styles.deleteBtn} title="Delete">
            Delete
          </button>
        </div>
      </div>

      <div style={styles.body}>
        {/* Label */}
        {payload.label && (
          <div style={styles.field}>
            <span style={styles.fieldLabel}>Label</span>
            <span style={styles.fieldValue}>{escapeHtml(payload.label)}</span>
          </div>
        )}

        {/* URL */}
        {payload.url && (
          <div style={styles.field}>
            <span style={styles.fieldLabel}>URL</span>
            <span style={styles.fieldValue}>{escapeHtml(payload.url)}</span>
          </div>
        )}

        {/* Username */}
        {payload.username && (
          <div style={styles.field}>
            <span style={styles.fieldLabel}>Username</span>
            <span style={styles.fieldValue}>
              {escapeHtml(payload.username)}
            </span>
          </div>
        )}

        {/* Secret — masked by default */}
        <div style={styles.field}>
          <span style={styles.fieldLabel}>Secret</span>
          {isDecryptionFailed ? (
            <span style={styles.failedText}>
              {escapeHtml(payload.secret)}
            </span>
          ) : (
            <div style={styles.valueRow}>
              <code style={styles.value}>
                {showSecret
                  ? escapeHtml(payload.secret)
                  : "\u2022".repeat(Math.min(payload.secret.length, 24))}
              </code>
              <button
                onClick={() => setShowSecret(!showSecret)}
                style={styles.toggleBtn}
              >
                {showSecret ? "Hide" : "Show"}
              </button>
            </div>
          )}
        </div>

        {/* Notes — collapsible */}
        {payload.notes && (
          <>
            <button
              onClick={() => setShowAllFields(!showAllFields)}
              style={styles.expandBtn}
            >
              {showAllFields ? "Hide notes" : "Show notes"}
            </button>
            {showAllFields && (
              <div style={styles.field}>
                <span style={styles.fieldLabel}>Notes</span>
                <pre style={styles.notes}>{escapeHtml(payload.notes)}</pre>
              </div>
            )}
          </>
        )}

        {/* Copy button with clipboard warning */}
        {!isDecryptionFailed && (
          <>
            <button
              onClick={handleCopy}
              style={{
                ...styles.copyBtn,
                backgroundColor: confirmCopy ? "#f59e0b" : "#2a2d35",
                color: confirmCopy ? "#000" : "#ccc",
              }}
            >
              {copied
                ? "Copied! (auto-clears in 30s)"
                : confirmCopy
                  ? "Click again to confirm copy"
                  : "Copy secret to clipboard"}
            </button>
            {confirmCopy && (
              <p style={styles.clipboardWarning}>
                Clipboard contents will be cleared in 30 seconds. Note: clipboard
                history tools, screen recorders, and other applications may
                retain copies beyond our control.
              </p>
            )}
          </>
        )}

        <div style={styles.meta}>
          <span>v{entry.version}</span>
          <span>Updated {new Date(entry.updatedAt).toLocaleDateString()}</span>
        </div>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  card: {
    border: "1px solid #2a2d35",
    borderRadius: 10,
    backgroundColor: "#161822",
    overflow: "hidden",
  },
  cardMatch: {
    border: "1px solid #3d6b5c",
    boxShadow: "0 0 0 1px #225c3333",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "12px 16px",
    borderBottom: "1px solid #2a2d35",
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  typeBadge: {
    fontSize: 12,
    fontWeight: 600,
    padding: "3px 8px",
    borderRadius: 4,
    backgroundColor: "#1e2030",
    color: "#7c8aff",
  },
  matchBadge: {
    fontSize: 11,
    fontWeight: 600,
    padding: "2px 6px",
    borderRadius: 4,
    backgroundColor: "#153a20",
    color: "#22c55e",
  },
  actions: {
    display: "flex",
    gap: 6,
  },
  actionBtn: {
    padding: "4px 10px",
    fontSize: 12,
    border: "1px solid #2a2d35",
    borderRadius: 4,
    backgroundColor: "transparent",
    color: "#aaa",
    cursor: "pointer",
  },
  deleteBtn: {
    padding: "4px 10px",
    fontSize: 12,
    border: "1px solid #3d2233",
    borderRadius: 4,
    backgroundColor: "transparent",
    color: "#ff6b8a",
    cursor: "pointer",
  },
  body: {
    padding: 16,
  },
  field: {
    marginBottom: 12,
  },
  fieldLabel: {
    display: "block",
    fontSize: 11,
    color: "#666",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    marginBottom: 4,
  },
  fieldValue: {
    display: "block",
    fontSize: 14,
    color: "#e0e0e0",
    wordBreak: "break-all",
  },
  valueRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  value: {
    flex: 1,
    fontSize: 14,
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    color: "#e0e0e0",
    wordBreak: "break-all",
    backgroundColor: "#0f1117",
    padding: "8px 10px",
    borderRadius: 4,
  },
  toggleBtn: {
    padding: "4px 8px",
    fontSize: 11,
    border: "1px solid #2a2d35",
    borderRadius: 4,
    backgroundColor: "transparent",
    color: "#888",
    cursor: "pointer",
    flexShrink: 0,
  },
  expandBtn: {
    background: "none",
    border: "none",
    color: "#7c8aff",
    fontSize: 12,
    cursor: "pointer",
    padding: "4px 0",
    marginBottom: 8,
    textAlign: "left",
  },
  notes: {
    margin: 0,
    fontSize: 13,
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    color: "#aaa",
    backgroundColor: "#0f1117",
    padding: "8px 10px",
    borderRadius: 4,
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
  },
  copyBtn: {
    width: "100%",
    padding: "8px 12px",
    fontSize: 12,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    cursor: "pointer",
    marginBottom: 4,
    transition: "background-color 0.15s, color 0.15s",
  },
  clipboardWarning: {
    margin: "0 0 12px",
    fontSize: 11,
    color: "#f59e0b",
    lineHeight: 1.5,
  },
  meta: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: 11,
    color: "#555",
    marginTop: 8,
  },
  failedText: {
    color: "#ff6b8a",
    fontSize: 13,
    fontStyle: "italic",
  },
};
