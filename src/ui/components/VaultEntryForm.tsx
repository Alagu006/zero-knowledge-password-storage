import React, { useState, FormEvent } from "react";
import { useVault } from "../contexts/VaultContext";
import type { VaultEntryPayload } from "../utils/entryTypes";
import type { DecryptedEntry } from "../contexts/VaultContext";

type Props = {
  entry: DecryptedEntry | null;
  onClose: () => void;
};

export function VaultEntryForm({ entry, onClose }: Props) {
  const { createEntry, updateEntry, loading } = useVault();
  const [entryType, setEntryType] = useState(entry?.entryType ?? "password");
  const [label, setLabel] = useState(entry?.payload.label ?? "");
  const [url, setUrl] = useState(entry?.payload.url ?? "");
  const [username, setUsername] = useState(entry?.payload.username ?? "");
  const [secret, setSecret] = useState(entry?.payload.secret ?? "");
  const [notes, setNotes] = useState(entry?.payload.notes ?? "");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const isEditing = !!entry;

  const buildPayload = (): VaultEntryPayload => ({
    label,
    url,
    username,
    secret,
    notes,
  });

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    const payload = buildPayload();
    let ok: boolean;
    if (isEditing) {
      ok = await updateEntry(entry.id, entryType, payload, entry.version);
    } else {
      ok = await createEntry(entryType, payload);
    }

    if (ok) {
      setSuccess(true);
      setTimeout(() => onClose(), 600);
    } else {
      setError(
        isEditing ? "Failed to update entry" : "Failed to create entry",
      );
    }
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>
        <div style={styles.modalHeader}>
          <h3 style={styles.modalTitle}>
            {isEditing ? "Edit Entry" : "New Entry"}
          </h3>
          <button onClick={onClose} style={styles.closeBtn}>
            x
          </button>
        </div>

        {error && (
          <div style={styles.error} role="alert">
            {error}
          </div>
        )}

        {success && (
          <div style={styles.success}>
            {isEditing ? "Entry updated" : "Entry created"}
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          <label style={styles.label}>
            Entry Type
            <select
              value={entryType}
              onChange={(e) => setEntryType(e.target.value)}
              style={styles.select}
            >
              <option value="password">Password</option>
              <option value="note">Secure Note</option>
              <option value="api-key">API Key</option>
              <option value="ssh-key">SSH Key</option>
              <option value="credit-card">Credit Card</option>
              <option value="other">Other</option>
            </select>
          </label>

          <label style={styles.label}>
            Label / Site Name
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. GitHub, Gmail, AWS"
              required
              style={styles.input}
            />
          </label>

          <label style={styles.label}>
            URL
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com"
              style={styles.input}
            />
          </label>

          <label style={styles.label}>
            Username / Email
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="user@example.com"
              autoComplete="off"
              style={styles.input}
            />
          </label>

          <label style={styles.label}>
            Secret / Password
            <textarea
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              required
              rows={3}
              placeholder="Enter the secret to encrypt..."
              autoComplete="off"
              style={styles.textarea}
            />
          </label>

          <label style={styles.label}>
            Notes
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Optional notes..."
              style={styles.textarea}
            />
          </label>

          <p style={styles.warning}>
            All fields are encrypted client-side before storage. The server
            never sees the plaintext.
          </p>

          <div style={styles.actions}>
            <button type="button" onClick={onClose} style={styles.cancelBtn}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !label || !secret}
              style={{
                ...styles.saveBtn,
                opacity: loading || !label || !secret ? 0.6 : 1,
              }}
            >
              {loading
                ? "Encrypting..."
                : isEditing
                  ? "Save Changes"
                  : "Encrypt & Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: "fixed",
    inset: 0,
    backgroundColor: "rgba(0,0,0,0.6)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1000,
  },
  modal: {
    width: "100%",
    maxWidth: 520,
    maxHeight: "85vh",
    overflow: "auto",
    backgroundColor: "#161822",
    border: "1px solid #2a2d35",
    borderRadius: 12,
    padding: 24,
  },
  modalHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 20,
  },
  modalTitle: {
    margin: 0,
    fontSize: 16,
    fontWeight: 600,
    color: "#e0e0e0",
  },
  closeBtn: {
    background: "none",
    border: "none",
    color: "#888",
    fontSize: 18,
    cursor: "pointer",
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
    backgroundColor: "#153a20",
    border: "1px solid #225c33",
    color: "#22c55e",
    fontSize: 13,
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: 14,
  },
  label: {
    display: "flex",
    flexDirection: "column",
    gap: 5,
    fontSize: 13,
    color: "#aaa",
  },
  input: {
    padding: "9px 12px",
    fontSize: 14,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    outline: "none",
  },
  select: {
    padding: "9px 12px",
    fontSize: 14,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    outline: "none",
  },
  textarea: {
    padding: "9px 12px",
    fontSize: 14,
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    outline: "none",
    resize: "vertical",
  },
  warning: {
    margin: 0,
    fontSize: 11,
    color: "#666",
    fontStyle: "italic",
  },
  actions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: 8,
    marginTop: 8,
  },
  cancelBtn: {
    padding: "8px 16px",
    fontSize: 13,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "transparent",
    color: "#aaa",
    cursor: "pointer",
  },
  saveBtn: {
    padding: "8px 16px",
    fontSize: 13,
    fontWeight: 600,
    border: "none",
    borderRadius: 6,
    backgroundColor: "#7c8aff",
    color: "#fff",
    cursor: "pointer",
  },
};
