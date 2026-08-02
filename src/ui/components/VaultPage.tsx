import React, { useState, useEffect, useMemo } from "react";
import { useVault, type DecryptedEntry } from "../contexts/VaultContext";
import { VaultEntryForm } from "./VaultEntryForm";
import { VaultEntryCard } from "./VaultEntryCard";
import { matchOrigin } from "../utils/urlMatch";

/**
 * Attempt to read the current page URL for autofill matching.
 * In a real browser extension or PWA this would use chrome.tabs or
 * window.location. For a standalone web app, we use window.location
 * and allow the user to manually enter a URL to match against.
 */
function useCurrentPageUrl(): string {
  const [currentUrl, setCurrentUrl] = useState(() => {
    try {
      return window.location.href;
    } catch {
      return "";
    }
  });

  useEffect(() => {
    const handler = () => {
      try {
        setCurrentUrl(window.location.href);
      } catch {
        // ignore
      }
    };
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, []);

  return currentUrl;
}

export function VaultPage() {
  const {
    decryptedEntries,
    loading,
    error,
    fetchEntries,
    deleteEntry,
    clearError,
  } = useVault();

  const [showForm, setShowForm] = useState(false);
  const [editingEntry, setEditingEntry] = useState<DecryptedEntry | null>(
    null,
  );
  const [filterUrl, setFilterUrl] = useState("");
  const currentUrl = useCurrentPageUrl();

  /**
   * URL matching for autofill suggestions.
   * Strictly compares origins (scheme + host + port), not substrings.
   * Entries with a matching URL are surfaced at the top with a "URL Match" badge.
   */
  const matchedEntries = useMemo(() => {
    const targetUrl = filterUrl || currentUrl;
    if (!targetUrl) return { matched: decryptedEntries, unmatched: [] };

    const matched: DecryptedEntry[] = [];
    const unmatched: DecryptedEntry[] = [];

    for (const entry of decryptedEntries) {
      if (entry.payload.url && matchOrigin(entry.payload.url, targetUrl)) {
        matched.push(entry);
      } else {
        unmatched.push(entry);
      }
    }

    return { matched, unmatched };
  }, [decryptedEntries, filterUrl, currentUrl]);

  const handleEdit = (entry: DecryptedEntry) => {
    setEditingEntry(entry);
    setShowForm(true);
  };

  const handleFormClose = () => {
    setShowForm(false);
    setEditingEntry(null);
  };

  const handleDelete = async (id: string) => {
    if (window.confirm("Delete this entry permanently?")) {
      await deleteEntry(id);
    }
  };

  return (
    <div>
      <div style={styles.toolbar}>
        <h2 style={styles.heading}>Vault Entries</h2>
        <div style={styles.toolbarRight}>
          <button
            onClick={fetchEntries}
            style={styles.secondaryBtn}
            disabled={loading}
          >
            Refresh
          </button>
          <button
            onClick={() => {
              setEditingEntry(null);
              setShowForm(true);
            }}
            style={styles.primaryBtn}
          >
            + New Entry
          </button>
        </div>
      </div>

      {/* URL filter for autofill matching */}
      <div style={styles.filterBar}>
        <label style={styles.filterLabel}>
          Match URL for autofill
          <input
            type="url"
            value={filterUrl}
            onChange={(e) => setFilterUrl(e.target.value)}
            placeholder={currentUrl || "https://example.com"}
            style={styles.filterInput}
          />
        </label>
        {filterUrl && (
          <button
            onClick={() => setFilterUrl("")}
            style={styles.clearFilterBtn}
          >
            Clear
          </button>
        )}
      </div>

      {error && (
        <div style={styles.error} role="alert">
          {error}
          <button onClick={clearError} style={styles.dismissBtn}>
            x
          </button>
        </div>
      )}

      {showForm && (
        <VaultEntryForm entry={editingEntry} onClose={handleFormClose} />
      )}

      {loading && decryptedEntries.length === 0 && (
        <p style={styles.loading}>Loading vault entries...</p>
      )}

      {!loading && decryptedEntries.length === 0 && !showForm && (
        <div style={styles.empty}>
          <p style={styles.emptyTitle}>Your vault is empty</p>
          <p style={styles.emptySub}>
            Add your first entry to get started. All data is encrypted
            client-side before being stored on the server.
          </p>
        </div>
      )}

      {/* URL-matched entries shown first with badge */}
      {matchedEntries.matched.length > 0 &&
        matchedEntries.matched !== decryptedEntries && (
          <>
            <h3 style={styles.sectionTitle}>
              Matching entries ({matchedEntries.matched.length})
            </h3>
            <div style={styles.list}>
              {matchedEntries.matched.map((entry) => (
                <VaultEntryCard
                  key={entry.id}
                  entry={entry}
                  onEdit={() => handleEdit(entry)}
                  onDelete={() => handleDelete(entry.id)}
                  urlMatch
                />
              ))}
            </div>
          </>
        )}

      {/* All entries */}
      <div style={styles.list}>
        {(matchedEntries.unmatched.length > 0
          ? matchedEntries.unmatched
          : matchedEntries.matched.length > 0
            ? []
            : decryptedEntries
        ).map((entry) => (
          <VaultEntryCard
            key={entry.id}
            entry={entry}
            onEdit={() => handleEdit(entry)}
            onDelete={() => handleDelete(entry.id)}
          />
        ))}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  toolbar: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 16,
  },
  toolbarRight: {
    display: "flex",
    gap: 8,
  },
  heading: {
    margin: 0,
    fontSize: 18,
    fontWeight: 600,
    color: "#e0e0e0",
  },
  primaryBtn: {
    padding: "8px 16px",
    fontSize: 13,
    fontWeight: 600,
    border: "none",
    borderRadius: 6,
    backgroundColor: "#7c8aff",
    color: "#fff",
    cursor: "pointer",
  },
  secondaryBtn: {
    padding: "8px 16px",
    fontSize: 13,
    border: "1px solid #2a2d35",
    borderRadius: 6,
    backgroundColor: "transparent",
    color: "#aaa",
    cursor: "pointer",
  },
  filterBar: {
    display: "flex",
    alignItems: "flex-end",
    gap: 8,
    marginBottom: 20,
    padding: "12px 16px",
    border: "1px solid #2a2d35",
    borderRadius: 8,
    backgroundColor: "#161822",
  },
  filterLabel: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: 4,
    fontSize: 12,
    color: "#888",
  },
  filterInput: {
    padding: "8px 10px",
    fontSize: 13,
    border: "1px solid #2a2d35",
    borderRadius: 4,
    backgroundColor: "#0f1117",
    color: "#e0e0e0",
    outline: "none",
    fontFamily: "'SF Mono', 'Fira Code', monospace",
  },
  clearFilterBtn: {
    padding: "8px 12px",
    fontSize: 12,
    border: "1px solid #2a2d35",
    borderRadius: 4,
    backgroundColor: "transparent",
    color: "#888",
    cursor: "pointer",
  },
  sectionTitle: {
    margin: "0 0 12px",
    fontSize: 14,
    fontWeight: 600,
    color: "#22c55e",
  },
  error: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "10px 12px",
    marginBottom: 16,
    borderRadius: 6,
    backgroundColor: "#3a1520",
    border: "1px solid #5c2233",
    color: "#ff6b8a",
    fontSize: 13,
  },
  dismissBtn: {
    background: "none",
    border: "none",
    color: "#ff6b8a",
    cursor: "pointer",
    fontSize: 16,
  },
  loading: {
    color: "#888",
    fontSize: 14,
    textAlign: "center",
    padding: 40,
  },
  empty: {
    textAlign: "center",
    padding: 60,
    border: "1px dashed #2a2d35",
    borderRadius: 12,
  },
  emptyTitle: {
    margin: "0 0 8px",
    fontSize: 16,
    color: "#aaa",
  },
  emptySub: {
    margin: 0,
    fontSize: 13,
    color: "#666",
    maxWidth: 400,
    marginInline: "auto",
  },
  list: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
};
