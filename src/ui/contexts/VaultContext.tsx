import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
} from "react";
import { useAuth } from "./AuthContext";
import {
  apiListEntries,
  apiCreateEntry,
  apiUpdateEntry,
  apiDeleteEntry,
  toHex,
  fromHex,
} from "../../client/api";
import { encryptEntry, decryptEntry, zeroize } from "../../crypto";
import type { EncryptedEntry } from "../../crypto/types";
import type { VaultEntryResponse } from "../../client/api";
import type { VaultEntryPayload } from "../utils/entryTypes";
import { serializePayload, deserializePayload } from "../utils/entryTypes";

/**
 * Decrypted entry as rendered by the UI.
 * `payload` holds the structured fields (label, url, username, notes, secret).
 * `rawJson` is kept for display/debugging but NEVER rendered via
 * dangerouslySetInnerHTML.
 */
export type DecryptedEntry = {
  id: string;
  entryType: string;
  payload: VaultEntryPayload;
  version: number;
  createdAt: string;
  updatedAt: string;
};

type VaultContextValue = {
  encryptedEntries: VaultEntryResponse[];
  decryptedEntries: DecryptedEntry[];
  loading: boolean;
  error: string | null;
  fetchEntries: () => Promise<void>;
  createEntry: (
    entryType: string,
    payload: VaultEntryPayload,
  ) => Promise<boolean>;
  updateEntry: (
    id: string,
    entryType: string,
    payload: VaultEntryPayload,
    version: number,
  ) => Promise<boolean>;
  deleteEntry: (id: string) => Promise<boolean>;
  clearError: () => void;
  /** Clear all decrypted state (called by auto-lock, defense-in-depth). */
  clearDecryptedState: () => void;
};

const VaultContext = createContext<VaultContextValue | null>(null);

export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be inside VaultProvider");
  return ctx;
}

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const { token, vaultKey } = useAuth();
  const [encryptedEntries, setEncryptedEntries] = useState<
    VaultEntryResponse[]
  >([]);
  const [decryptedEntries, setDecryptedEntries] = useState<DecryptedEntry[]>(
    [],
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => setError(null), []);

  /**
   * Explicitly wipe all decrypted state from memory.
   * Called on logout and by auto-lock for defense-in-depth.
   * Even though unmounting VaultProvider would GC the state, explicitly
   * zeroing prevents stale references from lingering in closure captures.
   */
  const clearDecryptedState = useCallback(() => {
    setDecryptedEntries([]);
    setEncryptedEntries([]);
    setError(null);
  }, []);

  const fetchEntries = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const { entries } = await apiListEntries(token);
      setEncryptedEntries(entries);

      if (vaultKey) {
        const decrypted: DecryptedEntry[] = [];
        for (const entry of entries) {
          try {
            const plainBytes = fromHex(entry.ciphertext);
            const iv = fromHex(entry.nonce);
            const authTag = fromHex(entry.authTag);

            const decryptedBuf = await decryptEntry(
              { ciphertext: plainBytes, iv, authTag },
              vaultKey,
            );
            const json = new TextDecoder().decode(decryptedBuf);
            const payload = deserializePayload(json);

            decrypted.push({
              id: entry.id,
              entryType: entry.entryType,
              payload,
              version: entry.version,
              createdAt: entry.createdAt,
              updatedAt: entry.updatedAt,
            });

            // Zeroize intermediate buffers
            zeroize(decryptedBuf);
          } catch {
            decrypted.push({
              id: entry.id,
              entryType: entry.entryType,
              payload: {
                label: "",
                url: "",
                username: "",
                notes: "",
                secret: "[Decryption failed — wrong key or tampered data]",
              },
              version: entry.version,
              createdAt: entry.createdAt,
              updatedAt: entry.updatedAt,
            });
          }
        }
        setDecryptedEntries(decrypted);
      }
    } catch {
      setError("Failed to load vault entries");
    } finally {
      setLoading(false);
    }
  }, [token, vaultKey]);

  const createEntry = useCallback(
    async (
      entryType: string,
      payload: VaultEntryPayload,
    ): Promise<boolean> => {
      if (!token || !vaultKey) return false;
      setLoading(true);
      setError(null);
      try {
        const json = serializePayload(payload);
        const plainBytes = new TextEncoder().encode(json);
        const encrypted: EncryptedEntry = await encryptEntry(
          plainBytes,
          vaultKey,
        );
        zeroize(plainBytes);

        await apiCreateEntry(token, {
          entryType,
          nonce: toHex(encrypted.iv),
          ciphertext: toHex(encrypted.ciphertext),
          authTag: toHex(encrypted.authTag),
        });

        await fetchEntries();
        return true;
      } catch {
        setError("Failed to create entry");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [token, vaultKey, fetchEntries],
  );

  const updateEntry = useCallback(
    async (
      id: string,
      entryType: string,
      payload: VaultEntryPayload,
      version: number,
    ): Promise<boolean> => {
      if (!token || !vaultKey) return false;
      setLoading(true);
      setError(null);
      try {
        const json = serializePayload(payload);
        const plainBytes = new TextEncoder().encode(json);
        const encrypted: EncryptedEntry = await encryptEntry(
          plainBytes,
          vaultKey,
        );
        zeroize(plainBytes);

        await apiUpdateEntry(token, id, {
          nonce: toHex(encrypted.iv),
          ciphertext: toHex(encrypted.ciphertext),
          authTag: toHex(encrypted.authTag),
          version,
        });

        await fetchEntries();
        return true;
      } catch {
        setError("Failed to update entry");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [token, vaultKey, fetchEntries],
  );

  const deleteEntry = useCallback(
    async (id: string): Promise<boolean> => {
      if (!token) return false;
      setLoading(true);
      setError(null);
      try {
        await apiDeleteEntry(token, id);
        await fetchEntries();
        return true;
      } catch {
        setError("Failed to delete entry");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [token, fetchEntries],
  );

  // Listen for the "vault:lock" custom event dispatched by AutoLockContext.
  // This ensures decrypted state is explicitly cleared even before React
  // unmounts the VaultProvider tree (defense-in-depth).
  useEffect(() => {
    const handler = () => clearDecryptedState();
    window.addEventListener("vault:lock", handler);
    return () => window.removeEventListener("vault:lock", handler);
  }, [clearDecryptedState]);

  useEffect(() => {
    if (token) {
      fetchEntries();
    }
  }, [token, fetchEntries]);

  return (
    <VaultContext.Provider
      value={{
        encryptedEntries,
        decryptedEntries,
        loading,
        error,
        fetchEntries,
        createEntry,
        updateEntry,
        deleteEntry,
        clearError,
        clearDecryptedState,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
}
