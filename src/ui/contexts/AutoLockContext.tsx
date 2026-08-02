import React, {
  createContext,
  useContext,
  useEffect,
  useRef,
  useCallback,
  useState,
} from "react";
import { useAuth } from "./AuthContext";

/**
 * Default auto-lock timeout in milliseconds.
 * Can be overridden via the ZKM_AUTO_LOCK_MINUTES environment variable
 * at build time (Vite replaces import.meta.env.ZKM_AUTO_LOCK_MINUTES).
 */
const DEFAULT_LOCK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function getLockTimeoutMs(): number {
  const envVal = import.meta.env.ZKM_AUTO_LOCK_MINUTES;
  if (envVal != null) {
    const parsed = Number(envVal);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed * 60 * 1000;
    }
  }
  return DEFAULT_LOCK_TIMEOUT_MS;
}

type AutoLockContextValue = {
  remainingMs: number;
  lockTimeoutMs: number;
  resetTimer: () => void;
};

const AutoLockContext = createContext<AutoLockContextValue | null>(null);

export function useAutoLock(): AutoLockContextValue {
  const ctx = useContext(AutoLockContext);
  if (!ctx) throw new Error("useAutoLock must be inside AutoLockProvider");
  return ctx;
}

/**
 * Dispatches a custom "vault:lock" event so that VaultContext can
 * explicitly clear decrypted state (defense-in-depth beyond unmount).
 */
function dispatchLockEvent(): void {
  window.dispatchEvent(new CustomEvent("vault:lock"));
}

export function AutoLockProvider({ children }: { children: React.ReactNode }) {
  const { token, logout } = useAuth();
  const lockTimeoutMs = useRef(getLockTimeoutMs());
  const remainingRef = useRef(lockTimeoutMs.current);
  const [remainingMs, setRemainingMs] = useState(lockTimeoutMs.current);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const logoutRef = useRef(logout);

  logoutRef.current = logout;

  const resetTimer = useCallback(() => {
    remainingRef.current = lockTimeoutMs.current;
    setRemainingMs(remainingRef.current);
  }, []);

  useEffect(() => {
    if (!token) {
      if (timerRef.current) clearInterval(timerRef.current);
      timerRef.current = null;
      return;
    }

    resetTimer();

    timerRef.current = setInterval(() => {
      remainingRef.current -= 1000;
      setRemainingMs(remainingRef.current);

      if (remainingRef.current <= 0) {
        if (timerRef.current) clearInterval(timerRef.current);
        timerRef.current = null;
        // Dispatch before logout so VaultContext can clear state
        dispatchLockEvent();
        logoutRef.current();
      }
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      timerRef.current = null;
    };
  }, [token, resetTimer]);

  // Reset timer on user activity
  useEffect(() => {
    if (!token) return;

    const events = ["mousedown", "keydown", "scroll", "touchstart"] as const;
    const handler = () => resetTimer();

    for (const event of events) {
      document.addEventListener(event, handler, { passive: true });
    }
    return () => {
      for (const event of events) {
        document.removeEventListener(event, handler);
      }
    };
  }, [token, resetTimer]);

  return (
    <AutoLockContext.Provider value={{ remainingMs, lockTimeoutMs: lockTimeoutMs.current, resetTimer }}>
      {children}
    </AutoLockContext.Provider>
  );
}
