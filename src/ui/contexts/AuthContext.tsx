import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
} from "react";
import {
  register as apiRegister,
  login as apiLogin,
  changePassword as apiChangePassword,
  verify2FA as apiVerify2FA,
  verify2FAWithBackupCode as apiVerify2FAWithBackupCode,
  setup2FA as apiSetup2FA,
  enable2FA as apiEnable2FA,
  disable2FA as apiDisable2FA,
  get2FAStatus as apiGet2FAStatus,
} from "../../client/auth";
import { zeroize } from "../../crypto";
import type { LoginResult, TwoFactorRequiredResult } from "../../client/auth";
import type { EncryptedVaultKey } from "../../crypto/types";

type AuthContextValue = {
  token: string | null;
  vaultKey: Uint8Array | null;
  email: string | null;
  loading: boolean;
  error: string | null;

  /** True when waiting for 2FA code entry. */
  twoFactorPending: boolean;

  register: (email: string, password: string) => Promise<{ ok: boolean; recoveryCode?: string; error?: string }>;
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  clearError: () => void;
  changePassword: (
    token: string,
    email: string,
    vaultKey: Uint8Array,
    currentPassword: string,
    newPassword: string,
  ) => Promise<boolean>;

  /** Complete 2FA login with a TOTP code. */
  verify2FA: (code: string) => Promise<boolean>;
  /** Complete 2FA login with a backup code. */
  verify2FAWithBackupCode: (code: string) => Promise<boolean>;
  /** Cancel 2FA attempt and return to login. */
  cancel2FA: () => void;

  /** Set up 2FA (returns URI + backup codes). */
  setup2FA: () => Promise<{ ok: boolean; totpUri?: string; backupCodes?: string[]; error?: string }>;
  /** Enable 2FA with a TOTP code. */
  enable2FA: (code: string) => Promise<boolean>;
  /** Disable 2FA with a TOTP code. */
  disable2FA: (code: string) => Promise<boolean>;
  /** Get 2FA status. */
  get2FAStatus: () => Promise<{ totpEnabled: boolean; backupCodesRemaining: number } | null>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside AuthProvider");
  return ctx;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 2FA state
  const [twoFactorPending, setTwoFactorPending] = useState(false);
  const tempTokenRef = useRef<string | null>(null);
  const wrappedVKRef = useRef<EncryptedVaultKey | null>(null);
  const masterKeyRef = useRef<Uint8Array | null>(null);
  const pendingEmailRef = useRef<string | null>(null);

  const vaultKeyRef = useRef<Uint8Array | null>(null);

  useEffect(() => {
    vaultKeyRef.current = vaultKey;
  }, [vaultKey]);

  const doRegister = useCallback(
    async (
      emailInput: string,
      passwordInput: string,
    ): Promise<{ ok: boolean; recoveryCode?: string; error?: string }> => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiRegister(emailInput, passwordInput);
        if (result.ok) {
          return { ok: true, recoveryCode: result.recoveryCode };
        }
        setError(result.message);
        return { ok: false, error: result.message };
      } catch {
        setError("An unexpected error occurred");
        return { ok: false, error: "An unexpected error occurred" };
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const doLogin = useCallback(
    async (emailInput: string, passwordInput: string): Promise<boolean> => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiLogin(emailInput, passwordInput);

        if (result.ok) {
          const loginResult = result as LoginResult;
          setToken(loginResult.token);
          setVaultKey(loginResult.vaultKey);
          setEmail(emailInput);
          pendingEmailRef.current = null;
          return true;
        }

        // Check if 2FA is required
        if (result.step === "2fa_required") {
          const mfResult = result as TwoFactorRequiredResult;
          tempTokenRef.current = mfResult.tempToken;
          wrappedVKRef.current = mfResult.wrappedVK;
          masterKeyRef.current = mfResult.masterKey;
          pendingEmailRef.current = emailInput;
          setTwoFactorPending(true);
          setLoading(false);
          return false; // Not logged in yet — waiting for 2FA
        }

        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const doVerify2FA = useCallback(
    async (code: string): Promise<boolean> => {
      const tempToken = tempTokenRef.current;
      const wrappedVK = wrappedVKRef.current;
      const masterKey = masterKeyRef.current;
      const userEmail = pendingEmailRef.current ?? email;

      if (!tempToken || !wrappedVK || !masterKey) {
        setError("Two-factor session expired — please log in again");
        setTwoFactorPending(false);
        return false;
      }

      setLoading(true);
      setError(null);
      try {
        const result = await apiVerify2FA(tempToken, code, wrappedVK, masterKey);
        if (result.ok) {
          setToken(result.token);
          setVaultKey(result.vaultKey);
          setEmail(userEmail);
          setTwoFactorPending(false);
          tempTokenRef.current = null;
          wrappedVKRef.current = null;
          masterKeyRef.current = null;
          pendingEmailRef.current = null;
          return true;
        }
        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [email],
  );

  const doVerify2FAWithBackupCode = useCallback(
    async (code: string): Promise<boolean> => {
      const tempToken = tempTokenRef.current;
      const wrappedVK = wrappedVKRef.current;
      const masterKey = masterKeyRef.current;
      const userEmail = pendingEmailRef.current ?? email;

      if (!tempToken || !wrappedVK || !masterKey) {
        setError("Two-factor session expired — please log in again");
        setTwoFactorPending(false);
        return false;
      }

      setLoading(true);
      setError(null);
      try {
        const result = await apiVerify2FAWithBackupCode(tempToken, code, wrappedVK, masterKey);
        if (result.ok) {
          setToken(result.token);
          setVaultKey(result.vaultKey);
          setEmail(userEmail);
          setTwoFactorPending(false);
          tempTokenRef.current = null;
          wrappedVKRef.current = null;
          masterKeyRef.current = null;
          pendingEmailRef.current = null;
          return true;
        }
        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [email],
  );

  const doCancel2FA = useCallback(() => {
    // Zeroize sensitive material
    if (masterKeyRef.current) {
      zeroize(masterKeyRef.current);
      masterKeyRef.current = null;
    }
    tempTokenRef.current = null;
    wrappedVKRef.current = null;
    pendingEmailRef.current = null;
    setTwoFactorPending(false);
    setError(null);
  }, []);

  const doLogout = useCallback(() => {
    const vk = vaultKeyRef.current;
    if (vk) {
      zeroize(vk);
      vaultKeyRef.current = null;
    }
    // Clean up 2FA state
    if (masterKeyRef.current) {
      zeroize(masterKeyRef.current);
      masterKeyRef.current = null;
    }
    tempTokenRef.current = null;
    wrappedVKRef.current = null;
    setTwoFactorPending(false);

    setToken(null);
    setVaultKey(null);
    setEmail(null);
    setError(null);
  }, []);

  const clearError = useCallback(() => setError(null), []);

  const doChangePassword = useCallback(
    async (
      tokenInput: string,
      emailInput: string,
      vaultKeyInput: Uint8Array,
      currentPasswordInput: string,
      newPasswordInput: string,
    ): Promise<boolean> => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiChangePassword(
          tokenInput,
          emailInput,
          vaultKeyInput,
          currentPasswordInput,
          newPasswordInput,
        );
        if (result.ok) {
          return true;
        }
        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const doSetup2FA = useCallback(async () => {
    if (!token) return { ok: false, error: "Not authenticated" };
    setLoading(true);
    try {
      const result = await apiSetup2FA(token);
      if (result.ok) {
        return { ok: true, totpUri: result.totpUri, backupCodes: result.backupCodes };
      }
      return { ok: false, error: result.message };
    } catch {
      return { ok: false, error: "Failed to set up 2FA" };
    } finally {
      setLoading(false);
    }
  }, [token]);

  const doEnable2FA = useCallback(
    async (code: string): Promise<boolean> => {
      if (!token) return false;
      setLoading(true);
      setError(null);
      try {
        const result = await apiEnable2FA(token, code);
        if (result.ok) return true;
        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [token],
  );

  const doDisable2FA = useCallback(
    async (code: string): Promise<boolean> => {
      if (!token) return false;
      setLoading(true);
      setError(null);
      try {
        const result = await apiDisable2FA(token, code);
        if (result.ok) return true;
        setError(result.message);
        return false;
      } catch {
        setError("An unexpected error occurred");
        return false;
      } finally {
        setLoading(false);
      }
    },
    [token],
  );

  const doGet2FAStatus = useCallback(async () => {
    if (!token) return null;
    try {
      const result = await apiGet2FAStatus(token);
      if (result.ok) {
        return {
          totpEnabled: result.totpEnabled,
          backupCodesRemaining: result.backupCodesRemaining,
        };
      }
      return null;
    } catch {
      return null;
    }
  }, [token]);

  return (
    <AuthContext.Provider
      value={{
        token,
        vaultKey,
        email,
        loading,
        error,
        twoFactorPending,
        register: doRegister,
        login: doLogin,
        logout: doLogout,
        clearError,
        changePassword: doChangePassword,
        verify2FA: doVerify2FA,
        verify2FAWithBackupCode: doVerify2FAWithBackupCode,
        cancel2FA: doCancel2FA,
        setup2FA: doSetup2FA,
        enable2FA: doEnable2FA,
        disable2FA: doDisable2FA,
        get2FAStatus: doGet2FAStatus,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
