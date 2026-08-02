export {
  register,
  login,
  changePassword,
  recoverVaultKey,
  completeRecovery,
  verify2FA,
  verify2FAWithBackupCode,
  setup2FA,
  enable2FA,
  disable2FA,
  get2FAStatus,
} from "./auth.js";
export type {
  RegistrationResult,
  LoginResult,
  AuthError,
  PasswordChangeResult,
  RecoveryResult,
  TwoFactorRequiredResult,
  TwoFactorSetupResult,
  TwoFactorStatusResult,
} from "./auth.js";

export {
  validatePasswordStrength,
  scoreLabel,
} from "./password.js";
export type { PasswordStrengthResult } from "./password.js";

export {
  apiRegister,
  apiLoginStep1,
  apiLoginStep2,
  apiChangePassword,
  apiRecoveryInitiate,
  apiRecoveryComplete,
  apiTotpSetup,
  apiTotpEnable,
  apiTotpDisable,
  apiTotpVerify,
  apiBackupCodeVerify,
  apiTotpStatus,
  apiListEntries,
  apiCreateEntry,
  apiUpdateEntry,
  apiDeleteEntry,
  toHex,
  fromHex,
} from "./api.js";
export type {
  ApiError,
  VaultEntryResponse,
  ChangePasswordRequest,
  RecoveryInitiateResponse,
  RecoveryCompleteRequest,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
} from "./api.js";
