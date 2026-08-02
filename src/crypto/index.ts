export {
  deriveMasterKey,
  deriveAuthKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  encryptEntry,
  decryptEntry,
  deriveRecoveryWrapKey,
  zeroize,
} from "./core.js";

export type { EncryptedEntry, EncryptedVaultKey, DerivedKeys } from "./types.js";

export {
  ARGON2_PARAMS_MASTER,
  ARGON2_PARAMS_AUTH,
  ARGON2_PARAMS_MASTER_PROD,
  ARGON2_PARAMS_AUTH_PROD,
  RECOVERY_CODE_LENGTH,
  KDF_CURRENT_VERSION,
  KDF_MIN_VERSION,
  KDF_MAX_VERSION,
  configureArgon2Mode,
  _resetArgon2ModeForTesting,
} from "./constants.js";
