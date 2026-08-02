export type EncryptedEntry = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
};

export type EncryptedVaultKey = {
  wrappedKey: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
};

export type DerivedKeys = {
  masterKey: Uint8Array;
  authKey: Uint8Array;
};
