import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  deriveMasterKey,
  deriveAuthKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  encryptEntry,
  decryptEntry,
  deriveRecoveryWrapKey,
  zeroize,
} from "../core.js";
import {
  configureArgon2Mode,
  _resetArgon2ModeForTesting,
  getArgon2Params,
  KDF_CURRENT_VERSION,
} from "../constants.js";
import type { EncryptedEntry } from "../types.js";

beforeAll(() => {
  configureArgon2Mode("test");
});

afterAll(() => {
  _resetArgon2ModeForTesting();
});

// Helper: generate random salt
function randomSalt(): Uint8Array {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

// Helper: check if two Uint8Arrays are equal
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Helper: check if a buffer is all zeros
function isAllZeros(buf: Uint8Array): boolean {
  return buf.every((v) => v === 0);
}

// ---------------------------------------------------------------------------
// IV Uniqueness Tests
// ---------------------------------------------------------------------------

describe("encryptEntry — IV uniqueness", () => {
  it("same plaintext encrypted twice produces different ciphertexts (random IVs)", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("my secret password");

    const entry1 = await encryptEntry(plaintext, vaultKey);
    const entry2 = await encryptEntry(plaintext, vaultKey);

    // IVs must differ (probability of collision: ~2^-96 per pair)
    expect(
      arraysEqual(entry1.iv, entry2.iv),
      "IVs should be different",
    ).toBe(false);

    // Ciphertexts must differ (different IV → different GCM keystream)
    expect(
      arraysEqual(entry1.ciphertext, entry2.ciphertext),
      "ciphertexts should differ",
    ).toBe(false);

    // Both should decrypt to the same plaintext
    const dec1 = await decryptEntry(entry1, vaultKey);
    const dec2 = await decryptEntry(entry2, vaultKey);
    expect(new TextDecoder().decode(dec1)).toBe("my secret password");
    expect(new TextDecoder().decode(dec2)).toBe("my secret password");
  });

  it("many encryptions of the same plaintext all have unique IVs", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("consistent plaintext");
    const ivSet = new Set<string>();
    const count = 20;

    for (let i = 0; i < count; i++) {
      const entry = await encryptEntry(plaintext, vaultKey);
      const ivHex = Array.from(entry.iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      expect(ivSet.has(ivHex), `duplicate IV on iteration ${i}`).toBe(false);
      ivSet.add(ivHex);
    }

    expect(ivSet.size).toBe(count);
  });
});

// ---------------------------------------------------------------------------
// Tamper Detection Tests
// ---------------------------------------------------------------------------

describe("decryptEntry — tamper detection", () => {
  it("tampering with 1 byte of ciphertext causes decryption to throw", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("sensitive data");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    // Tamper: flip a bit in the first byte of ciphertext
    const tampered: EncryptedEntry = {
      ciphertext: new Uint8Array(encrypted.ciphertext),
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    };
    tampered.ciphertext[0]! ^= 0x01;

    await expect(decryptEntry(tampered, vaultKey)).rejects.toThrow(
      /decryption failed/i,
    );
  });

  it("tampering with 1 byte of auth tag causes decryption to throw", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("another secret");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    // Tamper: flip a bit in the auth tag
    const tampered: EncryptedEntry = {
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: new Uint8Array(encrypted.authTag),
    };
    tampered.authTag[tampered.authTag.length - 1]! ^= 0xff;

    await expect(decryptEntry(tampered, vaultKey)).rejects.toThrow(
      /decryption failed/i,
    );
  });

  it("tampering with IV causes decryption to produce wrong result or throw", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("iv-sensitive data");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    const tampered: EncryptedEntry = {
      ciphertext: encrypted.ciphertext,
      iv: new Uint8Array(encrypted.iv),
      authTag: encrypted.authTag,
    };
    // Flip a bit in the IV
    tampered.iv[0]! ^= 0x01;

    // With a wrong IV, GCM auth will almost certainly fail
    await expect(decryptEntry(tampered, vaultKey)).rejects.toThrow(
      /decryption failed/i,
    );
  });

  it("truncated ciphertext causes decryption to throw", async () => {
    const vaultKey = generateVaultKey();
    const plaintext = new TextEncoder().encode("data to truncate");
    const encrypted = await encryptEntry(plaintext, vaultKey);

    const truncated: EncryptedEntry = {
      ciphertext: encrypted.ciphertext.slice(
        0,
        Math.floor(encrypted.ciphertext.length / 2),
      ),
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    };

    await expect(decryptEntry(truncated, vaultKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Key Derivation Independence Tests
// ---------------------------------------------------------------------------

describe("deriveMasterKey vs deriveAuthKey — independence", () => {
  it("same password + same salt produce different outputs from the two KDFs", async () => {
    const password = "correct-horse-battery-staple";
    const salt = randomSalt();

    const masterKey = await deriveMasterKey(password, salt);
    const authKey = await deriveAuthKey(password, salt);

    // Outputs must be entirely different bytes
    expect(arraysEqual(masterKey, authKey)).toBe(false);

    // Lengths should both be 32 bytes
    expect(masterKey.length).toBe(32);
    expect(authKey.length).toBe(32);
  });

  it("different passwords produce different master keys", async () => {
    const salt = randomSalt();

    const key1 = await deriveMasterKey("password-1", salt);
    const key2 = await deriveMasterKey("password-2", salt);

    expect(arraysEqual(key1, key2)).toBe(false);
  });

  it("different salts produce different master keys for the same password", async () => {
    const password = "same-password";
    const salt1 = randomSalt();
    const salt2 = randomSalt();

    const key1 = await deriveMasterKey(password, salt1);
    const key2 = await deriveMasterKey(password, salt2);

    expect(arraysEqual(key1, key2)).toBe(false);
  });

  it("deriveAuthKey is deterministic (same input → same output)", async () => {
    const password = "deterministic-test";
    const salt = randomSalt();

    const key1 = await deriveAuthKey(password, salt);
    const key2 = await deriveAuthKey(password, salt);

    expect(arraysEqual(key1, key2)).toBe(true);
  });

  it("deriveMasterKey is deterministic (same input → same output)", async () => {
    const password = "deterministic-test";
    const salt = randomSalt();

    const key1 = await deriveMasterKey(password, salt);
    const key2 = await deriveMasterKey(password, salt);

    expect(arraysEqual(key1, key2)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Vault Key Wrap/Unwrap Tests
// ---------------------------------------------------------------------------

describe("wrapVaultKey / unwrapVaultKey", () => {
  it("round-trips correctly: wrap then unwrap returns original vault key", async () => {
    const masterKey = generateVaultKey();
    const vaultKey = generateVaultKey();

    const wrapped = await wrapVaultKey(vaultKey, masterKey);
    const unwrapped = await unwrapVaultKey(wrapped, masterKey);

    expect(arraysEqual(vaultKey, unwrapped)).toBe(true);
  });

  it("wrong master key fails to unwrap — does NOT produce garbage", async () => {
    const masterKey = generateVaultKey();
    const wrongKey = generateVaultKey();
    const vaultKey = generateVaultKey();

    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    await expect(unwrapVaultKey(wrapped, wrongKey)).rejects.toThrow(
      /unwrap failed/i,
    );
  });

  it("tampered wrapped key fails to unwrap", async () => {
    const masterKey = generateVaultKey();
    const vaultKey = generateVaultKey();

    const wrapped = await wrapVaultKey(vaultKey, masterKey);

    // Tamper with the wrapped key data
    const tampered = {
      wrappedKey: new Uint8Array(wrapped.wrappedKey),
      iv: wrapped.iv,
      authTag: wrapped.authTag,
    };
    tampered.wrappedKey[0]! ^= 0xff;

    await expect(unwrapVaultKey(tampered, masterKey)).rejects.toThrow(
      /unwrap failed/i,
    );
  });

  it("each wrap call produces unique IV and ciphertext", async () => {
    const masterKey = generateVaultKey();
    const vaultKey = generateVaultKey();

    const w1 = await wrapVaultKey(vaultKey, masterKey);
    const w2 = await wrapVaultKey(vaultKey, masterKey);

    expect(arraysEqual(w1.iv, w2.iv)).toBe(false);
    expect(arraysEqual(w1.wrappedKey, w2.wrappedKey)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Wrong Master Password → Wrong Key → Decryption Failure
// ---------------------------------------------------------------------------

describe("wrong master password scenario", () => {
  it("full flow: wrong password → wrong MK → cannot unwrap VK → cannot decrypt", async () => {
    const correctPassword = "my-correct-password";
    const wrongPassword = "my-wrong-password";
    const salt = randomSalt();

    // Correct path: derive MK, generate VK, wrap it, encrypt an entry
    const correctMK = await deriveMasterKey(correctPassword, salt);
    const vaultKey = generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, correctMK);

    const entryPlaintext = new TextEncoder().encode("top secret entry");
    const encrypted = await encryptEntry(entryPlaintext, vaultKey);

    // Zeroize intermediate keys (simulating real usage)
    zeroize(correctMK);

    // Wrong path: attacker uses wrong password
    const wrongMK = await deriveMasterKey(wrongPassword, salt);

    // Step 1: Cannot unwrap VK with wrong MK
    await expect(unwrapVaultKey(wrapped, wrongMK)).rejects.toThrow(
      /unwrap failed/i,
    );

    // Step 2: Even if they somehow got a VK, they'd need the right one.
    // But let's verify: deriving a VK from wrong password gives a
    // completely different key
    const wrongVaultKey = generateVaultKey(); // arbitrary wrong key
    await expect(decryptEntry(encrypted, wrongVaultKey)).rejects.toThrow(
      /decryption failed/i,
    );

    zeroize(wrongMK);
  });

  it("correct password successfully decrypts the full chain", async () => {
    const password = "correct-horse-battery-staple";
    const salt = randomSalt();

    const mk = await deriveMasterKey(password, salt);
    const vaultKey = generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, mk);

    const secret = new TextEncoder().encode("the real secret");
    const encrypted = await encryptEntry(secret, vaultKey);

    // Simulate login: derive MK again, unwrap VK, decrypt entry
    const mk2 = await deriveMasterKey(password, salt);
    expect(arraysEqual(mk, mk2)).toBe(true);

    const recoveredVK = await unwrapVaultKey(wrapped, mk2);
    expect(arraysEqual(recoveredVK, vaultKey)).toBe(true);

    const decrypted = await decryptEntry(encrypted, recoveredVK);
    expect(new TextDecoder().decode(decrypted)).toBe("the real secret");

    zeroize(mk);
    zeroize(mk2);
    zeroize(recoveredVK);
  });
});

// ---------------------------------------------------------------------------
// generateVaultKey — quality checks
// ---------------------------------------------------------------------------

describe("generateVaultKey", () => {
  it("returns 32 bytes", () => {
    const key = generateVaultKey();
    expect(key.length).toBe(32);
  });

  it("two calls produce different keys", () => {
    const key1 = generateVaultKey();
    const key2 = generateVaultKey();
    expect(arraysEqual(key1, key2)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Memory hygiene — zeroize
// ---------------------------------------------------------------------------

describe("zeroize", () => {
  it("fills buffer with zeros", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroize(buf);
    expect(isAllZeros(buf)).toBe(true);
  });

  it("works on empty buffer", () => {
    const buf = new Uint8Array(0);
    zeroize(buf); // should not throw
    expect(buf.length).toBe(0);
  });

  it("zeroizes key material after use", async () => {
    const password = "test-password";
    const salt = randomSalt();
    const mk = await deriveMasterKey(password, salt);
    expect(isAllZeros(mk)).toBe(false); // confirm it has data
    zeroize(mk);
    expect(isAllZeros(mk)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// End-to-end: full vault lifecycle
// ---------------------------------------------------------------------------

describe("full vault lifecycle", () => {
  it("register → encrypt entries → decrypt entries → rotate MK", async () => {
    // --- Registration ---
    const password = "user-master-password";
    const saltEnc = randomSalt();
    const saltAuth = randomSalt();

    const mk = await deriveMasterKey(password, saltEnc);
    const authKey = await deriveAuthKey(password, saltAuth);
    const vaultKey = generateVaultKey();
    const wrappedVK = await wrapVaultKey(vaultKey, mk);

    // Auth key is stored on server for verification
    // Vault key (wrapped) is stored on server
    // Master key and vault key exist ONLY in client memory

    // --- Encrypt several vault entries ---
    const entries = [
      { label: "gmail", data: "user@gmail.com:SuperSecret1!" },
      { label: "github", data: "alice:ghp_xxxxxxxxxxxx" },
      { label: "bank", data: "1234-5678-9012-3456" },
    ];

    const encryptedEntries = [];
    for (const e of entries) {
      const pt = new TextEncoder().encode(e.data);
      const enc = await encryptEntry(pt, vaultKey);
      encryptedEntries.push({ label: e.label, ...enc });
      zeroize(pt);
    }

    zeroize(mk);

    // --- Simulate new session: re-derive keys, decrypt all entries ---
    const mk2 = await deriveMasterKey(password, saltEnc);
    const vk2 = await unwrapVaultKey(wrappedVK, mk2);
    expect(arraysEqual(vk2, vaultKey)).toBe(true);

    for (let i = 0; i < entries.length; i++) {
      const { ciphertext, iv, authTag } = encryptedEntries[i]!;
      const dec = await decryptEntry({ ciphertext, iv, authTag }, vk2);
      expect(new TextDecoder().decode(dec)).toBe(entries[i]!.data);
    }

    // --- Master password rotation: only re-wrap VK, entries untouched ---
    const newPassword = "new-master-password";
    const newSaltEnc = randomSalt();
    const newMK = await deriveMasterKey(newPassword, newSaltEnc);
    const newWrappedVK = await wrapVaultKey(vaultKey, newMK); // same VK, new MK

    // Verify old MK can no longer unwrap
    await expect(unwrapVaultKey(newWrappedVK, mk2)).rejects.toThrow();

    // Verify new MK can unwrap
    const vk3 = await unwrapVaultKey(newWrappedVK, newMK);
    expect(arraysEqual(vk3, vaultKey)).toBe(true);

    // Verify existing entries still decrypt with original VK
    for (let i = 0; i < entries.length; i++) {
      const { ciphertext, iv, authTag } = encryptedEntries[i]!;
      const dec = await decryptEntry({ ciphertext, iv, authTag }, vk3);
      expect(new TextDecoder().decode(dec)).toBe(entries[i]!.data);
    }

    zeroize(mk2);
    zeroize(vk2);
    zeroize(newMK);
    zeroize(vk3);
  });
});

// ---------------------------------------------------------------------------
// Recovery Wrap Key Tests
// ---------------------------------------------------------------------------

describe("deriveRecoveryWrapKey", () => {
  it("derives a 32-byte key from a 16-byte recovery code", async () => {
    const recoveryCode = randomSalt(); // 32 bytes — let's use 16
    const code16 = recoveryCode.slice(0, 16);
    const key = await deriveRecoveryWrapKey(code16);
    expect(key.length).toBe(32);
    expect(isAllZeros(key)).toBe(false);
  });

  it("same recovery code produces the same key (deterministic)", async () => {
    const code = randomSalt().slice(0, 16);
    const key1 = await deriveRecoveryWrapKey(code);
    const key2 = await deriveRecoveryWrapKey(code);
    expect(arraysEqual(key1, key2)).toBe(true);
  });

  it("different recovery codes produce different keys", async () => {
    const code1 = randomSalt().slice(0, 16);
    const code2 = randomSalt().slice(0, 16);
    const key1 = await deriveRecoveryWrapKey(code1);
    const key2 = await deriveRecoveryWrapKey(code2);
    expect(arraysEqual(key1, key2)).toBe(false);
  });

  it("recovery wrap key is independent of master key for same password", async () => {
    const password = "test-password";
    const salt = randomSalt();
    const code = randomSalt().slice(0, 16);

    const mk = await deriveMasterKey(password, salt);
    const rk = await deriveRecoveryWrapKey(code);

    expect(arraysEqual(mk, rk)).toBe(false);
  });

  it("recovery code wraps and unwraps vault key correctly", async () => {
    const code = randomSalt().slice(0, 16);
    const vaultKey = generateVaultKey();
    const wrapKey = await deriveRecoveryWrapKey(code);

    const wrapped = await wrapVaultKey(vaultKey, wrapKey);
    const unwrapped = await unwrapVaultKey(wrapped, wrapKey);

    expect(arraysEqual(vaultKey, unwrapped)).toBe(true);
  });

  it("wrong recovery code fails to unwrap vault key", async () => {
    const code = randomSalt().slice(0, 16);
    const wrongCode = randomSalt().slice(0, 16);
    const vaultKey = generateVaultKey();

    const wrapKey = await deriveRecoveryWrapKey(code);
    const wrapped = await wrapVaultKey(vaultKey, wrapKey);

    const wrongWrapKey = await deriveRecoveryWrapKey(wrongCode);
    await expect(unwrapVaultKey(wrapped, wrongWrapKey)).rejects.toThrow(
      /unwrap failed/i,
    );
  });
});

// ---------------------------------------------------------------------------
// configureArgon2Mode tests
// ---------------------------------------------------------------------------

describe("configureArgon2Mode", () => {
  it("throws if getArgon2Params is called before configureArgon2Mode", async () => {
    // Reset mode so we can test the unconfigured state
    _resetArgon2ModeForTesting();
    expect(() => getArgon2Params("master")).toThrow(/not configured/i);
    // Re-configure for remaining tests in this file
    configureArgon2Mode("test");
  });

  it("throws if configureArgon2Mode is called twice", () => {
    // Mode is already "test" from the beforeAll above
    expect(() => configureArgon2Mode("production")).toThrow(/already configured/i);
  });

  it("returns current-version test params when configured as test", () => {
    // Already configured as "test" — the default version is the CURRENT one.
    const params = getArgon2Params("master");
    expect(params.memory).toBe(96 * 1024);
    expect(params.iterations).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// KDF Parameter Versioning Tests
// ---------------------------------------------------------------------------

describe("KDF parameter versioning", () => {
  it("different versions produce different keys for the same password + salt", async () => {
    const password = "version-test-password-1!";
    const salt = randomSalt();

    const mk1 = await deriveMasterKey(password, salt, 1);
    const mk2 = await deriveMasterKey(password, salt, 2);
    expect(arraysEqual(mk1, mk2)).toBe(false);

    const ak1 = await deriveAuthKey(password, salt, 1);
    const ak2 = await deriveAuthKey(password, salt, 2);
    expect(arraysEqual(ak1, ak2)).toBe(false);
  });

  it("the same version is deterministic (stable re-derivation)", async () => {
    const password = "deterministic-version-test";
    const salt = randomSalt();

    const mk1 = await deriveMasterKey(password, salt, 1);
    const mk2 = await deriveMasterKey(password, salt, 1);
    expect(arraysEqual(mk1, mk2)).toBe(true);

    const ak1 = await deriveAuthKey(password, salt, 2);
    const ak2 = await deriveAuthKey(password, salt, 2);
    expect(arraysEqual(ak1, ak2)).toBe(true);
  });

  it("v2 parameters are stronger than v1 (higher memory cost)", () => {
    const v1 = getArgon2Params("master", 1);
    const v2 = getArgon2Params("master", 2);
    expect(v2.memory).toBeGreaterThan(v1.memory);
    expect(v2.memory).toBe(96 * 1024);
  });

  it("unknown versions fall back to the current version", () => {
    const unknown = getArgon2Params("auth", 999);
    const current = getArgon2Params("auth", KDF_CURRENT_VERSION);
    expect(unknown.memory).toBe(current.memory);
  });

  it("the current version has defined parameters for both purposes", () => {
    const master = getArgon2Params("master", KDF_CURRENT_VERSION);
    const auth = getArgon2Params("auth", KDF_CURRENT_VERSION);
    expect(master.memory).toBeGreaterThan(0);
    expect(auth.memory).toBeGreaterThan(0);
  });
});
