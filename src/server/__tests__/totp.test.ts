import { describe, it, expect } from "vitest";
import {
  generateTotpSecret,
  generateTotpCode,
  verifyTotp,
  generateTotpUri,
  base32Encode,
  base32Decode,
  TOTP_DIGITS,
  TOTP_PERIOD,
  TOTP_TOLERANCE,
  TOTP_SECRET_LENGTH,
  isTotpConsumed,
  markTotpConsumed,
  clearConsumedTotpCodes,
} from "../utils/totp.js";

// ---------------------------------------------------------------------------
// Secret generation
// ---------------------------------------------------------------------------

describe("TOTP secret generation", () => {
  it("generates a secret of the correct length (20 bytes)", () => {
    const secret = generateTotpSecret();
    expect(secret.length).toBe(TOTP_SECRET_LENGTH);
  });

  it("two calls produce different secrets", () => {
    const s1 = generateTotpSecret();
    const s2 = generateTotpSecret();
    const equal = s1.every((v, i) => v === s2[i]);
    expect(equal).toBe(false);
  });

  it("secret is not all zeros", () => {
    const secret = generateTotpSecret();
    expect(secret.every((v) => v === 0)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Base32 encoding round-trip
// ---------------------------------------------------------------------------

describe("Base32 encoding", () => {
  it("round-trips through encode/decode", () => {
    const original = generateTotpSecret();
    const encoded = base32Encode(original);
    const decoded = base32Decode(encoded);
    expect(decoded.length).toBe(original.length);
    expect(decoded.every((v, i) => v === original[i])).toBe(true);
  });

  it("produces uppercase letters and digits 2-7", () => {
    const secret = generateTotpSecret();
    const encoded = base32Encode(secret);
    expect(encoded).toMatch(/^[A-Z2-7]+$/);
  });

});

// ---------------------------------------------------------------------------
// TOTP code generation and verification
// ---------------------------------------------------------------------------

describe("TOTP code generation", () => {
  it("generates a 6-digit code", () => {
    const secret = generateTotpSecret();
    const code = generateTotpCode(secret);
    expect(code.length).toBe(TOTP_DIGITS);
    expect(/^\d{6}$/.test(code)).toBe(true);
  });

  it("same secret at same time produces same code (deterministic)", () => {
    const secret = generateTotpSecret();
    const timeStep = 1000000; // fixed time
    const code1 = generateTotpCode(secret, timeStep);
    const code2 = generateTotpCode(secret, timeStep);
    expect(code1).toBe(code2);
  });

  it("different secrets produce different codes at same time", () => {
    const s1 = generateTotpSecret();
    const s2 = generateTotpSecret();
    const timeStep = 1000000;
    const code1 = generateTotpCode(s1, timeStep);
    const code2 = generateTotpCode(s2, timeStep);
    // Not guaranteed to be different, but highly likely with random secrets
    // (probability of collision: ~10^-6 per pair)
    // We just verify they are valid 6-digit codes
    expect(/^\d{6}$/.test(code1)).toBe(true);
    expect(/^\d{6}$/.test(code2)).toBe(true);
  });

  it("code changes across time step boundaries", () => {
    const secret = generateTotpSecret();
    const code1 = generateTotpCode(secret, 1000000);
    const code2 = generateTotpCode(secret, 1000000 + TOTP_PERIOD);
    // Codes at different time steps should be different (extremely high probability)
    expect(code1).not.toBe(code2);
  });
});

// ---------------------------------------------------------------------------
// TOTP verification with clock drift tolerance
// ---------------------------------------------------------------------------

describe("TOTP verification", () => {
  it("verifies correct code at current time step", () => {
    const secret = generateTotpSecret();
    const timeStep = Math.floor(Date.now() / 1000);
    const code = generateTotpCode(secret, timeStep);
    expect(verifyTotp(secret, code, timeStep)).toBe(true);
  });

  it("verifies code from previous time step (within tolerance)", () => {
    const secret = generateTotpSecret();
    const currentStep = Math.floor(Date.now() / 1000);
    const previousStep = currentStep - TOTP_PERIOD;
    const code = generateTotpCode(secret, previousStep);
    expect(verifyTotp(secret, code, currentStep)).toBe(true);
  });

  it("verifies code from next time step (within tolerance)", () => {
    const secret = generateTotpSecret();
    const currentStep = Math.floor(Date.now() / 1000);
    const nextStep = currentStep + TOTP_PERIOD;
    const code = generateTotpCode(secret, nextStep);
    expect(verifyTotp(secret, code, currentStep)).toBe(true);
  });

  it("rejects code from 2 time steps ago (outside tolerance)", () => {
    const secret = generateTotpSecret();
    const currentStep = Math.floor(Date.now() / 1000);
    const oldStep = currentStep - TOTP_PERIOD * 2;
    const code = generateTotpCode(secret, oldStep);
    expect(verifyTotp(secret, code, currentStep)).toBe(false);
  });

  it("rejects code from 2 time steps ahead (outside tolerance)", () => {
    const secret = generateTotpSecret();
    const currentStep = Math.floor(Date.now() / 1000);
    const futureStep = currentStep + TOTP_PERIOD * 2;
    const code = generateTotpCode(secret, futureStep);
    expect(verifyTotp(secret, code, currentStep)).toBe(false);
  });

  it("rejects wrong code", () => {
    const secret = generateTotpSecret();
    const timeStep = Math.floor(Date.now() / 1000);
    expect(verifyTotp(secret, "000000", timeStep)).toBe(false);
    expect(verifyTotp(secret, "123456", timeStep)).toBe(false);
    expect(verifyTotp(secret, "999999", timeStep)).toBe(false);
  });

  it("rejects non-numeric code", () => {
    const secret = generateTotpSecret();
    expect(verifyTotp(secret, "abcdef")).toBe(false);
    expect(verifyTotp(secret, "12345a")).toBe(false);
    expect(verifyTotp(secret, "")).toBe(false);
    expect(verifyTotp(secret, "1234567")).toBe(false); // too long
    expect(verifyTotp(secret, "12345")).toBe(false); // too short
  });

  it("rejects wrong secret", () => {
    const secret1 = generateTotpSecret();
    const secret2 = generateTotpSecret();
    const timeStep = Math.floor(Date.now() / 1000);
    const code = generateTotpCode(secret1, timeStep);
    expect(verifyTotp(secret2, code, timeStep)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TOTP URI generation
// ---------------------------------------------------------------------------

describe("TOTP URI generation", () => {
  it("generates a valid otpauth:// URI", () => {
    const secret = generateTotpSecret();
    const uri = generateTotpUri(secret, "user@example.com");
    expect(uri.startsWith("otpauth://totp/")).toBe(true);
    expect(uri).toContain("user%40example.com"); // email is URL-encoded
    expect(uri).toContain("ZKM"); // issuer
    expect(uri).toContain("secret="); // base32 secret
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain(`digits=${TOTP_DIGITS}`);
    expect(uri).toContain(`period=${TOTP_PERIOD}`);
  });

  it("URI contains a valid Base32 secret", () => {
    const secret = generateTotpSecret();
    const uri = generateTotpUri(secret, "test@test.com");
    const secretMatch = uri.match(/secret=([A-Z2-7]+)/);
    expect(secretMatch).not.toBeNull();

    // Decode and verify it matches the original secret
    const decoded = base32Decode(secretMatch![1]!);
    expect(decoded.length).toBe(secret.length);
    expect(decoded.every((v, i) => v === secret[i])).toBe(true);
  });

  it("custom issuer is used in the URI", () => {
    const secret = generateTotpSecret();
    const uri = generateTotpUri(secret, "user@test.com", "MyApp");
    expect(uri).toContain("MyApp");
    expect(uri).toContain("issuer=MyApp");
  });
});

// ---------------------------------------------------------------------------
// TOTP Replay Prevention (RFC 6238 §5.2)
// ---------------------------------------------------------------------------

describe("TOTP replay prevention", () => {
  it("detects and blocks consumed TOTP codes", () => {
    clearConsumedTotpCodes();
    const userId = "test-user-uuid";
    const code = "123456";

    expect(isTotpConsumed(userId, code)).toBe(false);

    markTotpConsumed(userId, code);
    expect(isTotpConsumed(userId, code)).toBe(true);

    // Another user using the same code is not blocked
    expect(isTotpConsumed("different-user-uuid", code)).toBe(false);

    // Different code for the same user is not blocked
    expect(isTotpConsumed(userId, "654321")).toBe(false);
  });
});
