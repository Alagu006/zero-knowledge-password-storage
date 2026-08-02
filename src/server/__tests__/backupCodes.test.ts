import { describe, it, expect } from "vitest";
import {
  generateBackupCodes,
  hashBackupCode,
  verifyBackupCode,
  BACKUP_CODE_COUNT,
  BACKUP_CODE_LENGTH,
} from "../utils/backupCodes.js";

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

describe("Backup code generation", () => {
  it("generates the correct number of codes", () => {
    const { codes, records } = generateBackupCodes();
    expect(codes.length).toBe(BACKUP_CODE_COUNT);
    expect(records.length).toBe(BACKUP_CODE_COUNT);
  });

  it("each code is formatted as XXXX-XXXX", () => {
    const { codes } = generateBackupCodes();
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    }
  });

  it("each code has the correct length (9 chars including dash)", () => {
    const { codes } = generateBackupCodes();
    for (const code of codes) {
      expect(code.length).toBe(BACKUP_CODE_LENGTH + 1); // +1 for dash
    }
  });

  it("codes are unique", () => {
    const { codes } = generateBackupCodes();
    const unique = new Set(codes);
    expect(unique.size).toBe(codes.length);
  });

  it("records have SHA-256 hashes (64 hex chars)", () => {
    const { records } = generateBackupCodes();
    for (const record of records) {
      expect(record.codeHash).toMatch(/^[0-9a-f]{64}$/);
      expect(record.used).toBe(false);
    }
  });

  it("hashed code matches manually computed hash", () => {
    const { codes, records } = generateBackupCodes();
    const code = codes[0]!.replace(/-/g, "");
    const expectedHash = hashBackupCode(code);
    expect(records[0]!.codeHash).toBe(expectedHash);
  });
});

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

describe("Backup code hashing", () => {
  it("produces a 64-char hex SHA-256 hash", () => {
    const hash = hashBackupCode("ABCD1234");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic (same code → same hash)", () => {
    const h1 = hashBackupCode("ABCD1234");
    const h2 = hashBackupCode("ABCD1234");
    expect(h1).toBe(h2);
  });

  it("different codes produce different hashes", () => {
    const h1 = hashBackupCode("ABCD1234");
    const h2 = hashBackupCode("ABCD5678");
    expect(h1).not.toBe(h2);
  });

  it("normalizes input (strips dash, uppercases)", () => {
    const h1 = hashBackupCode("ABCD-1234");
    const h2 = hashBackupCode("abcd1234");
    const h3 = hashBackupCode("ABCD1234");
    expect(h1).toBe(h2);
    expect(h2).toBe(h3);
  });
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

describe("Backup code verification", () => {
  it("verifies a correct code", () => {
    const { codes, records } = generateBackupCodes();
    const rawCode = codes[0]!.replace(/-/g, "");
    const index = verifyBackupCode(rawCode, records);
    expect(index).toBe(0);
  });

  it("verifies with formatted code (including dash)", () => {
    const { codes, records } = generateBackupCodes();
    const index = verifyBackupCode(codes[0]!, records);
    expect(index).toBe(0);
  });

  it("verifies case-insensitive", () => {
    const { codes, records } = generateBackupCodes();
    const lower = codes[0]!.toLowerCase();
    const index = verifyBackupCode(lower, records);
    expect(index).toBe(0);
  });

  it("returns -1 for wrong code", () => {
    const { records } = generateBackupCodes();
    const index = verifyBackupCode("XXXX-XXXX", records);
    expect(index).toBe(-1);
  });

  it("returns -1 for already-used code", () => {
    const { codes, records } = generateBackupCodes();
    const rawCode = codes[0]!.replace(/-/g, "");

    // Mark first code as used
    records[0]!.used = true;

    const index = verifyBackupCode(rawCode, records);
    expect(index).toBe(-1);
  });

  it("skips used codes and finds unused ones", () => {
    const { codes, records } = generateBackupCodes();

    // Mark first 5 codes as used
    for (let i = 0; i < 5; i++) {
      records[i]!.used = true;
    }

    // Verify the 6th code (index 5)
    const rawCode = codes[5]!.replace(/-/g, "");
    const index = verifyBackupCode(rawCode, records);
    expect(index).toBe(5);
  });

  it("returns -1 for invalid format", () => {
    const { records } = generateBackupCodes();
    expect(verifyBackupCode("short", records)).toBe(-1);
    expect(verifyBackupCode("1234567890", records)).toBe(-1);
    expect(verifyBackupCode("ABCD-EFGH", records)).toBe(-1); // I is invalid
    expect(verifyBackupCode("", records)).toBe(-1);
  });

  it("returns -1 when no codes match (all used)", () => {
    const { codes, records } = generateBackupCodes();
    // Mark all as used
    for (const record of records) {
      record.used = true;
    }

    const rawCode = codes[0]!.replace(/-/g, "");
    const index = verifyBackupCode(rawCode, records);
    expect(index).toBe(-1);
  });
});
