/**
 * Tests for the HIBP Pwned Passwords breach check.
 *
 * Covers the k-anonymity protocol (only the 5-char SHA-1 prefix is sent),
 * local suffix comparison, and the fail-open contract: any network error,
 * non-200 response, or malformed body must NEVER be treated as "breached".
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkPasswordBreached } from "../breachCheck";

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
// The implementation emits lowercase hex, so prefix/suffix here are lowercase.
const PASSWORD_SHA1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
const HIBP_PREFIX = "5baa6";
const HIBP_SUFFIX = "1e4c9b93f3f0682250b6cf8331b7ee68fd8";
const HIBP_SUFFIX_UPPER = HIBP_SUFFIX.toUpperCase();

const mockFetch = vi.fn();

function lastFetchCall(): { url: string; init: RequestInit } {
  const call = mockFetch.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [url, init] = call;
  return { url: String(url), init: (init ?? {}) as RequestInit };
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkPasswordBreached — HIBP k-anonymity protocol", () => {
  it("sends ONLY the 5-char hash prefix to the range endpoint", async () => {
    mockFetch.mockResolvedValue(
      new Response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n", { status: 200 }),
    );

    await checkPasswordBreached("password");

    const { url, init } = lastFetchCall();
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${HIBP_PREFIX}`);
    expect(url).not.toContain(PASSWORD_SHA1);
    expect(init.body).toBeUndefined();
  });

  it("requests padded responses (Add-Padding header)", async () => {
    mockFetch.mockResolvedValue(
      new Response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n", { status: 200 }),
    );

    await checkPasswordBreached("password");

    const { init } = lastFetchCall();
    expect(init.headers).toEqual({ "Add-Padding": "true" });
  });

  it("reports breached when the local suffix matches a returned suffix", async () => {
    mockFetch.mockResolvedValue(
      new Response(`${HIBP_SUFFIX}:12345\n`, { status: 200 }),
    );

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: true, count: 12345 });
  });

  it("reports not breached when the suffix is absent from the response", async () => {
    mockFetch.mockResolvedValue(
      new Response("0123456789ABCDEF0123456789ABCDEF01234567:5\n", { status: 200 }),
    );

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: false, count: 0 });
  });

  it("matches suffixes case-insensitively", async () => {
    mockFetch.mockResolvedValue(
      new Response(`${HIBP_SUFFIX_UPPER}:42\n`, { status: 200 }),
    );

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: true, count: 42 });
  });

  it("finds the correct suffix among many lines (realistic Add-Padding body)", async () => {
    const body = [
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1",
      `${HIBP_SUFFIX}:999999`,
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2",
      `${HIBP_SUFFIX_UPPER}:123`,
    ].join("\n");
    mockFetch.mockResolvedValue(new Response(body, { status: 200 }));

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: true, count: 999999 });
  });

  it("fails open on network error (fetch rejects)", async () => {
    mockFetch.mockRejectedValue(new TypeError("Network request failed"));

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "error" });
  });

  it("fails open on non-200 response", async () => {
    mockFetch.mockResolvedValue(new Response("Server Error", { status: 503 }));

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "error" });
  });

  it("fails open on malformed body (line without a colon)", async () => {
    mockFetch.mockResolvedValue(new Response("no-colon-here\n", { status: 200 }));

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: false, count: 0 });
  });

  it("treats a non-numeric count as not breached", async () => {
    mockFetch.mockResolvedValue(
      new Response(`${HIBP_SUFFIX}:not-a-number\n`, { status: 200 }),
    );

    const result = await checkPasswordBreached("password");

    expect(result).toEqual({ status: "ok", breached: false, count: 0 });
  });

  it("never transmits the hash suffix over the wire", async () => {
    mockFetch.mockResolvedValue(
      new Response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n", { status: 200 }),
    );

    await checkPasswordBreached("password");

    const { url, init } = lastFetchCall();
    expect(url).not.toContain(HIBP_SUFFIX);
    expect(JSON.stringify(init)).not.toContain(HIBP_SUFFIX);
  });});
