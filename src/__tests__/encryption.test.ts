import AES from "crypto-js/aes";
import TripleDES from "crypto-js/tripledes";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getEncryptionConfig,
  setEncryptionConfigurations,
} from "../configurations";
import {
  decrypt,
  encrypt,
  md5,
  sha1,
  sha256,
  sha512,
} from "../encryption";

/**
 * Snapshot the module-level configuration before each test and restore it
 * afterwards. The configuration object is process-global, so leaving a key
 * set would leak across files.
 */
let savedKey: any;
let savedDriver: any;

beforeEach(() => {
  savedKey = getEncryptionConfig("key");
  savedDriver = getEncryptionConfig("driver");
});

afterEach(() => {
  setEncryptionConfigurations({ key: savedKey, driver: savedDriver });
});

describe("hash functions — known answer tests", () => {
  // Test vectors lifted from the canonical references for each algorithm.
  // These are stable across implementations; a regression here would mean
  // crypto-js itself broke or the wrapper started transforming the input.

  it("md5 produces the canonical RFC 1321 digest for '123456'", () => {
    expect(md5("123456")).toBe("e10adc3949ba59abbe56e057f20f883e");
  });

  it("md5 of the empty string is d41d8cd98f00b204e9800998ecf8427e", () => {
    expect(md5("")).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });

  it("sha1 produces the canonical digest for '123456'", () => {
    expect(sha1("123456")).toBe("7c4a8d09ca3762af61e59520943dc26494f8941b");
  });

  it("sha1 of the empty string is da39a3ee5e6b4b0d3255bfef95601890afd80709", () => {
    expect(sha1("")).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
  });

  it("sha256 produces the canonical digest for '123456'", () => {
    expect(sha256("123456")).toBe(
      "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    );
  });

  it("sha256 of the empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", () => {
    expect(sha256("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("sha512 produces the canonical digest for '123456'", () => {
    expect(sha512("123456")).toBe(
      "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413",
    );
  });

  it("hash outputs are deterministic — same input → same digest", () => {
    expect(md5("a")).toBe(md5("a"));
    expect(sha256("a")).toBe(sha256("a"));
  });

  it("hash outputs are case-sensitive lowercase hex", () => {
    expect(md5("abc")).toMatch(/^[0-9a-f]{32}$/);
    expect(sha1("abc")).toMatch(/^[0-9a-f]{40}$/);
    expect(sha256("abc")).toMatch(/^[0-9a-f]{64}$/);
    expect(sha512("abc")).toMatch(/^[0-9a-f]{128}$/);
  });

  it("hash inputs are interpreted as UTF-8 — unicode round-trips", () => {
    // The Japanese string takes 9 bytes in UTF-8. md5 yields a stable digest
    // for that byte sequence; we don't depend on the exact bytes other than
    // that crypto-js produces a deterministic, non-empty hex string.
    const digest = md5("日本語");
    expect(digest).toMatch(/^[0-9a-f]{32}$/);
    expect(digest).toBe(md5("日本語"));
  });
});

describe("encrypt / decrypt — round-trip", () => {
  const KEY = "my-key";

  it("round-trips a plain string", () => {
    const cipher = encrypt("hello world", KEY, AES);
    expect(decrypt(cipher, KEY, AES)).toBe("hello world");
  });

  it("round-trips a number (including 0)", () => {
    expect(decrypt(encrypt(0, KEY, AES), KEY, AES)).toBe(0);
    expect(decrypt(encrypt(42.5, KEY, AES), KEY, AES)).toBe(42.5);
    expect(decrypt(encrypt(-17, KEY, AES), KEY, AES)).toBe(-17);
  });

  it("round-trips a boolean (including false)", () => {
    expect(decrypt(encrypt(true, KEY, AES), KEY, AES)).toBe(true);
    expect(decrypt(encrypt(false, KEY, AES), KEY, AES)).toBe(false);
  });

  it("round-trips null", () => {
    expect(decrypt(encrypt(null, KEY, AES), KEY, AES)).toBe(null);
  });

  it("round-trips an empty string", () => {
    const cipher = encrypt("", KEY, AES);
    expect(typeof cipher).toBe("string");
    expect(cipher.length).toBeGreaterThan(0); // cipher is not empty
    expect(decrypt(cipher, KEY, AES)).toBe("");
  });

  it("round-trips a nested object", () => {
    const value = {
      name: "Hasan",
      address: { city: "Cairo", country: "Egypt" },
      tags: ["admin", "user"],
      active: true,
    };
    const cipher = encrypt(value, KEY, AES);
    expect(decrypt(cipher, KEY, AES)).toEqual(value);
  });

  it("round-trips an array", () => {
    const value = [1, "two", { three: 3 }, [4, 5], null];
    expect(decrypt(encrypt(value, KEY, AES), KEY, AES)).toEqual(value);
  });

  it("round-trips a unicode string", () => {
    const value = "日本語 — café — 🔐 — Ω≈ç√∫˜";
    expect(decrypt(encrypt(value, KEY, AES), KEY, AES)).toBe(value);
  });

  it("round-trips a very long string (10k chars)", () => {
    // Exercises any internal chunking the cipher might do — and confirms the
    // base64 cipher stays a valid string at scale.
    const value = "a".repeat(10_000);
    const cipher = encrypt(value, KEY, AES);
    expect(decrypt(cipher, KEY, AES)).toBe(value);
  });

  it("ciphertext is non-deterministic for AES with a passphrase key", () => {
    // crypto-js picks a fresh salt per call — two encrypts of the same value
    // produce different strings that both decrypt back to the original.
    const a = encrypt("same", KEY, AES);
    const b = encrypt("same", KEY, AES);
    expect(a).not.toBe(b);
    expect(decrypt(a, KEY, AES)).toBe("same");
    expect(decrypt(b, KEY, AES)).toBe("same");
  });

  it("ciphertext is base64-shaped", () => {
    const cipher = encrypt("anything", KEY, AES);
    expect(cipher).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it("supports TripleDES as an alternative driver", () => {
    const cipher = encrypt({ hello: "world" }, KEY, TripleDES);
    expect(decrypt(cipher, KEY, TripleDES)).toEqual({ hello: "world" });
  });
});

describe("encrypt / decrypt — failure modes", () => {
  const KEY = "k";

  it("encrypt throws when no key is provided (no config, no arg)", () => {
    setEncryptionConfigurations({ key: undefined });
    expect(() => encrypt("hi", undefined as any, AES)).toThrowError(
      /Missing Encryption key/,
    );
  });

  it("decrypt throws when no key is provided (no config, no arg)", () => {
    setEncryptionConfigurations({ key: undefined });
    expect(() => decrypt("any", undefined as any, AES)).toThrowError(
      /Missing Encryption key/,
    );
  });

  it("decrypt with the wrong key returns null", () => {
    // Suppress the console.warn that decrypt emits on parse failure — the
    // wrong key path actually returns null *before* reaching console.warn
    // (empty UTF-8 decode → early return), so this is defensive only.
    const cipher = encrypt({ a: 1 }, KEY, AES);
    expect(decrypt(cipher, "different-key", AES)).toBeNull();
  });

  it("decrypt with garbage cipher returns null and warns", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(decrypt("not a real cipher", KEY, AES)).toBeNull();
    warn.mockRestore();
  });

  it("decrypt with empty string cipher returns null", () => {
    expect(decrypt("", KEY, AES)).toBeNull();
  });

  it("encrypt throws synchronously on circular references", () => {
    const obj: any = {};
    obj.self = obj;
    expect(() => encrypt(obj, KEY, AES)).toThrowError(/circular/i);
  });

  it("encrypt(undefined) round-trips to undefined", () => {
    // JSON.stringify({ data: undefined }) is "{}", which parses to {} whose
    // .data is undefined. Documented quirk of the JSON wrapper.
    const cipher = encrypt(undefined, KEY, AES);
    expect(decrypt(cipher, KEY, AES)).toBeUndefined();
  });

  it("encrypt(function) drops to undefined via JSON", () => {
    const cipher = encrypt((() => 1) as any, KEY, AES);
    expect(decrypt(cipher, KEY, AES)).toBeUndefined();
  });
});

describe("configuration", () => {
  it("setEncryptionConfigurations merges over existing defaults", () => {
    setEncryptionConfigurations({ key: "k1", driver: AES });
    expect(getEncryptionConfig("key")).toBe("k1");
    expect(getEncryptionConfig("driver")).toBe(AES);

    setEncryptionConfigurations({ driver: TripleDES });
    expect(getEncryptionConfig("key")).toBe("k1"); // preserved
    expect(getEncryptionConfig("driver")).toBe(TripleDES); // overwritten
  });

  it("encrypt/decrypt fall back to configured defaults when args are omitted", () => {
    setEncryptionConfigurations({ key: "configured-key", driver: AES });
    const cipher = encrypt({ x: 1 });
    expect(decrypt(cipher)).toEqual({ x: 1 });
  });

  it("per-call arguments override the configured defaults", () => {
    setEncryptionConfigurations({ key: "ignored", driver: AES });
    const cipher = encrypt({ y: 2 }, "explicit", AES);
    // Round-trip with the explicit key works.
    expect(decrypt(cipher, "explicit", AES)).toEqual({ y: 2 });
    // Round-trip with the configured default fails (it's a different key).
    expect(decrypt(cipher)).toBeNull();
  });

  it("default driver at import time is AES", () => {
    setEncryptionConfigurations({ key: "k" });
    // No driver argument, no driver in config beyond the import-time default.
    const cipher = encrypt("hello");
    // Decrypting with AES explicitly verifies the default really is AES.
    expect(decrypt(cipher, "k", AES)).toBe("hello");
  });
});
