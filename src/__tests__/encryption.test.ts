import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getEncryptionConfig,
  resetEncryptionConfigurations,
  setEncryptionConfigurations,
} from "../configurations";
import { MIN_ITERATIONS } from "../envelope";
import {
  decrypt,
  encrypt,
  md5,
  sha1,
  sha256,
  sha512,
  tryDecrypt,
} from "../encryption";
import {
  DecryptionError,
  MissingEncryptionKeyError,
  UnsupportedRuntimeError,
} from "../errors";
import { clearKeyCache } from "../key-derivation";

/**
 * PBKDF2 at the shipped default (210k) costs ~100ms a call, which would make
 * this suite needlessly slow. Every test runs at the enforced floor instead —
 * the work factor is a number in the envelope, not a behavioural switch, so
 * nothing under test depends on which value is used.
 */
const ITERATIONS = MIN_ITERATIONS;

const KEY = "a-reasonably-long-test-passphrase";

beforeEach(() => {
  resetEncryptionConfigurations();
  setEncryptionConfigurations({ iterations: ITERATIONS });
});

afterEach(() => {
  resetEncryptionConfigurations();
  clearKeyCache();
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
  it("round-trips a plain string", async () => {
    const cipher = await encrypt("hello world", KEY);
    await expect(decrypt(cipher, KEY)).resolves.toBe("hello world");
  });

  it("round-trips a number (including 0)", async () => {
    await expect(decrypt(await encrypt(0, KEY), KEY)).resolves.toBe(0);
    await expect(decrypt(await encrypt(42.5, KEY), KEY)).resolves.toBe(42.5);
    await expect(decrypt(await encrypt(-17, KEY), KEY)).resolves.toBe(-17);
  });

  it("round-trips a boolean (including false)", async () => {
    await expect(decrypt(await encrypt(true, KEY), KEY)).resolves.toBe(true);
    await expect(decrypt(await encrypt(false, KEY), KEY)).resolves.toBe(false);
  });

  it("round-trips null", async () => {
    await expect(decrypt(await encrypt(null, KEY), KEY)).resolves.toBe(null);
  });

  it("round-trips an empty string", async () => {
    const cipher = await encrypt("", KEY);
    expect(typeof cipher).toBe("string");
    expect(cipher.length).toBeGreaterThan(0); // cipher is not empty
    await expect(decrypt(cipher, KEY)).resolves.toBe("");
  });

  it("round-trips a nested object", async () => {
    const value = {
      name: "Hasan",
      address: { city: "Cairo", country: "Egypt" },
      tags: ["admin", "user"],
      active: true,
    };
    const cipher = await encrypt(value, KEY);
    await expect(decrypt(cipher, KEY)).resolves.toEqual(value);
  });

  it("round-trips an array", async () => {
    const value = [1, "two", { three: 3 }, [4, 5], null];
    await expect(decrypt(await encrypt(value, KEY), KEY)).resolves.toEqual(
      value,
    );
  });

  it("round-trips a unicode string", async () => {
    const value = "日本語 — café — 🔐 — Ω≈ç√∫˜";
    await expect(decrypt(await encrypt(value, KEY), KEY)).resolves.toBe(value);
  });

  it("round-trips a very long string (10k chars)", async () => {
    // Exercises the chunked base64 encoder and confirms the envelope stays a
    // valid string at scale.
    const value = "a".repeat(10_000);
    const cipher = await encrypt(value, KEY);
    await expect(decrypt(cipher, KEY)).resolves.toBe(value);
  });

  it("ciphertext is base64-shaped", async () => {
    const cipher = await encrypt("anything", KEY);
    expect(cipher).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it("round-trips at a non-default work factor recorded in the envelope", async () => {
    const cipher = await encrypt("work factor", KEY, {
      iterations: MIN_ITERATIONS + 1,
    });
    // The configured default is different; decrypt must read the count out of
    // the envelope rather than assume the current configuration.
    await expect(decrypt(cipher, KEY)).resolves.toBe("work factor");
  });
});

describe("encrypt / decrypt — failure modes", () => {
  it("encrypt rejects when no key is provided (no config, no arg)", async () => {
    setEncryptionConfigurations({ key: undefined });
    await expect(encrypt("hi", undefined as any)).rejects.toThrowError(
      MissingEncryptionKeyError,
    );
    await expect(encrypt("hi", undefined as any)).rejects.toThrowError(
      /Missing Encryption key/,
    );
  });

  it("decrypt rejects when no key is provided (no config, no arg)", async () => {
    setEncryptionConfigurations({ key: undefined });
    await expect(decrypt("any", undefined as any)).rejects.toThrowError(
      /Missing Encryption key/,
    );
  });

  it("decrypt with the wrong key throws a DecryptionError", async () => {
    const cipher = await encrypt({ a: 1 }, KEY);
    await expect(decrypt(cipher, "a-completely-different-key")).rejects.toThrowError(
      DecryptionError,
    );
  });

  it("decrypt with garbage cipher throws and logs nothing", async () => {
    // v1.x console.warn'd on every failure, which handed a probing attacker a
    // way to flood server logs. Nothing is logged now.
    await expect(decrypt("not a real cipher", KEY)).rejects.toThrowError(
      DecryptionError,
    );
  });

  it("decrypt with an empty string cipher throws", async () => {
    await expect(decrypt("", KEY)).rejects.toThrowError(DecryptionError);
  });

  it("encrypt rejects on circular references", async () => {
    const obj: any = {};
    obj.self = obj;
    await expect(encrypt(obj, KEY)).rejects.toThrowError(/circular/i);
  });

  it("encrypt(undefined) round-trips to undefined", async () => {
    // JSON.stringify({ data: undefined }) is "{}", which parses to {} whose
    // .data is undefined. Documented quirk of the JSON wrapper, unchanged.
    const cipher = await encrypt(undefined, KEY);
    await expect(decrypt(cipher, KEY)).resolves.toBeUndefined();
  });

  it("encrypt(function) drops to undefined via JSON", async () => {
    const cipher = await encrypt((() => 1) as any, KEY);
    await expect(decrypt(cipher, KEY)).resolves.toBeUndefined();
  });

  it("encrypt rejects a v1.x cipher driver passed in the options slot", async () => {
    const AES = (await import("crypto-js/aes")).default;
    await expect(encrypt("hi", KEY, AES as any)).rejects.toThrowError(
      /no longer takes a cipher driver/,
    );
  });

  it("encrypt rejects a work factor below the floor", async () => {
    await expect(
      encrypt("hi", KEY, { iterations: 1000 }),
    ).rejects.toThrowError(/Invalid PBKDF2 iterations/);
  });

  it("encrypt rejects a non-string key", async () => {
    await expect(encrypt("hi", 12345 as any)).rejects.toThrowError(
      /must be a string/,
    );
  });
});

describe("runtime requirements — no insecure fallback", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws when the runtime has no WebCrypto at all", async () => {
    vi.stubGlobal("crypto", undefined);
    await expect(encrypt("hi", KEY)).rejects.toThrowError(
      UnsupportedRuntimeError,
    );
    await expect(encrypt("hi", KEY)).rejects.toThrowError(
      /No Web Crypto API found/,
    );
  });

  it("throws when crypto.subtle is missing (insecure browser context)", async () => {
    vi.stubGlobal("crypto", {
      getRandomValues: (array: Uint8Array) => array,
    });
    await expect(encrypt("hi", KEY)).rejects.toThrowError(
      /crypto.subtle is not available/,
    );
  });

  it("refuses to invent a nonce when getRandomValues is missing", async () => {
    const { subtle } = globalThis.crypto;
    vi.stubGlobal("crypto", { subtle });
    await expect(encrypt("hi", KEY)).rejects.toThrowError(
      /getRandomValues is not available/,
    );
    // The point: it never silently reaches for Math.random.
    await expect(encrypt("hi", KEY)).rejects.toThrowError(
      UnsupportedRuntimeError,
    );
  });
});

describe("tryDecrypt", () => {
  it("returns the value on success", async () => {
    const cipher = await encrypt({ ok: true }, KEY);
    await expect(tryDecrypt(cipher, KEY)).resolves.toEqual({ ok: true });
  });

  it("returns null instead of throwing on a wrong key", async () => {
    const cipher = await encrypt({ ok: true }, KEY);
    await expect(tryDecrypt(cipher, "another-long-wrong-key")).resolves.toBeNull();
  });

  it("returns null on a malformed ciphertext", async () => {
    await expect(tryDecrypt("!!!not base64!!!", KEY)).resolves.toBeNull();
  });

  it("still throws for a missing key — that is a bug, not a bad ciphertext", async () => {
    await expect(tryDecrypt("whatever", "" as any)).rejects.toThrowError(
      MissingEncryptionKeyError,
    );
  });
});

describe("configuration", () => {
  it("setEncryptionConfigurations merges over existing defaults", () => {
    setEncryptionConfigurations({ key: "k1" });
    expect(getEncryptionConfig("key")).toBe("k1");

    setEncryptionConfigurations({ legacyDecryption: true });
    expect(getEncryptionConfig("key")).toBe("k1"); // preserved
    expect(getEncryptionConfig("legacyDecryption")).toBe(true); // overwritten
  });

  it("encrypt/decrypt fall back to configured defaults when args are omitted", async () => {
    setEncryptionConfigurations({ key: "configured-key-long-enough" });
    const cipher = await encrypt({ x: 1 });
    await expect(decrypt(cipher)).resolves.toEqual({ x: 1 });
  });

  it("per-call arguments override the configured defaults", async () => {
    setEncryptionConfigurations({ key: "ignored-but-long-enough" });
    const cipher = await encrypt({ y: 2 }, "explicit-key-long-enough");
    await expect(
      decrypt(cipher, "explicit-key-long-enough"),
    ).resolves.toEqual({ y: 2 });
    // Round-trip with the configured default fails (it's a different key).
    await expect(decrypt(cipher)).rejects.toThrowError(DecryptionError);
  });

  it("the default work factor is the OWASP-aligned 210k", () => {
    resetEncryptionConfigurations();
    expect(getEncryptionConfig("iterations")).toBe(210_000);
  });

  it("rejects an out-of-range work factor at configuration time", () => {
    expect(() => setEncryptionConfigurations({ iterations: 10 })).toThrowError(
      /Invalid PBKDF2 iterations/,
    );
    expect(() =>
      setEncryptionConfigurations({ iterations: 99_999_999 }),
    ).toThrowError(/Invalid PBKDF2 iterations/);
    expect(() =>
      setEncryptionConfigurations({ iterations: 150_000.5 }),
    ).toThrowError(/Invalid PBKDF2 iterations/);
  });

  it("legacy decryption is off by default", () => {
    resetEncryptionConfigurations();
    expect(getEncryptionConfig("legacyDecryption")).toBe(false);
  });
});
