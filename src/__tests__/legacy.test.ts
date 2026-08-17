import AES from "crypto-js/aes";
import TripleDES from "crypto-js/tripledes";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  resetEncryptionConfigurations,
  setEncryptionConfigurations,
} from "../configurations";
import { decrypt, encrypt, tryDecrypt } from "../encryption";
import { MIN_ITERATIONS } from "../envelope";
import { DecryptionError } from "../errors";
import { clearKeyCache } from "../key-derivation";
import { isLegacyCipher } from "../legacy";

const KEY = "a-reasonably-long-test-passphrase";

/**
 * Produce a ciphertext exactly as @mongez/encryption v1.x did: crypto-js in
 * passphrase mode over the same `{ data: value }` JSON wrapper.
 */
function v1Encrypt(value: any, key = KEY, driver: any = AES): string {
  return driver.encrypt(JSON.stringify({ data: value }), key).toString();
}

beforeEach(() => {
  resetEncryptionConfigurations();
  setEncryptionConfigurations({ iterations: MIN_ITERATIONS });
});

afterEach(() => {
  resetEncryptionConfigurations();
  clearKeyCache();
});

describe("legacy (v1.x) format detection", () => {
  it("recognises a v1.x ciphertext by its Salted__ prefix", () => {
    expect(isLegacyCipher(v1Encrypt("hello"))).toBe(true);
    expect(v1Encrypt("hello").startsWith("U2FsdGVkX1")).toBe(true);
  });

  it("does not mistake a v2 envelope for a legacy ciphertext", async () => {
    expect(isLegacyCipher(await encrypt("hello", KEY))).toBe(false);
  });
});

describe("legacy decryption is opt-in", () => {
  it("refuses a legacy ciphertext by default, with a message that says how to enable it", async () => {
    await expect(decrypt(v1Encrypt({ a: 1 }), KEY)).rejects.toThrowError(
      /legacyDecryption: true/,
    );
    await expect(decrypt(v1Encrypt({ a: 1 }), KEY)).rejects.toThrowError(
      DecryptionError,
    );
  });

  it("reads a legacy ciphertext once enabled in configuration", async () => {
    setEncryptionConfigurations({ legacyDecryption: true });
    await expect(decrypt(v1Encrypt({ a: 1 }), KEY)).resolves.toEqual({ a: 1 });
  });

  it("reads a legacy ciphertext when enabled per call", async () => {
    await expect(
      decrypt(v1Encrypt("per call"), KEY, { legacyDecryption: true }),
    ).resolves.toBe("per call");
  });

  it("accepts a v1.x driver in the third positional slot, as v1.x callers wrote it", async () => {
    await expect(
      decrypt(v1Encrypt({ hello: "world" }, KEY, TripleDES), KEY, TripleDES),
    ).resolves.toEqual({ hello: "world" });
  });

  it("uses the configured legacy driver", async () => {
    setEncryptionConfigurations({
      legacyDecryption: true,
      legacyDriver: TripleDES,
    });
    await expect(
      decrypt(v1Encrypt("tripledes", KEY, TripleDES), KEY),
    ).resolves.toBe("tripledes");
  });

  it("round-trips every value shape v1.x supported", async () => {
    setEncryptionConfigurations({ legacyDecryption: true });

    const values = [
      "string",
      0,
      false,
      null,
      { nested: { deep: [1, 2, 3] } },
      "日本語 — 🔐",
    ];

    for (const value of values) {
      await expect(decrypt(v1Encrypt(value), KEY)).resolves.toEqual(value);
    }
  });

  it("throws on a legacy ciphertext read with the wrong key", async () => {
    setEncryptionConfigurations({ legacyDecryption: true });
    await expect(
      decrypt(v1Encrypt({ a: 1 }), "a-different-long-key"),
    ).rejects.toThrowError(DecryptionError);
  });

  it("tryDecrypt returns null for a rejected legacy ciphertext", async () => {
    await expect(tryDecrypt(v1Encrypt("nope"), KEY)).resolves.toBeNull();
  });

  it("the deprecated `driver` config nominates the legacy driver and warns once", async () => {
    const warnings: any[] = [];
    const original = console.warn;
    console.warn = (...args: any[]) => warnings.push(args);

    try {
      setEncryptionConfigurations({
        driver: TripleDES as any,
        legacyDecryption: true,
      });
      setEncryptionConfigurations({ driver: AES as any });
    } finally {
      console.warn = original;
    }

    // Deprecation is announced, but only once per process.
    expect(warnings.length).toBe(1);
    expect(String(warnings[0])).toMatch(/deprecated/);
  });
});

describe("migration path", () => {
  it("a legacy value can be read once and re-encrypted under AES-GCM", async () => {
    const legacy = v1Encrypt({ token: "abc123" });
    setEncryptionConfigurations({ legacyDecryption: true, key: KEY });

    const value = await decrypt(legacy);
    const migrated = await encrypt(value);

    expect(isLegacyCipher(migrated)).toBe(false);
    await expect(decrypt(migrated)).resolves.toEqual({ token: "abc123" });

    // And once migrated, the value is tamper-evident where the legacy one
    // was not.
    setEncryptionConfigurations({ legacyDecryption: false });
    await expect(decrypt(legacy)).rejects.toThrowError(DecryptionError);
  });
});
