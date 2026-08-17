import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  resetEncryptionConfigurations,
  setEncryptionConfigurations,
} from "../configurations";
import { decrypt, encrypt } from "../encryption";
import {
  AUTH_TAG_LENGTH,
  ENVELOPE_VERSION_1,
  HEADER_LENGTH,
  isEncryptionEnvelope,
  IV_LENGTH,
  MAX_ITERATIONS,
  MIN_ITERATIONS,
  SALT_LENGTH,
  SUITE_PBKDF2_SHA256_AES_256_GCM,
} from "../envelope";
import { DecryptionError } from "../errors";
import { clearKeyCache } from "../key-derivation";

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

function decodeBytes(cipher: string): Uint8Array {
  const binary = atob(cipher);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function encodeBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function readIterations(bytes: Uint8Array): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
    2,
    false,
  );
}

describe("envelope layout", () => {
  it("is version(1) + suite(1) + iterations(4) + salt(16) + iv(12) + ciphertext||tag(16)", async () => {
    const cipher = await encrypt("layout", KEY);
    const bytes = decodeBytes(cipher);

    expect(HEADER_LENGTH).toBe(2 + 4 + SALT_LENGTH + IV_LENGTH);
    expect(HEADER_LENGTH).toBe(34);

    expect(bytes[0]).toBe(ENVELOPE_VERSION_1);
    expect(bytes[1]).toBe(SUITE_PBKDF2_SHA256_AES_256_GCM);
    expect(readIterations(bytes)).toBe(ITERATIONS);

    // header + at least the auth tag
    expect(bytes.length).toBeGreaterThanOrEqual(
      HEADER_LENGTH + AUTH_TAG_LENGTH,
    );

    // The GCM tag is appended to the ciphertext, so the payload is exactly the
    // plaintext length plus 16 bytes.
    const plainTextLength = JSON.stringify({ data: "layout" }).length;
    expect(bytes.length).toBe(HEADER_LENGTH + plainTextLength + AUTH_TAG_LENGTH);
  });

  it("records the work factor actually used, not the current configuration", async () => {
    const cipher = await encrypt("x", KEY, { iterations: MIN_ITERATIONS + 7 });
    expect(readIterations(decodeBytes(cipher))).toBe(MIN_ITERATIONS + 7);
  });

  it("isEncryptionEnvelope recognises our own output and nothing else", async () => {
    expect(isEncryptionEnvelope(await encrypt("yes", KEY))).toBe(true);
    expect(isEncryptionEnvelope("U2FsdGVkX1+abcdefghijklmnop")).toBe(false);
    expect(isEncryptionEnvelope("not base64 at all !!")).toBe(false);
    expect(isEncryptionEnvelope("")).toBe(false);
  });
});

describe("nonce and salt hygiene", () => {
  it("never reuses a nonce or a salt across calls", async () => {
    const nonces = new Set<string>();
    const salts = new Set<string>();
    const runs = 40;

    for (let index = 0; index < runs; index++) {
      const bytes = decodeBytes(await encrypt("same plaintext", KEY));
      salts.add(encodeBytes(bytes.subarray(6, 6 + SALT_LENGTH)));
      nonces.add(encodeBytes(bytes.subarray(6 + SALT_LENGTH, HEADER_LENGTH)));
    }

    expect(nonces.size).toBe(runs);
    expect(salts.size).toBe(runs);
  }, 60_000);

  it("two encryptions of the same value under the same key differ", async () => {
    const a = await encrypt("same", KEY);
    const b = await encrypt("same", KEY);

    expect(a).not.toBe(b);
    await expect(decrypt(a, KEY)).resolves.toBe("same");
    await expect(decrypt(b, KEY)).resolves.toBe("same");
  });
});

describe("tamper detection", () => {
  it("decrypts unchanged when the envelope is decoded and re-encoded (control)", async () => {
    const cipher = await encrypt("control", KEY);
    const roundTripped = encodeBytes(decodeBytes(cipher));

    expect(roundTripped).toBe(cipher);
    await expect(decrypt(roundTripped, KEY)).resolves.toBe("control");
  });

  it("rejects a flip in EVERY byte of the envelope — header, salt, iv, ciphertext and tag", async () => {
    const cipher = await encrypt("tamper me", KEY);
    const original = decodeBytes(cipher);

    for (let index = 0; index < original.length; index++) {
      const mutated = Uint8Array.from(original);
      mutated[index] ^= 0x01;

      await expect(
        decrypt(encodeBytes(mutated), KEY),
        `byte ${index} was flipped but decrypt did not reject`,
      ).rejects.toThrowError(DecryptionError);
    }
  }, 120_000);

  it("rejects a flip in the last (auth tag) byte specifically", async () => {
    const cipher = await encrypt("tag", KEY);
    const bytes = decodeBytes(cipher);
    bytes[bytes.length - 1] ^= 0xff;

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /Authentication failed/,
    );
  });

  it("rejects an edited nonce even though the tag itself is untouched", async () => {
    const cipher = await encrypt("nonce", KEY);
    const bytes = decodeBytes(cipher);
    bytes[HEADER_LENGTH - 1] ^= 0xff;

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /Authentication failed/,
    );
  });

  it("rejects an edited work factor — the header is authenticated as AAD", async () => {
    const cipher = await encrypt("aad", KEY);
    const bytes = decodeBytes(cipher);
    // 100_000 → 100_001: a value still inside the accepted range, so it gets
    // past validation and has to be caught by the GCM tag.
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(
      2,
      ITERATIONS + 1,
      false,
    );

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /Authentication failed/,
    );
  });

  it("rejects truncation of the ciphertext", async () => {
    const cipher = await encrypt("truncate me, please", KEY);
    const bytes = decodeBytes(cipher);

    await expect(
      decrypt(encodeBytes(bytes.subarray(0, bytes.length - 4)), KEY),
    ).rejects.toThrowError(DecryptionError);
  });

  it("rejects an envelope shorter than its own header", async () => {
    const stub = new Uint8Array(10);
    stub[0] = ENVELOPE_VERSION_1;
    stub[1] = SUITE_PBKDF2_SHA256_AES_256_GCM;

    await expect(decrypt(encodeBytes(stub), KEY)).rejects.toThrowError(
      /shorter than its own header/,
    );
  });

  it("rejects splicing the body of one envelope onto the header of another", async () => {
    const [first, second] = [
      decodeBytes(await encrypt("first", KEY)),
      decodeBytes(await encrypt("second", KEY)),
    ];

    const spliced = new Uint8Array(first.length);
    spliced.set(first.subarray(0, HEADER_LENGTH), 0);
    spliced.set(second.subarray(HEADER_LENGTH, first.length), HEADER_LENGTH);

    await expect(decrypt(encodeBytes(spliced), KEY)).rejects.toThrowError(
      /Authentication failed/,
    );
  });
});

describe("hostile envelope headers", () => {
  it("rejects an unknown cipher suite instead of guessing", async () => {
    const cipher = await encrypt("suite", KEY);
    const bytes = decodeBytes(cipher);
    bytes[1] = 0x7f;

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /Unsupported cipher suite 0x7f/,
    );
  });

  it("rejects an absurd work factor BEFORE deriving a key (CPU-exhaustion guard)", async () => {
    const cipher = await encrypt("dos", KEY);
    const bytes = decodeBytes(cipher);
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(
      2,
      0xffffffff,
      false,
    );

    const startedAt = Date.now();
    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /outside the accepted range/,
    );
    // The point of the guard: it must fail fast rather than run 4 billion
    // PBKDF2 rounds first.
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(MAX_ITERATIONS).toBe(5_000_000);
  });

  it("rejects a zero work factor", async () => {
    const cipher = await encrypt("zero", KEY);
    const bytes = decodeBytes(cipher);
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(
      2,
      0,
      false,
    );

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /outside the accepted range/,
    );
  });

  it("rejects an unknown envelope version as unrecognised, not as legacy", async () => {
    const cipher = await encrypt("future", KEY);
    const bytes = decodeBytes(cipher);
    bytes[0] = 0x09;

    await expect(decrypt(encodeBytes(bytes), KEY)).rejects.toThrowError(
      /Unrecognised ciphertext/,
    );
  });
});
