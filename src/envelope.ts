import { concatBytes, toBase64, tryFromBase64 } from "./crypto-runtime";
import { DecryptionError } from "./errors";

/**
 * Envelope version 1 — the only format this package writes.
 *
 * A leading version byte makes the format self-describing: future algorithm
 * changes bump the version (or the suite) and `decrypt` can still recognise,
 * and refuse or handle, every generation of ciphertext it is handed.
 */
export const ENVELOPE_VERSION_1 = 0x01;

/**
 * Cipher suite 1 — PBKDF2-HMAC-SHA256 → AES-256-GCM with a 128-bit tag.
 */
export const SUITE_PBKDF2_SHA256_AES_256_GCM = 0x01;

/** Random per-message PBKDF2 salt, in bytes. */
export const SALT_LENGTH = 16;

/** Random per-message GCM nonce, in bytes. 96 bits is the GCM-native size. */
export const IV_LENGTH = 12;

/** GCM authentication tag, in bytes (128 bits). */
export const AUTH_TAG_LENGTH = 16;

/** GCM authentication tag, in bits — what WebCrypto's `tagLength` wants. */
export const AUTH_TAG_LENGTH_BITS = AUTH_TAG_LENGTH * 8;

/**
 * version(1) + suite(1) + iterations(4, uint32 BE) + salt(16) + iv(12).
 *
 * The whole header is fed to AES-GCM as additional authenticated data, so the
 * declared iteration count, salt and nonce are covered by the auth tag and
 * cannot be edited without the tag check failing.
 */
export const HEADER_LENGTH = 2 + 4 + SALT_LENGTH + IV_LENGTH;

/** OWASP-aligned default work factor for PBKDF2-HMAC-SHA256. */
export const DEFAULT_ITERATIONS = 210_000;

/** Floor enforced when encrypting. Below this the KDF is not worth its name. */
export const MIN_ITERATIONS = 100_000;

/**
 * Ceiling accepted when decrypting.
 *
 * The iteration count is read out of attacker-reachable ciphertext, so an
 * unbounded value would be a trivial CPU-exhaustion vector: a forged envelope
 * claiming 4 billion iterations would pin a core for minutes before the tag
 * check ever ran. Anything above this is rejected before key derivation.
 */
export const MAX_ITERATIONS = 5_000_000;

export type EncryptionEnvelope = {
  version: number;
  suite: number;
  iterations: number;
  salt: Uint8Array;
  iv: Uint8Array;
  /** The raw header bytes, reused verbatim as GCM additional authenticated data. */
  header: Uint8Array;
  /** Ciphertext with the GCM tag appended, exactly as WebCrypto returns it. */
  payload: Uint8Array;
};

/**
 * Build the 34-byte version-1 header.
 */
export function buildHeader(
  iterations: number,
  salt: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  const header = new Uint8Array(HEADER_LENGTH);

  header[0] = ENVELOPE_VERSION_1;
  header[1] = SUITE_PBKDF2_SHA256_AES_256_GCM;

  new DataView(header.buffer).setUint32(2, iterations, false);

  header.set(salt, 6);
  header.set(iv, 6 + SALT_LENGTH);

  return header;
}

/**
 * Serialise header + payload into the base64 string handed back to callers.
 */
export function encodeEnvelope(
  header: Uint8Array,
  payload: Uint8Array
): string {
  return toBase64(concatBytes(header, payload));
}

/**
 * Parse a ciphertext string as a version-1 envelope.
 *
 * Returns `null` when the input is not a version-1 envelope at all (bad
 * base64, or a different leading version byte) — that is the signal to try the
 * legacy path. Throws when the input *claims* to be a version-1 envelope but
 * is truncated, uses an unknown suite, or declares an implausible work factor;
 * those are corrupt/hostile inputs, not old data.
 */
export function parseEnvelope(cipher: string): EncryptionEnvelope | null {
  const bytes = tryFromBase64(cipher);

  if (!bytes || bytes.length === 0) return null;
  if (bytes[0] !== ENVELOPE_VERSION_1) return null;

  if (bytes.length < HEADER_LENGTH + AUTH_TAG_LENGTH) {
    throw new DecryptionError(
      "Malformed ciphertext: the envelope is shorter than its own header and authentication tag."
    );
  }

  const suite = bytes[1];

  if (suite !== SUITE_PBKDF2_SHA256_AES_256_GCM) {
    throw new DecryptionError(
      `Unsupported cipher suite 0x${suite
        .toString(16)
        .padStart(2, "0")} in a version 1 envelope; this ciphertext was produced by a newer version of @mongez/encryption.`
    );
  }

  const iterations = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  ).getUint32(2, false);

  if (iterations < 1 || iterations > MAX_ITERATIONS) {
    throw new DecryptionError(
      `Refusing to decrypt: the envelope declares ${iterations} PBKDF2 iterations, outside the accepted range of 1..${MAX_ITERATIONS}.`
    );
  }

  return {
    version: ENVELOPE_VERSION_1,
    suite,
    iterations,
    salt: bytes.subarray(6, 6 + SALT_LENGTH),
    iv: bytes.subarray(6 + SALT_LENGTH, HEADER_LENGTH),
    header: bytes.subarray(0, HEADER_LENGTH),
    payload: bytes.subarray(HEADER_LENGTH),
  };
}

/**
 * Whether the given string looks like a version-1 AES-GCM envelope.
 *
 * Useful for migration scripts that walk a store and re-encrypt whatever is
 * still in the legacy format.
 */
export function isEncryptionEnvelope(cipher: string): boolean {
  const bytes = tryFromBase64(cipher);

  return (
    !!bytes &&
    bytes.length >= HEADER_LENGTH + AUTH_TAG_LENGTH &&
    bytes[0] === ENVELOPE_VERSION_1 &&
    bytes[1] === SUITE_PBKDF2_SHA256_AES_256_GCM
  );
}
