import {
  getSubtle,
  toBase64,
  utf8ToBytes,
  type CryptoKeyLike,
} from "./crypto-runtime";

/**
 * Derived keys are cached in memory, keyed by the exact
 * (password, salt, iterations) triple that produced them.
 *
 * PBKDF2 at the default work factor costs ~100ms per call, and a browser app
 * that reads a dozen encrypted values from storage on boot would otherwise pay
 * it a dozen times. The cache never widens who can decrypt what: a hit
 * requires the same password AND the same salt, and the cached `CryptoKey` is
 * non-extractable, so it is not a more useful thing to hold than the password
 * the caller already keeps in memory.
 */
const MAX_CACHED_KEYS = 64;

const keyCache = new Map<string, Promise<CryptoKeyLike>>();

/**
 * Drop every cached derived key. Call it on logout, or between tests.
 */
export function clearKeyCache(): void {
  keyCache.clear();
}

function cacheKeyFor(
  password: string,
  salt: Uint8Array,
  iterations: number
): string {
  return `${iterations}:${toBase64(salt)}:${password}`;
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase with PBKDF2-HMAC-SHA256.
 *
 * The derived key is non-extractable: it can encrypt and decrypt through
 * WebCrypto but its bytes cannot be read back out by application code.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKeyLike> {
  const cacheKey = cacheKeyFor(password, salt, iterations);
  const cached = keyCache.get(cacheKey);

  if (cached) return cached;

  const subtle = getSubtle();

  const derivation = (async () => {
    const baseKey = await subtle.importKey(
      "raw",
      utf8ToBytes(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  })();

  // A failed derivation must not be memoised, otherwise a transient runtime
  // error would be replayed to every later caller with the same inputs.
  derivation.catch(() => keyCache.delete(cacheKey));

  if (keyCache.size >= MAX_CACHED_KEYS) {
    const oldest = keyCache.keys().next();
    if (!oldest.done) keyCache.delete(oldest.value);
  }

  keyCache.set(cacheKey, derivation);

  return derivation;
}
