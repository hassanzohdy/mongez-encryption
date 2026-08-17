import CryptoJS from "crypto-js";
import { assertIterations, getEncryptionConfig } from "./configurations";
import {
  bytesToUtf8,
  getSubtle,
  randomBytes,
  utf8ToBytes,
} from "./crypto-runtime";
import {
  AUTH_TAG_LENGTH_BITS,
  buildHeader,
  encodeEnvelope,
  IV_LENGTH,
  parseEnvelope,
  SALT_LENGTH,
} from "./envelope";
import {
  DecryptionError,
  EncryptionError,
  MissingEncryptionKeyError,
} from "./errors";
import { deriveKey } from "./key-derivation";
import { isLegacyCipher, isLegacyDriver, legacyDecrypt } from "./legacy";
import { DecryptOptions, EncryptOptions, LegacyCipherDriver } from "./types";

/**
 * Return md5 hashed string
 *
 * @deprecated MD5 is collision-broken. Never use it for passwords, signatures
 * or integrity checks — it is exported for legacy interop (cache keys,
 * gravatar-style identifiers) only.
 *
 * @param {string} text
 * @returns {string}
 */
export function md5(text: string): string {
  return CryptoJS.MD5(text).toString();
}

/**
 * Return sha1 hashed string
 *
 * @deprecated SHA-1 is collision-broken. Never use it for passwords,
 * signatures or integrity checks — it is exported for legacy interop only.
 *
 * @param {string} text
 * @returns {string}
 */
export function sha1(text: string): string {
  return CryptoJS.SHA1(text).toString();
}

/**
 * Return sha256 hashed string
 *
 * @param {string} text
 * @returns {string}
 */
export function sha256(text: string): string {
  return CryptoJS.SHA256(text).toString();
}

/**
 * Return sha512 hashed string
 *
 * @param {string} text
 * @returns {string}
 */
export function sha512(text: string): string {
  return CryptoJS.SHA512(text).toString();
}

function assertKey(key: string): asserts key is string {
  if (!key) {
    throw new MissingEncryptionKeyError();
  }

  if (typeof key !== "string") {
    throw new EncryptionError(
      `The encryption key must be a string, ${typeof key} given.`
    );
  }
}

/**
 * Encrypt the given value with AES-256-GCM.
 *
 * The key is stretched with PBKDF2-HMAC-SHA256 over a fresh random salt, and
 * the payload is sealed under a fresh random 96-bit nonce; both are stored in
 * the returned envelope. Two calls with the same value and key therefore never
 * produce the same string, and any edit to the returned string makes
 * {@link decrypt} reject rather than return altered data.
 *
 * @breaking-change v2 — this is `async`. v1.x returned the ciphertext directly.
 *
 * @param {any} value any JSON-encodable value
 * @param {string} key
 * @param {EncryptOptions} options
 * @returns {Promise<string>} base64 envelope
 */
export async function encrypt(
  value: any,
  key: string = getEncryptionConfig("key"),
  options: EncryptOptions = {}
): Promise<string> {
  assertKey(key);

  if (isLegacyDriver(options)) {
    throw new EncryptionError(
      "encrypt() no longer takes a cipher driver: v2 always encrypts with AES-256-GCM. Drop the third argument; pass a legacy driver to decrypt() instead if you still need to read v1.x ciphertexts."
    );
  }

  const iterations: number =
    options?.iterations ?? getEncryptionConfig("iterations");

  assertIterations(iterations);

  // Serialised before any randomness is drawn, so a circular value throws the
  // same synchronous-shaped TypeError v1.x threw (surfaced as a rejection).
  const data = utf8ToBytes(
    JSON.stringify({
      data: value,
    })
  );

  const subtle = getSubtle();
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const header = buildHeader(iterations, salt, iv);

  const cryptoKey = await deriveKey(key, salt, iterations);

  const payload = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      // Binds version, suite, iteration count, salt and nonce to the tag —
      // none of them can be edited in transit without the tag check failing.
      additionalData: header,
      tagLength: AUTH_TAG_LENGTH_BITS,
    },
    cryptoKey,
    data
  );

  return encodeEnvelope(header, new Uint8Array(payload));
}

/**
 * Decrypt the given ciphertext and return its original value.
 *
 * @breaking-change v2 — this is `async`, and it **throws** a
 * {@link DecryptionError} on a wrong key, a tampered envelope or a malformed
 * input, where v1.x returned `null`. Failing loudly is the entire point of
 * moving to an authenticated cipher: a returned `null` cannot be distinguished
 * from a legitimately encrypted `null`. Use {@link tryDecrypt} for the old
 * null-on-failure shape.
 *
 * @param {string} cypher
 * @param {string} key
 * @param {DecryptOptions|LegacyCipherDriver} options a v1.x cipher driver is
 *        accepted here and read as `{ legacyDriver, legacyDecryption: true }`.
 * @returns {Promise<any>}
 */
export async function decrypt(
  cypher: string,
  key: string = getEncryptionConfig("key"),
  options: DecryptOptions | LegacyCipherDriver = {}
): Promise<any> {
  assertKey(key);

  const { legacyDecryption, legacyDriver } = normalizeDecryptOptions(options);

  if (typeof cypher !== "string" || cypher.length === 0) {
    throw new DecryptionError(
      "Unable to decrypt: the given ciphertext is empty or not a string."
    );
  }

  const envelope = parseEnvelope(cypher);

  if (!envelope) {
    return decryptLegacy(cypher, key, legacyDecryption, legacyDriver);
  }

  const cryptoKey = await deriveKey(key, envelope.salt, envelope.iterations);

  let plainBytes: ArrayBuffer;

  try {
    plainBytes = await getSubtle().decrypt(
      {
        name: "AES-GCM",
        iv: envelope.iv,
        additionalData: envelope.header,
        tagLength: AUTH_TAG_LENGTH_BITS,
      },
      cryptoKey,
      envelope.payload
    );
  } catch {
    // Deliberately one message for both "wrong key" and "tampered": the two
    // are indistinguishable to GCM, and keeping them indistinguishable here
    // denies an attacker an oracle.
    throw new DecryptionError(
      "Authentication failed: the ciphertext was modified, or the key is wrong."
    );
  }

  try {
    return JSON.parse(bytesToUtf8(new Uint8Array(plainBytes))).data;
  } catch {
    // Authenticated, so this is our own data — just not a payload this
    // version knows how to read.
    throw new DecryptionError(
      "Decryption succeeded but the payload is not a @mongez/encryption envelope body."
    );
  }
}

/**
 * Decrypt, returning `null` instead of throwing when the ciphertext cannot be
 * authenticated.
 *
 * This is the v1.x failure shape, for callers that genuinely do not care why a
 * value failed to decrypt. Note the ambiguity it carries: `encrypt(null)`
 * round-trips to `null` too, so `null` here means "no usable value", not
 * "failure". Prefer {@link decrypt}.
 *
 * @param {string} cypher
 * @param {string} key
 * @param {DecryptOptions|LegacyCipherDriver} options
 * @returns {Promise<any|null>}
 */
export async function tryDecrypt(
  cypher: string,
  key: string = getEncryptionConfig("key"),
  options: DecryptOptions | LegacyCipherDriver = {}
): Promise<any> {
  try {
    return await decrypt(cypher, key, options);
  } catch (error) {
    // A missing key or an unusable runtime is a programming/deployment fault,
    // not a bad ciphertext — those still throw.
    if (error instanceof DecryptionError) return null;
    throw error;
  }
}

function normalizeDecryptOptions(options: DecryptOptions | LegacyCipherDriver) {
  if (isLegacyDriver(options)) {
    return { legacyDecryption: true, legacyDriver: options };
  }

  const { legacyDecryption, legacyDriver } = (options ??
    {}) as DecryptOptions;

  return {
    legacyDecryption: legacyDecryption ?? !!legacyDriver,
    legacyDriver,
  };
}

function decryptLegacy(
  cypher: string,
  key: string,
  legacyDecryption: boolean,
  legacyDriver?: LegacyCipherDriver
): any {
  if (!isLegacyCipher(cypher)) {
    throw new DecryptionError(
      "Unrecognised ciphertext: not an AES-GCM envelope, and not a legacy (v1.x) ciphertext either."
    );
  }

  const enabled =
    legacyDecryption || getEncryptionConfig("legacyDecryption") === true;

  if (!enabled) {
    throw new DecryptionError(
      "This is a legacy (v1.x) ciphertext, which is unauthenticated and therefore rejected by default. Enable it while migrating with setEncryptionConfigurations({ legacyDecryption: true }), then re-encrypt the value."
    );
  }

  return legacyDecrypt(
    cypher,
    key,
    legacyDriver ?? getEncryptionConfig("legacyDriver")
  );
}
