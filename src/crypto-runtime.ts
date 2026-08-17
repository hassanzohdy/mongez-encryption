import { UnsupportedRuntimeError } from "./errors";

/**
 * Minimal structural views over the WebCrypto surface this package touches.
 *
 * They exist so the package type-checks without requiring `lib.dom` (browser)
 * or `@types/node` (server) in the consumer's tsconfig — the real `CryptoKey`
 * and `SubtleCrypto` are structurally assignable to these.
 */
export type CryptoKeyLike = {
  readonly type: string;
  readonly extractable: boolean;
};

export type SubtleCryptoLike = {
  importKey(
    format: "raw",
    keyData: Uint8Array,
    algorithm: any,
    extractable: boolean,
    usages: string[]
  ): Promise<any>;
  deriveKey(
    algorithm: any,
    baseKey: any,
    derivedKeyAlgorithm: any,
    extractable: boolean,
    usages: string[]
  ): Promise<any>;
  encrypt(algorithm: any, key: any, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(algorithm: any, key: any, data: Uint8Array): Promise<ArrayBuffer>;
};

type CryptoLike = {
  subtle?: SubtleCryptoLike;
  getRandomValues?<T extends Uint8Array>(array: T): T;
};

const RUNTIME_HINT =
  "AES-GCM requires WebCrypto (globalThis.crypto.subtle), available in browsers over HTTPS/localhost and in Node.js 18+.";

function getCrypto(): CryptoLike {
  const runtimeCrypto = (globalThis as any)?.crypto as CryptoLike | undefined;

  if (!runtimeCrypto) {
    throw new UnsupportedRuntimeError(
      `No Web Crypto API found in this runtime. ${RUNTIME_HINT}`
    );
  }

  return runtimeCrypto;
}

/**
 * Get the runtime's `crypto.subtle`, or throw a clear error.
 *
 * Browsers only expose `subtle` in a secure context, which is why the error
 * mentions HTTPS/localhost — that is by far the most common cause.
 */
export function getSubtle(): SubtleCryptoLike {
  const { subtle } = getCrypto();

  if (!subtle) {
    throw new UnsupportedRuntimeError(
      `crypto.subtle is not available in this runtime (an insecure browser context, or a runtime older than Node.js 18). ${RUNTIME_HINT}`
    );
  }

  return subtle;
}

/**
 * Fill a buffer of the given length from the platform CSPRNG.
 *
 * Never falls back to `Math.random` — if there is no CSPRNG we refuse to
 * produce a salt or a nonce at all.
 */
export function randomBytes(length: number): Uint8Array {
  const runtimeCrypto = getCrypto();

  if (typeof runtimeCrypto.getRandomValues !== "function") {
    throw new UnsupportedRuntimeError(
      `crypto.getRandomValues is not available in this runtime; refusing to generate a salt/nonce from a non-cryptographic source. ${RUNTIME_HINT}`
    );
  }

  return runtimeCrypto.getRandomValues(new Uint8Array(length));
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8ToBytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((length, chunk) => length + chunk.length, 0);
  const output = new Uint8Array(total);

  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }

  return output;
}

// `btoa` chokes on very large argument lists, so the binary string is built in
// chunks — a 10k-character payload is a realistic input for this package.
const BASE64_CHUNK_SIZE = 0x8000;

export function toBase64(bytes: Uint8Array): string {
  let binary = "";

  for (let index = 0; index < bytes.length; index += BASE64_CHUNK_SIZE) {
    binary += String.fromCharCode(
      ...bytes.subarray(index, index + BASE64_CHUNK_SIZE)
    );
  }

  return btoa(binary);
}

/**
 * Decode base64 into bytes, returning `null` instead of throwing when the
 * input is not valid base64 — callers treat "not decodable" as "not one of
 * our envelopes" rather than as a hard failure.
 */
export function tryFromBase64(value: string): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0) return null;

  // `atob` tolerates some whitespace but not arbitrary characters; reject
  // anything outside the base64 alphabet up front so the shape check is ours.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;

  let binary: string;

  try {
    binary = atob(value);
  } catch {
    return null;
  }

  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}
