import CryptoJS from "crypto-js";
import AES from "crypto-js/aes";
import { DecryptionError } from "./errors";
import { type LegacyCipherDriver } from "./types";

/**
 * Base64 prefix of every ciphertext produced by @mongez/encryption v1.x.
 *
 * v1 always called crypto-js in passphrase mode, which emits
 * `"Salted__" + 8-byte salt + AES-CBC ciphertext`; the ASCII `Salted__` header
 * base64-encodes to this fixed 10-character prefix. A version-1 AES-GCM
 * envelope starts with byte 0x01 instead, so the two formats can never be
 * confused for one another.
 */
export const LEGACY_CIPHER_PREFIX = "U2FsdGVkX1";

/**
 * Whether the given string is a v1.x (AES-CBC, MD5-KDF) ciphertext.
 *
 * Exposed so consumers can walk a store and re-encrypt legacy values, which is
 * the only way to get integrity protection over data written by v1.x.
 */
export function isLegacyCipher(cipher: string): boolean {
  return typeof cipher === "string" && cipher.startsWith(LEGACY_CIPHER_PREFIX);
}

/**
 * Whether the given value can act as a crypto-js style cipher driver.
 *
 * Used both to accept a legacy driver in `decrypt`'s third positional slot and
 * to reject one in `encrypt`'s, where v1.x callers used to pass `AES`.
 */
export function isLegacyDriver(value: any): value is LegacyCipherDriver {
  return (
    !!value &&
    typeof value === "object" &&
    typeof value.encrypt === "function" &&
    typeof value.decrypt === "function"
  );
}

/**
 * Decrypt a v1.x ciphertext. **Decrypt only** — nothing in this package writes
 * this format any more.
 *
 * The value returned here is NOT authenticated: v1.x used AES-CBC with no MAC,
 * so a v1.x ciphertext an attacker can write to may have been tampered with
 * undetectably. That is exactly why this path is opt-in.
 */
export function legacyDecrypt(
  cipher: string,
  key: string,
  driver: LegacyCipherDriver = AES
): any {
  let plainText: string;

  try {
    plainText = driver.decrypt(cipher, key).toString(CryptoJS.enc.Utf8);
  } catch {
    throw new DecryptionError(
      "Unable to decrypt the given legacy (v1.x) ciphertext: wrong key, wrong driver, or corrupt data."
    );
  }

  if (!plainText) {
    throw new DecryptionError(
      "Unable to decrypt the given legacy (v1.x) ciphertext: wrong key, wrong driver, or corrupt data."
    );
  }

  try {
    return JSON.parse(plainText).data;
  } catch {
    throw new DecryptionError(
      "Legacy (v1.x) ciphertext decrypted to something that is not a @mongez/encryption payload."
    );
  }
}
