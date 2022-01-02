import CryptoJS from "crypto-js";
import { getEncryptionConfig } from "./configurations";

/**
 * Return sha1 hashed string
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

/**
 * Get the encrypted text of the given value
 *
 * @param {any} value
 * @param {string} key
 * @param {any} driver
 * @returns {string}
 */
export function encrypt(
  value: any,
  key: string = getEncryptionConfig("key"),
  driver: any = getEncryptionConfig("driver")
): string {
  if (!key) {
    throw new Error(
      "Missing Encryption key, please define it or set it in encryption configurations"
    );
  }

  const data = JSON.stringify({
    data: value,
  });

  return driver.encrypt(data, key).toString();
}

/**
 * Decrypt the given cypher text and return its original value, otherwise null will be returned.
 *
 * @param {string} cypher
 * @param {string} key
 * @param {any} driver
 * @returns {string|null}
 */
export function decrypt(
  cypher: string,
  key: string = getEncryptionConfig("key"),
  driver: any = getEncryptionConfig("driver")
): string | null {
  if (!key) {
    throw new Error(
      "Missing Encryption key, please define it or set it in encryption configurations"
    );
  }

  try {
    let value = driver.decrypt(cypher, key).toString(CryptoJS.enc.Utf8);

    if (!value) return null;

    return JSON.parse(value).data;
  } catch (error) {
    console.warn(error);
    return null;
  }
}
