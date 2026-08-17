/**
 * Base class for every error thrown by this package.
 *
 * Consumers can catch `EncryptionError` to handle any crypto failure, or the
 * narrower subclasses below when the distinction matters.
 */
export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionError";
    // Keeps `instanceof` working when the package is transpiled down to ES5.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when no encryption key was supplied, per call or in configurations.
 */
export class MissingEncryptionKeyError extends EncryptionError {
  constructor(
    message = "Missing Encryption key, please define it or set it in encryption configurations"
  ) {
    super(message);
    this.name = "MissingEncryptionKeyError";
  }
}

/**
 * Thrown when the runtime does not expose a usable WebCrypto implementation.
 *
 * There is deliberately no fallback: silently downgrading to a non-CSPRNG or a
 * hand-rolled cipher would defeat the point of the AEAD migration.
 */
export class UnsupportedRuntimeError extends EncryptionError {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedRuntimeError";
  }
}

/**
 * Thrown when a ciphertext cannot be decrypted.
 *
 * The message intentionally does NOT distinguish "wrong key" from "tampered
 * ciphertext" for the AES-GCM path — the two are indistinguishable to the
 * cipher itself, and keeping them indistinguishable to the caller avoids
 * handing an attacker a decryption oracle.
 */
export class DecryptionError extends EncryptionError {
  constructor(message: string) {
    super(message);
    this.name = "DecryptionError";
  }
}
