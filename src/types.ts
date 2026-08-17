/**
 * A crypto-js style cipher object (`AES`, `TripleDES`, ...).
 *
 * Only ever used for reading v1.x ciphertexts — see `legacyDecrypt`.
 */
export type LegacyCipherDriver = {
  encrypt: (text: string, key: string) => any;
  decrypt: (cipher: string, key: string) => any;
};

export type EncryptionConfigurations = {
  /**
   * Set encryption default key (passphrase).
   *
   * It is stretched with PBKDF2-HMAC-SHA256 before use, but stretching does
   * not rescue a short key — use a long, high-entropy secret.
   */
  key?: string;
  /**
   * PBKDF2 work factor used when encrypting.
   *
   * Defaults to 210,000. Must be at least 100,000. The value in force at
   * encryption time is written into the envelope, so raising it later does not
   * make older ciphertexts unreadable.
   */
  iterations?: number;
  /**
   * Allow `decrypt` to fall back to the v1.x (AES-CBC, MD5-KDF) format.
   *
   * Off by default: v1.x ciphertext is unauthenticated, and silently accepting
   * it forever would let an attacker who can write to your storage swap an
   * authenticated envelope for a malleable legacy blob. Turn it on only while
   * migrating, and re-encrypt as you read.
   */
  legacyDecryption?: boolean;
  /**
   * Cipher used for the legacy decrypt path. Defaults to crypto-js `AES`,
   * which is what v1.x defaulted to.
   */
  legacyDriver?: LegacyCipherDriver;
  /**
   * @deprecated v1.x pluggable cipher. New encryptions always use AES-256-GCM;
   * setting this now only nominates the driver for the legacy decrypt path.
   */
  driver?: LegacyCipherDriver;
};

/**
 * Per-call options for {@link encrypt}.
 */
export type EncryptOptions = {
  /**
   * Override the configured PBKDF2 work factor for this call.
   */
  iterations?: number;
};

/**
 * Per-call options for {@link decrypt}.
 */
export type DecryptOptions = {
  /**
   * Allow the v1.x fallback for this call, regardless of configuration.
   */
  legacyDecryption?: boolean;
  /**
   * Cipher to use for the v1.x fallback on this call. Passing one implies
   * `legacyDecryption: true`.
   */
  legacyDriver?: LegacyCipherDriver;
};
