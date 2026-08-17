import AES from "crypto-js/aes";
import { DEFAULT_ITERATIONS, MAX_ITERATIONS, MIN_ITERATIONS } from "./envelope";
import { EncryptionError } from "./errors";
import { EncryptionConfigurations } from "./types";

const defaultConfigurations: EncryptionConfigurations = {
  key: null as any,
  iterations: DEFAULT_ITERATIONS,
  legacyDecryption: false,
  legacyDriver: AES,
};

let configurations: EncryptionConfigurations = { ...defaultConfigurations };

let deprecatedDriverWarned = false;

export function setEncryptionConfigurations(
  newConfigurations: EncryptionConfigurations
) {
  if (newConfigurations.iterations !== undefined) {
    assertIterations(newConfigurations.iterations);
  }

  // v1.x callers configured a pluggable cipher. It can no longer change how we
  // encrypt — AES-256-GCM is not negotiable — so it is re-pointed at the
  // legacy decrypt path and the caller is told once.
  if (newConfigurations.driver !== undefined) {
    if (!deprecatedDriverWarned) {
      deprecatedDriverWarned = true;
      console.warn(
        "[@mongez/encryption] `driver` is deprecated: encryption is always AES-256-GCM. The driver you passed will only be used to read legacy (v1.x) ciphertexts."
      );
    }

    newConfigurations = {
      legacyDriver: newConfigurations.driver,
      ...newConfigurations,
    };
  }

  configurations = { ...configurations, ...newConfigurations };
}

export function getEncryptionConfig(key: keyof EncryptionConfigurations): any {
  return configurations[key];
}

/**
 * Reset every configuration value back to its import-time default.
 */
export function resetEncryptionConfigurations() {
  configurations = { ...defaultConfigurations };
}

/**
 * Reject work factors that would make PBKDF2 decorative.
 */
export function assertIterations(iterations: number) {
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_ITERATIONS ||
    iterations > MAX_ITERATIONS
  ) {
    throw new EncryptionError(
      `Invalid PBKDF2 iterations: ${iterations}. Expected an integer between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}.`
    );
  }
}
