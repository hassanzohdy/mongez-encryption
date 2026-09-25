---
description: "Use @mongez/encryption to seal JSON-compatible values with authenticated AES-256-GCM encryption, and to create synchronous MD5, SHA-1, SHA-256, or SHA-512 digests. Start by choosing and safely supplying a passphrase, then encrypt a value, decrypt it while handling authentication failures, and use hashes only for non-security fingerprinting. Configure the module only at application startup; use explicit keys for concurrent or multi-tenant requests. Includes legacy v1 ciphertext migration guidance."
---

# @mongez/encryption

## Encrypt and decrypt a value

For the usual case, supply a high-entropy passphrase explicitly and keep the
ciphertext wherever the protected value is stored. Both operations are async.

```ts
import { decrypt, encrypt, DecryptionError } from "@mongez/encryption";

const key = process.env.ENCRYPTION_KEY!;
const cipher = await encrypt({ userId: 42, expiresAt: "2026-10-01" }, key);

try {
  const payload = await decrypt(cipher, key);
  // payload is { userId: 42, expiresAt: "2026-10-01" }
} catch (error) {
  if (error instanceof DecryptionError) {
    // Wrong key, corrupt, or tampered ciphertext: treat as invalid input.
  } else {
    throw error; // Missing key or unsupported WebCrypto runtime.
  }
}
```

Each encryption uses a fresh salt and nonce. Do not compare ciphertext strings,
and do not put ciphertext directly in a URL without URL-encoding it. Values
must be JSON-compatible. `decrypt` throws on invalid or tampered input; use
`tryDecrypt` only when `null` is the intended invalid-input result.

For app-wide boot-time defaults, PBKDF2 iteration settings, key-cache cleanup,
or a temporary v1 migration setting, see [Configuration](configuration/SKILL.md).
For API signatures, envelope format, error behavior, and legacy compatibility,
see [Encrypt / decrypt](encrypt-decrypt/SKILL.md).

## Create a content fingerprint

```ts
import { sha256 } from "@mongez/encryption";

const cacheKey = sha256(JSON.stringify({ query: "phones", page: 1 }));
```

Hashes are synchronous lowercase-hex digests. Prefer SHA-256 or SHA-512 for
integrity-oriented fingerprints; MD5 and SHA-1 are not collision-resistant.
See [Hashes](hashes/SKILL.md) for all exports and appropriate uses.

## Common follow-ups

- Encrypting a field, an opaque URL token, rotating a key, or reading then
  re-encrypting v1 data: [Recipes](recipes/SKILL.md).
- Choosing package behavior and runtime requirements: [Overview](overview/SKILL.md).

## Not this package →

- Password storage: use Argon2id, scrypt, or bcrypt.
- Signed sessions or authorization tokens: use a signing/JWS or server-session solution.
- Large-file streaming, public-key cryptography, or managed key lifecycle: use WebCrypto
  directly, libsodium, or a KMS.
