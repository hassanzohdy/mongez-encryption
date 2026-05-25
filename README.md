# @mongez/encryption

> A thin wrapper around [crypto-js](https://www.npmjs.com/package/crypto-js) for symmetric encrypt/decrypt of JSON-encodable values and the common hash functions (`md5`, `sha1`, `sha256`, `sha512`).

`@mongez/encryption` is a convenience layer, not a cryptography library. It exists so the rest of the Mongez family can pass values through one consistent `encrypt(value, key)` / `decrypt(cipher, key)` pair without each caller having to remember to `JSON.stringify`, pick a UTF-8 encoder, and handle decode failures.

## Security notice — read this first

These helpers are **NOT a substitute for purpose-built cryptography**. Understand the threat model before you reach for them.

| Concern | This package |
|---|---|
| Authenticated encryption (AEAD) | No. `crypto-js`'s `AES.encrypt(text, passphrase)` runs AES-CBC with an MD5-based OpenSSL-style key derivation and a random salt. There is no authentication tag — ciphertext can be tampered with without detection. |
| Modern key derivation | No. The OpenSSL-style KDF is one round of MD5 by default. For passphrase-derived keys you want PBKDF2/scrypt/argon2 with a tunable cost. |
| Constant-time comparisons | No. Hash outputs are returned as hex strings; comparing them with `===` is not timing-safe. |
| FIPS / regulated environments | No. `crypto-js` is a pure-JS implementation; it is not validated and uses primitives (MD5, SHA-1, AES-CBC without MAC) that are inappropriate for several modern compliance regimes. |
| Salts / per-call IVs | crypto-js picks a fresh salt per call when the key is a passphrase string, so ciphertext is non-deterministic. No IV is exposed to the caller. |

**Use these helpers for** non-sensitive obfuscation that is convenient to round-trip through string form — opaquing query-string params, signing-free local storage payloads, masking values in logs, anything where the threat model is "casual reader" rather than "motivated attacker."

**Do NOT use these helpers for** passwords, session tokens, PII at rest, payment data, secrets in transit, anything subject to a compliance regime, or anywhere you need integrity guarantees. For those: reach for [`libsodium`](https://github.com/jedisjeu/libsodium.js), [Node `crypto`](https://nodejs.org/api/crypto.html) with AES-GCM, or a platform-managed KMS.

The hash functions (`md5`, `sha1`, `sha256`, `sha512`) are unkeyed digests — they are useful for content fingerprinting and ETags. `md5` and `sha1` are **broken for collision resistance** and must not be used as integrity or signature primitives.

## Install

```sh
yarn add @mongez/encryption
# peer dep: crypto-js (already installed as a dependency)
```

## A 30-second tour

```ts
import AES from "crypto-js/aes";
import { encrypt, decrypt, md5, sha256, setEncryptionConfigurations } from "@mongez/encryption";

// 1. Per-call encrypt/decrypt — pass key and driver explicitly.
const cipher = encrypt({ userId: 42 }, "my-key", AES);
const value  = decrypt(cipher, "my-key", AES);
// value === { userId: 42 }

// 2. Or set defaults once and call without arguments.
setEncryptionConfigurations({ key: "my-key", driver: AES });

encrypt("hello");                    // uses the configured key + driver
decrypt(encrypt("hello"));           // → "hello"

// 3. Hash functions are stateless — no config needed.
md5("123456");                       // "e10adc3949ba59abbe56e057f20f883e"
sha256("123456");                    // "8d969eef…"
```

## What's in the box

| Export | Purpose |
|---|---|
| `encrypt(value, key?, driver?)` | JSON-stringify `value`, encrypt with `driver`, return a base64 cipher. |
| `decrypt(cipher, key?, driver?)` | Decrypt with `driver`, JSON-parse, return the original value. Returns `null` on failure. |
| `md5(text)` | Hex-encoded MD5 digest. **Not collision-resistant.** |
| `sha1(text)` | Hex-encoded SHA-1 digest. **Not collision-resistant.** |
| `sha256(text)` | Hex-encoded SHA-256 digest. |
| `sha512(text)` | Hex-encoded SHA-512 digest. |
| `setEncryptionConfigurations(opts)` | Set the module-level default `key` and `driver`. |
| `getEncryptionConfig(key)` | Read one configuration value. |
| `type EncryptionConfigurations` | `{ key?: string; driver?: any }`. |

Every export ships from the package root — no subpath entry points.

## How encrypt / decrypt work

`encrypt(value, key, driver)`:

1. Wraps the input as `{ data: value }` so primitives (`0`, `false`, `null`) survive JSON encoding.
2. `JSON.stringify`s the wrapper.
3. Hands the result to `driver.encrypt(plaintext, key)` — typically `AES` from `crypto-js`.
4. Returns the ciphertext as a base64 string (via `toString()` on crypto-js's `CipherParams`).

`decrypt(cipher, key, driver)`:

1. Calls `driver.decrypt(cipher, key)` and decodes to UTF-8.
2. Returns `null` if the decoded plaintext is empty (wrong key → crypto-js silently yields `""`).
3. `JSON.parse`s the plaintext and returns the `.data` property.
4. Any thrown error (invalid base64, malformed JSON) is caught, logged via `console.warn`, and the function returns `null`.

A few consequences:

- **Wrong key** → `null` (not an exception). If you need to detect tampering or wrong-key situations explicitly, this wrapper cannot do it — you would need authenticated encryption.
- **`undefined` round-trips to `undefined`**: `JSON.stringify({ data: undefined })` is `"{}"`, which parses back to `{}`, and `.data` on that is `undefined`.
- **Circular references throw** at `JSON.stringify` time, before any encryption happens.
- **The cipher is non-deterministic** for AES with a passphrase key — each call to `encrypt` uses a fresh salt.

## Encryption configurations

To avoid threading the key and driver through every call site:

```ts
import AES from "crypto-js/aes";
import { encrypt, decrypt, setEncryptionConfigurations } from "@mongez/encryption";

setEncryptionConfigurations({
  key: process.env.ENCRYPTION_KEY!,
  driver: AES,
});

encrypt({ userId: 42 });             // uses the configured pair
decrypt(cipher);                     // same
```

Notes:

- `setEncryptionConfigurations` shallow-merges over the existing defaults. Calling it twice with only `{ key }` keeps the previously set `driver`.
- The default `driver` (set at import time) is `AES` — so if you only need AES, you only need to set the key.
- These are module-level globals. In a multi-tenant server (different keys per request) pass the key explicitly per call instead.

## Hash functions

All four return a lowercase hex string.

```ts
import { md5, sha1, sha256, sha512 } from "@mongez/encryption";

md5("123456");      // "e10adc3949ba59abbe56e057f20f883e"
sha1("123456");     // "7c4a8d09ca3762af61e59520943dc26494f8941b"
sha256("123456");   // "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
sha512("123456");   // "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548…"
```

Use cases that fit:

- ETags / cache keys / content addressing → any of the four.
- Idempotency keys → `sha256` or `sha512`.

Use cases that do NOT fit:

- Password hashing → use `bcrypt` / `argon2` / `scrypt`. Plain hashes are too fast and lack salting.
- Message authentication → use HMAC-SHA256 (crypto-js provides it directly: `CryptoJS.HmacSHA256`) or AEAD.
- Equality checks on secret material → use a constant-time comparison.

## Examples

### Opaquing a query-string parameter

```ts
import AES from "crypto-js/aes";
import { encrypt, decrypt } from "@mongez/encryption";

const token = encrypt({ orderId: 4242, exp: Date.now() + 3600_000 }, KEY, AES);
const url = `/orders?t=${encodeURIComponent(token)}`;

// Later, server side:
const claims = decrypt(decodeURIComponent(t), KEY, AES);
if (!claims) throw new Error("invalid token");
```

**Treat the result like an opaque-but-unauthenticated cookie**: an attacker who modifies the ciphertext gets garbage back (which decrypts as `null`), but cannot be detected lying about the structure when they bring a stolen-then-tampered token. Use a signed JWT or HMAC if you need integrity.

### Choosing a different driver

```ts
import TripleDES from "crypto-js/tripledes";
import { encrypt, decrypt, setEncryptionConfigurations } from "@mongez/encryption";

setEncryptionConfigurations({ key: "k", driver: TripleDES });
const c = encrypt("hello");
const v = decrypt(c);   // "hello"
```

Any `crypto-js` cipher module with `.encrypt(text, key)` / `.decrypt(cipher, key)` works as a driver: `AES`, `TripleDES`, `Rabbit`, `RC4` (don't), `RC4Drop`. Prefer `AES`.

### Content-addressed cache keys

```ts
import { sha256 } from "@mongez/encryption";

const key = `tile:${sha256(JSON.stringify(query))}`;
```

## What this package does NOT do

- Authenticated encryption (AEAD), MAC, or signatures → use `crypto.createCipheriv("aes-256-gcm", …)`, libsodium, or a JWT/JWS library.
- Password hashing → use `bcrypt`, `scrypt`, or `argon2`.
- Key derivation from passphrases → use `crypto.scryptSync`, PBKDF2 with a high iteration count, or argon2.
- Random IDs / UUIDs → use `crypto.randomUUID` or `nanoid`.
- Public-key crypto → use Node `crypto.generateKeyPair` or libsodium.

## Related packages

| Package | Purpose |
|---|---|
| [`@mongez/atom`](https://github.com/hassanzohdy/atom) | State primitive with action verbs. |
| [`@mongez/events`](https://github.com/hassanzohdy/events) | Tiny event bus. |
| [`@mongez/reinforcements`](https://github.com/hassanzohdy/reinforcements) | TypeScript utility belt. |
| [`@mongez/cache`](https://github.com/hassanzohdy/cache) | Pluggable cache adapters. |

## License

MIT
