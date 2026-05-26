<div align="center">

# @mongez/encryption

**A thin convenience layer over CryptoJS — one consistent `encrypt` / `decrypt` pair for JSON-encodable values, plus hex-encoded `md5` / `sha1` / `sha256` / `sha512` digests.**

[![npm](https://img.shields.io/npm/v/@mongez/encryption.svg)](https://www.npmjs.com/package/@mongez/encryption)
[![license](https://img.shields.io/npm/l/@mongez/encryption.svg)](LICENSE)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@mongez/encryption.svg)](https://bundlephobia.com/package/@mongez/encryption)
[![downloads](https://img.shields.io/npm/dw/@mongez/encryption.svg)](https://www.npmjs.com/package/@mongez/encryption)

</div>

---

## Why @mongez/encryption?

Raw `crypto-js` gives you `AES.encrypt(text, key)` and asks you to remember the JSON wrapping, the UTF-8 decode, the `.toString()` call on its `CipherParams`, and the "what does a wrong key return" rule. Native `WebCrypto` is the right tool when you need AEAD — but it's async, requires you to derive a `CryptoKey`, manage IVs, choose modes, and encode/decode `ArrayBuffer`s into base64 by hand. `bcrypt` and `argon2` are for passwords, not for round-tripping a `{ orderId: 42 }` through a URL.

`@mongez/encryption` is the smallest layer that gives you a synchronous, JSON-aware `encrypt(value, key)` / `decrypt(cipher, key)` pair on the browser side. One source file, one runtime dep (`crypto-js`), zero ceremony.

```ts
import { encrypt, decrypt, sha256 } from "@mongez/encryption";

const cipher = encrypt({ userId: 42 }, "my-key"); // AES by default
const value = decrypt(cipher, "my-key"); // { userId: 42 }
const tag = sha256(JSON.stringify({ q: "phones" })); // stable cache key
```

> **Read this before reaching for it.** These helpers are for **browser-side symmetric obfuscation and content fingerprinting**, not for password storage, session integrity, PII at rest, or anything under a compliance regime. There is no authentication tag — ciphertext can be tampered with undetectably. For passwords use `bcrypt` / `scrypt` / `argon2` (preferably **Argon2id**); for authenticated encryption use Node `crypto` AES-GCM or libsodium; for signed tokens use JWT/JWS. See [Security boundaries](#security-boundaries) below.

---

## Features

| Feature | Description |
|---|---|
| **`encrypt` / `decrypt` pair** | JSON-stringify a value, hand it to a `crypto-js` cipher driver, get back a base64 string. Reverse the whole pipeline with `decrypt`. |
| **Configurable key + driver** | Set defaults once with `setEncryptionConfigurations` or pass per-call. Defaults to `AES`. |
| **Driver-agnostic** | Any object with `.encrypt(text, key)` / `.decrypt(cipher, key)` works — `AES`, `TripleDES`, `Rabbit`, `RC4` (don't), or your own. |
| **Hash functions** | `md5`, `sha1`, `sha256`, `sha512` return lowercase hex digests. Stateless — no config. |
| **`null` on decrypt failure** | Wrong key, malformed input, or empty string all return `null` instead of throwing. One uniform error path. |
| **JSON-aware** | Primitives (`0`, `false`, `null`), arrays, plain objects, nested combinations all round-trip. |
| **Synchronous** | No promises, no `await`. Suits storage adapters and SSR-free code paths. |
| **TypeScript-first** | All exports typed; `EncryptionConfigurations` type for the config shape. |
| **`sideEffects: false`** | Tree-shakeable for hash-only consumers, except for the AES import that backs the default driver. |
| **Drops into `@mongez/cache`** | The `{ encrypt, decrypt }` pair is the contract `EncryptedLocalStorageDriver` expects. |

---

## Installation

```sh
npm install @mongez/encryption
```

```sh
yarn add @mongez/encryption
```

```sh
pnpm add @mongez/encryption
```

`crypto-js` is a runtime dependency and ships transitively — no separate install required.

---

## Quick start

```ts
import {
  encrypt,
  decrypt,
  md5,
  sha256,
  setEncryptionConfigurations,
} from "@mongez/encryption";

// 1. Per-call: pass key (and optional driver) explicitly.
const cipher = encrypt({ userId: 42 }, "my-key");
const value = decrypt(cipher, "my-key");
// value === { userId: 42 }

// 2. Or set defaults once at boot and call without arguments.
setEncryptionConfigurations({ key: import.meta.env.VITE_APP_SECRET });

encrypt("hello");                  // uses the configured key + AES
decrypt(encrypt("hello"));         // → "hello"

// 3. Hashes are stateless — no config needed.
md5("123456");                     // "e10adc3949ba59abbe56e057f20f883e"
sha256("123456");                  // "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
```

That's the entire happy path. Everything below is depth on the same nine exports.

---

## Configuration

`encrypt` and `decrypt` each accept an optional `key` and `driver`. To avoid threading them through every call site, set defaults once on the module.

```ts
import AES from "crypto-js/aes";
import {
  setEncryptionConfigurations,
  getEncryptionConfig,
  encrypt,
} from "@mongez/encryption";

setEncryptionConfigurations({
  key: import.meta.env.VITE_APP_SECRET,
  driver: AES, // optional — AES is the import-time default
});

encrypt({ a: 1 }); // no args needed — uses the configured pair
```

### `EncryptionConfigurations`

| Option | Default | Effect |
|---|---|---|
| `key` | `null` | Default passphrase / key string used by `encrypt` and `decrypt` when the caller omits it. |
| `driver` | `crypto-js/aes` | Default cipher module. Must expose `.encrypt(text, key)` and `.decrypt(cipher, key)`. |

### Merge semantics

`setEncryptionConfigurations` shallow-merges over the current state. Calling it twice with only `{ key }` keeps the previously set `driver`.

```ts
setEncryptionConfigurations({ key: "k1" });          // { key: "k1", driver: AES }
setEncryptionConfigurations({ driver: TripleDES });  // { key: "k1", driver: TripleDES }
setEncryptionConfigurations({ key: undefined });     // { key: undefined, driver: TripleDES }
```

> `undefined` keys ARE written through. Passing `{ key: undefined }` erases any previously set key — this is a property of the shallow merge, not a quirk to rely on.

### Reading the config

```ts
getEncryptionConfig("key");    // current default key (or null)
getEncryptionConfig("driver"); // current default driver (AES if untouched)
```

### Multi-tenant servers — prefer explicit per-call

The configuration is process-global. Two concurrent requests with different per-tenant keys would race:

```ts
// DON'T do this in a request handler:
setEncryptionConfigurations({ key: req.user.tenantKey });
return encrypt(payload);

// DO this instead:
return encrypt(payload, req.user.tenantKey, AES);
```

Treat `setEncryptionConfigurations` as boot-time setup, not request-time state.

---

## Encrypt / decrypt

Symmetric, passphrase-keyed, AES-CBC under the hood. Returns a base64 string. Reverses to the original JS value.

### Signatures

```ts
encrypt(value: any, key?: string, driver?: any): string
decrypt(cipher: string, key?: string, driver?: any): any | null
```

`key` and `driver` fall back to the configured defaults. `encrypt` and `decrypt` both throw `"Missing Encryption key, please define it or set it in encryption configurations"` when neither a per-call key nor a configured default exists.

### Round-trip semantics

```ts
import { encrypt, decrypt } from "@mongez/encryption";

const cipher = encrypt({ userId: 42 }, "my-key");
const value = decrypt(cipher, "my-key");
// value === { userId: 42 }
```

Reversible for any JSON-encodable value — primitives, arrays, plain objects, nested combinations, unicode.

### How `encrypt` works (internals)

1. Wraps the input as `{ data: value }`. The wrapper forces a consistent shape `decrypt` can rely on and makes primitives like `0`, `false`, and `null` survive the round trip.
2. `JSON.stringify`s the wrapper.
3. Calls `driver.encrypt(plaintext, key)` and returns `.toString()` on the result — a base64 string with the OpenSSL `Salted__` prefix when using AES with a passphrase key.

### How `decrypt` works (internals)

1. Calls `driver.decrypt(cipher, key)` and decodes the bytes to UTF-8.
2. If the decoded plaintext is empty (wrong key → crypto-js silently yields `""`), returns `null`.
3. `JSON.parse`s the plaintext and returns the `.data` property.
4. Any thrown error (invalid base64, malformed JSON) is caught, logged via `console.warn`, and the function returns `null`.

### Failure modes

| Situation | Behavior |
|---|---|
| Wrong key | `decrypt` returns `null`. **Cannot be distinguished** from tampered cipher or malformed input — the wrapper has no authentication tag. |
| Tampered cipher | Returns `null` for corrupted bytes. There is no MAC to check, so cleverly-crafted tampers may decode to arbitrary values. |
| Empty / non-base64 cipher | Returns `null`; a `console.warn` is emitted with the underlying error. |
| Falsy key (per-call AND config) | Both functions throw `"Missing Encryption key…"`. |
| Circular reference in `value` | `encrypt` throws synchronously from `JSON.stringify` before any cipher work happens. |
| `undefined` value | Round-trips as `undefined` (`JSON.stringify({ data: undefined })` is `"{}"`; `JSON.parse("{}").data` is `undefined`). |
| `function` value | Same as `undefined` — functions are dropped at JSON time. |

### Non-determinism

```ts
encrypt("hello", "k") === encrypt("hello", "k");
// false — crypto-js picks a fresh salt each call
```

Both ciphers decrypt to `"hello"`. **Do not compare ciphertexts for equality.** If you need a stable token for the same input, hash it (`sha256`) and use the digest as the comparison key.

### Switching driver

```ts
import TripleDES from "crypto-js/tripledes";
import { encrypt, decrypt } from "@mongez/encryption";

const c = encrypt("hello", "k", TripleDES);
const v = decrypt(c, "k", TripleDES); // "hello"
```

Any `crypto-js` cipher module with `.encrypt(text, key)` / `.decrypt(cipher, key)` works as a driver: `AES`, `TripleDES`, `Rabbit`, `RC4` (don't), `RC4Drop`. Prefer `AES`.

---

## Hash functions

Four hex-encoded digests: `md5`, `sha1`, `sha256`, `sha512`. All four take a string and return a lowercase hex string. No configuration, no module setup — direct passthroughs to `CryptoJS.MD5/SHA1/SHA256/SHA512` with `.toString()`.

### Signatures

```ts
md5(text: string):    string
sha1(text: string):   string
sha256(text: string): string
sha512(text: string): string
```

### Test vectors

```ts
md5("");          // "d41d8cd98f00b204e9800998ecf8427e"
md5("123456");    // "e10adc3949ba59abbe56e057f20f883e"
sha1("");         // "da39a3ee5e6b4b0d3255bfef95601890afd80709"
sha1("123456");   // "7c4a8d09ca3762af61e59520943dc26494f8941b"
sha256("");       // "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
sha256("123456"); // "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
sha512("123456"); // "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548…"
```

Unicode is encoded as UTF-8 before hashing — outputs match the standard test vectors for that scheme.

### Suitable uses

- **Content fingerprints** — static-asset dedup, build-output integrity (against wire corruption, not adversaries).
- **Cache keys / ETags** — `sha256(JSON.stringify(query))` makes a stable cache key for a complex input.
- **Idempotency keys** — `sha256(payload)` derives a stable key so retries collapse into one operation.
- **Bloom filter / probabilistic structure inputs.**

### Unsuitable uses

| Use case | Why these hashes don't fit | What to use instead |
|---|---|---|
| Password storage | Too fast; lack per-record salt; vulnerable to GPU brute force. | `bcrypt`, `scrypt`, or **Argon2id** |
| Message authentication | Plain hashes don't bind a secret. | HMAC — `crypto-js/hmac-sha256`, or Node `crypto.createHmac` |
| Digital signatures over adversarial inputs | `md5` and `sha1` are **broken for collision resistance**. | `sha256` + a signing primitive (RSA-PSS, Ed25519), or JWS |
| Constant-time equality of secrets | `===` on hex strings leaks length / timing. | `crypto.timingSafeEqual` (Node) |
| FIPS or regulatory validation | Pure-JS, unvalidated. | A vetted library or a managed KMS |

> **`md5` and `sha1` have practical collision attacks.** For non-adversarial fingerprinting (ETags, deduplicating your own files) that's fine — collisions don't appear by chance. For anything where an attacker controls part of the input, default to `sha256`.

---

## Security boundaries

The single most important thing about this package: pick the right tool for the threat. The table below is the actual capability surface, not a marketing claim.

| Concern | This package |
|---|---|
| Authenticated encryption (AEAD / tamper detection) | **No.** `crypto-js` `AES.encrypt(text, passphrase)` is AES-CBC + OpenSSL-style MD5 KDF + random salt. Ciphertext can be tampered with undetectably. |
| Modern key derivation | **No.** OpenSSL-style KDF is one round of MD5. For passphrase-derived keys you want PBKDF2 / scrypt / argon2 with a tunable cost. |
| Salts / IVs | crypto-js picks a fresh salt per call when the key is a passphrase string. Cipher is non-deterministic. No IV exposed to the caller. |
| Constant-time digest comparison | **No.** Outputs are hex strings; `===` is not timing-safe. |
| `md5` / `sha1` collision resistance | **Broken.** Suitable for fingerprinting / ETags only. |
| FIPS / regulated compliance | **No.** Pure-JS, not validated; uses primitives (MD5, SHA-1, AES-CBC without MAC) that several regimes disallow. |

> **Reach for it when**: opaquing query-string params, masking values in logs, signing-free local-storage payloads, encrypted browser-side cache entries, non-sensitive round-trips through string form. Threat model: "casual reader," not "motivated attacker."

> **Do NOT reach for it when**: passwords (use `bcrypt` / `scrypt` / **Argon2id**), session integrity (use a signed JWT/JWS), PII at rest in regulated systems, payment data, anything subject to a compliance regime, anywhere you need integrity guarantees. For server-side authenticated encryption use Node `crypto` AES-GCM or libsodium; for managed keys reach for a KMS.

---

## Integration with `@mongez/cache`

`@mongez/encryption` is the reference implementation of the `{ encrypt, decrypt }` contract that [`@mongez/cache`](https://github.com/hassanzohdy/cache)'s encrypted drivers expect. Drop the pair into the driver's `encryption` slot and every value written through the cache becomes ciphertext on disk.

```ts
import {
  encrypt,
  decrypt,
  setEncryptionConfigurations,
} from "@mongez/encryption";
import cache, {
  EncryptedLocalStorageDriver,
  setCacheConfigurations,
} from "@mongez/cache";

setEncryptionConfigurations({ key: import.meta.env.VITE_APP_SECRET });

setCacheConfigurations({
  driver: new EncryptedLocalStorageDriver(),
  encryption: { encrypt, decrypt },
});

cache.set("auth.accessToken", "abc123");
// On disk: { "auth.accessToken": "U2FsdGVkX18..." }  ← ciphertext
cache.get("auth.accessToken"); // "abc123" — decrypted transparently
```

The cache reads `{ encrypt, decrypt }` from its configuration on every call, so you can rotate the encryption key (re-run `setEncryptionConfigurations`) without rebuilding driver instances.

> **`@mongez/cache` is browser-side, and so is this encrypted layer.** Anyone with `window` access (extensions, devtools, injected scripts) can still observe `encrypt` calls in memory. Encrypted local-storage raises the bar against passive disk readers — it does **not** turn the browser into a trust boundary. For real secret material, the secret should never reach the browser in the first place.

---

## Recipes

### Encrypt auth tokens at rest

Tokens, refresh tokens, and PII should never sit in plaintext `localStorage` — any extension or injected script with `window` access can read them. Layer `EncryptedLocalStorageDriver` over this package's `encrypt`/`decrypt`.

```ts
import {
  encrypt,
  decrypt,
  setEncryptionConfigurations,
} from "@mongez/encryption";
import cache, {
  EncryptedLocalStorageDriver,
  setCacheConfigurations,
} from "@mongez/cache";

setEncryptionConfigurations({ key: import.meta.env.VITE_APP_SECRET });

setCacheConfigurations({
  driver: new EncryptedLocalStorageDriver(),
  encryption: { encrypt, decrypt },
  expiresAfter: 60 * 60, // 1-hour default for tokens
});

cache.set("auth.accessToken", accessToken);
cache.set("auth.refreshToken", refreshToken, 60 * 60 * 24 * 30); // 30 days

// On reload, transparently decrypted:
const accessToken = cache.get("auth.accessToken");
```

> **This is obfuscation, not a vault.** A motivated attacker with `window` access can still call `decrypt` themselves. The win is against passive disk-state inspection, browser-extension scrapers, and casual `localStorage` peeks. For truly sensitive material, keep it server-side and exchange short-lived tokens.

### Hash filenames for cache busting

Static assets need a content-derived suffix so a redeploy invalidates the browser cache without manual versioning. `sha256` over the file contents (or the build manifest) gives you a deterministic, collision-safe key.

```ts
import { readFileSync } from "node:fs";
import { sha256 } from "@mongez/encryption";

function hashedAssetName(srcPath: string) {
  const contents = readFileSync(srcPath, "utf8");
  const digest = sha256(contents).slice(0, 10); // 40 bits is enough
  const ext = srcPath.split(".").pop();
  return `${srcPath.replace(/\.[^.]+$/, "")}.${digest}.${ext}`;
}

hashedAssetName("dist/app.js");
// → "dist/app.a1b2c3d4e5.js"
```

Identical files always get the same digest; any byte change produces a new name. Use the first 10 hex chars (40 bits) for filename brevity — the collision space is still 2^40, ample for an asset pipeline.

### Build an opaqued URL token

Wrap a value so it isn't human-readable in the URL bar or query log. This is **obfuscation, not authentication** — an attacker who tampers with the token gets `null` back, but cannot be detected forging a different valid-looking ciphertext.

```ts
import { encrypt, decrypt } from "@mongez/encryption";

const KEY = import.meta.env.VITE_URL_TOKEN_KEY;

function makeToken(payload: { orderId: number; exp: number }) {
  const cipher = encrypt(payload, KEY);
  return encodeURIComponent(cipher);
}

function readToken(raw: string) {
  const payload = decrypt(decodeURIComponent(raw), KEY);
  if (!payload) return null; // wrong key, garbage, or tamper — indistinguishable
  if (payload.exp < Date.now()) return null;
  return payload;
}
```

> **If forgery matters, use a signed JWT or layer HMAC** (see the next recipe). This recipe stops casual users from reading and changing the token; it does not stop an attacker who specifically crafts ciphertext.

### Add integrity with HMAC (encrypt-then-MAC)

The package intentionally does NOT provide authenticated encryption. If your threat model requires it and you cannot move to AES-GCM, layer HMAC explicitly using `crypto-js/hmac-sha256`. Use two separate keys.

```ts
import HmacSHA256 from "crypto-js/hmac-sha256";
import { encrypt, decrypt } from "@mongez/encryption";

function seal(value: unknown, encKey: string, macKey: string) {
  const cipher = encrypt(value, encKey);
  const tag = HmacSHA256(cipher, macKey).toString();
  return `${cipher}.${tag}`;
}

function open(sealed: string, encKey: string, macKey: string) {
  const dot = sealed.lastIndexOf(".");
  if (dot < 0) return null;
  const cipher = sealed.slice(0, dot);
  const tag = sealed.slice(dot + 1);
  const expected = HmacSHA256(cipher, macKey).toString();
  if (tag !== expected) return null; // NOTE: not constant-time
  return decrypt(cipher, encKey);
}
```

> Caveats: (1) the `tag !== expected` check is **not constant-time** — swap in `crypto.timingSafeEqual` for a real production deployment. (2) `encKey` and `macKey` must be different keys; never reuse one secret for both. (3) Encrypt-then-MAC ordering (verify the tag before decrypting) is what this snippet implements — don't flip it.

> If you're writing this much code around the package, you're past its threat model. Move to AES-256-GCM via Node `crypto.createCipheriv` — confidentiality and integrity in one primitive. `crypto-js` does not provide GCM mode.

### Distinguish "decrypt failed" from "value was `null`"

`decrypt` returns `null` for both wrong-key/tampered input and a legitimately encrypted `null`. To tell them apart, wrap the value at encrypt time so a successful round-trip produces an object, not `null`.

```ts
import { encrypt, decrypt } from "@mongez/encryption";

function store(value: unknown, key: string) {
  return encrypt({ value }, key); // explicit wrapper
}

function load(cipher: string, key: string) {
  const out = decrypt(cipher, key);
  if (out === null) {
    return { ok: false as const }; // wrong key / tampered / garbage
  }
  return { ok: true as const, value: out.value }; // value may still be null
}

const sealed = store(null, "k");
load(sealed, "k");      // { ok: true, value: null } — round-trip succeeded
load("garbage", "k");   // { ok: false }              — failed
```

### Boot-time setup for a single-tenant app

The most common shape: one app, one key, every call site uses the configured pair.

```ts
// src/setup/encryption.ts — imported first by your entry point.
import { setEncryptionConfigurations } from "@mongez/encryption";

const key = import.meta.env.VITE_APP_SECRET;
if (!key) {
  throw new Error("VITE_APP_SECRET is required");
}

setEncryptionConfigurations({ key });
```

```ts
// src/anywhere.ts
import { encrypt, decrypt } from "@mongez/encryption";

const c = encrypt({ a: 1 }); // no args — uses the configured key + AES
const v = decrypt(c);        // { a: 1 }
```

Crash loudly at boot if the key is missing — never silently fall through to the throw inside `encrypt`. For multi-tenant servers, skip the global config and pass the per-tenant key as the second argument every call.

### Build a content-addressed cache key

Same input → same digest. Use this for deterministic cache keys, ETags, idempotency keys, or any "fingerprint a complex value" need.

```ts
import { sha256 } from "@mongez/encryption";

function cacheKey(query: unknown) {
  // JSON.stringify property order can vary across engines for object literals
  // with computed keys — sort if you need a truly canonical form.
  return `q:${sha256(JSON.stringify(query))}`;
}

const key = cacheKey({ user: 42, scope: "orders" });
// → "q:8d4f…" — stable across calls with equivalent input
```

For idempotency, hash the request body and short-circuit retries that produce the same key. For ETags, hash the response body and compare against the `If-None-Match` header.

---

## Related packages

| Package | Use when you need |
|---|---|
| [`@mongez/cache`](https://github.com/hassanzohdy/cache) | A pluggable browser cache facade. Drop this package's `{ encrypt, decrypt }` into the `EncryptedLocalStorageDriver` for transparently encrypted at-rest values. |
| [`@mongez/atom`](https://github.com/hassanzohdy/atom) | Reactive state primitive. Pairs with `@mongez/cache` for encrypted persistence — every atom that opts into the cache's `persist` adapter gets encrypted storage with zero changes at the call site. |
| [`@mongez/dotenv`](https://github.com/hassanzohdy/dotenv) | Typed `.env` loader. Use it to source `ENCRYPTION_KEY` / `VITE_APP_SECRET` at boot. |
| [`@mongez/events`](https://github.com/hassanzohdy/events) | Tiny event bus. Useful when you want write-through subscriptions on top of an encrypted cache. |

For the full API reference in a single LLM-friendly file, see [`llms-full.txt`](./llms-full.txt). For release history, see [`CHANGELOG.md`](./CHANGELOG.md).

---

## License

MIT — see [LICENSE](./LICENSE).
