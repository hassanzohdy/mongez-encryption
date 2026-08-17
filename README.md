<div align="center">

# @mongez/encryption

**Authenticated symmetric encryption for JSON-encodable values — WebCrypto AES-256-GCM sealed under a PBKDF2-HMAC-SHA256 key, in one `await encrypt(value, key)` / `await decrypt(cipher, key)` pair. Plus hex `md5` / `sha1` / `sha256` / `sha512` digests.**

[![npm](https://img.shields.io/npm/v/@mongez/encryption.svg)](https://www.npmjs.com/package/@mongez/encryption)
[![license](https://img.shields.io/npm/l/@mongez/encryption.svg)](LICENSE)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@mongez/encryption.svg)](https://bundlephobia.com/package/@mongez/encryption)
[![downloads](https://img.shields.io/npm/dw/@mongez/encryption.svg)](https://www.npmjs.com/package/@mongez/encryption)

</div>

---

> ### ⚠️ 2.0 is a breaking security release
>
> `encrypt` and `decrypt` are now **async**, `decrypt` **throws** instead of returning `null`, the pluggable cipher `driver` is gone, and v1.x ciphertext is **rejected by default**. If you are upgrading, read [`MIGRATION.md`](./MIGRATION.md) first — it is short.
>
> v1.x wrote AES-CBC with a **one-round-MD5 key derivation and no authentication tag**. Anything encrypted with v1.x could be modified by whoever could reach the storage, undetectably. Re-encrypt it. See [Threat model](#threat-model).

---

## Why @mongez/encryption?

Native WebCrypto is the right primitive for authenticated encryption, but using it means importing a key, choosing a KDF and a work factor, drawing a fresh nonce every message, remembering which of your bytes are the tag, and hand-rolling base64 both ways. Get any one of those wrong — a reused nonce, a forgotten tag check, a hard-coded salt — and you have a cipher that *looks* like it works.

`@mongez/encryption` is that pipeline, done once, behind two functions. You hand it a value and a passphrase; you get back one base64 string that carries everything needed to open it again, and that cannot be edited in transit without the next `decrypt` refusing it.

```ts
import { encrypt, decrypt, sha256 } from "@mongez/encryption";

const cipher = await encrypt({ userId: 42 }, "a long passphrase"); // AES-256-GCM
const value = await decrypt(cipher, "a long passphrase");          // { userId: 42 }
const tag = sha256(JSON.stringify({ q: "phones" }));               // stable cache key
```

What you get, concretely:

- **AES-256-GCM** — confidentiality *and* integrity. A single flipped bit anywhere in the string makes `decrypt` throw rather than hand back altered data.
- **PBKDF2-HMAC-SHA256, 210,000 iterations** (the OWASP-aligned default), over a **fresh random 16-byte salt per message**.
- **A fresh random 96-bit nonce per message.** Encrypting the same value twice never produces the same string.
- **A versioned envelope.** Version, cipher suite, work factor, salt and nonce all travel with the ciphertext *and are covered by the authentication tag*, so a future release can change algorithms without orphaning your data — and an attacker cannot downgrade the work factor of an existing message.
- **No silent fallbacks.** No WebCrypto, no `crypto.getRandomValues`, no encryption: it throws instead of quietly reaching for `Math.random`.

---

## Requirements

| Runtime | Status |
|---|---|
| Node.js 20+ | ✅ `crypto.subtle` is a global |
| Browser over HTTPS or `localhost` | ✅ secure context, `crypto.subtle` present |
| Browser over plain HTTP (non-localhost) | ❌ `crypto.subtle` is undefined — `UnsupportedRuntimeError` |
| Node.js < 20 | ❌ no global `crypto` — `UnsupportedRuntimeError` |
| React Native / Hermes | ⚠️ needs a WebCrypto polyfill exposing `crypto.subtle` **and** `crypto.getRandomValues` |

The hash functions (`md5`/`sha1`/`sha256`/`sha512`) are pure `crypto-js` and work anywhere; only `encrypt`/`decrypt` need WebCrypto.

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

`crypto-js` remains a runtime dependency — it backs the hash exports and the opt-in legacy decrypt path. Nothing this package *writes* goes through it any more.

---

## Quick start

```ts
import {
  encrypt,
  decrypt,
  tryDecrypt,
  md5,
  sha256,
  setEncryptionConfigurations,
  DecryptionError,
} from "@mongez/encryption";

// 1. Per-call: pass the key explicitly. Both functions are async.
const cipher = await encrypt({ userId: 42 }, "a long passphrase");
const value = await decrypt(cipher, "a long passphrase");
// value === { userId: 42 }

// 2. Or set defaults once at boot and call without a key.
setEncryptionConfigurations({ key: import.meta.env.VITE_APP_SECRET });

await encrypt("hello");                 // uses the configured key
await decrypt(await encrypt("hello"));  // → "hello"

// 3. decrypt THROWS on a wrong key / tampered / malformed input.
try {
  await decrypt(untrustedCipher);
} catch (error) {
  if (error instanceof DecryptionError) return badRequest();
  throw error; // missing key or unusable runtime — a deployment bug, not bad input
}

// 4. …or use tryDecrypt when you genuinely don't care why it failed.
const maybe = await tryDecrypt(untrustedCipher); // null on failure

// 5. Hashes are stateless, synchronous, and unchanged from v1.
md5("123456");    // "e10adc3949ba59abbe56e057f20f883e"
sha256("123456"); // "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
```

---

## Features

| Feature | Description |
|---|---|
| **Authenticated encryption** | AES-256-GCM with a 128-bit tag. Tampering is detected and rejected, not decrypted. |
| **Real key derivation** | PBKDF2-HMAC-SHA256, 210,000 iterations by default, fresh 16-byte salt per message. Configurable; floor of 100,000. |
| **Self-describing envelope** | `version ‖ suite ‖ iterations ‖ salt ‖ nonce ‖ ciphertext ‖ tag`, base64. The header is authenticated as AAD. |
| **Fails loudly** | `decrypt` throws `DecryptionError`; `encrypt` throws `EncryptionError` / `MissingEncryptionKeyError`; an unusable runtime throws `UnsupportedRuntimeError`. |
| **`tryDecrypt`** | The v1-style null-on-failure shape, for callers that want it — explicitly opted into. |
| **Opt-in v1 compatibility** | Old AES-CBC ciphertext is readable only when you enable `legacyDecryption`, so you can migrate; off by default because it is unauthenticated. |
| **Derived-key cache** | PBKDF2 is expensive; identical (key, salt, iterations) triples reuse a non-extractable `CryptoKey`. `clearKeyCache()` on logout. |
| **Hash functions** | `md5`, `sha1`, `sha256`, `sha512` → lowercase hex. Stateless, synchronous, no config. |
| **JSON-aware** | Primitives (`0`, `false`, `null`), arrays, plain objects, nested combinations and unicode all round-trip. |
| **TypeScript-first** | Every export typed. Types compile without `lib.dom` or `@types/node` in your tsconfig. |
| **No insecure fallback** | Missing `crypto.subtle` or `getRandomValues` is a hard error, never a downgrade. |

---

## Configuration

`encrypt` and `decrypt` both take an optional key. To avoid threading it through every call site, set it once at boot.

```ts
import {
  setEncryptionConfigurations,
  getEncryptionConfig,
  resetEncryptionConfigurations,
} from "@mongez/encryption";

setEncryptionConfigurations({
  key: import.meta.env.VITE_APP_SECRET,
  iterations: 210_000, // optional — this is the default
});
```

### `EncryptionConfigurations`

| Option | Default | Effect |
|---|---|---|
| `key` | `null` | Default passphrase used by `encrypt`/`decrypt`/`tryDecrypt` when the caller omits one. Stretched with PBKDF2 — which does not rescue a short key. Use a long, high-entropy secret. |
| `iterations` | `210_000` | PBKDF2 work factor used **when encrypting**. Must be an integer in `100_000 … 5_000_000`; anything else throws `EncryptionError` at configuration time. |
| `legacyDecryption` | `false` | Allow `decrypt` to fall back to the v1.x AES-CBC format. Off by default — v1.x ciphertext is unauthenticated. |
| `legacyDriver` | `crypto-js/aes` | Cipher used for that legacy fallback. Only matters if v1.x wrote your data with a non-default driver (e.g. `TripleDES`). |
| `driver` | — | **Deprecated.** v1.x's pluggable cipher. It can no longer influence encryption; setting it now only nominates the *legacy decrypt* driver, and logs one deprecation warning per process. |

### Reading and resetting

```ts
getEncryptionConfig("key");              // current default passphrase (or null)
getEncryptionConfig("iterations");       // 210000
getEncryptionConfig("legacyDecryption"); // false

resetEncryptionConfigurations();         // back to import-time defaults (useful in tests)
```

### Merge semantics

`setEncryptionConfigurations` shallow-merges over the current state, so partial updates keep everything else:

```ts
setEncryptionConfigurations({ key: "k1" });                 // { key: "k1", iterations: 210000, … }
setEncryptionConfigurations({ legacyDecryption: true });    // key preserved
setEncryptionConfigurations({ key: undefined });            // erases the key
```

> `undefined` values ARE written through. Passing `{ key: undefined }` clears a previously set key — a property of the shallow merge, not a feature to rely on.

### Work factor

The iteration count in force at encryption time is **written into the envelope**, so raising it later does not orphan older ciphertexts — they decrypt at whatever count they were sealed with, and the next `encrypt` uses the new value.

```ts
setEncryptionConfigurations({ iterations: 600_000 }); // slower, stronger
await encrypt(value, key, { iterations: 100_000 });   // or per call
```

Validation differs between the two directions, deliberately:

- **Encrypting** (and configuring): an integer in `100_000 … 5_000_000`. Below the floor PBKDF2 is decorative.
- **Decrypting**: the count is read out of attacker-reachable ciphertext, so it is accepted in `1 … 5_000_000` — low values so old envelopes stay readable, and a hard ceiling so a forged header claiming four billion iterations cannot pin a CPU core before the tag check runs.

### Multi-tenant servers — prefer explicit per-call keys

The configuration is process-global. Two concurrent requests carrying different tenant keys would race:

```ts
// DON'T do this in a request handler:
setEncryptionConfigurations({ key: req.user.tenantKey });
return encrypt(payload);

// DO this instead:
return encrypt(payload, req.user.tenantKey);
```

Treat `setEncryptionConfigurations` as boot-time setup, never request-time state.

---

## Encrypt / decrypt

### Signatures

```ts
encrypt(value: any, key?: string, options?: EncryptOptions): Promise<string>
decrypt(cipher: string, key?: string, options?: DecryptOptions | LegacyCipherDriver): Promise<any>
tryDecrypt(cipher: string, key?: string, options?: DecryptOptions | LegacyCipherDriver): Promise<any | null>

type EncryptOptions = { iterations?: number };
type DecryptOptions = { legacyDecryption?: boolean; legacyDriver?: LegacyCipherDriver };
```

`key` falls back to the configured default. All three throw `MissingEncryptionKeyError` when neither a per-call key nor a configured one exists, and `EncryptionError` when the key is not a string.

### Round trip

```ts
import { encrypt, decrypt } from "@mongez/encryption";

const cipher = await encrypt({ userId: 42 }, "my-key");
const value = await decrypt(cipher, "my-key");
// value === { userId: 42 }
```

Reversible for any JSON-encodable value — primitives, arrays, plain objects, nested combinations, unicode, 10k-character strings.

### What `encrypt` does

1. Wraps the input as `{ data: value }` so primitives like `0`, `false` and `null` survive JSON, and `decrypt` has one shape to rely on.
2. `JSON.stringify`s the wrapper (a circular value rejects here, before any randomness is drawn).
3. Draws a fresh 16-byte salt and 12-byte nonce from the platform CSPRNG.
4. Derives a 256-bit, non-extractable AES-GCM key with PBKDF2-HMAC-SHA256 over that salt.
5. Seals the payload with AES-256-GCM, passing the 34-byte header as **additional authenticated data**.
6. Returns `base64(header ‖ ciphertext ‖ tag)`.

### What `decrypt` does

1. Base64-decodes and checks the leading version byte. Not a version-1 envelope → the legacy path (below).
2. Rejects a truncated envelope, an unknown cipher suite, or an out-of-range work factor **before** deriving anything.
3. Re-derives the key from the passphrase and the envelope's own salt and iteration count.
4. Verifies the GCM tag over header + ciphertext, then decrypts. Any failure → `DecryptionError`.
5. `JSON.parse`s the plaintext and returns `.data`.

### Ciphertext format

```
byte 0        envelope version   (0x01)
byte 1        cipher suite       (0x01 = PBKDF2-SHA256 → AES-256-GCM, 128-bit tag)
bytes 2–5     PBKDF2 iterations  (uint32, big-endian)
bytes 6–21    salt               (16 bytes)
bytes 22–33   nonce / IV         (12 bytes)
bytes 34–     ciphertext ‖ GCM tag (tag is the trailing 16 bytes)
```

The whole 34-byte header is authenticated as AAD, so the declared work factor, salt and nonce are tamper-evident too. Overhead is 50 bytes plus base64 expansion. The encoding uses the **standard** base64 alphabet (`+`, `/`, `=`) — `encodeURIComponent` it before putting it in a URL.

Constants and helpers are exported if you need them: `ENVELOPE_VERSION_1`, `SUITE_PBKDF2_SHA256_AES_256_GCM`, `SALT_LENGTH`, `IV_LENGTH`, `AUTH_TAG_LENGTH`, `HEADER_LENGTH`, `DEFAULT_ITERATIONS`, `MIN_ITERATIONS`, `MAX_ITERATIONS`, `parseEnvelope`, `isEncryptionEnvelope`.

### Failure modes

| Situation | Behavior |
|---|---|
| Wrong key | `decrypt` rejects with `DecryptionError`: *"Authentication failed: the ciphertext was modified, or the key is wrong."* |
| Tampered ciphertext (any byte) | Same error, deliberately worded identically — GCM cannot tell the two apart, and neither should your error handler. Giving an attacker that distinction is a decryption oracle. |
| Truncated / short envelope | `DecryptionError` — *"shorter than its own header and authentication tag."* |
| Unknown cipher suite | `DecryptionError` — the ciphertext came from a newer version of this package. |
| Work factor outside `1…5,000,000` | `DecryptionError` before any key derivation (CPU-exhaustion guard). |
| Not base64 / unrecognised prefix | `DecryptionError` — *"not an AES-GCM envelope, and not a legacy (v1.x) ciphertext either."* |
| v1.x ciphertext, legacy path disabled | `DecryptionError` naming `legacyDecryption: true` as the way to opt in. |
| Empty string or non-string cipher | `DecryptionError`. |
| No key anywhere | `MissingEncryptionKeyError` (a subclass of `EncryptionError`). |
| Non-string key | `EncryptionError` — *"The encryption key must be a string, … given."* |
| Cipher driver passed to `encrypt` | `EncryptionError` — v2 does not take one. Pass it to `decrypt` instead if you need to read v1 data. |
| `iterations` below 100,000 or above 5,000,000 at encrypt time | `EncryptionError` — *"Invalid PBKDF2 iterations."* |
| No WebCrypto / no CSPRNG | `UnsupportedRuntimeError`. Never a downgrade. |
| Circular reference in `value` | `encrypt` rejects from `JSON.stringify`, before any randomness is drawn. |
| `undefined` or a function as `value` | Round-trips to `undefined` — JSON drops it. Unchanged from v1. |

Nothing is written to `console` on a decrypt failure. v1.x `console.warn`'d on every one, which let anyone probing your endpoint flood your logs.

### `decrypt` vs `tryDecrypt`

`decrypt` throws; `tryDecrypt` returns `null` for a `DecryptionError` and re-throws everything else — a missing key or an unusable runtime is a deployment fault, not a bad ciphertext, and swallowing it would hide the bug.

```ts
const value = await tryDecrypt(cipher, key); // null on wrong key / tamper / garbage
```

Prefer `decrypt`. `null` is ambiguous: `encrypt(null)` round-trips to `null` too, so `tryDecrypt` cannot tell "failed" from "successfully decrypted a null".

### Errors

```
EncryptionError                 base class — catch this for any failure from the package
├─ MissingEncryptionKeyError    no key per call and none configured
├─ UnsupportedRuntimeError      no crypto.subtle / no crypto.getRandomValues
└─ DecryptionError              wrong key, tampered, malformed, or rejected legacy ciphertext
```

`instanceof` works after transpilation down to ES5.

### Non-determinism

```ts
(await encrypt("hello", "k")) === (await encrypt("hello", "k"));
// false — fresh salt and nonce every call
```

Both strings decrypt to `"hello"`. **Never compare ciphertexts for equality**, and never use one as a cache key or a database index. If you need a stable token for the same input, hash it with `sha256` and index the digest.

### The derived-key cache

PBKDF2 at 210,000 iterations costs on the order of 100 ms per call. An app that reads a dozen encrypted values on boot would otherwise pay it a dozen times, so derived keys are memoised in-process, keyed by the exact `(passphrase, salt, iterations)` triple, up to 64 entries.

The cache cannot widen who can decrypt what — a hit requires the same passphrase *and* the same salt, and the cached `CryptoKey` is non-extractable. It does keep material in memory for the life of the process:

```ts
import { clearKeyCache } from "@mongez/encryption";

clearKeyCache(); // on logout, on key rotation, and between tests
```

---

## Reading v1.x ciphertext

v2 does not write the v1.x format, and refuses to read it unless you say so.

```ts
import { setEncryptionConfigurations, decrypt, encrypt, isLegacyCipher } from "@mongez/encryption";

// Globally, for the duration of a migration:
setEncryptionConfigurations({ legacyDecryption: true });

// …or per call:
await decrypt(oldCipher, key, { legacyDecryption: true });

// …or with the driver v1 used, if it wasn't AES:
import TripleDES from "crypto-js/tripledes";
await decrypt(oldCipher, key, { legacyDecryption: true, legacyDriver: TripleDES });
await decrypt(oldCipher, key, TripleDES); // v1-shaped third argument, implies legacyDecryption
```

Two properties worth being explicit about:

- **A value read through the legacy path is not authenticated.** v1.x had no MAC. If an attacker could write to that storage, the value you just read may have been altered. Re-encrypt it and stop trusting the old copy — that is the *point* of migrating.
- **The format is forward-only.** v2 envelopes are not readable by v1.x. Deploy v2 everywhere that reads a given store *before* anything starts writing v2 into it.

`isLegacyCipher(cipher)` and `isEncryptionEnvelope(cipher)` let a migration script tell the two apart without decrypting. See [`MIGRATION.md`](./MIGRATION.md) for the full walk-and-re-encrypt recipe.

---

## Hash functions

Four hex-encoded digests: `md5`, `sha1`, `sha256`, `sha512`. All take a string and return a lowercase hex string. Stateless, synchronous, no configuration, no WebCrypto requirement — direct passthroughs to `CryptoJS.MD5/SHA1/SHA256/SHA512` with `.toString()`. Unchanged in v2.

### Signatures

```ts
md5(text: string):    string  // @deprecated — legacy interop only
sha1(text: string):   string  // @deprecated — legacy interop only
sha256(text: string): string
sha512(text: string): string
```

`md5` and `sha1` are marked deprecated in their JSDoc so an editor flags them at the call site. They still work and are not going anywhere — they exist for legacy interop (gravatar-style identifiers, old cache keys). Do not add new uses.

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

Input is encoded as UTF-8 before hashing, so outputs match the standard vectors for that scheme.

### Suitable uses

- **Content fingerprints** — static-asset dedup, build-output integrity against wire corruption (not adversaries).
- **Cache keys / ETags** — `sha256(JSON.stringify(query))` is a stable key for a complex input.
- **Idempotency keys** — `sha256(payload)` collapses retries into one operation.
- **Bloom filter / probabilistic structure inputs.**

### Unsuitable uses

| Use case | Why these don't fit | Use instead |
|---|---|---|
| Password storage | Too fast, no per-record salt, GPU-brute-forceable | `bcrypt`, `scrypt`, or **Argon2id** |
| Message authentication | A plain hash binds no secret | HMAC — `crypto-js/hmac-sha256`, or `crypto.subtle.sign` |
| Signatures over adversarial input | `md5`/`sha1` are collision-broken | `sha256` + RSA-PSS / Ed25519, or JWS |
| Constant-time equality of secrets | `===` on hex leaks length and timing | `crypto.timingSafeEqual` (Node) |
| FIPS / regulatory validation | Pure JS, unvalidated | A vetted library or a managed KMS |

---

## Threat model

What v2 does and does not defend against. Read the "no" column before you decide this package is enough.

| Property | v2 |
|---|---|
| Confidentiality of the payload | **Yes** — AES-256-GCM under a PBKDF2-derived 256-bit key. |
| Integrity / tamper detection | **Yes** — 128-bit GCM tag over ciphertext *and* header. Any edit is rejected. |
| Nonce and salt hygiene | **Yes** — fresh CSPRNG values per message; nonces and salts are never reused, and never derived from the plaintext. |
| Downgrade of the recorded work factor | **Prevented** — the iteration count is authenticated as AAD. |
| CPU exhaustion via a forged header | **Bounded** — a declared work factor above 5,000,000 is rejected before key derivation. |
| Format confusion (v1 blob swapped for a v2 envelope) | **Prevented by default** — the legacy path is off unless you enable it, and the two formats are distinguishable by their first byte. |
| Weak passphrases | **No.** PBKDF2 raises the cost of an offline guess; it does not make `"password123"` safe. PBKDF2 is also GPU-friendly relative to scrypt/Argon2 — it is the strongest KDF WebCrypto exposes natively. Use a long, random secret. |
| Key management / rotation | **No.** The envelope carries no key identifier, so rotation means re-encrypting (or trying keys in order). Keys are your problem; consider a KMS. |
| Binding ciphertext to a context | **No.** Callers cannot supply their own AAD. A valid ciphertext moved from user A's row to user B's row still decrypts. If placement matters, put the context *inside* the value and check it after decrypting. |
| Replay / freshness | **No.** Ciphertext has no timestamp or counter. Add your own `exp`/nonce inside the payload if replay matters. |
| Length hiding | **No.** Ciphertext length reveals plaintext length (plus a constant). Pad if that leaks something. |
| Secrets in a browser | **No.** Anything shipped to a browser — including the passphrase — is readable by whoever controls the page: extensions, devtools, injected scripts. Encrypting `localStorage` raises the bar against passive disk inspection; it does not make the browser a trust boundary. |
| Constant-time hash comparison | **No.** Digests are hex strings; `===` is not timing-safe. |
| `md5` / `sha1` collision resistance | **Broken.** Fingerprinting only. |
| FIPS / regulated compliance | **No.** Not a validated module. |
| Side-channel resistance | Inherited from the platform's WebCrypto implementation; unaudited here. |

**Reach for it when**: encrypting values at rest in browser storage, opaquing query-string parameters, sealing payloads passed through untrusted intermediaries, protecting cached data against a passive reader, and anywhere you need a wrong-key or tampered value to *fail* rather than degrade.

**Do not reach for it when**: storing passwords (`bcrypt` / `scrypt` / **Argon2id**), issuing session tokens (a signed JWT/JWS or a server-side session), key exchange or public-key work (libsodium, WebCrypto ECDH), streaming large files, or where a compliance regime demands a validated module or a managed KMS.

---

## Integration with `@mongez/cache`

> **⚠️ v2 is not drop-in compatible with `@mongez/cache`'s encrypted drivers.**
>
> `EncryptedLocalStorageDriver` and `EncryptedSessionStorageDriver` call the configured `encrypt(...)` **synchronously** and write the return value straight to storage. Handed v2's async `encrypt`, they write the string `"[object Promise]"` — the value is lost, not leaked, and reads come back wrong. Until `@mongez/cache` supports an async encryption contract, either pin `@mongez/encryption@^1` for that integration, or encrypt outside the cache and store the resulting string through a plain driver:

```ts
import { encrypt, decrypt } from "@mongez/encryption";
import cache from "@mongez/cache";

// Encrypt first, await, then cache the finished string.
cache.set("auth.accessToken", await encrypt(accessToken, KEY));

const stored = cache.get("auth.accessToken");
const accessToken = stored ? await decrypt(stored, KEY) : null;
```

The trade-off is that the cache's own `{ data, expiresAt }` envelope is no longer encrypted alongside the value — expiry metadata is visible in storage. If that matters, wrap it yourself: `await encrypt({ value, expiresAt }, KEY)`.

---

## Recipes

### Boot-time setup for a single-tenant app

```ts
// src/setup/encryption.ts — imported first by your entry point.
import { setEncryptionConfigurations } from "@mongez/encryption";

const key = import.meta.env.VITE_APP_SECRET;

if (!key || key.length < 32) {
  throw new Error("VITE_APP_SECRET is required and must be at least 32 chars");
}

setEncryptionConfigurations({ key });
```

```ts
// src/anywhere.ts
import { encrypt, decrypt } from "@mongez/encryption";

const cipher = await encrypt({ a: 1 }); // no args — uses the configured key
const value = await decrypt(cipher);    // { a: 1 }
```

Crash loudly at boot if the key is missing or short — never fall through to the throw inside `encrypt`, which surfaces at some random call site later.

### An opaque, tamper-evident URL token

Unlike v1, a token edited in the URL bar now *fails* instead of silently decoding to something else.

```ts
import { encrypt, tryDecrypt } from "@mongez/encryption";

const KEY = process.env.URL_TOKEN_KEY!;

async function makeToken(payload: { orderId: number; exp: number }) {
  // Standard base64 contains + and / — always URL-encode it.
  return encodeURIComponent(await encrypt(payload, KEY));
}

async function readToken(raw: string) {
  const payload = await tryDecrypt(decodeURIComponent(raw), KEY);

  if (!payload) return null;                 // wrong key, garbage, or tampered
  if (payload.exp < Date.now()) return null; // freshness is still yours to enforce
  return payload;
}
```

This gives confidentiality *and* integrity, but it is still a bearer token: anyone who copies it can replay it until `exp`. It is not a substitute for a signed JWT when a third party must verify the token without your key.

### Bind a ciphertext to its context

The package does not expose caller-supplied AAD, so a ciphertext lifted from one record and dropped into another still decrypts. Put the binding in the plaintext and check it:

```ts
async function sealFor(userId: string, value: unknown, key: string) {
  return encrypt({ userId, value }, key);
}

async function openFor(userId: string, cipher: string, key: string) {
  const payload = await decrypt(cipher, key);

  if (payload?.userId !== userId) {
    throw new Error("ciphertext does not belong to this user");
  }

  return payload.value;
}
```

### Encrypt a field before it leaves the server

```ts
import { encrypt, decrypt, DecryptionError } from "@mongez/encryption";

async function storeSSN(userId: string, ssn: string) {
  await db.users.update(userId, { ssn: await encrypt(ssn, process.env.FIELD_KEY!) });
}

async function readSSN(userId: string) {
  const row = await db.users.find(userId);

  try {
    return await decrypt(row.ssn, process.env.FIELD_KEY!);
  } catch (error) {
    if (error instanceof DecryptionError) {
      // Not "missing" — either the row was tampered with or the key rotated.
      // Alert; do not fall back to a default.
      throw new Error(`unreadable ssn for ${userId}`);
    }
    throw error;
  }
}
```

Field-level encryption keeps the value out of backups, logs and read replicas in plaintext. It does not protect against an attacker who already has both the database and the key.

### Rotate a key

The envelope carries no key identifier, so rotation is a re-encrypt:

```ts
import { encrypt, tryDecrypt, clearKeyCache } from "@mongez/encryption";

async function rotate(cipher: string, oldKey: string, newKey: string) {
  const value = await tryDecrypt(cipher, oldKey);

  if (value === null) return null; // not ours, or already rotated

  return encrypt(value, newKey);
}

clearKeyCache(); // once the old key is retired
```

For a mixed store mid-rotation, try the new key first and fall back to the old one — `tryDecrypt` makes that a two-line ladder.

### Content-addressed cache key

```ts
import { sha256 } from "@mongez/encryption";

function cacheKey(query: unknown) {
  // Property order can vary across engines — sort keys if you need a truly
  // canonical form.
  return `q:${sha256(JSON.stringify(query))}`;
}

cacheKey({ user: 42, scope: "orders" }); // → "q:8d4f…" — stable across calls
```

Hash for keys; encrypt for secrecy. Never use a ciphertext as a cache key — it changes every call.

### Hash filenames for cache busting

```ts
import { readFileSync } from "node:fs";
import { sha256 } from "@mongez/encryption";

function hashedAssetName(srcPath: string) {
  const digest = sha256(readFileSync(srcPath, "utf8")).slice(0, 10);
  const ext = srcPath.split(".").pop();

  return `${srcPath.replace(/\.[^.]+$/, "")}.${digest}.${ext}`;
}

hashedAssetName("dist/app.js"); // → "dist/app.a1b2c3d4e5.js"
```

---

## Related packages

| Package | Use when you need |
|---|---|
| [`@mongez/cache`](https://github.com/hassanzohdy/cache) | A pluggable browser cache facade. See the compatibility note above before wiring v2 into its encrypted drivers. |
| [`@mongez/atom`](https://github.com/hassanzohdy/atom) | Reactive state primitive; pairs with `@mongez/cache` for persistence. |
| [`@mongez/dotenv`](https://github.com/hassanzohdy/dotenv) | Typed `.env` loader — source `ENCRYPTION_KEY` / `VITE_APP_SECRET` at boot. |
| [`@mongez/reinforcements`](https://github.com/hassanzohdy/reinforcements) | Utility belt; `Random.token` for generating the high-entropy secrets this package expects. |

Upgrading from v1? [`MIGRATION.md`](./MIGRATION.md). Release history: [`CHANGELOG.md`](./CHANGELOG.md). Full API reference in one LLM-friendly file: [`llms-full.txt`](./llms-full.txt).

---

## License

MIT — see [LICENSE](./LICENSE).
