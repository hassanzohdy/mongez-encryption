# Migration Guide

## 1.x → 2.0

Security release. `encrypt`/`decrypt` moved from `crypto-js` AES-CBC (with a one-round-MD5 key derivation and **no authentication tag**) to WebCrypto **AES-256-GCM** with **PBKDF2-HMAC-SHA256**. That change cannot be made compatibly, so this major breaks in five places.

The hash exports — `md5`, `sha1`, `sha256`, `sha512` — are **unchanged**. If that is all you import, there is nothing to do.

### At a glance

| v1.x | v2.0 |
|---|---|
| `const c = encrypt(v, key)` | `const c = await encrypt(v, key)` |
| `const v = decrypt(c, key)` → `null` on failure | `const v = await decrypt(c, key)` → **throws** `DecryptionError` |
| — | `const v = await tryDecrypt(c, key)` → `null` on failure |
| `encrypt(v, key, TripleDES)` | ❌ throws — v2 always uses AES-256-GCM |
| `setEncryptionConfigurations({ driver })` | deprecated; now only nominates the *legacy decrypt* driver |
| Reads v1 ciphertext | Rejects it unless `legacyDecryption: true` |
| Runs anywhere | Needs Node 18+ or a secure browser context |

---

### 1. `encrypt` and `decrypt` are async

Every call site needs `await`, and every enclosing function needs to become `async`.

```diff
- const cipher = encrypt({ userId: 42 }, KEY);
- const value = decrypt(cipher, KEY);
+ const cipher = await encrypt({ userId: 42 }, KEY);
+ const value = await decrypt(cipher, KEY);
```

**Why:** WebCrypto's `subtle` API is promise-based, and PBKDF2 at 210,000 iterations takes real time — blocking a UI thread for that long synchronously was never an option. `crypto-js` was synchronous only because it was pure JS running on the main thread.

**Where this bites:** anywhere the return value was used inline in a synchronous context — a React render, a getter, an object literal, a `.map()` that isn't awaited, or a synchronous plugin/driver contract. A missed `await` is not a type error if the value flows into `any`; it silently stores `[object Promise]`. Grep for `encrypt(` and `decrypt(` and check every hit.

```diff
- localStorage.setItem("token", encrypt(token, KEY));
+ localStorage.setItem("token", await encrypt(token, KEY));
```

### 2. `decrypt` throws instead of returning `null`

```diff
- const value = decrypt(cipher, KEY);
- if (value === null) return badRequest();
+ import { decrypt, DecryptionError } from "@mongez/encryption";
+
+ let value;
+ try {
+   value = await decrypt(cipher, KEY);
+ } catch (error) {
+   if (error instanceof DecryptionError) return badRequest();
+   throw error; // missing key / unusable runtime — a bug, not bad input
+ }
```

Or keep the old shape with `tryDecrypt`, which returns `null` for a `DecryptionError` and re-throws everything else:

```diff
- const value = decrypt(cipher, KEY);
+ const value = await tryDecrypt(cipher, KEY);
  if (value === null) return badRequest();
```

**Why:** now that the ciphertext is authenticated, "this failed" is real information, and `null` throws it away. Worse, `null` is ambiguous — `encrypt(null)` round-trips to `null`, so a `null` return could never be distinguished from a failure. Code that treated `null` as "no value yet" and wrote a fresh default over it was silently destroying data whenever a key was wrong.

**Note:** `tryDecrypt` is the compatibility shape, not the recommended one. Prefer `decrypt` where you can act on the failure.

### 3. The pluggable cipher `driver` is gone from `encrypt`

```diff
- import TripleDES from "crypto-js/tripledes";
- const cipher = encrypt(value, KEY, TripleDES);
+ const cipher = await encrypt(value, KEY);
```

Passing a cipher-shaped object as `encrypt`'s third argument now throws `EncryptionError`. The third argument is `{ iterations?: number }` instead.

```diff
- setEncryptionConfigurations({ key: KEY, driver: AES });
+ setEncryptionConfigurations({ key: KEY });
```

`driver` still parses in the configuration object, but it is deprecated: it can no longer change how anything is encrypted, it only nominates the driver used to read **legacy** ciphertext, and it logs one deprecation warning per process. If that is what you want, say so explicitly with `legacyDriver`.

**Why:** the choice was never a real one. `TripleDES`, `Rabbit`, `RC4` and friends are all worse than AES-256-GCM, none of them authenticate, and every configurable-cipher API is one misconfiguration away from a downgrade. AES-256-GCM is not negotiable in v2.

### 4. v1 ciphertext is rejected by default

```diff
+ setEncryptionConfigurations({ legacyDecryption: true });
  const value = await decrypt(oldCipher, KEY);
```

or per call:

```diff
+ const value = await decrypt(oldCipher, KEY, { legacyDecryption: true });
```

If v1 wrote your data with a non-default cipher, name it:

```ts
import TripleDES from "crypto-js/tripledes";

await decrypt(oldCipher, KEY, { legacyDecryption: true, legacyDriver: TripleDES });
await decrypt(oldCipher, KEY, TripleDES); // v1-shaped call; implies legacyDecryption
```

**Why:** v1 ciphertext is unauthenticated. If it stayed silently readable forever, an attacker who could write to your storage could swap an authenticated v2 envelope for a malleable v1 blob and get tampered plaintext accepted — a downgrade attack against the very property this release adds. Off by default makes the exposure a decision with a timebox, not a default.

**Treat anything read through this path as untrusted input.** It may have been altered before you read it.

### 5. New runtime floor: Node 18+ or a secure browser context

`encrypt`/`decrypt` need `globalThis.crypto.subtle` and `crypto.getRandomValues`. Without them you get an `UnsupportedRuntimeError` — there is no fallback, because the only available fallbacks (a non-CSPRNG, an unauthenticated cipher) defeat the point of the release.

- **Node.js 18+** — fine, `crypto` is a global.
- **Node.js 16 and older** — upgrade, or polyfill `globalThis.crypto` from `node:crypto`'s `webcrypto`.
- **Browsers** — `crypto.subtle` exists only in a **secure context**: HTTPS, or `http://localhost`. A staging site served over plain HTTP will throw.
- **React Native / Hermes / older WebViews** — needs a WebCrypto polyfill providing both `subtle` and `getRandomValues`.
- **Jest with the default `jsdom` environment** — older jsdom does not expose `crypto.subtle`; use `@jest-environment node`, or inject `require("node:crypto").webcrypto` in setup. (This package's own suite runs Vitest on the `node` environment.)

The hash exports have no such requirement.

---

## Migrating stored data

**v2 ciphertext is forward-only: v1 cannot read it.** Sequence the rollout accordingly.

1. **Deploy v2 everywhere that *reads* the store first**, with `legacyDecryption: true`. At this point everything still reads; nothing has changed shape.
2. **Then let writes switch to v2.** Any reader still on v1 will fail on the new envelopes, so do not overlap this step with step 1.
3. **Re-encrypt at rest**, lazily on read or with a batch walk.
4. **Turn `legacyDecryption` off** once nothing legacy is left, and delete the fallback config. Until you do, the downgrade path in §4 is open.

### Lazy re-encryption on read

```ts
import { decrypt, encrypt, isLegacyCipher } from "@mongez/encryption";

async function read(key: string) {
  const stored = storage.getItem(key);

  if (!stored) return null;

  const value = await decrypt(stored, KEY, { legacyDecryption: true });

  // Upgrade in place the first time we touch an old value.
  if (isLegacyCipher(stored)) {
    storage.setItem(key, await encrypt(value, KEY));
  }

  return value;
}
```

### Batch migration

```ts
import {
  decrypt,
  encrypt,
  isEncryptionEnvelope,
  isLegacyCipher,
  clearKeyCache,
} from "@mongez/encryption";

async function migrateAll(rows: { id: string; cipher: string }[]) {
  const failures: string[] = [];

  for (const row of rows) {
    if (isEncryptionEnvelope(row.cipher)) continue; // already v2
    if (!isLegacyCipher(row.cipher)) {
      failures.push(row.id); // neither format — inspect by hand
      continue;
    }

    try {
      const value = await decrypt(row.cipher, KEY, { legacyDecryption: true });
      await db.update(row.id, { cipher: await encrypt(value, KEY) });
    } catch {
      // Wrong key, or a row that was already corrupt under v1 — where v1
      // returned null and you never noticed.
      failures.push(row.id);
    }
  }

  clearKeyCache();

  return failures;
}
```

Both helpers are pure string checks — they never decrypt, so a migration script can classify a store without holding the key.

### Expect some failures

v1 returned `null` for corrupt rows, so a store can carry damage nobody ever saw. v2 surfaces it. Log the failures, count them, and decide before you delete anything — a spike here may mean tampering rather than corruption.

---

## Things that did **not** change

- `md5`, `sha1`, `sha256`, `sha512` — same signatures, same digests, still synchronous. (`md5`/`sha1` are now marked `@deprecated` in JSDoc for new use; they still work.)
- The `{ data: value }` JSON wrapper, so `0`, `false` and `null` still round-trip, and `undefined`/functions still come back as `undefined`.
- `setEncryptionConfigurations` / `getEncryptionConfig` names and shallow-merge semantics.
- `key` fallback: per-call argument, then configuration, then `MissingEncryptionKeyError`.
- Ciphertext is still non-deterministic and still must never be compared for equality.

## New in 2.0 that you may want

- `tryDecrypt(cipher, key?, options?)` — null-on-failure decrypt.
- `EncryptionError`, `MissingEncryptionKeyError`, `DecryptionError`, `UnsupportedRuntimeError` — typed errors for `instanceof` branching.
- `resetEncryptionConfigurations()` — back to import-time defaults; useful in test setup.
- `clearKeyCache()` — drop memoised derived keys on logout or key rotation.
- `isEncryptionEnvelope()` / `isLegacyCipher()` / `parseEnvelope()` — inspect a ciphertext without decrypting it.
- `iterations` — tune the PBKDF2 work factor globally or per call; the value used is recorded in each envelope.

## Known incompatibility: `@mongez/cache` encrypted drivers

`EncryptedLocalStorageDriver` / `EncryptedSessionStorageDriver` call the configured `encrypt(...)` synchronously and write the result straight to storage. Given v2's async `encrypt`, they store `"[object Promise]"` and the value is lost. Until `@mongez/cache` supports an async encryption contract, pin `@mongez/encryption@^1` for that integration, or encrypt outside the cache:

```diff
- setCacheConfigurations({ encryption: { encrypt, decrypt } });
- cache.set("auth.accessToken", token);
+ cache.set("auth.accessToken", await encrypt(token, KEY));
```

Reads become `const token = await decrypt(cache.get("auth.accessToken"), KEY)`. Note that the cache's `{ data, expiresAt }` envelope is then no longer encrypted — wrap the expiry into the value yourself if that metadata is sensitive.
