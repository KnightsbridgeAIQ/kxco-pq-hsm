# Changelog

## 1.4.0

### Added

**On-token key generation and signing.** `Pkcs11Backend.keygenOnToken` calls
`C_GenerateKeyPair` on the token with `CKA_EXTRACTABLE=false` and
`CKA_SENSITIVE=true`. The private key never enters host memory at any point,
signing is `C_Sign` through the token handle, and both objects are
`CKA_TOKEN=true` so a key survives a process restart and is located again by
`CKA_ID`. `PqHsm.keygen` prefers this path whenever the token offers both
mechanisms.

**Custody is proved, not advertised.** `signingMode` returns `'on-token'` only
after a probe signature has been produced through the token handle. A mechanism
list says what a token offers; only a signature says what happened. If the
token generates a pair and cannot sign with it, `keygenOnToken` throws rather
than returning a key that misreports its custody.

**Keys are destroyed on the token.** `deleteKey` calls `C_DestroyObject` on
both objects. Previously it removed a local map entry and left the private key
on the partition.

### Fixed

`entry.handle` is now assigned. It was read in three places and written in
none, which is why `signOnToken` threw `no token handle` for every key the
package generated.

`open()` repopulates the key store from token objects. Previously only the AES
wrapping key was reloaded and every generated key vanished with the process.

### Notes

The claim retracted in 1.3.2 is restored, and it is now owned by
`test/softhsm-integration.test.js` running against a real PKCS#11 token rather
than by a handwritten fake backend. 1.3.1 claimed it, 1.3.2 retracted it, 1.4.0
implements it.

No released SoftHSM can run that test: tag 2.7.0 has zero occurrences of
`CKM_ML_DSA` and support exists only on `master`. `ci/Dockerfile.softhsm`
builds it. The image deliberately uses Debian's `nodejs` rather than an
official tarball, because a bundled OpenSSL without ML-DSA captures the
token library's EVP calls and generation fails with `CKR_GENERAL_ERROR`.

This package remains a way to keep keys inside a module you already trust. It
is not a validated module and confers no FIPS 140-3 validation on anything.

## 1.3.2

### Corrected

Documentation only. No code change, no behaviour change.

The README claimed that where a token offers an ML-DSA mechanism, the key "is
generated on it, marked non-extractable, and never enters host memory." **The
code has never done this.**

- `PqHsm.keygen` generates the keypair in host memory with `ml_dsa65.keygen()`
  and passes the secret to the backend.
- `Pkcs11Backend.store` wraps that secret under the token-held AES key and
  records `{ alg, publicKey, iv, wrapped }`. No token object handle is stored.
- `signOnToken` requires `entry.handle`, which is read in three places and
  assigned in none, so it throws for every key this package generates.
- There is no `C_GenerateKeyPair` call anywhere in the package.

`signingMode === 'on-token'` therefore means only that the token advertises an
ML-DSA mechanism. It is not a measurement of where a key lives or where a
signature was produced, and it must not be presented to an auditor as one.

Also documented: `Pkcs11Backend` holds wrapped keys in a process-local `Map`.
The AES wrapping key is a persistent token object; the wrapped ML-DSA keys are
not persisted by the backend and do not survive a restart.

The package still does what it always did — private key material encrypted at
rest under a key the token will not release, zeroed after each use. That is a
real property. It is not never-leaves-the-module custody, and the previous
wording conflated the two.

On-token generation is a later release. It needs `C_GenerateKeyPair` with
`CKA_EXTRACTABLE=false`, a persisted object handle, `C_Sign` through that
handle, and a probe that exercises the real PKCS#11 path rather than a test
double. The old sentence can be restored when the code earns it.

## 1.2.0

### Corrected

The README claimed `@noble/post-quantum` was audited by Cure53 in 2024.
It is maintainer-audited (v0.6.1, April 2026), not Cure53-audited.

The other Noble packages were audited separately and at different dates, and
none of those engagements reached the post-quantum package:

| Package | Audited by |
|---|---|
| `@noble/post-quantum` | maintainer-audited |
| `@noble/hashes` | Cure53, Jan 2022, v1.0.0 |
| `@noble/curves` | Trail of Bits Feb 2023; Kudelski Sep 2023; Cure53 Sep 2024 |
| `@noble/ciphers` | Cure53, Sep 2024, v1.0.0 |

Dates from `kxco-post-quantum/audit/dependency-review.json`, which is generated
by `audit/run-audit.mjs` rather than written by hand.

Documentation only. No code changed and no behaviour changed.

### Pkcs11Backend now says what it actually does

The backend table described `Pkcs11Backend` as "Hardware-backed production;
FIPS 140-2/3", with the security property "private key material wrapped by an
AES-256 key that never leaves the HSM". The second half is true. The first half
invited a reading the code does not support.

**Signing does not happen on the token.** The HSM holds an AES-256 wrapping
key. To sign, the ML-DSA private key is unwrapped **into process memory**, used
by `mlDsa.sign`, and zeroed immediately afterwards (`hsm.js` does this in a
`finally` block). The key does exist in process memory during each signature.

That is still worth having — a stolen disk or database yields nothing without
the token — and it is materially weaker than what "HSM-backed signing" normally
means. No PKCS#11 token on the market signs ML-DSA-65 today, so this package
cannot ask one to, and no configuration will change that.

The "When to use this" section previously said this package suited
"deployments where private keys must never exist in process memory between
operations" and "compliance requirements such as FIPS 140-2/3, where a hardware
boundary is mandatory". The first is now scoped to *between* operations, which
is what is true. The second is removed: **this package is not a FIPS 140-2 or
140-3 validated module, and pairing it with a validated HSM does not make it
one.**

Version is 1.2.0 rather than 1.1.3 because a reader acting on the old table
could have made a compliance decision on it.
