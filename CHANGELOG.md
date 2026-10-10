# Changelog

## 1.8.0 (2026-10-10)

ML-KEM-1024 keys. `keygen(label, 'ml-kem-1024')` generates an ML-KEM-1024 key
(FIPS 203, Category 5: 1568-byte public key and ciphertext, 3168-byte secret
key) in the memory and file backends. New keys in KXCO's packages and platform
services use ML-KEM-1024 (FIPS 203, Category 5); ML-KEM-768 keys made earlier
keep decrypting.

`decapsulate` dispatches on the algorithm stored with the key. An
`ml-kem-768` entry works unchanged: a store written by 1.7.0 is read by 1.8.0,
alone and after a 1024 key is added to it. A key of one set is not used as the
other: a 768 ciphertext against a 1024 key (or the reverse) is refused, and so
is an entry whose stored secret key is the size of the other set. A damaged
ciphertext of the right length still gives an unrelated secret, as FIPS 203
implicit rejection specifies.

Nothing changes for ML-DSA. On-token PKCS#11 generation stays ML-DSA only.
Typings and the README name the new algorithm.

## 1.7.0 (2026-10-09)

Runtime support. No change to the API or its behaviour.

**Node.js 22.12 or later is required.** `engines.node` moves from `>=20.19`
to `>=22.12`. Node 20 reached end of life on 30 April 2026. 22.12 is the
first Node 22 release that loads ES modules through `require()` without a
flag, the same property the 20.19 floor provided.

**CI tests every change on Node 22, 24 and 26.** It tested Node 20 alone before.

**Releases are built on Node 26**, where they were built on Node 22.
Node 26 ships npm 11.20, which already carries Trusted Publishing, so the
release job no longer downloads npm 11 separately.

## 1.6.0 (2026-10-07)

ML-DSA-87 is the default. `keygen(label)` with no algorithm now generates an
ML-DSA-87 key, with a 2592-byte public key and 4627-byte signatures, in every
backend. On a token that generates the key itself, `CKA_PARAMETER_SET` is
written as `CKP_ML_DSA_87` (0x3). `keygenOnToken` defaults to ML-DSA-87 in the
same way.

Passing `'ml-dsa-65'` keeps the old behaviour: `keygen(label, 'ml-dsa-65')`
generates an ML-DSA-65 key exactly as before. A Pkcs11Backend constructed with
the 1.4.x option `parameterSet: 0x2` asked for ML-DSA-65, so it keeps
generating ML-DSA-65 when `keygen` is given no algorithm.

Existing keys are unaffected. A key signs under the parameter set it was
generated with, so every ML-DSA-65 key already in a memory, file or PKCS#11
store, or on a token, signs and verifies as ML-DSA-65. The store format is
unchanged.

## 1.5.1

Documentation. No source change.

The package description, the opening of the README and the keywords now say
what 1.5.0 already does: keys are generated and signed with ML-DSA-87 as well
as ML-DSA-65. `ml-dsa-87` joins the keywords.

## 1.5.0
ML-DSA strength is chosen per key. `keygen` takes `'ml-dsa-87'` beside
`'ml-dsa-65'`, the default, in every backend. A key signs under the set it was
generated with, and a key whose stored secret or public key is the size of the
other set is refused by `sign` and `getPublicKey` rather than used.

Pkcs11Backend writes the key's set to `CKA_PARAMETER_SET` on the token
(`CKP_ML_DSA_87` = 0x3 beside `CKP_ML_DSA_65` = 0x2, the PKCS#11 v3.2 values),
and PqHsm checks that the public key a token returns is the size of the set it
asked for. When a later process restores keys from the token, the parameter set
is read back from `CKA_PARAMETER_SET`, on the private object and then the
public one. Through 1.4.6 every key found on the token was labelled ml-dsa-65
without reading it. A key whose value is unknown, ML-DSA-44 included, or
cannot be read is not loaded, and using its label is refused with the reason.
The backend-wide `parameterSet` option is refused for any value other than the
old ML-DSA-65 default.

The kxco-post-quantum floor is raised to 1.6.0. Keys and stores written by
1.4.x, and every ML-DSA-65 signature they make, are unchanged.

## 1.4.6

PqHsm signs a text message as its UTF-8 bytes and a typed array or DataView as
the bytes it covers. Any other message or ciphertext is refused, and a label
must be a non-empty string.

FileBackend requires a password that is a non-empty string or bytes, keeps
labels as own keys so a label such as `constructor` is an ordinary key, keeps
memory in step with the store when a write fails, and reports a wrong password,
a damaged or unreadable store and malformed input as KxcoPqHsmError.
Pkcs11Backend reports a failed PKCS#11 call as KxcoPqHsmError. The store format
is unchanged.

## 1.4.5

Documentation. No source change.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.4.4

Documentation. No source change.

The release-integrity lines now name the version that SLSA provenance and
the CycloneDX SBOM start from, and the keyword list drops `quantum-safe`,
which was removed on purpose in an earlier release.

Every GitHub Action in CI is now pinned by commit SHA, as the page states.

## 1.4.3

Documentation. No source change.

**The npm page leads with what the package proves.** The first screen now leads with on-token custody, the proof behind
`signingMode`, the tokens it runs on and the migration dates set by NIST,
Executive Order 14412, OMB M-26-15 and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

## 1.4.2

Documentation. No source change.

**ASSESSMENT.md rewritten.** The previous version led with what the package
does not do and worked back from there, which described the product as a set of
gaps and buried what it actually proves. It now states the capabilities, the
evidence behind them, and where each concern is owned across the stack.

Nothing has been softened away. Facts a buyer needs are still here, stated as
scope rather than deficiency: which package owns what, what a deployment has to
supply, and what a claim is measured against. The change is which way round they
are told.

## 1.4.1

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**`npm run evidence` now exists.** The README already told you to run it and
there was no such script, so the command failed for anyone who followed it.
The bundle records identity, this package's own tests, its SBOM, registry
signature verification, and the `kxco-post-quantum` version actually installed
rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.4.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

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
