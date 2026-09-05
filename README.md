# kxco-pq-hsm

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM integration layer for the KXCO post-quantum stack. ML-DSA-65 signing and ML-KEM-768 decapsulation, with private key material encrypted at rest under a key the token never releases.

On-token custody, where the token supports it. Supply an ML-DSA mechanism and
`keygen` calls `C_GenerateKeyPair` on the token: the private object is
`CKA_EXTRACTABLE=false` and `CKA_SENSITIVE=true`, the private key never enters
host memory at any point, and signing is `C_Sign` through the token handle.
Both objects are `CKA_TOKEN=true`, so a key survives a process restart and is
found again by `CKA_ID`.

`signingMode` reports `'on-token'` **only after a probe signature has actually
been produced through that handle.** A mechanism list is an advertisement; a
signature is evidence. Where the token cannot generate or sign, the key is
wrapped under a token-held AES key instead and `signingMode` says `'wrapped'`,
which enters host memory to sign and does not meet a never-leaves-the-boundary
control.

> **History, and why this paragraph is worded carefully.** 1.3.1 claimed
> on-token custody with no `C_GenerateKeyPair` anywhere in the package and no
> token handle ever stored, so `signOnToken` threw for every key it generated.
> 1.3.2 retracted the claim without changing behaviour. **1.4.0 implements it**,
> and the claim is now owned by an integration test against a real PKCS#11
> token — not by the handwritten fake backend that let the original claim ship.

## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-hsm@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

## When to use this

- Regulated institutions that need private keys encrypted at rest under a key held in hardware
- Production deployments where private keys must not sit in process memory **between** operations
- Any deployment where you want to audit and control every key operation through a single interface

### How `Pkcs11Backend` protects a key

Two modes, and the package tells you which one is in force:

```js
const hsm = new PqHsm(new Pkcs11Backend({
  libraryPath: '/usr/lib/softhsm/libsofthsm2.so',
  pin: process.env.HSM_PIN,
  mlDsaMechanism: 0x0000001d,   // your token's ML-DSA mechanism
}))
hsm.signingMode   // 'on-token' | 'in-process'
```

**On-token.** Supply `mlDsaMechanism` and `keygen` generates the key pair on
the token with `C_GenerateKeyPair`. The private object is marked
`CKA_EXTRACTABLE=false` and `CKA_SENSITIVE=true`; this process never receives
the private bytes, so there is nothing to zero afterwards because nothing was
ever held. Signing is `C_Sign` through the token handle.

`signingMode` becomes `'on-token'` only once a probe signature has gone through
that handle. If the token generates a pair and then cannot sign with it,
`keygen` throws rather than returning a key that reports custody it does not
have.

The mechanism value is yours to supply, not ours to guess. PKCS#11 gained
ML-DSA mechanisms in v3.2 and tokens that shipped PQ firmware earlier expose it
under a vendor-defined value, so there is no constant that is right across an
estate. `open()` checks the value against the token's own `C_GetMechanismList`
and **refuses to start** if it is absent — a silent fallback would leave you
believing a control is in force when it is not.

**Wrapped.** Omit `mlDsaMechanism` and the token holds an AES-256 key that never
leaves it, with the ML-DSA key stored encrypted under it. To sign, the key is
unwrapped into host memory, used, and zeroed. A stolen disk, database or backup
yields nothing without the token — but the key is in memory for the duration of
each signature, so this does not meet a never-leaves-the-boundary control.

Wrapped keys are held for the life of the process; the AES wrapping key is a
persistent token object but the wrapped ML-DSA blobs are not written to the
token, so they do not survive a restart. Persist them yourself if you need
them to. **On-token keys do survive**, because they are token objects.

## What this package does not do

Stated plainly, because the only people who read this page are the ones for
whom it matters.

- **It is not a validated cryptographic module**, and using it confers no FIPS
  140-3 validation of any level on your software. A certificate covers the
  module it was issued for. If your control framework requires Level 3 custody,
  what satisfies it is the HSM's certificate, and what this package does is let
  you keep the key inside that HSM.
- **SoftHSM is a software token.** It is what the integration tests run
  against, and it is for testing. A SoftHSM key is not in Level 3 custody
  however the mechanism list reads.
- **`signingMode` is per token, not per key.** It tells you whether a probe
  signature succeeded on this backend, not that every key on it is on-token. A
  wrapped key and an on-token key can coexist.
- **Wrapped keys are not persisted to the token** and do not survive a restart.
  On-token keys do.
- **ML-KEM is wrapped only.** `decapsulate` always unwraps into host memory.
  On-token generation covers ML-DSA.

## Testing on-token custody

The on-token path is owned by an integration test against a real PKCS#11
token, because a fake backend that implements `signOnToken` will pass
regardless of what the package does. That is how the original claim shipped.

No released SoftHSM can run it: tag 2.7.0 contains zero occurrences of
`CKM_ML_DSA`, and support exists only on `master`. `ci/Dockerfile.softhsm`
builds it against OpenSSL 3.5, which is where ML-DSA lives.

```
docker build -f ci/Dockerfile.softhsm -t kxco-softhsm-mldsa .
docker run --rm -v "$PWD":/work:ro kxco-softhsm-mldsa bash -lc '
  mkdir -p /b && cd /b && cp -r /work/src /work/test /work/package.json .
  npm install --silent kxco-post-quantum pkcs11js
  export HSM_LIBRARY_PATH=/opt/softhsm/lib/softhsm/libsofthsm2.so HSM_PIN=1234
  node --test test/softhsm-integration.test.js'
```

**Use a Node that links the system OpenSSL.** An official Node tarball bundles
its own (22.x bundles 3.0.15, which has no ML-DSA), and because `pkcs11js`
dlopens the token library into that process, SoftHSM's `EVP_PKEY_CTX_new_from_name`
binds to Node's OpenSSL instead of the 3.5 it was compiled against. The token
then returns `CKR_GENERAL_ERROR` and its log reads `ML-DSA keygen context
failed (0x0308010C)` while the identical call in a C program succeeds. The
image uses Debian's `nodejs` for this reason.

## Install

```
npm install kxco-pq-hsm
```

For PKCS#11 hardware (SoftHSM2, Thales Luna, Utimaco, YubiKey HSM2):

```
npm install kxco-pq-hsm pkcs11js
```

## Backends

| Backend | Class | Use case | Security properties |
|---|---|---|---|
| In-memory | `MemoryBackend` | Development and testing | Keys lost on process exit; no persistence |
| Encrypted file | `FileBackend` | Lightweight production; no hardware required | Argon2id (t=3, m=65536, p=1) + AES-256-GCM; keys at rest are encrypted |
| PKCS#11 | `Pkcs11Backend` | Production key custody on an HSM you already run | **On-token** where the token offers ML-DSA generation and signing: `C_GenerateKeyPair` on the token, `CKA_EXTRACTABLE=false`, `C_Sign` through the handle, key survives restart, and `signingMode` says `on-token` only after a probe signature proved it. Otherwise **wrapped**: the token holds an AES-256 key that never leaves it and the ML-DSA key is stored encrypted under it, entering host memory to sign |

## Quick start

### MemoryBackend

```js
import { PqHsm, MemoryBackend } from 'kxco-pq-hsm'

const hsm = new PqHsm(new MemoryBackend())

const { publicKey } = await hsm.keygen('signing-key', 'ml-dsa-65')
const message = new TextEncoder().encode('payload')
const signature = await hsm.sign('signing-key', message)
```

### FileBackend

```js
import { PqHsm, FileBackend } from 'kxco-pq-hsm'

const hsm = new PqHsm(new FileBackend({
  path: './hsm-keys.json',
  password: process.env.HSM_PASSWORD,
}))

const { publicKey } = await hsm.keygen('prod-signing', 'ml-dsa-65')
const message = new TextEncoder().encode('payload')
const signature = await hsm.sign('prod-signing', message)
```

The key store file is created automatically on first use. The password is run through Argon2id (OWASP-minimum parameters) before any key material is encrypted.

### Pkcs11Backend

```js
import { PqHsm, Pkcs11Backend } from 'kxco-pq-hsm'

const backend = await new Pkcs11Backend({
  libraryPath: '/usr/lib/softhsm/libsofthsm2.so',
  slot: 0,
  pin: process.env.HSM_PIN,
}).open()

const hsm = new PqHsm(backend)

const { publicKey } = await hsm.keygen('prod-signing', 'ml-dsa-65')
const message = new TextEncoder().encode('payload')
const signature = await hsm.sign('prod-signing', message)

await backend.close()
```

The PKCS#11 backend stores an AES-256 wrapping key on the hardware token. All private key blobs are wrapped by that key; the plaintext private key exists in process memory only for the duration of a single sign or decapsulate call, then zeroed.

## API

### `new PqHsm(backend)`

Accepts any backend instance as its only argument.

### Methods

```ts
hsm.keygen(label: string, alg?: 'ml-dsa-65' | 'ml-kem-768'): Promise<{ publicKey: Uint8Array }>
```
Generate and store a keypair. Returns the public key only. Default algorithm is `'ml-dsa-65'`.

```ts
hsm.sign(label: string, message: Uint8Array | Buffer): Promise<Uint8Array>
```
Sign `message` with the ML-DSA-65 key stored at `label`. Returns the signature.

```ts
hsm.decapsulate(label: string, ciphertext: Uint8Array | Buffer): Promise<Uint8Array>
```
Decapsulate a KEM ciphertext with the ML-KEM-768 key at `label`. Returns the shared secret.

```ts
hsm.getPublicKey(label: string): Promise<Uint8Array>
```
Return the public key for `label` without performing any signing operation.

```ts
hsm.listKeys(): Promise<Array<{ label: string, alg: 'ml-dsa-65' | 'ml-kem-768' }>>
```
List all stored key labels and their algorithms.

```ts
hsm.deleteKey(label: string): Promise<void>
```
Permanently delete the key at `label`.

### Backend classes

```ts
new MemoryBackend()

new FileBackend(options: {
  path:     string           // Path to the encrypted JSON key store
  password: string | Uint8Array  // Passphrase for Argon2id key derivation
})

new Pkcs11Backend(options: {
  libraryPath:   string   // Path to PKCS#11 shared library
  slot?:         number   // Slot index, default 0
  pin:           string   // HSM user PIN
  wrapKeyLabel?: string   // Label for the AES-256 wrapping key, default "kxco-pq-wrap"
})
// Call .open() before passing to PqHsm; call .close() when done.
```

### Error class

```ts
import { KxcoPqHsmError } from 'kxco-pq-hsm'
```
All errors thrown by this package are instances of `KxcoPqHsmError`.

## Where this fits

The boundary between a key and the application that uses it. It signs and
decapsulates through a token, an HSM-held wrapping key, or an encrypted file,
and reports which of those is in force.

- [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) for raw ML-DSA and ML-KEM primitives
- [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) for a tamper-evident record of what was signed
- Rotation schedules and access policy belong to your KMS or your application

## Part of the KXCO stack

`kxco-pq-hsm` sits between the raw post-quantum primitives and the application layer:

```
kxco-post-quantum   — ML-DSA-65 / ML-KEM-768 primitives (NIST FIPS 204 / 203)
kxco-pq-hsm         — key storage and boundary (this package)
kxco-pq-sdk         — AuditedHsm, KxcoIdentity, attested envelopes
```

In `kxco-pq-sdk`, pass a `PqHsm` instance wherever a keypair is expected:

```js
import { PqHsm, FileBackend } from 'kxco-pq-hsm'
import { AuditedHsm } from 'kxco-pq-sdk'

const hsm = new PqHsm(new FileBackend({ path: './keys.json', password: process.env.HSM_PASSWORD }))
const audited = new AuditedHsm(hsm, auditLog)
```

Related packages:

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 / ML-KEM-768 primitives |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation envelopes |
| [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) | Tamper-evident operation log |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | `AuditedHsm` + `KxcoIdentity` |

## Security

**ML-DSA-65** (NIST FIPS 204) and **ML-KEM-768** (NIST FIPS 203) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **2,103 NIST ACVP vectors** across FIPS 203, 204 and 205, pinned by digest: 1,793 passed, 0 failed, 310 skipped, where each skip is the library refusing a pre-hash weaker than the parameter set
- **225 interoperability checks passed, 0 failed, 42 not applicable** against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every published release — verify with `npm audit signatures`
- **CycloneDX SBOM** published with each release
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Secret key material is held in memory only for the duration of a single operation and zeroed immediately afterwards.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
