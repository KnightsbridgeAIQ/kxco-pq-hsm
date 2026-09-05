# kxco-pq-hsm

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM integration layer for the KXCO post-quantum stack. ML-DSA-65 signing and ML-KEM-768 decapsulation, with private key material encrypted at rest under a key the token never releases.

> **Custody notice, 5 September 2026.** Earlier versions of this README, up to
> and including 1.3.1, said that where a token offers an ML-DSA mechanism the
> key "is generated on it, marked non-extractable, and never enters host
> memory." **The code does not do that, and never has.** `PqHsm.keygen`
> generates the keypair in host memory, and the PKCS#11 backend stores it
> encrypted under a token-held AES key without recording a token object handle.
> `signOnToken` therefore fails for every key this package generates.
>
> `signingMode === 'on-token'` reports only that **the token advertises an
> ML-DSA mechanism**. It is not a measurement of where a given key lives or
> where a signature was produced. Do not read it as a custody claim, and do not
> put it in front of an auditor as one.
>
> On-token key generation is not implemented in 1.3.x. It requires
> `C_GenerateKeyPair` with a non-extractable private object and a persisted
> object handle. Until that ships, this package does not satisfy a control that
> requires key material never to leave a cryptographic module. See
> [What this package does not do](#what-this-package-does-not-do).

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

**`mlDsaMechanism` is a mechanism check, not a custody switch.** Supplying it
makes `open()` verify that the token advertises that mechanism, and makes
`signingMode` report `'on-token'`. It does **not** cause the key to be
generated on the token: `PqHsm.keygen` runs `ml_dsa65.keygen()` in host memory
and hands the secret to the backend to wrap. Because no token object handle is
recorded, `signOnToken` throws `no token handle` for every such key, so a
configuration that reports `'on-token'` will fail to sign rather than sign
insecurely.

If you need a custody fact rather than an advertisement, take one signature
with the key and observe whether it went through the token. That is what KXCO
Command does at key generation, recording `hsm-on-token` only when a token
demonstrably produced the signature, and `hsm-in-process` otherwise.

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

This is what the PKCS#11 backend actually does in 1.3.x, in both modes.

Note also that the wrapped keys are held in a `Map` for the life of the
process. The AES wrapping key is a persistent token object; the wrapped ML-DSA
keys are not persisted anywhere by this backend, so they do not survive a
restart. Persist the wrapped material yourself if you need it to.

## What this package does not do

Stated plainly, because the only people who read this page are the ones for
whom it matters.

- **It does not generate keys on a token.** There is no `C_GenerateKeyPair`
  call anywhere in the package. Keys are generated in host memory by
  `PqHsm.keygen`.
- **It does not keep private keys inside a cryptographic boundary.** The
  private key exists in host memory at generation, and again on every signature
  in wrapped mode, where it is zeroed after use.
- **It does not record token object handles**, so `signOnToken` cannot address
  a key on the token and throws for every key the package generates.
- **`signingMode` is not a custody measurement.** It reflects the token's
  advertised mechanism list.
- **It is not a validated cryptographic module** and does not confer FIPS 140-3
  validation of any level on the software that uses it. A module's certificate
  covers that module. SoftHSM is a software token and is for testing.

What it does do is keep private key material encrypted at rest under a key your
HSM holds and will not release, and zero the plaintext after each use. That is
a real and useful property. It is not the same property as key material never
leaving a module, and this page previously conflated the two.

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
| PKCS#11 | `Pkcs11Backend` | Encrypting keys under a wrapping key your HSM holds | The token holds a persistent, non-extractable AES-256 key; the ML-DSA key is generated in host memory, stored encrypted under it, and unwrapped to sign. `signingMode` reports whether the token advertises an ML-DSA mechanism, **not** where a key lives. On-token generation is not implemented — see the custody notice. Wrapped keys are held in process memory and are not persisted by this backend |

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
