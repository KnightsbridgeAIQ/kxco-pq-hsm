# kxco-pq-hsm

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM integration layer for the KXCO post-quantum stack. ML-DSA-65 signing and ML-KEM-768 decapsulation through a secure key boundary — the private key never leaves the HSM.

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
  is run against **2,103 NIST ACVP vectors (0 failed)** and a **225-check
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

**On-token.** Supply `mlDsaMechanism` and the key is generated on the token,
marked non-extractable, and signed with inside it. The private key never enters
host memory. This satisfies a control that says key material must not leave the
cryptographic boundary.

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

`signingMode` exists so that distinction is something you read, not something
you assume.

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
| PKCS#11 | `Pkcs11Backend` | Production key custody on an HSM you already run | **On-token** where the token offers an ML-DSA mechanism: the key is generated on it, marked non-extractable, and never enters host memory. Otherwise **wrapped**: the token holds an AES-256 key that never leaves it and the ML-DSA key is stored encrypted under it. `hsm.signingMode` says which |

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

## What this does NOT do

- **Not a general crypto library.** It does not expose raw ML-DSA or ML-KEM primitives. Use `kxco-post-quantum` for that.
- **Not responsible for key generation algorithms.** The underlying post-quantum primitives come from `kxco-post-quantum`; this package provides the storage and boundary layer only.
- **Not certificate management.** It does not issue, sign, or parse X.509 certificates.
- **Not a KMS.** It does not manage key rotation schedules, access policies, or audit logs. Those concerns belong to the application layer or to `kxco-pq-sdk`.

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

- **2,103 NIST ACVP vectors** across FIPS 203, 204 and 205, pinned by digest
- **225 interoperability checks** against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
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
