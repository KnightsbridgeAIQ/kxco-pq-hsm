# kxco-pq-hsm

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM integration layer for the KXCO post-quantum stack. ML-DSA-65 signing and ML-KEM-768 decapsulation through a secure key boundary — the private key never leaves the HSM.

## When to use this

- Regulated institutions that need hardware-backed key storage
- Production deployments where private keys must never exist in process memory between operations
- Compliance requirements such as FIPS 140-2/3, where a hardware boundary is mandatory
- Any deployment where you want to audit and control every key operation through a single interface

If you are prototyping or running tests, use `MemoryBackend`. Move to `FileBackend` or `Pkcs11Backend` before any production deployment.

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
| PKCS#11 | `Pkcs11Backend` | Hardware-backed production; FIPS 140-2/3 | Private key material wrapped by an AES-256 key that never leaves the HSM |

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

Cryptographic operations are provided by [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum), [Noble hashes](https://github.com/paulmillr/noble-hashes), and [Noble ciphers](https://github.com/paulmillr/noble-ciphers) — independently audited by Cure53 (2024). All ML-DSA-65 and ML-KEM-768 operations conform to NIST FIPS 204 and FIPS 203. Secret key material is held in memory only for the duration of a single operation and zeroed immediately after.

To report a vulnerability, open a [private security advisory](https://github.com/JackKXCO/kxco-pq-hsm/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
