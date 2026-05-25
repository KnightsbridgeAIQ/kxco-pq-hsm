# kxco-pq-hsm

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM-backed post-quantum key management: ML-DSA-65 signing and ML-KEM-768 decapsulation through a hardware security module boundary. Secret keys are decrypted, used, and zeroed in one atomic operation — they never rest in plaintext memory between calls. Three backends: in-memory (dev), Argon2id-encrypted file, and PKCS#11 (SoftHSM2, Luna, Utimaco, YubiKey).

## Install

```
npm install kxco-pq-hsm
```

For PKCS#11 hardware:

```
npm install kxco-pq-hsm pkcs11js
```

## Quick start

```js
import { PqHsm, FileBackend } from 'kxco-pq-hsm'
import { mlDsa } from 'kxco-post-quantum'

const hsm = new PqHsm(new FileBackend({
  path: './hsm-keys.json',
  password: process.env.HSM_PASSWORD,
}))

const { publicKey } = await hsm.keygen('prod-signing', 'ml-dsa-65')

const message = new TextEncoder().encode('payload')
const signature = await hsm.sign('prod-signing', message)

mlDsa.ml_dsa65.verify(publicKey, message, signature) // true
```

## Backends

### `MemoryBackend`

In-memory. Keys lost on process exit. Use for development and testing.

```js
import { PqHsm, MemoryBackend } from 'kxco-pq-hsm'
const hsm = new PqHsm(new MemoryBackend())
```

### `FileBackend`

Argon2id (t=3, m=65536, p=1) + AES-256-GCM. Keys persist in a single JSON file. OWASP-minimum KDF parameters.

```js
import { PqHsm, FileBackend } from 'kxco-pq-hsm'
const hsm = new PqHsm(new FileBackend({ path: './keys.json', password: 'passphrase' }))
```

### `Pkcs11Backend`

Keys are wrapped by an AES-256 key that never leaves the hardware. Requires `pkcs11js` (optional peer dependency).

```js
import { PqHsm, Pkcs11Backend } from 'kxco-pq-hsm'

const backend = await new Pkcs11Backend({
  libraryPath: '/usr/lib/softhsm/libsofthsm2.so',
  slot: 0,
  pin: process.env.HSM_PIN,
}).open()

const hsm = new PqHsm(backend)
// ... use hsm ...
await backend.close()
```

## API

```js
const hsm = new PqHsm(backend)

await hsm.keygen(label, alg)       // alg: 'ml-dsa-65' | 'ml-kem-768'
await hsm.sign(label, message)     // → Uint8Array signature
await hsm.decapsulate(label, ct)   // → Uint8Array sharedSecret
await hsm.getPublicKey(label)      // → Uint8Array
await hsm.listKeys()               // → [{ label, alg }]
await hsm.deleteKey(label)
```

## Related packages

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 / ML-KEM-768 primitives |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation envelopes |
| [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) | Tamper-evident operation log |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | `AuditedHsm` + `KxcoIdentity` |

## Security

Cryptographic operations are provided by [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum), [Noble hashes](https://github.com/paulmillr/noble-hashes), and [Noble ciphers](https://github.com/paulmillr/noble-ciphers) — independently audited by Cure53 (2024). All ML-DSA-65 and ML-KEM-768 operations conform to NIST FIPS 204 and FIPS 203. Secret key material is held in memory only for the duration of a single operation and zeroed immediately after.

To report a vulnerability, open a [private security advisory](https://github.com/JackKXCO/kxco-pq-hsm/security/advisories/new) or email **security@kxco.ai**.

## Funding

Maintained by **Shayne Heffernan** and **John Heffernan** at [KXCO by Knightsbridge](https://kxco.ai).

[Knightsbridge Law](https://knightsbridge.law) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
