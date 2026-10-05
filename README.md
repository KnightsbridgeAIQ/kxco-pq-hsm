# kxco-pq-hsm

**Post-quantum key custody on the HSM you already run: ML-DSA-65 keys generated on the token and signed on the token.**

[![npm](https://img.shields.io/npm/v/kxco-pq-hsm?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-hsm?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-hsm)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-hsm)](https://socket.dev/npm/package/kxco-pq-hsm)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-hsm.svg)](https://nodejs.org)

HSM integration layer for the KXCO post-quantum stack. ML-DSA-65 signing and ML-KEM-768 decapsulation, with private key material held on the token or encrypted at rest under a key the token never releases.

- **Keys born on the token.** Supply an ML-DSA mechanism and `keygen` calls `C_GenerateKeyPair` on the token. The private object is `CKA_EXTRACTABLE=false` and `CKA_SENSITIVE=true`, the private key never enters host memory, and signing is `C_Sign` through the token handle.
- **Custody you can prove.** `signingMode` reports `'on-token'` only after a probe signature has gone through that handle. A mechanism list is an advertisement; a signature is evidence.
- **Keys that survive a restart.** On-token keys are `CKA_TOKEN=true` objects, found again by `CKA_ID`.
- **Works with the tokens institutions run.** PKCS#11 hardware such as Thales Luna, Utimaco and YubiKey HSM2, with SoftHSM2 for testing.
- **Three backends, one API.** In-memory for development, an Argon2id and AES-256-GCM encrypted file for hardware-free production, and PKCS#11 for the HSM.
- **Tested on a real token.** The on-token path is owned by an integration test against a real PKCS#11 token.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Backends](#backends) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

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
and **refuses to start** if it is absent, so a control you configured is a
control in force.

**Wrapped.** Omit `mlDsaMechanism` and the token holds an AES-256 key that never
leaves it, with the ML-DSA key stored encrypted under it. To sign, the key is
unwrapped into host memory, used, and zeroed. A stolen disk, database or backup
yields nothing without the token. For a never-leaves-the-boundary control, use
on-token mode.

Wrapped keys are held for the life of the process; the AES wrapping key is a
persistent token object but the wrapped ML-DSA blobs are not written to the
token, so persist them yourself when you need them across restarts.
**On-token keys persist on the token**, because they are token objects.

## Deploying on certified hardware

- **Your HSM's certificate does the certifying.** Where a control framework asks
  for FIPS 140-3 Level 3 custody, the HSM's certificate is what satisfies it, and
  on-token mode is how this package keeps the key inside that HSM.
- **SoftHSM2 is the test token.** The integration suite runs against it, and
  production keys belong on hardware.
- **`signingMode` is reported per token.** Wrapped and on-token keys can sit on
  one backend side by side.
- **ML-DSA generates and signs on the token.** ML-KEM decapsulation runs through
  the wrapped path.

## Testing on-token custody

The on-token path is owned by an integration test against a real PKCS#11
token. SoftHSM's ML-DSA support lives on its `master` branch, and
`ci/Dockerfile.softhsm` builds it against OpenSSL 3.5, which is where ML-DSA
lives.

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

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

### `new PqHsm(backend)`

Accepts any backend instance as its only argument.

### Methods

```ts
hsm.keygen(label: string, alg?: 'ml-dsa-65' | 'ml-dsa-87' | 'ml-kem-768'): Promise<{ publicKey: Uint8Array }>
```
Generate and store a keypair. Returns the public key only. Default algorithm is `'ml-dsa-65'`. The ML-DSA strength is chosen per key: pass `'ml-dsa-87'` for an ML-DSA-87 key (2592-byte public key, 4627-byte signatures). On a token that generates on the token, the parameter set is written to `CKA_PARAMETER_SET` (`CKP_ML_DSA_65` = 0x2, `CKP_ML_DSA_87` = 0x3), and the public key the token returns is checked against the set asked for.

```ts
hsm.sign(label: string, message: Uint8Array | Buffer): Promise<Uint8Array>
```
Sign `message` with the ML-DSA key stored at `label`, under the parameter set the key was generated with. Returns the signature: 3309 bytes for ML-DSA-65, 4627 for ML-DSA-87. A key whose stored bytes are the size of the other set is refused rather than used.

```ts
hsm.decapsulate(label: string, ciphertext: Uint8Array | Buffer): Promise<Uint8Array>
```
Decapsulate a KEM ciphertext with the ML-KEM-768 key at `label`. Returns the shared secret.

```ts
hsm.getPublicKey(label: string): Promise<Uint8Array>
```
Return the public key for `label` without performing any signing operation. An ML-DSA public key whose size is not that of its stored set is refused.

```ts
hsm.listKeys(): Promise<Array<{ label: string, alg: 'ml-dsa-65' | 'ml-dsa-87' | 'ml-kem-768' }>>
```
List all stored key labels and their algorithms. For a key found on a PKCS#11 token, the algorithm is read back from the token's `CKA_PARAMETER_SET`. A key whose value is not ML-DSA-65 or ML-DSA-87 (ML-DSA-44 included), or cannot be read, is not loaded, and using its label is refused with the reason.

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
  mlDsaMechanism?:           number  // The token's ML-DSA mechanism; enables on-token keys
  mlDsaKeyPairGenMechanism?: number  // Default 0x1c (CKM_ML_DSA_KEY_PAIR_GEN)
})
// Call .open() before passing to PqHsm; call .close() when done.
```

The parameter set is a property of each key, not of the backend. The
undocumented `parameterSet` option of 1.4.x is refused for any value other than
the old ML-DSA-65 default; pass the algorithm to `keygen` instead.

### Error class

```ts
import { KxcoPqHsmError } from 'kxco-pq-hsm'
```
All errors thrown by this package are instances of `KxcoPqHsmError`.

## Works with the rest of the stack

In `kxco-pq-sdk`, pass your `PqHsm` wherever a keypair is expected:

```js
import { PqHsm, FileBackend } from 'kxco-pq-hsm'
import { AuditedHsm } from 'kxco-pq-sdk'

const hsm = new PqHsm(new FileBackend({ path: './keys.json', password: process.env.HSM_PASSWORD }))
const audited = new AuditedHsm(hsm, auditLog)
```

## The KXCO post-quantum family

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.1.0 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-hsm@<version>`. A CycloneDX
SBOM is published, from v1.1.1, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-65** (NIST FIPS 204) and **ML-KEM-768** (NIST FIPS 203) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.0: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.1
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

In wrapped and file modes, secret key material is held in memory only for a single operation and zeroed immediately afterwards. In on-token mode it never enters host memory at all.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan · John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
