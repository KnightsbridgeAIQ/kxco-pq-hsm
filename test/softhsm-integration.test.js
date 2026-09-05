// On-token custody, against a real PKCS#11 token.
//
// This file owns the on-token claim. The handwritten fake backend in
// signing-mode.test.js proves the PqHsm facade routes correctly; it cannot
// prove anything about custody, because a fake that implements signOnToken
// will always pass. That is how 1.3.1 shipped a README claiming on-token
// generation with no C_GenerateKeyPair anywhere in the package.
//
// Requires a token that offers CKM_ML_DSA and CKM_ML_DSA_KEY_PAIR_GEN. No
// released SoftHSM has these: 2.7.0 contains zero occurrences of CKM_ML_DSA,
// and support exists only on master. ci/Dockerfile.softhsm builds it.
//
//   docker build -f ci/Dockerfile.softhsm -t kxco-softhsm-mldsa .
//   docker run --rm -v "$PWD":/work kxco-softhsm-mldsa \
//     sh -lc 'npm ci --no-audit --no-fund && npm run test:softhsm'
//
// Skipped when HSM_LIBRARY_PATH is unset so `npm test` stays offline. It is
// NOT skipped for any other reason: if the library is present and the token
// cannot do on-token ML-DSA, these fail rather than pass quietly.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'

const LIB = process.env.HSM_LIBRARY_PATH || null
const PIN = process.env.HSM_PIN || '1234'
const skip = LIB ? false : 'HSM_LIBRARY_PATH is not set'

const CKM_ML_DSA = 0x1d
const CKM_ML_DSA_KEY_PAIR_GEN = 0x1c

let Pkcs11Backend, PqHsm
let backend = null

/** A fresh backend over the same token, as a restarted process would see it. */
async function openBackend() {
  const b = new Pkcs11Backend({
    libraryPath: LIB,
    pin: PIN,
    slot: Number(process.env.HSM_SLOT ?? 0),
    mlDsaMechanism: CKM_ML_DSA,
    mlDsaKeyPairGenMechanism: CKM_ML_DSA_KEY_PAIR_GEN,
  })
  await b.open()
  return b
}

before(async () => {
  if (skip) return
  ;({ Pkcs11Backend, PqHsm } = await import('../src/index.js'))
  backend = await openBackend()
})

after(async () => {
  if (skip || !backend) return
  try { backend.close() } catch { /* best-effort */ }
})

const label = () => `kxco-it-${Date.now()}-${Math.floor(Math.random() * 1e6)}`

test('the token advertises ML-DSA signing and ML-DSA key-pair generation', { skip }, async () => {
  assert.ok(backend.mechanisms.includes(CKM_ML_DSA),
    'token does not offer CKM_ML_DSA — this is not an ML-DSA-capable build')
  assert.ok(backend.mechanisms.includes(CKM_ML_DSA_KEY_PAIR_GEN),
    'token does not offer CKM_ML_DSA_KEY_PAIR_GEN')
  assert.equal(backend.canGenerateOnToken, true)
})

test('keygen calls C_GenerateKeyPair and the private key is non-extractable', { skip }, async () => {
  const hsm = new PqHsm(backend)
  const l = label()
  const { publicKey } = await hsm.keygen(l, 'ml-dsa-65')

  // ML-DSA-65 public keys are 1952 bytes.
  assert.equal(publicKey.length, 1952, 'not an ML-DSA-65 public key')

  // The private key must not come back out. loadSecret is the only route that
  // would return private bytes, and for a token-generated key there is no
  // wrapped blob for it to decrypt.
  await assert.rejects(() => backend.loadSecret(l), /non-extractable|no wrapped|not found|point of it/i,
    'the token released private material for a CKA_EXTRACTABLE=false object')
})

test('signingMode is on-token only after a probe signature through the handle', { skip }, async () => {
  const hsm = new PqHsm(backend)
  const l = label()
  await hsm.keygen(l, 'ml-dsa-65')

  // keygenOnToken probes before returning, so by here it is established.
  assert.equal(backend.signingMode, 'on-token')
  assert.equal(hsm.signingMode, 'on-token')

  // And a backend that advertises the mechanism but has never signed must not
  // claim on-token. A fresh backend with no key on it is exactly that case.
  const fresh = new Pkcs11Backend({
    libraryPath: LIB, pin: PIN, slot: Number(process.env.HSM_SLOT ?? 0),
    mlDsaMechanism: CKM_ML_DSA, mlDsaKeyPairGenMechanism: CKM_ML_DSA_KEY_PAIR_GEN,
    wrapKeyLabel: `probe-isolation-${Date.now()}`,
  })
  // Not opened: no probe has run, so nothing may be claimed.
  assert.equal(fresh.signingMode, 'wrapped')
})

test('the signature verifies against the token public key and is made on the token', { skip }, async () => {
  const hsm = new PqHsm(backend)
  const l = label()
  const { publicKey } = await hsm.keygen(l, 'ml-dsa-65')

  const msg = Buffer.from('settlement instruction')
  const sig = await hsm.sign(l, msg)

  // Through the wrapper, never the raw primitive: noble takes
  // verify(signature, message, publicKey) while the wrapper takes
  // verify(publicKey, message, sigHex). Reaching past the wrapper and using
  // the wrapper's argument order is silently wrong, and is the exact defect
  // eslint-plugin-kxco-pq/no-raw-primitive exists to catch.
  const { mlDsa } = await import('kxco-post-quantum')
  const sigHex = Buffer.from(sig).toString('hex')
  assert.equal(mlDsa.verify(publicKey, new Uint8Array(msg), sigHex), true,
    'the token signature does not verify under the token public key')

  // The host never held the private key: there is no wrapped blob to unwrap.
  await assert.rejects(() => backend.loadSecret(l))
})

test('a key generated on the token survives a process restart and signs again', { skip }, async () => {
  const hsm = new PqHsm(backend)
  const l = label()
  const { publicKey: before } = await hsm.keygen(l, 'ml-dsa-65')
  const msg = Buffer.from('after restart')

  // Close the session entirely and open a new backend, as a restarted process
  // would. Through 1.3.x the key store was a process-local Map and everything
  // vanished here.
  backend.close()
  backend = await openBackend()
  const hsm2 = new PqHsm(backend)

  const after = await hsm2.getPublicKey(l)
  assert.deepEqual(Buffer.from(after), Buffer.from(before),
    'the reloaded key is not the same key')

  const sig = await hsm2.sign(l, msg)
  const { mlDsa } = await import('kxco-post-quantum')
  assert.equal(mlDsa.verify(before, new Uint8Array(msg), Buffer.from(sig).toString('hex')), true,
    'a signature made after restart does not verify under the original public key')
  assert.equal(backend.signingMode, 'on-token', 'custody must be re-established after restart')
})

test('signOnToken fails when the handle is missing', { skip }, async () => {
  // The regression guard. entry.handle was read in three places and assigned
  // in none, so this path threw for every key the package generated. If the
  // handle ever stops being persisted, this is what catches it.
  const l = label()
  await assert.rejects(() => backend.signOnToken(l, Buffer.from('x')), /not found|no token handle/i)
})

test('deleting a key destroys the token objects, not just the local entry', { skip }, async () => {
  const hsm = new PqHsm(backend)
  const l = label()
  await hsm.keygen(l, 'ml-dsa-65')

  await hsm.deleteKey(l)
  await assert.rejects(() => hsm.getPublicKey(l), /not found/i)

  // A restart must not resurrect it: if C_DestroyObject had not run, the
  // object would still be on the partition and reload would find it.
  backend.close()
  backend = await openBackend()
  await assert.rejects(() => new PqHsm(backend).getPublicKey(l), /not found/i,
    'the private object is still on the token after delete')
})
