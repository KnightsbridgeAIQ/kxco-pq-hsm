// Where an ML-KEM decapsulation happens, and whether the private key is ever
// in this process.
//
// No PKCS#11 token here, so the PqHsm routing is exercised with a stand-in, as
// signing-mode.test.js does for ML-DSA. A stand-in cannot prove custody; that
// is test/pkcs11-ml-kem.integration.test.js, against a real v3.2 token.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PqHsm, KxcoPqHsmError } from '../src/index.js'
import { mlKem, mlKem1024 } from 'kxco-post-quantum'

const KEM = { 'ml-kem-768': mlKem, 'ml-kem-1024': mlKem1024 }
const KEYGEN = { 'ml-kem-768': () => mlKem.ml_kem768.keygen(), 'ml-kem-1024': () => mlKem1024.ml_kem1024.keygen() }

/** A backend whose ML-KEM keys live in the "token" and are never handed out. */
class KemTokenBackend {
  #keys = new Map()
  canGenerateKemOnToken = true
  kemMode = 'on-token'
  loadSecretCalls = 0
  decapsulateOnTokenCalls = 0
  publicKeyOverride = null

  async keygenKemOnToken(label, alg) {
    const kp = KEYGEN[alg]()
    this.#keys.set(label, { alg, publicKey: kp.publicKey, secretKey: kp.secretKey, onToken: true })
    return { publicKey: this.publicKeyOverride ?? kp.publicKey }
  }
  async store(label, alg, publicKey, secretKey) {
    this.#keys.set(label, { alg, publicKey, secretKey: Uint8Array.from(secretKey), onToken: false })
  }
  async isOnToken(label) {
    return this.#keys.get(label)?.onToken === true
  }
  async getPublicKey(label) {
    const k = this.#keys.get(label)
    return { alg: k.alg, publicKey: k.publicKey }
  }
  async decapsulateOnToken(label, ciphertext) {
    this.decapsulateOnTokenCalls++
    const k = this.#keys.get(label)
    return KEM[k.alg].decapsulate(ciphertext, k.secretKey)
  }
  async loadSecret(label) {
    this.loadSecretCalls++
    const k = this.#keys.get(label)
    if (k.onToken) throw new Error('the key is non-extractable: loadSecret must not be called')
    return { alg: k.alg, secretKey: Uint8Array.from(k.secretKey) }
  }
}

for (const alg of ['ml-kem-768', 'ml-kem-1024']) {
  test(`${alg}: generated and decapsulated on the token, never loaded into the process`, async () => {
    const backend = new KemTokenBackend()
    const hsm = new PqHsm(backend)
    assert.equal(hsm.decapsulationMode, 'on-token')
    const { publicKey } = await hsm.keygen('k', alg)
    const { cipherText, sharedSecret } = KEM[alg].encapsulate(publicKey)
    assert.deepEqual(Buffer.from(await hsm.decapsulate('k', cipherText)), Buffer.from(sharedSecret))
    assert.equal(backend.decapsulateOnTokenCalls, 1)
    assert.equal(backend.loadSecretCalls, 0)
  })
}

test('a key wrapped before on-token ML-KEM was enabled still decapsulates in the process', async () => {
  const backend = new KemTokenBackend()
  const hsm = new PqHsm(backend)
  const kp = mlKem.ml_kem768.keygen()
  await backend.store('old', 'ml-kem-768', kp.publicKey, kp.secretKey)
  const { cipherText, sharedSecret } = mlKem.encapsulate(kp.publicKey)
  assert.deepEqual(Buffer.from(await hsm.decapsulate('old', cipherText)), Buffer.from(sharedSecret))
  assert.equal(backend.loadSecretCalls, 1)
  assert.equal(backend.decapsulateOnTokenCalls, 0)
})

test('a ciphertext of the other parameter set is refused before it reaches the token', async () => {
  const backend = new KemTokenBackend()
  const hsm = new PqHsm(backend)
  await hsm.keygen('k', 'ml-kem-1024')
  await assert.rejects(hsm.decapsulate('k', new Uint8Array(1088)), KxcoPqHsmError)
  assert.equal(backend.decapsulateOnTokenCalls, 0)
})

test('a backend that returns a public key of the wrong size for the set is refused', async () => {
  const backend = new KemTokenBackend()
  backend.publicKeyOverride = new Uint8Array(1184)
  await assert.rejects(new PqHsm(backend).keygen('k', 'ml-kem-1024'), /returned a public key of 1184 bytes, not 1568/)
})

test('a backend that has not proved on-token decapsulation reports in-process', () => {
  const backend = new KemTokenBackend()
  backend.kemMode = 'wrapped'
  assert.equal(new PqHsm(backend).decapsulationMode, 'in-process')
})
