// Where a signature is produced, and whether the key ever entered host memory.
//
// A control that says key material must not leave the cryptographic boundary
// is satisfied by 'on-token' and not by 'wrapped'. The package used to claim
// the former in its own npm description while doing the latter, so the
// distinction is now observable and tested rather than described.
//
// No PKCS#11 token here, so the backend contract is exercised with a stand-in.
// Real token behaviour is a function of the operator's firmware and is checked
// by the mechanism probe in Pkcs11Backend.open(), which refuses to start if the
// requested ML-DSA mechanism is not one the token advertises.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PqHsm, MemoryBackend } from '../src/index.js'
import { mlDsa } from 'kxco-post-quantum'

/** A backend that signs inside the "token" and never yields a private key. */
class TokenBackend {
  #keys = new Map()
  signingMode = 'on-token'
  loadSecretCalls = 0

  async store(label, alg, publicKey, secretKey) {
    // A real token generates in place; this keeps the pair private to the
    // backend so a test cannot accidentally read it the way PqHsm would.
    this.#keys.set(label, { alg, publicKey, secretKey: Uint8Array.from(secretKey) })
  }
  async getPublicKey(label) {
    const k = this.#keys.get(label)
    return { alg: k.alg, publicKey: k.publicKey }
  }
  async signOnToken(label, message) {
    const k = this.#keys.get(label)
    return Buffer.from(mlDsa.sign(k.secretKey, message), 'hex')
  }
  async loadSecret() {
    this.loadSecretCalls++
    throw new Error('the key is non-extractable — loadSecret must not be called')
  }
}

test('PqHsm reports where signing happens', async () => {
  assert.equal(new PqHsm(new MemoryBackend()).signingMode, 'in-process')
  assert.equal(new PqHsm(new TokenBackend()).signingMode, 'on-token')
})

// The behaviour the description now claims: with a token that can sign, the
// private key is never unwrapped into host memory.
test('an on-token backend signs without the key leaving it', async () => {
  const backend = new TokenBackend()
  const hsm = new PqHsm(backend)
  const { publicKey } = await hsm.keygen('inst', 'ml-dsa-65')

  const sig = await hsm.sign('inst', Buffer.from('board resolution'))
  assert.equal(mlDsa.verify(publicKey, 'board resolution', sig.toString('hex')), true)
  assert.equal(backend.loadSecretCalls, 0, 'the key must never be unwrapped')
})

// And the honest fallback still works, so nobody is forced onto hardware.
test('a software backend still signs in process', async () => {
  const hsm = new PqHsm(new MemoryBackend())
  const { publicKey } = await hsm.keygen('soft', 'ml-dsa-65')
  const sig = await hsm.sign('soft', Buffer.from('x'))
  assert.equal(mlDsa.verify(publicKey, 'x', sig.toString('hex')), true)
  assert.equal(hsm.signingMode, 'in-process')
})
