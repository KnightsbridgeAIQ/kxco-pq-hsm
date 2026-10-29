// On-token ML-KEM custody, against a real PKCS#11 v3.2 token.
//
// This file owns the on-token ML-KEM claim. test/kem-on-token.test.js proves
// the PqHsm facade routes correctly; only a real token can show that the
// private key is generated inside it, never released, and used there.
//
// Needs a token that offers CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM and the v3.2
// C_DecapsulateKey. Kryoptic does; ci/Dockerfile.kryoptic builds an image:
//
//   docker build -f ci/Dockerfile.kryoptic -t kxco-kryoptic-mlkem .
//   docker run --rm -v "$PWD":/work kxco-kryoptic-mlkem \
//     bash -lc 'npm ci --no-audit --no-fund && npm run test:kryoptic'
//
// Skipped when HSM_ML_KEM_LIBRARY_PATH is unset, so `npm test` stays offline.
// Not skipped for any other reason: with the library present, a token that
// cannot do on-token ML-KEM fails these tests.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mlKem, mlKem1024 } from 'kxco-post-quantum'
import { PqHsm, Pkcs11Backend } from '../src/index.js'

const LIB = process.env.HSM_ML_KEM_LIBRARY_PATH || null
const PIN = process.env.HSM_PIN || '1234'
const skip = LIB ? false : 'HSM_ML_KEM_LIBRARY_PATH is not set'
const CKM_ML_KEM = 0x17
const KEM = { 'ml-kem-768': mlKem, 'ml-kem-1024': mlKem1024 }
const LABELS = { 'ml-kem-768': 'kem-768-it', 'ml-kem-1024': 'kem-1024-it' }

const backend = () => new Pkcs11Backend({ libraryPath: LIB, pin: PIN, mlKemMechanism: CKM_ML_KEM })

test('ML-KEM keys are generated and decapsulated on the token', { skip }, async () => {
  const b = await backend().open()
  try {
    assert.equal(b.canGenerateKemOnToken, true)
    const hsm = new PqHsm(b)
    for (const [alg, label] of Object.entries(LABELS)) {
      const { publicKey } = await hsm.keygen(label, alg)
      assert.equal(hsm.decapsulationMode, 'on-token', 'the probe decapsulated on the token')
      const { cipherText, sharedSecret } = KEM[alg].encapsulate(publicKey)
      assert.deepEqual(Buffer.from(await hsm.decapsulate(label, cipherText)), Buffer.from(sharedSecret), alg)

      // FIPS 203 implicit rejection, inside the token: a changed ciphertext
      // gives a different secret, not an error.
      const tampered = Buffer.from(cipherText)
      tampered[7] ^= 0x80
      const other = await hsm.decapsulate(label, tampered)
      assert.equal(other.length, 32)
      assert.notDeepEqual(Buffer.from(other), Buffer.from(sharedSecret))

      // The private key never comes back to the process.
      await assert.rejects(b.loadSecret(label), /non-extractable/)
    }
  } finally {
    b.close()
  }
})

test('the token holds the private keys as sensitive and never extractable', { skip }, async () => {
  const { default: pkcs11js } = await import('pkcs11js')
  const p = new pkcs11js.PKCS11()
  p.load(LIB)
  p.C_Initialize()
  try {
    const s = p.C_OpenSession(p.C_GetSlotList(true)[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION)
    p.C_Login(s, pkcs11js.CKU_USER, PIN)
    for (const label of Object.values(LABELS)) {
      p.C_FindObjectsInit(s, [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_ID, value: Buffer.from(label, 'utf8') },
      ])
      const [h] = p.C_FindObjects(s, 1)
      p.C_FindObjectsFinal(s)
      assert.ok(h, `${label} is on the token`)
      const attrs = p.C_GetAttributeValue(s, h, [
        { type: pkcs11js.CKA_SENSITIVE }, { type: pkcs11js.CKA_EXTRACTABLE },
        { type: pkcs11js.CKA_NEVER_EXTRACTABLE }, { type: pkcs11js.CKA_LOCAL },
      ]).map((a) => a.value[0])
      assert.deepEqual(attrs, [1, 0, 1, 1], `${label}: SENSITIVE, not EXTRACTABLE, NEVER_EXTRACTABLE, LOCAL`)
      assert.throws(() => p.C_GetAttributeValue(s, h, [{ type: pkcs11js.CKA_VALUE }]), /SENSITIVE|0x11/i)
    }
    p.C_Logout(s)
    p.C_CloseSession(s)
  } finally {
    p.C_Finalize()
  }
})

test('the shared-secret object is destroyed after every decapsulation, even when reading it fails', { skip }, async () => {
  const { default: pkcs11js } = await import('pkcs11js')
  // The control below needs one read of a secret's value to fail. pkcs11js
  // methods are native, so the class is swapped for one that wraps the read on
  // each instance, before the backend constructs its own.
  const Original = pkcs11js.PKCS11
  let armed = false
  pkcs11js.PKCS11 = class extends Original {
    constructor(...args) {
      super(...args)
      const read = this.C_GetAttributeValue.bind(this)
      this.C_GetAttributeValue = (session, handle, template) => {
        if (armed && template?.[0]?.type === pkcs11js.CKA_VALUE) {
          armed = false
          throw new Error('forced failure reading the shared secret')
        }
        return read(session, handle, template)
      }
    }
  }
  const b = await backend().open()
  // A second view of the same token in this process, to count the session
  // objects the backend's own session creates. The library is already
  // initialised by the backend, so that error is expected and ignored.
  const p = new pkcs11js.PKCS11()
  p.load(LIB)
  try { p.C_Initialize() } catch (e) { if (!/ALREADY_INITIALIZED/.test(e.message)) throw e }
  const s = p.C_OpenSession(p.C_GetSlotList(true)[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION)
  const secrets = () => {
    p.C_FindObjectsInit(s, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
      { type: pkcs11js.CKA_KEY_TYPE, value: 0x10 }, // CKK_GENERIC_SECRET
    ])
    const found = p.C_FindObjects(s, 100)
    p.C_FindObjectsFinal(s)
    return found.length
  }
  try {
    const hsm = new PqHsm(b)
    const label = LABELS['ml-kem-1024']
    const publicKey = await hsm.getPublicKey(label)
    const { cipherText, sharedSecret } = mlKem1024.encapsulate(publicKey)

    const before = secrets()
    assert.deepEqual(Buffer.from(await hsm.decapsulate(label, cipherText)), Buffer.from(sharedSecret))
    assert.equal(secrets(), before, 'no secret object is left after a decapsulation')

    // The control: make the read of the secret's value fail once. The object
    // was created on the token before the read, so only the cleanup removes it.
    armed = true
    await assert.rejects(hsm.decapsulate(label, cipherText), /forced failure/)
    assert.equal(armed, false, 'the forced failure fired')
    assert.equal(secrets(), before, 'no secret object is left after a failed read')
  } finally {
    pkcs11js.PKCS11 = Original
    p.C_CloseSession(s)
    b.close()
  }
})

test('a wrapped key and a token key side by side each decapsulate on their own path', { skip }, async () => {
  const b = await backend().open()
  try {
    const hsm = new PqHsm(b)
    let onToken = 0
    const decapsulateOnToken = b.decapsulateOnToken.bind(b)
    b.decapsulateOnToken = async (...args) => { onToken++; return decapsulateOnToken(...args) }

    // A key wrapped under the token's AES key, as before mlKemMechanism existed.
    const kp = mlKem.ml_kem768.keygen()
    await b.store('kem-768-wrapped-it', 'ml-kem-768', kp.publicKey, kp.secretKey)
    const w = mlKem.encapsulate(kp.publicKey)
    assert.deepEqual(Buffer.from(await hsm.decapsulate('kem-768-wrapped-it', w.cipherText)), Buffer.from(w.sharedSecret))
    assert.equal(onToken, 0, 'the wrapped key decapsulated in the process')

    const label = LABELS['ml-kem-768']
    const t = mlKem.encapsulate(await hsm.getPublicKey(label))
    assert.deepEqual(Buffer.from(await hsm.decapsulate(label, t.cipherText)), Buffer.from(t.sharedSecret))
    assert.equal(onToken, 1, 'the token key decapsulated on the token')
    await b.deleteKey('kem-768-wrapped-it')
  } finally {
    b.close()
  }
})

test('a restarted backend finds the token keys and decapsulates with them', { skip }, async () => {
  const b = await backend().open()
  try {
    const hsm = new PqHsm(b)
    const listed = Object.fromEntries((await b.listKeys()).map(({ label, alg }) => [label, alg]))
    for (const [alg, label] of Object.entries(LABELS)) {
      assert.equal(listed[label], alg, 'the parameter set is read back from the token')
      const publicKey = await hsm.getPublicKey(label)
      const { cipherText, sharedSecret } = KEM[alg].encapsulate(publicKey)
      assert.deepEqual(Buffer.from(await hsm.decapsulate(label, cipherText)), Buffer.from(sharedSecret))
    }
    assert.equal(hsm.decapsulationMode, 'on-token')
    for (const label of Object.values(LABELS)) await b.deleteKey(label)
  } finally {
    b.close()
  }
})

test('asking for a mechanism the token does not offer is refused at open', { skip }, async () => {
  await assert.rejects(
    new Pkcs11Backend({ libraryPath: LIB, pin: PIN, mlKemMechanism: 0x7fff0000 }).open(),
    /does not offer/,
  )
})
