import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, mlKem } from 'kxco-post-quantum'
import { PqHsm, MemoryBackend, FileBackend, Pkcs11Backend } from '../src/index.js'

// Detect SoftHSM2 on CI or developer machines
const SOFTHSM_PATHS = [
  '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
  '/usr/lib/softhsm/libsofthsm2.so',
  '/usr/local/lib/softhsm/libsofthsm2.so',
]
const PKCS11_LIB  = process.env.PKCS11_LIB  || SOFTHSM_PATHS.find(existsSync) || null
const PKCS11_PIN  = process.env.PKCS11_PIN  || '1234'
const PKCS11_SLOT = parseInt(process.env.PKCS11_SLOT || '0', 10)

// Shared test suite run against each backend
function suite(name, makeHsm, teardown) {
  describe(name, () => {
    let hsm

    before(async () => { hsm = await makeHsm() })
    after(async  () => { if (teardown) await teardown(hsm) })

    test('keygen ml-dsa-65 returns publicKey', async () => {
      const { publicKey } = await hsm.keygen('dsa-key', 'ml-dsa-65')
      assert.ok(publicKey instanceof Uint8Array)
      assert.equal(publicKey.length, 1952)
    })

    test('sign + external verify round-trip', async () => {
      const pubKey  = await hsm.getPublicKey('dsa-key')
      const message = new TextEncoder().encode('kxco-pq-hsm test message')
      const sig     = await hsm.sign('dsa-key', message)
      assert.ok(mlDsa.verify(pubKey, message, Buffer.from(sig).toString('hex')))
    })

    test('keygen ml-kem-768 returns publicKey', async () => {
      const { publicKey } = await hsm.keygen('kem-key', 'ml-kem-768')
      assert.ok(publicKey instanceof Uint8Array)
      assert.equal(publicKey.length, 1184)
    })

    test('encapsulate + decapsulate round-trip', async () => {
      const pubKey  = await hsm.getPublicKey('kem-key')
      const { cipherText, sharedSecret: ss1 } = mlKem.encapsulate(pubKey)
      const ss2 = await hsm.decapsulate('kem-key', cipherText)
      assert.deepEqual(ss2, new Uint8Array(ss1))
    })

    test('listKeys returns both keys', async () => {
      const keys = await hsm.listKeys()
      assert.ok(keys.some(k => k.label === 'dsa-key' && k.alg === 'ml-dsa-65'))
      assert.ok(keys.some(k => k.label === 'kem-key' && k.alg === 'ml-kem-768'))
    })

    test('deleteKey removes the key', async () => {
      await hsm.keygen('temp', 'ml-dsa-65')
      await hsm.deleteKey('temp')
      const keys = await hsm.listKeys()
      assert.ok(!keys.some(k => k.label === 'temp'))
    })

    test('sign with KEM key throws', async () => {
      await assert.rejects(
        () => hsm.sign('kem-key', new Uint8Array([1, 2, 3])),
        /ml-dsa-65/
      )
    })

    test('decapsulate with DSA key throws', async () => {
      await assert.rejects(
        () => hsm.decapsulate('dsa-key', new Uint8Array(1088)),
        /ml-kem-768/
      )
    })

    test('getPublicKey on unknown label throws', async () => {
      await assert.rejects(() => hsm.getPublicKey('no-such-key'), /not found/)
    })
  })
}

// --- MemoryBackend ---
suite('MemoryBackend', async () => new PqHsm(new MemoryBackend()))

// --- FileBackend ---
const filePath = join(tmpdir(), `kxco-hsm-test-${process.pid}.json`)
suite(
  'FileBackend',
  async () => new PqHsm(new FileBackend({ path: filePath, password: 'test-pw-1234!' })),
  async () => { try { unlinkSync(filePath) } catch { /* ok */ } }
)

// --- Pkcs11Backend (requires SoftHSM2 or real HSM) ---
if (PKCS11_LIB) {
  let pkcs11Backend
  suite(
    'Pkcs11Backend',
    async () => {
      pkcs11Backend = await new Pkcs11Backend({
        libraryPath: PKCS11_LIB,
        slot:        PKCS11_SLOT,
        pin:         PKCS11_PIN,
      }).open()
      return new PqHsm(pkcs11Backend)
    },
    async () => pkcs11Backend?.close()
  )
} else {
  test('Pkcs11Backend — SKIPPED (set PKCS11_LIB env var or install softhsm2 to enable)', (t) => {
    t.skip('no PKCS#11 library found')
  })
}
