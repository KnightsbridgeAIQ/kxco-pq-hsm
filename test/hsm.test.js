import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, unlinkSync, mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, mlDsa87, mlKem } from 'kxco-post-quantum'
import { PqHsm, MemoryBackend, FileBackend, Pkcs11Backend, KxcoPqHsmError } from '../src/index.js'

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

    test('an ml-dsa-65 key still signs ML-DSA-65: 3309 bytes, and not an ML-DSA-87 signature', async () => {
      const pubKey  = await hsm.getPublicKey('dsa-key')
      const message = new TextEncoder().encode('kxco-pq-hsm stays ML-DSA-65')
      const sig     = Buffer.from(await hsm.sign('dsa-key', message)).toString('hex')
      assert.equal(sig.length, 3309 * 2)
      assert.equal(mlDsa.verify(pubKey, message, sig), true)
      assert.equal(mlDsa87.verify(pubKey, message, sig), false)
    })

    test('keygen ml-dsa-87 returns a 2592-byte public key and lists as ml-dsa-87', async () => {
      const { publicKey } = await hsm.keygen('dsa87-key', 'ml-dsa-87')
      assert.ok(publicKey instanceof Uint8Array)
      assert.equal(publicKey.length, 2592)
      assert.deepEqual(Buffer.from(await hsm.getPublicKey('dsa87-key')), Buffer.from(publicKey))
      assert.ok((await hsm.listKeys()).some(k => k.label === 'dsa87-key' && k.alg === 'ml-dsa-87'))
    })

    test('an ml-dsa-87 key signs ML-DSA-87: 4627 bytes, verified by ML-DSA-87 and not by ML-DSA-65', async () => {
      const pubKey  = await hsm.getPublicKey('dsa87-key')
      const message = new TextEncoder().encode('kxco-pq-hsm ML-DSA-87')
      const sig     = Buffer.from(await hsm.sign('dsa87-key', message)).toString('hex')
      assert.equal(sig.length, 4627 * 2)
      assert.equal(mlDsa87.verify(pubKey, message, sig), true)
      assert.equal(mlDsa.verify(pubKey, message, sig), false)
      assert.equal(mlDsa87.verify(pubKey, new TextEncoder().encode('another message'), sig), false)
    })

    test('keygen with no algorithm makes an ML-DSA-87 key: 2592-byte public key, 4627-byte signatures', async () => {
      const { publicKey } = await hsm.keygen('default-key')
      assert.equal(publicKey.length, 2592)
      assert.ok((await hsm.listKeys()).some(k => k.label === 'default-key' && k.alg === 'ml-dsa-87'))
      const message = new TextEncoder().encode('kxco-pq-hsm default')
      const sig     = Buffer.from(await hsm.sign('default-key', message)).toString('hex')
      assert.equal(sig.length, 4627 * 2)
      assert.equal(mlDsa87.verify(publicKey, message, sig), true)
      assert.equal(mlDsa.verify(publicKey, message, sig), false)
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

// --- Every refusal is the package error ---
//
// Stores made here use Argon2id at t=1, m=8 KiB so each open costs
// milliseconds. FileBackend reads its parameters from the store file, so this
// changes nothing about a store the package creates.

const scratch = mkdtempSync(join(tmpdir(), 'kxco-hsm-errors-'))
after(() => rmSync(scratch, { recursive: true, force: true }))

let seq = 0
function cheapStorePath() {
  const path = join(scratch, `store-${++seq}.json`)
  writeFileSync(path, JSON.stringify({
    'kxco-hsm': '1',
    kdf: { alg: 'argon2id', t: 1, m: 8, p: 1, salt: randomBytes(32).toString('base64url') },
    keys: {},
  }))
  return path
}

async function rejectsWithOwnError(fn, what) {
  await assert.rejects(fn, (err) => {
    assert.ok(err instanceof KxcoPqHsmError, `${what}: ${err?.name}: ${err?.message}`)
    return true
  })
}

test('FileBackend: a store written by 1.4.2 keeps working, and takes keys under built-in property names', async () => {
  const path = join(scratch, 'from-1.4.2.json')
  copyFileSync(new URL('./fixtures/filebackend-1.4.2.json', import.meta.url), path)
  const hsm = new PqHsm(new FileBackend({ path, password: 'kxco-pq-hsm-fixture' }))
  assert.deepEqual((await hsm.listKeys()).map((k) => `${k.label}:${k.alg}`).sort(), ['fixture-dsa:ml-dsa-65', 'fixture-kem:ml-kem-768'])

  const message = new TextEncoder().encode('written by 1.4.2')
  const sig = await hsm.sign('fixture-dsa', message)
  assert.ok(mlDsa.verify(await hsm.getPublicKey('fixture-dsa'), message, Buffer.from(sig).toString('hex')))
  const { cipherText, sharedSecret } = mlKem.encapsulate(await hsm.getPublicKey('fixture-kem'))
  assert.deepEqual(await hsm.decapsulate('fixture-kem', cipherText), new Uint8Array(sharedSecret))

  // Keys added now are written in the same shape, whatever their label.
  const names = ['__proto__', 'constructor', 'toString', 'hasOwnProperty']
  const added = {}
  for (const label of names) added[label] = (await hsm.keygen(label, 'ml-dsa-65')).publicKey
  const onDisk = JSON.parse(readFileSync(path, 'utf8'))
  assert.deepEqual(Object.keys(onDisk), ['kxco-hsm', 'kdf', 'keys'])
  assert.deepEqual(Object.keys(onDisk.keys).sort(), ['fixture-dsa', 'fixture-kem', ...names].sort())
  for (const label of names) assert.deepEqual(Object.keys(onDisk.keys[label]).sort(), ['alg', 'ciphertext', 'nonce', 'publicKey'], label)

  const reopened = new PqHsm(new FileBackend({ path, password: 'kxco-pq-hsm-fixture' }))
  assert.equal((await reopened.listKeys()).length, 2 + names.length)
  for (const label of names) {
    const signed = await reopened.sign(label, message)
    assert.ok(mlDsa.verify(added[label], message, Buffer.from(signed).toString('hex')), label)
  }
  await reopened.deleteKey('__proto__')
  assert.ok(!(await reopened.listKeys()).some((k) => k.label === '__proto__'))
  await rejectsWithOwnError(() => reopened.sign('__proto__', message), 'deleted __proto__')
})

test('an ML-DSA-65 key made before ML-DSA-87 became the default still signs and verifies as ML-DSA-65', async () => {
  const message = new TextEncoder().encode('made before 1.6.0')
  // A key written by 1.4.2, in the store it was written to.
  const path = join(scratch, 'from-1.4.2-after-default.json')
  copyFileSync(new URL('./fixtures/filebackend-1.4.2.json', import.meta.url), path)
  const fromFile = new PqHsm(new FileBackend({ path, password: 'kxco-pq-hsm-fixture' }))
  // A key a backend already holds, put there without keygen.
  const k65 = mlDsa.ml_dsa65.keygen()
  const memory = new MemoryBackend()
  await memory.store('existing-65', 'ml-dsa-65', k65.publicKey, k65.secretKey)
  const fromMemory = new PqHsm(memory)
  for (const [hsm, label] of [[fromFile, 'fixture-dsa'], [fromMemory, 'existing-65']]) {
    assert.ok((await hsm.listKeys()).some(k => k.label === label && k.alg === 'ml-dsa-65'), label)
    const publicKey = await hsm.getPublicKey(label)
    assert.equal(publicKey.length, 1952, label)
    const sig = Buffer.from(await hsm.sign(label, message)).toString('hex')
    assert.equal(sig.length, 3309 * 2, label)
    assert.equal(mlDsa.verify(publicKey, message, sig), true, label)
    assert.equal(mlDsa87.verify(publicKey, message, sig), false, label)
  }
})

test('FileBackend: a key store that cannot be read, or is not a key store, is refused with KxcoPqHsmError', () => {
  const kdf = { alg: 'argon2id', t: 1, m: 8, p: 1, salt: randomBytes(32).toString('base64url') }
  const cases = [
    ['not JSON', 'not json'],
    ['JSON null', 'null'],
    ['a number', '5'],
    ['version an object', JSON.stringify({ 'kxco-hsm': { toString: null }, kdf, keys: {} })],
    ['no keys', JSON.stringify({ 'kxco-hsm': '1', kdf })],
    ['keys not an object', JSON.stringify({ 'kxco-hsm': '1', kdf, keys: 'x' })],
    ['no kdf', JSON.stringify({ 'kxco-hsm': '1', keys: {} })],
  ]
  for (const [what, content] of cases) {
    const path = join(scratch, `open-${++seq}.json`)
    writeFileSync(path, content)
    assert.throws(() => new FileBackend({ path, password: 'pw' }), KxcoPqHsmError, what)
  }
  const directory = join(scratch, `a-directory-${++seq}`)
  mkdirSync(directory)
  assert.throws(() => new FileBackend({ path: directory, password: 'pw' }), KxcoPqHsmError, 'a directory')
  assert.throws(() => new FileBackend({ path: join(scratch, 'missing', 'keys.json'), password: 'pw' }), KxcoPqHsmError, 'a missing directory')
  assert.throws(() => new FileBackend({ path: cheapStorePath(), password: -1 }), KxcoPqHsmError, 'password -1')
})

test('FileBackend: a damaged entry or key-derivation block is refused with KxcoPqHsmError', async () => {
  const path = cheapStorePath()
  const hsm = new PqHsm(new FileBackend({ path, password: 'pw' }))
  await hsm.keygen('dsa', 'ml-dsa-65')
  await hsm.keygen('kem', 'ml-kem-768')
  const good = JSON.parse(readFileSync(path, 'utf8'))
  const damaged = (change) => {
    const store = structuredClone(good)
    change(store)
    const p = join(scratch, `damaged-${++seq}.json`)
    writeFileSync(p, JSON.stringify(store))
    return new PqHsm(new FileBackend({ path: p, password: 'pw' }))
  }
  const message = new Uint8Array([1, 2, 3])
  await rejectsWithOwnError(() => damaged((s) => { delete s.keys.dsa.nonce }).sign('dsa', message), 'nonce missing')
  await rejectsWithOwnError(() => damaged((s) => { s.keys.dsa.nonce = 'AAAA' }).sign('dsa', message), 'nonce too short')
  await rejectsWithOwnError(() => damaged((s) => { s.keys.kem.ciphertext = s.keys.dsa.ciphertext }).decapsulate('kem', new Uint8Array(1088)), 'ciphertext from another entry')
  await rejectsWithOwnError(() => damaged((s) => { delete s.keys.dsa.publicKey }).getPublicKey('dsa'), 'public key missing')
  await rejectsWithOwnError(() => damaged((s) => { s.keys.dsa = null }).sign('dsa', message), 'entry null, sign')
  await rejectsWithOwnError(() => damaged((s) => { s.keys.dsa = null }).listKeys(), 'entry null, listKeys')
  await rejectsWithOwnError(() => damaged((s) => { s.kdf.salt = 5 }).sign('dsa', message), 'salt not a string')
  await rejectsWithOwnError(() => damaged((s) => { s.kdf.m = 'x' }).sign('dsa', message), 'memory cost not a number')
})

test('FileBackend: a key store that can no longer be written is refused with KxcoPqHsmError', async () => {
  const path = cheapStorePath()
  const hsm = new PqHsm(new FileBackend({ path, password: 'pw' }))
  // The file is replaced by a directory of the same name, which no write replaces.
  rmSync(path)
  mkdirSync(path)
  await rejectsWithOwnError(() => hsm.keygen('k', 'ml-dsa-65'), 'store write')
})

test('PqHsm: a ciphertext of the wrong length, a stored secret of the wrong length or a message that is not bytes is refused with KxcoPqHsmError', async () => {
  for (const backend of [new MemoryBackend(), new FileBackend({ path: cheapStorePath(), password: 'pw' })]) {
    const hsm = new PqHsm(backend)
    const name = backend.constructor.name
    await hsm.keygen('kem', 'ml-kem-768')
    await hsm.keygen('dsa', 'ml-dsa-65')
    await rejectsWithOwnError(() => hsm.decapsulate('kem', new Uint8Array(10)), `${name} short ciphertext`)
    await rejectsWithOwnError(() => hsm.decapsulate('kem', -1), `${name} ciphertext -1`)
    await rejectsWithOwnError(() => hsm.sign('dsa', -1), `${name} message -1`)
    await backend.store('short-dsa', 'ml-dsa-65', new Uint8Array(1952), new Uint8Array(32))
    await backend.store('short-kem', 'ml-kem-768', new Uint8Array(1184), new Uint8Array(32))
    await rejectsWithOwnError(() => hsm.sign('short-dsa', new Uint8Array(1)), `${name} short signing secret`)
    await rejectsWithOwnError(() => hsm.decapsulate('short-kem', new Uint8Array(1088)), `${name} short KEM secret`)
  }
})

test('PqHsm: a text message is signed as its UTF-8 bytes, and a value that is not text or bytes is refused', async () => {
  for (const backend of [new MemoryBackend(), new FileBackend({ path: cheapStorePath(), password: 'pw' })]) {
    const hsm = new PqHsm(backend)
    const name = backend.constructor.name
    const { publicKey } = await hsm.keygen('dsa', 'ml-dsa-65')
    const sig = await hsm.sign('dsa', 'payload é')
    assert.ok(mlDsa.verify(publicKey, new TextEncoder().encode('payload é'), Buffer.from(sig).toString('hex')), name)
    assert.ok(!mlDsa.verify(publicKey, new Uint8Array(0), Buffer.from(sig).toString('hex')), `${name}: not the empty message`)
    const view = new Uint16Array([0x0100, 0x0001])
    const viewSig = await hsm.sign('dsa', view)
    assert.ok(mlDsa.verify(publicKey, new Uint8Array(view.buffer), Buffer.from(viewSig).toString('hex')), `${name}: a typed array is signed as the bytes it covers`)
    for (const bad of [12, true, null, undefined, { a: 1 }, [1, 2, 3]]) {
      await rejectsWithOwnError(() => hsm.sign('dsa', bad), `${name} message ${JSON.stringify(bad)}`)
    }
    await rejectsWithOwnError(() => hsm.decapsulate('dsa', 'text'), `${name} ciphertext as text`)
  }
})

test('FileBackend: a password must be text or bytes that are not empty, and a number is refused by name', () => {
  for (const bad of [12345678, 0, true, { toString: () => 'pw' }, new Uint8Array(0), Buffer.alloc(0), [1, 2, 3]]) {
    assert.throws(() => new FileBackend({ path: cheapStorePath(), password: bad }), (err) => {
      assert.ok(err instanceof KxcoPqHsmError, `${String(bad)}: ${err?.name}`)
      if (typeof bad === 'number') assert.match(err.message, /number/)
      return true
    })
  }
  assert.ok(new FileBackend({ path: cheapStorePath(), password: 'pw' }))
  assert.ok(new FileBackend({ path: cheapStorePath(), password: Buffer.from('pw') }))
})

test('PqHsm: a label must be text that is not empty, in every backend', async () => {
  for (const backend of [new MemoryBackend(), new FileBackend({ path: cheapStorePath(), password: 'pw' })]) {
    const hsm = new PqHsm(backend)
    const name = backend.constructor.name
    for (const bad of ['', 5, Symbol('k'), null, undefined, { toString: () => 'k' }]) {
      const shown = typeof bad === 'symbol' ? 'Symbol' : JSON.stringify(bad)
      await rejectsWithOwnError(() => hsm.keygen(bad, 'ml-dsa-65'), `${name} keygen ${shown}`)
      await rejectsWithOwnError(() => hsm.sign(bad, new Uint8Array(1)), `${name} sign ${shown}`)
      await rejectsWithOwnError(() => hsm.getPublicKey(bad), `${name} getPublicKey ${shown}`)
      await rejectsWithOwnError(() => hsm.deleteKey(bad), `${name} deleteKey ${shown}`)
    }
    assert.deepEqual(await hsm.listKeys(), [], name)
  }
})

test('FileBackend: a key whose store write fails is not kept in memory, and an earlier key under that label survives', async () => {
  const path = cheapStorePath()
  const backend = new FileBackend({ path, password: 'pw' })
  const hsm = new PqHsm(backend)
  const { publicKey: first } = await hsm.keygen('k', 'ml-dsa-65')
  rmSync(path)
  mkdirSync(path)
  await rejectsWithOwnError(() => hsm.keygen('k', 'ml-dsa-65'), 'second keygen')
  await rejectsWithOwnError(() => hsm.keygen('other', 'ml-dsa-65'), 'new label')
  assert.deepEqual((await hsm.listKeys()).map((k) => k.label), ['k'])
  assert.deepEqual(Buffer.from(await hsm.getPublicKey('k')), Buffer.from(first))
})

test('PqHsm: a key stored as one ML-DSA parameter set with the bytes of the other is refused, for signing and for its public key', async () => {
  const k65 = mlDsa.ml_dsa65.keygen()
  const k87 = mlDsa87.ml_dsa87.keygen()
  for (const backend of [new MemoryBackend(), new FileBackend({ path: cheapStorePath(), password: 'pw' })]) {
    const hsm = new PqHsm(backend)
    const name = backend.constructor.name
    await backend.store('65-stored-as-87', 'ml-dsa-87', k65.publicKey, k65.secretKey)
    await backend.store('87-stored-as-65', 'ml-dsa-65', k87.publicKey, k87.secretKey)
    for (const label of ['65-stored-as-87', '87-stored-as-65']) {
      const calls = [['sign', () => hsm.sign(label, new Uint8Array([1]))], ['getPublicKey', () => hsm.getPublicKey(label)]]
      for (const [what, fn] of calls) {
        await assert.rejects(fn, (err) => {
          assert.ok(err instanceof KxcoPqHsmError, `${name} ${label} ${what}: ${err?.name}: ${err?.message}`)
          assert.match(err.message, /not (used|presented) as another/, `${name} ${label} ${what}`)
          return true
        })
      }
    }
  }
})

test('PqHsm: an algorithm that is not ml-dsa-65, ml-dsa-87, ml-kem-768 or ml-kem-1024 is refused at keygen', async () => {
  const hsm = new PqHsm(new MemoryBackend())
  for (const bad of ['ml-dsa-44', 'ML-DSA-87', 'ml-kem-512', '', 'constructor']) {
    await rejectsWithOwnError(() => hsm.keygen('k', bad), `alg ${JSON.stringify(bad)}`)
  }
  assert.deepEqual(await hsm.listKeys(), [])
})

test('backends refuse a public or secret key that is not bytes', async () => {
  for (const backend of [new MemoryBackend(), new FileBackend({ path: cheapStorePath(), password: 'pw' })]) {
    const name = backend.constructor.name
    await rejectsWithOwnError(() => backend.store('k', 'ml-dsa-65', 'not bytes', new Uint8Array(32)), `${name} public key as text`)
    await rejectsWithOwnError(() => backend.store('k', 'ml-dsa-65', new Uint8Array(1952), 42), `${name} secret key as a number`)
    assert.deepEqual(await backend.listKeys(), [], name)
  }
})
