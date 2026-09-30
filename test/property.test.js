// Property-based tests with fast-check.
//
// hsm.test.js walks each backend through one fixed key and one fixed message.
// These ask the general question of the two backends that need no hardware,
// MemoryBackend and FileBackend: for ANY message, label and ciphertext, does a
// key generated through PqHsm sign so that kxco-post-quantum verifies it, does
// decapsulation recover exactly what was encapsulated, does the file store keep
// its secrets encrypted and give them back only to the right password?
// fast-check generates the inputs and shrinks any failure to a minimal case.
//
// Pkcs11Backend is left out: it needs a token, and softhsm-integration.test.js
// owns that path. FileBackend works in a temporary directory that is removed
// afterwards. Argon2id at the store's own parameters costs about a second and
// a half per password, so the properties that open a store with a new password
// run only a few cases; everything else reuses one derived key.
//
// Runs on whichever backend kxco-post-quantum reports.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, mlKem } from 'kxco-post-quantum'
import { PqHsm, MemoryBackend, FileBackend, KxcoPqHsmError } from '../src/index.js'

const RUNS = { numRuns: 20 }

const dir = mkdtempSync(join(tmpdir(), 'kxco-hsm-property-'))
after(() => rmSync(dir, { recursive: true, force: true }))

const PASSWORD = 'property-test-password'
const storePath = join(dir, 'keys.json')
const fileBackend = new FileBackend({ path: storePath, password: PASSWORD })

const backends = {
  memory: new PqHsm(new MemoryBackend()),
  file: new PqHsm(fileBackend),
}
const backendName = fc.constantFrom('memory', 'file')

// Labels are made unique per case so one case never overwrites another's key.
let n = 0
const label = fc.stringMatching(/^[a-z][a-z0-9._-]{0,24}$/).map((s) => `${++n}-${s}`)
const message = fc.uint8Array({ maxLength: 512, size: 'max' })
// Any label at all, with the names every plain object inherits drawn three
// times in four, so they are exercised on every run rather than by chance.
const PROTOTYPE_NAMES = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']
const anyLabel = fc.oneof(
  { weight: 1, arbitrary: fc.string({ maxLength: 40, size: 'max' }) },
  { weight: 3, arbitrary: fc.constantFrom(...PROTOTYPE_NAMES) },
)

const hex = (b) => Buffer.from(b).toString('hex')
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b))

async function refusedWithOwnError(fn) {
  try {
    await fn()
    return false
  } catch (err) {
    return err instanceof KxcoPqHsmError
  }
}

// Keys the reopen and wrong-password properties read back.
const persisted = {
  dsa: (await backends.file.keygen('persist-dsa', 'ml-dsa-65')).publicKey,
  kem: (await backends.file.keygen('persist-kem', 'ml-kem-768')).publicKey,
}

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (x) => x + 1 === x), { numRuns: 10 }))
})

test('ML-DSA-65: any message signed through PqHsm verifies with kxco-post-quantum, and a changed message does not', async () => {
  await fc.assert(fc.asyncProperty(backendName, label, fc.uint8Array({ minLength: 1, maxLength: 512 }), fc.nat(), async (b, l, msg, at) => {
    const hsm = backends[b]
    const { publicKey } = await hsm.keygen(l, 'ml-dsa-65')
    const sig = await hsm.sign(l, msg)
    const changed = Uint8Array.from(msg)
    changed[at % changed.length] ^= 0x01
    return publicKey.length === 1952 &&
      same(await hsm.getPublicKey(l), publicKey) &&
      mlDsa.verify(publicKey, msg, hex(sig)) === true &&
      mlDsa.verify(publicKey, changed, hex(sig)) === false
  }), RUNS)
})

test('ML-KEM-768: decapsulation through PqHsm recovers exactly the encapsulated secret, and a changed ciphertext does not', async () => {
  await fc.assert(fc.asyncProperty(backendName, label, fc.nat(), async (b, l, at) => {
    const hsm = backends[b]
    const { publicKey } = await hsm.keygen(l, 'ml-kem-768')
    const { ciphertext, sharedSecret } = mlKem.encapsulate(publicKey)
    const recovered = await hsm.decapsulate(l, ciphertext)
    const changed = Uint8Array.from(ciphertext)
    changed[at % changed.length] ^= 0x01
    const rejected = await hsm.decapsulate(l, changed)
    return publicKey.length === 1184 &&
      same(recovered, sharedSecret) &&
      rejected.length === 32 &&
      !same(rejected, sharedSecret)
  }), { numRuns: 20 })
})

test('keys are typed: a signing key never decapsulates and a KEM key never signs, and both refusals are the package error', async () => {
  for (const hsm of Object.values(backends)) {
    await hsm.keygen('typed-dsa', 'ml-dsa-65')
    await hsm.keygen('typed-kem', 'ml-kem-768')
  }
  await fc.assert(fc.asyncProperty(backendName, message, fc.uint8Array({ maxLength: 1200 }), async (b, msg, ct) => {
    const hsm = backends[b]
    return await refusedWithOwnError(() => hsm.sign('typed-kem', msg)) &&
      await refusedWithOwnError(() => hsm.decapsulate('typed-dsa', ct))
  }), RUNS)
})

test('any label never stored is refused with the package error, in either backend, prototype names included', async () => {
  // Fresh stores, so no generated label can name a key stored elsewhere in this file.
  const fresh = {
    memory: new PqHsm(new MemoryBackend()),
    file: new PqHsm(new FileBackend({ path: join(dir, 'never-stored.json'), password: PASSWORD })),
  }
  await fc.assert(fc.asyncProperty(backendName, anyLabel, message, async (b, l, msg) => {
    const hsm = fresh[b]
    return await refusedWithOwnError(() => hsm.sign(l, msg)) &&
      await refusedWithOwnError(() => hsm.decapsulate(l, msg)) &&
      await refusedWithOwnError(() => hsm.getPublicKey(l)) &&
      await refusedWithOwnError(() => hsm.deleteKey(l))
  }), { numRuns: 200 })
})

test('FileBackend: a key under any label, prototype names included, is listed, written to the file and signs after reopening', async () => {
  // Argon2id at t=1, m=8 KiB, read from the store file, so each reopen costs
  // milliseconds rather than the second and a half the real parameters take.
  const cheapStore = (path) => writeFileSync(path, JSON.stringify({
    'kxco-hsm': '1', kdf: { alg: 'argon2id', t: 1, m: 8, p: 1, salt: Buffer.alloc(32, 9).toString('base64url') }, keys: {},
  }))
  let run = 0
  await fc.assert(fc.asyncProperty(anyLabel, message, async (l, msg) => {
    const path = join(dir, `any-label-${++run}.json`)
    cheapStore(path)
    const { publicKey } = await new PqHsm(new FileBackend({ path, password: PASSWORD })).keygen(l, 'ml-dsa-65')
    const onDisk = JSON.parse(readFileSync(path, 'utf8'))
    const reopened = new PqHsm(new FileBackend({ path, password: PASSWORD }))
    const listed = await reopened.listKeys()
    const sig = await reopened.sign(l, msg)
    return Object.keys(onDisk.keys).length === 1 && Object.hasOwn(onDisk.keys, l) &&
      listed.length === 1 && listed[0].label === l && listed[0].alg === 'ml-dsa-65' &&
      mlDsa.verify(publicKey, msg, hex(sig)) === true
  }), {
    numRuns: 30,
    // Every built-in name is checked on every run, not only when drawn.
    examples: PROTOTYPE_NAMES.map((l) => [l, new Uint8Array([1, 2, 3])]),
  })
})

test('listKeys reports exactly the keys generated and not deleted, and a deleted key is refused', async () => {
  const op = fc.record({
    kind: fc.constantFrom('keygen', 'keygen', 'delete'),
    slot: fc.integer({ min: 0, max: 1 }),
    alg: fc.constantFrom('ml-dsa-65', 'ml-kem-768'),
  })
  let run = 0
  await fc.assert(fc.asyncProperty(backendName, fc.array(op, { minLength: 2, maxLength: 8 }), async (b, ops) => {
    const hsm = backends[b]
    const prefix = `model-${++run}-`
    const model = new Map()
    const deleted = new Set()
    for (const { kind, slot, alg } of ops) {
      const l = prefix + slot
      if (kind === 'keygen') {
        await hsm.keygen(l, alg)
        model.set(l, alg)
        deleted.delete(l)
      } else if (model.has(l)) {
        await hsm.deleteKey(l)
        model.delete(l)
        deleted.add(l)
      }
    }
    const listed = (await hsm.listKeys()).filter((k) => k.label.startsWith(prefix))
    const asMap = new Map(listed.map((k) => [k.label, k.alg]))
    let gone = true
    for (const l of deleted) gone = gone && await refusedWithOwnError(() => hsm.getPublicKey(l))
    return listed.length === model.size &&
      [...model].every(([l, alg]) => asMap.get(l) === alg) &&
      gone
  }), { numRuns: 20 })
})

test('FileBackend: any secret stored comes back byte for byte, and never appears in the file in the clear', async () => {
  await fc.assert(fc.asyncProperty(label, fc.uint8Array({ minLength: 32, maxLength: 2400 }), async (l, secret) => {
    await fileBackend.store(l, 'ml-dsa-65', new Uint8Array(1952), secret)
    const { secretKey } = await fileBackend.loadSecret(l)
    const onDisk = readFileSync(storePath, 'utf8')
    return same(secretKey, secret) &&
      !onDisk.includes(Buffer.from(secret).toString('base64url')) &&
      !onDisk.includes(hex(secret))
  }), RUNS)
})

test('FileBackend: a store reopened with the right password signs and decapsulates with the same keys', async () => {
  const reopened = new PqHsm(new FileBackend({ path: storePath, password: PASSWORD }))
  assert.deepEqual(
    (await reopened.listKeys()).map((k) => k.label).sort(),
    (await backends.file.listKeys()).map((k) => k.label).sort(),
  )
  await fc.assert(fc.asyncProperty(message, async (msg) => {
    const sig = await reopened.sign('persist-dsa', msg)
    const { ciphertext, sharedSecret } = mlKem.encapsulate(persisted.kem)
    return mlDsa.verify(persisted.dsa, msg, hex(sig)) === true &&
      same(await reopened.decapsulate('persist-kem', ciphertext), sharedSecret)
  }), { numRuns: 10 })
})

test('FileBackend: a store opened with any other password is refused with the package error, for signing and for decapsulation', async () => {
  const wrong = fc.string({ minLength: 1, maxLength: 40 }).filter((p) => p !== PASSWORD)
  await fc.assert(fc.asyncProperty(wrong, message, async (password, msg) => {
    const hsm = new PqHsm(new FileBackend({ path: storePath, password }))
    const { ciphertext } = mlKem.encapsulate(persisted.kem)
    // The public half is not secret, so it stays readable.
    return await refusedWithOwnError(() => hsm.sign('persist-dsa', msg)) &&
      await refusedWithOwnError(() => hsm.decapsulate('persist-kem', ciphertext)) &&
      same(await hsm.getPublicKey('persist-dsa'), persisted.dsa)
  }), { numRuns: 2 })
})
