import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, copyFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlKem, mlKem1024 } from 'kxco-post-quantum'
import { PqHsm, MemoryBackend, FileBackend, KxcoPqHsmError } from '../src/index.js'

const fixture = (name) => new URL(`./fixtures/${name}`, import.meta.url)
const known = JSON.parse(readFileSync(fixture('kem-768-1.7.0.json'), 'utf8'))
const u8 = (b64) => new Uint8Array(Buffer.from(b64, 'base64'))
const scratch = mkdtempSync(join(tmpdir(), 'kxco-pq-hsm-kem-'))
test.after(() => rmSync(scratch, { recursive: true, force: true }))

function openLegacy(name) {
  const path = join(scratch, name)
  copyFileSync(fixture('filebackend-1.7.0.json'), path)
  return { path, hsm: new PqHsm(new FileBackend({ path, password: known.password })) }
}

async function rejectsOwn(fn, pattern, what) {
  await assert.rejects(fn, (err) => {
    assert.ok(err instanceof KxcoPqHsmError, `${what}: ${err?.name}: ${err?.message}`)
    assert.match(err.message, pattern, what)
    return true
  })
}

test('a store written by the released 1.7.0 decapsulates the known encapsulation, alone', async () => {
  const { hsm } = openLegacy('alone.json')
  assert.deepEqual((await hsm.listKeys()).map((k) => `${k.label}:${k.alg}`), ['legacy-kem:ml-kem-768'])
  assert.deepEqual(Buffer.from(await hsm.getPublicKey('legacy-kem')), Buffer.from(u8(known.publicKey)))
  assert.deepEqual(await hsm.decapsulate('legacy-kem', u8(known.ciphertext)), u8(known.sharedSecret))
})

test('the same 768 key still decapsulates after a 1024 key is added to the store', async () => {
  const { path, hsm } = openLegacy('mixed.json')
  const { publicKey } = await hsm.keygen('new-kem', 'ml-kem-1024')
  assert.equal(publicKey.length, 1568)

  // Reopen from disk so nothing is carried over in memory.
  const reopened = new PqHsm(new FileBackend({ path, password: known.password }))
  assert.deepEqual((await reopened.listKeys()).map((k) => `${k.label}:${k.alg}`).sort(), ['legacy-kem:ml-kem-768', 'new-kem:ml-kem-1024'])
  assert.deepEqual(await reopened.decapsulate('legacy-kem', u8(known.ciphertext)), u8(known.sharedSecret))
  const { cipherText, sharedSecret } = mlKem1024.encapsulate(await reopened.getPublicKey('new-kem'))
  assert.deepEqual(await reopened.decapsulate('new-kem', cipherText), new Uint8Array(sharedSecret))
})

test('a 1024 key round-trips on the memory and file backends', async () => {
  for (const backend of [new MemoryBackend(), new FileBackend({ path: join(scratch, 'rt.json'), password: 'pw' })]) {
    const hsm = new PqHsm(backend)
    const { publicKey } = await hsm.keygen('k', 'ml-kem-1024')
    assert.equal(publicKey.length, 1568)
    const { cipherText, sharedSecret } = mlKem1024.encapsulate(publicKey)
    assert.equal(cipherText.length, 1568)
    const got = await hsm.decapsulate('k', cipherText)
    assert.equal(got.length, 32)
    assert.deepEqual(got, new Uint8Array(sharedSecret))
  }
})

test('a 768 ciphertext against a 1024 key is refused, and a 1024 ciphertext against a 768 key', async () => {
  const hsm = new PqHsm(new MemoryBackend())
  const pub1024 = (await hsm.keygen('k1024', 'ml-kem-1024')).publicKey
  const pub768 = (await hsm.keygen('k768', 'ml-kem-768')).publicKey
  await rejectsOwn(() => hsm.decapsulate('k1024', mlKem.encapsulate(pub768).cipherText), /1088 bytes, the size of an ml-kem-768 ciphertext/, '768 ct to 1024 key')
  await rejectsOwn(() => hsm.decapsulate('k768', mlKem1024.encapsulate(pub1024).cipherText), /1568 bytes, the size of an ml-kem-1024 ciphertext/, '1024 ct to 768 key')
})

test('a 1024 entry whose stored bytes are 768-sized is refused', async () => {
  const backend = new MemoryBackend()
  const hsm = new PqHsm(backend)
  const k768 = mlKem.ml_kem768.keygen()
  await backend.store('relabelled', 'ml-kem-1024', mlKem1024.ml_kem1024.keygen().publicKey, k768.secretKey)
  const ct = mlKem1024.encapsulate(mlKem1024.ml_kem1024.keygen().publicKey).cipherText
  await rejectsOwn(() => hsm.decapsulate('relabelled', ct), /2400 bytes, the size of an ml-kem-768 secret key/, '768 bytes under a 1024 label')
})

test('a one-byte change to the ciphertext gives a different shared secret (implicit rejection)', async () => {
  const hsm = new PqHsm(new MemoryBackend())
  const { publicKey } = await hsm.keygen('k', 'ml-kem-1024')
  const { cipherText, sharedSecret } = mlKem1024.encapsulate(publicKey)
  const altered = new Uint8Array(cipherText)
  altered[700] ^= 1
  const got = await hsm.decapsulate('k', altered)
  assert.equal(got.length, 32)
  assert.notDeepEqual(got, new Uint8Array(sharedSecret))
  assert.deepEqual(await hsm.decapsulate('k', cipherText), new Uint8Array(sharedSecret))
})

test('the old 768 fixture also gives a different secret for a one-byte change', async () => {
  const { hsm } = openLegacy('implicit.json')
  const altered = u8(known.ciphertext)
  altered[0] ^= 1
  assert.notDeepEqual(await hsm.decapsulate('legacy-kem', altered), u8(known.sharedSecret))
})
