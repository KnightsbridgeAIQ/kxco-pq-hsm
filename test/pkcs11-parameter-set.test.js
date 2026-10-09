// Pkcs11Backend and CKA_PARAMETER_SET, against a token held in memory.
//
// The strength of an ML-DSA key is chosen per key, written to the token in
// CKA_PARAMETER_SET when the key is generated, and read back from the token
// when a later process finds the key there. Through 1.4.x the read-back did
// not happen: every key on the token was labelled ml-dsa-65.
//
// pkcs11js is swapped for the stand-in in fixtures/fake-pkcs11.js by a resolve
// hook, so this runs without hardware and in CI. Custody on a real token is
// softhsm-integration.test.js's to prove; this file proves which parameter set
// the backend asks for and which algorithm it decides a found key is.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import * as nodeModule from 'node:module'
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'

const fake = new URL('./fixtures/fake-pkcs11.js', import.meta.url).href
// registerHooks where the runtime has it (Node 22.15 and later), and the
// older off-thread register on Node 22 releases before that.
if (typeof nodeModule.registerHooks === 'function') {
  nodeModule.registerHooks({
    resolve: (specifier, context, next) => (specifier === 'pkcs11js' ? { url: fake, shortCircuit: true } : next(specifier, context)),
  })
} else {
  nodeModule.register('data:text/javascript,' + encodeURIComponent(
    'export async function resolve(specifier, context, next) {' +
    `  return specifier === 'pkcs11js' ? { url: ${JSON.stringify(fake)}, shortCircuit: true } : next(specifier, context)` +
    '}',
  ))
}

let PqHsm, Pkcs11Backend, KxcoPqHsmError, F
before(async () => {
  ;({ PqHsm, Pkcs11Backend, KxcoPqHsmError } = await import('../src/index.js'))
  F = await import(fake)
})

const MESSAGE = new TextEncoder().encode('kxco-pq-hsm parameter set')
const hex = (b) => Buffer.from(b).toString('hex')
const byLabel = (keys) => [...keys].sort((a, b) => a.label.localeCompare(b.label))

async function open(opts = {}) {
  return new Pkcs11Backend({ libraryPath: 'fake', pin: '1234', ...opts }).open()
}
const onToken = { mlDsaMechanism: 0x1d, mlDsaKeyPairGenMechanism: 0x1c }

async function refused(fn, pattern) {
  await assert.rejects(fn, (err) => {
    assert.ok(err instanceof KxcoPqHsmError, `${err?.name}: ${err?.message}`)
    assert.match(err.message, pattern)
    return true
  })
}

test('the stand-in is the token: a key it holds signs through the backend on the token', async () => {
  F.resetToken()
  const kp = F.seedKeyPair('control', { parameterSet: F.ulong(2) })
  const backend = await open(onToken)
  assert.equal(backend.signingMode, 'on-token')
  const sig = await new PqHsm(backend).sign('control', MESSAGE)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, hex(sig)), true)
  backend.close()
})

test('a key found on the token takes its algorithm from CKA_PARAMETER_SET, in either CK_ULONG width', async () => {
  F.resetToken()
  const k65 = F.seedKeyPair('found-65', { parameterSet: F.ulong(2, 8), keySet: 2 })
  const k87 = F.seedKeyPair('found-87', { parameterSet: F.ulong(3, 4), keySet: 3 })
  const backend = await open(onToken)
  const hsm = new PqHsm(backend)
  assert.deepEqual(byLabel(await hsm.listKeys()), [
    { label: 'found-65', alg: 'ml-dsa-65' },
    { label: 'found-87', alg: 'ml-dsa-87' },
  ])

  const sig65 = await hsm.sign('found-65', MESSAGE)
  const sig87 = await hsm.sign('found-87', MESSAGE)
  assert.equal(sig65.length, 3309)
  assert.equal(sig87.length, 4627)
  assert.equal(mlDsa.verify(k65.publicKey, MESSAGE, hex(sig65)), true)
  assert.equal(mlDsa87.verify(k87.publicKey, MESSAGE, hex(sig87)), true)
  assert.equal(mlDsa.verify(k87.publicKey, MESSAGE, hex(sig87)), false)
  assert.deepEqual(Buffer.from(await hsm.getPublicKey('found-87')), Buffer.from(k87.publicKey))
  backend.close()
})

test('the parameter set is read from the public object when the private one does not carry it', async () => {
  F.resetToken()
  F.seedKeyPair('public-only-87', { parameterSet: F.ulong(3), on: 'public', keySet: 3 })
  F.seedKeyPair('private-only-65', { parameterSet: F.ulong(2), on: 'private', keySet: 2 })
  const backend = await open(onToken)
  assert.deepEqual(byLabel(await backend.listKeys()), [
    { label: 'private-only-65', alg: 'ml-dsa-65' },
    { label: 'public-only-87', alg: 'ml-dsa-87' },
  ])
  backend.close()
})

test('a key whose parameter set is unknown or cannot be read is not loaded, and using it is refused with the reason', async () => {
  F.resetToken()
  F.seedKeyPair('ml-dsa-44', { parameterSet: F.ulong(1) })
  F.seedKeyPair('no-parameter-set', { parameterSet: undefined })
  F.seedKeyPair('good', { parameterSet: F.ulong(2) })
  const backend = await open(onToken)
  const objectsBefore = F.token().objects.size
  const hsm = new PqHsm(backend)

  assert.deepEqual(await hsm.listKeys(), [{ label: 'good', alg: 'ml-dsa-65' }])
  for (const [label, reason] of [['ml-dsa-44', /CKA_PARAMETER_SET is 0x1\b/], ['no-parameter-set', /could not be read/]]) {
    await refused(() => hsm.sign(label, MESSAGE), reason)
    await refused(() => hsm.getPublicKey(label), reason)
    await refused(() => hsm.deleteKey(label), reason)
  }
  // Refusing a key is not destroying it: it may belong to something else.
  assert.equal(F.token().objects.size, objectsBefore)
  backend.close()
})

test('keygen on the token writes the parameter set of the algorithm asked for, and a later process reads it back', async () => {
  F.resetToken()
  const backend = await open(onToken)
  const hsm = new PqHsm(backend)
  const { publicKey: pk87 } = await hsm.keygen('made-87', 'ml-dsa-87')
  const { publicKey: pk65 } = await hsm.keygen('made-65', 'ml-dsa-65')

  const written = F.token().generated.map((g) => g.publicTemplate.find((a) => a.type === F.CKA_PARAMETER_SET)?.value)
  assert.deepEqual(written, [0x3, 0x2])
  assert.equal(pk87.length, 2592)
  assert.equal(pk65.length, 1952)
  assert.equal(backend.signingMode, 'on-token')
  assert.equal(mlDsa87.verify(pk87, MESSAGE, hex(await hsm.sign('made-87', MESSAGE))), true)
  backend.close()

  // A restarted process finds both keys and each is what it was made as.
  const again = await open(onToken)
  const hsm2 = new PqHsm(again)
  assert.deepEqual(byLabel(await hsm2.listKeys()), [
    { label: 'made-65', alg: 'ml-dsa-65' },
    { label: 'made-87', alg: 'ml-dsa-87' },
  ])
  assert.equal(mlDsa87.verify(pk87, MESSAGE, hex(await hsm2.sign('made-87', MESSAGE))), true)
  assert.equal(mlDsa.verify(pk65, MESSAGE, hex(await hsm2.sign('made-65', MESSAGE))), true)
  again.close()
})

const writtenSets = () => F.token().generated.map((g) => g.publicTemplate.find((a) => a.type === F.CKA_PARAMETER_SET)?.value)

test('keygen on the token with no algorithm writes ML-DSA-87 (0x3), and the key signs as ML-DSA-87', async () => {
  F.resetToken()
  const backend = await open(onToken)
  assert.equal(backend.defaultAlgorithm, 'ml-dsa-87')
  const hsm = new PqHsm(backend)
  const { publicKey } = await hsm.keygen('made-default')
  const { publicKey: direct } = await backend.keygenOnToken('made-direct')
  assert.deepEqual(writtenSets(), [0x3, 0x3])
  assert.equal(publicKey.length, 2592)
  assert.equal(direct.length, 2592)
  const sig = await hsm.sign('made-default', MESSAGE)
  assert.equal(sig.length, 4627)
  assert.equal(mlDsa87.verify(publicKey, MESSAGE, hex(sig)), true)
  assert.equal(mlDsa.verify(publicKey, MESSAGE, hex(sig)), false)
  assert.deepEqual(byLabel(await hsm.listKeys()), [
    { label: 'made-default', alg: 'ml-dsa-87' },
    { label: 'made-direct', alg: 'ml-dsa-87' },
  ])
  backend.close()

  // The same when the key is wrapped rather than generated on the token.
  F.resetToken({ mechanisms: [] })
  const wrapped = await open()
  assert.equal(wrapped.signingMode, 'wrapped')
  const wrappedHsm = new PqHsm(wrapped)
  const { publicKey: wrappedKey } = await wrappedHsm.keygen('wrapped-default')
  assert.equal(wrappedKey.length, 2592)
  assert.deepEqual(await wrapped.listKeys(), [{ label: 'wrapped-default', alg: 'ml-dsa-87' }])
  assert.equal(mlDsa87.verify(wrappedKey, MESSAGE, hex(await wrappedHsm.sign('wrapped-default', MESSAGE))), true)
  wrapped.close()
})

test('a backend constructed with the 1.4.x parameterSet 0x2 keeps generating ML-DSA-65 when no algorithm is passed', async () => {
  F.resetToken()
  const backend = await open({ ...onToken, parameterSet: 0x2 })
  assert.equal(backend.defaultAlgorithm, 'ml-dsa-65')
  const hsm = new PqHsm(backend)
  const { publicKey: pk65 } = await hsm.keygen('legacy-default')
  const { publicKey: pk87 } = await hsm.keygen('asked-87', 'ml-dsa-87')
  assert.deepEqual(writtenSets(), [0x2, 0x3])
  assert.equal(pk65.length, 1952)
  assert.equal(pk87.length, 2592)
  assert.equal(mlDsa.verify(pk65, MESSAGE, hex(await hsm.sign('legacy-default', MESSAGE))), true)
  assert.equal(mlDsa87.verify(pk87, MESSAGE, hex(await hsm.sign('asked-87', MESSAGE))), true)
  backend.close()

  // The same when the key is wrapped rather than generated on the token.
  F.resetToken({ mechanisms: [] })
  const wrapped = await open({ parameterSet: 0x2 })
  assert.equal(wrapped.signingMode, 'wrapped')
  const { publicKey } = await new PqHsm(wrapped).keygen('wrapped-legacy')
  assert.equal(publicKey.length, 1952)
  assert.deepEqual(await wrapped.listKeys(), [{ label: 'wrapped-legacy', alg: 'ml-dsa-65' }])
  wrapped.close()
})

test('on-token generation refuses an algorithm that is not an ML-DSA parameter set', async () => {
  F.resetToken()
  const backend = await open(onToken)
  await refused(() => backend.keygenOnToken('kem', 'ml-kem-768'), /ml-dsa-65 and ml-dsa-87/)
  await refused(() => backend.keygenOnToken('44', 'ml-dsa-44'), /ml-dsa-65 and ml-dsa-87/)
  assert.equal(F.token().generated.length, 0)
  backend.close()
})

test('a wrapped ML-DSA-87 key signs as ML-DSA-87', async () => {
  F.resetToken({ mechanisms: [] })
  const backend = await open()
  const hsm = new PqHsm(backend)
  assert.equal(backend.signingMode, 'wrapped')
  const { publicKey } = await hsm.keygen('wrapped-87', 'ml-dsa-87')
  assert.deepEqual(await hsm.listKeys(), [{ label: 'wrapped-87', alg: 'ml-dsa-87' }])
  const sig = await hsm.sign('wrapped-87', MESSAGE)
  assert.equal(mlDsa87.verify(publicKey, MESSAGE, hex(sig)), true)
  backend.close()
})

test('a backend-wide parameterSet other than ML-DSA-65 is refused, and the old default is still accepted', () => {
  assert.throws(
    () => new Pkcs11Backend({ libraryPath: 'fake', pin: '1234', parameterSet: 0x3 }),
    (err) => err instanceof KxcoPqHsmError && /chosen per key/.test(err.message),
  )
  assert.ok(new Pkcs11Backend({ libraryPath: 'fake', pin: '1234', parameterSet: 0x2 }))
})
