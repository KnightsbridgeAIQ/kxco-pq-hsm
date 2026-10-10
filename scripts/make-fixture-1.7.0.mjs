// Writes test/fixtures/filebackend-1.7.0.json and kem-768-1.7.0.json using the
// RELEASED kxco-pq-hsm 1.7.0 from npm (devDependency alias kxco-pq-hsm-1-7-0),
// FILE backend. The store holds one ML-KEM-768 key. The second file holds a
// known encapsulation to it: the ciphertext and the shared secret it carries.
// Run: node scripts/make-fixture-1.7.0.mjs
import { writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { mlKem } from 'kxco-post-quantum'
import { PqHsm, FileBackend } from 'kxco-pq-hsm-1-7-0'

const dir = fileURLToPath(new URL('../test/fixtures/', import.meta.url))
mkdirSync(dir, { recursive: true })
const store = `${dir}filebackend-1.7.0.json`
rmSync(store, { force: true })

const hsm = new PqHsm(new FileBackend({ path: store, password: 'kxco-pq-hsm-fixture' }))
const { publicKey } = await hsm.keygen('legacy-kem', 'ml-kem-768')
const { cipherText, sharedSecret } = mlKem.encapsulate(publicKey)
const b64 = (u) => Buffer.from(u).toString('base64')
writeFileSync(`${dir}kem-768-1.7.0.json`, JSON.stringify({
  writtenBy: 'kxco-pq-hsm 1.7.0 (npm)',
  label: 'legacy-kem',
  alg: 'ml-kem-768',
  password: 'kxco-pq-hsm-fixture',
  publicKey: b64(publicKey),
  ciphertext: b64(cipherText),
  sharedSecret: b64(sharedSecret),
}, null, 2) + '\n')
console.log('wrote', store)
