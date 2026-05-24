import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { argon2id } from '@noble/hashes/argon2'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { KxcoPqHsmError } from '../errors.js'

const VERSION = '1'
// Argon2id params: OWASP recommended minimum for sensitive key material
const KDF = { t: 3, m: 65536, p: 1 }

const b64u = (b) => Buffer.from(b).toString('base64url')
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))

export class FileBackend {
  #path
  #password
  #store
  #derivedKey = null  // cached after first derivation

  constructor({ path, password }) {
    if (!path)     throw new KxcoPqHsmError('FileBackend: path is required')
    if (!password) throw new KxcoPqHsmError('FileBackend: password is required')
    this.#path     = path
    this.#password = typeof password === 'string'
      ? new TextEncoder().encode(password)
      : new Uint8Array(password)
    this.#store = this.#load()
  }

  #load() {
    if (!existsSync(this.#path)) {
      const store = {
        'kxco-hsm': VERSION,
        kdf: { alg: 'argon2id', ...KDF, salt: b64u(randomBytes(32)) },
        keys: {},
      }
      writeFileSync(this.#path, JSON.stringify(store, null, 2), 'utf-8')
      return store
    }
    const store = JSON.parse(readFileSync(this.#path, 'utf-8'))
    if (store['kxco-hsm'] !== VERSION) {
      throw new KxcoPqHsmError(`unsupported store version: ${store['kxco-hsm']}`)
    }
    return store
  }

  #save() {
    writeFileSync(this.#path, JSON.stringify(this.#store, null, 2), 'utf-8')
  }

  #key() {
    if (this.#derivedKey) return this.#derivedKey
    const { salt, t, m, p } = this.#store.kdf
    this.#derivedKey = argon2id(this.#password, unb64u(salt), { t, m, p, dkLen: 32 })
    return this.#derivedKey
  }

  async store(label, alg, publicKey, secretKey) {
    const nonce = randomBytes(12)
    const ct    = gcm(this.#key(), nonce).encrypt(new Uint8Array(secretKey))
    this.#store.keys[label] = {
      alg,
      publicKey:  b64u(publicKey),
      nonce:      b64u(nonce),
      ciphertext: b64u(ct),
    }
    this.#save()
  }

  async loadSecret(label) {
    const entry = this.#store.keys[label]
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    const secretKey = gcm(this.#key(), unb64u(entry.nonce)).decrypt(unb64u(entry.ciphertext))
    return { alg: entry.alg, secretKey }
  }

  async getPublicKey(label) {
    const entry = this.#store.keys[label]
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    return { alg: entry.alg, publicKey: unb64u(entry.publicKey) }
  }

  async listKeys() {
    return Object.entries(this.#store.keys).map(([label, { alg }]) => ({ label, alg }))
  }

  async deleteKey(label) {
    if (!this.#store.keys[label]) throw new KxcoPqHsmError(`key not found: ${label}`)
    delete this.#store.keys[label]
    this.#save()
  }
}
