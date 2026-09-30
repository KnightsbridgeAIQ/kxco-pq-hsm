import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { argon2id } from '@noble/hashes/argon2.js'
import { gcm } from '@noble/ciphers/aes.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { KxcoPqHsmError } from '../errors.js'

const VERSION = '1'
// Argon2id params: OWASP recommended minimum for sensitive key material
const KDF = { t: 3, m: 65536, p: 1 }

const b64u = (b) => Buffer.from(b).toString('base64url')
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isBytes = (v) => v instanceof Uint8Array
// A value read from the store file, named in a message without the chance of
// the naming itself throwing.
const named = (v) => (typeof v === 'string' ? v : JSON.stringify(v))

export class FileBackend {
  #path
  #password
  #store
  #derivedKey = null  // cached after first derivation

  constructor({ path, password }) {
    if (!path)     throw new KxcoPqHsmError('FileBackend: path is required')
    // A number would become that many zero bytes, which anyone can reproduce,
    // so it is refused by name rather than converted.
    if (typeof password === 'number') {
      throw new KxcoPqHsmError('FileBackend: password must be a string or a Uint8Array; a number is not accepted')
    }
    if (!password) throw new KxcoPqHsmError('FileBackend: password is required')
    this.#path     = path
    if (typeof password === 'string') {
      this.#password = new TextEncoder().encode(password)
    } else if (isBytes(password) && password.length > 0) {
      this.#password = new Uint8Array(password)
    } else {
      throw new KxcoPqHsmError('FileBackend: password must be a non-empty string or Uint8Array')
    }
    this.#store = this.#load()
  }

  #load() {
    if (!existsSync(this.#path)) {
      const store = {
        'kxco-hsm': VERSION,
        kdf: { alg: 'argon2id', ...KDF, salt: b64u(randomBytes(32)) },
        keys: Object.create(null),
      }
      this.#write(store)
      return store
    }
    let store
    try {
      store = JSON.parse(readFileSync(this.#path, 'utf-8'))
    } catch (e) {
      throw new KxcoPqHsmError(`cannot read key store ${this.#path}: ${e.message}`)
    }
    if (!isObject(store)) throw new KxcoPqHsmError(`not a key store: ${this.#path}`)
    if (store['kxco-hsm'] !== VERSION) {
      throw new KxcoPqHsmError(`unsupported store version: ${named(store['kxco-hsm'])}`)
    }
    if (!isObject(store.kdf) || !isObject(store.keys)) {
      throw new KxcoPqHsmError(`key store is damaged: ${this.#path}`)
    }
    // Keys live in an object with no prototype, so a label such as
    // `constructor` or `__proto__` is an ordinary key: absent until stored,
    // and written to the file like any other. The file format is unchanged.
    store.keys = Object.assign(Object.create(null), store.keys)
    return store
  }

  #save() {
    this.#write(this.#store)
  }

  #write(store) {
    try {
      writeFileSync(this.#path, JSON.stringify(store, null, 2), 'utf-8')
    } catch (e) {
      throw new KxcoPqHsmError(`cannot write key store ${this.#path}: ${e.message}`)
    }
  }

  #key() {
    if (this.#derivedKey) return this.#derivedKey
    try {
      const { salt, t, m, p } = this.#store.kdf
      this.#derivedKey = argon2id(this.#password, unb64u(salt), { t, m, p, dkLen: 32 })
    } catch (e) {
      throw new KxcoPqHsmError(`cannot derive the key store's key: ${e.message}`)
    }
    return this.#derivedKey
  }

  #entry(label) {
    const entry = Object.hasOwn(this.#store.keys, label) ? this.#store.keys[label] : undefined
    if (entry === undefined) throw new KxcoPqHsmError(`key not found: ${label}`)
    if (!isObject(entry)) throw new KxcoPqHsmError(`key store entry for '${label}' is damaged`)
    return entry
  }

  async store(label, alg, publicKey, secretKey) {
    if (!isBytes(publicKey) || !isBytes(secretKey)) {
      throw new KxcoPqHsmError('FileBackend: public and secret keys must be a Uint8Array or Buffer')
    }
    const nonce = randomBytes(12)
    const ct    = gcm(this.#key(), nonce).encrypt(new Uint8Array(secretKey))
    const earlier = Object.hasOwn(this.#store.keys, label) ? this.#store.keys[label] : undefined
    this.#store.keys[label] = {
      alg,
      publicKey:  b64u(publicKey),
      nonce:      b64u(nonce),
      ciphertext: b64u(ct),
    }
    try {
      this.#save()
    } catch (e) {
      // What is in memory stays what is on disk.
      if (earlier === undefined) delete this.#store.keys[label]
      else this.#store.keys[label] = earlier
      throw e
    }
  }

  async loadSecret(label) {
    const entry = this.#entry(label)
    const key = this.#key()
    let secretKey
    try {
      secretKey = gcm(key, unb64u(entry.nonce)).decrypt(unb64u(entry.ciphertext))
    } catch {
      // AES-GCM cannot tell the two apart: the tag fails either way.
      throw new KxcoPqHsmError(`cannot decrypt key '${label}': wrong password, or the key store is damaged`)
    }
    return { alg: entry.alg, secretKey }
  }

  async getPublicKey(label) {
    const entry = this.#entry(label)
    if (typeof entry.publicKey !== 'string') {
      throw new KxcoPqHsmError(`key store entry for '${label}' is damaged: no public key`)
    }
    return { alg: entry.alg, publicKey: unb64u(entry.publicKey) }
  }

  async listKeys() {
    return Object.keys(this.#store.keys).map((label) => ({ label, alg: this.#entry(label).alg }))
  }

  async deleteKey(label) {
    // Presence only, so a damaged entry can still be removed.
    if (!Object.hasOwn(this.#store.keys, label)) throw new KxcoPqHsmError(`key not found: ${label}`)
    delete this.#store.keys[label]
    this.#save()
  }
}
