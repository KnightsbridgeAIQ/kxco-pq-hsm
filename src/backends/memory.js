import { KxcoPqHsmError } from '../errors.js'

export class MemoryBackend {
  #keys = new Map()  // label → { alg, publicKey, secretKey }

  async store(label, alg, publicKey, secretKey) {
    this.#keys.set(label, {
      alg,
      publicKey: new Uint8Array(publicKey),
      secretKey: new Uint8Array(secretKey),
    })
  }

  async loadSecret(label) {
    const entry = this.#keys.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    return { alg: entry.alg, secretKey: new Uint8Array(entry.secretKey) }
  }

  async getPublicKey(label) {
    const entry = this.#keys.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    return { alg: entry.alg, publicKey: new Uint8Array(entry.publicKey) }
  }

  async listKeys() {
    return [...this.#keys.entries()].map(([label, { alg }]) => ({ label, alg }))
  }

  async deleteKey(label) {
    const entry = this.#keys.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    entry.secretKey.fill(0)
    this.#keys.delete(label)
  }
}
