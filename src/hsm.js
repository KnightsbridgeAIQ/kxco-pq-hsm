import { mlDsa, mlKem } from 'kxco-post-quantum'
import { KxcoPqHsmError } from './errors.js'

export class PqHsm {
  constructor(backend) {
    if (!backend) throw new KxcoPqHsmError('backend is required')
    this._backend = backend
  }

  async keygen(label, alg = 'ml-dsa-65') {
    if (alg !== 'ml-dsa-65' && alg !== 'ml-kem-768') {
      throw new KxcoPqHsmError(`unsupported algorithm '${alg}' — use 'ml-dsa-65' or 'ml-kem-768'`)
    }
    const kp = alg === 'ml-dsa-65'
      ? mlDsa.ml_dsa65.keygen()
      : mlKem.ml_kem768.keygen()

    await this._backend.store(label, alg, kp.publicKey, kp.secretKey)
    kp.secretKey.fill(0)
    return { publicKey: kp.publicKey }
  }

  async sign(label, message) {
    const { alg, secretKey } = await this._backend.loadSecret(label)
    if (alg !== 'ml-dsa-65') {
      throw new KxcoPqHsmError(`key '${label}' is ${alg} — sign requires ml-dsa-65`)
    }
    try {
      return Buffer.from(mlDsa.sign(secretKey, new Uint8Array(message)), 'hex')
    } finally {
      secretKey.fill(0)
    }
  }

  async decapsulate(label, ciphertext) {
    const { alg, secretKey } = await this._backend.loadSecret(label)
    if (alg !== 'ml-kem-768') {
      throw new KxcoPqHsmError(`key '${label}' is ${alg} — decapsulate requires ml-kem-768`)
    }
    try {
      return new Uint8Array(
        mlKem.decapsulate(new Uint8Array(ciphertext), new Uint8Array(secretKey))
      )
    } finally {
      secretKey.fill(0)
    }
  }

  async getPublicKey(label) {
    return (await this._backend.getPublicKey(label)).publicKey
  }

  async listKeys() {
    return this._backend.listKeys()
  }

  async deleteKey(label) {
    return this._backend.deleteKey(label)
  }
}
