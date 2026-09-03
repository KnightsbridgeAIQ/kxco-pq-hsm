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

  /**
   * Where a signature is actually produced: 'on-token' or 'in-process'.
   *
   * Read it rather than assuming. A control that requires key material never
   * to leave the cryptographic boundary is satisfied only by 'on-token'.
   */
  get signingMode() {
    return this._backend.signingMode === 'on-token' ? 'on-token' : 'in-process'
  }

  async sign(label, message) {
    // Prefer the token. Where the backend can sign inside the hardware, the
    // private key never enters host memory at all, and there is nothing here
    // to zero afterwards because nothing was ever unwrapped.
    if (this._backend.signingMode === 'on-token' && typeof this._backend.signOnToken === 'function') {
      return Buffer.from(await this._backend.signOnToken(label, new Uint8Array(message)))
    }

    const { alg, secretKey } = await this._backend.loadSecret(label)
    if (alg !== 'ml-dsa-65') {
      throw new KxcoPqHsmError(`key '${label}' is ${alg} — sign requires ml-dsa-65`)
    }
    try {
      return Buffer.from(mlDsa.sign(secretKey, new Uint8Array(message)), 'hex')
    } finally {
      // The key was in host memory for the duration of this call. Zeroing it
      // bounds the window; it does not remove it.
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
