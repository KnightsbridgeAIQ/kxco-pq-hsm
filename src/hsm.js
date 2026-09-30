import { mlDsa, mlKem } from 'kxco-post-quantum'
import { KxcoPqHsmError } from './errors.js'

// Bytes are taken as they are, a typed array or DataView as the bytes it
// covers, and text (for a message) as its UTF-8. Anything else is refused:
// `new Uint8Array('hello')` is empty and `new Uint8Array(12)` is twelve zero
// bytes, so converting it would sign something other than what was passed.
function bytes(value, what, { text = false } = {}) {
  if (value instanceof Uint8Array) return new Uint8Array(value)
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0))
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength))
  }
  if (text && typeof value === 'string') return new TextEncoder().encode(value)
  throw new KxcoPqHsmError(`${what} must be ${text ? 'text, ' : ''}a Uint8Array or Buffer`)
}

// A label is the name a key is stored and found under, so it must be text.
function checkLabel(label) {
  if (typeof label !== 'string' || label === '') {
    throw new KxcoPqHsmError('label must be a non-empty string')
  }
}

export class PqHsm {
  constructor(backend) {
    if (!backend) throw new KxcoPqHsmError('backend is required')
    this._backend = backend
  }

  /**
   * Generate a key.
   *
   * Where the backend can generate on the token, it does, and the private key
   * is never in this process at any point. Otherwise the pair is generated
   * here and handed to the backend to protect at rest, which is a real
   * property but a different one: the key exists in host memory at generation
   * and again on every signature.
   *
   * Through 1.3.x there was only the second path, while `signingMode` could
   * still report 'on-token'. That is the defect this release closes.
   */
  async keygen(label, alg = 'ml-dsa-65') {
    checkLabel(label)
    if (alg !== 'ml-dsa-65' && alg !== 'ml-kem-768') {
      throw new KxcoPqHsmError(`unsupported algorithm '${alg}' — use 'ml-dsa-65' or 'ml-kem-768'`)
    }

    if (alg === 'ml-dsa-65' &&
        this._backend.canGenerateOnToken &&
        typeof this._backend.keygenOnToken === 'function') {
      return this._backend.keygenOnToken(label, alg)
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
    checkLabel(label)
    const msg = bytes(message, 'message', { text: true })
    // Prefer the token. Where the backend can sign inside the hardware, the
    // private key never enters host memory at all, and there is nothing here
    // to zero afterwards because nothing was ever unwrapped.
    if (this._backend.signingMode === 'on-token' && typeof this._backend.signOnToken === 'function') {
      return Buffer.from(await this._backend.signOnToken(label, msg))
    }

    const { alg, secretKey } = await this._backend.loadSecret(label)
    if (alg !== 'ml-dsa-65') {
      throw new KxcoPqHsmError(`key '${label}' is ${alg} — sign requires ml-dsa-65`)
    }
    try {
      return Buffer.from(mlDsa.sign(secretKey, msg), 'hex')
    } catch (e) {
      throw new KxcoPqHsmError(`cannot sign with '${label}': ${e.message}`)
    } finally {
      // The key was in host memory for the duration of this call. Zeroing it
      // bounds the window; it does not remove it.
      secretKey.fill(0)
    }
  }

  async decapsulate(label, ciphertext) {
    checkLabel(label)
    const ct = bytes(ciphertext, 'ciphertext')
    const { alg, secretKey } = await this._backend.loadSecret(label)
    if (alg !== 'ml-kem-768') {
      throw new KxcoPqHsmError(`key '${label}' is ${alg} — decapsulate requires ml-kem-768`)
    }
    try {
      return new Uint8Array(
        mlKem.decapsulate(ct, new Uint8Array(secretKey))
      )
    } catch (e) {
      // A ciphertext of the wrong length, or a stored secret that is not an
      // ML-KEM-768 key. A well-formed but wrong ciphertext does not throw: it
      // gives an unrelated secret, as FIPS 203 implicit rejection specifies.
      throw new KxcoPqHsmError(`cannot decapsulate with '${label}': ${e.message}`)
    } finally {
      secretKey.fill(0)
    }
  }

  async getPublicKey(label) {
    checkLabel(label)
    return (await this._backend.getPublicKey(label)).publicKey
  }

  async listKeys() {
    return this._backend.listKeys()
  }

  async deleteKey(label) {
    checkLabel(label)
    return this._backend.deleteKey(label)
  }
}
