import { mlDsa, mlDsa87, mlKem } from 'kxco-post-quantum'
import { KxcoPqHsmError } from './errors.js'

// The ML-DSA parameter sets a signing key may be. The set is chosen when the
// key is generated, stored with it, and decides how it signs: a key is never
// used as the other set, and one whose stored bytes are the size of the other
// set is refused rather than tried.
const ML_DSA = {
  'ml-dsa-65': { sign: mlDsa.sign,   keygen: () => mlDsa.ml_dsa65.keygen(),   publicKey: 1952, secretKey: 4032 },
  'ml-dsa-87': { sign: mlDsa87.sign, keygen: () => mlDsa87.ml_dsa87.keygen(), publicKey: 2592, secretKey: 4896 },
}
const ALGORITHMS = [...Object.keys(ML_DSA), 'ml-kem-768']

const mlDsaSet = (alg) => (typeof alg === 'string' && Object.hasOwn(ML_DSA, alg) ? ML_DSA[alg] : null)

// Names the set whose keys are `length` bytes, for a refusal message.
function sizeOf(length, part) {
  if (typeof length !== 'number') return 'no length'
  const match = Object.keys(ML_DSA).find((alg) => ML_DSA[alg][part] === length)
  const named = part === 'publicKey' ? 'public key' : 'secret key'
  return match ? `${length} bytes, the size of an ${match} ${named}` : `${length} bytes`
}

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
   *
   * The strength is chosen per key: 'ml-dsa-65' (the default) or 'ml-dsa-87'.
   */
  async keygen(label, alg = 'ml-dsa-65') {
    checkLabel(label)
    if (!ALGORITHMS.includes(alg)) {
      throw new KxcoPqHsmError(`unsupported algorithm '${alg}': use 'ml-dsa-65', 'ml-dsa-87' or 'ml-kem-768'`)
    }
    const dsa = mlDsaSet(alg)

    if (dsa &&
        this._backend.canGenerateOnToken &&
        typeof this._backend.keygenOnToken === 'function') {
      const generated = await this._backend.keygenOnToken(label, alg)
      // The token made the key, so check it made the set that was asked for.
      if (generated?.publicKey?.length !== dsa.publicKey) {
        throw new KxcoPqHsmError(
          `the backend was asked for an ${alg} key for '${label}' and returned a public key of ` +
          `${sizeOf(generated?.publicKey?.length, 'publicKey')}`,
        )
      }
      return generated
    }

    const kp = dsa ? dsa.keygen() : mlKem.ml_kem768.keygen()

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
    try {
      // The stored set decides how the key signs.
      const dsa = mlDsaSet(alg)
      if (!dsa) {
        throw new KxcoPqHsmError(`key '${label}' is ${alg}: sign requires ml-dsa-65 or ml-dsa-87`)
      }
      if (secretKey.length !== dsa.secretKey) {
        throw new KxcoPqHsmError(
          `key '${label}' is stored as ${alg} but its secret key is ${sizeOf(secretKey.length, 'secretKey')}, ` +
          `not ${dsa.secretKey}: a key of one parameter set is not used as another`,
        )
      }
      let sig
      try {
        sig = dsa.sign(secretKey, msg)
      } catch (e) {
        throw new KxcoPqHsmError(`cannot sign with '${label}': ${e.message}`)
      }
      return Buffer.from(sig, 'hex')
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
    const { alg, publicKey } = await this._backend.getPublicKey(label)
    const dsa = mlDsaSet(alg)
    if (dsa && publicKey?.length !== dsa.publicKey) {
      throw new KxcoPqHsmError(
        `key '${label}' is stored as ${alg} but its public key is ${sizeOf(publicKey?.length, 'publicKey')}, ` +
        `not ${dsa.publicKey}: a key of one parameter set is not presented as another`,
      )
    }
    return publicKey
  }

  async listKeys() {
    return this._backend.listKeys()
  }

  async deleteKey(label) {
    checkLabel(label)
    return this._backend.deleteKey(label)
  }
}
