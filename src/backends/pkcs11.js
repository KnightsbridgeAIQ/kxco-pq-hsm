import { KxcoPqHsmError } from '../errors.js'

// Lazy-load pkcs11js so the package installs cleanly without it if only using other backends
let _pkcs11mod = null
async function loadMod() {
  if (_pkcs11mod) return _pkcs11mod
  try {
    const imported = await import('pkcs11js')
    // Native CJS addon: ESM import() wraps it in { default: exports }; named exports are unavailable
    _pkcs11mod = imported.default ?? imported
    return _pkcs11mod
  } catch {
    throw new KxcoPqHsmError('pkcs11js is not installed — run: npm install pkcs11js')
  }
}

const b64u   = (b) => Buffer.from(b).toString('base64url')
const unb64u = (s) => Buffer.from(s, 'base64url')

export class Pkcs11Backend {
  #lib
  #slotIndex
  #pin
  #wrapLabel
  #p11 = null
  #session = null
  #wrapKey = null
  // Wrapped key store: label → { alg, publicKey: b64u, nonce: b64u, wrapped: b64u }
  #store = new Map()

  /**
   * @param {object} opts
   * @param {string}  opts.libraryPath  Path to PKCS#11 shared library (.so / .dll)
   * @param {number}  [opts.slot=0]     Index into C_GetSlotList(true) result
   * @param {string}  opts.pin          User PIN
   * @param {string}  [opts.wrapKeyLabel='kxco-pq-wrap']  Label for the AES-256 wrapping key
   */
  constructor({ libraryPath, slot = 0, pin, wrapKeyLabel = 'kxco-pq-wrap' }) {
    if (!libraryPath) throw new KxcoPqHsmError('Pkcs11Backend: libraryPath is required')
    if (!pin)         throw new KxcoPqHsmError('Pkcs11Backend: pin is required')
    this.#lib       = libraryPath
    this.#slotIndex = slot
    this.#pin       = pin
    this.#wrapLabel = wrapKeyLabel
  }

  /** Connect to the HSM, login, and locate or create the AES wrapping key. */
  async open() {
    const mod = await loadMod()
    const { PKCS11,
      CKF_SERIAL_SESSION, CKF_RW_SESSION, CKU_USER,
      CKM_AES_KEY_GEN, CKO_SECRET_KEY, CKK_AES,
      CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_LABEL,
      CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE,
      CKA_ENCRYPT, CKA_DECRYPT,
    } = mod

    this.#p11 = new PKCS11()
    this.#p11.load(this.#lib)
    this.#p11.C_Initialize()

    const slots = this.#p11.C_GetSlotList(true)
    if (this.#slotIndex >= slots.length) {
      throw new KxcoPqHsmError(
        `PKCS#11 slot index ${this.#slotIndex} out of range (${slots.length} slot(s) available)`
      )
    }

    this.#session = this.#p11.C_OpenSession(
      slots[this.#slotIndex],
      CKF_SERIAL_SESSION | CKF_RW_SESSION
    )
    this.#p11.C_Login(this.#session, CKU_USER, this.#pin)

    // Find or generate the persistent AES-256 wrapping key
    this.#p11.C_FindObjectsInit(this.#session, [
      { type: CKA_CLASS, value: CKO_SECRET_KEY },
      { type: CKA_LABEL, value: this.#wrapLabel },
    ])
    const found = this.#p11.C_FindObjects(this.#session, 1)
    this.#p11.C_FindObjectsFinal(this.#session)

    if (found.length > 0) {
      this.#wrapKey = found[0]
    } else {
      this.#wrapKey = this.#p11.C_GenerateKey(
        this.#session,
        { mechanism: CKM_AES_KEY_GEN },
        [
          { type: CKA_CLASS,       value: CKO_SECRET_KEY },
          { type: CKA_KEY_TYPE,    value: CKK_AES },
          { type: CKA_VALUE_LEN,   value: 32 },
          { type: CKA_LABEL,       value: this.#wrapLabel },
          { type: CKA_TOKEN,       value: true   },   // persists across sessions
          { type: CKA_SENSITIVE,   value: true   },
          { type: CKA_EXTRACTABLE, value: false  },   // never leaves the HSM
          { type: CKA_ENCRYPT,     value: true   },
          { type: CKA_DECRYPT,     value: true   },
        ]
      )
    }
    return this
  }

  /** Logout and finalise — call when done. */
  close() {
    if (!this.#p11) return
    try { this.#p11.C_Logout(this.#session)      } catch { /* best-effort */ }
    try { this.#p11.C_CloseSession(this.#session) } catch { /* best-effort */ }
    try { this.#p11.C_Finalize()                  } catch { /* best-effort */ }
    this.#p11 = null
  }

  #assertOpen() {
    if (!this.#p11) throw new KxcoPqHsmError('Pkcs11Backend is not open — call .open() first')
  }

  #cbcParams(mod, iv) {
    return { mechanism: mod.CKM_AES_CBC_PAD, parameter: Buffer.from(iv) }
  }

  async store(label, alg, publicKey, secretKey) {
    this.#assertOpen()
    const mod  = await loadMod()
    const iv   = this.#p11.C_GenerateRandom(this.#session, Buffer.alloc(16))
    const data = Buffer.from(secretKey)
    // pkcs11js v2: C_Encrypt(session, input, outputBuffer) — AES-CBC-PAD always adds one full padding block
    const encOut = Buffer.alloc((Math.floor(data.length / 16) + 1) * 16)
    this.#p11.C_EncryptInit(this.#session, this.#cbcParams(mod, iv), this.#wrapKey)
    const wrapped = this.#p11.C_Encrypt(this.#session, data, encOut)

    this.#store.set(label, {
      alg,
      publicKey: b64u(publicKey),
      iv:        b64u(iv),
      wrapped:   b64u(wrapped),
    })
  }

  async loadSecret(label) {
    this.#assertOpen()
    const mod   = await loadMod()
    const entry = this.#store.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)

    const enc    = unb64u(entry.wrapped)
    // pkcs11js v2: C_Decrypt(session, input, outputBuffer) — output ≤ input length after padding removal
    const decOut = Buffer.alloc(enc.length)
    this.#p11.C_DecryptInit(this.#session, this.#cbcParams(mod, unb64u(entry.iv)), this.#wrapKey)
    const secretKey = this.#p11.C_Decrypt(this.#session, enc, decOut)
    return { alg: entry.alg, secretKey: new Uint8Array(secretKey) }
  }

  async getPublicKey(label) {
    this.#assertOpen()
    const entry = this.#store.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    return { alg: entry.alg, publicKey: new Uint8Array(unb64u(entry.publicKey)) }
  }

  async listKeys() {
    return [...this.#store.entries()].map(([label, { alg }]) => ({ label, alg }))
  }

  async deleteKey(label) {
    if (!this.#store.has(label)) throw new KxcoPqHsmError(`key not found: ${label}`)
    this.#store.delete(label)
  }
}
