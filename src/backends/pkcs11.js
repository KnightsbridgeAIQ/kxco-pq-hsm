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

// PKCS#11 v3.2 values, taken from the specification header rather than guessed.
// A token that predates v3.2 exposes ML-DSA under a vendor-defined value, which
// is why both are constructor options.
const CKM_ML_DSA_KEY_PAIR_GEN = 0x1c
const CKM_ML_DSA              = 0x1d
const CKK_ML_DSA              = 0x4a
const CKA_PARAMETER_SET       = 0x61d
const CKP_ML_DSA_65           = 2

// Signed once against a freshly generated handle to establish that the token
// really does produce signatures, before anything is allowed to claim it does.
const CUSTODY_PROBE = Buffer.from('kxco-pq-hsm-custody-probe', 'utf8')

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
  #mlDsaMechanism = null
  #mlDsaKeyPairGenMechanism = null
  #parameterSet = CKP_ML_DSA_65
  #tokenSigning = false
  #mechanisms = null
  // Whether a signature has actually been produced by the token. null until
  // tried. `signingMode` reports 'on-token' only when this is true.
  #probeOk = null
  #canGenerateOnToken = false

  /**
   * @param {object} opts
   * @param {string}  opts.libraryPath  Path to PKCS#11 shared library (.so / .dll)
   * @param {number}  [opts.slot=0]     Index into C_GetSlotList(true) result
   * @param {string}  opts.pin          User PIN
   * @param {string}  [opts.wrapKeyLabel='kxco-pq-wrap']  Label for the AES-256 wrapping key
   */
  constructor({
    libraryPath, slot = 0, pin, wrapKeyLabel = 'kxco-pq-wrap',
    mlDsaMechanism, mlDsaKeyPairGenMechanism, parameterSet,
  } = {}) {
    if (!libraryPath) throw new KxcoPqHsmError('Pkcs11Backend: libraryPath is required')
    if (!pin)         throw new KxcoPqHsmError('Pkcs11Backend: pin is required')
    this.#lib       = libraryPath
    this.#slotIndex = slot
    this.#pin       = pin
    this.#wrapLabel = wrapKeyLabel
    this.#mlDsaMechanism = mlDsaMechanism ?? null
    // Defaulted rather than required: a token that offers CKM_ML_DSA almost
    // always offers the matching key-pair-gen mechanism at the spec value.
    this.#mlDsaKeyPairGenMechanism = mlDsaKeyPairGenMechanism ?? CKM_ML_DSA_KEY_PAIR_GEN
    this.#parameterSet = parameterSet ?? CKP_ML_DSA_65
  }

  /**
   * Whether this token can generate an ML-DSA key pair on itself.
   *
   * This is an advertisement — it says the mechanisms are offered, not that a
   * signature has ever been produced. It decides what to ATTEMPT. What may be
   * CLAIMED is decided by the probe; see `signingMode`.
   */
  get canGenerateOnToken() {
    return this.#canGenerateOnToken
  }

  /**
   * How this backend signs, once open(). Read it; do not assume it.
   *
   *   'on-token'  the private key was generated on the token, is marked
   *               non-extractable, and signing happens inside it. The key
   *               material never enters host memory.
   *
   *   'wrapped'   the token holds an AES-256 key that never leaves it, and the
   *               ML-DSA private key is stored encrypted under it. To sign, the
   *               key is unwrapped into process memory, used, and zeroed. A
   *               stolen disk or backup yields nothing; the key is nonetheless
   *               in host memory for the duration of each signature.
   *
   * The difference matters to a control that says key material must never exist
   * outside the cryptographic boundary, so it is reported rather than implied.
   */
  get signingMode() {
    // Both conditions, and the second one is the one that matters. Through
    // 1.3.x this getter returned 'on-token' whenever the token advertised a
    // mechanism, which is a statement about the token's feature list and not
    // about where any key lives. A caller reading it as custody was reading
    // something the package never measured.
    return this.#tokenSigning && this.#probeOk === true ? 'on-token' : 'wrapped'
  }

  /** Mechanisms the token advertises, populated by open(). For diagnostics. */
  get mechanisms() {
    return this.#mechanisms ? [...this.#mechanisms] : []
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

    // Ask the token what it can do rather than assuming.
    //
    // PKCS#11 gained ML-DSA mechanisms in v3.2, and tokens that shipped PQ
    // firmware earlier expose it under a vendor-defined value. There is no
    // single constant that is correct across the estate, so the value is
    // supplied by the operator (`mlDsaMechanism`) and confirmed against the
    // token's own list. Hardcoding a guess would either miss a token that can
    // sign, or send C_Sign a mechanism the token reads as something else.
    try {
      this.#mechanisms = this.#p11.C_GetMechanismList(slots[this.#slotIndex])
        .map((m) => (typeof m === 'object' && m !== null ? m.mechanism ?? m.type : m))
        .filter((m) => typeof m === 'number')
    } catch {
      // Not fatal: a token that will not enumerate can still wrap.
      this.#mechanisms = []
    }

    this.#tokenSigning =
      this.#mlDsaMechanism !== null && this.#mechanisms.includes(this.#mlDsaMechanism)

    this.#canGenerateOnToken =
      this.#tokenSigning && this.#mechanisms.includes(this.#mlDsaKeyPairGenMechanism)

    if (this.#mlDsaMechanism !== null && !this.#tokenSigning) {
      // Asked for on-token signing and the token does not offer it. Say so
      // loudly: silently falling back would leave an operator believing a
      // control is in force that is not.
      throw new KxcoPqHsmError(
        `mlDsaMechanism 0x${this.#mlDsaMechanism.toString(16)} is not offered by this token. ` +
        `It advertises ${this.#mechanisms.length} mechanism(s). Omit mlDsaMechanism to use ` +
        'wrapped-key signing, which keeps the key encrypted under a token-held AES key but ' +
        'unwraps it into process memory to sign.',
      )
    }

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
    // Keys generated on the token are token objects and outlive this process.
    // Reload them so a restart can find, use and destroy them: through 1.3.x
    // the key store was a process-local Map and every key vanished on exit.
    await this.#loadTokenKeys()

    return this
  }

  /**
   * Repopulate the key store from objects that live on the token.
   *
   * Matching is by CKA_ID, which is set to the label at generation time, so a
   * key generated by one process is addressable by the next one under the same
   * name. The public value is read from the public object rather than cached
   * here, because the token is the record.
   */
  async #loadTokenKeys() {
    const mod = await loadMod()
    const {
      CKA_CLASS, CKA_KEY_TYPE, CKA_ID, CKA_VALUE,
      CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    } = mod

    const privates = this.#findAll([
      { type: CKA_CLASS, value: CKO_PRIVATE_KEY },
      { type: CKA_KEY_TYPE, value: CKK_ML_DSA },
    ])

    for (const handle of privates) {
      let id
      try {
        [{ value: id }] = this.#p11.C_GetAttributeValue(this.#session, handle, [{ type: CKA_ID }])
      } catch { continue }
      const label = Buffer.from(id).toString('utf8')
      if (!label) continue

      const pubs = this.#findAll([
        { type: CKA_CLASS, value: CKO_PUBLIC_KEY },
        { type: CKA_KEY_TYPE, value: CKK_ML_DSA },
        { type: CKA_ID, value: Buffer.from(label, 'utf8') },
      ])
      let publicKey = null
      let publicHandle = null
      if (pubs.length > 0) {
        publicHandle = pubs[0]
        try {
          const [{ value }] = this.#p11.C_GetAttributeValue(this.#session, publicHandle, [{ type: CKA_VALUE }])
          publicKey = b64u(value)
        } catch { /* a token that will not release it leaves publicKey null */ }
      }

      this.#store.set(label, { alg: 'ml-dsa-65', handle, publicHandle, publicKey })
    }

    // A key that came back from the token is a key we can prove custody with.
    if (this.#tokenSigning && privates.length > 0 && this.#probeOk === null) {
      const first = [...this.#store.keys()][0]
      this.#probe(first)
    }
  }

  /** Every object matching a template. */
  #findAll(template) {
    this.#p11.C_FindObjectsInit(this.#session, template)
    const out = []
    try {
      for (;;) {
        const found = this.#p11.C_FindObjects(this.#session, 1)
        const arr = Array.isArray(found) ? found : (found ? [found] : [])
        if (arr.length === 0) break
        out.push(...arr)
      }
    } finally {
      this.#p11.C_FindObjectsFinal(this.#session)
    }
    return out
  }

  /**
   * Produce one signature through the token handle and record whether it
   * worked. This is the only thing that promotes signingMode to 'on-token'.
   */
  #probe(label) {
    const entry = this.#store.get(label)
    if (!entry?.handle) { this.#probeOk = false; return false }
    try {
      this.#p11.C_SignInit(this.#session, { mechanism: this.#mlDsaMechanism }, entry.handle)
      const out = Buffer.alloc(8192)
      const sig = this.#p11.C_Sign(this.#session, CUSTODY_PROBE, out)
      this.#probeOk = sig && sig.length > 0
    } catch {
      this.#probeOk = false
    }
    return this.#probeOk
  }

  /**
   * Generate an ML-DSA key pair ON the token.
   *
   * The private object is CKA_EXTRACTABLE=false and CKA_SENSITIVE=true, so the
   * token will not release it and this process never sees the private bytes at
   * any point — there is nothing to zero afterwards because nothing was ever
   * held. Both objects are CKA_TOKEN=true so they survive the process.
   *
   * A probe signature is taken before returning. If the token cannot sign with
   * the handle it just created, this throws rather than leaving a key that
   * reports on-token custody and fails at first use.
   */
  async keygenOnToken(label, alg = 'ml-dsa-65') {
    this.#assertOpen()
    if (alg !== 'ml-dsa-65') {
      throw new KxcoPqHsmError(`on-token generation supports ml-dsa-65, not '${alg}'`)
    }
    if (!this.#canGenerateOnToken) {
      throw new KxcoPqHsmError(
        'this token does not offer both an ML-DSA mechanism and ML-DSA key-pair generation',
      )
    }
    const mod = await loadMod()
    const {
      CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN, CKA_LABEL, CKA_ID, CKA_VALUE,
      CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_SIGN, CKA_VERIFY,
      CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    } = mod

    const id = Buffer.from(label, 'utf8')

    const publicTemplate = [
      { type: CKA_CLASS,         value: CKO_PUBLIC_KEY },
      { type: CKA_KEY_TYPE,      value: CKK_ML_DSA },
      { type: CKA_TOKEN,         value: true },
      { type: CKA_LABEL,         value: label },
      { type: CKA_ID,            value: id },
      { type: CKA_VERIFY,        value: true },
      // Required by the specification in the PUBLIC template, and the token
      // refuses the whole call without it.
      { type: CKA_PARAMETER_SET, value: this.#parameterSet },
    ]

    const privateTemplate = [
      { type: CKA_CLASS,       value: CKO_PRIVATE_KEY },
      { type: CKA_KEY_TYPE,    value: CKK_ML_DSA },
      { type: CKA_TOKEN,       value: true },
      { type: CKA_LABEL,       value: label },
      { type: CKA_ID,          value: id },
      { type: CKA_PRIVATE,     value: true },
      { type: CKA_SIGN,        value: true },
      { type: CKA_SENSITIVE,   value: true },
      // The whole point. The token will not hand this out, to us or anyone.
      { type: CKA_EXTRACTABLE, value: false },
    ]

    const pair = this.#p11.C_GenerateKeyPair(
      this.#session,
      { mechanism: this.#mlDsaKeyPairGenMechanism },
      publicTemplate,
      privateTemplate,
    )

    const publicHandle = pair.publicKey ?? pair.pubKey
    const privateHandle = pair.privateKey ?? pair.prvKey

    let publicKey = null
    const [{ value }] = this.#p11.C_GetAttributeValue(this.#session, publicHandle, [{ type: CKA_VALUE }])
    publicKey = b64u(value)

    this.#store.set(label, { alg, handle: privateHandle, publicHandle, publicKey })

    if (!this.#probe(label)) {
      throw new KxcoPqHsmError(
        `token generated a key pair for '${label}' but could not sign with it. ` +
        'Refusing to report on-token custody for a key the token will not use.',
      )
    }

    return { publicKey: new Uint8Array(unb64u(publicKey)) }
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

  /**
   * Sign on the token, without the private key entering host memory.
   *
   * Present only when `signingMode === 'on-token'`. PqHsm calls this in
   * preference to loadSecret, so the key never crosses the boundary.
   *
   * @returns {Promise<Uint8Array>} the raw signature
   */
  async signOnToken(label, message) {
    this.#assertOpen()
    if (!this.#tokenSigning) {
      throw new KxcoPqHsmError(
        'signOnToken requires a token that offers an ML-DSA mechanism; ' +
        'construct with mlDsaMechanism to enable it',
      )
    }
    const entry = this.#store.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    if (!entry.handle) {
      throw new KxcoPqHsmError(
        `key '${label}' has no token handle: it was wrapped by this package rather than ` +
        'generated on the token. Generate it with keygenOnToken() to sign on the token.',
      )
    }

    this.#p11.C_SignInit(this.#session, { mechanism: this.#mlDsaMechanism }, entry.handle)
    // ML-DSA-65 signatures are 3309 bytes; the buffer is generous rather than
    // exact so a token that pads or uses a different set does not truncate.
    const out = Buffer.alloc(8192)
    return new Uint8Array(this.#p11.C_Sign(this.#session, Buffer.from(message), out))
  }

  async loadSecret(label) {
    this.#assertOpen()
    const mod   = await loadMod()
    const entry = this.#store.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    if (entry.handle && !entry.wrapped) {
      throw new KxcoPqHsmError(
        `key '${label}' lives on the token and is non-extractable — that is the point of it. ` +
        'Use signOnToken(), which PqHsm does automatically.',
      )
    }

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
    if (!entry.publicKey) {
      throw new KxcoPqHsmError(`key '${label}' is on the token but it did not release a public value`)
    }
    return { alg: entry.alg, publicKey: new Uint8Array(unb64u(entry.publicKey)) }
  }

  async listKeys() {
    return [...this.#store.entries()].map(([label, { alg }]) => ({ label, alg }))
  }

  async deleteKey(label) {
    const entry = this.#store.get(label)
    if (!entry) throw new KxcoPqHsmError(`key not found: ${label}`)
    // A token object outlives the process, so forgetting it here would leave a
    // usable private key on the partition that nothing refers to any more.
    for (const h of [entry.handle, entry.publicHandle]) {
      if (h === undefined || h === null) continue
      try { this.#p11.C_DestroyObject(this.#session, h) } catch { /* best-effort */ }
    }
    this.#store.delete(label)
  }
}
