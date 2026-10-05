// A PKCS#11 token held in memory, loaded in place of pkcs11js by the resolve
// hook in pkcs11-parameter-set.test.js.
//
// It exists so that what Pkcs11Backend writes to and reads back from
// CKA_PARAMETER_SET can be checked without hardware. It is not a test of
// custody, which softhsm-integration.test.js owns against a real token: a
// stand-in that signs will always sign. What it can show is which parameter
// set the backend asks the token for, and which algorithm it decides a key
// already on the token is.
//
// Attributes come back from C_GetAttributeValue as raw bytes, as pkcs11js
// returns them, with a CK_ULONG in the width the test seeded (8 bytes as on
// 64-bit Linux, 4 as on Windows). The token's state is on globalThis so a test
// can seed objects an earlier process left behind and read what was written.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'

export const C = {
  CKF_RW_SESSION: 0x2,
  CKF_SERIAL_SESSION: 0x4,
  CKU_USER: 1,
  CKO_PUBLIC_KEY: 2,
  CKO_PRIVATE_KEY: 3,
  CKO_SECRET_KEY: 4,
  CKK_AES: 0x1f,
  CKA_CLASS: 0x0,
  CKA_TOKEN: 0x1,
  CKA_PRIVATE: 0x2,
  CKA_LABEL: 0x3,
  CKA_VALUE: 0x11,
  CKA_KEY_TYPE: 0x100,
  CKA_ID: 0x102,
  CKA_SENSITIVE: 0x103,
  CKA_ENCRYPT: 0x104,
  CKA_DECRYPT: 0x105,
  CKA_SIGN: 0x108,
  CKA_VERIFY: 0x10a,
  CKA_VALUE_LEN: 0x161,
  CKA_EXTRACTABLE: 0x162,
  CKM_AES_KEY_GEN: 0x1080,
  CKM_AES_CBC_PAD: 0x1085,
}
// PKCS#11 v3.2 values, which pkcs11js does not export.
export const CKM_ML_DSA_KEY_PAIR_GEN = 0x1c
export const CKM_ML_DSA = 0x1d
export const CKK_ML_DSA = 0x4a
export const CKA_PARAMETER_SET = 0x61d

/** A CK_ULONG as raw little-endian bytes, `size` bytes wide. */
export function ulong(n, size = 8) {
  const b = Buffer.alloc(size)
  if (size === 4) b.writeUInt32LE(n)
  else b.writeBigUInt64LE(BigInt(n))
  return b
}

const SETS = {
  2: { keygen: () => mlDsa.ml_dsa65.keygen(), sign: (sk, m) => mlDsa.sign(sk, m) },
  3: { keygen: () => mlDsa87.ml_dsa87.keygen(), sign: (sk, m) => mlDsa87.sign(sk, m) },
}

function asBytes(v) {
  if (Buffer.isBuffer(v)) return v
  if (v instanceof Uint8Array) return Buffer.from(v)
  if (typeof v === 'number') return ulong(v)
  if (typeof v === 'boolean') return Buffer.from([v ? 1 : 0])
  if (typeof v === 'string') return Buffer.from(v, 'utf8')
  throw new Error(`fake token: cannot store attribute value ${String(v)}`)
}
const readParameterSet = (o) => (o.attrs.has(CKA_PARAMETER_SET) ? Number(o.attrs.get(CKA_PARAMETER_SET).readUIntLE(0, 4)) : null)

export function resetToken({ mechanisms = [CKM_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN, C.CKM_AES_KEY_GEN, C.CKM_AES_CBC_PAD] } = {}) {
  globalThis.__kxcoFakeToken = { objects: new Map(), next: 1, mechanisms, generated: [] }
  return globalThis.__kxcoFakeToken
}
export const token = () => globalThis.__kxcoFakeToken ?? resetToken()

function addObject(template, extra = {}) {
  const t = token()
  const handle = t.next++
  const attrs = new Map()
  for (const { type, value } of template) attrs.set(type, asBytes(value))
  t.objects.set(handle, { attrs, ...extra })
  return handle
}

/**
 * Leave an ML-DSA key pair on the token as an earlier process or another
 * application would have. `parameterSet` is the raw CKA_PARAMETER_SET bytes,
 * or undefined for none; `on` says which of the two objects carries it.
 */
export function seedKeyPair(label, { parameterSet, on = 'both', keySet = 2 } = {}) {
  const kp = SETS[keySet].keygen()
  const id = Buffer.from(label, 'utf8')
  const common = [{ type: C.CKA_KEY_TYPE, value: CKK_ML_DSA }, { type: C.CKA_ID, value: id }, { type: C.CKA_LABEL, value: label }]
  const withSet = (which) => (parameterSet !== undefined && (on === 'both' || on === which)
    ? [{ type: CKA_PARAMETER_SET, value: parameterSet }]
    : [])
  addObject([{ type: C.CKA_CLASS, value: C.CKO_PUBLIC_KEY }, ...common, { type: C.CKA_VALUE, value: kp.publicKey }, ...withSet('public')])
  addObject([{ type: C.CKA_CLASS, value: C.CKO_PRIVATE_KEY }, ...common, ...withSet('private')], { secret: kp.secretKey, keySet })
  return kp
}

const object = (h) => {
  const o = token().objects.get(h)
  if (!o) throw new Error('CKR_OBJECT_HANDLE_INVALID')
  return o
}

class PKCS11 {
  #found = []
  #signWith = null
  #cipher = null

  load() {}
  C_Initialize() {}
  C_Finalize() {}
  C_GetSlotList() { return [Buffer.from([1])] }
  C_OpenSession() { return Buffer.from([2]) }
  C_Login() {}
  C_Logout() {}
  C_CloseSession() {}
  C_GetMechanismList() { return [...token().mechanisms] }

  C_FindObjectsInit(_session, template) {
    this.#found = [...token().objects]
      .filter(([, o]) => template.every(({ type, value }) => o.attrs.has(type) && o.attrs.get(type).equals(asBytes(value))))
      .map(([h]) => h)
  }
  C_FindObjects(_session, count = 1) { return this.#found.splice(0, count) }
  C_FindObjectsFinal() { this.#found = [] }

  C_GetAttributeValue(_session, h, template) {
    const o = object(h)
    return template.map(({ type }) => {
      if (!o.attrs.has(type)) throw new Error('CKR_ATTRIBUTE_TYPE_INVALID')
      return { type, value: Buffer.from(o.attrs.get(type)) }
    })
  }

  C_GenerateKey(_session, _mechanism, template) {
    return addObject(template, { secret: randomBytes(32) })
  }

  C_GenerateKeyPair(_session, _mechanism, publicTemplate, privateTemplate) {
    token().generated.push({ publicTemplate, privateTemplate })
    const wanted = publicTemplate.find((a) => a.type === CKA_PARAMETER_SET)?.value
    const set = SETS[wanted]
    if (!set) throw new Error('CKR_TEMPLATE_INCONSISTENT')
    const kp = set.keygen()
    const recorded = { type: CKA_PARAMETER_SET, value: wanted }
    const publicKey = addObject([...publicTemplate.filter((a) => a.type !== CKA_PARAMETER_SET), recorded, { type: C.CKA_VALUE, value: kp.publicKey }])
    const privateKey = addObject([...privateTemplate, recorded], { secret: kp.secretKey })
    return { publicKey, privateKey }
  }

  C_SignInit(_session, _mechanism, h) { this.#signWith = h }
  C_Sign(_session, data) {
    const o = object(this.#signWith)
    const set = SETS[o.keySet ?? readParameterSet(o)]
    if (!set) throw new Error('CKR_KEY_TYPE_INCONSISTENT')
    return Buffer.from(set.sign(o.secret, new Uint8Array(data)), 'hex')
  }

  C_GenerateRandom(_session, buffer) { return randomBytes(buffer.length) }
  C_EncryptInit(_session, mechanism, h) { this.#cipher = createCipheriv('aes-256-cbc', object(h).secret, mechanism.parameter) }
  C_Encrypt(_session, data) { return Buffer.concat([this.#cipher.update(data), this.#cipher.final()]) }
  C_DecryptInit(_session, mechanism, h) { this.#cipher = createDecipheriv('aes-256-cbc', object(h).secret, mechanism.parameter) }
  C_Decrypt(_session, data) { return Buffer.concat([this.#cipher.update(data), this.#cipher.final()]) }

  C_DestroyObject(_session, h) { token().objects.delete(h) }
}

export default { PKCS11, ...C }
