import { KxcoPqHsmError } from '../errors.js'

// The one PKCS#11 v3.2 call pkcs11js does not expose: C_DecapsulateKey.
//
// pkcs11js 2.1.x binds the v2.40 function list, which has no key-encapsulation
// functions. This reaches the same library through C_GetInterface("PKCS 11",
// 3.2) with koffi and calls C_DecapsulateKey on the session pkcs11js already
// opened and logged in. Loading the library a second time returns the image
// already in the process, so the session, the login and the key handles are
// shared.
//
// Function order and constant values are the OASIS PKCS#11 v3.2 header's
// (pkcs11f.h, pkcs11t.h). Cryptoki structures are packed to one byte on
// Windows and naturally aligned elsewhere; CK_ULONG is the platform's unsigned
// long. Tested against kryoptic on Linux x86_64.

// CK_FUNCTION_LIST_3_2 member order, verbatim from pkcs11f.h, up to the entry
// needed here.
const NAMES = ('C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo C_GetTokenInfo ' +
  'C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN C_SetPIN C_OpenSession C_CloseSession ' +
  'C_CloseAllSessions C_GetSessionInfo C_GetOperationState C_SetOperationState C_Login C_Logout C_CreateObject ' +
  'C_CopyObject C_DestroyObject C_GetObjectSize C_GetAttributeValue C_SetAttributeValue C_FindObjectsInit ' +
  'C_FindObjects C_FindObjectsFinal C_EncryptInit C_Encrypt C_EncryptUpdate C_EncryptFinal C_DecryptInit ' +
  'C_Decrypt C_DecryptUpdate C_DecryptFinal C_DigestInit C_Digest C_DigestUpdate C_DigestKey C_DigestFinal ' +
  'C_SignInit C_Sign C_SignUpdate C_SignFinal C_SignRecoverInit C_SignRecover C_VerifyInit C_Verify ' +
  'C_VerifyUpdate C_VerifyFinal C_VerifyRecoverInit C_VerifyRecover C_DigestEncryptUpdate C_DecryptDigestUpdate ' +
  'C_SignEncryptUpdate C_DecryptVerifyUpdate C_GenerateKey C_GenerateKeyPair C_WrapKey C_UnwrapKey C_DeriveKey ' +
  'C_SeedRandom C_GenerateRandom C_GetFunctionStatus C_CancelFunction C_WaitForSlotEvent C_GetInterfaceList ' +
  'C_GetInterface C_LoginUser C_SessionCancel C_MessageEncryptInit C_EncryptMessage C_EncryptMessageBegin ' +
  'C_EncryptMessageNext C_MessageEncryptFinal C_MessageDecryptInit C_DecryptMessage C_DecryptMessageBegin ' +
  'C_DecryptMessageNext C_MessageDecryptFinal C_MessageSignInit C_SignMessage C_SignMessageBegin ' +
  'C_SignMessageNext C_MessageSignFinal C_MessageVerifyInit C_VerifyMessage C_VerifyMessageBegin ' +
  'C_VerifyMessageNext C_MessageVerifyFinal C_EncapsulateKey C_DecapsulateKey').split(' ')

let _koffi = null
async function loadKoffi() {
  if (_koffi) return _koffi
  try {
    const imported = await import('koffi')
    _koffi = imported.default ?? imported
    return _koffi
  } catch {
    throw new KxcoPqHsmError('koffi is not installed — run: npm install koffi (needed for on-token ML-KEM)')
  }
}

/**
 * Bind C_DecapsulateKey from the PKCS#11 library at `libraryPath`.
 *
 * @returns {Promise<(session: number, mechanism: number, privateKey: number,
 *   template: Array<{type: number, value: boolean|number}>, ciphertext: Uint8Array) => number>}
 *   a function returning the handle of the secret-key object the token created
 */
export async function bindDecapsulate(libraryPath) {
  const koffi = await loadKoffi()
  const UL = 'unsigned long'
  const define = process.platform === 'win32' ? koffi.pack : koffi.struct
  const CK_VERSION = define({ major: 'uint8_t', minor: 'uint8_t' })
  const CK_INTERFACE = define({ pInterfaceName: 'const char *', pFunctionList: 'void *', flags: UL })
  const CK_MECHANISM = define({ mechanism: UL, pParameter: 'void *', ulParameterLen: UL })
  const CK_ATTRIBUTE = define({ type: UL, pValue: 'void *', ulValueLen: UL })
  const LIST = define({ version: CK_VERSION, fn: koffi.array('void *', NAMES.length) })

  const lib = koffi.load(libraryPath)
  const getInterface = lib.func('C_GetInterface', UL, ['const char *', koffi.pointer(CK_VERSION), koffi.out(koffi.pointer(koffi.pointer(CK_INTERFACE))), UL])
  const out = [null]
  const rv = getInterface('PKCS 11', { major: 3, minor: 2 }, out, 0)
  if (rv !== 0) {
    throw new KxcoPqHsmError(`the PKCS#11 library offers no v3.2 interface (C_GetInterface returned 0x${rv.toString(16)})`)
  }
  const list = koffi.decode(koffi.decode(out[0], CK_INTERFACE).pFunctionList, LIST)
  const proto = koffi.proto(UL, [UL, koffi.pointer(CK_MECHANISM), UL, koffi.pointer(CK_ATTRIBUTE), UL, 'uint8_t *', UL, koffi.out(koffi.pointer(UL))])
  const fn = koffi.decode(list.fn[NAMES.indexOf('C_DecapsulateKey')], proto)
  const ulSize = koffi.sizeof(UL)

  const encode = (v) => {
    if (typeof v === 'boolean') return Buffer.from([v ? 1 : 0])
    const b = Buffer.alloc(ulSize)
    if (ulSize === 8) b.writeBigUInt64LE(BigInt(v)); else b.writeUInt32LE(v)
    return b
  }

  return (session, mechanism, privateKey, template, ciphertext) => {
    const attrs = template.map(({ type, value }) => {
      const pValue = encode(value)
      return { type, pValue, ulValueLen: pValue.length }
    })
    const handle = [0]
    const r = fn(session, { mechanism, pParameter: null, ulParameterLen: 0 }, privateKey,
      attrs, attrs.length, Buffer.from(ciphertext), ciphertext.length, handle)
    if (r !== 0) throw new KxcoPqHsmError(`C_DecapsulateKey returned 0x${r.toString(16)}`)
    return handle[0]
  }
}
