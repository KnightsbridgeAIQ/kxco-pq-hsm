/// <reference types="node" />

/**
 * A key's algorithm, fixed when it is generated. The ML-DSA parameter set is
 * chosen per key: 'ml-dsa-87' (the default) or 'ml-dsa-65'. A KEM key is
 * 'ml-kem-1024' or 'ml-kem-768'.
 */
export type HsmAlgorithm = 'ml-dsa-87' | 'ml-dsa-65' | 'ml-kem-1024' | 'ml-kem-768'

export interface KeyInfo {
  label: string
  alg:   HsmAlgorithm
}

// ── PqHsm ────────────────────────────────────────────────────────────────────

export declare class PqHsm {
  constructor(backend: MemoryBackend | FileBackend | Pkcs11Backend)

  /**
   * Generate and store a keypair. Returns the public key only. The default
   * algorithm is 'ml-dsa-87'; pass 'ml-dsa-65' for an ML-DSA-65 key, or
   * 'ml-kem-1024' (FIPS 203, Category 5) for a KEM key.
   */
  keygen(label: string, alg?: HsmAlgorithm): Promise<{ publicKey: Uint8Array }>

  /**
   * Sign `message` with the ML-DSA key at `label`, under the parameter set the
   * key was generated with. A key whose stored bytes are the size of the other
   * set is refused.
   */
  sign(label: string, message: Uint8Array | Buffer): Promise<Uint8Array>

  /**
   * Decapsulate a KEM ciphertext with the ML-KEM key at `label`, under the
   * parameter set the key was generated with ('ml-kem-1024' or 'ml-kem-768').
   * A ciphertext of the other set's size, or a stored key of the other set's
   * size, is refused.
   */
  decapsulate(label: string, ciphertext: Uint8Array | Buffer): Promise<Uint8Array>

  /**
   * Return the public key for `label`. An ML-DSA public key whose size is not
   * that of its stored parameter set is refused.
   */
  getPublicKey(label: string): Promise<Uint8Array>

  /** List all stored key labels and algorithms. */
  listKeys(): Promise<KeyInfo[]>

  /** Delete the key at `label`. */
  deleteKey(label: string): Promise<void>
}

// ── MemoryBackend ─────────────────────────────────────────────────────────────

/** In-memory backend. Keys are lost on process exit. For dev and testing. */
export declare class MemoryBackend {
  constructor()
}

// ── FileBackend ───────────────────────────────────────────────────────────────

export interface FileBackendOptions {
  /** Path to the encrypted JSON key store. Created automatically if absent. */
  path:     string
  /** Passphrase for Argon2id key derivation (OWASP-minimum params: t=3, m=65536, p=1). */
  password: string | Uint8Array
}

/** Argon2id-encrypted JSON file backend. */
export declare class FileBackend {
  constructor(options: FileBackendOptions)
}

// ── Pkcs11Backend ─────────────────────────────────────────────────────────────

export interface Pkcs11BackendOptions {
  /** Path to the PKCS#11 shared library (e.g. `/usr/lib/softhsm/libsofthsm2.so`). */
  libraryPath:   string
  /** Slot index. Default `0`. */
  slot?:         number
  /** HSM user PIN. */
  pin:           string
  /** Label for the AES-256 wrapping key. Default `"kxco-pq-wrap"`. */
  wrapKeyLabel?: string
  /**
   * The token's ML-DSA signing mechanism. Supplying it enables on-token
   * generation and signing, and `open()` refuses to start if the token does
   * not advertise it. Each key's parameter set is chosen by the algorithm
   * passed to `keygen` and written to CKA_PARAMETER_SET.
   */
  mlDsaMechanism?: number
  /** The token's ML-DSA key-pair generation mechanism. Default `0x1c`. */
  mlDsaKeyPairGenMechanism?: number
}

/**
 * PKCS#11 backend (SoftHSM2, Luna, Utimaco, YubiKey).
 * Requires the optional `pkcs11js` peer dependency.
 * Call `await backend.open()` before passing to `PqHsm`.
 */
export declare class Pkcs11Backend {
  constructor(options: Pkcs11BackendOptions)
  /** Connect to the HSM slot and initialise the wrapping key. */
  open(): Promise<this>
  /** Log out and close the PKCS#11 session. */
  close(): void
}

export class KxcoPqHsmError extends Error {
  name: 'KxcoPqHsmError'
}
