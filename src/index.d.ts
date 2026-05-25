/// <reference types="node" />

export type HsmAlgorithm = 'ml-dsa-65' | 'ml-kem-768'

export interface KeyInfo {
  label: string
  alg:   HsmAlgorithm
}

// ── PqHsm ────────────────────────────────────────────────────────────────────

export declare class PqHsm {
  constructor(backend: MemoryBackend | FileBackend | Pkcs11Backend)

  /** Generate and store a keypair. Returns the public key only. */
  keygen(label: string, alg?: HsmAlgorithm): Promise<{ publicKey: Uint8Array }>

  /** Sign `message` with the ML-DSA-65 key at `label`. */
  sign(label: string, message: Uint8Array | Buffer): Promise<Uint8Array>

  /** Decapsulate a KEM ciphertext with the ML-KEM-768 key at `label`. */
  decapsulate(label: string, ciphertext: Uint8Array | Buffer): Promise<Uint8Array>

  /** Return the public key for `label`. */
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
