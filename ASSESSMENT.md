# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

Post-quantum key custody on a PKCS#11 token. It is the package that takes the
private key out of the process.

**`Pkcs11Backend` generates ML-DSA keys on the token.** `C_GenerateKeyPair`
with `CKA_EXTRACTABLE=false` and `CKA_SENSITIVE=true`, and signing through
`C_Sign`. The private key never enters a JavaScript heap, never appears in a
core dump, and cannot be exported by the process that uses it. That is the
strongest statement available about a signing key on a general-purpose host,
and it is the specific mitigation the primitives package's own threat model
names first: it removes the whole side-channel column, because the code that
touches the secret is not this code.

**On-token keys survive a restart.** They live in the token, not the process,
which is what makes them an institutional identity rather than a session key.

**Three backends, so the same code runs everywhere it needs to.**
`MemoryBackend` for tests, `FileBackend` for development, `Pkcs11Backend` for
custody. One API across all three: a deployment moves from a laptop to an HSM by
changing the backend, not the application.

**`signingMode` reports what the token actually did.** It records whether a
probe signature succeeded on this backend, so an operator can confirm the
custody path is live rather than assume it. Per token rather than per key, and
the README is explicit about that.

## Scope

The assurance a buyer wants from custody is mostly an assurance about the token,
and this package is the seam that lets them have it. A FIPS 140-3 Level 3
certificate covers the module it was issued for; what this does is keep your key
inside that module, so the certificate you already hold applies to the key you
actually sign with. Using it confers no validation of its own, and the README
says so in those words.

Two boundaries worth naming because they decide what to test:

- **The PKCS#11 module is the vendor's.** What happens between that library and
  the hardware, including the transport to a network HSM, is their design and
  their certificate's scope.
- **On-token generation covers ML-DSA, and ML-KEM when `mlKemMechanism` is
  set.** Without that option, `decapsulate` unwraps ML-KEM into host memory. With
  it, ML-KEM keys are generated and decapsulated on the token through PKCS#11
  v3.2 `C_DecapsulateKey`, tested against kryoptic on Linux and not yet against a
  hardware token. The shared secret is returned to the process in both modes.

Nothing in `src/` opens a socket. The only external interface is the PKCS#11
module on the local machine.

## Agility

**Inherited.** Parameter sets and the two interchangeable backends belong to
`kxco-post-quantum`.

**Bounded by firmware, and that is the useful thing to know.** A token performs
the mechanisms its firmware implements. Everywhere else in this family a
parameter-set change is a release; here it is a conversation with the vendor
first. That makes this the one package where a migration date depends on
somebody else's roadmap, which is exactly why it belongs in a plan rather than
being discovered during one. Ask the token vendor for their post-quantum
mechanism roadmap before committing to a date.

`signingMode` and the mechanism list are how a deployment answers that question
against real hardware rather than a datasheet.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.
`@noble/ciphers` and `@noble/hashes` are pinned exactly.

**Supported versions.** One line moving forward. Fixes land in the next release.

**`pkcs11js` is an optional dependency**, and deliberately: it is a native
binding, so the package installs and the memory and file backends work on a
machine with no toolchain, and the on-token path is available wherever the
binding builds. On a machine without it, `npm sbom` reports `ESBOMPROBLEMS`
because a locked package is absent from the tree; install the optional
dependency, or generate the SBOM in CI where it is present.

**Testing custody.** SoftHSM is what the integration tests run against and it is
a software token, so it proves the code path rather than the custody. The
README's **Testing on-token custody** section covers proving it against real
hardware, which is the test that matters before go-live.

## Correcting this document

Every claim here is checkable against `src/` and the README. If one does not
match, that is a defect worth reporting through the repository's issues.
