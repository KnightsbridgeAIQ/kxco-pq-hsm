# Changelog

## 1.2.0

### Corrected

The README claimed `@noble/post-quantum` was audited by Cure53 in 2024.
It is maintainer-audited (v0.6.1, April 2026), not Cure53-audited.

The other Noble packages were audited separately and at different dates, and
none of those engagements reached the post-quantum package:

| Package | Audited by |
|---|---|
| `@noble/post-quantum` | maintainer-audited |
| `@noble/hashes` | Cure53, Jan 2022, v1.0.0 |
| `@noble/curves` | Trail of Bits Feb 2023; Kudelski Sep 2023; Cure53 Sep 2024 |
| `@noble/ciphers` | Cure53, Sep 2024, v1.0.0 |

Dates from `kxco-post-quantum/audit/dependency-review.json`, which is generated
by `audit/run-audit.mjs` rather than written by hand.

Documentation only. No code changed and no behaviour changed.

### Pkcs11Backend now says what it actually does

The backend table described `Pkcs11Backend` as "Hardware-backed production;
FIPS 140-2/3", with the security property "private key material wrapped by an
AES-256 key that never leaves the HSM". The second half is true. The first half
invited a reading the code does not support.

**Signing does not happen on the token.** The HSM holds an AES-256 wrapping
key. To sign, the ML-DSA private key is unwrapped **into process memory**, used
by `mlDsa.sign`, and zeroed immediately afterwards (`hsm.js` does this in a
`finally` block). The key does exist in process memory during each signature.

That is still worth having — a stolen disk or database yields nothing without
the token — and it is materially weaker than what "HSM-backed signing" normally
means. No PKCS#11 token on the market signs ML-DSA-65 today, so this package
cannot ask one to, and no configuration will change that.

The "When to use this" section previously said this package suited
"deployments where private keys must never exist in process memory between
operations" and "compliance requirements such as FIPS 140-2/3, where a hardware
boundary is mandatory". The first is now scoped to *between* operations, which
is what is true. The second is removed: **this package is not a FIPS 140-2 or
140-3 validated module, and pairing it with a validated HSM does not make it
one.**

Version is 1.2.0 rather than 1.1.3 because a reader acting on the old table
could have made a compliance decision on it.
