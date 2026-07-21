# nuntius v4 — Authoritative Protocol Specification

**Status:** Normative. Supersedes the undocumented `0x03` wire format implemented in nuntius v0.0.9.
**Version byte:** `0x04`
**Date:** 2026-07-19

This document is the single source of truth for the nuntius protocol. Four implementations
(Objective-C reference, Java, Kotlin, Swift) MUST interoperate byte-for-byte on the basis of this
document alone. Where this document and any implementation disagree, this document is correct and
the implementation has a bug.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in
RFC 2119.

---

## Table of contents

1. [Overview and threat model](#1-overview-and-threat-model)
2. [What changed versus the 0x03 format, and why](#2-what-changed-versus-the-0x03-format-and-why)
3. [Notation, primitives, and banned APIs](#3-notation-primitives-and-banned-apis)
4. [Key types](#4-key-types)
5. [Identity binding and the prekey bundle](#5-identity-binding-and-the-prekey-bundle)
6. [X3DH key agreement](#6-x3dh-key-agreement)
7. [Double Ratchet](#7-double-ratchet)
8. [AEAD construction and associated data](#8-aead-construction-and-associated-data)
9. [Wire format](#9-wire-format)
10. [Parsing and validation rules](#10-parsing-and-validation-rules)
11. [Session lifecycle](#11-session-lifecycle)
12. [State serialization](#12-state-serialization)
13. [Randomness, return values, and zeroization](#13-randomness-return-values-and-zeroization)
14. [Defect resolution table](#14-defect-resolution-table)
15. [Test vector plan](#15-test-vector-plan)
16. [Per-platform trap catalogue](#16-per-platform-trap-catalogue)
17. [Open risks and deliberate non-goals](#17-open-risks-and-deliberate-non-goals)
18. [Constant reference](#18-constant-reference)
19. [Recorded decisions and rejected alternatives](#19-recorded-decisions-and-rejected-alternatives)

---

## 1. Overview and threat model

### 1.1 What the protocol does

nuntius v4 provides end-to-end encrypted messaging between two parties using:

- **X3DH** (Extended Triple Diffie-Hellman) for asynchronous session establishment against a
  published prekey bundle, giving mutual authentication and forward secrecy at the handshake.
- **Double Ratchet** for per-message key derivation, giving forward secrecy and post-compromise
  security (self-healing) over the lifetime of the session.
- **ChaCha20-Poly1305** (RFC 8439, IETF variant) for authenticated encryption of every message.

Roles are fixed for the lifetime of a session:

- **A** = **initiator**. Fetches B's bundle, runs X3DH, sends the first message.
- **B** = **responder**. Published the bundle, receives the first message.

These labels never change, regardless of who sends any subsequent message. Every construction in
this document that mentions A or B means the role, not the current sender.

### 1.2 Threat model

**In scope. The protocol defends against:**

| Adversary capability | Defence |
|---|---|
| Passive network observation of ciphertext | ChaCha20-Poly1305 under per-message keys |
| Active modification, insertion, reordering, replay of ciphertext | Poly1305 tag over the full header (§8), replay rules (§7.8, §11.4) |
| Active man-in-the-middle at session setup | Mandatory Ed25519 verification of the identity binding and the signed prekey before any DH (§5, §6.3) |
| Compromise of a long-term identity private key alone, retroactively | Forward secrecy from DH3/DH4 and the ratchet (§6.4): both need `EK_A_priv`, which is zeroized at §6.3 |
| Compromise of the identity **and** signed-prekey private keys, retroactively | Forward secrecy from DH4 alone — and therefore **only** for handshakes that used an OPK, and only if that OPK private was erased per §6.6 and §13.3. See §5.6 and §17.10 |
| Compromise of session state at time *t*, for messages before *t* | Forward secrecy: chain keys and used message keys are deleted and zeroized (§7.5, §13.3) |
| Compromise of session state at time *t*, for messages after *t* | Post-compromise security: the DH ratchet re-randomises the root chain (§7.4) |
| Replay of the initial handshake message | One-time prekey consume-once plus session cache (§6.6, §11.4) |
| Malformed / hostile ciphertext (memory safety, resource exhaustion) | Fixed-offset parsing with no wire-derived lengths (§9), bounded skip and storage (§7.6), explicit maximum sizes (§10.4) |
| Unauthenticated denial of service by desynchronising a live session | Snapshot-and-commit atomicity: no state mutates until the tag verifies (§7.7) |

**Out of scope. The protocol does NOT defend against:**

- **Metadata.** Ratchet public keys, message counters `N` and `PN`, and message sizes travel in the
  clear. A network observer can count messages, observe ratchet steps, and correlate sessions by
  ratchet key. Header encryption (Double Ratchet §4) is not specified in v4.
- **Endpoint compromise at the time of use.** If the device is compromised while a session is live,
  the adversary reads plaintext.
- **Identity distribution.** This document specifies how to *verify* that a bundle is
  self-consistent and signed by a claimed identity key. It does not specify how a user learns that
  an identity key is the right one. That is the application's trust-on-first-use, directory, or
  out-of-band fingerprint problem. See §5.5 — this obligation is REQUIRED reading, because the
  two-key identity introduces a binding requirement that v3 did not have.
- **Quantum adversaries.** X25519-only agreement is harvest-now-decrypt-later vulnerable. See §17.5.
- **Traffic analysis, timing of sends, or message-size padding.**
- **Rollback of persisted state by a privileged local adversary.** Mitigated but not prevented; see
  §12.5 and §17.2.

### 1.3 Security goals, stated as checkable properties

1. Every message key MUST be a function of the X3DH output `SK`. (v3 violated this.)
2. Every message key MUST be a function of **all** of DH1, DH2, DH3, and DH4 when DH4 is present.
   (v3 violated this.)
3. No session MUST be establishable with a peer whose signed prekey signature does not verify under
   the claimed identity key. (v3 violated this.)
4. No state MUST mutate as a result of a message whose Poly1305 tag does not verify. (v3 violated
   this.)
5. No length, offset, or allocation size MUST be derived from received bytes before authentication.
   (v3 violated this.)

Properties 1, 2, and 4 are directly testable and the corresponding tests are REQUIRED (§15.4).

---

## 2. What changed versus the 0x03 format, and why

**v4 is not wire-compatible with v3 and no in-band upgrade path exists.** A v4 receiver MUST reject
a message whose first byte is not `0x04` with `ERR_UNSUPPORTED_VERSION` (§10.6). Existing identities
must be re-registered and existing sessions torn down, because the identity key type changes.

This is not a gratuitous break. Fixing defects 1 and 2 changes every derived key, so wire
compatibility was already lost the moment the protocol became correct.

| # | v3 behaviour | v4 behaviour | Why |
|---|---|---|---|
| 1 | `crypto_kdf_derive_from_key` for all KDFs | **HKDF-SHA256** (RFC 5869), Extract/Expand, everywhere | `crypto_kdf_derive_from_key` takes `const unsigned char k[32]` and reads exactly 32 bytes regardless of what is passed. The 96–128 byte X3DH input silently degraded to DH1. HKDF-Extract's `(ikm, ikm_len)` signature makes that mistake **inexpressible**. |
| 2 | One Ed25519 keypair converted to X25519 on demand | **Two keypairs**: Ed25519 `IK^s` for signing, X25519 `IK^d` for ECDH | `crypto_sign_ed25519_pk_to_curve25519` has no JDK equivalent and CryptoKit deliberately makes `Curve25519.Signing` and `Curve25519.KeyAgreement` non-interconvertible. It is also the source of v3's uninitialized-stack-buffer-as-private-key bug. |
| 3 | ECDH = `BLAKE2b(q ‖ sender_pk ‖ receiver_pk)` | ECDH = **raw RFC 7748 X25519 output** | BLAKE2b is absent from the JDK standard library and from CryptoKit. Public-key binding moves to an explicit transcript hash (§6.2), which binds strictly more material in a canonical order. |
| 4 | AES-256-CBC + PKCS7 + hand-rolled encrypt-then-MAC | **ChaCha20-Poly1305 (RFC 8439)** | Deletes `consistentTimeEqual:` (broken), the PKCS7 padding oracle behind it, the separate HMAC key, and the separate derived IV — four defect surfaces in one decision. |
| 5 | Self-describing 1-byte ratchet-header length at offset [2] | **No length field anywhere.** Header length is a constant selected by the 1-byte type field | The `*(NSInteger*)` 8-byte read of a 1-byte `NSData` has nothing left to read. The bug becomes unreachable rather than merely fixed. |
| 6 | 1-byte message counters | **uint32 big-endian**, capped at `0x7FFFFFFF` | Counters wrapped at 256. |
| 7 | Version and options bytes parsed and discarded | Version, type, and flags validated **and** covered by the AEAD associated data | A tampered version byte becomes an authentication failure, not a silent no-op. |
| 8 | Derived 16-byte CBC IV | **Random 12-byte nonce carried on the wire** | See §8.3 for the full argument. This is a deliberate reversal of a "derive the nonce" proposal, taken to make state rollback survivable rather than catastrophic. |
| 9 | `aeEncryptSimpleData:` / `aeDecryptSimpleData:` "simple" format | **Deleted**, no replacement | It was a second copy of the broken MAC comparison with no ratchet. Callers needing raw sealing should call the AEAD directly with their own key management. |
| 10 | `NSKeyedArchiver` state, base64 strings in an `NSDictionary` | **Fixed-layout binary blob**, sealed at rest | `unarchiveObjectWithData:` without secure coding is a deserialization gadget surface. No language-native serializer can produce four-way byte-identical state. |
| 11 | `crypto_sign_init` / `_update` / `_final_create` | **`crypto_sign_detached`** (pure Ed25519, RFC 8032 §5.1) | See §3.4. This is an interoperability break not previously documented. |

---

## 3. Notation, primitives, and banned APIs

### 3.1 Notation

- `‖` denotes byte-string concatenation.
- `X[a..b)` denotes the bytes of `X` from offset `a` inclusive to `b` exclusive.
- `uint16_be(v)`, `uint32_be(v)`, `uint64_be(v)` denote unsigned big-endian encodings of width 2, 4,
  and 8 bytes.
- `Z32` denotes 32 bytes of `0x00`.
- `F32` denotes 32 bytes of `0xFF`.
- All ASCII string literals in this document are **raw bytes with no NUL terminator and no length
  prefix**. C implementations MUST pass an explicit length and MUST NOT use `strlen` on a literal
  that might be embedded in a longer buffer. Every literal's exact length and hex encoding appears
  in §18.

**All multi-byte integers everywhere in this protocol — on the wire, in signed messages, in
transcripts, and in serialized state — are BIG-ENDIAN.** No implementation may `memcpy` a native
integer into a protocol buffer.

### 3.2 Primitives

| Primitive | Definition | Output |
|---|---|---|
| `SHA256(m)` | SHA-256, FIPS 180-4 | 32 bytes |
| `HMAC(k, m)` | HMAC-SHA256, RFC 2104 | 32 bytes |
| `HKDF-Extract(salt, ikm)` | `HMAC(key = salt, message = ikm)`, RFC 5869 §2.2 | 32 bytes (the PRK) |
| `HKDF-Expand(prk, info, L)` | RFC 5869 §2.3 counter loop | `L` bytes |
| `HKDF(salt, ikm, info, L)` | `HKDF-Expand(HKDF-Extract(salt, ikm), info, L)` | `L` bytes |
| `X25519(sk, pk)` | RFC 7748 §5 scalar multiplication | 32 bytes |
| `Ed25519-Sign(sk, m)` | **Pure** Ed25519, RFC 8032 §5.1 | 64 bytes |
| `Ed25519-Verify(pk, m, sig)` | **Pure** Ed25519, RFC 8032 §5.1 | boolean |
| `AEAD-Seal(k, n, pt, ad)` | ChaCha20-Poly1305, RFC 8439 §2.8 (IETF, 12-byte nonce) | `len(pt) + 16` bytes |
| `AEAD-Open(k, n, ct, ad)` | inverse | plaintext or FAIL |

**Note on HKDF-Expand with `L > 32`.** `KDF_RK` requires `L = 64`, which spans two HMAC blocks.
Any implementation that hand-rolls Expand MUST implement the `T(i)` counter loop correctly:
`T(0) = ""`, `T(i) = HMAC(prk, T(i-1) ‖ info ‖ byte(i))`, `OKM = T(1) ‖ T(2) ‖ … ` truncated to `L`.
Omitting the second block is the most common hand-rolled-HKDF bug. Validate against the RFC 5869
Appendix A test vectors before running any protocol test.

**Note on the HKDF salt.** Where this document specifies `salt = Z32`, an implementation MAY pass a
zero-length salt instead: HMAC pads any key shorter than its 64-byte block with zeros, so a
32-zero-byte salt and an empty salt produce an **identical** PRK. RFC 5869 §2.2 says as much when it
defines the default salt as `HashLen` zeros. This document specifies `Z32` for explicitness only.
Do not treat the two spellings as a divergence point; they are not one.

### 3.3 Banned APIs

The following MUST NOT appear in any nuntius v4 implementation or port:

| Banned | Reason |
|---|---|
| `crypto_kdf_derive_from_key`, `crypto_kdf_blake2b_*` | Fixed 32-byte key input; silently truncates. Root cause of defect 1. Also truncates the context to 8 bytes. |
| `crypto_kx_*` | Expresses only a single DH; BLAKE2b derivation has no JDK or CryptoKit equivalent. |
| `crypto_sign_ed25519_pk_to_curve25519`, `_sk_to_curve25519` | No JDK equivalent; no CryptoKit equivalent; source of the uninitialized-stack-buffer bug. |
| `crypto_sign_init` / `crypto_sign_update` / `crypto_sign_final_create` / `crypto_sign_final_verify` | Prehashed variant, not pure Ed25519. See §3.4. |
| `crypto_aead_chacha20poly1305_encrypt` (non-IETF) | 8-byte nonce; silently incompatible with the `_ietf_` variant. |
| `crypto_aead_xchacha20poly1305_ietf_*` | Absent from CryptoKit and from BouncyCastle's JCE provider; would force two ports to hand-roll HChaCha20. See §8.4. |
| `crypto_aead_aes256gcm_*` | Hardware-gated behind `crypto_aead_aes256gcm_is_available()`; requires a runtime availability branch the other three ports do not have. |
| `*(NSInteger*)data.bytes` and equivalent pointer-cast integer reads | Defect 6. SHOULD be enforced by a lint rule in all four repositories. |
| `NSKeyedArchiver` / `NSKeyedUnarchiver`, `java.io.Serializable`, Kotlin `@Serializable`, Swift `Codable`-to-JSON — **for key material or session state** | Defect 12; no two runtimes agree byte-for-byte. |
| `java.util.Random`, `kotlin.random.Random` | Non-cryptographic PRNG with a more inviting API than `SecureRandom`. |
| `NSParameterAssert` / `NSAssert` / `assert` as the sole guard on a non-null parameter | Compiled out under `NS_BLOCK_ASSERTIONS`, which is the default in a Release build of a framework dependency — so the guard does nothing in the configuration consumers actually ship. §13.4 requires a check that survives Release. SHOULD be enforced by a lint rule in all four repositories. |

### 3.4 Signing: use the one-shot detached API, not the multi-part API

**This is an interoperability hazard that was not previously documented, and its failure mode is
indistinguishable from an attack.**

Verified in the vendored tree: `Clibsodium.xcframework/…/sodium/crypto_sign.h` line 23 reads

```c
typedef crypto_sign_ed25519ph_state crypto_sign_state;
```

so libsodium's multi-part `crypto_sign_init` / `crypto_sign_update` / `crypto_sign_final_create`
API — which v3 uses at `IREncryptionService.m:431-433` and `:449-450` — is a **prehashed** variant,
not the pure Ed25519 of RFC 8032 §5.1 that `java.security.Signature.getInstance("Ed25519")` and
CryptoKit's `Curve25519.Signing` implement.

**Normative rule: all signing and verification in nuntius v4 MUST use pure Ed25519 —
`crypto_sign_detached` and `crypto_sign_verify_detached`.**

**Second hazard on the same API: the secret-key width.** `crypto_sign_detached(sig, siglen_p, m,
mlen, sk)` reads exactly `crypto_sign_SECRETKEYBYTES` = 64 bytes from `sk` and uses `sk[32..64)` as
the public key `A`, which is hashed into the RFC 8032 challenge. The nominal `Ed25519Private` type
in this document is the **32-byte seed** (§4.2). Passing a 32-byte seed directly to
`crypto_sign_detached` is therefore an **out-of-bounds read of 32 bytes** — undefined behaviour, not
merely a wrong-key bug — and yields a signature that fails verification against the real `IK^s`.
libsodium-based ports MUST expand the seed with `crypto_sign_seed_keypair(pk, sk, seed)`
immediately before signing and MUST zeroize the 64-byte `sk` afterwards.

**Signature bytes are NOT reproducible across platforms, and no rule in this document may assume
they are.** An earlier revision of this section claimed that a correctly expanded `sk` "produces
byte-identical output to the JDK and CryptoKit seed-based APIs". That is false, and it was measured
rather than reasoned about. RFC 8032 §5.1.6 derives the per-signature nonce deterministically from
the private key and the message, but §8.2 explicitly permits additional randomness, and Apple's
CryptoKit / swift-crypto `Curve25519.Signing` takes that option. Signing RFC 8032 §7.1 TEST 1's
empty message three times under its published seed:

```
pub  matches RFC 8032 TEST 1 : true
sig1 == sig2                 : false
sig1 == RFC 8032 expected    : false
sig1 verifies                : true
RFC 8032's own sig verifies  : true
```

Three distinct signatures, none equal to the published one, all valid. What IS universal, and what
this specification is therefore allowed to depend on:

1. **Seed → public key is deterministic and identical everywhere.** `IK^s_pub` derived from a seed
   is the same 32 bytes on libsodium, the JDK and CryptoKit. `ED25519-SEED-EXPAND` (§15.3) pins
   exactly this.
2. **Verification is deterministic and total.** Every conformant verifier accepts every valid
   signature over the same `(A, M)`, whoever produced it.

**Normative consequence for signatures on the wire and in vectors.** `IKB`, `SPK_SIG` and every
§15 signature value MUST be asserted **verify-side**: a runner MUST verify the published signature
against the published public key and message, and MUST NOT require that its own signing
reproduces the published bytes. A vector MUST carry a signature it needs as an **input**, never as
an expected **output**. An implementation MAY additionally assert byte-equality of its own
signatures **only** against itself, and MUST NOT make that a conformance condition for any other
port. See §15.3 and §15.5 rule 8.

This costs nothing cryptographically: nothing in this protocol depends on two parties producing the
same signature bytes, only on each verifying the other's. It matters because the opposite reading
makes the Swift port fail a mandatory vector for no defect at all — and §15.6 step 4 would freeze
that failure into the contract.

Implementers MUST NOT "fix" a cross-port verification failure by reaching for a prehashed mode on
the other platform. libsodium's prehashed construction is not guaranteed to match RFC 8032
Ed25519ph with an empty context, so substituting JDK `Ed25519ph` may fail too. The prescription is
unambiguous even though the precise characterisation of the libsodium variant is not: **do not use
the multi-part API at all.**

Consequence to watch for: a port that mirrors v3's signing code shape will fail signature
verification in exactly the place where failure is supposed to mean "active MITM". Every port MUST
carry the cross-language signature vector in §15.3 to catch this.

### 3.5 Dependency status

The vendored libsodium has been verified at **1.0.22**
(`Clibsodium.xcframework/…/sodium/version.h`: `SODIUM_VERSION_STRING "1.0.22"`), and
`crypto_kdf_hkdf_sha256.h` is present with the required signatures:

```c
int crypto_kdf_hkdf_sha256_extract(unsigned char prk[32],
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *ikm,  size_t ikm_len);
int crypto_kdf_hkdf_sha256_expand (unsigned char *out, size_t out_len,
                                   const char *ctx, size_t ctx_len,
                                   const unsigned char prk[32]);
```

`crypto_kdf_hkdf_sha256_expand`'s `ctx` / `ctx_len` pair **is** the HKDF `info` parameter. There is
no blocking dependency work. Note that the vendored form is an **XCFramework**, not the
`libsodium/lib/libsodium.a` static library described in `CLAUDE.md` — that documentation is stale
and should be corrected.

---

## 4. Key types

### 4.1 The two-key identity, and why

**Each identity consists of two independently generated key pairs.**

| Name | Algorithm | Public | Private | Used for |
|---|---|---|---|---|
| `IK^s` | Ed25519 | 32 bytes | **32-byte seed** (§4.2); the 64-byte libsodium `sk` = seed ‖ pk is an internal expansion only | Signing **only**. Never used for DH. |
| `IK^d` | X25519 | 32 bytes | 32 bytes | ECDH **only**. Never used for signing. |

All other keys are X25519 only, 32-byte public and 32-byte private:

| Name | Lifetime | Notes |
|---|---|---|
| `SPK` | Rotated; validity window ≤ 90 days (§5.3) | Signed prekey, identified by `spk_id` (uint32) |
| `OPK` | Single use | One-time prekey, identified by `opk_id` (uint32) |
| `EK_A` | Single handshake | Initiator's handshake ephemeral. Private half zeroized immediately after `SK` is derived. |
| `DHs` / `DHr` | Per ratchet step | Ratchet keys |

**Rationale for abandoning the Ed25519→X25519 conversion trick.** Three independent reasons, any
one of which would suffice:

1. **Portability, which is decisive.** `crypto_sign_ed25519_pk_to_curve25519` has no JDK equivalent
   at any version. CryptoKit models `Curve25519.Signing.PrivateKey` and
   `Curve25519.KeyAgreement.PrivateKey` as separate types with no bridge, deliberately. BouncyCastle
   can compute the birational map only through low-level field arithmetic that each porter would
   hand-roll differently. Keeping the trick guarantees that two of four implementations need custom
   curve arithmetic in their trusted computing base.
2. **It deletes a bug class rather than patching it.** v3 discards the return value of both
   conversions (`IREncryptionService.m:82-84`, `:115-117`). On failure — which
   `_pk_to_curve25519` genuinely returns for non-canonical or small-order Ed25519 points — the stack
   buffers `curve25519_sender_sk[32]` and `curve25519_receiver_pk[32]` are left **uninitialized** and
   are then used directly as ECDH inputs. Removing the call removes the failure mode.
3. **Cross-protocol hygiene.** Using one keypair for both a signature scheme and a key-agreement
   scheme is a documented hazard. Separation costs 32 published bytes per identity.

**The cost of the split is a new obligation**, and it is the single most important thing an
implementer must not get wrong: something must attest that a given `IK^s` and `IK^d` belong to the
same identity. §5 discharges that obligation in **both** directions. Read §5.5.

### 4.2 Encoding

- X25519 public keys are the raw 32-byte little-endian u-coordinate of RFC 7748.
- Ed25519 public keys are the raw 32-byte encoding of RFC 8032 §5.1.2.
- Ed25519 signatures are the raw 64-byte encoding of RFC 8032 §5.1.6.
- **Ed25519 private keys are the raw 32-byte RFC 8032 seed.** The 64-byte libsodium `sk`
  (= seed ‖ pk) is an internal expanded representation only: it MUST NOT appear in any nominal
  type, in any vector file, in any serialized structure, or at any API boundary. libsodium-based
  ports MUST derive it with `crypto_sign_seed_keypair(pk, sk, seed)` immediately before
  `crypto_sign_detached` and MUST zeroize it immediately after (§3.4). JDK
  `Ed25519PrivateKeySpec`, BouncyCastle `Ed25519PrivateKeyParameters`, and CryptoKit
  `Curve25519.Signing.PrivateKey(rawRepresentation:)` all take the seed directly.
- **X25519 private keys are stored in CLAMPED form:** `k[0] &= 0xF8; k[31] &= 0x7F; k[31] |= 0x40`.
  An implementation MUST apply this normalization **at generation**, to every X25519 private key it
  creates — ratchet keys, `EK_A`, `SPK`, `OPK`, and `IK^d` alike — before that key is stored
  anywhere, and MUST apply it again to any private scalar read from a state blob or from vector
  `inputs` before use. Clamping at generation rather than at serialization is what keeps the rule
  simple: the responder's initial `DHs_priv` is a copy of `SPK_B_priv` taken from the prekey store
  (§7.5), so a scalar that was not clamped when the signed prekey was generated would reach §12.1
  offset 243 unclamped and be rejected by §12.2 rule 8. Clamping is idempotent and
  RFC 7748 §5 clamps internally, so `X25519(s, P) == X25519(clamp(s), P)` for every `s`: this
  normalizes the stored representation and changes **no** cryptographic output. libsodium and
  BoringSSL/CryptoKit store the raw CSPRNG bytes and clamp inside scalar multiplication;
  BouncyCastle's `X25519.generatePrivateKey` clamps at generation. Without this rule the two write
  different bytes at state-blob offsets 243 and 274 for cryptographically identical state. Ed25519
  private keys are **not** affected: Ed25519 clamps the SHA-512 hash of the seed, not the seed
  itself, so Ed25519 seeds are stored verbatim.
- No DER, no PEM, no X.509, no ASN.1 anywhere in this protocol.

### 4.3 Nominal key types are REQUIRED

Every implementation MUST represent each key kind as a distinct type with a compile-time-fixed
length whose constructor rejects a wrong-length input (throws, returns nil, or fails to compile).
No API in the crypto layer may accept or return a bare `NSData` / `byte[]` / `Data` for key
material.

This is not style. Defect 1 was a length-mismatch that no type system was asked to catch, and
defect 2 was an ignored argument. A `RootKey` parameter that cannot be omitted and cannot be the
wrong length converts both into compile-time or construction-time failures.

Required nominal types: `Ed25519Public(32)`, `Ed25519Private(32)`, `Ed25519Signature(64)`,
`X25519Public(32)`, `X25519Private(32)`, `RootKey(32)`, `ChainKey(32)`, `MessageKey(32)`,
`MessageEncKey(32)`, `Nonce(12)`.

Every entry carries an explicit width, and `Ed25519Private` is **32 bytes — the RFC 8032 seed**
(§4.2), never libsodium's 64-byte expanded `sk`. A type with no fixed width cannot discharge the
MUST above, and the 32-vs-64 ambiguity is a memory-safety bug rather than a style question (§3.4).

Implementations MUST also keep **`KeyPair` (public + private) distinct from `PublicKey`
(public only)**, so that a public-key-only value cannot be passed where a private key is required.
v3's `IRCurve25519KeyPair` has a nullable `privateKey`, and its `isEqual:`
(`IRCurve25519KeyPair.m:176-186`) returns `NO` whenever one side has a private key and the other
does not — which is why v3's header-key comparison at `IRDoubleRatchetService.m:177` behaves
according to how a field was populated rather than according to the key bytes. In v4 the header
ratchet key is compared as **raw 32 bytes and nothing else**.

### 4.4 Public key validation

Before any X25519 public key from the wire, from a bundle, or from restored state is used, an
implementation MUST check, in this order:

1. Length is exactly 32 bytes → else `ERR_INVALID_PUBLIC_KEY`.
2. The high bit is clear: `(pk[31] & 0x80) == 0` → else `ERR_INVALID_PUBLIC_KEY`.

**Rationale for check 2.** RFC 7748 §5 has X25519 ignore bit 255 of the u-coordinate, and every
implementation (libsodium, BoringSSL/CryptoKit, BouncyCastle) masks it internally. Without this
check a single ratchet key therefore has *two* distinct wire encodings producing identical DH
output, which breaks the injectivity that the transcript hash, `SESSION_AD`, and the skipped-key map
key all depend on: an attacker could flip that bit to mint a second distinct map key or a second
distinct `DHr` for the same actual key, forcing spurious DH ratchets and state growth. Canonical
encodings never set the bit, so rejecting is free.

Implementations MUST NOT attempt to forbid the internal masking that libraries perform — that rule
would be unenforceable. Reject the encoding at the boundary instead.

Before any DH with a public key that arrived in a message:

2b. The key MUST NOT be a **reflection**: it MUST NOT equal the public key that the receiving site's
    context already fixes for it (table below) → else `ERR_INVALID_PUBLIC_KEY`. Compare all 32
    bytes. Both operands are public, so this comparison branches on no secret and need not be
    constant-time. **Before any DH.**

Check 2b is numbered `2b` rather than `3` deliberately. §5.3 rule 2, §10.1 check 7, §10.2 check 10
and §12.2 rule 7 cite "checks 1–2" by number, and §6.1, §7.4, §7.5 and §10.7 step 8 cite "check 3" by
number; renumbering would silently redirect every one of those citations, and §15.4 pins some of them
as conformance requirements.

**Check 2b is the third condition in `ERR_INVALID_PUBLIC_KEY`'s definition** — §10.5 code 7106 reads
"wrong length, high bit set, or reflected own key", and those are checks 1, 2 and 2b respectively.
It is stated here because this section is where a port looks for the definition of public-key
validation: without it, a port implements two thirds of the condition set for a code it returns, and
finds the missing third only if it happens to read §10.1, §10.2, §10.7 and §11.2 as well.

**What the key is compared against is site-specific**, because what a reflection would duplicate
depends on the message type and on how far the receiver has resolved its own state. Each site
performs the check at the earliest point at which the value it needs exists and still precedes any
DH, and each is normative in position:

| Site | Key from the wire | MUST NOT equal |
|---|---|---|
| §10.1 check 8 | type `0x01` `DHs_pub` | our own current `DHs` public |
| §10.2 check 11 | type `0x02` `DHs_pub` | `EK_A`, carried in the same message |
| §10.7 step 6 | type `0x02` `DHs_pub`, new session | the `SPK_B` public resolved from `spk_id` |
| §11.2 | type `0x02` `DHs_pub`, existing session | that session's `DHs` public |

That table is exhaustive. An implementation MUST perform all four, and MUST NOT add a fifth
comparison of its own: an extra rejection is an interop divergence in the direction that looks
prudent — it makes one port reject a message the other three accept — and §15.4 makes the exact code
returned for a given input a conformance requirement, so a port cannot add rejections privately.
Each site is covered by its own negative vector: `NEG-PUBKEY-REFLECT-01`,
`NEG-PUBKEY-REFLECT-02-EKA`, `NEG-PUBKEY-REFLECT-02-SPK` and `NEG-PUBKEY-REFLECT-02-DHS` (§15.4).

**Rationale for check 2b.** Every comparand above is a public value an attacker can obtain — a
ratchet public key is on the wire in cleartext, `SPK_B` is in the published bundle — so mounting a
reflection costs nothing, and check 3 does not catch it: a reflected key is a legitimate curve point
and the DH against it is not all-zero. Two distinct things go wrong, one per shape of the check.

1. **The DH stops being contributory.** When the arriving key is one whose private half the
   *receiver* holds (§10.1 check 8, §10.7 step 6, §11.2), the X25519 output is a function of the
   receiver's own key material alone; the sender's private key contributes nothing to it. §7.4
   exists to inject fresh peer entropy into the root chain at every ratchet step, and with
   `DHr == DHs_pub` both of that step's `KDF_RK` inputs — step 3's `dh1`, and step 5's `dh2`, since
   step 4 replaces only `DHs` and not `DHr` — are values the receiver can compute unilaterally. The
   root chain advances on a secret the peer never chose.
2. **One DH output is reused across two constructions.** When `DHs_pub == EK_A` (§10.2 check 11) no
   receiver key is involved at all: the initiator has placed one of its own public keys in two roles
   in the same message. The responder's first ratchet then computes
   `X25519(SPK_B_priv, DHr) == X25519(SPK_B_priv, EK_A)`, which is exactly DH3 of the X3DH set
   (§6.1) — a value already consumed as `IKM` for `SK` (§6.3). The first ratchet step, whose whole
   purpose is to move the root chain off `SK`, moves it nowhere new.

Neither failure is visible downstream. Both parties still derive the same keys, the AEAD still
authenticates, and the session runs normally — which is why this is a MUST at the parser, next to
the other structural checks, rather than an assertion inside the ratchet.

After **every** DH operation:

3. The 32-byte output MUST NOT be all zero. Test in constant time by OR-accumulating all 32 bytes
   and comparing the accumulator to zero. If zero: zeroize the output, abort the entire operation
   with `ERR_SMALL_ORDER_KEY`, and mutate no state.

Check 3 is the normative small-order defence and is equivalent to rejecting the twelve small-order
points. Implementations MUST NOT use a hard-coded blacklist of those points as their only check —
mistyping one of twelve 32-byte constants is a silent failure. Implementations MUST perform check 3
themselves even on platforms whose library already fails closed, so that behaviour is uniform
across all four ports. Every backend targeted here does in fact fail closed — libsodium
`crypto_scalarmult` returns `-1`; BouncyCastle `X25519Agreement` throws; JDK `XDHKeyAgreement`
throws `InvalidKeyException`; and CryptoKit / swift-crypto
`sharedSecretFromKeyAgreement` throws (measured: `underlyingCoreCryptoError(-7)` on an all-zero
public key). An earlier revision of this paragraph asserted that CryptoKit performs no such check
and that the accumulator was Swift's only defence; that was wrong.

The rule is unchanged by the correction, and this is the point of stating check 3 as a MUST rather
than as a fallback: an implementation may not skip its own check because it believes the library
underneath it already fails closed. That belief is exactly what was wrong here, it was wrong in the
direction that *sounds* safe, and a port written against the corrected text still performs the
check. Library behaviour is also not a stable property — it can change under a dependency bump with
no code change here — so the accumulator is what makes the `ERR_SMALL_ORDER_KEY` result uniform and
peer-indistinguishable regardless.

---

## 5. Identity binding and the prekey bundle

### 5.1 The identity binding signature (IKB)

Every identity MUST produce, once at registration, a self-signature binding its two public keys:

```
IKBIND_MSG = "nuntius:IKBIND:v4"   (17 bytes)
          ‖ IK^s                   (32 bytes, Ed25519 public)
          ‖ IK^d                   (32 bytes, X25519 public)
                                   = 81 bytes total

IKB = Ed25519-Sign(IK^s_priv, IKBIND_MSG)     (64 bytes)
```

`IKB` is a long-lived value stored alongside the identity. It MUST be stored, not recomputed on
demand — see §5.4.

**A party MUST verify a peer's `IKB` before performing any DH with any of that peer's keys.**
Failure is `ERR_BAD_SIGNATURE` and a hard abort.

- The **initiator A** verifies `IKB_B` when it ingests B's bundle (§6.3).
- The **responder B** verifies `IKB_A` from the type `0x02` message header (§10.7), before X3DH.

### 5.2 The signed prekey signature

```
SPK_SIGN_MSG = "nuntius:SPK:v4"       (14 bytes)
             ‖ IK^s                   (32 bytes)
             ‖ IK^d                   (32 bytes)
             ‖ uint32_be(spk_id)      (4 bytes)
             ‖ SPK                    (32 bytes, X25519 public)
             ‖ uint64_be(not_before)  (8 bytes, Unix seconds UTC)
             ‖ uint64_be(not_after)   (8 bytes, Unix seconds UTC)
                                      = 130 bytes total

SPK_SIG = Ed25519-Sign(IK^s_priv, SPK_SIGN_MSG)     (64 bytes)
```

Binding `spk_id` prevents transplanting a signature onto a different prekey slot. Binding both
identity keys ties the prekey to the whole identity, not just the signing half. Both timestamps are
inside the signature, so the validity window cannot be extended by an intermediary.

One-time prekeys are **not** individually signed. They are authenticated transitively: a wrong OPK
simply yields a different `SK` and an AEAD failure. Implementations MUST NOT invent a per-OPK
signature — doing so would diverge from every other port.

### 5.3 Bundle verification rules

Before performing **any** Diffie-Hellman with a fetched bundle, the initiator MUST, in this order:

1. Parse the bundle per §5.4; any structural failure → `ERR_BUNDLE_MALFORMED`.
2. Validate `IK^d`, `SPK`, and every `OPK` per §4.4 checks 1–2 → `ERR_INVALID_PUBLIC_KEY`.
3. `Ed25519-Verify(IK^s, IKBIND_MSG, IKB)` → else `ERR_BAD_SIGNATURE`.
4. `Ed25519-Verify(IK^s, SPK_SIGN_MSG, SPK_SIG)` → else `ERR_BAD_SIGNATURE`.
5. `not_before ≤ now < not_after` → else `ERR_PREKEY_EXPIRED`.
6. `not_after - not_before ≤ 7776000` (90 days) → else `ERR_PREKEY_EXPIRED`.

All six are hard aborts that return an error. There is no fallback and no "verify later" path.

`now` in rule 5 is Unix seconds UTC, read from the single injectable time source of §15.5 runner
rule 6. In production that source MUST be the system clock; in the conformance suite it is supplied
as `inputs.now_s`. Every clock read in this document routes through that one source — otherwise the
frozen vectors of §15.6 are not reproducible.

`IRTripleDHService initWithData:` MUST NOT re-sign a peer's prekey with the local identity key.
v3 does exactly that at `IRTripleDHService.m:66-68`, which does not merely skip verification — it
destroys the evidence by overwriting the peer's signature with a locally manufactured one that
later code would find "valid". That code is deleted.

**Signed prekey lifecycle.** The responder MUST retain the private key of the **current and exactly
one previous** signed prekey, so that messages already in flight against a just-rotated `spk_id`
still decrypt. An `spk_id` outside that set is `ERR_UNKNOWN_PREKEY_ID`. Retention of the previous
`SPK` private key MAY end once its `not_after` has passed.

`SPK_B_priv` is owned **exclusively by the prekey store** and its lifetime is governed by this
paragraph alone. No ratchet operation may shorten it: the responder's ratchet holds a *copy*
(§7.5), and §7.4 step 4 zeroizes only that copy. When retention does end — the key has left the
{current, one previous} set, or its `not_after` has passed — the private key MUST be zeroized in
place, not merely unlinked (§13.3).

**One-time prekey lifecycle.** Each OPK private MUST carry a local creation timestamp, stored in the
responder's prekey store and **NOT** published in the bundle. An unconsumed OPK MUST be deleted and
zeroized once `OPK_MAX_AGE_S` (§18) has elapsed since creation; an `opk_id` naming a deleted entry
resolves to `ERR_UNKNOWN_PREKEY_ID` like any other unknown id. Responders SHOULD replenish the
published OPK set on the same cadence. This bounds the window in §1.2's "identity **and** signed
prekey compromised" row: an OPK private that no initiator ever selects would otherwise be retained
forever, keeping DH4 — the only remaining forward-secrecy term at that point — recoverable from a
device image indefinitely.

The creation timestamp is **responder-local**. It MUST NOT be added to the §5.4 bundle OPK entry:
that entry is 36 bytes and the total-length rule `251 + 36 * opk_count` depends on it, so widening
it would break every bundle parser in every port. Published OPK expiry, if it is ever wanted,
belongs in a batched format revision.

### 5.4 Prekey bundle wire format

The bundle is what A fetches and what B publishes. It has a byte-exact encoding because all four
implementations must parse each other's bundles.

```
off   len   field                notes
----  ----  -------------------  --------------------------------------------------
0     4     magic = "NTB4"       4E 54 42 34
4     1     version = 0x04       MUST equal 0x04
5     32    IK^s                 Ed25519 identity public key
37    32    IK^d                 X25519 identity public key
69    64    IKB                  Ed25519-Sign over IKBIND_MSG (§5.1)
133   4     spk_id               uint32_be
137   32    SPK                  X25519 signed prekey public
169   8     not_before           uint64_be, Unix seconds UTC
177   8     not_after            uint64_be, Unix seconds UTC
185   64    SPK_SIG              Ed25519-Sign over SPK_SIGN_MSG (§5.2)
249   2     opk_count            uint16_be
--- fixed prefix ends: 251 bytes ---
251   36*n  opk entries          n = opk_count; each entry is:
                                   +0  4   opk_id (uint32_be)
                                   +4  32  OPK    (X25519 public)

total length MUST equal exactly 251 + 36 * opk_count, with no trailing bytes.
```

A **published** bundle MAY carry many OPKs. A bundle **fetched for a single handshake** MUST carry
`opk_count` of `0` or `1`; a fetching client that receives more MUST use only the first entry, and
MUST NOT treat additional entries as usable. The distribution server is responsible for handing out
each OPK at most once; that server is outside the scope of this document, but a server that reissues
an OPK degrades that handshake to the 3-DH case in effect and MUST be treated as a bug.

`opk_count` MUST be ≤ 1000 on parse → else `ERR_BUNDLE_MALFORMED`.

### 5.5 REQUIRED: identity is the pair

**This section is normative and closes the gap that the two-key split would otherwise open.**

An identity in nuntius v4 **is the pair `(IK^s, IK^d)`**, not either key alone.

- Applications MUST key identity lookup, contact registration, trust-store entries, pinning, and
  any displayed identity on the **pair**, or equivalently on the fingerprint below. An application
  that keys on `IK^s` alone is not conformant.
- The public fingerprint / safety number is:

  ```
  FP = SHA256( "nuntius:FP:v4"  (13 bytes)
             ‖ IK^s             (32 bytes)
             ‖ IK^d             (32 bytes) )      input = 77 bytes, output = 32 bytes
  ```

- The `IKB` signature (§5.1) is what makes the pair unforgeable, and it MUST be verified on **every**
  identity ingest — from a fetched bundle, from a type `0x02` message header, from a cached contact
  record, and after state restore. Not only on first contact.

Rationale, stated plainly because it is the design's sharpest edge: under v3's single-key identity,
possession of the identity private key was proved implicitly by DH1 and DH2, so the identity could
not be split from the key that authenticated it. The moment the identity is split into a signing key
and a DH key, the DH operations prove possession of `IK^d` only. Without `IKB` covering both keys,
and without the rule that identity means the pair, an attacker could present a victim's genuine
`IK^s` alongside an attacker-controlled `IK^d`, complete a cryptographically sound session, and be
attributed to the victim by any implementation that looks up contacts by the signing key. `IKB` plus
this section removes that possibility in both directions: A verifies `IKB_B` from the bundle, and B
verifies `IKB_A` from the message header (§10.7 step 3, **before any DH** — and §11.2 for the
existing-session path, which re-verifies rather than relying on AEAD coverage).

Negative tests for this are REQUIRED: §15.4 tests `NEG-IKB-SWAP` and `NEG-IKB-RETRANS`.

### 5.6 Prekey and identity storage at rest

**Normative.** The store holding OPK private keys, SPK private keys, and the identity private keys
`IK^s_priv` / `IK^d_priv` MUST be sealed with the construction of §12.3 — ChaCha20-Poly1305 under a
device-bound keystore key, with a fresh random 12-byte nonce stored alongside — and MUST be excluded
from application backups:

- Apple: Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, no iCloud sync.
- Android / JVM: Keystore-backed storage excluded from auto-backup.

The at-rest key MUST NOT be derived from the store's own contents. Only the plaintext session-blob
layout of §12.1 is byte-normative; the prekey store's internal format is deliberately unspecified,
because no peer ever observes it. That is precisely why it is easy to leave unsealed.

**Why this is not optional.** §12.3 seals the session blob while this store holds every input to
every future handshake. A device backup image that yields `SPK_B_priv` and the unconsumed OPK
privates collapses the forward secrecy §1.2 claims: an adversary who images the device at `t0`, goes
passive, and records A's handshake at `t1 > t0` computes DH1, DH2 and DH3 directly, and needs only
DH4 — whose private half is the OPK sitting in that same store. §8.3 already reasons about iOS device
backups as a threat to persisted ratchet state; the same threat applies with more force here,
because a session blob compromises one session and this store compromises all of them.

---

## 6. X3DH key agreement

### 6.1 The DH set

`EK_A` is a fresh X25519 key pair generated per handshake and used for nothing else.

```
DH1 = X25519(IK_A^d_priv, SPK_B)          both long-lived-ish: authenticates A to B
DH2 = X25519(EK_A_priv,   IK_B^d)         authenticates B to A
DH3 = X25519(EK_A_priv,   SPK_B)          forward secrecy
DH4 = X25519(EK_A_priv,   OPK_B)          present only when a one-time prekey is used
```

The responder computes the mirror image, in the identical order:

```
DH1 = X25519(SPK_B_priv,  IK_A^d)
DH2 = X25519(IK_B^d_priv, EK_A)
DH3 = X25519(SPK_B_priv,  EK_A)
DH4 = X25519(OPK_B_priv,  EK_A)
```

Every one of these MUST be checked per §4.4 check 3. Any all-zero output aborts the whole handshake
with `ERR_SMALL_ORDER_KEY`; no session is created and no OPK is consumed.

This DH assignment and ordering matches v3 (`IRTripleDHService.m:100-110` and `:134-145`) and is
already correct there. Only the KDF and the missing verification change.

### 6.2 The transcript hash

```
TRANSCRIPT = "nuntius:X3DH:transcript:v4"   (26 bytes)
           ‖ IK_A^s                          (32)
           ‖ IK_A^d                          (32)
           ‖ EK_A                            (32)
           ‖ IK_B^s                          (32)
           ‖ IK_B^d                          (32)
           ‖ SPK_B                           (32)
           ‖ uint32_be(spk_id)               (4)
           ‖ opk_flag                        (1)   0x00 absent, 0x01 present
           ‖ uint32_be(opk_id)               (4)   0x00000000 when opk_flag == 0x00
           ‖ OPK_B                           (32)  32 × 0x00 when opk_flag == 0x00
                                             = 259 bytes, always

TH = SHA256(TRANSCRIPT)                      (32 bytes)
```

Implementations MUST assert `len(TRANSCRIPT) == 259` before hashing. A transcript builder that
appends fixed-width fields and asserts the total is RECOMMENDED in all four languages, so that a
missing field is a test failure rather than a silent interop break.

**The transcript is fixed-length in both the OPK and no-OPK cases**, with the absent OPK encoded as
32 zero bytes rather than omitted. The field count never varies, so the builder has no conditional
structure. `opk_flag` disambiguates, so a genuine all-zero OPK public key (which §4.4 would have
rejected anyway) cannot be confused with absence.

**The transcript contains NO signature bytes.** This is deliberate and load-bearing. Hashing
`IKB` or `SPK_SIG` into `TH` would require both parties to reconstruct byte-identical 64-byte
signatures, which is not merely unsafe to assume but **measured to be false**: CryptoKit /
swift-crypto takes RFC 8032 §8.2's permitted added randomness and emits a different valid signature
each time it signs the same message under the same key (§3.4). Verifier strictness on non-canonical
`S` values and small-order `A` values also differs across libsodium, BouncyCastle, the JDK and
CryptoKit / swift-crypto (the documented "many EdDSAs" hazard, §17.8). Binding
the signed *contents* — which is what `TRANSCRIPT` does, since it carries every key and id that the
signatures cover — achieves the same binding with none of the reproducibility risk.

This transcript replaces v3's `BLAKE2b(q ‖ sender_pk ‖ receiver_pk)` ECDH wrapper and binds strictly
more material: both identity keys of both parties, the ephemeral, the signed prekey, and both key
ids, in one canonical order.

### 6.3 Deriving SK

```
IKM = F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]

      len(IKM) = 128 when opk_flag == 0x00
      len(IKM) = 160 when opk_flag == 0x01

SK  = HKDF( salt = Z32,
            ikm  = IKM,
            info = "nuntius:X3DH:v4" (15 bytes) ‖ TH (32 bytes)   = 47 bytes,
            L    = 32 )
```

`F32` is the X3DH specification's domain separator for Curve25519 (X3DH §2.2). v3 computed this
constant into a local named `separation` and then commented out its use
(`IRTripleDHService.m:92-93`, `:112`) — the intent was there, the wiring was not.

**DH4 is omitted, not zero-filled**, when no OPK is used. The `opk_flag` inside `TH` removes any
ambiguity that omission could create.

Both parties MUST assert `len(IKM) ∈ {128, 160}` and `len(SK) == 32` before proceeding. That
assertion alone would have caught defect 1 on the day it was introduced.

Immediately after `SK` is computed: zeroize `DH1`, `DH2`, `DH3`, `DH4`, `IKM`, and `EK_A_priv`.

### 6.4 Why this fixes forward secrecy

v3 passed the 96–128 byte `IKM` to `crypto_kdf_derive_from_key`, whose key parameter is
`const unsigned char k[crypto_kdf_KEYBYTES]` — exactly 32 bytes. Only DH1 was ever read. DH1 is
`X25519(IK_A^d, SPK_B)`, both of which are long-lived, so there was no forward secrecy from the
handshake and the one-time prekey contributed nothing. Both parties still agreed, so every test
passed.

HKDF-Extract's `(ikm, ikm_len)` signature cannot express that mistake: the length travels with the
pointer. This is the whole reason for the KDF change — the fix is structural, not a corrected length.

### 6.5 Session associated data

```
SESSION_AD = "nuntius:AD:v4"   (13 bytes)
           ‖ IK_A^s            (32)
           ‖ IK_A^d            (32)
           ‖ IK_B^s            (32)
           ‖ IK_B^d            (32)
                               = 141 bytes
```

A is the **initiator** and B the **responder**, by role, fixed at handshake time and never
reordered. `SESSION_AD` is computed once, stored in session state as bytes (§12), and prefixed to
the associated data of **every** AEAD operation in the session. It is never transmitted.

**Sub-offsets, stated normatively so the stored bytes are readable rather than opaque.** Both
identities of a session are recoverable from the stored `SESSION_AD` alone, which is why neither
identity key is duplicated elsewhere in the state blob:

```
SESSION_AD[0..13)     "nuntius:AD:v4"
SESSION_AD[13..45)    IK_A^s          blob offset 19   (§12.1: 6 + 13)
SESSION_AD[45..77)    IK_A^d          blob offset 51
SESSION_AD[77..109)   IK_B^s          blob offset 83
SESSION_AD[109..141)  IK_B^d          blob offset 115
```

The **peer** identity pair is `SESSION_AD[77..141)` when `role == initiator` and
`SESSION_AD[13..77)` when `role == responder`. §11.1 keys the single-live-session invariant on that
pair, and §11.3 re-emits `IK_A^s` and `IK_A^d` in the type `0x02` header from these offsets.

**A port that recomputes `SESSION_AD` as `(self, peer)` at send time will interoperate with itself
and with nothing else.** This is among the most likely divergence points in the whole protocol; the
role ordering is why the state blob stores a `role` byte (§12.1) and why test `RATCHET-BIDI`
(§15.4) requires B to send first after the ratchet turns.

### 6.6 One-time prekey consumption

The responder stores one-time prekeys as a map `uint32 opk_id → X25519Private`.

1. On a type `0x02` message with `opk_flag == 0x01` **for which no session already exists**
   (§11.2), the responder looks up `opk_id`.
2. If absent → `ERR_UNKNOWN_PREKEY_ID`. **There is no fallback to the 3-DH derivation.** Rejecting
   rather than falling back is what converts OPK consumption into replay protection, and it
   forecloses a downgrade an implementer would otherwise be tempted to add.
3. If present, the private key is used for DH4.
4. The entry MUST be deleted and the deletion **durably committed before the decrypted plaintext is
   returned to the caller.** A crash between returning plaintext and committing the delete reopens
   the replay window that rule 2 exists to close.
   Deletion MUST **zeroize the private key bytes in place before the map entry is unlinked.** An
   unlink alone — `Map.remove`, `NSMutableDictionary removeObjectForKey:`, a Swift dictionary
   subscript assignment to `nil` — is NOT sufficient: it releases the reference and leaves the
   scalar resident in the heap. Rule 4 as originally worded is a *persistence-ordering*
   requirement; this sentence adds the *memory-hygiene* requirement, and both are MUSTs. On the JVM
   the wipe is best-effort per §17.1.
5. The deletion MUST NOT happen if the AEAD tag fails. Order of operations is fixed in §10.7.

`opk_flag == 0x00` is a legitimate, weaker mode — not an error. See §17.3 for its replay caveat.

The initiator selects a specific OPK from the fetched bundle and transmits its `opk_id`.
`ephemeralKeyPairs.firstObject` (v3, `IRTripleDHService.m:98`) does not appear anywhere in v4: in v3
the "one-time" key was neither one-time nor selected, so every session with a given peer used the
same ephemeral — the exact property OPKs exist to prevent.

---

## 7. Double Ratchet

### 7.1 State variables

| Variable | Type | Meaning |
|---|---|---|
| `RK` | `RootKey(32)` | Root key |
| `DHs` | X25519 key pair | Our current ratchet key pair |
| `DHr` | `X25519Public(32)` or none | Peer's current ratchet public key |
| `CKs` | `ChainKey(32)` or none | Sending chain key |
| `CKr` | `ChainKey(32)` or none | Receiving chain key |
| `Ns` | uint32 | Messages sent in the current sending chain |
| `Nr` | uint32 | Messages received in the current receiving chain |
| `PN` | uint32 | Length of the **previous** sending chain |
| `skipped` | map | See §7.6 |
| `role` | enum | initiator or responder |
| `SESSION_AD` | 141 bytes | §6.5 |
| `handshake_id` | 64 bytes | §11.2 |
| `send_counter` | uint64 | §12.5 |

### 7.2 KDF_RK — the root chain

```
KDF_RK(RK, DH_out) -> (RK', CK):
    okm = HKDF( salt = RK,               (32 bytes — MANDATORY)
                ikm  = DH_out,           (32 bytes)
                info = "nuntius:RK:v4",  (13 bytes)
                L    = 64 )
    RK' = okm[0..32)
    CK  = okm[32..64)
```

**The previous root key is the HKDF salt and MUST be present.** There is no code path that calls
`KDF_RK` without it. Using `RK` as the *salt* rather than as part of the IKM is the Double Ratchet
specification's own recommendation and it is what makes continuity structural: HKDF-Extract cannot
be invoked without a salt argument, so "forgot to chain the previous root key" is not expressible.

v3's `performDHRatchet:` (`IRDoubleRatchetService.m:239-271`) calls `rootKeyKDFWithSecret:` on the
DH output alone and then assigns `self.rootKey` twice from two independent derivations, discarding
the previous root key both times. The root chain had no continuity, so no message key was a function
of the handshake.

> **⚠ Argument-order trap — the single highest-risk divergence point in this protocol.**
> BouncyCastle's `HKDFParameters(ikm, salt, info)` takes IKM **first**. CryptoKit's
> `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` takes IKM first as well but
> names it, while libsodium's `crypto_kdf_hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len)`
> takes salt **first**. Swapping them produces a working, self-consistent, completely incompatible
> implementation. Every port MUST wrap this in a single `kdfRk(rk:dhOut:)` helper and MUST cover it
> with vector `KDF-RK-1` (§15.3).

### 7.3 KDF_CK — the symmetric chain

```
KDF_CK(CK) -> (MK, CK'):
    MK  = HMAC(key = CK, message = 0x01)     (single byte 0x01)
    CK' = HMAC(key = CK, message = 0x02)     (single byte 0x02)
```

Both outputs are 32 bytes. HKDF is deliberately **not** used here: two raw HMACs are the Double
Ratchet specification's own recommendation, are cheaper per message, and require zero convention
agreement between ports — no salt, no info, no length, no truncation.

The constants `0x01` and `0x02` MUST NOT be renumbered. v3 used salt 0 for the message key and salt
1 for the chain key; ports MUST NOT carry those numbers over.

The old `CK` MUST be zeroized once its successor exists.

> **On consistency with §3.3.** libsodium's `crypto_auth_hmacsha256` takes a fixed 32-byte key,
> which is the same API *shape* that got `crypto_kdf_derive_from_key` banned. That ban is not about
> fixed-size parameters as such — it is about a fixed-size parameter silently consuming a
> **variable-length** input. Here the input is `CK`, which is 32 bytes by construction and by
> nominal type, so the constraint is an exact match rather than a truncation hazard.
> Implementations MUST assert `len(CK) == 32` at the call site. Any HMAC-SHA256 API is acceptable.

### 7.4 DH ratchet step

```
DHRatchet(state, header):
    # 1. drain the OLD receiving chain up to the peer's stated previous-chain length
    SkipMessageKeys(state, header.PN)          # no-op when CKr is none — see §7.6

    # 2. roll the chains
    state.PN  = state.Ns
    state.Ns  = 0
    state.Nr  = 0
    state.DHr = header.dh

    # 3. first root-chain step: derive the new RECEIVING chain
    dh1 = X25519(state.DHs.priv, state.DHr)          # §4.4 check 3
    (state.RK, state.CKr) = KDF_RK(state.RK, dh1)
    zeroize(dh1)

    # 4. fresh ratchet key
    zeroize(state.DHs.priv)                          # session-owned copy ONLY — see §7.5
    state.DHs = generate_X25519_keypair()            # stored clamped, §4.2

    # 5. second root-chain step: derive the new SENDING chain
    dh2 = X25519(state.DHs.priv, state.DHr)          # §4.4 check 3
    (state.RK, state.CKs) = KDF_RK(state.RK, dh2)
    zeroize(dh2)
```

The two `KDF_RK` calls are **strictly sequential**: the second consumes the `RK` produced by the
first. The root chain advances twice per ratchet and never restarts.

Step 1's guard matters: on the responder's very first receive, `CKr` is none. `SkipMessageKeys` MUST
be a no-op in that case rather than dereferencing a null chain key.

Step 4 is **unconditional and identical for both roles**. It is safe on the responder's first
ratchet — where `state.DHs.priv` is initialized from the signed prekey — only because §7.5 requires
the ratchet to hold a session-owned **copy** of that scalar. Read §7.5 before implementing this
step; a port that aliases the prekey store destroys a live medium-term key here.

### 7.5 Ratchet initialization

**Initiator A**, after computing `SK` (§6.3) and verifying B's bundle (§5.3):

```
RK          = SK
DHr         = SPK_B                       # B's signed prekey public
DHs         = generate_X25519_keypair()
dh          = X25519(DHs.priv, DHr)       # §4.4 check 3
(RK, CKs)   = KDF_RK(RK, dh)
CKr         = none
Ns = Nr = PN = 0
skipped     = {}
role        = initiator
```

**Responder B**, on first receiving a type `0x02` message and computing the same `SK`:

```
RK          = SK
DHs         = COPY of the SPK_B key pair  # both halves; a session-owned copy — see below
DHr         = none
CKs         = none
CKr         = none
Ns = Nr = PN = 0
skipped     = {}
role        = responder
```

B then processes the message header normally: `header.dh != DHr` (`DHr` is none), so B runs
`DHRatchet`, which produces a `CKr` equal to A's `CKs`.

`SK` MUST be zeroized after this step on both sides.

**The `sharedKey` argument MUST be consumed.** v3's
`setupRatchetForSendingWithSharedKey:andDHReceiverKey:` (`IRDoubleRatchetService.m:80-102`) never
reads it, while the receiving counterpart at `:111` assigns it straight to `rootKey`. The two sides
initialised asymmetrically and no message key was a function of the handshake. In v4 the session
setup API takes a `RootKey` nominal type, non-optional; there is no code path that constructs a
ratchet without one.

**Note for the responder — ownership of `SPK_B_priv`. This is normative and it is the single
easiest way to brick a live deployment.** `DHs` is *initialized from* the signed prekey key pair,
but the ratchet state MUST hold its **own copy** of the private half — never an alias, a reference,
or a shared buffer into the prekey store. §7.4 step 4 zeroizes only that session-owned copy.
`SPK_B_priv` itself is owned exclusively by the prekey store and its lifetime is governed solely by
§5.3; no ratchet operation may shorten it.

A port that aliases the prekey store destroys the live signed prekey on B's **first ratchet of any
session** — which is every session B accepts — and thereby breaks every concurrent and future
handshake against that `spk_id` until rotation. The failure is silent and misattributed: X25519
clamping maps an all-zero scalar to `2^254`, so DH1 and DH3 against the wiped key produce non-zero
garbage, §4.4 check 3 does **not** fire, `spk_id` still resolves at §10.7 step 5, and B reports
`ERR_AEAD_AUTH_FAILED` — the code §1.2 defines as "active man-in-the-middle". B misdiagnoses its own
self-inflicted key destruction as an attack.

Copy semantics are chosen over making §7.4 step 4 conditional so that the DH ratchet stays
branch-free and identical for both roles, so that the intended forward secrecy is preserved (the
session copy really is wiped at the first ratchet), and so that the flat 32-byte `DHs_priv` field at
§12.1 offset 243 means exactly one thing: a scalar this session owns and may destroy. Note the
consequence for §12.3 — until a responder session takes its first ratchet, its sealed blob contains
a copy of `SPK_B_priv`, so rotating an SPK does not by itself remove that key from disk. This is
acceptable because §12.3 and §5.6 seal both stores under the same device-bound key, and because the
copy is wiped by the first ratchet of each session.

Test `NEG-SPK-SURVIVES-RATCHET` (§15.4) is the vector that catches an aliasing port; no
single-session ratchet vector can.

> **Correct conformance assertion.** After A's setup and B's setup-plus-first-message, assert
> `A.CKs == B.CKr`. Do **not** assert `A.RK == B.RK`: B's `DHRatchet` performs two `KDF_RK` steps
> while A has performed one, so B's root key is legitimately one step ahead at that instant. An
> implementer who asserts root-key equality here will "fix" working code.

### 7.6 Skipped message keys

**Store key:** the raw 36-byte tuple `DHr_pub (32) ‖ uint32_be(N) (4)`. Not a base64 string, not a
`|`-separated composite. v3 used `base64(pk) + "|" + decimal(N)`
(`IRDoubleRatchetService.m:432-437`), which costs an encoding round-trip per lookup in a hot path
and is not injective if a component could ever contain the separator.

**Stored value:** the 32-byte message key plus a uint64 insertion timestamp in Unix milliseconds.

**Bounds — all normative:**

| Constant | Value | Meaning |
|---|---|---|
| `MAX_SKIP_PER_MESSAGE` | 1000 | Maximum message keys a **single received message** may cause to be derived, **summed across both `SkipMessageKeys` calls** in that message's processing |
| `MAX_SKIPPED_STORED` | 2000 | Maximum entries in the store, across the whole session |
| `SKIPPED_TTL_MS` | 604800000 | 7 days |

`MAX_SKIP_PER_MESSAGE` is deliberately specified as an **aggregate per received message**, not a
per-call bound. A DH-ratchet message skips `header.PN` keys in the old chain and then `header.N` in
the new one; a per-call bound of 1000 would permit 2000 derivations per message and let a single
message evict the entire store.

```
SkipMessageKeys(state, until):
    if state.CKr is none:
        return OK                                  # nothing to skip; responder's first receive
    if until < state.Nr:
        return OK                                  # handled as replay by the caller
    needed = until - state.Nr
    if state.skip_budget < needed:
        return ERR_TOO_MANY_SKIPPED                # state MUST be left unmodified
    state.skip_budget -= needed
    while state.Nr < until:
        (mk, state.CKr) = KDF_CK(state.CKr)
        key = state.DHr ‖ uint32_be(state.Nr)
        insert(state.skipped, key, mk, now_ms())   # FIFO-evict if over MAX_SKIPPED_STORED
        state.Nr += 1
    return OK
```

`skip_budget` is initialised to `MAX_SKIP_PER_MESSAGE` at the start of processing each received
message and is **not** persisted. It is initialised **once per received message**, not once per
decryption attempt: §11.5 forbids attempting more than one session per message precisely so that
this bound cannot be multiplied.

`now_ms()` denotes the implementation's single time source — Unix milliseconds UTC. In production it
MUST be the system clock; in the conformance suite it is injectable as `inputs.now_ms` per §15.5
runner rule 6. A production API MUST NOT expose clock injection.

**Eviction** is a single global FIFO ordered by insertion. When an insert would exceed
`MAX_SKIPPED_STORED`, evict and zeroize the oldest entry first. FIFO is chosen over LRU because LRU
would require specifying access-time semantics identically across four languages. Entries older than
`SKIPPED_TTL_MS` — measured as `now_ms() - inserted_at_ms`, against the §15.5 rule 6 time source —
MUST be dropped and zeroized on every state load and on every ratchet step.

**A stored key MUST be removed ONLY after the AEAD decryption using it SUCCEEDS.** v3 calls
`removeObjectForKey:` at `IRDoubleRatchetService.m:168` and `aeDecryptData:` at `:170` — in that
order — so a message that fails to decrypt permanently destroys the only copy of its key and the
message is unrecoverable. This ordering is normative and is covered by test `NEG-SKIP-RETAIN`.

Keys MUST be zeroized on use, on eviction, and on TTL expiry.

### 7.7 Atomicity — decrypt MUST fail closed

**`RatchetDecrypt` MUST be atomic with respect to session state.**

An implementation MUST operate on a snapshot (or a journal) of all mutable ratchet state — `DHs`,
`DHr`, `RK`, `CKs`, `CKr`, `Ns`, `Nr`, `PN`, and the skipped-key store — and commit that snapshot to
the live session **only after the AEAD tag has verified and the plaintext has been produced.** If
any step fails, the live state MUST be byte-identical to what it was before the call, and every
intermediate secret derived during the attempt MUST be zeroized.

Specifically: an `ERR_AEAD_AUTH_FAILED` MUST NOT leave behind a performed DH ratchet, an advanced
`Nr`, a consumed one-time prekey, or newly inserted skipped keys.

This rule is absent from v3 entirely. v3's `decryptData:` calls `addSkippedMessages:` at
`IRDoubleRatchetService.m:178` and `:188`, `performDHRatchet:` at `:184`, advances
`chainKeyReceiver` at `:196`, and increments `numberOfReceivedMessages` at `:199` — and only then
calls `aeDecryptData:` at `:203`, which may fail. An attacker who can inject a well-formed but
unauthenticated message carrying a novel ratchet key can therefore force the receiver's ratchet
forward and **permanently desynchronise a live session**: an unauthenticated denial of service. It
is state corruption rather than a wrong plaintext, so no round-trip test detects it.

(v3 also discards the error returned by the second `addSkippedMessages:` call at `:188`, so an
over-limit skip on that path is ignored.)

Every port MUST carry test `NEG-ATOMIC` (§15.4).

**Implementation note:** modelling ratchet state as a value type makes the snapshot free — a Swift
`struct` of value types, or a Kotlin `data class` with an explicitly copied map. Kotlin's `copy()`
is **shallow**, so the skipped-key map must be copied explicitly. Ports SHOULD NOT mirror v3's
class-with-mutable-properties shape.

### 7.8 RatchetEncrypt

```
RatchetEncrypt(state, plaintext, type) -> message:
    if len(plaintext) > MAX_PLAINTEXT:      return ERR_PLAINTEXT_TOO_LARGE
    if state.CKs is none:                   return ERR_NO_SENDING_CHAIN
    if state.Ns >= 0x7FFFFFFF:              return ERR_COUNTER_OVERFLOW

    (mk, state.CKs) = KDF_CK(state.CKs)
    enc_key = KDF_MK(mk)                              # §8.1
    nonce   = random_bytes(12)                        # §8.3
    header  = build_header(type, state, nonce)        # §9
    ad      = state.SESSION_AD ‖ header
    ct_tag  = AEAD-Seal(enc_key, nonce, plaintext, ad)

    state.Ns += 1
    state.send_counter += 1                           # §12.5
    zeroize(mk, enc_key)
    persist(state)                                    # MUST complete before the message is emitted
    return header ‖ ct_tag
```

The header's `N` field is written from `state.Ns` and the `PN` field from `state.PN` — two distinct
stored variables. v3 writes `self.numberOfSentMessages` into **both** slots
(`IRDoubleRatchetService.m:140-145`), so the previous-chain count is never transmitted and
skipped-message recovery across a DH ratchet cannot work.

`type` is `0x02` while the initiator has not yet received any message from the responder, and
`0x01` thereafter. See §11.3.

### 7.9 RatchetDecrypt

```
RatchetDecrypt(live_state, message) -> plaintext:
    # ---- Phase 1: structural validation. Touches no secret; branches on no secret. ----
    hdr = parse_and_validate(message)                 # §10; returns an error or a header struct

    # ---- Phase 2: work on a snapshot ----
    s = deep_snapshot(live_state)
    s.skip_budget = MAX_SKIP_PER_MESSAGE
    drop_expired_skipped(s)

    ad = s.SESSION_AD ‖ message[0 .. HDR_LEN(hdr.type))
    ct = message[HDR_LEN(hdr.type) .. end)

    # ---- Phase 3a: a skipped key, if we have one ----
    store_key = hdr.dh ‖ uint32_be(hdr.N)
    if store_key in s.skipped:
        mk      = s.skipped[store_key].mk
        enc_key = KDF_MK(mk)
        pt      = AEAD-Open(enc_key, hdr.nonce, ct, ad)
        zeroize(enc_key)
        if pt is FAIL:
            discard s                                 # key is RETAINED — §7.6
            return ERR_AEAD_AUTH_FAILED
        remove_and_zeroize(s.skipped, store_key)      # only on success
        commit(s); persist(s)
        return pt

    # ---- Phase 3b: DH ratchet if the peer moved ----
    if s.DHr is none or hdr.dh != s.DHr:
        err = DHRatchet(s, hdr)                       # §7.4; may return ERR_TOO_MANY_SKIPPED
        if err: discard s; return err                 #        or ERR_SMALL_ORDER_KEY

    # ---- Phase 3c: skip forward within the current chain ----
    if hdr.N < s.Nr:
        discard s; return ERR_REPLAY                  # duplicate or replay; no skipped key held
    err = SkipMessageKeys(s, hdr.N)
    if err: discard s; return err

    # ---- Phase 3d: derive and decrypt ----
    (mk, s.CKr) = KDF_CK(s.CKr)
    s.Nr += 1
    enc_key = KDF_MK(mk)
    pt = AEAD-Open(enc_key, hdr.nonce, ct, ad)
    zeroize(mk, enc_key)
    if pt is FAIL:
        discard s                                     # live state untouched — §7.7
        return ERR_AEAD_AUTH_FAILED

    commit(s); persist(s)
    return pt
```

`live_state` is an **input**, not something `RatchetDecrypt` discovers. Selecting it is specified in
§11.5 and MUST happen before this function is entered; a conformant implementation MUST NOT expose a
decrypt entry point that takes only a message.

Rules that MUST be honoured exactly, because they are where independent ports diverge:

- A skipped-key hit returns **without** performing a DH ratchet and **without** advancing `Nr`.
- `SkipMessageKeys(s, hdr.PN)` runs on the **old** receiving chain, inside `DHRatchet`, **before**
  `DHr` is replaced.
- `SkipMessageKeys(s, hdr.N)` runs on the **new** receiving chain, after the ratchet.
- `Nr` advances once per derived key, whether that key is stored as skipped or used immediately.
- `hdr.N < s.Nr` with no matching skipped key is `ERR_REPLAY`, not a silent AEAD failure.

---

## 8. AEAD construction and associated data

### 8.1 Message key expansion

```
KDF_MK(MK) -> enc_key:
    enc_key = HKDF( salt = Z32,
                    ikm  = MK,                  (32 bytes)
                    info = "nuntius:MK:v4",     (13 bytes)
                    L    = 32 )
```

There is no HMAC key and no derived IV. v3 derived three values (AES key at salt 1, HMAC key at salt
2, IV at salt 3) from one message key by re-invoking the same `chainKey` label three times — reusing
one label across three semantic roles, and requesting a 16-byte IV that hit the
`crypto_kdf_BYTES_MIN` clamp. All of that is gone.

`MK` MUST be zeroized immediately after expansion; `enc_key` immediately after the AEAD call
returns, on both the success and failure paths.

### 8.2 The AEAD call

```
ct_and_tag = AEAD-Seal(key = enc_key, nonce = nonce, plaintext = pt, ad = AD)
```

- Algorithm: **ChaCha20-Poly1305, RFC 8439, IETF construction.** 256-bit key, 96-bit nonce, 128-bit
  tag.
- The 16-byte Poly1305 tag is **appended** to the ciphertext. libsodium, the JDK, and BouncyCastle
  all do this natively.
- `len(ct_and_tag) == len(pt) + 16`. ChaCha20 is a stream cipher: there is no padding and ciphertext
  length equals plaintext length.
- Decryption returns plaintext or an error. There is no separate MAC step, no comparison function,
  and no padding. `consistentTimeEqual:hmachToCompare:` is **deleted, not fixed** (see §14, defect 5).

### 8.3 The nonce is random and travels on the wire

**A fresh 12-byte nonce MUST be generated from the CSPRNG for every AEAD-Seal and MUST be carried in
the message header.**

This is a deliberate reversal of the "derive the nonce from `MK`" approach, and the reasoning is
worth stating because the derived form is superficially attractive (it saves 12 bytes and removes an
RNG call from the hot path).

Under a derived nonce, `nonce = f(MK)`, so the nonce is a pure function of the key. Message-key
uniqueness then carries the entire burden of nonce uniqueness. That holds for a correctly
functioning, strictly monotonic state store — but this library **explicitly persists and restores
ratchet state**, and on iOS that state can land in a device backup. If a session state is restored
from a snapshot, or forked across two devices, and a message is then sent, the same `MK` yields the
same `enc_key` **and** the same nonce. `(key, nonce)` reuse under ChaCha20-Poly1305 is not a
degraded-confidentiality event: it discloses the keystream XOR **and** leaks the Poly1305 one-time
key, permitting forgery.

With a random nonce, the identical rollback yields the same `enc_key` but a different nonce. That is
a plaintext-repetition event, not a key-recovery event. The failure mode becomes survivable.

Since no specification can enforce monotonic persistence across four ports and an unknown host
application, the primitive is chosen so that the unenforceable precondition is not
catastrophic. Twelve bytes per message is the correct price. §12.5 additionally specifies a rollback
tripwire, but the tripwire is defence in depth, not the primary mitigation.

The nonce MUST come from the platform CSPRNG (§13.1). It MUST NOT be a counter, MUST NOT be derived
from the message key, and MUST NOT be reused.

### 8.4 Why ChaCha20-Poly1305 and not XChaCha20 or AES-GCM

**XChaCha20-Poly1305 is rejected.** Its 24-byte nonce is the more idiomatic libsodium choice and
would remove even the birthday-bound concern for random nonces. But it is absent from the JDK,
absent from CryptoKit (`ChaChaPoly` is RFC 8439 only), and not dependably exposed by BouncyCastle's
JCE provider. Adopting it would force two of four ports to hand-implement HChaCha20 — reintroducing
exactly the hand-rolled-construction risk this redesign exists to eliminate. With 96-bit random
nonces and single-use keys, the collision probability within one message key is zero (one nonce per
key), so XChaCha's advantage is worth nothing here.

**AES-256-GCM is rejected.** It is available everywhere, but libsodium's `crypto_aead_aes256gcm_*`
is hardware-gated behind `crypto_aead_aes256gcm_is_available()`, requiring a runtime availability
branch and a fallback path that the other three ports do not have.

### 8.5 Associated data — exactly which bytes

> **AD = `SESSION_AD` (141 bytes) ‖ the complete message header.**

| Message type | Header length | AD length |
|---|---|---|
| `0x01` normal | 56 | `141 + 56` = **197** |
| `0x02` prekey | 225 | `141 + 225` = **366** |

"The complete header" means `message[0 .. HDR_LEN)` verbatim, including the version byte, the type
byte, the flags, the ratchet public key, `N`, `PN`, and the nonce.

The nonce is therefore both the AEAD nonce and part of the AD. That redundancy is intentional: it
makes the rule "AD is everything before the ciphertext" exceptionless, which is worth more than the
bytes it saves.

Consequences:

- **Version, type, and flags are cryptographically enforced**, not merely checked by an `if`. A
  tampered version byte is an authentication failure. This is a strictly stronger fix for defect 13
  than adding validation code, and it comes free with the AEAD.
- **The header is authenticated before any plaintext is produced.** v3 authenticated the header via
  HMAC input but *parsed* it before verifying.
- Both parties compute `SESSION_AD` from stored role-ordered bytes, so a session with different
  identities fails Poly1305 verification even if an adversary could otherwise influence the ratchet.

---

## 9. Wire format

**All integers are big-endian. There is no length field anywhere in the format.** Header length is a
constant determined **solely** by the 1-byte type field at offset 1. The only variable-length region
is the ciphertext, whose extent is derived by subtraction from the total received length.

This is what makes defect 6 unreachable rather than merely fixed: there is no attacker-controlled
length to misparse, so the `*(NSInteger*)` 8-byte read of a 1-byte `NSData` has nothing to read.

**No redundant length fields are included.** A redundant `ciphertext_len` that implementations are
told in prose not to use would put an attacker-supplied length back on the wire and rely on prose as
the enforcement mechanism — which is precisely what the rest of this format exists to avoid.
Truncation is already caught by the Poly1305 tag and by the minimum-length precondition.

### 9.1 Type `0x01` — normal ratchet message

```
off   len   field           notes
----  ----  --------------  ------------------------------------------------------
0     1     version         MUST be 0x04
1     1     type            MUST be 0x01; selects header length 56
2     2     flags           uint16_be, MUST be 0x0000 (reserved)
4     32    DHs_pub         sender's current X25519 ratchet public key
36    4     N               uint32_be, message number in the current sending chain
40    4     PN              uint32_be, length of the sender's PREVIOUS sending chain
                            (from state.PN — never from state.Ns)
44    12    nonce           random, per message (§8.3)
--- end of header: 56 bytes ---
56    L     ciphertext      L == plaintext length
56+L  16    Poly1305 tag

total  = 56 + L + 16
minimum total = 72   (empty plaintext is legal)
maximum total = 56 + 16777216 + 16 = 16777288
AD     = SESSION_AD(141) ‖ msg[0..56)                    = 197 bytes
```

### 9.2 Type `0x02` — prekey / initial message

```
off   len   field           notes
----  ----  --------------  ------------------------------------------------------
0     1     version         MUST be 0x04
1     1     type            MUST be 0x02; selects header length 225
2     2     flags           uint16_be, MUST be 0x0000
4     32    IK_A^s          initiator Ed25519 identity public key
36    32    IK_A^d          initiator X25519 identity public key
68    64    IKB_A           initiator identity binding signature (§5.1)
132   32    EK_A            initiator X25519 handshake ephemeral public key
164   4     spk_id          uint32_be, which of B's signed prekeys was used
168   1     opk_flag        0x00 = none, 0x01 = one used; any other value -> reject
169   4     opk_id          uint32_be; MUST be 0x00000000 when opk_flag == 0x00
173   32    DHs_pub         initiator's ratchet public key; distinct from EK_A
                            (enforced: §10.2 check 11)
205   4     N               uint32_be; MAY be non-zero (see below)
209   4     PN              uint32_be; MUST be 0x00000000
213   12    nonce           random, per message
--- end of header: 225 bytes ---
225   L     ciphertext
225+L 16    Poly1305 tag

total  = 225 + L + 16
minimum total = 241
maximum total = 225 + 16777216 + 16 = 16777457
AD     = SESSION_AD(141) ‖ msg[0..225)                   = 366 bytes
```

**`N` MAY be non-zero in a type `0x02` header.** This is essential and easy to get wrong. Until A
receives a message from B, A does not know that B has established the session, so A's second, third,
… messages MUST also be prekey messages — carrying the identical X3DH prologue fields (same `EK_A`,
same `spk_id`, same `opk_flag` / `opk_id`, same `IKB_A`) with an incrementing `N`. A protocol that
pinned `N` to zero here would have no legal encoding for A's second message before a reply, breaking
the most common real-world send pattern.

**`PN` is always zero** in a type `0x02` header: a fresh session has no previous sending chain. B
MUST reject a non-zero `PN` with `ERR_MALFORMED_HEADER`.

**B's own `OPK` public key is not transmitted.** B recovers it from `opk_id`.

### 9.3 There is no type `0x03`

The v3 "simple" format (`aeEncryptSimpleData:` / `aeDecryptSimpleData:`) is deleted with no
replacement. It was a second copy of the broken MAC comparison, outside the ratchet, with no
structural guarantee of key single-use. Respecifying it as a deterministic-nonce AEAD under a
caller-supplied long-lived key would guarantee catastrophic nonce reuse on the second call; keeping
it at all would leave defect 5 alive in a corner of the API. Callers who need raw symmetric sealing
should call ChaCha20-Poly1305 directly with a random nonce and their own key management.

Type values other than `0x01` and `0x02` MUST be rejected with `ERR_UNKNOWN_MESSAGE_TYPE`.

---

## 10. Parsing and validation rules

Every check below is a **MUST**. Every failure returns the specified error, produces no plaintext,
and mutates no state. There is no partial success and no "best effort" path.

**No field is ever read at an offset derived from a value carried in the message.** Every offset in
§9 is a compile-time constant.

### 10.0 Entry-point demultiplex

**Executed by both receive entry points before §10.1 or §10.2, and by the routing helper of §11.5
rule 5.** Execute in this exact order; return on the first failure.

| # | Check | Error on failure |
|---|---|---|
| 1 | `len(msg) >= 72` | `ERR_TRUNCATED_MESSAGE` |
| 2 | `len(msg) <= 16777457` | `ERR_PLAINTEXT_TOO_LARGE` |
| 3 | `msg[0] == 0x04` | `ERR_UNSUPPORTED_VERSION` |
| 4 | `msg[1] ∈ {0x01, 0x02}` | `ERR_UNKNOWN_MESSAGE_TYPE` |
| 5 | `msg[1]` equals the type accepted by the entry point invoked | `ERR_WRONG_ENTRY_POINT` |

The routing helper executes rows 1–4 only — it has no expected type — and returns `msg[1]`.

**The type-dependent length floors of §10.1 and §10.2 MUST NOT be evaluated before §10.0 completes.**
Those floors are functions of the type, so applying one to a message whose type has not yet been read
asserts a property the message does not have: §10.2's floor of 241 fires before its own check 4 reads
the type byte, so a 200-byte message that is genuinely a type `0x01` was previously reported out of
the type `0x02` entry point as `ERR_TRUNCATED_MESSAGE` — a truncation that does not exist, sending an
implementer looking for a short read instead of a misrouted call. The asymmetry was an artifact of
the two gates having different floors, not a statement about the input.

Rows 1 and 2 are **not** type-dependent and therefore precede the demultiplex legitimately: 72 is
check 1 of *both* gates, so no message failing it could have reached either gate's check 4, and
16777457 is the **looser** of the two caps (§10.4), so §10.0 can never pre-empt a code the applicable
gate would have produced for a message of the type it actually is. The tighter type `0x01` cap of
16777288 stays where it is, as that gate's own check 2. Keeping row 1 ahead of rows 3–5 is also what
keeps this section inside §1.3 property 5: reading `msg[0..2)` on a zero- or one-byte input is the
out-of-bounds class §10.3 documents at length — Objective-C reads adjacent heap or a `NULL` `bytes`
pointer, Swift `Data` subscripting **traps**, and the JVM raises an unchecked
`IndexOutOfBoundsException` that escapes the taxonomy entirely.

Row 3 precedes row 4, matching the order both gates use, and it is what makes §10.6 true. Under the
previous ordering a v3 message shorter than the invoked gate's floor returned `ERR_TRUNCATED_MESSAGE`,
so §10.6's guarantee about the previous protocol version held only for full-length inputs.

**Entry points do not forward.** A decrypt entry point MUST reject a message of the type it does not
handle with `ERR_WRONG_ENTRY_POINT`, and MUST NOT process it, forward it, or dispatch it to the other
entry point. Auto-forwarding a type `0x01` message to the self-routing prekey entry point is a §11.5
rule 1 violation in disguise: that entry point accepts no session handle, so a forwarded type `0x01`
has none and the implementation must either fabricate one or trial-decrypt — both rejected in §19.2.
The supported way for a host holding bytes of unknown type to choose an entry point is the routing
helper (§11.5 rule 5), not an error code it has to interpret.

§10.0 performs no allocation, touches no secret, and branches on no secret.

### 10.1 Ordered gate — type `0x01`

§10.0 has passed and has resolved the type to this gate's. Execute in this exact order; return on the
first failure. Checks 1–4 are re-applied here at this gate's own, tighter bounds, and remain
normative **in position**: a port that elides them because §10.0 already ran is non-conformant, and
§15.4 references these rows by number.

| # | Check | Error on failure |
|---|---|---|
| 1 | `len(msg) >= 72` | `ERR_TRUNCATED_MESSAGE` |
| 2 | `len(msg) <= 16777288` | `ERR_PLAINTEXT_TOO_LARGE` |
| 3 | `msg[0] == 0x04` | `ERR_UNSUPPORTED_VERSION` |
| 4 | `msg[1] == 0x01` | `ERR_UNKNOWN_MESSAGE_TYPE` |
| 5 | `msg[2..4) == 0x0000` | `ERR_RESERVED_FLAGS_SET` |
| 6 | the caller supplied a session handle and it resolves (§11.5) | `ERR_NO_SESSION` |
| 7 | `DHs_pub = msg[4..36)` passes §4.4 checks 1–2 | `ERR_INVALID_PUBLIC_KEY` |
| 8 | `DHs_pub != our own DHs public key` (anti-reflection, §4.4 check 2b) | `ERR_INVALID_PUBLIC_KEY` |
| 9 | `N  = be32(msg[36..40)) <= 0x7FFFFFFF` | `ERR_COUNTER_OVERFLOW` |
| 10 | `PN = be32(msg[40..44)) <= 0x7FFFFFFF` | `ERR_COUNTER_OVERFLOW` |
| — | *Steps 1–10 touch no secret and branch on no secret.* | |
| 11 | run `RatchetDecrypt` phases 2–3 on a **snapshot** (§7.9) | as returned |
| 12 | `AEAD-Open` succeeds with `ad = msg[0..56)` prefixed by `SESSION_AD` | `ERR_AEAD_AUTH_FAILED` |
| 13 | commit the snapshot, persist, zeroize consumed key material | — |

### 10.2 Ordered gate — type `0x02`

§10.0 has passed and has resolved the type to this gate's. Checks 1–4 are re-applied here at this
gate's own, tighter bounds, on the same terms as §10.1's preamble.

| # | Check | Error on failure |
|---|---|---|
| 1 | `len(msg) >= 241` | `ERR_TRUNCATED_MESSAGE` |
| 2 | `len(msg) <= 16777457` | `ERR_PLAINTEXT_TOO_LARGE` |
| 3 | `msg[0] == 0x04` | `ERR_UNSUPPORTED_VERSION` |
| 4 | `msg[1] == 0x02` | `ERR_UNKNOWN_MESSAGE_TYPE` |
| 5 | `msg[2..4) == 0x0000` | `ERR_RESERVED_FLAGS_SET` |
| 6 | `opk_flag = msg[168] ∈ {0x00, 0x01}` | `ERR_MALFORMED_HEADER` |
| 7 | `opk_flag == 0x00` implies `be32(msg[169..173)) == 0` | `ERR_MALFORMED_HEADER` |
| 8 | `PN = be32(msg[209..213)) == 0` | `ERR_MALFORMED_HEADER` |
| 9 | `N = be32(msg[205..209)) <= 0x7FFFFFFF` | `ERR_COUNTER_OVERFLOW` |
| 10 | `IK_A^d`, `EK_A`, `DHs_pub` each pass §4.4 checks 1–2 | `ERR_INVALID_PUBLIC_KEY` |
| 11 | `DHs_pub = msg[173..205)` **!=** `EK_A = msg[132..164)` (anti-reflection, §4.4 check 2b) | `ERR_INVALID_PUBLIC_KEY` |
| — | *Steps 1–11 touch no secret and branch on no secret.* | |
| 12 | dispatch on session existence — §11.2 | — |

Then §10.7 (new session) or §11.2 (existing session).

Check 11 is this gate's instance of §4.4 check 2b, and the enforcement gate for §9.2's prose rule
that `DHs_pub` is distinct from `EK_A`. It compares two fields of the same message, so it touches no
local state and preserves the no-secret invariant above. The **other** anti-reflection comparisons
for type `0x02` — against B's own keys — cannot live here, because at gate time B has resolved
neither `spk_id` (that is §10.7 step 5) nor the session's `DHs` (that is §11.2's load). They are
specified at those two sites instead, so that each check sits at the earliest point where the state
it needs exists and still precedes any DH. §4.4 check 2b lists all four sites in one place.

### 10.3 Bundle parsing

Execute this ordered gate before §5.3 steps 2–6; return on the first failure. It exists because the
bundle is the only structure in this protocol whose length rule is expressed in terms of a value
carried inside it, and every other decoder in this document (§10.1, §10.2, §12.2) leads with a
length floor.

| # | Check | Error on failure |
|---|---|---|
| 1 | `len(bundle) >= 251` | `ERR_BUNDLE_MALFORMED` |
| 2 | `bundle[0..4) == "NTB4"` (`4E 54 42 34`) | `ERR_BUNDLE_MALFORMED` |
| 3 | `bundle[4] == 0x04` | `ERR_UNSUPPORTED_VERSION` |
| 4 | `opk_count = be16(bundle[249..251)) <= 1000` | `ERR_BUNDLE_MALFORMED` |
| 5 | `len(bundle) == 251 + 36 * opk_count` **exactly** | `ERR_BUNDLE_MALFORMED` |

Then §5.3 steps 2–6 proceed unchanged.

**Step 1 is load-bearing and MUST precede step 4.** `opk_count` sits at the fixed offset 249, but
both normative structural rules — the `<= 1000` cap of §5.4 and the exact-length identity — are
predicates *over* `opk_count`, so neither can be evaluated without first loading two bytes at 249.
On a 5-byte or 0-byte input that load is out of bounds, and the three ports fail three different
ways: Objective-C over a `const uint8_t *` reads adjacent heap silently and may then copy
`36 * opk_count` bytes from offset 251; Swift `Data` subscripting on a slice **traps**, which is an
uncatchable remote DoS from a bundle fetch; the JVM raises an unchecked `IndexOutOfBoundsException`
that escapes the `ERR_BUNDLE_MALFORMED` contract entirely unless the whole parser happens to be
wrapped. Three observable behaviours for the same bytes, in the one structure §5.4 requires all four
implementations to parse for each other.

This is §1.3 property 5 ("no length, offset, or allocation size derived from received bytes before
authentication") applied to the bundle, which §5.3 orders *before* the `IKB` and `SPK_SIG`
verifications. It is not the same mechanism as defect 6 — that was a wire-derived *offset*, this is
a missing floor at a fixed offset — but it is the same class of failure and it deserved the same
discipline the state-blob parser got.

Steps 2 and 3 close a smaller gap: §5.4 declares the magic and version bytes MUST-equal but no
section previously assigned them an error code or a position in any order.

Covered by `NEG-BUNDLE-EMPTY`, `NEG-BUNDLE-SHORT`, `NEG-BUNDLE-MAGIC`, `NEG-BUNDLE-VERSION`,
`NEG-BUNDLE-OPKCOUNT` and `NEG-BUNDLE-LEN` (§15.4).

### 10.4 Size bounds

| Constant | Value |
|---|---|
| `MAX_PLAINTEXT` | `16777216` (2²⁴ bytes = 16 MiB) |
| Max type `0x01` message | `16777288` |
| Max type `0x02` message | `16777457` |

Empty plaintext (length 0) is **legal** and produces a 72-byte type `0x01` message. v3's
`encryptData:` returns `nil` when the CBC output is zero-length, conflating "empty input" with
"encryption failed"; v4 has no such ambiguity.

Bounds MUST be checked **before** any allocation sized from the input. On the JVM an unchecked
allocation here is an `OutOfMemoryError`, which on a server takes down unrelated sessions — this is
a liveness issue, not hygiene.

### 10.5 Error taxonomy

Domain: `com.ivrodriguez.nuntius`. The v3 codes 7001–7003 are retired.

| Code | Name | Meaning |
|---|---|---|
| 7100 | `ERR_UNSUPPORTED_VERSION` | Byte 0 is not `0x04` |
| 7101 | `ERR_UNKNOWN_MESSAGE_TYPE` | Byte 1 is not `0x01` or `0x02` |
| 7102 | `ERR_RESERVED_FLAGS_SET` | Flags are not `0x0000` |
| 7103 | `ERR_TRUNCATED_MESSAGE` | Below the type's minimum length |
| 7104 | `ERR_MALFORMED_HEADER` | A header field is outside its permitted domain |
| 7105 | `ERR_TRAILING_BYTES` | A **state blob** has bytes beyond its declared extent. Never a bundle: every bundle structural failure, including a wrong total length in either direction, is `ERR_BUNDLE_MALFORMED` (§10.3) |
| 7106 | `ERR_INVALID_PUBLIC_KEY` | Wrong length, high bit set, or reflected own key — §4.4 checks 1, 2 and 2b respectively; check 2b names the four sites that perform the reflection comparison and what each compares against |
| 7107 | `ERR_SMALL_ORDER_KEY` | A DH produced an all-zero output |
| 7108 | `ERR_BAD_SIGNATURE` | `IKB` or `SPK_SIG` failed to verify |
| 7109 | `ERR_AEAD_AUTH_FAILED` | Poly1305 tag mismatch |
| 7110 | `ERR_TOO_MANY_SKIPPED` | `MAX_SKIP_PER_MESSAGE` exceeded |
| 7111 | `ERR_REPLAY` | `N < Nr` with no matching skipped key |
| 7112 | `ERR_COUNTER_OVERFLOW` | `N` or `PN` above `0x7FFFFFFF`, or `Ns` exhausted |
| 7113 | `ERR_RNG_FAILURE` | The CSPRNG failed |
| 7114 | `ERR_UNKNOWN_PREKEY_ID` | `spk_id` or `opk_id` does not resolve |
| 7115 | `ERR_OPK_ALREADY_CONSUMED` | The one-time prekey was already used |
| 7116 | `ERR_PREKEY_EXPIRED` | Outside the validity window, or window too long |
| 7117 | `ERR_STATE_CORRUPT` | State blob failed structural validation |
| 7118 | `ERR_NOT_INITIALIZED` | The crypto backend has a mandatory one-time initialization step and it has not completed successfully (§13.2). Unreachable on a backend that has no such step — see below |
| 7119 | `ERR_PLAINTEXT_TOO_LARGE` | Above `MAX_PLAINTEXT`, or message above its maximum |
| 7120 | `ERR_NO_SESSION` | A type `0x01` message was submitted with no session handle, or with one that does not resolve (§11.5) |
| 7121 | `ERR_NO_SENDING_CHAIN` | Encrypt attempted with `CKs` unset |
| 7122 | `ERR_BUNDLE_MALFORMED` | Bundle failed structural validation |
| 7123 | `ERR_IDENTITY_MISMATCH` | Header identity keys disagree with the cached session |
| 7124 | `ERR_STATE_ROLLBACK` | `send_counter` went backwards (§12.5) |
| 7125 | `ERR_WRONG_ENTRY_POINT` | A well-formed message of one type was submitted to the entry point for the other type (§10.0 row 5) |

**On 7125 rather than 7101.** Byte 1 genuinely *is* a valid message type in this case, so 7101's
meaning — a predicate over the message alone — does not describe it. The condition is a predicate
over *(message, entry point)*, and the two have different remedies: 7101 means a peer sent bytes that
are not a message type and the message should be dropped, while 7125 means the host routed a genuine
message to the wrong call and the host's demultiplexer should be fixed. Overloading 7101 would have
required rewriting its meaning into a disjunction that no longer distinguishes them. 7125 takes the
next free number; no existing assignment moves.

**On 7118, and on backends that have no initialization step.** This code was previously specified as
"`sodium_init()` failed or was not called", which is a fact about one library rather than a
condition of this protocol, and it left the code's meaning undefined on the two of four target
backends that have no such call. Restated backend-neutrally: **where the backend requires a one-time
initialization before any cryptographic operation, that initialization MUST be performed exactly
once, its outcome MUST be checked, and a failed or omitted initialization MUST make every subsequent
cryptographic entry point return 7118** rather than proceed as a silently degraded service (§13.2).
For libsodium that step is `sodium_init()`.

**BouncyCastle, the JDK providers, and CryptoKit / swift-crypto have no initialization step, so on
those backends 7118 has no reachable condition and MUST NOT be returned. That is conformant, not a
gap** — there is nothing for the port to detect, and a code with no producing condition is the
correct outcome. A port MAY define the constant for taxonomy completeness, but MUST NOT invent a
condition for it. Repurposing it for host-lifecycle state — "the prekey store was not opened", "the
session was not set up", "the identity has not been registered" — is specifically forbidden: none of
those is a crypto-backend initialization failure, they are caller contract violations or conditions
with their own codes, and giving one code two meanings across four ports is worse than an unused
number. This is why §15.4 contains no vector for 7118: on two backends there is no input that
produces it.

**Information leakage.** These distinct codes exist for **local diagnosability only**. An
application MUST NOT reveal which code occurred to the network peer, and MUST NOT vary its response
timing by code. The recommended contract is that codes 7100–7112 **and 7125** surface to a peer, if
at all, as a single opaque "undecryptable" signal. Distinguishing `ERR_REPLAY` from
`ERR_AEAD_AUTH_FAILED` to a peer tells an attacker whether a guessed counter sat in the skipped-key
store; 7125 is reachable from a hostile transport that flips the inner type byte, and disclosing it
tells a peer which entry point a host used, which is host routing structure disclosed for no benefit.

**Not in this taxonomy.** Every code above describes a condition produced by **data** — a peer's
bytes, a store's contents, a clock. A condition produced by the **caller's own control flow** — a
null reference passed for a parameter the API declares non-null, concurrent entry from two threads —
is a caller contract violation, is governed by §13.4, has no code, and MUST NOT be assigned one.

**Every failure path MUST set the error out-parameter, and MUST NOT dereference a null one.** v3's
`aeEncryptSimpleData:` (`IREncryptionService.m:199`) and `aeDecryptSimpleData:` (`:302`) both write
`*error = err` with no null check, crashing any caller that passes `NULL` — which every test in the
repository does. Implementations MUST NOT return a null result with a null error.

### 10.6 Rejecting v3 traffic

A v3 message begins with `0x03`. **§10.0 row 3 rejects it with `ERR_UNSUPPORTED_VERSION`, before any
type-dependent length floor and before the type is read**, so the rejection is unconditional on the
message's length and on which entry point the host used. There is no downgrade path and no
dual-stack mode.

The ordering is the whole content of this section. Under the previous ordering — each gate's own
check 3, reached only after that gate's check 1 — a v3 message shorter than the invoked gate's floor
returned `ERR_TRUNCATED_MESSAGE`, and this section's guarantee was silently conditional on length.
`NEG-VERSION-SHORT` (§15.4) is the vector that pins it.

### 10.7 Type `0x02`, new session — full order of operations

When §11.2 determines that no session exists for the handshake id:

1. Gate §10.2 has passed.
2. Compute `handshake_id = IK_A^d ‖ EK_A` (64 bytes).
3. Verify `IKB_A` over `IKBIND_MSG(IK_A^s, IK_A^d)` → else `ERR_BAD_SIGNATURE`. **Before any DH.**
4. `handshake_id` MUST NOT match a tombstone retained under §11.4 → else `ERR_REPLAY`.
5. Resolve `spk_id` to a retained signed prekey private key (§5.3) → else `ERR_UNKNOWN_PREKEY_ID`.
6. `DHs_pub = msg[173..205)` MUST NOT equal the signed-prekey public resolved in step 5
   (anti-reflection, §4.4 check 2b: the responder's initial `DHs` is that key pair, §7.5) →
   else `ERR_INVALID_PUBLIC_KEY`. **Before any DH.**
7. If `opk_flag == 0x01`, resolve `opk_id` → else `ERR_UNKNOWN_PREKEY_ID` /
   `ERR_OPK_ALREADY_CONSUMED`. No fallback to the 3-DH form.
8. Compute DH1–DH4, checking §4.4 check 3 on each → `ERR_SMALL_ORDER_KEY`.
9. Build `TRANSCRIPT`, `TH`, `IKM`; assert lengths; derive `SK` (§6.3).
10. Build `SESSION_AD` (§6.5) with A = the header's identity, B = ourselves.
11. Initialize the ratchet as responder (§7.5) **on a snapshot**, copying the signed prekey private
    half into the snapshot rather than aliasing the prekey store.
12. Run `RatchetDecrypt` phases 3b–3d on that snapshot with `ad = SESSION_AD ‖ msg[0..225)`.
13. On AEAD failure: return `ERR_AEAD_AUTH_FAILED`, discard the snapshot, **do not commit the
    session, and do not delete the one-time prekey.**
14. On AEAD success only, in this exact order:
    - **14a.** Durably delete and zeroize `opk_id` (§6.6 step 4). **This deletion is final.** It MUST
      NOT be undone by any later sub-step, including 14b going against the session just built.
    - **14b.** Apply the single-live-session rule of §11.1.1 against any existing live session with
      the same peer identity pair.
    - **14c.** Commit the outcome of 14b durably — the survivor's state **and** the loser's teardown,
      zeroization and tombstone — before anything is returned. When the **existing** session is the
      survivor, the session built by this run MUST NOT be persisted at any point; only its tombstone
      is written. The surviving session's state MUST NOT be modified by this message in any way: no
      `RK`, `CKs`, `CKr`, `Ns`, `Nr`, `PN`, `DHr`, skipped key or `SESSION_AD` derived on the losing
      session may be merged into it, and `send_counter` (§12.5) does not advance.
    - **14d.** Return the result of §11.6, carrying the plaintext.

**The plaintext is delivered on every path that reaches step 14, including the path on which the
session just established is the loser of 14b.** Step 13 is the only AEAD outcome that produces no
plaintext. An implementation MUST NOT make plaintext delivery conditional on the collapse outcome,
MUST NOT return an error on the losing branch, and MUST NOT return a success value that carries no
plaintext.

Three reasons, because this is the branch four ports would each answer differently. First, the
taxonomy cannot express the alternative: §10.5 assigns no code to "your message authenticated and we
discarded it", and this section's closing rule in §10.5 forbids returning a null result with a null
error, so a dropping port must either invent a code for a success or violate a MUST. Second, dropping
is permanent rather than deferred: 14a has already burned the one-time prekey and 14c tombstones the
loser, and §11.3 has the initiator retransmitting an *identical* prologue, hence an identical
`handshake_id`, so every retransmission now dies at step 4 with `ERR_REPLAY`. No mechanism in this
document ever redelivers it. Third, there is no security argument on the other side: this plaintext
cleared step 3's `IKB_A`, steps 8–9's four DHs and transcript binding, and step 12's Poly1305 — the
strongest authentication the protocol has — and step 13's AEAD success authenticates the sender's
identity private key through DH1, so the plaintext and the surviving handle provably belong to the
same peer. The branch is unreachable without that peer's private keys; it is driven only by an honest
concurrent initiation, or by an attacker who merely **delays** one packet. Dropping would hand a
pure-network attacker a silent, permanent message-suppression primitive that costs it nothing.

14c's durability requirement is the load-bearing half. A crash between returning the plaintext and
committing the loser's teardown and tombstone resurrects a session §11.1.1 has already decided is
dead, and the two parties then hold different survivors permanently — the exact divergence the
deterministic comparison exists to prevent, reintroduced through a persistence hole. 14a's finality is
the other: a port that reads "the session was torn down, so undo its side effects" and restores the
one-time prekey reopens defect 7's replay window on the one path where an attacker can drive a
teardown by racing, and each replay then costs the receiver a full X3DH — one Ed25519 verification
and four X25519 operations — and re-delivers the same plaintext.

Step 3 before step 8 is the fix for defect 3 in the responder direction; step 14's ordering is the
fix for defect 7's replay window, and 14a's finality is what keeps that fix intact when 14b goes
against the newly built session. Step 4 bounds the no-OPK handshake replay of §17.3 to
`HANDSHAKE_CACHE_MS` by enforcement rather than by implication, and stops a replayed handshake
from displacing a live session under step 14. Step 6 is the type `0x02` counterpart of §10.1 check
8; it sits here rather than in §10.2 because `spk_id` is not resolved until step 5.

Covered by `SESSION-COLLAPSE`, `NEG-COLLAPSE-LOSER-REPLAY` and `NEG-COLLAPSE-LOSER-HANDLE` (§15.3,
§15.4).

---

## 11. Session lifecycle

### 11.1 Handshake identifier

```
handshake_id = IK_A^d (32) ‖ EK_A (32)        = 64 bytes
```

Both components are public, and both are carried in every type `0x02` header, so a type `0x02`
message is self-routing (§11.2). A type `0x01` message carries neither and is **not** self-routing;
§11.5 specifies how it is delivered.

Implementations maintain two indices over the same session records:

- by `handshake_id` — used to dispatch type `0x02` (§11.2);
- by **peer identity pair** `(IK^s, IK^d)`, read from `SESSION_AD` at the offsets in §6.5 — used to
  select a session for type `0x01` (§11.5).

### 11.1.1 At most one live session per peer

**Normative.** An implementation MUST hold **at most one live session per peer identity pair**,
counting both roles together. This is what makes the second index above a function rather than a
relation, and it is what allows §11.5 to forbid trial decryption.

**The bound is per peer identity pair, not global.** A receiver holding live sessions with several
different peers simultaneously is conformant and is the normal case; a receiver with *n*
correspondents holds *n* candidate sessions. §11.5 rules 2–4 are what make the selection among them a
function of the transport-authenticated sender rather than of the message. Reading this rule as a
global cap of one makes §11.5 rule 3 untestable — there would be no sibling for a trial-decrypting
implementation to succeed against — which is exactly the hole `NEG-DEMUX-WRONG-SESSION` was rewritten
to close.

The invariant is not automatic: both parties may legitimately initiate at the same time, which is
routine on a mobile transport. A then holds a session in which it is initiator and another in which
it is responder, both with B, with distinct `handshake_id`s — and B holds the mirror image. The two
sides must converge on the **same** survivor without exchanging any further message, so the rule
must be a pure function of data both already have.

**Collapse rule.** When a new session is established (§10.7 step 14) with a peer for whom a live
session already exists, compare the two `handshake_id`s as 64-byte unsigned big-endian integers and
keep the **greater**. The loser is torn down immediately: its ratchet state and skipped-key store
are zeroized (§13.3), and its `handshake_id` is retained as a tombstone for `HANDSHAKE_CACHE_MS`
(§11.4) so that a retransmission cannot resurrect it.

Both parties compute this from public values each already holds — its own `IK^d` and `EK_A`, and the
peer's from the received type `0x02` header — so both converge on the same survivor with no
negotiation, no timestamps, and no dependence on arrival order. "Newest wins" was rejected for
exactly that reason: each side observes a different arrival order, so it is not a function and the
two sides can diverge permanently.

**Collapse never suppresses a plaintext.** When the collapse runs from §10.7 step 14b and the newly
built session is the loser, the message that established it has already authenticated under §10.7
step 13; that plaintext MUST be delivered, together with the **surviving** session's handle, per
§10.7 step 14d and §11.6. The loser is torn down, zeroized and tombstoned exactly as the other
direction would be, and is never persisted.

Three consequences, stated rather than hidden:

- Messages already **sent** on the losing session are lost. The sender learns this only when its peer
  stops replying on that session; recovery is the application's retry, not the protocol's. This is
  the accepted cost of the race and is bounded to the handful of messages in flight during it. A
  message already **received and authenticated** on the losing session is *not* lost: §10.7 step 14d
  delivers it, because it has cleared `IKB_A`, the four DHs, the transcript binding and Poly1305.
- Exactly one plaintext is delivered per losing handshake — the message that established it. Every
  retransmission of that message is `ERR_REPLAY` under §10.7 step 4, because 14c tombstoned the
  loser. Delivery is once per handshake, never once per arrival; without the tombstone, delivery on
  the losing branch would be a plaintext-harvesting oracle.
- A `handshake_id` is grindable by its owner — an initiator can regenerate `EK_A` until the
  comparison favours it. This wins nothing: a peer that can grind can simply initiate, and §10.7
  step 4's tombstone check plus §10.7 step 14's requirement that the AEAD verify first mean an
  attacker cannot manufacture a session it does not control. The residual case — a peer replaying
  its own captured OPK-less handshake after the tombstone expires, displacing a live session — is
  the pre-existing §17.3 limitation and is disclosed there.

Covered by `SESSION-COLLAPSE` (§15.3) and by `NEG-HANDSHAKE-TOMBSTONE`, `NEG-COLLAPSE-LOSER-REPLAY`
and `NEG-COLLAPSE-LOSER-HANDLE` (§15.4).

### 11.2 Dispatching a type `0x02` message

```
hid = msg[36..68) ‖ msg[132..164)             # IK_A^d ‖ EK_A
if session_exists(hid):
    s = load(hid)
    if msg[4..36) != s.IK_A^s or msg[36..68) != s.IK_A^d:
        return ERR_IDENTITY_MISMATCH
    if not Ed25519-Verify(msg[4..36),
                          IKBIND_MSG(msg[4..36), msg[36..68)),
                          msg[68..132)):
        return ERR_BAD_SIGNATURE
    if msg[173..205) == s.DHs.pub:
        return ERR_INVALID_PUBLIC_KEY          # anti-reflection, §4.4 check 2b;
                                               #   cf. §10.1 check 8
    # Do NOT re-run X3DH. Do NOT re-initialize the ratchet. Do NOT touch the OPK.
    process as a normal ratchet message against s,
      with ad = s.SESSION_AD ‖ msg[0..225)
else:
    run §10.7
```

**A responder that re-runs X3DH on a repeated prekey message destroys the live session.** This rule
is what reconciles one-time-prekey single-use with legitimate retransmission: the second prekey
message cannot re-derive `SK` because the OPK is gone, so it must not try.

**The three checks are ordered, and the order is normative**: identity comparison, then `IKB_A`,
then anti-reflection, then the ratchet. Each returns its own code and returns immediately.

**On re-verifying `IKB_A` here.** §5.5 requires `IKB` verification on *every* identity ingest,
including "from a type `0x02` message header". Without the check above, this branch was the one
ingest path that skipped it, and the omission was observable: `IKB_A` occupies `msg[68..132)`, which
is inside the AD (§8.5), so a tampered `IKB_A` reaches the AEAD and fails there instead. Both
outcomes fail closed — a forged `IKB_A` can never be *accepted* on either reading — but they return
different codes for identical input, and §15.4 makes the exact code a conformance requirement. A
failure here MUST return `ERR_BAD_SIGNATURE`, never `ERR_AEAD_AUTH_FAILED`, even though the AD
covers those bytes. The cost is one Ed25519 verification per retransmitted prekey message, paid to
keep §5.5's blanket MUST intact and to keep the error code aligned with what actually went wrong.
Arbitrated by `NEG-IKB-RETRANS` (§15.4).

### 11.3 When the initiator stops sending type `0x02`

A sends type `0x02` for every message until A has successfully decrypted **any** message from B —
equivalently, until `CKr` becomes non-none. From then on A sends type `0x01` and clears the stored
prologue (`prologue_present = 0x00`, §12.1).

A MUST reuse the **identical** prologue field values across all its type `0x02` messages: the same
`EK_A`, `spk_id`, `opk_flag`, and `opk_id`. Only `DHs_pub`, `N`, `nonce`, and the ciphertext vary.
(A's `DHs_pub` does not change during its first sending chain, so in practice only `N`, the nonce,
and the ciphertext vary.)

This is why the state blob retains the prologue block (§12.1) and why `EK_A`'s **public** half is
stored while its private half is zeroized after `SK` derivation — the public half is all that is
needed to re-emit the prologue.

The remaining type `0x02` header fields are **not session state**, which is why the prologue block
is 41 bytes and not larger. `IK_A^s` and `IK_A^d` are recovered from the stored `SESSION_AD` at the
offsets given in §6.5 (blob offsets 19 and 51). `IKB_A` is read from the long-lived identity record
(§5.1) — it is a per-identity value, not a per-session one, and it MUST NOT be re-signed at send
time, since Ed25519 signing is not byte-reproducible across platforms (§3.4) and a
port that re-signs would emit a different 64-byte value per message. Nothing in the receive path
compares `IKB_A` across messages, so such a divergence would decrypt correctly and never be caught;
storing rather than recomputing is what makes the rule enforceable at the source.

### 11.4 Replay handling

| Scenario | Outcome |
|---|---|
| Replayed type `0x01`, `N < Nr`, no skipped key | `ERR_REPLAY` (§7.9 phase 3c) |
| Replayed type `0x01`, `N` matches a stored skipped key | Decrypts once; the key is then removed, so a second replay is `ERR_REPLAY` |
| Replayed type `0x02` with `opk_flag == 0x01`, session exists | Routed to §11.2; duplicate `N` → `ERR_REPLAY` |
| Replayed type `0x02` with `opk_flag == 0x01`, session evicted, within `HANDSHAKE_CACHE_MS` | `ERR_REPLAY` (§10.7 step 4, tombstone) |
| Replayed type `0x02` with `opk_flag == 0x01`, session evicted, tombstone expired | `ERR_UNKNOWN_PREKEY_ID` — the OPK is gone |
| Replayed type `0x02` with `opk_flag == 0x00`, session exists | Routed to §11.2; duplicate `N` → `ERR_REPLAY` |
| Replayed type `0x02` with `opk_flag == 0x00`, session evicted, within `HANDSHAKE_CACHE_MS` | `ERR_REPLAY` (§10.7 step 4, tombstone) |
| Replayed type `0x02` with `opk_flag == 0x00`, session evicted, tombstone expired | **Establishes a new session and re-delivers the plaintext.** See §17.3. |
| Retransmitted type `0x02` whose `handshake_id` **lost** a §11.1.1 collapse, within `HANDSHAKE_CACHE_MS` | `ERR_REPLAY` (§10.7 step 4, tombstone written by step 14c). The first arrival was delivered (§10.7 step 14d); retransmissions are not |

The last row is X3DH's well-known limitation in the no-OPK case and is called out honestly rather
than papered over. Implementations MUST retain the session record — or at minimum a
`handshake_id` tombstone — for at least `HANDSHAKE_CACHE_MS = 604800000` (7 days) to bound the
window, and §10.7 step 4 enforces the tombstone rather than leaving it implied. A tombstone is
written whenever a session is torn down for any reason: eviction, explicit deletion, or the collapse
of §11.1.1 — **including the newly established session of §10.7 step 14b when it is the loser. A
session that was never committed to the store is tombstoned too**, and that tombstone is what stops
the delivery rule of step 14d from becoming a plaintext-harvesting oracle. Applications for which
replay of a first message is unacceptable MUST ensure their prekey server never serves a bundle
without an OPK.

### 11.5 Session selection for type `0x01`

A type `0x01` message carries **no session identifier, by design** (§9.1), and none can be recovered
from its contents. The header's `DHs_pub` is not usable as a routing key: it is a value the receiver
has never seen on the first message of every sending chain, which in an ordinary alternating
conversation is *every* message — that case is precisely what §7.9 phase 3b exists to handle.
Session selection is therefore not an in-band operation and MUST be resolved before decryption
begins. The rules below are normative.

1. **Explicit handle.** The decrypt entry point MUST take an explicit session handle, matching
   §7.9's `RatchetDecrypt(live_state, message)` signature. An implementation MUST NOT expose a
   decrypt API that accepts a type `0x01` message alone. §10.1 check 6 fails with `ERR_NO_SESSION`
   when no handle is supplied or the handle does not resolve.

2. **The sender identity comes from the transport, never from the message.** The host MUST derive
   the handle from a sender identity authenticated by the transport, or from its own out-of-band
   channel binding, and MUST NOT derive it from any field of the message. Nothing in a type `0x01`
   header is authenticated before decryption, so routing on header bytes lets an attacker choose
   which of the receiver's sessions absorbs the cost of processing a message it forged.

3. **No trial decryption.** An implementation MUST NOT attempt `RatchetDecrypt` for one type `0x01`
   message against more than one session. A message that does not decrypt under the selected session
   MUST return `ERR_AEAD_AUTH_FAILED` and MUST NOT be retried against another session; per §7.7 no
   state has mutated, so there is nothing to unwind. Trial decryption multiplies §17.6's per-message
   derivation bound by the candidate count — §7.9 phase 3c runs `SkipMessageKeys` *before* the AEAD
   check, so every extra candidate costs up to `MAX_SKIP_PER_MESSAGE` HMAC operations and as many
   snapshot insertions — and it turns the AEAD into an oracle for how many sessions a receiver holds.
   It also lets an attacker who cannot influence the host's routing get its packet tried against every
   session the receiver holds, which is precisely the capability rule 2 exists to deny it.

   **This prohibition is observable, and the observation is its definition.** An implementation
   holding a live session under which a type `0x01` message *would* decrypt MUST still return
   `ERR_AEAD_AUTH_FAILED` when that message is submitted against a different session, and MUST leave
   that other session's state byte-identical (§12.1). A trial-decrypting implementation fails by
   returning the plaintext where the vector requires an error, or — if it retries and then suppresses
   the result — by an advanced `Nr` and a rewritten `CKr` in the other session's blob.
   `NEG-DEMUX-WRONG-SESSION`, `NEG-DEMUX-WRONG-PEER` and `DEMUX-NO-TRIAL` construct exactly that
   situation, and it is constructible only because §11.1.1's bound is per peer.

   This is a constraint on the API as well as on the control flow: an implementation MUST NOT expose
   a decrypt entry point for a type `0x01` message that accepts more than one handle, a collection of
   handles, a peer set, or no selector at all. Selection is a total function evaluated **before**
   decryption begins, and its only permitted inputs are a handle (rule 1) or a transport-authenticated
   peer identity (rule 2).

4. **One session per peer makes rules 2 and 3 sufficient.** Because §11.1.1 permits at most one live
   session **per peer identity pair**, an authenticated sender names exactly one session and no
   tiebreak is required. The candidate set is one *per peer*, not one globally: a receiver with 50
   correspondents holds 50 sessions, which is the figure §17.6's worst case multiplies by, and rule 3
   is what stops a single message being tried against all of them. A tiebreak among sibling sessions
   is not merely unnecessary but unspecifiable: no deterministic function of a type `0x01` header can
   identify the right one.

5. **A type router is required API.** An implementation MUST expose an entry point that runs §10.0
   rows 1–4 and returns the resolved message type, so a host holding bytes off a transport selects the
   correct decrypt entry point rather than inferring it from an error code. The router MUST NOT
   decrypt, MUST NOT resolve a session, and MUST NOT accept a handle. It is what makes
   `ERR_WRONG_ENTRY_POINT` a diagnosable bug rather than a trap: a conformant host cannot reach it.

The design alternatives, and why each was rejected, are recorded in §19.2 so this is not
re-litigated. Covered by `NEG-DEMUX-WRONG-SESSION`, `NEG-DEMUX-WRONG-PEER`, `NEG-NO-SESSION` (§15.4)
and `DEMUX-NO-TRIAL` (§15.3).

### 11.6 What a successful decrypt returns

**Normative.** Every decrypt entry point returns, on success, a value carrying exactly these four
things:

| Field | Meaning |
|---|---|
| `plaintext` | The decrypted bytes. Present on every success, including §10.7 step 14d's losing branch. Zero length is a legal value (§10.4). |
| `session` | The handle the caller MUST use from now on. **Always the survivor**, never a torn-down session. |
| `established_new_session` | True iff this call ran §10.7 **and** the session it built is the survivor. False on every §11.2 path, every §10.1 path, and on §10.7's losing branch. |
| `torn_down_handshake_id` | The 64-byte `handshake_id` destroyed by this call, absent when nothing was destroyed. |

A caller MUST compare any handle it already holds against `torn_down_handshake_id` and discard it on
a match, and MUST adopt `session`. Every subsequent operation on a torn-down handle MUST fail with
`ERR_NO_SESSION` (§10.5, 7120); a torn-down handle MUST NOT resolve, and MUST NOT be written back by
`persist`.

**A bare "a collapse occurred" boolean is NOT sufficient and MUST NOT be the only signal.** It is
true on both branches of §10.7 step 14b while the caller's obligation is opposite on each: on the
winning branch the caller's cached handle is dead and must be discarded, and on the losing branch the
caller's cached handle is the survivor and must be *kept*. A port that reports the disjunction and
documents it as "your handle is dead" instructs the caller to destroy its live session in the one
branch that matters, and an attacker triggers that by delaying a single packet during a concurrent
initiation. An implementation MAY additionally expose a derived boolean meaning "a handle you may
previously have held for this peer is now dead", which is `torn_down_handshake_id` present **and**
`established_new_session` true — but the id is what makes the condition observable at all, since a
handle is an opaque object with no byte representation.

---

## 12. State serialization

Language-native serialization is BANNED for session state (§3.3). Beyond the deserialization-gadget
problem, any native serializer makes byte-for-byte state interoperation across four runtimes
impossible by definition.

### 12.1 Layout

```
off   len   field               notes
----  ----  ------------------  --------------------------------------------------
0     4     magic = "NTS4"      4E 54 53 34
4     1     state_format = 0x01
5     1     role                0x01 initiator, 0x02 responder
6     141   SESSION_AD          §6.5, stored verbatim
147   64    handshake_id        §11.1
211   32    RK
243   32    DHs_priv
275   32    DHs_pub
307   1     DHr_present         0x00 or 0x01
308   32    DHr_pub             32 × 0x00 when absent
340   1     CKs_present         0x00 or 0x01
341   32    CKs                 32 × 0x00 when absent
373   1     CKr_present         0x00 or 0x01
374   32    CKr                 32 × 0x00 when absent
406   4     Ns                  uint32_be
410   4     Nr                  uint32_be
414   4     PN                  uint32_be
418   8     send_counter        uint64_be, §12.5
426   1     prologue_present    0x00 or 0x01
427   41    prologue            41 × 0x00 when absent; layout below
468   4     skipped_count       uint32_be, MUST be <= 2000
--- fixed prefix ends: 472 bytes ---
472   76*n  skipped entries     n = skipped_count; each entry is:
                                  +0   32  dh_pub
                                  +32  4   N               (uint32_be)
                                  +36  32  mk
                                  +68  8   inserted_at_ms  (uint64_be)

total length MUST equal exactly 472 + 76 * skipped_count.

prologue block (41 bytes, initiator only, while type 0x02 is still being sent):
  +0   32  EK_A_pub        public half only; the private half is zeroized after SK
  +32  4   spk_id          uint32_be
  +36  1   opk_flag
  +37  4   opk_id          uint32_be
```

Fixed-size optional fields are **always present and zero-filled when absent**, so the fixed region
has no conditional structure. Readers MUST branch on the `_present` flag, never on whether the bytes
happen to be zero.

### 12.2 Parsing rules

1. `len(blob) >= 472` → else `ERR_STATE_CORRUPT`.
2. `magic == "NTS4"` → else `ERR_STATE_CORRUPT`.
3. `state_format == 0x01` → else `ERR_STATE_CORRUPT`.
4. `role ∈ {0x01, 0x02}`; every `_present` byte `∈ {0x00, 0x01}` → else `ERR_STATE_CORRUPT`.
5. `skipped_count = be32(blob[468..472)) <= 2000` → else `ERR_STATE_CORRUPT`.
6. `len(blob) == 472 + 76 * skipped_count` **exactly** → else `ERR_TRAILING_BYTES`.
7. Every stored public key passes §4.4 checks 1–2 → else `ERR_STATE_CORRUPT`.
8. `DHs_priv` is in clamped form (§4.2): `(blob[243] & 0x07) == 0` **and**
   `(blob[274] & 0xC0) == 0x40` → else `ERR_STATE_CORRUPT`.
9. Drop and zeroize entries whose `inserted_at_ms` is older than `SKIPPED_TTL_MS`, measured against
   the §15.5 rule 6 time source.

A failure at any step MUST yield **no** partially-loaded state.

Rule 8 **rejects** rather than silently re-clamping. That matches the fail-closed posture of every
other rule here and preserves the exact-bytes property the layout depends on; it is safe to impose
now because `state_format 0x01` has not shipped. Covered by `NEG-STATE-UNCLAMPED` (§15.4).

> Implementers: derive `472` from the field table above and confirm it against the constant. The
> exact-length assertion is the enforcement mechanism, so an error in this constant would make every
> conformant implementation reject every other's blobs. The sum is
> `4+1+1+141+64+32+32+32+1+32+1+32+1+32+4+4+4+8+1+41+4 = 472`.

### 12.3 Encryption at rest

The blob MUST NOT be persisted in plaintext. Seal it with ChaCha20-Poly1305 under a device-bound key
from the platform keystore, with a **fresh random 12-byte nonce stored alongside**:

- Apple: Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- Android / JVM: Android Keystore or a platform-appropriate KMS.

The at-rest key MUST NOT be derived from the state itself. The plaintext blob MUST be zeroized after
sealing and after parsing. Keystore selection, rotation, and behaviour on device migration are
deliberately outside this document's byte-compatible surface — only the plaintext layout is
normative.

### 12.4 Fuzzing

Every port MUST fuzz **all four hand-written decoders in this document**: the state-blob parser
(§12.2), the bundle parser (§10.3), the type `0x01` parser (§10.1), and the type `0x02` parser
(§10.2). Each takes attacker-adjacent bytes into a hand-written decoder, and the bundle parser in
particular is reachable from a hostile or compromised prekey-distribution server before any
signature has been verified (§5.3 orders parsing first).

The corpus MUST include the zero-length input and every length from zero to one byte past each
structure's fixed prefix. A fuzz run is a failure if any input produces anything other than a
specified error code — a trap, an uncaught exception, an out-of-bounds read, or an allocation
proportional to an unvalidated field all count as failures, not as "rejected".

### 12.5 Rollback tripwire

`send_counter` is a uint64 incremented on **every** successful `RatchetEncrypt`, persisted before
the message is emitted.

An implementation SHOULD additionally record the last observed `send_counter` in storage that is
**excluded from application backups** (iOS: a Keychain item with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and no iCloud sync; Android: Keystore-backed
preferences excluded from auto-backup). On state load, if the blob's `send_counter` is **less than**
the recorded value, the state has been rolled back: the implementation SHOULD refuse to encrypt on
that session and SHOULD return `ERR_STATE_ROLLBACK`, requiring a fresh handshake.

This is defence in depth. The primary mitigation for rollback is the random nonce (§8.3), which is
what makes a missed rollback survivable rather than catastrophic.

---

## 13. Randomness, return values, and zeroization

### 13.1 Randomness

**The invariant, which is what every bullet below exists to serve: a fill of a key-material buffer
either succeeds completely or the buffer MUST NOT be used. A fill that does not succeed MUST NOT
leave usable bytes behind, and the caller MUST NOT proceed.** It is stated as an invariant rather
than as a claim about any one library because the four backends do not agree on how — or whether — a
failed fill is reported, so a rule phrased as "check the status" or "catch the exception" is vacuous
on a backend that offers neither.

**No key-material buffer may be allocated with a zero-filling API and then handed to a possibly
failing fill.** This is the reason the invariant is load-bearing rather than pedantic: every
allocator in reach zero-fills — `NSMutableData dataWithLength:`, `new byte[n]`, and
`Data(count:)` all hand back zeros — so a fill that fails silently over one of them yields an
**all-zero key** rather than unusable garbage. An all-zero key is a value *both parties agree on*,
so everything appears to work and the session has no security whatsoever. `NSMutableData
dataWithLength:` followed by an unchecked `SecRandomCopyBytes` (v3,
`IREncryptionService.m:476-481`) is exactly that bug, and it is v3's defect 4.

How the invariant is discharged differs per backend, and the differences are precisely where a port
guesses:

- **Objective-C / libsodium.** `randombytes_buf(void*, size_t)` returns `void` and cannot fail — it
  aborts the process on entropy failure — so the invariant holds with no caller action and there is
  no return value to forget. This is why it is preferred over `SecRandomCopyBytes`.
- **`SecRandomCopyBytes`**, wherever it is used, returns an `OSStatus` which MUST be compared
  against `errSecSuccess`; a failure MUST zeroize the buffer and return `ERR_RNG_FAILURE`.
- **JVM.** Construct with `new SecureRandom()`, not `getInstanceStrong()`, which can block
  indefinitely on Linux. `nextBytes(byte[])` returns `void`, declares no checked exception, and is
  **not specified to throw** on entropy exhaustion; a provider MAY raise an unchecked
  `ProviderException`, but nothing in the API contract requires one and no caller may depend on it.
  An earlier revision of this section said of the JVM RNG that "it throws rather than returning a
  status". That is false, and false in the direction that makes a port believe the invariant is
  being enforced on its behalf. The JVM hands the caller neither a status to check nor a guaranteed
  exception to catch.
- **Swift.** CryptoKit's key generators use the system CSPRNG internally and cannot silently fail;
  prefer them. A bare `SecRandomCopyBytes` in Swift returns an `OSStatus` that Swift will **not**
  warn about discarding, so call sites MUST check it explicitly.

**The all-zero tripwire.** Every freshly generated private key SHOULD additionally be tested against
all-zero before first use, as a cheap last line of defence. On a backend whose fill reports failure
by neither a status nor a guaranteed exception — the JVM — that test is **REQUIRED** rather than
merely RECOMMENDED, because it is the only mechanism by which the invariant above can be discharged
there at all.

### 13.2 Return values

- **Where the backend has a mandatory one-time initialization step, it MUST be performed exactly
  once and its outcome MUST be checked**, and a failure MUST make every subsequent API call return
  `ERR_NOT_INITIALIZED`. Never a silently degraded service. For libsodium that step is
  `sodium_init()` (`dispatch_once` or equivalent): `0` and `1` are both success, `< 0` is fatal.
  BouncyCastle, the JDK providers and CryptoKit / swift-crypto have no such step, so this bullet
  imposes nothing on them and `ERR_NOT_INITIALIZED` is unreachable there — which §10.5 states is
  conformant rather than a gap.
- `__unused`, `@discardableResult`, and ignored `Bool`/`int` returns are **banned** on every crypto
  call. The crypto layer SHOULD be compiled with `-Wunused-result` promoted to an error.
- `crypto_scalarmult`, `crypto_sign_verify_detached`, and every AEAD open return value MUST be
  checked.
- Swift's `Curve25519.Signing.PublicKey.isValidSignature(_:for:)` returns `Bool` and never throws;
  a discarded `Bool` there is the exact Swift analogue of v3's `__unused int`.

v3 marks four return values `__unused`: `sodium_init` (`:41`), `SecRandomCopyBytes` (`:478`), and
both `crypto_sign_ed25519_*_to_curve25519` calls (`:82-84`, `:115-117`). The last two are eliminated
entirely by §4.1 rather than fixed.

### 13.3 Zeroization schedule

The *schedule* matters more than the mechanism: "zero your keys" as general advice produces four
implementations that zero different subsets.

**This table is exhaustive for every private key and derived secret this protocol handles.** An
omission is not a licence: if a secret is not listed, that is a defect in this document and MUST be
raised, not resolved locally. The previous revision omitted the prekey and identity privates, and an
omission read as "unspecified, therefore optional" is exactly the divergence the schedule exists to
prevent.

| Secret | Zeroize when |
|---|---|
| `DH1`–`DH4`, `IKM` | Immediately after `SK` is derived |
| `EK_A` private half | Immediately after `SK` is derived |
| `SK` | Immediately after ratchet initialization |
| `CK` (each) | Immediately after `KDF_CK` produces its successor |
| `MK` (each) | Immediately after `KDF_MK` expands it |
| `enc_key` | Immediately after the AEAD call returns — success **and** failure paths |
| Skipped message keys | On use, on eviction, and on TTL expiry |
| Ratchet private keys — **session-owned copies only** | When replaced by a fresh one (§7.4 step 4). This row NEVER covers `SPK_B_priv` or any other prekey-store key: the responder's initial `DHs.priv` is a session-owned copy per §7.5, and the prekey store's original is governed by §5.3 and the row below |
| `OPK` private | On the AEAD-success path, in place and **before** the durable delete of §6.6 step 4 commits; and on expiry per `OPK_MAX_AGE_S` (§5.3) |
| `SPK` private | When §5.3 retention ends — the key has left the {current, one previous} set, and at the latest once its `not_after` has passed |
| `IK^s_priv`, `IK^d_priv` | On identity deletion or application data erasure. Otherwise held for the identity's lifetime in a zeroizing container (below), never in a copying type |
| Expanded 64-byte Ed25519 `sk` | Immediately after `crypto_sign_detached` returns (§3.4); it MUST NOT outlive the single signing call that needed it |
| Serialized state buffer | After sealing, and after parsing |
| Every intermediate secret in a discarded snapshot | When the snapshot is discarded (§7.7) |

Four of these rows are not observable by a peer and therefore cannot be covered by a test vector:
the `OPK`, `SPK`, identity, and expanded-`sk` rows describe memory hygiene, not wire behaviour.
`NEG-OPK-EXPIRED` (§15.4) covers the one externally visible consequence — an expired OPK no longer
resolves. The rest MUST be enforced by code review and by the §3.3 lint rules, and each port's
`CLAUDE.md` SHOULD name them.

Zeroization MUST use a primitive the toolchain is required to respect — never a plain loop or a
`memset` that a compiler may eliminate as a dead store.

- Objective-C: `sodium_memzero`. Consider `sodium_malloc` / `sodium_mlock` for long-lived root and
  chain keys. Do **not** re-enable v3's commented-out `memset` blocks
  (`IREncryptionService.m:357-360`, `:388-391`, `:412-415`): they mutate a caller-owned `NSData`'s
  backing store through a `const` pointer, which is both a const-correctness violation and
  legitimately optimizable away.
- Swift: `memset_s` via `withUnsafeMutableBytes`, or swift-sodium's zeroizer. Do **not** hold
  secrets in `Data` — copy-on-write means a wipe may zero one buffer while another copy survives.
  Prefer `SymmetricKey` (which wipes its own storage on deinit) or a class with a zeroizing `deinit`.
  Avoid `struct` value types for secrets, since copies multiply.
- JVM: `java.util.Arrays.fill(buf, (byte) 0)` in a `finally` block. **This is best-effort only** —
  see §17.1.

### 13.4 Argument contracts

§13.2's closing rule governs what an operation may return. This section governs what it may be
handed, and it is the counterpart: the argument side was previously unspecified, and the Objective-C
default there is the dangerous one.

**Scope.** This section governs the parameters of the operations this document specifies — bundle
publication and ingest, encrypt, both decrypt entry points, and the routing helper of §11.5 rule 5. A
port's internal seams are not part of the interop contract and this section does not dictate how they
report a null; what it does forbid, everywhere, is clause 2.

1. **A null reference passed for a parameter the API declares non-null is a caller contract
   violation, not a protocol condition.** It MUST NOT be reported through the §10.5 taxonomy, MUST
   NOT be assigned an error code, and MUST NOT be surfaced as a returned null with an error set. Every
   §10.5 code describes something a peer, the network or stored data did; this is something the host
   did, in the same address space, and a code for it invites a caller to retry a call that can never
   succeed.

2. **An implementation MUST NOT substitute a default for a missing required argument** — not an empty
   byte string, not a zero-filled buffer, not a freshly generated key, not a silently skipped check.
   This is the failing-open branch and the reason this section exists. §10.4 makes a **zero-length
   plaintext legal**, so a null-as-empty coercion is indistinguishable downstream from a legitimate
   empty input; an empty `IKM` reaching HKDF-Extract yields a 32-byte `SK` that both parties can agree
   on and that contains no key material, and an empty `ad` silently voids §8.5's binding of the header
   to the ciphertext. Both are §13.1's failing-open pattern reached through the argument list instead
   of the RNG. Against a fixed-width primitive it is worse still: handing an empty buffer to a call
   expecting 32 bytes is the same out-of-bounds read §3.4 documents, which surfaces disguised as
   `ERR_BAD_SIGNATURE`.

3. **Where the language permits the call to be made at all, the implementation MUST fail fast,
   unconditionally, and in Release builds**, through its own mechanism for unrecoverable programming
   errors — and that mechanism MUST NOT be catchable and mappable into a protocol error. Objective-C:
   a check that survives `NS_BLOCK_ASSERTIONS`, never `NSParameterAssert` or `NSAssert` (§3.3). JVM:
   `Objects.requireNonNull` at every entry point, with the resulting unchecked throwable propagating
   uncaught — the same rule §16.3 already states for `AEADBadTagException`. Kotlin: non-null parameter
   types, whose compiler-inserted intrinsic already does this, plus the explicit check at the
   Java-interop boundary. Swift: non-optional parameter types, so the call does not compile.

4. **No port may widen a non-null parameter to a nullable or optional one, or add a
   nullable-accepting overload.** This is the clause that binds all four ports, and it is the
   enforceable half of the rule where the language cannot enforce it — Java has no non-null in its
   type system, and a Java port declaring `byte[] plaintext` and defensively writing
   `if (pt == null) pt = new byte[0]` looks *more* careful than one that throws while being exactly
   the clause-2 bug.

5. **Absence of a session handle is NOT covered by this section.** §10.1 check 6 makes "the caller
   supplied a session handle and it resolves" a specified protocol condition with its own code
   (`ERR_NO_SESSION`, 7120) and its own vector (`NEG-NO-SESSION`, whose first case is *no handle at
   all*). **Every session handle parameter MUST therefore be declared nullable/optional in every
   port**, on send as well as on receive: a non-null handle guarded by a trap makes `ERR_NO_SESSION`
   unreachable from Swift and contradicts a required vector. A handle naming a session torn down
   under §11.1.1 is stale and resolves the same way (§11.6) — and §11.1.1's collapse is precisely the
   mechanism that manufactures stale handles, which is why this is the one parameter the outside
   world can legitimately render absent, and why it is specified rather than trapped.

6. **This rule is deliberately not covered by a conformance vector, and that absence is normative
   rather than an oversight.** A null argument has no hex encoding, §15.5's `inputs` are typed hex and
   decimal strings, a vector asserting an abort is not runnable by a runner that must survive it, and
   the call is uncompilable in Swift. A `NEG-NULL-ARG` row would be a permanent skip in at least two
   of four ports, which §15.6 step 5 forbids. Enforcement is the §3.3 lint and per-port unit tests
   instead, and each port's `CLAUDE.md` MUST name it. What the vectors *do* pin is the adjacent legal
   case, so the two are never conflated: `NEG-BUNDLE-EMPTY`, `NEG-TRUNCATED`, and §10.4's legal empty
   plaintext are all about the **content** of a value that exists, which is the side a vector can
   reach.

§12.4's fuzzing rule is unaffected and does not collide with this one: a fuzz harness supplies byte
strings, never null references, so a trap on a fuzz input remains a **failure**. The two rules
partition cleanly along the reference/content line, and that line is why clause 6's list matters.

---

## 14. Defect resolution table

The thirteen confirmed defects, each mapped to the section that fixes it. Line references are to the
v3 sources verified while writing this document.

Defect 1 was not found here. It was reported against the published library in May 2019 by
**Yuri Buyanov** (`@digal`), who read the `crypto_kdf_derive_from_key` signature and worked out the
consequence — that the library was a single-DH implementation — from the parameter type alone. It
sat unfixed for seven years. Defect 4's Ed25519→X25519 half surfaced as a separate interoperability
report from **Burhan** (`@NoVoLuMe`) and **`@raojunbo`**, who could not agree a key with standard
X25519 libraries and were correct about why: the API silently ran `_pk_to_curve25519` over whatever
public key it was handed, and hashed the scalar multiplication output with BLAKE2b, so it was never
speaking X25519 on the wire at all.

Both reports describe conditions no test in the v3 suite could have detected, and both are the
reason §15.1 says what it says.

| # | Defect | v3 location | Fixed by | Mechanism |
|---|---|---|---|---|
| 1 | **X3DH collapses to a single DH.** `crypto_kdf_derive_from_key` reads exactly 32 bytes of the 96–128 byte `kdfInput`; DH2/DH3/DH4 discarded | `IREncryptionService.m:180-183`; `IRTripleDHService.m:112-122` | §3.2, §3.3, §6.3, §6.4 | HKDF-Extract's `(ikm, ikm_len)` makes truncation inexpressible; `crypto_kdf_derive_from_key` banned outright; `len(IKM) ∈ {128,160}` asserted |
| 2 | **X3DH output never reaches the ratchet.** `sharedKey` ignored; `performDHRatchet:` discards the previous root key | `IRDoubleRatchetService.m:80-102`, `:239-271` | §7.2, §7.5 | `SK` becomes the initial `RK`; `KDF_RK` takes the previous `RK` as the **mandatory HKDF salt**; `RootKey` is a non-optional nominal type |
| 3 | **Signed prekeys never verified;** `initWithData:` re-signs the peer's prekey with the local identity key | `IRTripleDHService.m:66-68` | §5.1, §5.2, §5.3, §10.7 | Mandatory `Ed25519-Verify` of `IKB` **and** `SPK_SIG` before any DH, in **both** directions; re-signing deleted |
| 4 | **RNG / return-value failures silent;** zero-filled buffers yield all-zero keys; conversions leave uninitialized stack keys | `IREncryptionService.m:41`, `:82-84`, `:115-117`, `:476-481` | §4.1, §13.1, §13.2 | `randombytes_buf`; every return value checked; `-Wunused-result` as error; the two conversion calls **deleted** with the key-type split |
| 5 | **`consistentTimeEqual:` neither constant-time nor correct;** gates AES-CBC + PKCS7 | `IREncryptionService.m:522-536` | §8.2, §9.3 | Function **deleted**, not fixed. One AEAD call: no MAC to compare, no comparator, no padding, no separate IV |
| 6 | **Out-of-bounds reads.** `*(NSInteger*)` on a 1-byte `NSData`, three call sites | `IREncryptionService.m:495`, `:508`, `:513`, `:614`, `:649` | §9, §10 | **No length field exists.** Header length is a constant selected by the type byte; no offset is derived from received bytes |
| 7 | **One-time prekeys never consumed** — always `firstObject` | `IRTripleDHService.m:98` | §6.6, §10.7, §11.2 | Map keyed by `opk_id`; reject-on-unknown with no 3-DH fallback; durable delete **before** plaintext release; session cache reconciles retransmission |
| 8 | **Key material never zeroed;** `memset` scrubbing commented out | `IREncryptionService.m:357-360`, `:388-391`, `:412-415` | §13.3 | Explicit per-secret zeroization schedule with non-elidable primitives; the commented `memset` blocks deleted rather than re-enabled |
| 9 | **1-byte header counters wrap at 256** | `IRDoubleRatchetService.m:140-145` | §9.1, §9.2 | `uint32_be`, capped at `0x7FFFFFFF`; sender refuses at exhaustion with `ERR_COUNTER_OVERFLOW` rather than wrapping |
| 10 | **`Ns` written into both header counter fields;** `PN` never transmitted | `IRDoubleRatchetService.m:140-145` | §7.8, §9.1 | `N` from `state.Ns`, `PN` from `state.PN` — two distinct stored variables, explicitly never interchangeable |
| 11 | **`skippedMessagesKeys` grows unbounded;** pruned only on successful use | `IRDoubleRatchetService.m:212-237` | §7.6 | `MAX_SKIP_PER_MESSAGE` 1000 (aggregate), `MAX_SKIPPED_STORED` 2000, FIFO eviction, 7-day TTL, zeroize on evict |
| 12 | **State restore uses `NSKeyedUnarchiver unarchiveObjectWithData:`** | `IRDoubleRatchetService.m:315`, `:410` | §12 | Fixed-layout binary blob, exact-length assertion, reject trailing bytes, sealed at rest, fuzzed |
| 13 | **version / options never validated on decrypt** | `IREncryptionService.m:601-609` (read, commented out) | §8.5, §10.1, §10.2 | Validated in the ordered gate **and** covered by the AEAD associated data — a tampered byte is an authentication failure, not a silent no-op |

### 14.1 Additional defects found while writing this specification

These are **not** in the original list of thirteen and MUST NOT be reproduced in any port.

| Defect | v3 location | Fixed by |
|---|---|---|
| **Decrypt is not atomic.** Skip-insert, DH ratchet, chain advance, and counter increment all commit *before* the MAC is checked, so an unauthenticated message permanently desynchronises a live session | `IRDoubleRatchetService.m:178-199` vs `:203` | §7.7 |
| **Skipped key removed before decryption.** A message that fails to decrypt destroys the only copy of its key and is permanently lost | `IRDoubleRatchetService.m:168` vs `:170` | §7.6, §7.9 |
| **Signing uses the prehashed multi-part API**, not pure Ed25519 — silently incompatible with JDK and CryptoKit, and the failure looks exactly like a MITM | `IREncryptionService.m:431-433`, `:449-450`; `crypto_sign.h:23` | §3.4 |
| **Null `NSError**` dereference** in both "simple" AEAD entry points | `IREncryptionService.m:199`, `:302` | §10.5, §9.3 |
| **Second `addSkippedMessages:` return value discarded**, so an over-limit skip on that path is ignored | `IRDoubleRatchetService.m:188` | §7.9 |
| **`IRCurve25519KeyPair isEqual:` is asymmetric** on private-key presence, so the header-key comparison depends on how a field was populated rather than on key bytes | `IRCurve25519KeyPair.m:176-186`; used at `IRDoubleRatchetService.m:177` | §4.3, §10.1 step 8 |
| **`IRAEADInfo infoWithRawData:` reads 80 bytes** from a possibly shorter `NSData` | `IRAEADInfo.m:34-45` | §9.3 (type deleted) |
| **No maximum message size**; ranges computed by subtraction from attacker-controlled lengths | `IREncryptionService.m:623`, `:652` | §10.4 |
| **Empty plaintext conflated with encryption failure** | `IREncryptionService.m:239-246` | §10.4 |

---

## 15. Test vector plan

### 15.1 Why vectors, not prose

Byte-for-byte interoperability across four implementations will not be achieved by prose. Worse,
the existing test suite **cannot detect a regression on defects 1 or 2**: `IRTripleDHServiceSpec`
asserts only that Alice's and Bob's shared keys are equal and 32 bytes long, which holds true when
only DH1 contributes, and `IRDoubleRatchetServiceSpec` passes all its cases while `sharedKey` is
never read. **Positive round-trip tests certify nothing about this protocol.**

A frozen vector set is therefore a required deliverable, not an implied one. An implementation is
**conformant** only when every vector in §15.3 and §15.4 passes.

### 15.2 File set

All files live in `spec/vectors/` and are UTF-8 JSON. All byte strings are **lowercase hex, no
`0x` prefix, no separators**.

**Integer encoding is type-driven, not value-driven.** Integers of protocol type uint8, uint16 or
uint32 are JSON numbers. The six uint64-typed fields — `send_counter` (§12.1), `inserted_at_ms`
(§12.1), `not_before` and `not_after` (§5.2), and the injected `now_s` / `now_ms` (§15.5 rule 6) —
are **always** JSON strings holding the unsigned decimal value: no sign, no leading zeros (except
the single digit `"0"`), no separators, **irrespective of magnitude**. A generator MUST NOT emit
these as JSON numbers, and a runner MUST reject a uint64 field that is not a string. No JSON number
may appear anywhere a value can exceed 2⁵³.

The unconditional phrasing is load-bearing. The previous rule — "JSON numbers except where a value
may exceed 2⁵³, in which case a decimal string (documented per field)" — had two defects: no field
was ever so documented, and the condition was a property of the *value* rather than the *type*, so
one conformant generator emitted `send_counter: 5` and another `send_counter: "5"` with nothing
telling a runner to accept both. It also left a real corruption path: Jackson parses a bare JSON
integer into a `long` exactly, while Swift `JSONSerialization` and every JS-based tool coerce to
`Double`, so `send_counter: 9007199254740993` serializes as `00 20 00 00 00 00 00 01` on the JVM and
`00 20 00 00 00 00 00 00` in Swift — a byte-level split inside a structure §12 declares
byte-normative.

| File | Contents |
|---|---|
| `primitives.json` | HKDF, HMAC, X25519, Ed25519, ChaCha20-Poly1305 known-answer tests |
| `x3dh.json` | Full handshakes from fixed keys, with and without an OPK |
| `ratchet.json` | Full conversations including ratchet steps and out-of-order delivery |
| `wire.json` | Byte-exact encodings of every structure |
| `state.json` | State blob round-trips |
| `negative.json` | Every rejection path |

### 15.3 Positive vectors — required coverage

**`primitives.json`**

| id | Purpose |
|---|---|
| `RFC5869-A1`…`A3` | RFC 5869 HKDF-SHA256 test vectors verbatim. **Run these first**; nothing else is trustworthy until they pass. |
| `HKDF-SALT-EQUIV` | `HKDF-Extract(Z32, ikm) == HKDF-Extract("", ikm)`. Documents that this is *not* a divergence point. |
| `HKDF-EXPAND-64` | A 64-byte expansion, exercising the two-block `T(i)` loop that `KDF_RK` needs. |
| `RFC7748-X25519` | RFC 7748 §5.2 scalar multiplication vectors. |
| `X25519-ZERO` | A small-order input; MUST produce the all-zero output and be **rejected**. |
| `RFC8032-ED25519` | RFC 8032 §7.1 pure-Ed25519 vectors, asserted **verify-side** per §3.4 and §15.5 rule 8: the runner MUST verify the RFC's published signature against the RFC's public key and message, and MUST additionally sign the message itself and verify *that* signature. It MUST NOT compare its own signature bytes to the RFC's. **A port using the prehashed API fails here** (§3.4) — on the verify of the published signature, which is where the failure belongs. Private-key inputs are 32-byte **seeds** (§4.2); a libsodium port MUST expand via `crypto_sign_seed_keypair` first. |
| `ED25519-SEED-EXPAND` | The same seed, asserting `crypto_sign_seed_keypair(seed)` reproduces the published `IK^s` public key byte for byte. This is the only Ed25519 quantity that IS byte-reproducible across libsodium, the JDK and CryptoKit, and it is what makes an identity key portable at all. It does **not** assert anything about signature bytes. |
| `RFC8439-AEAD` | RFC 8439 §2.8.2 ChaCha20-Poly1305 vector, tag appended. |
| `KDF-CK-1` | `KDF_CK` over a fixed chain key: both `MK` and `CK'`. |
| `KDF-RK-1` | `KDF_RK` over a fixed `(RK, DH_out)`. **The salt/IKM argument-order checkpoint** (§7.2). |
| `KDF-MK-1` | `KDF_MK` over a fixed `MK`. |

**`x3dh.json`**

| id | Purpose |
|---|---|
| `X3DH-OPK` | Full handshake with an OPK. Exposes `TRANSCRIPT`, `TH`, `IKM`, `SK`, `SESSION_AD`. |
| `X3DH-NOOPK` | Same without an OPK. `IKM` is 128 bytes; DH4 omitted, not zero-filled. |
| `X3DH-IKBIND` | `IKBIND_MSG` bytes as an **output** (they are deterministic and byte-normative); the signature over them as an **input**, verified but never regenerated for comparison (§3.4, §15.5 rule 8). |
| `X3DH-SPKSIG` | `SPK_SIGN_MSG` bytes as an **output**; the signature over them as an **input**, verified but never regenerated for comparison (§3.4, §15.5 rule 8). |
| `X3DH-FP` | Identity fingerprint (§5.5). |

`X3DH-OPK` and `X3DH-NOOPK` ingest a bundle and so run §5.3 rules 5–6. Each MUST carry fixed
`not_before` / `not_after` literals and an `inputs.now_s` inside that window. Without the injected
clock these two vectors return `ERR_PREKEY_EXPIRED` for an `expect: "ok"` vector at most 90 days
after the freeze — rule 6 caps the window at `MAX_SPK_VALIDITY_SECONDS`, so no choice of timestamps
avoids it — and §15.6 forbids regenerating them.

**`ratchet.json`**

| id | Purpose |
|---|---|
| `RATCHET-INIT` | A and B initial states; asserts `A.CKs == B.CKr` and **explicitly asserts `A.RK != B.RK`** at that instant (§7.5). |
| `RATCHET-LINEAR` | Ten messages A→B, no ratchet turn. |
| `RATCHET-BIDI` | A→B, B→A, A→B, B→A. Exercises `SESSION_AD` role ordering (§6.5) — **a port that recomputes AD as (self, peer) fails only here.** |
| `RATCHET-SKIP` | Messages 0,1,2,3 sent; 1 and 2 delivered last. Exercises the skipped store within one chain. |
| `RATCHET-SKIP-XCHAIN` | Skipped messages recovered **across** a DH ratchet — exactly what defect 10 was masking. |
| `RATCHET-PREKEY-BURST` | A sends three type `0x02` messages with `N` = 0, 1, 2 before B replies; all decrypt (§9.2, §11.3). |
| `RATCHET-RETRANSMIT` | The same type `0x02` message delivered twice; the second is `ERR_REPLAY`, and the session survives (§11.2). |
| `SESSION-COLLAPSE` | A and B initiate concurrently, with fixed keys chosen so the comparison is decided in advance, and each receives the other's type `0x02`. **Two-sided, with per-side assertions, because the two sides exercise different branches of §10.7 step 14b.** Both MUST converge on the same surviving `handshake_id` (the greater of the two, compared as a 64-byte unsigned big-endian value), with the loser torn down, zeroized and tombstoned. Each side's `outputs` carries `plaintext` (**REQUIRED on both sides** — its presence on the side whose incoming session LOSES is the assertion that resolves §10.7 step 14d, and the fixture MUST be constructed so exactly one side is that side), `surviving_handshake_id`, `established_new_session`, `torn_down_handshake_id`, and `sessions.<name>.state_blob_after`. On the losing side the surviving session's blob MUST be byte-identical to its pre-call value (§10.7 step 14c), and the consumed `opk_id` MUST be absent from the prekey store (step 14a is final). Reads a clock, so `inputs.now_ms` is REQUIRED (§15.5 rule 6). |
| `DEMUX-NO-TRIAL` | The `NEG-DEMUX-WRONG-SESSION` fixture, second step: after the wrong-handle submission has failed with `ERR_AEAD_AUTH_FAILED`, the **same** message under the **correct** handle MUST decrypt to the original plaintext. A port that trial-decrypted and committed answers this with `ERR_REPLAY` and fails here; a port that trial-decrypted and *returned* the plaintext already failed `NEG-DEMUX-WRONG-SESSION`'s `expect`. Together the two are the only pair in the suite that makes §11.5 rule 3 falsifiable. |

**`wire.json`** — byte-exact encodings of: a type `0x01` message, a type `0x02` message, a bundle
with `opk_count` 0, a bundle with `opk_count` 1, and the `AD` byte strings for both message types.

`wire.json` bundle vectors are **encoding-only**: they assert the byte layout of §5.4 and the
structural gate of §10.3, and they do **not** run the §5.3 signature and validity-window checks.
They therefore read no clock and supply no `now_s`. Their `not_before` / `not_after` fields are
fixed literals chosen by the generator and are part of the frozen bytes. Signature and
validity-window verification is carried by `X3DH-OPK` / `X3DH-NOOPK` and by the `NEG-SPK*` vectors,
each of which supplies an explicit `inputs.now_s`.

**The same reads-no-clock carve-out extends to `X3DH-SPKSIG`**, and it is granted here in writing so
that no runner reports it malformed under §15.5 rule 6. That vector's `not_before` / `not_after` are
signed **content**, not a window being evaluated: §5.2 binds both timestamps into `SPK_SIGN_MSG`
precisely so an intermediary cannot widen them, and nothing on the vector's path calls §5.3 rules
5–6, which live on the initiator's bundle-ingest path. `X3DH-SPKSIG` therefore carries the two
timestamps as fixed literals, reads no clock, and supplies no `now_s`.

**`state.json`** — a state blob with `skipped_count` 0, one with `skipped_count` 3, initiator and
responder roles, and `prologue_present` both set and clear.

`state.json` vectors are **parse-then-reserialize** round-trips over the literal blob bytes in
`inputs`, never "execute `RATCHET-SKIP`, then serialize". The three `inserted_at_ms` values in the
`skipped_count = 3` blob are fixed literals, and every such vector supplies an `inputs.now_ms` that
places all entries **inside** `SKIPPED_TTL_MS`, so §12.2 rule 9 drops nothing and the reserialized
blob is byte-identical to the input. Without both of these the artifact is unreproducible by
construction: a runner that reached the state by executing a ratchet would write its own
`now_ms()` into blob offsets 540–548, 616–624 and 692–700, and any runner loading the frozen blob
more than seven days after the freeze would re-emit a 472-byte `skipped_count = 0` blob under §12.2
rule 9 — a MUST, in two places, that silently destroys the vector.

### 15.4 Negative vectors — required

Each MUST produce the exact error code named. **Fail-closed behaviour is as normative as the happy
path.**

| id | Scenario | Expected |
|---|---|---|
| `NEG-DH2-ALTERED` | Alter DH2 in isolation; assert `SK` **changes** | `SK` differs |
| `NEG-DH3-ALTERED` | Alter DH3 in isolation | `SK` differs |
| `NEG-DH4-ALTERED` | Alter DH4 in isolation | `SK` differs |
| `NEG-RK-ALTERED` | Alter `RK` before `KDF_RK`; assert the output changes | Output differs |
| `NEG-SK-TAMPER` | Flip one byte of `SK` **on one side only**; assert decryption fails | `ERR_AEAD_AUTH_FAILED` |
| `NEG-ATOMIC` | Inject a header-valid, tag-invalid message with a novel ratchet key; assert the **next legitimate message still decrypts** | Session survives |
| `NEG-SKIP-RETAIN` | A skipped-key message with a corrupted tag; assert the key is **retained** and a later correct delivery succeeds | Message recoverable |
| `NEG-IKB-SWAP` | Victim's genuine `IK^s` with an attacker-chosen `IK^d` in a type `0x02` header, **no existing session** (§10.7 step 3) | `ERR_BAD_SIGNATURE` |
| `NEG-IKB-RETRANS` | Retransmitted type `0x02` to an **existing** session with one byte of `IKB_A` (offset 68..132) flipped. Arbitrates §5.5 against §11.2: the code MUST be the signature failure, not the AEAD failure | `ERR_BAD_SIGNATURE` |
| `NEG-SPKSIG-BAD` | Bundle with a corrupted `SPK_SIG` | `ERR_BAD_SIGNATURE` |
| `NEG-SPK-EXPIRED` | Bundle with fixed `not_before` / `not_after` and an injected `inputs.now_s` **outside** that window, so the rejection is caused rather than merely observed | `ERR_PREKEY_EXPIRED` |
| `NEG-SPK-WINDOW-TOO-LONG` | Bundle whose `not_after - not_before` exceeds `MAX_SPK_VALIDITY_SECONDS`, with `now_s` inside the window | `ERR_PREKEY_EXPIRED` |
| `NEG-SPK-SURVIVES-RATCHET` | Two initiators fetch one bundle with the same `spk_id`. Complete initiator 1's handshake and let B ratchet past it; then run initiator 2's handshake against that same `spk_id`. **This is the only vector that catches a port aliasing the prekey store from ratchet state** (§7.5); every other ratchet vector is single-session and passes either way | Initiator 2's handshake **succeeds** |
| `NEG-OPK-UNKNOWN` | `opk_flag == 0x01` with an unresolvable `opk_id`, no session | `ERR_UNKNOWN_PREKEY_ID` |
| `NEG-OPK-EXPIRED` | `opk_id` naming an OPK whose local creation timestamp is older than `OPK_MAX_AGE_S`, with an injected `inputs.now_s`; the entry MUST have been deleted per §5.3 | `ERR_UNKNOWN_PREKEY_ID` |
| `NEG-OPK-NOFALLBACK` | Same, asserting **no** 3-DH fallback occurred | No session created |
| `NEG-VERSION` | First byte `0x03` (a v3 message), at or above the 72-byte global floor | `ERR_UNSUPPORTED_VERSION` |
| `NEG-VERSION-SHORT` | A 100-byte message with `msg[0] == 0x03` and `msg[1] == 0x02`, i.e. **below** §10.2's floor of 241, submitted with `entry_point: "decrypt_prekey"`. Pins §10.0 row 3 ahead of every type-dependent floor and is what makes §10.6's guarantee testable; an implementation that kept a floor first returns `ERR_TRUNCATED_MESSAGE` and fails | `ERR_UNSUPPORTED_VERSION` |
| `NEG-TYPE` | Type byte `0x03` (§10.0 row 4), from either entry point | `ERR_UNKNOWN_MESSAGE_TYPE` |
| `NEG-ENTRYPOINT-01-TO-02` | A **72-byte, otherwise valid** type `0x01` message submitted with `entry_point: "decrypt_prekey"`. The length band is normative and MUST NOT be widened: 72 sits *below* §10.2's floor of 241, so an implementation that evaluated the floor before the demultiplex returns `ERR_TRUNCATED_MESSAGE` and fails. A ≥241-byte fixture does not distinguish the two orderings | `ERR_WRONG_ENTRY_POINT` |
| `NEG-ENTRYPOINT-02-TO-01` | A valid, complete type `0x02` message submitted with `entry_point: "decrypt_with_handle"` **and a handle that resolves** — the handle is load-bearing, because without it a port checking §10.1 check 6 too early returns `ERR_NO_SESSION` and passes for the wrong reason. This is also the direction that catches auto-forwarding: a forwarding port succeeds and returns a plaintext against an `expect: "error"` vector | `ERR_WRONG_ENTRY_POINT` |
| `NEG-FLAGS` | Flags `0x0001` | `ERR_RESERVED_FLAGS_SET` |
| `NEG-TRUNCATED` | 71-byte type `0x01` message — one byte below §10.0 row 1's global floor | `ERR_TRUNCATED_MESSAGE` |
| `NEG-PUBKEY-HIGHBIT` | Ratchet key with `pk[31] & 0x80` set | `ERR_INVALID_PUBLIC_KEY` |
| `NEG-PUBKEY-REFLECT-01` | Type `0x01`, header ratchet key equal to our own `DHs` public (§10.1 check 8) | `ERR_INVALID_PUBLIC_KEY` |
| `NEG-PUBKEY-REFLECT-02-EKA` | Type `0x02` with `DHs_pub == EK_A` (§10.2 check 11) | `ERR_INVALID_PUBLIC_KEY` |
| `NEG-PUBKEY-REFLECT-02-SPK` | Type `0x02`, **new session**, `DHs_pub` equal to the `SPK_B` public for the referenced `spk_id` — a value any client can fetch from the bundle (§10.7 step 6) | `ERR_INVALID_PUBLIC_KEY` |
| `NEG-PUBKEY-REFLECT-02-DHS` | Type `0x02` to an **existing** session with `DHs_pub == s.DHs.pub` (§11.2) | `ERR_INVALID_PUBLIC_KEY` |
| `NEG-SMALLORDER` | A small-order ratchet public key | `ERR_SMALL_ORDER_KEY` |
| `NEG-COUNTER` | `N = 0x80000000` | `ERR_COUNTER_OVERFLOW` |
| `NEG-SKIP-LIMIT` | `N = 1001` beyond `Nr` | `ERR_TOO_MANY_SKIPPED` |
| `NEG-REPLAY` | `N < Nr` with no stored skipped key | `ERR_REPLAY` |
| `NEG-NO-SESSION` | Type `0x01` submitted with no session handle, and again with a handle that does not resolve (§11.5 rule 1) | `ERR_NO_SESSION` |
| `NEG-DEMUX-WRONG-SESSION` | Receiver B holds **two live sessions with two different peers** — `S1` with `P1`, `S2` with `P2`, distinct identity pairs, both established through §10.7 against the same `spk_id` with distinct `opk_id`s. Two live sessions is §11.1.1-conformant because the bound is per peer, and the vector says so explicitly, because a port that read it as a global cap cannot build the fixture. The stimulus is `M`, the next legitimate type `0x01` message of `P1`'s current sending chain — so it **would** decrypt under `S1` — submitted with `entry_point: "decrypt_with_handle"` and the handle for **`S2`**. The fixture MUST be constructed so that under `S2` every §10.1 check and every §7.9 phase-3 step succeeds up to and including the AEAD call, making the AEAD the unique failure point; otherwise a port may legitimately return `ERR_TOO_MANY_SKIPPED` or `ERR_SMALL_ORDER_KEY` and the vector arbitrates nothing. Asserts the exact code, that no plaintext is produced, and that the state blobs of **both** `S1` and `S2` are byte-identical to their pre-call values (§7.7, §12.1). A trial-decrypting port fails by returning `P1`'s plaintext, or — if it retries and suppresses the result — by an advanced `Nr` and rewritten `CKr` in `S1`'s blob | `ERR_AEAD_AUTH_FAILED` |
| `NEG-DEMUX-WRONG-PEER` | The same fixture and the same `M`, submitted through `entry_point: "decrypt_by_peer"` naming `P2`. Same blob assertions. This is the entry point whose signature invites a loop over the peer index, and it is the only place a "helpful" retry is natural to write | `ERR_AEAD_AUTH_FAILED` |
| `NEG-HANDSHAKE-TOMBSTONE` | Type `0x02` whose `handshake_id` matches a tombstone inside `HANDSHAKE_CACHE_MS`, with an injected `inputs.now_ms` (§10.7 step 4) | `ERR_REPLAY` |
| `NEG-COLLAPSE-LOSER-REPLAY` | Re-submit the identical type `0x02` message whose session **lost** the `SESSION-COLLAPSE` comparison, with `inputs.now_ms` inside `HANDSHAKE_CACHE_MS`. This is what stops §10.7 step 14d's delivery rule from becoming a plaintext-harvesting oracle, and it is the row that fails a port which delivers but forgets step 14c's tombstone. Not reachable from `NEG-HANDSHAKE-TOMBSTONE`, whose tombstone comes from an explicit eviction rather than from a collapse | `ERR_REPLAY` |
| `NEG-COLLAPSE-LOSER-HANDLE` | After `SESSION-COLLAPSE`, a valid type `0x01` message submitted against the handle for the session that lost the collapse (§11.6). The only way the "which handle comes back" half of §10.7 step 14d is observable at all, since a handle is opaque and has no byte representation; and the only row that catches a port treating a torn-down session as live | `ERR_NO_SESSION` |
| `NEG-PREKEY-PN` | Type `0x02` with `PN != 0` | `ERR_MALFORMED_HEADER` |
| `NEG-OPKFLAG-ID` | `opk_flag == 0x00` with a non-zero `opk_id` | `ERR_MALFORMED_HEADER` |
| `NEG-STATE-TRAILING` | State blob with one extra trailing byte | `ERR_TRAILING_BYTES` |
| `NEG-STATE-COUNT` | State blob with `skipped_count = 2001` | `ERR_STATE_CORRUPT` |
| `NEG-STATE-UNCLAMPED` | State blob whose `DHs_priv` is not in clamped form — one vector with `blob[243] & 0x07 != 0`, one with `blob[274] & 0xC0 != 0x40` (§12.2 rule 8) | `ERR_STATE_CORRUPT` |
| `NEG-BUNDLE-EMPTY` | Zero-length bundle | `ERR_BUNDLE_MALFORMED` |
| `NEG-BUNDLE-SHORT` | 250-byte bundle — the exact boundary, one byte below the fixed prefix, so `opk_count` at offset 249 is unreadable | `ERR_BUNDLE_MALFORMED` |
| `NEG-BUNDLE-MAGIC` | 251-byte bundle whose first four bytes are not `NTB4` | `ERR_BUNDLE_MALFORMED` |
| `NEG-BUNDLE-VERSION` | Well-formed 251-byte bundle with `bundle[4] == 0x03` | `ERR_UNSUPPORTED_VERSION` |
| `NEG-BUNDLE-OPKCOUNT` | Bundle with `opk_count = 1001`, length consistent with it | `ERR_BUNDLE_MALFORMED` |
| `NEG-BUNDLE-LEN` | Bundle whose length ≠ `251 + 36 * opk_count`. **Both directions are required**: one vector one byte too long, one vector one byte too short with `opk_count >= 1` | `ERR_BUNDLE_MALFORMED` |

The first six rows are the highest-value tests in the suite: `NEG-DH2/3/4-ALTERED` and
`NEG-RK-ALTERED` fail immediately against the v3 implementation, `NEG-SK-TAMPER` is the only test
that would have caught defect 2, and `NEG-ATOMIC` is the only one that catches the
desynchronisation DoS.

Four rows deserve the same billing because no other vector reaches what they test:
`NEG-SPK-SURVIVES-RATCHET` is the only vector that distinguishes a port which copies the signed
prekey private from one which aliases it; `NEG-BUNDLE-EMPTY` and `NEG-BUNDLE-SHORT` are the only
inputs that exercise the bundle parser's length floor, and the over-long direction that a test author
writes naturally exercises the safe side; `NEG-IKB-RETRANS` is the only vector that arbitrates a
genuine contradiction between two normative sections rather than checking a single rule; and
`NEG-DEMUX-WRONG-SESSION` with `DEMUX-NO-TRIAL` is the only pair that makes a forbidden *behaviour*
rather than a forbidden *value* observable — the only pair in which a sibling session exists that a
violating implementation would succeed against. `NEG-SPK-SURVIVES-RATCHET` is no longer the suite's
only multi-session vector: `SESSION-COLLAPSE`, `NEG-DEMUX-WRONG-SESSION`, `NEG-DEMUX-WRONG-PEER` and
`DEMUX-NO-TRIAL` all require more than one session, and three of them require more than one peer.

**No vector covers a null argument, deliberately.** §13.4 declares a null passed for a non-null
parameter a caller contract violation with a mandatory fail-fast, which is by construction not
observable as an error code and not expressible in this envelope — and is uncompilable in Swift, so
any such row would be a permanent skip in at least two of four ports, which §15.6 step 5 forbids. Its
absence from this table is a decision, not an omission; §13.4 clause 6 records why, and
`NEG-BUNDLE-EMPTY`, `NEG-TRUNCATED` and §10.4's legal empty plaintext are what pin the adjacent
content cases so the two are never conflated.

Note that `NEG-BUNDLE-VERSION` is the one bundle-structure vector that does **not** expect
`ERR_BUNDLE_MALFORMED`. Version is a distinguishable condition with its own code, and §10.3 step 3
assigns it deliberately; every other bundle structural failure, in either length direction, is
`ERR_BUNDLE_MALFORMED` and never `ERR_TRAILING_BYTES` (§10.5, code 7105).

### 15.5 JSON schema

Every vector file shares this envelope.

```json
{
  "$schema": "https://nuntius.dev/schema/vectors-v1.json",
  "spec_version": "4",
  "file": "x3dh",
  "generated_by": "nuntius-objc 0.1.0",
  "generated_at": "2026-07-19T00:00:00Z",
  "notes": "Free-form. Not normative.",
  "vectors": [ /* Vector objects */ ]
}
```

A **Vector** object:

```json
{
  "id": "X3DH-OPK",
  "kind": "x3dh",
  "description": "Full X3DH handshake with a one-time prekey.",
  "expect": "ok",
  "inputs":        { "…": "…" },
  "intermediates": { "…": "…" },
  "outputs":       { "…": "…" }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique across all files. Stable forever; never renumbered. |
| `kind` | enum | yes | `primitive`, `x3dh`, `ratchet`, `wire`, `state` |
| `description` | string | yes | Human-readable |
| `expect` | enum | yes | `ok` or `error` |
| `error` | string | when `expect == "error"` | The exact error name from §10.5, e.g. `ERR_BAD_SIGNATURE` |
| `inputs` | object | yes | Everything needed to reproduce, including all private keys |
| `intermediates` | object | no | Values a runner MUST check if it can expose them (see below) |
| `outputs` | object | when `expect == "ok"` | Final values a runner MUST check |

**Reserved `inputs` keys.** These are part of the envelope, not per-vector free-form, and rule 3
makes any *other* unrecognised key an error.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `entry_point` | enum | for every vector whose evaluation calls one | Which API was invoked: `decrypt_prekey`, `decrypt_with_handle`, `decrypt_by_peer`, `encrypt`, `parse_bundle`, `parse_state`, `message_type`. Without it §10.0 row 5 is unassertable and `NEG-ENTRYPOINT-*` cannot state what they did. |
| `sessions` | object | for multi-session vectors | A map of fixture names (`S1`, `S2`, …) to `{ handshake_id, peer_identity, state_blob }`. Session fixtures are supplied as literal §12.1 blobs, never as "replay these handshakes", for the same reproducibility reason `state.json` gives. |
| `selected_session` | string | when `sessions` is present and an entry point takes a handle | Which fixture the handle names. |

**Within `negative.json`, `inputs.entry_point` is authoritative for selecting the API under test,
and `kind` is a classification.** A runner MUST choose which parser or entry point to invoke from
`entry_point`, and MUST NOT infer it from `kind`. The two answer different questions — `kind` says
which family of construction a vector belongs to, `entry_point` says which call was made against it
— so they are not redundant and a runner that treats them as synonyms will eventually hand a §5.4
prekey bundle to its §12.1 state-blob parser. Where the two appear to disagree, `entry_point`
governs, and the vector is not malformed for it.

**Reserved `outputs` keys.** `sessions.<name>.state_blob_after`, a §12.1 blob a runner compares
byte-for-byte against `inputs.sessions.<name>.state_blob`. This is the only expressible form of the
"no state mutated" assertion that §7.7, `NEG-ATOMIC`, `NEG-SKIP-RETAIN`, `NEG-DEMUX-WRONG-SESSION` and
`NEG-DEMUX-WRONG-PEER` all rest on, and §12.1 is byte-normative precisely so it is possible. It is
REQUIRED on any vector whose description asserts that a session did not change — including on an
`expect: "error"` vector, which is the one place `outputs` is otherwise absent.

**JSON booleans are permitted in `outputs`** for **any boolean assertion flag** — not only
`established_new_session` and the other flags §11.6 defines, but equally the verification,
rejection and absence flags a vector needs in order to state its assertion at all: a signature
verified against a published key (`verified_N`, `IKB_verified`, `SPK_SIG_verified`), a malformed
encoding refused at a type boundary (`u_2_high_bit_rejected`), a torn-down session's identifier
gone from the store (`torn_down_handshake_id_absent`, `survivor_torn_down`). They are not
uint64-typed and rule 7 does not apply to them.

The same permission extends to **`intermediates`**, on the same terms — `incoming_wins`,
`receiver_is_B` and `tombstone_present` are boolean assertion flags that happen to describe an
intermediate state rather than a final one. Granting this for `outputs` alone would invite the
reading that `intermediates` excludes booleans by contrast, which nothing in this document intends:
the difference between the two objects is rule 1 versus rule 2 — whether checking is unconditional
or conditional on the implementation being able to expose the value — and never the JSON type.

**Normative runner rules.**

1. A runner MUST check every key present in `outputs`.
2. A runner MUST check every key in `intermediates` **that its implementation can expose**, and MUST
   report which it skipped. `intermediates` is where interop actually breaks — `TRANSCRIPT`, `TH`,
   `IKM`, and `AD` are the fields that localise a bug to a single construction instead of leaving
   "the ciphertext differs".
3. A runner MUST NOT skip a vector because a field is unrecognised; unknown keys within `inputs` are
   an error, not a forward-compatibility affordance.
4. All hex strings MUST have even length and lowercase digits.
5. Where a vector requires randomness (nonces, ephemeral keys), the value is supplied in `inputs`
   and the implementation MUST accept an injected value **in tests only**. A production API MUST NOT
   expose nonce or key injection.
6. Where a vector's evaluation reads a clock, the value is supplied in `inputs` as `now_s` (Unix
   seconds UTC) and/or `now_ms` (Unix milliseconds UTC), both as decimal strings per §15.2, and the
   implementation MUST accept an injected value **in tests only**. A production API MUST NOT expose
   clock injection. **Every clock read in this document routes through this single injectable time
   source** — §5.3 rules 5–6, §7.6's `now_ms()`, the `SKIPPED_TTL_MS` expiry of §7.6 and §12.2
   rule 9, the `OPK_MAX_AGE_S` expiry of §5.3, and the `HANDSHAKE_CACHE_MS` tombstone window of
   §10.7 step 4 / §11.4. A vector that reads a clock and supplies no `now_*` is **malformed**, and a
   runner MUST report it as a suite error rather than passing or skipping it.
7. A runner MUST reject any uint64-typed field (§15.2) that is not a JSON string.
8. **Ed25519 signatures are verify-side only.** A signature always appears in `inputs`, never in
   `outputs` or `intermediates`. A runner MUST verify it against the corresponding public key and
   message, and MUST NOT sign the message and compare its own bytes against the vector — Ed25519
   signature generation is not byte-reproducible across platforms (§3.4), so such a comparison
   fails on a conformant implementation. A runner SHOULD additionally produce its own signature and
   verify that, which exercises the signing path without depending on its output being canonical.
   This rule is the reason no `outputs` field anywhere in §15.3 holds a signature.

Worked example, abbreviated:

```json
{
  "id": "X3DH-OPK",
  "kind": "x3dh",
  "description": "Full X3DH handshake with a one-time prekey; 160-byte IKM.",
  "expect": "ok",
  "inputs": {
    "role": "initiator",
    "IK_A_s_priv": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "IK_A_s_pub":  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "IK_A_d_priv": "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
    "IK_A_d_pub":  "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    "EK_A_priv":   "4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d",
    "EK_A_pub":    "be85e12f6f56bf1e0a5a9b9d8c4e0a4a1f2b3c4d5e6f708192a3b4c5d6e7f809",
    "IK_B_s_pub":  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "IK_B_d_pub":  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "SPK_B_pub":   "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "spk_id": 7,
    "opk_flag": 1,
    "opk_id": 42,
    "OPK_B_pub":   "0e5e1b1e1a1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536",
    "not_before":  "1767225600",
    "not_after":   "1774828800",
    "now_s":       "1767830400"
  },
  "intermediates": {
    "DH1": "…64 hex chars…",
    "DH2": "…", "DH3": "…", "DH4": "…",
    "TRANSCRIPT": "…518 hex chars (259 bytes)…",
    "TH":         "…64 hex chars…",
    "IKM":        "…320 hex chars (160 bytes)…",
    "IKM_len": 160,
    "X3DH_info":  "…94 hex chars (47 bytes)…"
  },
  "outputs": {
    "SK":         "…64 hex chars…",
    "SESSION_AD": "…282 hex chars (141 bytes)…"
  }
}
```

> The hex values above are **illustrative placeholders** — several are borrowed from RFC 8032 and
> RFC 7748 test data purely to show the shape and field widths, and the public/private pairs do not
> correspond. Three details of the example **are** normative in shape, and a generator MUST
> reproduce them: `IK_A_s_priv` is a 32-byte Ed25519 **seed** (§4.2), the X25519 private keys are in
> **clamped** form (`IK_A_d_priv` begins `a0` and ends `44`; `EK_A_priv` begins `48` and ends `4d`),
> and the three uint64 fields `not_before` / `not_after` / `now_s` are **decimal strings** (§15.2)
> whose values satisfy §5.3 rules 5 and 6. The real vector files MUST be generated by the
> Objective-C reference implementation once it conforms to this document, and MUST then be frozen
> and treated as normative. No vector may be regenerated to make a failing port pass.

### 15.6 Generation and freezing

1. The Objective-C reference implementation is brought into conformance with this document.
2. It generates `spec/vectors/*.json`.
3. Those files are reviewed byte-by-byte against §18 and committed.
4. **Frozen.** A change to any frozen vector requires a spec version bump.
5. Each port runs the frozen vectors in CI. A port is conformant when all pass and none are skipped
   without an explicit, reviewed reason.

**No frozen vector may depend on the runner's wall clock.** The generator MUST emit an explicit
`now_s` and/or `now_ms` for every vector whose evaluation reads a clock, and MUST NOT emit a
clock-reading vector without one. CI MUST additionally run the whole suite with the system clock set
arbitrarily far in the future — ten years is sufficient — and the suite MUST pass unchanged. That
run is what proves the property: without it, a suite that is green on the day it is frozen goes red
at most 90 days later on the bundle validity window, and exactly 7 days later on the skipped-key
TTL, with §15.6 step 4 forbidding the obvious workaround of regenerating.

---

## 16. Per-platform trap catalogue

These are the concrete bugs the ports will hit. Each is a realistic silent interop break. Each port's
`CLAUDE.md` SHOULD name these explicitly.

### 16.1 All platforms

- **`KDF_RK` argument order.** libsodium takes salt first; BouncyCastle's `HKDFParameters(ikm, salt,
  info)` takes IKM first. Swapping yields a working, incompatible implementation. Covered by
  `KDF-RK-1`.
- **`SESSION_AD` role ordering.** Fixed by role at handshake time, persisted, never recomputed as
  `(self, peer)`. Covered by `RATCHET-BIDI`.
- **Big-endian integers.** Write with explicit shifts and masks. Never `memcpy` a native integer.
- **Hand-rolled HKDF-Expand.** The 64-byte `KDF_RK` output spans two HMAC blocks. Covered by
  `HKDF-EXPAND-64`.

### 16.2 Objective-C

- `*(NSInteger*)data.bytes` is banned; lint for it.
- `NSMutableData dataWithLength:` zero-fills — never combine it with an unchecked fill (§13.1).
- `subdataWithRange:` **raises** on an out-of-range `NSRange` (crash, not leak) — the length
  precondition must still be explicit.
- Use `crypto_sign_detached`, never the multi-part API (§3.4).
- **`crypto_sign_detached` reads a 64-byte secret key, and `Ed25519Private` is the 32-byte seed.**
  Passing the seed straight through — the natural transcription of a vector file's
  `IK_A_s_priv` — is an out-of-bounds read of 32 bytes, not merely a wrong-key bug: libsodium takes
  `sk[32..64)` as the public key `A` and hashes whatever adjacent memory happens to be there into
  the RFC 8032 challenge. Always `crypto_sign_seed_keypair(pk, sk, seed)` first, then zeroize `sk`
  (§4.2, §13.3). The resulting failure is `ERR_BAD_SIGNATURE`, which §1.2 defines as an active MITM,
  so this bug arrives disguised as an attack.
- Use `crypto_aead_chacha20poly1305_ietf_*` — the non-IETF variant has an 8-byte nonce and is a
  silent incompatibility. Assert nonce length 12.
- **`NSParameterAssert` and `NSAssert` are compiled out under `NS_BLOCK_ASSERTIONS`**, which is the
  default in a Release build of a framework dependency. A precondition written with them does nothing
  in the configuration consumers ship. §13.4 clause 3's check MUST survive Release; §3.3 bans them as
  a sole guard.
- **Messaging `nil` does not raise.** `[nilData length]` is `0` and `[nilData bytes]` is `NULL`, so a
  nil `NSData` argument flows silently into any length-driven copy as a zero-length buffer. This is
  how §13.4 clause 2's banned coercion happens without anyone writing it — the two bullets together
  are the whole of the Objective-C exposure.

### 16.3 JVM (Java and Kotlin)

- **`byte[]` as a map key uses identity semantics.** A raw `byte[]` skipped-key map key silently
  never matches, which simultaneously leaks every skipped key and fails every lookup. Wrap it in a
  value type with content-based `equals`/`hashCode`, or use `ByteBuffer.wrap`. Kotlin's `ByteArray`
  has the same trap.
- **`XECPublicKeySpec` carries the u-coordinate as an unpadded big-endian `BigInteger`**, against a
  32-byte little-endian wire format. BouncyCastle's `X25519Agreement` / `X25519PublicKeyParameters`
  take raw 32-byte arrays and are the RECOMMENDED path.
- **Signed-int comparison inverts the counter check.** `0x7FFFFFFF` as a signed `int` is fine, but
  `0x80000000` is negative — use `Integer.toUnsignedLong`, or `long` throughout, or Kotlin's `UInt`
  (kept out of the serialization path).
- `Cipher.getInstance("ChaCha20-Poly1305")` throws `AEADBadTagException` on failure; catch it and
  map it to `ERR_AEAD_AUTH_FAILED`. Do not let it propagate to a handler that retries.
- Ed25519 needs JDK 15+; X25519 needs JDK 11+. Below that, and on Android below API 33, use
  BouncyCastle or Conscrypt. **Pin one provider** — providers differ on small-order and
  non-canonical Ed25519 point handling.
- `LinkedHashMap` gives FIFO eviction directly via `removeEldestEntry`.
- Kotlin `data class` `copy()` is **shallow** — copy the skipped-key map explicitly for §7.7.
- **Java has no non-null in its type system**, so §13.4 clause 4 is the only thing holding the line
  here. A port declaring `byte[] plaintext` and defensively coercing null to `new byte[0]` looks more
  careful than one that throws and is the clause-2 failing-open bug. Use `Objects.requireNonNull` at
  every entry point and let the `NullPointerException` propagate; do not catch it into an error code.
  Kotlin's non-null types cover the Kotlin-to-Kotlin case only — the Java-interop boundary still needs
  the explicit check, because the compiler-inserted intrinsic is what a Java caller bypasses.
- **A single `parse(bytes) -> SealedClass` that dispatches is the idiomatic shape and is banned by
  §10.0.** It has no representation for a type mismatch and therefore auto-routes. Keep two entry
  points and a non-decrypting router (§11.5 rule 5).

### 16.4 Swift

- **`ChaChaPoly.SealedBox.combined` is `nonce ‖ ct ‖ tag`.** Our wire format carries the nonce in the
  header, separately. On seal use `box.ciphertext + box.tag`; on open reconstruct via
  `ChaChaPoly.SealedBox(nonce:ciphertext:tag:)`, **not** the `combined:` initializer. This is the
  single most likely Swift interop bug.
- **`Data` slices do not rebase indices to zero.** `buf[56...]` has `startIndex == 56`, so
  `slice[0]` traps. Rebase with `Data(buf[56...])` or index relative to `startIndex` consistently.
- **Unaligned loads trap.** Use `loadUnaligned(fromByteOffset:as:)` then `UInt32(bigEndian:)`, or
  shift manually. Never `load(fromByteOffset:as:)` on `Data`.
- `SecRandomCopyBytes` returns an `OSStatus` that Swift does **not** warn about discarding.
- `isValidSignature(_:for:)` returns `Bool` and never throws — a discarded `Bool` is a silent
  verification bypass.
- CryptoKit's `SharedSecret` must be extracted via `withUnsafeBytes` to get the raw 32 bytes, since
  we feed the raw output to our own HKDF rather than using `hkdfDerivedSymmetricKey`.
- **Swift is the only port in which a §13.4 violation is unrepresentable. Preserve that.** Do not add
  `Data?`-taking overloads, do not import an Objective-C non-null parameter as an implicitly-unwrapped
  optional to accommodate one, and do not add optional parameters "for symmetry" with the other ports.
  The one parameter that MUST be optional is the type `0x01` session handle (§13.4 clause 5) — that
  absence is a specified protocol condition with its own code, not a contract violation.
- **`enum IncomingMessage { case normal, prekey }` produced by one parsing function is the idiomatic
  Swift shape and is banned by §10.0**: it has no case for a type mismatch, so it auto-routes, and
  auto-routing a type `0x01` through the prekey entry point is a §11.5 rule 1 violation. Two entry
  points, plus a router that returns the type and nothing else.
- **Deployment target.** `ChaChaPoly`, `HKDF<SHA256>`, and `Curve25519.Signing` require
  iOS 13 / macOS 10.15. The current CI configuration pins iOS 10.3.1, and the podspec targets an
  older floor. The Swift port MUST either raise its deployment target to iOS 13+ or use swift-sodium
  throughout. This must be decided before the Swift port begins.

---

## 17. Open risks and deliberate non-goals

### 17.1 JVM zeroization is best-effort

`Arrays.fill` is not guaranteed against JIT dead-store elimination, and a relocating GC may have
already copied a `byte[]` before the wipe runs, leaving an unreachable copy. There is no JVM
equivalent of `sodium_malloc`'s guard pages.

The Java and Kotlin ports are therefore **strictly weaker than the Objective-C and Swift ports on
defect 8**, and MUST say so in their READMEs rather than paper over it. Compensate by keeping key
lifetimes short, holding key material only in `byte[]` (never `String`, never boxed types, never a
collection that copies), and preferring `javax.crypto.SecretKey` implementations supporting
`destroy()` for anything long-lived.

### 17.2 State rollback is mitigated, not solved

§8.3's random nonce makes rollback survivable rather than catastrophic, and §12.5 adds a tripwire.
But the tripwire depends on backup-excluded storage that the library cannot verify, and a
sufficiently privileged local adversary can roll back both the state and the tripwire. Multi-device
session sync is **not supported** by this specification; an application that forks a session across
devices is outside the model.

### 17.3 Replay of a no-OPK initial message

When `opk_flag == 0x00`, nothing is consumed, so a captured type `0x02` message can be replayed to
establish a new session and re-deliver its plaintext once the original session record has aged out
of the handshake cache (§11.4). This is X3DH's documented limitation in the no-OPK case, not a
defect introduced here. The 7-day handshake cache bounds the window, and §10.7 step 4 now enforces
the tombstone rather than leaving it to the implementer to infer.

**One consequence of §11.1.1 belongs here.** Because a newly established session displaces an
existing one with the same peer, a successful post-tombstone replay of this kind does not merely
re-deliver a plaintext — it may also tear down the live session with that peer, costing the messages
in flight on it. The window is the same 7 days, the precondition is the same (an OPK-less bundle
plus a captured handshake), and the same mitigation closes both: ensure the prekey server never
serves an OPK-less bundle. The alternative — allowing two live sessions per peer — was rejected in
§19.2 for reasons that outweigh this, since it would make every type `0x01` message
unroutable rather than making one replay more costly.

### 17.4 No header encryption

Ratchet public keys, `N`, and `PN` travel in the clear, so an observer can count messages and detect
ratchet steps. The published Double Ratchet specification describes header encryption as an optional
variant; v4 does not implement it. This is a conscious scope decision, but the v4 format reserves no
space to add header encryption without a version bump.

### 17.5 No post-quantum component

X25519-only agreement is harvest-now-decrypt-later vulnerable. Adding a PQ KEM (ML-KEM-768 alongside
X25519, as PQXDH does) would change the X3DH IKM and the bundle format. Deferred; the version byte
is the intended lever.

### 17.6 Skipped-key DoS

`MAX_SKIP_PER_MESSAGE = 1000` means a single crafted header can force up to 1000 HMAC-SHA256
operations before rejection. The bound is deliberately generous for real out-of-order delivery. If
the transport is unauthenticated and unrated-limited, it is also cheap to abuse; consider lowering
to 200 once real delivery statistics exist. Note also that a message rejected at the AEAD stage
after a full ratchet plus 1000 derivations is a cheaper CPU amplification than the raw numbers
suggest — the work is discarded by §7.7's rollback.

This bound is **per received message, not per decryption attempt**, and it holds only because §11.5
rule 3 forbids trying a type `0x01` message against more than one session. A port that trial-decrypts
across candidate sessions multiplies this figure by the candidate count — §7.9 phase 3c runs
`SkipMessageKeys` before the AEAD check, so 50 sessions — which under §11.1.1's *per-peer* bound means
50 correspondents, an unremarkable number — would mean 50,000 derivations per injected packet. That is
why rule 3 is a MUST rather than a recommendation, and `NEG-DEMUX-WRONG-SESSION` /
`NEG-DEMUX-WRONG-PEER` (§15.4) are what enforce it: this bound and the vectors that hold it are the
same set of sessions, viewed from two directions.

The skipped-key store is specified as **per-session**. Any port that shares one store across
sessions MUST partition the FIFO per session, or a peer that skips aggressively can evict a
different correspondent's pending keys.

### 17.7 The transcript-hash binding has not been externally reviewed

The claim that folding `TH` into the X3DH `info` is strictly stronger than v3's
`BLAKE2b(q ‖ pk ‖ pk)` ECDH wrapper is informal. The construction closely resembles standard
practice (X3DH's own `AD` parameter, Noise's handshake hash), but the exact composition — `TH` in
`info` rather than in `IKM` or in the AEAD associated data — SHOULD be reviewed by someone who did
not write this document before any of the four implementations ships.

### 17.8 Ed25519 verifier strictness differs across platforms

libsodium, SunEC/SunJCE, BouncyCastle, and CryptoKit / swift-crypto differ on cofactored versus
cofactorless verification and on the canonical-`S` check — the documented "many EdDSAs" hazard. A
mauled signature can be accepted by one implementation and rejected by another. All four backends
are in scope here: CryptoKit (CoreCrypto-backed) and swift-crypto (BoringSSL-backed) are two further
distinct verifiers, and §3.4 and §4.4 record that assuming anything about the Swift backend without
measuring it has already been wrong twice in this document. This specification reduces the blast
radius by keeping signature bytes **out** of the transcript (§6.2), so a divergence causes a clean
`ERR_BAD_SIGNATURE` on one side rather than two peers computing different session keys.

Each port MUST pin its verifier. On the JVM that means pinning a JCE provider explicitly rather than
taking whatever the platform resolves. On Swift the backend is **not pluggable** — there is no
provider to select — so the Swift port discharges this by pinning its platform floor (§16.4) and
recording which of CryptoKit or swift-crypto it builds against, not by choosing a provider. A port
SHOULD extend the suite with edge-case signature vectors once its verifier is pinned; note that
`primitives.json` is frozen (§15.6 step 4), so adding any is a spec version bump across all four
repositories and cannot be done by one port alone.

### 17.9 No v3 → v4 migration

The identity key type changes, so every user must re-register and every session must be torn down.
The version byte lets a receiver detect and reject v3 traffic cleanly, but there is no in-band
upgrade. This is unavoidable given §4.1 and should be confirmed as acceptable before implementation
begins.

---

### 17.10 Forward secrecy is bounded by prekey-store hygiene, not by the ratchet

The §1.2 forward-secrecy rows are worth stating precisely, because the imprecise version invites a
serious overread.

- **Identity private key alone, compromised retroactively.** DH3 = `X25519(SPK_B_priv, EK_A)` and
  DH4 = `X25519(OPK_B_priv, EK_A)` both remain out of reach, because `EK_A_priv` is zeroized the
  moment `SK` is computed (§6.3) and neither `SPK_B_priv` nor `OPK_B_priv` is an identity key. Two
  independent terms protect `SK`.
- **Identity *and* signed prekey private keys, compromised together.** DH1, DH2 and DH3 all fall.
  DH4 is the only remaining term — so forward secrecy survives **only** for handshakes that used a
  one-time prekey, and only if that OPK private was actually erased.

That second row is the one that matters operationally, because a single unsealed prekey store yields
both keys at once. It is why §5.6 requires the store to be sealed and backup-excluded, why §6.6
step 4 requires the OPK private to be zeroized in place rather than merely unlinked, and why §5.3
bounds an unconsumed OPK's lifetime with `OPK_MAX_AGE_S`. Before this revision none of the three was
required, and the threat-model claim rested on erasure the document never mandated: an adversary
could image a device at `t0`, go passive, record A's handshake at `t1 > t0`, recover `SK`, and derive
A's entire first sending chain via `KDF_RK(SK, X25519(DHs_A, SPK_B))` — with healing beginning only
at B's first reply.

None of this is enforceable by a test vector; it is memory and storage hygiene, and it is
enumerated in §13.3 for that reason. The residual risk after those three requirements is an
`opk_flag == 0x00` handshake, which has no DH4 at all and for which this row offers nothing. That is
X3DH's shape, not a defect introduced here, and it is the same reason §17.3 recommends never serving
an OPK-less bundle.

### 17.11 Caller contract violations are outside the taxonomy and outside the suite

§13.4 puts a null passed for a non-null parameter outside §10.5 entirely and outside §15's vectors,
for reasons clause 6 records. The residual risk is a host that passes null in a Release build against
a port whose precondition was written with an elidable assert — the failure then is not a loud abort
but §13.4 clause 2's silent coercion, and the resulting `SK` derived from an empty `IKM` is
well-formed, agreed by both parties, and cryptographically void. That is §13.1's failing-open pattern
reached through the argument list, and no vector in this suite can see it.

The mitigation is the §3.3 lint plus per-port unit tests, which for Objective-C means a test compiled
**without** `NS_BLOCK_ASSERTIONS` and for the JVM an expected-`NullPointerException` test. Those are
language-local by necessity and are not interop assertions, which is exactly why this is disclosed
here rather than claimed as covered.

## 18. Constant reference

Every ASCII literal, with its exact byte length and hex encoding. **No NUL terminators. No length
prefixes.**

| Literal | Len | Hex | Used in |
|---|---|---|---|
| `nuntius:IKBIND:v4` | 17 | `6e756e746975733a494b42494e443a7634` | §5.1 |
| `nuntius:SPK:v4` | 14 | `6e756e746975733a53504b3a7634` | §5.2 |
| `nuntius:X3DH:transcript:v4` | 26 | `6e756e746975733a583344483a7472616e7363726970743a7634` | §6.2 |
| `nuntius:X3DH:v4` | 15 | `6e756e746975733a583344483a7634` | §6.3 |
| `nuntius:RK:v4` | 13 | `6e756e746975733a524b3a7634` | §7.2 |
| `nuntius:MK:v4` | 13 | `6e756e746975733a4d4b3a7634` | §8.1 |
| `nuntius:AD:v4` | 13 | `6e756e746975733a41443a7634` | §6.5 |
| `nuntius:FP:v4` | 13 | `6e756e746975733a46503a7634` | §5.5 |
| `NTB4` | 4 | `4e544234` | §5.4 |
| `NTS4` | 4 | `4e545334` | §12.1 |

| Byte constant | Value |
|---|---|
| `F32` | 32 × `0xFF` |
| `Z32` | 32 × `0x00` |
| version | `0x04` |
| type: normal | `0x01` |
| type: prekey | `0x02` |
| flags | `0x0000` |
| `KDF_CK` message-key input | `0x01` |
| `KDF_CK` chain-key input | `0x02` |
| state_format | `0x01` |
| role: initiator | `0x01` |
| role: responder | `0x02` |

**Derived lengths.** Every value below is the sum of its field table and MUST be asserted at
runtime.

| Structure | Length | Sum |
|---|---|---|
| `IKBIND_MSG` | 81 | `17+32+32` |
| `SPK_SIGN_MSG` | 130 | `14+32+32+4+32+8+8` |
| `TRANSCRIPT` | 259 | `26+32+32+32+32+32+32+4+1+4+32` |
| `TH` | 32 | SHA-256 output |
| X3DH `info` | 47 | `15+32` |
| `IKM` (no OPK) | 128 | `32+32*3` |
| `IKM` (OPK) | 160 | `32+32*4` |
| `SK` | 32 | |
| `SESSION_AD` | 141 | `13+32*4` |
| `FP` input | 77 | `13+32+32` |
| `KDF_RK` output | 64 | `32+32` |
| `KDF_MK` output | 32 | |
| Type `0x01` header | 56 | `1+1+2+32+4+4+12` |
| Type `0x01` AD | 197 | `141+56` |
| Type `0x01` minimum | 72 | `56+0+16` |
| Type `0x01` maximum | 16777288 | `56+2^24+16` |
| Type `0x02` header | 225 | `1+1+2+32+32+64+32+4+1+4+32+4+4+12` |
| Type `0x02` AD | 366 | `141+225` |
| Type `0x02` minimum | 241 | `225+0+16` |
| Type `0x02` maximum | 16777457 | `225+2^24+16` |
| Bundle fixed prefix | 251 | `4+1+32+32+64+4+32+8+8+64+2` |
| Bundle OPK entry | 36 | `4+32` |
| State fixed prefix | 472 | `4+1+1+141+64+32+32+32+1+32+1+32+1+32+4+4+4+8+1+41+4` |
| State skipped entry | 76 | `32+4+32+8` |
| State prologue block | 41 | `32+4+1+4` |
| Skipped-key map key | 36 | `32+4` |
| `handshake_id` | 64 | `32+32` |

| Numeric constant | Value |
|---|---|
| `MAX_PLAINTEXT` | 16777216 (2²⁴) |
| `MAX_SKIP_PER_MESSAGE` | 1000 |
| `MAX_SKIPPED_STORED` | 2000 |
| `SKIPPED_TTL_MS` | 604800000 (7 days) |
| `HANDSHAKE_CACHE_MS` | 604800000 (7 days) |
| `MAX_COUNTER` | `0x7FFFFFFF` |
| `MAX_SPK_VALIDITY_SECONDS` | 7776000 (90 days) |
| `OPK_MAX_AGE_S` | 7776000 (90 days) — responder-local unconsumed-OPK lifetime, §5.3. Matches the SPK window cap deliberately; it is **not** a wire field |
| `MAX_BUNDLE_OPK_COUNT` | 1000 |
| `MIN_BUNDLE_LENGTH` | 251 — the §10.3 step 1 length floor, identical to the bundle fixed prefix |

---

## 19. Recorded decisions and rejected alternatives

This section exists so that decisions taken under adversarial review are not silently reopened by
the next reader. Each entry states what was decided, what was rejected, and why. A future revision
may overturn any of them — but it MUST do so by amending this section, not by rediscovering the
question.

### 19.1 Ownership of `SPK_B_priv` — copy, not a conditional zeroize

**Decided.** §7.5 gives the responder's ratchet a session-owned **copy** of the signed prekey
private half. §7.4 step 4 stays unconditional and identical for both roles. §13.3's ratchet-key row
is scoped to session-owned copies; the prekey store's original is governed by §5.3 alone.

**Rejected: make §7.4 step 4 conditional** ("do not zeroize a ratchet private key the ratchet did
not generate"). It works, but it puts a role-and-first-ratchet branch into the single hottest piece
of ratchet pseudocode in the document, gives the two roles different code paths where they currently
have one, and leaves the responder's first session key alive longer than necessary. Copy semantics
achieve the same protection while preserving the forward secrecy the step exists for — the copy
really is destroyed — and match the flat 32-byte `DHs_priv` field at §12.1 offset 243, which already
implies session ownership.

**The underlying defect was that neither rule was stated**, so aliasing and copying were both
literally conformant readings of the same text. Under aliasing, one well-formed handshake from any
party permanently destroys a bundle-published key that every other concurrent initiator depends on;
under copying, the same code is correct. An unstated ownership rule across four independent ports is
exactly the failure this document exists to prevent, so the fix is to state it, and to state it in
both places an implementer will look.

### 19.2 Session selection for type `0x01` — host-supplied handle, one session per peer

**Decided.** §11.5: the decrypt entry point takes an explicit handle; the sender identity comes from
the transport, never from the message; trial decryption is forbidden. §11.1.1: at most one live
session per peer identity pair, with a deterministic collapse on the greater `handshake_id`.

**Rejected: trial decryption across candidate sessions.** It is what several deployed protocols do
and it is the most forgiving option operationally. It was rejected because §7.9 phase 3c runs
`SkipMessageKeys` *before* the AEAD check, so each additional candidate costs up to
`MAX_SKIP_PER_MESSAGE` HMAC operations and as many snapshot insertions, multiplying §17.6's
disclosed bound by the candidate count; and because success-versus-failure across candidates is an
oracle for how many sessions a receiver holds with a peer.

**Rejected: route on the header's `DHs_pub`, matching against the stored `DHr_pub`.** This is the
tempting fix and it does not work. `DHs_pub` is a value the receiver has never seen on the first
message of every sending chain, which in an alternating conversation is every message — that case is
what §7.9 phase 3b exists to handle. A rule that matches only within a batch of consecutive messages
from one chain, and falls back to a guess otherwise, is worse than no rule: it appears to work in
the exact test a developer would write.

**Rejected: append `handshake_id` to `SESSION_AD`** (proposed as making cross-session misrouting a
guaranteed rather than probabilistic authentication failure). The premise is wrong. Misrouting to a
sibling session already fails Poly1305 with overwhelming probability, because the message key
differs; identical `SESSION_AD` between two sessions of the same identity pair creates no forgery
path. The change would cost `SESSION_AD` 141→205, the two AD lengths 197→261 and 366→430, the §12.1
`SESSION_AD` field width, and the state fixed prefix 472→536, in exchange for no security gain. If a
future revision adopts it for defence in depth, it MUST be batched into one coherent format revision
alongside every other §9/§12 change — never applied piecemeal.

**Rejected: add a session id to the type `0x01` header.** This is the only option that makes the
message genuinely self-routing, and it is the right answer if the format is ever reopened. It is a
wire change, and this revision deliberately makes none: the demultiplexing hole is closable in prose
alone, and mixing a format change into a prose-hardening pass is how offset tables come to disagree
with their own text.

**Rejected: "newest session wins" as the collapse rule.** Not a function of shared data. Each side
observes a different arrival order during a simultaneous initiation, so the two sides can select
different survivors and stay diverged permanently. The `handshake_id` comparison is computable by
both parties from values both already hold, which is the property the rule needs.

**Accepted cost.** Collapsing loses the messages in flight on the losing session, and a
post-tombstone replay of an OPK-less handshake can displace a live session (§17.3). Both are
bounded, both are disclosed, and neither is as bad as a mandatory receive-path step that four ports
implement four different ways.

### 19.3 `IKB_A` on the existing-session path — verify, do not carve out

**Decided.** §11.2 re-verifies `IKB_A` on every type `0x02` message, including retransmissions to an
established session, and returns `ERR_BAD_SIGNATURE` rather than letting the failure fall through to
the AEAD.

**Rejected: relax §5.5 instead**, carving out the established-session case on the grounds that AD
coverage of `IKB_A` already makes tampering unforgeable. That reading is sound on security grounds —
both paths fail closed, and neither can be made to *accept* a forged `IKB_A` — and it saves one
Ed25519 verification per retransmitted prekey message. It was rejected because it punches a
conditional hole in §5.5's blanket "every identity ingest" MUST for a saving that is invisible at
protocol rates, and because the returned code should describe what actually went wrong. Either
resolution was acceptable; what was not acceptable was leaving two normative sections in
contradiction with no vector to arbitrate.

### 19.4 Bundle over-length — `ERR_BUNDLE_MALFORMED`, not `ERR_TRAILING_BYTES`

**Decided.** §10.5 code 7105 is now state-blob-only. Every bundle structural failure, in either
length direction, is `ERR_BUNDLE_MALFORMED`.

**Rejected: route the bundle length case to 7105 instead** and amend §10.3 and `NEG-BUNDLE-LEN`.
7105-for-bundles was one outlier against four consistent statements (§5.3 rule 1, §10.3, §5.4, and
the vector table), and `ERR_BUNDLE_MALFORMED` is already the catch-all for every other bundle
structural failure. Splitting bundle parsing across two codes would fragment it for no diagnostic
gain.

### 19.5 X25519 private-key clamping — normalize on write, reject on read

**Decided.** §4.2 mandates the clamped form for stored scalars; §12.2 rule 8 **rejects** an
unclamped `DHs_priv` with `ERR_STATE_CORRUPT`.

**Rejected: silently re-clamp on load.** More forgiving, and functionally equivalent since clamping
is idempotent — but it would let a non-conformant writer's blobs circulate undetected, and it breaks
the exact-bytes property that makes §12.1 testable at all. **Rejected: store verbatim and never
compare.** That concedes the byte-normativity of the one structure §12 exists to make byte-normative.
Rejecting is safe to impose now only because `state_format 0x01` has not shipped; after it ships,
this decision cannot be revisited without a format bump.

Note the scope: clamping changes no cryptographic output whatsoever. RFC 7748 §5 clamps internally,
so `X25519(s, P) == X25519(clamp(s), P)` for every `s`. This is a state-portability and
conformance-testing decision, not a security one, and it is recorded here mainly so that nobody
"fixes" it later by removing the check.

### 19.6 Clock injection — one source, or the frozen suite has a shelf life

**Decided.** §15.5 runner rule 6 defines a single injectable time source; every clock read in the
document routes through it; §15.6 requires CI to run the suite with the system clock set far in the
future.

**Rejected: leave the clock implicit and pin only the timestamps.** Insufficient — pinning
`not_before` / `not_after` does not stop §5.3 rule 5 from comparing them against a real clock, and
rule 6 caps the validity window at 90 days, so no choice of literals survives. Pinning
`inserted_at_ms` does not stop §12.2 rule 9 from dropping every skipped entry exactly seven days
after the freeze. The suite is the sole interop mechanism and §15.6 step 4 forbids regenerating it,
so a clock-dependent vector is a scheduled, unfixable failure — and the two mechanisms above would
have fired at 90 days and 7 days respectively.

### 19.7 The plaintext on §10.7's losing collapse branch — deliver it

**Decided.** §10.7 step 14d delivers the plaintext on **every** path that reaches step 14, including
the path on which the session just established loses §11.1.1's comparison. The handle returned is
always the survivor. §11.6 fixes the result shape, and §11.4 tombstones the loser so that delivery is
once per handshake rather than once per arrival.

**Rejected: drop the plaintext on the losing branch.** It is unrepresentable in the return contract
all four ports share. §10.5 assigns no code to "your message authenticated and we discarded it" and
forbids returning a null result with a null error, so a dropping port must either invent a code that
describes a success — a taxonomy fork across four repositories — or violate a MUST. In Swift that
becomes throwing on a successful decrypt and in Java returning null from a method that never returns
null; four ports would each pick a different fudge. It also buys no atomicity, because step 14a has
already irreversibly consumed the one-time prekey, and §7.7's fail-closed guarantee is scoped to "if
any step fails" — the AEAD did not fail. And the loss is permanent, not deferred: §11.3 has the
initiator retransmitting an identical prologue and therefore an identical `handshake_id`, which step
4 now rejects as `ERR_REPLAY` forever. Worst of all it is attacker-reachable without any forgery: an
attacker who merely **delays** one packet during a legitimate concurrent initiation obtains a silent,
permanent message-suppression primitive, and the absence of a reply becomes an oracle telling the
sender that the receiver already holds a session with a greater `handshake_id`.

**Rejected: return the losing session's handle with the plaintext.** Every operation on it fails, and
a caller that filed it under its peer index would recreate the two-live-sessions state §11.1.1 exists
to forbid.

**Rejected: return success with no plaintext.** Same §10.5 violation as dropping, with a worse shape.

**Rejected: defer and redeliver on the retransmission.** Unreachable — step 4 makes every
retransmission `ERR_REPLAY`.

**Rejected: skip the collapse when the incoming session would lose, keeping both.** Destroys the
function property that §11.5 rule 4 depends on to forbid trial decryption. Not available.

**Rejected: merge the losing session's ratchet material into the survivor** ("adopt the newer keys").
This is the sort of thing a port writes as a convenience, so §10.7 step 14c forbids it explicitly: an
attacker replaying an old handshake could otherwise reset a live session's root key, destroying
post-compromise security and desynchronising the peer.

**The part that was not in the question, and that would actually have split four ports**, is step
14c's durability requirement and step 14a's finality. A crash between returning the plaintext and
committing the loser's teardown resurrects a session the collapse already killed, and the two sides
then diverge permanently on which one is live — the failure the deterministic comparison exists to
prevent, reintroduced through a persistence hole. A port that instead returns early on losing, having
skipped the OPK consumption and the tombstone, gives an attacker unlimited re-delivery of the same
plaintext by plain retransmission, each replay costing the receiver a full X3DH.

**§11.6's result shape is part of this decision, not a footnote.** A boolean meaning "a collapse
occurred" is true on both branches while the caller's obligation is opposite on each, so a port that
reports the disjunction and documents it as "discard your handle" instructs the caller to destroy its
live session in precisely the branch this decision is about. The observable must name the **torn-down
`handshake_id`**, not the fact of a collapse.

### 19.8 Entry-point type mismatch — demultiplex first, and a new code 7125

**Decided.** New §10.0 runs the global length floor, the global cap, the version check, the type-domain
check and the entry-point match, in that order, before either §10.1 or §10.2 — so no type-dependent
length floor is ever evaluated against a message whose type has not been read. A mismatch is
`ERR_WRONG_ENTRY_POINT` (7125), the next free number; nothing is renumbered. Entry points MUST NOT
forward, and §11.5 rule 5 makes the non-decrypting router required API so a conformant host cannot
reach 7125 at all.

**The diagnosis generalises past the case that raised it.** A length floor is a function of the type,
so evaluating it before the type is known is a category error, not merely a bad code — and the same
mis-ordering already falsified §10.6, which promised that a v3 message is rejected with
`ERR_UNSUPPORTED_VERSION` while in fact any v3 message shorter than the invoked gate's floor returned
`ERR_TRUNCATED_MESSAGE`. That is the stronger argument for demultiplexing first, and it survives
independently of the error-code question. `NEG-VERSION-SHORT` is its vector.

**Rejected: reuse 7101 with a broadened meaning.** Cheapest, and it changes no frozen expectation.
Rejected because §10.5's meaning column for 7101 is a predicate over the message alone — "byte 1 is
not `0x01` or `0x02`" — while this condition is a predicate over *(message, entry point)* and byte 1
genuinely *is* a valid type. Four teams reading that column independently would not converge on 7101
here, which is the test this document exists to pass. Broadening it into a disjunction would also
erase the distinction between "a peer sent bytes that are not a message type", whose remedy is to drop
the message, and "the host routed a genuine message to the wrong call", whose remedy is to fix the
host — two conditions an operator needs to tell apart, the second being remotely triggerable by a
transport that flips the inner type byte.

**Rejected: a new code but keep the type-dependent floor first.** Fixes one symptom of a mis-ordered
gate and leaves §10.6 false.

**Rejected: demultiplex before *any* length check.** Reading `msg[0..2)` on a zero- or one-byte input
is the out-of-bounds class §10.3 documents: Objective-C reads a `NULL` `bytes` pointer, Swift traps —
an uncatchable remote DoS — and the JVM throws past the taxonomy. The global 72-byte floor stays ahead
of the demultiplex; it is check 1 of both gates, so it can pre-empt nothing.

**Rejected: restructure the API so the mismatch is unrepresentable.** It cannot hold in all four
languages — Objective-C and Java cannot prevent calling the wrong method with the right bytes — and
where it *can* be approximated it is actively dangerous. A Swift port modelling this as one
`parse(_:) -> IncomingMessage` enum, or a Kotlin sealed class, has no case for the mismatch and
therefore auto-routes; auto-routing a type `0x01` into the self-routing prekey entry point is a §11.5
rule 1 violation, since that entry point takes no handle and the implementation must then either
fabricate one or trial-decrypt. That reopens §19.2. The anti-forwarding MUST in §10.0 exists because
the most idiomatic Swift and Kotlin shapes each walk into it.

**Rejected: merge the two receive entry points into one `decrypt(message, handle?)`.** It also makes
the mismatch unrepresentable, and it fails closed — but the split entry points are how §11.5 rule 1
is enforced *structurally* rather than by prose, and merging makes the handle optional at the type
level in all four languages, which is the hole rule 1 closes.

### 19.9 `NEG-DEMUX-WRONG-SESSION` — a two-peer fixture, or the rule is untestable

**Decided.** §15.4's row is restated around a fixture in which the receiver holds two live sessions
with two **different** peers, and the misrouted message is the next legitimate message of the *other*
session's sending chain — so it genuinely decrypts there. `NEG-DEMUX-WRONG-PEER` repeats it through
the by-peer entry point, and `DEMUX-NO-TRIAL` (§15.3) redelivers the same message under the correct
handle afterwards. §11.5 rule 3 gains the observable that makes the prohibition checkable, and rule 4
is amended to say the bound is one session per *peer*.

**The old wording was worse than weak; it was unsatisfiable.** §11.1.1 forbids a second session with
the same peer, so "a handle for a different session" in a single-peer setup names a session that
either does not exist or belongs to another peer, and the text never said which. A port building the
natural fixture — one peer, one session, a bogus handle — was actually testing `NEG-NO-SESSION`. The
two rows overlapped and neither covered rule 3. "Asserts that the implementation did not retry" is
not something a runner can evaluate; "asserts the call failed even though a live session existed under
which the message would have decrypted" is, and that is the whole content of the fix.

Three construction details carry the weight, and each is a place four ports would otherwise diverge.
`M` must be decryptable under the sibling — against a corrupted message a trial-decrypter fails every
candidate and passes. The AEAD must be the unique failure point under the *selected* session, or three
ports produce three different codes for the same bytes. And byte-exact `state_blob_after` on **both**
sessions is the only expressible form of "no state mutated": the selected session's blob catches a
non-atomic implementation, and the *other* session's blob catches the residual case of a port that
trial-decrypts and then suppresses the result, since a successful retry advances `Nr` and rewrites
`CKr`.

**Rejected: assert a derivation count, a `sessions_attempted` counter, or timing.** §11.5 rule 3's own
DoS rationale invites it, but none of the three is expressible in a frozen JSON vector or portable
across four runtimes, and a counter would require a production API to expose it.

**Rejected: assert a skipped-key-store count on the wrong session.** That measures §7.7's snapshot
discipline, not rule 3 — a §7.7-conformant trial-decrypter leaves the store untouched — so it would
replace one unfalsifiable assertion with another.

**Rejected: rename or renumber the vector.** §15.5 makes ids stable forever, and this one is already
referenced from §11.5's closing line.

### 19.10 A null argument — out of the taxonomy, with a mandatory fail-fast

**Decided.** §13.4. A null passed for a non-null parameter is a caller contract violation: no error
code, no vector, mandatory non-elidable fail-fast, and an explicit MUST NOT on substituting a default.
No port may widen a non-null parameter or add a nullable-accepting overload. The one exception is the
type `0x01` session handle, whose absence §10.1 check 6 already specifies as `ERR_NO_SESSION` — that
parameter MUST be nullable in every port.

**Rejected: assign it an error code.** A conformance vector's `inputs` are hex and decimal strings;
"argument absent" has no encoding, and a vector asserting an abort is not runnable. Swift cannot make
the call at all and Kotlin cannot without `!!` gymnastics, so the row would be a permanent skip in two
of four ports, which §15.6 step 5 forbids — we would be manufacturing the skip. A code that no vector
can exercise is a code that will not be honoured, and there is already one such entry in the taxonomy
(7115, documented as unreachable as specified) that this document does not need a second of.
Separately, a code invites `if (err == ERR_NULL_ARGUMENT) { retry }` — a recoverable-looking response
to a bug the caller has already demonstrated — and every other §10.5 code describes something a peer
or the network did, not something the host did in the same address space.

**Rejected: treat null as an empty value, uniformly.** This is the Objective-C default and therefore
the status quo, and it is the failing-open branch. §10.4 makes a zero-length plaintext *legal*, so the
coercion is indistinguishable downstream from a legitimate empty input; an empty `IKM` into
HKDF-Extract yields a real, agreed, valueless key, and against a fixed-width primitive an empty buffer
is the same out-of-bounds read §3.4 documents, surfacing disguised as `ERR_BAD_SIGNATURE`.

**Rejected: a two-tier rule** mapping a null message onto `ERR_TRUNCATED_MESSAGE` and a null bundle
onto `ERR_BUNDLE_MALFORMED` while trapping on everything else. It is tempting because those two
parameters can legitimately arrive from a failed I/O read, and a trap there converts a host bug into a
remotely-influenced abort. It was rejected because a *null* message and a *zero-length* message are
different things with different remedies — reporting the former as a truncation sends a developer
looking for a short read, which is the identical complaint §19.8 raises about the entry-point
mismatch — and because a per-parameter tier table is exactly the sort of rule four ports each partition
differently. The zero-length case, which is what a failed read actually produces in a
non-null-carrying language, is already specified and already has vectors.

**Rejected: leave it undefined.** The status quo produces four behaviours from four ports —
Objective-C proceeds with a zero-length buffer, the JVM throws, Kotlin throws a differently-shaped
exception, Swift never compiles the call — and the Objective-C default is the dangerous one.

---

*End of specification.*
