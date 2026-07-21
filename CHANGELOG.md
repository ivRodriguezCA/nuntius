# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-20

### ⚠ BREAKING — this release is not interoperable with any 0.0.x release

**Read this before upgrading. There is no migration path.**

- **The wire format is v4 (`0x04`). v3 (`0x03`) traffic is rejected outright.** A v4 receiver
  rejects any message whose first byte is not `0x04` with `ERR_UNSUPPORTED_VERSION` (7100). The
  check runs at the entry-point demultiplex, *before* any type-dependent length floor and *before*
  the type byte is read, so the rejection is unconditional on the message's length and on which
  entry point the host called (SPEC §10.0, §10.6).
- **There is no dual-stack mode and no in-band upgrade.** No downgrade negotiation, no v3
  compatibility shim, no "accept v3 on read". A v3 peer and a v4 peer cannot communicate at all
  (SPEC §10.6, §17.9).
- **Every existing identity must be re-registered.** The identity key *type* changed: an identity
  is now a pair of independently generated key pairs — Ed25519 `IK^s` for signing and X25519 `IK^d`
  for ECDH — replacing the single Ed25519 key pair that v3 converted to X25519 on demand. Old
  identity material cannot be carried forward.
- **Every existing session must be torn down.** Persisted v3 session state (`NSKeyedArchiver`
  blobs) is not readable by v4 and no converter exists.
- **Every published prekey bundle must be re-published** in the new `NTB4` format (SPEC §5.4).
- **v3's "simple" AEAD API (`aeEncryptSimpleData:` / `aeDecryptSimpleData:`) is deleted with no
  replacement.** There is no type `0x03` message (SPEC §9.3).

This break is not gratuitous. Fixing the two most severe defects below changes every derived key,
so wire compatibility was already lost the moment the protocol became correct. The version byte
exists so that a v4 receiver can detect and reject v3 traffic cleanly rather than fail obscurely.

### Added

- **SPEC.md** — a normative, byte-level protocol specification covering the wire format, parsing
  and validation order, the error taxonomy, state serialization, the zeroization schedule, the
  test-vector plan, and a per-platform trap catalogue. Where SPEC.md and code disagree, SPEC.md
  wins. It is the shared contract for the Objective-C reference implementation and the Java,
  Kotlin, and Swift ports.
- **Identity binding signature `IKB`** (SPEC §5.1, §5.5). Because identity is now a *pair* of keys,
  something must attest that a given `IK^s` and `IK^d` belong to the same identity. `IKB` is an
  Ed25519 signature over `"nuntius:IKBIND:v4" ‖ IK^s ‖ IK^d`, and it is verified on **every**
  identity ingest — fetched bundle, type `0x02` header, cached contact record, and after state
  restore — not only on first contact.
- **Public fingerprint / safety number** `FP = SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d)` (SPEC §5.5).
  Applications MUST key identity lookup, pinning, and any displayed identity on the pair or on
  this fingerprint.
- **X3DH transcript hash** `TH = SHA256(TRANSCRIPT)` over a fixed-length 259-byte transcript
  binding both identity keys of both parties, the initiator ephemeral, the signed prekey, and both
  key ids in one canonical order, folded into the X3DH HKDF `info` (SPEC §6.2). This replaces
  v3's per-ECDH `BLAKE2b(q ‖ sender_pk ‖ receiver_pk)` wrapper and binds strictly more material.
  The transcript deliberately contains **no** signature bytes, so it does not depend on two
  platforms producing byte-identical Ed25519 signatures.
- **Session associated data** `SESSION_AD` (141 bytes, SPEC §6.5), computed once at handshake time
  and prefixed to the AEAD associated data of every message, so every message is bound to both
  parties' full identities and to the fixed initiator/responder roles.
- **Byte-exact prekey bundle format** `NTB4` (SPEC §5.4), with signed-prekey validity windows
  (`not_before` / `not_after`, capped at 90 days) and an `opk_count` bounded at 1000.
- **Byte-exact state blob format** `NTS4` (SPEC §12), fixed-layout binary with an exact-length
  assertion, trailing-byte rejection, and mandatory sealing at rest under a device-bound keystore
  key. No language-native serializer is used, because no two runtimes agree byte-for-byte.
- **State rollback tripwire** (SPEC §12.5): a monotonic `send_counter` checked against a value
  recorded in backup-excluded storage, returning `ERR_STATE_ROLLBACK` (7124) on regression.
- **Bounded skipped-message-key store** (SPEC §7.6): `MAX_SKIP_PER_MESSAGE` 1000,
  `MAX_SKIPPED_STORED` 2000, FIFO eviction, 7-day TTL, zeroize on evict.
- **At most one live session per peer identity pair** (SPEC §11.1.1), which is what lets type
  `0x01` delivery forbid trial decryption across candidate sessions.
- **Structured error taxonomy**, codes 7100–7125 in domain `com.ivrodriguez.nuntius` (SPEC §10.5),
  with an explicit rule that these codes are for local diagnosability only and MUST NOT be
  revealed to, or timing-distinguishable by, a network peer. v3's codes 7001–7003 are retired.
- **Explicit zeroization schedule** for every secret, with non-elidable primitives (SPEC §13.3).
- **Nominal key types** (`IRKeyTypes`), so an Ed25519 signing key and an X25519 agreement key
  cannot be passed to each other's APIs (SPEC §4.3).
- **Public key validation** on ingest — length, high-bit, all-zero DH output, and reflected-own-key
  checks (SPEC §4.4, `ERR_INVALID_PUBLIC_KEY` / `ERR_SMALL_ORDER_KEY`).
- **`tools/lint_banned_apis.py`**, wired as a pre-Sources build phase, enforcing the banned-API
  list (SPEC §3.3) and the `IRSetError` failure convention. A banned call stops the build.
- **`tools/pbxproj_tool.py`** for project-file mutation, so `project.pbxproj` is never hand-edited
  and a source file can never be silently omitted from the Sources build phase.
- **A frozen, language-agnostic conformance corpus** — `spec/vectors/*.json`, 88 vectors across six
  files, covering every id SPEC §15.3 and §15.4 require: primitives, full X3DH handshakes, full
  conversations with out-of-order delivery and cross-chain skipped-key recovery, byte-exact
  encodings of every structure, state blob round-trips, and every rejection path. This is what
  verifies interoperability across the four implementations instead of asserting it in prose, and
  §15.6 step 4 makes a change to any frozen vector a spec version bump.
  - The RFC-anchored vectors are **transcribed from the RFC text**, not generated here. A corpus
    produced entirely by the implementation under test proves only self-consistency.
  - The suite rebuilds the corpus in memory on every run and compares byte-for-byte, so drift
    fails a test instead of quietly rewriting the contract.
  - Every clock read routes through one injectable source, and CI runs the whole suite with the
    clock ten years forward. Without that, a suite green on the day it is frozen goes red 7 days
    later on the skipped-key TTL and 90 days later on the prekey validity window.
  - Ed25519 signatures are asserted **verify-side only** (§15.5 rule 8): signature generation is
    not byte-reproducible across platforms, so requiring a port to reproduce signature bytes would
    fail a conformant implementation.
- **Mandatory fuzzing** of all four hand-written decoders — state blob, bundle, type `0x01`, type
  `0x02` (SPEC §12.4).
- **Test suite rebuilt** as one `*Spec.m` per layer, with negative cases named for the `NEG-*`
  vector ids in SPEC §15.4.

### Changed

- **KDF: `crypto_kdf_derive_from_key` → HKDF-SHA256 (RFC 5869)**, Extract/Expand, everywhere. See
  *Security* below — this is the root-cause fix for the worst defect in v3, and it is structural:
  HKDF-Extract's `(ikm, ikm_len)` signature makes the v3 truncation bug inexpressible.
- **Identity: one Ed25519 key pair converted on demand → two independent key pairs.** Ed25519
  `IK^s` signs and never does DH; X25519 `IK^d` does DH and never signs. Motivated by portability
  (`crypto_sign_ed25519_pk_to_curve25519` has no JDK equivalent, and CryptoKit deliberately makes
  `Curve25519.Signing` and `Curve25519.KeyAgreement` non-interconvertible), by cross-protocol
  hygiene, and by the fact that the conversion calls were themselves a bug source.
- **ECDH: `BLAKE2b(q ‖ sender_pk ‖ receiver_pk)` → raw RFC 7748 X25519 output.** BLAKE2b is absent
  from the JDK standard library and from CryptoKit. Public-key binding moved to the explicit
  transcript hash.
- **Symmetric encryption: AES-256-CBC + PKCS7 + hand-rolled encrypt-then-MAC with HMAC-SHA256 via
  CommonCrypto → ChaCha20-Poly1305 (RFC 8439, IETF construction).** One AEAD call replaces a
  cipher call, a padding mode, a separately derived HMAC key, a separately derived IV, and a
  hand-written MAC comparison. XChaCha20-Poly1305 and AES-256-GCM were both considered and
  rejected: the former is absent from CryptoKit and BouncyCastle's JCE provider, the latter is
  hardware-gated behind a runtime availability branch the other ports do not have.
- **Nonce/IV: derived 16-byte CBC IV → random 12-byte nonce carried on the wire** (SPEC §8.3). A
  deliberate reversal of a "derive the nonce" proposal, taken so that state rollback is survivable
  rather than catastrophic.
- **Message key expansion:** one HKDF call producing a single 32-byte encryption key, replacing
  v3's three derivations (AES key, HMAC key, IV) that re-used one label across three semantic
  roles and requested a 16-byte IV that silently hit the `crypto_kdf_BYTES_MIN` clamp.
- **Signing: `crypto_sign_init` / `_update` / `_final_create` → `crypto_sign_detached`.** v3 used
  the prehashed multi-part API, not pure Ed25519 (RFC 8032 §5.1). This was an undocumented
  interoperability break with the JDK and CryptoKit whose failure mode looks exactly like a MITM.
- **Ed25519 private keys are the raw 32-byte RFC 8032 seed** at every API boundary and in every
  serialized structure; the 64-byte libsodium `sk` is an internal expansion only.
- **X25519 private keys are normalized (clamped) at generation**, so that cryptographically
  identical state serializes to identical bytes across libsodium, BouncyCastle, and CryptoKit.
- **Message counters: 1 byte → `uint32` big-endian**, capped at `0x7FFFFFFF`, with
  `ERR_COUNTER_OVERFLOW` at exhaustion instead of wrapping.
- **Header layout: self-describing 1-byte length field → no length field anywhere.** Header length
  is a constant selected by the 1-byte type field (56 bytes for type `0x01`, 225 for type `0x02`).
- **Version, type, and flags bytes are now validated *and* covered by the AEAD associated data**, so
  tampering with them is an authentication failure rather than a silent no-op.
- **State serialization: `NSKeyedArchiver` / base64 strings in an `NSDictionary` → fixed-layout
  binary blob, sealed at rest.**
- **Session state is restored through a hand-written, length-checked, fuzzed decoder** rather than
  `unarchiveObjectWithData:`.
- **libsodium 1.0.13 → 1.0.22**, now vendored as `Clibsodium.xcframework` instead of the
  `libsodium/lib/libsodium.a` static library plus loose headers. This is what makes
  `crypto_kdf_hkdf_sha256_extract` / `_expand` available.
- **Deployment target: iOS 10.3 → iOS 13.0.**
- **Distribution: CocoaPods → Swift Package Manager.** `nuntius.podspec` is removed; the pod is
  not being updated for 1.0.0.
- **Failure convention** is uniform: return `nil`/`NO` plus an `NSError **` out-parameter assigned
  through `IRSetError`, checked by the banned-API lint.
- **Nullability** is annotated per parameter (`_Nullable` / `_Nonnull`), never with audited regions.
- **README** rewritten for the v4 API surface.

### Removed

- **`nuntius.podspec`** and CocoaPods support.
- **`aeEncryptSimpleData:` / `aeDecryptSimpleData:`** — the "simple" AEAD format, with no
  replacement. It was a second copy of the broken MAC comparison, outside the ratchet, with no
  structural guarantee of key single-use. There is no type `0x03`.
- **`consistentTimeEqual:hmachToCompare:`** — deleted, not fixed. With one AEAD call there is no
  MAC to compare.
- **PKCS7 padding**, the separate HMAC key, and the separately derived IV.
- **`crypto_sign_ed25519_pk_to_curve25519` / `_sk_to_curve25519`** — both call sites deleted with
  the key-type split rather than having their ignored return values fixed.
- **`crypto_kdf_derive_from_key`, `crypto_kdf_blake2b_*`, `crypto_kx_*`, the multi-part
  `crypto_sign_*` API, non-IETF `crypto_aead_chacha20poly1305_*`,
  `crypto_aead_xchacha20poly1305_ietf_*`, `crypto_aead_aes256gcm_*`, pointer-cast integer reads,
  `NSKeyedArchiver` / `NSKeyedUnarchiver` for key material or session state** — all on the banned
  list, enforced by lint (SPEC §3.3).
- **`IRAEADInfo`** — the type whose `infoWithRawData:` read 80 bytes from a possibly shorter
  `NSData`.
- **The commented-out `memset` scrubbing blocks** — deleted rather than re-enabled, and replaced
  by an explicit zeroization schedule.
- **Error codes 7001–7003.**

### Fixed

The thirteen confirmed v3 defects (SPEC §14) and the nine further defects found while writing the
specification (SPEC §14.1). The cryptographically fatal ones are itemized under *Security*; the
remainder:

- **One-time prekeys are actually consumed.** v3 always took `firstObject` from the OPK array and
  never removed it, so a "one-time" prekey was reused indefinitely. OPKs are now held in a map
  keyed by `opk_id`, an unknown id is rejected with no silent fallback to the 3-DH case, and the
  durable delete happens *before* the plaintext is released.
- **Signed prekeys are verified.** v3 never verified a peer's signed prekey signature and, worse,
  `initWithData:` **re-signed the peer's prekey with the local identity key**, manufacturing a
  signature that would then "verify". `IKB` and `SPK_SIG` are now both verified before any DH, in
  both directions; the re-signing is deleted.
- **Header counters no longer wrap at 256**, and `PN` is actually transmitted. v3 wrote `Ns` into
  *both* header counter fields, so the previous-chain length was never sent.
- **Decrypt is atomic and fails closed.** In v3 the skipped-key insert, the DH ratchet step, the
  chain advance, and the counter increment all committed *before* the MAC was checked, so a single
  unauthenticated message permanently desynchronized a live session. All state mutation is now
  staged and committed only after the AEAD tag verifies.
- **A skipped message key is no longer destroyed by a failed decryption.** v3 removed the key from
  the store before attempting decryption, so a message that failed to decrypt took the only copy
  of its key with it and was permanently lost.
- **The skipped-key store is bounded.** v3's `skippedMessagesKeys` grew without limit and was
  pruned only on successful use.
- **Key material is zeroized.** v3's scrubbing was commented out at every site.
- **No out-of-bounds reads.** See *Security* — the `*(NSInteger*)` reads are gone, and the
  construct is banned and linted.
- **The second `addSkippedMessages:` return value is no longer discarded**, so an over-limit skip
  on that path can no longer be ignored.
- **`IRCurve25519KeyPair isEqual:` asymmetry.** v3's comparison behaved differently depending on
  whether a private key happened to be populated, so the ratchet's header-key comparison depended
  on how a field was filled in rather than on key bytes. Replaced by nominal key types compared on
  public key bytes.
- **Null `NSError **` dereference** in both "simple" AEAD entry points, which crashed any caller
  passing `NULL` — which every test in the v3 repository did. Every failure path now sets the error
  out-parameter and none dereferences a null one.
- **A maximum message size exists** (`MAX_PLAINTEXT` = 2²⁴), and no range is computed by
  subtraction from an attacker-controlled length.
- **Empty plaintext is no longer conflated with encryption failure.** An empty plaintext is legal
  and produces a 72-byte type `0x01` message.
- **`sodium_init()`'s return value is checked** and a failure makes every subsequent call return
  `ERR_NOT_INITIALIZED`, rather than yielding a silently degraded service.

### Security

**v3 was cryptographically broken, not merely dated.** Anyone running 0.0.x should treat every
message ever sent under it as unprotected. The four defects below are each individually fatal, and
each one passed v3's entire test suite, because in every case *both parties agreed* — agreement was
never the property in question.

Two of them were reported by users, years before this release, and neither report was acted on at
the time. **Yuri Buyanov ([@digal](https://github.com/digal), [#13](https://github.com/ivRodriguezCA/nuntius/issues/13))**
identified the single-DH collapse in May 2019 from the `crypto_kdf_derive_from_key` signature
alone. **Burhan ([@NoVoLuMe](https://github.com/NoVoLuMe)) and [@raojunbo](https://github.com/raojunbo)
([#12](https://github.com/ivRodriguezCA/nuntius/issues/12))** reported that the library could not
agree a key with standard X25519 implementations, which was true and had two independent causes.
Thank you both — this release exists because of those issues.

- **X3DH collapsed to a single Diffie-Hellman.** v3 assembled a 96–128 byte X3DH input
  (`DH1 ‖ DH2 ‖ DH3 [‖ DH4]`) and passed it to `crypto_kdf_derive_from_key`, whose key parameter is
  declared `const unsigned char k[crypto_kdf_KEYBYTES]` — **it reads exactly 32 bytes no matter
  what you hand it.** Only DH1 was ever used. DH2, DH3, and DH4 were silently discarded. DH1 is
  `X25519(IK_A^d, SPK_B)`, both long-lived, so the handshake provided **no forward secrecy** and
  the one-time prekey contributed **nothing**. Both parties derived the same wrong key, so every
  test passed and nothing looked wrong. *Fixed by* HKDF-SHA256, whose `(ikm, ikm_len)` signature
  makes the truncation inexpressible, plus a hard assertion that the input material is exactly 128
  or 160 bytes. `crypto_kdf_derive_from_key` is banned outright.

- **The X3DH output never reached the ratchet, and the root key was never chained.** v3 computed a
  shared key and then ignored it: the Double Ratchet's root key was not seeded from it, and
  `performDHRatchet:` derived a new root key from the fresh DH output *alone*, assigning
  `self.rootKey` twice from two independent derivations and discarding the previous root key both
  times. The root chain had no continuity, so **no message key was a function of the handshake** —
  authentication established at the handshake bought the message keys nothing. *Fixed by* making
  `SK` the initial root key and making the previous root key the **mandatory HKDF salt** of every
  root-chain step, so "forgot to chain the previous root key" is not expressible: HKDF-Extract
  cannot be invoked without its salt argument.

- **RNG failures produced all-zero keys, silently.** v3 allocated key buffers with
  `NSMutableData dataWithLength:` — which zero-fills — and then filled them with
  `SecRandomCopyBytes` whose `OSStatus` was marked `__unused` and never checked. On any RNG
  failure the "key" was 32 zero bytes, with no indication of any kind. This is the canonical
  failing-open bug: everything appears to work, both parties agree, and the session has no
  security whatsoever. The two Ed25519→X25519 conversion calls had the same shape — their return
  values were discarded and, on failure, the *uninitialized stack buffers* they were supposed to
  fill were used directly as ECDH inputs. *Fixed by* `randombytes_buf` (which aborts rather than
  returning a status), mandatory return-value checking on every crypto call with `-Wunused-result`
  promoted to an error, an all-zero tripwire on freshly generated private keys, and deletion of
  the two conversion calls entirely.

- **A wire-supplied length was used as a `subdata` bound.** v3 read a 1-byte ratchet-header length
  field out of the received message and then dereferenced it as `*(NSInteger*)` — an **8-byte read
  of a 1-byte `NSData`**, at five call sites — and used the resulting attacker-influenced value as
  the range for `subdataWithRange:` and as the basis for the ciphertext range computed by
  subtraction, all **before** any authentication. Out-of-bounds read from unauthenticated input.
  *Fixed by* removing the length field from the format entirely: header length is a constant
  selected by the type byte, no offset or allocation size is derived from received bytes, and the
  pointer-cast read is banned and linted. The bug is unreachable rather than merely patched.

- **A hand-rolled MAC comparison that was neither constant-time nor correct**, gating AES-CBC with
  PKCS7 padding — i.e. a broken comparator in front of a padding oracle. *Fixed by* deleting the
  comparator and the padding along with the construction: ChaCha20-Poly1305 has no MAC to compare
  and no padding.

- **The version and options bytes were parsed and discarded** (the validation was present but
  commented out), so tampering with them was a silent no-op. They are now validated in an ordered
  gate *and* covered by the AEAD associated data, so tampering is an authentication failure.

**Known limitations, stated deliberately** (SPEC §17): JVM zeroization is best-effort; state
rollback is mitigated by the random nonce and the `send_counter` tripwire but not solved; a no-OPK
initial message remains replayable within the handshake cache window; headers are not encrypted;
there is no post-quantum component; and the transcript-hash binding has not yet been externally
reviewed.

---

## [0.0.9] - 2017-09-22

### Added
- Root key constant for Double Ratchet state (`IRConstants`).

### Changed
- Separated initial Double Ratchet setup from setup-from-restored-state.

### Fixed
- Double Ratchet state did not store all the variables needed to restore a session.

## [0.0.8] - 2017-09-15

### Fixed
- Triple DH bug where ephemeral keys were used incorrectly when generating a shared key.

### Changed
- README: added the class-name prefix, plus Triple DH setup and shared-key generation examples.

## [0.0.7] - 2017-08-13

### Changed
- Fixed namespacing by adding the `IR` prefix to all public classes.

## [0.0.6] - 2017-08-10

### Added
- `IREncryptionService` and Double Ratchet usage examples in the README.

## [0.0.5] - 2017-08-09

### Fixed
- Removed copyright symbols from source headers, which were preventing CocoaPods from loading the
  unit-test classes.

## [0.0.4] - 2017-08-09

### Added
- Travis CI configuration, build-status and pod badges; shared the `nuntius` scheme.

### Changed
- Promoted from alpha to beta.

## [0.0.3] - 2017-08-08

### Changed
- Expanded the README.

## [0.0.2] - 2017-08-07

### Fixed
- `IREncryptionService` was not calling `sodium_init()`.

## [0.0.1] - 2017-08-06

### Added
- Initial release: Objective-C implementation of X3DH and Double Ratchet over libsodium, with
  AES-CBC-HMAC-SHA256 authenticated encryption via CommonCrypto. Distributed via CocoaPods.

---

[1.0.0]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.9...1.0.0
[0.0.9]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.8...0.0.9
[0.0.8]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.7...0.0.8
[0.0.7]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.6...0.0.7
[0.0.6]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.5...0.0.6
[0.0.5]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.4...0.0.5
[0.0.4]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.3...0.0.4
[0.0.3]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.2...0.0.3
[0.0.2]: https://github.com/ivRodriguezCA/nuntius/compare/0.0.1...0.0.2
[0.0.1]: https://github.com/ivRodriguezCA/nuntius/releases/tag/0.0.1
