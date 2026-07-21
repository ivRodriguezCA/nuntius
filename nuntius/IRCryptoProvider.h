/*
 The MIT License (MIT)
 Copyright © 2017 Ivan Rodriguez. All rights reserved.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import <Foundation/Foundation.h>
#import <nuntius/IRErrors.h>
#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRSecretBytes.h>

/**
 The crypto seam — SPEC §3.2, §3.4, §4.4, §8.2, §13.1.

 One method per row of §3.2's primitive table, and nothing else. This is the layer boundary the
 repository CLAUDE.md requires be preserved: X3DH and the Double Ratchet sit on top of it and never
 call a primitive directly, so this is the single place a platform crypto backend gets swapped.

 NO DEFAULT IMPLEMENTATIONS. Objective-C protocols cannot carry them, which is fortunate — a default
 method is exactly where a richer port grows behaviour the other three lack, and the whole point of
 the seam is that four implementations do the same thing.

 SECRETS DO NOT CROSS THIS BOUNDARY AS NSData. §4.3 forbids a bare NSData for key material anywhere
 in the crypto layer, and §13.3 schedules a wipe for every private key and derived secret this
 protocol handles — an NSData can honour neither, because it is copy-on-write and offers no
 deallocation hook. Every secret in or out of these methods is an IRSecretBytes or a nominal
 subclass of one. NSData survives only where the bytes are genuinely public: hash inputs, HKDF
 `info` labels, associated data, ciphertext, and the application's own plaintext.

 NO METHOD EVER RETURNS nil WITH A nil ERROR (§10.5). The one method that returns BOOL rather than
 an object — signature verification — returns NO for every failure including an uninitialized
 library, which is fail-closed and is the answer a caller should act on either way.
 */
@protocol IRCryptoProvider <NSObject>

#pragma mark - Hash and MAC (§3.2)

/**
 SHA-256, FIPS 180-4. Both call sites are public values: §6.2's TRANSCRIPT (259 bytes) producing TH,
 and §5.5's FP input (77 bytes) producing the identity fingerprint.
 */
- (NSData * _Nullable)sha256OfData:(NSData * _Nonnull)data
                             error:(NSError * _Nullable * _Nullable)error;

/**
 HMAC-SHA256, RFC 2104, over an ARBITRARY-LENGTH key.

 The key is a secret and the message is not: §7.3's KDF_CK is `MK = HMAC(CK, 0x01)` and
 `CK' = HMAC(CK, 0x02)`, where CK is a 32-byte chain key and the message is a single public byte.

 Implementations MUST NOT restrict the key to 32 bytes. libsodium's one-shot crypto_auth_hmacsha256
 does exactly that; the multi-part init/update/final form takes a length and is the correct choice.
 A 32-byte-only HMAC cannot express HKDF-Extract, whose salt is arbitrary length.
 */
- (IRSecretBytes * _Nullable)hmacSHA256WithKey:(IRSecretBytes * _Nonnull)key
                                       message:(NSData * _Nonnull)message
                                         error:(NSError * _Nullable * _Nullable)error;

#pragma mark - HKDF (§3.2)

/**
 HKDF-Extract, RFC 5869 §2.2 — `PRK = HMAC(key = salt, message = ikm)`, 32 bytes out.

 A nil salt and a 32-zero-byte salt produce an IDENTICAL PRK, and §3.2 says so explicitly: HMAC pads
 any key shorter than its 64-byte block with zeros, so Z32 and the empty string are the same key.
 Everywhere this document specifies `salt = Z32` an implementation MAY pass nil. THIS IS NOT A
 DIVERGENCE POINT, and the HKDF-SALT-EQUIV vector exists to record that it is not.

 The salt is typed as a secret because §7.2's KDF_RK passes the ROOT KEY as the salt. That is the
 single highest-risk argument-order trap in this protocol (§16.1): libsodium takes salt first,
 BouncyCastle's HKDFParameters(ikm, salt, info) takes IKM first, and swapping them yields a working,
 self-consistent, incompatible implementation.
 */
- (IRSecretBytes * _Nullable)hkdfExtractWithSalt:(IRSecretBytes * _Nullable)salt
                                             ikm:(IRSecretBytes * _Nonnull)ikm
                                           error:(NSError * _Nullable * _Nullable)error;

/**
 HKDF-Expand, RFC 5869 §2.3 — the `T(i)` counter loop.

 `T(0) = ""`, `T(i) = HMAC(prk, T(i-1) ‖ info ‖ byte(i))`, `OKM = T(1) ‖ T(2) ‖ …` truncated to L.

 §7.2's KDF_RK needs L = 64, which spans TWO blocks. §3.2 names omitting the second block "the most
 common hand-rolled-HKDF bug"; HKDF-EXPAND-64 is the vector that catches it.

 `info` is public in every call site — a §18 label, optionally suffixed with the transcript hash.
 */
- (IRSecretBytes * _Nullable)hkdfExpandWithPRK:(IRSecretBytes * _Nonnull)prk
                                           info:(NSData * _Nonnull)info
                                   outputLength:(NSUInteger)outputLength
                                          error:(NSError * _Nullable * _Nullable)error;

/// `HKDF-Expand(HKDF-Extract(salt, ikm), info, L)`. All four protocol KDF call sites are one-shot;
/// extract and expand are exposed separately only because the RFC 5869 vectors publish the
/// intermediate PRK.
- (IRSecretBytes * _Nullable)hkdfWithSalt:(IRSecretBytes * _Nullable)salt
                                       ikm:(IRSecretBytes * _Nonnull)ikm
                                      info:(NSData * _Nonnull)info
                              outputLength:(NSUInteger)outputLength
                                     error:(NSError * _Nullable * _Nullable)error;

#pragma mark - X25519 (§4.2, §4.4)

/**
 A fresh X25519 pair, private half CLAMPED per §4.2 and public half derived from it.

 §13.1's all-zero tripwire is applied to the RAW CSPRNG output, BEFORE clamping. The order is
 load-bearing: clamping sets `k[31] |= 0x40`, so a scalar that arrived all-zero from a broken RNG is
 `00…40` by the time it is stored and sails past an all-zero test. Checking after the clamp is a
 tripwire that cannot fire.
 */
- (IRX25519KeyPair * _Nullable)generateX25519KeyPairWithError:(NSError * _Nullable * _Nullable)error;

/**
 As -generateX25519KeyPairWithError:, choosing the allocation class of the private half.

 `guarded` = YES asks for sodium_malloc — guard-paged, canaried, mlock'd — and is for the few
 long-lived privates §13.3 keeps for an identity's lifetime: IK^d, SPK and OPK. Ratchet keys and
 EK_A MUST use NO. Guarded allocation is page-granular and iOS arm64 pages are 16 KiB, so taking it
 as the default would cost thousands of pages and thousands of RLIMIT_MEMLOCK reservations for the
 §7.6 skipped-key store alone.
 */
- (IRX25519KeyPair * _Nullable)generateX25519KeyPairGuarded:(BOOL)guarded
                                                       error:(NSError * _Nullable * _Nullable)error;

/**
 X25519 scalar multiplication, RFC 7748 §5 — one DH, 32 secret bytes out.

 §4.4 CHECK 3 IS PERFORMED INSIDE THIS METHOD and reports IRErrorSmallOrderKey. That placement is
 the point: no caller can omit it, and no caller has to remember that libsodium already fails
 closed. §4.4 requires the check be run "even on platforms whose library already fails closed", so
 that all four ports behave uniformly — CryptoKit performs no such check at all, so on Swift the
 accumulator is the only defence.

 The output is a secret. §13.3 requires DH1–DH4 be zeroized immediately after SK is derived, which
 is why this returns an IRSecretBytes and not an NSData: the caller can honour that schedule.
 */
- (IRSecretBytes * _Nullable)x25519WithPrivateKey:(IRX25519Private * _Nonnull)privateKey
                                         publicKey:(IRX25519Public * _Nonnull)publicKey
                                             error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Ed25519 (§3.4, §4.2)

/// A fresh Ed25519 pair. The private half is the 32-byte RFC 8032 SEED (§4.2) — never libsodium's
/// 64-byte expanded `sk`, which MUST NOT appear at any API boundary. §13.1's all-zero tripwire is
/// applied to the seed before the public key is derived from it.
- (IREd25519KeyPair * _Nullable)generateEd25519KeyPairWithError:(NSError * _Nullable * _Nullable)error;

/// As -generateEd25519KeyPairWithError:, choosing the allocation class of the seed. IK^s is a
/// lifetime-of-identity private and is the intended `guarded` = YES caller.
- (IREd25519KeyPair * _Nullable)generateEd25519KeyPairGuarded:(BOOL)guarded
                                                         error:(NSError * _Nullable * _Nullable)error;

/// Recovers the public key from a seed, for an identity restored from storage that kept only the
/// seed. Deterministic: RFC 8032 defines the public key as a pure function of the seed.
- (IREd25519Public * _Nullable)ed25519PublicKeyForSeed:(IREd25519Private * _Nonnull)seed
                                                  error:(NSError * _Nullable * _Nullable)error;

/**
 PURE Ed25519 detached signing, RFC 8032 §5.1 — 64 bytes.

 MUST NOT be implemented with libsodium's multi-part crypto_sign_init/_update/_final_create. §3.4
 verified in the vendored tree that crypto_sign.h line 23 reads
 `typedef crypto_sign_ed25519ph_state crypto_sign_state`, so that API is PREHASHED — a different
 signature scheme that neither java.security.Signature.getInstance("Ed25519") nor CryptoKit's
 Curve25519.Signing can verify. v3 used it at IREncryptionService.m:431-433 and :449-450.

 The failure mode is why this matters: a port that mirrors v3's code shape fails verification in
 exactly the place where failure is defined to mean "active MITM" (§1.2). The bug arrives disguised
 as an attack.

 Implementations MUST expand the seed with crypto_sign_seed_keypair immediately before signing and
 MUST zeroize the 64-byte expansion immediately after (§3.4, §13.3). Passing the 32-byte seed
 straight to crypto_sign_detached is a 32-BYTE OUT-OF-BOUNDS READ, not merely a wrong key:
 libsodium takes sk[32..64) as the public key A and hashes whatever adjacent memory holds into the
 RFC 8032 challenge.
 */
- (IREd25519Signature * _Nullable)ed25519SignMessage:(NSData * _Nonnull)message
                                             withSeed:(IREd25519Private * _Nonnull)seed
                                                error:(NSError * _Nullable * _Nullable)error;

/**
 Pure Ed25519 detached verification, RFC 8032 §5.1.

 NS_WARN_UNUSED_RESULT is not decoration. §13.2 names a discarded Bool here "the exact Swift
 analogue of v3's __unused int", and a dropped return is a silent verification bypass on the one
 path that decides whether a peer is who it claims to be.

 There is no NSError out-parameter: every failure — bad signature, malformed point, uninitialized
 library — is NO, and the caller maps NO to IRErrorBadSignature. Fail-closed by construction, with
 nothing for a caller to accidentally treat as recoverable.
 */
- (BOOL)ed25519VerifySignature:(IREd25519Signature * _Nonnull)signature
                     ofMessage:(NSData * _Nonnull)message
                     publicKey:(IREd25519Public * _Nonnull)publicKey NS_WARN_UNUSED_RESULT;

#pragma mark - AEAD (§8.2)

/**
 ChaCha20-Poly1305, RFC 8439 §2.8, IETF construction — 256-bit key, 96-bit nonce, 128-bit tag.

 Returns `len(plaintext) + 16` bytes: the 16-byte Poly1305 tag APPENDED to the ciphertext. ChaCha20
 is a stream cipher, so there is no padding and ciphertext length equals plaintext length.

 MUST be the `_ietf_` variant. The non-IETF libsodium spelling takes an 8-byte nonce and is a silent
 incompatibility (§3.3). XChaCha20 and AES-256-GCM are both banned, for portability reasons §8.4
 records.

 THE CALLER OWNS `key`'s ZEROIZATION. §13.3 requires enc_key be wiped "immediately after the AEAD
 call returns — success AND failure paths", and this method deliberately does not do it: a provider
 that mutates its arguments is a worse trap across four ports than an explicit schedule point at the
 one call site that created the key.
 */
- (NSData * _Nullable)aeadSealPlaintext:(NSData * _Nonnull)plaintext
                                     key:(IRMessageEncKey * _Nonnull)key
                                   nonce:(IRNonce * _Nonnull)nonce
                          associatedData:(NSData * _Nonnull)associatedData
                                   error:(NSError * _Nullable * _Nullable)error;

/**
 The inverse. `ciphertextAndTag` is ciphertext ‖ 16-byte tag; returns the plaintext, or nil with
 IRErrorAEADAuthFailed.

 There is no separate MAC step, no comparison function and no padding oracle to worry about. v3's
 consistentTimeEqual:hmachToCompare: is DELETED, NOT FIXED (§8.2, §14 defect 5) — under an AEAD
 there is nothing left to compare.

 As with sealing, the caller owns `key`'s zeroization, on this failure path too.
 */
- (NSData * _Nullable)aeadOpenCiphertextAndTag:(NSData * _Nonnull)ciphertextAndTag
                                            key:(IRMessageEncKey * _Nonnull)key
                                          nonce:(IRNonce * _Nonnull)nonce
                                 associatedData:(NSData * _Nonnull)associatedData
                                          error:(NSError * _Nullable * _Nullable)error;

#pragma mark - AEAD over SECRET plaintext (§12.3, §13.3)

/**
 As -aeadSealPlaintext:…, taking the plaintext as an IRSecretBytes.

 REQUIRED BY §12.3, not a convenience. The at-rest construction seals a §12.1 state blob, which
 contains `RK`, `DHs_priv`, `CKs`, `CKr` and every stored message key; §13.3 schedules that buffer
 for zeroization "after sealing, and after parsing". Routing it through NSData first would
 materialize all of it in a copy-on-write container with no zeroizing hook — the same reason
 -fillSecretBytes:error: exists, and the same correction Layer 0 made for IKM.

 Does NOT zeroize `plaintext`: every layer in this framework leaves its arguments alone, and
 §13.3's schedule point here belongs to whoever built the buffer. The message path keeps using the
 NSData form, because a message plaintext is the application's and this framework does not get to
 decide when the application's data is wiped.

 The ciphertext output is NOT secret and is returned as NSData.
 */
- (NSData * _Nullable)aeadSealSecret:(IRSecretBytes * _Nonnull)plaintext
                                 key:(IRMessageEncKey * _Nonnull)key
                               nonce:(IRNonce * _Nonnull)nonce
                      associatedData:(NSData * _Nonnull)associatedData
                               error:(NSError * _Nullable * _Nullable)error;

/**
 As -aeadOpenCiphertextAndTag:…, yielding the plaintext in wipeable storage.

 This is the direction that matters most: opening a sealed state blob into an NSData would leave a
 complete copy of the session's key material in a buffer nothing can wipe, and §13.3 explicitly
 forbids the alternative of scrubbing an NSData's backing store through a const pointer — that is
 v3's commented-out `memset` block, which is both a const-correctness violation and legitimately
 optimizable away.

 `guarded` selects `sodium_malloc` for the result. Opt-in, per the same reasoning as elsewhere: a
 guarded allocation costs a page plus guard pages, so it is for long-lived secrets rather than for
 a buffer that is parsed and dropped.

 Fails with IRErrorAEADAuthFailed on a tag mismatch, as the NSData form does.
 */
- (IRSecretBytes * _Nullable)aeadOpenCiphertextAndTagToSecret:(NSData * _Nonnull)ciphertextAndTag
                                                           key:(IRMessageEncKey * _Nonnull)key
                                                         nonce:(IRNonce * _Nonnull)nonce
                                                associatedData:(NSData * _Nonnull)associatedData
                                                       guarded:(BOOL)guarded
                                                         error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Randomness (§13.1)

/**
 A fresh 12-byte AEAD nonce from the CSPRNG.

 §8.3: it MUST come from the CSPRNG, MUST NOT be a counter, MUST NOT be derived from the message
 key, and MUST NOT be reused. A derived nonce is superficially attractive — it saves 12 wire bytes —
 but this library persists and restores ratchet state, and a restored or forked state replays the
 same MK: under a derived nonce that is identical (key, nonce), which discloses the keystream XOR
 and leaks the Poly1305 one-time key, permitting FORGERY. With a random nonce the same rollback is
 a plaintext-repetition event instead. Twelve bytes is the right price.
 */
- (IRNonce * _Nullable)randomNonceWithError:(NSError * _Nullable * _Nullable)error;

/// Raw CSPRNG bytes, for PUBLIC values only — a nonce, a salt. Returns NSData precisely because
/// nothing secret may leave by this door: key generation fills an IRSecretBytes in place and never
/// round-trips through an NSData that §13.3 could not wipe.
- (NSData * _Nullable)randomBytesOfLength:(NSUInteger)length
                                     error:(NSError * _Nullable * _Nullable)error;

/// Fills an existing secret in place from the CSPRNG, so that no copy of the material ever exists
/// outside a container with a zeroizing -dealloc. Returns NO having zeroized `secret` on failure.
- (BOOL)fillSecretBytes:(IRSecretBytes * _Nonnull)secret
                   error:(NSError * _Nullable * _Nullable)error;

@end
