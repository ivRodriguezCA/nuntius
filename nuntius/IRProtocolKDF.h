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
#import <nuntius/IRCryptoProvider.h>
#import <nuntius/IRErrors.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRSecretBytes.h>

/**
 The four protocol key derivations — SPEC §6.3, §7.2, §7.3, §8.1.

 ALL FOUR PROTOCOL KDF CALL SITES LIVE HERE AND NOWHERE ELSE. v3 funnelled everything through one
 `genericKDFWithSecret:andSalt:outputLength:infoLabel:` over `crypto_kdf_derive_from_key`, whose key
 parameter is a fixed `unsigned char k[32]`: the 96–128 byte X3DH input was silently truncated to
 its first 32 bytes, so only DH1 was ever read (defect 1). HKDF-Extract's `(ikm, ikm_len)` signature
 cannot express that mistake — the length travels with the pointer — which is why §6.4 calls the fix
 structural rather than a corrected length.

 THE NOMINAL TYPES ARE THE POINT. Passing an IRChainKey where an IRRootKey belongs is a compile
 error here. That is the one mistake which produces a working, self-consistent, INCOMPATIBLE port,
 and no test written against a single implementation can catch it.

 THIS CLASS NEVER MUTATES ITS ARGUMENTS — see the zeroization note on each method. Every input
 secret belongs to its caller, and §13.3's schedule for it is set by the caller.
 */

#pragma mark - Value results

/// §7.2 — the pair KDF_RK produces. A tuple in Swift, a record in Java.
@interface IRRootChainStep : NSObject

@property (nonatomic, strong, readonly) IRRootKey  * _Nonnull rootKey;   ///< okm[0..32)
@property (nonatomic, strong, readonly) IRChainKey * _Nonnull chainKey;  ///< okm[32..64)

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

/// Zeroizes both halves. For a caller abandoning a step it computed but did not commit.
- (void)zeroize;

@end

/// §7.3 — the pair KDF_CK produces.
@interface IRChainStep : NSObject

@property (nonatomic, strong, readonly) IRMessageKey * _Nonnull messageKey;    ///< HMAC(CK, 0x01)
@property (nonatomic, strong, readonly) IRChainKey   * _Nonnull nextChainKey;  ///< HMAC(CK, 0x02)

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

- (void)zeroize;

@end

#pragma mark - IRProtocolKDF

@interface IRProtocolKDF : NSObject

/**
 §7.2 KDF_RK — `HKDF(salt = RK, ikm = DH_out, info = "nuntius:RK:v4", L = 64)`, split
 `RK' = okm[0..32)`, `CK = okm[32..64)`.

 THE PARAMETER IS NAMED `RootKeyAsSalt` SO THE ARGUMENT-ORDER TRAP CANNOT BE WRITTEN BY ACCIDENT.
 §7.2 calls that trap "the single highest-risk divergence point in this protocol": libsodium's
 `crypto_kdf_hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len)` takes the salt FIRST, while
 BouncyCastle's `HKDFParameters(ikm, salt, info)` and CryptoKit's
 `HKDF.deriveKey(inputKeyMaterial:salt:info:)` take the IKM first. Swapping them produces a working,
 self-consistent, completely incompatible implementation, and `KDF-RK-1` (§15.3) is the vector that
 arbitrates it.

 The previous root key is MANDATORY and is the salt, never part of the IKM. HKDF-Extract cannot be
 invoked without a salt argument, so "forgot to chain the previous root key" — v3's
 `performDHRatchet:`, which derived from the DH output alone — is not expressible here.

 `dhOutput` is an IRSecretBytes rather than an NSData because it is exactly the 32-byte X25519
 output §13.3 schedules for zeroization; a copy-on-write NSData has no hook that could honour it.

 ZEROIZATION: neither argument is touched. The caller owns `rootKey`'s wipe, which §13.3 places at
 the moment its successor replaces it in COMMITTED state — not when this function returns, because
 a §7.7 snapshot that is later discarded must leave the live root key intact.
 */
+ (IRRootChainStep * _Nullable)deriveRootStepWithRootKeyAsSalt:(IRRootKey * _Nonnull)rootKey
                                                      dhOutput:(IRSecretBytes * _Nonnull)dhOutput
                                                      provider:(id<IRCryptoProvider> _Nonnull)provider
                                                         error:(NSError * _Nullable * _Nullable)error;

/**
 §7.3 KDF_CK — `MK = HMAC(key = CK, message = 0x01)` and `CK' = HMAC(key = CK, message = 0x02)`.

 HKDF is deliberately NOT used: two raw HMACs are the Double Ratchet specification's own
 recommendation, are cheaper per message, and require zero convention agreement between ports — no
 salt, no info, no length, no truncation. The constants 0x01 and 0x02 MUST NOT be renumbered; v3
 used salt 0 for the message key and salt 1 for the chain key and ports MUST NOT carry those over.

 `len(CK) == 32` is asserted here, per §7.3's note on why an HMAC with a fixed 32-byte key would be
 acceptable at this one site while `crypto_kdf_derive_from_key` is banned: the ban is about a
 fixed-size parameter silently consuming a VARIABLE-length input, and CK is 32 bytes by nominal type.

 ZEROIZATION: `chainKey` IS NOT WIPED, deliberately, and this is a correction to the plan rather
 than an omission. §13.3 schedules the old CK for zeroization "immediately after KDF_CK produces its
 successor", but that schedule point belongs to the COMMIT, not to this call. §7.6's SkipMessageKeys
 advances the receiving chain on a §7.7 SNAPSHOT which is discarded whenever the AEAD tag fails; a
 KDF that wiped its input would destroy the live session's CKr on every forged message — precisely
 the desynchronisation DoS `NEG-ATOMIC` exists to catch.
 */
+ (IRChainStep * _Nullable)deriveChainStepWithChainKey:(IRChainKey * _Nonnull)chainKey
                                              provider:(id<IRCryptoProvider> _Nonnull)provider
                                                 error:(NSError * _Nullable * _Nullable)error;

/**
 §8.1 KDF_MK — `enc_key = HKDF(salt = Z32, ikm = MK, info = "nuntius:MK:v4", L = 32)`.

 There is no HMAC key and no derived IV. v3 derived three values from one message key by re-invoking
 the same `chainKey` label at salts 1, 2 and 3 — one label across three semantic roles, with the
 16-byte IV request hitting `crypto_kdf_BYTES_MIN` and being silently widened. All of it is gone.

 ZEROIZATION: `messageKey` IS NOT WIPED, for the same reason as KDF_CK and with a sharper
 consequence. A message key drawn from the §7.6 skipped store is expanded BEFORE the AEAD runs, and
 `NEG-SKIP-RETAIN` (§15.4) requires that a corrupted tag leave that stored key intact so a later
 correct delivery still succeeds. Wiping here fails that vector. The caller zeroizes MK once the
 AEAD has succeeded and the store entry is being removed.

 The returned enc_key IS the caller's to wipe, on the AEAD's success AND failure paths (§13.3) —
 IRCryptoProvider's seal and open deliberately do not touch it either.
 */
+ (IRMessageEncKey * _Nullable)expandMessageKey:(IRMessageKey * _Nonnull)messageKey
                                       provider:(id<IRCryptoProvider> _Nonnull)provider
                                          error:(NSError * _Nullable * _Nullable)error;

/**
 §6.3 — `SK = HKDF(salt = Z32, ikm = IKM, info = "nuntius:X3DH:v4" ‖ TH, L = 32)`.

 ASSERTS `len(IKM) ∈ {128, 160}` AND `len(SK) == 32`. §6.3 says of that first assertion: "That
 assertion alone would have caught defect 1 on the day it was introduced." A wrong length reports
 IRErrorStateCorrupt — an internal invariant violation, never a parse failure, since every caller
 assembled the IKM itself.

 `ikm` is an IRSecretBytes: it is `F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]`, which §13.3 requires be zeroized
 immediately after this call returns. The caller owns that wipe — IRX3DH performs it.

 `transcriptHash` is the 32-byte public SHA256 of §6.2's TRANSCRIPT; it is not secret and is the one
 value binding this derivation to the exact keys and ids both parties saw.
 */
+ (IRRootKey * _Nullable)deriveSharedKeyWithIKM:(IRSecretBytes * _Nonnull)ikm
                                 transcriptHash:(NSData * _Nonnull)transcriptHash
                                       provider:(id<IRCryptoProvider> _Nonnull)provider
                                          error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
