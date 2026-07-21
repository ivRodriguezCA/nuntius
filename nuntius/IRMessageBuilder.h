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
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>

#import "IRX3DH.h"

/**
 The send side of the wire format — SPEC §9.1, §9.2, §11.3, §10.4.

 The inverse of IRMessageGate, and deliberately the only place a v4 header is written. Every method
 finishes through -[IRByteWriter finishExpectingLength:], so a field omitted, duplicated, or written
 at the wrong width changes the total and fails HERE rather than as an unexplained
 ERR_AEAD_AUTH_FAILED on a peer running another language.

 THREE RULES ARE ENFORCED BY THE SHAPE OF THE PARAMETER LISTS, NOT BY VALIDATION:

 1. `N` AND `PN` ARE SEPARATELY NAMED for type `0x01`. This is the structural answer to defect 10 —
    v3 wrote `numberOfSentMessages` into both slots, and §9.1 has to say in prose that `PN` comes
    "from state.PN — never from state.Ns". Passing one variable for both now requires typing it
    twice, in two differently-named argument positions.

 2. TYPE `0x02` ACCEPTS NO `PN` AT ALL. §9.2 fixes it at zero and §10.2 check 8 rejects anything
    else, so it is written as a literal. Making a field unwritable is stronger than validating it.

 3. TYPE `0x02` TAKES THE PROLOGUE AS ONE OBJECT, not four loose fields. §11.3 requires A to reuse
    the IDENTICAL `EK_A`, `spk_id`, `opk_flag` and `opk_id` on every prekey message until B replies;
    consuming the single stored IRSessionPrologue (§12.1's 41-byte block) whole is what makes
    "identical" a property of the data flow rather than of the caller's diligence.

 `IKB_A` IS PASSED IN, NEVER RE-SIGNED. §11.3: it "MUST NOT be re-signed at send time, since Ed25519
 signing is not contractually deterministic on all four platforms". A port that re-signed would emit
 a different 64-byte value per message; nothing in the receive path compares `IKB_A` across
 messages, so the divergence would decrypt correctly and never be caught. It is read from the
 long-lived identity record (§5.1) — a per-identity value, not a per-session one.
 */
@interface IRMessageBuilder : NSObject

#pragma mark - Bounds

/**
 §10.4 — `MAX_PLAINTEXT` is 16777216 (16 MiB). Above it, `ERR_PLAINTEXT_TOO_LARGE`.

 EMPTY PLAINTEXT IS LEGAL and yields a 72-byte type `0x01` message. §10.4 calls this out because v3's
 `encryptData:` returned nil when the CBC output was zero-length, conflating "empty input" with
 "encryption failed"; v4 has no such ambiguity, and a caller MUST NOT treat 0 as an error.

 Callers MUST run this BEFORE sealing, not after: §10.4 requires bounds be checked "before any
 allocation sized from the input".
 */
+ (BOOL)validatePlaintextLength:(NSUInteger)plaintextLength
                          error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Headers

/**
 §9.1 — the 56-byte type `0x01` header.

     0   1   version    0x04
     1   1   type       0x01
     2   2   flags      0x0000
     4   32  DHs_pub
     36  4   N
     40  4   PN
     44  12  nonce

 `nonce` MUST be freshly drawn from the CSPRNG for every seal (§8.3). It is never a counter and
 never derived from the message key: this library persists and restores ratchet state, so a derived
 nonce would repeat `(key, nonce)` after any restore or fork — which under ChaCha20-Poly1305
 discloses the keystream XOR and leaks the Poly1305 one-time key, permitting forgery. With a random
 nonce the same rollback is a plaintext-repetition event instead.
 */
+ (NSData * _Nullable)type01HeaderWithRatchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                               N:(uint32_t)N
                                              PN:(uint32_t)PN
                                           nonce:(IRNonce * _Nonnull)nonce
                                           error:(NSError * _Nullable * _Nullable)error;

/**
 §9.2 — the 225-byte type `0x02` header.

     0   1   version    0x04            132 32  EK_A          (from `prologue`)
     1   1   type       0x02            164 4   spk_id        (from `prologue`)
     2   2   flags      0x0000          168 1   opk_flag      (from `prologue`)
     4   32  IK_A^s                     169 4   opk_id        (from `prologue`)
     36  32  IK_A^d                     173 32  DHs_pub
     68  64  IKB_A                      205 4   N
                                        209 4   PN            always 0x00000000
                                        213 12  nonce

 `N` MAY be non-zero (§9.2): until A has decrypted a message from B, A does not know the session was
 established, so A's second and subsequent messages are also prekey messages carrying the identical
 prologue with an incrementing `N`.

 `ratchetKey` MUST NOT equal the prologue's `EK_A` — §10.2 check 11 on the receive side. It is
 checked here too, because a port that wired one key pair into both slots would emit messages every
 conformant peer rejects, and the failure should name the sender's bug rather than surface on the
 receiver as a public-key error about a message it did not create.

 B's own `OPK` public is NOT transmitted; B recovers it from `opk_id` (§9.2).
 */
+ (NSData * _Nullable)type02HeaderWithInitiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                                        identityBinding:(IREd25519Signature * _Nonnull)identityBinding
                                               prologue:(IRSessionPrologue * _Nonnull)prologue
                                             ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                                      N:(uint32_t)N
                                                  nonce:(IRNonce * _Nonnull)nonce
                                                  error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Assembly

/**
 `header ‖ ciphertext ‖ tag` — the complete message.

 `headerBytes` MUST be 56 or 225 bytes; its length selects the type, which is the same rule §9 gives
 the reader in reverse. `ciphertextAndTag` MUST be at least 16 bytes, since §8.2 appends a 128-bit
 Poly1305 tag to a ciphertext whose length equals the plaintext's — so a shorter payload could not
 have come from a seal.

 The result is bounds-checked against the type's maximum (§10.4), so a message this framework emits
 can never be one its own gate would reject with `ERR_PLAINTEXT_TOO_LARGE`.
 */
+ (NSData * _Nullable)messageWithHeaderBytes:(NSData * _Nonnull)headerBytes
                            ciphertextAndTag:(NSData * _Nonnull)ciphertextAndTag
                                       error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
