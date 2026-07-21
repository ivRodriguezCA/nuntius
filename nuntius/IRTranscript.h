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
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>

/**
 The X3DH transcript and its derived byte strings — SPEC §6.2, §6.3.

 THE TRANSCRIPT IS THE BINDING. It replaces v3's `BLAKE2b(q ‖ sender_pk ‖ receiver_pk)` ECDH wrapper
 and covers strictly more material: both identity keys of BOTH parties, the handshake ephemeral, the
 signed prekey, and both key ids, in one canonical order. Feeding its hash into the X3DH HKDF `info`
 is what ties the derived SK to the exact keys and ids the two parties actually saw.

 THE TRANSCRIPT CONTAINS NO SIGNATURE BYTES, and that is deliberate and load-bearing (§6.2). Hashing
 IKB or SPK_SIG into TH would oblige both parties to reconstruct byte-identical 64-byte signatures,
 which is not safe to assume: CryptoKit's Ed25519 signing is not contractually deterministic, and
 verifier strictness on non-canonical `S` and small-order `A` differs across libsodium,
 BouncyCastle and the JDK — the documented "many EdDSAs" hazard. Binding the signed CONTENTS
 achieves the same binding with none of the reproducibility risk, because TRANSCRIPT already carries
 every key and id those signatures cover.

 259 BYTES, ALWAYS, IN BOTH THE OPK AND NO-OPK CASES. An absent one-time prekey is encoded as
 `opk_id = 0` and 32 zero bytes rather than omitted, so the WRITE path has no conditional structure
 and no branch to get wrong. `opk_flag` disambiguates, so a genuine all-zero OPK public key — which
 §4.4 would have rejected anyway — cannot be confused with absence.

 The IKBIND_MSG (§5.1) and SPK_SIGN_MSG (§5.2) builders are NOT here: they already have exactly one
 home each, as IRIKBindMessage in IRPublicIdentity.h and IRSPKSignMessage in IRPreKeyRecords.h, and
 a second builder for a signed structure is precisely the drift these single-source functions exist
 to prevent. The §5.5 fingerprint input is likewise owned by IRPublicIdentity.
 */
@interface IRTranscript : NSObject

/**
 §6.2 — the 259-byte TRANSCRIPT.

     TRANSCRIPT = "nuntius:X3DH:transcript:v4"  (26)
                ‖ IK_A^s                         (32)
                ‖ IK_A^d                         (32)
                ‖ EK_A                           (32)
                ‖ IK_B^s                         (32)
                ‖ IK_B^d                         (32)
                ‖ SPK_B                          (32)
                ‖ uint32_be(spk_id)              (4)
                ‖ opk_flag                       (1)
                ‖ uint32_be(opk_id)              (4)   0 when opk_flag == 0x00
                ‖ OPK_B                          (32)  32 × 0x00 when opk_flag == 0x00
                                                 = 259

 THE PARAMETERS ARE NAMED `initiator:` AND `responder:` — NEVER `self:` / `peer:`. A is always the
 initiator and B always the responder, fixed at handshake time and never reordered, exactly as in
 §6.5's SESSION_AD. Naming them by role is what makes the role-swap trap unwritable at the call
 site rather than merely documented.

 `oneTimePreKey` MUST be non-nil when `opkFlag` is IROPKFlagPresent and nil when it is
 IROPKFlagAbsent, and `opkId` MUST be 0 in the absent case (§9.2). A violation reports
 IRErrorMalformedHeader, the same code §10.2 check 7 assigns to the wire-side form of that
 inconsistency — which is what normally makes this branch unreachable on the responder's path.
 */
+ (NSData * _Nullable)transcriptWithInitiator:(IRIdentityKeyPair * _Nonnull)initiator
                                    ephemeral:(IRX25519Public * _Nonnull)ephemeral
                                    responder:(IRIdentityKeyPair * _Nonnull)responder
                                 signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                                        spkId:(uint32_t)spkId
                                      opkFlag:(IROPKFlag)opkFlag
                                        opkId:(uint32_t)opkId
                                oneTimePreKey:(IRX25519Public * _Nullable)oneTimePreKey
                                        error:(NSError * _Nullable * _Nullable)error;

/// §6.2 — `TH = SHA256(TRANSCRIPT)`. Asserts `len(TRANSCRIPT) == 259` before hashing, which §6.2
/// makes an explicit MUST: a missing field then fails here rather than on a peer's machine in
/// another language.
+ (NSData * _Nullable)transcriptHashOf:(NSData * _Nonnull)transcript
                              provider:(id<IRCryptoProvider> _Nonnull)provider
                                 error:(NSError * _Nullable * _Nullable)error;

/// §6.3 — the 47-byte X3DH HKDF info, `"nuntius:X3DH:v4" (15) ‖ TH (32)`. One builder, shared by
/// IRProtocolKDF's derivation and by IRX3DH's exposed intermediate, so the two cannot drift.
+ (NSData * _Nullable)x3dhInfoWithTranscriptHash:(NSData * _Nonnull)transcriptHash
                                           error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
