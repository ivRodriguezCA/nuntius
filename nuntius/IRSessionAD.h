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

/**
 The session associated data — SPEC §6.5, §8.5, §11.1, §12.1.

     SESSION_AD = "nuntius:AD:v4"   (13)
                ‖ IK_A^s            (32)
                ‖ IK_A^d            (32)
                ‖ IK_B^s            (32)
                ‖ IK_B^d            (32)
                                    = 141 bytes

 A IS ALWAYS THE INITIATOR AND B ALWAYS THE RESPONDER, by role, fixed at handshake time and never
 reordered. Computed once, stored verbatim in the state blob at §12.1 offset 6, prefixed to the
 associated data of EVERY AEAD operation in the session, and never transmitted.

 §6.5 names the trap outright: "A port that recomputes SESSION_AD as (self, peer) at send time will
 interoperate with itself and with nothing else. This is among the most likely divergence points in
 the whole protocol." Two things here answer that. The constructor's parameters are named
 `initiator:` and `responder:` and there is no `self:` / `peer:` spelling available; and the
 role-relative accessors are separate, explicitly named methods that read from the fixed offsets
 rather than reordering anything. `RATCHET-BIDI` (§15.4) is the vector that catches a port which
 ignores both, and it catches it only because B sends after the ratchet turns.

 THE STORED BYTES ARE THE RECORD OF BOTH IDENTITIES. §6.5 states the sub-offsets normatively so the
 blob is readable rather than opaque, which is why neither identity key is duplicated elsewhere in
 §12.1:

     SESSION_AD[0..13)     "nuntius:AD:v4"
     SESSION_AD[13..45)    IK_A^s          blob offset 19
     SESSION_AD[45..77)    IK_A^d          blob offset 51
     SESSION_AD[77..109)   IK_B^s          blob offset 83
     SESSION_AD[109..141)  IK_B^d          blob offset 115
 */
@interface IRSessionAD : NSObject

/// §6.5 — builds the 141 bytes from the two identity pairs, in role order.
+ (instancetype _Nullable)adWithInitiator:(IRIdentityKeyPair * _Nonnull)initiator
                                responder:(IRIdentityKeyPair * _Nonnull)responder
                                    error:(NSError * _Nullable * _Nullable)error;

/**
 Rehydrates from §12.1 offset 6, the 141 bytes exactly as stored.

 EVERY FAILURE HERE IS IRErrorStateCorrupt, including a bad public key: §12.2 rule 7 requires
 "every stored public key passes §4.4 checks 1–2 → else ERR_STATE_CORRUPT", whereas the nominal
 constructors report IRErrorInvalidPublicKey for the same bytes arriving from the wire. This method
 therefore runs the encoding predicate itself and maps the residual failure, rather than letting a
 constructor's code escape into a state-blob parse. The original is threaded through
 NSUnderlyingErrorKey for local diagnosis.

 §4.4 checks 1–2 apply to IK^d ONLY, never to IK^s: bit 255 of an Ed25519 public key is the sign of
 x (RFC 8032 §5.1.2) and is set in roughly half of all valid identities.
 */
+ (instancetype _Nullable)adFromStoredBytes:(NSData * _Nonnull)bytes
                                      error:(NSError * _Nullable * _Nullable)error;

/// The 141 stored bytes. Not secret — every component is a public key or a fixed label — but never
/// transmitted either.
@property (nonatomic, copy, readonly) NSData * _Nonnull bytes;

/// SESSION_AD[13..77), the A pair.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull initiatorIdentity;

/// SESSION_AD[77..141), the B pair.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull responderIdentity;

/**
 §6.5 — the PEER pair as seen by a session holding `role`: the responder pair for an initiator, the
 initiator pair for a responder.

 §11.1 keys its second session index on exactly this value, and §11.1.1 makes that index a function
 rather than a relation by permitting at most one live session per peer identity pair.

 Returns nil for a role outside {0x01, 0x02}. §12.2 rule 4 rejects any other byte before a session
 is loaded, so the nil is unreachable through the state parser; it is nil rather than a defaulted
 pair because the failure this guards — a session filed under the wrong peer — is one that must be
 loud.
 */
- (IRIdentityKeyPair * _Nullable)peerIdentityForRole:(IRSessionRole)role;

/// The complement of -peerIdentityForRole:. Same nil contract.
- (IRIdentityKeyPair * _Nullable)ownIdentityForRole:(IRSessionRole)role;

/**
 §8.5 — `AD = SESSION_AD (141) ‖ the complete message header`, 197 bytes for a type `0x01` header
 and 366 for a type `0x02`.

 "The complete header" means `message[0 .. HDR_LEN)` verbatim: version, type, flags, the ratchet
 public key, N, PN and the nonce. The nonce is therefore both the AEAD nonce and part of the AD, and
 that redundancy is intentional — it makes "AD is everything before the ciphertext" exceptionless,
 which is worth more than the twelve bytes it costs.

 The consequence is that version, type and flags are CRYPTOGRAPHICALLY enforced rather than merely
 checked by an `if`: a tampered version byte is an authentication failure. That is a strictly
 stronger fix for defect 13 than adding validation code, and it comes free with the AEAD.

 A `headerBytes` length other than 56 or 225 reports IRErrorMalformedHeader.
 */
- (NSData * _Nullable)associatedDataWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                              error:(NSError * _Nullable * _Nullable)error;

- (BOOL)isEqualToSessionAD:(IRSessionAD * _Nullable)other;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
