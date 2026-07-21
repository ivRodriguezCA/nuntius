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
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRSession.h>

#import "IRMessageHeader.h"

/**
 Session demultiplexing — SPEC §11.1.1, §11.2, §11.5.

 The routing decisions that are pure functions of a message and a session record, separated from
 the store that holds the records and from the messenger that owns §10.7's fourteen steps. Two
 things live here:

   §11.2's three ordered checks, run when a type `0x02` message resolves to an EXISTING session.
   §11.1.1's collapse comparison, run when a NEW session is established for a peer that has one.

 §11.5 HAS NOTHING TO IMPLEMENT HERE, and that is the point. Rule 1 (an explicit handle) and rule 3
 (no trial decryption) are enforced by the SHAPE of the API above this layer — there is no entry
 point that takes a type `0x01` message alone, and none that loops over candidate sessions. Rule 2
 (the sender identity comes from the transport) is a host obligation the library cannot check.
 Rule 4 is discharged by §11.1.1: because at most one live session exists per peer identity pair,
 an authenticated sender names exactly one session and no tiebreak is needed — nor could one exist,
 since no deterministic function of a type `0x01` header identifies the right sibling.
 */

#pragma mark - §11.1.1 handshake_id ordering

/**
 §11.1.1 — compares two `handshake_id`s as 64-byte UNSIGNED BIG-ENDIAN integers.

 Returns NO, leaving `outResult` untouched, unless both operands are exactly
 `kIRLenHandshakeId` bytes. A wrong-length id must not silently compare equal: equality is the one
 answer that means "these are the same session", and defaulting to it would merge two.

 THE UNSIGNED READING IS LOAD-BEARING FOR THE PORTS. `memcmp` is correct here only because C
 compares as `unsigned char`. On the JVM `byte` is signed, so the naive loop compares `0x80` as
 -128 and picks the wrong survivor — and because both sides must converge on the SAME survivor from
 the same public data, one port getting this backwards diverges the two sides permanently rather
 than failing loudly. `SESSION-COLLAPSE` (§15.3) is the vector.
 */
BOOL IRCompareHandshakeIds(NSData * _Nullable a,
                           NSData * _Nullable b,
                           NSComparisonResult * _Nonnull outResult);

#pragma mark - IRSessionDispatch

@interface IRSessionDispatch : NSObject

/**
 §11.2's three checks against an already-resolved session, in the normative order.

     1. header identity != s.(IK_A^s, IK_A^d)      -> IRErrorIdentityMismatch
     2. IKB_A fails to verify                       -> IRErrorBadSignature
     3. header DHs_pub == s.DHs.pub                 -> IRErrorInvalidPublicKey

 "The three checks are ordered, and the order is normative... Each returns its own code and returns
 immediately."

 CHECK 2 IS NOT REDUNDANT, and §19.3 records why it was kept. `IKB_A` occupies `msg[68..132)`,
 which is inside the type `0x02` associated data (§8.5), so a tampered binding already reaches the
 AEAD and fails there. Both readings fail closed — a forged `IKB_A` can never be ACCEPTED either
 way — but they return different codes for identical input, and §15.4 makes the exact code a
 conformance requirement: `NEG-IKB-RETRANS` demands IRErrorBadSignature and never
 IRErrorAEADAuthFailed. The cost is one Ed25519 verification per retransmitted prekey message, paid
 to keep §5.5's blanket "every identity ingest" MUST free of conditional holes.

 Check 1 reads the session's INITIATOR identity regardless of our role, because that is what
 `s.IK_A^s` and `s.IK_A^d` name. For a responder that is the peer; for an initiator it is
 ourselves, and the check then rejects a peer reflecting our own handshake back at us.

 Check 3 is the type `0x02` counterpart of §10.1 check 8. It cannot live in the §10.2 gate, which
 sees no session — §10.2 says so explicitly, and lists this and §10.7 step 6 as the two
 anti-reflection checks a gate cannot perform.

 `header` MUST be a type `0x02` header from IRMessageGate; a type `0x01` header reports
 IRErrorMalformedHeader.
 */
+ (BOOL)validatePreKeyMessageHeader:(IRMessageHeader * _Nonnull)header
                     againstSession:(IRSession * _Nonnull)session
                           provider:(id<IRCryptoProvider> _Nonnull)provider
                              error:(NSError * _Nullable * _Nullable)error;

/**
 §11.1.1 — resolves which of two sessions for one peer survives: the GREATER `handshake_id`.

 Returns YES on a decided comparison, writing the answer to `outIncomingWins`; returns NO with an
 error otherwise. The out-parameter exists because "the existing session wins" and "the comparison
 could not be made" are different answers, and a bare BOOL return would conflate them into the one
 that silently keeps a session it should have replaced.

 Both parties compute this from public values each already holds — its own `IK^d` and `EK_A`, and
 the peer's from the received type `0x02` header — so both converge on the same survivor with no
 negotiation, no timestamps, and no dependence on arrival order. "Newest wins" was rejected for
 exactly that reason (§19.2): each side observes a different arrival order, so it is not a function
 and the two sides can diverge permanently.

 Equal ids mean the two handles name the SAME handshake, which is not a collapse at all — that case
 is IRErrorStateCorrupt, because a caller reaching it has resolved one session twice and the answer
 "keep the existing one" would hide the bug.
 */
+ (BOOL)resolveCollapseForIncomingSession:(IRSession * _Nonnull)incoming
                          againstExisting:(IRSession * _Nonnull)existing
                             incomingWins:(BOOL * _Nonnull)outIncomingWins
                                    error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
