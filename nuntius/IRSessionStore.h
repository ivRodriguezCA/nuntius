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
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>
#import <nuntius/IRSession.h>

#pragma mark - IRSessionEstablishResult

/**
 What §10.7 step 14 did — SPEC §11.1.1.

 Establishing a session for a peer that already has one is a COLLAPSE, not an addition, and the
 caller has to be told which handle survived: the one it just built may be the loser, in which case
 every handle it holds for that peer is now the OTHER object.
 */
@interface IRSessionEstablishResult : NSObject

/// The session the store now holds for this peer. Always live.
@property (nonatomic, strong, readonly) IRSession * _Nonnull survivingSession;

/// The loser of a §11.1.1 collapse — already torn down, zeroized and tombstoned — or nil when no
/// live session existed for this peer and nothing was displaced.
@property (nonatomic, strong, readonly) IRSession * _Nullable tornDownSession;

/// The 64-byte `handshake_id` of `tornDownSession`, captured before teardown so it outlives the
/// object, or nil when nothing was displaced. §11.6 makes this the caller-facing observable: a
/// handle has no byte representation, so the id is the only way a caller can tell whether a handle
/// IT holds is the one that died.
@property (nonatomic, copy, readonly) NSData * _Nullable tornDownHandshakeId;

/// NO when the session passed in LOST the collapse. A caller that just decrypted a message on it
/// still returns that plaintext — the message was authenticated, and §10.7 step 14d requires
/// delivery on this branch — but MUST NOT keep the handle.
@property (nonatomic, readonly) BOOL incomingSessionSurvived;

/**
 Convenience for `tornDownSession != nil`, and DELIBERATELY NOT the caller-facing signal.

 §11.6: this is YES on BOTH branches of §10.7 step 14b while the caller's obligation is opposite on
 each. On the losing branch the torn-down session is the one the message arrived on, which the caller
 never held, and the caller's cached handle is the SURVIVOR. Anything surfaced to a host must be
 `tornDownHandshakeId`, or the conjunction with `incomingSessionSurvived` — never this alone.
 */
@property (nonatomic, readonly) BOOL collapseOccurred;

/// For store implementations. Building one of these grants no capability — it is a triple of
/// values the caller already holds — so it is exposed rather than hidden behind a fourth header.
+ (instancetype _Nullable)resultWithSurvivingSession:(IRSession * _Nonnull)survivingSession
                                     tornDownSession:(IRSession * _Nullable)tornDownSession
                             incomingSessionSurvived:(BOOL)incomingSessionSurvived;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRSessionStore

/**
 The session record store — SPEC §11.1, §11.1.1, §11.4, §11.5.

 TWO INDICES OVER ONE SET OF RECORDS, and §11.1 names both:

   by `handshake_id`      — dispatches type `0x02`, which is self-routing (§11.2).
   by peer identity pair  — selects a session for type `0x01`, which is NOT (§11.5).

 §11.1.1 IS WHAT MAKES THE SECOND INDEX A FUNCTION rather than a relation, and that is the whole
 reason §11.5 can forbid trial decryption. At most one live session per peer identity pair,
 counting both roles together. The invariant is not automatic — both parties may legitimately
 initiate at once, which is routine on a mobile transport — so -establishSession:atTimeMs:error: is
 the only way to add a session and it applies the collapse itself.

 THERE IS DELIBERATELY NO PLAIN -removeSession:. §11.4 requires a tombstone whenever a session is
 torn down FOR ANY REASON — eviction, explicit deletion, or a §11.1.1 collapse — so the only
 removal method writes one. A store that let a caller drop a record without a tombstone would
 reopen the §17.3 replay window that §10.7 step 4 exists to bound.

 IMPLEMENTATIONS ARE NOT REQUIRED TO BE THREAD-SAFE. See IRSession's note: a host receiving on more
 than one queue MUST serialize.
 */
@protocol IRSessionStore <NSObject>

#pragma mark §11.1 — the two indices

/// §11.2's dispatch index. Nil when no live session has that id — which, together with
/// -hasTombstoneForHandshakeId:atTimeMs:, is what §10.7 step 4 distinguishes.
- (IRSession * _Nullable)sessionForHandshakeId:(NSData * _Nonnull)handshakeId;

/// §11.5's selection index, a FUNCTION by §11.1.1. The peer MUST have been authenticated by the
/// transport (§11.5 rule 2): nothing in a type `0x01` header is authenticated before decryption,
/// so routing on header bytes would let an attacker choose which session absorbs the cost of
/// processing a message it forged.
- (IRSession * _Nullable)sessionForPeerIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)peer;

/// Every live session, in unspecified order.
- (NSArray<IRSession *> * _Nonnull)allSessions;

#pragma mark §10.7 step 14 / §11.1.1 — establishing

/**
 Adds a NEWLY ESTABLISHED session, applying §11.1.1's collapse against any live session for the
 same peer: the greater `handshake_id` survives, the loser is torn down, zeroized and tombstoned.

 This is the ONLY way to introduce a session, so the single-live-session invariant cannot be broken
 by forgetting to check for a sibling. §10.7 step 14 orders this AFTER the AEAD has verified and
 after the one-time prekey has been consumed, and before the plaintext is returned.
 */
- (IRSessionEstablishResult * _Nullable)establishSession:(IRSession * _Nonnull)session
                                                atTimeMs:(uint64_t)nowMs
                                                   error:(NSError * _Nullable * _Nullable)error;

#pragma mark Persistence

/**
 Persists an ALREADY-ESTABLISHED session, after a commit (§7.7) or a successful encrypt (§7.8).

 §7.8 requires `persist(state)` to complete BEFORE the message is emitted, because §12.5's rollback
 tripwire is only meaningful if `send_counter` reaches storage first. It does NOT apply §11.1.1 —
 the session is already the survivor for its peer — and it MUST reject a session the store does not
 hold, so that a torn-down loser cannot be written back by a caller still holding the handle.
 */
- (BOOL)persistSession:(IRSession * _Nonnull)session
                 error:(NSError * _Nullable * _Nullable)error;

#pragma mark §11.4 — teardown and tombstones

/**
 Tears the session down, zeroizes it (§13.3), and records its `handshake_id` as a tombstone for
 `HANDSHAKE_CACHE_MS` (7 days).

 The only removal method, by design — see the protocol comment.
 */
- (BOOL)tearDownSession:(IRSession * _Nonnull)session
               atTimeMs:(uint64_t)nowMs
                  error:(NSError * _Nullable * _Nullable)error;

/**
 §10.7 step 4 / §11.4 — YES when this `handshake_id` was torn down within the last
 `HANDSHAKE_CACHE_MS`.

 The check that bounds §17.3's no-OPK handshake replay by ENFORCEMENT rather than by implication,
 and that stops a replayed handshake from displacing a live session under §10.7 step 14. `nowMs` is
 the §15.5 rule 6 injectable time source.
 */
- (BOOL)hasTombstoneForHandshakeId:(NSData * _Nonnull)handshakeId
                          atTimeMs:(uint64_t)nowMs;

/// Drops tombstones older than `HANDSHAKE_CACHE_MS` and sweeps each live session's skipped-key
/// store for `SKIPPED_TTL_MS` expiries (§7.6). Safe to call on any schedule, including never —
/// both bounds are also enforced at the point of use.
- (BOOL)pruneAtTimeMs:(uint64_t)nowMs
                error:(NSError * _Nullable * _Nullable)error;

@end
