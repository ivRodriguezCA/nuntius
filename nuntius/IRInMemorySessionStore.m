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

#import "IRInMemorySessionStore.h"

#import "IRRatchetState.h"
#import "IRSession+Internal.h"
#import "IRSessionDispatch.h"
#import "IRSkippedKeyStore.h"

@interface IRInMemorySessionStore ()

- (instancetype _Nonnull)initPrivate;
- (void)indexSession:(IRSession * _Nonnull)session;
- (BOOL)tombstoneRecordedAtMs:(uint64_t)recordedMs hasExpiredAtMs:(uint64_t)nowMs;

@end

@implementation IRInMemorySessionStore {
    /// §11.1's first index. Keys are the 64-byte handshake ids; NSData hashes by content.
    NSMutableDictionary<NSData *, IRSession *> *_sessionsByHandshakeId;

    /// §11.1's second index, a FUNCTION by §11.1.1. IRIdentityKeyPair conforms to NSCopying and
    /// hashes over its 64 raw bytes; without NSCopying this insertion would raise at runtime with
    /// no compile-time diagnostic, because the parameter is typed id<NSCopying>.
    NSMutableDictionary<IRIdentityKeyPair *, IRSession *> *_sessionsByPeer;

    /// §11.4 — handshake id to the Unix millisecond at which the session was torn down.
    NSMutableDictionary<NSData *, NSNumber *> *_tombstones;
}

+ (instancetype _Nonnull)store {
    return [[IRInMemorySessionStore alloc] initPrivate];
}

- (instancetype _Nonnull)initPrivate {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _sessionsByHandshakeId = [NSMutableDictionary dictionary];
    _sessionsByPeer = [NSMutableDictionary dictionary];
    _tombstones = [NSMutableDictionary dictionary];

    return self;
}

#pragma mark - §11.1 indices

- (IRSession * _Nullable)sessionForHandshakeId:(NSData * _Nonnull)handshakeId {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        return nil;
    }

    return _sessionsByHandshakeId[handshakeId];
}

- (IRSession * _Nullable)sessionForPeerIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)peer {
    if (peer == nil) {
        return nil;
    }

    return _sessionsByPeer[peer];
}

- (NSArray<IRSession *> * _Nonnull)allSessions {
    return _sessionsByHandshakeId.allValues;
}

- (NSUInteger)sessionCount {
    return _sessionsByHandshakeId.count;
}

- (NSUInteger)tombstoneCount {
    return _tombstones.count;
}

#pragma mark - §10.7 step 14 / §11.1.1

- (IRSessionEstablishResult * _Nullable)establishSession:(IRSession * _Nonnull)session
                                                atTimeMs:(uint64_t)nowMs
                                                   error:(NSError * _Nullable * _Nullable)error {
    if (session == nil || session.isTornDown ||
        session.handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRIdentityKeyPair *peer = session.peerIdentityKeyPair;
    IRSession *existing = _sessionsByPeer[peer];

    if (existing == session) {
        /* Idempotent re-establish of a session already installed for this peer. Not a collapse —
           there is only one object — so nothing is torn down and nothing is tombstoned. */
        [self indexSession:session];
        return [IRSessionEstablishResult resultWithSurvivingSession:session
                                                    tornDownSession:nil
                                            incomingSessionSurvived:YES];
    }

    if (existing == nil) {
        [self indexSession:session];
        return [IRSessionEstablishResult resultWithSurvivingSession:session
                                                    tornDownSession:nil
                                            incomingSessionSurvived:YES];
    }

    /* §11.1.1. Two distinct live sessions with one peer — the simultaneous-initiation race, which
       is routine on a mobile transport. Both sides run this comparison over public values each
       already holds and converge on the same survivor with no further message. */
    BOOL incomingWins = NO;
    if (![IRSessionDispatch resolveCollapseForIncomingSession:session
                                              againstExisting:existing
                                                 incomingWins:&incomingWins
                                                        error:error]) {
        return nil;
    }

    if (incomingWins) {
        /* The loser is torn down IMMEDIATELY: its ratchet state and skipped-key store are zeroized
           (§13.3) and its handshake_id is tombstoned for HANDSHAKE_CACHE_MS so that a
           retransmission cannot resurrect it. */
        if (![self tearDownSession:existing atTimeMs:nowMs error:error]) {
            return nil;
        }
        [self indexSession:session];
        return [IRSessionEstablishResult resultWithSurvivingSession:session
                                                    tornDownSession:existing
                                            incomingSessionSurvived:YES];
    }

    /* The session we were just handed LOSES. It is torn down and tombstoned exactly as the other
       direction would be — §11.4 requires a tombstone "whenever a session is torn down for any
       reason", and this is one. A caller that decrypted a message on it still returns that
       plaintext, because the message authenticated; what it must not do is keep the handle.
       "Messages already sent on the losing session are lost... recovery is the application's
       retry, not the protocol's" (§11.1.1). */
    if (![self tearDownSession:session atTimeMs:nowMs error:error]) {
        return nil;
    }

    return [IRSessionEstablishResult resultWithSurvivingSession:existing
                                                tornDownSession:session
                                        incomingSessionSurvived:NO];
}

- (void)indexSession:(IRSession * _Nonnull)session {
    _sessionsByHandshakeId[session.handshakeId] = session;
    _sessionsByPeer[session.peerIdentityKeyPair] = session;
}

#pragma mark - Persistence

- (BOOL)persistSession:(IRSession * _Nonnull)session
                 error:(NSError * _Nullable * _Nullable)error {
    if (session == nil || session.isTornDown) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* Rejects a session this store does not hold, so a torn-down collapse loser cannot be written
       back by a caller still holding the handle. The identity comparison is deliberate: an equal
       handshake id belonging to a DIFFERENT object is the case this is guarding against. */
    if (_sessionsByHandshakeId[session.handshakeId] != session) {
        IRSetError(error, IRErrorNoSession);
        return NO;
    }

    /* Nothing to write — the store holds the live object, so a commit is already visible here.
       IRSealedSessionStore is where this method does work; the protocol carries it so that a
       caller's §7.8 "persist before emitting" sequence is identical against either store. */
    return YES;
}

#pragma mark - §11.4 teardown and tombstones

- (BOOL)tearDownSession:(IRSession * _Nonnull)session
               atTimeMs:(uint64_t)nowMs
                  error:(NSError * _Nullable * _Nullable)error {
    if (session == nil || session.handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* Only unlink entries that are THIS session. A collapse tears down the loser while the winner
       is already installed under the same peer key, and removing by key alone would evict it. */
    if (_sessionsByHandshakeId[session.handshakeId] == session) {
        [_sessionsByHandshakeId removeObjectForKey:session.handshakeId];
    }
    if (_sessionsByPeer[session.peerIdentityKeyPair] == session) {
        [_sessionsByPeer removeObjectForKey:session.peerIdentityKeyPair];
    }

    [session tearDown];

    /* §11.4: written whenever a session is torn down FOR ANY REASON — eviction, explicit deletion,
       or the collapse of §11.1.1. A session never added to this store is tombstoned too: the
       collapse path above tears down a loser that was never indexed. */
    _tombstones[[session.handshakeId copy]] = @(nowMs);

    return YES;
}

- (BOOL)hasTombstoneForHandshakeId:(NSData * _Nonnull)handshakeId
                          atTimeMs:(uint64_t)nowMs {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        return NO;
    }

    NSNumber *recorded = _tombstones[handshakeId];
    if (recorded == nil) {
        return NO;
    }

    return ![self tombstoneRecordedAtMs:recorded.unsignedLongLongValue hasExpiredAtMs:nowMs];
}

/**
 §11.4's window, with the same two decisions the skipped-key store makes for `SKIPPED_TTL_MS`.

 A tombstone whose timestamp lies in the FUTURE relative to `nowMs` is KEPT. The clock is injectable
 (§15.5 rule 6) and in production is a system clock that can be corrected backwards; an unsigned
 `nowMs - recordedMs` would underflow to an enormous age and expire every tombstone at once, which
 here means reopening the §17.3 replay window for every session torn down in the last seven days.

 The comparator is `>` rather than `>=`, so the tombstone is still present at exactly
 `HANDSHAKE_CACHE_MS`. §11.4 says implementations MUST retain "for at least HANDSHAKE_CACHE_MS" and
 states no comparator; the inclusive reading is the one that satisfies "at least" under either
 interpretation of the boundary.
 */
- (BOOL)tombstoneRecordedAtMs:(uint64_t)recordedMs hasExpiredAtMs:(uint64_t)nowMs {
    if (recordedMs > nowMs) {
        return NO;
    }

    return ((nowMs - recordedMs) > (uint64_t)kIRHandshakeCacheMs);
}

#pragma mark - Pruning

- (BOOL)pruneAtTimeMs:(uint64_t)nowMs
                error:(NSError * _Nullable * _Nullable)error {
    NSMutableArray<NSData *> *expired = [NSMutableArray array];
    for (NSData *key in _tombstones.allKeys) {
        NSNumber *recorded = _tombstones[key];
        if ([self tombstoneRecordedAtMs:recorded.unsignedLongLongValue hasExpiredAtMs:nowMs]) {
            [expired addObject:key];
        }
    }
    [_tombstones removeObjectsForKeys:expired];

    /* §7.6 / §13.3 — "skipped message keys: on use, on eviction, and on TTL expiry". §7.9 phase 2
       already sweeps on every decrypt, so this is what bounds a session that is receiving nothing.

       MUST NOT be called while a decrypt is in flight. A snapshot shares entry objects with the
       live store, so wiping the live store's expired entries underneath one would destroy keys the
       snapshot still references. Nothing in the framework interleaves them; a host that receives on
       more than one queue must serialize, as IRSession's header states. */
    for (IRSession *session in _sessionsByHandshakeId.allValues) {
        if (session.isTornDown) {
            continue;
        }
        [session.state.skipped dropEntriesExpiredAtTimeMs:nowMs];
        [session.state.skipped zeroizePendingRemovals];
    }

    return YES;
}

#pragma mark - §13.3 teardown

- (void)zeroizeAll {
    for (IRSession *session in _sessionsByHandshakeId.allValues) {
        [session tearDown];
    }

    [_sessionsByHandshakeId removeAllObjects];
    [_sessionsByPeer removeAllObjects];
    [_tombstones removeAllObjects];
}

@end
