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

#import "IRSealedSessionStore.h"

#import "IRRatchetState.h"
#import "IRSession+Internal.h"
#import "IRSessionDispatch.h"
#import "IRSessionStateCodec.h"
#import "IRSkippedKeyStore.h"

#pragma mark - IRInMemorySessionRecordStorage

@implementation IRInMemorySessionRecordStorage {
    NSMutableDictionary<NSData *, NSData *> *_records;
    NSMutableDictionary<NSData *, NSNumber *> *_tombstones;
}

+ (instancetype _Nonnull)storage {
    return [[IRInMemorySessionRecordStorage alloc] init];
}

- (instancetype _Nonnull)init {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _records = [NSMutableDictionary dictionary];
    _tombstones = [NSMutableDictionary dictionary];

    return self;
}

- (NSUInteger)recordCount {
    return _records.count;
}

- (NSUInteger)tombstoneCount {
    return _tombstones.count;
}

- (NSData * _Nullable)sealedRecordForHandshakeId:(NSData * _Nonnull)handshakeId {
    if (handshakeId.length == 0) {
        return nil;
    }

    return _records[handshakeId];
}

- (NSArray<NSData *> * _Nonnull)allHandshakeIds {
    return _records.allKeys;
}

- (BOOL)storeSealedRecord:(NSData * _Nonnull)sealed
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    if (sealed.length == 0 || handshakeId.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    _records[[handshakeId copy]] = [sealed copy];

    return YES;
}

- (BOOL)removeRecordForHandshakeId:(NSData * _Nonnull)handshakeId
                             error:(NSError * _Nullable * _Nullable)error {
    (void)error;

    if (handshakeId.length > 0) {
        [_records removeObjectForKey:handshakeId];
    }

    return YES;
}

- (BOOL)storeTombstoneAtTimeMs:(uint64_t)nowMs
                forHandshakeId:(NSData * _Nonnull)handshakeId
                         error:(NSError * _Nullable * _Nullable)error {
    if (handshakeId.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    _tombstones[[handshakeId copy]] = @(nowMs);

    return YES;
}

- (BOOL)tombstoneTimeMs:(uint64_t * _Nonnull)outTimeMs
         forHandshakeId:(NSData * _Nonnull)handshakeId {
    if (outTimeMs == NULL || handshakeId.length == 0) {
        return NO;
    }

    NSNumber *recorded = _tombstones[handshakeId];
    if (recorded == nil) {
        return NO;
    }

    *outTimeMs = recorded.unsignedLongLongValue;

    return YES;
}

- (NSArray<NSData *> * _Nonnull)allTombstoneHandshakeIds {
    return _tombstones.allKeys;
}

- (BOOL)removeTombstoneForHandshakeId:(NSData * _Nonnull)handshakeId
                                error:(NSError * _Nullable * _Nullable)error {
    (void)error;

    if (handshakeId.length > 0) {
        [_tombstones removeObjectForKey:handshakeId];
    }

    return YES;
}

@end

#pragma mark - IRSealedSessionStore

@interface IRSealedSessionStore ()

- (instancetype _Nonnull)initWithSealedStore:(IRSealedStore * _Nonnull)sealedStore
                                     storage:(id<IRSessionRecordStorage> _Nonnull)storage
                            rollbackTripwire:(id<IRRollbackTripwire> _Nonnull)tripwire;

- (BOOL)writeSession:(IRSession * _Nonnull)session
               error:(NSError * _Nullable * _Nullable)error;

- (void)indexSession:(IRSession * _Nonnull)session;

- (BOOL)tombstoneRecordedAtMs:(uint64_t)recordedMs hasExpiredAtMs:(uint64_t)nowMs;

@end

@implementation IRSealedSessionStore {
    IRSealedStore *_sealedStore;
    id<IRSessionRecordStorage> _storage;
    id<IRRollbackTripwire> _tripwire;

    /// §11.1's first index, over LIVE objects. See the header on why instances are cached.
    NSMutableDictionary<NSData *, IRSession *> *_sessionsByHandshakeId;

    /// §11.1's second index, a function by §11.1.1.
    NSMutableDictionary<IRIdentityKeyPair *, IRSession *> *_sessionsByPeer;

    NSMutableArray<NSData *> *_unloadableHandshakeIds;
    NSMutableArray<NSData *> *_rolledBackHandshakeIds;
}

+ (instancetype _Nullable)storeWithSealedStore:(IRSealedStore * _Nonnull)sealedStore
                                       storage:(id<IRSessionRecordStorage> _Nonnull)storage
                              rollbackTripwire:(id<IRRollbackTripwire> _Nonnull)tripwire
                                         error:(NSError * _Nullable * _Nullable)error {
    if (sealedStore == nil || storage == nil || tripwire == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[IRSealedSessionStore alloc] initWithSealedStore:sealedStore
                                                     storage:storage
                                            rollbackTripwire:tripwire];
}

- (instancetype _Nonnull)initWithSealedStore:(IRSealedStore * _Nonnull)sealedStore
                                     storage:(id<IRSessionRecordStorage> _Nonnull)storage
                            rollbackTripwire:(id<IRRollbackTripwire> _Nonnull)tripwire {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _sealedStore = sealedStore;
    _storage = storage;
    _tripwire = tripwire;

    _sessionsByHandshakeId = [NSMutableDictionary dictionary];
    _sessionsByPeer = [NSMutableDictionary dictionary];
    _unloadableHandshakeIds = [NSMutableArray array];
    _rolledBackHandshakeIds = [NSMutableArray array];

    return self;
}

- (IRSealedStore * _Nonnull)sealedStore {
    return _sealedStore;
}

- (id<IRSessionRecordStorage> _Nonnull)storage {
    return _storage;
}

- (id<IRRollbackTripwire> _Nonnull)rollbackTripwire {
    return _tripwire;
}

- (NSArray<NSData *> * _Nonnull)unloadableHandshakeIds {
    return [_unloadableHandshakeIds copy];
}

- (NSArray<NSData *> * _Nonnull)rolledBackHandshakeIds {
    return [_rolledBackHandshakeIds copy];
}

- (NSUInteger)sessionCount {
    return _sessionsByHandshakeId.count;
}

#pragma mark - Loading

- (BOOL)loadAtTimeMs:(uint64_t)nowMs
               error:(NSError * _Nullable * _Nullable)error {
    /* PER-RECORD outcomes are reported through -unloadableHandshakeIds and
       -rolledBackHandshakeIds, not through this return: failing the whole load because one blob
       will not open would take every other session down with it (see the header).

       A TRIPWIRE READ FAILURE IS NOT A PER-RECORD OUTCOME. It is an environmental fault — a device
       rebooted and never unlocked, a keychain-group change — that fails EVERY session closed, and
       that the host has to act on rather than discover by noticing an empty store. It is the one
       condition that also fails this return. */
    NSError *firstTripwireError = nil;

    [_unloadableHandshakeIds removeAllObjects];
    [_rolledBackHandshakeIds removeAllObjects];

    for (NSData *handshakeId in _storage.allHandshakeIds) {
        if (_sessionsByHandshakeId[handshakeId] != nil) {
            /* Already live. Re-decoding would mint a second IRSession for one session and
               invalidate every handle a caller holds — see the header. */
            continue;
        }

        NSData *sealed = [_storage sealedRecordForHandshakeId:handshakeId];
        if (sealed == nil) {
            [_unloadableHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        IRSecretBytes *blob = [_sealedStore openSealed:sealed
                                                 label:IRSealedStoreLabelSession
                                               guarded:NO
                                                 error:NULL];
        if (blob == nil) {
            [_unloadableHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        /* §12.2, including rule 9's TTL sweep against the injected clock. */
        IRRatchetState *state = [IRSessionStateCodec deserializeState:blob
                                                             atTimeMs:nowMs
                                                                error:NULL];
        /* §13.3 — "serialized state buffer: after sealing, AND AFTER PARSING". The codec read this
           buffer in place and copied nothing out of it that it did not need. */
        [blob zeroizeNow];

        if (state == nil) {
            [_unloadableHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        /* §12.5 — the rollback comparison, on the load path, before the session becomes reachable.
           "if the blob's send_counter is LESS THAN the recorded value, the state has been rolled
           back." A rolled-back session is not indexed, so it cannot be encrypted on; that is what
           "requiring a fresh handshake" means operationally.

           A TRIPWIRE THAT WILL NOT READ EXCLUDES THE SESSION TOO. The comparison cannot be
           performed, so the alternative is to perform it against a fabricated 0 and let everything
           through — which is failing open on the one check whose entire job is to catch a restored
           backup. Refusing a session that was probably fine costs one handshake; admitting one that
           was probably rolled back costs the nonce-reuse protection §8.3 is holding in reserve. */
        uint64_t recorded = 0;
        NSError *tripwireError = nil;
        if (![_tripwire lastObservedSendCounter:&recorded
                                 forHandshakeId:handshakeId
                                          error:&tripwireError]) {
            [state zeroize];
            [_rolledBackHandshakeIds addObject:[handshakeId copy]];
            if (firstTripwireError == nil) {
                firstTripwireError = tripwireError;
            }
            continue;
        }

        if (state.sendCounter < recorded) {
            [state zeroize];
            [_rolledBackHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        IRSession *session = [IRSession sessionWithState:state error:NULL];
        if (session == nil) {
            [state zeroize];
            [_unloadableHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        /* A record filed under an id that does not match the blob's own handshake_id is a storage
           inconsistency, not a decodable session. It fails closed rather than being indexed under
           two different ids. */
        if (![session.handshakeId isEqualToData:handshakeId]) {
            [session tearDown];
            [_unloadableHandshakeIds addObject:[handshakeId copy]];
            continue;
        }

        [self indexSession:session];
    }

    if (firstTripwireError != nil) {
        /* IRErrorStateRollback (7124) is the right code even though the tripwire could not be read
           rather than definitely tripping: it is the code that tells a host "this session needs a
           fresh handshake", which is the remedy in both cases. The underlying error carries the
           IRErrorStateCorrupt that says the tripwire itself is the thing that failed, so a host
           that wants to distinguish "unlock the device and retry" from "you have been rolled back"
           can. */
        IRSetErrorWithUnderlying(error, IRErrorStateRollback, firstTripwireError);
        return NO;
    }

    return YES;
}

- (BOOL)hasRollbackForHandshakeId:(NSData * _Nonnull)handshakeId {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        return NO;
    }

    for (NSData *candidate in _rolledBackHandshakeIds) {
        if ([candidate isEqualToData:handshakeId]) {
            return YES;
        }
    }

    return NO;
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

- (void)indexSession:(IRSession * _Nonnull)session {
    _sessionsByHandshakeId[session.handshakeId] = session;
    _sessionsByPeer[session.peerIdentityKeyPair] = session;
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

    IRSession *existing = _sessionsByPeer[session.peerIdentityKeyPair];

    if (existing == nil || existing == session) {
        if (![self writeSession:session error:error]) {
            return nil;
        }
        [self indexSession:session];
        return [IRSessionEstablishResult resultWithSurvivingSession:session
                                                    tornDownSession:nil
                                            incomingSessionSurvived:YES];
    }

    /* §11.1.1 — the simultaneous-initiation race. The comparison is in IRSessionDispatch so that
       this store and IRInMemorySessionStore cannot disagree about which side survives. */
    BOOL incomingWins = NO;
    if (![IRSessionDispatch resolveCollapseForIncomingSession:session
                                              againstExisting:existing
                                                 incomingWins:&incomingWins
                                                        error:error]) {
        return nil;
    }

    if (incomingWins) {
        /* The record is written BEFORE the loser is torn down. A crash between the two leaves both
           records on disk and the next load indexes both — but §11.1.1 is deterministic, so the
           very next -establishSession: for that peer collapses them the same way again. The
           opposite order can lose the winner entirely. */
        if (![self writeSession:session error:error]) {
            return nil;
        }
        if (![self tearDownSession:existing atTimeMs:nowMs error:error]) {
            return nil;
        }
        [self indexSession:session];

        return [IRSessionEstablishResult resultWithSurvivingSession:session
                                                    tornDownSession:existing
                                            incomingSessionSurvived:YES];
    }

    if (![self tearDownSession:session atTimeMs:nowMs error:error]) {
        return nil;
    }

    return [IRSessionEstablishResult resultWithSurvivingSession:existing
                                                tornDownSession:session
                                        incomingSessionSurvived:NO];
}

#pragma mark - Persistence

- (BOOL)persistSession:(IRSession * _Nonnull)session
                 error:(NSError * _Nullable * _Nullable)error {
    if (session == nil || session.isTornDown) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (_sessionsByHandshakeId[session.handshakeId] != session) {
        IRSetError(error, IRErrorNoSession);
        return NO;
    }

    return [self writeSession:session error:error];
}

/**
 §12.1 serialize, §12.3 seal, store, then §12.5 record.

 The plaintext blob is wiped on every path, which is §13.3's "serialized state buffer — after
 sealing". IRSealedStore deliberately does not do it: no layer of this framework zeroizes an
 argument it did not create, and this method is what created it.
 */
- (BOOL)writeSession:(IRSession * _Nonnull)session
               error:(NSError * _Nullable * _Nullable)error {
    IRSecretBytes *blob = [session serializedState:error];
    if (blob == nil) {
        return NO;
    }

    NSData *sealed = [_sealedStore sealSecret:blob
                                        label:IRSealedStoreLabelSession
                                        error:error];
    [blob zeroizeNow];

    if (sealed == nil) {
        return NO;
    }

    if (![_storage storeSealedRecord:sealed forHandshakeId:session.handshakeId error:error]) {
        return NO;
    }

    /* §12.5 — the high-water mark is advanced only once the record is durable. Recording first
       would let a failed write leave a tripwire above the stored counter, which reads as a
       rollback on the next load and refuses a session that was never rolled back. */
    return [_tripwire recordSendCounter:session.sendCounter
                         forHandshakeId:session.handshakeId
                                  error:error];
}

#pragma mark - §11.4 teardown and tombstones

- (BOOL)tearDownSession:(IRSession * _Nonnull)session
               atTimeMs:(uint64_t)nowMs
                  error:(NSError * _Nullable * _Nullable)error {
    if (session == nil || session.handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (_sessionsByHandshakeId[session.handshakeId] == session) {
        [_sessionsByHandshakeId removeObjectForKey:session.handshakeId];
    }
    if (_sessionsByPeer[session.peerIdentityKeyPair] == session) {
        [_sessionsByPeer removeObjectForKey:session.peerIdentityKeyPair];
    }

    [session tearDown];

    /* §11.4 — the tombstone is written BEFORE the record is removed, and the record's removal is
       what may fail. A tombstone without a record is correct; a record without a tombstone would
       reopen §17.3's replay window, which §10.7 step 4 exists to bound. */
    if (![_storage storeTombstoneAtTimeMs:nowMs forHandshakeId:session.handshakeId error:error]) {
        return NO;
    }

    if (![_storage removeRecordForHandshakeId:session.handshakeId error:error]) {
        return NO;
    }

    /* The handshake id embeds EK_A (§11.1) and so can never recur; keeping the tripwire entry
       would leak one item per torn-down session for the life of the installation. */
    return [_tripwire forgetHandshakeId:session.handshakeId error:error];
}

- (BOOL)hasTombstoneForHandshakeId:(NSData * _Nonnull)handshakeId
                          atTimeMs:(uint64_t)nowMs {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        return NO;
    }

    uint64_t recordedMs = 0;
    if (![_storage tombstoneTimeMs:&recordedMs forHandshakeId:handshakeId]) {
        return NO;
    }

    return ![self tombstoneRecordedAtMs:recordedMs hasExpiredAtMs:nowMs];
}

/// Identical to IRInMemorySessionStore's, and for the identical reasons: a future-dated tombstone
/// is KEPT rather than allowed to underflow an unsigned subtraction, and the comparator is `>` so
/// the window is inclusive of §11.4's "at least HANDSHAKE_CACHE_MS".
- (BOOL)tombstoneRecordedAtMs:(uint64_t)recordedMs hasExpiredAtMs:(uint64_t)nowMs {
    if (recordedMs > nowMs) {
        return NO;
    }

    return ((nowMs - recordedMs) > (uint64_t)kIRHandshakeCacheMs);
}

#pragma mark - Pruning

- (BOOL)pruneAtTimeMs:(uint64_t)nowMs
                error:(NSError * _Nullable * _Nullable)error {
    for (NSData *handshakeId in _storage.allTombstoneHandshakeIds) {
        uint64_t recordedMs = 0;
        if (![_storage tombstoneTimeMs:&recordedMs forHandshakeId:handshakeId]) {
            continue;
        }
        if ([self tombstoneRecordedAtMs:recordedMs hasExpiredAtMs:nowMs]) {
            if (![_storage removeTombstoneForHandshakeId:handshakeId error:error]) {
                return NO;
            }
        }
    }

    /* §7.6 / §13.3. MUST NOT run while a decrypt is in flight — a snapshot shares entry objects
       with the live store. Each swept session is rewritten so the shortened skipped list reaches
       storage; without that the next load would restore the entries this just dropped. */
    for (IRSession *session in _sessionsByHandshakeId.allValues) {
        if (session.isTornDown) {
            continue;
        }

        NSUInteger before = session.state.skipped.count;
        [session.state.skipped dropEntriesExpiredAtTimeMs:nowMs];
        [session.state.skipped zeroizePendingRemovals];

        if (session.state.skipped.count != before) {
            if (![self writeSession:session error:error]) {
                return NO;
            }
        }
    }

    return YES;
}

#pragma mark - §13.3

- (void)zeroizeAll {
    for (IRSession *session in _sessionsByHandshakeId.allValues) {
        [session tearDown];
    }

    [_sessionsByHandshakeId removeAllObjects];
    [_sessionsByPeer removeAllObjects];
    [_unloadableHandshakeIds removeAllObjects];
    [_rolledBackHandshakeIds removeAllObjects];
}

@end
