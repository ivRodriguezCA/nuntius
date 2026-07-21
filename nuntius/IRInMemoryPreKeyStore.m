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

#import "IRInMemoryPreKeyStore.h"

#import "IRProtocolConstants.h"

#include <os/lock.h>

@implementation IRInMemoryPreKeyStore {
    /* Non-recursive. Every method below either takes the lock and calls only `unlocked_` helpers,
       or takes no lock at all. A helper that locks and is also called from a locked context
       deadlocks, so the naming convention is load-bearing. */
    os_unfair_lock _lock;

    IRSignedPreKeyRecord * _Nullable _currentSignedPreKey;
    IRSignedPreKeyRecord * _Nullable _previousSignedPreKey;

    NSMutableDictionary<NSNumber *, IROneTimePreKeyRecord *> * _Nonnull _oneTimePreKeys;
    /// Insertion order, so a published bundle advertises the oldest usable prekeys first. An
    /// NSDictionary has no order, and publishing in a hash-dependent order would make a bundle's
    /// bytes depend on the platform's hash seed.
    NSMutableArray<NSNumber *> * _Nonnull _oneTimePreKeyOrder;
}

#pragma mark - Construction

+ (instancetype _Nonnull)store {
    return [[self alloc] init];
}

- (instancetype _Nonnull)init {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _lock = OS_UNFAIR_LOCK_INIT;
    _oneTimePreKeys = [NSMutableDictionary dictionary];
    _oneTimePreKeyOrder = [NSMutableArray array];

    return self;
}

#pragma mark - Unlocked helpers

/// Drops and zeroizes `key`'s record. §6.6 step 4: the wipe happens IN PLACE and BEFORE the unlink,
/// because an unlink alone releases the reference and leaves the scalar resident in the heap.
- (void)unlocked_removeOneTimePreKeyForKey:(NSNumber * _Nonnull)key {
    IROneTimePreKeyRecord *record = _oneTimePreKeys[key];
    if (record == nil) {
        return;
    }

    [record zeroize];
    [_oneTimePreKeys removeObjectForKey:key];
    [_oneTimePreKeyOrder removeObject:key];
}

/// §5.3 — deletes and zeroizes every OPK for which OPK_MAX_AGE_S has elapsed. Shared by every entry
/// point that observes a clock, so "an expired OPK no longer resolves" has ONE implementation.
- (void)unlocked_sweepExpiredOneTimePreKeysAtUnixSeconds:(uint64_t)nowS {
    NSMutableArray<NSNumber *> *expired = nil;

    for (NSNumber *key in _oneTimePreKeyOrder) {
        IROneTimePreKeyRecord *record = _oneTimePreKeys[key];
        if (record != nil && [record isExpiredAtUnixSeconds:nowS]) {
            if (expired == nil) {
                expired = [NSMutableArray array];
            }
            [expired addObject:key];
        }
    }

    for (NSNumber *key in expired) {
        [self unlocked_removeOneTimePreKeyForKey:key];
    }
}

/// Zeroizes `record` unless it is still reachable through the other retained slot. Zeroizing a live
/// generation because it happens to be the same object as the one being displaced would destroy a
/// key §5.3 requires be retained.
- (void)unlocked_retireSignedPreKey:(IRSignedPreKeyRecord * _Nullable)record
                         keepIfSame:(IRSignedPreKeyRecord * _Nullable)other {
    if (record == nil || record == other) {
        return;
    }

    [record zeroize];
}

#pragma mark - Write and lifecycle

- (BOOL)storeSignedPreKeyRecord:(IRSignedPreKeyRecord * _Nonnull)record
                    makeCurrent:(BOOL)makeCurrent
                          error:(NSError * _Nullable * _Nullable)error {
    if (record == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    os_unfair_lock_lock(&_lock);

    if (makeCurrent) {
        if (_currentSignedPreKey != nil && _currentSignedPreKey.spkId == record.spkId) {
            /* Re-storing the same slot — replace in place. Demoting here would evict the genuine
               previous generation for a write that added no new generation at all.

               KNOWN GAP, DELIBERATELY LEFT AS IS — SPEC AMBIGUITY, NOT A LOCAL DECISION.
               When the incoming record carries DIFFERENT key material under the same spk_id, the
               outgoing private key is zeroized here without being demoted, so it leaves §5.3's
               {current, one previous} set while its spk_id still resolves — to the new key. §5.3's
               stated purpose for the two-slot set, "so that messages already in flight against a
               just-rotated spk_id still decrypt", is therefore defeated for exactly the id that
               was rotated, and -[IRMessenger publishBundleWithSPKId:...] makes that the default
               path: it rotates unconditionally for the caller-supplied id.

               NOT fixed here because no local fix is available. Demoting instead of zeroizing does
               not help: -signedPreKeyRecordForId: resolves an id to exactly ONE record, and §9.2's
               type 0x02 header carries only spk_id, so two generations sharing an id are
               indistinguishable ON THE WIRE. The demoted key would be retained and unreachable —
               a live secret with no reader, which §13.3 would rather see destroyed.

               The only implementable reading of §5.3 is that a rotation assigns a NEW spk_id, and
               §5.3 does not say so. That sentence needs to be added to the spec before this can be
               enforced anywhere, because enforcing it in one port and not the others is worse than
               the gap: a responder that refuses id reuse and one that accepts it disagree about
               which bundles are publishable, and the disagreement shows up as
               ERR_AEAD_AUTH_FAILED at the initiator, i.e. as an active MITM (§1.2). Raised for
               SPEC.md §5.3 rather than resolved in this file. */
            [self unlocked_retireSignedPreKey:_currentSignedPreKey keepIfSame:record];
            _currentSignedPreKey = record;
        } else {
            /* §5.3 — the retained set is {current, exactly one previous}. Whatever the incoming
               record pushes out has left that set, and §13.3 requires it be zeroized in place
               rather than merely unlinked. */
            [self unlocked_retireSignedPreKey:_previousSignedPreKey keepIfSame:record];
            _previousSignedPreKey = _currentSignedPreKey;
            _currentSignedPreKey = record;
        }
    } else {
        [self unlocked_retireSignedPreKey:_previousSignedPreKey keepIfSame:record];
        _previousSignedPreKey = record;
    }

    os_unfair_lock_unlock(&_lock);

    return YES;
}

- (BOOL)storeOneTimePreKeyRecords:(NSArray<IROneTimePreKeyRecord *> * _Nonnull)records
                            error:(NSError * _Nullable * _Nullable)error {
    if (records == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* DUPLICATE opk_ids WITHIN THE BATCH ARE REFUSED, BEFORE ANYTHING IS STORED.

       The old code resolved a collision by zeroizing the displaced record and installing the new
       one. The displaced record was still in the caller's array — -[IRMessenger
       publishBundleWithSPKId:...] passes the same array to IRPreKeyBundle right after this call —
       so the published bundle advertised one opk_id twice, with two different public keys, and the
       private half of the first was already wiped. An initiator selecting that entry builds a
       handshake the responder can never complete: DH4 is computed against a zeroized scalar, SK
       differs, and B reports ERR_AEAD_AUTH_FAILED, which §1.2 defines as an active MITM. A
       silently burned one-time prekey is also §6.6's consumption invariant broken in the
       responder's favour of nobody.

       Refusing the whole batch keeps the store and the bundle the caller is about to publish in
       agreement, which is the property that actually matters here — a partial apply would leave
       them disagreeing in a way no error code can describe. */
    NSMutableSet<NSNumber *> *seen = [NSMutableSet setWithCapacity:records.count];
    for (IROneTimePreKeyRecord *record in records) {
        if (![record isKindOfClass:[IROneTimePreKeyRecord class]]) {
            IRSetError(error, IRErrorStateCorrupt);
            return NO;
        }

        NSNumber *key = @(record.opkId);
        if ([seen containsObject:key]) {
            IRSetError(error, IRErrorStateCorrupt);
            return NO;
        }
        [seen addObject:key];
    }

    os_unfair_lock_lock(&_lock);

    /* An id already RESIDENT under different key material is the same collision across two calls,
       and is refused for the same reason. Checked before any mutation so the batch stays atomic. */
    for (IROneTimePreKeyRecord *record in records) {
        IROneTimePreKeyRecord *existing = _oneTimePreKeys[@(record.opkId)];
        if (existing == nil || existing == record) {
            continue;
        }

        if (![existing.keyPair.publicKey isEqualToX25519Public:record.keyPair.publicKey]) {
            os_unfair_lock_unlock(&_lock);
            IRSetError(error, IRErrorStateCorrupt);
            return NO;
        }
    }

    for (IROneTimePreKeyRecord *record in records) {
        NSNumber *key = @(record.opkId);

        IROneTimePreKeyRecord *existing = _oneTimePreKeys[key];
        if (existing == record) {
            continue;
        }

        if (existing != nil) {
            /* Same id AND same public key — an idempotent re-store of one generation, verified
               above. Retiring the old object is a zeroize of a duplicate, not of a live key. */
            [self unlocked_removeOneTimePreKeyForKey:key];
        }

        _oneTimePreKeys[key] = record;
        [_oneTimePreKeyOrder addObject:key];
    }

    os_unfair_lock_unlock(&_lock);

    return YES;
}

- (IRSignedPreKeyRecord * _Nullable)currentSignedPreKeyRecord {
    os_unfair_lock_lock(&_lock);
    IRSignedPreKeyRecord *record = _currentSignedPreKey;
    os_unfair_lock_unlock(&_lock);

    return record;
}

- (IRSignedPreKeyRecord * _Nullable)previousSignedPreKeyRecord {
    os_unfair_lock_lock(&_lock);
    IRSignedPreKeyRecord *record = _previousSignedPreKey;
    os_unfair_lock_unlock(&_lock);

    return record;
}

- (NSArray<IROneTimePreKeyRecord *> * _Nonnull)
    unconsumedOneTimePreKeyRecordsWithLimit:(NSUInteger)limit
                              atUnixSeconds:(uint64_t)nowS {
    NSMutableArray<IROneTimePreKeyRecord *> *result = [NSMutableArray array];

    os_unfair_lock_lock(&_lock);

    /* Sweeping first is what makes it impossible to publish an OPK §5.3 required be deleted. */
    [self unlocked_sweepExpiredOneTimePreKeysAtUnixSeconds:nowS];

    for (NSNumber *key in _oneTimePreKeyOrder) {
        if (result.count >= limit) {
            break;
        }

        IROneTimePreKeyRecord *record = _oneTimePreKeys[key];
        if (record != nil) {
            [result addObject:record];
        }
    }

    os_unfair_lock_unlock(&_lock);

    return result;
}

- (NSUInteger)oneTimePreKeyCount {
    os_unfair_lock_lock(&_lock);
    NSUInteger count = _oneTimePreKeys.count;
    os_unfair_lock_unlock(&_lock);

    return count;
}

#pragma mark - Resolution

- (IRSignedPreKeyRecord * _Nullable)signedPreKeyRecordForId:(uint32_t)spkId
                                                      error:(NSError * _Nullable * _Nullable)error {
    os_unfair_lock_lock(&_lock);

    IRSignedPreKeyRecord *record = nil;
    if (_currentSignedPreKey != nil && _currentSignedPreKey.spkId == spkId) {
        record = _currentSignedPreKey;
    } else if (_previousSignedPreKey != nil && _previousSignedPreKey.spkId == spkId) {
        record = _previousSignedPreKey;
    }

    os_unfair_lock_unlock(&_lock);

    if (record == nil) {
        /* §5.3 — an spk_id outside the {current, one previous} set is unknown, full stop. */
        IRSetError(error, IRErrorUnknownPreKeyId);
        return nil;
    }

    return record;
}

- (IROneTimePreKeyRecord * _Nullable)oneTimePreKeyRecordForId:(uint32_t)opkId
                                                atUnixSeconds:(uint64_t)nowS
                                                        error:(NSError * _Nullable * _Nullable)error {
    os_unfair_lock_lock(&_lock);

    [self unlocked_sweepExpiredOneTimePreKeysAtUnixSeconds:nowS];
    IROneTimePreKeyRecord *record = _oneTimePreKeys[@(opkId)];

    os_unfair_lock_unlock(&_lock);

    if (record == nil) {
        /* Unknown, expired, and already-consumed are ONE observable outcome. §6.6 step 4 leaves no
           tombstone, so ERR_OPK_ALREADY_CONSUMED (7115) cannot be distinguished and is never
           emitted — plan gap G1. */
        IRSetError(error, IRErrorUnknownPreKeyId);
        return nil;
    }

    return record;
}

#pragma mark - Consumption

- (BOOL)consumeOneTimePreKeyId:(uint32_t)opkId
                         error:(NSError * _Nullable * _Nullable)error {
    NSNumber *key = @(opkId);

    os_unfair_lock_lock(&_lock);

    BOOL present = (_oneTimePreKeys[key] != nil);
    if (present) {
        /* Zeroize IN PLACE, THEN unlink — §6.6 step 4 and §13.3's OPK row. */
        [self unlocked_removeOneTimePreKeyForKey:key];
    }

    os_unfair_lock_unlock(&_lock);

    if (!present) {
        IRSetError(error, IRErrorUnknownPreKeyId);
        return NO;
    }

    /* THEN durably commit. Outside the lock, because a durable subclass performs I/O here and may
       call back into the store; the in-memory deletion has already been applied, and this method
       does not return until the commit reports success. */
    return [self commitDurably:error];
}

- (BOOL)commitDurably:(NSError * _Nullable * _Nullable)error {
    /* A no-op, honestly: an in-memory store has nothing to commit. A durable subclass MUST override
       this and MUST NOT return until the deletion has reached stable storage — §10.7 step 14
       returns plaintext immediately afterwards. */
    return YES;
}

#pragma mark - Maintenance

- (IRSignedPreKeyRecord * _Nullable)rotateSignedPreKeyWithIdentity:(IRIdentity * _Nonnull)identity
                                                             spkId:(uint32_t)spkId
                                                        notBeforeS:(uint64_t)notBeforeS
                                                         notAfterS:(uint64_t)notAfterS
                                                          provider:(id<IRCryptoProvider> _Nonnull)provider
                                                             error:(NSError * _Nullable * _Nullable)error {
    /* Generated outside the lock: it is a pure function of its arguments and touches no store
       state, and holding a lock across key generation would serialize the CSPRNG needlessly. */
    IRSignedPreKeyRecord *record = [IRSignedPreKeyRecord generateWithIdentity:identity
                                                                        spkId:spkId
                                                                   notBeforeS:notBeforeS
                                                                    notAfterS:notAfterS
                                                                     provider:provider
                                                                        error:error];
    if (record == nil) {
        return nil;
    }

    if (![self storeSignedPreKeyRecord:record makeCurrent:YES error:error]) {
        return nil;
    }

    return record;
}

- (BOOL)pruneExpiredAtUnixSeconds:(uint64_t)nowS
                            error:(NSError * _Nullable * _Nullable)error {
    os_unfair_lock_lock(&_lock);

    /* §13.3 makes `not_after` the LATEST moment an SPK private may be retained, so this applies to
       the current generation as well as the previous one. A store left without a current signed
       prekey is the intended pressure to rotate. */
    if (_currentSignedPreKey != nil && [_currentSignedPreKey isExpiredAtUnixSeconds:nowS]) {
        [self unlocked_retireSignedPreKey:_currentSignedPreKey keepIfSame:nil];
        _currentSignedPreKey = nil;
    }

    if (_previousSignedPreKey != nil && [_previousSignedPreKey isExpiredAtUnixSeconds:nowS]) {
        [self unlocked_retireSignedPreKey:_previousSignedPreKey keepIfSame:_currentSignedPreKey];
        _previousSignedPreKey = nil;
    }

    [self unlocked_sweepExpiredOneTimePreKeysAtUnixSeconds:nowS];

    os_unfair_lock_unlock(&_lock);

    return YES;
}

- (void)zeroizeAll {
    os_unfair_lock_lock(&_lock);

    [self unlocked_retireSignedPreKey:_currentSignedPreKey keepIfSame:nil];
    [self unlocked_retireSignedPreKey:_previousSignedPreKey keepIfSame:_currentSignedPreKey];
    _currentSignedPreKey = nil;
    _previousSignedPreKey = nil;

    for (NSNumber *key in [_oneTimePreKeyOrder copy]) {
        [self unlocked_removeOneTimePreKeyForKey:key];
    }

    [_oneTimePreKeys removeAllObjects];
    [_oneTimePreKeyOrder removeAllObjects];

    os_unfair_lock_unlock(&_lock);
}

- (NSString * _Nonnull)description {
    os_unfair_lock_lock(&_lock);
    NSString *value = [NSString stringWithFormat:
                       @"<%@: %p; current = %@; previous = %@; opk_count = %lu>",
                       NSStringFromClass([self class]), (void *)self,
                       _currentSignedPreKey, _previousSignedPreKey,
                       (unsigned long)_oneTimePreKeys.count];
    os_unfair_lock_unlock(&_lock);

    return value;
}

@end
