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

#import "IRSkippedKeyStore.h"

#import "IRByteWriter.h"

#pragma mark - IRSkippedKeyEntry

@interface IRSkippedKeyEntry ()

- (instancetype _Nullable)initWithMessageKey:(IRMessageKey * _Nonnull)messageKey
                                    dhPublic:(IRX25519Public * _Nonnull)dhPublic
                                           N:(uint32_t)N
                                insertedAtMs:(uint64_t)insertedAtMs;

/// Called only through IRSkippedKeyStore's three-way schedule. Idempotent.
- (void)zeroize;

@end

@implementation IRSkippedKeyEntry {
    IRX25519Public *_dhPublic;
    uint32_t _N;
    IRMessageKey *_messageKey;
    uint64_t _insertedAtMs;
    NSData *_storeKey;
    BOOL _isZeroized;
}

- (instancetype _Nullable)initWithMessageKey:(IRMessageKey * _Nonnull)messageKey
                                    dhPublic:(IRX25519Public * _Nonnull)dhPublic
                                           N:(uint32_t)N
                                insertedAtMs:(uint64_t)insertedAtMs {
    if (messageKey == nil || messageKey.length != kIRLenMessageKey) {
        return nil;
    }

    if (dhPublic == nil || dhPublic.length != kIRLenX25519Public) {
        return nil;
    }

    self = [super init];
    if (self == nil) {
        return nil;
    }

    /* §7.6 — the raw 36-byte tuple, built through IRByteWriter like every other byte structure in
       the framework so that the layout has exactly one author. §12.1's skipped entry reuses these
       same 36 bytes as its prefix (offsets +0 and +32), which is why this is a stored property
       rather than something recomputed per lookup. */
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSkippedMapKey];
    [writer appendData:dhPublic.data];
    [writer appendUInt32BE:N];

    NSData *storeKey = [writer finishExpectingLength:kIRLenSkippedMapKey error:NULL];
    if (storeKey == nil) {
        return nil;
    }

    _dhPublic = dhPublic;
    _N = N;
    _messageKey = messageKey;
    _insertedAtMs = insertedAtMs;
    _storeKey = storeKey;
    _isZeroized = NO;

    return self;
}

- (IRX25519Public * _Nonnull)dhPublic {
    return _dhPublic;
}

- (uint32_t)N {
    return _N;
}

- (IRMessageKey * _Nonnull)messageKey {
    return _messageKey;
}

- (uint64_t)insertedAtMs {
    return _insertedAtMs;
}

- (NSData * _Nonnull)storeKey {
    return [_storeKey copy];
}

- (BOOL)isZeroized {
    return _isZeroized;
}

- (void)zeroize {
    [_messageKey zeroizeNow];
    _isZeroized = YES;
}

- (NSString * _Nonnull)description {
    /* The key itself is never printed. */
    return [NSString stringWithFormat:@"<%@: %p; dh = %@; N = %u; insertedAtMs = %llu; zeroized = %@>",
            NSStringFromClass([self class]), (void *)self, [_dhPublic hexString], _N,
            (unsigned long long)_insertedAtMs, _isZeroized ? @"YES" : @"NO"];
}

@end

#pragma mark - IRSkippedKeyStore

@implementation IRSkippedKeyStore {
    /// Store key (36 bytes, content-hashed NSData) -> entry. Lookup only.
    NSMutableDictionary<NSData *, IRSkippedKeyEntry *> *_entriesByStoreKey;

    /// INSERTION ORDER. Index 0 is the FIFO eviction victim and index 0 is also §12.1's first
    /// serialized entry. §7.6 orders eviction "by insertion", which is deliberately not the same as
    /// ordering by `insertedAtMs` — see the header.
    NSMutableArray<IRSkippedKeyEntry *> *_entriesInInsertionOrder;

    /// Removed, evicted or TTL-expired since -copyForSnapshot. Wiped at COMMIT, never at discard:
    /// a live store may still reference these objects.
    NSMutableArray<IRSkippedKeyEntry *> *_pendingZeroize;

    /// Inserted since -copyForSnapshot. Wiped at DISCARD, since nothing else references them.
    /// Retained even after eviction, so a key derived and then evicted inside one failed attempt is
    /// still wiped.
    NSMutableArray<IRSkippedKeyEntry *> *_derivedInsertions;
}

+ (instancetype _Nonnull)store {
    return [[self alloc] init];
}

- (instancetype _Nonnull)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _entriesByStoreKey = [NSMutableDictionary dictionary];
    _entriesInInsertionOrder = [NSMutableArray array];
    _pendingZeroize = [NSMutableArray array];
    _derivedInsertions = [NSMutableArray array];

    return self;
}

#pragma mark - Lookup

- (IRSkippedKeyEntry * _Nullable)entryForDHPublic:(IRX25519Public * _Nonnull)dhPublic
                                                N:(uint32_t)N {
    NSData *storeKey = [[self class] storeKeyForDHPublic:dhPublic N:N];
    if (storeKey == nil) {
        return nil;
    }

    return _entriesByStoreKey[storeKey];
}

- (NSUInteger)count {
    return _entriesInInsertionOrder.count;
}

- (NSArray<IRSkippedKeyEntry *> * _Nonnull)entriesInInsertionOrder {
    return [_entriesInInsertionOrder copy];
}

#pragma mark - Mutation

- (BOOL)insertMessageKey:(IRMessageKey * _Nonnull)messageKey
                dhPublic:(IRX25519Public * _Nonnull)dhPublic
                       N:(uint32_t)N
                atTimeMs:(uint64_t)nowMs {
    IRSkippedKeyEntry *entry = [[IRSkippedKeyEntry alloc] initWithMessageKey:messageKey
                                                                    dhPublic:dhPublic
                                                                           N:N
                                                                insertedAtMs:nowMs];
    if (entry == nil) {
        return NO;
    }

    /* A store key that is already present supersedes rather than duplicates. Unreachable from one
       SkipMessageKeys call — Nr strictly increases while DHr is fixed — but reachable across calls
       when a peer reuses a ratchet public key, and a duplicate would leave the dictionary and the
       order array disagreeing about `count` forever. */
    IRSkippedKeyEntry *existing = _entriesByStoreKey[entry.storeKey];
    if (existing != nil) {
        [self retireEntry:existing];
    }

    /* §7.6 eviction. A `while` rather than an `if`: MAX_SKIPPED_STORED is also §12.2 rule 5's bound
       on a restored blob, so a store built by a future loader that inserted before checking would
       still be brought back inside the bound here rather than growing without limit. */
    while (_entriesInInsertionOrder.count >= (NSUInteger)kIRMaxSkippedStored) {
        IRSkippedKeyEntry *oldest = _entriesInInsertionOrder.firstObject;
        if (oldest == nil) {
            break;
        }
        [self retireEntry:oldest];
    }

    _entriesByStoreKey[entry.storeKey] = entry;
    [_entriesInInsertionOrder addObject:entry];
    [_derivedInsertions addObject:entry];

    return YES;
}

- (void)removeEntryForDHPublic:(IRX25519Public * _Nonnull)dhPublic
                              N:(uint32_t)N {
    IRSkippedKeyEntry *entry = [self entryForDHPublic:dhPublic N:N];
    if (entry == nil) {
        return;
    }

    [self retireEntry:entry];
}

- (void)dropEntriesExpiredAtTimeMs:(uint64_t)nowMs {
    if (_entriesInInsertionOrder.count == 0) {
        return;
    }

    NSMutableArray<IRSkippedKeyEntry *> *expired = [NSMutableArray array];

    for (IRSkippedKeyEntry *entry in _entriesInInsertionOrder) {
        /* An entry stamped in the future is KEPT. `nowMs - insertedAtMs` on unsigned values would
           underflow to a ~584-million-year age and purge the entire store the first time an
           injected or corrected clock stepped backwards — a silent, total loss of every recoverable
           out-of-order message. §7.6 defines the age as that subtraction; guarding its precondition
           is not a deviation from it. */
        if (entry.insertedAtMs > nowMs) {
            continue;
        }

        const uint64_t age = nowMs - entry.insertedAtMs;
        if (age >= (uint64_t)kIRSkippedTTLMs) {
            [expired addObject:entry];
        }
    }

    for (IRSkippedKeyEntry *entry in expired) {
        [self retireEntry:entry];
    }
}

#pragma mark - Snapshotting

- (IRSkippedKeyStore * _Nonnull)copyForSnapshot {
    IRSkippedKeyStore *copy = [[[self class] alloc] init];

    /* D4: the two CONTAINERS are copied; the entries are immutable and are shared by reference.
       2000 entries is 64 KB of key material, and copying it per received message would be both a
       per-message cost and a second set of secrets to schedule for zeroization. */
    [copy->_entriesByStoreKey addEntriesFromDictionary:_entriesByStoreKey];
    [copy->_entriesInInsertionOrder addObjectsFromArray:_entriesInInsertionOrder];

    /* Deliberately NOT copied. The snapshot's schedule describes what THIS attempt did, so both
       lists start empty. */

    return copy;
}

#pragma mark - Zeroization

- (void)zeroizePendingRemovals {
    for (IRSkippedKeyEntry *entry in _pendingZeroize) {
        [entry zeroize];
    }

    [_pendingZeroize removeAllObjects];
}

- (void)zeroizeDerivedInsertions {
    for (IRSkippedKeyEntry *entry in _derivedInsertions) {
        [entry zeroize];
    }

    [_derivedInsertions removeAllObjects];

    /* The derived entries are also still in the live containers of this (discarded) snapshot. They
       are dropped wholesale rather than left as wiped-but-present objects, so that no lookup can
       ever return an entry whose key is all zeros. */
    [self forgetZeroizedEntries];
}

- (void)zeroizeAll {
    for (IRSkippedKeyEntry *entry in _entriesInInsertionOrder) {
        [entry zeroize];
    }

    for (IRSkippedKeyEntry *entry in _pendingZeroize) {
        [entry zeroize];
    }

    for (IRSkippedKeyEntry *entry in _derivedInsertions) {
        [entry zeroize];
    }

    [_entriesByStoreKey removeAllObjects];
    [_entriesInInsertionOrder removeAllObjects];
    [_pendingZeroize removeAllObjects];
    [_derivedInsertions removeAllObjects];
}

#pragma mark - Internals

+ (NSData * _Nullable)storeKeyForDHPublic:(IRX25519Public * _Nonnull)dhPublic N:(uint32_t)N {
    if (dhPublic == nil || dhPublic.length != kIRLenX25519Public) {
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSkippedMapKey];
    [writer appendData:dhPublic.data];
    [writer appendUInt32BE:N];

    return [writer finishExpectingLength:kIRLenSkippedMapKey error:NULL];
}

/// Remove from the live containers and schedule for the COMMIT-time wipe. The single exit an entry
/// has from this store, so removal, eviction, TTL expiry and supersession cannot drift apart.
- (void)retireEntry:(IRSkippedKeyEntry * _Nonnull)entry {
    [_entriesByStoreKey removeObjectForKey:entry.storeKey];
    [_entriesInInsertionOrder removeObjectIdenticalTo:entry];
    [_pendingZeroize addObject:entry];
}

- (void)forgetZeroizedEntries {
    NSMutableArray<IRSkippedKeyEntry *> *survivors = [NSMutableArray array];

    for (IRSkippedKeyEntry *entry in _entriesInInsertionOrder) {
        if (entry.isZeroized) {
            [_entriesByStoreKey removeObjectForKey:entry.storeKey];
        } else {
            [survivors addObject:entry];
        }
    }

    [_entriesInInsertionOrder setArray:survivors];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; count = %lu; pending = %lu; derived = %lu>",
            NSStringFromClass([self class]), (void *)self,
            (unsigned long)_entriesInInsertionOrder.count,
            (unsigned long)_pendingZeroize.count,
            (unsigned long)_derivedInsertions.count];
}

@end
