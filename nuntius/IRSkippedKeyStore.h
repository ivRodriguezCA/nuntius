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

/**
 The bounded skipped-message-key store — SPEC §7.6, §7.7, §12.1, §13.3.

 STORE KEY: the raw 36-byte tuple `DHr_pub (32) ‖ uint32_be(N) (4)`, wrapped in an NSData whose
 -hash and -isEqual: are content-based. §7.6 names v3's `base64(pk) + "|" + decimal(N)` composite as
 the thing not to do: it costs an encoding round-trip per lookup on a hot path and is not injective
 if a component could ever contain the separator.

 THREE ZEROIZATION ENTRY POINTS, AND CHOOSING WRONG BREAKS A REQUIRED VECTOR EACH WAY. This is the
 subtlest part of the layer, so it is stated once, here, in full.

 A snapshot store (§7.7) SHARES its IRSkippedKeyEntry objects with the live store — the entries are
 immutable and there may be 2000 of them, so -copyForSnapshot duplicates the two CONTAINERS and not
 the 64 KB of key material. That sharing is what forces the three-way split, because "who else still
 points at this key?" now has three different answers:

   -zeroizePendingRemovals   COMMIT ONLY. Entries this store REMOVED, EVICTED or EXPIRED. They were
                             inherited from the live store, which still references them, so wiping
                             at removal time would destroy a live key. Once the snapshot commits,
                             the state that referenced them is superseded and the wipe is correct.
                             This is §13.3's "skipped message keys: on use, on eviction, and on TTL
                             expiry" — deferred to the only instant at which it is true.

   -zeroizeDerivedInsertions DISCARD ONLY. Entries this store INSERTED — derived during a decrypt
                             attempt that then failed. Nothing else references them and §7.7
                             requires that "every intermediate secret derived during the attempt
                             MUST be zeroized". Note it deliberately does NOT touch the removals:
                             on the discard path the live store still owns those, and wiping them
                             is exactly the `NEG-SKIP-RETAIN` failure.

   -zeroizeAll               TEARDOWN ONLY. Everything. Correct only when no other store shares
                             these entries — i.e. on a live store whose session is being destroyed.

 The plan specified only the first and the last. -zeroizeDerivedInsertions is an addition: without
 it, a failed decrypt that had already skipped forward leaves those derived keys resident, which
 §7.7's final sentence forbids and which no round-trip test observes.

 EVICTION IS BY INSERTION ORDER, NOT BY TIMESTAMP. §7.6 says "a single global FIFO ordered by
 insertion", and the distinction is observable: `now_ms` is injectable (§15.5 rule 6) and a host
 clock can move backwards, so the oldest `inserted_at_ms` and the oldest insertion are not always
 the same entry. The insertion-ordered array is the authority; the timestamp is used only for TTL.
 That array is also §12.1's serialization order, so the two are one mechanism rather than two.

 `skip_budget` IS DELIBERATELY NOT HERE. §7.6 makes it per-received-message and explicitly not
 persisted; it lives in IRSkipBudget (IRRatchetState.h) and is created once per received message.
 */

#pragma mark - IRSkippedKeyEntry

/**
 One stored key. IMMUTABLE, and shared by reference between a live store and its snapshots — which
 is why it has no setters and why -zeroize is routed through the store's three-way schedule above
 rather than being called directly by protocol code.
 */
@interface IRSkippedKeyEntry : NSObject

/// The peer ratchet public the key was derived under — §7.6's `state.DHr` at insertion time, which
/// is NOT necessarily the session's current `DHr` once a ratchet has happened.
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull dhPublic;

/// The message number within that chain.
@property (nonatomic, readonly) uint32_t N;

/// The 32-byte message key. NOT the expanded enc_key — §8.1's KDF_MK runs at use time, on both the
/// skipped-key path and the ordinary path.
@property (nonatomic, strong, readonly) IRMessageKey * _Nonnull messageKey;

/// Unix milliseconds at insertion, from the §15.5 rule 6 time source. §12.1 stores it verbatim so a
/// restored session's TTL continues to run rather than restarting.
@property (nonatomic, readonly) uint64_t insertedAtMs;

/// The 36-byte `dhPublic ‖ uint32_be(N)` tuple — the store key, and §12.1's entry prefix.
@property (nonatomic, copy, readonly) NSData * _Nonnull storeKey;

/// YES once the key has been wiped. Reading a zeroized entry is a defect, not a recoverable state,
/// so IRRatchet treats it as IRErrorStateCorrupt rather than as a cache miss.
@property (nonatomic, readonly) BOOL isZeroized;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRSkippedKeyStore

@interface IRSkippedKeyStore : NSObject

/// An empty store.
+ (instancetype _Nonnull)store;

#pragma mark - Lookup

/// §7.9 phase 3a — `store_key = hdr.dh ‖ uint32_be(hdr.N)`. Note the lookup uses the HEADER's
/// ratchet key, never the session's current `DHr`: that is what lets a key skipped in a previous
/// chain still be found after the ratchet has moved on.
- (IRSkippedKeyEntry * _Nullable)entryForDHPublic:(IRX25519Public * _Nonnull)dhPublic
                                                N:(uint32_t)N;

/// Number of live entries. Never exceeds `MAX_SKIPPED_STORED` (2000).
@property (nonatomic, readonly) NSUInteger count;

/// Insertion order — §7.6's FIFO order and §12.1's serialization order, which are the same list.
- (NSArray<IRSkippedKeyEntry *> * _Nonnull)entriesInInsertionOrder;

#pragma mark - Mutation

/**
 §7.6 — insert, FIFO-evicting the OLDEST BY INSERTION first when the store is at
 `MAX_SKIPPED_STORED`. FIFO rather than LRU because LRU would require specifying access-time
 semantics identically across four languages.

 `atTimeMs` is the §15.5 rule 6 time source, and it is a parameter rather than an ambient clock read
 so that nothing in this layer can drift when §15.6's ten-years-forward run moves the clock.

 An insert whose store key already exists supersedes the old entry: the old one goes to the pending
 list (never wiped in place — a snapshot may share it) and the new one takes a fresh position at the
 tail. SkipMessageKeys cannot produce a collision on its own, since `Nr` strictly increases while
 `DHr` is fixed within one call — but a peer that REUSES a ratchet public key it has already used
 drives §7.9 phase 3b to ratchet back onto that key and re-derive over the same `(DHr, N)` range, so
 the case is reachable from the network and must not corrupt the ordering.

 Returns NO on allocation failure only.
 */
- (BOOL)insertMessageKey:(IRMessageKey * _Nonnull)messageKey
                dhPublic:(IRX25519Public * _Nonnull)dhPublic
                       N:(uint32_t)N
                atTimeMs:(uint64_t)nowMs;

/**
 §7.9 phase 3a — removal AFTER a successful AEAD, never before.

 v3 called `removeObjectForKey:` at IRDoubleRatchetService.m:168 and `aeDecryptData:` at :170, in
 that order, so a message that failed to decrypt permanently destroyed the only copy of its key and
 the message became unrecoverable. `NEG-SKIP-RETAIN` is the vector; the ordering is normative.

 The entry is moved to the pending list, NOT wiped — see the class comment.
 */
- (void)removeEntryForDHPublic:(IRX25519Public * _Nonnull)dhPublic
                              N:(uint32_t)N;

/**
 §7.6 / §12.2 rule 9 — drop entries whose age exceeds `SKIPPED_TTL_MS` (7 days), measured as
 `nowMs - insertedAtMs` against the §15.5 rule 6 time source. Required "on every state load and on
 every ratchet step"; §7.9 phase 2 additionally runs it on every decrypt.

 An entry whose `insertedAtMs` lies in the FUTURE relative to `nowMs` is kept rather than dropped.
 Unsigned subtraction of a larger value would underflow to an enormous age and silently purge the
 whole store the first time an injected or corrected clock moved backwards.

 Dropped entries go to the pending list, so a snapshot that is later discarded has not destroyed
 anything the live store still holds.
 */
- (void)dropEntriesExpiredAtTimeMs:(uint64_t)nowMs;

#pragma mark - Snapshotting (§7.7)

/**
 A store that shares every entry object with the receiver — O(n) pointer copies, not O(n) key
 copies. The returned store's pending and derived lists start empty, so its zeroization schedule
 describes only what THIS decrypt attempt did.
 */
- (IRSkippedKeyStore * _Nonnull)copyForSnapshot;

#pragma mark - Zeroization (§13.3) — read the class comment before choosing one

/// COMMIT path. Wipes entries removed, evicted or expired since -copyForSnapshot.
- (void)zeroizePendingRemovals;

/// DISCARD path. Wipes entries INSERTED since -copyForSnapshot, and nothing else.
- (void)zeroizeDerivedInsertions;

/// TEARDOWN path. Wipes every entry this store can reach. MUST NOT be called on a snapshot.
- (void)zeroizeAll;

@end
