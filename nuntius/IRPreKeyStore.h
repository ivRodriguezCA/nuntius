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
#import <nuntius/IRIdentity.h>
#import <nuntius/IRPreKeyRecords.h>

/**
 The responder's prekey store — SPEC §5.3, §5.6, §6.6, §7.5, §13.3.

 THE WRITE PATH IS PART OF THE PROTOCOL. A read-only store cannot discharge §5.3's retention rule,
 and a host that can publish a bundle but cannot express which keys it has retained will publish one
 it can never decrypt against.

 THIS STORE HOLDS EVERY INPUT TO EVERY FUTURE HANDSHAKE, which is why §5.6 makes its at-rest sealing
 normative rather than advisory: an adversary who images the device at t0, goes passive, and records
 A's handshake at t1 > t0 computes DH1, DH2 and DH3 directly from SPK_B_priv and the identity
 privates, and needs only DH4 — whose private half is the unconsumed OPK sitting in this same store.
 A session blob compromises one session; this store compromises all of them. Only the §12.1 session
 blob layout is byte-normative — this store's internal format is deliberately unspecified, because
 no peer ever observes it, and that is precisely why it is easy to leave unsealed.

 EVERY CLOCK VALUE IS A PARAMETER, NEVER A READ. A store that consults an ambient clock cannot honour
 §15.5 rule 6's single injectable time source, and §15.6's ten-years-forward CI run would fail on
 `NEG-OPK-EXPIRED` alone.

 NOTE ON ERR_OPK_ALREADY_CONSUMED (7115). It is UNREACHABLE as specified and this store never emits
 it. §6.6 step 4 requires the consumed entry be zeroized and unlinked, and no section requires a
 per-opk_id tombstone, so after consumption a used OPK is byte-indistinguishable from one that never
 existed. Both resolve to ERR_UNKNOWN_PREKEY_ID. Raised as plan gap G1.
 */
@protocol IRPreKeyStore <NSObject>

#pragma mark - Write and lifecycle

/**
 Stores a signed prekey.

 `makeCurrent` = YES promotes `record` to current and demotes the existing current to previous,
 zeroizing whatever leaves the {current, one previous} set. = NO writes the PREVIOUS slot directly,
 which is the shape a restore-from-storage path needs when it loads both generations.

 §5.3: the responder MUST retain the private key of the current and EXACTLY ONE previous signed
 prekey, so that messages already in flight against a just-rotated `spk_id` still decrypt.
 */
- (BOOL)storeSignedPreKeyRecord:(IRSignedPreKeyRecord * _Nonnull)record
                    makeCurrent:(BOOL)makeCurrent
                          error:(NSError * _Nullable * _Nullable)error;

/// Adds one-time prekeys. An `opk_id` already present is REPLACED, and the displaced record's
/// private half is zeroized in place.
- (BOOL)storeOneTimePreKeyRecords:(NSArray<IROneTimePreKeyRecord *> * _Nonnull)records
                            error:(NSError * _Nullable * _Nullable)error;

/// The signed prekey a freshly published bundle should advertise, or nil if none has been stored.
- (IRSignedPreKeyRecord * _Nullable)currentSignedPreKeyRecord;

/// The one retained previous generation, or nil. Exposed because §5.3's retention rule is otherwise
/// unobservable, and `NEG-SPK-SURVIVES-RATCHET` (§15.4) is written against it.
- (IRSignedPreKeyRecord * _Nullable)previousSignedPreKeyRecord;

/**
 Up to `limit` unconsumed, unexpired one-time prekeys in insertion order, for publishing.

 Expired entries are swept before the list is taken, so this method can never hand back an OPK that
 §5.3 required be deleted. `limit` is a maximum and 0 yields an empty array; pass NSUIntegerMax for
 every available record.
 */
- (NSArray<IROneTimePreKeyRecord *> * _Nonnull)
    unconsumedOneTimePreKeyRecordsWithLimit:(NSUInteger)limit
                              atUnixSeconds:(uint64_t)nowS;

#pragma mark - Resolution

/**
 §5.3 — resolves ONLY within the {current, exactly one previous} set. Anything else, including an
 `spk_id` that was valid two rotations ago, is ERR_UNKNOWN_PREKEY_ID.

 NO VALIDITY-WINDOW CHECK HAPPENS HERE, deliberately. The window is the INITIATOR's check against
 the bundle (§5.3 rules 5–6); a responder that additionally rejected a just-expired `spk_id` at
 resolution time would drop messages legitimately sent moments before expiry. Retention policy is
 enforced by -pruneExpiredAtUnixSeconds:error:, and a pruned key is simply unknown.

 THE CALLER MUST -deepCopy the returned key pair before it reaches ratchet state (§7.5, §19.1). This
 store owns `SPK_B_priv` exclusively and §5.3 says no ratchet operation may shorten its lifetime.
 */
- (IRSignedPreKeyRecord * _Nullable)signedPreKeyRecordForId:(uint32_t)spkId
                                                      error:(NSError * _Nullable * _Nullable)error;

/**
 §5.3, §6.6 step 2 — resolves an `opk_id`, or ERR_UNKNOWN_PREKEY_ID.

 An entry older than OPK_MAX_AGE_S is deleted and zeroized here before the lookup, so an expired id
 resolves exactly as an unknown one does. That gives `NEG-OPK-EXPIRED` (§15.4) a single
 implementation point, and it is why this method takes a clock while the signed-prekey resolver does
 not.

 §6.6 step 2 is emphatic that absence is a HARD FAILURE: "There is no fallback to the 3-DH
 derivation. Rejecting rather than falling back is what converts OPK consumption into replay
 protection, and it forecloses a downgrade an implementer would otherwise be tempted to add."
 */
- (IROneTimePreKeyRecord * _Nullable)oneTimePreKeyRecordForId:(uint32_t)opkId
                                                atUnixSeconds:(uint64_t)nowS
                                                        error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Consumption

/**
 §6.6 step 4 + §13.3 — zeroize the scalar IN PLACE, THEN unlink, THEN durably commit, in that order.

 An unlink alone is NOT sufficient: -removeObjectForKey:, Map.remove and a Swift subscript
 assignment to nil all release the reference and leave the scalar resident in the heap. Rule 4 as
 originally worded is a persistence-ordering requirement; the in-place wipe is the memory-hygiene
 requirement, and both are MUSTs.

 MUST NOT return until the commit is durable. §10.7 step 14 returns the decrypted plaintext
 immediately after this call, and a crash in between reopens the replay window that §6.6 rule 2
 exists to close.

 Callable only on the AEAD-SUCCESS path. §10.7 step 13 is explicit that an AEAD failure must discard
 the snapshot, not commit the session, and NOT delete the one-time prekey.
 */
- (BOOL)consumeOneTimePreKeyId:(uint32_t)opkId
                         error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Maintenance

/**
 Generates a new signed prekey, signs it with `identity` (§5.2), and promotes it to current.

 Returns the new record so the caller can publish a bundle from it directly; nil on failure.
 */
- (IRSignedPreKeyRecord * _Nullable)rotateSignedPreKeyWithIdentity:(IRIdentity * _Nonnull)identity
                                                             spkId:(uint32_t)spkId
                                                        notBeforeS:(uint64_t)notBeforeS
                                                         notAfterS:(uint64_t)notAfterS
                                                          provider:(id<IRCryptoProvider> _Nonnull)provider
                                                             error:(NSError * _Nullable * _Nullable)error;

/**
 §5.3, §13.3 — zeroizes in place and drops: signed prekeys whose `not_after` has passed, and
 one-time prekeys older than OPK_MAX_AGE_S.

 §13.3 makes `not_after` the LATEST moment an SPK private may be retained, which is why this applies
 to the current generation too and not only to the previous one. A store left with no current signed
 prekey is the intended pressure to rotate, not a failure.
 */
- (BOOL)pruneExpiredAtUnixSeconds:(uint64_t)nowS
                            error:(NSError * _Nullable * _Nullable)error;

@end
