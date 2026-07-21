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
#import <nuntius/IRSealedStore.h>
#import <nuntius/IRSessionStore.h>

#pragma mark - IRSessionRecordStorage

/**
 Where sealed session records live — the host's half of §12.3.

 §12.3 makes the CONSTRUCTION normative and the STORAGE explicitly not: "Keystore selection,
 rotation, and behaviour on device migration are deliberately outside this document's
 byte-compatible surface — only the plaintext layout is normative." This protocol is that boundary
 drawn in the type system. Everything above it — serialize, seal, the §12.5 comparison, the two
 §11.1 indices — is the library's and is identical for every host. Everything below it is a
 key-value store the host already has: a directory, SQLite, Core Data, a server-side blob.

 EVERY VALUE HANDED TO AN IMPLEMENTATION IS ALREADY SEALED. A conforming store never sees a
 plaintext §12.1 blob, cannot leak one, and needs no zeroization schedule of its own. It does not
 need to be encrypted, backed up, or excluded from backups: the ciphertext is inert without the
 keystore key, which is the property §12.3 is built to give.

 Tombstones (§11.4) are stored alongside because they must outlive the record they refer to, for
 `HANDSHAKE_CACHE_MS`. A tombstone is a handshake id and a timestamp; both are public.
 */
@protocol IRSessionRecordStorage <NSObject>

- (NSData * _Nullable)sealedRecordForHandshakeId:(NSData * _Nonnull)handshakeId;
- (NSArray<NSData *> * _Nonnull)allHandshakeIds;

- (BOOL)storeSealedRecord:(NSData * _Nonnull)sealed
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error;

- (BOOL)removeRecordForHandshakeId:(NSData * _Nonnull)handshakeId
                             error:(NSError * _Nullable * _Nullable)error;

/// §11.4 — writes the teardown instant. Overwrites any existing entry for the same id.
- (BOOL)storeTombstoneAtTimeMs:(uint64_t)nowMs
                forHandshakeId:(NSData * _Nonnull)handshakeId
                         error:(NSError * _Nullable * _Nullable)error;

/// YES when a tombstone exists, writing its recorded millisecond to `outTimeMs`. The WINDOW is
/// applied by the caller, not here — an implementation stores what it is told and reads it back.
- (BOOL)tombstoneTimeMs:(uint64_t * _Nonnull)outTimeMs
         forHandshakeId:(NSData * _Nonnull)handshakeId;

- (NSArray<NSData *> * _Nonnull)allTombstoneHandshakeIds;

- (BOOL)removeTombstoneForHandshakeId:(NSData * _Nonnull)handshakeId
                                error:(NSError * _Nullable * _Nullable)error;

@end

/**
 An IRSessionRecordStorage backed by a dictionary — for tests and for the conformance suite.

 Deliberately the only implementation shipped. A durable one is a dozen lines over whatever
 key-value store the host already uses, and writing a file-system one here would bake in choices
 §12.3 says are the host's: where the container directory goes, what file protection class applies,
 how migration behaves, whether it is excluded from backups. The seam exists so those stay yours.
 */
@interface IRInMemorySessionRecordStorage : NSObject <IRSessionRecordStorage>

+ (instancetype _Nonnull)storage;

@property (nonatomic, readonly) NSUInteger recordCount;
@property (nonatomic, readonly) NSUInteger tombstoneCount;

@end

#pragma mark - IRSealedSessionStore

/**
 The production IRSessionStore — SPEC §11.1, §11.1.1, §11.4, §12.1, §12.3, §12.5.

 IRInMemorySessionStore's routing rules over §12.1 blobs sealed per §12.3, with §12.5's rollback
 tripwire on the load path. The §11 behaviour is identical by construction: both stores implement
 the same protocol and the collapse comparison lives in IRSessionDispatch, so a conformance vector
 passes or fails the same way against either.

 LIVE OBJECTS ARE CACHED, AND THAT IS PART OF THE CONTRACT. -sessionForHandshakeId: returns the
 SAME IRSession instance across calls, because a caller holds the handle across a snapshot, a
 decrypt and a commit — and because §11.5's "no trial decryption" is enforced by there being one
 session per peer, which a store minting a fresh object per lookup would quietly break.

 §12.5 ON LOAD. A record whose blob carries a `send_counter` BELOW the tripwire's high-water mark
 has been rolled back. It is NOT indexed: every lookup misses, which is §12.5's "refuse to encrypt
 on that session... requiring a fresh handshake" expressed as unavailability rather than as an error
 a caller might ignore. -rolledBackHandshakeIds and -hasRollbackForHandshakeId: report which, so a
 host can surface IRErrorStateRollback to its user rather than an unexplained missing session.

 A RECORD THAT WILL NOT OPEN OR WILL NOT PARSE IS SKIPPED, not fatal, and is listed in
 -unloadableHandshakeIds. Failing construction on one corrupt record would take every other session
 down with it; skipping costs one session, which the peer's next handshake replaces. §12.2's "no
 partially-loaded state" is about a single blob and is honoured strictly — the codec builds nothing
 until every rule passes.
 */
@interface IRSealedSessionStore : NSObject <IRSessionStore>

/**
 `tripwire` is REQUIRED, and IRDisabledRollbackTripwire is how a host declines it. §12.5 is a
 SHOULD, so declining is legitimate — but it has to be said out loud, because the alternative
 failure mode is a tripwire stored in a backup that a restore rolls back along with the state,
 which looks like protection and is not (§17.2).
 */
+ (instancetype _Nullable)storeWithSealedStore:(IRSealedStore * _Nonnull)sealedStore
                                       storage:(id<IRSessionRecordStorage> _Nonnull)storage
                              rollbackTripwire:(id<IRRollbackTripwire> _Nonnull)tripwire
                                         error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IRSealedStore * _Nonnull sealedStore;
@property (nonatomic, strong, readonly) id<IRSessionRecordStorage> _Nonnull storage;
@property (nonatomic, strong, readonly) id<IRRollbackTripwire> _Nonnull rollbackTripwire;

/**
 Opens, parses and indexes every stored record. MUST be called before the store is used; until it
 is, every lookup misses.

 `nowMs` is the §15.5 rule 6 injectable time source and drives §12.2 rule 9's TTL sweep, so a
 restored session drops skipped keys older than `SKIPPED_TTL_MS` on the way in rather than carrying
 them forward.

 Idempotent: a second call re-reads storage and re-indexes, keeping the cached IRSession instance
 for any handshake id already live so that handles a caller holds stay valid.

 RETURNS NO ONLY WHEN THE TRIPWIRE COULD NOT BE READ, with IRErrorStateRollback. Per-record
 failures — a record that will not unseal, will not parse, is filed under the wrong id, or is
 genuinely rolled back — are reported through -unloadableHandshakeIds and -rolledBackHandshakeIds
 and do NOT fail the load, because one bad blob must not cost every other session. A tripwire read
 failure is different in kind: it is environmental (device rebooted and never unlocked; keychain
 group changed), it excludes EVERY session, and it is the case §12.5 would otherwise fail open on.
 The store is still usable after a NO — the sessions that loaded are indexed — but a host that
 ignores the return will see an empty store with no explanation.
 */
- (BOOL)loadAtTimeMs:(uint64_t)nowMs
               error:(NSError * _Nullable * _Nullable)error;

/// Records skipped at the last -loadAtTimeMs:error: because they would not open or would not
/// parse. Empty on a clean load.
@property (nonatomic, copy, readonly) NSArray<NSData *> * _Nonnull unloadableHandshakeIds;

/// §12.5 — records excluded at the last load because their `send_counter` was below the recorded
/// high-water mark, OR because the tripwire could not be read and the comparison therefore could
/// not be performed. Both exclusions have the same remedy — a fresh handshake — and the second is
/// additionally reported through this method's `error` out-parameter, since it is not a fact about
/// the record.
@property (nonatomic, copy, readonly) NSArray<NSData *> * _Nonnull rolledBackHandshakeIds;

/// §12.5 — YES when this handshake id was excluded as rolled back. A host SHOULD surface
/// IRErrorStateRollback rather than reporting an absent session.
- (BOOL)hasRollbackForHandshakeId:(NSData * _Nonnull)handshakeId;

/// Live sessions currently indexed.
@property (nonatomic, readonly) NSUInteger sessionCount;

/// §13.3 — zeroizes every cached session and drops the caches. Leaves the sealed records and the
/// tombstones in storage: they are ciphertext and public timestamps respectively, and dropping the
/// tombstones would reopen §17.3's replay window.
- (void)zeroizeAll;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
