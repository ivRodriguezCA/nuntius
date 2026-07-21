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

#import <XCTest/XCTest.h>

#import "IRCryptoProvider.h"
#import "IRErrors.h"
#import "IRIdentity.h"
#import "IRInMemorySessionStore.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageBuilder.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSealedSessionStore.h"
#import "IRSealedStore.h"
#import "IRSecretBytes.h"
#import "IRSession+Internal.h"
#import "IRSessionAD.h"
#import "IRSessionDispatch.h"
#import "IRSessionStateCodec.h"
#import "IRSessionStore.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

/**
 LAYER 9 GATE (§11 and §12's composition) — SPEC §11.1, §11.1.1, §11.2, §11.4, §11.5, §12.3, §12.5.

 Named rows covered: SESSION-COLLAPSE, NEG-HANDSHAKE-TOMBSTONE, NEG-IKB-RETRANS,
 NEG-PUBKEY-REFLECT-02-DHS.

 SESSIONS ARE BUILT FROM LITERAL STATE BLOBS wherever the test is about routing rather than about
 cryptography. §11.1.1's collapse is a comparison of two 64-byte public values and §11.4's tombstone
 is a timestamp; running a full X3DH to reach them would make the test slower, less precise about
 which `handshake_id`s are being compared, and no more faithful. The §11.2 tests DO use real
 identities, because check 2 is an Ed25519 verification and a synthetic binding would verify
 nothing.
 */

#pragma mark - Literal state-blob construction

static void IRLFillPattern(uint8_t *buffer, NSUInteger length, uint8_t seed) {
    for (NSUInteger i = 0; i < length; i++) {
        buffer[i] = (uint8_t)((seed * 31u) + (i * 7u) + 1u);
    }
}

static NSData *IRLDataWithPattern(NSUInteger length, uint8_t seed) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    IRLFillPattern((uint8_t *)data.mutableBytes, length, seed);

    return data;
}

/**
 A structurally valid §12.1 blob whose `handshake_id`, SESSION_AD identity pairs and `DHs_pub` are
 all caller-supplied — the four values every §11 rule is expressed over.
 */
static NSMutableData *IRLSessionBlob(uint8_t role,
                                     NSData *handshakeId,
                                     NSData *initiatorPair,
                                     NSData *responderPair,
                                     NSData *dhsPublic,
                                     uint64_t sendCounter) {
    NSMutableData *blob = [NSMutableData dataWithLength:(NSUInteger)kIRLenStatePrefix];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    memcpy(raw + kIROffStateMagic, kIRStateMagic, (size_t)kIRLenMagic);
    raw[kIROffStateFormat] = (uint8_t)kIRStateFormat;
    raw[kIROffStateRole] = role;

    memcpy(raw + kIROffStateSessionAD, kIRLabelAD, (size_t)kIRLenLabelAD);
    memcpy(raw + kIROffStateInitiatorSigning, initiatorPair.bytes, (size_t)kIRLenIdentityPair);
    memcpy(raw + kIROffStateResponderSigning, responderPair.bytes, (size_t)kIRLenIdentityPair);
    memcpy(raw + kIROffStateHandshakeId, handshakeId.bytes, (size_t)kIRLenHandshakeId);

    IRLFillPattern(raw + kIROffStateRK, kIRLenRootKey, 66);

    IRLFillPattern(raw + kIROffStateDHsPriv, kIRLenX25519Private, 77);
    raw[kIROffStateDHsPriv] &= 0xF8;
    raw[kIROffStateDHsPriv + 31] &= 0x7F;
    raw[kIROffStateDHsPriv + 31] |= 0x40;

    memcpy(raw + kIROffStateDHsPub, dhsPublic.bytes, (size_t)kIRLenX25519Public);

    raw[kIROffStateDHrPresent] = 0x01;
    IRLFillPattern(raw + kIROffStateDHrPub, kIRLenX25519Public, 99);
    raw[kIROffStateDHrPub + 31] &= 0x7F;

    raw[kIROffStateCKsPresent] = 0x01;
    IRLFillPattern(raw + kIROffStateCKs, kIRLenChainKey, 110);

    raw[kIROffStateCKrPresent] = 0x01;
    IRLFillPattern(raw + kIROffStateCKr, kIRLenChainKey, 121);

    for (NSUInteger i = 0; i < 8; i++) {
        raw[kIROffStateSendCounter + i] = (uint8_t)((sendCounter >> (8 * (7 - i))) & 0xFF);
    }

    return blob;
}

#pragma mark - A tripwire whose backing store will not read

/**
 Models the §12.5 Keychain condition that has no in-process analogue: the item is THERE, and
 SecItemCopyMatching still will not return it.

 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — which §12.5 mandates by name — returns
 errSecInteractionNotAllowed (-25308) when the device has been rebooted and not yet unlocked once,
 and errSecMissingEntitlement (-34018) after a keychain-access-group or provisioning change. Both
 are transient and the first is attacker-influenceable: forcing a reboot is enough.

 The point of the double is that this is NOT the same fact as "no record recorded", and the
 difference is invisible to the caller unless the read reports it. IRInMemoryRollbackTripwire cannot
 model it — a dictionary lookup does not fail — which is precisely why the fail-open bug survived
 in the Keychain implementation while every test passed.
 */
@interface IRLUnreadableRollbackTripwire : NSObject <IRRollbackTripwire>
@property (nonatomic, assign) BOOL readsFail;
@property (nonatomic, assign) NSUInteger readAttempts;
@end

@implementation IRLUnreadableRollbackTripwire {
    NSMutableDictionary<NSData *, NSNumber *> *_counters;
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _counters = [NSMutableDictionary dictionary];
        _readsFail = YES;
    }

    return self;
}

- (BOOL)lastObservedSendCounter:(uint64_t * _Nonnull)outSendCounter
                 forHandshakeId:(NSData * _Nonnull)handshakeId
                          error:(NSError * _Nullable * _Nullable)error {
    _readAttempts++;

    if (outSendCounter != NULL) {
        *outSendCounter = 0;
    }

    if (_readsFail) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (outSendCounter != NULL) {
        *outSendCounter = _counters[handshakeId].unsignedLongLongValue;
    }

    return YES;
}

- (BOOL)recordSendCounter:(uint64_t)sendCounter
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    (void)error;
    _counters[[handshakeId copy]] = @(sendCounter);

    return YES;
}

- (BOOL)forgetHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    (void)error;
    [_counters removeObjectForKey:handshakeId];

    return YES;
}

@end

@interface IRSessionLifecycleSpec : XCTestCase
@end

@implementation IRSessionLifecycleSpec {
    IRSodiumCryptoProvider *_provider;
    IRIdentity *_alice;
    IRIdentity *_bob;
    IRIdentity *_mallory;
}

- (void)setUp {
    [super setUp];

    NSError *error = nil;
    XCTAssertTrue([IRSodium ensureInitialized:&error], @"%@", error);

    _provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(_provider, @"%@", error);

    _alice = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_alice, @"%@", error);
    _bob = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_bob, @"%@", error);
    _mallory = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_mallory, @"%@", error);
}

#pragma mark - Helpers

- (NSData *)handshakeIdWithFirstByte:(uint8_t)first seed:(uint8_t)seed {
    NSMutableData *hid = [NSMutableData dataWithLength:(NSUInteger)kIRLenHandshakeId];
    IRLFillPattern((uint8_t *)hid.mutableBytes, hid.length, seed);
    ((uint8_t *)hid.mutableBytes)[0] = first;

    return hid;
}

- (NSData *)freshX25519Public {
    NSError *error = nil;
    IRX25519KeyPair *pair = [_provider generateX25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(pair, @"%@", error);

    return pair.publicKey.data;
}

- (IRSession *)sessionWithRole:(uint8_t)role
                   handshakeId:(NSData *)handshakeId
                 initiatorPair:(NSData *)initiatorPair
                 responderPair:(NSData *)responderPair
                        dhsPub:(NSData *)dhsPublic
                   sendCounter:(uint64_t)sendCounter {
    NSData *blob = IRLSessionBlob(role, handshakeId, initiatorPair, responderPair,
                                  (dhsPublic != nil ? dhsPublic : [self freshX25519Public]),
                                  sendCounter);

    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:1000
                                                                    error:&error];
    XCTAssertNotNil(state, @"%@", error);

    IRSession *session = [IRSession sessionWithState:state error:&error];
    XCTAssertNotNil(session, @"%@", error);

    return session;
}

/// A responder-role session with Alice as initiator and Bob as responder, so its peer is Alice.
- (IRSession *)responderSessionWithHandshakeId:(NSData *)handshakeId dhsPub:(NSData *)dhsPublic {
    return [self sessionWithRole:0x02
                     handshakeId:handshakeId
                   initiatorPair:_alice.identityKeyPair.rawPair
                   responderPair:_bob.identityKeyPair.rawPair
                          dhsPub:dhsPublic
                     sendCounter:0];
}

#pragma mark - §11.1 — the two indices

- (void)testSessionExposesBothIndexKeysFromTheStoredSessionAD {
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    XCTAssertEqualObjects(session.handshakeId, hid);
    XCTAssertEqual(session.role, IRSessionRoleResponder);

    /* §6.5 — the peer pair is SESSION_AD[13..77) when role == responder. Neither identity key is
       duplicated elsewhere in the blob, so this is the only record of them. */
    XCTAssertTrue([session.peerIdentityKeyPair isEqualToIdentityKeyPair:_alice.identityKeyPair]);
    XCTAssertTrue([session.ownIdentityKeyPair isEqualToIdentityKeyPair:_bob.identityKeyPair]);
}

- (void)testInitiatorRoleReadsThePeerFromTheOtherHalfOfSessionAD {
    IRSession *session = [self sessionWithRole:0x01
                                   handshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                 initiatorPair:_alice.identityKeyPair.rawPair
                                 responderPair:_bob.identityKeyPair.rawPair
                                        dhsPub:nil
                                   sendCounter:0];

    /* A port that recomputes SESSION_AD as (self, peer) rather than (initiator, responder)
       "will interoperate with itself and with nothing else" (§6.5). The role byte is what makes
       the same 141 bytes mean opposite things on the two sides. */
    XCTAssertTrue([session.peerIdentityKeyPair isEqualToIdentityKeyPair:_bob.identityKeyPair]);
    XCTAssertTrue([session.ownIdentityKeyPair isEqualToIdentityKeyPair:_alice.identityKeyPair]);
}

- (void)testStoreIndexesBySessionIdAndByPeer {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    NSError *error = nil;
    XCTAssertNotNil([store establishSession:session atTimeMs:1000 error:&error], @"%@", error);

    XCTAssertEqual([store sessionForHandshakeId:hid], session);
    XCTAssertEqual([store sessionForPeerIdentityKeyPair:_alice.identityKeyPair], session);
    XCTAssertEqual(store.sessionCount, (NSUInteger)1);

    XCTAssertNil([store sessionForHandshakeId:[self handshakeIdWithFirstByte:0x99 seed:9]]);
    XCTAssertNil([store sessionForPeerIdentityKeyPair:_mallory.identityKeyPair]);
    XCTAssertNil([store sessionForHandshakeId:[NSData dataWithBytes:"short" length:5]]);
}

- (void)testStoreLookupReturnsTheSameInstanceEveryTime {
    /* A caller holds the handle across snapshot → decrypt → commit. A store minting a fresh object
       per lookup would silently break §11.5 rule 3's premise that there IS one session. */
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];
    [store establishSession:session atTimeMs:1000 error:NULL];

    XCTAssertEqual([store sessionForHandshakeId:hid], [store sessionForHandshakeId:hid]);
    XCTAssertEqual([store sessionForHandshakeId:hid],
                   [store sessionForPeerIdentityKeyPair:_alice.identityKeyPair]);
}

#pragma mark - §11.1.1 — the comparator

- (void)testHandshakeIdComparisonIsUNSIGNEDBigEndian {
    /* THE JVM TRAP, made explicit. `byte` is signed on the JVM, so a naive loop compares 0x80 as
       -128 and picks the opposite survivor. Because both sides must converge on the SAME survivor
       from identical public data, one port getting this backwards diverges the two sides
       PERMANENTLY rather than failing loudly. */
    NSData *high = [self handshakeIdWithFirstByte:0x80 seed:1];
    NSData *low = [self handshakeIdWithFirstByte:0x7F seed:1];

    NSComparisonResult order = NSOrderedSame;
    XCTAssertTrue(IRCompareHandshakeIds(high, low, &order));
    XCTAssertEqual(order, NSOrderedDescending, @"0x80… is GREATER than 0x7F…");

    XCTAssertTrue(IRCompareHandshakeIds(low, high, &order));
    XCTAssertEqual(order, NSOrderedAscending);
}

- (void)testHandshakeIdComparisonIsDecidedByTheFirstDifferingByte {
    NSMutableData *a = [[self handshakeIdWithFirstByte:0x40 seed:1] mutableCopy];
    NSMutableData *b = [a mutableCopy];
    ((uint8_t *)b.mutableBytes)[17] = (uint8_t)(((const uint8_t *)a.bytes)[17] + 1);

    NSComparisonResult order = NSOrderedSame;
    XCTAssertTrue(IRCompareHandshakeIds(a, b, &order));
    XCTAssertEqual(order, NSOrderedAscending);
}

- (void)testHandshakeIdComparisonRefusesWrongLengths {
    NSData *good = [self handshakeIdWithFirstByte:0x40 seed:1];
    NSData *short63 = [good subdataWithRange:NSMakeRange(0, 63)];

    NSComparisonResult order = NSOrderedDescending;
    XCTAssertFalse(IRCompareHandshakeIds(good, short63, &order));
    XCTAssertFalse(IRCompareHandshakeIds(short63, good, &order));
    XCTAssertFalse(IRCompareHandshakeIds(nil, good, &order));

    /* A wrong-length id must NOT default to NSOrderedSame: equality is the one answer that means
       "these are the same session", and defaulting to it would merge two. */
    XCTAssertEqual(order, NSOrderedDescending, @"outResult untouched on refusal");
}

- (void)testEqualHandshakeIdsAreNotACollapse {
    NSData *hid = [self handshakeIdWithFirstByte:0x40 seed:1];
    IRSession *a = [self responderSessionWithHandshakeId:hid dhsPub:nil];
    IRSession *b = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    BOOL incomingWins = NO;
    NSError *error = nil;
    XCTAssertFalse([IRSessionDispatch resolveCollapseForIncomingSession:a
                                                        againstExisting:b
                                                           incomingWins:&incomingWins
                                                                  error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
}

#pragma mark - §11.1.1 — SESSION-COLLAPSE

- (void)testSESSION_COLLAPSE_GreaterHandshakeIdSurvivesAndTheLoserIsTornDown {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];

    NSData *lowId = [self handshakeIdWithFirstByte:0x11 seed:1];
    NSData *highId = [self handshakeIdWithFirstByte:0xF0 seed:2];

    IRSession *low = [self responderSessionWithHandshakeId:lowId dhsPub:nil];
    IRSession *high = [self responderSessionWithHandshakeId:highId dhsPub:nil];

    NSError *error = nil;
    XCTAssertNotNil([store establishSession:low atTimeMs:1000 error:&error], @"%@", error);

    IRSessionEstablishResult *result = [store establishSession:high atTimeMs:2000 error:&error];
    XCTAssertNotNil(result, @"%@", error);

    XCTAssertEqual(result.survivingSession, high);
    XCTAssertTrue(result.incomingSessionSurvived);
    XCTAssertTrue(result.collapseOccurred);
    XCTAssertEqual(result.tornDownSession, low);

    XCTAssertTrue(low.isTornDown);
    XCTAssertFalse(high.isTornDown);

    // §11.1.1's invariant: one live session per peer, counting both roles together.
    XCTAssertEqual(store.sessionCount, (NSUInteger)1);
    XCTAssertEqual([store sessionForPeerIdentityKeyPair:_alice.identityKeyPair], high);
    XCTAssertNil([store sessionForHandshakeId:lowId]);

    // "its handshake_id is retained as a tombstone... so that a retransmission cannot resurrect it"
    XCTAssertTrue([store hasTombstoneForHandshakeId:lowId atTimeMs:2000]);
}

- (void)testSESSION_COLLAPSE_TheINCOMINGSessionCanLoseAndIsTornDownToo {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];

    NSData *lowId = [self handshakeIdWithFirstByte:0x11 seed:1];
    NSData *highId = [self handshakeIdWithFirstByte:0xF0 seed:2];

    IRSession *high = [self responderSessionWithHandshakeId:highId dhsPub:nil];
    IRSession *low = [self responderSessionWithHandshakeId:lowId dhsPub:nil];

    [store establishSession:high atTimeMs:1000 error:NULL];

    NSError *error = nil;
    IRSessionEstablishResult *result = [store establishSession:low atTimeMs:2000 error:&error];
    XCTAssertNotNil(result, @"%@", error);

    /* The session the caller just built LOSES. It still returns the plaintext it decrypted — the
       message authenticated — but it must not keep the handle, which is what this flag says. */
    XCTAssertFalse(result.incomingSessionSurvived);
    XCTAssertEqual(result.survivingSession, high);
    XCTAssertEqual(result.tornDownSession, low);

    XCTAssertTrue(low.isTornDown);
    XCTAssertFalse(high.isTornDown);
    XCTAssertEqual(store.sessionCount, (NSUInteger)1);
    XCTAssertEqual([store sessionForHandshakeId:highId], high);

    // §11.4: "a tombstone is written whenever a session is torn down FOR ANY REASON."
    XCTAssertTrue([store hasTombstoneForHandshakeId:lowId atTimeMs:2000]);
}

- (void)testSESSION_COLLAPSE_BothSidesConvergeOnTheSameSurvivorRegardlessOfArrivalOrder {
    /* THE PROPERTY THE RULE EXISTS FOR. "Newest wins" was rejected because each side observes a
       different arrival order, so it is not a function and the two sides can diverge permanently
       (§19.2). Here the two stores see the two sessions in OPPOSITE orders and must still agree. */
    NSData *idA = [self handshakeIdWithFirstByte:0x11 seed:1];
    NSData *idB = [self handshakeIdWithFirstByte:0xF0 seed:2];

    IRInMemorySessionStore *aliceSide = [IRInMemorySessionStore store];
    [aliceSide establishSession:[self responderSessionWithHandshakeId:idA dhsPub:nil]
                       atTimeMs:1000
                          error:NULL];
    IRSessionEstablishResult *aliceResult =
        [aliceSide establishSession:[self responderSessionWithHandshakeId:idB dhsPub:nil]
                           atTimeMs:1001
                              error:NULL];

    IRInMemorySessionStore *bobSide = [IRInMemorySessionStore store];
    [bobSide establishSession:[self responderSessionWithHandshakeId:idB dhsPub:nil]
                     atTimeMs:1000
                        error:NULL];
    IRSessionEstablishResult *bobResult =
        [bobSide establishSession:[self responderSessionWithHandshakeId:idA dhsPub:nil]
                         atTimeMs:1001
                            error:NULL];

    XCTAssertEqualObjects(aliceResult.survivingSession.handshakeId,
                          bobResult.survivingSession.handshakeId);
    XCTAssertEqualObjects(aliceResult.survivingSession.handshakeId, idB);

    /* And the two sides disagree about whose session it was, which is exactly the asymmetry the
       result object exists to report. */
    XCTAssertTrue(aliceResult.incomingSessionSurvived);
    XCTAssertFalse(bobResult.incomingSessionSurvived);
}

- (void)testDifferentPeersDoNotCollapse {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];

    IRSession *withAlice = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                          dhsPub:nil];
    IRSession *withMallory = [self sessionWithRole:0x02
                                       handshakeId:[self handshakeIdWithFirstByte:0xF0 seed:2]
                                     initiatorPair:_mallory.identityKeyPair.rawPair
                                     responderPair:_bob.identityKeyPair.rawPair
                                            dhsPub:nil
                                       sendCounter:0];

    [store establishSession:withAlice atTimeMs:1000 error:NULL];
    IRSessionEstablishResult *result = [store establishSession:withMallory atTimeMs:1001 error:NULL];

    XCTAssertFalse(result.collapseOccurred);
    XCTAssertEqual(store.sessionCount, (NSUInteger)2);
    XCTAssertFalse(withAlice.isTornDown);
    XCTAssertFalse(withMallory.isTornDown);
}

- (void)testReEstablishingTheSameObjectIsNotACollapse {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];

    [store establishSession:session atTimeMs:1000 error:NULL];
    IRSessionEstablishResult *again = [store establishSession:session atTimeMs:2000 error:NULL];

    XCTAssertNotNil(again);
    XCTAssertFalse(again.collapseOccurred);
    XCTAssertFalse(session.isTornDown);
    XCTAssertEqual(store.tombstoneCount, (NSUInteger)0);
}

#pragma mark - §11.4 — tombstones

- (void)testNEG_HANDSHAKE_TOMBSTONE_WithinTheWindow {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    [store establishSession:session atTimeMs:1000 error:NULL];
    XCTAssertTrue([store tearDownSession:session atTimeMs:1000 error:NULL]);

    XCTAssertNil([store sessionForHandshakeId:hid]);
    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:1000]);
    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:(1000 + 86400000ull)]);
}

- (void)testTombstoneWindowBoundaryIsInclusiveOfHANDSHAKE_CACHE_MS {
    /* §11.4: "MUST retain... for AT LEAST HANDSHAKE_CACHE_MS", with no comparator stated. The
       inclusive reading is the one that satisfies "at least" under either interpretation of the
       boundary; raised as a spec gap so four ports do not pick two answers. */
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    [store establishSession:session atTimeMs:0 error:NULL];
    [store tearDownSession:session atTimeMs:0 error:NULL];

    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:((uint64_t)kIRHandshakeCacheMs - 1)]);
    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:(uint64_t)kIRHandshakeCacheMs]);
    XCTAssertFalse([store hasTombstoneForHandshakeId:hid atTimeMs:((uint64_t)kIRHandshakeCacheMs + 1)]);
}

- (void)testAFutureDatedTombstoneIsKeptRatherThanUnderflowing {
    /* Same class of defect as the skipped store's TTL: one backwards clock correction past the
       recorded instant would expire EVERY tombstone at once, reopening §17.3's replay window for
       every session torn down in the last seven days. */
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    [store establishSession:session atTimeMs:0 error:NULL];
    [store tearDownSession:session atTimeMs:5000000ull error:NULL];

    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:1000ull]);
    XCTAssertTrue([store pruneAtTimeMs:1000ull error:NULL]);
    XCTAssertEqual(store.tombstoneCount, (NSUInteger)1);
}

- (void)testPruneDropsExpiredTombstonesAndKeepsLiveOnes {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];

    IRSession *old = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                     dhsPub:nil];
    IRSession *recent = [self sessionWithRole:0x02
                                  handshakeId:[self handshakeIdWithFirstByte:0x22 seed:2]
                                initiatorPair:_mallory.identityKeyPair.rawPair
                                responderPair:_bob.identityKeyPair.rawPair
                                       dhsPub:nil
                                  sendCounter:0];

    [store establishSession:old atTimeMs:0 error:NULL];
    [store establishSession:recent atTimeMs:0 error:NULL];
    [store tearDownSession:old atTimeMs:0 error:NULL];
    [store tearDownSession:recent atTimeMs:(uint64_t)kIRHandshakeCacheMs error:NULL];

    XCTAssertEqual(store.tombstoneCount, (NSUInteger)2);

    uint64_t nowMs = (uint64_t)kIRHandshakeCacheMs + 10;
    XCTAssertTrue([store pruneAtTimeMs:nowMs error:NULL]);

    XCTAssertEqual(store.tombstoneCount, (NSUInteger)1);
    XCTAssertFalse([store hasTombstoneForHandshakeId:old.handshakeId atTimeMs:nowMs]);
    XCTAssertTrue([store hasTombstoneForHandshakeId:recent.handshakeId atTimeMs:nowMs]);
}

- (void)testTearDownZeroizesTheSessionAndRefusesLaterUse {
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    [store establishSession:session atTimeMs:1000 error:NULL];

    [store tearDownSession:session atTimeMs:1000 error:NULL];

    XCTAssertTrue(session.isTornDown);
    XCTAssertTrue(session.state.isZeroized);
    XCTAssertNil([session snapshot]);
    XCTAssertFalse(session.sendsPreKeyMessages);

    NSError *error = nil;
    XCTAssertNil([session serializedState:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
}

- (void)testPersistRefusesASessionTheStoreDoesNotHold {
    /* A torn-down collapse loser must not be writable back by a caller still holding the handle. */
    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];

    NSError *error = nil;
    XCTAssertFalse([store persistSession:session error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorNoSession);

    [store establishSession:session atTimeMs:1000 error:NULL];
    XCTAssertTrue([store persistSession:session error:NULL]);

    [store tearDownSession:session atTimeMs:1000 error:NULL];
    XCTAssertFalse([store persistSession:session error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
}

#pragma mark - §11.2 — the three ordered checks

/// A type `0x02` message from `identity` to a session, with each field individually overridable so
/// that a test can be wrong in exactly one way — or in two.
- (NSData *)preKeyMessageFromIdentity:(IRIdentity *)identity
                              binding:(IREd25519Signature *)binding
                           ratchetKey:(IRX25519Public *)ratchetKey {
    NSError *error = nil;

    IRSessionPrologue *prologue =
        [IRSessionPrologue prologueWithEphemeralPublic:
            [IRX25519Public fromData:[self freshX25519Public] error:&error]
                                                 spkId:7
                                               opkFlag:IROPKFlagAbsent
                                                 opkId:0
                                                 error:&error];
    XCTAssertNotNil(prologue, @"%@", error);

    IRNonce *nonce = [_provider randomNonceWithError:&error];
    XCTAssertNotNil(nonce, @"%@", error);

    NSData *header = [IRMessageBuilder type02HeaderWithInitiatorIdentity:identity.identityKeyPair
                                                         identityBinding:binding
                                                                prologue:prologue
                                                              ratchetKey:ratchetKey
                                                                       N:0
                                                                   nonce:nonce
                                                                   error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSMutableData *ciphertext = [NSMutableData dataWithLength:(NSUInteger)kIRLenAEADTag];
    IRLFillPattern((uint8_t *)ciphertext.mutableBytes, ciphertext.length, 7);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:ciphertext
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    return message;
}

- (IRMessageHeader *)parsedPreKeyHeaderFromIdentity:(IRIdentity *)identity
                                            binding:(IREd25519Signature *)binding
                                         ratchetKey:(IRX25519Public *)ratchetKey {
    NSData *message = [self preKeyMessageFromIdentity:identity binding:binding ratchetKey:ratchetKey];

    NSError *error = nil;
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@", error);

    return header;
}

- (void)testRetransmittedPreKeyMessagePassesAllThreeChecks {
    NSError *error = nil;
    IRX25519Public *senderRatchet = [IRX25519Public fromData:[self freshX25519Public] error:&error];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRMessageHeader *header = [self parsedPreKeyHeaderFromIdentity:_alice
                                                          binding:_alice.binding
                                                       ratchetKey:senderRatchet];

    XCTAssertTrue([IRSessionDispatch validatePreKeyMessageHeader:header
                                                  againstSession:session
                                                        provider:_provider
                                                           error:&error], @"%@", error);
}

- (void)testCheck1_IdentityMismatch {
    NSError *error = nil;
    IRX25519Public *senderRatchet = [IRX25519Public fromData:[self freshX25519Public] error:&error];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    /* Mallory's own genuine identity and her own genuine binding, offered to a session cached for
       Alice. The binding VERIFIES — it is hers — so only check 1 catches this. */
    IRMessageHeader *header = [self parsedPreKeyHeaderFromIdentity:_mallory
                                                          binding:_mallory.binding
                                                       ratchetKey:senderRatchet];

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorIdentityMismatch);
}

- (void)testNEG_IKB_RETRANS {
    /* §15.4: "Retransmitted type 0x02 to an EXISTING session with one byte of IKB_A flipped.
       Arbitrates §5.5 against §11.2: the code MUST be the signature failure, not the AEAD failure."

       IKB_A occupies msg[68..132), which is inside the type 0x02 associated data (§8.5), so without
       §11.2's check 2 the tampered binding would reach the AEAD and fail there. Both fail closed;
       only one returns the code §15.4 requires, and §19.3 records why the verification was kept. */
    NSError *error = nil;
    IRX25519Public *senderRatchet = [IRX25519Public fromData:[self freshX25519Public] error:&error];

    NSMutableData *corrupted = [_alice.binding.data mutableCopy];
    ((uint8_t *)corrupted.mutableBytes)[13] ^= 0x01;
    IREd25519Signature *badBinding = [IREd25519Signature fromData:corrupted error:&error];
    XCTAssertNotNil(badBinding, @"%@", error);

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRMessageHeader *header = [self parsedPreKeyHeaderFromIdentity:_alice
                                                          binding:badBinding
                                                       ratchetKey:senderRatchet];

    /* The gate carries the binding UNVERIFIED — a corrupted one still parses — which is what makes
       this check §11.2's and not §10.2's. */
    XCTAssertNotNil(header);

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorBadSignature);
    XCTAssertNotEqual((IRErrorCode)error.code, IRErrorAEADAuthFailed);
}

- (void)testNEG_PUBKEY_REFLECT_02_DHS {
    /* §11.2's third check, and §10.2 says explicitly that a gate cannot perform it: a gate sees no
       session. Reflecting our own ratchet public back at us would otherwise drive a DH ratchet
       against our own key. */
    NSError *error = nil;
    NSData *ourRatchetPublic = [self freshX25519Public];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:ourRatchetPublic];
    IRMessageHeader *header =
        [self parsedPreKeyHeaderFromIdentity:_alice
                                     binding:_alice.binding
                                  ratchetKey:[IRX25519Public fromData:ourRatchetPublic error:&error]];

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorInvalidPublicKey);
}

- (void)testOrder_IdentityCheckBeatsSignatureCheck {
    /* Wrong in TWO ways: Mallory's identity AND a binding that does not verify for it. §11.2 says
       "the three checks are ordered, and the order is normative... Each returns its own code and
       returns immediately", so this MUST be the identity code. */
    NSError *error = nil;
    IRX25519Public *senderRatchet = [IRX25519Public fromData:[self freshX25519Public] error:&error];

    NSMutableData *corrupted = [_mallory.binding.data mutableCopy];
    ((uint8_t *)corrupted.mutableBytes)[3] ^= 0xFF;
    IREd25519Signature *badBinding = [IREd25519Signature fromData:corrupted error:&error];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRMessageHeader *header = [self parsedPreKeyHeaderFromIdentity:_mallory
                                                          binding:badBinding
                                                       ratchetKey:senderRatchet];

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorIdentityMismatch);
}

- (void)testOrder_SignatureCheckBeatsAntiReflection {
    /* Wrong in two ways: a broken binding AND a reflected DHs_pub. Check 2 owns it. This is the one
       ordering §19.3 was decided against — routing the binding failure to the AEAD instead — and
       the reason the order is observable at all. */
    NSError *error = nil;
    NSData *ourRatchetPublic = [self freshX25519Public];

    NSMutableData *corrupted = [_alice.binding.data mutableCopy];
    ((uint8_t *)corrupted.mutableBytes)[63] ^= 0x40;
    IREd25519Signature *badBinding = [IREd25519Signature fromData:corrupted error:&error];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:ourRatchetPublic];
    IRMessageHeader *header =
        [self parsedPreKeyHeaderFromIdentity:_alice
                                     binding:badBinding
                                  ratchetKey:[IRX25519Public fromData:ourRatchetPublic error:&error]];

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorBadSignature);
}

- (void)testDispatchRefusesATornDownSession {
    NSError *error = nil;
    IRX25519Public *senderRatchet = [IRX25519Public fromData:[self freshX25519Public] error:&error];

    IRInMemorySessionStore *store = [IRInMemorySessionStore store];
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    [store establishSession:session atTimeMs:1000 error:NULL];
    [store tearDownSession:session atTimeMs:1000 error:NULL];

    IRMessageHeader *header = [self parsedPreKeyHeaderFromIdentity:_alice
                                                          binding:_alice.binding
                                                       ratchetKey:senderRatchet];

    XCTAssertFalse([IRSessionDispatch validatePreKeyMessageHeader:header
                                                   againstSession:session
                                                         provider:_provider
                                                            error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorNoSession);
}

#pragma mark - §7.7 — snapshot, commit, discard

- (void)testCommitSnapshotReplacesTheStateAndSupersedesThePredecessor {
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRRatchetState *original = session.state;
    IRRatchetState *snapshot = [session snapshot];
    XCTAssertNotNil(snapshot);
    XCTAssertNotEqual(snapshot, original);

    snapshot.Nr = original.Nr + 1;

    NSError *error = nil;
    XCTAssertTrue([session commitSnapshot:snapshot error:&error], @"%@", error);

    XCTAssertEqual(session.state, snapshot);
    XCTAssertTrue(original.isZeroized);

    /* The live root key survives its predecessor's wipe ONLY because -snapshot deep-copies RK,
       CKs, CKr and DHs.priv. Had they shared one object this would have zeroized the live key on
       the commit path of every non-ratcheting message — which is most messages. */
    XCTAssertFalse([session.state.RK isAllZero]);
    XCTAssertFalse([session.state.CKr isAllZero]);
}

- (void)testCommitRefusesAZeroizedSnapshot {
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRRatchetState *snapshot = [session snapshot];
    [snapshot zeroizeAsDiscardedSnapshot];

    NSError *error = nil;
    XCTAssertFalse([session commitSnapshot:snapshot error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
    XCTAssertFalse(session.state.isZeroized, @"the live state must be untouched");
}

- (void)testCommitRefusesTheLiveStateItself {
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];

    NSError *error = nil;
    XCTAssertFalse([session commitSnapshot:session.state error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
    XCTAssertFalse(session.state.isZeroized);
}

- (void)testDiscardLeavesTheLiveStateIntact {
    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    IRRatchetState *live = session.state;
    IRRatchetState *snapshot = [session snapshot];

    [session discardSnapshot:snapshot];

    XCTAssertEqual(session.state, live);
    XCTAssertFalse(live.isZeroized);
    XCTAssertFalse([live.RK isAllZero]);
    XCTAssertTrue(snapshot.isZeroized);
}

#pragma mark - §12.3 — the at-rest construction

- (IRSealedStore *)sealedStoreWithFixedKey {
    NSError *error = nil;

    IRSecretBytes *key = [[IRSecretBytes alloc] initWithLength:32];
    XCTAssertNotNil(key);
    XCTAssertTrue([_provider fillSecretBytes:key error:&error], @"%@", error);

    id<IRSealKeyProvider> keyProvider = [IRInMemorySealKeyProvider providerWithFixedKey:key
                                                                                  error:&error];
    XCTAssertNotNil(keyProvider, @"%@", error);

    IRSealedStore *store = [IRSealedStore storeWithKeyProvider:keyProvider
                                                cryptoProvider:_provider
                                                         error:&error];
    XCTAssertNotNil(store, @"%@", error);

    return store;
}

- (IRSecretBytes *)secretWithPattern:(uint8_t)seed length:(NSUInteger)length {
    IRSecretBytes *secret = [[IRSecretBytes alloc] initWithLength:length];
    XCTAssertNotNil(secret);
    IRLFillPattern([secret mutableBytes], length, seed);

    return secret;
}

- (void)testSealOpenRoundTrip {
    IRSealedStore *store = [self sealedStoreWithFixedKey];
    IRSecretBytes *plaintext = [self secretWithPattern:5 length:472];

    NSError *error = nil;
    NSData *sealed = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:&error];
    XCTAssertNotNil(sealed, @"%@", error);
    XCTAssertEqual(sealed.length, plaintext.length + [IRSealedStore containerOverhead]);
    XCTAssertEqual([IRSealedStore containerOverhead], (NSUInteger)33);

    IRSecretBytes *opened = [store openSealed:sealed
                                        label:IRSealedStoreLabelSession
                                      guarded:NO
                                        error:&error];
    XCTAssertNotNil(opened, @"%@", error);
    XCTAssertTrue([opened isEqualToSecretBytes:plaintext]);

    /* §12.3 — "The blob MUST NOT be persisted in plaintext." The container must not contain it. */
    NSData *plaintextCopy = [NSData dataWithBytes:plaintext.constBytes length:plaintext.length];
    XCTAssertEqual([sealed rangeOfData:plaintextCopy options:0 range:NSMakeRange(0, sealed.length)].location,
                   (NSUInteger)NSNotFound);
}

- (void)testTheSecretPlaintextAEADIsByteEquivalentToTheNSDataOne {
    /* §12.3's at-rest path uses -aeadSealSecret: / -aeadOpenCiphertextAndTagToSecret:, which exist
       so a §12.1 blob never lands in a container §13.3 cannot wipe. They must be the SAME
       construction as the message path, not a second one: RFC 8439 with the tag appended and the
       identical associated data. A divergence here would be invisible — both halves would agree
       with themselves — until a port implemented only one of them. */
    NSError *error = nil;

    IRMessageEncKey *key = [IRMessageEncKey fromData:IRLDataWithPattern(32, 3) guarded:NO error:&error];
    XCTAssertNotNil(key, @"%@", error);
    IRNonce *nonce = [IRNonce fromData:IRLDataWithPattern((NSUInteger)kIRLenNonce, 4) error:&error];
    XCTAssertNotNil(nonce, @"%@", error);

    NSData *associatedData = IRLDataWithPattern(64, 5);
    NSData *plaintextData = IRLDataWithPattern(200, 6);
    IRSecretBytes *plaintextSecret = [[IRSecretBytes alloc] initWithData:plaintextData guarded:NO];
    XCTAssertNotNil(plaintextSecret);

    NSData *viaData = [_provider aeadSealPlaintext:plaintextData
                                                key:key
                                              nonce:nonce
                                     associatedData:associatedData
                                              error:&error];
    XCTAssertNotNil(viaData, @"%@", error);

    NSData *viaSecret = [_provider aeadSealSecret:plaintextSecret
                                              key:key
                                            nonce:nonce
                                   associatedData:associatedData
                                            error:&error];
    XCTAssertNotNil(viaSecret, @"%@", error);
    XCTAssertEqualObjects(viaData, viaSecret);

    IRSecretBytes *opened = [_provider aeadOpenCiphertextAndTagToSecret:viaData
                                                                    key:key
                                                                  nonce:nonce
                                                         associatedData:associatedData
                                                                guarded:NO
                                                                  error:&error];
    XCTAssertNotNil(opened, @"%@", error);
    XCTAssertTrue([opened isEqualToSecretBytes:plaintextSecret]);

    // And it fails closed on the same input the NSData form rejects.
    NSMutableData *tampered = [viaData mutableCopy];
    ((uint8_t *)tampered.mutableBytes)[7] ^= 0x01;
    XCTAssertNil([_provider aeadOpenCiphertextAndTagToSecret:tampered
                                                         key:key
                                                       nonce:nonce
                                              associatedData:associatedData
                                                     guarded:NO
                                                       error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorAEADAuthFailed);
}

- (void)testEverySealUsesAFreshNonce {
    /* §8.3's rule, applied at rest. A session blob is rewritten after every message, so one
       long-lived key seals many containers; a counted or derived nonce would make (key, nonce)
       reuse a consequence of a rollback, which discloses the keystream XOR and leaks the Poly1305
       one-time key. */
    IRSealedStore *store = [self sealedStoreWithFixedKey];
    IRSecretBytes *plaintext = [self secretWithPattern:5 length:472];

    NSData *first = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:NULL];
    NSData *second = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:NULL];

    XCTAssertNotEqualObjects(first, second);
    XCTAssertNotEqualObjects([first subdataWithRange:NSMakeRange(5, kIRLenNonce)],
                             [second subdataWithRange:NSMakeRange(5, kIRLenNonce)]);
}

- (void)testOpeningUnderTheWrongLabelFails {
    /* The label is bound into the associated data, so a sealed prekey store cannot be substituted
       for a sealed session blob — a confused deputy that a host with one key per device would
       otherwise accept silently. */
    IRSealedStore *store = [self sealedStoreWithFixedKey];
    IRSecretBytes *plaintext = [self secretWithPattern:5 length:472];

    NSData *sealed = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:NULL];

    NSError *error = nil;
    XCTAssertNil([store openSealed:sealed label:IRSealedStoreLabelPreKeys guarded:NO error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorAEADAuthFailed);
}

- (void)testEveryByteOfTheContainerIsAuthenticatedOrStructural {
    IRSealedStore *store = [self sealedStoreWithFixedKey];
    IRSecretBytes *plaintext = [self secretWithPattern:5 length:120];
    NSData *sealed = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:NULL];

    for (NSUInteger i = 0; i < sealed.length; i++) {
        NSMutableData *tampered = [sealed mutableCopy];
        ((uint8_t *)tampered.mutableBytes)[i] ^= 0x01;

        NSError *error = nil;
        XCTAssertNil([store openSealed:tampered label:IRSealedStoreLabelSession guarded:NO error:&error],
                     @"byte %lu", (unsigned long)i);
        XCTAssertEqual((IRErrorCode)error.code, IRErrorAEADAuthFailed, @"byte %lu", (unsigned long)i);
    }
}

- (void)testEveryTruncationOfTheContainerIsRejectedWithoutTrapping {
    IRSealedStore *store = [self sealedStoreWithFixedKey];
    IRSecretBytes *plaintext = [self secretWithPattern:5 length:64];
    NSData *sealed = [store sealSecret:plaintext label:IRSealedStoreLabelSession error:NULL];

    for (NSUInteger length = 0; length < sealed.length; length++) {
        NSData *truncated = [sealed subdataWithRange:NSMakeRange(0, length)];

        NSError *error = nil;
        XCTAssertNil([store openSealed:truncated label:IRSealedStoreLabelSession guarded:NO error:&error],
                     @"length %lu", (unsigned long)length);
        XCTAssertNotNil(error);
    }
}

- (void)testAnAllZeroSealKeyIsRefusedAsAnRNGFailure {
    /* v3's defect 4 in the at-rest path: NSMutableData dataWithLength: zero-fills, so a discarded
       RNG return produced an all-zero key and every seal succeeded. */
    NSError *error = nil;
    IRSecretBytes *zeroKey = [[IRSecretBytes alloc] initWithLength:32];
    id<IRSealKeyProvider> keyProvider = [IRInMemorySealKeyProvider providerWithFixedKey:zeroKey
                                                                                  error:&error];
    IRSealedStore *store = [IRSealedStore storeWithKeyProvider:keyProvider
                                                cryptoProvider:_provider
                                                         error:&error];

    XCTAssertNil([store sealSecret:[self secretWithPattern:5 length:64]
                             label:IRSealedStoreLabelSession
                             error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorRNGFailure);
}

#pragma mark - §12.1 + §12.3 + §12.5 composed — IRSealedSessionStore

- (IRSealedSessionStore *)sealedSessionStoreWithStorage:(id<IRSessionRecordStorage>)storage
                                                sealed:(IRSealedStore *)sealed
                                              tripwire:(id<IRRollbackTripwire>)tripwire {
    NSError *error = nil;
    IRSealedSessionStore *store = [IRSealedSessionStore storeWithSealedStore:sealed
                                                                     storage:storage
                                                            rollbackTripwire:tripwire
                                                                       error:&error];
    XCTAssertNotNil(store, @"%@", error);

    return store;
}

- (void)testSealedStoreRoundTripsASessionThroughStorage {
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];
    NSData *expectedBlob = [self blobOfSession:session];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    NSError *error = nil;
    XCTAssertNotNil([writer establishSession:session atTimeMs:1000 error:&error], @"%@", error);
    XCTAssertEqual(storage.recordCount, (NSUInteger)1);

    /* Nothing readable on the way out — §12.3's whole point. */
    NSData *record = [storage sealedRecordForHandshakeId:hid];
    XCTAssertNotNil(record);
    XCTAssertEqual([record rangeOfData:expectedBlob options:0 range:NSMakeRange(0, record.length)].location,
                   (NSUInteger)NSNotFound);

    // A second store over the same storage — the restart case.
    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertEqual(reader.sessionCount, (NSUInteger)0, @"nothing is live until -loadAtTimeMs:");
    XCTAssertTrue([reader loadAtTimeMs:2000 error:&error], @"%@", error);

    IRSession *restored = [reader sessionForHandshakeId:hid];
    XCTAssertNotNil(restored);
    XCTAssertNotEqual(restored, session);
    XCTAssertEqualObjects([self blobOfSession:restored], expectedBlob);
    XCTAssertTrue([restored.peerIdentityKeyPair isEqualToIdentityKeyPair:_alice.identityKeyPair]);

    // §11.1's second index survives the restart, rebuilt from the stored SESSION_AD.
    XCTAssertEqual([reader sessionForPeerIdentityKeyPair:_alice.identityKeyPair], restored);
    XCTAssertEqual(reader.unloadableHandshakeIds.count, (NSUInteger)0);
    XCTAssertEqual(reader.rolledBackHandshakeIds.count, (NSUInteger)0);
}

- (NSData *)blobOfSession:(IRSession *)session {
    NSError *error = nil;
    IRSecretBytes *blob = [session serializedState:&error];
    XCTAssertNotNil(blob, @"%@", error);

    NSData *copy = [NSData dataWithBytes:blob.constBytes length:blob.length];
    [blob zeroizeNow];

    return copy;
}

- (void)testSealedStoreTearDownRemovesTheRecordAndKeepsTheTombstone {
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    IRSealedSessionStore *store = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    [store establishSession:session atTimeMs:1000 error:NULL];
    XCTAssertEqual(tripwire.recordCount, (NSUInteger)0, @"send_counter 0 records no high-water mark");

    XCTAssertTrue([store tearDownSession:session atTimeMs:2000 error:NULL]);

    XCTAssertEqual(storage.recordCount, (NSUInteger)0);
    XCTAssertEqual(storage.tombstoneCount, (NSUInteger)1);
    XCTAssertTrue([store hasTombstoneForHandshakeId:hid atTimeMs:2000]);
    XCTAssertNil([store sessionForHandshakeId:hid]);

    // The tombstone survives a restart; the record does not.
    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertTrue([reader loadAtTimeMs:3000 error:NULL]);
    XCTAssertEqual(reader.sessionCount, (NSUInteger)0);
    XCTAssertTrue([reader hasTombstoneForHandshakeId:hid atTimeMs:3000]);
}

- (uint64_t)counterFrom:(id<IRRollbackTripwire>)tripwire handshakeId:(NSData *)hid {
    /* Seeded with a value the tripwire cannot legitimately produce, so a would-be implementation
       that returns YES without writing through the out-parameter fails the assertion rather than
       accidentally agreeing with an expected 0. */
    uint64_t counter = 0xA5A5A5A5A5A5A5A5ULL;
    NSError *error = nil;
    XCTAssertTrue([tripwire lastObservedSendCounter:&counter forHandshakeId:hid error:&error],
                  @"%@", error);

    return counter;
}

- (void)testNEG_STATE_ROLLBACK_ARecordBelowTheHighWaterMarkIsNotIndexed {
    /* §12.5 — "On state load, if the blob's send_counter is LESS THAN the recorded value, the state
       has been rolled back: the implementation SHOULD refuse to encrypt on that session and SHOULD
       return ERR_STATE_ROLLBACK, requiring a fresh handshake."

       Modelled exactly as the threat is: the tripwire lives in backup-excluded storage and survives,
       while the sealed record is replaced by an older one from a backup image. */
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    IRSession *advanced = [self sessionWithRole:0x02
                                    handshakeId:hid
                                  initiatorPair:_alice.identityKeyPair.rawPair
                                  responderPair:_bob.identityKeyPair.rawPair
                                         dhsPub:nil
                                    sendCounter:20];
    [writer establishSession:advanced atTimeMs:1000 error:NULL];
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)20);

    // The rollback: an older sealed record under the same handshake id.
    IRSession *older = [self sessionWithRole:0x02
                                 handshakeId:hid
                               initiatorPair:_alice.identityKeyPair.rawPair
                               responderPair:_bob.identityKeyPair.rawPair
                                      dhsPub:nil
                                 sendCounter:3];
    NSError *error = nil;
    IRSecretBytes *olderBlob = [older serializedState:&error];
    NSData *olderSealed = [sealed sealSecret:olderBlob label:IRSealedStoreLabelSession error:&error];
    [olderBlob zeroizeNow];
    XCTAssertTrue([storage storeSealedRecord:olderSealed forHandshakeId:hid error:&error], @"%@", error);

    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertTrue([reader loadAtTimeMs:2000 error:&error], @"%@", error);

    XCTAssertEqual(reader.sessionCount, (NSUInteger)0, @"a rolled-back session must not be encryptable");
    XCTAssertNil([reader sessionForHandshakeId:hid]);
    XCTAssertNil([reader sessionForPeerIdentityKeyPair:_alice.identityKeyPair]);
    XCTAssertTrue([reader hasRollbackForHandshakeId:hid]);
    XCTAssertEqual(reader.rolledBackHandshakeIds.count, (NSUInteger)1);
    XCTAssertEqual(reader.unloadableHandshakeIds.count, (NSUInteger)0, @"rollback is not corruption");
}

- (void)testARecordAtOrAboveTheHighWaterMarkLoadsNormally {
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self sessionWithRole:0x02
                                   handshakeId:hid
                                 initiatorPair:_alice.identityKeyPair.rawPair
                                 responderPair:_bob.identityKeyPair.rawPair
                                        dhsPub:nil
                                   sendCounter:20];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    [writer establishSession:session atTimeMs:1000 error:NULL];

    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertTrue([reader loadAtTimeMs:2000 error:NULL]);

    XCTAssertEqual(reader.sessionCount, (NSUInteger)1);
    XCTAssertFalse([reader hasRollbackForHandshakeId:hid]);
    XCTAssertEqual([reader sessionForHandshakeId:hid].sendCounter, (uint64_t)20);
}

- (void)testTheTripwireIsMonotonic {
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];

    XCTAssertTrue([tripwire recordSendCounter:10 forHandshakeId:hid error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)10);

    /* A restored-then-advanced session must not be able to LOWER its own tripwire, or §12.5's
       check disables itself the first time it is exercised. */
    XCTAssertTrue([tripwire recordSendCounter:4 forHandshakeId:hid error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)10);

    XCTAssertTrue([tripwire recordSendCounter:11 forHandshakeId:hid error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)11);

    XCTAssertTrue([tripwire forgetHandshakeId:hid error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)0);
}

- (void)testNEG_TRIPWIRE_UNREADABLE_AFailedTripwireReadExcludesTheSessionRatherThanAdmittingIt {
    /* §12.5 + §13.2. The regression this test exists for: -lastObservedSendCounter... used to be a
       bare uint64_t, and EVERY non-errSecSuccess status returned 0 — the same value that means "no
       record". `state.sendCounter < 0` is false for every session, so a device that had been
       rebooted and not unlocked (errSecInteractionNotAllowed) silently disabled §12.5 entirely and
       indexed the restored backup. No log, no error, and nothing distinguishing it from a clean
       load.

       Modelled as the attack: the tripwire HAS the high-water mark, the record on disk is an older
       one from a backup, and the read fails. The old code admitted that session. */
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRLUnreadableRollbackTripwire *tripwire = [[IRLUnreadableRollbackTripwire alloc] init];
    tripwire.readsFail = NO;

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *advanced = [self sessionWithRole:0x02
                                    handshakeId:hid
                                  initiatorPair:_alice.identityKeyPair.rawPair
                                  responderPair:_bob.identityKeyPair.rawPair
                                         dhsPub:nil
                                    sendCounter:20];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertNotNil([writer establishSession:advanced atTimeMs:1000 error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)20);

    // The rollback: an older sealed record swapped in under the same handshake id.
    IRSession *older = [self sessionWithRole:0x02
                                 handshakeId:hid
                               initiatorPair:_alice.identityKeyPair.rawPair
                               responderPair:_bob.identityKeyPair.rawPair
                                      dhsPub:nil
                                 sendCounter:3];
    NSError *error = nil;
    IRSecretBytes *olderBlob = [older serializedState:&error];
    NSData *olderSealed = [sealed sealSecret:olderBlob label:IRSealedStoreLabelSession error:&error];
    [olderBlob zeroizeNow];
    XCTAssertTrue([storage storeSealedRecord:olderSealed forHandshakeId:hid error:&error], @"%@", error);

    // ...and now the Keychain will not answer.
    tripwire.readsFail = YES;

    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    NSError *loadError = nil;
    XCTAssertFalse([reader loadAtTimeMs:2000 error:&loadError],
                   @"an unreadable tripwire must fail the load, not pass silently");
    XCTAssertEqual((IRErrorCode)loadError.code, IRErrorStateRollback);

    /* The underlying error names the tripwire as the thing that failed, so a host can tell "unlock
       the device and retry" from "you have genuinely been rolled back". */
    NSError *underlying = loadError.userInfo[NSUnderlyingErrorKey];
    XCTAssertNotNil(underlying);
    XCTAssertEqual((IRErrorCode)underlying.code, IRErrorStateCorrupt);

    // Fail CLOSED: the stale state is not reachable by any route.
    XCTAssertEqual(reader.sessionCount, (NSUInteger)0);
    XCTAssertNil([reader sessionForHandshakeId:hid]);
    XCTAssertNil([reader sessionForPeerIdentityKeyPair:_alice.identityKeyPair]);
    XCTAssertTrue([reader hasRollbackForHandshakeId:hid]);
    XCTAssertEqual(reader.rolledBackHandshakeIds.count, (NSUInteger)1);
    XCTAssertEqual(reader.unloadableHandshakeIds.count, (NSUInteger)0,
                   @"an unreadable tripwire is not a corrupt record");

    // And it recovers: once the device is unlocked, the comparison runs and still catches it.
    tripwire.readsFail = NO;
    IRSealedSessionStore *retry = [self sealedSessionStoreWithStorage:storage
                                                               sealed:sealed
                                                             tripwire:tripwire];
    XCTAssertTrue([retry loadAtTimeMs:3000 error:NULL]);
    XCTAssertTrue([retry hasRollbackForHandshakeId:hid], @"3 < 20 — still rolled back");
    XCTAssertEqual(retry.sessionCount, (NSUInteger)0);
}

- (void)testAFailedTripwireReadAlsoFailsTheWriteRatherThanLoweringTheMark {
    /* The monotonic guard reads before it writes. If the read cannot be performed, monotonicity
       cannot be established, and writing anyway is how a high-water mark gets LOWERED — the exact
       outcome the guard exists to prevent. */
    IRLUnreadableRollbackTripwire *tripwire = [[IRLUnreadableRollbackTripwire alloc] init];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];

    tripwire.readsFail = NO;
    XCTAssertTrue([tripwire recordSendCounter:20 forHandshakeId:hid error:NULL]);

    /* The real IRKeychainRollbackTripwire returns NO here. Asserted against the in-memory one,
       which shares the read-then-compare shape, so the contract is pinned for both. */
    IRInMemoryRollbackTripwire *inMemory = [IRInMemoryRollbackTripwire tripwire];
    NSError *error = nil;
    XCTAssertFalse([inMemory recordSendCounter:5 forHandshakeId:[NSData data] error:&error],
                   @"a read that cannot be performed must fail the write");
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
}

- (void)testADisabledTripwireIsASuccessfulReadNotAFailedOne {
    /* §12.5 is a SHOULD and IRDisabledRollbackTripwire is the opt-out. Since callers now treat a
       FAILED read as rolled-back, the opt-out has to report success-with-no-record — otherwise
       declining the tripwire would make every session unloadable, and the explicit opt-out would be
       strictly worse than the silent one it replaced. */
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    id<IRRollbackTripwire> tripwire = [IRDisabledRollbackTripwire tripwire];

    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *session = [self responderSessionWithHandshakeId:hid dhsPub:nil];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertNotNil([writer establishSession:session atTimeMs:1000 error:NULL]);

    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    NSError *error = nil;
    XCTAssertTrue([reader loadAtTimeMs:2000 error:&error], @"%@", error);
    XCTAssertEqual(reader.sessionCount, (NSUInteger)1);
    XCTAssertEqual(reader.rolledBackHandshakeIds.count, (NSUInteger)0);
}

- (void)testTheDisabledTripwireNeverFires {
    /* §12.5 is a SHOULD, and IRDisabledRollbackTripwire is how a host declines it OUT LOUD. The
       alternative — a tripwire stored inside the backup — is worse than none, because it rolls back
       with the state and looks like protection (§17.2). */
    id<IRRollbackTripwire> tripwire = [IRDisabledRollbackTripwire tripwire];
    NSData *hid = [self handshakeIdWithFirstByte:0x11 seed:1];

    XCTAssertTrue([tripwire recordSendCounter:9999 forHandshakeId:hid error:NULL]);
    XCTAssertEqual([self counterFrom:tripwire handshakeId:hid], (uint64_t)0);
}

- (void)testAnUnopenableRecordIsSkippedRatherThanFatal {
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];
    IRInMemoryRollbackTripwire *tripwire = [IRInMemoryRollbackTripwire tripwire];

    NSData *goodId = [self handshakeIdWithFirstByte:0x11 seed:1];
    IRSession *good = [self responderSessionWithHandshakeId:goodId dhsPub:nil];

    IRSealedSessionStore *writer = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    [writer establishSession:good atTimeMs:1000 error:NULL];

    NSData *badId = [self handshakeIdWithFirstByte:0x22 seed:2];
    NSMutableData *garbage = [NSMutableData dataWithLength:200];
    IRLFillPattern((uint8_t *)garbage.mutableBytes, garbage.length, 3);
    [storage storeSealedRecord:garbage forHandshakeId:badId error:NULL];

    IRSealedSessionStore *reader = [self sealedSessionStoreWithStorage:storage
                                                                sealed:sealed
                                                              tripwire:tripwire];
    XCTAssertTrue([reader loadAtTimeMs:2000 error:NULL]);

    /* Failing construction on one corrupt record would take every other session down with it.
       Skipping costs one session, which the peer's next handshake replaces. */
    XCTAssertEqual(reader.sessionCount, (NSUInteger)1);
    XCTAssertNotNil([reader sessionForHandshakeId:goodId]);
    XCTAssertEqual(reader.unloadableHandshakeIds.count, (NSUInteger)1);
    XCTAssertEqualObjects(reader.unloadableHandshakeIds.firstObject, badId);
}

- (void)testARecordFiledUnderTheWrongHandshakeIdIsRejected {
    IRSealedStore *sealed = [self sealedStoreWithFixedKey];
    IRInMemorySessionRecordStorage *storage = [IRInMemorySessionRecordStorage storage];

    IRSession *session = [self responderSessionWithHandshakeId:[self handshakeIdWithFirstByte:0x11 seed:1]
                                                        dhsPub:nil];
    NSError *error = nil;
    IRSecretBytes *blob = [session serializedState:&error];
    NSData *record = [sealed sealSecret:blob label:IRSealedStoreLabelSession error:&error];
    [blob zeroizeNow];

    NSData *wrongId = [self handshakeIdWithFirstByte:0x99 seed:9];
    [storage storeSealedRecord:record forHandshakeId:wrongId error:NULL];

    IRSealedSessionStore *reader =
        [self sealedSessionStoreWithStorage:storage
                                     sealed:sealed
                                   tripwire:[IRInMemoryRollbackTripwire tripwire]];
    XCTAssertTrue([reader loadAtTimeMs:2000 error:NULL]);

    XCTAssertEqual(reader.sessionCount, (NSUInteger)0);
    XCTAssertEqual(reader.unloadableHandshakeIds.count, (NSUInteger)1);
}

- (void)testSealedStoreAppliesTheSameCollapseAsTheInMemoryStore {
    /* §11 behaviour must not depend on where records live. Both stores route through
       IRSessionDispatch, so the two cannot disagree about which side survives. */
    IRSealedSessionStore *store =
        [self sealedSessionStoreWithStorage:[IRInMemorySessionRecordStorage storage]
                                     sealed:[self sealedStoreWithFixedKey]
                                   tripwire:[IRInMemoryRollbackTripwire tripwire]];

    NSData *lowId = [self handshakeIdWithFirstByte:0x11 seed:1];
    NSData *highId = [self handshakeIdWithFirstByte:0xF0 seed:2];
    IRSession *low = [self responderSessionWithHandshakeId:lowId dhsPub:nil];
    IRSession *high = [self responderSessionWithHandshakeId:highId dhsPub:nil];

    [store establishSession:low atTimeMs:1000 error:NULL];
    IRSessionEstablishResult *result = [store establishSession:high atTimeMs:2000 error:NULL];

    XCTAssertEqual(result.survivingSession, high);
    XCTAssertTrue(low.isTornDown);
    XCTAssertEqual(store.sessionCount, (NSUInteger)1);
    XCTAssertTrue([store hasTombstoneForHandshakeId:lowId atTimeMs:2000]);
    XCTAssertNil([store.storage sealedRecordForHandshakeId:lowId]);
    XCTAssertNotNil([store.storage sealedRecordForHandshakeId:highId]);
}

@end
