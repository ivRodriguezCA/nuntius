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
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageBuilder.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRProtocolConstants.h"
#import "IRProtocolKDF.h"
#import "IRPublicIdentity.h"
#import "IRRatchet.h"
#import "IRRatchetState.h"
#import "IRSessionAD.h"
#import "IRSkippedKeyStore.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

/**
 LAYER 7 GATE — SPEC §7.2–§7.9, §8.1, §8.3, §8.5, §10.4, §11.3, §11.4, §12.5, §13.3, §15.4.

 Named rows covered: RATCHET-INIT, RATCHET-LINEAR, RATCHET-BIDI, RATCHET-SKIP, RATCHET-SKIP-XCHAIN,
 NEG-SK-TAMPER, NEG-ATOMIC, NEG-SKIP-RETAIN, NEG-SKIP-LIMIT, NEG-REPLAY, NEG-SPK-SURVIVES-RATCHET.

 The -receive: helper below IS the four-step sequence IRRatchet.h prescribes for Layer 9 — gate,
 budget, snapshot, decrypt-then-commit-or-discard — so every end-to-end test here exercises the same
 orchestration the messenger will, and a Layer 9 that deviates from it will fail these tests rather
 than quietly reintroduce v3's ordering.
 */
@interface IRRatchetSpec : XCTestCase
@end

@implementation IRRatchetSpec {
    IRSodiumCryptoProvider *_provider;
    IRIdentity *_alice;
    IRIdentity *_bob;
    IRSignedPreKeyRecord *_bobSignedPreKey;
    IROneTimePreKeyRecord *_bobOneTimePreKey;
    NSData *_bobBundleData;
    uint64_t _nowS;
    uint64_t _nowMs;
}

static const uint32_t kSpkId = 0x11223344;
static const uint32_t kOpkId = 0x55667788;

- (void)setUp {
    [super setUp];

    NSError *error = nil;

    _provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(_provider, @"%@", error);

    _nowS = 1700000000ULL;
    _nowMs = _nowS * 1000ULL;

    _alice = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_alice, @"%@", error);

    _bob = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_bob, @"%@", error);

    _bobSignedPreKey = [IRSignedPreKeyRecord generateWithIdentity:_bob
                                                           spkId:kSpkId
                                                      notBeforeS:_nowS - 100
                                                       notAfterS:_nowS + 100000
                                                        provider:_provider
                                                           error:&error];
    XCTAssertNotNil(_bobSignedPreKey, @"%@", error);

    _bobOneTimePreKey = [IROneTimePreKeyRecord generateWithOpkId:kOpkId
                                              createdAtUnixSecs:_nowS
                                                       provider:_provider
                                                          error:&error];
    XCTAssertNotNil(_bobOneTimePreKey, @"%@", error);

    _bobBundleData = [IRPreKeyBundle serializeWithIdentity:_bob.publicIdentity
                                       signedPreKeyRecord:_bobSignedPreKey
                                     oneTimePreKeyRecords:@[ _bobOneTimePreKey ]
                                                    error:&error];
    XCTAssertNotNil(_bobBundleData, @"%@", error);
}

#pragma mark - Harness

/// A's §6 handshake against B's published bundle, then §7.5's initiator ratchet initialization.
- (IRRatchetState * _Nullable)aliceInitialStateWithResult:(IRX3DHResult * _Nullable * _Nullable)outResult
                                                     error:(NSError * _Nullable * _Nullable)error {
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:_bobBundleData provider:_provider error:error];
    if (bundle == nil) {
        return nil;
    }

    /* A fresh ephemeral per handshake: +initiatorResultWith... consumes and zeroizes the private
       half on every path, so reusing one is not expressible. */
    IRX25519KeyPair *ephemeral = [_provider generateX25519KeyPairGuarded:NO error:error];
    if (ephemeral == nil) {
        return nil;
    }

    IRX3DHResult *result = [IRX3DH initiatorResultWithIdentity:_alice
                                                        bundle:bundle
                                              ephemeralKeyPair:ephemeral
                                                nowUnixSeconds:_nowS
                                                      provider:_provider
                                                     retainIKM:NO
                                                         error:error];
    if (result == nil) {
        return nil;
    }

    IRRatchetState *state = [IRRatchet initiatorStateWithSharedKey:result.sharedKey
                                            responderSignedPreKey:bundle.signedPreKey
                                                        sessionAD:result.sessionAD
                                                      handshakeId:result.handshakeId
                                                         prologue:result.prologue
                                                         provider:_provider
                                                            error:error];

    if (outResult != NULL) {
        *outResult = result;
    }

    return state;
}

/// §10.7 steps 3 and 8–11 plus §7.5's responder initialization, from an already-gated header.
- (IRRatchetState * _Nullable)bobStateForHeader:(IRMessageHeader * _Nonnull)header
                             signedPreKeyRecord:(IRSignedPreKeyRecord * _Nonnull)signedPreKeyRecord
                            oneTimePreKeyRecord:(IROneTimePreKeyRecord * _Nullable)oneTimePreKeyRecord
                                          error:(NSError * _Nullable * _Nullable)error {
    /* §10.7 step 3 — verify IKB_A BEFORE any DH. Structural: IRPublicIdentity has exactly one
       constructor and it performs the check, so an unverified identity cannot reach IRX3DH. */
    IRPublicIdentity *verifiedInitiator = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                                       binding:header.identityBinding
                                                                      provider:_provider
                                                                         error:error];
    if (verifiedInitiator == nil) {
        return nil;
    }

    IRX3DHResult *result = [IRX3DH responderResultWithIdentity:_bob
                                            initiatorIdentity:verifiedInitiator
                                              ephemeralPublic:header.ephemeralPublic
                                             signedPreKeyPair:signedPreKeyRecord.keyPair
                                                        spkId:header.spkId
                                                      opkFlag:header.opkFlag
                                                        opkId:header.opkId
                                            oneTimePreKeyPair:oneTimePreKeyRecord.keyPair
                                                     provider:_provider
                                                    retainIKM:NO
                                                        error:error];
    if (result == nil) {
        return nil;
    }

    IRRatchetState *state = [IRRatchet responderStateWithSharedKey:result.sharedKey
                                                 signedPreKeyPair:signedPreKeyRecord.keyPair
                                                        sessionAD:result.sessionAD
                                                      handshakeId:result.handshakeId
                                                            error:error];

    /* §13.3 — SK dies "immediately after ratchet initialization", and this is the call that proves
       IRRatchet copied rather than adopted it. Every end-to-end test below runs after this wipe. */
    [result zeroize];

    return state;
}

- (NSData * _Nullable)send:(NSData * _Nonnull)plaintext
                      from:(IRRatchetState * _Nonnull)state
                     error:(NSError * _Nullable * _Nullable)error {
    const BOOL prekey = state.shouldSendPreKeyMessage;

    return [IRRatchet encryptOnState:state
                           plaintext:plaintext
                         messageType:(prekey ? IRMessageTypePrekey : IRMessageTypeNormal)
                   initiatorIdentity:(prekey ? _alice.identityKeyPair : nil)
                     identityBinding:(prekey ? _alice.binding : nil)
                            provider:_provider
                               error:error];
}

/// The gate for a message about to be delivered to `liveState`.
- (IRMessageHeader * _Nullable)gate:(NSData * _Nonnull)message
                          forState:(IRRatchetState * _Nullable)liveState
                             error:(NSError * _Nullable * _Nullable)error {
    const IRMessageType type = [IRMessageGate messageTypeOfMessage:message error:error];
    if (type == 0) {
        return nil;
    }

    if (type == IRMessageTypePrekey) {
        return [IRMessageGate parseType02Message:message error:error];
    }

    if (![IRMessageGate gateType01Prefix:message error:error]) {
        return nil;
    }

    return [IRMessageGate parseType01Message:message
                        ownRatchetPublicKey:liveState.DHs.publicKey
                                      error:error];
}

/**
 IRRatchet.h's four-step receive sequence, verbatim. On success `*live` is replaced by the committed
 snapshot and the superseded state is zeroized; on failure `*live` is left exactly as it was.
 */
- (NSData * _Nullable)receive:(NSData * _Nonnull)message
                          into:(IRRatchetState * __strong _Nonnull * _Nonnull)live
                      atTimeMs:(uint64_t)nowMs
                         error:(NSError * _Nullable * _Nullable)error {
    IRRatchetState *liveState = *live;

    IRMessageHeader *header = [self gate:message forState:liveState error:error];
    if (header == nil) {
        return nil;
    }

    IRSkipBudget *budget = [IRSkipBudget budget];

    IRRatchetState *snapshot = [liveState snapshot];
    if (snapshot == nil) {
        return nil;
    }

    NSData *plaintext = [IRRatchet decryptOnSnapshot:snapshot
                                             message:message
                                              header:header
                                              budget:budget
                                            atTimeMs:nowMs
                                            provider:_provider
                                               error:error];
    if (plaintext == nil) {
        /* Discard. IRRatchet has already zeroized it; the live state is untouched. */
        return nil;
    }

    [snapshot.skipped zeroizePendingRemovals];
    [liveState zeroizeAsSupersededState];
    *live = snapshot;

    return plaintext;
}

- (NSData * _Nullable)receive:(NSData * _Nonnull)message
                          into:(IRRatchetState * __strong _Nonnull * _Nonnull)live
                         error:(NSError * _Nullable * _Nullable)error {
    return [self receive:message into:live atTimeMs:_nowMs error:error];
}

/// Establishes a live session on both sides by delivering A's first (type `0x02`) message.
- (void)establishAlice:(IRRatchetState * __strong _Nonnull * _Nonnull)outAlice
                    bob:(IRRatchetState * __strong _Nonnull * _Nonnull)outBob {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    NSData *first = [self send:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] from:alice error:&error];
    XCTAssertNotNil(first, @"%@", error);

    IRMessageHeader *header = [self gate:first forState:nil error:&error];
    XCTAssertNotNil(header, @"%@", error);

    IRRatchetState *bob = [self bobStateForHeader:header
                               signedPreKeyRecord:_bobSignedPreKey
                              oneTimePreKeyRecord:_bobOneTimePreKey
                                            error:&error];
    XCTAssertNotNil(bob, @"%@", error);

    NSData *recovered = [self receive:first into:&bob error:&error];
    XCTAssertNotNil(recovered, @"%@", error);
    XCTAssertEqualObjects(recovered, [@"hello" dataUsingEncoding:NSUTF8StringEncoding]);

    *outAlice = alice;
    *outBob = bob;
}

- (NSData * _Nonnull)corruptLastByteOf:(NSData * _Nonnull)message {
    NSMutableData *mutable = [message mutableCopy];
    uint8_t *bytes = (uint8_t *)mutable.mutableBytes;
    bytes[mutable.length - 1] ^= 0x01;
    return mutable;
}

- (NSData * _Nonnull)plaintext:(NSString * _Nonnull)text {
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - RATCHET-INIT (§7.5)

- (void)testRatchetInit_ACKsEqualsBCKrAfterFirstMessage {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    /* §7.5's "correct conformance assertion". A's sending chain and B's receiving chain have each
       taken exactly one KDF_CK step for the delivered message, so the two chain keys are equal. */
    XCTAssertNotNil(alice.CKs);
    XCTAssertNotNil(bob.CKr);
    XCTAssertTrue([alice.CKs isEqualToSecretBytes:bob.CKr]);
}

- (void)testRatchetInit_RootKeysDeliberatelyDiffer {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    /* §7.5: "Do NOT assert A.RK == B.RK: B's DHRatchet performs two KDF_RK steps while A has
       performed one, so B's root key is legitimately one step ahead at that instant. An implementer
       who asserts root-key equality here will 'fix' working code."

       This test exists to make that inequality a REQUIREMENT, so the "fix" fails loudly. */
    XCTAssertFalse([alice.RK isEqualToSecretBytes:bob.RK]);
}

- (void)testRatchetInit_ResponderHasNoSendingChainUntilItRatchets {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    NSData *first = [self send:[self plaintext:@"hi"] from:alice error:&error];
    XCTAssertNotNil(first, @"%@", error);

    IRMessageHeader *header = [self gate:first forState:nil error:&error];
    XCTAssertNotNil(header, @"%@", error);

    IRRatchetState *bob = [self bobStateForHeader:header
                               signedPreKeyRecord:_bobSignedPreKey
                              oneTimePreKeyRecord:_bobOneTimePreKey
                                            error:&error];
    XCTAssertNotNil(bob, @"%@", error);

    /* §7.5 responder: DHr, CKs and CKr are all none. DHr being none is exactly what drives §7.9
       phase 3b to ratchet on the first received message. */
    XCTAssertNil(bob.DHr);
    XCTAssertNil(bob.CKs);
    XCTAssertNil(bob.CKr);
    XCTAssertEqual(bob.role, IRSessionRoleResponder);

    /* §7.8 guard 2 — a send in this window is ERR_NO_SENDING_CHAIN, not a crash. */
    NSError *sendError = nil;
    NSData *tooEarly = [IRRatchet encryptOnState:bob
                                       plaintext:[self plaintext:@"too early"]
                                     messageType:IRMessageTypeNormal
                               initiatorIdentity:nil
                                 identityBinding:nil
                                        provider:_provider
                                           error:&sendError];
    XCTAssertNil(tooEarly);
    XCTAssertEqual(sendError.code, IRErrorNoSendingChain);
}

- (void)testRatchetInit_SharedKeyIsCopiedNotAdopted {
    NSError *error = nil;

    IRX3DHResult *result = nil;
    IRRatchetState *alice = [self aliceInitialStateWithResult:&result error:&error];
    XCTAssertNotNil(alice, @"%@", error);
    XCTAssertNotNil(result);

    /* §13.3 puts SK's wipe immediately after ratchet initialization and IRX3DHResult owns it. If
       IRRatchet had adopted the caller's object rather than copying it, this line would wipe the
       new session's root key — and the failure would appear only at the first message. */
    [result zeroize];

    XCTAssertFalse([alice.RK isAllZero]);
    XCTAssertFalse([alice.CKs isAllZero]);

    NSData *message = [self send:[self plaintext:@"after the wipe"] from:alice error:&error];
    XCTAssertNotNil(message, @"%@", error);
}

- (void)testRatchetInit_ResponderCopiesSignedPreKeyPrivate {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    NSData *first = [self send:[self plaintext:@"hi"] from:alice error:&error];
    IRMessageHeader *header = [self gate:first forState:nil error:&error];
    IRRatchetState *bob = [self bobStateForHeader:header
                               signedPreKeyRecord:_bobSignedPreKey
                              oneTimePreKeyRecord:_bobOneTimePreKey
                                            error:&error];
    XCTAssertNotNil(bob, @"%@", error);

    /* §7.5 / §19.1 — the state must hold its OWN scalar, never an alias into the prekey store. */
    XCTAssertNotEqual(bob.DHs.privateKey, _bobSignedPreKey.keyPair.privateKey);
    XCTAssertTrue([bob.DHs.privateKey isEqualToSecretBytes:_bobSignedPreKey.keyPair.privateKey]);

    NSData *recovered = [self receive:first into:&bob error:&error];
    XCTAssertNotNil(recovered, @"%@", error);

    /* §7.4 step 4 has now run and destroyed the session copy. The prekey store's original MUST be
       untouched — this is the assertion whose failure v3-shaped ports misreport as an active MITM. */
    XCTAssertFalse([_bobSignedPreKey.keyPair.privateKey isAllZero]);
}

#pragma mark - RATCHET-LINEAR / RATCHET-BIDI

- (void)testRatchetLinear_TenMessagesInOrder {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    for (NSUInteger i = 0; i < 10; i++) {
        NSError *error = nil;
        NSData *expected = [self plaintext:[NSString stringWithFormat:@"linear-%lu", (unsigned long)i]];

        NSData *message = [self send:expected from:alice error:&error];
        XCTAssertNotNil(message, @"%@", error);

        NSData *recovered = [self receive:message into:&bob error:&error];
        XCTAssertNotNil(recovered, @"%@", error);
        XCTAssertEqualObjects(recovered, expected);
    }

    XCTAssertEqual(alice.Ns, 11u);
    XCTAssertEqual(bob.Nr, 11u);
    XCTAssertEqual(bob.skipped.count, 0u);

    /* §12.5 — one increment per successful RatchetEncrypt, including the establishing message. */
    XCTAssertEqual(alice.sendCounter, 11ULL);
}

- (void)testRatchetBidi_AlternatingTurnsRatchetBothWays {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    for (NSUInteger round = 0; round < 4; round++) {
        NSError *error = nil;

        NSData *fromBob = [self plaintext:[NSString stringWithFormat:@"b-%lu", (unsigned long)round]];
        NSData *bobMessage = [self send:fromBob from:bob error:&error];
        XCTAssertNotNil(bobMessage, @"%@", error);

        NSData *aliceGot = [self receive:bobMessage into:&alice error:&error];
        XCTAssertNotNil(aliceGot, @"%@", error);
        XCTAssertEqualObjects(aliceGot, fromBob);

        NSData *fromAlice = [self plaintext:[NSString stringWithFormat:@"a-%lu", (unsigned long)round]];
        NSData *aliceMessage = [self send:fromAlice from:alice error:&error];
        XCTAssertNotNil(aliceMessage, @"%@", error);

        NSData *bobGot = [self receive:aliceMessage into:&bob error:&error];
        XCTAssertNotNil(bobGot, @"%@", error);
        XCTAssertEqualObjects(bobGot, fromAlice);
    }
}

- (void)testRatchetBidi_SessionADIsRoleOrderedOnBothSides {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    /* §6.5 — "A port that recomputes SESSION_AD as (self, peer) at send time will interoperate with
       itself and with nothing else." Both sides hold the identical 141 bytes; RATCHET-BIDI catches
       a port that does not, but only because B sends after the ratchet turns. */
    XCTAssertEqualObjects(alice.sessionAD.bytes, bob.sessionAD.bytes);
    XCTAssertTrue([alice.sessionAD.initiatorIdentity isEqualToIdentityKeyPair:_alice.identityKeyPair]);
    XCTAssertTrue([alice.sessionAD.responderIdentity isEqualToIdentityKeyPair:_bob.identityKeyPair]);
}

- (void)testPreviousChainLengthTravelsSeparatelyFromNs {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* A's first sending chain reaches length 3: the establishing message plus two more. */
    for (NSUInteger i = 0; i < 2; i++) {
        NSData *message = [self send:[self plaintext:@"chain one"] from:alice error:&error];
        XCTAssertNotNil(message, @"%@", error);
        XCTAssertNotNil([self receive:message into:&bob error:&error], @"%@", error);
    }
    XCTAssertEqual(alice.Ns, 3u);

    /* B replies, so A ratchets and starts a new sending chain. */
    NSData *bobMessage = [self send:[self plaintext:@"turn"] from:bob error:&error];
    XCTAssertNotNil([self receive:bobMessage into:&alice error:&error], @"%@", error);

    XCTAssertEqual(alice.PN, 3u);
    XCTAssertEqual(alice.Ns, 0u);

    NSData *next = [self send:[self plaintext:@"chain two"] from:alice error:&error];
    XCTAssertNotNil(next, @"%@", error);

    IRMessageHeader *header = [self gate:next forState:bob error:&error];
    XCTAssertNotNil(header, @"%@", error);

    /* DEFECT 10 — v3 wrote numberOfSentMessages into BOTH header slots, so the previous-chain count
       was never transmitted and cross-chain recovery could not work. N and PN must differ here. */
    XCTAssertEqual(header.N, 0u);
    XCTAssertEqual(header.PN, 3u);
}

#pragma mark - RATCHET-SKIP / RATCHET-SKIP-XCHAIN (§7.6)

- (void)testRatchetSkip_OutOfOrderWithinOneChain {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    NSData *m2 = [self send:[self plaintext:@"m2"] from:alice error:&error];
    XCTAssertNotNil(m2, @"%@", error);

    /* m2 first: m0 and m1 are derived and stored. */
    XCTAssertEqualObjects([self receive:m2 into:&bob error:&error], [self plaintext:@"m2"]);
    XCTAssertEqual(bob.skipped.count, 2u);
    XCTAssertEqual(bob.Nr, 4u);

    XCTAssertEqualObjects([self receive:m0 into:&bob error:&error], [self plaintext:@"m0"]);
    XCTAssertEqual(bob.skipped.count, 1u);

    /* §7.9 — a skipped-key hit returns WITHOUT advancing Nr. */
    XCTAssertEqual(bob.Nr, 4u);

    XCTAssertEqualObjects([self receive:m1 into:&bob error:&error], [self plaintext:@"m1"]);
    XCTAssertEqual(bob.skipped.count, 0u);
}

- (void)testRatchetSkipXChain_KeysFromTheOldChainSurviveTheRatchet {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *a0 = [self send:[self plaintext:@"a0"] from:alice error:&error];
    NSData *a1 = [self send:[self plaintext:@"a1"] from:alice error:&error];
    NSData *a2 = [self send:[self plaintext:@"a2"] from:alice error:&error];
    XCTAssertNotNil(a2, @"%@", error);

    /* B jumps to a2; a0 and a1 are stored under A's CURRENT ratchet key. */
    XCTAssertEqualObjects([self receive:a2 into:&bob error:&error], [self plaintext:@"a2"]);
    XCTAssertEqual(bob.skipped.count, 2u);

    /* B replies and A ratchets, so A's next chain uses a NEW ratchet public. */
    NSData *b0 = [self send:[self plaintext:@"b0"] from:bob error:&error];
    XCTAssertNotNil([self receive:b0 into:&alice error:&error], @"%@", error);

    NSData *a3 = [self send:[self plaintext:@"a3"] from:alice error:&error];
    XCTAssertNotNil(a3, @"%@", error);

    /* Delivering a3 drives B through a DH ratchet — §7.4 step 1 drains the old chain to header.PN,
       which is already fully consumed, so nothing new is stored. */
    XCTAssertEqualObjects([self receive:a3 into:&bob error:&error], [self plaintext:@"a3"]);
    XCTAssertEqual(bob.skipped.count, 2u);

    /* THE POINT OF THIS TEST: the two stragglers are keyed under A's PREVIOUS ratchet public, and
       the store is looked up by the HEADER's key rather than by the session's current DHr. */
    XCTAssertEqualObjects([self receive:a0 into:&bob error:&error], [self plaintext:@"a0"]);
    XCTAssertEqualObjects([self receive:a1 into:&bob error:&error], [self plaintext:@"a1"]);
    XCTAssertEqual(bob.skipped.count, 0u);
}

- (void)testSkipAcrossARatchetDrainsTheOldChainToPN {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* A sends two more in chain one; B receives NEITHER. */
    NSData *a0 = [self send:[self plaintext:@"a0"] from:alice error:&error];
    NSData *a1 = [self send:[self plaintext:@"a1"] from:alice error:&error];
    XCTAssertNotNil(a1, @"%@", error);

    /* B replies out of band; A ratchets and sends in a new chain. */
    NSData *b0 = [self send:[self plaintext:@"b0"] from:bob error:&error];
    XCTAssertNotNil([self receive:b0 into:&alice error:&error], @"%@", error);

    NSData *a2 = [self send:[self plaintext:@"a2"] from:alice error:&error];
    XCTAssertNotNil(a2, @"%@", error);

    /* §7.4 step 1 — SkipMessageKeys(header.PN) on the OLD receiving chain, before DHr is replaced.
       header.PN is 3, B's Nr is 1, so exactly the two undelivered keys are stored. */
    XCTAssertEqualObjects([self receive:a2 into:&bob error:&error], [self plaintext:@"a2"]);
    XCTAssertEqual(bob.skipped.count, 2u);

    XCTAssertEqualObjects([self receive:a0 into:&bob error:&error], [self plaintext:@"a0"]);
    XCTAssertEqualObjects([self receive:a1 into:&bob error:&error], [self plaintext:@"a1"]);
    XCTAssertEqual(bob.skipped.count, 0u);
}

#pragma mark - NEG-SK-TAMPER (§15.4)

- (void)testNegSKTamper_OneFlippedByteOnOneSideFailsAuthentication {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    NSData *first = [self send:[self plaintext:@"tampered"] from:alice error:&error];
    IRMessageHeader *header = [self gate:first forState:nil error:&error];
    XCTAssertNotNil(header, @"%@", error);

    IRPublicIdentity *verified = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                              binding:header.identityBinding
                                                             provider:_provider
                                                                error:&error];
    XCTAssertNotNil(verified, @"%@", error);

    IRX3DHResult *result = [IRX3DH responderResultWithIdentity:_bob
                                            initiatorIdentity:verified
                                              ephemeralPublic:header.ephemeralPublic
                                             signedPreKeyPair:_bobSignedPreKey.keyPair
                                                        spkId:header.spkId
                                                      opkFlag:header.opkFlag
                                                        opkId:header.opkId
                                            oneTimePreKeyPair:_bobOneTimePreKey.keyPair
                                                     provider:_provider
                                                    retainIKM:NO
                                                        error:&error];
    XCTAssertNotNil(result, @"%@", error);

    /* Flip one byte of SK on B's side only. Every downstream key diverges, and the AEAD is what
       notices — this is the only vector that would have caught defect 2, where the handshake output
       never reached the ratchet at all and a tampered SK changed nothing. */
    uint8_t *skBytes = [result.sharedKey mutableBytes];
    skBytes[0] ^= 0x01;

    IRRatchetState *bob = [IRRatchet responderStateWithSharedKey:result.sharedKey
                                               signedPreKeyPair:_bobSignedPreKey.keyPair
                                                      sessionAD:result.sessionAD
                                                    handshakeId:result.handshakeId
                                                          error:&error];
    XCTAssertNotNil(bob, @"%@", error);

    NSError *decryptError = nil;
    NSData *recovered = [self receive:first into:&bob error:&decryptError];
    XCTAssertNil(recovered);
    XCTAssertEqual(decryptError.code, IRErrorAEADAuthFailed);
}

#pragma mark - NEG-ATOMIC (§7.7, §15.4)

- (void)testNegAtomic_ForgedNovelRatchetKeyDoesNotDesynchroniseTheSession {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* B replies so that A ratchets; A's next message therefore carries a ratchet key B has never
       seen, which is what forces §7.9 phase 3b to run. */
    NSData *b0 = [self send:[self plaintext:@"b0"] from:bob error:&error];
    XCTAssertNotNil([self receive:b0 into:&alice error:&error], @"%@", error);

    NSData *a1 = [self send:[self plaintext:@"a1"] from:alice error:&error];
    XCTAssertNotNil(a1, @"%@", error);

    IRX25519Public *dhrBefore = bob.DHr;
    const uint32_t nrBefore = bob.Nr;
    const uint32_t pnBefore = bob.PN;
    IRChainKey *ckrBefore = [bob.CKr duplicate];

    /* Header-valid, tag-invalid, novel ratchet key. v3 ratcheted, advanced Nr and inserted skipped
       keys BEFORE calling aeDecryptData:, so this single injected message permanently
       desynchronised a live session — an unauthenticated denial of service that is state corruption
       rather than a wrong plaintext, which is why no round-trip test detects it. */
    NSData *forged = [self corruptLastByteOf:a1];

    NSError *forgedError = nil;
    XCTAssertNil([self receive:forged into:&bob error:&forgedError]);
    XCTAssertEqual(forgedError.code, IRErrorAEADAuthFailed);

    /* §7.7 — "the live state MUST be byte-identical to what it was before the call". */
    XCTAssertEqual(bob.DHr, dhrBefore);
    XCTAssertEqual(bob.Nr, nrBefore);
    XCTAssertEqual(bob.PN, pnBefore);
    XCTAssertTrue([bob.CKr isEqualToSecretBytes:ckrBefore]);
    XCTAssertEqual(bob.skipped.count, 0u);
    XCTAssertFalse(bob.isZeroized);

    /* And the session survives: the genuine message still decrypts. */
    XCTAssertEqualObjects([self receive:a1 into:&bob error:&error], [self plaintext:@"a1"]);
}

- (void)testNegAtomic_ForgedMessageDoesNotConsumeSkipBudgetOfTheNextOne {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    for (NSUInteger i = 0; i < 4; i++) {
        (void)[self send:[self plaintext:@"filler"] from:alice error:&error];
    }

    NSData *ahead = [self send:[self plaintext:@"ahead"] from:alice error:&error];
    XCTAssertNotNil(ahead, @"%@", error);

    NSError *forgedError = nil;
    XCTAssertNil([self receive:[self corruptLastByteOf:ahead] into:&bob error:&forgedError]);
    XCTAssertEqual(forgedError.code, IRErrorAEADAuthFailed);

    /* The four keys the forged attempt derived went with the discarded snapshot: none reached the
       live store, so the genuine delivery derives them again from an untouched chain. */
    XCTAssertEqual(bob.skipped.count, 0u);

    XCTAssertEqualObjects([self receive:ahead into:&bob error:&error], [self plaintext:@"ahead"]);
    XCTAssertEqual(bob.skipped.count, 4u);
}

#pragma mark - NEG-SKIP-RETAIN (§7.6, §15.4)

- (void)testNegSkipRetain_CorruptedTagLeavesTheStoredKeyIntact {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    XCTAssertNotNil(m1, @"%@", error);

    /* m1 first, so m0's key is derived and stored. */
    XCTAssertEqualObjects([self receive:m1 into:&bob error:&error], [self plaintext:@"m1"]);
    XCTAssertEqual(bob.skipped.count, 1u);

    /* v3 removed the entry BEFORE decrypting (IRDoubleRatchetService.m:168 then :170), so a
       corrupted delivery destroyed the only copy of the key and the message became permanently
       unrecoverable. The removal MUST happen only after the AEAD succeeds. */
    NSError *forgedError = nil;
    XCTAssertNil([self receive:[self corruptLastByteOf:m0] into:&bob error:&forgedError]);
    XCTAssertEqual(forgedError.code, IRErrorAEADAuthFailed);
    XCTAssertEqual(bob.skipped.count, 1u);

    /* The key is still there and still correct. */
    XCTAssertEqualObjects([self receive:m0 into:&bob error:&error], [self plaintext:@"m0"]);
    XCTAssertEqual(bob.skipped.count, 0u);
}

- (void)testFailedSkippedKeyDecryptDoesNotEvenRemoveTheEntryFromTheSNAPSHOT {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    XCTAssertNotNil(m1, @"%@", error);

    XCTAssertNotNil([self receive:m1 into:&bob error:&error], @"%@", error);
    XCTAssertEqual(bob.skipped.count, 1u);

    /* WHY THIS TEST EXISTS, AND WHY NEG-SKIP-RETAIN IS NOT ENOUGH ON ITS OWN.

       §7.6's ordering rule — "a stored key MUST be removed ONLY after the AEAD decryption using it
       SUCCEEDS" — is stated as the fix for v3, which called removeObjectForKey: at
       IRDoubleRatchetService.m:168 and aeDecryptData: at :170. But in ANY implementation that also
       honours §7.7, that removal lands on a snapshot which is then discarded, so the live store
       keeps the key regardless and NEG-SKIP-RETAIN passes with the two calls in either order.
       Verified by mutation: moving the removal above the AEAD leaves the whole suite green except
       for this assertion.

       So the ordering is pinned where it is actually observable — on the snapshot itself. A port
       that keeps the two rules independent needs this; a port that relies on atomicity to mask the
       ordering will not notice when its snapshot granularity later changes. */
    IRMessageHeader *header = [self gate:[self corruptLastByteOf:m0] forState:bob error:&error];
    XCTAssertNotNil(header, @"%@", error);

    IRRatchetState *snapshot = [bob snapshot];
    XCTAssertEqual(snapshot.skipped.count, 1u);

    NSError *forgedError = nil;
    XCTAssertNil([IRRatchet decryptOnSnapshot:snapshot
                                      message:[self corruptLastByteOf:m0]
                                       header:header
                                       budget:[IRSkipBudget budget]
                                     atTimeMs:_nowMs
                                     provider:_provider
                                        error:&forgedError]);
    XCTAssertEqual(forgedError.code, IRErrorAEADAuthFailed);

    /* §7.9 phase 3a: the failure exit precedes remove_and_zeroize entirely. */
    XCTAssertEqual(snapshot.skipped.count, 1u, @"the entry MUST NOT be removed on the AEAD failure path");
    XCTAssertEqual(bob.skipped.count, 1u);
}

- (void)testSkippedKeyIsRemovedAfterUseSoASecondDeliveryIsReplay {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    XCTAssertNotNil(m1, @"%@", error);

    XCTAssertNotNil([self receive:m1 into:&bob error:&error], @"%@", error);
    XCTAssertNotNil([self receive:m0 into:&bob error:&error], @"%@", error);

    /* §11.4 — "Decrypts once; the key is then removed, so a second replay is ERR_REPLAY." */
    NSError *replayError = nil;
    XCTAssertNil([self receive:m0 into:&bob error:&replayError]);
    XCTAssertEqual(replayError.code, IRErrorReplay);
}

#pragma mark - NEG-REPLAY (§7.9 phase 3c, §15.4)

- (void)testNegReplay_DuplicateWithNoStoredKeyIsAnExplicitCode {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    XCTAssertNotNil([self receive:m0 into:&bob error:&error], @"%@", error);

    /* §7.9's rule list: "hdr.N < s.Nr with no matching skipped key is ERR_REPLAY, not a silent AEAD
       failure" — the two describe different facts about the session and a host may act on them
       differently. */
    NSError *replayError = nil;
    XCTAssertNil([self receive:m0 into:&bob error:&replayError]);
    XCTAssertEqual(replayError.code, IRErrorReplay);

    /* And the session is unharmed. */
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    XCTAssertEqualObjects([self receive:m1 into:&bob error:&error], [self plaintext:@"m1"]);
}

#pragma mark - NEG-SKIP-LIMIT (§7.6, §15.4)

- (void)testNegSkipLimit_MoreThanMaxSkipPerMessageIsRejected {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* B's Nr is 1. Driving A's counter to 1002 makes the required span 1001 — one past the bound. */
    alice.Ns = 1002;

    NSData *farAhead = [self send:[self plaintext:@"far ahead"] from:alice error:&error];
    XCTAssertNotNil(farAhead, @"%@", error);

    NSError *skipError = nil;
    XCTAssertNil([self receive:farAhead into:&bob error:&skipError]);
    XCTAssertEqual(skipError.code, IRErrorTooManySkipped);

    /* §7.6 — "state MUST be left unmodified". */
    XCTAssertEqual(bob.Nr, 1u);
    XCTAssertEqual(bob.skipped.count, 0u);
}

- (void)testSkipBudgetIsAggregateAcrossBothCallsOfOneMessage {
    /* §7.6 is explicit that MAX_SKIP_PER_MESSAGE is "an aggregate per received message, not a
       per-call bound. A DH-ratchet message skips header.PN keys in the old chain and then header.N
       in the new one; a per-call bound of 1000 would permit 2000 derivations per message and let a
       single message evict the entire store." */
    IRSkipBudget *budget = [IRSkipBudget budgetWithLimit:10];

    XCTAssertEqual(budget.remaining, 10u);
    XCTAssertTrue([budget consume:6]);
    XCTAssertEqual(budget.remaining, 4u);

    /* The second call sees only what the first left. */
    XCTAssertFalse([budget consume:5]);
    XCTAssertEqual(budget.remaining, 4u, @"a rejected consume MUST leave the budget untouched");

    XCTAssertTrue([budget consume:4]);
    XCTAssertEqual(budget.remaining, 0u);
    XCTAssertFalse([budget consume:1]);
}

- (void)testOneMessageCannotSkipMaxSkipPerMessageInEachOfTwoChains {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* §7.6: "MAX_SKIP_PER_MESSAGE is deliberately specified as an AGGREGATE per received message,
       not a per-call bound. A DH-ratchet message skips header.PN keys in the old chain and then
       header.N in the new one; a per-call bound of 1000 would permit 2000 derivations per message
       and let a single message evict the entire store."

       This is the only test that distinguishes the two readings. Every other skip test drives a
       single call, and both a per-call and an aggregate budget pass all of them. */
    const uint32_t firstChain = 600;
    const uint32_t secondChain = 600;

    for (uint32_t i = 0; i < firstChain; i++) {
        XCTAssertNotNil([self send:[self plaintext:@"undelivered"] from:alice error:&error], @"%@", error);
    }

    /* B replies so A ratchets; A's PN becomes the full length of that undelivered chain. */
    NSData *bobReply = [self send:[self plaintext:@"turn"] from:bob error:&error];
    XCTAssertNotNil([self receive:bobReply into:&alice error:&error], @"%@", error);
    XCTAssertEqual(alice.PN, firstChain + 1);

    NSData *last = nil;
    for (uint32_t i = 0; i < secondChain; i++) {
        last = [self send:[self plaintext:@"second chain"] from:alice error:&error];
    }
    XCTAssertNotNil(last, @"%@", error);

    /* Delivering only the last one asks B for 600 keys in the old chain and 599 in the new: 1199
       derivations for one message. Each call alone is under the bound; together they are not. */
    NSError *skipError = nil;
    XCTAssertNil([self receive:last into:&bob error:&skipError]);
    XCTAssertEqual(skipError.code, IRErrorTooManySkipped);

    /* And nothing was retained from the rejected attempt — §7.7. */
    XCTAssertEqual(bob.skipped.count, 0u);
    XCTAssertEqual(bob.Nr, 1u);
}

- (void)testSkipMessageKeysBoundaryIsExactlyMaxSkipPerMessage {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* Exactly at the bound: accepted, and the whole span is derived. */
    IRSkipBudget *exact = [IRSkipBudget budgetWithLimit:5];
    XCTAssertTrue([IRRatchet skipMessageKeysOnState:bob
                                              until:bob.Nr + 5
                                             budget:exact
                                           atTimeMs:_nowMs
                                           provider:_provider
                                              error:&error], @"%@", error);
    XCTAssertEqual(bob.skipped.count, 5u);
    XCTAssertEqual(exact.remaining, 0u);

    /* One past it: rejected, and NOTHING moves. */
    const uint32_t nrBefore = bob.Nr;
    IRSkipBudget *tight = [IRSkipBudget budgetWithLimit:5];
    NSError *skipError = nil;
    XCTAssertFalse([IRRatchet skipMessageKeysOnState:bob
                                               until:bob.Nr + 6
                                              budget:tight
                                            atTimeMs:_nowMs
                                            provider:_provider
                                               error:&skipError]);
    XCTAssertEqual(skipError.code, IRErrorTooManySkipped);
    XCTAssertEqual(bob.Nr, nrBefore);
    XCTAssertEqual(bob.skipped.count, 5u);
    XCTAssertEqual(tight.remaining, 5u);
}

- (void)testSkipMessageKeysIsANoOpWithoutAReceivingChain {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    /* §7.6 guard 1 and §7.4 step 1's note: on the responder's very first receive CKr is none, and
       SkipMessageKeys MUST be a no-op rather than dereferencing a null chain key. An initiator
       before B's first reply is in the same state. */
    XCTAssertNil(alice.CKr);

    IRSkipBudget *budget = [IRSkipBudget budget];
    XCTAssertTrue([IRRatchet skipMessageKeysOnState:alice
                                              until:500
                                             budget:budget
                                           atTimeMs:_nowMs
                                           provider:_provider
                                              error:&error], @"%@", error);

    XCTAssertEqual(alice.skipped.count, 0u);
    XCTAssertEqual(budget.remaining, (uint32_t)kIRMaxSkipPerMessage, @"a no-op MUST not spend budget");
}

#pragma mark - NEG-SPK-SURVIVES-RATCHET (§7.5, §15.4)

- (void)testNegSPKSurvivesRatchet_SecondInitiatorAgainstTheSameSpkIdStillSucceeds {
    NSError *error = nil;

    /* Initiator 1 completes a handshake and B ratchets past it — §7.4 step 4 destroys B's
       session-owned copy of SPK_B_priv on that very first ratchet. */
    IRRatchetState *alice1 = nil;
    IRRatchetState *bob1 = nil;
    [self establishAlice:&alice1 bob:&bob1];

    NSData *bobReply = [self send:[self plaintext:@"b0"] from:bob1 error:&error];
    XCTAssertNotNil(bobReply, @"%@", error);

    /* Initiator 2 fetches the SAME bundle, naming the same spk_id. A port that aliased the prekey
       store from ratchet state has already wiped SPK_B_priv, and this handshake fails — reported as
       ERR_AEAD_AUTH_FAILED, the code §1.2 defines as an active man-in-the-middle, because clamping
       maps the wiped all-zero scalar to 2^254 so §4.4 check 3 never fires.

       THIS IS THE ONLY VECTOR THAT DISTINGUISHES COPY FROM ALIAS; every other ratchet test in this
       file is single-session and passes either way. */
    IRIdentity *savedAlice = _alice;
    _alice = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_alice, @"%@", error);

    IRRatchetState *alice2 = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice2, @"%@", error);

    NSData *second = [self send:[self plaintext:@"second initiator"] from:alice2 error:&error];
    XCTAssertNotNil(second, @"%@", error);

    IRMessageHeader *header = [self gate:second forState:nil error:&error];
    XCTAssertNotNil(header, @"%@", error);
    XCTAssertEqual(header.spkId, kSpkId);

    IRRatchetState *bob2 = [self bobStateForHeader:header
                                signedPreKeyRecord:_bobSignedPreKey
                               oneTimePreKeyRecord:_bobOneTimePreKey
                                             error:&error];
    XCTAssertNotNil(bob2, @"%@", error);

    NSData *recovered = [self receive:second into:&bob2 error:&error];
    XCTAssertNotNil(recovered, @"%@", error);
    XCTAssertEqualObjects(recovered, [self plaintext:@"second initiator"]);

    _alice = savedAlice;
}

#pragma mark - §7.7 snapshot isolation

- (void)testSnapshotOwnsItsSecretsSoDiscardCannotTouchTheLiveState {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    IRRatchetState *snapshot = [bob snapshot];
    XCTAssertNotNil(snapshot);

    /* Distinct objects, equal values — the split IRRatchetState.h documents. */
    XCTAssertNotEqual(snapshot.RK, bob.RK);
    XCTAssertNotEqual(snapshot.CKr, bob.CKr);
    XCTAssertNotEqual(snapshot.DHs.privateKey, bob.DHs.privateKey);
    XCTAssertTrue([snapshot.RK isEqualToSecretBytes:bob.RK]);
    XCTAssertTrue([snapshot.CKr isEqualToSecretBytes:bob.CKr]);
    XCTAssertTrue([snapshot.DHs.privateKey isEqualToSecretBytes:bob.DHs.privateKey]);

    /* Immutable values are shared, which is safe precisely because they are immutable. */
    XCTAssertEqual(snapshot.DHr, bob.DHr);
    XCTAssertEqual(snapshot.sessionAD, bob.sessionAD);

    [snapshot zeroizeAsDiscardedSnapshot];

    XCTAssertTrue(snapshot.isZeroized);
    XCTAssertFalse(bob.isZeroized);
    XCTAssertFalse([bob.RK isAllZero]);
    XCTAssertFalse([bob.CKr isAllZero]);
    XCTAssertFalse([bob.DHs.privateKey isAllZero]);
}

- (void)testDiscardedSnapshotIsInertAndCannotBeUsedAgain {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    IRRatchetState *snapshot = [bob snapshot];
    [snapshot zeroizeAsDiscardedSnapshot];

    /* A caller that commits a discarded snapshot gets a loud error on its next operation rather
       than a session silently keyed with zeros. */
    NSError *error = nil;
    XCTAssertNil([IRRatchet encryptOnState:snapshot
                                 plaintext:[self plaintext:@"x"]
                               messageType:IRMessageTypeNormal
                         initiatorIdentity:nil
                           identityBinding:nil
                                  provider:_provider
                                     error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    XCTAssertNil([snapshot snapshot]);
}

- (void)testCommitZeroizesTheSupersededStateButNotTheCommittedOne {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;
    NSData *message = [self send:[self plaintext:@"committed"] from:alice error:&error];
    XCTAssertNotNil(message, @"%@", error);

    IRRatchetState *superseded = bob;
    XCTAssertNotNil([self receive:message into:&bob error:&error], @"%@", error);

    XCTAssertNotEqual(bob, superseded);
    XCTAssertTrue(superseded.isZeroized);
    XCTAssertTrue([superseded.RK isAllZero]);
    XCTAssertTrue([superseded.CKr isAllZero]);

    /* §13.3's rows for RK, CK and the session-owned ratchet private land at the commit, not inside
       the KDFs: a KDF that wiped its input would destroy the live CKr on every forged message. */
    XCTAssertFalse(bob.isZeroized);
    XCTAssertFalse([bob.RK isAllZero]);
    XCTAssertFalse([bob.CKr isAllZero]);
}

#pragma mark - §7.4 DH ratchet

- (void)testDHRatchetReplacesTheRatchetKeyForBothRoles {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    IRX25519Public *bobKeyBefore = bob.DHs.publicKey;
    IRRootKey *bobRootBefore = [bob.RK duplicate];

    NSData *message = [self send:[self plaintext:@"turn"] from:alice error:&error];
    XCTAssertNotNil([self receive:message into:&bob error:&error], @"%@", error);

    /* Bob already ratcheted on the establishing message, so this in-chain message must NOT ratchet
       again: §7.9 phase 3b runs only when the peer's key actually moved. */
    XCTAssertTrue([bob.DHs.publicKey isEqualToX25519Public:bobKeyBefore]);
    XCTAssertTrue([bob.RK isEqualToSecretBytes:bobRootBefore]);

    /* Now make A move, and B must roll everything. */
    NSData *bobReply = [self send:[self plaintext:@"b"] from:bob error:&error];
    XCTAssertNotNil([self receive:bobReply into:&alice error:&error], @"%@", error);

    NSData *newChain = [self send:[self plaintext:@"new chain"] from:alice error:&error];
    XCTAssertNotNil([self receive:newChain into:&bob error:&error], @"%@", error);

    XCTAssertFalse([bob.DHs.publicKey isEqualToX25519Public:bobKeyBefore]);
    XCTAssertFalse([bob.RK isEqualToSecretBytes:bobRootBefore]);
    XCTAssertEqual(bob.Nr, 1u);
    XCTAssertEqual(bob.Ns, 0u);
}

- (void)testDHRatchetProducesTwoDistinctChainsFromTwoSequentialRootSteps {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    /* §7.4 steps 3 and 5 are strictly sequential: the second KDF_RK consumes the RK the first
       produced, so the receiving and sending chains are different keys. v3 assigned rootKey twice
       from two INDEPENDENT derivations of the DH output alone, discarding the previous root key
       both times, so the root chain had no continuity at all. */
    XCTAssertNotNil(bob.CKs);
    XCTAssertNotNil(bob.CKr);
    XCTAssertFalse([bob.CKs isEqualToSecretBytes:bob.CKr]);
}

#pragma mark - §7.8 send-side guards

- (void)testEmptyPlaintextIsLegalAndProducesTheMinimumMessage {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    /* B is the responder, so it always sends type `0x01`.

       §10.4 — "Empty plaintext (length 0) is LEGAL and produces a 72-byte type 0x01 message." v3
       returned nil when the CBC output was zero-length, conflating "empty input" with "encryption
       failed"; a caller MUST NOT treat 0 as an error. The length is exact because ChaCha20 is a
       stream cipher: 56 header + 0 ciphertext + 16 tag. */
    NSData *fromBob = [self send:[NSData data] from:bob error:&error];
    XCTAssertNotNil(fromBob, @"%@", error);
    XCTAssertEqual(fromBob.length, (NSUInteger)kIRLenType01Min);

    NSData *aliceGot = [self receive:fromBob into:&alice error:&error];
    XCTAssertNotNil(aliceGot, @"%@", error);
    XCTAssertEqual(aliceGot.length, 0u);

    /* A has not yet decrypted anything from B at the point it built ITS empty message, so §11.3
       keeps it on type `0x02` — whose floor is 241, and which is equally legal empty. Asserting
       both floors here is what makes this test cover §10.4 rather than just one of its two rows. */
    IRRatchetState *aliceBeforeReply = nil;
    IRRatchetState *bobBeforeReply = nil;
    [self establishAlice:&aliceBeforeReply bob:&bobBeforeReply];

    NSData *fromAlice = [self send:[NSData data] from:aliceBeforeReply error:&error];
    XCTAssertNotNil(fromAlice, @"%@", error);
    XCTAssertEqual(fromAlice.length, (NSUInteger)kIRLenType02Min);

    NSData *bobGot = [self receive:fromAlice into:&bobBeforeReply error:&error];
    XCTAssertNotNil(bobGot, @"%@", error);
    XCTAssertEqual(bobGot.length, 0u);
}

- (void)testPlaintextAboveMaxIsRejectedBeforeAnythingIsDerived {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    IRChainKey *chainBefore = [alice.CKs duplicate];
    const uint32_t nsBefore = alice.Ns;
    const uint64_t sendCounterBefore = alice.sendCounter;

    NSError *error = nil;
    NSData *oversize = [NSMutableData dataWithLength:(NSUInteger)kIRMaxPlaintext + 1];
    XCTAssertNil([self send:oversize from:alice error:&error]);
    XCTAssertEqual(error.code, IRErrorPlaintextTooLarge);

    /* §10.4 — the bound is checked "before any allocation sized from the input", and a rejected
       send must not have consumed a chain-key step. */
    XCTAssertTrue([alice.CKs isEqualToSecretBytes:chainBefore]);
    XCTAssertEqual(alice.Ns, nsBefore);
    XCTAssertEqual(alice.sendCounter, sendCounterBefore);
}

- (void)testCounterCeilingIsRefusedBeforeTheChainAdvances {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    alice.Ns = (uint32_t)kIRMaxCounter;

    IRChainKey *chainBefore = [alice.CKs duplicate];

    NSError *error = nil;
    XCTAssertNil([self send:[self plaintext:@"overflow"] from:alice error:&error]);
    XCTAssertEqual(error.code, IRErrorCounterOverflow);

    /* The same 0x7FFFFFFF ceiling the receive gates apply, so this framework can never emit a
       message its own parser would reject. */
    XCTAssertTrue([alice.CKs isEqualToSecretBytes:chainBefore]);
}

- (void)testEveryMessageCarriesAFreshRandomNonce {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;
    NSMutableSet<NSData *> *nonces = [NSMutableSet set];

    for (NSUInteger i = 0; i < 8; i++) {
        NSData *message = [self send:[self plaintext:@"nonce"] from:alice error:&error];
        XCTAssertNotNil(message, @"%@", error);

        IRMessageHeader *header = [self gate:message forState:bob error:&error];
        XCTAssertNotNil(header, @"%@", error);
        [nonces addObject:header.nonce.data];

        XCTAssertNotNil([self receive:message into:&bob error:&error], @"%@", error);
    }

    /* §8.3 — the nonce MUST come from the CSPRNG, MUST NOT be a counter and MUST NOT be derived
       from the message key. A derived nonce repeats (key, nonce) after any state restore or fork,
       which under ChaCha20-Poly1305 discloses the keystream XOR and leaks the Poly1305 one-time
       key, permitting forgery. */
    XCTAssertEqual(nonces.count, 8u);
}

#pragma mark - §11.3 prologue lifecycle

- (void)testInitiatorSendsPrekeyMessagesUntilItDecryptsOneAndThenStops {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);
    XCTAssertTrue(alice.shouldSendPreKeyMessage);

    NSData *first = [self send:[self plaintext:@"1"] from:alice error:&error];
    IRMessageHeader *firstHeader = [self gate:first forState:nil error:&error];
    XCTAssertEqual(firstHeader.type, IRMessageTypePrekey);

    IRRatchetState *bob = [self bobStateForHeader:firstHeader
                               signedPreKeyRecord:_bobSignedPreKey
                              oneTimePreKeyRecord:_bobOneTimePreKey
                                            error:&error];
    XCTAssertNotNil([self receive:first into:&bob error:&error], @"%@", error);

    /* §11.3 — A does not yet know the session was established, so its second message is also a
       prekey message carrying the IDENTICAL prologue with an incrementing N. */
    NSData *second = [self send:[self plaintext:@"2"] from:alice error:&error];
    IRMessageHeader *secondHeader = [self gate:second forState:nil error:&error];
    XCTAssertEqual(secondHeader.type, IRMessageTypePrekey);
    XCTAssertEqual(secondHeader.N, 1u);
    XCTAssertTrue([secondHeader.ephemeralPublic isEqualToX25519Public:firstHeader.ephemeralPublic]);
    XCTAssertEqual(secondHeader.spkId, firstHeader.spkId);
    XCTAssertEqual(secondHeader.opkFlag, firstHeader.opkFlag);
    XCTAssertEqual(secondHeader.opkId, firstHeader.opkId);
    XCTAssertEqualObjects(secondHeader.identityBinding.data, firstHeader.identityBinding.data);
    XCTAssertNotNil([self receive:second into:&bob error:&error], @"%@", error);

    /* B replies. Once A decrypts it, CKr exists and the prologue is cleared. */
    NSData *reply = [self send:[self plaintext:@"b"] from:bob error:&error];
    XCTAssertNotNil([self receive:reply into:&alice error:&error], @"%@", error);

    XCTAssertNil(alice.prologue);
    XCTAssertFalse(alice.shouldSendPreKeyMessage);

    NSData *third = [self send:[self plaintext:@"3"] from:alice error:&error];
    IRMessageHeader *thirdHeader = [self gate:third forState:bob error:&error];
    XCTAssertEqual(thirdHeader.type, IRMessageTypeNormal);
}

- (void)testPrekeyMessageRequiresAMatchingInitiatorIdentity {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceInitialStateWithResult:NULL error:&error];
    XCTAssertNotNil(alice, @"%@", error);

    IRIdentity *stranger = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(stranger, @"%@", error);

    /* A type `0x02` header whose IK_A is not the identity SESSION_AD was built from makes every
       receiver compute a different AD and report ERR_AEAD_AUTH_FAILED — §1.2's code for an active
       man-in-the-middle — for what is really a local wiring mistake. Name it at the source. */
    NSError *mismatchError = nil;
    XCTAssertNil([IRRatchet encryptOnState:alice
                                 plaintext:[self plaintext:@"x"]
                               messageType:IRMessageTypePrekey
                         initiatorIdentity:stranger.identityKeyPair
                           identityBinding:stranger.binding
                                  provider:_provider
                                     error:&mismatchError]);
    XCTAssertEqual(mismatchError.code, IRErrorIdentityMismatch);
}

- (void)testResponderCannotEmitAPrekeyMessage {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    XCTAssertFalse(bob.shouldSendPreKeyMessage);

    NSError *error = nil;
    XCTAssertNil([IRRatchet encryptOnState:bob
                                 plaintext:[self plaintext:@"x"]
                               messageType:IRMessageTypePrekey
                         initiatorIdentity:_alice.identityKeyPair
                           identityBinding:_alice.binding
                                  provider:_provider
                                     error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);
}

#pragma mark - §7.6 store semantics

- (IRMessageKey * _Nonnull)freshMessageKey {
    NSError *error = nil;
    IRMessageKey *key = [IRMessageKey zeroValueGuarded:NO error:&error];
    XCTAssertNotNil(key, @"%@", error);
    XCTAssertTrue([_provider fillSecretBytes:key error:&error], @"%@", error);
    return key;
}

- (IRX25519Public * _Nonnull)freshRatchetPublic {
    NSError *error = nil;
    IRX25519KeyPair *pair = [_provider generateX25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(pair, @"%@", error);
    return pair.publicKey;
}

- (void)testStoreKeyIsTheRaw36ByteTuple {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:0x01020304 atTimeMs:_nowMs]);

    IRSkippedKeyEntry *entry = [store entryForDHPublic:dh N:0x01020304];
    XCTAssertNotNil(entry);
    XCTAssertEqual(entry.storeKey.length, (NSUInteger)kIRLenSkippedMapKey);

    /* §7.6 — "the raw 36-byte tuple DHr_pub (32) ‖ uint32_be(N) (4). Not a base64 string, not a
       `|`-separated composite." */
    const uint8_t *bytes = entry.storeKey.bytes;
    XCTAssertEqualObjects([entry.storeKey subdataWithRange:NSMakeRange(0, kIRLenX25519Public)], dh.data);
    XCTAssertEqual(bytes[32], 0x01);
    XCTAssertEqual(bytes[33], 0x02);
    XCTAssertEqual(bytes[34], 0x03);
    XCTAssertEqual(bytes[35], 0x04);

    /* A different N under the same key is a different entry. */
    XCTAssertNil([store entryForDHPublic:dh N:0x01020305]);
}

- (void)testStoreEvictsTheOLDESTBYINSERTIONNotTheOldestByTimestamp {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    /* Timestamps DECREASE as insertion proceeds, so the first-inserted entry carries the LARGEST
       `inserted_at_ms`. §7.6 specifies "a single global FIFO ordered by insertion", and with an
       injectable clock (§15.5 rule 6) that can move backwards the two orderings genuinely differ.
       A port that sorted by timestamp evicts the wrong entry here. */
    const uint64_t base = _nowMs + (uint64_t)kIRMaxSkippedStored;
    for (uint32_t i = 0; i < (uint32_t)kIRMaxSkippedStored; i++) {
        XCTAssertTrue([store insertMessageKey:[self freshMessageKey]
                                     dhPublic:dh
                                            N:i
                                     atTimeMs:base - i]);
    }

    XCTAssertEqual(store.count, (NSUInteger)kIRMaxSkippedStored);
    XCTAssertNotNil([store entryForDHPublic:dh N:0]);

    IRSkippedKeyEntry *newestByInsertionOldestByClock = [store entryForDHPublic:dh
                                                                             N:(uint32_t)kIRMaxSkippedStored - 1];
    XCTAssertNotNil(newestByInsertionOldestByClock);

    XCTAssertTrue([store insertMessageKey:[self freshMessageKey]
                                 dhPublic:dh
                                        N:(uint32_t)kIRMaxSkippedStored
                                 atTimeMs:base]);

    /* The bound holds, the FIRST-INSERTED entry is gone, and the entry with the smallest timestamp
       survives. */
    XCTAssertEqual(store.count, (NSUInteger)kIRMaxSkippedStored);
    XCTAssertNil([store entryForDHPublic:dh N:0]);
    XCTAssertNotNil([store entryForDHPublic:dh N:(uint32_t)kIRMaxSkippedStored - 1]);
    XCTAssertNotNil([store entryForDHPublic:dh N:(uint32_t)kIRMaxSkippedStored]);

    /* Eviction zeroizes — but only once the removal is committed, since a snapshot may share it. */
    [store zeroizePendingRemovals];
}

- (void)testStoreTTLDropsOnlyEntriesAtOrPastTheBound {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:0 atTimeMs:_nowMs]);
    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:1 atTimeMs:_nowMs]);

    /* One millisecond short of SKIPPED_TTL_MS: both survive. */
    [store dropEntriesExpiredAtTimeMs:_nowMs + (uint64_t)kIRSkippedTTLMs - 1];
    XCTAssertEqual(store.count, 2u);

    /* Exactly at it: both go. */
    [store dropEntriesExpiredAtTimeMs:_nowMs + (uint64_t)kIRSkippedTTLMs];
    XCTAssertEqual(store.count, 0u);
}

- (void)testStoreTTLDoesNotPurgeEverythingWhenTheClockMovesBackwards {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:0 atTimeMs:_nowMs]);

    /* §7.6 defines the age as `now_ms() - inserted_at_ms`. On unsigned values a corrected or
       injected clock that moved backwards makes that subtraction underflow to a ~584-million-year
       age, silently destroying every recoverable out-of-order message in the session. */
    [store dropEntriesExpiredAtTimeMs:_nowMs - 60000];
    XCTAssertEqual(store.count, 1u);

    [store dropEntriesExpiredAtTimeMs:0];
    XCTAssertEqual(store.count, 1u);
}

- (void)testStoreInsertionOrderIsStableForSerialization {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    for (uint32_t i = 0; i < 5; i++) {
        XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:i atTimeMs:_nowMs + i]);
    }

    /* §12.1 serializes the entries in this order, and §7.6 evicts from its head. One list, so the
       two cannot drift. */
    NSArray<IRSkippedKeyEntry *> *ordered = [store entriesInInsertionOrder];
    XCTAssertEqual(ordered.count, 5u);
    for (uint32_t i = 0; i < 5; i++) {
        XCTAssertEqual(ordered[i].N, i);
    }

    [store removeEntryForDHPublic:dh N:2];

    NSArray<IRSkippedKeyEntry *> *afterRemoval = [store entriesInInsertionOrder];
    XCTAssertEqual(afterRemoval.count, 4u);
    XCTAssertEqual(afterRemoval[0].N, 0u);
    XCTAssertEqual(afterRemoval[1].N, 1u);
    XCTAssertEqual(afterRemoval[2].N, 3u);
    XCTAssertEqual(afterRemoval[3].N, 4u);
}

- (void)testSnapshotStoreSharesEntriesAndDefersRemovalZeroization {
    IRSkippedKeyStore *live = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([live insertMessageKey:[self freshMessageKey] dhPublic:dh N:0 atTimeMs:_nowMs]);

    IRSkippedKeyEntry *shared = [live entryForDHPublic:dh N:0];
    XCTAssertNotNil(shared);

    IRSkippedKeyStore *snapshot = [live copyForSnapshot];
    XCTAssertEqual([snapshot entryForDHPublic:dh N:0], shared, @"entries are shared by reference");

    [snapshot removeEntryForDHPublic:dh N:0];
    XCTAssertEqual(snapshot.count, 0u);
    XCTAssertEqual(live.count, 1u);

    /* THE DISCARD PATH. The live store still references this entry, so it MUST survive — wiping it
       here is exactly the NEG-SKIP-RETAIN failure. */
    [snapshot zeroizeDerivedInsertions];
    XCTAssertFalse(shared.isZeroized);
    XCTAssertFalse([shared.messageKey isAllZero]);

    /* THE COMMIT PATH. Now the removal is real. */
    [snapshot zeroizePendingRemovals];
    XCTAssertTrue(shared.isZeroized);
    XCTAssertTrue([shared.messageKey isAllZero]);
}

- (void)testDiscardWipesOnlyTheKeysTheAttemptDerived {
    IRSkippedKeyStore *live = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([live insertMessageKey:[self freshMessageKey] dhPublic:dh N:0 atTimeMs:_nowMs]);
    IRSkippedKeyEntry *inherited = [live entryForDHPublic:dh N:0];

    IRSkippedKeyStore *snapshot = [live copyForSnapshot];
    XCTAssertTrue([snapshot insertMessageKey:[self freshMessageKey] dhPublic:dh N:1 atTimeMs:_nowMs]);
    IRSkippedKeyEntry *derived = [snapshot entryForDHPublic:dh N:1];
    XCTAssertNotNil(derived);

    [snapshot zeroizeDerivedInsertions];

    /* §7.7 — "every intermediate secret derived during the attempt MUST be zeroized", and nothing
       else. The inherited entry belongs to the live store. */
    XCTAssertTrue(derived.isZeroized);
    XCTAssertFalse(inherited.isZeroized);
    XCTAssertEqual(live.count, 1u);
    XCTAssertNil([snapshot entryForDHPublic:dh N:1], @"a wiped entry must never be returned");
}

- (void)testStoreSupersedesRatherThanDuplicatesARepeatedStoreKey {
    IRSkippedKeyStore *store = [IRSkippedKeyStore store];
    IRX25519Public *dh = [self freshRatchetPublic];

    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:7 atTimeMs:_nowMs]);
    IRSkippedKeyEntry *first = [store entryForDHPublic:dh N:7];

    /* Unreachable from one SkipMessageKeys call, but reachable from the network: a peer that reuses
       a ratchet public key drives §7.9 phase 3b to ratchet back onto it and re-derive over the same
       (DHr, N) range. A duplicate would leave the dictionary and the order array disagreeing about
       `count` for the rest of the session. */
    XCTAssertTrue([store insertMessageKey:[self freshMessageKey] dhPublic:dh N:7 atTimeMs:_nowMs + 1]);

    XCTAssertEqual(store.count, 1u);
    XCTAssertEqual([store entriesInInsertionOrder].count, 1u);
    XCTAssertNotEqual([store entryForDHPublic:dh N:7], first);
}

- (void)testTTLExpiryIsAppliedOnEveryDecrypt {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;

    NSData *m0 = [self send:[self plaintext:@"m0"] from:alice error:&error];
    NSData *m1 = [self send:[self plaintext:@"m1"] from:alice error:&error];
    XCTAssertNotNil(m1, @"%@", error);

    XCTAssertNotNil([self receive:m1 into:&bob error:&error], @"%@", error);
    XCTAssertEqual(bob.skipped.count, 1u);

    /* §7.9 phase 2 sweeps the store on every decrypt against the §15.5 rule 6 time source. Deliver
       a later message a full TTL on, and the straggler's key is gone. */
    NSData *m2 = [self send:[self plaintext:@"m2"] from:alice error:&error];
    XCTAssertNotNil([self receive:m2
                             into:&bob
                         atTimeMs:_nowMs + (uint64_t)kIRSkippedTTLMs
                            error:&error], @"%@", error);
    XCTAssertEqual(bob.skipped.count, 0u);

    NSError *goneError = nil;
    XCTAssertNil([self receive:m0 into:&bob atTimeMs:_nowMs + (uint64_t)kIRSkippedTTLMs error:&goneError]);
    XCTAssertEqual(goneError.code, IRErrorReplay);
}

#pragma mark - Argument hygiene

- (void)testDecryptRejectsAHeaderThatDidNotComeFromTheMessage {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;
    NSData *first = [self send:[self plaintext:@"one"] from:alice error:&error];
    NSData *second = [self send:[self plaintext:@"two"] from:alice error:&error];
    XCTAssertNotNil(second, @"%@", error);

    IRMessageHeader *headerOfFirst = [self gate:first forState:bob error:&error];
    XCTAssertNotNil(headerOfFirst, @"%@", error);

    /* The AD comes from the header and the ciphertext from the message; a mismatched pair would
       authenticate one byte string while decrypting another. */
    IRRatchetState *snapshot = [bob snapshot];
    NSError *mismatchError = nil;
    XCTAssertNil([IRRatchet decryptOnSnapshot:snapshot
                                      message:second
                                       header:headerOfFirst
                                       budget:[IRSkipBudget budget]
                                     atTimeMs:_nowMs
                                     provider:_provider
                                        error:&mismatchError]);
    XCTAssertEqual(mismatchError.code, IRErrorStateCorrupt);
}

- (void)testTamperedHeaderBytesAreAnAuthenticationFailure {
    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    [self establishAlice:&alice bob:&bob];

    NSError *error = nil;
    NSData *message = [self send:[self plaintext:@"authentic"] from:alice error:&error];
    XCTAssertNotNil(message, @"%@", error);

    /* §8.5 — AD is SESSION_AD ‖ the COMPLETE header, so the nonce field is both the AEAD nonce and
       part of the AD. Flipping a byte inside the header region is an authentication failure, not a
       parse error: version, type and flags are cryptographically enforced rather than checked by an
       `if`, which is a strictly stronger fix for defect 13 and comes free with the AEAD. */
    NSMutableData *tampered = [message mutableCopy];
    ((uint8_t *)tampered.mutableBytes)[kIROffType01Nonce] ^= 0x01;

    NSError *tamperError = nil;
    XCTAssertNil([self receive:tampered into:&bob error:&tamperError]);
    XCTAssertEqual(tamperError.code, IRErrorAEADAuthFailed);

    XCTAssertEqualObjects([self receive:message into:&bob error:&error], [self plaintext:@"authentic"]);
}

@end
