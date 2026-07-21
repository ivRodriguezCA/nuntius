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
#import "IREnvironment.h"
#import "IREnvironment+Testing.h"
#import "IRErrors.h"
#import "IRIdentity.h"
#import "IRInMemoryPreKeyStore.h"
#import "IRInMemorySessionStore.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRMessenger.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRPreKeyStore.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSession+Internal.h"
#import "IRSessionStore.h"
#import "IRSodiumCryptoProvider.h"

/**
 The consumer API — SPEC §5.3, §6.6, §10.7, §11.1.1, §11.2, §11.3, §11.5.

 THE FIVE ROWS OF §15.3/§15.4 THAT EXIST NOWHERE ELSE IN THE SUITE ARE HERE, because each of them
 tests the RECEIVE ENTRY POINT rather than a component beneath it, and until IRMessenger existed
 they had no subject:

   NEG-NO-SESSION             §11.5 rule 1 — both variants
   NEG-DEMUX-WRONG-SESSION    §11.5 rules 1 and 3
   NEG-PUBKEY-REFLECT-02-SPK  §10.7 step 6, the one anti-reflection check no gate can perform
   RATCHET-PREKEY-BURST       §9.2, §11.3
   RATCHET-RETRANSMIT         §11.2

 Ordering assertions here follow the discipline the lower layers established: an ordering claim is
 only tested by an input that is wrong in TWO ways, because an input wrong in one way passes under
 every ordering. Three such tests bracket §10.7's steps 3-4, 4-5 and 6-7.
 */
@interface IRMessengerSpec : XCTestCase
@end

@implementation IRMessengerSpec {
    IRFixedClock *_clock;
    IREnvironment *_environment;
    IRSodiumCryptoProvider *_provider;

    IRIdentity *_aliceIdentity;
    IRIdentity *_bobIdentity;

    IRInMemoryPreKeyStore *_alicePreKeys;
    IRInMemoryPreKeyStore *_bobPreKeys;
    IRInMemorySessionStore *_aliceSessions;
    IRInMemorySessionStore *_bobSessions;

    IRMessenger *_alice;
    IRMessenger *_bob;

    NSData *_bobBundle;
}

static const uint64_t kNowS = 1700000000ULL;
static const uint32_t kBobSpkId = 0x11223344;

#pragma mark - Fixture

- (void)setUp {
    [super setUp];

    NSError *error = nil;

    _clock = [IRFixedClock clockAtUnixSeconds:kNowS];
    _environment = [IREnvironment environmentWithClock:_clock];

    _provider = [IRSodiumCryptoProvider providerWithEnvironment:_environment error:&error];
    XCTAssertNotNil(_provider, @"%@", error);

    _aliceIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_aliceIdentity, @"%@", error);

    _bobIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_bobIdentity, @"%@", error);

    _alicePreKeys = [IRInMemoryPreKeyStore store];
    _bobPreKeys = [IRInMemoryPreKeyStore store];
    _aliceSessions = [IRInMemorySessionStore store];
    _bobSessions = [IRInMemorySessionStore store];

    _alice = [self messengerWithIdentity:_aliceIdentity
                            preKeyStore:_alicePreKeys
                           sessionStore:_aliceSessions];
    _bob = [self messengerWithIdentity:_bobIdentity
                          preKeyStore:_bobPreKeys
                         sessionStore:_bobSessions];

    _bobBundle = [self publishBundleFrom:_bob opkCount:1];
}

- (IRMessenger *)messengerWithIdentity:(IRIdentity *)identity
                           preKeyStore:(id<IRPreKeyStore>)preKeyStore
                          sessionStore:(id<IRSessionStore>)sessionStore {
    NSError *error = nil;
    IRMessenger *messenger = [[IRMessenger alloc] initWithIdentity:identity
                                                       preKeyStore:preKeyStore
                                                      sessionStore:sessionStore
                                                          provider:_provider
                                                       environment:_environment
                                                             error:&error];
    XCTAssertNotNil(messenger, @"%@", error);
    return messenger;
}

- (NSData *)publishBundleFrom:(IRMessenger *)messenger opkCount:(uint16_t)opkCount {
    NSError *error = nil;
    NSData *bundle = [messenger publishBundleWithSPKId:kBobSpkId
                                            notBeforeS:kNowS - 100
                                             notAfterS:kNowS + 100000
                                              opkCount:opkCount
                                                 error:&error];
    XCTAssertNotNil(bundle, @"%@", error);
    return bundle;
}

#pragma mark - Helpers

/// Alice opens a session against Bob's published bundle. The returned session sends type `0x02`.
- (IRSession *)aliceBeginsSession {
    NSError *error = nil;
    IRSession *session = [_alice beginSessionWithBundleData:_bobBundle error:&error];
    XCTAssertNotNil(session, @"%@", error);
    return session;
}

- (NSData *)encryptFrom:(IRMessenger *)messenger
              inSession:(IRSession *)session
                   text:(NSString *)text {
    NSError *error = nil;
    NSData *message = [messenger encrypt:[text dataUsingEncoding:NSUTF8StringEncoding]
                               inSession:session
                                   error:&error];
    XCTAssertNotNil(message, @"%@", error);
    return message;
}

- (NSString *)textOf:(IRDecryptedMessage *)decrypted {
    return [[NSString alloc] initWithData:decrypted.plaintext encoding:NSUTF8StringEncoding];
}

/// A complete A->B handshake: Alice opens, sends one prekey message, Bob receives it.
- (void)establishAliceToBobWithSession:(IRSession * __autoreleasing *)outAlice
                            bobSession:(IRSession * __autoreleasing *)outBob {
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *message = [self encryptFrom:_alice inSession:aliceSession text:@"hello"];

    IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:message error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqualObjects([self textOf:decrypted], @"hello");
    XCTAssertTrue(decrypted.establishedNewSession);

    if (outAlice != NULL) {
        *outAlice = aliceSession;
    }
    if (outBob != NULL) {
        *outBob = decrypted.session;
    }
}

/// A copy of `message` with one field overwritten in place. Every forgery below is expressed this
/// way so the test states exactly which §9.2 field it is attacking and at which offset.
- (NSData *)message:(NSData *)message
      withBytes:(NSData *)replacement
       atOffset:(NSUInteger)offset {
    NSMutableData *forged = [message mutableCopy];
    XCTAssertLessThanOrEqual(offset + replacement.length, forged.length);
    [forged replaceBytesInRange:NSMakeRange(offset, replacement.length)
                      withBytes:replacement.bytes];
    return forged;
}

- (NSData *)message:(NSData *)message withFlippedByteAtOffset:(NSUInteger)offset {
    NSMutableData *forged = [message mutableCopy];
    XCTAssertLessThan(offset, forged.length);
    uint8_t *bytes = (uint8_t *)forged.mutableBytes;
    bytes[offset] ^= 0xFF;
    return forged;
}

- (NSData *)bigEndianUInt32:(uint32_t)value {
    uint8_t bytes[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8), (uint8_t)value
    };
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)freshX25519PublicData {
    NSError *error = nil;
    IRX25519KeyPair *pair = [_provider generateX25519KeyPairWithError:&error];
    XCTAssertNotNil(pair, @"%@", error);
    return pair.publicKey.data;
}

- (void)assertError:(NSError *)error hasCode:(IRErrorCode)code {
    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.domain, IRErrorDomain);
    XCTAssertEqual(error.code, code,
                   @"expected %@, got %@",
                   IRErrorNameForCode(code), IRErrorNameForCode((IRErrorCode)error.code));
}

#pragma mark - §5.4 publish

- (void)testPublishedBundleIsExactly251Plus36PerOPK {
    for (uint16_t opkCount = 0; opkCount <= 5; opkCount++) {
        NSError *error = nil;
        NSData *bundle = [_bob publishBundleWithSPKId:kBobSpkId + opkCount
                                           notBeforeS:kNowS - 100
                                            notAfterS:kNowS + 100000
                                             opkCount:opkCount
                                                error:&error];
        XCTAssertNotNil(bundle, @"%@", error);
        XCTAssertEqual(bundle.length, (NSUInteger)(251 + 36 * opkCount),
                       @"opkCount %u", opkCount);
    }
}

- (void)testPublishStoresThePrivateHalvesSoAHandshakeCanResolveThem {
    /* The bundle carries public components only; the responder must still be able to resolve
       spk_id and opk_id locally, which is what §10.7 steps 5 and 7 do. */
    NSError *error = nil;
    XCTAssertNotNil([_bobPreKeys signedPreKeyRecordForId:kBobSpkId error:&error], @"%@", error);
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)1);
}

- (void)testPublishRefusesAWindowLongerThanMaxSPKValidity {
    /* §5.3 rule 6 is the PEER's check, but a window that can never satisfy it is a local
       misconfiguration; failing at the publisher is what makes it diagnosable. */
    NSError *error = nil;
    NSData *bundle = [_bob publishBundleWithSPKId:0x99
                                       notBeforeS:kNowS
                                        notAfterS:kNowS + (uint64_t)kIRMaxSPKValiditySeconds + 1
                                         opkCount:0
                                            error:&error];
    XCTAssertNil(bundle);
    [self assertError:error hasCode:IRErrorPreKeyExpired];
}

- (void)testPublishRefusesAnInvertedWindow {
    /* §5.3 rule 6's subtraction is only safe because rule 5 bounds its operands; an inverted
       window underflows on unsigned values and yields a silently enormous difference. */
    NSError *error = nil;
    NSData *bundle = [_bob publishBundleWithSPKId:0x9A
                                       notBeforeS:kNowS + 1000
                                        notAfterS:kNowS
                                         opkCount:0
                                            error:&error];
    XCTAssertNil(bundle);
    [self assertError:error hasCode:IRErrorPreKeyExpired];
}

- (void)testPublishRefusesMoreOPKsThanABundleCanCarry {
    NSError *error = nil;
    NSData *bundle = [_bob publishBundleWithSPKId:0x9B
                                       notBeforeS:kNowS - 100
                                        notAfterS:kNowS + 100000
                                         opkCount:(uint16_t)(kIRMaxBundleOPKCount + 1)
                                            error:&error];
    XCTAssertNil(bundle);
    [self assertError:error hasCode:IRErrorBundleMalformed];
}

#pragma mark - End-to-end

- (void)testHandshakeAndFirstMessage {
    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    XCTAssertEqual(aliceSession.role, IRSessionRoleInitiator);
    XCTAssertEqual(bobSession.role, IRSessionRoleResponder);
    XCTAssertEqualObjects(aliceSession.handshakeId, bobSession.handshakeId);

    /* §6.5 — each side sees the other as the peer, from the same SESSION_AD read at role-ordered
       offsets. A port that recomputed AD as (self, peer) would still agree here and fail only on
       the reply, which is why RATCHET-BIDI exists. */
    XCTAssertTrue([aliceSession.peerIdentityKeyPair
                      isEqualToIdentityKeyPair:_bobIdentity.identityKeyPair]);
    XCTAssertTrue([bobSession.peerIdentityKeyPair
                      isEqualToIdentityKeyPair:_aliceIdentity.identityKeyPair]);
}

- (void)testRATCHET_BIDI_ThroughTheConsumerAPI {
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *reply = [self encryptFrom:_bob inSession:bobSession text:@"hi back"];
    IRDecryptedMessage *atAlice = [_alice decryptMessage:reply
                                fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                                  error:&error];
    XCTAssertNotNil(atAlice, @"%@", error);
    XCTAssertEqualObjects([self textOf:atAlice], @"hi back");

    NSData *third = [self encryptFrom:_alice inSession:aliceSession text:@"third"];
    IRDecryptedMessage *atBob = [_bob decryptMessage:third
                             fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                               error:&error];
    XCTAssertNotNil(atBob, @"%@", error);
    XCTAssertEqualObjects([self textOf:atBob], @"third");

    NSData *fourth = [self encryptFrom:_bob inSession:bobSession text:@"fourth"];
    IRDecryptedMessage *atAliceAgain = [_alice decryptMessage:fourth
                                     fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                                       error:&error];
    XCTAssertNotNil(atAliceAgain, @"%@", error);
    XCTAssertEqualObjects([self textOf:atAliceAgain], @"fourth");
}

- (void)testTenMessagesInOneDirection {
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    /* Bob replies once so Alice leaves §11.3's prekey phase and the run is over type `0x01`. */
    NSData *reply = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:reply
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    for (NSUInteger index = 0; index < 10; index++) {
        NSString *text = [NSString stringWithFormat:@"message-%lu", (unsigned long)index];
        NSData *message = [self encryptFrom:_alice inSession:aliceSession text:text];

        IRDecryptedMessage *decrypted = [_bob decryptMessage:message
                                     fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                       error:&error];
        XCTAssertNotNil(decrypted, @"%@", error);
        XCTAssertEqualObjects([self textOf:decrypted], text);
        XCTAssertFalse(decrypted.establishedNewSession);
    }
}

- (void)testEmptyPlaintextRoundTripsThroughTheConsumerAPI {
    /* §10.4 — zero-length plaintext is LEGAL and produces the type's minimum message. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *message = [_alice encrypt:[NSData data] inSession:aliceSession error:&error];
    XCTAssertNotNil(message, @"%@", error);
    XCTAssertEqual(message.length,
                   [IRMessageHeader minimumMessageLengthForType:IRMessageTypePrekey]);

    IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:message error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqual(decrypted.plaintext.length, (NSUInteger)0);
}

- (void)testPlaintextAboveMaxIsRefused {
    NSError *error = nil;
    IRSession *aliceSession = [self aliceBeginsSession];

    NSData *tooLarge = [NSMutableData dataWithLength:(NSUInteger)kIRMaxPlaintext + 1];
    NSData *message = [_alice encrypt:tooLarge inSession:aliceSession error:&error];
    XCTAssertNil(message);
    [self assertError:error hasCode:IRErrorPlaintextTooLarge];
}

- (void)testFingerprintsAgreeAcrossParties {
    /* §5.5 — the value an application displays as a safety number. Both sides must derive the same
       32 bytes for the same identity, or the comparison a user performs is meaningless. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    IRFingerprint *bobsOwn = [_bob fingerprint:&error];
    XCTAssertNotNil(bobsOwn, @"%@", error);

    IRFingerprint *bobAsSeenByAlice = [aliceSession peerFingerprintWithProvider:_provider
                                                                         error:&error];
    XCTAssertNotNil(bobAsSeenByAlice, @"%@", error);
    XCTAssertTrue([bobsOwn isEqualToFixedLengthData:bobAsSeenByAlice]);
}

#pragma mark - §11.3 — when the initiator stops sending type 0x02

- (void)testInitiatorSendsPreKeyMessagesUntilItDecryptsOneAndThenStops {
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    XCTAssertTrue(aliceSession.sendsPreKeyMessages);

    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"one"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:first error:&error], IRMessageTypePrekey);

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:first error:&error];
    XCTAssertNotNil(atBob, @"%@", error);

    /* Bob is a responder and never sends type `0x02`. */
    XCTAssertFalse(atBob.session.sendsPreKeyMessages);
    NSData *reply = [self encryptFrom:_bob inSession:atBob.session text:@"reply"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:reply error:&error], IRMessageTypeNormal);

    /* The transition is DERIVED: Alice's first successful decrypt clears the prologue. */
    XCTAssertTrue(aliceSession.sendsPreKeyMessages);
    XCTAssertNotNil([_alice decryptMessage:reply
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    XCTAssertFalse(aliceSession.sendsPreKeyMessages);

    NSData *third = [self encryptFrom:_alice inSession:aliceSession text:@"three"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:third error:&error], IRMessageTypeNormal);
}

- (void)testRATCHET_PREKEY_BURST {
    /* §15.3 — A sends three type `0x02` messages with N = 0, 1, 2 before B replies; all decrypt.
       §9.2 is emphatic that `N` MAY be non-zero here: a protocol pinning it to zero would have no
       legal encoding for A's second message before a reply, which is the common send pattern. */
    NSError *error = nil;
    IRSession *aliceSession = [self aliceBeginsSession];

    NSMutableArray<NSData *> *burst = [NSMutableArray array];
    for (NSUInteger index = 0; index < 3; index++) {
        NSString *text = [NSString stringWithFormat:@"burst-%lu", (unsigned long)index];
        NSData *message = [self encryptFrom:_alice inSession:aliceSession text:text];
        [burst addObject:message];

        XCTAssertEqual([IRMessenger messageTypeOfMessage:message error:&error],
                       IRMessageTypePrekey);

        IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
        XCTAssertNotNil(header, @"%@", error);
        XCTAssertEqual(header.N, (uint32_t)index);
        XCTAssertEqual(header.PN, (uint32_t)0);
    }

    for (NSUInteger index = 0; index < burst.count; index++) {
        IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:burst[index] error:&error];
        XCTAssertNotNil(decrypted, @"%@", error);
        XCTAssertEqualObjects([self textOf:decrypted],
                              ([NSString stringWithFormat:@"burst-%lu", (unsigned long)index]));
    }

    /* Only the FIRST opened a session; the other two routed through §11.2 to the same one. */
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)1);
}

- (void)testEveryPreKeyMessageReusesTheIdenticalPrologueAndBinding {
    /* §11.3 — "A MUST reuse the identical prologue field values across all its type `0x02`
       messages". IKB_A is read from the long-lived identity record and MUST NOT be re-signed:
       Ed25519 is not contractually deterministic on all four platforms, and nothing in the receive
       path compares IKB_A across messages, so a re-signing port would never be caught. */
    NSError *error = nil;
    IRSession *aliceSession = [self aliceBeginsSession];

    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"a"];
    NSData *second = [self encryptFrom:_alice inSession:aliceSession text:@"b"];

    /* IK_A^s ‖ IK_A^d ‖ IKB_A ‖ EK_A ‖ spk_id ‖ opk_flag ‖ opk_id — offsets 4..173. */
    XCTAssertEqualObjects([first subdataWithRange:NSMakeRange(4, 169)],
                          [second subdataWithRange:NSMakeRange(4, 169)]);

    /* Only DHs_pub, N, nonce and the ciphertext may vary — and DHs_pub does not change within
       A's first sending chain, so in practice only N, the nonce and the ciphertext do. */
    XCTAssertEqualObjects([first subdataWithRange:NSMakeRange(173, 32)],
                          [second subdataWithRange:NSMakeRange(173, 32)]);

    IRMessageHeader *firstHeader = [IRMessageGate parseType02Message:first error:&error];
    IRMessageHeader *secondHeader = [IRMessageGate parseType02Message:second error:&error];
    XCTAssertEqual(firstHeader.N, (uint32_t)0);
    XCTAssertEqual(secondHeader.N, (uint32_t)1);
    XCTAssertFalse([firstHeader.nonce isEqualToFixedLengthData:secondHeader.nonce]);
}

- (void)testResponderCannotBeAskedToEmitAPreKeyMessage {
    /* §11.3 — a responder has no prologue, so there is no state from which one could be built. */
    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    XCTAssertFalse(bobSession.sendsPreKeyMessages);
    XCTAssertNil(bobSession.state.prologue);
}

#pragma mark - §11.5 — NEG-NO-SESSION

- (void)testNEG_NO_SESSION_PeerWithNoSessionAtAll {
    /* §15.4 row one of two: "a type `0x01` message submitted with a handle that does not resolve".
       Bob has never heard of Alice, so the peer index is empty. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *reply = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:reply
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    NSData *normal = [self encryptFrom:_alice inSession:aliceSession text:@"normal"];

    /* A third party with no session — the handle resolves to nothing. */
    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(carolIdentity, @"%@", error);
    IRMessenger *carol = [self messengerWithIdentity:carolIdentity
                                        preKeyStore:[IRInMemoryPreKeyStore store]
                                       sessionStore:[IRInMemorySessionStore store]];

    error = nil;
    IRDecryptedMessage *decrypted = [carol decryptMessage:normal
                                  fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                    error:&error];
    XCTAssertNil(decrypted);
    [self assertError:error hasCode:IRErrorNoSession];
}

- (void)testNEG_NO_SESSION_HandleThatNoLongerResolves {
    /* §15.4 row two: a handle the host still holds but which names nothing live. A torn-down
       session is exactly that — the pointer is valid, the session is not. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *reply = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:reply
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    NSData *normal = [self encryptFrom:_alice inSession:aliceSession text:@"normal"];

    XCTAssertTrue([_bobSessions tearDownSession:bobSession
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);

    error = nil;
    IRDecryptedMessage *byHandle = [_bob decryptMessage:normal inSession:bobSession error:&error];
    XCTAssertNil(byHandle);
    [self assertError:error hasCode:IRErrorNoSession];

    /* And through the peer index, which no longer holds it either. */
    error = nil;
    IRDecryptedMessage *byPeer = [_bob decryptMessage:normal
                              fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                error:&error];
    XCTAssertNil(byPeer);
    [self assertError:error hasCode:IRErrorNoSession];
}

- (void)testNEG_NO_SESSION_SitsAtCheck6AndNotBeforeTheGate {
    /* §10.1 puts the handle at CHECK 6 — after length, version, type and flags. The ordering is
       observable and it is decision D1: an implementation that resolves the session first reports
       a malformed input as ERR_NO_SESSION, turning the code into an ORACLE for which peers the
       receiver holds sessions with. Every input that fails the gate must fail identically whether
       or not a session exists.

       Each input below is wrong in TWO ways — malformed AND unresolvable — which is the only
       construction that distinguishes the two orderings. */
    NSError *error = nil;
    IRIdentityKeyPair *strangerPeer = _aliceIdentity.identityKeyPair;   /* Bob has no session */

    /* Check 1 — below the 72-byte floor. */
    error = nil;
    XCTAssertNil([_bob decryptMessage:[NSMutableData dataWithLength:10]
              fromPeerIdentityKeyPair:strangerPeer
                                error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage];

    /* Check 3 — 100 zero bytes clears the floor, then the version byte is 0x00. */
    error = nil;
    XCTAssertNil([_bob decryptMessage:[NSMutableData dataWithLength:100]
              fromPeerIdentityKeyPair:strangerPeer
                                error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion];

    /* Check 6 itself — a WELL-FORMED type `0x01` message whose peer does not resolve. This is the
       control: without it the assertions above would also pass on an implementation that never
       returns ERR_NO_SESSION at all. */
    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    NSData *wellFormed = [self encryptFrom:_alice inSession:aliceSession text:@"normal"];

    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(carolIdentity, @"%@", error);

    error = nil;
    XCTAssertNil([_bob decryptMessage:wellFormed
              fromPeerIdentityKeyPair:carolIdentity.identityKeyPair
                                error:&error]);
    [self assertError:error hasCode:IRErrorNoSession];
}

#pragma mark - §11.5 — NEG-DEMUX-WRONG-SESSION

- (void)testNEG_DEMUX_WRONG_SESSION {
    /* §15.4 — restated around a TWO-PEER fixture, because that is the only construction in which
       §11.5 rule 3 has an observable consequence.

       §11.1.1's bound is per PEER, not global, so in a single-peer setup there is no sibling to
       retry against: "did not retry" is satisfied vacuously and a trial-decrypting port passes. Here
       Bob holds two live sessions with two different peers, and the message offered against the
       wrong handle is the next legitimate message of the OTHER session's sending chain — so it
       genuinely WOULD decrypt there. A port that retries returns Alice's plaintext where the vector
       requires an error; a port that retries and then suppresses the result is caught by an advanced
       Nr and a rewritten CKr in Alice's session blob.

       Both blobs are asserted byte-identical because §12.1 is byte-normative precisely so that
       "no state mutated" (§7.7) is expressible rather than merely asserted in prose. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobWithAlice = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobWithAlice];

    NSData *ackToAlice = [self encryptFrom:_bob inSession:bobWithAlice text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ackToAlice
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    /* Carol opens her own session with Bob, against a second published bundle. */
    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(carolIdentity, @"%@", error);
    IRMessenger *carol = [self messengerWithIdentity:carolIdentity
                                        preKeyStore:[IRInMemoryPreKeyStore store]
                                       sessionStore:[IRInMemorySessionStore store]];

    NSData *secondBundle = [self publishBundleFrom:_bob opkCount:1];
    IRSession *carolSession = [carol beginSessionWithBundleData:secondBundle error:&error];
    XCTAssertNotNil(carolSession, @"%@", error);

    NSData *carolOpener = [self encryptFrom:carol inSession:carolSession text:@"carol here"];
    IRDecryptedMessage *carolAtBob = [_bob decryptPreKeyMessage:carolOpener error:&error];
    XCTAssertNotNil(carolAtBob, @"%@", error);
    IRSession *bobWithCarol = carolAtBob.session;

    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)2);
    XCTAssertNotEqualObjects(bobWithAlice.handshakeId, bobWithCarol.handshakeId);

    /* A perfectly valid type `0x01` message from Alice. */
    NSData *fromAlice = [self encryptFrom:_alice inSession:aliceSession text:@"for alice's session"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:fromAlice error:&error], IRMessageTypeNormal);

    uint64_t carolSendCounterBefore = bobWithCarol.sendCounter;
    NSData *carolStateBefore = [self serializedStateOf:bobWithCarol];
    NSData *aliceStateBefore = [self serializedStateOf:bobWithAlice];

    /* Offered against the WRONG handle. */
    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptMessage:fromAlice
                                               inSession:bobWithCarol
                                                   error:&error];
    XCTAssertNil(decrypted);
    [self assertError:error hasCode:IRErrorAEADAuthFailed];

    /* §7.7 — NOTHING mutated, on either session. */
    XCTAssertEqual(bobWithCarol.sendCounter, carolSendCounterBefore);
    XCTAssertEqualObjects([self serializedStateOf:bobWithCarol], carolStateBefore);
    XCTAssertEqualObjects([self serializedStateOf:bobWithAlice], aliceStateBefore);

    /* §15.4 `NEG-DEMUX-WRONG-PEER` — the SAME fixture and the same message, through the
       peer-resolving form. This is the entry point whose signature invites a loop over the peer
       index; the handle-taking form structurally has only one session to try. Carol's identity
       resolves to Bob's session with Carol, and Alice's message must fail there and MUST NOT fall
       back to the session where it would succeed. */
    error = nil;
    IRDecryptedMessage *viaPeer = [_bob decryptMessage:fromAlice
                               fromPeerIdentityKeyPair:carolIdentity.identityKeyPair
                                                 error:&error];
    XCTAssertNil(viaPeer, @"a retry against another session is forbidden by §11.5 rule 3");
    [self assertError:error hasCode:IRErrorAEADAuthFailed];

    /* And still nothing mutated on either session after the second attempt. */
    XCTAssertEqualObjects([self serializedStateOf:bobWithCarol], carolStateBefore);
    XCTAssertEqualObjects([self serializedStateOf:bobWithAlice], aliceStateBefore);

    /* §15.3 `DEMUX-NO-TRIAL` — the recovery step, and the one that catches the remaining shape: a
       port that trial-decrypted, COMMITTED, and reported the failure anyway. It would answer this
       with ERR_REPLAY, because Alice's session would already have consumed the message. */
    error = nil;
    IRDecryptedMessage *correct = [_bob decryptMessage:fromAlice
                                             inSession:bobWithAlice
                                                 error:&error];
    XCTAssertNotNil(correct, @"DEMUX-NO-TRIAL: the message must still decrypt; got %@", error);
    XCTAssertEqualObjects([self textOf:correct], @"for alice's session");
}

- (void)testNEG_DEMUX_TheWrongSessionAttemptDoesNotPoisonTheSkippedStore {
    /* §11.5 rule 3's stated cost: phase 3c runs SkipMessageKeys BEFORE the AEAD check, so a
       trial-decrypting port pays up to MAX_SKIP_PER_MESSAGE derivations and as many snapshot
       insertions per candidate. On the correct implementation the failed attempt leaves the
       wrong session's skipped store exactly as it was, because the snapshot is discarded. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobWithAlice = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobWithAlice];

    NSData *ack = [self encryptFrom:_bob inSession:bobWithAlice text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSUInteger skippedBefore = bobWithAlice.state.skipped.count;

    /* A forged message with a large N against the right session's own key would legitimately fill
       the store; here the same message goes to the WRONG session and must fill nothing. */
    NSData *fromAlice = [self encryptFrom:_alice inSession:aliceSession text:@"x"];

    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    IRMessenger *carol = [self messengerWithIdentity:carolIdentity
                                        preKeyStore:[IRInMemoryPreKeyStore store]
                                       sessionStore:[IRInMemorySessionStore store]];
    NSData *secondBundle = [self publishBundleFrom:_bob opkCount:1];
    IRSession *carolSession = [carol beginSessionWithBundleData:secondBundle error:&error];
    NSData *carolOpener = [self encryptFrom:carol inSession:carolSession text:@"c"];
    IRSession *bobWithCarol = [_bob decryptPreKeyMessage:carolOpener error:&error].session;
    XCTAssertNotNil(bobWithCarol, @"%@", error);

    error = nil;
    XCTAssertNil([_bob decryptMessage:fromAlice inSession:bobWithCarol error:&error]);
    [self assertError:error hasCode:IRErrorAEADAuthFailed];

    XCTAssertEqual(bobWithCarol.state.skipped.count, (NSUInteger)0);
    XCTAssertEqual(bobWithAlice.state.skipped.count, skippedBefore);
}

- (void)testNEG_ENTRYPOINT_BothDirectionsThroughTheMessenger {
    /* §15.4 `NEG-ENTRYPOINT-01-TO-02` and `NEG-ENTRYPOINT-02-TO-01`, end to end.

       The split IS §11.5 rule 1. Feeding one entry point the other's type must be a loud, SPECIFIC
       failure — ERR_WRONG_ENTRY_POINT (7125), never ERR_UNKNOWN_MESSAGE_TYPE — and never a silent
       forward. 7101's meaning is a predicate over the message alone ("byte 1 is not 0x01 or 0x02")
       and byte 1 here genuinely IS a valid type; the condition is a predicate over (message, entry
       point), with a different remedy: fix the host's demultiplexer, not drop the message (§19.8).

       §10.2's own check 1 is the 241-byte floor and fires BEFORE its check 4 reads the type byte, so
       a gate-first implementation reports a short type `0x01` message as ERR_TRUNCATED_MESSAGE — a
       truncation that is not there. §10.0 runs before both gates so both entry points answer the
       same way about a mismatch, at any length. */
    NSError *error = nil;

    /* Captured while Alice is still in §11.3's prekey phase — a genuine type `0x02`. */
    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *realPrekey = [self encryptFrom:_alice inSession:aliceSession text:@"real prekey"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:realPrekey error:&error],
                   IRMessageTypePrekey);

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:realPrekey error:&error];
    XCTAssertNotNil(atBob, @"%@", error);
    IRSession *bobSession = atBob.session;

    /* And a genuine type `0x01`, once Alice has left the prekey phase. */
    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *normal = [self encryptFrom:_alice inSession:aliceSession text:@"normal"];
    XCTAssertEqual([IRMessenger messageTypeOfMessage:normal error:&error], IRMessageTypeNormal);

    /* NEG-ENTRYPOINT-01-TO-02 — type `0x01` into the prekey-only entry point. */
    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:normal error:&error]);
    [self assertError:error hasCode:IRErrorWrongEntryPoint];

    /* And the load-bearing length case: a 72-byte type `0x01` sits BELOW §10.2's 241-byte floor, so
       this is the input that separates §10.0-first from gate-first. The vector fixes the length at
       72 for exactly this reason and forbids widening it. */
    NSData *shortNormal = [normal subdataWithRange:NSMakeRange(0, (NSUInteger)kIRLenType01Min)];
    XCTAssertLessThan(shortNormal.length, (NSUInteger)kIRLenType02Min);

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:shortNormal error:&error]);
    [self assertError:error hasCode:IRErrorWrongEntryPoint];

    /* NEG-ENTRYPOINT-02-TO-01 — type `0x02` into the normal-only entry point, through both
       handle-taking forms. THE RESOLVING HANDLE IS LOAD-BEARING: without it a port that checked
       §10.1 check 6 too early would return ERR_NO_SESSION and pass for the wrong reason. It is also
       the direction that catches auto-forwarding, which would SUCCEED and hand back a plaintext. */
    error = nil;
    XCTAssertNil([_bob decryptMessage:realPrekey inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorWrongEntryPoint];

    error = nil;
    XCTAssertNil([_bob decryptMessage:realPrekey
                fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                  error:&error]);
    [self assertError:error hasCode:IRErrorWrongEntryPoint];

    /* A type byte outside the DOMAIN is still 7101 from either entry point (NEG-TYPE). The two codes
       must stay distinct, or 7125 has swallowed an older frozen expectation. */
    NSData *unknownType = [self message:normal
                              withBytes:[NSData dataWithBytes:(uint8_t[]){0x03} length:1]
                               atOffset:1];
    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:unknownType error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType];

    error = nil;
    XCTAssertNil([_bob decryptMessage:unknownType inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType];

    /* §11.5 rule 5 — the router is REQUIRED API and is what lets a conformant host avoid 7125
       entirely. It never decrypts and takes no handle. */
    error = nil;
    XCTAssertEqual([IRMessenger messageTypeOfMessage:realPrekey error:&error], IRMessageTypePrekey);
    XCTAssertNil(error);
    XCTAssertEqual([IRMessenger messageTypeOfMessage:normal error:&error], IRMessageTypeNormal);
    XCTAssertNil(error);
}

#pragma mark - §10.7 step 6 — NEG-PUBKEY-REFLECT-02-SPK

- (void)testNEG_PUBKEY_REFLECT_02_SPK {
    /* §15.4 — "type `0x02`, NEW session, `DHs_pub` equal to the `SPK_B` public for the referenced
       `spk_id` — a value any client can fetch from the bundle".

       This is the one anti-reflection check no gate can perform, and §10.2 says so explicitly: the
       gate has not resolved `spk_id`, so it does not know what `SPK_B` is. The responder's initial
       DHs IS that key pair (§7.5), so accepting this would drive B into a DH with itself. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"reflect me"];

    IRSignedPreKeyRecord *bobSPK = [_bobPreKeys signedPreKeyRecordForId:kBobSpkId error:&error];
    XCTAssertNotNil(bobSPK, @"%@", error);

    /* Splice SPK_B's public into DHs_pub at offset 173. */
    NSData *forged = [self message:genuine
                         withBytes:bobSPK.keyPair.publicKey.data
                          atOffset:173];

    /* The §10.2 gate still passes it — DHs_pub != EK_A, the key is a valid X25519 encoding. */
    IRMessageHeader *header = [IRMessageGate parseType02Message:forged error:&error];
    XCTAssertNotNil(header, @"%@", error);

    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:forged error:&error];
    XCTAssertNil(decrypted);
    [self assertError:error hasCode:IRErrorInvalidPublicKey];

    /* Rejected BEFORE any DH — no session, and the one-time prekey is untouched. */
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)0);
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)1);
}

- (void)testAnUnreflectedRatchetKeyAgainstTheSameSpkIdIsAccepted {
    /* The negative above must not be passing because Bob rejects everything: the same message with
       a DIFFERENT DHs_pub is a genuine handshake. This is the control. */
    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"genuine"];

    NSError *error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:genuine error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)1);
}

#pragma mark - §10.7 — the remaining steps, at the messenger

- (void)testNEG_IKB_SWAP_AtTheMessenger {
    /* §15.4 — victim's genuine IK^s with an attacker-chosen IK^d, no existing session. §10.7 step
       3 verifies IKB_A BEFORE any DH, and §5.5 is the attack: an application keying trust on IK^s
       alone would display the attacker as the victim. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"swap"];

    /* Replace IK_A^d at offset 36, leaving IK_A^s and IKB_A genuine. */
    NSData *forged = [self message:genuine
                         withBytes:[self freshX25519PublicData]
                          atOffset:36];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorBadSignature];

    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)0);
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)1);
}

- (void)testNEG_OPK_UNKNOWN_AtTheMessenger {
    /* §15.4 — opk_flag == 0x01 with an unresolvable opk_id, no session. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"unknown opk"];

    NSData *forged = [self message:genuine
                         withBytes:[self bigEndianUInt32:0xDEADBEEF]
                          atOffset:169];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorUnknownPreKeyId];
}

- (void)testNEG_OPK_NOFALLBACK {
    /* §6.6 rule 2 — "There is no fallback to the 3-DH derivation." A port that fell back would
       produce a DIFFERENT SK on each side and fail at the AEAD, so the observable difference is
       the error CODE and the absence of a session. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"no fallback"];

    NSData *forged = [self message:genuine
                         withBytes:[self bigEndianUInt32:0x0BADF00D]
                          atOffset:169];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorUnknownPreKeyId];

    /* NO SESSION CREATED — the assertion §15.4 names for this row. Not ERR_AEAD_AUTH_FAILED, which
       is what a silent 3-DH fallback would have produced. */
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)0);
}

- (void)testUnresolvableSpkIdIsUnknownPreKeyId {
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"bad spk"];

    NSData *forged = [self message:genuine
                         withBytes:[self bigEndianUInt32:0x77777777]
                          atOffset:164];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorUnknownPreKeyId];
}

- (void)testNEG_HANDSHAKE_TOMBSTONE_AtTheMessenger {
    /* §15.4 / §10.7 step 4 — a type `0x02` whose handshake_id matches a tombstone inside
       HANDSHAKE_CACHE_MS. This is what bounds §17.3's no-OPK handshake replay by enforcement
       rather than by implication. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"opener"];

    IRDecryptedMessage *first = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNotNil(first, @"%@", error);

    /* Tear the session down: §11.4 writes a tombstone whenever a session is torn down for ANY
       reason, so the handshake_id is now poisoned for HANDSHAKE_CACHE_MS. */
    XCTAssertTrue([_bobSessions tearDownSession:first.session
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);
    XCTAssertEqual(_bobSessions.tombstoneCount, (NSUInteger)1);

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:opener error:&error]);
    [self assertError:error hasCode:IRErrorReplay];
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)0);
}

- (void)testATombstonedHandshakeIsAcceptedOnceTheWindowExpires {
    /* §11.4's last row, stated honestly rather than papered over: past HANDSHAKE_CACHE_MS a no-OPK
       replay establishes a new session and re-delivers the plaintext (§17.3). Here the OPK is what
       actually stops it, so the code is ERR_UNKNOWN_PREKEY_ID — the row above that one. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"opener"];

    IRDecryptedMessage *first = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNotNil(first, @"%@", error);
    XCTAssertTrue([_bobSessions tearDownSession:first.session
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);

    [_clock advanceByMilliseconds:(uint64_t)kIRHandshakeCacheMs + 1];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:opener error:&error]);
    [self assertError:error hasCode:IRErrorUnknownPreKeyId];
}

#pragma mark - §6.6 / §10.7 steps 13-14 — one-time prekey consumption

- (void)testOPKIsConsumedExactlyOnceOnTheSuccessPath {
    NSError *error = nil;
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)1);

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"consume"];

    XCTAssertNotNil([_bob decryptPreKeyMessage:opener error:&error], @"%@", error);
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)0);
}

- (void)testOPKIsNotConsumedWhenTheAEADFails {
    /* §10.7 step 13 — "On AEAD failure: return ERR_AEAD_AUTH_FAILED, discard the snapshot, do not
       commit the session, AND DO NOT DELETE THE ONE-TIME PREKEY." This ordering is the fix for
       defect 7's replay window: a forgery that burned the OPK would let an attacker deny the
       legitimate sender its own handshake. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"tamper me"];

    /* Flip a ciphertext byte, leaving every header field intact so the message reaches the AEAD. */
    NSData *forged = [self message:genuine withFlippedByteAtOffset:genuine.length - 1];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorAEADAuthFailed];

    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)1);
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)0);

    /* And the genuine message still works — the forgery cost the legitimate sender nothing. */
    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptPreKeyMessage:genuine error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqualObjects([self textOf:decrypted], @"tamper me");
    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)0);
}

#pragma mark - §10.7 ordering — inputs wrong in TWO ways

- (void)testOrder_Step3IKBVerificationBeatsStep4Tombstone {
    /* An input wrong in one way passes under every ordering, so each of these three is wrong in
       two. Here: a corrupted IKB_A whose handshake_id is ALSO tombstoned. Step 3 must win. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"opener"];

    IRDecryptedMessage *first = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNotNil(first, @"%@", error);
    XCTAssertTrue([_bobSessions tearDownSession:first.session
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);

    /* IKB_A occupies 68..132; corrupting it leaves handshake_id = IK_A^d ‖ EK_A untouched, so the
       tombstone at step 4 would still match. */
    NSData *forged = [self message:opener withFlippedByteAtOffset:68];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorBadSignature];
}

- (void)testOrder_Step4TombstoneBeatsStep5SpkResolution {
    /* A tombstoned handshake_id AND an unresolvable spk_id. Step 4 must win. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"opener"];

    IRDecryptedMessage *first = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNotNil(first, @"%@", error);
    XCTAssertTrue([_bobSessions tearDownSession:first.session
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);

    NSData *forged = [self message:opener
                         withBytes:[self bigEndianUInt32:0x77777777]
                          atOffset:164];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorReplay];
}

- (void)testOrder_Step6SpkReflectionBeatsStep7OpkResolution {
    /* DHs_pub reflected onto SPK_B AND an unresolvable opk_id. Step 6 must win — and it is the
       step that must happen BEFORE ANY DH, so getting this backwards is not merely a wrong code. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"opener"];

    IRSignedPreKeyRecord *bobSPK = [_bobPreKeys signedPreKeyRecordForId:kBobSpkId error:&error];
    XCTAssertNotNil(bobSPK, @"%@", error);

    NSData *forged = [self message:opener
                         withBytes:bobSPK.keyPair.publicKey.data
                          atOffset:173];
    forged = [self message:forged withBytes:[self bigEndianUInt32:0xDEADBEEF] atOffset:169];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey];
}

#pragma mark - §11.2 — the existing-session branch

- (void)testRATCHET_RETRANSMIT {
    /* §15.3 — "the same type `0x02` message delivered twice; the second is ERR_REPLAY, and the
       session survives (§11.2)".

       The second delivery routes to §11.2, NOT to §10.7: re-running X3DH would destroy the live
       session, and it could not succeed anyway because the OPK is gone. This is the rule that
       reconciles one-time-prekey single-use with legitimate retransmission. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *opener = [self encryptFrom:_alice inSession:aliceSession text:@"only once"];

    IRDecryptedMessage *first = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNotNil(first, @"%@", error);
    XCTAssertEqualObjects([self textOf:first], @"only once");
    IRSession *bobSession = first.session;

    error = nil;
    IRDecryptedMessage *second = [_bob decryptPreKeyMessage:opener error:&error];
    XCTAssertNil(second);
    [self assertError:error hasCode:IRErrorReplay];

    /* THE SESSION SURVIVES — the half of this row that a fail-open implementation passes and a
       fail-catastrophic one does not. */
    XCTAssertFalse(bobSession.isTornDown);
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)1);

    NSData *next = [self encryptFrom:_alice inSession:aliceSession text:@"still working"];
    error = nil;
    IRDecryptedMessage *third = [_bob decryptPreKeyMessage:next error:&error];
    XCTAssertNotNil(third, @"%@", error);
    XCTAssertEqualObjects([self textOf:third], @"still working");
    XCTAssertEqualObjects(third.session.handshakeId, bobSession.handshakeId);
}

- (void)testRetransmissionDoesNotReRunX3DHOrTouchTheOPK {
    /* §11.2 — "Do NOT re-run X3DH. Do NOT re-initialize the ratchet. Do NOT touch the OPK."
       A responder that re-runs X3DH on a repeated prekey message destroys the live session. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"first"];
    NSData *second = [self encryptFrom:_alice inSession:aliceSession text:@"second"];

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:first error:&error];
    XCTAssertNotNil(atBob, @"%@", error);
    IRSession *bobSession = atBob.session;

    XCTAssertEqual(_bobPreKeys.oneTimePreKeyCount, (NSUInteger)0);
    NSData *rootAfterFirst = [self serializedStateOf:bobSession];

    /* The second prekey message carries the same prologue and cannot re-derive SK — the OPK is
       gone. It must be processed as a NORMAL ratchet message against the live session. */
    IRDecryptedMessage *secondAtBob = [_bob decryptPreKeyMessage:second error:&error];
    XCTAssertNotNil(secondAtBob, @"%@", error);
    XCTAssertEqualObjects([self textOf:secondAtBob], @"second");
    XCTAssertFalse(secondAtBob.establishedNewSession);
    XCTAssertEqual(secondAtBob.session, bobSession);

    /* State advanced (Nr moved) but the session was not rebuilt. */
    XCTAssertNotEqualObjects([self serializedStateOf:bobSession], rootAfterFirst);
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)1);
}

- (void)testNEG_IKB_RETRANS_AtTheMessenger {
    /* §15.4 — a retransmitted type `0x02` to an EXISTING session with one byte of IKB_A flipped.
       This row arbitrates §5.5 against §11.2: IKB_A is inside the AD, so a tampered binding
       already reaches the AEAD and fails there. Both fail closed, but the CODE is a conformance
       requirement, and it MUST be the signature failure. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"first"];
    NSData *second = [self encryptFrom:_alice inSession:aliceSession text:@"second"];

    XCTAssertNotNil([_bob decryptPreKeyMessage:first error:&error], @"%@", error);

    NSData *forged = [self message:second withFlippedByteAtOffset:100];   /* inside 68..132 */

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorBadSignature];
}

- (void)testNEG_PUBKEY_REFLECT_02_DHS_AtTheMessenger {
    /* §15.4 / §11.2 check 3 — a type `0x02` to an EXISTING session with DHs_pub == s.DHs.pub. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"first"];
    NSData *second = [self encryptFrom:_alice inSession:aliceSession text:@"second"];

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:first error:&error];
    XCTAssertNotNil(atBob, @"%@", error);

    NSData *forged = [self message:second
                         withBytes:atBob.session.state.DHs.publicKey.data
                          atOffset:173];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey];
}

- (void)testIdentityMismatchOnAnExistingSession {
    /* §11.2 check 1 — the header's identity disagreeing with the cached session. Reachable only
       by pointing a genuine-looking header at a session established under a different identity. */
    NSError *error = nil;

    IRSession *aliceSession = [self aliceBeginsSession];
    NSData *first = [self encryptFrom:_alice inSession:aliceSession text:@"first"];
    NSData *second = [self encryptFrom:_alice inSession:aliceSession text:@"second"];

    XCTAssertNotNil([_bob decryptPreKeyMessage:first error:&error], @"%@", error);

    /* Replace IK_A^s at offset 4 with a different Ed25519 identity public. handshake_id is
       IK_A^d ‖ EK_A, so it is unchanged and the message still routes to the live session. */
    IRIdentity *malloryIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(malloryIdentity, @"%@", error);

    NSData *forged = [self message:second
                         withBytes:malloryIdentity.identityKeyPair.signingKey.data
                          atOffset:4];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:forged error:&error]);
    [self assertError:error hasCode:IRErrorIdentityMismatch];
}

#pragma mark - §11.1.1 — SESSION-COLLAPSE through the consumer API

- (void)testSESSION_COLLAPSE_ConcurrentInitiationConvergesOnOneSurvivor {
    /* §15.3 — A and B initiate concurrently; both independently apply §11.1.1 and MUST converge on
       the SAME surviving handshake_id, the greater of the two compared as a 64-byte unsigned
       big-endian value. "Newest wins" is not a function: each side observes a different arrival
       order, so the two sides would diverge permanently. */
    NSError *error = nil;

    /* Alice publishes too, so Bob can initiate against her. */
    NSData *aliceBundle = [_alice publishBundleWithSPKId:kBobSpkId
                                              notBeforeS:kNowS - 100
                                               notAfterS:kNowS + 100000
                                                opkCount:1
                                                   error:&error];
    XCTAssertNotNil(aliceBundle, @"%@", error);

    IRSession *aliceInitiated = [_alice beginSessionWithBundleData:_bobBundle error:&error];
    XCTAssertNotNil(aliceInitiated, @"%@", error);

    IRSession *bobInitiated = [_bob beginSessionWithBundleData:aliceBundle error:&error];
    XCTAssertNotNil(bobInitiated, @"%@", error);

    NSData *fromAlice = [self encryptFrom:_alice inSession:aliceInitiated text:@"from alice"];
    NSData *fromBob = [self encryptFrom:_bob inSession:bobInitiated text:@"from bob"];

    /* Each side receives the other's opener, which forces the collapse on both. */
    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:fromAlice error:&error];
    XCTAssertNotNil(atBob, @"%@", error);

    IRDecryptedMessage *atAlice = [_alice decryptPreKeyMessage:fromBob error:&error];
    XCTAssertNotNil(atAlice, @"%@", error);

    /* Exactly one live session per peer on each side (§11.1.1), and the SAME one. */
    XCTAssertEqual(_aliceSessions.sessionCount, (NSUInteger)1);
    XCTAssertEqual(_bobSessions.sessionCount, (NSUInteger)1);

    IRSession *aliceSurvivor = _aliceSessions.allSessions.firstObject;
    IRSession *bobSurvivor = _bobSessions.allSessions.firstObject;
    XCTAssertEqualObjects(aliceSurvivor.handshakeId, bobSurvivor.handshakeId);

    /* And it is the GREATER of the two handshake ids, compared as unsigned big-endian. */
    NSData *greater = [self greaterHandshakeIdOf:aliceInitiated.handshakeId
                                             and:bobInitiated.handshakeId];
    XCTAssertEqualObjects(aliceSurvivor.handshakeId, greater);

    /* The plaintext is delivered on BOTH sides regardless of which handshake won — a message that
       completed X3DH and passed Poly1305 is not discarded because of a race. */
    XCTAssertEqualObjects([self textOf:atBob], @"from alice");
    XCTAssertEqualObjects([self textOf:atAlice], @"from bob");
}

- (NSData *)greaterHandshakeIdOf:(NSData *)a and:(NSData *)b {
    XCTAssertEqual(a.length, (NSUInteger)kIRLenHandshakeId);
    XCTAssertEqual(b.length, (NSUInteger)kIRLenHandshakeId);
    /* Unsigned, big-endian, first differing byte. On the JVM the naive loop compares 0x80 as -128
       and picks the wrong survivor, which diverges the two sides permanently. */
    const uint8_t *left = a.bytes;
    const uint8_t *right = b.bytes;
    for (NSUInteger index = 0; index < (NSUInteger)kIRLenHandshakeId; index++) {
        if (left[index] != right[index]) {
            return (left[index] > right[index]) ? a : b;
        }
    }
    return a;
}

#pragma mark - Out-of-order and skipped delivery, end to end

- (void)testOutOfOrderDeliveryWithinOneChain {
    /* §7.6 — messages 0..3 sent, delivered 0, 3, 1, 2. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSMutableArray<NSData *> *sent = [NSMutableArray array];
    for (NSUInteger index = 0; index < 4; index++) {
        NSString *text = [NSString stringWithFormat:@"ooo-%lu", (unsigned long)index];
        [sent addObject:[self encryptFrom:_alice inSession:aliceSession text:text]];
    }

    NSArray<NSNumber *> *order = @[ @0, @3, @1, @2 ];
    for (NSNumber *slot in order) {
        NSUInteger index = slot.unsignedIntegerValue;
        IRDecryptedMessage *decrypted = [_bob decryptMessage:sent[index]
                                     fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                       error:&error];
        XCTAssertNotNil(decrypted, @"index %lu: %@", (unsigned long)index, error);
        XCTAssertEqualObjects([self textOf:decrypted],
                              ([NSString stringWithFormat:@"ooo-%lu", (unsigned long)index]));
    }

    /* Every stored key was consumed; nothing leaked into the persisted state. */
    XCTAssertEqual(bobSession.state.skipped.count, (NSUInteger)0);
}

- (void)testSkippedKeysSurviveADHRatchet {
    /* RATCHET-SKIP-XCHAIN through the consumer API — skipped messages recovered ACROSS a DH
       ratchet, which is exactly what defect 10 was masking by writing Ns into the PN slot. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    /* Bob replies and Alice decrypts it, which turns Alice's first DH ratchet onto chain A2 and
       clears her prologue — so everything she sends below is type `0x01` (§11.3). */
    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    XCTAssertFalse(aliceSession.sendsPreKeyMessages);

    /* Hold back A2's first message. */
    NSData *heldOnA2 = [self encryptFrom:_alice inSession:aliceSession text:@"held-on-A2"];

    /* A2's second message IS delivered, which makes Bob ratchet onto A2 and skip past the held
       one — so its key enters the store while Bob is on chain A2. */
    NSData *bridge = [self encryptFrom:_alice inSession:aliceSession text:@"bridge"];
    IRDecryptedMessage *atBridge = [_bob decryptMessage:bridge
                                fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                  error:&error];
    XCTAssertNotNil(atBridge, @"%@", error);
    XCTAssertEqual(bobSession.state.skipped.count, (NSUInteger)1);

    /* Now force a SECOND DH ratchet: Bob replies on a new chain, Alice decrypts it and turns onto
       A3, and Bob then ratchets onto A3 as well. The stored key belongs to A2 and must survive. */
    NSData *ack2 = [self encryptFrom:_bob inSession:bobSession text:@"ack2"];
    XCTAssertNotNil([_alice decryptMessage:ack2
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *onA3 = [self encryptFrom:_alice inSession:aliceSession text:@"on-A3"];
    IRMessageHeader *header = [IRMessageGate parseType01Message:onA3
                                            ownRatchetPublicKey:bobSession.state.DHs.publicKey
                                                          error:&error];
    XCTAssertNotNil(header, @"%@", error);
    /* PN carries A2's length (2), NOT Ns — writing Ns into this slot is defect 10 verbatim, and
       it is what made cross-chain recovery impossible in v3. */
    XCTAssertEqual(header.PN, (uint32_t)2);
    XCTAssertEqual(header.N, (uint32_t)0);

    IRDecryptedMessage *atA3 = [_bob decryptMessage:onA3
                            fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                              error:&error];
    XCTAssertNotNil(atA3, @"%@", error);
    XCTAssertEqualObjects([self textOf:atA3], @"on-A3");

    /* Bob has MOVED ON: DHr is A3's key now, while the one stored entry is still filed under A2's.
       That gap is the whole point — the lookup is keyed on the HEADER's ratchet key, not on the
       session's current DHr, and a port that keys it on DHr recovers nothing after any turn. */
    XCTAssertEqual(bobSession.state.skipped.count, (NSUInteger)1);
    XCTAssertTrue([bobSession.state.DHr isEqualToX25519Public:header.ratchetKey]);

    /* THE ASSERTION THIS TEST EXISTS FOR — a message from a chain Bob has already ratcheted PAST
       still decrypts. Defect 10 was masking exactly this. */
    IRDecryptedMessage *recovered = [_bob decryptMessage:heldOnA2
                                 fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                   error:&error];
    XCTAssertNotNil(recovered, @"%@", error);
    XCTAssertEqualObjects([self textOf:recovered], @"held-on-A2");

    XCTAssertEqual(bobSession.state.skipped.count, (NSUInteger)0);
}

- (void)testNEG_REPLAY_AtTheMessenger {
    /* §7.9 phase 3c — N < Nr with no stored skipped key. A key consumed once is gone, so the
       second delivery of a message that already decrypted is a replay. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *message = [self encryptFrom:_alice inSession:aliceSession text:@"once"];
    XCTAssertNotNil([_bob decryptMessage:message
                 fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                   error:&error], @"%@", error);

    error = nil;
    XCTAssertNil([_bob decryptMessage:message
              fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                error:&error]);
    [self assertError:error hasCode:IRErrorReplay];
}

- (void)testNEG_ATOMIC_AtTheMessenger {
    /* §15.4 — inject a header-valid, tag-invalid message with a NOVEL ratchet key and assert the
       next legitimate message still decrypts. This is the desynchronisation DoS: a port that
       mutates the live state before the AEAD verifies lets any observer permanently break the
       session with one forged packet. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *genuine = [self encryptFrom:_alice inSession:aliceSession text:@"genuine"];

    /* A novel ratchet key forces phase 3b — the expensive path — before the tag is checked. */
    NSData *forged = [self message:genuine withBytes:[self freshX25519PublicData] atOffset:4];

    error = nil;
    XCTAssertNil([_bob decryptMessage:forged
              fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                error:&error]);
    [self assertError:error hasCode:IRErrorAEADAuthFailed];

    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptMessage:genuine
                                 fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                   error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqualObjects([self textOf:decrypted], @"genuine");
}

#pragma mark - Gate codes surface unchanged through the consumer API

- (void)testGateRejectionsKeepTheirExactCodes {
    /* §10.5 — the messenger must not remap a gate's code. Each of these is already covered at the
       gate; what is asserted here is that the composition above it is transparent. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);
    NSData *normal = [self encryptFrom:_alice inSession:aliceSession text:@"normal"];

    /* NEG-VERSION — a v3 message. §10.6: there is no downgrade path and no dual-stack mode. */
    NSMutableData *v3 = [normal mutableCopy];
    ((uint8_t *)v3.mutableBytes)[0] = 0x03;
    error = nil;
    XCTAssertNil([_bob decryptMessage:v3 inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion];

    /* NEG-TYPE */
    NSMutableData *badType = [normal mutableCopy];
    ((uint8_t *)badType.mutableBytes)[1] = 0x03;
    error = nil;
    XCTAssertNil([_bob decryptMessage:badType inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType];

    /* NEG-FLAGS */
    NSMutableData *flags = [normal mutableCopy];
    ((uint8_t *)flags.mutableBytes)[3] = 0x01;
    error = nil;
    XCTAssertNil([_bob decryptMessage:flags inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet];

    /* NEG-TRUNCATED — 71 bytes, one below the type `0x01` minimum. */
    error = nil;
    XCTAssertNil([_bob decryptMessage:[normal subdataWithRange:NSMakeRange(0, 71)]
                            inSession:bobSession
                                error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage];

    /* NEG-PUBKEY-HIGHBIT — ratchet key with pk[31] & 0x80 set. */
    NSMutableData *highBit = [normal mutableCopy];
    ((uint8_t *)highBit.mutableBytes)[4 + 31] |= 0x80;
    error = nil;
    XCTAssertNil([_bob decryptMessage:highBit inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey];

    /* NEG-PUBKEY-REFLECT-01 — the header ratchet key equal to our own DHs public. */
    NSData *reflected = [self message:normal
                            withBytes:bobSession.state.DHs.publicKey.data
                             atOffset:4];
    error = nil;
    XCTAssertNil([_bob decryptMessage:reflected inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey];

    /* NEG-COUNTER — N = 0x80000000. */
    NSData *counter = [self message:normal withBytes:[self bigEndianUInt32:0x80000000] atOffset:36];
    error = nil;
    XCTAssertNil([_bob decryptMessage:counter inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow];
}

- (void)testNEG_SKIP_LIMIT_AtTheMessenger {
    /* §7.6 — MAX_SKIP_PER_MESSAGE exceeded. The bound is an AGGREGATE across both SkipMessageKeys
       calls of one message, and §11.5 rule 3 is what stops a trial-decrypting port multiplying it
       by the number of candidate sessions. */
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *normal = [self encryptFrom:_alice inSession:aliceSession text:@"far ahead"];

    /* N one past the budget. The message is header-valid, so it reaches phase 3c. */
    NSData *farAhead = [self message:normal
                           withBytes:[self bigEndianUInt32:(uint32_t)kIRMaxSkipPerMessage + 1]
                            atOffset:36];

    error = nil;
    XCTAssertNil([_bob decryptMessage:farAhead inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorTooManySkipped];

    /* §7.7 — and the session is untouched, so the legitimate message still arrives. */
    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptMessage:normal
                                 fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                                   error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqualObjects([self textOf:decrypted], @"far ahead");
}

#pragma mark - §5.3 rules 5-6 at the initiator

- (void)testBeginSessionRejectsABundleOutsideItsValidityWindow {
    /* §15.4 NEG-SPK-EXPIRED — the rejection is CAUSED by an injected clock outside the fixed
       window, not merely observed. §5.3 requires all six rules before any Diffie-Hellman. */
    NSError *error = nil;

    NSData *bundle = [_bob publishBundleWithSPKId:0xABCD
                                       notBeforeS:kNowS + 10000
                                        notAfterS:kNowS + 20000
                                         opkCount:1
                                            error:&error];
    XCTAssertNotNil(bundle, @"%@", error);

    error = nil;
    XCTAssertNil([_alice beginSessionWithBundleData:bundle error:&error]);
    [self assertError:error hasCode:IRErrorPreKeyExpired];
    XCTAssertEqual(_aliceSessions.sessionCount, (NSUInteger)0);
}

- (void)testBeginSessionRejectsAMalformedBundle {
    NSError *error = nil;
    XCTAssertNil([_alice beginSessionWithBundleData:[NSData data] error:&error]);
    [self assertError:error hasCode:IRErrorBundleMalformed];

    error = nil;
    NSData *truncated = [_bobBundle subdataWithRange:NSMakeRange(0, 250)];
    XCTAssertNil([_alice beginSessionWithBundleData:truncated error:&error]);
    [self assertError:error hasCode:IRErrorBundleMalformed];
}

- (void)testBeginSessionRejectsACorruptedSignedPreKeySignature {
    /* NEG-SPKSIG-BAD, through the consumer API. */
    NSMutableData *forged = [_bobBundle mutableCopy];
    ((uint8_t *)forged.mutableBytes)[185] ^= 0xFF;   /* inside SPK_SIG */

    NSError *error = nil;
    XCTAssertNil([_alice beginSessionWithBundleData:forged error:&error]);
    [self assertError:error hasCode:IRErrorBadSignature];
}

#pragma mark - NEG-SPK-SURVIVES-RATCHET, at the messenger

- (void)testNEG_SPK_SURVIVES_RATCHET_ThroughTheConsumerAPI {
    /* §15.4 — "the ONLY vector that catches a port aliasing the prekey store from ratchet state".
       Two initiators fetch bundles naming the same spk_id; initiator 1 completes and B ratchets
       past it; initiator 2 must still succeed.

       An aliasing port destroys SPK_B_priv on B's FIRST ratchet of ANY session — which is every
       session B accepts — and misreports it as ERR_AEAD_AUTH_FAILED, i.e. as an active MITM. */
    NSError *error = nil;

    /* Initiator 1. */
    IRSession *aliceSession = nil;
    IRSession *bobWithAlice = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobWithAlice];

    /* Let B ratchet past it: B replies, A answers, B receives — B's DHs is now a fresh pair and
       the session copy of SPK_B_priv has been zeroized by §7.4 step 4. */
    NSData *bobReply = [self encryptFrom:_bob inSession:bobWithAlice text:@"reply"];
    XCTAssertNotNil([_alice decryptMessage:bobReply
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    NSData *aliceAnswer = [self encryptFrom:_alice inSession:aliceSession text:@"answer"];
    XCTAssertNotNil([_bob decryptMessage:aliceAnswer
                 fromPeerIdentityKeyPair:_aliceIdentity.identityKeyPair
                                   error:&error], @"%@", error);

    XCTAssertFalse([bobWithAlice.state.DHs.publicKey isEqualToX25519Public:
                       [_bobPreKeys signedPreKeyRecordForId:kBobSpkId
                                                      error:&error].keyPair.publicKey]);

    /* Initiator 2, against the SAME spk_id. A bundle re-published under the same id would rotate
       the key, so this one is serialized from the record B still holds. */
    IRSignedPreKeyRecord *retained = [_bobPreKeys signedPreKeyRecordForId:kBobSpkId error:&error];
    XCTAssertNotNil(retained, @"%@", error);

    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    IRMessenger *carol = [self messengerWithIdentity:carolIdentity
                                        preKeyStore:[IRInMemoryPreKeyStore store]
                                       sessionStore:[IRInMemorySessionStore store]];

    IROneTimePreKeyRecord *freshOPK = [IROneTimePreKeyRecord generateWithOpkId:0x4444
                                                            createdAtUnixSecs:kNowS
                                                                     provider:_provider
                                                                        error:&error];
    XCTAssertNotNil(freshOPK, @"%@", error);
    XCTAssertTrue([_bobPreKeys storeOneTimePreKeyRecords:@[ freshOPK ] error:&error], @"%@", error);

    NSData *sameSpkBundle = [IRPreKeyBundle serializeWithIdentity:_bobIdentity.publicIdentity
                                              signedPreKeyRecord:retained
                                            oneTimePreKeyRecords:@[ freshOPK ]
                                                           error:&error];
    XCTAssertNotNil(sameSpkBundle, @"%@", error);

    IRSession *carolSession = [carol beginSessionWithBundleData:sameSpkBundle error:&error];
    XCTAssertNotNil(carolSession, @"%@", error);

    NSData *carolOpener = [self encryptFrom:carol inSession:carolSession text:@"initiator two"];

    error = nil;
    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:carolOpener error:&error];
    XCTAssertNotNil(atBob, @"initiator 2 must still succeed; got %@", error);
    XCTAssertEqualObjects([self textOf:atBob], @"initiator two");
}

#pragma mark - §13.4 — argument contracts

/**
 §13.4 clause 5 — absence of a SESSION HANDLE is the one parameter this section does not govern.

 §10.1 check 6 already specifies it ("the caller supplied a session handle and it resolves"), gives
 it a code, and `NEG-NO-SESSION`'s first case is "no handle at all" — so the handle parameter is
 _Nullable in every port and reports through the taxonomy. A _Nonnull handle guarded by a trap would
 make ERR_NO_SESSION unreachable from Swift and contradict a required vector. §11.1.1's collapse is
 the mechanism that manufactures stale handles, which is why this is the one parameter the outside
 world can legitimately render absent.

 The send path used to answer a nil session with ERR_STATE_CORRUPT (7117, "state blob failed
 structural validation"), which is not what happened and disagreed with the torn-down branch three
 lines below it in the same method.
 */
- (void)testSessionHandleAbsenceIsAlwaysNoSessionAndNeverStateCorrupt {
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    error = nil;
    XCTAssertNil([_bob encrypt:[@"x" dataUsingEncoding:NSUTF8StringEncoding]
                     inSession:nil
                         error:&error]);
    [self assertError:error hasCode:IRErrorNoSession];

    XCTAssertTrue([_bobSessions tearDownSession:bobSession
                                       atTimeMs:kNowS * 1000ULL
                                          error:&error], @"%@", error);

    error = nil;
    XCTAssertNil([_bob encrypt:[@"x" dataUsingEncoding:NSUTF8StringEncoding]
                     inSession:bobSession
                         error:&error]);
    [self assertError:error hasCode:IRErrorNoSession];
}

/**
 §13.4 clause 2 and clause 6 — the CONTENT side, which is the side a vector can reach.

 A null reference and a zero-length byte string are different conditions with different remedies: the
 first is a caller contract violation that traps, the second is a normal value with a specified
 outcome everywhere in the document. §10.4 makes a zero-length PLAINTEXT legal and it produces the
 72-byte minimum type `0x01` message; a zero-length MESSAGE is below every floor and is
 ERR_TRUNCATED_MESSAGE. Coercing nil into either would make the two indistinguishable downstream,
 which is precisely what clause 2 bans.
 */
- (void)testZeroLengthIsAValueAndNotAMissingArgument {
    NSError *error = nil;

    IRSession *aliceSession = nil;
    IRSession *bobSession = nil;
    [self establishAliceToBobWithSession:&aliceSession bobSession:&bobSession];

    NSData *ack = [self encryptFrom:_bob inSession:bobSession text:@"ack"];
    XCTAssertNotNil([_alice decryptMessage:ack
                   fromPeerIdentityKeyPair:_bobIdentity.identityKeyPair
                                     error:&error], @"%@", error);

    /* §10.4 — an empty plaintext is LEGAL and round-trips. */
    error = nil;
    NSData *emptyMessage = [_alice encrypt:[NSData data] inSession:aliceSession error:&error];
    XCTAssertNotNil(emptyMessage, @"%@", error);
    XCTAssertEqual(emptyMessage.length, (NSUInteger)kIRLenType01Min);

    error = nil;
    IRDecryptedMessage *decrypted = [_bob decryptMessage:emptyMessage
                                               inSession:bobSession
                                                   error:&error];
    XCTAssertNotNil(decrypted, @"%@", error);
    XCTAssertEqual(decrypted.plaintext.length, (NSUInteger)0);

    /* A zero-length MESSAGE is a value too, and it lands on the length floor of §10.0 row 1 rather
       than anywhere near the argument contract. */
    error = nil;
    XCTAssertNil([_bob decryptMessage:[NSData data] inSession:bobSession error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage];

    error = nil;
    XCTAssertNil([_bob decryptPreKeyMessage:[NSData data] error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage];

    error = nil;
    XCTAssertEqual([IRMessenger messageTypeOfMessage:[NSData data] error:&error],
                   (IRMessageType)0);
    [self assertError:error hasCode:IRErrorTruncatedMessage];
}

#pragma mark - §10.7 step 14 / §11.1.1 — the collapse branches

/**
 A concurrent initiation, which is routine on a mobile transport: Alice opens toward Bob and Bob
 opens toward Alice, neither having seen the other's prekey message, and each then receives the
 other's type `0x02` while already holding a live session with that peer.

 EXACTLY ONE OF THE TWO SIDES IS THE BRANCH §10.7 STEP 14d IS ABOUT — the side where the session the
 message just established LOSES §11.1.1's comparison and is torn down. Which side that is depends on
 the identity keys generated in -setUp, so the fixture reports it rather than assuming it.
 */
- (void)runConcurrentInitiationWithAliceOwn:(IRSession * __autoreleasing *)outAliceOwn
                                     bobOwn:(IRSession * __autoreleasing *)outBobOwn
                              messageToAlice:(NSData * __autoreleasing *)outToAlice
                                messageToBob:(NSData * __autoreleasing *)outToBob
                                  atAliceOut:(IRDecryptedMessage * __autoreleasing *)outAtAlice
                                    atBobOut:(IRDecryptedMessage * __autoreleasing *)outAtBob {
    NSError *error = nil;

    NSData *aliceBundle = [self publishBundleFrom:_alice opkCount:1];

    IRSession *aliceOwn = [_alice beginSessionWithBundleData:_bobBundle error:&error];
    XCTAssertNotNil(aliceOwn, @"%@", error);
    IRSession *bobOwn = [_bob beginSessionWithBundleData:aliceBundle error:&error];
    XCTAssertNotNil(bobOwn, @"%@", error);

    XCTAssertNotEqualObjects(aliceOwn.handshakeId, bobOwn.handshakeId);

    NSData *toBob = [self encryptFrom:_alice inSession:aliceOwn text:@"alice opens"];
    NSData *toAlice = [self encryptFrom:_bob inSession:bobOwn text:@"bob opens"];

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:toBob error:&error];
    XCTAssertNotNil(atBob, @"%@", error);
    IRDecryptedMessage *atAlice = [_alice decryptPreKeyMessage:toAlice error:&error];
    XCTAssertNotNil(atAlice, @"%@", error);

    /* §11.1.1 — both sides converge on the same survivor with no negotiation, and the collapse
       resolves in opposite directions at the two of them. */
    XCTAssertEqualObjects(atAlice.session.handshakeId, atBob.session.handshakeId);
    XCTAssertNotEqual(atAlice.establishedNewSession, atBob.establishedNewSession,
                      @"exactly one side's incoming session must be the loser");

    if (outAliceOwn != NULL) { *outAliceOwn = aliceOwn; }
    if (outBobOwn != NULL) { *outBobOwn = bobOwn; }
    if (outToAlice != NULL) { *outToAlice = toAlice; }
    if (outToBob != NULL) { *outToBob = toBob; }
    if (outAtAlice != NULL) { *outAtAlice = atAlice; }
    if (outAtBob != NULL) { *outAtBob = atBob; }
}

/**
 §15.3 `SESSION-COLLAPSE`, the assertion that resolves §10.7 step 14d: THE PLAINTEXT IS DELIVERED ON
 THE BRANCH WHERE THE INCOMING SESSION LOSES.

 The old text ended step 14 with "then commit the session and persist, then return the plaintext",
 having assumed the new session wins — and on the losing branch there is no committed session to
 return a handle for. Dropping the plaintext there would discard a message that completed X3DH and
 passed Poly1305, and would hand an attacker who merely DELAYS one packet a silent, permanent
 message-suppression primitive: §11.3 has the initiator retransmitting an identical prologue, hence
 an identical handshake_id, which step 4 then rejects as ERR_REPLAY forever (§19.7).
 */
- (void)testSESSION_COLLAPSE_DeliversThePlaintextOnBothBranches {
    IRSession *aliceOwn = nil;
    IRSession *bobOwn = nil;
    IRDecryptedMessage *atAlice = nil;
    IRDecryptedMessage *atBob = nil;

    [self runConcurrentInitiationWithAliceOwn:&aliceOwn
                                       bobOwn:&bobOwn
                                messageToAlice:NULL
                                  messageToBob:NULL
                                    atAliceOut:&atAlice
                                      atBobOut:&atBob];

    /* Both sides produced a plaintext. Neither returned an error, and neither returned a success
       carrying nothing — §10.5 forbids a null result with a null error, which is why "drop it" is
       not merely worse policy but unrepresentable in the return contract all four ports share. */
    XCTAssertEqualObjects([self textOf:atAlice], @"bob opens");
    XCTAssertEqualObjects([self textOf:atBob], @"alice opens");

    /* And the handle returned is ALWAYS the survivor, on both branches. */
    IRDecryptedMessage *loserSide = atAlice.establishedNewSession ? atBob : atAlice;
    IRDecryptedMessage *winnerSide = atAlice.establishedNewSession ? atAlice : atBob;
    IRSession *loserSideOwn = (loserSide == atAlice) ? aliceOwn : bobOwn;

    XCTAssertFalse(loserSide.establishedNewSession);
    XCTAssertFalse(loserSide.session.isTornDown);
    XCTAssertEqualObjects(loserSide.session.handshakeId, loserSideOwn.handshakeId,
                          @"on the losing branch the survivor is the PRE-EXISTING session");

    XCTAssertTrue(winnerSide.establishedNewSession);
    XCTAssertFalse(winnerSide.session.isTornDown);
}

/**
 §11.6 — the caller-facing flag, and the live defect this pinned down.

 `collapsedExistingSession` is documented as "establishing this session tore down a DIFFERENT live
 session with the same peer; a caller holding that handle MUST discard it". The store's
 `collapseOccurred` is the bare disjunction `tornDownSession != nil`, which is YES on BOTH branches —
 and on the losing branch the torn-down session is the one the message arrived on, which the caller
 never saw, while the caller's cached handle is the SURVIVOR. Forwarding the disjunction under this
 name tells that caller to discard the one handle it must keep, and an attacker triggers it by
 delaying a single packet.
 */
- (void)testCollapseFlagsDistinguishTheTwoBranches {
    IRSession *aliceOwn = nil;
    IRSession *bobOwn = nil;
    IRDecryptedMessage *atAlice = nil;
    IRDecryptedMessage *atBob = nil;

    [self runConcurrentInitiationWithAliceOwn:&aliceOwn
                                       bobOwn:&bobOwn
                                messageToAlice:NULL
                                  messageToBob:NULL
                                    atAliceOut:&atAlice
                                      atBobOut:&atBob];

    IRDecryptedMessage *loserSide = atAlice.establishedNewSession ? atBob : atAlice;
    IRDecryptedMessage *winnerSide = atAlice.establishedNewSession ? atAlice : atBob;
    IRSession *loserSideOwn = (loserSide == atAlice) ? aliceOwn : bobOwn;
    IRSession *winnerSideOwn = (winnerSide == atAlice) ? aliceOwn : bobOwn;

    /* LOSING BRANCH. Something WAS torn down — so the store's collapseOccurred is YES — but it is
       the incoming session, not a handle the caller holds. */
    XCTAssertNotNil(loserSide.tornDownHandshakeId);
    XCTAssertNotEqualObjects(loserSide.tornDownHandshakeId, loserSideOwn.handshakeId,
                             @"the caller's cached handle is the SURVIVOR on this branch");
    XCTAssertFalse(loserSide.collapsedExistingSession,
                   @"reporting YES here would tell the caller to destroy its live session");
    XCTAssertFalse(loserSideOwn.isTornDown);

    /* WINNING BRANCH. The torn-down session IS the caller's cached handle, and the id says so. */
    XCTAssertNotNil(winnerSide.tornDownHandshakeId);
    XCTAssertEqualObjects(winnerSide.tornDownHandshakeId, winnerSideOwn.handshakeId);
    XCTAssertTrue(winnerSide.collapsedExistingSession);
    XCTAssertTrue(winnerSideOwn.isTornDown);

    /* A plain §10.7 establishment with no sibling tears nothing down, so the id is absent and a
       caller cannot misread "nil" as "something died". */
    NSError *error = nil;
    IRIdentity *carolIdentity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(carolIdentity, @"%@", error);
    IRMessenger *carol = [self messengerWithIdentity:carolIdentity
                                        preKeyStore:[IRInMemoryPreKeyStore store]
                                       sessionStore:[IRInMemorySessionStore store]];
    NSData *freshBundle = [self publishBundleFrom:_bob opkCount:1];
    IRSession *carolSession = [carol beginSessionWithBundleData:freshBundle error:&error];
    XCTAssertNotNil(carolSession, @"%@", error);

    IRDecryptedMessage *atBobFromCarol =
        [_bob decryptPreKeyMessage:[self encryptFrom:carol inSession:carolSession text:@"hi"]
                             error:&error];
    XCTAssertNotNil(atBobFromCarol, @"%@", error);
    XCTAssertTrue(atBobFromCarol.establishedNewSession);
    XCTAssertNil(atBobFromCarol.tornDownHandshakeId);
    XCTAssertFalse(atBobFromCarol.collapsedExistingSession);
}

/**
 §10.7 step 14c — the surviving session's state MUST NOT be modified by a message that lost the
 collapse. No RK, chain key, counter or skipped key derived on the loser may be merged into it, and
 `send_counter` does not advance.

 An attacker replaying an old handshake could otherwise reset a live session's root key, destroying
 post-compromise security and desynchronising the peer — and merging is exactly the sort of thing a
 port writes as a convenience, which is why step 14c says it out loud.
 */
- (void)testSESSION_COLLAPSE_LosingBranchLeavesTheSurvivorByteIdentical {
    NSError *error = nil;

    NSData *aliceBundle = [self publishBundleFrom:_alice opkCount:1];

    IRSession *aliceOwn = [_alice beginSessionWithBundleData:_bobBundle error:&error];
    XCTAssertNotNil(aliceOwn, @"%@", error);
    IRSession *bobOwn = [_bob beginSessionWithBundleData:aliceBundle error:&error];
    XCTAssertNotNil(bobOwn, @"%@", error);

    NSData *toBob = [self encryptFrom:_alice inSession:aliceOwn text:@"alice opens"];
    NSData *toAlice = [self encryptFrom:_bob inSession:bobOwn text:@"bob opens"];

    NSData *aliceOwnBefore = [self serializedStateOf:aliceOwn];
    NSData *bobOwnBefore = [self serializedStateOf:bobOwn];
    uint64_t aliceCounterBefore = aliceOwn.sendCounter;
    uint64_t bobCounterBefore = bobOwn.sendCounter;

    IRDecryptedMessage *atBob = [_bob decryptPreKeyMessage:toBob error:&error];
    XCTAssertNotNil(atBob, @"%@", error);
    IRDecryptedMessage *atAlice = [_alice decryptPreKeyMessage:toAlice error:&error];
    XCTAssertNotNil(atAlice, @"%@", error);

    if (!atAlice.establishedNewSession) {
        XCTAssertEqualObjects([self serializedStateOf:aliceOwn], aliceOwnBefore,
                              @"§10.7 step 14c — the survivor is untouched by the losing message");
        XCTAssertEqual(aliceOwn.sendCounter, aliceCounterBefore);
    } else {
        XCTAssertEqualObjects([self serializedStateOf:bobOwn], bobOwnBefore,
                              @"§10.7 step 14c — the survivor is untouched by the losing message");
        XCTAssertEqual(bobOwn.sendCounter, bobCounterBefore);
    }
}

/**
 §15.4 `NEG-COLLAPSE-LOSER-REPLAY` — re-submit the identical type `0x02` whose session lost the
 collapse, inside HANDSHAKE_CACHE_MS.

 THIS IS WHAT STOPS §10.7 STEP 14d's DELIVERY RULE FROM BECOMING A PLAINTEXT-HARVESTING ORACLE, and
 it is the row that fails a port which delivers but forgets step 14c's tombstone. It is not reachable
 from `NEG-HANDSHAKE-TOMBSTONE`, whose tombstone comes from an explicit eviction: this one was never
 committed to the store at all, and §11.4 requires a session that was never stored to be tombstoned
 too.
 */
- (void)testNEG_COLLAPSE_LOSER_REPLAY {
    IRSession *aliceOwn = nil;
    IRSession *bobOwn = nil;
    NSData *toAlice = nil;
    NSData *toBob = nil;
    IRDecryptedMessage *atAlice = nil;
    IRDecryptedMessage *atBob = nil;

    [self runConcurrentInitiationWithAliceOwn:&aliceOwn
                                       bobOwn:&bobOwn
                                messageToAlice:&toAlice
                                  messageToBob:&toBob
                                    atAliceOut:&atAlice
                                      atBobOut:&atBob];

    BOOL aliceIsLoserSide = !atAlice.establishedNewSession;
    IRMessenger *receiver = aliceIsLoserSide ? _alice : _bob;
    NSData *losingMessage = aliceIsLoserSide ? toAlice : toBob;

    NSError *error = nil;
    XCTAssertNil([receiver decryptPreKeyMessage:losingMessage error:&error],
                 @"a second delivery would be a plaintext-harvesting oracle");
    [self assertError:error hasCode:IRErrorReplay];

    /* Delivery is once per HANDSHAKE, not once per arrival — and a third attempt is no different. */
    error = nil;
    XCTAssertNil([receiver decryptPreKeyMessage:losingMessage error:&error]);
    [self assertError:error hasCode:IRErrorReplay];

    /* The survivor is still live and still usable, so the tombstone did not cost the session. */
    IRSession *survivor = aliceIsLoserSide ? atAlice.session : atBob.session;
    XCTAssertFalse(survivor.isTornDown);
}

/**
 §15.4 `NEG-COLLAPSE-LOSER-HANDLE` — a valid type `0x01` submitted against the handle for the session
 that lost the collapse (§11.6).

 This is the only way the "which handle comes back" half of §10.7 step 14d is observable at all: a
 handle is an opaque object with no byte representation, so without this row a port could return the
 dead one and nothing would notice. It is taken on the WINNING side, because that is where the loser
 is a handle the caller actually holds.
 */
- (void)testNEG_COLLAPSE_LOSER_HANDLE {
    IRSession *aliceOwn = nil;
    IRSession *bobOwn = nil;
    IRDecryptedMessage *atAlice = nil;
    IRDecryptedMessage *atBob = nil;

    [self runConcurrentInitiationWithAliceOwn:&aliceOwn
                                       bobOwn:&bobOwn
                                messageToAlice:NULL
                                  messageToBob:NULL
                                    atAliceOut:&atAlice
                                      atBobOut:&atBob];

    BOOL aliceIsWinnerSide = atAlice.establishedNewSession;
    IRMessenger *receiver = aliceIsWinnerSide ? _alice : _bob;
    IRDecryptedMessage *winnerSide = aliceIsWinnerSide ? atAlice : atBob;
    IRSession *deadHandle = aliceIsWinnerSide ? aliceOwn : bobOwn;

    /* §11.6 — the caller is told which id died, and it is the handle it was holding. */
    XCTAssertEqualObjects(winnerSide.tornDownHandshakeId, deadHandle.handshakeId);
    XCTAssertTrue(deadHandle.isTornDown);

    /* Any well-formed type `0x01` will do; the handle fails at §10.1 check 6 before the message is
       ever looked at, which is the point. */
    NSData *wellFormed = [NSMutableData dataWithLength:200];
    NSMutableData *shaped = [wellFormed mutableCopy];
    uint8_t *bytes = (uint8_t *)shaped.mutableBytes;
    bytes[0] = 0x04;
    bytes[1] = (uint8_t)IRMessageTypeNormal;

    NSError *error = nil;
    XCTAssertNil([receiver decryptMessage:shaped inSession:deadHandle error:&error]);
    [self assertError:error hasCode:IRErrorNoSession];

    /* And it is gone from the peer index too, so the by-peer form cannot resurrect it. The peer
       index now resolves to the SURVIVOR, which is the handle §11.6 told the caller to adopt. */
    IRIdentityKeyPair *peer = aliceIsWinnerSide ? _bobIdentity.identityKeyPair
                                                : _aliceIdentity.identityKeyPair;
    id<IRSessionStore> store = aliceIsWinnerSide ? _aliceSessions : _bobSessions;
    IRSession *resolved = [store sessionForPeerIdentityKeyPair:peer];
    XCTAssertNotNil(resolved);
    XCTAssertEqualObjects(resolved.handshakeId, winnerSide.session.handshakeId);
    XCTAssertNotEqualObjects(resolved.handshakeId, deadHandle.handshakeId);

    /* §11.6 — every operation on a torn-down handle fails, including send. */
    error = nil;
    XCTAssertNil([receiver encrypt:[NSData data] inSession:deadHandle error:&error]);
    [self assertError:error hasCode:IRErrorNoSession];
}

#pragma mark - Utilities

- (NSData *)serializedStateOf:(IRSession *)session {
    NSError *error = nil;
    IRSecretBytes *blob = [session serializedState:&error];
    XCTAssertNotNil(blob, @"%@", error);
    NSData *copy = [NSData dataWithBytes:blob.constBytes length:blob.length];
    [blob zeroizeNow];
    return copy;
}

@end
