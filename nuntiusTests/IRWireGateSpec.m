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

#import "IRByteReader.h"
#import "IRCryptoProvider.h"
#import "IRErrors.h"
#import "IRIdentity.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageBuilder.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRSessionAD.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

/**
 LAYER 6 GATE — SPEC §9.1, §9.2, §9.3, §10.1, §10.2, §10.4, §8.5, §15.4.

 THE ORDERING TESTS ARE THE POINT OF THIS FILE. A round-trip test cannot see a reordered gate:
 build a valid message, parse it, and every ordering of checks 1–11 succeeds identically. The only
 input that distinguishes two orderings is one that is wrong in TWO ways whose checks return
 DIFFERENT codes — then the returned code names which check ran first. Every `testOrder…` method
 below is such an input, and each one names the pair of checks it pins.

 This matters more here than anywhere else in the framework. §15.4 makes the exact code a
 conformance requirement, this implementation generates the frozen vectors (§15.6), and §15.6 step 4
 forbids regenerating them. A gate reordered today becomes the normative order for Java, Kotlin and
 Swift tomorrow.

 Two orderings are deliberately NOT tested, because they are unobservable rather than untested:
 §10.2 checks 10 and 11 both return ERR_INVALID_PUBLIC_KEY, as do §10.1 checks 7 and 8. Where two
 adjacent checks share a code, no input can distinguish them and no port can diverge.

 THE MARQUEE TEST IS -testOrderD1_TruncatedBeatsNoSession. §10.1 check 6 — session resolution — sits
 between checks 5 and 7, so a parser that took the session up front would answer a 10-byte input
 with ERR_NO_SESSION where §10.1 mandates ERR_TRUNCATED_MESSAGE. That is decision D1, and it is the
 one gate-ordering flaw that a natural, well-intentioned API design walks straight into.
 */
@interface IRWireGateSpec : XCTestCase

@property (nonatomic, strong) IRSodiumCryptoProvider *provider;
@property (nonatomic, strong) IRIdentity *alice;              ///< A, the initiator
@property (nonatomic, strong) IRIdentity *bob;                ///< B, the responder
@property (nonatomic, strong) IRX25519KeyPair *senderRatchet; ///< the DHs_pub that travels
@property (nonatomic, strong) IRX25519KeyPair *ownRatchet;    ///< the receiver's own DHs, for check 8
@property (nonatomic, strong) IRX25519KeyPair *ephemeral;     ///< EK_A
@property (nonatomic, strong) IRNonce *nonce;
@property (nonatomic, strong) IRSessionPrologue *prologue;
@property (nonatomic, strong) IRSessionAD *sessionAD;

@end

@implementation IRWireGateSpec

static const uint32_t kSpkId = 0x11223344u;
static const uint32_t kOpkId = 0x55667788u;

/// Distinct, non-equal, and neither is zero — so a builder that wrote one into both slots (defect
/// 10) is visible in the parsed result rather than merely possible.
static const uint32_t kTestN = 7u;
static const uint32_t kTestPN = 3u;

#pragma mark - Fixtures

- (void)setUp {
    [super setUp];

    XCTAssertTrue([IRSodium ensureInitialized:NULL], @"libsodium must initialize");

    NSError *error = nil;
    self.provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(self.provider, @"%@", error);

    self.alice = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(self.alice, @"%@", error);

    self.bob = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(self.bob, @"%@", error);

    self.senderRatchet = [self.provider generateX25519KeyPairWithError:&error];
    XCTAssertNotNil(self.senderRatchet, @"%@", error);

    self.ownRatchet = [self.provider generateX25519KeyPairWithError:&error];
    XCTAssertNotNil(self.ownRatchet, @"%@", error);

    self.ephemeral = [self.provider generateX25519KeyPairWithError:&error];
    XCTAssertNotNil(self.ephemeral, @"%@", error);

    self.nonce = [self.provider randomNonceWithError:&error];
    XCTAssertNotNil(self.nonce, @"%@", error);

    self.prologue = [IRSessionPrologue prologueWithEphemeralPublic:self.ephemeral.publicKey
                                                             spkId:kSpkId
                                                           opkFlag:IROPKFlagPresent
                                                             opkId:kOpkId
                                                             error:&error];
    XCTAssertNotNil(self.prologue, @"%@", error);

    self.sessionAD = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                        responder:self.bob.identityKeyPair
                                            error:&error];
    XCTAssertNotNil(self.sessionAD, @"%@", error);
}

#pragma mark - Helpers

- (void)assertError:(NSError * _Nullable)error
            hasCode:(IRErrorCode)expected
            because:(NSString *)because {
    XCTAssertNotNil(error, @"%@ — expected %@ but no error was set. §10.5: every failure path MUST "
                    @"set the error out-parameter.", because, IRErrorNameForCode(expected));
    if (error == nil) {
        return;
    }

    XCTAssertEqualObjects(error.domain, IRErrorDomain, @"%@", because);
    XCTAssertEqual((IRErrorCode)error.code, expected, @"%@ — expected %@ (%ld) but got %@ (%ld)",
                   because, IRErrorNameForCode(expected), (long)expected,
                   IRErrorNameForCode((IRErrorCode)error.code), (long)error.code);
}

/// 16 bytes: the shortest legal payload, a bare Poly1305 tag over an empty plaintext (§10.4 —
/// "Empty plaintext (length 0) is legal and produces a 72-byte type 0x01 message").
- (NSData *)minimumPayload {
    return [NSMutableData dataWithLength:(NSUInteger)kIRLenAEADTag];
}

- (NSMutableData *)validType01MessageWithN:(uint32_t)N PN:(uint32_t)PN {
    NSError *error = nil;
    NSData *header = [IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                                N:N
                                                               PN:PN
                                                            nonce:self.nonce
                                                            error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:[self minimumPayload]
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    return [message mutableCopy];
}

- (NSMutableData *)validType01Message {
    return [self validType01MessageWithN:kTestN PN:kTestPN];
}

- (NSMutableData *)validType02MessageWithPrologue:(IRSessionPrologue *)prologue N:(uint32_t)N {
    NSError *error = nil;
    NSData *header =
        [IRMessageBuilder type02HeaderWithInitiatorIdentity:self.alice.identityKeyPair
                                            identityBinding:self.alice.binding
                                                   prologue:prologue
                                                 ratchetKey:self.senderRatchet.publicKey
                                                          N:N
                                                      nonce:self.nonce
                                                      error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:[self minimumPayload]
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    return [message mutableCopy];
}

- (NSMutableData *)validType02Message {
    return [self validType02MessageWithPrologue:self.prologue N:kTestN];
}

- (void)setByte:(uint8_t)value atOffset:(NSUInteger)offset in:(NSMutableData *)message {
    XCTAssertLessThan(offset, message.length);
    ((uint8_t *)message.mutableBytes)[offset] = value;
}

- (void)setUInt32BE:(uint32_t)value atOffset:(NSUInteger)offset in:(NSMutableData *)message {
    uint8_t *bytes = (uint8_t *)message.mutableBytes;
    bytes[offset + 0] = (uint8_t)((value >> 24) & 0xFF);
    bytes[offset + 1] = (uint8_t)((value >> 16) & 0xFF);
    bytes[offset + 2] = (uint8_t)((value >> 8) & 0xFF);
    bytes[offset + 3] = (uint8_t)(value & 0xFF);
}

static NSData *IRDataFromHex(NSString *hex) {
    NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger index = 0; index + 1 < hex.length; index += 2) {
        unsigned int byte = 0;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(index, 2)]]
            scanHexInt:&byte];
        uint8_t value = (uint8_t)byte;
        [data appendBytes:&value length:1];
    }
    return data;
}

#pragma mark - §9.1 / §9.2 — encoding is byte-exact

/// §9.1 — the 56-byte layout, field by field, at the offsets the specification states.
- (void)testType01HeaderLayoutIsByteExact {
    NSMutableData *message = [self validType01Message];
    XCTAssertEqual(message.length, (NSUInteger)kIRLenType01Min,
                   @"§9.1 — an empty plaintext yields exactly 72 bytes");

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    uint8_t version = 0;
    XCTAssertTrue([reader readUInt8:&version atOffset:(NSUInteger)kIROffType01Version]);
    XCTAssertEqual(version, (uint8_t)kIRProtocolVersion);

    uint8_t type = 0;
    XCTAssertTrue([reader readUInt8:&type atOffset:(NSUInteger)kIROffType01Type]);
    XCTAssertEqual(type, (uint8_t)IRMessageTypeNormal);

    uint16_t flags = 0xFFFF;
    XCTAssertTrue([reader readUInt16BE:&flags atOffset:(NSUInteger)kIROffType01Flags]);
    XCTAssertEqual(flags, 0x0000, @"§9.1 — flags are reserved and MUST be zero");

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType01DHs
                                        length:(NSUInteger)kIRLenX25519Public],
                          self.senderRatchet.publicKey.data);

    uint32_t N = 0;
    XCTAssertTrue([reader readUInt32BE:&N atOffset:(NSUInteger)kIROffType01N]);
    XCTAssertEqual(N, kTestN);

    uint32_t PN = 0;
    XCTAssertTrue([reader readUInt32BE:&PN atOffset:(NSUInteger)kIROffType01PN]);
    XCTAssertEqual(PN, kTestPN);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType01Nonce
                                        length:(NSUInteger)kIRLenNonce],
                          self.nonce.data);
}

/// DEFECT 10. v3 wrote `numberOfSentMessages` into both the N and PN slots. With N != PN, a builder
/// that collapsed them writes 7 into both and this fails at the PN assertion.
- (void)testType01NAndPNAreDistinctFields {
    NSMutableData *message = [self validType01MessageWithN:kTestN PN:kTestPN];
    XCTAssertNotEqual(kTestN, kTestPN, @"the fixture must actually distinguish the two slots");

    NSError *error = nil;
    IRMessageHeader *header = [IRMessageGate parseType01Message:message
                                            ownRatchetPublicKey:self.ownRatchet.publicKey
                                                          error:&error];
    XCTAssertNotNil(header, @"%@", error);
    XCTAssertEqual(header.N, kTestN);
    XCTAssertEqual(header.PN, kTestPN, @"§9.1 — PN comes from state.PN, never from state.Ns");
}

/// §9.2 — the 225-byte layout.
- (void)testType02HeaderLayoutIsByteExact {
    NSMutableData *message = [self validType02Message];
    XCTAssertEqual(message.length, (NSUInteger)kIRLenType02Min,
                   @"§9.2 — an empty plaintext yields exactly 241 bytes");

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    uint8_t version = 0;
    XCTAssertTrue([reader readUInt8:&version atOffset:(NSUInteger)kIROffType02Version]);
    XCTAssertEqual(version, (uint8_t)kIRProtocolVersion);

    uint8_t type = 0;
    XCTAssertTrue([reader readUInt8:&type atOffset:(NSUInteger)kIROffType02Type]);
    XCTAssertEqual(type, (uint8_t)IRMessageTypePrekey);

    uint16_t flags = 0xFFFF;
    XCTAssertTrue([reader readUInt16BE:&flags atOffset:(NSUInteger)kIROffType02Flags]);
    XCTAssertEqual(flags, 0x0000);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02IdentitySigning
                                        length:(NSUInteger)kIRLenEd25519Public],
                          self.alice.identityKeyPair.signingKey.data);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02IdentityAgreement
                                        length:(NSUInteger)kIRLenX25519Public],
                          self.alice.identityKeyPair.agreementKey.data);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02IKB
                                        length:(NSUInteger)kIRLenEd25519Signature],
                          self.alice.binding.data);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02EK
                                        length:(NSUInteger)kIRLenX25519Public],
                          self.ephemeral.publicKey.data);

    uint32_t spkId = 0;
    XCTAssertTrue([reader readUInt32BE:&spkId atOffset:(NSUInteger)kIROffType02SPKId]);
    XCTAssertEqual(spkId, kSpkId);

    uint8_t opkFlag = 0xFF;
    XCTAssertTrue([reader readUInt8:&opkFlag atOffset:(NSUInteger)kIROffType02OPKFlag]);
    XCTAssertEqual(opkFlag, (uint8_t)IROPKFlagPresent);

    uint32_t opkId = 0;
    XCTAssertTrue([reader readUInt32BE:&opkId atOffset:(NSUInteger)kIROffType02OPKId]);
    XCTAssertEqual(opkId, kOpkId);

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02DHs
                                        length:(NSUInteger)kIRLenX25519Public],
                          self.senderRatchet.publicKey.data);

    uint32_t N = 0;
    XCTAssertTrue([reader readUInt32BE:&N atOffset:(NSUInteger)kIROffType02N]);
    XCTAssertEqual(N, kTestN);

    uint32_t PN = 0xFFFFFFFFu;
    XCTAssertTrue([reader readUInt32BE:&PN atOffset:(NSUInteger)kIROffType02PN]);
    XCTAssertEqual(PN, 0u, @"§9.2 — PN is always zero in a type 0x02 header");

    XCTAssertEqualObjects([reader dataAtOffset:(NSUInteger)kIROffType02Nonce
                                        length:(NSUInteger)kIRLenNonce],
                          self.nonce.data);
}

/// §9.2 — B's own OPK public is NOT on the wire; B recovers it from `opk_id`. If it ever were, the
/// header could not be 225 bytes.
- (void)testType02HeaderCarriesNoResponderKeyMaterial {
    NSMutableData *message = [self validType02Message];
    NSData *header = [message subdataWithRange:NSMakeRange(0, (NSUInteger)kIRLenType02Header)];

    XCTAssertEqual([header rangeOfData:self.bob.identityKeyPair.agreementKey.data
                               options:0
                                 range:NSMakeRange(0, header.length)].location,
                   (NSUInteger)NSNotFound,
                   @"§9.2 — no responder key material travels in a prekey header");
}

#pragma mark - Round trip

- (void)testType01RoundTripPreservesEveryField {
    NSMutableData *message = [self validType01Message];

    NSError *error = nil;
    IRMessageHeader *header = [IRMessageGate parseType01Message:message
                                            ownRatchetPublicKey:self.ownRatchet.publicKey
                                                          error:&error];
    XCTAssertNotNil(header, @"%@", error);

    XCTAssertEqual(header.type, IRMessageTypeNormal);
    XCTAssertEqual(header.headerLength, (NSUInteger)kIRLenType01Header);
    XCTAssertFalse(header.isPreKeyMessage);
    XCTAssertTrue([header.ratchetKey isEqualToX25519Public:self.senderRatchet.publicKey]);
    XCTAssertEqual(header.N, kTestN);
    XCTAssertEqual(header.PN, kTestPN);
    XCTAssertTrue([header.nonce isEqualToNonce:self.nonce]);

    /* Type 0x02 fields are absent, not defaulted to something plausible. */
    XCTAssertNil(header.initiatorIdentity);
    XCTAssertNil(header.identityBinding);
    XCTAssertNil(header.ephemeralPublic);
    XCTAssertNil(header.handshakeId, @"§11.5 — a type 0x01 message carries no session identifier");
}

- (void)testType02RoundTripPreservesEveryField {
    NSMutableData *message = [self validType02Message];

    NSError *error = nil;
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@", error);

    XCTAssertEqual(header.type, IRMessageTypePrekey);
    XCTAssertEqual(header.headerLength, (NSUInteger)kIRLenType02Header);
    XCTAssertTrue(header.isPreKeyMessage);
    XCTAssertTrue([header.initiatorIdentity isEqualToIdentityKeyPair:self.alice.identityKeyPair]);
    XCTAssertTrue([header.identityBinding isEqualToEd25519Signature:self.alice.binding]);
    XCTAssertTrue([header.ephemeralPublic isEqualToX25519Public:self.ephemeral.publicKey]);
    XCTAssertEqual(header.spkId, kSpkId);
    XCTAssertEqual(header.opkFlag, IROPKFlagPresent);
    XCTAssertEqual(header.opkId, kOpkId);
    XCTAssertTrue([header.ratchetKey isEqualToX25519Public:self.senderRatchet.publicKey]);
    XCTAssertEqual(header.N, kTestN);
    XCTAssertEqual(header.PN, 0u, @"§9.2 — always zero, and unwritable through the builder");
    XCTAssertTrue([header.nonce isEqualToNonce:self.nonce]);
}

/// §11.1 — `handshake_id = IK_A^d ‖ EK_A`, 64 bytes, and §11.2 reads it from `msg[36..68)` and
/// `msg[132..164)`. Both spellings must produce the same bytes or session dispatch misroutes.
- (void)testType02HandshakeIdMatchesTheWireSlices {
    NSMutableData *message = [self validType02Message];

    NSError *error = nil;
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@", error);

    XCTAssertEqual(header.handshakeId.length, (NSUInteger)kIRLenHandshakeId);

    NSMutableData *expected = [NSMutableData data];
    [expected appendData:self.alice.identityKeyPair.agreementKey.data];
    [expected appendData:self.ephemeral.publicKey.data];
    XCTAssertEqualObjects(header.handshakeId, expected);

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];
    NSMutableData *fromWire = [NSMutableData data];
    [fromWire appendData:[reader dataAtOffset:(NSUInteger)kIROffType02IdentityAgreement
                                       length:(NSUInteger)kIRLenX25519Public]];
    [fromWire appendData:[reader dataAtOffset:(NSUInteger)kIROffType02EK
                                       length:(NSUInteger)kIRLenX25519Public]];
    XCTAssertEqualObjects(header.handshakeId, fromWire, @"§11.2's slices must agree with §11.1");
}

/// §8.5 — `headerBytes` is the RECEIVED prefix, not a re-serialization. Every valid header
/// re-serializes identically, so this pins the contract rather than catching a live bug; the bug it
/// forecloses only ever appears as an interop failure against another language.
- (void)testHeaderBytesAreTheVerbatimPrefix {
    for (NSNumber *isPrekey in @[@NO, @YES]) {
        NSMutableData *message = isPrekey.boolValue ? [self validType02Message]
                                                    : [self validType01Message];
        NSError *error = nil;
        IRMessageHeader *header =
            isPrekey.boolValue
                ? [IRMessageGate parseType02Message:message error:&error]
                : [IRMessageGate parseType01Message:message
                                ownRatchetPublicKey:self.ownRatchet.publicKey
                                              error:&error];
        XCTAssertNotNil(header, @"%@", error);

        XCTAssertEqual(header.headerBytes.length, header.headerLength);
        XCTAssertEqualObjects(header.headerBytes,
                              [message subdataWithRange:NSMakeRange(0, header.headerLength)]);
    }
}

#pragma mark - §8.5 — associated data

- (void)testAssociatedDataIsSessionADFollowedByTheHeader {
    NSError *error = nil;

    NSMutableData *type01 = [self validType01Message];
    IRMessageHeader *header01 = [IRMessageGate parseType01Message:type01
                                             ownRatchetPublicKey:self.ownRatchet.publicKey
                                                           error:&error];
    XCTAssertNotNil(header01, @"%@", error);

    NSData *ad01 = [IRMessageGate associatedDataWithSessionAD:self.sessionAD
                                                       header:header01
                                                        error:&error];
    XCTAssertNotNil(ad01, @"%@", error);
    XCTAssertEqual(ad01.length, (NSUInteger)kIRLenType01AD, @"§8.5 — 141 + 56 = 197");

    NSMutableData *expected01 = [NSMutableData data];
    [expected01 appendData:self.sessionAD.bytes];
    [expected01 appendData:header01.headerBytes];
    XCTAssertEqualObjects(ad01, expected01);

    NSMutableData *type02 = [self validType02Message];
    IRMessageHeader *header02 = [IRMessageGate parseType02Message:type02 error:&error];
    XCTAssertNotNil(header02, @"%@", error);

    NSData *ad02 = [IRMessageGate associatedDataWithSessionAD:self.sessionAD
                                                       header:header02
                                                        error:&error];
    XCTAssertNotNil(ad02, @"%@", error);
    XCTAssertEqual(ad02.length, (NSUInteger)kIRLenType02AD, @"§8.5 — 141 + 225 = 366");

    NSMutableData *expected02 = [NSMutableData data];
    [expected02 appendData:self.sessionAD.bytes];
    [expected02 appendData:header02.headerBytes];
    XCTAssertEqualObjects(ad02, expected02);
}

/// The gate forwards to IRSessionAD rather than owning a second copy of the concatenation. If those
/// two ever diverge, this is where it shows.
- (void)testAssociatedDataAgreesWithIRSessionADDirectly {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    IRMessageHeader *header = [IRMessageGate parseType01Message:message
                                           ownRatchetPublicKey:self.ownRatchet.publicKey
                                                         error:&error];
    XCTAssertNotNil(header, @"%@", error);

    XCTAssertEqualObjects([IRMessageGate associatedDataWithSessionAD:self.sessionAD
                                                              header:header
                                                               error:&error],
                          [self.sessionAD associatedDataWithHeaderBytes:header.headerBytes
                                                                  error:&error]);
}

/// §8.5 — version, type and flags are inside the AD, so tampering with them is an AUTHENTICATION
/// failure and not merely an `if`. The gate rejects them first, but this asserts the deeper
/// property: those bytes are covered, so a peer that skipped the checks still fails closed.
- (void)testAssociatedDataCoversVersionTypeAndFlags {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    IRMessageHeader *header = [IRMessageGate parseType01Message:message
                                           ownRatchetPublicKey:self.ownRatchet.publicKey
                                                         error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *ad = [IRMessageGate associatedDataWithSessionAD:self.sessionAD header:header error:&error];
    XCTAssertNotNil(ad, @"%@", error);

    const uint8_t *adBytes = (const uint8_t *)ad.bytes;
    NSUInteger headerStart = (NSUInteger)kIRLenSessionAD;
    XCTAssertEqual(adBytes[headerStart + (NSUInteger)kIROffType01Version], (uint8_t)kIRProtocolVersion);
    XCTAssertEqual(adBytes[headerStart + (NSUInteger)kIROffType01Type], (uint8_t)IRMessageTypeNormal);
    XCTAssertEqual(adBytes[headerStart + (NSUInteger)kIROffType01Flags], 0x00);
    XCTAssertEqual(adBytes[headerStart + (NSUInteger)kIROffType01Flags + 1], 0x00);
}

#pragma mark - §9 — ciphertext extent by subtraction

- (void)testCiphertextIsTheRemainderAfterTheHeader {
    NSError *error = nil;
    NSData *payload = IRDataFromHex(@"00112233445566778899aabbccddeeff0123456789");

    NSData *header = [IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                                N:kTestN
                                                               PN:kTestPN
                                                            nonce:self.nonce
                                                            error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:payload
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    IRMessageHeader *parsed = [IRMessageGate parseType01Message:message
                                           ownRatchetPublicKey:self.ownRatchet.publicKey
                                                         error:&error];
    XCTAssertNotNil(parsed, @"%@", error);

    XCTAssertEqualObjects([IRMessageGate ciphertextAndTagOfMessage:message
                                                            header:parsed
                                                             error:&error],
                          payload,
                          @"§9 — the ciphertext extent is derived by subtraction, and there is no "
                          @"length field on the wire to misparse");
}

#pragma mark - Decision D2 — routing

- (void)testRoutingResolvesBothTypes {
    NSError *error = nil;
    XCTAssertEqual([IRMessageGate messageTypeOfMessage:[self validType01Message] error:&error],
                   IRMessageTypeNormal);
    XCTAssertNil(error);

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:[self validType02Message] error:&error],
                   IRMessageTypePrekey);
    XCTAssertNil(error);
}

/// The global floor is 72 — check 1 of BOTH gates — so a 71-byte input can never reach a type byte.
- (void)testRoutingAppliesTheGlobalLengthFloor {
    NSError *error = nil;
    NSMutableData *tooShort = [[self validType01Message] mutableCopy];
    tooShort.length = (NSUInteger)kIRLenType01Min - 1;

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:tooShort error:&error], (IRMessageType)0);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"D2 — 71 bytes is below the global floor"];
}

- (void)testRoutingRejectsUnknownType {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Type in:message];

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:message error:&error], (IRMessageType)0);
    [self assertError:error
              hasCode:IRErrorUnknownMessageType
              because:@"NEG-TYPE / §9.3 — there is no type 0x03"];
}

/// §10.0 — "row 3 precedes row 4". A message that is BOTH a wrong version and an unknown type must
/// report the version, or routing contradicts the gates it dispatches into.
- (void)testOrderRoutingVersionBeatsUnknownType {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Type in:message];

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:message error:&error], (IRMessageType)0);
    [self assertError:error
              hasCode:IRErrorUnsupportedVersion
              because:@"§10.0 — row 3 precedes row 4 in both gates, so routing must agree"];
}

/// §10.6 — a v3 message begins with 0x03 and dies at §10.0 ROW 3, before the type is read at all.
///
/// This test previously asserted the opposite: that routing dispatched on msg[1] first and returned
/// IRMessageTypeNormal for a v3 message, leaving the version to the gate. The final code agreed for
/// a FULL-LENGTH message, which is why nothing caught it — but it made §10.6 false for any v3
/// message below the invoked gate's floor. `NEG-VERSION-SHORT` below is that case.
- (void)testNEG_VERSION_RejectedAtTheDemuxBeforeTheTypeIsRead {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:message error:&error], (IRMessageType)0);
    [self assertError:error
              hasCode:IRErrorUnsupportedVersion
              because:@"NEG-VERSION / §10.0 row 3 — no downgrade path, no dual-stack mode"];

    /* And the gate's own check 3 agrees, so the two cannot drift apart. */
    error = nil;
    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"§10.1 check 3"];
}

/**
 §15.4 `NEG-VERSION-SHORT` — "a 100-byte message with `msg[0] == 0x03` and `msg[1] == 0x02`, i.e.
 BELOW §10.2's floor of 241".

 This is the vector that makes §10.6's guarantee testable, and the one that fails against a gate
 ordering that puts a type-dependent length floor ahead of the version check: 100 < 241, so §10.2
 check 1 would fire first and report ERR_TRUNCATED_MESSAGE — silently making "a v3 message is
 rejected with ERR_UNSUPPORTED_VERSION" conditional on message length.
 */
- (void)testNEG_VERSION_SHORT {
    NSMutableData *message = [NSMutableData dataWithLength:100];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];
    [self setByte:(uint8_t)IRMessageTypePrekey atOffset:(NSUInteger)kIROffType01Type in:message];

    XCTAssertLessThan(message.length, (NSUInteger)kIRLenType02Min,
                      @"the fixture must sit BELOW the type 0x02 floor or it tests nothing");
    XCTAssertGreaterThanOrEqual(message.length, (NSUInteger)kIRLenMessageMin,
                                @"...and above the global floor, or row 1 fires instead");

    NSError *error = nil;
    XCTAssertEqual([IRMessageGate messageTypeOfMessage:message error:&error], (IRMessageType)0);
    [self assertError:error
              hasCode:IRErrorUnsupportedVersion
              because:@"NEG-VERSION-SHORT / §10.6 — the version check is unconditional on length"];

    /* Through the full demultiplex, at the prekey entry point, which is where a host would land. */
    error = nil;
    XCTAssertFalse([IRMessageGate demultiplexMessage:message
                                        expectedType:IRMessageTypePrekey
                                               error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"§10.0 row 3 precedes row 5"];
}

#pragma mark - §10.0 — the entry-point demultiplex

/**
 §15.4 `NEG-ENTRYPOINT-01-TO-02` — a 72-byte, otherwise valid type `0x01` message submitted to the
 type `0x02` entry point.

 THE 72-BYTE LENGTH IS THE WHOLE POINT and the vector forbids widening it. 72 sits BELOW §10.2's
 floor of 241, so an implementation that evaluated that floor before the demultiplex returns
 ERR_TRUNCATED_MESSAGE — a truncation that does not exist. A 300-byte fixture returns the right code
 on both orderings and distinguishes nothing.
 */
- (void)testNEG_ENTRYPOINT_01_TO_02 {
    NSMutableData *message = [self validType01Message];
    message.length = (NSUInteger)kIRLenType01Min;

    XCTAssertEqual(message.length, (NSUInteger)72);
    XCTAssertLessThan(message.length, (NSUInteger)kIRLenType02Min);

    NSError *error = nil;
    XCTAssertFalse([IRMessageGate demultiplexMessage:message
                                        expectedType:IRMessageTypePrekey
                                               error:&error]);
    [self assertError:error
              hasCode:IRErrorWrongEntryPoint
              because:@"NEG-ENTRYPOINT-01-TO-02 / §10.0 row 5 — not a truncation, a misrouted call"];
}

/// §15.4 `NEG-ENTRYPOINT-02-TO-01` — the other direction. A complete, valid type `0x02` message is
/// well above the type `0x01` floor, so only row 5 can reject it.
- (void)testNEG_ENTRYPOINT_02_TO_01 {
    NSData *message = [self validType02Message];

    NSError *error = nil;
    XCTAssertFalse([IRMessageGate demultiplexMessage:message
                                        expectedType:IRMessageTypeNormal
                                               error:&error]);
    [self assertError:error
              hasCode:IRErrorWrongEntryPoint
              because:@"NEG-ENTRYPOINT-02-TO-01 / §10.0 row 5"];
}

/// §10.0 row 5 is the LAST row. Every earlier failure keeps its own code even when the type is also
/// wrong for the entry point, or the new code would swallow four older vectors.
- (void)testOrderDemux_EveryEarlierRowBeatsTheEntryPointMatch {
    NSError *error = nil;

    /* Row 1 — below the global floor, and the wrong type for the entry point. */
    NSMutableData *tooShort = [self validType01Message];
    tooShort.length = (NSUInteger)kIRLenMessageMin - 1;
    XCTAssertFalse([IRMessageGate demultiplexMessage:tooShort
                                        expectedType:IRMessageTypePrekey
                                               error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"row 1 beats row 5"];

    /* Row 3 — wrong version, and the wrong type for the entry point. */
    error = nil;
    NSMutableData *badVersion = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:badVersion];
    XCTAssertFalse([IRMessageGate demultiplexMessage:badVersion
                                        expectedType:IRMessageTypePrekey
                                               error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"row 3 beats row 5"];

    /* Row 4 — a type byte outside the domain is NEG-TYPE's 7101, never 7125, whichever entry point
       was invoked. The two codes must not merge. */
    error = nil;
    NSMutableData *badType = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Type in:badType];
    XCTAssertFalse([IRMessageGate demultiplexMessage:badType
                                        expectedType:IRMessageTypePrekey
                                               error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType because:@"row 4 beats row 5"];

    /* And the control: the matching entry point accepts the valid message. */
    error = nil;
    XCTAssertTrue([IRMessageGate demultiplexMessage:[self validType01Message]
                                       expectedType:IRMessageTypeNormal
                                              error:&error], @"%@", error);
    XCTAssertNil(error);
}

/// 7125 is remotely triggerable through a transport that flips the inner type byte, so §10.5 puts it
/// in the mandatory peer-opaque set alongside 7100–7112 even though it is not contiguous with them.
- (void)testWrongEntryPointCodeIsOpaqueToPeer {
    XCTAssertTrue(IRErrorMustBeOpaqueToPeer(IRErrorWrongEntryPoint));
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorWrongEntryPoint), @"ERR_WRONG_ENTRY_POINT");

    IRErrorCode roundTrip = (IRErrorCode)0;
    XCTAssertTrue(IRErrorCodeFromName(@"ERR_WRONG_ENTRY_POINT", &roundTrip));
    XCTAssertEqual(roundTrip, IRErrorWrongEntryPoint);
}

#pragma mark - Decision D1 — the split type 0x01 gate

/**
 THE D1 ORDERING ASSERTION. §10.1 check 6 (session resolution) sits between checks 5 and 7, so a
 10-byte input with no session MUST report ERR_TRUNCATED_MESSAGE, never ERR_NO_SESSION.

 A single parser entry point taking `ownRatchetPublicKey:` forces the caller to resolve the session
 BEFORE checks 1–5 run, and returns the wrong code here. That is the design D1 rejects, and this is
 the test that catches it.
 */
- (void)testOrderD1_TruncatedBeatsNoSession {
    NSError *error = nil;
    NSMutableData *tiny = [NSMutableData dataWithLength:10];

    XCTAssertFalse([IRMessageGate gateType01Prefix:tiny error:&error]);
    [self assertError:error
              hasCode:IRErrorTruncatedMessage
              because:@"D1 — checks 1–5 run before the caller resolves a session"];

    /* And the same through the full parse: checks 1–5 are re-run FIRST, so even a caller that has
       already lost its session gets the truncation code rather than a session error. */
    error = nil;
    XCTAssertNil([IRMessageGate parseType01Message:tiny
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error
              hasCode:IRErrorTruncatedMessage
              because:@"D1 — parseType01Message re-runs checks 1–5 before touching the session"];
}

/**
 The sharpest available statement of D1, INSIDE the one method that could get it wrong.

 A caller with no resolved session has no own-ratchet key to supply. §10.1 still orders check 1
 before check 6, so a truncated message submitted with no session key must report truncation. An
 implementation that validated its `ownRatchetPublicKey` argument before re-running checks 1–5 would
 answer ERR_NO_SESSION here — the exact substitution D1 exists to prevent, one call deeper than the
 API split can express on its own.
 */
- (void)testOrderD1_TruncatedBeatsNoSessionEvenWithNoOwnKey {
    NSError *error = nil;
    NSMutableData *tiny = [NSMutableData dataWithLength:10];

    /* See -testEveryFailurePathToleratesANullErrorPointer for why the annotation is suppressed:
       nullability is advisory, and "the caller has no session" is precisely how a nil arrives. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRMessageGate parseType01Message:tiny ownRatchetPublicKey:nil error:&error]);
#pragma clang diagnostic pop

    [self assertError:error
              hasCode:IRErrorTruncatedMessage
              because:@"§10.1 — check 1 precedes check 6 even when both would fire"];

    /* And with a full-length, well-formed message the same call DOES report the session failure,
       so the assertion above is about ordering and not about the code being unreachable. */
    error = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRMessageGate parseType01Message:[self validType01Message]
                               ownRatchetPublicKey:nil
                                             error:&error]);
#pragma clang diagnostic pop

    [self assertError:error
              hasCode:IRErrorNoSession
              because:@"§10.1 check 6 — no resolved session means no key for check 8"];
}

/// The other half of D1: a full-length message with a bad version, submitted by a caller with no
/// session. The prefix gate answers before session resolution is even attempted.
- (void)testOrderD1_VersionBeatsNoSession {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error
              hasCode:IRErrorUnsupportedVersion
              because:@"D1 — a monolithic parser would have returned ERR_NO_SESSION here"];
}

/// Checks 1–5 are pure and idempotent, which is what makes re-running them in step 4 of the D1
/// sequence free of side effects.
- (void)testPrefixGateIsIdempotent {
    NSMutableData *message = [self validType01Message];
    for (NSUInteger attempt = 0; attempt < 4; attempt++) {
        NSError *error = nil;
        XCTAssertTrue([IRMessageGate gateType01Prefix:message error:&error], @"%@", error);
    }
}

#pragma mark - §10.1 — type 0x01 gate rows

- (void)testType01Check1TruncatedBelowFloor {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    message.length = (NSUInteger)kIRLenType01Min - 1;

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"NEG-TRUNCATED — 71 bytes"];
}

- (void)testType01Check3Version {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"NEG-VERSION"];
}

- (void)testType01Check4Type {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x02 atOffset:(NSUInteger)kIROffType01Type in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error
              hasCode:IRErrorUnknownMessageType
              because:@"a type 0x02 byte submitted to the type 0x01 gate"];
}

- (void)testType01Check5Flags {
    NSError *error = nil;

    /* Both flag bytes, independently — a gate that only compared one would pass one of these. */
    NSMutableData *lowBit = [self validType01Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType01Flags + 1 in:lowBit];
    XCTAssertFalse([IRMessageGate gateType01Prefix:lowBit error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet because:@"NEG-FLAGS — flags 0x0001"];

    error = nil;
    NSMutableData *highBit = [self validType01Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType01Flags in:highBit];
    XCTAssertFalse([IRMessageGate gateType01Prefix:highBit error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet because:@"flags 0x0100"];
}

- (void)testType01Check7PublicKeyHighBit {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    NSUInteger lastByte = (NSUInteger)kIROffType01DHs + (NSUInteger)kIRLenX25519Public - 1;
    uint8_t value = ((const uint8_t *)message.bytes)[lastByte] | 0x80;
    [self setByte:value atOffset:lastByte in:message];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error
              hasCode:IRErrorInvalidPublicKey
              because:@"NEG-PUBKEY-HIGHBIT — §4.4 check 2 rejects the non-canonical encoding"];
}

- (void)testType01Check8AntiReflection {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [message replaceBytesInRange:NSMakeRange((NSUInteger)kIROffType01DHs,
                                             (NSUInteger)kIRLenX25519Public)
                       withBytes:self.ownRatchet.publicKey.data.bytes];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error
              hasCode:IRErrorInvalidPublicKey
              because:@"NEG-PUBKEY-REFLECT-01 — our own DHs public reflected back at us"];
}

- (void)testType01Checks9And10CounterOverflow {
    for (NSNumber *offset in @[@((NSUInteger)kIROffType01N), @((NSUInteger)kIROffType01PN)]) {
        NSError *error = nil;
        NSMutableData *message = [self validType01Message];
        [self setUInt32BE:0x80000000u atOffset:offset.unsignedIntegerValue in:message];

        XCTAssertNil([IRMessageGate parseType01Message:message
                                   ownRatchetPublicKey:self.ownRatchet.publicKey
                                                 error:&error]);
        [self assertError:error
                  hasCode:IRErrorCounterOverflow
                  because:[NSString stringWithFormat:@"NEG-COUNTER at offset %@", offset]];
    }
}

/// 0x7FFFFFFF is the largest legal value on both counters — the bound is inclusive.
- (void)testType01CounterBoundaryIsInclusive {
    NSError *error = nil;
    NSMutableData *message = [self validType01MessageWithN:(uint32_t)kIRMaxCounter
                                                        PN:(uint32_t)kIRMaxCounter];

    IRMessageHeader *header = [IRMessageGate parseType01Message:message
                                           ownRatchetPublicKey:self.ownRatchet.publicKey
                                                         error:&error];
    XCTAssertNotNil(header, @"%@ — §10.1 checks 9–10 are `<= 0x7FFFFFFF`, not `<`", error);
    XCTAssertEqual(header.N, (uint32_t)kIRMaxCounter);
    XCTAssertEqual(header.PN, (uint32_t)kIRMaxCounter);
}

#pragma mark - §10.1 — ordering

/// Checks 1 before 3: an input that is both truncated and mis-versioned reports truncation.
- (void)testOrderType01_TruncationBeatsVersion {
    NSError *error = nil;
    NSMutableData *message = [NSMutableData dataWithLength:10];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"§10.1 — check 1 before check 3"];
}

/// Checks 3 before 4.
- (void)testOrderType01_VersionBeatsType {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType01Version in:message];
    [self setByte:0x07 atOffset:(NSUInteger)kIROffType01Type in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"§10.1 — check 3 before check 4"];
}

/// Checks 4 before 5.
- (void)testOrderType01_TypeBeatsFlags {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x07 atOffset:(NSUInteger)kIROffType01Type in:message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType01Flags + 1 in:message];

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType because:@"§10.1 — check 4 before check 5"];
}

/// Checks 5 before 7.
- (void)testOrderType01_FlagsBeatPublicKey {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType01Flags + 1 in:message];
    NSUInteger lastByte = (NSUInteger)kIROffType01DHs + (NSUInteger)kIRLenX25519Public - 1;
    [self setByte:((const uint8_t *)message.bytes)[lastByte] | 0x80 atOffset:lastByte in:message];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet because:@"§10.1 — check 5 before check 7"];
}

/// Checks 7 before 9.
- (void)testOrderType01_PublicKeyBeatsCounter {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    NSUInteger lastByte = (NSUInteger)kIROffType01DHs + (NSUInteger)kIRLenX25519Public - 1;
    [self setByte:((const uint8_t *)message.bytes)[lastByte] | 0x80 atOffset:lastByte in:message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType01N in:message];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey because:@"§10.1 — check 7 before check 9"];
}

/// Checks 8 before 9 — the anti-reflection comparison precedes the counter bounds.
- (void)testOrderType01_AntiReflectionBeatsCounter {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [message replaceBytesInRange:NSMakeRange((NSUInteger)kIROffType01DHs,
                                             (NSUInteger)kIRLenX25519Public)
                       withBytes:self.ownRatchet.publicKey.data.bytes];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType01N in:message];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    [self assertError:error hasCode:IRErrorInvalidPublicKey because:@"§10.1 — check 8 before check 9"];
}

/// Check 9 before check 10: N is bounded before PN is even read.
- (void)testOrderType01_NBeatsPN {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType01N in:message];
    [self setUInt32BE:0x90000000u atOffset:(NSUInteger)kIROffType01PN in:message];

    XCTAssertNil([IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:&error]);
    /* Both report ERR_COUNTER_OVERFLOW, so this pins that the gate does not stop at the first
       readable field; it is a regression guard for a parser that read PN and forgot N. */
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"§10.1 — checks 9 and 10"];
}

#pragma mark - §10.2 — type 0x02 gate rows

- (void)testType02Check1TruncatedBelowFloor {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    message.length = (NSUInteger)kIRLenType02Min - 1;

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"§10.2 check 1 — 240 bytes"];
}

- (void)testType02Check3Version {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x03 atOffset:(NSUInteger)kIROffType02Version in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorUnsupportedVersion because:@"§10.2 check 3"];
}

- (void)testType02Check4Type {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType02Type in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorUnknownMessageType because:@"§10.2 check 4"];
}

- (void)testType02Check5Flags {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType02Flags + 1 in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet because:@"§10.2 check 5"];
}

/// §9.2 — "any other value -> reject". Every byte outside {0x00, 0x01} must fail identically.
- (void)testType02Check6OPKFlagDomain {
    for (unsigned candidate = 0x02; candidate <= 0xFF; candidate++) {
        NSError *error = nil;
        NSMutableData *message = [self validType02Message];
        [self setByte:(uint8_t)candidate atOffset:(NSUInteger)kIROffType02OPKFlag in:message];

        XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
        [self assertError:error
                  hasCode:IRErrorMalformedHeader
                  because:[NSString stringWithFormat:@"§10.2 check 6 — opk_flag 0x%02x", candidate]];
    }
}

- (void)testType02Check7OPKFlagAbsentForcesZeroId {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:(uint8_t)IROPKFlagAbsent atOffset:(NSUInteger)kIROffType02OPKFlag in:message];
    /* opk_id is still kOpkId from the fixture, so the flag and the id now contradict each other. */

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error
              hasCode:IRErrorMalformedHeader
              because:@"NEG-OPKFLAG-ID — opk_flag 0x00 with a non-zero opk_id"];
}

/// The CONVERSE of check 7 is deliberately not a rule: 0 is a legal one-time prekey id, and §10.7
/// step 7 resolves it like any other. A port that symmetrized check 7 would reject a legitimate
/// sender whose OPK happened to be numbered zero.
- (void)testType02OPKFlagPresentWithZeroIdIsLegal {
    NSError *error = nil;
    IRSessionPrologue *zeroIdPrologue =
        [IRSessionPrologue prologueWithEphemeralPublic:self.ephemeral.publicKey
                                                 spkId:kSpkId
                                               opkFlag:IROPKFlagPresent
                                                 opkId:0
                                                 error:&error];
    XCTAssertNotNil(zeroIdPrologue, @"%@", error);

    NSMutableData *message = [self validType02MessageWithPrologue:zeroIdPrologue N:kTestN];
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@ — opk_id 0 with opk_flag 0x01 is a legal encoding", error);
    XCTAssertEqual(header.opkFlag, IROPKFlagPresent);
    XCTAssertEqual(header.opkId, 0u);
}

/// §5.3 / §6.2 — the no-OPK form, where `opk_flag` is 0x00 and `opk_id` is 0.
- (void)testType02NoOPKFormParses {
    NSError *error = nil;
    IRSessionPrologue *noOPK =
        [IRSessionPrologue prologueWithEphemeralPublic:self.ephemeral.publicKey
                                                 spkId:kSpkId
                                               opkFlag:IROPKFlagAbsent
                                                 opkId:0
                                                 error:&error];
    XCTAssertNotNil(noOPK, @"%@", error);

    NSMutableData *message = [self validType02MessageWithPrologue:noOPK N:kTestN];
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@", error);
    XCTAssertEqual(header.opkFlag, IROPKFlagAbsent);
    XCTAssertEqual(header.opkId, 0u);
}

- (void)testType02Check8PNMustBeZero {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setUInt32BE:1u atOffset:(NSUInteger)kIROffType02PN in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorMalformedHeader because:@"NEG-PREKEY-PN"];
}

/// §9.2 — "N MAY be non-zero in a type 0x02 header. This is essential and easy to get wrong."
- (void)testType02Check9NMayBeNonZero {
    NSError *error = nil;
    NSMutableData *message = [self validType02MessageWithPrologue:self.prologue N:41u];

    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@ — A's second prekey message before B replies", error);
    XCTAssertEqual(header.N, 41u);
}

- (void)testType02Check9CounterOverflow {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"§10.2 check 9"];
}

/// §10.2 check 10 covers three keys. Each one independently.
- (void)testType02Check10ValidatesThreeX25519Keys {
    NSArray<NSNumber *> *offsets = @[@((NSUInteger)kIROffType02IdentityAgreement),
                                     @((NSUInteger)kIROffType02EK),
                                     @((NSUInteger)kIROffType02DHs)];
    for (NSNumber *offset in offsets) {
        NSError *error = nil;
        NSMutableData *message = [self validType02Message];
        NSUInteger lastByte = offset.unsignedIntegerValue + (NSUInteger)kIRLenX25519Public - 1;
        [self setByte:((const uint8_t *)message.bytes)[lastByte] | 0x80 atOffset:lastByte in:message];

        XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
        [self assertError:error
                  hasCode:IRErrorInvalidPublicKey
                  because:[NSString stringWithFormat:@"§10.2 check 10 at offset %@", offset]];
    }
}

/**
 §4.4 SCOPING — the regression this spec exists to hold. `IK_A^s` at offset 4 is Ed25519, and bit
 255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2), set in roughly half of all valid
 identities. §10.2 check 10 lists three keys and deliberately excludes this one.

 The key below is RFC 8032 §7.1's SHA(abc) public key, whose last byte is 0xbf — high bit SET and
 entirely valid. A port that applied §4.4 check 2 to all four keys in this header would reject about
 half of all legitimate senders, intermittently, in a way that reads as a signature bug.

 This is the sixth layer of this implementation to hit the same under-scoped sentence in §4.4.
 */
- (void)testType02Check10ExcludesTheEd25519IdentityKey {
    NSData *rfc8032PublicKey =
        IRDataFromHex(@"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    XCTAssertEqual(rfc8032PublicKey.length, (NSUInteger)kIRLenEd25519Public);
    XCTAssertEqual(((const uint8_t *)rfc8032PublicKey.bytes)[31] & 0x80, 0x80,
                   @"the fixture must actually have bit 255 set, or it proves nothing");

    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [message replaceBytesInRange:NSMakeRange((NSUInteger)kIROffType02IdentitySigning,
                                             (NSUInteger)kIRLenEd25519Public)
                       withBytes:rfc8032PublicKey.bytes];

    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@ — §4.4 checks 1–2 are X25519-only", error);
    XCTAssertEqualObjects(header.initiatorIdentity.signingKey.data, rfc8032PublicKey);
}

- (void)testType02Check11AntiReflectionAgainstEphemeral {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [message replaceBytesInRange:NSMakeRange((NSUInteger)kIROffType02DHs,
                                             (NSUInteger)kIRLenX25519Public)
                       withBytes:self.ephemeral.publicKey.data.bytes];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error
              hasCode:IRErrorInvalidPublicKey
              because:@"NEG-PUBKEY-REFLECT-02-EKA — §10.2 check 11, DHs_pub == EK_A"];
}

/// §10.2 — `IKB_A` is carried, not verified. A corrupted binding must still PARSE; §10.7 step 3 and
/// §11.2 are what reject it, and both must return ERR_BAD_SIGNATURE rather than the AEAD failure.
- (void)testType02CarriesUnverifiedIdentityBinding {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    NSUInteger target = (NSUInteger)kIROffType02IKB;
    [self setByte:((const uint8_t *)message.bytes)[target] ^ 0xFF atOffset:target in:message];

    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    XCTAssertNotNil(header, @"%@ — the gate is the no-secret prefix; it performs no signature "
                    @"verification", error);
    XCTAssertFalse([header.identityBinding isEqualToEd25519Signature:self.alice.binding]);
}

#pragma mark - §10.2 — ordering

/// Checks 5 before 6.
- (void)testOrderType02_FlagsBeatOPKFlag {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x01 atOffset:(NSUInteger)kIROffType02Flags + 1 in:message];
    [self setByte:0x7F atOffset:(NSUInteger)kIROffType02OPKFlag in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorReservedFlagsSet because:@"§10.2 — check 5 before check 6"];
}

/// Checks 6 before 9.
- (void)testOrderType02_OPKFlagBeatsCounter {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x7F atOffset:(NSUInteger)kIROffType02OPKFlag in:message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorMalformedHeader because:@"§10.2 — check 6 before check 9"];
}

/// Checks 7 before 9.
- (void)testOrderType02_OPKIdBeatsCounter {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:(uint8_t)IROPKFlagAbsent atOffset:(NSUInteger)kIROffType02OPKFlag in:message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorMalformedHeader because:@"§10.2 — check 7 before check 9"];
}

/**
 CHECKS 8 BEFORE 9 — and this is the one that proves gate order and LAYOUT order are independent.

 Check 8 reads `PN` at offset 209. Check 9 reads `N` at offset 205. The gate therefore inspects a
 HIGHER offset first, which a purely sequential reader cannot express: a port that walked the header
 front to back would bound `N` before it ever looked at `PN`, and would answer this input with
 ERR_COUNTER_OVERFLOW instead of ERR_MALFORMED_HEADER.
 */
- (void)testOrderType02_PNBeatsN {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setUInt32BE:1u atOffset:(NSUInteger)kIROffType02PN in:message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error
              hasCode:IRErrorMalformedHeader
              because:@"§10.2 — check 8 (offset 209) runs BEFORE check 9 (offset 205)"];
}

/// Checks 9 before 10.
- (void)testOrderType02_CounterBeatsPublicKey {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];
    NSUInteger lastByte = (NSUInteger)kIROffType02DHs + (NSUInteger)kIRLenX25519Public - 1;
    [self setByte:((const uint8_t *)message.bytes)[lastByte] | 0x80 atOffset:lastByte in:message];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"§10.2 — check 9 before check 10"];
}

/// Checks 9 before 11.
- (void)testOrderType02_CounterBeatsAntiReflection {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setUInt32BE:0x80000000u atOffset:(NSUInteger)kIROffType02N in:message];
    [message replaceBytesInRange:NSMakeRange((NSUInteger)kIROffType02DHs,
                                             (NSUInteger)kIRLenX25519Public)
                       withBytes:self.ephemeral.publicKey.data.bytes];

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"§10.2 — check 9 before check 11"];
}

/// Checks 1 before 6 — a 240-byte input cannot have offset 168 read at all, and must report
/// truncation rather than trapping or inventing a malformed-header verdict.
- (void)testOrderType02_TruncationBeatsOPKFlag {
    NSError *error = nil;
    NSMutableData *message = [self validType02Message];
    [self setByte:0x7F atOffset:(NSUInteger)kIROffType02OPKFlag in:message];
    message.length = (NSUInteger)kIRLenType02Min - 1;

    XCTAssertNil([IRMessageGate parseType02Message:message error:&error]);
    [self assertError:error hasCode:IRErrorTruncatedMessage because:@"§10.2 — check 1 before check 6"];
}

#pragma mark - Exhaustive truncation

/**
 §12.4's discipline applied to the wire parsers: "a fuzz run is a failure if any input produces
 anything other than a specified error code". Every prefix of a valid message — including the empty
 one — must return exactly ERR_TRUNCATED_MESSAGE, and none may trap.

 §10.3's rationale for the bundle names the three-way divergence this forecloses: Objective-C over a
 raw pointer reads adjacent heap silently, Swift `Data` subscripting TRAPS (an uncatchable remote
 DoS), and the JVM throws an unchecked `IndexOutOfBoundsException` that escapes the error contract.
 The wire parsers deserve the same guarantee, and here it is enumerated rather than sampled.
 */
- (void)testEveryTruncatedPrefixOfAType01MessageIsRejectedCleanly {
    NSMutableData *valid = [self validType01Message];

    for (NSUInteger prefix = 0; prefix < (NSUInteger)kIRLenType01Min; prefix++) {
        NSData *truncated = [valid subdataWithRange:NSMakeRange(0, prefix)];

        NSError *error = nil;
        XCTAssertFalse([IRMessageGate gateType01Prefix:truncated error:&error]);
        [self assertError:error
                  hasCode:IRErrorTruncatedMessage
                  because:[NSString stringWithFormat:@"prefix gate at %lu bytes", (unsigned long)prefix]];

        error = nil;
        XCTAssertNil([IRMessageGate parseType01Message:truncated
                                   ownRatchetPublicKey:self.ownRatchet.publicKey
                                                 error:&error]);
        [self assertError:error
                  hasCode:IRErrorTruncatedMessage
                  because:[NSString stringWithFormat:@"full parse at %lu bytes", (unsigned long)prefix]];
    }
}

- (void)testEveryTruncatedPrefixOfAType02MessageIsRejectedCleanly {
    NSMutableData *valid = [self validType02Message];

    for (NSUInteger prefix = 0; prefix < (NSUInteger)kIRLenType02Min; prefix++) {
        NSData *truncated = [valid subdataWithRange:NSMakeRange(0, prefix)];

        NSError *error = nil;
        XCTAssertNil([IRMessageGate parseType02Message:truncated error:&error]);
        [self assertError:error
                  hasCode:IRErrorTruncatedMessage
                  because:[NSString stringWithFormat:@"type 0x02 at %lu bytes", (unsigned long)prefix]];
    }
}

/// Routing must survive the same corpus. Below 72 it is always truncation; from 72 up it reads a
/// type byte that the fixture happens to make valid.
- (void)testRoutingSurvivesEveryTruncatedPrefix {
    NSMutableData *valid = [self validType02Message];

    for (NSUInteger prefix = 0; prefix <= valid.length; prefix++) {
        NSError *error = nil;
        NSData *truncated = [valid subdataWithRange:NSMakeRange(0, prefix)];
        IRMessageType type = [IRMessageGate messageTypeOfMessage:truncated error:&error];

        if (prefix < (NSUInteger)kIRLenMessageMin) {
            XCTAssertEqual(type, (IRMessageType)0);
            [self assertError:error
                      hasCode:IRErrorTruncatedMessage
                      because:[NSString stringWithFormat:@"routing at %lu bytes", (unsigned long)prefix]];
        } else {
            XCTAssertEqual(type, IRMessageTypePrekey);
            XCTAssertNil(error);
        }
    }
}

#pragma mark - §10.4 — size bounds

- (void)testType01MaximumLengthBoundary {
    NSError *error = nil;

    NSMutableData *atMaximum = [self validType01Message];
    atMaximum.length = (NSUInteger)kIRLenType01Max;
    XCTAssertTrue([IRMessageGate gateType01Prefix:atMaximum error:&error], @"%@", error);

    error = nil;
    NSMutableData *overMaximum = [self validType01Message];
    overMaximum.length = (NSUInteger)kIRLenType01Max + 1;
    XCTAssertFalse([IRMessageGate gateType01Prefix:overMaximum error:&error]);
    [self assertError:error
              hasCode:IRErrorPlaintextTooLarge
              because:@"§10.1 check 2 — the type 0x01 cap is 16777288"];
}

/**
 D2's "looser cap" rule, made observable. A 16777289-byte type `0x01` message is over ITS cap but
 under the routing cap of 16777457, so routing must let it through and the type `0x01` gate must be
 what rejects it. A router that applied the tighter bound would return the right code by luck here
 and the wrong verdict on a large type `0x02` message.
 */
- (void)testRoutingUsesTheLooserCapSoTheGateOwnsTheTighterOne {
    NSError *error = nil;
    NSMutableData *message = [self validType01Message];
    message.length = (NSUInteger)kIRLenType01Max + 1;

    XCTAssertEqual([IRMessageGate messageTypeOfMessage:message error:&error], IRMessageTypeNormal);
    XCTAssertNil(error, @"D2 — routing applies the LOOSER of the two caps");

    XCTAssertFalse([IRMessageGate gateType01Prefix:message error:&error]);
    [self assertError:error hasCode:IRErrorPlaintextTooLarge because:@"the gate owns its own cap"];
}

- (void)testType02MaximumLengthBoundary {
    NSError *error = nil;

    NSMutableData *overMaximum = [self validType02Message];
    overMaximum.length = (NSUInteger)kIRLenType02Max + 1;

    XCTAssertNil([IRMessageGate parseType02Message:overMaximum error:&error]);
    [self assertError:error hasCode:IRErrorPlaintextTooLarge because:@"§10.2 check 2 — 16777457"];

    error = nil;
    XCTAssertEqual([IRMessageGate messageTypeOfMessage:overMaximum error:&error], (IRMessageType)0);
    [self assertError:error
              hasCode:IRErrorPlaintextTooLarge
              because:@"D2 — above the loosest cap, routing itself refuses"];
}

- (void)testPlaintextBoundsAcceptEmptyAndRejectOversize {
    NSError *error = nil;

    XCTAssertTrue([IRMessageBuilder validatePlaintextLength:0 error:&error],
                  @"§10.4 — empty plaintext is LEGAL; v3 conflated it with failure");
    XCTAssertTrue([IRMessageBuilder validatePlaintextLength:(NSUInteger)kIRMaxPlaintext error:&error],
                  @"§10.4 — the bound is inclusive");

    XCTAssertFalse([IRMessageBuilder validatePlaintextLength:(NSUInteger)kIRMaxPlaintext + 1
                                                       error:&error]);
    [self assertError:error hasCode:IRErrorPlaintextTooLarge because:@"§10.4 — MAX_PLAINTEXT"];
}

#pragma mark - IRMessageBuilder

- (void)testBuilderRejectsOverflowingCounters {
    NSError *error = nil;

    XCTAssertNil([IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                            N:0x80000000u
                                                           PN:0
                                                        nonce:self.nonce
                                                        error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"a sender must not emit N > 0x7FFFFFFF"];

    error = nil;
    XCTAssertNil([IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                            N:0
                                                           PN:0x80000000u
                                                        nonce:self.nonce
                                                        error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"…nor PN"];

    error = nil;
    XCTAssertNil([IRMessageBuilder type02HeaderWithInitiatorIdentity:self.alice.identityKeyPair
                                                     identityBinding:self.alice.binding
                                                            prologue:self.prologue
                                                          ratchetKey:self.senderRatchet.publicKey
                                                                   N:0x80000000u
                                                               nonce:self.nonce
                                                               error:&error]);
    [self assertError:error hasCode:IRErrorCounterOverflow because:@"…nor N on a prekey message"];
}

/// §10.2 check 11 mirrored on the send side, so a port that wired one key pair into both the
/// ephemeral and the initial ratchet slot fails at the source rather than on every peer.
- (void)testBuilderRejectsRatchetKeyEqualToEphemeral {
    NSError *error = nil;
    XCTAssertNil([IRMessageBuilder type02HeaderWithInitiatorIdentity:self.alice.identityKeyPair
                                                     identityBinding:self.alice.binding
                                                            prologue:self.prologue
                                                          ratchetKey:self.ephemeral.publicKey
                                                                   N:kTestN
                                                               nonce:self.nonce
                                                               error:&error]);
    [self assertError:error
              hasCode:IRErrorInvalidPublicKey
              because:@"§9.2 — DHs_pub is distinct from EK_A, enforced at both ends"];
}

- (void)testBuilderAssemblyRejectsShortPayload {
    NSError *error = nil;
    NSData *header = [IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                                N:kTestN
                                                               PN:kTestPN
                                                            nonce:self.nonce
                                                            error:&error];
    XCTAssertNotNil(header, @"%@", error);

    error = nil;
    XCTAssertNil([IRMessageBuilder messageWithHeaderBytes:header
                                         ciphertextAndTag:[NSMutableData dataWithLength:15]
                                                    error:&error]);
    [self assertError:error
              hasCode:IRErrorTruncatedMessage
              because:@"§8.2 — a seal output is at least the 16-byte Poly1305 tag"];
}

- (void)testBuilderAssemblyRejectsWrongHeaderLength {
    NSError *error = nil;
    XCTAssertNil([IRMessageBuilder messageWithHeaderBytes:[NSMutableData dataWithLength:57]
                                         ciphertextAndTag:[self minimumPayload]
                                                    error:&error]);
    [self assertError:error
              hasCode:IRErrorMalformedHeader
              because:@"§9 — a header is 56 or 225 bytes and nothing else"];
}

/// §10.4 — "Empty plaintext (length 0) is legal and produces a 72-byte type 0x01 message."
- (void)testEmptyPlaintextProducesTheMinimumMessage {
    NSError *error = nil;
    NSData *header = [IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                                N:0
                                                               PN:0
                                                            nonce:self.nonce
                                                            error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:[self minimumPayload]
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);
    XCTAssertEqual(message.length, (NSUInteger)kIRLenType01Min);

    IRMessageHeader *parsed = [IRMessageGate parseType01Message:message
                                           ownRatchetPublicKey:self.ownRatchet.publicKey
                                                         error:&error];
    XCTAssertNotNil(parsed, @"%@", error);
    XCTAssertEqual([IRMessageGate ciphertextAndTagOfMessage:message header:parsed error:&error].length,
                   (NSUInteger)kIRLenAEADTag);
}

#pragma mark - Type-derived constants

- (void)testHeaderLengthComesFromTheTypeAndNeverFromTheWire {
    XCTAssertEqual([IRMessageHeader headerLengthForType:IRMessageTypeNormal],
                   (NSUInteger)kIRLenType01Header);
    XCTAssertEqual([IRMessageHeader headerLengthForType:IRMessageTypePrekey],
                   (NSUInteger)kIRLenType02Header);
    XCTAssertEqual([IRMessageHeader headerLengthForType:(IRMessageType)0x03], (NSUInteger)0,
                   @"§9.3 — there is no type 0x03");

    XCTAssertEqual([IRMessageHeader associatedDataLengthForType:IRMessageTypeNormal],
                   (NSUInteger)kIRLenType01AD);
    XCTAssertEqual([IRMessageHeader associatedDataLengthForType:IRMessageTypePrekey],
                   (NSUInteger)kIRLenType02AD);

    XCTAssertEqual([IRMessageHeader minimumMessageLengthForType:IRMessageTypeNormal],
                   (NSUInteger)kIRLenType01Min);
    XCTAssertEqual([IRMessageHeader minimumMessageLengthForType:IRMessageTypePrekey],
                   (NSUInteger)kIRLenType02Min);

    XCTAssertEqual([IRMessageHeader maximumMessageLengthForType:IRMessageTypeNormal],
                   (NSUInteger)kIRLenType01Max);
    XCTAssertEqual([IRMessageHeader maximumMessageLengthForType:IRMessageTypePrekey],
                   (NSUInteger)kIRLenType02Max);
}

/// §8.5's two tables must agree: `AD == SESSION_AD + header`, for both types.
- (void)testAssociatedDataLengthsAreTheSumOfTheirParts {
    XCTAssertEqual((NSUInteger)kIRLenType01AD,
                   (NSUInteger)kIRLenSessionAD + (NSUInteger)kIRLenType01Header);
    XCTAssertEqual((NSUInteger)kIRLenType02AD,
                   (NSUInteger)kIRLenSessionAD + (NSUInteger)kIRLenType02Header);
}

#pragma mark - §10.5 — the error contract

/// "Every failure path MUST set the error out-parameter, and MUST NOT dereference a null one." v3
/// crashed on NULL at two sites, and every test in that repository passed NULL.
- (void)testEveryFailurePathToleratesANullErrorPointer {
    NSMutableData *tiny = [NSMutableData dataWithLength:10];
    XCTAssertEqual([IRMessageGate messageTypeOfMessage:tiny error:NULL], (IRMessageType)0);
    XCTAssertFalse([IRMessageGate gateType01Prefix:tiny error:NULL]);
    XCTAssertNil([IRMessageGate parseType01Message:tiny
                               ownRatchetPublicKey:self.ownRatchet.publicKey
                                             error:NULL]);
    XCTAssertNil([IRMessageGate parseType02Message:tiny error:NULL]);
    /* Objective-C nullability is ADVISORY — `_Nonnull` is a diagnostic, not a runtime barrier, and
       a nil arriving from an upstream failure the caller forgot to check is the ordinary way it
       happens (§16.2). Both methods nil-check defensively, and proving that requires deliberately
       violating the annotation, so the diagnostic is suppressed for exactly these two lines. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRMessageGate associatedDataWithSessionAD:self.sessionAD header:nil error:NULL]);
    XCTAssertNil([IRMessageGate ciphertextAndTagOfMessage:tiny header:nil error:NULL]);
#pragma clang diagnostic pop

    XCTAssertNil([IRMessageBuilder type01HeaderWithRatchetKey:self.senderRatchet.publicKey
                                                            N:0x80000000u
                                                           PN:0
                                                        nonce:self.nonce
                                                        error:NULL]);
    XCTAssertNil([IRMessageBuilder messageWithHeaderBytes:[NSMutableData dataWithLength:3]
                                         ciphertextAndTag:[self minimumPayload]
                                                    error:NULL]);
    XCTAssertFalse([IRMessageBuilder validatePlaintextLength:(NSUInteger)kIRMaxPlaintext + 1
                                                       error:NULL]);
}

/// §10.5 — codes 7100–7112 are the ones an application must collapse into a single opaque
/// "undecryptable" signal before anything reaches a peer. Every code this layer can emit on a
/// receive path falls in that band, so a host that honours the rule needs no per-code table.
- (void)testEveryReceivePathCodeIsOpaqueToPeer {
    NSArray<NSNumber *> *codes = @[@(IRErrorUnsupportedVersion), @(IRErrorUnknownMessageType),
                                   @(IRErrorReservedFlagsSet), @(IRErrorTruncatedMessage),
                                   @(IRErrorMalformedHeader), @(IRErrorInvalidPublicKey),
                                   @(IRErrorCounterOverflow), @(IRErrorPlaintextTooLarge)];
    for (NSNumber *code in codes) {
        IRErrorCode value = (IRErrorCode)code.integerValue;
        if (value == IRErrorPlaintextTooLarge) {
            /* 7119 sits outside the 7100–7112 band by design: it is a local resource decision, not
               a decryption outcome, and §10.4 has the sender check it before allocating. */
            XCTAssertFalse(IRErrorMustBeOpaqueToPeer(value));
            continue;
        }
        XCTAssertTrue(IRErrorMustBeOpaqueToPeer(value), @"%@", IRErrorNameForCode(value));
    }
}

@end
