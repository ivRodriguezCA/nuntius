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
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSessionStateCodec.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

/**
 §12.4 — FUZZING ALL FOUR HAND-WRITTEN DECODERS.

 "Every port MUST fuzz all four hand-written decoders in this document: the state-blob parser
 (§12.2), the bundle parser (§10.3), the type `0x01` parser (§10.1), and the type `0x02` parser
 (§10.2). Each takes attacker-adjacent bytes into a hand-written decoder, and the bundle parser in
 particular is reachable from a hostile or compromised prekey-distribution server before any
 signature has been verified.

 The corpus MUST include the zero-length input and every length from zero to one byte past each
 structure's fixed prefix. A FUZZ RUN IS A FAILURE IF ANY INPUT PRODUCES ANYTHING OTHER THAN A
 SPECIFIED ERROR CODE — a trap, an uncaught exception, an out-of-bounds read, or an allocation
 proportional to an unvalidated field all count as failures, not as 'rejected'."

 THE CORPUS IS DETERMINISTIC. A fuzz failure that cannot be reproduced is a rumour, so the PRNG
 below is a fixed-seed xorshift rather than the system RNG, and every case's index appears in its
 assertion message. Four generators feed each decoder:

   1. every length from 0 to one past the fixed prefix, in three fill patterns (zeros, 0xFF, PRNG);
   2. every length from 0 to one past the fixed prefix, taken as a PREFIX OF A VALID STRUCTURE —
      the corpus that actually reaches the deep field reads, since the magic and version survive;
   3. a valid structure with each single byte in turn flipped;
   4. pseudorandom blobs at pseudorandom lengths, including lengths far above every bound.

 WHAT IS ASSERTED. Not merely "did not crash": every failure must carry IRErrorDomain and a code
 inside §10.5's taxonomy, and for the state decoder the code must be one of the exactly two §12.2
 permits. `XCTAssertNoThrow` covers the Objective-C-specific half of §16.2 — `subdataWithRange:`
 RAISES rather than returning nil when its range is out of bounds, which on this platform is how an
 out-of-bounds read presents.
 */

#pragma mark - Deterministic PRNG

/// xorshift64*. Fixed seed, so a failing case index reproduces exactly.
typedef struct { uint64_t state; } IRFuzzRandom;

static void IRFuzzSeed(IRFuzzRandom *rng, uint64_t seed) {
    rng->state = (seed != 0 ? seed : 0x9E3779B97F4A7C15ull);
}

static uint64_t IRFuzzNext(IRFuzzRandom *rng) {
    uint64_t x = rng->state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng->state = x;

    return x * 0x2545F4914F6CDD1Dull;
}

static void IRFuzzFill(IRFuzzRandom *rng, uint8_t *buffer, NSUInteger length) {
    for (NSUInteger i = 0; i < length; i++) {
        buffer[i] = (uint8_t)(IRFuzzNext(rng) & 0xFF);
    }
}

static NSData *IRFuzzBytes(IRFuzzRandom *rng, NSUInteger length) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    IRFuzzFill(rng, (uint8_t *)data.mutableBytes, length);

    return data;
}

static NSData *IRFilledBytes(NSUInteger length, uint8_t value) {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    memset(data.mutableBytes, value, length);

    return data;
}

@interface IRDecoderFuzzSpec : XCTestCase
@end

@implementation IRDecoderFuzzSpec {
    IRSodiumCryptoProvider *_provider;
    IRIdentity *_identity;
    IRX25519Public *_ownRatchetPublic;
    IRFuzzRandom _rng;
}

- (void)setUp {
    [super setUp];

    NSError *error = nil;
    XCTAssertTrue([IRSodium ensureInitialized:&error], @"%@", error);

    _provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(_provider, @"%@", error);

    _identity = [IRIdentity generateWithProvider:_provider error:&error];
    XCTAssertNotNil(_identity, @"%@", error);

    IRX25519KeyPair *pair = [_provider generateX25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(pair, @"%@", error);
    _ownRatchetPublic = pair.publicKey;

    IRFuzzSeed(&_rng, 0xC0FFEE12345678ull);
}

#pragma mark - Corpus construction

/// Generators 1, 2 and 4 of the four described in the class comment, for one structure.
- (NSArray<NSData *> *)corpusForFixedPrefix:(NSUInteger)fixedPrefix
                                validSample:(NSData * _Nullable)validSample {
    NSMutableArray<NSData *> *corpus = [NSMutableArray array];

    // 1 — every length from zero to one past the fixed prefix, three fill patterns.
    for (NSUInteger length = 0; length <= fixedPrefix + 1; length++) {
        [corpus addObject:IRFilledBytes(length, 0x00)];
        [corpus addObject:IRFilledBytes(length, 0xFF)];
        [corpus addObject:IRFuzzBytes(&_rng, length)];
    }

    // 2 — the same lengths taken as PREFIXES OF A VALID STRUCTURE, so magic and version survive and
    //     the deep field reads are actually reached.
    if (validSample != nil) {
        for (NSUInteger length = 0; length <= MIN(fixedPrefix + 1, validSample.length); length++) {
            [corpus addObject:[validSample subdataWithRange:NSMakeRange(0, length)]];
        }
    }

    // 4 — pseudorandom blobs at pseudorandom lengths, including well past every bound.
    for (NSUInteger i = 0; i < 200; i++) {
        NSUInteger length = (NSUInteger)(IRFuzzNext(&_rng) % (fixedPrefix * 3 + 64));
        [corpus addObject:IRFuzzBytes(&_rng, length)];
    }

    return corpus;
}

/// Generator 3 — a valid structure with each single byte in turn flipped.
- (NSArray<NSData *> *)singleByteMutationsOf:(NSData *)sample {
    NSMutableArray<NSData *> *corpus = [NSMutableArray array];

    for (NSUInteger i = 0; i < sample.length; i++) {
        NSMutableData *mutated = [sample mutableCopy];
        ((uint8_t *)mutated.mutableBytes)[i] ^= 0xFF;
        [corpus addObject:mutated];
    }

    return corpus;
}

/// Every failure must be one of §10.5's codes in §10.5's domain. A code outside the taxonomy means
/// an error escaped from a layer that had no business defining one.
- (void)assertSpecifiedError:(NSError *)error
                     allowed:(NSArray<NSNumber *> *)allowed
                       label:(NSString *)label {
    XCTAssertNotNil(error, @"%@: a nil result MUST carry an error", label);
    XCTAssertEqualObjects(error.domain, IRErrorDomain, @"%@", label);
    XCTAssertNotEqualObjects(IRErrorNameForCode((IRErrorCode)error.code), @"ERR_UNSPECIFIED",
                             @"%@: code %ld is outside the §10.5 taxonomy", label, (long)error.code);

    if (allowed != nil) {
        XCTAssertTrue([allowed containsObject:@(error.code)],
                      @"%@: %@ is not one of the codes this decoder may return",
                      label, IRErrorNameForCode((IRErrorCode)error.code));
    }
}

#pragma mark - Valid samples

- (NSData *)validStateBlob {
    /* Built from literal bytes, for the same reason IRStateCodecSpec builds them that way. */
    NSMutableData *blob = [NSMutableData dataWithLength:(NSUInteger)kIRLenStatePrefix];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    memcpy(raw + kIROffStateMagic, kIRStateMagic, (size_t)kIRLenMagic);
    raw[kIROffStateFormat] = (uint8_t)kIRStateFormat;
    raw[kIROffStateRole] = (uint8_t)IRSessionRoleInitiator;
    memcpy(raw + kIROffStateSessionAD, kIRLabelAD, (size_t)kIRLenLabelAD);

    for (NSUInteger i = 0; i < kIRLenStatePrefix; i++) {
        if (i >= kIROffStateInitiatorSigning) {
            raw[i] = (uint8_t)((i * 7u) + 3u);
        }
    }

    raw[kIROffStateInitiatorAgreement + 31] &= 0x7F;
    raw[kIROffStateResponderAgreement + 31] &= 0x7F;
    raw[kIROffStateDHsPub + 31] &= 0x7F;
    raw[kIROffStateDHsPriv] &= 0xF8;
    raw[kIROffStateDHsPriv + 31] &= 0x7F;
    raw[kIROffStateDHsPriv + 31] |= 0x40;

    raw[kIROffStateDHrPresent] = 0x00;
    memset(raw + kIROffStateDHrPub, 0, (size_t)kIRLenX25519Public);
    raw[kIROffStateCKsPresent] = 0x01;
    raw[kIROffStateCKrPresent] = 0x00;
    memset(raw + kIROffStateCKr, 0, (size_t)kIRLenChainKey);
    raw[kIROffStateProloguePresent] = 0x00;
    memset(raw + kIROffStatePrologue, 0, (size_t)kIRLenStatePrologue);
    memset(raw + kIROffStateSkippedCount, 0, 4);

    NSError *error = nil;
    XCTAssertNotNil([IRSessionStateCodec deserializeStateFromData:blob atTimeMs:1000 error:&error],
                    @"the fuzz sample must itself be valid: %@", error);

    return blob;
}

- (NSData *)validBundle {
    NSError *error = nil;

    IRSignedPreKeyRecord *spk = [IRSignedPreKeyRecord generateWithIdentity:_identity
                                                                    spkId:1
                                                               notBeforeS:1000
                                                                notAfterS:(1000 + 86400)
                                                                 provider:_provider
                                                                    error:&error];
    XCTAssertNotNil(spk, @"%@", error);

    IROneTimePreKeyRecord *opk = [IROneTimePreKeyRecord generateWithOpkId:1
                                                        createdAtUnixSecs:1000
                                                                 provider:_provider
                                                                    error:&error];
    XCTAssertNotNil(opk, @"%@", error);

    NSData *bundle = [IRPreKeyBundle serializeWithIdentity:_identity.publicIdentity
                                       signedPreKeyRecord:spk
                                     oneTimePreKeyRecords:@[opk]
                                                    error:&error];
    XCTAssertNotNil(bundle, @"%@", error);

    return bundle;
}

- (NSData *)validType01Message {
    NSError *error = nil;

    IRX25519KeyPair *senderRatchet = [_provider generateX25519KeyPairGuarded:NO error:&error];
    IRNonce *nonce = [_provider randomNonceWithError:&error];

    NSData *header = [IRMessageBuilder type01HeaderWithRatchetKey:senderRatchet.publicKey
                                                                N:3
                                                               PN:1
                                                            nonce:nonce
                                                            error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:IRFilledBytes((NSUInteger)kIRLenAEADTag, 0xAB)
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    return message;
}

- (NSData *)validType02Message {
    NSError *error = nil;

    IRX25519KeyPair *ephemeral = [_provider generateX25519KeyPairGuarded:NO error:&error];
    IRX25519KeyPair *senderRatchet = [_provider generateX25519KeyPairGuarded:NO error:&error];
    IRNonce *nonce = [_provider randomNonceWithError:&error];

    IRSessionPrologue *prologue = [IRSessionPrologue prologueWithEphemeralPublic:ephemeral.publicKey
                                                                           spkId:1
                                                                         opkFlag:IROPKFlagPresent
                                                                           opkId:1
                                                                           error:&error];
    XCTAssertNotNil(prologue, @"%@", error);

    NSData *header = [IRMessageBuilder type02HeaderWithInitiatorIdentity:_identity.identityKeyPair
                                                         identityBinding:_identity.binding
                                                                prologue:prologue
                                                              ratchetKey:senderRatchet.publicKey
                                                                       N:0
                                                                   nonce:nonce
                                                                   error:&error];
    XCTAssertNotNil(header, @"%@", error);

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:IRFilledBytes((NSUInteger)kIRLenAEADTag, 0xCD)
                                                         error:&error];
    XCTAssertNotNil(message, @"%@", error);

    return message;
}

#pragma mark - Decoder 1 — the state blob (§12.2)

- (void)testFuzzStateBlobDecoder {
    /* §12.2 permits EXACTLY TWO codes, and the split is not cosmetic: §19.4 made 7105
       state-blob-only so that ERR_TRAILING_BYTES means one thing across four ports. */
    NSArray<NSNumber *> *allowed = @[@(IRErrorStateCorrupt), @(IRErrorTrailingBytes)];

    NSData *sample = [self validStateBlob];
    NSMutableArray<NSData *> *corpus =
        [[self corpusForFixedPrefix:(NSUInteger)kIRLenStatePrefix validSample:sample] mutableCopy];
    [corpus addObjectsFromArray:[self singleByteMutationsOf:sample]];

    NSUInteger index = 0;
    NSUInteger accepted = 0;
    for (NSData *input in corpus) {
        NSString *label = [NSString stringWithFormat:@"state case %lu (len %lu)",
                           (unsigned long)index, (unsigned long)input.length];

        __block IRRatchetState *state = nil;
        __block NSError *error = nil;
        XCTAssertNoThrow(state = [IRSessionStateCodec deserializeStateFromData:input
                                                                      atTimeMs:1700000000000ull
                                                                         error:&error],
                         @"%@", label);

        if (state == nil) {
            [self assertSpecifiedError:error allowed:allowed label:label];
        } else {
            accepted += 1;
        }

        index += 1;
    }

    /* The single-byte mutations of a valid blob land in RK, CKs and the counters, which carry no
       structural constraint — so a corpus in which NOTHING parses would mean the sample was not
       valid and the run proved nothing. */
    XCTAssertGreaterThan(accepted, (NSUInteger)0, @"the corpus must reach the accepting path too");
}

- (void)testFuzzStateBlobNeverAllocatesFromAnUnvalidatedCount {
    /* §12.4: "an allocation proportional to an unvalidated field... counts as a failure." The state
       decoder is the one structure where that is reachable — `skipped_count` sits at offset 468 and
       would size 76 bytes of allocation each. Rule 5 bounds it at 2000 and rule 6 cross-checks it
       against the real length BEFORE anything is allocated from it. */
    NSMutableData *blob = [[self validStateBlob] mutableCopy];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    const uint32_t hostileCounts[] = {2001, 0x0000FFFF, 0x00FFFFFF, 0x7FFFFFFF, 0xFFFFFFFF};

    for (NSUInteger i = 0; i < (sizeof(hostileCounts) / sizeof(hostileCounts[0])); i++) {
        uint32_t count = hostileCounts[i];
        raw[kIROffStateSkippedCount + 0] = (uint8_t)((count >> 24) & 0xFF);
        raw[kIROffStateSkippedCount + 1] = (uint8_t)((count >> 16) & 0xFF);
        raw[kIROffStateSkippedCount + 2] = (uint8_t)((count >>  8) & 0xFF);
        raw[kIROffStateSkippedCount + 3] = (uint8_t)(count & 0xFF);

        NSDate *start = [NSDate date];
        NSError *error = nil;
        XCTAssertNil([IRSessionStateCodec deserializeStateFromData:blob atTimeMs:1000 error:&error]);
        XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt, @"count %u", count);
        XCTAssertLessThan([[NSDate date] timeIntervalSinceDate:start], 0.5,
                          @"count %u must be rejected without work proportional to it", count);
    }
}

#pragma mark - Decoder 2 — the prekey bundle (§10.3)

- (void)testFuzzBundleDecoder {
    /* §12.4 singles this one out: "reachable from a hostile or compromised prekey-distribution
       server BEFORE any signature has been verified", because §5.3 orders parsing first. */
    NSArray<NSNumber *> *allowed = @[
        @(IRErrorBundleMalformed),
        @(IRErrorUnsupportedVersion),
        @(IRErrorInvalidPublicKey),
        @(IRErrorBadSignature),
        @(IRErrorNotInitialized),
    ];

    NSData *sample = [self validBundle];
    NSMutableArray<NSData *> *corpus =
        [[self corpusForFixedPrefix:(NSUInteger)kIRLenBundlePrefix validSample:sample] mutableCopy];
    [corpus addObjectsFromArray:[self singleByteMutationsOf:sample]];

    NSUInteger index = 0;
    for (NSData *input in corpus) {
        NSString *label = [NSString stringWithFormat:@"bundle case %lu (len %lu)",
                           (unsigned long)index, (unsigned long)input.length];

        __block IRPreKeyBundle *bundle = nil;
        __block NSError *error = nil;
        XCTAssertNoThrow(bundle = [IRPreKeyBundle bundleFromData:input
                                                        provider:_provider
                                                           error:&error],
                         @"%@", label);

        if (bundle == nil) {
            [self assertSpecifiedError:error allowed:allowed label:label];
        }

        index += 1;
    }
}

- (void)testFuzzBundleNeverAllocatesFromAnUnvalidatedOPKCount {
    /* `opk_count` sits at offset 249, two bytes below the 251-byte fixed prefix — which is exactly
       why §10.3 step 1's length floor must precede the read, and why NEG-BUNDLE-SHORT pins 250. */
    NSMutableData *bundle = [[self validBundle] mutableCopy];
    uint8_t *raw = (uint8_t *)bundle.mutableBytes;

    raw[kIROffBundleOPKCount + 0] = 0xFF;
    raw[kIROffBundleOPKCount + 1] = 0xFF;

    NSDate *start = [NSDate date];
    NSError *error = nil;
    XCTAssertNil([IRPreKeyBundle bundleFromData:bundle provider:_provider error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorBundleMalformed);
    XCTAssertLessThan([[NSDate date] timeIntervalSinceDate:start], 0.5);
}

#pragma mark - Decoder 3 — the type 0x01 message (§10.1)

- (void)testFuzzType01Decoder {
    NSArray<NSNumber *> *allowed = @[
        @(IRErrorUnsupportedVersion),
        @(IRErrorUnknownMessageType),
        @(IRErrorReservedFlagsSet),
        @(IRErrorTruncatedMessage),
        @(IRErrorPlaintextTooLarge),
        @(IRErrorMalformedHeader),
        @(IRErrorInvalidPublicKey),
        @(IRErrorSmallOrderKey),
        @(IRErrorCounterOverflow),
        @(IRErrorNoSession),
    ];

    NSData *sample = [self validType01Message];
    NSMutableArray<NSData *> *corpus =
        [[self corpusForFixedPrefix:(NSUInteger)kIRLenType01Header validSample:sample] mutableCopy];
    [corpus addObjectsFromArray:[self singleByteMutationsOf:sample]];

    NSUInteger index = 0;
    for (NSData *input in corpus) {
        NSString *label = [NSString stringWithFormat:@"type01 case %lu (len %lu)",
                           (unsigned long)index, (unsigned long)input.length];

        /* Both halves of D1's required sequence: the prefix gate, then the full parse. The gate is
           what a host runs before it has resolved a session, so it is the one an attacker reaches
           first with no state at all. */
        __block NSError *gateError = nil;
        __block BOOL gated = NO;
        XCTAssertNoThrow(gated = [IRMessageGate gateType01Prefix:input error:&gateError], @"%@", label);
        if (!gated) {
            [self assertSpecifiedError:gateError allowed:allowed label:label];
        }

        __block IRMessageHeader *header = nil;
        __block NSError *parseError = nil;
        XCTAssertNoThrow(header = [IRMessageGate parseType01Message:input
                                               ownRatchetPublicKey:_ownRatchetPublic
                                                             error:&parseError],
                         @"%@", label);
        if (header == nil) {
            [self assertSpecifiedError:parseError allowed:allowed label:label];
        }

        index += 1;
    }
}

#pragma mark - Decoder 4 — the type 0x02 message (§10.2)

- (void)testFuzzType02Decoder {
    /* THE ONE GATE THAT READS FIELDS OUT OF LAYOUT ORDER — check 6 inspects msg[168] and check 8
       msg[209], both before check 9 reads msg[205]. It is safe only because check 1's length floor
       fires first, which is precisely what a fuzz corpus of short inputs exercises. */
    NSArray<NSNumber *> *allowed = @[
        @(IRErrorUnsupportedVersion),
        @(IRErrorUnknownMessageType),
        @(IRErrorReservedFlagsSet),
        @(IRErrorTruncatedMessage),
        @(IRErrorPlaintextTooLarge),
        @(IRErrorMalformedHeader),
        @(IRErrorInvalidPublicKey),
        @(IRErrorSmallOrderKey),
        @(IRErrorCounterOverflow),
        @(IRErrorBadSignature),
    ];

    NSData *sample = [self validType02Message];
    NSMutableArray<NSData *> *corpus =
        [[self corpusForFixedPrefix:(NSUInteger)kIRLenType02Header validSample:sample] mutableCopy];
    [corpus addObjectsFromArray:[self singleByteMutationsOf:sample]];

    NSUInteger index = 0;
    NSUInteger accepted = 0;
    for (NSData *input in corpus) {
        NSString *label = [NSString stringWithFormat:@"type02 case %lu (len %lu)",
                           (unsigned long)index, (unsigned long)input.length];

        __block IRMessageHeader *header = nil;
        __block NSError *error = nil;
        XCTAssertNoThrow(header = [IRMessageGate parseType02Message:input error:&error], @"%@", label);

        if (header == nil) {
            [self assertSpecifiedError:error allowed:allowed label:label];
        } else {
            accepted += 1;
        }

        index += 1;
    }

    /* A mutation inside IKB_A still PARSES — the gate carries the binding unverified, by design,
       because the only route to a verified identity is IRPublicIdentity's constructor. If nothing
       in this corpus parsed, that structural claim would be untested here. */
    XCTAssertGreaterThan(accepted, (NSUInteger)0);
}

#pragma mark - The zero-length input, named explicitly by §12.4

- (void)testZeroLengthInputAgainstAllFourDecoders {
    NSData *empty = [NSData data];
    NSError *error = nil;

    XCTAssertNil([IRSessionStateCodec deserializeStateFromData:empty atTimeMs:1000 error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);

    error = nil;
    XCTAssertNil([IRPreKeyBundle bundleFromData:empty provider:_provider error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorBundleMalformed);

    error = nil;
    XCTAssertFalse([IRMessageGate gateType01Prefix:empty error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorTruncatedMessage);

    error = nil;
    XCTAssertNil([IRMessageGate parseType02Message:empty error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorTruncatedMessage);

    error = nil;
    XCTAssertEqual([IRMessageGate messageTypeOfMessage:empty error:&error], (IRMessageType)0);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorTruncatedMessage);
}

@end
