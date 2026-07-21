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

#import "IRProtocolConstants.h"
#import "IRErrors.h"
#import "IRSodium.h"
#import "IRSecretBytes.h"
#import "IRByteReader.h"
#import "IRByteWriter.h"

/**
 Layer 0 gate — SPEC §18, §10.5, §13.1, §13.2, §13.3, §3.1, §16.2.

 IRByteReader.h and IRByteWriter.h are PROJECT-visibility headers with no PBXHeadersBuildPhase
 entry. That they are importable here at all is the empirical confirmation of the plan's decision
 D8: Xcode's generated project header map reaches them with no HEADER_SEARCH_PATHS work, so internal
 types can stay off the public API surface (§15.5 rules 5–6) and remain fully testable.
 */
@interface IRFoundationSpec : XCTestCase
@end

@implementation IRFoundationSpec

- (void)setUp {
    [super setUp];
    XCTAssertTrue([IRSodium ensureInitialized:NULL], @"libsodium must initialize");
}

#pragma mark - Helpers

- (NSString *)hexOfBytes:(const uint8_t *)bytes length:(NSUInteger)length {
    NSMutableString *hex = [NSMutableString stringWithCapacity:(length * 2)];
    for (NSUInteger index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", bytes[index]];
    }
    return hex;
}

- (void)assertLabel:(const uint8_t *)bytes
             length:(NSUInteger)length
              ascii:(NSString *)ascii
                hex:(NSString *)hex
               name:(NSString *)name {
    /* Three independent statements of the same constant have to agree: the sized array in
       IRProtocolConstants.m, §18's hex column, and the ASCII spelling. */
    XCTAssertEqual(length, ascii.length, @"%@: declared length disagrees with its ASCII spelling", name);

    NSData *asciiBytes = [ascii dataUsingEncoding:NSASCIIStringEncoding];
    XCTAssertEqual(asciiBytes.length, length, @"%@: ASCII encoding length", name);
    XCTAssertEqual(memcmp(bytes, asciiBytes.bytes, length), 0, @"%@: bytes differ from ASCII", name);

    XCTAssertEqualObjects([self hexOfBytes:bytes length:length], hex, @"%@: hex differs from SPEC 18", name);
}

#pragma mark - SPEC 18 literals

- (void)testLabelsMatchSpecSection18 {
    [self assertLabel:kIRLabelIKBind length:sizeof(kIRLabelIKBind)
                ascii:@"nuntius:IKBIND:v4"
                  hex:@"6e756e746975733a494b42494e443a7634" name:@"IKBIND"];

    [self assertLabel:kIRLabelSPK length:sizeof(kIRLabelSPK)
                ascii:@"nuntius:SPK:v4"
                  hex:@"6e756e746975733a53504b3a7634" name:@"SPK"];

    [self assertLabel:kIRLabelTranscript length:sizeof(kIRLabelTranscript)
                ascii:@"nuntius:X3DH:transcript:v4"
                  hex:@"6e756e746975733a583344483a7472616e7363726970743a7634" name:@"TRANSCRIPT"];

    [self assertLabel:kIRLabelX3DH length:sizeof(kIRLabelX3DH)
                ascii:@"nuntius:X3DH:v4"
                  hex:@"6e756e746975733a583344483a7634" name:@"X3DH"];

    [self assertLabel:kIRLabelRK length:sizeof(kIRLabelRK)
                ascii:@"nuntius:RK:v4" hex:@"6e756e746975733a524b3a7634" name:@"RK"];

    [self assertLabel:kIRLabelMK length:sizeof(kIRLabelMK)
                ascii:@"nuntius:MK:v4" hex:@"6e756e746975733a4d4b3a7634" name:@"MK"];

    [self assertLabel:kIRLabelAD length:sizeof(kIRLabelAD)
                ascii:@"nuntius:AD:v4" hex:@"6e756e746975733a41443a7634" name:@"AD"];

    [self assertLabel:kIRLabelFP length:sizeof(kIRLabelFP)
                ascii:@"nuntius:FP:v4" hex:@"6e756e746975733a46503a7634" name:@"FP"];

    [self assertLabel:kIRBundleMagic length:sizeof(kIRBundleMagic)
                ascii:@"NTB4" hex:@"4e544234" name:@"NTB4"];

    [self assertLabel:kIRStateMagic length:sizeof(kIRStateMagic)
                ascii:@"NTS4" hex:@"4e545334" name:@"NTS4"];
}

- (void)testLabelArraysCarryNoNULTerminator {
    /* §3.1 — the literals are raw bytes with no NUL and no length prefix. A sized array makes
       strlen on an embedded literal inexpressible; this asserts the sizes did not drift. */
    XCTAssertEqual(sizeof(kIRLabelIKBind), (size_t)kIRLenLabelIKBind);
    XCTAssertEqual(sizeof(kIRLabelSPK), (size_t)kIRLenLabelSPK);
    XCTAssertEqual(sizeof(kIRLabelTranscript), (size_t)kIRLenLabelTranscript);
    XCTAssertEqual(sizeof(kIRLabelX3DH), (size_t)kIRLenLabelX3DH);
    XCTAssertEqual(sizeof(kIRLabelRK), (size_t)kIRLenLabelRK);
    XCTAssertEqual(sizeof(kIRLabelMK), (size_t)kIRLenLabelMK);
    XCTAssertEqual(sizeof(kIRLabelAD), (size_t)kIRLenLabelAD);
    XCTAssertEqual(sizeof(kIRLabelFP), (size_t)kIRLenLabelFP);

    XCTAssertNotEqual(kIRLabelIKBind[kIRLenLabelIKBind - 1], 0x00);
    XCTAssertNotEqual(kIRLabelFP[kIRLenLabelFP - 1], 0x00);
}

- (void)testF32AndZ32 {
    for (NSUInteger index = 0; index < kIRLenF32; index++) {
        XCTAssertEqual(kIRF32[index], 0xFF);
        XCTAssertEqual(kIRZ32[index], 0x00);
    }
}

- (void)testDerivedLengthsMatchSpecSection18 {
    XCTAssertEqual((NSUInteger)kIRLenIKBindMsg, (NSUInteger)81);
    XCTAssertEqual((NSUInteger)kIRLenSPKSignMsg, (NSUInteger)130);
    XCTAssertEqual((NSUInteger)kIRLenTranscript, (NSUInteger)259);
    XCTAssertEqual((NSUInteger)kIRLenTH, (NSUInteger)32);
    XCTAssertEqual((NSUInteger)kIRLenX3DHInfo, (NSUInteger)47);
    XCTAssertEqual((NSUInteger)kIRLenIKMNoOPK, (NSUInteger)128);
    XCTAssertEqual((NSUInteger)kIRLenIKMOPK, (NSUInteger)160);
    XCTAssertEqual((NSUInteger)kIRLenSK, (NSUInteger)32);
    XCTAssertEqual((NSUInteger)kIRLenSessionAD, (NSUInteger)141);
    XCTAssertEqual((NSUInteger)kIRLenFPInput, (NSUInteger)77);
    XCTAssertEqual((NSUInteger)kIRLenKDFRKOutput, (NSUInteger)64);
    XCTAssertEqual((NSUInteger)kIRLenType01Header, (NSUInteger)56);
    XCTAssertEqual((NSUInteger)kIRLenType01AD, (NSUInteger)197);
    XCTAssertEqual((NSUInteger)kIRLenType01Min, (NSUInteger)72);
    XCTAssertEqual((NSUInteger)kIRLenType01Max, (NSUInteger)16777288);
    XCTAssertEqual((NSUInteger)kIRLenType02Header, (NSUInteger)225);
    XCTAssertEqual((NSUInteger)kIRLenType02AD, (NSUInteger)366);
    XCTAssertEqual((NSUInteger)kIRLenType02Min, (NSUInteger)241);
    XCTAssertEqual((NSUInteger)kIRLenType02Max, (NSUInteger)16777457);
    XCTAssertEqual((NSUInteger)kIRLenBundlePrefix, (NSUInteger)251);
    XCTAssertEqual((NSUInteger)kIRLenBundleOPKEntry, (NSUInteger)36);
    XCTAssertEqual((NSUInteger)kIRLenStatePrefix, (NSUInteger)472);
    XCTAssertEqual((NSUInteger)kIRLenStateSkippedEntry, (NSUInteger)76);
    XCTAssertEqual((NSUInteger)kIRLenStatePrologue, (NSUInteger)41);
    XCTAssertEqual((NSUInteger)kIRLenSkippedMapKey, (NSUInteger)36);
    XCTAssertEqual((NSUInteger)kIRLenHandshakeId, (NSUInteger)64);
}

- (void)testBoundsMatchSpecSection18 {
    XCTAssertEqual((NSUInteger)kIRMaxPlaintext, (NSUInteger)16777216);
    XCTAssertEqual((NSUInteger)kIRMaxSkipPerMessage, (NSUInteger)1000);
    XCTAssertEqual((NSUInteger)kIRMaxSkippedStored, (NSUInteger)2000);
    XCTAssertEqual((NSUInteger)kIRSkippedTTLMs, (NSUInteger)604800000);
    XCTAssertEqual((NSUInteger)kIRHandshakeCacheMs, (NSUInteger)604800000);
    XCTAssertEqual((NSUInteger)kIRMaxCounter, (NSUInteger)0x7FFFFFFF);
    XCTAssertEqual((NSUInteger)kIRMaxSPKValiditySeconds, (NSUInteger)7776000);
    XCTAssertEqual((NSUInteger)kIROPKMaxAgeSeconds, (NSUInteger)7776000);
    XCTAssertEqual((NSUInteger)kIRMaxBundleOPKCount, (NSUInteger)1000);
    XCTAssertEqual((NSUInteger)kIRMinBundleLength, (NSUInteger)251);
}

- (void)testWireOffsetsMatchSpecSections9And12 {
    /* Spot-checks of the offsets other layers read literally out of §10.1, §10.2, §10.7 and §11.2. */
    XCTAssertEqual((NSUInteger)kIROffType01DHs, (NSUInteger)4);
    XCTAssertEqual((NSUInteger)kIROffType01N, (NSUInteger)36);
    XCTAssertEqual((NSUInteger)kIROffType01PN, (NSUInteger)40);
    XCTAssertEqual((NSUInteger)kIROffType02IdentityAgreement, (NSUInteger)36);
    XCTAssertEqual((NSUInteger)kIROffType02IKB, (NSUInteger)68);
    XCTAssertEqual((NSUInteger)kIROffType02EK, (NSUInteger)132);
    XCTAssertEqual((NSUInteger)kIROffType02OPKFlag, (NSUInteger)168);
    XCTAssertEqual((NSUInteger)kIROffType02DHs, (NSUInteger)173);
    XCTAssertEqual((NSUInteger)kIROffBundleOPKCount, (NSUInteger)249);
    XCTAssertEqual((NSUInteger)kIROffStateDHsPriv, (NSUInteger)243);
    XCTAssertEqual((NSUInteger)kIROffStateSkippedCount, (NSUInteger)468);
    XCTAssertEqual((NSUInteger)kIROffStateInitiatorSigning, (NSUInteger)19);
    XCTAssertEqual((NSUInteger)kIROffStateResponderAgreement, (NSUInteger)115);
}

#pragma mark - SPEC 10.5 errors

- (void)testSetErrorToleratesANullOutParameter {
    /* The v3 defect, exactly: -aeEncryptSimpleData: and -aeDecryptSimpleData: wrote `*error = err`
       with no null check, crashing every caller that passed NULL. Reaching the assertion below is
       the whole test. */
    IRSetError(NULL, IRErrorAEADAuthFailed);
    IRSetErrorWithUnderlying(NULL, IRErrorReplay, IRErrorWithCode(IRErrorStateCorrupt));
    XCTAssertTrue(YES);
}

- (void)testSetErrorPopulatesDomainAndCode {
    NSError *error = nil;
    IRSetError(&error, IRErrorSmallOrderKey);

    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.domain, @"com.ivrodriguez.nuntius");
    XCTAssertEqualObjects(error.domain, IRErrorDomain);
    XCTAssertEqual(error.code, 7107);
}

- (void)testUnderlyingErrorIsThreaded {
    NSError *underlying = IRErrorWithCode(IRErrorRNGFailure);
    NSError *error = nil;
    IRSetErrorWithUnderlying(&error, IRErrorStateCorrupt, underlying);

    XCTAssertEqual(error.code, 7117);
    XCTAssertEqual([error.userInfo[NSUnderlyingErrorKey] code], 7113);
}

- (void)testErrorNamesRoundTrip {
    /* §15.5 — the vector runner compares error NAMES, so name and code must be a bijection. */
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    for (NSInteger raw = 7100; raw <= 7124; raw++) {
        IRErrorCode code = (IRErrorCode)raw;
        NSString *name = IRErrorNameForCode(code);

        XCTAssertNotEqualObjects(name, @"ERR_UNSPECIFIED", @"code %ld has no name", (long)raw);
        XCTAssertFalse([seen containsObject:name], @"duplicate name %@", name);
        [seen addObject:name];

        IRErrorCode decoded = IRErrorUnsupportedVersion;
        XCTAssertTrue(IRErrorCodeFromName(name, &decoded), @"%@ does not decode", name);
        XCTAssertEqual(decoded, code);
    }

    XCTAssertEqual(seen.count, (NSUInteger)25);
}

- (void)testErrorNamesMatchSpecSection10_5 {
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorUnsupportedVersion), @"ERR_UNSUPPORTED_VERSION");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorTruncatedMessage), @"ERR_TRUNCATED_MESSAGE");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorSmallOrderKey), @"ERR_SMALL_ORDER_KEY");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorAEADAuthFailed), @"ERR_AEAD_AUTH_FAILED");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorUnknownPreKeyId), @"ERR_UNKNOWN_PREKEY_ID");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorNoSendingChain), @"ERR_NO_SENDING_CHAIN");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorStateRollback), @"ERR_STATE_ROLLBACK");
}

- (void)testUnknownErrorNameIsRejected {
    IRErrorCode code = IRErrorStateCorrupt;
    XCTAssertFalse(IRErrorCodeFromName(@"ERR_NOT_A_REAL_CODE", &code));
    XCTAssertEqual(code, IRErrorStateCorrupt, @"a failed decode must not disturb the out-parameter");
}

- (void)testPeerOpaqueRangeIs7100Through7112 {
    for (NSInteger raw = 7100; raw <= 7112; raw++) {
        XCTAssertTrue(IRErrorMustBeOpaqueToPeer((IRErrorCode)raw), @"%ld must be opaque", (long)raw);
    }
    for (NSInteger raw = 7113; raw <= 7124; raw++) {
        XCTAssertFalse(IRErrorMustBeOpaqueToPeer((IRErrorCode)raw), @"%ld is outside the range", (long)raw);
    }
}

- (void)testRetiredV3CodesAreNotInTheTaxonomy {
    /* §10.5 — 7001–7003 are retired and MUST NOT be reused. */
    for (NSInteger raw = 7001; raw <= 7003; raw++) {
        XCTAssertEqualObjects(IRErrorNameForCode((IRErrorCode)raw), @"ERR_UNSPECIFIED");
    }
}

#pragma mark - SPEC 13.3 secrets

- (void)testSecretBytesZeroizeNowWipesInPlace {
    uint8_t material[32];
    memset(material, 0xAB, sizeof(material));

    IRSecretBytes *secret = [[IRSecretBytes alloc] initWithBytes:material length:sizeof(material)];
    XCTAssertNotNil(secret);
    XCTAssertEqual(secret.length, (NSUInteger)32);
    XCTAssertFalse([secret isAllZero]);

    const uint8_t *borrowed = [secret constBytes];
    [secret zeroizeNow];

    XCTAssertTrue([secret isAllZero]);
    /* The allocation survives a wipe, so a pointer handed out earlier does not dangle. */
    XCTAssertEqual(borrowed[0], 0x00);
    XCTAssertEqual(borrowed[31], 0x00);

    [secret zeroizeNow];
    XCTAssertTrue([secret isAllZero], @"zeroizeNow must be idempotent");
}

- (void)testSecretBytesRejectsZeroLength {
    XCTAssertNil([[IRSecretBytes alloc] initWithLength:0]);
    XCTAssertNil([[IRSecretBytes alloc] initGuardedWithLength:0]);
}

- (void)testSecretBytesConstantTimeEquality {
    uint8_t a[32]; memset(a, 0x11, sizeof(a));
    uint8_t b[32]; memset(b, 0x11, sizeof(b));
    uint8_t c[32]; memset(c, 0x11, sizeof(c)); c[31] = 0x12;

    IRSecretBytes *first = [[IRSecretBytes alloc] initWithBytes:a length:sizeof(a)];
    IRSecretBytes *second = [[IRSecretBytes alloc] initWithBytes:b length:sizeof(b)];
    IRSecretBytes *third = [[IRSecretBytes alloc] initWithBytes:c length:sizeof(c)];
    IRSecretBytes *shorter = [[IRSecretBytes alloc] initWithBytes:a length:16];

    XCTAssertTrue([first isEqualToSecretBytes:second]);
    XCTAssertTrue([first isEqualToSecretBytes:first]);
    XCTAssertFalse([first isEqualToSecretBytes:third]);
    XCTAssertFalse([first isEqualToSecretBytes:shorter]);
    XCTAssertFalse([first isEqualToSecretBytes:nil]);
}

- (void)testGuardedAllocationIsUsable {
    uint8_t material[32];
    memset(material, 0x5A, sizeof(material));

    IRSecretBytes *secret = [[IRSecretBytes alloc] initGuardedWithBytes:material length:sizeof(material)];
    XCTAssertNotNil(secret, @"sodium_malloc must succeed after sodium_init");
    XCTAssertTrue(secret.isGuarded);
    XCTAssertEqual([secret constBytes][0], 0x5A);
}

- (void)testDescriptionDoesNotLeakBytes {
    uint8_t material[32];
    memset(material, 0xC3, sizeof(material));

    IRSecretBytes *secret = [[IRSecretBytes alloc] initWithBytes:material length:sizeof(material)];
    NSString *text = [secret description];

    /* -description embeds the object's ADDRESS via %p, and an address is a hex string that can
       contain "c3" by chance — roughly a 4% chance per run for a 12-digit address, which made this
       test flaky rather than wrong. Masking every 0x-prefixed hex run keeps the assertion pointed
       at what it is actually about: no byte of the SECRET may appear in a description that can
       reach a log, a crash report or the Xcode console. */
    NSRegularExpression *addresses = [NSRegularExpression regularExpressionWithPattern:@"0x[0-9a-fA-F]+"
                                                                               options:0
                                                                                 error:NULL];
    NSString *withoutAddresses = [addresses stringByReplacingMatchesInString:text
                                                                     options:0
                                                                       range:NSMakeRange(0, text.length)
                                                                withTemplate:@"<addr>"];

    XCTAssertFalse([withoutAddresses containsString:@"c3"], @"%@", text);
    XCTAssertFalse([withoutAddresses containsString:@"C3"], @"%@", text);
    XCTAssertTrue([withoutAddresses containsString:@"length = 32"]);

    /* The material's own hex encoding cannot collide with an address, so this half of the check
       needs no masking and covers the whole string. */
    XCTAssertFalse([text containsString:@"c3c3"], @"%@", text);
    XCTAssertFalse([text containsString:@"C3C3"], @"%@", text);
}

#pragma mark - SPEC 3.1, 16.2 byte reader

- (void)testReaderRefusesEveryReadOnEmptyInput {
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData data]];

    XCTAssertEqual(reader.count, (NSUInteger)0);
    XCTAssertEqual(reader.remaining, (NSUInteger)0);
    XCTAssertTrue([reader atEnd]);

    uint8_t byte = 0xFF;
    uint16_t half = 0xFFFF;
    uint32_t word = 0xFFFFFFFF;
    uint64_t giant = 0xFFFFFFFFFFFFFFFFULL;

    XCTAssertFalse([reader readUInt8:&byte]);
    XCTAssertFalse([reader readUInt16BE:&half]);
    XCTAssertFalse([reader readUInt32BE:&word]);
    XCTAssertFalse([reader readUInt64BE:&giant]);
    XCTAssertNil([reader readDataOfLength:1]);
    XCTAssertFalse([reader skip:1]);
    XCTAssertNil([reader dataAtOffset:0 length:1]);
    XCTAssertEqual([reader bytesAtOffset:0 length:1], NULL);
}

- (void)testReaderIsBigEndian {
    uint8_t raw[15] = {
        0x01,
        0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData dataWithBytes:raw length:sizeof(raw)]];

    uint8_t byte = 0;
    uint16_t half = 0;
    uint32_t word = 0;
    uint64_t giant = 0;

    XCTAssertTrue([reader readUInt8:&byte]);
    XCTAssertTrue([reader readUInt16BE:&half]);
    XCTAssertTrue([reader readUInt32BE:&word]);
    XCTAssertTrue([reader readUInt64BE:&giant]);

    XCTAssertEqual(byte, 0x01);
    XCTAssertEqual(half, 0x0203);
    XCTAssertEqual(word, 0x04050607u);
    XCTAssertEqual(giant, 0x08090A0B0C0D0E0FULL);
    XCTAssertTrue([reader atEnd]);
}

- (void)testReaderRejectsPartialReadAtTheEnd {
    uint8_t raw[3] = { 0xAA, 0xBB, 0xCC };
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData dataWithBytes:raw length:sizeof(raw)]];

    uint32_t word = 0x12345678;
    XCTAssertFalse([reader readUInt32BE:&word], @"3 bytes cannot satisfy a 4-byte read");
    XCTAssertEqual(word, 0x12345678u, @"a refused read must not disturb the out-parameter");
    XCTAssertEqual(reader.offset, (NSUInteger)0, @"a refused read must not move the cursor");
}

- (void)testReaderBoundsAreOverflowSafe {
    uint8_t raw[8] = { 0 };
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData dataWithBytes:raw length:sizeof(raw)]];

    /* An offset+length that would wrap must not manufacture an in-bounds answer. */
    XCTAssertFalse([reader hasBytesAtOffset:1 length:NSUIntegerMax]);
    XCTAssertFalse([reader hasBytesAtOffset:NSUIntegerMax length:1]);
    XCTAssertFalse([reader hasBytesAtOffset:NSUIntegerMax length:NSUIntegerMax]);
    XCTAssertFalse([reader hasBytesAtOffset:4 length:5]);
    XCTAssertTrue([reader hasBytesAtOffset:4 length:4]);
    XCTAssertTrue([reader hasBytesAtOffset:8 length:0]);
    XCTAssertFalse([reader hasBytesAtOffset:9 length:0]);
}

- (void)testAbsoluteReadsDoNotMoveTheCursor {
    uint8_t raw[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData dataWithBytes:raw length:sizeof(raw)]];

    uint8_t byte = 0;
    XCTAssertTrue([reader readUInt8:&byte atOffset:5]);
    XCTAssertEqual(byte, 0x55);
    XCTAssertEqual(reader.offset, (NSUInteger)0);

    uint32_t word = 0;
    XCTAssertTrue([reader readUInt32BE:&word atOffset:4]);
    XCTAssertEqual(word, 0x44556677u);
    XCTAssertEqual(reader.offset, (NSUInteger)0);

    XCTAssertFalse([reader readUInt32BE:&word atOffset:5]);
}

- (void)testMatchLiteralConsumesOnlyOnAMatch {
    NSMutableData *blob = [NSMutableData dataWithBytes:kIRStateMagic length:sizeof(kIRStateMagic)];
    [blob appendBytes:"XY" length:2];

    IRByteReader *reader = [[IRByteReader alloc] initWithData:blob];

    XCTAssertFalse([reader matchLiteral:kIRBundleMagic length:sizeof(kIRBundleMagic)]);
    XCTAssertEqual(reader.offset, (NSUInteger)0, @"a mismatch must not consume");

    XCTAssertTrue([reader matchLiteral:kIRStateMagic length:sizeof(kIRStateMagic)]);
    XCTAssertEqual(reader.offset, (NSUInteger)4);
    XCTAssertEqual(reader.remaining, (NSUInteger)2);
}

- (void)testSeekAndSkipAreBounded {
    uint8_t raw[4] = { 1, 2, 3, 4 };
    IRByteReader *reader = [[IRByteReader alloc] initWithData:[NSData dataWithBytes:raw length:sizeof(raw)]];

    XCTAssertTrue([reader seekToOffset:4]);
    XCTAssertTrue([reader atEnd]);
    XCTAssertFalse([reader seekToOffset:5]);
    XCTAssertEqual(reader.offset, (NSUInteger)4);

    XCTAssertTrue([reader seekToOffset:0]);
    XCTAssertTrue([reader skip:4]);
    XCTAssertFalse([reader skip:1]);
}

- (void)testReaderSnapshotsItsInput {
    NSMutableData *mutable = [NSMutableData dataWithBytes:(uint8_t[]){ 0xAA } length:1];
    IRByteReader *reader = [[IRByteReader alloc] initWithData:mutable];

    ((uint8_t *)mutable.mutableBytes)[0] = 0xBB;

    uint8_t byte = 0;
    XCTAssertTrue([reader readUInt8:&byte]);
    XCTAssertEqual(byte, 0xAA, @"the parser must not see a post-construction mutation");
}

#pragma mark - SPEC 6.2, 9, 12 byte writer

- (void)testWriterIsBigEndianAndRoundTrips {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:15];
    [writer appendUInt8:0x01];
    [writer appendUInt16BE:0x0203];
    [writer appendUInt32BE:0x04050607u];
    [writer appendUInt64BE:0x08090A0B0C0D0E0FULL];

    NSError *error = nil;
    NSData *encoded = [writer finishExpectingLength:15 error:&error];

    XCTAssertNotNil(encoded);
    XCTAssertNil(error);

    uint8_t expected[15] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    XCTAssertEqualObjects(encoded, [NSData dataWithBytes:expected length:sizeof(expected)]);
}

- (void)testWriterRejectsAShortStructure {
    /* §6.2's "assert the total" builder: a missing field is a construction failure here rather
       than a silent interop break on a peer's machine. */
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSessionAD];
    [writer appendBytes:kIRLabelAD length:sizeof(kIRLabelAD)];
    [writer appendZeros:(kIRLenX25519Public * 3)];   // one identity key short

    NSError *error = nil;
    XCTAssertNil([writer finishExpectingLength:kIRLenSessionAD error:&error]);
    XCTAssertEqual(error.code, 7117);
}

- (void)testWriterRejectsAnOverlongStructure {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSessionAD];
    [writer appendBytes:kIRLabelAD length:sizeof(kIRLabelAD)];
    [writer appendZeros:(kIRLenX25519Public * 5)];   // one identity key too many

    NSError *error = nil;
    XCTAssertNil([writer finishExpectingLength:kIRLenSessionAD error:&error]);
    XCTAssertNotNil(error);
}

- (void)testWriterHonoursACallerSuppliedMismatchCode {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:4];
    [writer appendUInt8:0x00];

    NSError *error = nil;
    XCTAssertNil([writer finishExpectingLength:kIRLenBundlePrefix
                             mismatchErrorCode:IRErrorBundleMalformed
                                         error:&error]);
    XCTAssertEqual(error.code, 7122);
}

- (void)testWriterBuildsAWellFormedSessionADShape {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSessionAD];
    [writer appendBytes:kIRLabelAD length:sizeof(kIRLabelAD)];
    [writer appendZeros:(kIRLenX25519Public * 4)];

    NSError *error = nil;
    NSData *sessionAD = [writer finishExpectingLength:kIRLenSessionAD error:&error];

    XCTAssertNotNil(sessionAD);
    XCTAssertEqual(sessionAD.length, (NSUInteger)141);

    IRByteReader *reader = [[IRByteReader alloc] initWithData:sessionAD];
    XCTAssertTrue([reader matchLiteral:kIRLabelAD length:sizeof(kIRLabelAD) atOffset:kIROffSessionADLabel]);
}

- (void)testSecretFinishYieldsSecretBytesAndWipesTheWriter {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenIKMNoOPK];
    [writer appendBytes:kIRF32 length:sizeof(kIRF32)];
    [writer appendZeros:(kIRLenDHOutput * 3)];

    NSError *error = nil;
    IRSecretBytes *ikm = [writer finishSecretExpectingLength:kIRLenIKMNoOPK guarded:NO error:&error];

    XCTAssertNotNil(ikm);
    XCTAssertNil(error);
    XCTAssertEqual(ikm.length, (NSUInteger)128);
    XCTAssertEqual([ikm constBytes][0], 0xFF);
    XCTAssertEqual([ikm constBytes][31], 0xFF);
    XCTAssertEqual([ikm constBytes][32], 0x00);

    XCTAssertEqual(writer.length, (NSUInteger)0, @"the writer's own copy must be gone");
}

- (void)testSecretFinishWipesOnAMismatchToo {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenIKMOPK];
    [writer appendBytes:kIRF32 length:sizeof(kIRF32)];

    NSError *error = nil;
    XCTAssertNil([writer finishSecretExpectingLength:kIRLenIKMOPK guarded:NO error:&error]);
    XCTAssertNotNil(error);
    XCTAssertEqual(writer.length, (NSUInteger)0);
}

- (void)testWriterGrowsBeyondItsHint {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:1];
    for (NSUInteger index = 0; index < 1000; index++) {
        [writer appendUInt8:(uint8_t)(index & 0xFF)];
    }

    NSError *error = nil;
    NSData *encoded = [writer finishExpectingLength:1000 error:&error];

    XCTAssertNotNil(encoded);
    XCTAssertEqual(((const uint8_t *)encoded.bytes)[999], (uint8_t)(999 & 0xFF));
}

- (void)testWriterAndReaderAgreeOnEveryIntegerWidth {
    for (uint32_t sample = 0; sample < 8; sample++) {
        uint64_t value = (0x0123456789ABCDEFULL >> sample);

        IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:8];
        [writer appendUInt64BE:value];

        NSData *encoded = [writer finishExpectingLength:8 error:NULL];
        IRByteReader *reader = [[IRByteReader alloc] initWithData:encoded];

        uint64_t decoded = 0;
        XCTAssertTrue([reader readUInt64BE:&decoded]);
        XCTAssertEqual(decoded, value);
    }
}

#pragma mark - SPEC 13.2 sodium

- (void)testSodiumInitializationIsLatchedAndIdempotent {
    XCTAssertTrue([IRSodium isInitialized]);
    XCTAssertTrue([IRSodium ensureInitialized:NULL]);

    NSError *error = nil;
    XCTAssertTrue([IRSodium ensureInitialized:&error]);
    XCTAssertNil(error);
}

- (void)testConstantTimeHelpers {
    uint8_t a[32]; memset(a, 0x7E, sizeof(a));
    uint8_t b[32]; memset(b, 0x7E, sizeof(b));
    uint8_t zeros[32]; memset(zeros, 0x00, sizeof(zeros));

    XCTAssertTrue(IRConstantTimeEquals(a, b, sizeof(a)));
    XCTAssertFalse(IRConstantTimeEquals(a, zeros, sizeof(a)));
    XCTAssertTrue(IRConstantTimeEquals(a, b, 0));

    XCTAssertTrue(IRIsAllZero(zeros, sizeof(zeros)));
    XCTAssertFalse(IRIsAllZero(a, sizeof(a)));

    /* The tripwire has to catch a single set bit anywhere, including the last byte. */
    uint8_t nearlyZero[32]; memset(nearlyZero, 0x00, sizeof(nearlyZero));
    nearlyZero[31] = 0x01;
    XCTAssertFalse(IRIsAllZero(nearlyZero, sizeof(nearlyZero)));
}

- (void)testZeroizeToleratesNullAndZeroLength {
    IRZeroize(NULL, 0);
    IRZeroize(NULL, 32);

    uint8_t material[4] = { 1, 2, 3, 4 };
    IRZeroize(material, 0);
    XCTAssertEqual(material[0], 1);

    IRZeroize(material, sizeof(material));
    XCTAssertTrue(IRIsAllZero(material, sizeof(material)));
}

@end
