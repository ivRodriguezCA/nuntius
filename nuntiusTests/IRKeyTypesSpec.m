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
#import "IRKeyTypes.h"
#import "IRKeyPairs.h"

/// Layer 1 gate — SPEC §4.2, §4.3, §4.4, §7.5, §12.2 rule 8, §19.1, §19.5.
@interface IRKeyTypesSpec : XCTestCase
@end

@implementation IRKeyTypesSpec

- (void)setUp {
    [super setUp];
    XCTAssertTrue([IRSodium ensureInitialized:NULL]);
}

#pragma mark - Helpers

- (NSData *)bytesOfLength:(NSUInteger)length fill:(uint8_t)fill {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    memset(data.mutableBytes, fill, length);
    return data;
}

/// A 32-byte value whose high bit is clear, so it is a legal §4.4 X25519 public encoding.
- (NSData *)validX25519PublicFilledWith:(uint8_t)fill {
    NSMutableData *data = [[self bytesOfLength:kIRLenX25519Public fill:fill] mutableCopy];
    ((uint8_t *)data.mutableBytes)[31] &= 0x7F;
    return data;
}

#pragma mark - SPEC 4.3 fixed widths

- (void)testEveryNominalTypeDeclaresItsSpecWidth {
    XCTAssertEqual([IREd25519Public fixedLength], (NSUInteger)32);
    XCTAssertEqual([IREd25519Signature fixedLength], (NSUInteger)64);
    XCTAssertEqual([IRX25519Public fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRNonce fixedLength], (NSUInteger)12);
    XCTAssertEqual([IRFingerprint fixedLength], (NSUInteger)32);

    XCTAssertEqual([IREd25519Private fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRX25519Private fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRRootKey fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRChainKey fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRMessageKey fixedLength], (NSUInteger)32);
    XCTAssertEqual([IRMessageEncKey fixedLength], (NSUInteger)32);
}

- (void)testNonSecretTypesRejectEveryWrongLength {
    NSArray<Class> *types = @[
        [IREd25519Public class], [IREd25519Signature class],
        [IRX25519Public class], [IRNonce class], [IRFingerprint class],
    ];

    for (Class type in types) {
        NSUInteger correct = [type fixedLength];

        for (NSUInteger length = 0; length <= (correct + 2); length++) {
            if (length == correct) {
                continue;
            }

            NSError *error = nil;
            id value = [type fromData:[self bytesOfLength:length fill:0x00] error:&error];

            XCTAssertNil(value, @"%@ accepted %lu bytes", type, (unsigned long)length);
            XCTAssertEqual(error.code, (NSInteger)[type lengthErrorCode], @"%@ wrong code", type);
        }
    }
}

- (void)testSecretTypesRejectEveryWrongLength {
    NSArray<Class> *types = @[
        [IREd25519Private class], [IRX25519Private class], [IRRootKey class],
        [IRChainKey class], [IRMessageKey class], [IRMessageEncKey class],
    ];

    for (Class type in types) {
        NSUInteger correct = [type fixedLength];

        for (NSUInteger length = 0; length <= (correct + 2); length++) {
            if (length == correct) {
                continue;
            }

            NSError *error = nil;
            id value = [type fromData:[self bytesOfLength:length fill:0x00] guarded:NO error:&error];

            XCTAssertNil(value, @"%@ accepted %lu bytes", type, (unsigned long)length);
            XCTAssertEqual(error.code, (NSInteger)[type lengthErrorCode], @"%@ wrong code", type);
        }
    }
}

- (void)testEd25519PrivateRejectsTheExpanded64ByteSecretKey {
    /* §4.2 / §3.4 — libsodium's `sk` (= seed ‖ pk) MUST NOT appear at any API boundary. Its width
       is the only thing distinguishing it from the seed, so the width check IS the defence. */
    NSError *error = nil;
    XCTAssertNil([IREd25519Private fromData:[self bytesOfLength:64 fill:0x42] guarded:NO error:&error]);
    XCTAssertNotNil(error);
}

- (void)testWrongLengthCodesFollowTheDocumentedMapping {
    XCTAssertEqual([IREd25519Public lengthErrorCode], IRErrorInvalidPublicKey);
    XCTAssertEqual([IRX25519Public lengthErrorCode], IRErrorInvalidPublicKey);
    XCTAssertEqual([IREd25519Signature lengthErrorCode], IRErrorBadSignature);
    XCTAssertEqual([IRNonce lengthErrorCode], IRErrorMalformedHeader);
    XCTAssertEqual([IRFingerprint lengthErrorCode], IRErrorStateCorrupt);
}

#pragma mark - SPEC 4.4 public key validation

- (void)testX25519PublicRejectsASetHighBit {
    /* §4.4 check 2. Without it a single ratchet key has two distinct wire encodings producing
       identical DH output, which breaks the injectivity the transcript hash, SESSION_AD and the
       skipped-key map key all depend on. */
    NSMutableData *raw = [[self bytesOfLength:kIRLenX25519Public fill:0x11] mutableCopy];
    ((uint8_t *)raw.mutableBytes)[31] = 0x80;

    NSError *error = nil;
    XCTAssertNil([IRX25519Public fromData:raw error:&error]);
    XCTAssertEqual(error.code, 7106);

    XCTAssertFalse([IRX25519Public dataIsValidEncoding:raw]);
    XCTAssertFalse([IRX25519Public highBitIsClear:(const uint8_t *)raw.bytes]);
}

- (void)testX25519PublicAcceptsACanonicalEncoding {
    NSData *raw = [self validX25519PublicFilledWith:0xFF];

    NSError *error = nil;
    IRX25519Public *key = [IRX25519Public fromData:raw error:&error];

    XCTAssertNotNil(key);
    XCTAssertNil(error);
    XCTAssertEqual(key.length, (NSUInteger)32);
    XCTAssertEqualObjects(key.data, raw);
    XCTAssertTrue([IRX25519Public dataIsValidEncoding:raw]);
}

- (void)testX25519PublicRejectsTheHighBitAtEveryOtherBitPattern {
    for (uint8_t low = 0; low < 0x80; low += 0x10) {
        NSMutableData *raw = [[self bytesOfLength:kIRLenX25519Public fill:0x00] mutableCopy];
        ((uint8_t *)raw.mutableBytes)[31] = (uint8_t)(0x80 | low);

        XCTAssertNil([IRX25519Public fromData:raw error:NULL], @"accepted high bit with low nibble %u", low);
    }
}

- (void)testEd25519PublicDoesNotApplyTheX25519HighBitRule {
    /* §4.4 checks 1–2 are about X25519 u-coordinates. An Ed25519 public key's top bit is the sign
       bit of x and is legitimately set half the time; rejecting it would break every second key. */
    NSMutableData *raw = [[self bytesOfLength:kIRLenEd25519Public fill:0x22] mutableCopy];
    ((uint8_t *)raw.mutableBytes)[31] = 0x80;

    XCTAssertNotNil([IREd25519Public fromData:raw error:NULL]);
}

#pragma mark - SPEC 4.2 clamping

- (void)testClampIsAppliedAtConstruction {
    NSData *raw = [self bytesOfLength:kIRLenX25519Private fill:0xFF];

    IRX25519Private *scalar = [IRX25519Private fromData:raw guarded:NO error:NULL];
    XCTAssertNotNil(scalar);

    const uint8_t *bytes = [scalar constBytes];
    /* 0xFF & 0xF8 == 0xF8; (0xFF & 0x7F) | 0x40 == 0x7F. */
    XCTAssertEqual(bytes[0], 0xF8, @"k[0] &= 0xF8");
    XCTAssertEqual(bytes[31], 0x7F, @"k[31] &= 0x7F; k[31] |= 0x40");
    XCTAssertTrue([IRX25519Private bytesAreClamped:bytes]);
}

- (void)testClampIsIdempotent {
    NSMutableData *raw = [[self bytesOfLength:kIRLenX25519Private fill:0xA5] mutableCopy];
    uint8_t *bytes = (uint8_t *)raw.mutableBytes;

    [IRX25519Private clampBytes:bytes];
    uint8_t once[32];
    memcpy(once, bytes, sizeof(once));

    [IRX25519Private clampBytes:bytes];
    XCTAssertEqual(memcmp(once, bytes, sizeof(once)), 0);

    /* And constructing from an already-clamped scalar must not change it. */
    IRX25519Private *scalar = [IRX25519Private fromBytes:once guarded:NO error:NULL];
    XCTAssertEqual(memcmp([scalar constBytes], once, sizeof(once)), 0);
}

- (void)testClampPredicateMatchesSpecSection12_2Rule8 {
    /* §12.2 rule 8 inspects blob[243] and blob[274] — the first and last byte of DHs_priv.
       +bytesAreClamped: MUST be the same predicate over the scalar. */
    XCTAssertEqual((NSUInteger)(kIROffStateDHsPrivLastByte - kIROffStateDHsPriv),
                   (NSUInteger)(kIRLenX25519Private - 1));

    uint8_t scalar[32];
    memset(scalar, 0x00, sizeof(scalar));

    scalar[0] = 0xF8;
    scalar[31] = 0x40;
    XCTAssertTrue([IRX25519Private bytesAreClamped:scalar]);

    for (uint8_t bit = 0x01; bit <= 0x04; bit <<= 1) {
        scalar[0] = (uint8_t)(0xF8 | bit);
        XCTAssertFalse([IRX25519Private bytesAreClamped:scalar], @"low bit %u must be rejected", bit);
    }

    scalar[0] = 0xF8;
    scalar[31] = 0xC0;
    XCTAssertFalse([IRX25519Private bytesAreClamped:scalar], @"high bit set must be rejected");

    scalar[31] = 0x00;
    XCTAssertFalse([IRX25519Private bytesAreClamped:scalar], @"bit 6 clear must be rejected");
}

- (void)testAnUnclampedScalarIsDetectableBeforeConstruction {
    /* §19.5 — the state decoder REJECTS rather than silently re-clamping, so it must be able to
       see the violation. Construction would mask it, which is why the predicate is separate. */
    uint8_t unclamped[32];
    memset(unclamped, 0xFF, sizeof(unclamped));

    XCTAssertFalse([IRX25519Private bytesAreClamped:unclamped]);

    IRX25519Private *scalar = [IRX25519Private fromBytes:unclamped guarded:NO error:NULL];
    XCTAssertTrue([IRX25519Private bytesAreClamped:[scalar constBytes]],
                  @"construction normalizes, which is exactly why the decoder must check first");
}

- (void)testEd25519SeedsAreStoredVerbatim {
    /* §4.2 — Ed25519 clamps the SHA-512 hash of the seed, not the seed, so seeds are NOT clamped. */
    NSData *raw = [self bytesOfLength:kIRLenEd25519Private fill:0xFF];
    IREd25519Private *seed = [IREd25519Private fromData:raw guarded:NO error:NULL];

    XCTAssertNotNil(seed);
    XCTAssertEqual([seed constBytes][0], 0xFF);
    XCTAssertEqual([seed constBytes][31], 0xFF);
}

#pragma mark - SPEC 4.3 nominal typing

- (void)testIdenticalBytesInDifferentTypesAreNotEqual {
    /* The mistake these types exist to prevent: a ChainKey passed where a RootKey belongs produces
       a working, self-consistent, INCOMPATIBLE port. */
    NSData *raw = [self bytesOfLength:32 fill:0x5C];

    IRRootKey *rootKey = [IRRootKey fromData:raw guarded:NO error:NULL];
    IRChainKey *chainKey = [IRChainKey fromData:raw guarded:NO error:NULL];
    IRMessageKey *messageKey = [IRMessageKey fromData:raw guarded:NO error:NULL];

    XCTAssertNotNil(rootKey);
    XCTAssertNotNil(chainKey);
    XCTAssertNotNil(messageKey);

    XCTAssertFalse([rootKey isEqual:chainKey]);
    XCTAssertFalse([chainKey isEqual:messageKey]);
    XCTAssertFalse([rootKey isEqual:messageKey]);

    /* Byte equality still holds across the type boundary, so the inequality above is nominal and
       not an accident of the contents. */
    XCTAssertTrue([rootKey isEqualToSecretBytes:chainKey]);
}

- (void)testIdenticalBytesInDifferentPublicTypesAreNotEqual {
    NSData *raw = [self validX25519PublicFilledWith:0x3D];

    IRX25519Public *agreement = [IRX25519Public fromData:raw error:NULL];
    IREd25519Public *signing = [IREd25519Public fromData:raw error:NULL];
    IRFingerprint *fingerprint = [IRFingerprint fromData:raw error:NULL];

    XCTAssertFalse([agreement isEqual:signing]);
    XCTAssertFalse([signing isEqual:fingerprint]);
    XCTAssertFalse([agreement isEqual:fingerprint]);
}

- (void)testSameTypeSameBytesAreEqualAndHashAlike {
    NSData *raw = [self validX25519PublicFilledWith:0x77];

    IRX25519Public *first = [IRX25519Public fromData:raw error:NULL];
    IRX25519Public *second = [IRX25519Public fromData:raw error:NULL];

    XCTAssertTrue([first isEqualToX25519Public:second]);
    XCTAssertTrue([first isEqual:second]);
    XCTAssertEqual(first.hash, second.hash);

    NSSet *set = [NSSet setWithObjects:first, second, nil];
    XCTAssertEqual(set.count, (NSUInteger)1, @"public keys must be usable as set members");
}

- (void)testHeaderRatchetKeysCompareAsRawBytesOnly {
    /* §4.3 — v3's IRCurve25519KeyPair -isEqual: returned NO whenever one side had a private key and
       the other did not, so its header-key comparison depended on how a field had been populated.
       Here the public key is its own type and carries no private half at all. */
    NSData *raw = [self validX25519PublicFilledWith:0x2A];

    IRX25519Public *fromWire = [IRX25519Public fromData:raw error:NULL];
    IRX25519Private *scalar = [IRX25519Private fromData:[self bytesOfLength:32 fill:0x99]
                                                guarded:NO
                                                  error:NULL];
    IRX25519KeyPair *pair = [IRX25519KeyPair pairWithPublicKey:[IRX25519Public fromData:raw error:NULL]
                                                    privateKey:scalar
                                                         error:NULL];

    XCTAssertTrue([fromWire isEqualToX25519Public:pair.publicKey]);
}

- (void)testSecretHashDoesNotDependOnTheKeyBytes {
    /* Secrets must not spread across hash-table buckets the wipe schedule does not know about. */
    IRRootKey *a = [IRRootKey fromData:[self bytesOfLength:32 fill:0x01] guarded:NO error:NULL];
    IRRootKey *b = [IRRootKey fromData:[self bytesOfLength:32 fill:0xFE] guarded:NO error:NULL];

    XCTAssertEqual(a.hash, b.hash);
    XCTAssertFalse([a isEqual:b]);
}

- (void)testHexStringIsLowercaseAndFullWidth {
    uint8_t raw[12] = { 0x00, 0x0f, 0x10, 0xff, 0xab, 0xcd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    IRNonce *nonce = [IRNonce fromBytes:raw error:NULL];

    XCTAssertEqualObjects([nonce hexString], @"000f10ffabcd010203040506");
}

#pragma mark - SPEC 4.3, 7.5, 19.1 key pairs

- (void)testKeyPairRequiresBothHalves {
    IRX25519Public *publicKey = [IRX25519Public fromData:[self validX25519PublicFilledWith:0x01] error:NULL];
    IRX25519Private *privateKey = [IRX25519Private fromData:[self bytesOfLength:32 fill:0x02]
                                                    guarded:NO
                                                      error:NULL];

    /* Both halves are declared _Nonnull, so passing nil here is a deliberate contract violation:
       the point of the test is that the constructor fails closed with an error instead of
       constructing a pair with a missing private half the way v3's IRCurve25519KeyPair could. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    NSError *error = nil;
    XCTAssertNil([IRX25519KeyPair pairWithPublicKey:publicKey privateKey:nil error:&error]);
    XCTAssertEqual(error.code, 7106);

    error = nil;
    XCTAssertNil([IRX25519KeyPair pairWithPublicKey:nil privateKey:privateKey error:&error]);
    XCTAssertEqual(error.code, 7106);
#pragma clang diagnostic pop

    XCTAssertNotNil([IRX25519KeyPair pairWithPublicKey:publicKey privateKey:privateKey error:NULL]);
}

- (void)testDeepCopyProducesAnIndependentPrivateBuffer {
    /* §7.5 / §19.1 — the responder's initial DHs is a COPY of SPK_B, and §7.4 step 4 zeroizes only
       that copy. Aliasing the prekey store's object would let a routine ratchet step destroy a key
       whose lifetime §5.3 gives exclusively to the store. */
    IRX25519Public *publicKey = [IRX25519Public fromData:[self validX25519PublicFilledWith:0x0A] error:NULL];
    IRX25519Private *privateKey = [IRX25519Private fromData:[self bytesOfLength:32 fill:0x0B]
                                                    guarded:NO
                                                      error:NULL];
    IRX25519KeyPair *original = [IRX25519KeyPair pairWithPublicKey:publicKey
                                                        privateKey:privateKey
                                                             error:NULL];

    IRX25519KeyPair *copy = [original deepCopy];
    XCTAssertNotNil(copy);
    XCTAssertNotEqual(copy.privateKey, original.privateKey, @"the private half must be a new object");
    XCTAssertTrue([copy.privateKey isEqualToSecretBytes:original.privateKey]);

    /* Zeroize the session-owned copy the way §7.4 step 4 does, and the store's original survives. */
    [copy zeroize];

    XCTAssertTrue([copy.privateKey isAllZero]);
    XCTAssertFalse([original.privateKey isAllZero], @"the prekey store's key must be untouched");
    XCTAssertEqual([original.privateKey constBytes][0], 0x08, @"0x0B clamped by k[0] &= 0xF8");
}

- (void)testDeepCopySharesTheImmutablePublicHalf {
    IRX25519Public *publicKey = [IRX25519Public fromData:[self validX25519PublicFilledWith:0x0C] error:NULL];
    IRX25519Private *privateKey = [IRX25519Private fromData:[self bytesOfLength:32 fill:0x0D]
                                                    guarded:NO
                                                      error:NULL];
    IRX25519KeyPair *original = [IRX25519KeyPair pairWithPublicKey:publicKey
                                                        privateKey:privateKey
                                                             error:NULL];

    XCTAssertEqual([original deepCopy].publicKey, original.publicKey);
}

- (void)testEd25519KeyPairRejectsAnExpandedSecretKey {
    IREd25519Public *publicKey = [IREd25519Public fromData:[self bytesOfLength:32 fill:0x0E] error:NULL];

    /* A 64-byte value cannot even become an IREd25519Private, which is the point. */
    XCTAssertNil([IREd25519Private fromData:[self bytesOfLength:64 fill:0x0F] guarded:NO error:NULL]);

    IREd25519Private *seed = [IREd25519Private fromData:[self bytesOfLength:32 fill:0x0F]
                                                guarded:NO
                                                  error:NULL];
    XCTAssertNotNil([IREd25519KeyPair pairWithPublicKey:publicKey seed:seed error:NULL]);
}

- (void)testEd25519KeyPairDeepCopyAndZeroize {
    IREd25519Public *publicKey = [IREd25519Public fromData:[self bytesOfLength:32 fill:0x10] error:NULL];
    IREd25519Private *seed = [IREd25519Private fromData:[self bytesOfLength:32 fill:0x11]
                                                guarded:NO
                                                  error:NULL];
    IREd25519KeyPair *original = [IREd25519KeyPair pairWithPublicKey:publicKey seed:seed error:NULL];

    IREd25519KeyPair *copy = [original deepCopy];
    XCTAssertNotEqual(copy.seed, original.seed);
    XCTAssertTrue([copy.seed isEqualToSecretBytes:original.seed]);

    [copy zeroize];
    XCTAssertTrue([copy.seed isAllZero]);
    XCTAssertFalse([original.seed isAllZero]);
}

- (void)testGuardedSecretsRoundTripAndPreserveAllocationClassOnDuplicate {
    IRX25519Private *guarded = [IRX25519Private fromData:[self bytesOfLength:32 fill:0x21]
                                                 guarded:YES
                                                   error:NULL];
    XCTAssertNotNil(guarded);
    XCTAssertTrue(guarded.isGuarded);

    IRX25519Private *duplicate = [guarded duplicate];
    XCTAssertNotNil(duplicate);
    XCTAssertTrue(duplicate.isGuarded, @"a duplicate must keep the original's allocation class");
    XCTAssertTrue([duplicate isEqualToSecretBytes:guarded]);
}

- (void)testZeroValueIsNotNormalized {
    /* A zero buffer is not key material yet, so the clamp must NOT have run: a caller filling it
       through -mutableBytes is responsible for calling -normalizeRepresentation. */
    IRX25519Private *blank = [IRX25519Private zeroValueGuarded:NO error:NULL];

    XCTAssertNotNil(blank);
    XCTAssertTrue([blank isAllZero]);
    XCTAssertFalse([IRX25519Private bytesAreClamped:[blank constBytes]]);

    memset([blank mutableBytes], 0xFF, blank.length);
    [blank normalizeRepresentation];

    XCTAssertTrue([IRX25519Private bytesAreClamped:[blank constBytes]]);
}

@end
