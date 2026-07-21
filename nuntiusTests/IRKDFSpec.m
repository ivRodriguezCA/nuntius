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
#import "IRKeyTypes.h"
#import "IRProtocolConstants.h"
#import "IRProtocolKDF.h"
#import "IRSecretBytes.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"

/**
 LAYER 3 GATE — SPEC §6.3, §7.2, §7.3, §8.1, §15.3, §15.4.

 The RFC 5869, RFC 4231 and FIPS 180-4 known-answer vectors for the primitives themselves are Layer
 2's (IRPrimitivesSpec); nothing here re-tests HKDF or HMAC. What this file tests is the four
 COMPOSITIONS layered on top of them, because that is where the ports can diverge while every
 primitive KAT still passes:

   - which argument is the salt and which the IKM (§7.2's "single highest-risk divergence point");
   - which label goes with which derivation;
   - how a 64-byte output is split;
   - that all 128 or 160 bytes of the X3DH IKM reach the KDF, which is defect 1 exactly.

 THE ARGUMENT-ORDER TEST IS THE POINT OF THIS FILE. A port that swaps salt and IKM in KDF_RK
 produces a working, self-consistent, completely incompatible ratchet, and no round-trip test
 written against one implementation can see it. testKDFRK_SaltAndIKMAreNotInterchangeable asserts
 that the two orderings differ, so a port that swaps them cannot also match the frozen KDF-RK-1
 vector.

 THIS CLASS NEVER MUTATES ITS ARGUMENTS, and three tests below pin that. §13.3's schedule rows for
 CK and MK are COMMIT-time actions owned by the ratchet, not by the KDF: SkipMessageKeys advances a
 §7.7 snapshot that is discarded whenever a tag fails, so a KDF that wiped its input chain key would
 destroy live state on every forged message (NEG-ATOMIC), and one that wiped a message key would
 destroy a stored skipped key on every corrupted delivery (NEG-SKIP-RETAIN).
 */
@interface IRKDFSpec : XCTestCase
@property (nonatomic, strong) IRSodiumCryptoProvider *provider;
@end

@implementation IRKDFSpec

- (void)setUp {
    [super setUp];

    XCTAssertTrue([IRSodium ensureInitialized:NULL], @"libsodium must initialize");

    NSError *error = nil;
    self.provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(self.provider, @"provider construction failed: %@", error);
}

#pragma mark - Helpers

/// A deterministic, non-uniform filler, so a test that accidentally compares two zero buffers
/// cannot pass by coincidence.
- (NSData *)patternOfLength:(NSUInteger)length seed:(uint8_t)seed {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;

    for (NSUInteger index = 0; index < length; index++) {
        bytes[index] = (uint8_t)((index * 7u) + seed + 1u);
    }

    return [data copy];
}

- (IRSecretBytes *)secretOfLength:(NSUInteger)length seed:(uint8_t)seed {
    NSData *pattern = [self patternOfLength:length seed:seed];
    IRSecretBytes *secret = [[IRSecretBytes alloc] initWithData:pattern guarded:NO];
    XCTAssertNotNil(secret);

    return secret;
}

- (IRRootKey *)rootKeyWithSeed:(uint8_t)seed {
    NSError *error = nil;
    IRRootKey *key = [IRRootKey fromData:[self patternOfLength:kIRLenRootKey seed:seed]
                                 guarded:NO
                                   error:&error];
    XCTAssertNotNil(key, @"%@", error);

    return key;
}

- (IRChainKey *)chainKeyWithSeed:(uint8_t)seed {
    NSError *error = nil;
    IRChainKey *key = [IRChainKey fromData:[self patternOfLength:kIRLenChainKey seed:seed]
                                   guarded:NO
                                     error:&error];
    XCTAssertNotNil(key, @"%@", error);

    return key;
}

- (IRMessageKey *)messageKeyWithSeed:(uint8_t)seed {
    NSError *error = nil;
    IRMessageKey *key = [IRMessageKey fromData:[self patternOfLength:kIRLenMessageKey seed:seed]
                                       guarded:NO
                                         error:&error];
    XCTAssertNotNil(key, @"%@", error);

    return key;
}

- (NSData *)dataFromSecret:(IRSecretBytes *)secret {
    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

#pragma mark - KDF_RK (§7.2) — vector KDF-RK-1

- (void)testKDFRK_ProducesTwoDistinctThirtyTwoByteHalves {
    NSError *error = nil;

    IRRootChainStep *step =
        [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:1]
                                              dhOutput:[self secretOfLength:kIRLenDHOutput seed:2]
                                              provider:self.provider
                                                 error:&error];

    XCTAssertNotNil(step, @"%@", error);
    XCTAssertNil(error);
    XCTAssertEqual(step.rootKey.length, (NSUInteger)kIRLenRootKey);
    XCTAssertEqual(step.chainKey.length, (NSUInteger)kIRLenChainKey);

    /* okm[0..32) and okm[32..64) come from two different HKDF-Expand blocks. Equal halves would
       mean the T(i) loop emitted T(1) twice — §3.2 names omitting or repeating the second block
       "the most common hand-rolled-HKDF bug". */
    XCTAssertFalse([[self dataFromSecret:step.rootKey]
                    isEqualToData:[self dataFromSecret:step.chainKey]]);
}

- (void)testKDFRK_MatchesHKDFWithRootKeyAsSaltSplitAtThirtyTwo {
    NSError *error = nil;

    IRRootKey *rootKey = [self rootKeyWithSeed:3];
    IRSecretBytes *dhOutput = [self secretOfLength:kIRLenDHOutput seed:4];

    IRRootChainStep *step = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                  dhOutput:dhOutput
                                                                  provider:self.provider
                                                                     error:&error];
    XCTAssertNotNil(step, @"%@", error);

    /* The independent statement of §7.2, spelled out at the call site rather than through the
       helper under test: salt = RK, ikm = DH_out, info = "nuntius:RK:v4", L = 64. */
    IRSecretBytes *expected =
        [self.provider hkdfWithSalt:rootKey
                                ikm:dhOutput
                               info:[NSData dataWithBytes:kIRLabelRK length:kIRLenLabelRK]
                       outputLength:kIRLenKDFRKOutput
                              error:&error];
    XCTAssertNotNil(expected, @"%@", error);
    XCTAssertEqual(expected.length, (NSUInteger)kIRLenKDFRKOutput);

    NSData *expectedBytes = [self dataFromSecret:expected];

    XCTAssertEqualObjects([self dataFromSecret:step.rootKey],
                          [expectedBytes subdataWithRange:NSMakeRange(0, kIRLenRootKey)]);
    XCTAssertEqualObjects([self dataFromSecret:step.chainKey],
                          [expectedBytes subdataWithRange:NSMakeRange(kIRLenRootKey, kIRLenChainKey)]);
}

/// §7.2's argument-order trap, made observable. THIS is the assertion that a swapped port fails.
- (void)testKDFRK_SaltAndIKMAreNotInterchangeable {
    NSError *error = nil;

    IRRootKey *rootKey = [self rootKeyWithSeed:5];
    IRSecretBytes *dhOutput = [self secretOfLength:kIRLenDHOutput seed:6];

    IRRootChainStep *correct = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                     dhOutput:dhOutput
                                                                     provider:self.provider
                                                                        error:&error];
    XCTAssertNotNil(correct, @"%@", error);

    /* BouncyCastle's HKDFParameters(ikm, salt, info) and CryptoKit's
       deriveKey(inputKeyMaterial:salt:info:) both take the IKM first; libsodium's
       crypto_kdf_hkdf_sha256_extract takes the salt first. This is what a port that follows the
       wrong one computes. */
    IRSecretBytes *swapped =
        [self.provider hkdfWithSalt:dhOutput
                                ikm:rootKey
                               info:[NSData dataWithBytes:kIRLabelRK length:kIRLenLabelRK]
                       outputLength:kIRLenKDFRKOutput
                              error:&error];
    XCTAssertNotNil(swapped, @"%@", error);

    NSData *swappedBytes = [self dataFromSecret:swapped];

    XCTAssertNotEqualObjects([self dataFromSecret:correct.rootKey],
                             [swappedBytes subdataWithRange:NSMakeRange(0, kIRLenRootKey)],
                             @"salt and IKM must not be interchangeable in KDF_RK");
    XCTAssertNotEqualObjects([self dataFromSecret:correct.chainKey],
                             [swappedBytes subdataWithRange:NSMakeRange(kIRLenRootKey,
                                                                       kIRLenChainKey)]);
}

/// NEG-RK-ALTERED (§15.4) — "Alter RK before KDF_RK; assert the output changes."
/// Fails immediately against v3, whose performDHRatchet: derived from the DH output alone.
- (void)testNEGRKAltered_ChangingTheRootKeyChangesBothOutputs {
    NSError *error = nil;

    IRSecretBytes *dhOutput = [self secretOfLength:kIRLenDHOutput seed:7];

    IRRootChainStep *first = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:8]
                                                                   dhOutput:dhOutput
                                                                   provider:self.provider
                                                                      error:&error];
    XCTAssertNotNil(first, @"%@", error);

    NSMutableData *altered = [[self patternOfLength:kIRLenRootKey seed:8] mutableCopy];
    ((uint8_t *)altered.mutableBytes)[0] ^= 0x01;

    IRRootKey *alteredRootKey = [IRRootKey fromData:altered guarded:NO error:&error];
    XCTAssertNotNil(alteredRootKey, @"%@", error);

    IRRootChainStep *second = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:alteredRootKey
                                                                    dhOutput:dhOutput
                                                                    provider:self.provider
                                                                       error:&error];
    XCTAssertNotNil(second, @"%@", error);

    XCTAssertNotEqualObjects([self dataFromSecret:first.rootKey],
                             [self dataFromSecret:second.rootKey],
                             @"one flipped bit of RK must change RK'");
    XCTAssertNotEqualObjects([self dataFromSecret:first.chainKey],
                             [self dataFromSecret:second.chainKey],
                             @"one flipped bit of RK must change CK");
}

- (void)testKDFRK_ChangingTheDHOutputChangesBothOutputs {
    NSError *error = nil;

    IRRootKey *rootKey = [self rootKeyWithSeed:9];

    IRRootChainStep *first =
        [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                              dhOutput:[self secretOfLength:kIRLenDHOutput seed:10]
                                              provider:self.provider
                                                 error:&error];
    IRRootChainStep *second =
        [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                              dhOutput:[self secretOfLength:kIRLenDHOutput seed:11]
                                              provider:self.provider
                                                 error:&error];

    XCTAssertNotNil(first);
    XCTAssertNotNil(second);
    XCTAssertNotEqualObjects([self dataFromSecret:first.rootKey],
                             [self dataFromSecret:second.rootKey]);
}

- (void)testKDFRK_RejectsAMissingOrWrongLengthArgument {
    NSError *error = nil;

    XCTAssertNil([IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:12]
                                                       dhOutput:[self secretOfLength:31 seed:13]
                                                       provider:self.provider
                                                          error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    /* Deliberately violating the _Nonnull annotation. Objective-C nullability is ADVISORY — it
       produces a diagnostic and nothing more, and a Swift or Java caller bridging in, a value
       arriving from a dictionary, or a store lookup that missed all deliver nil at runtime past
       any annotation. §10.5 requires a reported failure rather than a crash, so the runtime guard
       is the contract and the annotation is documentation of intent. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    error = nil;
    XCTAssertNil([IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:12]
                                                       dhOutput:[self secretOfLength:kIRLenDHOutput
                                                                                seed:13]
                                                       provider:nil
                                                          error:&error]);
    XCTAssertEqual(error.code, IRErrorNotInitialized);
#pragma clang diagnostic pop
}

- (void)testKDFRK_DoesNotDereferenceANullErrorOutParameter {
    /* §10.5: "Every failure path MUST set the error out-parameter, and MUST NOT dereference a null
       one." v3 crashed here in two places. */
    XCTAssertNil([IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:14]
                                                       dhOutput:[self secretOfLength:1 seed:15]
                                                       provider:self.provider
                                                          error:NULL]);
}

#pragma mark - KDF_CK (§7.3) — vector KDF-CK-1

- (void)testKDFCK_MatchesTwoRawHMACsOverTheConstantsZeroOneAndZeroTwo {
    NSError *error = nil;

    IRChainKey *chainKey = [self chainKeyWithSeed:20];

    IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                          provider:self.provider
                                                             error:&error];
    XCTAssertNotNil(step, @"%@", error);

    const uint8_t one = 0x01;
    const uint8_t two = 0x02;

    IRSecretBytes *expectedMK = [self.provider hmacSHA256WithKey:chainKey
                                                         message:[NSData dataWithBytes:&one length:1]
                                                           error:&error];
    IRSecretBytes *expectedCK = [self.provider hmacSHA256WithKey:chainKey
                                                         message:[NSData dataWithBytes:&two length:1]
                                                           error:&error];
    XCTAssertNotNil(expectedMK);
    XCTAssertNotNil(expectedCK);

    XCTAssertEqualObjects([self dataFromSecret:step.messageKey], [self dataFromSecret:expectedMK]);
    XCTAssertEqualObjects([self dataFromSecret:step.nextChainKey], [self dataFromSecret:expectedCK]);

    /* §7.3: "The constants 0x01 and 0x02 MUST NOT be renumbered." v3 used salt 0 for the message
       key and salt 1 for the chain key; a port carrying those over lands here. */
    XCTAssertNotEqualObjects([self dataFromSecret:step.messageKey],
                             [self dataFromSecret:step.nextChainKey]);
}

- (void)testKDFCK_IsDeterministicAndAdvancesTheChain {
    NSError *error = nil;

    IRChainKey *chainKey = [self chainKeyWithSeed:21];

    IRChainStep *first = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                           provider:self.provider
                                                              error:&error];
    IRChainStep *repeat = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                            provider:self.provider
                                                               error:&error];
    XCTAssertNotNil(first);
    XCTAssertNotNil(repeat);
    XCTAssertEqualObjects([self dataFromSecret:first.messageKey],
                          [self dataFromSecret:repeat.messageKey]);

    IRChainStep *next = [IRProtocolKDF deriveChainStepWithChainKey:first.nextChainKey
                                                          provider:self.provider
                                                             error:&error];
    XCTAssertNotNil(next);
    XCTAssertNotEqualObjects([self dataFromSecret:first.messageKey],
                             [self dataFromSecret:next.messageKey],
                             @"each chain step must yield a fresh message key");
}

/**
 NEG-ATOMIC's precondition at unit scale (§7.7, §15.4).

 §7.6's SkipMessageKeys runs KDF_CK against a SNAPSHOT of the receiving chain, and §7.9 phase 3c
 runs it BEFORE the AEAD check. A KDF that zeroized its input would therefore wipe the live
 session's CKr on every header-valid, tag-invalid message an attacker sends — the desynchronisation
 DoS §15.4 calls the only failure NEG-ATOMIC catches.
 */
- (void)testKDFCK_DoesNotZeroizeTheChainKeyItWasGiven {
    NSError *error = nil;

    IRChainKey *chainKey = [self chainKeyWithSeed:22];
    NSData *before = [self dataFromSecret:chainKey];

    XCTAssertNotNil([IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                      provider:self.provider
                                                         error:&error]);

    XCTAssertEqualObjects(before, [self dataFromSecret:chainKey],
                          @"KDF_CK must leave its input chain key intact");
    XCTAssertFalse([chainKey isAllZero]);
}

- (void)testKDFCK_RejectsAMissingChainKeyWithoutDereferencingANullError {
    NSError *error = nil;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRProtocolKDF deriveChainStepWithChainKey:nil
                                                   provider:self.provider
                                                      error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    XCTAssertNil([IRProtocolKDF deriveChainStepWithChainKey:nil
                                                   provider:self.provider
                                                      error:NULL]);
#pragma clang diagnostic pop
}

#pragma mark - KDF_MK (§8.1) — vector KDF-MK-1

- (void)testKDFMK_MatchesHKDFOverZ32WithTheMessageKeyLabel {
    NSError *error = nil;

    IRMessageKey *messageKey = [self messageKeyWithSeed:30];

    IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:messageKey
                                                     provider:self.provider
                                                        error:&error];
    XCTAssertNotNil(encKey, @"%@", error);
    XCTAssertEqual(encKey.length, (NSUInteger)kIRLenMessageEncKey);

    IRSecretBytes *z32 = [[IRSecretBytes alloc] initWithBytes:kIRZ32 length:kIRLenZ32];
    IRSecretBytes *expected =
        [self.provider hkdfWithSalt:z32
                                ikm:messageKey
                               info:[NSData dataWithBytes:kIRLabelMK length:kIRLenLabelMK]
                       outputLength:kIRLenKDFMKOutput
                              error:&error];
    XCTAssertNotNil(expected, @"%@", error);

    XCTAssertEqualObjects([self dataFromSecret:encKey], [self dataFromSecret:expected]);

    /* §8.1 has ONE output. v3 derived an AES key, an HMAC key and an IV from a single message key by
       re-invoking one label at three salts; there is nothing here for a port to derive a second
       value from. */
    XCTAssertNotEqualObjects([self dataFromSecret:encKey], [self dataFromSecret:messageKey]);
}

- (void)testKDFMK_UsesADistinctLabelFromKDFRK {
    NSError *error = nil;

    /* "nuntius:MK:v4" and "nuntius:RK:v4" are both 13 bytes and differ in one character. A port
       that copy-pastes the label constant gets identical output from two derivations that must
       never agree. */
    IRSecretBytes *ikm = [self secretOfLength:kIRLenMessageKey seed:31];

    IRSecretBytes *z32 = [[IRSecretBytes alloc] initWithBytes:kIRZ32 length:kIRLenZ32];

    IRSecretBytes *underMK = [self.provider hkdfWithSalt:z32
                                                     ikm:ikm
                                                    info:[NSData dataWithBytes:kIRLabelMK
                                                                        length:kIRLenLabelMK]
                                            outputLength:kIRLenKDFMKOutput
                                                   error:&error];
    IRSecretBytes *underRK = [self.provider hkdfWithSalt:z32
                                                     ikm:ikm
                                                    info:[NSData dataWithBytes:kIRLabelRK
                                                                        length:kIRLenLabelRK]
                                            outputLength:kIRLenKDFMKOutput
                                                   error:&error];
    XCTAssertNotNil(underMK);
    XCTAssertNotNil(underRK);
    XCTAssertNotEqualObjects([self dataFromSecret:underMK], [self dataFromSecret:underRK]);
}

/**
 NEG-SKIP-RETAIN's precondition at unit scale (§15.4).

 A message key drawn from the §7.6 skipped store is expanded BEFORE the AEAD runs. §15.4 requires
 that a corrupted tag leave that stored key intact so a later correct delivery still succeeds — so
 KDF_MK wiping its argument would fail that vector outright.
 */
- (void)testKDFMK_DoesNotZeroizeTheMessageKeyItWasGiven {
    NSError *error = nil;

    IRMessageKey *messageKey = [self messageKeyWithSeed:32];
    NSData *before = [self dataFromSecret:messageKey];

    XCTAssertNotNil([IRProtocolKDF expandMessageKey:messageKey provider:self.provider error:&error]);

    XCTAssertEqualObjects(before, [self dataFromSecret:messageKey],
                          @"KDF_MK must leave the message key intact for the skipped-key store");
    XCTAssertFalse([messageKey isAllZero]);
}

#pragma mark - X3DH SK derivation (§6.3)

- (void)testDeriveSharedKey_AcceptsExactlyTheTwoLegalIKMLengths {
    NSError *error = nil;

    NSData *transcriptHash = [self patternOfLength:kIRLenTH seed:40];

    for (NSNumber *length in @[@((NSUInteger)kIRLenIKMNoOPK), @((NSUInteger)kIRLenIKMOPK)]) {
        error = nil;
        IRRootKey *sharedKey =
            [IRProtocolKDF deriveSharedKeyWithIKM:[self secretOfLength:length.unsignedIntegerValue
                                                                  seed:41]
                                   transcriptHash:transcriptHash
                                         provider:self.provider
                                            error:&error];
        XCTAssertNotNil(sharedKey, @"IKM of %@ bytes must be accepted: %@", length, error);
        XCTAssertEqual(sharedKey.length, (NSUInteger)kIRLenSK);
    }
}

/**
 §6.3: "Both parties MUST assert len(IKM) ∈ {128, 160} ... That assertion alone would have caught
 defect 1 on the day it was introduced."

 The four rejected lengths bracket both legal values, so an off-by-one in either bound is caught.
 */
- (void)testDeriveSharedKey_RejectsEveryOtherIKMLength {
    NSData *transcriptHash = [self patternOfLength:kIRLenTH seed:42];

    for (NSNumber *length in @[@32, @96, @127, @129, @159, @161, @192]) {
        NSError *error = nil;
        XCTAssertNil([IRProtocolKDF deriveSharedKeyWithIKM:[self secretOfLength:length.unsignedIntegerValue
                                                                           seed:43]
                                            transcriptHash:transcriptHash
                                                  provider:self.provider
                                                     error:&error],
                     @"IKM of %@ bytes must be rejected", length);
        XCTAssertEqual(error.code, IRErrorStateCorrupt);
    }
}

- (void)testDeriveSharedKey_RejectsAWrongLengthTranscriptHash {
    NSError *error = nil;

    XCTAssertNil([IRProtocolKDF deriveSharedKeyWithIKM:[self secretOfLength:kIRLenIKMOPK seed:44]
                                        transcriptHash:[self patternOfLength:31 seed:45]
                                              provider:self.provider
                                                 error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);
}

/**
 Every byte of the IKM must reach the KDF. This is defect 1 stated as a property: v3 passed the
 128-byte IKM to crypto_kdf_derive_from_key, whose key parameter is exactly 32 bytes, so a change
 anywhere at or beyond offset 32 produced an IDENTICAL shared key.

 IRX3DHSpec makes the same assertion against real Diffie-Hellman outputs at the DH1–DH4 offsets;
 this one covers the whole span at 8-byte granularity.
 */
- (void)testDeriveSharedKey_EveryByteOfTheIKMAffectsTheOutput {
    NSError *error = nil;

    NSData *transcriptHash = [self patternOfLength:kIRLenTH seed:46];
    NSData *base = [self patternOfLength:kIRLenIKMOPK seed:47];

    IRSecretBytes *baseIKM = [[IRSecretBytes alloc] initWithData:base guarded:NO];
    IRRootKey *baseKey = [IRProtocolKDF deriveSharedKeyWithIKM:baseIKM
                                                transcriptHash:transcriptHash
                                                      provider:self.provider
                                                         error:&error];
    XCTAssertNotNil(baseKey, @"%@", error);
    NSData *baseKeyBytes = [self dataFromSecret:baseKey];

    for (NSUInteger offset = 0; offset < kIRLenIKMOPK; offset += 8) {
        NSMutableData *altered = [base mutableCopy];
        ((uint8_t *)altered.mutableBytes)[offset] ^= 0x80;

        IRSecretBytes *alteredIKM = [[IRSecretBytes alloc] initWithData:altered guarded:NO];
        IRRootKey *alteredKey = [IRProtocolKDF deriveSharedKeyWithIKM:alteredIKM
                                                       transcriptHash:transcriptHash
                                                             provider:self.provider
                                                                error:&error];
        XCTAssertNotNil(alteredKey);
        XCTAssertNotEqualObjects(baseKeyBytes, [self dataFromSecret:alteredKey],
                                 @"IKM byte %lu must affect SK", (unsigned long)offset);
    }
}

- (void)testDeriveSharedKey_IsBoundToTheTranscriptHash {
    NSError *error = nil;

    IRSecretBytes *ikm = [self secretOfLength:kIRLenIKMOPK seed:48];

    IRRootKey *first = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                              transcriptHash:[self patternOfLength:kIRLenTH seed:49]
                                                    provider:self.provider
                                                       error:&error];
    IRRootKey *second = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                               transcriptHash:[self patternOfLength:kIRLenTH seed:50]
                                                     provider:self.provider
                                                        error:&error];
    XCTAssertNotNil(first);
    XCTAssertNotNil(second);
    XCTAssertNotEqualObjects([self dataFromSecret:first], [self dataFromSecret:second],
                             @"TH is inside the HKDF info; a different transcript must give a "
                             @"different SK");
}

/// §13.3 gives IKM's wipe to IRX3DH, which owns it together with DH1–DH4 and EK_A's private half,
/// so no subset can be forgotten. The KDF must therefore leave it alone.
- (void)testDeriveSharedKey_DoesNotZeroizeTheIKMItWasGiven {
    NSError *error = nil;

    IRSecretBytes *ikm = [self secretOfLength:kIRLenIKMNoOPK seed:51];
    NSData *before = [self dataFromSecret:ikm];

    XCTAssertNotNil([IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                           transcriptHash:[self patternOfLength:kIRLenTH seed:52]
                                                 provider:self.provider
                                                    error:&error]);

    XCTAssertEqualObjects(before, [self dataFromSecret:ikm]);
}

#pragma mark - Value types

- (void)testRootChainStepAndChainStepZeroizeBothHalves {
    NSError *error = nil;

    IRRootChainStep *rootStep =
        [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:[self rootKeyWithSeed:60]
                                              dhOutput:[self secretOfLength:kIRLenDHOutput seed:61]
                                              provider:self.provider
                                                 error:&error];
    XCTAssertNotNil(rootStep);
    [rootStep zeroize];
    XCTAssertTrue([rootStep.rootKey isAllZero]);
    XCTAssertTrue([rootStep.chainKey isAllZero]);

    IRChainStep *chainStep = [IRProtocolKDF deriveChainStepWithChainKey:[self chainKeyWithSeed:62]
                                                               provider:self.provider
                                                                  error:&error];
    XCTAssertNotNil(chainStep);
    [chainStep zeroize];
    XCTAssertTrue([chainStep.messageKey isAllZero]);
    XCTAssertTrue([chainStep.nextChainKey isAllZero]);
}

@end
