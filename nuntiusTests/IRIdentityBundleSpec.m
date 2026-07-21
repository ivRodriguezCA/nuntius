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
#import "IRInMemoryPreKeyStore.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRPreKeyStore.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"

/**
 LAYER 4 GATE — SPEC §5.1–§5.6, §6.6, §10.3, §13.3, §15.3, §15.4.

 Two properties carry most of this file's weight, and neither is a round trip.

 ORDER IS OBSERVABLE. §10.3 and §5.3 are ordered gates, and an implementation that runs the right
 checks in the wrong order returns the wrong error code for an input that is wrong in two ways.
 Those codes are frozen into the conformance vectors, so a reordering here is a cross-port break
 rather than a cosmetic difference. Every ordering claim below is tested with an input that violates
 two rules at once, which is the only construction that can distinguish them.

 §4.4 CHECKS 1–2 ARE X25519-ONLY. §5.3 rule 2 lists IK^d, SPK and OPK — not IK^s. Bit 255 of an
 Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is set in roughly half of all valid keys,
 so a port that reads §4.4's heading as governing every public key rejects half of all identities
 intermittently, and the failure presents as a signature bug. That is a regression test here, with
 the RFC 8032 §7.1 key whose high bit is genuinely set.

 EVERY CLOCK VALUE IN THIS LAYER IS A PARAMETER. Nothing here reads an ambient clock, so §15.5
 rule 6's injected `now_s` is supplied by passing it, and §15.6's ten-years-forward CI run cannot
 affect a single assertion in this file.

 Each test names the §15.3 / §15.4 vector id it will become when the generator runs at Layer 10.
 */
@interface IRIdentityBundleSpec : XCTestCase
@property (nonatomic, strong) IRSodiumCryptoProvider *provider;
@property (nonatomic, strong) IRIdentity *bob;
@end

@implementation IRIdentityBundleSpec

/// A window well inside MAX_SPK_VALIDITY_SECONDS, with fixed literals so no assertion below depends
/// on the wall clock (§15.3).
static const uint64_t kNotBefore = 1700000000ULL;
static const uint64_t kNotAfter = 1700000000ULL + 86400ULL * 30ULL;
static const uint64_t kNowInsideWindow = 1700000000ULL + 86400ULL;

- (void)setUp {
    [super setUp];

    XCTAssertTrue([IRSodium ensureInitialized:NULL], @"libsodium must initialize");

    NSError *error = nil;
    self.provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(self.provider, @"provider construction failed: %@", error);

    self.bob = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(self.bob, @"identity generation failed: %@", error);
    XCTAssertNil(error);
}

#pragma mark - Helpers

- (NSData *)dataFromHex:(NSString *)hex {
    XCTAssertEqual(hex.length % 2, 0u, @"hex literal must have even length");

    NSMutableData *data = [NSMutableData dataWithCapacity:(hex.length / 2)];

    for (NSUInteger index = 0; index < hex.length; index += 2) {
        NSString *pair = [hex substringWithRange:NSMakeRange(index, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        unsigned int value = 0;

        XCTAssertTrue([scanner scanHexInt:&value], @"not hex: %@", pair);

        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    }

    return [data copy];
}

- (IRIdentity *)makeIdentity {
    NSError *error = nil;
    IRIdentity *identity = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(identity, @"identity generation failed: %@", error);

    return identity;
}

/// Builds an identity whose IK^s comes from a chosen RFC 8032 seed, so a test can pin a public key
/// with a particular bit pattern.
- (IRIdentity *)makeIdentityWithSigningSeedHex:(NSString *)seedHex {
    NSError *error = nil;

    IREd25519Private *seed = [IREd25519Private fromData:[self dataFromHex:seedHex]
                                                guarded:NO
                                                  error:&error];
    XCTAssertNotNil(seed, @"seed construction failed: %@", error);

    IREd25519Public *publicKey = [self.provider ed25519PublicKeyForSeed:seed error:&error];
    XCTAssertNotNil(publicKey, @"public key derivation failed: %@", error);

    IREd25519KeyPair *signingKeyPair = [IREd25519KeyPair pairWithPublicKey:publicKey
                                                                      seed:seed
                                                                     error:&error];
    XCTAssertNotNil(signingKeyPair, @"signing pair construction failed: %@", error);

    IRX25519KeyPair *agreementKeyPair = [self.provider generateX25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(agreementKeyPair, @"agreement pair generation failed: %@", error);

    IRIdentityKeyPair *keyPair =
        [IRIdentityKeyPair pairWithSigningKey:signingKeyPair.publicKey
                                 agreementKey:agreementKeyPair.publicKey
                                        error:&error];
    XCTAssertNotNil(keyPair, @"identity pair construction failed: %@", error);

    NSData *message = IRIKBindMessage(keyPair, &error);
    XCTAssertNotNil(message, @"IKBIND_MSG construction failed: %@", error);

    IREd25519Signature *binding = [self.provider ed25519SignMessage:message
                                                           withSeed:seed
                                                              error:&error];
    XCTAssertNotNil(binding, @"IKB signing failed: %@", error);

    IRIdentity *identity = [IRIdentity identityWithSigningKeyPair:signingKeyPair
                                                 agreementKeyPair:agreementKeyPair
                                                          binding:binding
                                                         provider:self.provider
                                                            error:&error];
    XCTAssertNotNil(identity, @"identity construction failed: %@", error);

    return identity;
}

- (IRSignedPreKeyRecord *)makeSignedPreKeyForIdentity:(IRIdentity *)identity
                                                spkId:(uint32_t)spkId
                                           notBeforeS:(uint64_t)notBeforeS
                                            notAfterS:(uint64_t)notAfterS {
    NSError *error = nil;
    IRSignedPreKeyRecord *record = [IRSignedPreKeyRecord generateWithIdentity:identity
                                                                        spkId:spkId
                                                                   notBeforeS:notBeforeS
                                                                    notAfterS:notAfterS
                                                                     provider:self.provider
                                                                        error:&error];
    XCTAssertNotNil(record, @"signed prekey generation failed: %@", error);

    return record;
}

- (IRSignedPreKeyRecord *)makeSignedPreKey {
    return [self makeSignedPreKeyForIdentity:self.bob
                                       spkId:0x11223344
                                  notBeforeS:kNotBefore
                                   notAfterS:kNotAfter];
}

- (IROneTimePreKeyRecord *)makeOneTimePreKeyWithId:(uint32_t)opkId createdAt:(uint64_t)createdAt {
    NSError *error = nil;
    IROneTimePreKeyRecord *record = [IROneTimePreKeyRecord generateWithOpkId:opkId
                                                           createdAtUnixSecs:createdAt
                                                                    provider:self.provider
                                                                       error:&error];
    XCTAssertNotNil(record, @"one-time prekey generation failed: %@", error);

    return record;
}

- (NSArray<IROneTimePreKeyRecord *> *)makeOneTimePreKeys:(NSUInteger)count {
    NSMutableArray<IROneTimePreKeyRecord *> *records = [NSMutableArray arrayWithCapacity:count];

    for (NSUInteger index = 0; index < count; index++) {
        [records addObject:[self makeOneTimePreKeyWithId:(uint32_t)(0x1000 + index)
                                              createdAt:kNotBefore]];
    }

    return records;
}

/// A structurally and cryptographically valid bundle, as mutable bytes so a negative test can
/// corrupt exactly one field. Every §15.4 negative bundle artifact is byte surgery on this.
- (NSMutableData *)validBundleBytesWithOPKCount:(NSUInteger)opkCount {
    NSError *error = nil;
    NSData *bundle = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                        signedPreKeyRecord:[self makeSignedPreKey]
                                      oneTimePreKeyRecords:[self makeOneTimePreKeys:opkCount]
                                                     error:&error];
    XCTAssertNotNil(bundle, @"bundle serialization failed: %@", error);
    XCTAssertEqual(bundle.length,
                   (NSUInteger)kIRLenBundlePrefix + (NSUInteger)kIRLenBundleOPKEntry * opkCount);

    return [bundle mutableCopy];
}

- (IRPreKeyBundle *)parseBundle:(NSData *)data error:(NSError **)error {
    return [IRPreKeyBundle bundleFromData:data provider:self.provider error:error];
}

/// Asserts a parse fails with exactly `code`, and that §10.5's "MUST NOT return a null result with
/// a null error" holds.
- (void)assertBundle:(NSData *)data rejectedWith:(IRErrorCode)code message:(NSString *)message {
    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];

    XCTAssertNil(bundle, @"%@: bundle was accepted", message);
    XCTAssertNotNil(error, @"%@: nil result with nil error", message);
    XCTAssertEqualObjects(error.domain, IRErrorDomain, @"%@", message);
    XCTAssertEqual(error.code, (NSInteger)code,
                   @"%@: expected %@, got %@", message,
                   IRErrorNameForCode(code), IRErrorNameForCode((IRErrorCode)error.code));

    /* §10.5 — the same call MUST NOT dereference a null out-parameter. v3 crashed here. */
    XCTAssertNil([self parseBundle:data error:NULL], @"%@: NULL error crashed or succeeded", message);
}

#pragma mark - §5.1 IKBIND_MSG — vector X3DH-IKBIND

- (void)testIKBindMessageHasSpecifiedLayoutAndLength {
    NSError *error = nil;
    NSData *message = IRIKBindMessage(self.bob.identityKeyPair, &error);

    XCTAssertNotNil(message, @"%@", error);
    XCTAssertNil(error);
    XCTAssertEqual(message.length, (NSUInteger)kIRLenIKBindMsg);
    XCTAssertEqual(message.length, (NSUInteger)81);

    /* §18 — "nuntius:IKBIND:v4", no NUL terminator and no length prefix. */
    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffIKBindLabel,
                                                               kIRLenLabelIKBind)],
                          [self dataFromHex:@"6e756e746975733a494b42494e443a7634"]);

    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffIKBindSigning,
                                                               kIRLenEd25519Public)],
                          self.bob.signingKeyPair.publicKey.data);

    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffIKBindAgreement,
                                                               kIRLenX25519Public)],
                          self.bob.agreementKeyPair.publicKey.data);
}

- (void)testIdentityBindingVerifiesOverIKBindMessage {
    NSError *error = nil;
    NSData *message = IRIKBindMessage(self.bob.identityKeyPair, &error);

    XCTAssertTrue([self.provider ed25519VerifySignature:self.bob.binding
                                              ofMessage:message
                                              publicKey:self.bob.signingKeyPair.publicKey]);
}

- (void)testIKBindMessageBindsBothKeysSoASwapBreaksVerification {
    /* §5.5's core claim: without IKB covering BOTH keys, an attacker could present a victim's
       genuine IK^s alongside an attacker-controlled IK^d and be attributed to the victim. */
    IRIdentity *attacker = [self makeIdentity];

    NSError *error = nil;
    IRIdentityKeyPair *swapped =
        [IRIdentityKeyPair pairWithSigningKey:self.bob.signingKeyPair.publicKey
                                 agreementKey:attacker.agreementKeyPair.publicKey
                                        error:&error];
    XCTAssertNotNil(swapped, @"%@", error);

    NSData *swappedMessage = IRIKBindMessage(swapped, &error);
    XCTAssertNotNil(swappedMessage);

    XCTAssertFalse([self.provider ed25519VerifySignature:self.bob.binding
                                               ofMessage:swappedMessage
                                               publicKey:self.bob.signingKeyPair.publicKey]);
}

#pragma mark - §5.2 SPK_SIGN_MSG — vector X3DH-SPKSIG

- (void)testSPKSignMessageHasSpecifiedLayoutAndLength {
    IRSignedPreKeyRecord *record = [self makeSignedPreKey];

    NSError *error = nil;
    NSData *message = IRSPKSignMessage(self.bob.identityKeyPair,
                                       record.spkId,
                                       record.keyPair.publicKey,
                                       record.notBeforeS,
                                       record.notAfterS,
                                       &error);

    XCTAssertNotNil(message, @"%@", error);
    XCTAssertEqual(message.length, (NSUInteger)kIRLenSPKSignMsg);
    XCTAssertEqual(message.length, (NSUInteger)130);

    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffSPKSignLabel,
                                                               kIRLenLabelSPK)],
                          [self dataFromHex:@"6e756e746975733a53504b3a7634"]);

    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffSPKSignSigning, 32)],
                          self.bob.signingKeyPair.publicKey.data);
    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffSPKSignAgreement, 32)],
                          self.bob.agreementKeyPair.publicKey.data);

    const uint8_t *bytes = (const uint8_t *)message.bytes;
    uint32_t spkId = ((uint32_t)bytes[kIROffSPKSignSPKId] << 24) |
                     ((uint32_t)bytes[kIROffSPKSignSPKId + 1] << 16) |
                     ((uint32_t)bytes[kIROffSPKSignSPKId + 2] << 8) |
                     ((uint32_t)bytes[kIROffSPKSignSPKId + 3]);
    XCTAssertEqual(spkId, record.spkId, @"spk_id must be big-endian at offset 78");

    XCTAssertEqualObjects([message subdataWithRange:NSMakeRange(kIROffSPKSignSPK, 32)],
                          record.keyPair.publicKey.data);

    uint64_t notBefore = 0;
    uint64_t notAfter = 0;
    for (NSUInteger index = 0; index < 8; index++) {
        notBefore = (notBefore << 8) | bytes[kIROffSPKSignNotBefore + index];
        notAfter = (notAfter << 8) | bytes[kIROffSPKSignNotAfter + index];
    }
    XCTAssertEqual(notBefore, kNotBefore);
    XCTAssertEqual(notAfter, kNotAfter);
}

- (void)testSignedPreKeySignatureVerifies {
    IRSignedPreKeyRecord *record = [self makeSignedPreKey];

    NSError *error = nil;
    NSData *message = IRSPKSignMessage(self.bob.identityKeyPair,
                                       record.spkId,
                                       record.keyPair.publicKey,
                                       record.notBeforeS,
                                       record.notAfterS,
                                       &error);

    XCTAssertTrue([self.provider ed25519VerifySignature:record.signature
                                              ofMessage:message
                                              publicKey:self.bob.signingKeyPair.publicKey]);
}

- (void)testSignedPreKeySignatureBindsEveryCoveredField {
    /* §5.2: binding spk_id prevents transplanting a signature onto a different prekey slot; binding
       both identity keys ties the prekey to the whole identity; both timestamps sit inside the
       signature so an intermediary cannot extend the window. Each is checked by altering exactly
       one field and asserting the signature no longer verifies. */
    IRSignedPreKeyRecord *record = [self makeSignedPreKey];
    IRIdentity *other = [self makeIdentity];
    NSError *error = nil;

    IRIdentityKeyPair *alteredAgreement =
        [IRIdentityKeyPair pairWithSigningKey:self.bob.signingKeyPair.publicKey
                                 agreementKey:other.agreementKeyPair.publicKey
                                        error:&error];

    NSArray<NSData *> *altered = @[
        IRSPKSignMessage(self.bob.identityKeyPair, record.spkId + 1, record.keyPair.publicKey,
                         record.notBeforeS, record.notAfterS, &error),
        IRSPKSignMessage(self.bob.identityKeyPair, record.spkId, other.agreementKeyPair.publicKey,
                         record.notBeforeS, record.notAfterS, &error),
        IRSPKSignMessage(self.bob.identityKeyPair, record.spkId, record.keyPair.publicKey,
                         record.notBeforeS + 1, record.notAfterS, &error),
        IRSPKSignMessage(self.bob.identityKeyPair, record.spkId, record.keyPair.publicKey,
                         record.notBeforeS, record.notAfterS + 1, &error),
        IRSPKSignMessage(alteredAgreement, record.spkId, record.keyPair.publicKey,
                         record.notBeforeS, record.notAfterS, &error),
    ];

    for (NSUInteger index = 0; index < altered.count; index++) {
        XCTAssertNotNil(altered[index]);
        XCTAssertFalse([self.provider ed25519VerifySignature:record.signature
                                                   ofMessage:altered[index]
                                                   publicKey:self.bob.signingKeyPair.publicKey],
                       @"altered field %lu still verified", (unsigned long)index);
    }
}

#pragma mark - §5.5 fingerprint — vector X3DH-FP

- (void)testFingerprintIsSHA256OfTheSpecifiedSeventySevenByteInput {
    NSMutableData *input = [NSMutableData dataWithCapacity:kIRLenFPInput];
    [input appendData:[self dataFromHex:@"6e756e746975733a46503a7634"]];
    [input appendData:self.bob.signingKeyPair.publicKey.data];
    [input appendData:self.bob.agreementKeyPair.publicKey.data];

    XCTAssertEqual(input.length, (NSUInteger)kIRLenFPInput);
    XCTAssertEqual(input.length, (NSUInteger)77);

    NSError *error = nil;
    NSData *expected = [self.provider sha256OfData:input error:&error];
    XCTAssertNotNil(expected, @"%@", error);

    IRFingerprint *fingerprint = [self.bob fingerprint:&error];
    XCTAssertNotNil(fingerprint, @"%@", error);
    XCTAssertEqual(fingerprint.length, (NSUInteger)kIRLenFingerprint);
    XCTAssertEqualObjects(fingerprint.data, expected);
}

- (void)testFingerprintKeysOnThePairNotOnTheSigningKeyAlone {
    /* §5.5: "An application that keys on IK^s alone is not conformant." Two identity pairs sharing
       IK^s but differing in IK^d MUST fingerprint differently, or the swap attack §5.5 describes is
       invisible to a trust store. */
    IRIdentity *other = [self makeIdentity];
    NSError *error = nil;

    IRIdentityKeyPair *sameSigningDifferentAgreement =
        [IRIdentityKeyPair pairWithSigningKey:self.bob.signingKeyPair.publicKey
                                 agreementKey:other.agreementKeyPair.publicKey
                                        error:&error];
    XCTAssertNotNil(sameSigningDifferentAgreement, @"%@", error);

    IRFingerprint *original = [self.bob fingerprint:&error];
    IRFingerprint *swapped = [sameSigningDifferentAgreement fingerprintWithProvider:self.provider
                                                                             error:&error];

    XCTAssertNotNil(original);
    XCTAssertNotNil(swapped);
    XCTAssertFalse([original isEqualToFingerprint:swapped]);
}

#pragma mark - §4.4 scoping regression — checks 1–2 are X25519-only

- (void)testEd25519IdentityKeyWithHighBitSetIsAcceptedEverywhere {
    /* RFC 8032 §7.1's SHA(abc) vector: public key ec172b…e2bf, whose byte 31 is 0xbf — bit 255 SET
       and entirely valid, because there that bit is the sign of x (RFC 8032 §5.1.2).

       A port that applies §4.4 check 2 to Ed25519 rejects roughly half of all identities. The
       failure is intermittent and presents as ERR_BAD_SIGNATURE — that is, disguised as an active
       MITM. §5.3 rule 2 gets the scoping right by listing only IK^d, SPK and OPK; §4.4's heading
       does not, and that is the ambiguity this test pins down. */
    IRIdentity *identity =
        [self makeIdentityWithSigningSeedHex:
         @"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"];

    const uint8_t *signingBytes = identity.signingKeyPair.publicKey.constBytes;
    XCTAssertEqual(signingBytes[31] & 0x80, 0x80, @"vector precondition: bit 255 must be set");
    XCTAssertEqualObjects(identity.signingKeyPair.publicKey.data,
                          [self dataFromHex:
                           @"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"]);

    NSError *error = nil;
    NSData *bundleData =
        [IRPreKeyBundle serializeWithIdentity:identity.publicIdentity
                           signedPreKeyRecord:[self makeSignedPreKeyForIdentity:identity
                                                                          spkId:7
                                                                     notBeforeS:kNotBefore
                                                                      notAfterS:kNotAfter]
                         oneTimePreKeyRecords:[self makeOneTimePreKeys:1]
                                        error:&error];
    XCTAssertNotNil(bundleData, @"%@", error);

    IRPreKeyBundle *bundle = [self parseBundle:bundleData error:&error];
    XCTAssertNotNil(bundle, @"a valid identity was rejected for its Ed25519 high bit: %@", error);
    XCTAssertNil(error);
}

#pragma mark - §5.4 bundle encoding

- (void)testBundleByteLayoutMatchesTheSpecifiedOffsets {
    IRSignedPreKeyRecord *spk = [self makeSignedPreKey];
    NSArray<IROneTimePreKeyRecord *> *opks = [self makeOneTimePreKeys:1];

    NSError *error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:spk
                                   oneTimePreKeyRecords:opks
                                                  error:&error];
    XCTAssertNotNil(data, @"%@", error);
    XCTAssertEqual(data.length, (NSUInteger)287);

    const uint8_t *bytes = (const uint8_t *)data.bytes;

    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleMagic, 4)],
                          [self dataFromHex:@"4e544234"]);
    XCTAssertEqual(bytes[kIROffBundleVersion], 0x04);
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleIdentitySigning, 32)],
                          self.bob.signingKeyPair.publicKey.data);
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleIdentityAgreement, 32)],
                          self.bob.agreementKeyPair.publicKey.data);
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleIKB, 64)],
                          self.bob.binding.data);
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleSPK, 32)],
                          spk.keyPair.publicKey.data);
    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleSPKSig, 64)],
                          spk.signature.data);

    XCTAssertEqual(bytes[kIROffBundleSPKId], 0x11);
    XCTAssertEqual(bytes[kIROffBundleSPKId + 3], 0x44, @"spk_id must be big-endian");

    XCTAssertEqual(bytes[kIROffBundleOPKCount], 0x00);
    XCTAssertEqual(bytes[kIROffBundleOPKCount + 1], 0x01, @"opk_count must be big-endian");

    XCTAssertEqualObjects([data subdataWithRange:NSMakeRange(kIROffBundleOPKEntries +
                                                            kIROffBundleOPKEntryKey, 32)],
                          opks.firstObject.keyPair.publicKey.data);
}

- (void)testBundleRoundTripsWithNoOneTimePreKey {
    NSData *data = [self validBundleBytesWithOPKCount:0];
    XCTAssertEqual(data.length, (NSUInteger)251);

    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];

    XCTAssertNotNil(bundle, @"%@", error);
    XCTAssertNil(error);
    XCTAssertEqual(bundle.opkEntries.count, 0u);
    XCTAssertNil([bundle firstUsableOPKEntry], @"absent OPK is legitimate, not an error (§6.6)");
    XCTAssertEqual(bundle.spkId, 0x11223344u);
    XCTAssertEqual(bundle.notBeforeS, kNotBefore);
    XCTAssertEqual(bundle.notAfterS, kNotAfter);
    XCTAssertTrue([bundle.identity.keyPair isEqualToIdentityKeyPair:self.bob.identityKeyPair]);
    XCTAssertEqualObjects([bundle serializedData:&error], data, @"parse -> re-encode must be exact");
}

- (void)testBundleRoundTripsWithOneOneTimePreKey {
    NSError *error = nil;
    IRSignedPreKeyRecord *spk = [self makeSignedPreKey];
    IROneTimePreKeyRecord *opk = [self makeOneTimePreKeyWithId:0xDEADBEEF createdAt:kNotBefore];

    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:spk
                                   oneTimePreKeyRecords:@[opk]
                                                  error:&error];
    XCTAssertNotNil(data, @"%@", error);
    XCTAssertEqual(data.length, (NSUInteger)287);

    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];
    XCTAssertNotNil(bundle, @"%@", error);
    XCTAssertEqual(bundle.opkEntries.count, 1u);
    XCTAssertEqual([bundle firstUsableOPKEntry].opkId, 0xDEADBEEFu);
    XCTAssertTrue([[bundle firstUsableOPKEntry].publicKey
                   isEqualToX25519Public:opk.keyPair.publicKey]);
    XCTAssertEqualObjects([bundle serializedData:&error], data);
}

- (void)testPublishedBundleMayCarryManyButOnlyTheFirstIsUsable {
    /* §5.4: "A fetching client that receives more MUST use only the first entry, and MUST NOT treat
       additional entries as usable." A server that reissues an OPK degrades that handshake to the
       3-DH case in effect and MUST be treated as a bug. */
    NSError *error = nil;
    NSArray<IROneTimePreKeyRecord *> *opks = [self makeOneTimePreKeys:5];

    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:[self makeSignedPreKey]
                                   oneTimePreKeyRecords:opks
                                                  error:&error];
    XCTAssertEqual(data.length, (NSUInteger)(251 + 36 * 5));

    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];
    XCTAssertNotNil(bundle, @"%@", error);
    XCTAssertEqual(bundle.opkEntries.count, 5u);
    XCTAssertEqual([bundle firstUsableOPKEntry].opkId, opks.firstObject.opkId);
    XCTAssertEqual(bundle.opkEntries.firstObject.opkId, opks.firstObject.opkId,
                   @"entries must be in wire order");
}

- (void)testEncoderRefusesToEmitAboveTheOPKCountCap {
    /* A conformant encoder never produces a bundle §10.3 step 4 would reject. */
    NSMutableArray<IRPreKeyBundleOPKEntry *> *entries = [NSMutableArray array];
    NSError *error = nil;

    IRPreKeyBundleOPKEntry *entry =
        [IRPreKeyBundleOPKEntry entryWithOpkId:1
                                     publicKey:[self makeOneTimePreKeyWithId:1
                                                                   createdAt:kNotBefore]
                                                   .keyPair.publicKey
                                         error:&error];
    XCTAssertNotNil(entry, @"%@", error);

    for (NSUInteger index = 0; index <= (NSUInteger)kIRMaxBundleOPKCount; index++) {
        [entries addObject:entry];
    }

    IRSignedPreKeyRecord *spk = [self makeSignedPreKey];
    error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                                  spkId:spk.spkId
                                           signedPreKey:spk.keyPair.publicKey
                                             notBeforeS:spk.notBeforeS
                                              notAfterS:spk.notAfterS
                                  signedPreKeySignature:spk.signature
                                             opkEntries:entries
                                                  error:&error];

    XCTAssertNil(data);
    XCTAssertEqual(error.code, (NSInteger)IRErrorBundleMalformed);
}

#pragma mark - §10.3 ordered gate

- (void)testNegBundleEmpty {
    /* NEG-BUNDLE-EMPTY. The load at offset 249 is out of bounds on this input, and without step 1
       the three ports fail three different ways: a silent adjacent-heap read here, an uncatchable
       trap in Swift, an escaping IndexOutOfBoundsException on the JVM. */
    [self assertBundle:[NSData data]
          rejectedWith:IRErrorBundleMalformed
               message:@"NEG-BUNDLE-EMPTY"];
}

- (void)testNegBundleShortAtTheExactBoundary {
    /* NEG-BUNDLE-SHORT — 250 bytes, one below the fixed prefix, so opk_count at offset 249 spans
       the end of the buffer. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    [data setLength:(NSUInteger)kIRMinBundleLength - 1];

    XCTAssertEqual(data.length, 250u);
    [self assertBundle:data rejectedWith:IRErrorBundleMalformed message:@"NEG-BUNDLE-SHORT"];
}

- (void)testLengthFloorIsEvaluatedBeforeTheVersionByte {
    /* §10.3 step 1 MUST precede everything. This five-byte input has a VALID magic and an INVALID
       version, both at readable offsets: a parser that checks the version first answers
       ERR_UNSUPPORTED_VERSION, and a parser that honours the ordering answers
       ERR_BUNDLE_MALFORMED. Nothing else distinguishes the two orders. */
    NSMutableData *data = [NSMutableData dataWithBytes:"\x4e\x54\x42\x34\x03" length:5];

    [self assertBundle:data
          rejectedWith:IRErrorBundleMalformed
               message:@"length floor must precede the version check"];
}

- (void)testNegBundleMagic {
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleMagic] ^= 0xFF;

    [self assertBundle:data rejectedWith:IRErrorBundleMalformed message:@"NEG-BUNDLE-MAGIC"];
}

- (void)testMagicIsEvaluatedBeforeTheVersionByte {
    /* Wrong in both ways at once: §10.3 step 2 fires, so the code is ERR_BUNDLE_MALFORMED and not
       ERR_UNSUPPORTED_VERSION. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleMagic] ^= 0xFF;
    ((uint8_t *)data.mutableBytes)[kIROffBundleVersion] = 0x03;

    [self assertBundle:data
          rejectedWith:IRErrorBundleMalformed
               message:@"magic must precede version"];
}

- (void)testNegBundleVersion {
    /* NEG-BUNDLE-VERSION — the ONE bundle-structure failure that is not ERR_BUNDLE_MALFORMED.
       Version is a distinguishable condition with its own code and §10.3 step 3 assigns it
       deliberately. 0x03 is a v3 bundle: there is no downgrade path (§10.6). */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleVersion] = 0x03;

    [self assertBundle:data rejectedWith:IRErrorUnsupportedVersion message:@"NEG-BUNDLE-VERSION"];
}

- (void)testNegBundleOPKCountAboveCap {
    /* NEG-BUNDLE-OPKCOUNT — opk_count 1001 with a length consistent with it, so ONLY the cap can
       reject it. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;
    bytes[kIROffBundleOPKCount] = 0x03;
    bytes[kIROffBundleOPKCount + 1] = 0xE9;   /* 1001 */
    [data increaseLengthBy:(NSUInteger)kIRLenBundleOPKEntry * 1001];

    XCTAssertEqual(data.length, (NSUInteger)(251 + 36 * 1001));
    [self assertBundle:data rejectedWith:IRErrorBundleMalformed message:@"NEG-BUNDLE-OPKCOUNT"];
}

- (void)testOPKCountAtTheCapIsAccepted {
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;
    bytes[kIROffBundleOPKCount] = 0x03;
    bytes[kIROffBundleOPKCount + 1] = 0xE8;   /* 1000, exactly MAX_BUNDLE_OPK_COUNT */
    [data increaseLengthBy:(NSUInteger)kIRLenBundleOPKEntry * 1000];

    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];

    XCTAssertNotNil(bundle, @"the cap is inclusive: %@", error);
    XCTAssertEqual(bundle.opkEntries.count, 1000u);
}

- (void)testNegBundleLengthTooLong {
    /* NEG-BUNDLE-LEN, over-length direction. §19.4 / §10.5: this is ERR_BUNDLE_MALFORMED and NEVER
       ERR_TRAILING_BYTES — 7105 is for state blobs alone. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    [data increaseLengthBy:1];

    [self assertBundle:data
          rejectedWith:IRErrorBundleMalformed
               message:@"NEG-BUNDLE-LEN over-length"];

    NSError *error = nil;
    XCTAssertNil([self parseBundle:data error:&error]);
    XCTAssertNotEqual(error.code, (NSInteger)IRErrorTrailingBytes,
                      @"7105 is reserved for state blobs (§10.5, §19.4)");
}

- (void)testNegBundleLengthTooShort {
    /* NEG-BUNDLE-LEN, under-length direction, with opk_count >= 1 so the shortfall is inside the
       entry array rather than in the fixed prefix. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:1];
    [data setLength:data.length - 1];

    XCTAssertEqual(data.length, 286u);
    [self assertBundle:data
          rejectedWith:IRErrorBundleMalformed
               message:@"NEG-BUNDLE-LEN under-length"];
}

- (void)testEveryTruncationOfAValidBundleIsRejectedCleanly {
    /* §1.3 property 5 applied exhaustively: no length, offset or allocation size may be derived
       from received bytes before authentication. Every prefix must produce a specified error and
       must not trap. */
    NSData *valid = [self validBundleBytesWithOPKCount:2];

    for (NSUInteger length = 0; length < valid.length; length++) {
        NSError *error = nil;
        IRPreKeyBundle *bundle = [self parseBundle:[valid subdataWithRange:NSMakeRange(0, length)]
                                             error:&error];

        XCTAssertNil(bundle, @"prefix of %lu bytes was accepted", (unsigned long)length);
        XCTAssertEqual(error.code, (NSInteger)IRErrorBundleMalformed,
                       @"prefix of %lu bytes", (unsigned long)length);
    }
}

#pragma mark - §5.3 rules 2–4, and their order

- (void)testNegPublicKeyHighBitInIdentityAgreementKey {
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleIdentityAgreement + 31] |= 0x80;

    [self assertBundle:data
          rejectedWith:IRErrorInvalidPublicKey
               message:@"IK^d with bit 255 set"];
}

- (void)testNegPublicKeyHighBitInSignedPreKey {
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleSPK + 31] |= 0x80;

    [self assertBundle:data
          rejectedWith:IRErrorInvalidPublicKey
               message:@"SPK with bit 255 set"];
}

- (void)testPublicKeyValidationPrecedesSignatureVerification {
    /* §5.3 rule 2 BEFORE rules 3–4. This bundle is wrong in two ways at once — a high-bit SPK and a
       corrupted IKB — and only the ordering decides the code. A parser that verifies signatures
       first because they are the cheaper early exit returns ERR_BAD_SIGNATURE here. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;
    bytes[kIROffBundleSPK + 31] |= 0x80;
    bytes[kIROffBundleIKB] ^= 0xFF;

    [self assertBundle:data
          rejectedWith:IRErrorInvalidPublicKey
               message:@"§5.3 rule 2 must precede rules 3–4"];
}

- (void)testEveryOneTimePreKeyIsValidatedBeforeSignatures {
    /* Rule 2 says "every OPK". The corruption is in the LAST entry, and the signatures are broken
       too, so a parser that validates only the first OPK — or that verifies signatures first —
       returns ERR_BAD_SIGNATURE instead. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:3];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;

    NSUInteger lastEntry = (NSUInteger)kIROffBundleOPKEntries + (NSUInteger)kIRLenBundleOPKEntry * 2;
    bytes[lastEntry + kIROffBundleOPKEntryKey + 31] |= 0x80;
    bytes[kIROffBundleIKB] ^= 0xFF;
    bytes[kIROffBundleSPKSig] ^= 0xFF;

    [self assertBundle:data
          rejectedWith:IRErrorInvalidPublicKey
               message:@"rule 2 covers every OPK and precedes rules 3–4"];
}

- (void)testNegIKBSwap {
    /* NEG-IKB-SWAP — the victim's genuine IK^s and IKB, with an attacker-chosen IK^d spliced in.
       Without IKB covering both keys the attacker would complete a cryptographically sound session
       and be attributed to the victim by any implementation that looks up contacts by IK^s. */
    IRIdentity *attacker = [self makeIdentity];

    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    [data replaceBytesInRange:NSMakeRange(kIROffBundleIdentityAgreement, kIRLenX25519Public)
                    withBytes:attacker.agreementKeyPair.publicKey.constBytes];

    [self assertBundle:data rejectedWith:IRErrorBadSignature message:@"NEG-IKB-SWAP"];
}

- (void)testNegIKBCorrupted {
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleIKB + 10] ^= 0x01;

    [self assertBundle:data rejectedWith:IRErrorBadSignature message:@"corrupted IKB"];
}

- (void)testNegSPKSigBad {
    /* NEG-SPKSIG-BAD. v3 never reached an equivalent check: IRTripleDHService.m:66-68 re-signed the
       peer's prekey with the LOCAL identity key, overwriting the evidence with a locally
       manufactured signature that later code found "valid". That code is deleted (§5.3). */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleSPKSig + 5] ^= 0x01;

    [self assertBundle:data rejectedWith:IRErrorBadSignature message:@"NEG-SPKSIG-BAD"];
}

- (void)testSignedPreKeySignedByADifferentIdentityIsRejected {
    /* The transplant §5.2 exists to prevent: a well-formed signature over a well-formed message,
       made by the wrong identity. */
    IRIdentity *attacker = [self makeIdentity];
    IRSignedPreKeyRecord *attackerSigned = [self makeSignedPreKeyForIdentity:attacker
                                                                      spkId:0x11223344
                                                                 notBeforeS:kNotBefore
                                                                  notAfterS:kNotAfter];

    NSError *error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                                  spkId:attackerSigned.spkId
                                           signedPreKey:attackerSigned.keyPair.publicKey
                                             notBeforeS:attackerSigned.notBeforeS
                                              notAfterS:attackerSigned.notAfterS
                                  signedPreKeySignature:attackerSigned.signature
                                             opkEntries:@[]
                                                  error:&error];
    XCTAssertNotNil(data, @"%@", error);

    [self assertBundle:data
          rejectedWith:IRErrorBadSignature
               message:@"SPK_SIG from a foreign identity"];
}

- (void)testSpkIdIsCoveredBySignatureInsideTheBundle {
    /* End-to-end version of the transplant check: alter spk_id in the encoded bundle and the
       signature no longer covers it. */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleSPKId + 3] ^= 0x01;

    [self assertBundle:data rejectedWith:IRErrorBadSignature message:@"spk_id is signed"];
}

- (void)testValidityWindowIsCoveredBySignatureInsideTheBundle {
    /* §5.2: "Both timestamps are inside the signature, so the validity window cannot be extended by
       an intermediary." */
    NSMutableData *data = [self validBundleBytesWithOPKCount:0];
    ((uint8_t *)data.mutableBytes)[kIROffBundleNotAfter + 7] ^= 0x01;

    [self assertBundle:data rejectedWith:IRErrorBadSignature message:@"not_after is signed"];
}

#pragma mark - §5.3 rules 5–6 — vectors NEG-SPK-EXPIRED, NEG-SPK-WINDOW-TOO-LONG

- (void)testParsingReadsNoClock {
    /* §15.3: wire.json's bundle vectors are encoding-only — they assert §5.4's layout and §10.3's
       structural gate, read no clock and supply no now_s. A parser that folded rules 5–6 in would
       make those vectors unreproducible, and §15.6 step 4 forbids regenerating them. */
    NSError *error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:[self makeSignedPreKeyForIdentity:self.bob
                                                                                    spkId:1
                                                                               notBeforeS:1000
                                                                                notAfterS:2000]
                                   oneTimePreKeyRecords:@[]
                                                  error:&error];

    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];
    XCTAssertNotNil(bundle, @"a long-expired window must still PARSE: %@", error);

    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNowInsideWindow error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorPreKeyExpired);
}

- (void)testValidityWindowBoundariesAreHalfOpen {
    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:[self validBundleBytesWithOPKCount:0] error:&error];
    XCTAssertNotNil(bundle, @"%@", error);

    /* not_before <= now < not_after */
    XCTAssertTrue([bundle validateValidityWindowAtUnixSeconds:kNotBefore error:NULL],
                  @"the lower bound is INCLUSIVE");
    XCTAssertTrue([bundle validateValidityWindowAtUnixSeconds:kNotAfter - 1 error:NULL]);
    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNotAfter error:NULL],
                   @"the upper bound is EXCLUSIVE");
    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNotBefore - 1 error:NULL]);
}

- (void)testNegSPKExpired {
    /* NEG-SPK-EXPIRED — fixed literals with an injected now_s OUTSIDE the window, so the rejection
       is CAUSED rather than merely observed. */
    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:[self validBundleBytesWithOPKCount:0] error:&error];

    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNotAfter + 1 error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorPreKeyExpired);

    error = nil;
    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNotBefore - 1000 error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorPreKeyExpired);
}

- (void)testNegSPKWindowTooLong {
    /* NEG-SPK-WINDOW-TOO-LONG — now_s INSIDE the window, so only rule 6 can reject it. */
    uint64_t notAfter = kNotBefore + (uint64_t)kIRMaxSPKValiditySeconds + 1;

    NSError *error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:[self makeSignedPreKeyForIdentity:self.bob
                                                                                    spkId:1
                                                                               notBeforeS:kNotBefore
                                                                                notAfterS:notAfter]
                                   oneTimePreKeyRecords:@[]
                                                  error:&error];

    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];
    XCTAssertNotNil(bundle, @"an over-long window must still PARSE: %@", error);

    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:kNowInsideWindow error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorPreKeyExpired);
}

- (void)testWindowExactlyAtTheCapIsAccepted {
    uint64_t notAfter = kNotBefore + (uint64_t)kIRMaxSPKValiditySeconds;

    NSError *error = nil;
    NSData *data = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                     signedPreKeyRecord:[self makeSignedPreKeyForIdentity:self.bob
                                                                                    spkId:1
                                                                               notBeforeS:kNotBefore
                                                                                notAfterS:notAfter]
                                   oneTimePreKeyRecords:@[]
                                                  error:&error];

    IRPreKeyBundle *bundle = [self parseBundle:data error:&error];
    XCTAssertNotNil(bundle, @"%@", error);
    XCTAssertTrue([bundle validateValidityWindowAtUnixSeconds:kNowInsideWindow error:&error],
                  @"the 90-day cap is inclusive: %@", error);
}

#pragma mark - §5.3 signed prekey retention

- (void)testSignedPreKeyResolvesForCurrentAndExactlyOnePrevious {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IRSignedPreKeyRecord *first = [store rotateSignedPreKeyWithIdentity:self.bob
                                                                  spkId:1
                                                             notBeforeS:kNotBefore
                                                              notAfterS:kNotAfter
                                                               provider:self.provider
                                                                  error:&error];
    XCTAssertNotNil(first, @"%@", error);
    XCTAssertEqual([store currentSignedPreKeyRecord].spkId, 1u);

    IRSignedPreKeyRecord *second = [store rotateSignedPreKeyWithIdentity:self.bob
                                                                   spkId:2
                                                              notBeforeS:kNotBefore
                                                               notAfterS:kNotAfter
                                                                provider:self.provider
                                                                   error:&error];
    XCTAssertNotNil(second, @"%@", error);
    XCTAssertEqual([store currentSignedPreKeyRecord].spkId, 2u);
    XCTAssertEqual([store previousSignedPreKeyRecord].spkId, 1u);

    /* §5.3 — messages already in flight against a just-rotated spk_id still decrypt. */
    XCTAssertNotNil([store signedPreKeyRecordForId:2 error:&error]);
    XCTAssertNotNil([store signedPreKeyRecordForId:1 error:&error]);
}

- (void)testSignedPreKeyTwoRotationsAgoIsUnknownAndZeroized {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IRSignedPreKeyRecord *first = [store rotateSignedPreKeyWithIdentity:self.bob
                                                                  spkId:1
                                                             notBeforeS:kNotBefore
                                                              notAfterS:kNotAfter
                                                               provider:self.provider
                                                                  error:&error];
    XCTAssertFalse([first.keyPair.privateKey isAllZero]);

    (void)[store rotateSignedPreKeyWithIdentity:self.bob spkId:2 notBeforeS:kNotBefore
                                      notAfterS:kNotAfter provider:self.provider error:&error];
    (void)[store rotateSignedPreKeyWithIdentity:self.bob spkId:3 notBeforeS:kNotBefore
                                      notAfterS:kNotAfter provider:self.provider error:&error];

    error = nil;
    XCTAssertNil([store signedPreKeyRecordForId:1 error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);

    /* §13.3 — the key left the {current, one previous} set, so its private half MUST have been
       zeroized IN PLACE, not merely unlinked. */
    XCTAssertTrue([first.keyPair.privateKey isAllZero],
                  @"a retired SPK private must be wiped, not just dropped");
}

- (void)testSignedPreKeyResolutionIgnoresTheValidityWindow {
    /* A responder that additionally rejected a just-expired spk_id at resolution time would drop
       messages legitimately sent moments before expiry. Retention policy is enforced by pruning. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    (void)[store rotateSignedPreKeyWithIdentity:self.bob spkId:9 notBeforeS:kNotBefore
                                      notAfterS:kNotAfter provider:self.provider error:&error];

    XCTAssertNotNil([store signedPreKeyRecordForId:9 error:&error]);

    XCTAssertTrue([store pruneExpiredAtUnixSeconds:kNotAfter + 1 error:&error]);

    error = nil;
    XCTAssertNil([store signedPreKeyRecordForId:9 error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
    XCTAssertNil([store currentSignedPreKeyRecord],
                 @"§13.3 makes not_after the LATEST moment an SPK private may be retained");
}

- (void)testDeepCopyIsWhatKeepsAStoreOwnedSignedPreKeyAlive {
    /* The unit-level form of NEG-SPK-SURVIVES-RATCHET (§15.4), the only vector in the suite that
       distinguishes a port which COPIES the signed prekey private from one which ALIASES it.

       §7.5 has the responder's initial DHs be a copy of SPK_B; §7.4 step 4 zeroizes that copy when
       the ratchet turns; §5.3 gives the prekey store exclusive ownership of the original, whose
       lifetime "no ratchet operation may shorten". Aliasing destroys, on the first routine ratchet
       step, a key that a second initiator's in-flight handshake still needs. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    (void)[store rotateSignedPreKeyWithIdentity:self.bob spkId:5 notBeforeS:kNotBefore
                                      notAfterS:kNotAfter provider:self.provider error:&error];

    IRSignedPreKeyRecord *record = [store signedPreKeyRecordForId:5 error:&error];
    XCTAssertNotNil(record, @"%@", error);

    IRX25519KeyPair *sessionOwnedCopy = [record.keyPair deepCopy];
    XCTAssertNotNil(sessionOwnedCopy);
    XCTAssertTrue([sessionOwnedCopy.publicKey isEqualToX25519Public:record.keyPair.publicKey]);

    /* §7.4 step 4 zeroizes the SESSION-OWNED copy. */
    [sessionOwnedCopy zeroize];

    XCTAssertTrue([sessionOwnedCopy.privateKey isAllZero]);
    XCTAssertFalse([record.keyPair.privateKey isAllZero],
                   @"the prekey store's original MUST survive a ratchet step");

    IRSignedPreKeyRecord *reread = [store signedPreKeyRecordForId:5 error:&error];
    XCTAssertNotNil(reread);
    XCTAssertFalse([reread.keyPair.privateKey isAllZero]);
}

#pragma mark - §5.3 / §6.6 one-time prekeys

- (void)testNegOPKUnknown {
    /* NEG-OPK-UNKNOWN. §6.6 rule 2: there is NO fallback to the 3-DH derivation. Rejecting rather
       than falling back is what converts OPK consumption into replay protection. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    XCTAssertTrue([store storeOneTimePreKeyRecords:[self makeOneTimePreKeys:2] error:&error]);

    XCTAssertNil([store oneTimePreKeyRecordForId:0xFFFFFFFF
                                   atUnixSeconds:kNowInsideWindow
                                           error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
}

- (void)testDuplicateOPKIdsWithinOneBatchAreRefusedBeforeAnythingIsStored {
    /* The regression this exists for: the store used to resolve a same-id collision by ZEROIZING
       the displaced record and installing the new one. The displaced record was still in the
       caller's array — -[IRMessenger publishBundleWithSPKId:...] hands the very same array to
       IRPreKeyBundle on the next line — so the published bundle advertised one opk_id twice, with
       two different public keys, and the private half of the first was already wiped. An initiator
       selecting that entry computes DH4 against a zeroized scalar; B derives a different SK and
       reports ERR_AEAD_AUTH_FAILED, which §1.2 defines as an active MITM.

       Refused as a BATCH so the store and the bundle the caller is about to publish cannot
       disagree — a partial apply leaves them inconsistent in a way no error code describes. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IROneTimePreKeyRecord *first = [self makeOneTimePreKeyWithId:0x2000 createdAt:kNotBefore];
    IROneTimePreKeyRecord *second = [self makeOneTimePreKeyWithId:0x2000 createdAt:kNotBefore];
    XCTAssertFalse([first.keyPair.publicKey isEqualToX25519Public:second.keyPair.publicKey],
                   @"two generated records must not share key material");

    /* Doubled parentheses: the comma in an @[] literal is otherwise read as an XCTAssert macro
       argument separator. */
    XCTAssertFalse(([store storeOneTimePreKeyRecords:@[first, second] error:&error]));
    XCTAssertEqual(error.code, (NSInteger)IRErrorStateCorrupt);
    XCTAssertEqual(store.oneTimePreKeyCount, 0u, @"a refused batch must store nothing");

    /* And neither record was wiped on the way out — the caller still owns them. */
    XCTAssertFalse([first.keyPair.privateKey isAllZero]);
    XCTAssertFalse([second.keyPair.privateKey isAllZero]);
}

- (void)testAnOPKIdAlreadyResidentUnderDifferentKeyMaterialIsRefused {
    /* The same collision spread across two calls. Checked before any mutation, so the earlier
       generation survives intact rather than being zeroized out from under a bundle that is
       already published and that initiators may already hold. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IROneTimePreKeyRecord *original = [self makeOneTimePreKeyWithId:0x3000 createdAt:kNotBefore];
    XCTAssertTrue([store storeOneTimePreKeyRecords:@[original] error:&error], @"%@", error);

    IROneTimePreKeyRecord *collision = [self makeOneTimePreKeyWithId:0x3000 createdAt:kNotBefore];
    IROneTimePreKeyRecord *innocent = [self makeOneTimePreKeyWithId:0x3001 createdAt:kNotBefore];

    XCTAssertFalse(([store storeOneTimePreKeyRecords:@[innocent, collision] error:&error]));
    XCTAssertEqual(error.code, (NSInteger)IRErrorStateCorrupt);

    XCTAssertEqual(store.oneTimePreKeyCount, 1u, @"the batch is atomic: `innocent` is not stored");
    XCTAssertFalse([original.keyPair.privateKey isAllZero],
                   @"the resident generation must survive a refused collision");

    IROneTimePreKeyRecord *resolved = [store oneTimePreKeyRecordForId:0x3000
                                                        atUnixSeconds:kNowInsideWindow
                                                                error:&error];
    XCTAssertEqual(resolved, original);
}

- (void)testReStoringTheIdenticalOPKRecordIsIdempotent {
    /* The legitimate same-id case: same id, same object. Must not be mistaken for a collision. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IROneTimePreKeyRecord *record = [self makeOneTimePreKeyWithId:0x4000 createdAt:kNotBefore];
    XCTAssertTrue([store storeOneTimePreKeyRecords:@[record] error:&error], @"%@", error);
    XCTAssertTrue([store storeOneTimePreKeyRecords:@[record] error:&error], @"%@", error);

    XCTAssertEqual(store.oneTimePreKeyCount, 1u);
    XCTAssertFalse([record.keyPair.privateKey isAllZero], @"an idempotent re-store must not wipe");
}

- (void)testNegOPKExpired {
    /* NEG-OPK-EXPIRED — an OPK whose local creation timestamp is older than OPK_MAX_AGE_S, with an
       injected now_s. §5.3 requires the entry to have been DELETED, not merely hidden: this bounds
       §1.2's "identity AND signed prekey compromised" row, where DH4 is the only remaining
       forward-secrecy term. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IROneTimePreKeyRecord *record = [self makeOneTimePreKeyWithId:77 createdAt:kNotBefore];
    XCTAssertTrue([store storeOneTimePreKeyRecords:@[record] error:&error]);
    XCTAssertEqual(store.oneTimePreKeyCount, 1u);

    uint64_t expiredAt = kNotBefore + (uint64_t)kIROPKMaxAgeSeconds;

    XCTAssertNil([store oneTimePreKeyRecordForId:77 atUnixSeconds:expiredAt error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
    XCTAssertEqual(store.oneTimePreKeyCount, 0u, @"§5.3 requires DELETION, not concealment");
    XCTAssertTrue([record.keyPair.privateKey isAllZero], @"§13.3 requires an in-place wipe");
}

- (void)testOPKOneSecondInsideMaxAgeStillResolves {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    [store storeOneTimePreKeyRecords:@[[self makeOneTimePreKeyWithId:77 createdAt:kNotBefore]]
                              error:&error];

    uint64_t justInside = kNotBefore + (uint64_t)kIROPKMaxAgeSeconds - 1;
    XCTAssertNotNil([store oneTimePreKeyRecordForId:77 atUnixSeconds:justInside error:&error]);
}

- (void)testExpiredOPKsAreNeverPublished {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    [store storeOneTimePreKeyRecords:@[
        [self makeOneTimePreKeyWithId:1 createdAt:kNotBefore],
        [self makeOneTimePreKeyWithId:2 createdAt:kNotBefore + 10000],
    ] error:&error];

    uint64_t now = kNotBefore + (uint64_t)kIROPKMaxAgeSeconds + 1;
    NSArray<IROneTimePreKeyRecord *> *publishable =
        [store unconsumedOneTimePreKeyRecordsWithLimit:NSUIntegerMax atUnixSeconds:now];

    XCTAssertEqual(publishable.count, 1u);
    XCTAssertEqual(publishable.firstObject.opkId, 2u);
}

- (void)testUnconsumedOPKsArePublishedInInsertionOrderAndRespectTheLimit {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    NSArray<IROneTimePreKeyRecord *> *records = [self makeOneTimePreKeys:5];
    [store storeOneTimePreKeyRecords:records error:&error];

    NSArray<IROneTimePreKeyRecord *> *published =
        [store unconsumedOneTimePreKeyRecordsWithLimit:3 atUnixSeconds:kNowInsideWindow];

    XCTAssertEqual(published.count, 3u);
    for (NSUInteger index = 0; index < published.count; index++) {
        XCTAssertEqual(published[index].opkId, records[index].opkId);
    }

    XCTAssertEqual([store unconsumedOneTimePreKeyRecordsWithLimit:0
                                                    atUnixSeconds:kNowInsideWindow].count, 0u);
}

- (void)testConsumptionZeroizesInPlaceBeforeUnlinking {
    /* §6.6 step 4 + §13.3. "An unlink alone — Map.remove, removeObjectForKey:, a Swift subscript
       assignment to nil — is NOT sufficient: it releases the reference and leaves the scalar
       resident in the heap." Holding a strong reference across the consumption is what makes the
       difference observable. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IROneTimePreKeyRecord *record = [self makeOneTimePreKeyWithId:42 createdAt:kNotBefore];
    [store storeOneTimePreKeyRecords:@[record] error:&error];
    XCTAssertFalse([record.keyPair.privateKey isAllZero]);

    XCTAssertTrue([store consumeOneTimePreKeyId:42 error:&error]);

    XCTAssertTrue([record.keyPair.privateKey isAllZero],
                  @"the scalar must be wiped in place, not merely unlinked");
    XCTAssertEqual(store.oneTimePreKeyCount, 0u);
}

- (void)testASecondConsumptionReportsUnknownAndNeverAlreadyConsumed {
    /* Plan gap G1. §6.6 step 4 leaves NO tombstone, so a consumed OPK is indistinguishable from one
       that never existed, and ERR_OPK_ALREADY_CONSUMED (7115) is unreachable as specified. This
       implementation never emits it; if the specification later adds a tombstone, this assertion is
       the one that must change. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    [store storeOneTimePreKeyRecords:@[[self makeOneTimePreKeyWithId:42 createdAt:kNotBefore]]
                              error:&error];

    XCTAssertTrue([store consumeOneTimePreKeyId:42 error:&error]);

    error = nil;
    XCTAssertFalse([store consumeOneTimePreKeyId:42 error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
    XCTAssertNotEqual(error.code, (NSInteger)IRErrorOPKAlreadyConsumed);

    error = nil;
    XCTAssertNil([store oneTimePreKeyRecordForId:42 atUnixSeconds:kNowInsideWindow error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
}

- (void)testConsumingAnUnknownIdFailsWithoutMutatingTheStore {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    [store storeOneTimePreKeyRecords:[self makeOneTimePreKeys:3] error:&error];

    error = nil;
    XCTAssertFalse([store consumeOneTimePreKeyId:0xABCDEF error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorUnknownPreKeyId);
    XCTAssertEqual(store.oneTimePreKeyCount, 3u);
}

- (void)testStoreZeroizesEverythingOnErasure {
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];
    NSError *error = nil;

    IRSignedPreKeyRecord *spk = [store rotateSignedPreKeyWithIdentity:self.bob
                                                                spkId:1
                                                           notBeforeS:kNotBefore
                                                            notAfterS:kNotAfter
                                                             provider:self.provider
                                                                error:&error];
    IROneTimePreKeyRecord *opk = [self makeOneTimePreKeyWithId:1 createdAt:kNotBefore];
    [store storeOneTimePreKeyRecords:@[opk] error:&error];

    [store zeroizeAll];

    XCTAssertTrue([spk.keyPair.privateKey isAllZero]);
    XCTAssertTrue([opk.keyPair.privateKey isAllZero]);
    XCTAssertEqual(store.oneTimePreKeyCount, 0u);
    XCTAssertNil([store currentSignedPreKeyRecord]);
}

#pragma mark - §5.1, §5.5 identity

- (void)testGeneratedIdentityHasTwoIndependentKeyPairs {
    /* §4.1 — the Ed25519→X25519 conversion trick is GONE, so the two public keys are unrelated. */
    XCTAssertEqual(self.bob.signingKeyPair.publicKey.length, (NSUInteger)32);
    XCTAssertEqual(self.bob.agreementKeyPair.publicKey.length, (NSUInteger)32);
    XCTAssertEqual(self.bob.signingKeyPair.seed.length, (NSUInteger)32,
                   @"the private half is the RFC 8032 SEED, never libsodium's 64-byte expanded sk");
    XCTAssertNotEqualObjects(self.bob.signingKeyPair.publicKey.data,
                             self.bob.agreementKeyPair.publicKey.data);

    IRIdentity *other = [self makeIdentity];
    XCTAssertFalse([self.bob.identityKeyPair isEqualToIdentityKeyPair:other.identityKeyPair]);
}

- (void)testIdentityBindingIsStoredNotRecomputed {
    /* §5.1: "IKB is a long-lived value stored alongside the identity. It MUST be stored, not
       recomputed on demand." §11.3 depends on it: the type 0x02 header re-emits these exact bytes
       on every prekey message. */
    NSData *first = self.bob.binding.data;
    NSData *second = self.bob.binding.data;

    XCTAssertEqualObjects(first, second);
    XCTAssertEqual(self.bob.binding.length, (NSUInteger)64);
    XCTAssertTrue([self.bob.publicIdentity.binding isEqualToEd25519Signature:self.bob.binding]);
}

- (void)testIdentityRestoreVerifiesTheStoredBinding {
    /* §5.5 — IKB MUST be verified on every ingest, INCLUDING after state restore. */
    NSError *error = nil;

    IRIdentity *restored = [IRIdentity identityWithSigningKeyPair:self.bob.signingKeyPair
                                                 agreementKeyPair:self.bob.agreementKeyPair
                                                          binding:self.bob.binding
                                                         provider:self.provider
                                                            error:&error];
    XCTAssertNotNil(restored, @"%@", error);
    XCTAssertTrue([restored.identityKeyPair isEqualToIdentityKeyPair:self.bob.identityKeyPair]);

    NSMutableData *corrupted = [self.bob.binding.data mutableCopy];
    ((uint8_t *)corrupted.mutableBytes)[0] ^= 0x01;

    IREd25519Signature *badBinding = [IREd25519Signature fromData:corrupted error:&error];
    error = nil;

    IRIdentity *rejected = [IRIdentity identityWithSigningKeyPair:self.bob.signingKeyPair
                                                 agreementKeyPair:self.bob.agreementKeyPair
                                                          binding:badBinding
                                                         provider:self.provider
                                                            error:&error];
    XCTAssertNil(rejected);
    XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature);

    /* §10.5 — and it must not dereference a NULL out-parameter. */
    XCTAssertNil([IRIdentity identityWithSigningKeyPair:self.bob.signingKeyPair
                                       agreementKeyPair:self.bob.agreementKeyPair
                                                binding:badBinding
                                               provider:self.provider
                                                  error:NULL]);
}

- (void)testAnUnverifiedPublicIdentityCannotBeConstructed {
    /* The whole point of the type: §5.5's "verified on every identity ingest" is discharged by
       construction, not by four remembered call sites. */
    IRIdentity *attacker = [self makeIdentity];
    NSError *error = nil;

    IRIdentityKeyPair *swapped =
        [IRIdentityKeyPair pairWithSigningKey:self.bob.signingKeyPair.publicKey
                                 agreementKey:attacker.agreementKeyPair.publicKey
                                        error:&error];

    error = nil;
    IRPublicIdentity *forged = [IRPublicIdentity identityWithKeyPair:swapped
                                                             binding:self.bob.binding
                                                            provider:self.provider
                                                               error:&error];
    XCTAssertNil(forged, @"NEG-IKB-SWAP at the type level");
    XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature);
}

- (void)testIdentityZeroizeWipesBothPrivateHalves {
    IRIdentity *identity = [self makeIdentity];

    XCTAssertFalse([identity.signingKeyPair.seed isAllZero]);
    XCTAssertFalse([identity.agreementKeyPair.privateKey isAllZero]);

    [identity zeroize];

    XCTAssertTrue([identity.signingKeyPair.seed isAllZero]);
    XCTAssertTrue([identity.agreementKeyPair.privateKey isAllZero]);
}

- (void)testIdentitySignsWithTheSigningKeyOnly {
    NSData *message = [@"nuntius" dataUsingEncoding:NSUTF8StringEncoding];

    NSError *error = nil;
    IREd25519Signature *signature = [self.bob signData:message error:&error];

    XCTAssertNotNil(signature, @"%@", error);
    XCTAssertTrue([self.provider ed25519VerifySignature:signature
                                              ofMessage:message
                                              publicKey:self.bob.signingKeyPair.publicKey]);
}

#pragma mark - §11.1 / §6.5 identity as an index key

- (void)testIdentityKeyPairIsRawPairOrderedSigningThenAgreement {
    IRIdentityKeyPair *pair = self.bob.identityKeyPair;

    XCTAssertEqual(pair.rawPair.length, (NSUInteger)kIRLenIdentityPair);
    XCTAssertEqual(pair.rawPair.length, (NSUInteger)64);
    XCTAssertEqualObjects([pair.rawPair subdataWithRange:NSMakeRange(0, 32)],
                          self.bob.signingKeyPair.publicKey.data);
    XCTAssertEqualObjects([pair.rawPair subdataWithRange:NSMakeRange(32, 32)],
                          self.bob.agreementKeyPair.publicKey.data);
}

- (void)testIdentityKeyPairRoundTripsThroughItsRawBytesAndWorksAsADictionaryKey {
    /* §11.1 keys the single-live-session invariant on the peer identity pair, recovered from
       SESSION_AD where no signature is available — so this type must be constructible from bytes
       alone and usable as a hash key. */
    NSError *error = nil;
    IRIdentityKeyPair *restored = [IRIdentityKeyPair pairFromData:self.bob.identityKeyPair.rawPair
                                                            error:&error];

    XCTAssertNotNil(restored, @"%@", error);
    XCTAssertTrue([restored isEqualToIdentityKeyPair:self.bob.identityKeyPair]);
    XCTAssertEqualObjects(restored, self.bob.identityKeyPair);
    XCTAssertEqual(restored.hash, self.bob.identityKeyPair.hash);

    NSMutableDictionary *sessions = [NSMutableDictionary dictionary];
    sessions[self.bob.identityKeyPair] = @"session";
    XCTAssertEqualObjects(sessions[restored], @"session");
}

- (void)testIdentityKeyPairRejectsWrongLengthAndInvalidAgreementKey {
    NSError *error = nil;

    XCTAssertNil([IRIdentityKeyPair pairFromData:[NSMutableData dataWithLength:63] error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorInvalidPublicKey);

    error = nil;
    XCTAssertNil([IRIdentityKeyPair pairFromData:[NSMutableData dataWithLength:65] error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorInvalidPublicKey);

    /* §4.4 check 2 on the X25519 half only. */
    NSMutableData *highBit = [self.bob.identityKeyPair.rawPair mutableCopy];
    ((uint8_t *)highBit.mutableBytes)[63] |= 0x80;

    error = nil;
    XCTAssertNil([IRIdentityKeyPair pairFromData:highBit error:&error]);
    XCTAssertEqual(error.code, (NSInteger)IRErrorInvalidPublicKey);

    /* …and NOT on the Ed25519 half: flipping bit 255 of IK^s yields a different but structurally
       acceptable pair. */
    NSMutableData *signingHighBit = [self.bob.identityKeyPair.rawPair mutableCopy];
    ((uint8_t *)signingHighBit.mutableBytes)[31] |= 0x80;

    error = nil;
    XCTAssertNotNil([IRIdentityKeyPair pairFromData:signingHighBit error:&error],
                    @"§4.4 checks 1–2 are X25519-only");
}

#pragma mark - §10.5 error discipline

- (void)testEveryFailurePathToleratesANullErrorOutParameter {
    /* v3's aeEncryptSimpleData: and aeDecryptSimpleData: wrote `*error = err` with no null check,
       crashing every caller that passed NULL — which every test in the repository did. */
    IRInMemoryPreKeyStore *store = [IRInMemoryPreKeyStore store];

    XCTAssertNil([self parseBundle:[NSData data] error:NULL]);
    XCTAssertNil([self parseBundle:[NSMutableData dataWithLength:251] error:NULL]);
    XCTAssertNil([store signedPreKeyRecordForId:1 error:NULL]);
    XCTAssertNil([store oneTimePreKeyRecordForId:1 atUnixSeconds:0 error:NULL]);
    XCTAssertFalse([store consumeOneTimePreKeyId:1 error:NULL]);
    XCTAssertNil([IRIdentityKeyPair pairFromData:[NSData data] error:NULL]);

    NSError *error = nil;
    IRPreKeyBundle *bundle = [self parseBundle:[self validBundleBytesWithOPKCount:0] error:&error];
    XCTAssertFalse([bundle validateValidityWindowAtUnixSeconds:0 error:NULL]);
}

- (void)testErrorCodesUsedByThisLayerMatchTheTaxonomy {
    XCTAssertEqual((NSInteger)IRErrorInvalidPublicKey, 7106);
    XCTAssertEqual((NSInteger)IRErrorBadSignature, 7108);
    XCTAssertEqual((NSInteger)IRErrorUnknownPreKeyId, 7114);
    XCTAssertEqual((NSInteger)IRErrorPreKeyExpired, 7116);
    XCTAssertEqual((NSInteger)IRErrorBundleMalformed, 7122);
    XCTAssertEqual((NSInteger)IRErrorUnsupportedVersion, 7100);

    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorBundleMalformed), @"ERR_BUNDLE_MALFORMED");
    XCTAssertEqualObjects(IRErrorNameForCode(IRErrorPreKeyExpired), @"ERR_PREKEY_EXPIRED");
}

@end
