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
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRProtocolConstants.h"
#import "IRProtocolKDF.h"
#import "IRPublicIdentity.h"
#import "IRSecretBytes.h"
#import "IRSessionAD.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRTranscript.h"
#import "IRX3DH.h"

/**
 LAYER 5 GATE — SPEC §6.1–§6.6, §5.3, §10.7, §11.1, §15.3, §15.4.

 THE HIGHEST-VALUE TESTS HERE ARE THE ONES THAT FAIL AGAINST v3. v3's X3DH agreed with itself
 perfectly: both parties computed the same shared key, every round trip succeeded, and all 23 of its
 tests passed — while `crypto_kdf_derive_from_key` silently read only the first 32 bytes of the
 128-byte IKM, so DH2, DH3 and DH4 contributed NOTHING. The handshake had no forward secrecy and the
 one-time prekey was decorative. No round-trip test can see that. NEG-DH2/3/4-ALTERED can, because
 they change one DH term in isolation and require the shared key to move.

 The IKM is the instrument. With `retainIKM:YES` a test can read
 `F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]` at the §18 offsets, reconstruct each term through an independent
 scalar multiplication, and flip single bytes inside a chosen term. Production callers pass NO and
 §13.3's wipe happens on schedule; the retention exists for the §15.6 vector generator and for these
 tests.

 EVERY CLOCK VALUE IS A PARAMETER. §5.3 rules 5–6 run on the initiator's ingest path, and §15.3
 requires X3DH-OPK and X3DH-NOOPK to carry fixed `not_before` / `not_after` literals with an
 injected `now_s` inside the window — otherwise both `expect: "ok"` vectors start returning
 ERR_PREKEY_EXPIRED within 90 days of the freeze, and §15.6 forbids regenerating them. Nothing in
 this file reads an ambient clock.

 Each test names the §15.3 / §15.4 vector id it will become when the generator runs at Layer 10.
 */
@interface IRX3DHSpec : XCTestCase

@property (nonatomic, strong) IRSodiumCryptoProvider *provider;
@property (nonatomic, strong) IRIdentity *alice;   ///< A, the initiator
@property (nonatomic, strong) IRIdentity *bob;     ///< B, the responder
@property (nonatomic, strong) IRSignedPreKeyRecord *bobSignedPreKey;
@property (nonatomic, strong) IROneTimePreKeyRecord *bobOneTimePreKey;

@end

@implementation IRX3DHSpec

/// §15.3 — fixed literals, a window well inside MAX_SPK_VALIDITY_SECONDS, and a `now` inside it.
static const uint64_t kNotBeforeS = 1700000000ULL;
static const uint64_t kNotAfterS = 1700000000ULL + 86400ULL * 30ULL;
static const uint64_t kNowS = 1700000000ULL + 86400ULL;

static const uint32_t kSpkId = 0x11223344u;
static const uint32_t kOpkId = 0x55667788u;

- (void)setUp {
    [super setUp];

    XCTAssertTrue([IRSodium ensureInitialized:NULL], @"libsodium must initialize");

    NSError *error = nil;
    self.provider = [IRSodiumCryptoProvider productionProvider:&error];
    XCTAssertNotNil(self.provider, @"provider construction failed: %@", error);

    self.alice = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(self.alice, @"%@", error);

    self.bob = [IRIdentity generateWithProvider:self.provider error:&error];
    XCTAssertNotNil(self.bob, @"%@", error);

    self.bobSignedPreKey = [IRSignedPreKeyRecord generateWithIdentity:self.bob
                                                               spkId:kSpkId
                                                          notBeforeS:kNotBeforeS
                                                           notAfterS:kNotAfterS
                                                            provider:self.provider
                                                               error:&error];
    XCTAssertNotNil(self.bobSignedPreKey, @"%@", error);

    self.bobOneTimePreKey = [IROneTimePreKeyRecord generateWithOpkId:kOpkId
                                                   createdAtUnixSecs:kNotBeforeS
                                                            provider:self.provider
                                                               error:&error];
    XCTAssertNotNil(self.bobOneTimePreKey, @"%@", error);
}

#pragma mark - Helpers

- (IRX25519KeyPair *)freshEphemeral {
    NSError *error = nil;
    IRX25519KeyPair *pair = [self.provider generateX25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(pair, @"%@", error);

    return pair;
}

/// An independent pair carrying the same scalar, so a test can run the initiator twice from one
/// ephemeral even though each run consumes its argument (§6.1, §13.3).
- (IRX25519KeyPair *)duplicateOfKeyPair:(IRX25519KeyPair *)pair {
    NSError *error = nil;
    IRX25519KeyPair *copy = [IRX25519KeyPair pairWithPublicKey:pair.publicKey
                                                    privateKey:[pair.privateKey duplicate]
                                                         error:&error];
    XCTAssertNotNil(copy, @"%@", error);

    return copy;
}

- (IRPreKeyBundle *)bundleWithOneTimePreKey:(BOOL)withOPK {
    NSError *error = nil;

    NSArray<IROneTimePreKeyRecord *> *opks = withOPK ? @[self.bobOneTimePreKey] : @[];

    NSData *encoded = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                        signedPreKeyRecord:self.bobSignedPreKey
                                      oneTimePreKeyRecords:opks
                                                     error:&error];
    XCTAssertNotNil(encoded, @"%@", error);

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:encoded
                                                   provider:self.provider
                                                      error:&error];
    XCTAssertNotNil(bundle, @"%@", error);

    return bundle;
}

- (IRX3DHResult *)initiatorResultWithBundle:(IRPreKeyBundle *)bundle
                                   ephemeral:(IRX25519KeyPair *)ephemeral {
    NSError *error = nil;
    IRX3DHResult *result = [IRX3DH initiatorResultWithIdentity:self.alice
                                                        bundle:bundle
                                              ephemeralKeyPair:ephemeral
                                                nowUnixSeconds:kNowS
                                                      provider:self.provider
                                                     retainIKM:YES
                                                         error:&error];
    XCTAssertNotNil(result, @"initiator agreement failed: %@", error);

    return result;
}

- (IRX3DHResult *)responderResultForEphemeral:(IRX25519Public *)ephemeralPublic
                                  withOneTime:(BOOL)withOPK {
    NSError *error = nil;
    IRX3DHResult *result =
        [IRX3DH responderResultWithIdentity:self.bob
                          initiatorIdentity:self.alice.publicIdentity
                            ephemeralPublic:ephemeralPublic
                           signedPreKeyPair:self.bobSignedPreKey.keyPair
                                      spkId:kSpkId
                                    opkFlag:(withOPK ? IROPKFlagPresent : IROPKFlagAbsent)
                                      opkId:(withOPK ? kOpkId : 0)
                          oneTimePreKeyPair:(withOPK ? self.bobOneTimePreKey.keyPair : nil)
                                   provider:self.provider
                                  retainIKM:YES
                                      error:&error];
    XCTAssertNotNil(result, @"responder agreement failed: %@", error);

    return result;
}

- (NSData *)dataFromSecret:(IRSecretBytes *)secret {
    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

- (NSData *)ikmRange:(NSRange)range ofResult:(IRX3DHResult *)result {
    XCTAssertNotNil(result.ikm);
    return [[self dataFromSecret:result.ikm] subdataWithRange:range];
}

/// A 32-byte point of small order. Its high bit is clear, so §4.4 checks 1–2 admit it and the
/// rejection can only come from check 3, inside the provider, on the DH output itself.
- (IRX25519Public *)smallOrderPublicKey {
    NSError *error = nil;
    IRX25519Public *key = [IRX25519Public fromData:[NSMutableData dataWithLength:kIRLenX25519Public]
                                             error:&error];
    XCTAssertNotNil(key, @"the all-zero point must be a VALID ENCODING: %@", error);

    return key;
}

/// Derives SK from an IKM with one byte flipped, so a single Diffie-Hellman term can be altered in
/// isolation without disturbing the transcript.
- (NSData *)sharedKeyFromResult:(IRX3DHResult *)result flippingIKMByteAtOffset:(NSInteger)offset {
    NSError *error = nil;

    NSMutableData *bytes = [[self dataFromSecret:result.ikm] mutableCopy];
    if (offset >= 0) {
        ((uint8_t *)bytes.mutableBytes)[offset] ^= 0x01;
    }

    IRSecretBytes *ikm = [[IRSecretBytes alloc] initWithData:bytes guarded:NO];
    IRRootKey *sharedKey = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                                  transcriptHash:result.transcriptHash
                                                        provider:self.provider
                                                           error:&error];
    XCTAssertNotNil(sharedKey, @"%@", error);

    return [self dataFromSecret:sharedKey];
}

#pragma mark - X3DH-OPK / X3DH-NOOPK (§15.3)

- (void)testX3DHOPK_BothPartiesDeriveTheSameSharedKey {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    IRX3DHResult *b = [self responderResultForEphemeral:ephemeralPublic withOneTime:YES];

    XCTAssertEqualObjects([self dataFromSecret:a.sharedKey], [self dataFromSecret:b.sharedKey],
                          @"X3DH-OPK: A and B must agree");
    XCTAssertEqual(a.sharedKey.length, (NSUInteger)kIRLenSK);
    XCTAssertFalse([a.sharedKey isAllZero]);

    /* Everything downstream of the four scalar multiplications must be byte-identical on both
       sides — §6.1 specifies the responder's DH set as "the mirror image, in the identical
       order". */
    XCTAssertEqualObjects(a.transcript, b.transcript);
    XCTAssertEqualObjects(a.transcriptHash, b.transcriptHash);
    XCTAssertEqualObjects(a.x3dhInfo, b.x3dhInfo);
    XCTAssertEqualObjects(a.sessionAD.bytes, b.sessionAD.bytes);
    XCTAssertEqualObjects(a.handshakeId, b.handshakeId);
    XCTAssertEqualObjects([self dataFromSecret:a.ikm], [self dataFromSecret:b.ikm]);

    XCTAssertEqual(a.role, IRSessionRoleInitiator);
    XCTAssertEqual(b.role, IRSessionRoleResponder);
}

- (void)testX3DHNOOPK_BothPartiesDeriveTheSameSharedKey {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                            ephemeral:ephemeral];
    IRX3DHResult *b = [self responderResultForEphemeral:ephemeralPublic withOneTime:NO];

    XCTAssertEqualObjects([self dataFromSecret:a.sharedKey], [self dataFromSecret:b.sharedKey],
                          @"X3DH-NOOPK: A and B must agree");
    XCTAssertEqual(a.prologue.opkFlag, IROPKFlagAbsent);
    XCTAssertEqual(a.prologue.opkId, 0u);
}

/// §6.3 — "DH4 is OMITTED, not zero-filled, when no OPK is used." The two legal IKM lengths are the
/// observable consequence, and a port that zero-fills produces 160 bytes in both cases.
- (void)testX3DHNOOPK_IKMIsExactlyOneHundredTwentyEightBytesWithDH4Omitted {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *withoutOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                                     ephemeral:ephemeral];
    XCTAssertEqual(withoutOPK.ikm.length, (NSUInteger)kIRLenIKMNoOPK);

    IRX3DHResult *responder = [self responderResultForEphemeral:ephemeralPublic withOneTime:NO];
    XCTAssertEqual(responder.ikm.length, (NSUInteger)kIRLenIKMNoOPK);

    IRX3DHResult *withOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                                  ephemeral:[self freshEphemeral]];
    XCTAssertEqual(withOPK.ikm.length, (NSUInteger)kIRLenIKMOPK);
}

/**
 The IKM is `F32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4` in exactly that order, proved term by term against four
 independent scalar multiplications.

 This is the assertion defect 1 needed. v3 built the same concatenation and then handed it to an API
 that read 32 bytes of it, so the layout was right and the consumption was not; checking the layout
 alone is necessary but not sufficient, which is why NEG-DH2/3/4-ALTERED below check consumption.
 */
- (void)testX3DHOPK_IKMIsF32ThenDH1DH2DH3DH4InSpecOrder {
    NSError *error = nil;

    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    XCTAssertEqual(a.ikm.length, (NSUInteger)kIRLenIKMOPK);

    /* §6.3 — F32 is X3DH §2.2's Curve25519 domain separator. v3 computed it into a local named
       `separation` and then commented out its use, so it never reached the KDF at all. */
    NSMutableData *f32 = [NSMutableData dataWithLength:kIRLenF32];
    memset(f32.mutableBytes, 0xFF, kIRLenF32);
    XCTAssertEqualObjects([self ikmRange:NSMakeRange(kIROffIKMSeparator, kIRLenF32) ofResult:a], f32);

    /* The responder's mirror set (§6.1), computed here from B's private halves. Equality with the
       initiator's IKM proves both the values and their order. */
    IRSecretBytes *dh1 = [self.provider x25519WithPrivateKey:self.bobSignedPreKey.keyPair.privateKey
                                                   publicKey:self.alice.identityKeyPair.agreementKey
                                                       error:&error];
    IRSecretBytes *dh2 = [self.provider x25519WithPrivateKey:self.bob.agreementKeyPair.privateKey
                                                   publicKey:ephemeralPublic
                                                       error:&error];
    IRSecretBytes *dh3 = [self.provider x25519WithPrivateKey:self.bobSignedPreKey.keyPair.privateKey
                                                   publicKey:ephemeralPublic
                                                       error:&error];
    IRSecretBytes *dh4 = [self.provider x25519WithPrivateKey:self.bobOneTimePreKey.keyPair.privateKey
                                                   publicKey:ephemeralPublic
                                                       error:&error];
    XCTAssertNotNil(dh1);
    XCTAssertNotNil(dh2);
    XCTAssertNotNil(dh3);
    XCTAssertNotNil(dh4);

    XCTAssertEqualObjects([self ikmRange:NSMakeRange(kIROffIKMDH1, kIRLenDHOutput) ofResult:a],
                          [self dataFromSecret:dh1], @"DH1 = X25519(IK_A^d, SPK_B)");
    XCTAssertEqualObjects([self ikmRange:NSMakeRange(kIROffIKMDH2, kIRLenDHOutput) ofResult:a],
                          [self dataFromSecret:dh2], @"DH2 = X25519(EK_A, IK_B^d)");
    XCTAssertEqualObjects([self ikmRange:NSMakeRange(kIROffIKMDH3, kIRLenDHOutput) ofResult:a],
                          [self dataFromSecret:dh3], @"DH3 = X25519(EK_A, SPK_B)");
    XCTAssertEqualObjects([self ikmRange:NSMakeRange(kIROffIKMDH4, kIRLenDHOutput) ofResult:a],
                          [self dataFromSecret:dh4], @"DH4 = X25519(EK_A, OPK_B)");

    /* The four terms are pairwise distinct, so none of the four assertions above could have passed
       by matching the wrong term. */
    NSSet *distinct = [NSSet setWithArray:@[[self dataFromSecret:dh1], [self dataFromSecret:dh2],
                                            [self dataFromSecret:dh3], [self dataFromSecret:dh4]]];
    XCTAssertEqual(distinct.count, 4u);
}

#pragma mark - NEG-DH2 / DH3 / DH4-ALTERED (§15.4) — the tests v3 fails

/**
 §15.4's first three rows, and §15.4's own note: "NEG-DH2/3/4-ALTERED and NEG-RK-ALTERED fail
 immediately against the v3 implementation."

 One byte is flipped inside one DH term of the IKM, with the transcript hash held constant, so the
 only thing that can move the shared key is that term reaching the KDF. Under v3's
 `crypto_kdf_derive_from_key`, which reads `k[crypto_kdf_KEYBYTES]` = the first 32 bytes,
 offsets 64, 96 and 128 are all beyond what is consumed and every one of these produces an
 IDENTICAL shared key.
 */
- (void)testNEGDHAltered_EveryDiffieHellmanTermReachesTheKDF {
    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:[self freshEphemeral]];

    NSData *unaltered = [self sharedKeyFromResult:a flippingIKMByteAtOffset:-1];
    XCTAssertEqualObjects(unaltered, [self dataFromSecret:a.sharedKey],
                          @"the control derivation must reproduce the agreed key");

    NSDictionary<NSString *, NSNumber *> *terms = @{
        @"F32 (separator)":   @(kIROffIKMSeparator),
        @"DH1":               @(kIROffIKMDH1),
        @"NEG-DH2-ALTERED":   @(kIROffIKMDH2),
        @"NEG-DH3-ALTERED":   @(kIROffIKMDH3),
        @"NEG-DH4-ALTERED":   @(kIROffIKMDH4),
    };

    for (NSString *name in terms) {
        NSInteger offset = (NSInteger)terms[name].unsignedIntegerValue;
        NSData *altered = [self sharedKeyFromResult:a flippingIKMByteAtOffset:offset];

        XCTAssertNotEqualObjects(unaltered, altered,
                                 @"%@: a flipped bit at IKM offset %ld must change SK",
                                 name, (long)offset);
    }
}

/// The same property stated as forward secrecy: a fresh ephemeral must move the shared key even
/// when every long-lived key is unchanged. Under v3 only DH1 was read, and DH1 involves no
/// ephemeral, so two handshakes with the same peer produced the same X3DH output forever.
- (void)testTwoHandshakesWithTheSamePeerProduceDifferentSharedKeys {
    IRX3DHResult *first = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                                ephemeral:[self freshEphemeral]];
    IRX3DHResult *second = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                                 ephemeral:[self freshEphemeral]];

    XCTAssertNotEqualObjects([self dataFromSecret:first.sharedKey],
                             [self dataFromSecret:second.sharedKey]);
    XCTAssertNotEqualObjects(first.handshakeId, second.handshakeId);
}

#pragma mark - NEG-SMALLORDER (§15.4), §4.4 check 3

- (void)testNEGSMALLORDER_ResponderRejectsASmallOrderEphemeral {
    NSError *error = nil;

    IRX3DHResult *result =
        [IRX3DH responderResultWithIdentity:self.bob
                          initiatorIdentity:self.alice.publicIdentity
                            ephemeralPublic:[self smallOrderPublicKey]
                           signedPreKeyPair:self.bobSignedPreKey.keyPair
                                      spkId:kSpkId
                                    opkFlag:IROPKFlagAbsent
                                      opkId:0
                          oneTimePreKeyPair:nil
                                   provider:self.provider
                                  retainIKM:NO
                                      error:&error];

    XCTAssertNil(result, @"§6.1: any all-zero DH output aborts the whole handshake");
    XCTAssertEqual(error.code, IRErrorSmallOrderKey);
}

/**
 The initiator's reachable small-order path, and it is reachable precisely because §5.2 says
 "One-time prekeys are NOT individually signed ... Implementations MUST NOT invent a per-OPK
 signature." An OPK therefore carries no authentication of its own, so a hostile or buggy
 distribution server can serve one, and §4.4 check 3 is the only thing standing behind it.
 */
- (void)testNEGSMALLORDER_InitiatorRejectsASmallOrderOneTimePreKey {
    NSError *error = nil;

    IRPreKeyBundleOPKEntry *entry = [IRPreKeyBundleOPKEntry entryWithOpkId:kOpkId
                                                                publicKey:[self smallOrderPublicKey]
                                                                    error:&error];
    XCTAssertNotNil(entry, @"%@", error);

    NSData *encoded =
        [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                        spkId:kSpkId
                                 signedPreKey:self.bobSignedPreKey.keyPair.publicKey
                                   notBeforeS:kNotBeforeS
                                    notAfterS:kNotAfterS
                        signedPreKeySignature:self.bobSignedPreKey.signature
                                   opkEntries:@[entry]
                                        error:&error];
    XCTAssertNotNil(encoded, @"%@", error);

    /* The bundle PARSES: §5.3 rule 2 is §4.4 checks 1–2 only, and the all-zero point passes both. */
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:encoded
                                                   provider:self.provider
                                                      error:&error];
    XCTAssertNotNil(bundle, @"a small-order OPK is a well-formed bundle: %@", error);

    error = nil;
    IRX3DHResult *result = [IRX3DH initiatorResultWithIdentity:self.alice
                                                        bundle:bundle
                                              ephemeralKeyPair:[self freshEphemeral]
                                                nowUnixSeconds:kNowS
                                                      provider:self.provider
                                                     retainIKM:NO
                                                         error:&error];

    XCTAssertNil(result);
    XCTAssertEqual(error.code, IRErrorSmallOrderKey, @"DH4 must be rejected by §4.4 check 3");
}

#pragma mark - NEG-OPK-NOFALLBACK (§15.4), §6.6

/**
 §6.6 rule 2 — "If absent → ERR_UNKNOWN_PREKEY_ID. THERE IS NO FALLBACK TO THE 3-DH DERIVATION.
 Rejecting rather than falling back is what converts OPK consumption into replay protection, and it
 forecloses a downgrade an implementer would otherwise be tempted to add."

 The tempting implementation returns a perfectly valid three-DH session here, and the initiator
 would never notice, because a session that derives a different SK simply fails the AEAD later. This
 test pins the error code AND that no result comes back.
 */
- (void)testNEGOPKNOFALLBACK_ResponderWithAnUnresolvedOneTimePreKeyDoesNotDowngrade {
    NSError *error = nil;

    IRX3DHResult *result =
        [IRX3DH responderResultWithIdentity:self.bob
                          initiatorIdentity:self.alice.publicIdentity
                            ephemeralPublic:[self freshEphemeral].publicKey
                           signedPreKeyPair:self.bobSignedPreKey.keyPair
                                      spkId:kSpkId
                                    opkFlag:IROPKFlagPresent
                                      opkId:kOpkId
                          oneTimePreKeyPair:nil
                                   provider:self.provider
                                  retainIKM:NO
                                      error:&error];

    XCTAssertNil(result, @"no session may be created without the named one-time prekey");
    XCTAssertEqual(error.code, IRErrorUnknownPreKeyId);
}

- (void)testResponderRejectsAnInconsistentOneTimePreKeyTriple {
    NSError *error = nil;
    IRX25519Public *ephemeralPublic = [self freshEphemeral].publicKey;

    /* Flag clear but a key pair supplied: would silently produce a 160-byte IKM the initiator never
       computed. */
    XCTAssertNil([IRX3DH responderResultWithIdentity:self.bob
                                   initiatorIdentity:self.alice.publicIdentity
                                     ephemeralPublic:ephemeralPublic
                                    signedPreKeyPair:self.bobSignedPreKey.keyPair
                                               spkId:kSpkId
                                             opkFlag:IROPKFlagAbsent
                                               opkId:0
                                   oneTimePreKeyPair:self.bobOneTimePreKey.keyPair
                                            provider:self.provider
                                           retainIKM:NO
                                               error:&error]);
    XCTAssertEqual(error.code, IRErrorMalformedHeader);

    /* NEG-OPKFLAG-ID's shape (§15.4): opk_flag == 0x00 with a non-zero opk_id. §10.2 check 7 is the
       wire-side gate; this is the same rule enforced where the transcript is built. */
    error = nil;
    XCTAssertNil([IRX3DH responderResultWithIdentity:self.bob
                                   initiatorIdentity:self.alice.publicIdentity
                                     ephemeralPublic:ephemeralPublic
                                    signedPreKeyPair:self.bobSignedPreKey.keyPair
                                               spkId:kSpkId
                                             opkFlag:IROPKFlagAbsent
                                               opkId:kOpkId
                                   oneTimePreKeyPair:nil
                                            provider:self.provider
                                           retainIKM:NO
                                               error:&error]);
    XCTAssertEqual(error.code, IRErrorMalformedHeader);
}

- (void)testOneTimePreKeyParticipationChangesTheSharedKey {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519KeyPair *sameEphemeral = [self duplicateOfKeyPair:ephemeral];

    IRX3DHResult *withOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                                  ephemeral:ephemeral];
    IRX3DHResult *withoutOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                                     ephemeral:sameEphemeral];

    /* Same identities, same signed prekey, same ephemeral: the ONLY difference is DH4 and the
       opk_flag / opk_id inside the transcript. Under v3, where neither reached the KDF, these two
       shared keys were equal. */
    XCTAssertNotEqualObjects([self dataFromSecret:withOPK.sharedKey],
                             [self dataFromSecret:withoutOPK.sharedKey]);
}

#pragma mark - Transcript binding (§6.2)

- (void)testTranscriptIsTwoHundredFiftyNineBytesInBothCases {
    IRX3DHResult *withOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                                  ephemeral:[self freshEphemeral]];
    IRX3DHResult *withoutOPK = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                                     ephemeral:[self freshEphemeral]];

    XCTAssertEqual(withOPK.transcript.length, (NSUInteger)kIRLenTranscript);
    XCTAssertEqual(withoutOPK.transcript.length, (NSUInteger)kIRLenTranscript);
    XCTAssertEqual(withOPK.transcriptHash.length, (NSUInteger)kIRLenTH);
    XCTAssertEqual(withOPK.x3dhInfo.length, (NSUInteger)kIRLenX3DHInfo);
}

- (void)testTranscriptFieldsSitAtTheSpecifiedOffsets {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    NSData *transcript = a.transcript;

    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptLabel,
                                                                  kIRLenLabelTranscript)],
                          [NSData dataWithBytes:kIRLabelTranscript length:kIRLenLabelTranscript]);

    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptInitiatorSigning,
                                                                  kIRLenEd25519Public)],
                          self.alice.identityKeyPair.signingKey.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptInitiatorAgreement,
                                                                  kIRLenX25519Public)],
                          self.alice.identityKeyPair.agreementKey.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptEK,
                                                                  kIRLenX25519Public)],
                          ephemeralPublic.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptResponderSigning,
                                                                  kIRLenEd25519Public)],
                          self.bob.identityKeyPair.signingKey.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptResponderAgreement,
                                                                  kIRLenX25519Public)],
                          self.bob.identityKeyPair.agreementKey.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptSPK,
                                                                  kIRLenX25519Public)],
                          self.bobSignedPreKey.keyPair.publicKey.data);
    XCTAssertEqualObjects([transcript subdataWithRange:NSMakeRange(kIROffTranscriptOPK,
                                                                  kIRLenX25519Public)],
                          self.bobOneTimePreKey.keyPair.publicKey.data);

    const uint8_t *raw = (const uint8_t *)transcript.bytes;
    XCTAssertEqual(raw[kIROffTranscriptOPKFlag], (uint8_t)IROPKFlagPresent);

    uint32_t spkId = ((uint32_t)raw[kIROffTranscriptSPKId] << 24) |
                     ((uint32_t)raw[kIROffTranscriptSPKId + 1] << 16) |
                     ((uint32_t)raw[kIROffTranscriptSPKId + 2] << 8) |
                     ((uint32_t)raw[kIROffTranscriptSPKId + 3]);
    XCTAssertEqual(spkId, kSpkId, @"spk_id is big-endian (§3.1)");
}

/// §6.2 — "The transcript is fixed-length in BOTH the OPK and no-OPK cases, with the absent OPK
/// encoded as 32 zero bytes rather than omitted." Note this is the OPPOSITE convention from the
/// IKM, where DH4 is genuinely omitted; a port that unifies them breaks one of the two.
- (void)testTranscriptEncodesAnAbsentOneTimePreKeyAsThirtyTwoZeroBytes {
    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                            ephemeral:[self freshEphemeral]];

    const uint8_t *raw = (const uint8_t *)a.transcript.bytes;
    XCTAssertEqual(a.transcript.length, (NSUInteger)kIRLenTranscript);
    XCTAssertEqual(raw[kIROffTranscriptOPKFlag], (uint8_t)IROPKFlagAbsent);

    XCTAssertEqualObjects([a.transcript subdataWithRange:NSMakeRange(kIROffTranscriptOPKId, 4)],
                          [NSMutableData dataWithLength:4]);
    XCTAssertEqualObjects([a.transcript subdataWithRange:NSMakeRange(kIROffTranscriptOPK,
                                                                    kIRLenX25519Public)],
                          [NSMutableData dataWithLength:kIRLenX25519Public]);
}

/**
 §6.2 — "The transcript contains NO signature bytes. This is deliberate and load-bearing."

 Hashing IKB or SPK_SIG into TH would require both parties to reconstruct byte-identical 64-byte
 signatures, which is not safe to assume: CryptoKit's Ed25519 signing is not contractually
 deterministic, and verifier strictness on non-canonical S and small-order A differs across
 libsodium, BouncyCastle and the JDK.
 */
- (void)testTranscriptContainsNeitherIdentityBindingNorSignedPreKeySignature {
    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:[self freshEphemeral]];

    XCTAssertEqual([a.transcript rangeOfData:self.bob.binding.data
                                     options:0
                                       range:NSMakeRange(0, a.transcript.length)].location,
                   NSNotFound, @"IKB_B must not appear in the transcript");

    XCTAssertEqual([a.transcript rangeOfData:self.bobSignedPreKey.signature.data
                                     options:0
                                       range:NSMakeRange(0, a.transcript.length)].location,
                   NSNotFound, @"SPK_SIG must not appear in the transcript");
}

- (void)testSharedKeyIsBoundToTheSignedPreKeyIdentifier {
    NSError *error = nil;
    IRX25519Public *ephemeralPublic = [self freshEphemeral].publicKey;

    IRX3DHResult *first = [self responderResultForEphemeral:ephemeralPublic withOneTime:NO];

    /* Identical keys, identical DH set, one different id. §5.2 binds spk_id into SPK_SIGN_MSG to
       stop a signature being transplanted onto another slot; §6.2 binds it into TH so the two
       parties cannot even agree unless they agree on which slot was used. */
    IRX3DHResult *second =
        [IRX3DH responderResultWithIdentity:self.bob
                          initiatorIdentity:self.alice.publicIdentity
                            ephemeralPublic:ephemeralPublic
                           signedPreKeyPair:self.bobSignedPreKey.keyPair
                                      spkId:(kSpkId + 1u)
                                    opkFlag:IROPKFlagAbsent
                                      opkId:0
                          oneTimePreKeyPair:nil
                                   provider:self.provider
                                  retainIKM:NO
                                      error:&error];
    XCTAssertNotNil(second, @"%@", error);

    XCTAssertEqualObjects([self dataFromSecret:first.ikm],
                          [self dataFromSecret:[self responderResultForEphemeral:ephemeralPublic
                                                                     withOneTime:NO].ikm],
                          @"control: the DH set is unchanged");
    XCTAssertNotEqualObjects([self dataFromSecret:first.sharedKey],
                             [self dataFromSecret:second.sharedKey],
                             @"spk_id is inside TH, so it must change SK");
}

/**
 §5.5's threat model, run forwards.

 Two identities sharing one `IK^d` but with different `IK^s` produce IDENTICAL DH1–DH4 — every
 scalar multiplication in the protocol involves `IK^d`, never `IK^s`. Only the transcript
 distinguishes them. Without §6.2 binding both identity keys, an attacker presenting a victim's
 genuine `IK^s` beside its own `IK^d` would complete a cryptographically sound session and be
 attributed to the victim by any implementation that looks up contacts by the signing key.
 */
- (void)testSharedKeyIsBoundToTheSigningIdentityEvenWhenEveryDHIsUnchanged {
    NSError *error = nil;

    IREd25519KeyPair *otherSigning = [self.provider generateEd25519KeyPairGuarded:NO error:&error];
    XCTAssertNotNil(otherSigning, @"%@", error);

    /* A second identity reusing Alice's agreement key pair, correctly self-bound over its own
       (IK^s, IK^d) pair so it is a fully valid identity — not a forgery. */
    IRIdentityKeyPair *impostorPair =
        [IRIdentityKeyPair pairWithSigningKey:otherSigning.publicKey
                                 agreementKey:self.alice.agreementKeyPair.publicKey
                                        error:&error];
    XCTAssertNotNil(impostorPair, @"%@", error);

    NSData *bindMessage = IRIKBindMessage(impostorPair, &error);
    XCTAssertNotNil(bindMessage, @"%@", error);

    IREd25519Signature *binding = [self.provider ed25519SignMessage:bindMessage
                                                           withSeed:otherSigning.seed
                                                              error:&error];
    XCTAssertNotNil(binding, @"%@", error);

    IRIdentity *impostor = [IRIdentity identityWithSigningKeyPair:otherSigning
                                                agreementKeyPair:self.alice.agreementKeyPair
                                                         binding:binding
                                                        provider:self.provider
                                                           error:&error];
    XCTAssertNotNil(impostor, @"%@", error);

    IRX25519Public *ephemeralPublic = [self freshEphemeral].publicKey;

    IRX3DHResult *genuine = [self responderResultForEphemeral:ephemeralPublic withOneTime:NO];

    error = nil;
    IRX3DHResult *substituted =
        [IRX3DH responderResultWithIdentity:self.bob
                          initiatorIdentity:impostor.publicIdentity
                            ephemeralPublic:ephemeralPublic
                           signedPreKeyPair:self.bobSignedPreKey.keyPair
                                      spkId:kSpkId
                                    opkFlag:IROPKFlagAbsent
                                      opkId:0
                          oneTimePreKeyPair:nil
                                   provider:self.provider
                                  retainIKM:YES
                                      error:&error];
    XCTAssertNotNil(substituted, @"%@", error);

    XCTAssertEqualObjects([self dataFromSecret:genuine.ikm],
                          [self dataFromSecret:substituted.ikm],
                          @"IK^s takes part in no Diffie-Hellman, so the DH set is identical");
    XCTAssertNotEqualObjects([self dataFromSecret:genuine.sharedKey],
                             [self dataFromSecret:substituted.sharedKey],
                             @"the transcript binds IK^s, so the shared keys MUST differ");
    XCTAssertNotEqualObjects(genuine.sessionAD.bytes, substituted.sessionAD.bytes);
}

#pragma mark - SESSION_AD (§6.5, §8.5)

- (void)testSessionADIsRoleOrderedAndIdenticalOnBothSides {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    IRX3DHResult *b = [self responderResultForEphemeral:ephemeralPublic withOneTime:YES];

    XCTAssertEqual(a.sessionAD.bytes.length, (NSUInteger)kIRLenSessionAD);
    XCTAssertEqualObjects(a.sessionAD.bytes, b.sessionAD.bytes,
                          @"§6.5: A is the initiator on BOTH sides and is never reordered");
    XCTAssertTrue([a.sessionAD isEqualToSessionAD:b.sessionAD]);
}

/// §6.5's headline trap: "A port that recomputes SESSION_AD as (self, peer) at send time will
/// interoperate with itself and with nothing else."
- (void)testSessionADRoleOrderIsObservable {
    NSError *error = nil;

    IRSessionAD *correct = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                              responder:self.bob.identityKeyPair
                                                  error:&error];
    IRSessionAD *swapped = [IRSessionAD adWithInitiator:self.bob.identityKeyPair
                                              responder:self.alice.identityKeyPair
                                                  error:&error];
    XCTAssertNotNil(correct);
    XCTAssertNotNil(swapped);

    XCTAssertNotEqualObjects(correct.bytes, swapped.bytes,
                             @"the responder computing (self, peer) must not land on the same bytes");
    XCTAssertFalse([correct isEqualToSessionAD:swapped]);
}

- (void)testSessionADSubOffsetsMatchTheSpecification {
    NSError *error = nil;

    IRSessionAD *ad = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                         responder:self.bob.identityKeyPair
                                             error:&error];
    XCTAssertNotNil(ad, @"%@", error);

    XCTAssertEqualObjects([ad.bytes subdataWithRange:NSMakeRange(kIROffSessionADLabel,
                                                                kIRLenLabelAD)],
                          [NSData dataWithBytes:kIRLabelAD length:kIRLenLabelAD]);
    XCTAssertEqualObjects([ad.bytes subdataWithRange:NSMakeRange(kIROffSessionADInitiatorSigning,
                                                                kIRLenEd25519Public)],
                          self.alice.identityKeyPair.signingKey.data);
    XCTAssertEqualObjects([ad.bytes subdataWithRange:NSMakeRange(kIROffSessionADInitiatorAgreement,
                                                                kIRLenX25519Public)],
                          self.alice.identityKeyPair.agreementKey.data);
    XCTAssertEqualObjects([ad.bytes subdataWithRange:NSMakeRange(kIROffSessionADResponderSigning,
                                                                kIRLenEd25519Public)],
                          self.bob.identityKeyPair.signingKey.data);
    XCTAssertEqualObjects([ad.bytes subdataWithRange:NSMakeRange(kIROffSessionADResponderAgreement,
                                                                kIRLenX25519Public)],
                          self.bob.identityKeyPair.agreementKey.data);
}

/// §11.1's second index — the peer identity pair, which §11.1.1 makes a function rather than a
/// relation by permitting at most one live session per peer.
- (void)testSessionADResolvesPeerAndOwnIdentityByRole {
    NSError *error = nil;

    IRSessionAD *ad = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                         responder:self.bob.identityKeyPair
                                             error:&error];
    XCTAssertNotNil(ad);

    XCTAssertTrue([[ad peerIdentityForRole:IRSessionRoleInitiator]
                   isEqualToIdentityKeyPair:self.bob.identityKeyPair]);
    XCTAssertTrue([[ad ownIdentityForRole:IRSessionRoleInitiator]
                   isEqualToIdentityKeyPair:self.alice.identityKeyPair]);
    XCTAssertTrue([[ad peerIdentityForRole:IRSessionRoleResponder]
                   isEqualToIdentityKeyPair:self.alice.identityKeyPair]);
    XCTAssertTrue([[ad ownIdentityForRole:IRSessionRoleResponder]
                   isEqualToIdentityKeyPair:self.bob.identityKeyPair]);

    XCTAssertNil([ad peerIdentityForRole:(IRSessionRole)0x00]);
    XCTAssertNil([ad ownIdentityForRole:(IRSessionRole)0x7F]);
}

- (void)testSessionADRoundTripsThroughItsStoredBytes {
    NSError *error = nil;

    IRSessionAD *original = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                               responder:self.bob.identityKeyPair
                                                   error:&error];
    IRSessionAD *restored = [IRSessionAD adFromStoredBytes:original.bytes error:&error];

    XCTAssertNotNil(restored, @"%@", error);
    XCTAssertEqualObjects(original.bytes, restored.bytes);
    XCTAssertTrue([restored.initiatorIdentity isEqualToIdentityKeyPair:self.alice.identityKeyPair]);
    XCTAssertTrue([restored.responderIdentity isEqualToIdentityKeyPair:self.bob.identityKeyPair]);
}

/// §12.2 rule 7 assigns ERR_STATE_CORRUPT to a bad stored public key, while the nominal
/// constructors report ERR_INVALID_PUBLIC_KEY for the same bytes off the wire. §15.4 makes the exact
/// code a conformance requirement, so the two must not be allowed to blur.
- (void)testSessionADParseFailuresAllReportStateCorrupt {
    NSError *error = nil;

    IRSessionAD *valid = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                            responder:self.bob.identityKeyPair
                                                error:&error];
    XCTAssertNotNil(valid);

    XCTAssertNil([IRSessionAD adFromStoredBytes:[NSData data] error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    error = nil;
    NSMutableData *tooLong = [valid.bytes mutableCopy];
    [tooLong appendBytes:"\x00" length:1];
    XCTAssertNil([IRSessionAD adFromStoredBytes:tooLong error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    error = nil;
    NSMutableData *badLabel = [valid.bytes mutableCopy];
    ((uint8_t *)badLabel.mutableBytes)[0] ^= 0xFF;
    XCTAssertNil([IRSessionAD adFromStoredBytes:badLabel error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    /* §4.4 check 2 on the two X25519 halves — and on neither Ed25519 half. */
    for (NSNumber *offset in @[@((NSUInteger)kIROffSessionADInitiatorAgreement),
                               @((NSUInteger)kIROffSessionADResponderAgreement)]) {
        error = nil;
        NSMutableData *highBit = [valid.bytes mutableCopy];
        ((uint8_t *)highBit.mutableBytes)[offset.unsignedIntegerValue + 31] |= 0x80;

        XCTAssertNil([IRSessionAD adFromStoredBytes:highBit error:&error],
                     @"IK^d at offset %@ with bit 255 set must be rejected", offset);
        XCTAssertEqual(error.code, IRErrorStateCorrupt);
    }
}

/**
 The X25519-only scoping of §4.4 checks 1–2, at the SESSION_AD layer.

 Bit 255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is set in roughly half of
 all valid identities. A port that reads §4.4's heading as governing every public key rejects half
 of all restored sessions intermittently, and the failure presents as a signature bug. §5.3 rule 2
 and §6.5 both scope correctly; §4.4's heading does not, and this is the fourth layer to pin it.
 */
- (void)testSessionADAcceptsAnEd25519IdentityKeyWithBitTwoFiftyFiveSet {
    NSError *error = nil;

    IRSessionAD *valid = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                            responder:self.bob.identityKeyPair
                                                error:&error];
    XCTAssertNotNil(valid);

    for (NSNumber *offset in @[@((NSUInteger)kIROffSessionADInitiatorSigning),
                               @((NSUInteger)kIROffSessionADResponderSigning)]) {
        error = nil;
        NSMutableData *highBit = [valid.bytes mutableCopy];
        ((uint8_t *)highBit.mutableBytes)[offset.unsignedIntegerValue + 31] |= 0x80;

        XCTAssertNotNil([IRSessionAD adFromStoredBytes:highBit error:&error],
                        @"IK^s at offset %@ with bit 255 set is VALID: %@", offset, error);
    }
}

/// §8.5 — "AD = SESSION_AD (141) ‖ the complete message header", 197 and 366 bytes.
- (void)testAssociatedDataIsSessionADFollowedByTheCompleteHeader {
    NSError *error = nil;

    IRSessionAD *ad = [IRSessionAD adWithInitiator:self.alice.identityKeyPair
                                         responder:self.bob.identityKeyPair
                                             error:&error];
    XCTAssertNotNil(ad);

    NSData *type01Header = [NSMutableData dataWithLength:kIRLenType01Header];
    NSData *type02Header = [NSMutableData dataWithLength:kIRLenType02Header];

    NSData *type01AD = [ad associatedDataWithHeaderBytes:type01Header error:&error];
    XCTAssertNotNil(type01AD, @"%@", error);
    XCTAssertEqual(type01AD.length, (NSUInteger)kIRLenType01AD);
    XCTAssertEqualObjects([type01AD subdataWithRange:NSMakeRange(0, kIRLenSessionAD)], ad.bytes);

    NSData *type02AD = [ad associatedDataWithHeaderBytes:type02Header error:&error];
    XCTAssertNotNil(type02AD, @"%@", error);
    XCTAssertEqual(type02AD.length, (NSUInteger)kIRLenType02AD);
    XCTAssertEqualObjects([type02AD subdataWithRange:NSMakeRange(0, kIRLenSessionAD)], ad.bytes);

    /* §9: the header length is a constant selected by the type byte alone. Nothing else is a legal
       header width, and there is no length field anywhere in the format to make one. */
    error = nil;
    XCTAssertNil([ad associatedDataWithHeaderBytes:[NSMutableData dataWithLength:57] error:&error]);
    XCTAssertEqual(error.code, IRErrorMalformedHeader);
}

#pragma mark - handshake_id (§11.1)

- (void)testHandshakeIdentifierIsInitiatorAgreementKeyThenEphemeral {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    IRX3DHResult *b = [self responderResultForEphemeral:ephemeralPublic withOneTime:YES];

    XCTAssertEqual(a.handshakeId.length, (NSUInteger)kIRLenHandshakeId);
    XCTAssertEqualObjects(a.handshakeId, b.handshakeId,
                          @"both sides read it from the same public values (§11.2)");

    XCTAssertEqualObjects([a.handshakeId subdataWithRange:
                           NSMakeRange(kIROffHandshakeIdIdentityAgreement, kIRLenX25519Public)],
                          self.alice.identityKeyPair.agreementKey.data);
    XCTAssertEqualObjects([a.handshakeId subdataWithRange:
                           NSMakeRange(kIROffHandshakeIdEK, kIRLenX25519Public)],
                          ephemeralPublic.data);
}

#pragma mark - Prologue (§11.3, §12.1)

- (void)testInitiatorProducesAPrologueAndResponderDoesNot {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];
    IRX3DHResult *b = [self responderResultForEphemeral:ephemeralPublic withOneTime:YES];

    XCTAssertNotNil(a.prologue);
    XCTAssertNil(b.prologue, @"a responder never sends type 0x02 and has no prologue to re-emit");

    XCTAssertTrue([a.prologue.ephemeralPublic isEqualToX25519Public:ephemeralPublic]);
    XCTAssertEqual(a.prologue.spkId, kSpkId);
    XCTAssertEqual(a.prologue.opkFlag, IROPKFlagPresent);
    XCTAssertEqual(a.prologue.opkId, kOpkId);
}

- (void)testPrologueRoundTripsThroughItsFortyOneStoredBytes {
    NSError *error = nil;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:[self freshEphemeral]];

    NSData *stored = [a.prologue serializedBytes:&error];
    XCTAssertNotNil(stored, @"%@", error);
    XCTAssertEqual(stored.length, (NSUInteger)kIRLenStatePrologue);

    IRSessionPrologue *restored = [IRSessionPrologue prologueFromStoredBytes:stored error:&error];
    XCTAssertNotNil(restored, @"%@", error);
    XCTAssertTrue([restored isEqualToSessionPrologue:a.prologue]);
    XCTAssertEqualObjects([restored serializedBytes:&error], stored);

    XCTAssertEqualObjects([stored subdataWithRange:NSMakeRange(kIROffPrologueEK,
                                                              kIRLenX25519Public)],
                          a.prologue.ephemeralPublic.data);
    XCTAssertEqual(((const uint8_t *)stored.bytes)[kIROffPrologueOPKFlag],
                   (uint8_t)IROPKFlagPresent);
}

- (void)testPrologueRejectsAnInconsistentOneTimePreKeyPair {
    NSError *error = nil;

    XCTAssertNil([IRSessionPrologue prologueWithEphemeralPublic:[self freshEphemeral].publicKey
                                                          spkId:kSpkId
                                                        opkFlag:IROPKFlagAbsent
                                                          opkId:kOpkId
                                                          error:&error]);
    XCTAssertEqual(error.code, IRErrorMalformedHeader);

    error = nil;
    XCTAssertNil([IRSessionPrologue prologueWithEphemeralPublic:[self freshEphemeral].publicKey
                                                          spkId:kSpkId
                                                        opkFlag:(IROPKFlag)0x02
                                                          opkId:0
                                                          error:&error]);
    XCTAssertEqual(error.code, IRErrorMalformedHeader);
}

- (void)testPrologueParseFailuresAllReportStateCorrupt {
    NSError *error = nil;

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:NO]
                                            ephemeral:[self freshEphemeral]];
    NSData *stored = [a.prologue serializedBytes:&error];
    XCTAssertNotNil(stored);

    XCTAssertNil([IRSessionPrologue prologueFromStoredBytes:[NSData data] error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    error = nil;
    NSMutableData *highBit = [stored mutableCopy];
    ((uint8_t *)highBit.mutableBytes)[kIROffPrologueEK + 31] |= 0x80;
    XCTAssertNil([IRSessionPrologue prologueFromStoredBytes:highBit error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    error = nil;
    NSMutableData *badFlag = [stored mutableCopy];
    ((uint8_t *)badFlag.mutableBytes)[kIROffPrologueOPKFlag] = 0x05;
    XCTAssertNil([IRSessionPrologue prologueFromStoredBytes:badFlag error:&error]);
    XCTAssertEqual(error.code, IRErrorStateCorrupt);

    error = nil;
    NSMutableData *strayId = [stored mutableCopy];
    ((uint8_t *)strayId.mutableBytes)[kIROffPrologueOPKId] = 0x01;
    XCTAssertNil([IRSessionPrologue prologueFromStoredBytes:strayId error:&error],
                 @"opk_flag == 0x00 with a non-zero opk_id would re-emit a header §10.2 check 7 "
                 @"rejects");
    XCTAssertEqual(error.code, IRErrorStateCorrupt);
}

#pragma mark - §5.3 rules 5–6 on the initiator's ingest path

- (void)testNEGSPKEXPIRED_InitiatorRejectsABundleOutsideItsValidityWindow {
    NSError *error = nil;

    IRX3DHResult *result = [IRX3DH initiatorResultWithIdentity:self.alice
                                                        bundle:[self bundleWithOneTimePreKey:YES]
                                              ephemeralKeyPair:[self freshEphemeral]
                                                nowUnixSeconds:(kNotAfterS + 1ULL)
                                                      provider:self.provider
                                                     retainIKM:NO
                                                         error:&error];

    XCTAssertNil(result, @"§5.3: all six rules run BEFORE any Diffie-Hellman");
    XCTAssertEqual(error.code, IRErrorPreKeyExpired);

    error = nil;
    XCTAssertNil([IRX3DH initiatorResultWithIdentity:self.alice
                                              bundle:[self bundleWithOneTimePreKey:YES]
                                    ephemeralKeyPair:[self freshEphemeral]
                                      nowUnixSeconds:(kNotBeforeS - 1ULL)
                                            provider:self.provider
                                           retainIKM:NO
                                               error:&error]);
    XCTAssertEqual(error.code, IRErrorPreKeyExpired);
}

- (void)testNEGSPKWINDOWTOOLONG_InitiatorRejectsAnOverlongValidityWindow {
    NSError *error = nil;

    IRSignedPreKeyRecord *wide =
        [IRSignedPreKeyRecord generateWithIdentity:self.bob
                                             spkId:kSpkId
                                        notBeforeS:kNotBeforeS
                                         notAfterS:(kNotBeforeS + kIRMaxSPKValiditySeconds + 1ULL)
                                          provider:self.provider
                                             error:&error];
    XCTAssertNotNil(wide, @"%@", error);

    NSData *encoded = [IRPreKeyBundle serializeWithIdentity:self.bob.publicIdentity
                                        signedPreKeyRecord:wide
                                      oneTimePreKeyRecords:@[]
                                                     error:&error];
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:encoded
                                                   provider:self.provider
                                                      error:&error];
    XCTAssertNotNil(bundle, @"%@", error);

    error = nil;
    XCTAssertNil([IRX3DH initiatorResultWithIdentity:self.alice
                                              bundle:bundle
                                    ephemeralKeyPair:[self freshEphemeral]
                                      nowUnixSeconds:kNowS
                                            provider:self.provider
                                           retainIKM:NO
                                               error:&error]);
    XCTAssertEqual(error.code, IRErrorPreKeyExpired);
}

#pragma mark - Zeroization schedule (§13.3)

/// §13.3 — "EK_A private half: immediately after SK is derived." §6.1: EK_A "is used for nothing
/// else", so the method consumes it and the public half is all §11.3 needs afterwards.
- (void)testInitiatorConsumesTheEphemeralPrivateHalfAndKeepsThePublic {
    IRX25519KeyPair *ephemeral = [self freshEphemeral];
    NSData *publicBefore = ephemeral.publicKey.data;
    XCTAssertFalse([ephemeral.privateKey isAllZero]);

    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:ephemeral];

    XCTAssertTrue([ephemeral.privateKey isAllZero], @"EK_A_priv must be wiped");
    XCTAssertEqualObjects(ephemeral.publicKey.data, publicBefore, @"EK_A_pub must survive");
    XCTAssertEqualObjects(a.prologue.ephemeralPublic.data, publicBefore);
}

- (void)testInitiatorConsumesTheEphemeralOnTheFailurePathToo {
    NSError *error = nil;

    IRX25519KeyPair *ephemeral = [self freshEphemeral];

    XCTAssertNil([IRX3DH initiatorResultWithIdentity:self.alice
                                              bundle:[self bundleWithOneTimePreKey:YES]
                                    ephemeralKeyPair:ephemeral
                                      nowUnixSeconds:(kNotAfterS + 1ULL)
                                            provider:self.provider
                                           retainIKM:NO
                                               error:&error]);

    XCTAssertTrue([ephemeral.privateKey isAllZero],
                  @"an ephemeral offered to a rejected bundle must not be reusable");
}

/// §13.3 — "DH1–DH4, IKM: immediately after SK is derived." retainIKM:YES is the one documented
/// suppression, for the §15.6 generator and for the tests above; production passes NO.
- (void)testIKMIsNotRetainedUnlessExplicitlyRequested {
    NSError *error = nil;

    IRX3DHResult *wiped = [IRX3DH initiatorResultWithIdentity:self.alice
                                                       bundle:[self bundleWithOneTimePreKey:YES]
                                             ephemeralKeyPair:[self freshEphemeral]
                                               nowUnixSeconds:kNowS
                                                     provider:self.provider
                                                    retainIKM:NO
                                                        error:&error];
    XCTAssertNotNil(wiped, @"%@", error);
    XCTAssertNil(wiped.ikm, @"§13.3: the IKM must not survive the derivation");

    /* The public intermediates are unconditional — every byte of them is a public key, a key id or
       a fixed label, so §15.5 rule 2 can require them without a §13.3 conflict. */
    XCTAssertNotNil(wiped.transcript);
    XCTAssertNotNil(wiped.transcriptHash);
    XCTAssertNotNil(wiped.x3dhInfo);

    IRX3DHResult *retained = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                                   ephemeral:[self freshEphemeral]];
    XCTAssertNotNil(retained.ikm);
    XCTAssertEqual(retained.ikm.length, (NSUInteger)kIRLenIKMOPK);
    XCTAssertFalse([retained.ikm isAllZero]);
}

/// §13.3 — "SK: immediately after ratchet initialization." The ratchet is Layer 7's; this is the
/// handle it uses.
- (void)testResultZeroizeWipesTheSharedKeyAndAnyRetainedIKM {
    IRX3DHResult *a = [self initiatorResultWithBundle:[self bundleWithOneTimePreKey:YES]
                                            ephemeral:[self freshEphemeral]];

    XCTAssertFalse([a.sharedKey isAllZero]);
    XCTAssertFalse([a.ikm isAllZero]);

    [a zeroize];

    XCTAssertTrue([a.sharedKey isAllZero]);
    XCTAssertTrue([a.ikm isAllZero]);

    [a zeroize];
    XCTAssertTrue([a.sharedKey isAllZero], @"-zeroize must be idempotent");
}

/**
 §5.3 / §7.5 — "SPK_B_priv is owned EXCLUSIVELY by the prekey store ... No ratchet operation may
 shorten it." The responder's DH set reads both prekey privates; neither may be disturbed.

 A port that wipes them here breaks every concurrent and future handshake against that spk_id,
 silently, and then reports ERR_AEAD_AUTH_FAILED — misdiagnosing its own key destruction as an
 active man-in-the-middle (§7.5). NEG-SPK-SURVIVES-RATCHET is the full multi-session form of this;
 the unit-level statement is here because this is the layer that touches the keys.
 */
- (void)testResponderLeavesTheSignedAndOneTimePreKeyPrivatesIntact {
    IRX25519Private *spkPrivate = self.bobSignedPreKey.keyPair.privateKey;
    IRX25519Private *opkPrivate = self.bobOneTimePreKey.keyPair.privateKey;

    NSData *spkBefore = [self dataFromSecret:spkPrivate];
    NSData *opkBefore = [self dataFromSecret:opkPrivate];

    XCTAssertNotNil([self responderResultForEphemeral:[self freshEphemeral].publicKey
                                          withOneTime:YES]);

    XCTAssertEqualObjects(spkBefore, [self dataFromSecret:spkPrivate], @"SPK_B_priv must survive");
    XCTAssertEqualObjects(opkBefore, [self dataFromSecret:opkPrivate], @"OPK_B_priv must survive");

    /* And a second handshake against the same records still works — the property the store exists
       to provide. */
    XCTAssertNotNil([self responderResultForEphemeral:[self freshEphemeral].publicKey
                                          withOneTime:YES]);
}

#pragma mark - Error-handling contract (§10.5)

- (void)testNoEntryPointDereferencesANullErrorOutParameter {
    /* v3's aeEncryptSimpleData: and aeDecryptSimpleData: wrote `*error = err` with no null check,
       crashing every caller that passed NULL — which every test in the repository did.

       The nil arguments below deliberately violate the _Nonnull annotations. Objective-C
       nullability is ADVISORY: it emits a diagnostic and nothing more, and nil still arrives at
       runtime from a bridged Swift optional, a dictionary lookup that missed, or a prekey store
       that returned nothing. §10.5 requires every failure path to report rather than crash, so the
       runtime guard is the contract that has to hold. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRX3DH initiatorResultWithIdentity:nil
                                              bundle:nil
                                    ephemeralKeyPair:nil
                                      nowUnixSeconds:kNowS
                                            provider:self.provider
                                           retainIKM:NO
                                               error:NULL]);

    XCTAssertNil([IRX3DH responderResultWithIdentity:nil
                                   initiatorIdentity:nil
                                     ephemeralPublic:nil
                                    signedPreKeyPair:nil
                                               spkId:0
                                             opkFlag:IROPKFlagAbsent
                                               opkId:0
                                   oneTimePreKeyPair:nil
                                            provider:self.provider
                                           retainIKM:NO
                                               error:NULL]);

    XCTAssertNil(IRHandshakeIdentifier(nil, nil, NULL));
    XCTAssertNil([IRTranscript transcriptHashOf:[NSData data] provider:self.provider error:NULL]);
    XCTAssertNil([IRSessionAD adFromStoredBytes:[NSData data] error:NULL]);
    XCTAssertNil([IRSessionPrologue prologueFromStoredBytes:[NSData data] error:NULL]);
#pragma clang diagnostic pop
}

- (void)testMissingProviderIsReportedRatherThanCrashing {
    NSError *error = nil;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertNil([IRX3DH initiatorResultWithIdentity:self.alice
                                              bundle:[self bundleWithOneTimePreKey:YES]
                                    ephemeralKeyPair:[self freshEphemeral]
                                      nowUnixSeconds:kNowS
                                            provider:nil
                                           retainIKM:NO
                                               error:&error]);
    XCTAssertEqual(error.code, IRErrorNotInitialized);
#pragma clang diagnostic pop
}

@end
