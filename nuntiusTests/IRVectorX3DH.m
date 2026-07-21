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

#import "IRVectorModules.h"
#import "IRVectorIO.h"

#import "IRByteWriter.h"
#import "IRCryptoProvider.h"
#import "IRErrors.h"
#import "IRIdentity.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRSecretBytes.h"
#import "IRSessionAD.h"
#import "IRTranscript.h"
#import "IRX3DH.h"

/**
 x3dh.json — SPEC §5.1, §5.2, §5.3, §5.5, §6.1–§6.6, §11.1, §15.3, §15.5.

 FIVE VECTORS, exactly the set §15.3's `x3dh.json` table requires:

     X3DH-OPK      full handshake WITH a one-time prekey; 160-byte IKM   (§6.1–§6.5)
     X3DH-NOOPK    the same without one; 128-byte IKM, DH4 OMITTED       (§6.3)
     X3DH-IKBIND   IKBIND_MSG (81 bytes) and its signature               (§5.1)
     X3DH-SPKSIG   SPK_SIGN_MSG (130 bytes) and its signature            (§5.2)
     X3DH-FP       the identity fingerprint                              (§5.5)

 THE TWO HANDSHAKE VECTORS ARE TWO-SIDED, AND THAT IS THE POINT. §6.1 specifies the responder's DH
 set as "the mirror image, in the identical order", so every value downstream of the four scalar
 multiplications — TRANSCRIPT, TH, IKM, SK, SESSION_AD, handshake_id — must be byte-identical on
 both sides. `inputs` therefore carries BOTH parties' private keys, which §15.5 licenses in as many
 words ("Everything needed to reproduce, including all private keys"), and the executor runs the
 initiator direction AND the responder direction and requires them to agree. A one-sided vector
 would certify only that the initiator is self-consistent, which is precisely the property §15.1
 says certifies nothing: v3's X3DH agreed with itself perfectly while DH2, DH3 and DH4 contributed
 nothing at all.

 THERE IS DELIBERATELY NO `role` INPUT. §15.5's worked example carries `"role": "initiator"`, but
 that example is abbreviated and lists only A's privates, so it can express one direction. These
 vectors evaluate both, and a `role` key naming one of them would misdescribe the vector while
 §15.5 rule 3 forced every runner to read it. Only three `inputs` keys are reserved by the envelope
 — `entry_point`, `sessions`, `selected_session` — and `role` is not among them.

 THE CLOCK IS INJECTED, NOT READ (§15.3, §15.5 rule 6). `X3DH-OPK` and `X3DH-NOOPK` ingest a bundle
 and therefore run §5.3 rules 5–6, so each carries fixed `not_before` / `not_after` literals and an
 `inputs.now_s` INSIDE that window. Rule 6 caps the window at MAX_SPK_VALIDITY_SECONDS (90 days), so
 no choice of timestamps avoids expiry: without the injected clock these two `expect: "ok"` vectors
 would start returning ERR_PREKEY_EXPIRED at most 90 days after the freeze, and §15.6 step 4 forbids
 regenerating them. The window here is 1767225600 … 1774828800 (2026-01-01 to 2026-03-30, 7603200
 seconds, inside the cap) with `now_s` = 1767830400, which are the values §15.5's worked example
 prints — the frozen file lines up with the specification's illustration on purpose.

 X3DH-IKBIND, X3DH-SPKSIG and X3DH-FP READ NO CLOCK and supply no `now_s`. X3DH-SPKSIG's
 `not_before` / `not_after` are SIGNED CONTENT, not a window being evaluated: §5.2 binds both
 timestamps into SPK_SIGN_MSG so an intermediary cannot extend the window, and §5.3 rules 5–6 —
 which do read a clock — live on the initiator's bundle-ingest path and are carried by the two
 handshake vectors and by the `NEG-SPK*` rows.

 THE BUNDLE IS BOTH AN INPUT AND A CROSS-CHECK. Each handshake vector carries `bundle`, the §5.4
 serialization, AND the individual fields inside it. That redundancy is deliberate: the executor
 parses `bundle` through +[IRPreKeyBundle bundleFromData:provider:error:] — §10.3's ordered gate
 plus §5.3 rules 1–4 — and then asserts every parsed field against the separately named input. A
 port whose bundle parser reads a field at the wrong offset fails here as well as in `wire.json`,
 and the named fields are what let a port build B's side without re-deriving anything from the wire
 bytes.

 EVERY BYTE IN `inputs` IS DERIVED FROM A LITERAL IN THIS FILE. The X25519 private scalars are fed
 to the real key generator through IRScriptedRandomSource (§15.5 rule 5) rather than being
 hand-clamped, so what lands in the frozen file is whatever the implementation actually stores —
 which is the §4.2 CLAMPED form, one of the three details §15.5's worked example makes normative in
 shape. The other two are honoured here as well: `IK_*_s_priv` is the 32-byte RFC 8032 SEED and
 never libsodium's 64-byte expanded `sk`, and `not_before` / `not_after` / `now_s` are decimal
 STRINGS.

 NO SIGNATURE IS AN `outputs` FIELD, AND THE MESSAGE BYTES ARE (§3.4, §15.3, §15.5 rule 8). This is
 the reverse of what an earlier revision of this file did, and the inversion mattered twice over.

 Ed25519 signature generation is NOT byte-reproducible across platforms. RFC 8032 §5.1.6 derives the
 nonce deterministically, but §8.2 explicitly permits additional randomness and CryptoKit /
 swift-crypto takes that option: three signings of one message under one seed give three distinct
 valid signatures, none equal to RFC 8032's published one. So `IKB` and `SPK_SIG` are INPUTS on
 X3DH-IKBIND and X3DH-SPKSIG. A runner verifies them against the published public key and message,
 asserts the `*_verified` boolean, and additionally signs the message itself and verifies THAT
 signature — never comparing the two. A regenerate-and-compare assertion would fail a conformant
 Swift port for no defect at all, and §15.6 step 4 would freeze that failure into the contract.

 `IKBIND_MSG` and `SPK_SIGN_MSG` are the byte-normative quantities here — deterministic on every
 platform, and the real interoperability contract — so they are `outputs`, which §15.5 rule 1 makes
 mandatory to check. As `intermediates` they were skippable under rule 2, and they are the only
 assertions in the corpus pinning the 81-byte and 130-byte layouts.
 */

#pragma mark - Fixed key material

/* Ed25519 seeds (§4.2: the 32-byte RFC 8032 seed, never libsodium's 64-byte expanded sk). */
static NSString * const kX3DHAliceEd25519Seed =
    @"a01f2e3d4c5b6a798887766554433221100f1e2d3c4b5a69788796a5b4c3d2e1";
static NSString * const kX3DHBobEd25519Seed =
    @"b02f3e4d5c6b7a898988776655443322110f1e2d3c4b5a69788796a5b4c3d2e2";

/* Raw X25519 scalars as handed to the CSPRNG seam. The stored form — and therefore the form that
   lands in `inputs` — is the §4.2 CLAMP of these, applied by the code under test rather than here,
   and the public halves are derived from the clamped scalar. */
static NSString * const kX3DHAliceX25519Scalar =
    @"a1112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0";
static NSString * const kX3DHBobX25519Scalar =
    @"b1223344556677889900aabbccddeeff1f2e3d4c5b6a798887796a5b4c3d2e1f";
static NSString * const kX3DHSignedPreKeyScalar =
    @"5a334455667788990011aabbccddeeff2f3e4d5c6b7a89988879695a4b3c2d1e";
static NSString * const kX3DHOneTimePreKeyScalar =
    @"6a445566778899001122aabbccddeeff3f4e5d6c7b8a99a8987969584a3b2c1d";

/* §6.1 — "EK_A is a fresh X25519 key pair generated per handshake and used for nothing else." The
   two handshake vectors are two DIFFERENT handshakes, so they get two different ephemerals. Reusing
   one across both would reproduce, inside the frozen corpus, the exact property §6.6 records v3
   getting wrong: `ephemeralKeyPairs.firstObject` meant every session with a peer shared one
   ephemeral. */
static NSString * const kX3DHEphemeralScalarOPK =
    @"e1556677889900112233aabbccddeeff4f5e6d7c8b9aa9b8a879695849382a1b";
static NSString * const kX3DHEphemeralScalarNoOPK =
    @"e2667788990011223344aabbccddeeff5f6e7d8c9baab9c8b88979695a4b3c2d";

#pragma mark - Fixed ids and timestamps

static const uint32_t kX3DHSpkId = 7;
static const uint32_t kX3DHOpkId = 42;

/* §5.3 rules 5–6, as fixed literals that are part of the frozen bytes. 2026-01-01T00:00:00Z to
   2026-03-30T00:00:00Z is 7603200 seconds, inside MAX_SPK_VALIDITY_SECONDS (7776000), and `now_s`
   is 2026-01-08T00:00:00Z, strictly inside `[not_before, not_after)`. These are §15.5's worked
   example's values. */
static const uint64_t kX3DHNotBeforeS = 1767225600ULL;
static const uint64_t kX3DHNotAfterS  = 1774828800ULL;
static const uint64_t kX3DHNowS       = 1767830400ULL;

#pragma mark - Small helpers

/// The bytes of a secret, for a value §15.5 requires be written into `inputs` or checked against
/// `outputs`. Never called on anything this port is not already obliged to publish.
static NSData *IRX3DHDataFromSecret(IRSecretBytes *secret) {
    IRVectorRequire(secret != nil, @"a required secret is nil");

    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

/// One 32-byte Diffie-Hellman term, read out of the retained IKM at its §18 offset.
static NSData *IRX3DHIKMSlice(IRSecretBytes *ikm, NSUInteger offset) {
    IRVectorRequire(ikm != nil, @"IKM was not retained; pass retainIKM:YES");
    IRVectorRequire(offset + (NSUInteger)kIRLenDHOutput <= ikm.length,
                    @"IKM is %lu bytes; cannot read 32 at offset %lu",
                    (unsigned long)ikm.length, (unsigned long)offset);

    return [NSData dataWithBytes:(ikm.constBytes + offset) length:(NSUInteger)kIRLenDHOutput];
}

/**
 §5.5 — the 77-byte fingerprint input, `"nuntius:FP:v4" ‖ IK^s ‖ IK^d`.

 THIS IS THE ONE STRUCTURE IN THIS MODULE THAT THE FRAMEWORK DOES NOT EXPORT A BUILDER FOR: the
 fingerprint input is a static function inside IRPublicIdentity.m, and only the 32-byte digest
 crosses an API boundary. Rather than report `FP_input` as an unexposable intermediate (§15.5 rule
 2 would accept that, and it would cost the ports the one field that localises a fingerprint
 mismatch), it is built here from §5.5's definition — and BOUND to the implementation by the
 assertion both the generator and the executor make: `SHA256(FP_input)` MUST equal the fingerprint
 the framework returns. A hand-built structure that agrees with nothing is worthless; one that is
 required to hash to the implementation's own output is a check.
 */
static NSData *IRX3DHFingerprintInput(IRIdentityKeyPair *keyPair) {
    NSError *error = nil;

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:(NSUInteger)kIRLenFPInput];
    [writer appendBytes:kIRLabelFP length:(NSUInteger)kIRLenLabelFP];
    [writer appendData:keyPair.signingKey.data];
    [writer appendData:keyPair.agreementKey.data];

    NSData *input = [writer finishExpectingLength:(NSUInteger)kIRLenFPInput error:&error];
    IRVectorRequire(input != nil, @"FP input is not %d bytes (§5.5): %@", (int)kIRLenFPInput, error);

    return input;
}

#pragma mark - Deterministic construction (generator side)

/**
 An X25519 pair derived from a fixed scalar through the REAL generator (§15.5 rule 5).

 A fresh IRScriptedRandomSource per pair, holding exactly the 32 bytes
 -generateX25519KeyPairGuarded:error: draws. That source FAILS on exhaustion rather than cycling, so
 a generator that drew more than it scripted stops here instead of silently reusing bytes — and the
 leftover check catches the opposite mistake, scripting bytes nothing consumed.
 */
static IRX25519KeyPair *IRX3DHX25519PairFromScalar(NSString *scalarHex) {
    NSData *scalar = IRVectorBytes(scalarHex);
    IRVectorRequire(scalar.length == 32, @"X25519 scalar must be 32 bytes, got %lu",
                    (unsigned long)scalar.length);

    IRScriptedRandomSource *source = [IRScriptedRandomSource sourceWithData:scalar];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;

    /* guarded:NO — §13.3 reserves sodium_malloc for the long-lived identity and prekey privates,
       and a handshake ephemeral is explicitly not one of them (§6.1, IRX3DH.h). */
    IRX25519KeyPair *pair = [provider generateX25519KeyPairGuarded:NO error:&error];
    IRVectorRequire(pair != nil, @"X25519 generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"scripted %lu bytes for one X25519 pair and %lu were left over",
                    (unsigned long)scalar.length, (unsigned long)source.bytesRemaining);

    return pair;
}

/// An identity from a fixed Ed25519 seed and a fixed X25519 scalar, with a GENUINE `IKB` (§5.1).
static IRIdentity *IRX3DHIdentity(NSString *seedHex, NSString *scalarHex) {
    NSData *seedBytes = IRVectorBytes(seedHex);
    NSData *scalarBytes = IRVectorBytes(scalarHex);
    IRVectorRequire(seedBytes.length == 32, @"Ed25519 seed must be 32 bytes");
    IRVectorRequire(scalarBytes.length == 32, @"X25519 scalar must be 32 bytes");

    /* +generateWithProvider: draws the Ed25519 seed first and the X25519 scalar second, then signs
       IKBIND_MSG and VERIFIES the result before returning (§3.4's self-test). Scripting the two in
       that order reproduces a whole identity, IKB included, with no injection point the production
       API exposes. */
    IRScriptedRandomSource *source =
        [IRScriptedRandomSource sourceWithDataItems:@[seedBytes, scalarBytes]];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IRIdentity *identity = [IRIdentity generateWithProvider:provider error:&error];
    IRVectorRequire(identity != nil, @"identity generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"identity generation left %lu scripted bytes unread",
                    (unsigned long)source.bytesRemaining);

    return identity;
}

/// B's signed prekey record: a fixed scalar through the real generator, then a GENUINE `SPK_SIG`
/// over §5.2's SPK_SIGN_MSG under `IK_B^s_priv` (§5.2, §5.3 rule 4).
static IRSignedPreKeyRecord *IRX3DHSignedPreKeyRecord(IRIdentity *responder) {
    NSData *scalar = IRVectorBytes(kX3DHSignedPreKeyScalar);

    IRScriptedRandomSource *source = [IRScriptedRandomSource sourceWithData:scalar];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IRSignedPreKeyRecord *record = [IRSignedPreKeyRecord generateWithIdentity:responder
                                                                        spkId:kX3DHSpkId
                                                                   notBeforeS:kX3DHNotBeforeS
                                                                    notAfterS:kX3DHNotAfterS
                                                                     provider:provider
                                                                        error:&error];
    IRVectorRequire(record != nil, @"signed prekey generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"signed prekey generation left %lu scripted bytes unread",
                    (unsigned long)source.bytesRemaining);

    return record;
}

/**
 B's one-time prekey record.

 `createdAtUnixSecs` is RESPONDER-LOCAL and never reaches the bundle (§5.3: the 36-byte entry may
 not be widened, because `251 + 36 * opk_count` depends on its width). It is therefore not part of
 the frozen bytes and is not in `inputs`: nothing in §6 reads it, and the OPK_MAX_AGE_S expiry that
 does read it is `NEG-OPK-EXPIRED`'s subject, not this file's.
 */
static IROneTimePreKeyRecord *IRX3DHOneTimePreKeyRecord(void) {
    NSData *scalar = IRVectorBytes(kX3DHOneTimePreKeyScalar);

    IRScriptedRandomSource *source = [IRScriptedRandomSource sourceWithData:scalar];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IROneTimePreKeyRecord *record = [IROneTimePreKeyRecord generateWithOpkId:kX3DHOpkId
                                                           createdAtUnixSecs:kX3DHNotBeforeS
                                                                    provider:provider
                                                                       error:&error];
    IRVectorRequire(record != nil, @"one-time prekey generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"one-time prekey generation left %lu scripted bytes unread",
                    (unsigned long)source.bytesRemaining);

    return record;
}

/// A provider whose clock is PINNED to `now_s` (§15.5 rule 6). The ambient skew is not applied, so
/// the driver's ten-years-forward run cannot move it — which is the whole property §15.6 tests.
static id<IRCryptoProvider> IRX3DHProviderAtNow(void) {
    return IRVectorProviderWithEnvironment(
        IRVectorEnvironmentAtUnixMilliseconds(kX3DHNowS * 1000ULL, nil));
}

#pragma mark - Generator: X3DH-OPK / X3DH-NOOPK

static NSDictionary *IRX3DHHandshakeVector(NSString *identifier,
                                           BOOL withOneTimePreKey,
                                           NSString *ephemeralScalarHex,
                                           NSString *vectorDescription) {
    NSError *error = nil;

    IRIdentity *alice = IRX3DHIdentity(kX3DHAliceEd25519Seed, kX3DHAliceX25519Scalar);
    IRIdentity *bob = IRX3DHIdentity(kX3DHBobEd25519Seed, kX3DHBobX25519Scalar);

    IRSignedPreKeyRecord *signedPreKey = IRX3DHSignedPreKeyRecord(bob);
    IROneTimePreKeyRecord *oneTimePreKey = withOneTimePreKey ? IRX3DHOneTimePreKeyRecord() : nil;

    IROPKFlag opkFlag = withOneTimePreKey ? IROPKFlagPresent : IROPKFlagAbsent;
    uint32_t opkId = withOneTimePreKey ? kX3DHOpkId : 0;

    /* §5.4 — what B publishes and A fetches. The encoder is the record-based one, so `IKB` and
       `SPK_SIG` inside these bytes are the genuine signatures produced above. */
    NSArray<IROneTimePreKeyRecord *> *opkRecords = withOneTimePreKey ? @[oneTimePreKey] : @[];
    NSData *bundleData = [IRPreKeyBundle serializeWithIdentity:bob.publicIdentity
                                            signedPreKeyRecord:signedPreKey
                                          oneTimePreKeyRecords:opkRecords
                                                         error:&error];
    IRVectorRequire(bundleData != nil, @"bundle encoding failed: %@", error);
    IRVectorRequire(bundleData.length ==
                        (NSUInteger)kIRLenBundlePrefix +
                        (NSUInteger)kIRLenBundleOPKEntry * (withOneTimePreKey ? 1u : 0u),
                    @"bundle length is 251 + 36 * opk_count (§5.4), got %lu",
                    (unsigned long)bundleData.length);

    id<IRCryptoProvider> provider = IRX3DHProviderAtNow();

    /* §10.3's ordered gate then §5.3 rules 1–4. Rules 5–6 are NOT run here — the parser reads no
       clock deliberately — they run inside +initiatorResultWithIdentity:… below, from `now_s`. */
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleData
                                                   provider:provider
                                                      error:&error];
    IRVectorRequire(bundle != nil, @"bundle parse failed: %@", error);

    IRX25519KeyPair *ephemeral = IRX3DHX25519PairFromScalar(ephemeralScalarHex);

    /* Both halves are read BEFORE the handshake: +initiatorResultWithIdentity:… consumes the pair
       and zeroizes its private half before returning, on the success path and on every failure path
       (§6.1, §13.3). The public half survives in the prologue, but `EK_A_priv` would be 32 zero
       bytes by the time the vector dictionary is built. */
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;
    NSData *ephemeralPrivateBytes = IRX3DHDataFromSecret(ephemeral.privateKey);

    IRX3DHResult *initiator = [IRX3DH initiatorResultWithIdentity:alice
                                                           bundle:bundle
                                                 ephemeralKeyPair:ephemeral
                                                   nowUnixSeconds:kX3DHNowS
                                                         provider:provider
                                                        retainIKM:YES
                                                            error:&error];
    IRVectorRequire(initiator != nil, @"initiator agreement failed: %@", error);

    IRX3DHResult *responder =
        [IRX3DH responderResultWithIdentity:bob
                          initiatorIdentity:alice.publicIdentity
                            ephemeralPublic:ephemeralPublic
                           signedPreKeyPair:signedPreKey.keyPair
                                      spkId:kX3DHSpkId
                                    opkFlag:opkFlag
                                      opkId:opkId
                          oneTimePreKeyPair:(withOneTimePreKey ? oneTimePreKey.keyPair : nil)
                                   provider:provider
                                  retainIKM:YES
                                      error:&error];
    IRVectorRequire(responder != nil, @"responder agreement failed: %@", error);

    /* §6.1 — "the mirror image, in the identical order". A generator that froze a corpus in which
       the two sides disagreed would freeze a contract no port could satisfy. */
    IRVectorRequire([IRX3DHDataFromSecret(initiator.ikm)
                        isEqualToData:IRX3DHDataFromSecret(responder.ikm)],
                    @"%@: A and B derived different IKM", identifier);
    IRVectorRequire([initiator.transcript isEqualToData:responder.transcript],
                    @"%@: A and B derived different TRANSCRIPT", identifier);
    IRVectorRequire([IRX3DHDataFromSecret(initiator.sharedKey)
                        isEqualToData:IRX3DHDataFromSecret(responder.sharedKey)],
                    @"%@: A and B derived different SK", identifier);
    IRVectorRequire([initiator.sessionAD.bytes isEqualToData:responder.sessionAD.bytes],
                    @"%@: A and B derived different SESSION_AD", identifier);
    IRVectorRequire([initiator.handshakeId isEqualToData:responder.handshakeId],
                    @"%@: A and B derived different handshake_id", identifier);

    /* §6.3 and §18 — the length assertions §6.3 makes mandatory, restated at the freeze boundary. */
    NSUInteger expectedIKMLength =
        withOneTimePreKey ? (NSUInteger)kIRLenIKMOPK : (NSUInteger)kIRLenIKMNoOPK;
    IRVectorRequire(initiator.ikm.length == expectedIKMLength,
                    @"%@: IKM is %lu bytes, expected %lu — DH4 is OMITTED, not zero-filled (§6.3)",
                    identifier, (unsigned long)initiator.ikm.length,
                    (unsigned long)expectedIKMLength);
    IRVectorRequire(initiator.transcript.length == (NSUInteger)kIRLenTranscript,
                    @"%@: TRANSCRIPT is %lu bytes, expected 259 (§6.2)",
                    identifier, (unsigned long)initiator.transcript.length);
    IRVectorRequire(initiator.transcriptHash.length == (NSUInteger)kIRLenTH, @"%@: TH", identifier);
    IRVectorRequire(initiator.x3dhInfo.length == (NSUInteger)kIRLenX3DHInfo,
                    @"%@: X3DH info is %lu bytes, expected 47 (§6.3)",
                    identifier, (unsigned long)initiator.x3dhInfo.length);
    IRVectorRequire(initiator.sharedKey.length == (NSUInteger)kIRLenSK, @"%@: SK", identifier);
    IRVectorRequire(initiator.sessionAD.bytes.length == (NSUInteger)kIRLenSessionAD,
                    @"%@: SESSION_AD", identifier);
    IRVectorRequire(initiator.handshakeId.length == (NSUInteger)kIRLenHandshakeId,
                    @"%@: handshake_id", identifier);

    NSMutableDictionary *inputs = [@{
        @"entry_point"  : @"parse_bundle",

        @"IK_A_s_priv"  : IRVectorHex(IRX3DHDataFromSecret(alice.signingKeyPair.seed)),
        @"IK_A_s_pub"   : IRVectorHex(alice.signingKeyPair.publicKey.data),
        @"IK_A_d_priv"  : IRVectorHex(IRX3DHDataFromSecret(alice.agreementKeyPair.privateKey)),
        @"IK_A_d_pub"   : IRVectorHex(alice.agreementKeyPair.publicKey.data),
        @"IKB_A"        : IRVectorHex(alice.binding.data),

        @"IK_B_s_priv"  : IRVectorHex(IRX3DHDataFromSecret(bob.signingKeyPair.seed)),
        @"IK_B_s_pub"   : IRVectorHex(bob.signingKeyPair.publicKey.data),
        @"IK_B_d_priv"  : IRVectorHex(IRX3DHDataFromSecret(bob.agreementKeyPair.privateKey)),
        @"IK_B_d_pub"   : IRVectorHex(bob.agreementKeyPair.publicKey.data),
        @"IKB_B"        : IRVectorHex(bob.binding.data),

        @"EK_A_priv"    : IRVectorHex(ephemeralPrivateBytes),
        @"EK_A_pub"     : IRVectorHex(ephemeralPublic.data),

        @"spk_id"       : @(kX3DHSpkId),
        @"SPK_B_priv"   : IRVectorHex(IRX3DHDataFromSecret(signedPreKey.keyPair.privateKey)),
        @"SPK_B_pub"    : IRVectorHex(signedPreKey.keyPair.publicKey.data),
        @"SPK_SIG"      : IRVectorHex(signedPreKey.signature.data),
        @"not_before"   : IRVectorUInt64String(kX3DHNotBeforeS),
        @"not_after"    : IRVectorUInt64String(kX3DHNotAfterS),

        @"opk_flag"     : @((uint32_t)opkFlag),
        @"opk_id"       : @(opkId),

        @"bundle"       : IRVectorHex(bundleData),
        @"now_s"        : IRVectorUInt64String(kX3DHNowS),
    } mutableCopy];

    if (withOneTimePreKey) {
        inputs[@"OPK_B_priv"] = IRVectorHex(IRX3DHDataFromSecret(oneTimePreKey.keyPair.privateKey));
        inputs[@"OPK_B_pub"] = IRVectorHex(oneTimePreKey.keyPair.publicKey.data);
    }

    NSMutableDictionary *intermediates = [@{
        @"DH1"        : IRVectorHex(IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH1)),
        @"DH2"        : IRVectorHex(IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH2)),
        @"DH3"        : IRVectorHex(IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH3)),
        @"TRANSCRIPT" : IRVectorHex(initiator.transcript),
        @"TH"         : IRVectorHex(initiator.transcriptHash),
        @"IKM"        : IRVectorHex(IRX3DHDataFromSecret(initiator.ikm)),
        @"IKM_len"    : @(initiator.ikm.length),
        @"X3DH_info"  : IRVectorHex(initiator.x3dhInfo),
    } mutableCopy];

    /* §6.3 — "DH4 is OMITTED, not zero-filled, when no OPK is used." The absence of the key is the
       assertion: a port that zero-fills produces a 160-byte IKM in both cases and fails on IKM_len,
       and a port that emits a DH4 intermediate here fails §15.5 rule 3's sibling on the way in. */
    if (withOneTimePreKey) {
        intermediates[@"DH4"] = IRVectorHex(IRX3DHIKMSlice(initiator.ikm,
                                                           (NSUInteger)kIROffIKMDH4));
    }

    return @{
        @"id"            : identifier,
        @"kind"          : @"x3dh",
        @"description"   : vectorDescription,
        @"expect"        : @"ok",
        @"inputs"        : inputs,
        @"intermediates" : intermediates,
        @"outputs"       : @{
            @"SK"           : IRVectorHex(IRX3DHDataFromSecret(initiator.sharedKey)),
            @"SESSION_AD"   : IRVectorHex(initiator.sessionAD.bytes),
            @"handshake_id" : IRVectorHex(initiator.handshakeId),
        },
    };
}

#pragma mark - Generator: X3DH-IKBIND

static NSDictionary *IRX3DHIdentityBindingVector(void) {
    NSError *error = nil;

    IRIdentity *alice = IRX3DHIdentity(kX3DHAliceEd25519Seed, kX3DHAliceX25519Scalar);

    NSData *message = IRIKBindMessage(alice.identityKeyPair, &error);
    IRVectorRequire(message != nil, @"IKBIND_MSG: %@", error);
    IRVectorRequire(message.length == (NSUInteger)kIRLenIKBindMsg,
                    @"IKBIND_MSG is %lu bytes, expected 81 (§5.1)",
                    (unsigned long)message.length);

    return @{
        @"id"          : @"X3DH-IKBIND",
        @"kind"        : @"x3dh",
        /* No ASCII double quotes anywhere in a description, here or below. NSJSONSerialization
           would write them as \" — the only backslash in the whole corpus — and §15.6 step 3 has a
           human reviewing these bytes. The §18 labels are quoted typographically instead. */
        @"description" : @"§5.1's IKBIND_MSG — “nuntius:IKBIND:v4” ‖ IK^s ‖ IK^d, 81 bytes — as an "
                         @"OUTPUT, because those bytes are deterministic and byte-normative and "
                         @"this is the only vector that pins their layout. The Ed25519 signature "
                         @"over them is an INPUT, to be verified and never regenerated for "
                         @"comparison (§3.4, §15.5 rule 8): signature generation is not "
                         @"byte-reproducible across platforms, so a runner MUST verify IKB against "
                         @"IK_s_pub and IKBIND_MSG, MUST NOT compare its own signing to it, and "
                         @"SHOULD additionally sign IKBIND_MSG itself and verify that signature. "
                         @"IKB is what makes §5.5's identity PAIR unforgeable: without it an "
                         @"attacker could present a victim's genuine IK^s beside an "
                         @"attacker-controlled IK^d, complete a cryptographically sound session, "
                         @"and be attributed to the victim.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"IK_s_priv" : IRVectorHex(IRX3DHDataFromSecret(alice.signingKeyPair.seed)),
            @"IK_s_pub"  : IRVectorHex(alice.signingKeyPair.publicKey.data),
            @"IK_d_priv" : IRVectorHex(IRX3DHDataFromSecret(alice.agreementKeyPair.privateKey)),
            @"IK_d_pub"  : IRVectorHex(alice.agreementKeyPair.publicKey.data),
            @"IKB"       : IRVectorHex(alice.binding.data),
        },
        @"outputs" : @{
            @"IKBIND_MSG"     : IRVectorHex(message),
            @"IKBIND_MSG_len" : @(message.length),
            @"IKB_verified"   : @YES,
        },
    };
}

#pragma mark - Generator: X3DH-SPKSIG

static NSDictionary *IRX3DHSignedPreKeySignatureVector(void) {
    NSError *error = nil;

    IRIdentity *bob = IRX3DHIdentity(kX3DHBobEd25519Seed, kX3DHBobX25519Scalar);
    IRSignedPreKeyRecord *record = IRX3DHSignedPreKeyRecord(bob);

    NSData *message = IRSPKSignMessage(bob.identityKeyPair,
                                       kX3DHSpkId,
                                       record.keyPair.publicKey,
                                       kX3DHNotBeforeS,
                                       kX3DHNotAfterS,
                                       &error);
    IRVectorRequire(message != nil, @"SPK_SIGN_MSG: %@", error);
    IRVectorRequire(message.length == (NSUInteger)kIRLenSPKSignMsg,
                    @"SPK_SIGN_MSG is %lu bytes, expected 130 (§5.2)",
                    (unsigned long)message.length);

    /* THE SIGNED PREKEY'S PRIVATE HALF IS NOT IN `inputs`, DELIBERATELY. SPK_SIGN_MSG covers the
       PUBLIC key only, so nothing on this vector's path reads `SPK_priv`, and §15.5 rule 3 makes an
       input no runner reads a failure rather than a harmless extra. The private half is in
       `X3DH-OPK` / `X3DH-NOOPK`, where DH1 and DH3 actually consume it. */
    return @{
        @"id"          : @"X3DH-SPKSIG",
        @"kind"        : @"x3dh",
        @"description" : @"§5.2's SPK_SIGN_MSG — “nuntius:SPK:v4” ‖ IK^s ‖ IK^d ‖ uint32_be(spk_id) "
                         @"‖ SPK ‖ uint64_be(not_before) ‖ uint64_be(not_after), 130 bytes — as an "
                         @"OUTPUT, because those bytes are deterministic and byte-normative and "
                         @"this is the only vector that pins their layout. The Ed25519 signature "
                         @"over them is an INPUT, verified but never regenerated for comparison "
                         @"(§3.4, §15.5 rule 8): a runner MUST verify SPK_SIG against IK_s_pub and "
                         @"SPK_SIGN_MSG, MUST NOT compare its own signing to it, and SHOULD "
                         @"additionally sign SPK_SIGN_MSG itself and verify that signature. Binding "
                         @"spk_id stops a signature being transplanted onto another prekey slot, "
                         @"and both timestamps sit INSIDE the signature so the validity window "
                         @"cannot be extended by an intermediary. This vector reads no clock: the "
                         @"timestamps are signed content, not a window being evaluated — §15.3 "
                         @"grants the carve-out by name, and §5.3 rules 5–6 are carried by "
                         @"X3DH-OPK and the NEG-SPK* rows.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"IK_s_priv"  : IRVectorHex(IRX3DHDataFromSecret(bob.signingKeyPair.seed)),
            @"IK_s_pub"   : IRVectorHex(bob.signingKeyPair.publicKey.data),
            @"IK_d_pub"   : IRVectorHex(bob.agreementKeyPair.publicKey.data),
            @"spk_id"     : @(kX3DHSpkId),
            @"SPK"        : IRVectorHex(record.keyPair.publicKey.data),
            @"not_before" : IRVectorUInt64String(kX3DHNotBeforeS),
            @"not_after"  : IRVectorUInt64String(kX3DHNotAfterS),
            @"SPK_SIG"    : IRVectorHex(record.signature.data),
        },
        @"outputs" : @{
            @"SPK_SIGN_MSG"     : IRVectorHex(message),
            @"SPK_SIGN_MSG_len" : @(message.length),
            @"SPK_SIG_verified" : @YES,
        },
    };
}

#pragma mark - Generator: X3DH-FP

static NSDictionary *IRX3DHFingerprintVector(void) {
    NSError *error = nil;

    IRIdentity *alice = IRX3DHIdentity(kX3DHAliceEd25519Seed, kX3DHAliceX25519Scalar);

    NSData *fingerprintInput = IRX3DHFingerprintInput(alice.identityKeyPair);

    IRFingerprint *fingerprint = [alice fingerprint:&error];
    IRVectorRequire(fingerprint != nil, @"fingerprint: %@", error);
    IRVectorRequire(fingerprint.length == (NSUInteger)kIRLenFingerprint, @"FP is not 32 bytes");

    /* The binding described on IRX3DHFingerprintInput: the locally built §5.5 input MUST hash to
       the fingerprint the framework returned, or the intermediate about to be frozen describes
       nothing. */
    NSData *digest = [IRVectorAmbientProvider() sha256OfData:fingerprintInput error:&error];
    IRVectorRequire(digest != nil, @"SHA-256 of the FP input: %@", error);
    IRVectorRequire([digest isEqualToData:fingerprint.data],
                    @"SHA256(FP input) does not match -fingerprint:; the §5.5 input built here "
                    @"disagrees with the one IRPublicIdentity builds");

    /* NO PRIVATE KEYS. FP is a pure function of the two PUBLIC halves (§5.5), so a runner needs
       nothing else — and this is the one vector in the file that every port can check with no
       signing, no agreement and no clock. */
    return @{
        @"id"          : @"X3DH-FP",
        @"kind"        : @"x3dh",
        @"description" : @"§5.5's public fingerprint / safety number, FP = SHA256(“nuntius:FP:v4” "
                         @"‖ IK^s ‖ IK^d) over a 77-byte input. §5.5 requires applications key "
                         @"identity lookup, contact registration, pinning and any displayed "
                         @"identity on the PAIR or equivalently on this value; an application that "
                         @"keys on IK^s alone is not conformant.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"IK_s_pub" : IRVectorHex(alice.signingKeyPair.publicKey.data),
            @"IK_d_pub" : IRVectorHex(alice.agreementKeyPair.publicKey.data),
        },
        @"intermediates" : @{
            @"FP_input"     : IRVectorHex(fingerprintInput),
            @"FP_input_len" : @(fingerprintInput.length),
        },
        @"outputs" : @{
            @"FP" : IRVectorHex(fingerprint.data),
        },
    };
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForX3DH(void) {
    NSDictionary *opk = IRX3DHHandshakeVector(
        @"X3DH-OPK",
        YES,
        kX3DHEphemeralScalarOPK,
        @"Full X3DH handshake WITH a one-time prekey, run in both directions from one set of fixed "
        @"keys. IKM is 160 bytes: F32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4. The bundle is ingested through §10.3 "
        @"and §5.3 rules 1–4, and rules 5–6 run against inputs.now_s, which sits inside the fixed "
        @"not_before / not_after window. A port that reads only the first 32 bytes of IKM — v3's "
        @"defect 1 — still agrees with itself and still fails here, because DH2, DH3 and DH4 are "
        @"frozen alongside SK.");

    NSDictionary *noOPK = IRX3DHHandshakeVector(
        @"X3DH-NOOPK",
        NO,
        kX3DHEphemeralScalarNoOPK,
        @"The same handshake with NO one-time prekey — a legitimate, weaker mode (§6.6) with the "
        @"replay caveat of §17.3, not an error. IKM is 128 bytes and DH4 is OMITTED, not "
        @"zero-filled, so a port that zero-fills produces 160 bytes in both cases and fails on "
        @"IKM_len. TRANSCRIPT is still 259 bytes: §6.2 encodes the absent OPK as opk_id 0 and 32 "
        @"zero bytes, the OPPOSITE convention from §6.3's IKM, and a port that unifies the two "
        @"breaks interoperation in exactly one of them.");

    return @[
        opk,
        noOPK,
        IRX3DHIdentityBindingVector(),
        IRX3DHSignedPreKeySignatureVector(),
        IRX3DHFingerprintVector(),
    ];
}

#pragma mark - Executor helpers

/**
 THE GUARD IS NOT DEFENSIVE PROGRAMMING, IT IS §13.4.

 A nil passed for a `_Nonnull` parameter is a caller contract violation that traps through
 IRRequireArgument — it is not an error code and it is not recoverable. A vector whose hex is the
 wrong width produces a nil nominal type, and passing that on would abort the whole test binary with
 a trap instead of reporting which vector was malformed. Every constructed value is therefore
 checked before it is handed to the implementation.

 `testCase` and `vectorCase` must be in scope, which they are in every executor below.
 */
#define IRX3DHGuard(value, ...)                                                                    \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRVectorRecordFailure(testCase, __VA_ARGS__);                                          \
            [vectorCase finish];                                                                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

/**
 An X25519 key pair from the two halves a vector supplies.

 The private half arrives in §4.2 CLAMPED form and +fromData:guarded:error: re-applies the clamp —
 idempotent, and it changes no cryptographic output, because RFC 7748 §5 clamps internally anyway.
 The pair constructor does NOT verify that the public half corresponds to the private one; it
 cannot, because that needs a scalar multiplication and the crypto seam sits above these value
 types. The frozen halves came from one real generation, so they correspond.

 `guarded:NO` throughout. §13.3 reserves sodium_malloc for long-lived privates in a running process;
 a runner rebuilding a fixture from a frozen file is not that, and iOS arm64 pages are 16 KiB.
 */
static IRX25519KeyPair * _Nullable IRX3DHKeyPairFromBytes(NSData *privateBytes,
                                                          NSData *publicBytes,
                                                          NSError * _Nullable * _Nullable error) {
    IRX25519Private *privateKey = [IRX25519Private fromData:privateBytes guarded:NO error:error];
    if (privateKey == nil) {
        return nil;
    }

    IRX25519Public *publicKey = [IRX25519Public fromData:publicBytes error:error];
    if (publicKey == nil) {
        return nil;
    }

    return [IRX25519KeyPair pairWithPublicKey:publicKey privateKey:privateKey error:error];
}

/**
 A local identity from the four key halves and the stored `IKB`.

 +identityWithSigningKeyPair:agreementKeyPair:binding:provider:error: is the REHYDRATE constructor,
 and it VERIFIES the binding — §5.5's "after state restore" ingest point. That is what a runner
 wants here: re-signing instead of verifying is v3's defect at IRTripleDHService.m:66-68, where a
 peer's signature was overwritten by a locally manufactured one that later code then found "valid",
 destroying the evidence rather than merely skipping the check.
 */
static IRIdentity * _Nullable IRX3DHIdentityFromBytes(NSData *seedBytes,
                                                      NSData *signingPublicBytes,
                                                      NSData *agreementPrivateBytes,
                                                      NSData *agreementPublicBytes,
                                                      NSData *bindingBytes,
                                                      id<IRCryptoProvider> provider,
                                                      NSError * _Nullable * _Nullable error) {
    IREd25519Private *seed = [IREd25519Private fromData:seedBytes guarded:NO error:error];
    if (seed == nil) {
        return nil;
    }

    IREd25519Public *signingPublic = [IREd25519Public fromData:signingPublicBytes error:error];
    if (signingPublic == nil) {
        return nil;
    }

    IREd25519KeyPair *signingKeyPair = [IREd25519KeyPair pairWithPublicKey:signingPublic
                                                                      seed:seed
                                                                     error:error];
    if (signingKeyPair == nil) {
        return nil;
    }

    IRX25519KeyPair *agreementKeyPair =
        IRX3DHKeyPairFromBytes(agreementPrivateBytes, agreementPublicBytes, error);
    if (agreementKeyPair == nil) {
        return nil;
    }

    IREd25519Signature *binding = [IREd25519Signature fromData:bindingBytes error:error];
    if (binding == nil) {
        return nil;
    }

    return [IRIdentity identityWithSigningKeyPair:signingKeyPair
                                 agreementKeyPair:agreementKeyPair
                                          binding:binding
                                         provider:provider
                                            error:error];
}

#pragma mark - Executor: X3DH-OPK / X3DH-NOOPK

static void IRX3DHRunHandshakeVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    /* Every input is read FIRST, so that §15.5 rule 3's consumption bookkeeping is complete even on
       a path that then bails out. */
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];

    NSData *aliceSeed = [vectorCase dataInput:@"IK_A_s_priv"];
    NSData *aliceSigningPublic = [vectorCase dataInput:@"IK_A_s_pub"];
    NSData *aliceAgreementPrivate = [vectorCase dataInput:@"IK_A_d_priv"];
    NSData *aliceAgreementPublic = [vectorCase dataInput:@"IK_A_d_pub"];
    NSData *aliceBinding = [vectorCase dataInput:@"IKB_A"];

    NSData *bobSeed = [vectorCase dataInput:@"IK_B_s_priv"];
    NSData *bobSigningPublic = [vectorCase dataInput:@"IK_B_s_pub"];
    NSData *bobAgreementPrivate = [vectorCase dataInput:@"IK_B_d_priv"];
    NSData *bobAgreementPublic = [vectorCase dataInput:@"IK_B_d_pub"];
    NSData *bobBinding = [vectorCase dataInput:@"IKB_B"];

    NSData *ephemeralPrivate = [vectorCase dataInput:@"EK_A_priv"];
    NSData *ephemeralPublicBytes = [vectorCase dataInput:@"EK_A_pub"];

    uint32_t spkId = [vectorCase uint32Input:@"spk_id"];
    NSData *signedPreKeyPrivate = [vectorCase dataInput:@"SPK_B_priv"];
    NSData *signedPreKeyPublic = [vectorCase dataInput:@"SPK_B_pub"];
    NSData *signedPreKeySignature = [vectorCase dataInput:@"SPK_SIG"];
    uint64_t notBeforeS = [vectorCase uint64Input:@"not_before"];
    uint64_t notAfterS = [vectorCase uint64Input:@"not_after"];

    uint32_t opkFlagRaw = [vectorCase uint32Input:@"opk_flag"];
    uint32_t opkId = [vectorCase uint32Input:@"opk_id"];
    NSData *oneTimePreKeyPrivate = [vectorCase optionalDataInput:@"OPK_B_priv"];
    NSData *oneTimePreKeyPublic = [vectorCase optionalDataInput:@"OPK_B_pub"];

    NSData *bundleBytes = [vectorCase dataInput:@"bundle"];
    uint64_t nowS = [vectorCase uint64Input:@"now_s"];

    if (![entryPoint isEqualToString:@"parse_bundle"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"parse_bundle\"",
                              vectorCase.identifier, entryPoint);
    }

    if (opkFlagRaw != (uint32_t)IROPKFlagAbsent && opkFlagRaw != (uint32_t)IROPKFlagPresent) {
        IRVectorRecordFailure(testCase, @"[%@] opk_flag is %u; §6.2 admits only 0x00 and 0x01",
                              vectorCase.identifier, (unsigned)opkFlagRaw);
        [vectorCase finish];
        return;
    }

    IROPKFlag opkFlag = (IROPKFlag)opkFlagRaw;
    BOOL withOneTimePreKey = (opkFlag == IROPKFlagPresent);

    if (withOneTimePreKey != (oneTimePreKeyPrivate != nil) ||
        withOneTimePreKey != (oneTimePreKeyPublic != nil)) {
        IRVectorRecordFailure(testCase,
                              @"[%@] opk_flag is %u but OPK_B_priv/OPK_B_pub are %@present",
                              vectorCase.identifier, (unsigned)opkFlagRaw,
                              oneTimePreKeyPrivate ? @"" : @"not ");
        [vectorCase finish];
        return;
    }

    /* §15.5 rule 6 — the clock is PINNED to `now_s`, not merely passed alongside an ambient one.
       The driver's ten-years-forward run is what makes the difference observable: a port that
       reached for the host clock anywhere on this path moves and this vector fails. */
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorEnvironmentAtUnixMilliseconds(nowS * 1000ULL, nil));

    IRIdentity *alice = IRX3DHIdentityFromBytes(aliceSeed,
                                                aliceSigningPublic,
                                                aliceAgreementPrivate,
                                                aliceAgreementPublic,
                                                aliceBinding,
                                                provider,
                                                &error);
    IRX3DHGuard(alice, @"[%@] A's identity could not be rehydrated (IKB_A must verify, §5.1): %@",
                vectorCase.identifier, error);

    IRIdentity *bob = IRX3DHIdentityFromBytes(bobSeed,
                                              bobSigningPublic,
                                              bobAgreementPrivate,
                                              bobAgreementPublic,
                                              bobBinding,
                                              provider,
                                              &error);
    IRX3DHGuard(bob, @"[%@] B's identity could not be rehydrated (IKB_B must verify, §5.1): %@",
                vectorCase.identifier, error);

    /* §10.3's ordered gate, then §5.3 rules 2–4. Rules 5–6 are NOT here: the parser reads no clock
       deliberately, and they run inside the initiator entry point below. */
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleBytes
                                                   provider:provider
                                                      error:&error];
    IRX3DHGuard(bundle, @"[%@] the bundle failed §10.3 / §5.3 rules 1–4: %@",
                vectorCase.identifier, error);

    /* THE REDUNDANCY IS THE CHECK. `bundle` and the named B-side fields describe the same values,
       so a parser reading a field at the wrong §5.4 offset disagrees here. */
    if (![bundle.identity.keyPair isEqualToIdentityKeyPair:bob.identityKeyPair]) {
        IRVectorRecordFailure(testCase, @"[%@] the parsed bundle's identity is not B's pair",
                              vectorCase.identifier);
    }

    if (bundle.spkId != spkId || bundle.notBeforeS != notBeforeS || bundle.notAfterS != notAfterS) {
        IRVectorRecordFailure(testCase,
                              @"[%@] parsed bundle: spk_id %u/%u, not_before %llu/%llu, "
                              @"not_after %llu/%llu",
                              vectorCase.identifier,
                              (unsigned)bundle.spkId, (unsigned)spkId,
                              (unsigned long long)bundle.notBeforeS,
                              (unsigned long long)notBeforeS,
                              (unsigned long long)bundle.notAfterS,
                              (unsigned long long)notAfterS);
    }

    if (![bundle.signedPreKey.data isEqualToData:signedPreKeyPublic]) {
        IRVectorRecordFailure(testCase, @"[%@] the parsed bundle's SPK is not SPK_B_pub",
                              vectorCase.identifier);
    }

    if (![bundle.signedPreKeySignature.data isEqualToData:signedPreKeySignature]) {
        IRVectorRecordFailure(testCase, @"[%@] the parsed bundle's SPK_SIG is not SPK_SIG",
                              vectorCase.identifier);
    }

    /* §5.4 — "a bundle fetched for a single handshake MUST carry opk_count of 0 or 1", and the
       initiator's OPK selection is -firstUsableOPKEntry, never an index the caller chooses. */
    IRPreKeyBundleOPKEntry *bundleOPK = [bundle firstUsableOPKEntry];

    if (withOneTimePreKey) {
        if (bundleOPK == nil || bundleOPK.opkId != opkId ||
            ![bundleOPK.publicKey.data isEqualToData:oneTimePreKeyPublic]) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] the bundle's first usable OPK is not (opk_id %u, OPK_B_pub)",
                                  vectorCase.identifier, (unsigned)opkId);
        }
    } else if (bundleOPK != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] opk_flag is 0x00 but the bundle carries a usable OPK entry",
                              vectorCase.identifier);
    }

    IRX25519KeyPair *ephemeral =
        IRX3DHKeyPairFromBytes(ephemeralPrivate, ephemeralPublicBytes, &error);
    IRX3DHGuard(ephemeral, @"[%@] EK_A: %@", vectorCase.identifier, error);

    /* Read BEFORE the handshake: the initiator entry point consumes the pair and zeroizes its
       private half before returning, on the success path and on every failure path (§6.1, §13.3).
       The public half is an immutable value and survives. */
    IRX25519Public *ephemeralPublic = ephemeral.publicKey;

    IRX25519KeyPair *signedPreKeyPair =
        IRX3DHKeyPairFromBytes(signedPreKeyPrivate, signedPreKeyPublic, &error);
    IRX3DHGuard(signedPreKeyPair, @"[%@] SPK_B: %@", vectorCase.identifier, error);

    IRX25519KeyPair *oneTimePreKeyPair = nil;
    if (withOneTimePreKey) {
        oneTimePreKeyPair =
            IRX3DHKeyPairFromBytes(oneTimePreKeyPrivate, oneTimePreKeyPublic, &error);
        IRX3DHGuard(oneTimePreKeyPair, @"[%@] OPK_B: %@", vectorCase.identifier, error);
    }

    /* §6.1–§6.5, initiator direction. §5.3 rules 5–6 run inside this call, from `now_s`. */
    IRX3DHResult *initiator = [IRX3DH initiatorResultWithIdentity:alice
                                                           bundle:bundle
                                                 ephemeralKeyPair:ephemeral
                                                   nowUnixSeconds:nowS
                                                         provider:provider
                                                        retainIKM:YES
                                                            error:&error];
    IRX3DHGuard(initiator, @"[%@] the initiator agreement failed: %@", vectorCase.identifier, error);
    IRX3DHGuard(initiator.ikm, @"[%@] retainIKM:YES did not retain the IKM", vectorCase.identifier);

    /* §15.5 rule 2 — the intermediates are where interop actually breaks. DH1–DH4 are read out of
       the retained IKM at §18's offsets, which is also the assertion that §6.3's concatenation
       order is F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] and not some other permutation that would still
       produce a self-consistent port. */
    [vectorCase checkIntermediate:@"DH1"
                             data:IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH1)];
    [vectorCase checkIntermediate:@"DH2"
                             data:IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH2)];
    [vectorCase checkIntermediate:@"DH3"
                             data:IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH3)];

    if (withOneTimePreKey) {
        [vectorCase checkIntermediate:@"DH4"
                                 data:IRX3DHIKMSlice(initiator.ikm, (NSUInteger)kIROffIKMDH4)];
    }

    [vectorCase checkIntermediate:@"TRANSCRIPT" data:initiator.transcript];
    [vectorCase checkIntermediate:@"TH" data:initiator.transcriptHash];
    [vectorCase checkIntermediate:@"IKM" data:IRX3DHDataFromSecret(initiator.ikm)];
    [vectorCase checkIntermediate:@"IKM_len" number:@(initiator.ikm.length)];
    [vectorCase checkIntermediate:@"X3DH_info" data:initiator.x3dhInfo];

    /* §6.3 — the two legal IKM lengths, and nothing between them. A port that zero-fills DH4
       instead of omitting it produces 160 bytes here in the no-OPK case. */
    NSUInteger expectedIKMLength =
        withOneTimePreKey ? (NSUInteger)kIRLenIKMOPK : (NSUInteger)kIRLenIKMNoOPK;
    if (initiator.ikm.length != expectedIKMLength) {
        IRVectorRecordFailure(testCase,
                              @"[%@] IKM is %lu bytes, §6.3 requires %lu — DH4 is OMITTED, not "
                              @"zero-filled",
                              vectorCase.identifier,
                              (unsigned long)initiator.ikm.length,
                              (unsigned long)expectedIKMLength);
    }

    [vectorCase checkOutput:@"SK" data:IRX3DHDataFromSecret(initiator.sharedKey)];
    [vectorCase checkOutput:@"SESSION_AD" data:initiator.sessionAD.bytes];
    [vectorCase checkOutput:@"handshake_id" data:initiator.handshakeId];
    [vectorCase checkResultError:nil];

    /* §11.3 — the prologue A must re-emit unchanged on every type 0x02 message. It is not an
       output: §12.1 stores it, §9.2 transmits its fields, and `wire.json` pins their offsets. What
       is asserted here is only that X3DH filled it from the bundle rather than from its caller. */
    if (initiator.role != IRSessionRoleInitiator) {
        IRVectorRecordFailure(testCase, @"[%@] the initiator result carries role 0x%02x",
                              vectorCase.identifier, (unsigned)initiator.role);
    }

    if (initiator.prologue == nil) {
        IRVectorRecordFailure(testCase, @"[%@] an initiator result has no §11.3 prologue",
                              vectorCase.identifier);
    } else if (initiator.prologue.spkId != spkId ||
               initiator.prologue.opkFlag != opkFlag ||
               initiator.prologue.opkId != opkId ||
               ![initiator.prologue.ephemeralPublic isEqualToX25519Public:ephemeralPublic]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] prologue: spk_id %u/%u, opk_flag %u/%u, opk_id %u/%u",
                              vectorCase.identifier,
                              (unsigned)initiator.prologue.spkId, (unsigned)spkId,
                              (unsigned)initiator.prologue.opkFlag, (unsigned)opkFlag,
                              (unsigned)initiator.prologue.opkId, (unsigned)opkId);
    }

    /* §6.1's mirror image, and the reason this vector carries B's private keys at all. Everything
       downstream of the four scalar multiplications MUST be byte-identical on both sides; a port
       that swaps two DH terms, or that recomputes SESSION_AD as (self, peer) rather than
       (initiator, responder), agrees with itself and fails here. */
    IRX3DHResult *responder =
        [IRX3DH responderResultWithIdentity:bob
                          initiatorIdentity:alice.publicIdentity
                            ephemeralPublic:ephemeralPublic
                           signedPreKeyPair:signedPreKeyPair
                                      spkId:spkId
                                    opkFlag:opkFlag
                                      opkId:opkId
                          oneTimePreKeyPair:oneTimePreKeyPair
                                   provider:provider
                                  retainIKM:YES
                                      error:&error];

    if (responder == nil) {
        IRVectorRecordFailure(testCase, @"[%@] the responder agreement failed: %@",
                              vectorCase.identifier, error);
        [vectorCase finish];
        return;
    }

    if (![IRX3DHDataFromSecret(responder.ikm) isEqualToData:IRX3DHDataFromSecret(initiator.ikm)]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §6.1: B's IKM is %@, A's is %@",
                              vectorCase.identifier,
                              IRVectorHex(IRX3DHDataFromSecret(responder.ikm)),
                              IRVectorHex(IRX3DHDataFromSecret(initiator.ikm)));
    }

    if (![responder.transcript isEqualToData:initiator.transcript]) {
        IRVectorRecordFailure(testCase, @"[%@] §6.2: the two sides built different TRANSCRIPTs",
                              vectorCase.identifier);
    }

    if (![IRX3DHDataFromSecret(responder.sharedKey)
              isEqualToData:IRX3DHDataFromSecret(initiator.sharedKey)]) {
        IRVectorRecordFailure(testCase, @"[%@] §6.3: A and B derived different SKs",
                              vectorCase.identifier);
    }

    if (![responder.sessionAD.bytes isEqualToData:initiator.sessionAD.bytes]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §6.5: SESSION_AD differs between the sides — the role ordering "
                              @"is (initiator, responder) and is never recomputed as (self, peer)",
                              vectorCase.identifier);
    }

    if (![responder.handshakeId isEqualToData:initiator.handshakeId]) {
        IRVectorRecordFailure(testCase, @"[%@] §11.1: the two sides derived different handshake_ids",
                              vectorCase.identifier);
    }

    if (responder.role != IRSessionRoleResponder) {
        IRVectorRecordFailure(testCase, @"[%@] the responder result carries role 0x%02x",
                              vectorCase.identifier, (unsigned)responder.role);
    }

    /* §11.3 — "present for an initiator, always nil for a responder": a responder never sends a
       type 0x02 message and so has no prologue to re-emit. */
    if (responder.prologue != nil) {
        IRVectorRecordFailure(testCase, @"[%@] a responder result carries a §11.3 prologue",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark - Executor: X3DH-IKBIND

static void IRX3DHRunIdentityBindingVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *seedBytes = [vectorCase dataInput:@"IK_s_priv"];
    NSData *signingPublicBytes = [vectorCase dataInput:@"IK_s_pub"];
    NSData *agreementPrivateBytes = [vectorCase dataInput:@"IK_d_priv"];
    NSData *agreementPublicBytes = [vectorCase dataInput:@"IK_d_pub"];

    /* §15.5 RULE 8 — IKB IS AN INPUT. It is verified below against IK_s_pub and IKBIND_MSG, and it
       is never compared against a signature produced here. */
    NSData *bindingBytes = [vectorCase dataInput:@"IKB"];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IREd25519Private *seed = [IREd25519Private fromData:seedBytes guarded:NO error:&error];
    IRX3DHGuard(seed, @"[%@] IK_s_priv is not a 32-byte RFC 8032 seed (§4.2): %@",
                vectorCase.identifier, error);

    IREd25519Public *signingPublic = [IREd25519Public fromData:signingPublicBytes error:&error];
    IRX3DHGuard(signingPublic, @"[%@] IK_s_pub: %@", vectorCase.identifier, error);

    IRX25519Public *agreementPublic = [IRX25519Public fromData:agreementPublicBytes error:&error];
    IRX3DHGuard(agreementPublic, @"[%@] IK_d_pub: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *keyPair = [IRIdentityKeyPair pairWithSigningKey:signingPublic
                                                         agreementKey:agreementPublic
                                                                error:&error];
    IRX3DHGuard(keyPair, @"[%@] identity pair: %@", vectorCase.identifier, error);

    /* §4.2 — IK_d_priv is present because §15.5 requires `inputs` to carry the private keys of the
       identity the vector describes, and because a runner that could not reconstruct the whole
       identity could not check that this IKB belongs to it. IKBIND_MSG itself covers only the two
       PUBLIC halves, so the scalar is validated (clamped form, correct width) and not otherwise
       used on this path. */
    IRX25519Private *agreementPrivate = [IRX25519Private fromData:agreementPrivateBytes
                                                          guarded:NO
                                                            error:&error];
    IRX3DHGuard(agreementPrivate, @"[%@] IK_d_priv: %@", vectorCase.identifier, error);

    NSData *message = IRIKBindMessage(keyPair, &error);
    IRX3DHGuard(message, @"[%@] IKBIND_MSG: %@", vectorCase.identifier, error);

    /* THE BYTES, NOT THE SIGNATURE, ARE THE BYTE-NORMATIVE QUANTITY (§15.3). They are an OUTPUT so
       that §15.5 rule 1 makes them mandatory to check: this is the only vector that pins the 81-byte
       §5.1 layout, and as an `intermediates` field rule 2 would have let a port skip it. */
    [vectorCase checkOutput:@"IKBIND_MSG" data:message];
    [vectorCase checkOutput:@"IKBIND_MSG_len" number:@(message.length)];

    IREd25519Signature *binding = [IREd25519Signature fromData:bindingBytes error:&error];
    IRX3DHGuard(binding, @"[%@] IKB: %@", vectorCase.identifier, error);

    /* §3.4 — PURE Ed25519, detached. A port wired to libsodium's multi-part
       crypto_sign_init/_update/_final_create is verifying Ed25519ph, a DIFFERENT scheme, and
       rejects this signature; that rejection arrives disguised as ERR_BAD_SIGNATURE — that is, as
       an active MITM (§1.2) — which is exactly where the failure belongs. */
    BOOL verified = [provider ed25519VerifySignature:binding
                                           ofMessage:message
                                           publicKey:signingPublic];
    [vectorCase checkOutput:@"IKB_verified" boolean:verified];
    [vectorCase checkResultError:nil];

    /* §15.5 rule 8's SHOULD — sign IKBIND_MSG here and verify THAT signature, so the signing path
       (including §3.4's mandatory crypto_sign_seed_keypair expansion, whose omission is a 32-byte
       out-of-bounds read) is exercised. The two signatures are NEVER compared: signature generation
       is not byte-reproducible across platforms, so a comparison would fail a conformant port. */
    IREd25519Signature *ownBinding = [provider ed25519SignMessage:message withSeed:seed error:&error];
    IRX3DHGuard(ownBinding, @"[%@] signing IKBIND_MSG locally: %@", vectorCase.identifier, error);

    if (![provider ed25519VerifySignature:ownBinding ofMessage:message publicKey:signingPublic]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] this implementation signed IKBIND_MSG and could not verify its "
                              @"own signature against IK_s_pub",
                              vectorCase.identifier);
    }

    /* §5.1 / §5.5 — the binding is what IRPublicIdentity's ONLY constructor verifies, so building
       one is the same assertion stated where the framework enforces it: an unverified identity
       value cannot exist in this process. */
    IRPublicIdentity *identity = [IRPublicIdentity identityWithKeyPair:keyPair
                                                              binding:binding
                                                             provider:provider
                                                                error:&error];
    if (identity == nil) {
        IRVectorRecordFailure(testCase, @"[%@] IKB did not verify through the ingest type (§5.1): %@",
                              vectorCase.identifier, error);
    }

    [vectorCase finish];
}

#pragma mark - Executor: X3DH-SPKSIG

static void IRX3DHRunSignedPreKeySignatureVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *seedBytes = [vectorCase dataInput:@"IK_s_priv"];
    NSData *signingPublicBytes = [vectorCase dataInput:@"IK_s_pub"];
    NSData *agreementPublicBytes = [vectorCase dataInput:@"IK_d_pub"];
    uint32_t spkId = [vectorCase uint32Input:@"spk_id"];
    NSData *signedPreKeyBytes = [vectorCase dataInput:@"SPK"];
    uint64_t notBeforeS = [vectorCase uint64Input:@"not_before"];
    uint64_t notAfterS = [vectorCase uint64Input:@"not_after"];

    /* §15.5 RULE 8 — SPK_SIG IS AN INPUT, verified below and never compared against local signing. */
    NSData *signatureBytes = [vectorCase dataInput:@"SPK_SIG"];

    /* NO CLOCK IS READ ON THIS PATH, so the ambient environment is used rather than an injected
       one — §15.3 grants this vector the reads-no-clock carve-out by name, and the driver's
       ten-years-forward run is what proves the claim. §5.3 rules 5–6 do read one, but they live on
       the bundle-ingest path, which this vector does not touch. */
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IREd25519Private *seed = [IREd25519Private fromData:seedBytes guarded:NO error:&error];
    IRX3DHGuard(seed, @"[%@] IK_s_priv: %@", vectorCase.identifier, error);

    IREd25519Public *signingPublic = [IREd25519Public fromData:signingPublicBytes error:&error];
    IRX3DHGuard(signingPublic, @"[%@] IK_s_pub: %@", vectorCase.identifier, error);

    IRX25519Public *agreementPublic = [IRX25519Public fromData:agreementPublicBytes error:&error];
    IRX3DHGuard(agreementPublic, @"[%@] IK_d_pub: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *keyPair = [IRIdentityKeyPair pairWithSigningKey:signingPublic
                                                         agreementKey:agreementPublic
                                                                error:&error];
    IRX3DHGuard(keyPair, @"[%@] identity pair: %@", vectorCase.identifier, error);

    IRX25519Public *signedPreKey = [IRX25519Public fromData:signedPreKeyBytes error:&error];
    IRX3DHGuard(signedPreKey, @"[%@] SPK: %@", vectorCase.identifier, error);

    NSData *message = IRSPKSignMessage(keyPair, spkId, signedPreKey, notBeforeS, notAfterS, &error);
    IRX3DHGuard(message, @"[%@] SPK_SIGN_MSG: %@", vectorCase.identifier, error);

    /* AN OUTPUT, NOT AN INTERMEDIATE (§15.3). The 130-byte §5.2 layout is deterministic and
       byte-normative and this is the only vector pinning it; rule 1 makes an `outputs` field
       mandatory to check, where rule 2 would have made it skippable. */
    [vectorCase checkOutput:@"SPK_SIGN_MSG" data:message];
    [vectorCase checkOutput:@"SPK_SIGN_MSG_len" number:@(message.length)];

    IREd25519Signature *signature = [IREd25519Signature fromData:signatureBytes error:&error];
    IRX3DHGuard(signature, @"[%@] SPK_SIG: %@", vectorCase.identifier, error);

    BOOL verified = [provider ed25519VerifySignature:signature
                                           ofMessage:message
                                           publicKey:signingPublic];
    [vectorCase checkOutput:@"SPK_SIG_verified" boolean:verified];
    [vectorCase checkResultError:nil];

    /* §15.5 rule 8's SHOULD, and the two signatures are never compared. */
    IREd25519Signature *ownSignature = [provider ed25519SignMessage:message
                                                           withSeed:seed
                                                              error:&error];
    IRX3DHGuard(ownSignature, @"[%@] signing SPK_SIGN_MSG locally: %@",
                vectorCase.identifier, error);

    if (![provider ed25519VerifySignature:ownSignature ofMessage:message publicKey:signingPublic]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] this implementation signed SPK_SIGN_MSG and could not verify "
                              @"its own signature against IK_s_pub",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark - Executor: X3DH-FP

static void IRX3DHRunFingerprintVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *signingPublicBytes = [vectorCase dataInput:@"IK_s_pub"];
    NSData *agreementPublicBytes = [vectorCase dataInput:@"IK_d_pub"];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IREd25519Public *signingPublic = [IREd25519Public fromData:signingPublicBytes error:&error];
    IRX3DHGuard(signingPublic, @"[%@] IK_s_pub: %@", vectorCase.identifier, error);

    IRX25519Public *agreementPublic = [IRX25519Public fromData:agreementPublicBytes error:&error];
    IRX3DHGuard(agreementPublic, @"[%@] IK_d_pub: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *keyPair = [IRIdentityKeyPair pairWithSigningKey:signingPublic
                                                         agreementKey:agreementPublic
                                                                error:&error];
    IRX3DHGuard(keyPair, @"[%@] identity pair: %@", vectorCase.identifier, error);

    NSData *fingerprintInput = IRX3DHFingerprintInput(keyPair);

    [vectorCase checkIntermediate:@"FP_input" data:fingerprintInput];
    [vectorCase checkIntermediate:@"FP_input_len" number:@(fingerprintInput.length)];

    IRFingerprint *fingerprint = [keyPair fingerprintWithProvider:provider error:&error];
    IRX3DHGuard(fingerprint, @"[%@] fingerprint: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"FP" data:fingerprint.data];
    [vectorCase checkResultError:nil];

    /* What binds the locally built §5.5 input to the framework's own: the digest of one MUST be the
       other. Without this the FP_input intermediate would be a value the vector asserts about
       itself. */
    NSData *digest = [provider sha256OfData:fingerprintInput error:&error];
    if (![digest isEqualToData:fingerprint.data]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] SHA256(FP_input) is %@ but -fingerprintWithProvider: returned "
                              @"%@ (%@)",
                              vectorCase.identifier,
                              digest ? IRVectorHex(digest) : @"nil",
                              IRVectorHex(fingerprint.data), error);
    }

    [vectorCase finish];
}

#pragma mark - Dispatch

void IRRunX3DHVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    if (![vectorCase.kind isEqualToString:@"x3dh"]) {
        IRVectorRecordFailure(testCase, @"[%@] kind is \"%@\"; x3dh.json carries only \"x3dh\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    NSString *identifier = vectorCase.identifier;

    if ([identifier isEqualToString:@"X3DH-OPK"] || [identifier isEqualToString:@"X3DH-NOOPK"]) {
        IRX3DHRunHandshakeVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"X3DH-IKBIND"]) {
        IRX3DHRunIdentityBindingVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"X3DH-SPKSIG"]) {
        IRX3DHRunSignedPreKeySignatureVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"X3DH-FP"]) {
        IRX3DHRunFingerprintVector(testCase, vectorCase);
    } else {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is exactly
           what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase, @"[%@] x3dh.json has no executor for this id", identifier);
    }
}
