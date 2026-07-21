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
#import "IRSessionAD.h"
#import "IRX3DH.h"

/**
 wire.json — SPEC §9.1, §9.2, §5.4, §8.5, §10.3, §15.3, §15.5.

 THE WORKED EXAMPLE. Seven other modules copy this file's shape, so it is written to be imitated
 rather than to be short.

 SIX VECTORS, exactly the set §15.3 requires of wire.json:

     WIRE-MSG-01        a type 0x01 message, byte-exact             (§9.1)
     WIRE-MSG-02        a type 0x02 message, byte-exact             (§9.2)
     WIRE-BUNDLE-OPK0   a prekey bundle with opk_count 0, 251 bytes (§5.4)
     WIRE-BUNDLE-OPK1   a prekey bundle with opk_count 1, 287 bytes (§5.4)
     WIRE-AD-01         the AD byte string for a type 0x01 message  (§8.5, 197 bytes)
     WIRE-AD-02         the AD byte string for a type 0x02 message  (§8.5, 366 bytes)

 THESE VECTORS ARE ENCODING-ONLY, and §15.3 says so in as many words. They assert the byte layout of
 §5.4 and the structural gate of §10.3; they do NOT run §5.3's rules 5–6. They therefore READ NO
 CLOCK and supply no `now_s`, and the bundle vectors' `not_before` / `not_after` are fixed literals
 that are part of the frozen bytes. Signature and validity-window verification is carried by
 `X3DH-OPK` / `X3DH-NOOPK` and by the `NEG-SPK*` rows, each of which supplies an explicit
 `inputs.now_s`.

 What the bundle vectors DO exercise, because it comes free and is worth having: §5.3 rules 2–4 —
 the public-key encoding checks and the two Ed25519 verifications — since -bundleFromData: runs them
 and they read no clock. The `IKB` and `SPK_SIG` in `inputs` are therefore GENUINE signatures, not
 opaque filler, produced once by this generator from the fixed seeds below.

 THE CIPHERTEXT IS OPAQUE, AND THAT IS THE POINT. `ciphertext_and_tag` is a fixed literal rather
 than the output of a real seal. A wire vector's job is to pin `header ‖ ciphertext ‖ tag` and the
 offsets inside the header; making it depend on the AEAD would couple every port's wire-format
 conformance to its ratchet being finished, and would duplicate what ratchet.json already proves.
 WIRE-MSG-02 carries a zero-length plaintext on purpose: 225 + 0 + 16 = 241 is §9.2's minimum, and
 §10.4 makes an empty plaintext legal.

 EVERY BYTE IN `inputs` IS A LITERAL IN THIS FILE OR IS DERIVED FROM ONE. The X25519 private scalars
 are fed to the real key generator through IRScriptedRandomSource (§15.5 rule 5) rather than being
 hand-clamped, so the public halves in the frozen file are whatever the implementation actually
 derives, and the §4.2 clamp is applied by the code under test rather than by the test.

 THE PRIVATE KEYS ARE NOT IN `inputs`, DELIBERATELY. §15.5 requires `inputs` to carry "everything
 needed to reproduce", and for an encoding-only vector that is the public keys, the signatures, the
 counters, the nonce and the ciphertext — nothing here is computed from a private key at run time.
 Adding the seeds would put keys in the file that no runner reads, and §15.5 rule 3 makes an unread
 `inputs` key a failure rather than a harmless extra.
 */

#pragma mark - Fixed key material

/* Ed25519 seeds (§4.2: the 32-byte RFC 8032 seed, never libsodium's 64-byte expanded sk). */
static NSString * const kWireAliceEd25519Seed =
    @"a11a2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f";
static NSString * const kWireBobEd25519Seed =
    @"b11b2c3d4e5f60718293a4b5c6d7e8f9101112131415161718191a1b1c1d1e1f";

/* Raw X25519 scalars as handed to the CSPRNG seam. The stored form is the §4.2 CLAMP of these, and
   the public halves are derived from the clamped scalar by the implementation. */
static NSString * const kWireAliceX25519Scalar =
    @"a2202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e";
static NSString * const kWireBobX25519Scalar =
    @"b2404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e";
static NSString * const kWireEphemeralScalar =
    @"e1606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e";
static NSString * const kWireRatchetScalarPrekey =
    @"d1808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e";
static NSString * const kWireRatchetScalarNormal =
    @"d2a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe";
static NSString * const kWireSignedPreKeyScalar =
    @"51c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcddde";
static NSString * const kWireOneTimePreKeyScalar =
    @"61e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe";

#pragma mark - Fixed non-key material

static NSString * const kWireNonceNormal = @"000102030405060708090a0b";
static NSString * const kWireNoncePrekey = @"101112131415161718191a1b";

/* Five ciphertext bytes and a 16-byte Poly1305 tag: a 77-byte type 0x01 message. */
static NSString * const kWireCiphertextAndTagNormal =
    @"c0c1c2c3c4a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

/* Tag only — the empty plaintext of §10.4, giving §9.2's 241-byte minimum. */
static NSString * const kWireCiphertextAndTagPrekey =
    @"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

static const uint32_t kWireSpkId = 7;
static const uint32_t kWireOpkId = 42;

/* §5.2's window, as fixed literals that are part of the frozen bytes. 2026-01-01T00:00:00Z to
   2026-03-30T00:00:00Z: 7603200 seconds, inside MAX_SPK_VALIDITY_SECONDS (7776000). No vector here
   evaluates the window — see the file comment — but a value that could not pass §5.3 rule 6 would
   be a trap for whoever reuses these bytes. */
static const uint64_t kWireNotBeforeS = 1767225600ULL;
static const uint64_t kWireNotAfterS  = 1774828800ULL;

/* §9.1: N is this message's number in the current sending chain, PN the length of the PREVIOUS
   sending chain. They are deliberately DIFFERENT here: a port that writes state.Ns into both slots
   — defect 10 — produces bytes that differ from the frozen file at offset 40. */
static const uint32_t kWireNormalN  = 3;
static const uint32_t kWireNormalPN = 2;

/* §9.2: N MAY be non-zero in a type 0x02 header, and this vector pins that it is legal. PN is not a
   parameter of the type 0x02 builder at all — §9.2 fixes it at zero. */
static const uint32_t kWirePrekeyN = 1;

#pragma mark - Deterministic construction helpers

/**
 An X25519 pair derived from a fixed scalar through the REAL generator (§15.5 rule 5).

 A fresh IRScriptedRandomSource per pair, holding exactly the 32 bytes
 -generateX25519KeyPairWithError: draws. That source fails on exhaustion rather than cycling, so a
 generator that drew more than it scripted stops here instead of silently reusing bytes.
 */
static IRX25519KeyPair *IRWireX25519PairFromScalar(NSString *scalarHex) {
    NSData *scalar = IRVectorBytes(scalarHex);
    IRVectorRequire(scalar.length == 32, @"X25519 scalar must be 32 bytes, got %lu",
                    (unsigned long)scalar.length);

    IRScriptedRandomSource *source = [IRScriptedRandomSource sourceWithData:scalar];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IRX25519KeyPair *pair = [provider generateX25519KeyPairWithError:&error];
    IRVectorRequire(pair != nil, @"X25519 generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"scripted %lu bytes for one X25519 pair and %lu were left over",
                    (unsigned long)scalar.length, (unsigned long)source.bytesRemaining);

    return pair;
}

/// An identity from a fixed Ed25519 seed and a fixed X25519 scalar, with a GENUINE `IKB` (§5.1).
static IRIdentity *IRWireIdentity(NSString *seedHex, NSString *scalarHex) {
    NSData *seedBytes = IRVectorBytes(seedHex);
    NSData *scalarBytes = IRVectorBytes(scalarHex);
    IRVectorRequire(seedBytes.length == 32, @"Ed25519 seed must be 32 bytes");
    IRVectorRequire(scalarBytes.length == 32, @"X25519 scalar must be 32 bytes");

    /* +generateWithProvider: draws the Ed25519 seed first and the X25519 scalar second, then signs
       IKBIND_MSG. Scripting the two in that order reproduces a whole identity, IKB included, with
       no injection point the production API exposes. */
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

static IRNonce *IRWireNonce(NSString *hex) {
    NSError *error = nil;
    IRNonce *nonce = [IRNonce fromData:IRVectorBytes(hex) error:&error];
    IRVectorRequire(nonce != nil, @"nonce %@: %@", hex, error);

    return nonce;
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForWire(void) {
    NSError *error = nil;

    IRIdentity *alice = IRWireIdentity(kWireAliceEd25519Seed, kWireAliceX25519Scalar);
    IRIdentity *bob = IRWireIdentity(kWireBobEd25519Seed, kWireBobX25519Scalar);

    IRX25519KeyPair *ephemeral = IRWireX25519PairFromScalar(kWireEphemeralScalar);
    IRX25519KeyPair *ratchetPrekey = IRWireX25519PairFromScalar(kWireRatchetScalarPrekey);
    IRX25519KeyPair *ratchetNormal = IRWireX25519PairFromScalar(kWireRatchetScalarNormal);
    IRX25519KeyPair *signedPreKey = IRWireX25519PairFromScalar(kWireSignedPreKeyScalar);
    IRX25519KeyPair *oneTimePreKey = IRWireX25519PairFromScalar(kWireOneTimePreKeyScalar);

    /* §5.2 — SPK_SIG over the 130-byte SPK_SIGN_MSG, under Bob's IK^s. Ed25519 is deterministic
       (RFC 8032 §5.1.6), so this is reproducible across runs and across platforms. */
    NSData *spkSignMessage = IRSPKSignMessage(bob.identityKeyPair,
                                              kWireSpkId,
                                              signedPreKey.publicKey,
                                              kWireNotBeforeS,
                                              kWireNotAfterS,
                                              &error);
    IRVectorRequire(spkSignMessage != nil, @"SPK_SIGN_MSG: %@", error);

    IREd25519Signature *spkSignature = [bob signData:spkSignMessage error:&error];
    IRVectorRequire(spkSignature != nil, @"SPK_SIG: %@", error);

    #pragma mark WIRE-MSG-01

    NSData *normalHeader = [IRMessageBuilder type01HeaderWithRatchetKey:ratchetNormal.publicKey
                                                                      N:kWireNormalN
                                                                     PN:kWireNormalPN
                                                                  nonce:IRWireNonce(kWireNonceNormal)
                                                                  error:&error];
    IRVectorRequire(normalHeader != nil, @"type 0x01 header: %@", error);

    NSData *normalMessage =
        [IRMessageBuilder messageWithHeaderBytes:normalHeader
                                ciphertextAndTag:IRVectorBytes(kWireCiphertextAndTagNormal)
                                           error:&error];
    IRVectorRequire(normalMessage != nil, @"type 0x01 message: %@", error);

    NSDictionary *msg01 = @{
        @"id"          : @"WIRE-MSG-01",
        @"kind"        : @"wire",
        @"description" : @"Byte-exact type 0x01 normal ratchet message: 56-byte header, 5-byte "
                         @"ciphertext, 16-byte Poly1305 tag. N and PN differ, so a port that "
                         @"writes state.Ns into both slots diverges at offset 40.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"entry_point"        : @"encrypt",
            @"DHs_pub"            : IRVectorHex(ratchetNormal.publicKey.data),
            @"N"                  : @(kWireNormalN),
            @"PN"                 : @(kWireNormalPN),
            @"nonce"              : kWireNonceNormal,
            @"ciphertext_and_tag" : kWireCiphertextAndTagNormal,
        },
        @"intermediates" : @{
            @"header"     : IRVectorHex(normalHeader),
            @"header_len" : @(normalHeader.length),
        },
        @"outputs" : @{
            @"message"     : IRVectorHex(normalMessage),
            @"message_len" : @(normalMessage.length),
        },
    };

    #pragma mark WIRE-MSG-02

    IRSessionPrologue *prologue =
        [IRSessionPrologue prologueWithEphemeralPublic:ephemeral.publicKey
                                                 spkId:kWireSpkId
                                               opkFlag:IROPKFlagPresent
                                                 opkId:kWireOpkId
                                                 error:&error];
    IRVectorRequire(prologue != nil, @"prologue: %@", error);

    NSData *prekeyHeader =
        [IRMessageBuilder type02HeaderWithInitiatorIdentity:alice.identityKeyPair
                                            identityBinding:alice.binding
                                                   prologue:prologue
                                                 ratchetKey:ratchetPrekey.publicKey
                                                          N:kWirePrekeyN
                                                      nonce:IRWireNonce(kWireNoncePrekey)
                                                      error:&error];
    IRVectorRequire(prekeyHeader != nil, @"type 0x02 header: %@", error);

    NSData *prekeyMessage =
        [IRMessageBuilder messageWithHeaderBytes:prekeyHeader
                                ciphertextAndTag:IRVectorBytes(kWireCiphertextAndTagPrekey)
                                           error:&error];
    IRVectorRequire(prekeyMessage != nil, @"type 0x02 message: %@", error);

    NSDictionary *msg02 = @{
        @"id"          : @"WIRE-MSG-02",
        @"kind"        : @"wire",
        @"description" : @"Byte-exact type 0x02 prekey message: 225-byte header and an empty "
                         @"plaintext, giving the 241-byte minimum of §9.2. N is 1, pinning §9.2's "
                         @"rule that N MAY be non-zero; PN is not a parameter and is written as a "
                         @"literal zero at offset 209.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"entry_point"        : @"encrypt",
            @"IK_A_s_pub"         : IRVectorHex(alice.identityKeyPair.signingKey.data),
            @"IK_A_d_pub"         : IRVectorHex(alice.identityKeyPair.agreementKey.data),
            @"IKB_A"              : IRVectorHex(alice.binding.data),
            @"EK_A_pub"           : IRVectorHex(ephemeral.publicKey.data),
            @"spk_id"             : @(kWireSpkId),
            @"opk_flag"           : @(IROPKFlagPresent),
            @"opk_id"             : @(kWireOpkId),
            @"DHs_pub"            : IRVectorHex(ratchetPrekey.publicKey.data),
            @"N"                  : @(kWirePrekeyN),
            @"nonce"              : kWireNoncePrekey,
            @"ciphertext_and_tag" : kWireCiphertextAndTagPrekey,
        },
        @"intermediates" : @{
            @"header"     : IRVectorHex(prekeyHeader),
            @"header_len" : @(prekeyHeader.length),
        },
        @"outputs" : @{
            @"message"     : IRVectorHex(prekeyMessage),
            @"message_len" : @(prekeyMessage.length),
        },
    };

    #pragma mark WIRE-BUNDLE-OPK0 / WIRE-BUNDLE-OPK1

    IRPreKeyBundleOPKEntry *opkEntry = [IRPreKeyBundleOPKEntry entryWithOpkId:kWireOpkId
                                                                    publicKey:oneTimePreKey.publicKey
                                                                        error:&error];
    IRVectorRequire(opkEntry != nil, @"OPK entry: %@", error);

    NSData *bundleOPK0 = [IRPreKeyBundle serializeWithIdentity:bob.publicIdentity
                                                         spkId:kWireSpkId
                                                  signedPreKey:signedPreKey.publicKey
                                                    notBeforeS:kWireNotBeforeS
                                                     notAfterS:kWireNotAfterS
                                         signedPreKeySignature:spkSignature
                                                    opkEntries:@[]
                                                         error:&error];
    IRVectorRequire(bundleOPK0 != nil, @"bundle, opk_count 0: %@", error);
    IRVectorRequire(bundleOPK0.length == 251, @"bundle prefix is 251 bytes (§18), got %lu",
                    (unsigned long)bundleOPK0.length);

    NSData *bundleOPK1 = [IRPreKeyBundle serializeWithIdentity:bob.publicIdentity
                                                         spkId:kWireSpkId
                                                  signedPreKey:signedPreKey.publicKey
                                                    notBeforeS:kWireNotBeforeS
                                                     notAfterS:kWireNotAfterS
                                         signedPreKeySignature:spkSignature
                                                    opkEntries:@[opkEntry]
                                                         error:&error];
    IRVectorRequire(bundleOPK1 != nil, @"bundle, opk_count 1: %@", error);
    IRVectorRequire(bundleOPK1.length == 287, @"251 + 36 * 1 is 287 (§5.4), got %lu",
                    (unsigned long)bundleOPK1.length);

    NSDictionary *bundleInputsCommon = @{
        @"entry_point" : @"parse_bundle",
        @"IK_s"        : IRVectorHex(bob.identityKeyPair.signingKey.data),
        @"IK_d"        : IRVectorHex(bob.identityKeyPair.agreementKey.data),
        @"IKB"         : IRVectorHex(bob.binding.data),
        @"spk_id"      : @(kWireSpkId),
        @"SPK"         : IRVectorHex(signedPreKey.publicKey.data),
        @"not_before"  : IRVectorUInt64String(kWireNotBeforeS),
        @"not_after"   : IRVectorUInt64String(kWireNotAfterS),
        @"SPK_SIG"     : IRVectorHex(spkSignature.data),
    };

    NSMutableDictionary *bundle0Inputs = [bundleInputsCommon mutableCopy];
    bundle0Inputs[@"opk_entries"] = @[];

    NSMutableDictionary *bundle1Inputs = [bundleInputsCommon mutableCopy];
    bundle1Inputs[@"opk_entries"] = @[@{
        @"opk_id"  : @(kWireOpkId),
        @"opk_pub" : IRVectorHex(oneTimePreKey.publicKey.data),
    }];

    NSDictionary *bundle0 = @{
        @"id"          : @"WIRE-BUNDLE-OPK0",
        @"kind"        : @"wire",
        @"description" : @"Byte-exact prekey bundle with opk_count 0 — the 251-byte fixed prefix of "
                         @"§5.4 and nothing after it. Encoding-only: §10.3's structural gate and "
                         @"§5.3 rules 2–4 run, rules 5–6 do not, and no clock is read.",
        @"expect"      : @"ok",
        @"inputs"      : bundle0Inputs,
        @"intermediates" : @{ @"opk_count" : @0 },
        @"outputs"     : @{
            @"bundle"     : IRVectorHex(bundleOPK0),
            @"bundle_len" : @(bundleOPK0.length),
        },
    };

    NSDictionary *bundle1 = @{
        @"id"          : @"WIRE-BUNDLE-OPK1",
        @"kind"        : @"wire",
        @"description" : @"Byte-exact prekey bundle with opk_count 1 — 251 + 36 * 1 = 287 bytes, "
                         @"pinning the 36-byte OPK entry layout that the total-length identity "
                         @"depends on. Encoding-only, as WIRE-BUNDLE-OPK0.",
        @"expect"      : @"ok",
        @"inputs"      : bundle1Inputs,
        @"intermediates" : @{ @"opk_count" : @1 },
        @"outputs"     : @{
            @"bundle"     : IRVectorHex(bundleOPK1),
            @"bundle_len" : @(bundleOPK1.length),
        },
    };

    #pragma mark WIRE-AD-01 / WIRE-AD-02

    IRSessionAD *sessionAD = [IRSessionAD adWithInitiator:alice.identityKeyPair
                                                responder:bob.identityKeyPair
                                                    error:&error];
    IRVectorRequire(sessionAD != nil, @"SESSION_AD: %@", error);
    IRVectorRequire(sessionAD.bytes.length == 141, @"SESSION_AD is 141 bytes (§18), got %lu",
                    (unsigned long)sessionAD.bytes.length);

    NSData *adNormal = [sessionAD associatedDataWithHeaderBytes:normalHeader error:&error];
    IRVectorRequire(adNormal != nil, @"AD for type 0x01: %@", error);
    IRVectorRequire(adNormal.length == 197, @"type 0x01 AD is 197 bytes (§8.5), got %lu",
                    (unsigned long)adNormal.length);

    NSData *adPrekey = [sessionAD associatedDataWithHeaderBytes:prekeyHeader error:&error];
    IRVectorRequire(adPrekey != nil, @"AD for type 0x02: %@", error);
    IRVectorRequire(adPrekey.length == 366, @"type 0x02 AD is 366 bytes (§8.5), got %lu",
                    (unsigned long)adPrekey.length);

    NSDictionary *adInputsCommon = @{
        @"IK_A_s_pub" : IRVectorHex(alice.identityKeyPair.signingKey.data),
        @"IK_A_d_pub" : IRVectorHex(alice.identityKeyPair.agreementKey.data),
        @"IK_B_s_pub" : IRVectorHex(bob.identityKeyPair.signingKey.data),
        @"IK_B_d_pub" : IRVectorHex(bob.identityKeyPair.agreementKey.data),
    };

    NSMutableDictionary *ad01Inputs = [adInputsCommon mutableCopy];
    ad01Inputs[@"header"] = IRVectorHex(normalHeader);

    NSMutableDictionary *ad02Inputs = [adInputsCommon mutableCopy];
    ad02Inputs[@"header"] = IRVectorHex(prekeyHeader);

    NSDictionary *ad01 = @{
        @"id"          : @"WIRE-AD-01",
        @"kind"        : @"wire",
        @"description" : @"AD = SESSION_AD (141) ‖ the complete 56-byte type 0x01 header = 197 "
                         @"bytes (§8.5). The identities are in ROLE order — A is the initiator, B "
                         @"the responder — so a port that recomputes SESSION_AD as (self, peer) "
                         @"produces different bytes here.",
        @"expect"      : @"ok",
        @"inputs"      : ad01Inputs,
        @"intermediates" : @{
            @"SESSION_AD"     : IRVectorHex(sessionAD.bytes),
            @"SESSION_AD_len" : @(sessionAD.bytes.length),
        },
        @"outputs" : @{
            @"AD"     : IRVectorHex(adNormal),
            @"AD_len" : @(adNormal.length),
        },
    };

    NSDictionary *ad02 = @{
        @"id"          : @"WIRE-AD-02",
        @"kind"        : @"wire",
        @"description" : @"AD = SESSION_AD (141) ‖ the complete 225-byte type 0x02 header = 366 "
                         @"bytes (§8.5). The nonce at header offset 213 is inside the AD as well "
                         @"as being the AEAD nonce; §8.5 makes that redundancy deliberate.",
        @"expect"      : @"ok",
        @"inputs"      : ad02Inputs,
        @"intermediates" : @{
            @"SESSION_AD"     : IRVectorHex(sessionAD.bytes),
            @"SESSION_AD_len" : @(sessionAD.bytes.length),
        },
        @"outputs" : @{
            @"AD"     : IRVectorHex(adPrekey),
            @"AD_len" : @(adPrekey.length),
        },
    };

    return @[msg01, msg02, bundle0, bundle1, ad01, ad02];
}

#pragma mark - Executor

/**
 THE GUARD IS NOT DEFENSIVE PROGRAMMING, IT IS §13.4.

 A nil passed for a `_Nonnull` parameter is a caller contract violation that traps through
 IRRequireArgument — it is not an error code and it is not recoverable. A vector whose hex is the
 wrong width produces a nil nominal type, and passing that on would abort the whole test binary with
 a trap instead of reporting which vector was malformed. Every constructed value is therefore
 checked before it is handed to the implementation.

 `testCase` and `vectorCase` must be in scope, which they are in every executor below.
 */
#define IRWireGuard(value, ...)                                                                    \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRVectorRecordFailure(testCase, __VA_ARGS__);                                          \
            [vectorCase finish];                                                                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

/**
 A valid X25519 public key that is NOT `key`, for §10.1 check 8.

 -parseType01Message: takes `ownRatchetPublicKey` as `_Nonnull` on purpose: check 8 — the
 anti-reflection check — is not optional, and a nullable parameter would let a caller opt out of it.
 A wire vector has no session and therefore no own ratchet key, so one is synthesized here by
 flipping the low bit of byte 0. Byte 31 is untouched, so §4.4 check 2 still holds, and the result
 cannot equal the header's key.
 */
static IRX25519Public * _Nullable IRWireDistinctPublic(IRX25519Public *key) {
    NSMutableData *bytes = [key.data mutableCopy];
    uint8_t *raw = [bytes mutableBytes];
    raw[0] = raw[0] ^ 0x01;

    NSError *error = nil;

    return [IRX25519Public fromData:bytes error:&error];
}

#pragma mark WIRE-MSG-01 / WIRE-MSG-02

static void IRWireRunMessageVector(XCTestCase *testCase,
                                   IRVectorCase *vectorCase,
                                   IRMessageType type) {
    NSError *error = nil;

    /* Every input is read FIRST, so that §15.5 rule 3's consumption bookkeeping is complete even on
       a path that then bails out. */
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *ratchetKeyBytes = [vectorCase dataInput:@"DHs_pub"];
    uint32_t n = [vectorCase uint32Input:@"N"];
    NSData *nonceBytes = [vectorCase dataInput:@"nonce"];
    NSData *ciphertextAndTag = [vectorCase dataInput:@"ciphertext_and_tag"];

    uint32_t pn = 0;
    NSData *signingKeyBytes = nil;
    NSData *agreementKeyBytes = nil;
    NSData *bindingBytes = nil;
    NSData *ephemeralBytes = nil;
    uint32_t spkId = 0;
    uint32_t opkFlag = 0;
    uint32_t opkId = 0;

    if (type == IRMessageTypeNormal) {
        pn = [vectorCase uint32Input:@"PN"];
    } else {
        signingKeyBytes = [vectorCase dataInput:@"IK_A_s_pub"];
        agreementKeyBytes = [vectorCase dataInput:@"IK_A_d_pub"];
        bindingBytes = [vectorCase dataInput:@"IKB_A"];
        ephemeralBytes = [vectorCase dataInput:@"EK_A_pub"];
        spkId = [vectorCase uint32Input:@"spk_id"];
        opkFlag = [vectorCase uint32Input:@"opk_flag"];
        opkId = [vectorCase uint32Input:@"opk_id"];
    }

    if (![entryPoint isEqualToString:@"encrypt"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"encrypt\"",
                              vectorCase.identifier, entryPoint);
    }

    IRX25519Public *ratchetKey = [IRX25519Public fromData:ratchetKeyBytes error:&error];
    IRWireGuard(ratchetKey, @"[%@] DHs_pub is not a valid X25519 public key: %@",
                vectorCase.identifier, error);

    IRNonce *nonce = [IRNonce fromData:nonceBytes error:&error];
    IRWireGuard(nonce, @"[%@] nonce: %@", vectorCase.identifier, error);

    NSData *header = nil;
    IRSessionPrologue *prologue = nil;
    IRIdentityKeyPair *initiator = nil;
    IREd25519Signature *binding = nil;

    if (type == IRMessageTypeNormal) {
        header = [IRMessageBuilder type01HeaderWithRatchetKey:ratchetKey
                                                            N:n
                                                           PN:pn
                                                        nonce:nonce
                                                        error:&error];
    } else {
        IREd25519Public *signingKey = [IREd25519Public fromData:signingKeyBytes error:&error];
        IRWireGuard(signingKey, @"[%@] IK_A_s_pub: %@", vectorCase.identifier, error);

        IRX25519Public *agreementKey = [IRX25519Public fromData:agreementKeyBytes error:&error];
        IRWireGuard(agreementKey, @"[%@] IK_A_d_pub: %@", vectorCase.identifier, error);

        initiator = [IRIdentityKeyPair pairWithSigningKey:signingKey
                                             agreementKey:agreementKey
                                                    error:&error];
        IRWireGuard(initiator, @"[%@] initiator identity pair: %@", vectorCase.identifier, error);

        binding = [IREd25519Signature fromData:bindingBytes error:&error];
        IRWireGuard(binding, @"[%@] IKB_A: %@", vectorCase.identifier, error);

        IRX25519Public *ephemeral = [IRX25519Public fromData:ephemeralBytes error:&error];
        IRWireGuard(ephemeral, @"[%@] EK_A_pub: %@", vectorCase.identifier, error);

        prologue = [IRSessionPrologue prologueWithEphemeralPublic:ephemeral
                                                            spkId:spkId
                                                          opkFlag:(IROPKFlag)opkFlag
                                                            opkId:opkId
                                                            error:&error];
        IRWireGuard(prologue, @"[%@] prologue: %@", vectorCase.identifier, error);

        /* §11.3 — the prologue travels as ONE object, and `IKB_A` is passed in rather than
           re-signed. Ed25519 signing is not contractually deterministic on all four platforms, and
           nothing in the receive path compares IKB_A across messages, so a re-signing port would
           diverge and never be caught. */
        header = [IRMessageBuilder type02HeaderWithInitiatorIdentity:initiator
                                                     identityBinding:binding
                                                            prologue:prologue
                                                          ratchetKey:ratchetKey
                                                                   N:n
                                                               nonce:nonce
                                                               error:&error];
    }

    IRWireGuard(header, @"[%@] header construction failed: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"header" data:header];
    [vectorCase checkIntermediate:@"header_len" number:@(header.length)];

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:header
                                              ciphertextAndTag:ciphertextAndTag
                                                         error:&error];
    IRWireGuard(message, @"[%@] message assembly failed: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"message" data:message];
    [vectorCase checkOutput:@"message_len" number:@(message.length)];
    [vectorCase checkResultError:nil];

    /* THE ENCODER IS ONLY HALF THE FORMAT. Re-reading the bytes just written is what proves the
       decoder reads every field at the offset the encoder wrote it to; a matched pair of transposed
       offsets round-trips inside one port and interoperates with nothing. */
    IRMessageType parsedType = [IRMessageGate messageTypeOfMessage:message error:&error];
    if (parsedType != type) {
        IRVectorRecordFailure(testCase, @"[%@] §10.0 read type %u, expected %u: %@",
                              vectorCase.identifier, (unsigned)parsedType, (unsigned)type, error);
    }

    if (![IRMessageGate demultiplexMessage:message expectedType:type error:&error]) {
        IRVectorRecordFailure(testCase, @"[%@] §10.0 rejected its own encoding: %@",
                              vectorCase.identifier, error);
    }

    IRMessageHeader *parsed = nil;

    if (type == IRMessageTypeNormal) {
        if (![IRMessageGate gateType01Prefix:message error:&error]) {
            IRVectorRecordFailure(testCase, @"[%@] §10.1 checks 1–5 rejected its own encoding: %@",
                                  vectorCase.identifier, error);
        }

        IRX25519Public *ownRatchetKey = IRWireDistinctPublic(ratchetKey);
        IRWireGuard(ownRatchetKey, @"[%@] cannot synthesize a distinct own ratchet key",
                    vectorCase.identifier);

        parsed = [IRMessageGate parseType01Message:message
                               ownRatchetPublicKey:ownRatchetKey
                                             error:&error];
    } else {
        parsed = [IRMessageGate parseType02Message:message error:&error];
    }

    if (parsed == nil) {
        IRVectorRecordFailure(testCase, @"[%@] the gate could not parse its own encoding: %@",
                              vectorCase.identifier, error);
        [vectorCase finish];
        return;
    }

    if (![parsed.headerBytes isEqualToData:header]) {
        IRVectorRecordFailure(testCase, @"[%@] parsed headerBytes differ from the encoder's",
                              vectorCase.identifier);
    }

    if (![parsed.ratchetKey isEqualToX25519Public:ratchetKey]) {
        IRVectorRecordFailure(testCase, @"[%@] round-trip lost DHs_pub", vectorCase.identifier);
    }

    if (![parsed.nonce isEqualToNonce:nonce]) {
        IRVectorRecordFailure(testCase, @"[%@] round-trip lost the nonce", vectorCase.identifier);
    }

    /* §9.1's N and PN are separately named, and §9.2 fixes PN at zero. Reading both back is what
       catches defect 10 — a port writing state.Ns into the PN slot. */
    if (parsed.N != n || parsed.PN != pn) {
        IRVectorRecordFailure(testCase, @"[%@] round-trip counters: N %u/%u, PN %u/%u",
                              vectorCase.identifier,
                              (unsigned)parsed.N, (unsigned)n, (unsigned)parsed.PN, (unsigned)pn);
    }

    if (type == IRMessageTypePrekey) {
        if (parsed.spkId != spkId || parsed.opkId != opkId ||
            (uint32_t)parsed.opkFlag != opkFlag) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] round-trip prologue fields: spk_id %u/%u, opk_flag %u/%u, "
                                  @"opk_id %u/%u",
                                  vectorCase.identifier,
                                  (unsigned)parsed.spkId, (unsigned)spkId,
                                  (unsigned)parsed.opkFlag, (unsigned)opkFlag,
                                  (unsigned)parsed.opkId, (unsigned)opkId);
        }

        if (![parsed.ephemeralPublic isEqualToX25519Public:prologue.ephemeralPublic]) {
            IRVectorRecordFailure(testCase, @"[%@] round-trip lost EK_A", vectorCase.identifier);
        }

        if (![parsed.identityBinding isEqualToEd25519Signature:binding]) {
            IRVectorRecordFailure(testCase, @"[%@] round-trip lost IKB_A", vectorCase.identifier);
        }

        if (![parsed.initiatorIdentity isEqualToIdentityKeyPair:initiator]) {
            IRVectorRecordFailure(testCase, @"[%@] round-trip lost the initiator identity",
                                  vectorCase.identifier);
        }
    }

    /* §9 — the ciphertext's extent is derived by subtraction from the total length, because there
       is no length field on the wire to misparse. */
    NSData *payload = [IRMessageGate ciphertextAndTagOfMessage:message header:parsed error:&error];
    if (![payload isEqualToData:ciphertextAndTag]) {
        IRVectorRecordFailure(testCase, @"[%@] ciphertext extraction returned %@ (%@)",
                              vectorCase.identifier,
                              payload ? IRVectorHex(payload) : @"nil", error);
    }

    [vectorCase finish];
}

#pragma mark WIRE-BUNDLE-OPK0 / WIRE-BUNDLE-OPK1

static void IRWireRunBundleVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *signingKeyBytes = [vectorCase dataInput:@"IK_s"];
    NSData *agreementKeyBytes = [vectorCase dataInput:@"IK_d"];
    NSData *bindingBytes = [vectorCase dataInput:@"IKB"];
    uint32_t spkId = [vectorCase uint32Input:@"spk_id"];
    NSData *signedPreKeyBytes = [vectorCase dataInput:@"SPK"];
    uint64_t notBeforeS = [vectorCase uint64Input:@"not_before"];
    uint64_t notAfterS = [vectorCase uint64Input:@"not_after"];
    NSData *spkSignatureBytes = [vectorCase dataInput:@"SPK_SIG"];
    NSArray *rawEntries = [vectorCase arrayInput:@"opk_entries"];

    if (![entryPoint isEqualToString:@"parse_bundle"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"parse_bundle\"",
                              vectorCase.identifier, entryPoint);
    }

    IREd25519Public *signingKey = [IREd25519Public fromData:signingKeyBytes error:&error];
    IRWireGuard(signingKey, @"[%@] IK_s: %@", vectorCase.identifier, error);

    IRX25519Public *agreementKey = [IRX25519Public fromData:agreementKeyBytes error:&error];
    IRWireGuard(agreementKey, @"[%@] IK_d: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *keyPair = [IRIdentityKeyPair pairWithSigningKey:signingKey
                                                          agreementKey:agreementKey
                                                                 error:&error];
    IRWireGuard(keyPair, @"[%@] identity pair: %@", vectorCase.identifier, error);

    IREd25519Signature *binding = [IREd25519Signature fromData:bindingBytes error:&error];
    IRWireGuard(binding, @"[%@] IKB: %@", vectorCase.identifier, error);

    /* Encoding-only vectors read no clock, so the ambient environment is used rather than an
       injected one — and the driver's ten-years-forward run is what proves that claim. */
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    /* §5.1 — the binding is VERIFIED by this constructor. A bundle whose IKB did not verify is one
       no conformant port would parse, so this is part of the vector, not scaffolding. */
    IRPublicIdentity *identity = [IRPublicIdentity identityWithKeyPair:keyPair
                                                              binding:binding
                                                             provider:provider
                                                                error:&error];
    IRWireGuard(identity, @"[%@] IKB failed to verify (§5.1): %@", vectorCase.identifier, error);

    IRX25519Public *signedPreKey = [IRX25519Public fromData:signedPreKeyBytes error:&error];
    IRWireGuard(signedPreKey, @"[%@] SPK: %@", vectorCase.identifier, error);

    IREd25519Signature *spkSignature = [IREd25519Signature fromData:spkSignatureBytes error:&error];
    IRWireGuard(spkSignature, @"[%@] SPK_SIG: %@", vectorCase.identifier, error);

    NSMutableArray<IRPreKeyBundleOPKEntry *> *opkEntries = [NSMutableArray array];
    for (id raw in rawEntries) {
        NSNumber *opkId = [raw isKindOfClass:[NSDictionary class]] ? raw[@"opk_id"] : nil;
        NSString *opkHex = [raw isKindOfClass:[NSDictionary class]] ? raw[@"opk_pub"] : nil;

        if (![opkId isKindOfClass:[NSNumber class]] || !IRVectorHexIsWellFormed(opkHex)) {
            IRVectorRecordFailure(testCase, @"[%@] malformed opk entry: %@",
                                  vectorCase.identifier, raw);
            continue;
        }

        IRX25519Public *opkPublic = [IRX25519Public fromData:IRVectorBytes(opkHex) error:&error];
        if (opkPublic == nil) {
            IRVectorRecordFailure(testCase, @"[%@] OPK %@: %@", vectorCase.identifier, opkHex, error);
            continue;
        }

        IRPreKeyBundleOPKEntry *entry =
            [IRPreKeyBundleOPKEntry entryWithOpkId:(uint32_t)opkId.unsignedLongLongValue
                                         publicKey:opkPublic
                                             error:&error];
        if (entry == nil) {
            IRVectorRecordFailure(testCase, @"[%@] opk entry: %@", vectorCase.identifier, error);
            continue;
        }

        [opkEntries addObject:entry];
    }

    NSData *bundle = [IRPreKeyBundle serializeWithIdentity:identity
                                                     spkId:spkId
                                              signedPreKey:signedPreKey
                                                notBeforeS:notBeforeS
                                                 notAfterS:notAfterS
                                     signedPreKeySignature:spkSignature
                                                opkEntries:opkEntries
                                                     error:&error];
    IRWireGuard(bundle, @"[%@] bundle encoding failed: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"bundle" data:bundle];
    [vectorCase checkOutput:@"bundle_len" number:@(bundle.length)];
    [vectorCase checkResultError:nil];

    /* §10.3's ordered gate, then §5.3 rules 2–4. Rules 5–6 read a clock and live in
       -validateValidityWindowAtUnixSeconds:error:, which these encoding-only vectors do NOT call
       (§15.3): they supply no now_s, and §15.5 rule 6 makes a clock read without one malformed. */
    IRPreKeyBundle *parsed = [IRPreKeyBundle bundleFromData:bundle provider:provider error:&error];
    IRWireGuard(parsed, @"[%@] §10.3 rejected its own encoding: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"opk_count" number:@(parsed.opkEntries.count)];

    if (parsed.spkId != spkId || parsed.notBeforeS != notBeforeS || parsed.notAfterS != notAfterS) {
        IRVectorRecordFailure(testCase,
                              @"[%@] round-trip: spk_id %u/%u, not_before %llu/%llu, "
                              @"not_after %llu/%llu",
                              vectorCase.identifier,
                              (unsigned)parsed.spkId, (unsigned)spkId,
                              (unsigned long long)parsed.notBeforeS,
                              (unsigned long long)notBeforeS,
                              (unsigned long long)parsed.notAfterS,
                              (unsigned long long)notAfterS);
    }

    if (![parsed.signedPreKey isEqualToX25519Public:signedPreKey]) {
        IRVectorRecordFailure(testCase, @"[%@] round-trip lost SPK", vectorCase.identifier);
    }

    if (![parsed.identity isEqualToPublicIdentity:identity]) {
        IRVectorRecordFailure(testCase, @"[%@] round-trip lost the identity", vectorCase.identifier);
    }

    NSData *reEncoded = [parsed serializedData:&error];
    if (![reEncoded isEqualToData:bundle]) {
        IRVectorRecordFailure(testCase, @"[%@] parse then re-encode is not the identity: %@ (%@)",
                              vectorCase.identifier,
                              reEncoded ? IRVectorHex(reEncoded) : @"nil", error);
    }

    [vectorCase finish];
}

#pragma mark WIRE-AD-01 / WIRE-AD-02

static void IRWireRunADVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *initiatorSigningBytes = [vectorCase dataInput:@"IK_A_s_pub"];
    NSData *initiatorAgreementBytes = [vectorCase dataInput:@"IK_A_d_pub"];
    NSData *responderSigningBytes = [vectorCase dataInput:@"IK_B_s_pub"];
    NSData *responderAgreementBytes = [vectorCase dataInput:@"IK_B_d_pub"];
    NSData *header = [vectorCase dataInput:@"header"];

    IREd25519Public *initiatorSigning = [IREd25519Public fromData:initiatorSigningBytes
                                                            error:&error];
    IRWireGuard(initiatorSigning, @"[%@] IK_A_s_pub: %@", vectorCase.identifier, error);

    IRX25519Public *initiatorAgreement = [IRX25519Public fromData:initiatorAgreementBytes
                                                            error:&error];
    IRWireGuard(initiatorAgreement, @"[%@] IK_A_d_pub: %@", vectorCase.identifier, error);

    IREd25519Public *responderSigning = [IREd25519Public fromData:responderSigningBytes
                                                            error:&error];
    IRWireGuard(responderSigning, @"[%@] IK_B_s_pub: %@", vectorCase.identifier, error);

    IRX25519Public *responderAgreement = [IRX25519Public fromData:responderAgreementBytes
                                                            error:&error];
    IRWireGuard(responderAgreement, @"[%@] IK_B_d_pub: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *initiator = [IRIdentityKeyPair pairWithSigningKey:initiatorSigning
                                                            agreementKey:initiatorAgreement
                                                                   error:&error];
    IRWireGuard(initiator, @"[%@] initiator pair: %@", vectorCase.identifier, error);

    IRIdentityKeyPair *responder = [IRIdentityKeyPair pairWithSigningKey:responderSigning
                                                            agreementKey:responderAgreement
                                                                   error:&error];
    IRWireGuard(responder, @"[%@] responder pair: %@", vectorCase.identifier, error);

    /* §6.5 — `initiator:` and `responder:`, BY ROLE. There is no self:/peer: spelling available,
       which is the structural answer to the divergence §6.5 calls the most likely in the whole
       protocol: a port that recomputes SESSION_AD as (self, peer) interoperates with itself and
       with nothing else. */
    IRSessionAD *sessionAD = [IRSessionAD adWithInitiator:initiator
                                                responder:responder
                                                    error:&error];
    IRWireGuard(sessionAD, @"[%@] SESSION_AD: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"SESSION_AD" data:sessionAD.bytes];
    [vectorCase checkIntermediate:@"SESSION_AD_len" number:@(sessionAD.bytes.length)];

    NSData *associatedData = [sessionAD associatedDataWithHeaderBytes:header error:&error];
    IRWireGuard(associatedData, @"[%@] AD: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"AD" data:associatedData];
    [vectorCase checkOutput:@"AD_len" number:@(associatedData.length)];
    [vectorCase checkResultError:nil];

    [vectorCase finish];
}

#pragma mark - Dispatch

void IRRunWireVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    if (![vectorCase.kind isEqualToString:@"wire"]) {
        IRVectorRecordFailure(testCase, @"[%@] kind is \"%@\"; wire.json carries only \"wire\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    NSString *identifier = vectorCase.identifier;

    if ([identifier isEqualToString:@"WIRE-MSG-01"]) {
        IRWireRunMessageVector(testCase, vectorCase, IRMessageTypeNormal);
    } else if ([identifier isEqualToString:@"WIRE-MSG-02"]) {
        IRWireRunMessageVector(testCase, vectorCase, IRMessageTypePrekey);
    } else if ([identifier hasPrefix:@"WIRE-BUNDLE-"]) {
        IRWireRunBundleVector(testCase, vectorCase);
    } else if ([identifier hasPrefix:@"WIRE-AD-"]) {
        IRWireRunADVector(testCase, vectorCase);
    } else {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is exactly
           what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase, @"[%@] wire.json has no executor for this id", identifier);
    }
}
