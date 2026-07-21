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
#import "IRProtocolKDF.h"
#import "IRPublicIdentity.h"
#import "IRRatchet.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSession+Internal.h"
#import "IRSessionDispatch.h"
#import "IRSessionStore.h"
#import "IRSkippedKeyStore.h"
#import "IRX3DH.h"

/**
 negative.json, part 1 of 3 — SPEC §15.4, §15.5.

 THE REJECTIONS THAT NEED KEY AGREEMENT, A RATCHET, A PREKEY STORE OR A SESSION TO REACH. Kinds
 `primitive`, `x3dh` and `ratchet`; the driver routes every other kind to the wire and store modules
 (IRVectorModules.h). The partition there is exhaustive, so this file emits every row §15.4 assigns
 to it and no row it does not.

 TWENTY-SIX VECTORS, in the order §15.4 lists them:

     NEG-DH2-ALTERED  NEG-DH3-ALTERED  NEG-DH4-ALTERED   every DH term reaches the KDF   (§6.3)
     NEG-RK-ALTERED                                      the root chain has continuity   (§7.2)
     NEG-SK-TAMPER                                       one flipped SK byte fails closed
     NEG-ATOMIC                                          the desynchronisation DoS       (§7.7)
     NEG-SKIP-RETAIN                                     a stored key survives a bad tag (§7.6)
     NEG-IKB-SWAP     NEG-IKB-RETRANS                    identity is the PAIR            (§5.5)
     NEG-SPKSIG-BAD   NEG-SPK-EXPIRED  NEG-SPK-WINDOW-TOO-LONG                           (§5.3)
     NEG-SPK-SURVIVES-RATCHET                            copy, never alias, SPK_B_priv   (§7.5)
     NEG-OPK-UNKNOWN  NEG-OPK-EXPIRED  NEG-OPK-NOFALLBACK                                (§5.3, §6.6)
     NEG-SMALLORDER   NEG-COUNTER      NEG-SKIP-LIMIT    NEG-REPLAY
     NEG-NO-SESSION   NEG-DEMUX-WRONG-SESSION  NEG-DEMUX-WRONG-PEER                      (§11.5)
     NEG-HANDSHAKE-TOMBSTONE  NEG-COLLAPSE-LOSER-REPLAY  NEG-COLLAPSE-LOSER-HANDLE       (§10.7, §11.4)

 §15.4 SINGLES OUT SIX OF THEM AS THE HIGHEST-VALUE TESTS IN THE SUITE, and every one is here:
 `NEG-DH2/3/4-ALTERED` and `NEG-RK-ALTERED` fail immediately against v3 — v3 handed a 128-byte IKM
 to an API that reads 32 bytes, so a bit flipped at IKM offset 64, 96 or 128 changed nothing at all;
 `NEG-SK-TAMPER` is the only row that would have caught defect 2; and `NEG-ATOMIC` is the only one
 that catches the unauthenticated desynchronisation DoS, which is state corruption rather than a
 wrong plaintext and which therefore no round-trip test can see.

 HOW A SCENARIO IS MADE REPRODUCIBLE, AND WHY IT IS NOT A PILE OF LITERAL KEYS.

 Every vector in this file drives whole protocol layers — a bundle publication, an X3DH, a ratchet,
 a session store — and each of those draws from the CSPRNG at points no public API exposes. §15.5
 rule 5 requires the randomness be supplied in `inputs` and injected, so each ACTOR is given ONE
 literal byte script in `inputs` (`rng_A`, `rng_B`, `rng_C`) which its IRScriptedRandomSource serves
 in draw order: the Ed25519 identity seed first, then the X25519 identity scalar, then whatever that
 actor's part of the scenario asks for — a signed prekey scalar, a one-time prekey scalar, `EK_A`,
 a ratchet scalar, a 12-byte nonce.

 A single script per actor rather than a named field per key is deliberate. Naming the fields would
 require this file to assert the exact number and order of draws inside four production classes,
 and every such assertion is a guess that breaks the freeze the day an implementation reorders two
 lines that were never specified to be in that order. The script is the seam §13.1 already defines,
 it is the only seam every port must have, and it fails LOUD: IRScriptedRandomSource returns
 IRErrorRNGFailure on exhaustion rather than cycling, so an over-drawing port stops here instead of
 quietly reusing a nonce under one key (§8.3).

 SESSION FIXTURES ARE EMITTED, NOT INVENTED. §15.5's reserved `sessions` key wants each fixture as a
 literal §12.1 blob. These vectors REPLAY the handshake that produced the session — from the scripts
 above, so it is reproducible — and then emit the resulting blob, `handshake_id` and peer identity
 pair into `inputs.sessions`, where a runner compares them against what its own replay produced.
 That comparison is the interop check: two ports that disagree about §12.1 by one byte, or about
 which identity pair §6.5 calls the peer's, diverge here rather than three vectors later.

 `outputs` then carries `sessions.<name>.state_blob_after` — the reserved output key, spelled as the
 flat dotted path §15.5 writes it as — captured IMMEDIATELY after the stimulus call. That is the
 only expressible form of the "no state mutated" assertion §7.7, `NEG-ATOMIC`, `NEG-SKIP-RETAIN`,
 `NEG-DEMUX-WRONG-SESSION` and `NEG-DEMUX-WRONG-PEER` all rest on, and §12.1 is byte-normative
 precisely so that it is possible.

 NO VECTOR HERE READS THE HOST WALL CLOCK. Every scenario that reaches a clock — and every scenario
 that goes through IRMessenger does, since §11.4's tombstone window and §7.6's TTL are evaluated on
 every receive — supplies `now_ms`, and `now_s` as well wherever §5.3's second-granularity windows
 or `OPK_MAX_AGE_S` are the subject. Both are injected through IRVectorEnvironmentAtUnixMilliseconds.
 The two vectors that touch no clock at all (`NEG-RK-ALTERED` and the three IKM rows) take the
 ambient environment, which is what makes the driver's ten-years-forward run (§15.6) a real check on
 them rather than a formality.

 ONE STRUCTURE, TWICE. Each row names a SCENARIO — a C function that takes decoded inputs, drives
 the implementation, and returns what it observed. The generator calls it to build the frozen bytes;
 the executor calls the same function on the frozen bytes and asserts against them. A scenario never
 asserts and never raises: it reports through IRNegResult, so a fixture that cannot be built names
 itself in both directions instead of aborting the corpus run.
 */

#pragma mark - Fixed CSPRNG scripts (§15.5 rule 5)

/*
 512 bytes per actor, served in draw order by IRScriptedRandomSource. The longest scenario here —
 NEG-SPK-SURVIVES-RATCHET, whose responder generates an identity, a signed prekey, two one-time
 prekeys, three ratchet scalars and a nonce — consumes under 300, so every script has headroom and
 none is ever exhausted. Exhaustion is a hard failure by design and is not worked around by
 scripting more than the code path draws: the surplus is never served.

 These bytes are arbitrary and synthetic. They are NOT key material of any kind until a production
 generator has clamped (§4.2) or expanded (RFC 8032) them, which is the point: §15.5 rule 5 injects
 at the CSPRNG seam so that the code under test performs every derivation the wire depends on.
*/

static NSString * const kNegScriptA =
    @"b71f83c5b2c7308ce469bcecc9668dafa45e6b3b111727ae7e8fb0a8a13c9ec7"
    @"d48223d362567896c90fb06ae86b02711fc17c825a652fc61637c3ff4c6e7c83"
    @"4f83b6eda057c96ea8885fe469f040891f5e8067c970306fb0af6e45cfccf1ba"
    @"3718faf75b21c05a508a4700fb0ca4fe33a9b450cc0e466f992ab2a15aebdbf0"
    @"9a37add8810afd9f8dcde6654ad48cd7e81955a3d017908c1fe08b38196219ad"
    @"86d68d76fe681c852f04b9b8055f5719cd25a3c643602c8b9007f8313cc68875"
    @"08ec58b7c391bd4f04e73fa0dbc262ca7042db1e94be38333bd4f6b1efad07d0"
    @"2f6dcc81bcda7c46d82cf5c278130bf05fe53b133008d2496d7e84de62ad7343"
    @"0950a8b9d79af8ae7b895ac48b68b1922786020986141894743a9fdfc15daa55"
    @"a48ca8470327cecdbab2eb4dc2d8b1b458996c6804b727da9e3f46da3c528b8a"
    @"0d158c102ed79eeb63602702cb786a5e7e96b89417c91ee13ac377f3ff22f36a"
    @"53e311f944ff044c44478c8a555e399527f225f42d1e1c6e94fb2f533a64c079"
    @"84eaf5ea36f7a0372c1d978a0ca07c5fe323f0eeb58d3d48fc1d6d1d19add13f"
    @"ad22f6c7f0130ef1e899c7a99f5592c23e9f56e91ceca034c0602e79cb930341"
    @"dd80d27760aaedc146719a8cbc92d8c5c7dc9749d11062f92cfa728d7fad3406"
    @"22f947e17512dbed145a8dd9116eac6d0b50f07441d1a35d9020347d618f4312";

static NSString * const kNegScriptB =
    @"e2ebdd336769bb487f4c14523048306c4a0d7d2abcb787cdeb725f16ed4e70d7"
    @"b840c72a4458cd6197216999c4349a0ddbff7f0ccab3cba8286bad0cf77a288a"
    @"50f5da59076031f735931650b8cfff7da6fd7948a5242054420d01f5291178c0"
    @"582172c43ef72672c67a393d5c4e5be2d79c48645bff43b726aefa1852c7df1f"
    @"7ed9ef727693e837b9aaf027fde8ad639d72cbe7f93af4b6c3a336bb3e52db4c"
    @"7033af6a3eabb7ab7bfb59d4e9d3f2262616df558ecbf03906435323bd69eaed"
    @"dc450fb124b3d0357b40910a6e44294fa11d623628a8f525dee5ef989dc289a9"
    @"70266d4db522703c2652b88edb7150073a1d330fd5c8c15f38dca85daa123625"
    @"daeb2844806fd724ea06ea277c91647120ac2f66a21f13cf03811bbbb40f7108"
    @"c8ab9d9c130e43543631479aa2da64b5816134c19ea4a7592c29e8f68870b6f7"
    @"e87a2a5cfc77f03278aaebaf98814df98bd121a6d74d3de4a129ab55f4eb8398"
    @"e8702e89c81e1d241d47f52aadbd1e626d92d39c5a11915651d8031dc6355792"
    @"76a20628077b099094de82d130c3d516533b292737e463962a8c8e96cd05b08b"
    @"402710414403f0dc4a45b26b6eca6f3c6c61ffcf7abd7088199bea03d6110b27"
    @"f414abda102b126ead51a2beb507ebf9e69a3619319376130d5ab5adaf0ee70e"
    @"407f34f7f76babab2cd96f9054b14774ef7da98b6c5a331df3218cd826b2c2e6";

static NSString * const kNegScriptC =
    @"0db737a21d0b45041a2e6bb9982ad229efbc8f1a6756e8ec58540e84385f41e6"
    @"9dfe6b82275a222b653221c89ffd33a9983d82963a0266893a9e9719a286d491"
    @"5268fdc56e699a80c19fcdbb07adbe712c9c732981d90f38d46b94a5835500c7"
    @"7a2aeb9120cd8b8a3c692b7abd9013c67b8fdd79eaf040feb431438f49a2e44e"
    @"637a320d6b1dd3cee488faeaaffcceef52cb412a235d58e16766e23e63429deb"
    @"5b8fd15e7ded51d1c6f1f9f0cc468e327f061be5d937b4e77c80af163f0c4b65"
    @"b19fc6ab85d5e31bf19ae47402c6f1d5d1f8e94dbc93b21781f5e87e4ad60b82"
    @"b2df0e19af6b653273787b5a3dd0941d15542a0a7987b175033bccddf276fa07"
    @"ac86a7cf2943b79a5a837b8a6ebb175119d35cc2be2a0e0991c89897a6c137bb"
    @"edc991f223f5b7dbb3b0a2e881dc16b6ab29fd1a389127d8b9128913d48fe064"
    @"c4dfc8a8ca1742798df5ae5b648b3194990c8ab897d25be8098fdfb6e8b413c7"
    @"7dfe4a184c3d36fcf6485dc9061c042fb23381438803073f0eb6d7e85307eeab"
    @"685b1667d7ff71e9fc9f6d1854e62ecdc3536160b93b89e458fbaf0e815d8fd6"
    @"d32c2abc99f2d2c7acf09d2e3d3f4db59a23a8b6d78f40db72d5a58ee08e130d"
    @"0aa8843cc0ac361a1531a9f1af7dfe2d0559d4ea9215892cedbbf8cddf6e9a17"
    @"5d05210d7ac47c6a4558514796f5e17bd3aa62a296e4c2dc5521e433ebd440ba";

#pragma mark - Fixed non-key literals

/* §5.2's window and an instant inside it. 2026-01-01T00:00:00Z to 2026-03-30T00:00:00Z is 7603200
   seconds, comfortably inside MAX_SPK_VALIDITY_SECONDS (7776000), so every vector that is NOT about
   the window passes §5.3 rules 5–6 rather than tripping over them by accident. */
static const uint64_t kNegNotBeforeS = 1767225600ULL;
static const uint64_t kNegNotAfterS  = 1774828800ULL;
static const uint64_t kNegNowS       = 1767830400ULL;
static const uint64_t kNegNowMs      = 1767830400000ULL;

static const uint32_t kNegSpkId  = 7;
static const uint32_t kNegOpkId  = 42;
static const uint32_t kNegOpkId2 = 43;

/* A valid X25519 public key that belongs to nobody: byte 31's high bit is clear, so §4.4 check 2
   passes, and it is not any key in any fixture, so it is the "novel ratchet key" NEG-ATOMIC needs to
   drive a DH ratchet on a message whose tag will not verify. */
static NSString * const kNegForeignRatchetPublic =
    @"5b3d1e2f4a6c8d0e1f2a3b4c5d6e7f80919293a4b5c6d7e8f90a1b2c3d4e5f60";

/* NEG-RK-ALTERED's two 32-byte inputs to §7.2's KDF_RK. Opaque by design: the row asserts that a
   changed root key changes the output, which is a property of the KDF and not of any handshake. */
static NSString * const kNegRootKeyHex =
    @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static NSString * const kNegDHOutputHex =
    @"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

#pragma mark - Result of one scenario

/**
 WHAT A SCENARIO OBSERVED, reported rather than asserted.

 A scenario is called twice over a vector's life — once by the generator to produce the frozen bytes
 and once by the executor to check them — and only the executor has an XCTestCase to record against.
 Returning the observation keeps one code path for both and makes "the fixture could not be built"
 (`failure`) a distinct outcome from "the implementation returned the wrong thing", which is the
 distinction that tells a port whether its bug is in the vector's setup or in the rule under test.
 */
@interface IRNegResult : NSObject

/// Set when the scenario could not be constructed at all. Everything else is then meaningless.
@property (nonatomic, copy, nullable) NSString *failure;

/// The error the stimulus produced, or nil when the vector expects success.
@property (nonatomic, strong, nullable) NSError *error;

/// §15.5 rule 2 — values a runner MUST check if it can expose them.
@property (nonatomic, strong) NSMutableDictionary *intermediates;

/// §15.5 rule 1 — including the `sessions.<name>.state_blob_after` reserved key.
@property (nonatomic, strong) NSMutableDictionary *outputs;

/// §15.5's reserved `inputs.sessions` map, as the replay produced it.
@property (nonatomic, strong) NSMutableDictionary *sessions;

/// §15.5's reserved `inputs.selected_session`, when an entry point took a handle.
@property (nonatomic, copy, nullable) NSString *selectedSession;

+ (instancetype)result;

@end

@implementation IRNegResult

+ (instancetype)result {
    IRNegResult *result = [[IRNegResult alloc] init];
    result.intermediates = [NSMutableDictionary dictionary];
    result.outputs = [NSMutableDictionary dictionary];
    result.sessions = [NSMutableDictionary dictionary];

    return result;
}

@end

/// Abandons the scenario, naming what could not be built. Never an assertion: see IRNegResult.
#define IRNegAbort(...)                                                                            \
    do {                                                                                           \
        IRNegResult *_r = [IRNegResult result];                                                    \
        _r.failure = [NSString stringWithFormat:__VA_ARGS__];                                      \
        return _r;                                                                                 \
    } while (0)

#define IRNegNeed(value, ...)                                                                      \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRNegAbort(__VA_ARGS__);                                                               \
        }                                                                                          \
    } while (0)

#define IRNegNeedTrue(condition, ...)                                                              \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            IRNegAbort(__VA_ARGS__);                                                               \
        }                                                                                          \
    } while (0)

#pragma mark - Decoded inputs

/* A scenario reads its inputs from a plain dictionary: NSData for every hex field, NSNumber for
   every numeric one. The generator fills it from the literals above; the executor fills it from the
   frozen file through IRVectorCase, which is what makes rule 3's consumption bookkeeping complete.
   One decoding, one set of key names, and no way for the two directions to drift apart. */

static NSData *IRNegData(NSDictionary *inputs, NSString *key) {
    id value = inputs[key];

    return [value isKindOfClass:[NSData class]] ? value : [NSData data];
}

static uint32_t IRNegU32(NSDictionary *inputs, NSString *key) {
    id value = inputs[key];

    return [value isKindOfClass:[NSNumber class]] ? (uint32_t)[value unsignedLongLongValue] : 0;
}

static uint64_t IRNegU64(NSDictionary *inputs, NSString *key) {
    id value = inputs[key];

    return [value isKindOfClass:[NSNumber class]] ? [value unsignedLongLongValue] : 0;
}

static NSString *IRNegString(NSDictionary *inputs, NSString *key) {
    id value = inputs[key];

    return [value isKindOfClass:[NSString class]] ? value : @"";
}

#pragma mark - Byte surgery

/// A copy of `data` with `mask` XORed into the byte at `offset`. Every forgery below is expressed
/// this way so each vector states exactly which §9 field it attacks and at which offset.
static NSData *_Nullable IRNegFlipByte(NSData *data, NSUInteger offset, uint8_t mask) {
    if (offset >= data.length) {
        return nil;
    }

    NSMutableData *copy = [data mutableCopy];
    ((uint8_t *)copy.mutableBytes)[offset] ^= mask;

    return copy;
}

/// A copy of `data` with `replacement` written over it at `offset`.
static NSData *_Nullable IRNegSplice(NSData *data, NSUInteger offset, NSData *replacement) {
    if (offset + replacement.length > data.length) {
        return nil;
    }

    NSMutableData *copy = [data mutableCopy];
    [copy replaceBytesInRange:NSMakeRange(offset, replacement.length) withBytes:replacement.bytes];

    return copy;
}

/// A copy of `data` with a big-endian uint32 written at `offset` — §9.1's `N` and `PN` slots.
static NSData *_Nullable IRNegSetUInt32(NSData *data, NSUInteger offset, uint32_t value) {
    uint8_t encoded[4] = {
        (uint8_t)((value >> 24) & 0xFF),
        (uint8_t)((value >> 16) & 0xFF),
        (uint8_t)((value >> 8) & 0xFF),
        (uint8_t)(value & 0xFF),
    };

    return IRNegSplice(data, offset, [NSData dataWithBytes:encoded length:sizeof(encoded)]);
}

static NSData *IRNegSecretCopy(IRSecretBytes *secret) {
    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

#pragma mark - Actors

/**
 ONE PARTICIPANT, WITH EVERY AMBIENT INPUT INJECTED.

 The identity is generated from the head of `script` by the REAL generator rather than being
 assembled from literals, so `IKB` (§5.1) is a genuine signature over the pair this actor actually
 holds and every §5.5 ingest check in every scenario below is verifying something real. The same
 source then serves the messenger, so a signed prekey scalar, a one-time prekey scalar, `EK_A`, a
 ratchet scalar and a nonce all come from one reproducible stream in the order the code draws them.
 */
@interface IRNegActor : NSObject

@property (nonatomic, strong) IRIdentity *identity;
@property (nonatomic, strong) IRInMemoryPreKeyStore *preKeys;
@property (nonatomic, strong) IRInMemorySessionStore *sessions;
@property (nonatomic, strong) id<IRCryptoProvider> provider;
@property (nonatomic, strong) IREnvironment *environment;
@property (nonatomic, strong) IRMessenger *messenger;
@property (nonatomic, strong) IRScriptedRandomSource *source;

@end

@implementation IRNegActor
@end

/**
 Builds an actor over `script`, with its clock pinned to `nowMs` (§15.5 rule 6).

 Returns nil and fills `outFailure` rather than raising: a scenario reports, it does not assert.
 */
static IRNegActor *_Nullable IRNegMakeActor(NSData *script,
                                            uint64_t nowMs,
                                            NSString *label,
                                            NSString *__autoreleasing *outFailure) {
    NSError *error = nil;

    if (script.length == 0) {
        *outFailure = [NSString stringWithFormat:@"rng_%@ is empty", label];
        return nil;
    }

    IRNegActor *actor = [[IRNegActor alloc] init];
    actor.source = [IRScriptedRandomSource sourceWithData:script];
    actor.environment = IRVectorEnvironmentAtUnixMilliseconds(nowMs, actor.source);
    actor.provider = IRVectorProviderWithEnvironment(actor.environment);

    actor.identity = [IRIdentity generateWithProvider:actor.provider error:&error];
    if (actor.identity == nil) {
        *outFailure = [NSString stringWithFormat:@"identity %@: %@", label, error];
        return nil;
    }

    actor.preKeys = [IRInMemoryPreKeyStore store];
    actor.sessions = [IRInMemorySessionStore store];

    actor.messenger = [[IRMessenger alloc] initWithIdentity:actor.identity
                                                preKeyStore:actor.preKeys
                                               sessionStore:actor.sessions
                                                   provider:actor.provider
                                                environment:actor.environment
                                                      error:&error];
    if (actor.messenger == nil) {
        *outFailure = [NSString stringWithFormat:@"messenger %@: %@", label, error];
        return nil;
    }

    return actor;
}

#pragma mark - Prekey publication

/**
 A responder's signed prekey, one-time prekey and published bundle — SPEC §5.2, §5.4.

 -publishBundleWithSPKId:… is deliberately NOT used. It draws four CSPRNG bytes per one-time prekey
 to invent an `opk_id`, so a vector built on it could not name the id it is about, and
 `NEG-OPK-UNKNOWN` is precisely a vector about a named id. The records are generated and stored
 explicitly instead, which is also what lets `storeOneTimePreKey` be false for the row that needs a
 bundle advertising a key its publisher never retained.
 */
@interface IRNegPublication : NSObject

@property (nonatomic, strong) IRSignedPreKeyRecord *signedPreKey;
@property (nonatomic, strong) IROneTimePreKeyRecord *oneTimePreKey;
@property (nonatomic, copy) NSData *bundleData;

@end

@implementation IRNegPublication
@end

static IRNegPublication *_Nullable IRNegPublish(IRNegActor *responder,
                                                uint32_t spkId,
                                                uint32_t opkId,
                                                uint64_t notBeforeS,
                                                uint64_t notAfterS,
                                                uint64_t opkCreatedAtS,
                                                BOOL storeOneTimePreKey,
                                                NSString *__autoreleasing *outFailure) {
    NSError *error = nil;

    IRSignedPreKeyRecord *spk = [IRSignedPreKeyRecord generateWithIdentity:responder.identity
                                                                    spkId:spkId
                                                               notBeforeS:notBeforeS
                                                                notAfterS:notAfterS
                                                                 provider:responder.provider
                                                                    error:&error];
    if (spk == nil) {
        *outFailure = [NSString stringWithFormat:@"signed prekey: %@", error];
        return nil;
    }

    if (![responder.preKeys storeSignedPreKeyRecord:spk makeCurrent:YES error:&error]) {
        *outFailure = [NSString stringWithFormat:@"store signed prekey: %@", error];
        return nil;
    }

    IROneTimePreKeyRecord *opk = [IROneTimePreKeyRecord generateWithOpkId:opkId
                                                        createdAtUnixSecs:opkCreatedAtS
                                                                 provider:responder.provider
                                                                    error:&error];
    if (opk == nil) {
        *outFailure = [NSString stringWithFormat:@"one-time prekey: %@", error];
        return nil;
    }

    /* The publisher advertises the key either way. Withholding it from the store is what makes
       `opk_id` unresolvable at §10.7 step 7 without touching a single byte of the wire. */
    if (storeOneTimePreKey &&
        ![responder.preKeys storeOneTimePreKeyRecords:@[opk] error:&error]) {
        *outFailure = [NSString stringWithFormat:@"store one-time prekey: %@", error];
        return nil;
    }

    NSData *bundle = [IRPreKeyBundle serializeWithIdentity:responder.identity.publicIdentity
                                       signedPreKeyRecord:spk
                                     oneTimePreKeyRecords:@[opk]
                                                    error:&error];
    if (bundle == nil) {
        *outFailure = [NSString stringWithFormat:@"bundle: %@", error];
        return nil;
    }

    IRNegPublication *publication = [[IRNegPublication alloc] init];
    publication.signedPreKey = spk;
    publication.oneTimePreKey = opk;
    publication.bundleData = bundle;

    return publication;
}

#pragma mark - Establishing a link

/**
 A complete two-way establishment: A opens against B's bundle and sends `opener`, B receives it and
 replies with `ack`, A receives the reply.

 THE REPLY IS NOT DECORATION. §11.3 makes A send type `0x02` "until A has successfully decrypted ANY
 message from B", so without it A never emits the type `0x01` message that eight of these vectors
 use as their stimulus. It is also what puts B one DH ratchet past its signed prekey, which is the
 precondition `NEG-SPK-SURVIVES-RATCHET` is built on.
 */
@interface IRNegLink : NSObject

@property (nonatomic, strong) IRSession *initiatorSession;   ///< A's handle
@property (nonatomic, strong) IRSession *responderSession;   ///< B's handle
@property (nonatomic, copy) NSData *openerMessage;           ///< the type 0x02 A sent

@end

@implementation IRNegLink
@end

static IRNegLink *_Nullable IRNegEstablishLink(IRNegActor *initiator,
                                               IRNegActor *responder,
                                               NSData *bundleData,
                                               NSData *openerPlaintext,
                                               NSData *ackPlaintext,
                                               NSString *__autoreleasing *outFailure) {
    NSError *error = nil;

    IRSession *initiatorSession = [initiator.messenger beginSessionWithBundleData:bundleData
                                                                            error:&error];
    if (initiatorSession == nil) {
        *outFailure = [NSString stringWithFormat:@"beginSession: %@", error];
        return nil;
    }

    NSData *opener = [initiator.messenger encrypt:openerPlaintext
                                        inSession:initiatorSession
                                            error:&error];
    if (opener == nil) {
        *outFailure = [NSString stringWithFormat:@"encrypt opener: %@", error];
        return nil;
    }

    IRDecryptedMessage *atResponder = [responder.messenger decryptPreKeyMessage:opener error:&error];
    if (atResponder == nil) {
        *outFailure = [NSString stringWithFormat:@"decryptPreKeyMessage: %@", error];
        return nil;
    }

    NSData *ack = [responder.messenger encrypt:ackPlaintext
                                     inSession:atResponder.session
                                         error:&error];
    if (ack == nil) {
        *outFailure = [NSString stringWithFormat:@"encrypt ack: %@", error];
        return nil;
    }

    IRDecryptedMessage *atInitiator =
        [initiator.messenger decryptMessage:ack
                    fromPeerIdentityKeyPair:responder.identity.identityKeyPair
                                      error:&error];
    if (atInitiator == nil) {
        *outFailure = [NSString stringWithFormat:@"decrypt ack: %@", error];
        return nil;
    }

    IRNegLink *link = [[IRNegLink alloc] init];
    link.initiatorSession = initiatorSession;
    link.responderSession = atResponder.session;
    link.openerMessage = opener;

    return link;
}

#pragma mark - Session fixtures (§15.5 reserved `sessions`)

/// §12.1 — the session's blob, as bytes. The caller owns nothing secret afterwards: the blob is
/// copied out and the IRSecretBytes is wiped immediately, per §13.3's "after sealing, and after
/// parsing" row.
static NSData *_Nullable IRNegStateBlob(IRSession *session) {
    NSError *error = nil;

    IRSecretBytes *blob = [session serializedState:&error];
    if (blob == nil) {
        return nil;
    }

    NSData *copy = IRNegSecretCopy(blob);
    [blob zeroizeNow];

    return copy;
}

/**
 One `inputs.sessions.<name>` entry: `handshake_id`, `peer_identity` and the §12.1 `state_blob`.

 §11.1's two indices are exactly `handshake_id` and the peer identity PAIR, and §6.5 reads the pair
 out of the stored SESSION_AD rather than storing it twice — so a port that recomputes SESSION_AD as
 (self, peer) instead of (initiator, responder) disagrees with this fixture on `peer_identity`
 before it ever gets to the rule the vector is about.
 */
static NSDictionary *_Nullable IRNegSessionFixture(IRSession *session) {
    NSData *blob = IRNegStateBlob(session);
    if (blob == nil) {
        return nil;
    }

    return @{
        @"handshake_id" : IRVectorHex(session.handshakeId),
        @"peer_identity" : @{
            @"IK_s" : IRVectorHex(session.peerIdentityKeyPair.signingKey.data),
            @"IK_d" : IRVectorHex(session.peerIdentityKeyPair.agreementKey.data),
        },
        @"state_blob" : IRVectorHex(blob),
    };
}

#pragma mark - NEG-RK-ALTERED — §7.2, §15.4

/**
 "Alter `RK` before `KDF_RK`; assert the output changes."

 §7.2's KDF_RK is `HKDF(salt = RK, ikm = DH_out, info = "nuntius:RK:v4", L = 64)`, split into the
 next root key and the sending chain key. THE PREVIOUS ROOT KEY IS THE SALT, and this row is what
 pins that it is consumed at all: v3's `performDHRatchet:` derived from the DH output ALONE and
 assigned `self.rootKey` twice from two independent derivations, discarding its predecessor both
 times, so the root chain had no continuity and altering `RK` changed nothing.

 Both halves of both outputs are frozen, not just the root half. A port that swapped the split —
 `CK = okm[0..32)`, `RK' = okm[32..64)` — agrees with itself forever and interoperates with nothing.
 */
static IRNegResult *IRNegScenarioRootKeyAltered(NSDictionary *inputs) {
    NSError *error = nil;
    IRNegResult *result = [IRNegResult result];

    NSData *rootKeyBytes = IRNegData(inputs, @"RK");
    NSData *dhOutputBytes = IRNegData(inputs, @"DH_out");
    uint32_t offset = IRNegU32(inputs, @"altered_offset");

    /* No clock, no randomness. The ambient environment is what makes that claim checkable: the
       driver re-runs this vector with the host clock ten years forward (§15.6) and a hidden read
       would move the frozen bytes. */
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRRootKey *rootKey = [IRRootKey fromData:rootKeyBytes guarded:NO error:&error];
    IRNegNeed(rootKey, @"RK is not a 32-byte root key: %@", error);

    IRSecretBytes *dhOutput = [[IRSecretBytes alloc] initWithData:dhOutputBytes guarded:NO];
    IRNegNeed(dhOutput, @"DH_out could not be wrapped");

    IRRootChainStep *step = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                  dhOutput:dhOutput
                                                                  provider:provider
                                                                     error:&error];
    IRNegNeed(step, @"KDF_RK: %@", error);

    NSData *alteredRootKeyBytes = IRNegFlipByte(rootKeyBytes, offset, 0x01);
    IRNegNeed(alteredRootKeyBytes, @"altered_offset %u is outside RK", (unsigned)offset);

    IRRootKey *alteredRootKey = [IRRootKey fromData:alteredRootKeyBytes guarded:NO error:&error];
    IRNegNeed(alteredRootKey, @"altered RK: %@", error);

    IRRootChainStep *alteredStep = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:alteredRootKey
                                                                         dhOutput:dhOutput
                                                                         provider:provider
                                                                            error:&error];
    IRNegNeed(alteredStep, @"KDF_RK on the altered root key: %@", error);

    NSData *rk = IRNegSecretCopy(step.rootKey);
    NSData *ck = IRNegSecretCopy(step.chainKey);
    NSData *rkAltered = IRNegSecretCopy(alteredStep.rootKey);
    NSData *ckAltered = IRNegSecretCopy(alteredStep.chainKey);

    IRNegNeedTrue(![rk isEqualToData:rkAltered],
                  @"§15.4: a flipped bit in RK MUST change KDF_RK's root output");
    IRNegNeedTrue(![ck isEqualToData:ckAltered],
                  @"§15.4: a flipped bit in RK MUST change KDF_RK's chain output");

    result.intermediates[@"RK_altered"] = IRVectorHex(alteredRootKeyBytes);
    result.outputs[@"RK_out"] = IRVectorHex(rk);
    result.outputs[@"CK_out"] = IRVectorHex(ck);
    result.outputs[@"RK_out_altered"] = IRVectorHex(rkAltered);
    result.outputs[@"CK_out_altered"] = IRVectorHex(ckAltered);

    [step zeroize];
    [alteredStep zeroize];
    [dhOutput zeroizeNow];

    return result;
}

#pragma mark - NEG-DH2 / DH3 / DH4-ALTERED — §6.3, §15.4

/**
 "Alter DHn in isolation; assert `SK` **changes**."

 THE THREE ROWS §15.4 CALLS THE HIGHEST-VALUE TESTS IN THE SUITE, and the three v3 fails outright.
 v3 concatenated `DH1 ‖ DH2 ‖ DH3 [‖ DH4]` and handed the buffer to `crypto_kdf_derive_from_key`,
 whose key parameter is `const unsigned char k[crypto_kdf_KEYBYTES]` — exactly 32 bytes. Only DH1
 was ever read. IKM offsets 64, 96 and 128 are all past what that API consumes, so under v3 each of
 these three vectors produces a shared key IDENTICAL to the control, and both parties still agree,
 which is why every v3 test passed while the handshake had no forward secrecy and the one-time
 prekey contributed nothing at all.

 ONE BYTE IS FLIPPED INSIDE THE IKM, WITH THE TRANSCRIPT HASH HELD CONSTANT. §6.3 derives
 `SK = HKDF(salt = Z32, ikm = IKM, info = "nuntius:X3DH:v4" ‖ TH, L = 32)`, so altering a DH term
 through the IKM rather than through a key is the only way to move exactly one input: substituting a
 different `SPK_B` or `OPK_B` would change `TRANSCRIPT` too (§6.2) and the vector would no longer
 isolate the term it names.

 The handshake itself is a genuine one — a real bundle, really parsed, really verified — because the
 IKM has to be the one a conformant implementation actually builds for the flip to mean anything.
 */
static IRNegResult *IRNegScenarioIKMAltered(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint32_t ikmOffset = IRNegU32(inputs, @"ikm_offset");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowS * 1000ULL, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowS * 1000ULL, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:published.bundleData
                                                   provider:alice.provider
                                                      error:&error];
    IRNegNeed(bundle, @"§10.3 rejected a bundle this generator produced: %@", error);

    IRX25519KeyPair *ephemeral = [alice.provider generateX25519KeyPairGuarded:NO error:&error];
    IRNegNeed(ephemeral, @"EK_A: %@", error);

    /* retainIKM:YES exists for exactly this row. §13.3 wipes the IKM immediately after SK is
       derived on every production path, so there is no other way to observe the buffer whose
       consumption is the property under test. */
    IRX3DHResult *x3dh = [IRX3DH initiatorResultWithIdentity:alice.identity
                                                      bundle:bundle
                                            ephemeralKeyPair:ephemeral
                                              nowUnixSeconds:nowS
                                                    provider:alice.provider
                                                   retainIKM:YES
                                                       error:&error];
    IRNegNeed(x3dh, @"X3DH: %@", error);
    IRNegNeed(x3dh.ikm, @"retainIKM:YES did not retain the IKM");
    IRNegNeedTrue(x3dh.ikm.length == (NSUInteger)kIRLenIKMOPK,
                  @"an OPK handshake's IKM is %d bytes (§18), got %lu",
                  (int)kIRLenIKMOPK, (unsigned long)x3dh.ikm.length);

    NSData *ikm = IRNegSecretCopy(x3dh.ikm);
    NSData *transcriptHash = [x3dh.transcriptHash copy];
    NSData *sharedKey = IRNegSecretCopy(x3dh.sharedKey);

    NSData *alteredIKMBytes = IRNegFlipByte(ikm, ikmOffset, 0x01);
    IRNegNeed(alteredIKMBytes, @"ikm_offset %u is outside a %lu-byte IKM",
              (unsigned)ikmOffset, (unsigned long)ikm.length);

    IRSecretBytes *alteredIKM = [[IRSecretBytes alloc] initWithData:alteredIKMBytes guarded:NO];
    IRNegNeed(alteredIKM, @"altered IKM could not be wrapped");

    IRRootKey *alteredSharedKey = [IRProtocolKDF deriveSharedKeyWithIKM:alteredIKM
                                                         transcriptHash:transcriptHash
                                                               provider:alice.provider
                                                                  error:&error];
    IRNegNeed(alteredSharedKey, @"SK from the altered IKM: %@", error);

    NSData *alteredSK = IRNegSecretCopy(alteredSharedKey);

    IRNegNeedTrue(![sharedKey isEqualToData:alteredSK],
                  @"§15.4: a flipped bit at IKM offset %u MUST change SK — this term never reaches "
                  @"the KDF", (unsigned)ikmOffset);

    result.intermediates[@"IKM"] = IRVectorHex(ikm);
    result.intermediates[@"IKM_len"] = @(ikm.length);
    result.intermediates[@"IKM_altered"] = IRVectorHex(alteredIKMBytes);
    result.intermediates[@"TH"] = IRVectorHex(transcriptHash);
    result.outputs[@"SK"] = IRVectorHex(sharedKey);
    result.outputs[@"SK_altered"] = IRVectorHex(alteredSK);

    [alteredIKM zeroizeNow];
    [alteredSharedKey zeroizeNow];
    [x3dh zeroize];

    return result;
}

#pragma mark - NEG-SPKSIG-BAD — §5.3 rule 4, §15.4

/**
 "Bundle with a corrupted `SPK_SIG`" → `ERR_BAD_SIGNATURE`.

 v3 never reached an equivalent check. `IRTripleDHService initWithData:` (`:66-68`) RE-SIGNED the
 peer's signed prekey with the LOCAL identity key, which does not merely skip verification — it
 destroys the evidence, overwriting the peer's signature with a locally manufactured one that later
 code then finds valid. §5.3 deletes that code and makes rule 4 a hard abort.

 The corruption is one byte inside `SPK_SIG` at bundle offset 185 (§5.4). Everything else about the
 bundle is genuine, so nothing but rule 4 can reject it — an input wrong in two ways would pass
 under any ordering and would arbitrate nothing.
 */
static IRNegResult *IRNegScenarioSignedPreKeySignatureBad(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowS * 1000ULL, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    /* The genuine bundle MUST parse first. Without that control the vector would also pass on an
       implementation that rejects every bundle it is offered. */
    IRPreKeyBundle *genuine = [IRPreKeyBundle bundleFromData:published.bundleData
                                                    provider:bob.provider
                                                       error:&error];
    IRNegNeed(genuine, @"the unmodified bundle must parse: %@", error);

    NSData *forged = IRNegFlipByte(published.bundleData,
                                   (NSUInteger)kIROffBundleSPKSig + IRNegU32(inputs, @"sig_offset"),
                                   0xFF);
    IRNegNeed(forged, @"sig_offset is outside SPK_SIG");

    IRPreKeyBundle *parsed = [IRPreKeyBundle bundleFromData:forged
                                                   provider:bob.provider
                                                      error:&error];
    IRNegNeedTrue(parsed == nil, @"a corrupted SPK_SIG must not parse");

    result.intermediates[@"bundle"] = IRVectorHex(forged);
    result.intermediates[@"bundle_len"] = @(forged.length);
    result.error = error;

    return result;
}

#pragma mark - NEG-SPK-EXPIRED / NEG-SPK-WINDOW-TOO-LONG — §5.3 rules 5–6, §15.4

/**
 The two clock-reading bundle rules, each reached by a bundle that satisfies the other.

 `NEG-SPK-EXPIRED` supplies `not_before` / `not_after` as fixed literals and an `inputs.now_s`
 OUTSIDE that window, "so the rejection is caused rather than merely observed" — a vector that let
 the window lapse against the host clock would pass on the day it was frozen and fail forever after,
 and §15.6 step 4 forbids regenerating it.

 `NEG-SPK-WINDOW-TOO-LONG` supplies a window longer than `MAX_SPK_VALIDITY_SECONDS` (7776000) with
 `now_s` INSIDE it, so rule 5 passes and only rule 6 can reject.

 RULE 5 IS EVALUATED BEFORE RULE 6 AND THAT ORDER MAKES RULE 6'S SUBTRACTION SAFE: `not_before <=
 now < not_after` implies `not_before < not_after`, so `not_after - not_before` cannot wrap. A port
 that reorders them subtracts unsigned quantities in the wrong order — silently enormous in C, an
 exception in a checked-arithmetic language.

 The parse is separated from the window check on purpose. §10.3 and §5.3 rules 1–4 read NO clock,
 which is what lets `wire.json`'s encoding-only bundle vectors exist; the window lives in
 -validateValidityWindowAtUnixSeconds:error: and is the only part these two rows exercise.
 */
static IRNegResult *IRNegScenarioValidityWindow(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t notBeforeS = IRNegU64(inputs, @"not_before");
    uint64_t notAfterS = IRNegU64(inputs, @"not_after");

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowS * 1000ULL, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               notBeforeS,
                                               notAfterS,
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    /* §5.3 rules 1–4 pass — the bundle is structurally sound and both signatures verify. The
       generator asserting that here is what makes the rejection below attributable to the window
       and to nothing else. */
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:published.bundleData
                                                   provider:bob.provider
                                                      error:&error];
    IRNegNeed(bundle, @"rules 1–4 must pass before the window is evaluated: %@", error);

    BOOL valid = [bundle validateValidityWindowAtUnixSeconds:nowS error:&error];
    IRNegNeedTrue(!valid, @"the window MUST be rejected at now_s = %llu",
                  (unsigned long long)nowS);

    result.intermediates[@"window_seconds"] = @(notAfterS - notBeforeS);
    result.intermediates[@"bundle_len"] = @(published.bundleData.length);
    result.error = error;

    return result;
}

#pragma mark - NEG-SMALLORDER — §4.4 check 3, §15.4

/**
 "A small-order ratchet public key" → `ERR_SMALL_ORDER_KEY`.

 Taken on the INITIATOR's one-time prekey, which is the reachable path and is reachable precisely
 because §5.2 says one-time prekeys are NOT individually signed and that implementations MUST NOT
 invent a per-OPK signature. An OPK therefore carries no authentication of its own; a hostile or
 merely buggy distribution server can serve the all-zero point, and §4.4 check 3 — "any all-zero DH
 output aborts the whole handshake" — is the only thing standing behind it.

 THE BUNDLE PARSES, AND THAT IS THE POINT. §5.3 rule 2 is §4.4 checks 1 and 2 only — a length and a
 high bit — and the all-zero encoding passes both. The rejection can only come later, from the DH
 output itself, which is why this row is `x3dh` and not `wire`.
 */
static IRNegResult *IRNegScenarioSmallOrder(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint32_t spkId = IRNegU32(inputs, @"spk_id");
    uint32_t opkId = IRNegU32(inputs, @"opk_id");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowS * 1000ULL, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowS * 1000ULL, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               spkId,
                                               opkId,
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRX25519Public *smallOrder = [IRX25519Public fromData:IRNegData(inputs, @"OPK_B_pub")
                                                    error:&error];
    IRNegNeed(smallOrder, @"the all-zero point must be a VALID ENCODING (§4.4 checks 1–2): %@",
              error);

    IRPreKeyBundleOPKEntry *entry = [IRPreKeyBundleOPKEntry entryWithOpkId:opkId
                                                                publicKey:smallOrder
                                                                    error:&error];
    IRNegNeed(entry, @"OPK entry: %@", error);

    /* The public-components encoder, so a key no responder ever generated can be advertised. The
       record-taking form could not express this: it emits what the store holds. */
    NSData *bundleData =
        [IRPreKeyBundle serializeWithIdentity:bob.identity.publicIdentity
                                        spkId:spkId
                                 signedPreKey:published.signedPreKey.keyPair.publicKey
                                   notBeforeS:IRNegU64(inputs, @"not_before")
                                    notAfterS:IRNegU64(inputs, @"not_after")
                        signedPreKeySignature:published.signedPreKey.signature
                                   opkEntries:@[entry]
                                        error:&error];
    IRNegNeed(bundleData, @"bundle: %@", error);

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleData
                                                   provider:alice.provider
                                                      error:&error];
    IRNegNeed(bundle, @"a small-order OPK is a WELL-FORMED bundle (§5.3 rule 2 is checks 1–2): %@",
              error);

    IRX25519KeyPair *ephemeral = [alice.provider generateX25519KeyPairGuarded:NO error:&error];
    IRNegNeed(ephemeral, @"EK_A: %@", error);

    IRX3DHResult *x3dh = [IRX3DH initiatorResultWithIdentity:alice.identity
                                                      bundle:bundle
                                            ephemeralKeyPair:ephemeral
                                              nowUnixSeconds:nowS
                                                    provider:alice.provider
                                                   retainIKM:NO
                                                       error:&error];
    IRNegNeedTrue(x3dh == nil, @"DH4 against the all-zero point must abort the handshake");

    result.intermediates[@"bundle_len"] = @(bundleData.length);
    result.error = error;

    return result;
}

#pragma mark - NEG-IKB-SWAP — §5.5, §10.7 step 3, §15.4

/**
 "Victim's genuine `IK^s` with an attacker-chosen `IK^d` in a type `0x02` header, no existing
 session (§10.7 step 3)" → `ERR_BAD_SIGNATURE`.

 THE ATTACK §5.5 EXISTS TO CLOSE, STATED AS BYTES. Under a single-key identity, possession of the
 identity private was proved implicitly by DH1 and DH2, so the identity could not be split from the
 key that authenticated it. Splitting it into `IK^s` and `IK^d` means the DH operations prove
 possession of `IK^d` ALONE — so without `IKB` covering both, an attacker presents the victim's
 genuine signing key beside its own agreement key, completes a cryptographically sound session, and
 is attributed to the victim by any implementation that looks up contacts by the signing key.

 The forgery is one splice: a third actor's `IK^d` written over `msg[36..68)`. `IK_A^s` and `IKB_A`
 are the victim's, untouched and genuine. The spliced key passes §4.4 checks 1–2 — it is a real
 X25519 public — so §10.2's gate has nothing to say about it, and the rejection can only come from
 §10.7 step 3's verification of `IKB_A` over `IKBIND_MSG(IK_A^s, IK_A^d)`, WHICH RUNS BEFORE ANY DH.

 Splicing `IK_A^d` also changes `handshake_id` (§11.1 is `IK_A^d ‖ EK_A`), so this lands on the
 no-existing-session branch that §15.4 names, and never on §11.2's.
 */
static IRNegResult *IRNegScenarioIKBSwap(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegActor *mallory = IRNegMakeActor(IRNegData(inputs, @"rng_C"), nowMs, @"C", &failure);
    IRNegNeed(mallory, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:published.bundleData
                                                                    error:&error];
    IRNegNeed(aliceSession, @"beginSession: %@", error);

    NSData *genuine = [alice.messenger encrypt:IRNegData(inputs, @"plaintext")
                                     inSession:aliceSession
                                         error:&error];
    IRNegNeed(genuine, @"encrypt: %@", error);

    NSData *forged = IRNegSplice(genuine,
                                 (NSUInteger)kIROffType02IdentityAgreement,
                                 mallory.identity.identityKeyPair.agreementKey.data);
    IRNegNeed(forged, @"IK_A^d does not fit at offset %d", (int)kIROffType02IdentityAgreement);

    IRDecryptedMessage *decrypted = [bob.messenger decryptPreKeyMessage:forged error:&error];
    IRNegNeedTrue(decrypted == nil, @"a swapped IK^d must never authenticate");

    /* §10.7 step 3 is BEFORE any DH, so nothing was consumed and nothing was built: the one-time
       prekey is still there and the session store is still empty. */
    result.intermediates[@"IK_A_d_spliced"] =
        IRVectorHex(mallory.identity.identityKeyPair.agreementKey.data);
    result.outputs[@"session_count"] = @(bob.sessions.sessionCount);
    result.outputs[@"opk_count_after"] = @(bob.preKeys.oneTimePreKeyCount);
    result.error = error;

    return result;
}

#pragma mark - NEG-IKB-RETRANS — §5.5 against §11.2, §15.4

/**
 "Retransmitted type `0x02` to an EXISTING session with one byte of `IKB_A` (offset 68..132) flipped.
 Arbitrates §5.5 against §11.2: the code MUST be the signature failure, not the AEAD failure."

 THE ONLY VECTOR IN THE SUITE THAT ARBITRATES A GENUINE CONTRADICTION BETWEEN TWO NORMATIVE SECTIONS
 rather than checking a single rule. §5.5 requires `IKB` verification on EVERY identity ingest,
 including "from a type `0x02` message header". Without §11.2's check 2 this branch is the one ingest
 path that skips it — and the omission is not silent, because `IKB_A` occupies `msg[68..132)`, which
 is inside the type `0x02` associated data (§8.5), so a tampered binding reaches the AEAD and fails
 THERE instead.

 Both readings fail closed. A forged `IKB_A` can never be ACCEPTED either way. But they return
 different codes for identical input, and §15.4 makes the exact code a conformance requirement:
 `ERR_BAD_SIGNATURE`, never `ERR_AEAD_AUTH_FAILED`. §19.3 records the decision and its price — one
 Ed25519 verification per retransmitted prekey message, paid to keep §5.5's blanket MUST free of
 conditional holes.

 The retransmission is real, not synthesised. §11.3 has A sending type `0x02` for every message until
 it has decrypted anything from B, reusing the IDENTICAL prologue, so the second message routes to
 §11.2's existing-session branch by construction — which is the branch this row is about.
 */
static IRNegResult *IRNegScenarioIKBRetrans(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:published.bundleData
                                                                    error:&error];
    IRNegNeed(aliceSession, @"beginSession: %@", error);

    NSData *first = [alice.messenger encrypt:IRNegData(inputs, @"plaintext")
                                   inSession:aliceSession
                                       error:&error];
    IRNegNeed(first, @"encrypt first: %@", error);

    IRDecryptedMessage *established = [bob.messenger decryptPreKeyMessage:first error:&error];
    IRNegNeed(established, @"decryptPreKeyMessage: %@", error);
    IRNegNeedTrue(established.establishedNewSession, @"the first message must open the session");

    /* Still type `0x02` — A has decrypted nothing from B, so §11.3 has not fired. */
    NSData *second = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_2")
                                    inSession:aliceSession
                                        error:&error];
    IRNegNeed(second, @"encrypt retransmission: %@", error);
    IRNegNeedTrue([IRMessenger messageTypeOfMessage:second error:NULL] == IRMessageTypePrekey,
                  @"§11.3: A still sends type 0x02 until it decrypts something from B");

    NSData *forged = IRNegFlipByte(second,
                                   (NSUInteger)kIROffType02IKB + IRNegU32(inputs, @"ikb_offset"),
                                   0x01);
    IRNegNeed(forged, @"ikb_offset is outside IKB_A");

    NSDictionary *fixture = IRNegSessionFixture(established.session);
    IRNegNeed(fixture, @"§12.1 blob for the established session");
    result.sessions[@"S1"] = fixture;

    IRDecryptedMessage *decrypted = [bob.messenger decryptPreKeyMessage:forged error:&error];
    IRNegNeedTrue(decrypted == nil, @"a tampered IKB_A must not authenticate");

    NSData *after = IRNegStateBlob(established.session);
    IRNegNeed(after, @"§12.1 blob after the rejected retransmission");

    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
    result.error = error;

    return result;
}

#pragma mark - NEG-OPK-UNKNOWN / NEG-OPK-EXPIRED / NEG-OPK-NOFALLBACK — §5.3, §6.6, §15.4

/**
 The three rows about an `opk_id` that does not resolve, all landing on `ERR_UNKNOWN_PREKEY_ID`.

 `NEG-OPK-UNKNOWN` publishes a bundle advertising a one-time prekey the responder never retained.
 `NEG-OPK-EXPIRED` retains it with a local creation timestamp older than `OPK_MAX_AGE_S`, so §5.3's
 sweep deletes and zeroizes it at resolution time and an expired id resolves exactly as an unknown
 one does. That single implementation point is why -oneTimePreKeyRecordForId:atUnixSeconds:error:
 takes a clock while the signed-prekey resolver does not, and it is why this row carries an
 `inputs.now_s`: the deletion must be CAUSED by the injected instant, not waited for.

 `NEG-OPK-NOFALLBACK` is the same stimulus asserting the consequence §6.6 rule 2 cares about:
 **no 3-DH fallback occurred.** "There is no fallback to the 3-DH derivation. Rejecting rather than
 falling back is what converts OPK consumption into replay protection, and it forecloses a downgrade
 an implementer would otherwise be tempted to add." A port that fell back would open a session and
 return a plaintext, so the row is expressed as `session_count == 0` and a peer index that resolves
 to nothing — both of which a falling-back port fails.

 THE CREATION TIMESTAMP IS RESPONDER-LOCAL AND IS NOT ON THE WIRE (§5.3). The bundle's 36-byte OPK
 entry carries an id and a public key and nothing else, because the total-length rule
 `251 + 36 * opk_count` depends on that width. So the initiator cannot tell an expired prekey from a
 live one, which is exactly why the responder's rejection has to be unambiguous.
 */
static IRNegResult *IRNegScenarioOPKUnresolvable(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint64_t opkCreatedAtS = IRNegU64(inputs, @"opk_created_at_s");
    BOOL retained = (IRNegU32(inputs, @"opk_retained") != 0);

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               opkCreatedAtS,
                                               retained,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:published.bundleData
                                                                    error:&error];
    IRNegNeed(aliceSession, @"beginSession: %@", error);

    NSData *opener = [alice.messenger encrypt:IRNegData(inputs, @"plaintext")
                                    inSession:aliceSession
                                        error:&error];
    IRNegNeed(opener, @"encrypt: %@", error);

    IRDecryptedMessage *decrypted = [bob.messenger decryptPreKeyMessage:opener error:&error];
    IRNegNeedTrue(decrypted == nil, @"an unresolvable opk_id must not open a session");

    /* §6.6 rule 2, as an observable: nothing was built and nothing resolves to a session. A port
       that quietly degraded to the three-DH form would have both. */
    IRSession *byPeer =
        [bob.sessions sessionForPeerIdentityKeyPair:alice.identity.identityKeyPair];

    result.intermediates[@"opk_age_seconds"] = @(nowS - opkCreatedAtS);
    result.outputs[@"session_count"] = @(bob.sessions.sessionCount);
    result.outputs[@"peer_session_present"] = @(byPeer != nil);
    result.outputs[@"opk_count_after"] = @(bob.preKeys.oneTimePreKeyCount);
    result.error = error;

    return result;
}

#pragma mark - NEG-SPK-SURVIVES-RATCHET — §7.5, §19.1, §15.4

/**
 "Two initiators fetch one bundle with the same `spk_id`. Complete initiator 1's handshake and let B
 ratchet past it; then run initiator 2's handshake against that same `spk_id`." Initiator 2's
 handshake **succeeds**.

 THE ONLY VECTOR IN THE SUITE THAT DISTINGUISHES A PORT WHICH COPIES THE SIGNED-PREKEY PRIVATE FROM
 ONE WHICH ALIASES IT, and §15.4 says so: every other ratchet vector is single-session and passes
 either way.

 §7.5 calls aliasing "the single easiest way to brick a live deployment". §7.4 step 4 zeroizes
 `DHs.priv` unconditionally on B's FIRST ratchet of EVERY session — which is every session B accepts
 — so an alias destroys `SPK_B_priv` itself and breaks every concurrent and future handshake against
 that `spk_id` until rotation. AND THE FAILURE IS MISATTRIBUTED: X25519 clamping maps an all-zero
 scalar to 2^254, so DH1 and DH3 against the wiped key produce non-zero garbage, §4.4 check 3 does
 NOT fire, `spk_id` still resolves at §10.7 step 5, and B reports `ERR_AEAD_AUTH_FAILED` — the code
 §1.2 defines as an active man-in-the-middle. B misdiagnoses its own key destruction as an attack.

 THE SECOND BUNDLE IS SERIALIZED FROM THE RETAINED RECORD, NOT REPUBLISHED. Republishing under the
 same id would rotate the key material and the vector would prove nothing; §5.3's retention rule is
 what makes the record still be there, and -currentSignedPreKeyRecord is how the fixture reaches it.
 */
static IRNegResult *IRNegScenarioSPKSurvivesRatchet(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint32_t spkId = IRNegU32(inputs, @"spk_id");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegActor *carol = IRNegMakeActor(IRNegData(inputs, @"rng_C"), nowMs, @"C", &failure);
    IRNegNeed(carol, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               spkId,
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    /* One more leg, so B performs its own DH ratchet and §7.4 step 4 runs against the session copy
       of SPK_B_priv. Without this the vector would prove nothing: B's first receive alone does not
       reach step 4's zeroize on B's side. */
    NSData *answer = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                    inSession:link.initiatorSession
                                        error:&error];
    IRNegNeed(answer, @"encrypt answer: %@", error);

    IRDecryptedMessage *atBob =
        [bob.messenger decryptMessage:answer
              fromPeerIdentityKeyPair:alice.identity.identityKeyPair
                                error:&error];
    IRNegNeed(atBob, @"decrypt answer: %@", error);

    IRSignedPreKeyRecord *retainedRecord = [bob.preKeys signedPreKeyRecordForId:spkId error:&error];
    IRNegNeed(retainedRecord, @"§5.3 retention: spk_id %u must still resolve: %@",
              (unsigned)spkId, error);

    /* The session has ratcheted away from the signed prekey — so if the two were ever the same
       object, the store's copy is now zeros. */
    IRNegNeedTrue(![link.responderSession.state.DHs.publicKey
                       isEqualToX25519Public:retainedRecord.keyPair.publicKey],
                  @"B has not ratcheted past its signed prekey; the fixture proves nothing");

    IROneTimePreKeyRecord *secondOPK =
        [IROneTimePreKeyRecord generateWithOpkId:IRNegU32(inputs, @"opk_id_2")
                               createdAtUnixSecs:nowS
                                        provider:bob.provider
                                           error:&error];
    IRNegNeed(secondOPK, @"second one-time prekey: %@", error);
    IRNegNeedTrue([bob.preKeys storeOneTimePreKeyRecords:@[secondOPK] error:&error],
                  @"store second one-time prekey: %@", error);

    NSData *sameSpkBundle = [IRPreKeyBundle serializeWithIdentity:bob.identity.publicIdentity
                                              signedPreKeyRecord:retainedRecord
                                            oneTimePreKeyRecords:@[secondOPK]
                                                           error:&error];
    IRNegNeed(sameSpkBundle, @"bundle from the retained record: %@", error);

    IRSession *carolSession = [carol.messenger beginSessionWithBundleData:sameSpkBundle error:&error];
    IRNegNeed(carolSession, @"initiator 2 beginSession: %@", error);

    NSData *carolOpener = [carol.messenger encrypt:IRNegData(inputs, @"plaintext_4")
                                         inSession:carolSession
                                             error:&error];
    IRNegNeed(carolOpener, @"initiator 2 encrypt: %@", error);

    IRDecryptedMessage *atBobFromCarol = [bob.messenger decryptPreKeyMessage:carolOpener
                                                                       error:&error];
    IRNegNeed(atBobFromCarol,
              @"initiator 2 MUST still succeed — an aliasing port reports IRErrorAEADAuthFailed "
              @"here and misreads its own key destruction as an attack: %@", error);

    IRNegNeedTrue(atBobFromCarol.establishedNewSession,
                  @"initiator 2's handshake must open a session of its own");

    result.intermediates[@"SPK_pub"] = IRVectorHex(retainedRecord.keyPair.publicKey.data);
    result.intermediates[@"B_DHs_pub_after_ratchet"] =
        IRVectorHex(link.responderSession.state.DHs.publicKey.data);
    result.outputs[@"plaintext_initiator_2"] = IRVectorHex(atBobFromCarol.plaintext);
    result.outputs[@"session_count"] = @(bob.sessions.sessionCount);

    return result;
}

#pragma mark - NEG-SK-TAMPER — §6.3, §7.5, §15.4

/**
 "Flip one byte of `SK` **on one side only**; assert decryption fails" → `ERR_AEAD_AUTH_FAILED`.

 §15.4: the only test that would have caught defect 2. v3's
 `setupRatchetForSendingWithSharedKey:andDHReceiverKey:` NEVER READ its `sharedKey` argument while
 the receiving counterpart assigned it straight to `rootKey`. The two sides initialised
 asymmetrically and no message key was a function of the handshake at all — so tampering with the
 shared key changed nothing on the sending side, and every round-trip test still passed because both
 sides were consistently wrong in the same way.

 This vector is built at the ratchet layer rather than through IRMessenger because there is
 deliberately no production path that lets a caller supply a shared key: §7.5's initializers take a
 nominally typed, non-optional `IRRootKey` produced by §6.3, and IRMessenger derives it internally.
 One byte is flipped between B's derivation and B's ratchet initialization, which is the narrowest
 possible statement of "on one side only": both parties really did agree, and only the value that
 reaches the root chain differs.

 The failure MUST be the AEAD's. A wrong root key produces a wrong chain key, a wrong message key
 and a wrong `enc_key`, and Poly1305 is the first thing that notices — no earlier check can, because
 every public value on the wire is genuine.
 */
static IRNegResult *IRNegScenarioSharedKeyTampered(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint32_t skOffset = IRNegU32(inputs, @"sk_offset");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:published.bundleData
                                                   provider:alice.provider
                                                      error:&error];
    IRNegNeed(bundle, @"bundle: %@", error);

    IRX25519KeyPair *ephemeral = [alice.provider generateX25519KeyPairGuarded:NO error:&error];
    IRNegNeed(ephemeral, @"EK_A: %@", error);

    IRX3DHResult *initiator = [IRX3DH initiatorResultWithIdentity:alice.identity
                                                           bundle:bundle
                                                 ephemeralKeyPair:ephemeral
                                                   nowUnixSeconds:nowS
                                                         provider:alice.provider
                                                        retainIKM:NO
                                                            error:&error];
    IRNegNeed(initiator, @"X3DH initiator: %@", error);

    IRRatchetState *aliceState = [IRRatchet initiatorStateWithSharedKey:initiator.sharedKey
                                                  responderSignedPreKey:bundle.signedPreKey
                                                              sessionAD:initiator.sessionAD
                                                            handshakeId:initiator.handshakeId
                                                               prologue:initiator.prologue
                                                               provider:alice.provider
                                                                  error:&error];
    IRNegNeed(aliceState, @"§7.5 initiator: %@", error);
    [initiator zeroize];

    NSData *message = [IRRatchet encryptOnState:aliceState
                                       plaintext:IRNegData(inputs, @"plaintext")
                                     messageType:IRMessageTypePrekey
                               initiatorIdentity:alice.identity.identityKeyPair
                                 identityBinding:alice.identity.binding
                                        provider:alice.provider
                                           error:&error];
    IRNegNeed(message, @"§7.8 encrypt: %@", error);

    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:&error];
    IRNegNeed(header, @"§10.2 gate: %@", error);

    IRPublicIdentity *verified = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                               binding:header.identityBinding
                                                              provider:bob.provider
                                                                 error:&error];
    IRNegNeed(verified, @"§10.7 step 3: %@", error);

    IRX3DHResult *responder =
        [IRX3DH responderResultWithIdentity:bob.identity
                          initiatorIdentity:verified
                            ephemeralPublic:header.ephemeralPublic
                           signedPreKeyPair:published.signedPreKey.keyPair
                                      spkId:header.spkId
                                    opkFlag:header.opkFlag
                                      opkId:header.opkId
                          oneTimePreKeyPair:published.oneTimePreKey.keyPair
                                   provider:bob.provider
                                  retainIKM:NO
                                      error:&error];
    IRNegNeed(responder, @"X3DH responder: %@", error);

    NSData *agreedSK = IRNegSecretCopy(responder.sharedKey);

    NSData *tamperedBytes = IRNegFlipByte(agreedSK, skOffset, 0x01);
    IRNegNeed(tamperedBytes, @"sk_offset %u is outside a 32-byte SK", (unsigned)skOffset);

    IRRootKey *tamperedSK = [IRRootKey fromData:tamperedBytes guarded:NO error:&error];
    IRNegNeed(tamperedSK, @"tampered SK: %@", error);

    IRRatchetState *bobState = [IRRatchet responderStateWithSharedKey:tamperedSK
                                                     signedPreKeyPair:published.signedPreKey.keyPair
                                                            sessionAD:responder.sessionAD
                                                          handshakeId:responder.handshakeId
                                                                error:&error];
    IRNegNeed(bobState, @"§7.5 responder: %@", error);
    [responder zeroize];

    IRRatchetState *snapshot = [bobState snapshot];
    IRNegNeed(snapshot, @"§7.7 snapshot");

    NSData *plaintext = [IRRatchet decryptOnSnapshot:snapshot
                                              message:message
                                               header:header
                                               budget:[IRSkipBudget budget]
                                             atTimeMs:nowMs
                                             provider:bob.provider
                                                error:&error];
    IRNegNeedTrue(plaintext == nil, @"a tampered SK must not produce a plaintext");

    result.intermediates[@"SK_agreed"] = IRVectorHex(agreedSK);
    result.intermediates[@"SK_tampered"] = IRVectorHex(tamperedBytes);
    result.intermediates[@"message_len"] = @(message.length);
    result.error = error;

    [bobState zeroize];
    [aliceState zeroize];

    return result;
}

#pragma mark - NEG-ATOMIC — §7.7, §15.4

/**
 "Inject a header-valid, tag-invalid message with a novel ratchet key; assert the **next legitimate
 message still decrypts**." Session survives.

 §15.4: THE ONLY ROW THAT CATCHES THE DESYNCHRONISATION DoS, and the reason is that the damage is
 state corruption rather than a wrong plaintext — no round-trip test can see it. v3's `decryptData:`
 called `addSkippedMessages:` at `IRDoubleRatchetService.m:178` and `:188`, `performDHRatchet:` at
 `:184`, advanced `chainKeyReceiver` at `:196` and incremented `numberOfReceivedMessages` at `:199`,
 and ONLY THEN called `aeDecryptData:` at `:203`, which may fail. An attacker who can inject a
 well-formed but unauthenticated message carrying a novel ratchet key therefore forces the receiver's
 ratchet forward and PERMANENTLY DESYNCHRONISES a live session — unauthenticated, and free.

 THE NOVEL RATCHET KEY IS WHAT MAKES THE FORGERY EXPENSIVE TO A BROKEN PORT. A message whose `DHs`
 the receiver has already seen does not reach §7.9 phase 3b; splicing a key the receiver has never
 seen does, so a port without §7.7's snapshot performs a real DH ratchet — two `KDF_RK` steps, a new
 `DHs` pair, a discarded `CKr` — before Poly1305 says no. The spliced key is a valid X25519 public
 (§4.4 checks 1–2 pass) and is not the receiver's own (§10.1 check 8 passes), so every structural
 check the gate can make succeeds and the AEAD is the unique failure point.

 The vector then asserts BOTH halves: the state blob is byte-identical afterwards (§12.1 is
 byte-normative so that this is expressible at all), and the genuine message — held back until after
 the blob comparison — still decrypts.
 */
static IRNegResult *IRNegScenarioAtomic(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    NSData *genuine = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                     inSession:link.initiatorSession
                                         error:&error];
    IRNegNeed(genuine, @"encrypt: %@", error);
    IRNegNeedTrue([IRMessenger messageTypeOfMessage:genuine error:NULL] == IRMessageTypeNormal,
                  @"§11.3: A sends type 0x01 once it has decrypted a message from B");

    NSData *foreignRatchetKey = IRNegData(inputs, @"forged_DHs_pub");
    IRNegNeedTrue([IRX25519Public dataIsValidEncoding:foreignRatchetKey],
                  @"forged_DHs_pub must pass §4.4 checks 1–2, or the gate rejects it first");

    NSData *forged = IRNegSplice(genuine, (NSUInteger)kIROffType01DHs, foreignRatchetKey);
    IRNegNeed(forged, @"DHs_pub does not fit at offset %d", (int)kIROffType01DHs);

    NSDictionary *fixture = IRNegSessionFixture(link.responderSession);
    IRNegNeed(fixture, @"§12.1 blob before the forgery");
    result.sessions[@"S1"] = fixture;

    IRDecryptedMessage *rejected = [bob.messenger decryptMessage:forged
                                                       inSession:link.responderSession
                                                           error:&error];
    IRNegNeedTrue(rejected == nil, @"a forged tag must not produce a plaintext");

    NSData *after = IRNegStateBlob(link.responderSession);
    IRNegNeed(after, @"§12.1 blob after the forgery");

    /* §7.7's whole point, and the half a broken port fails: the session is still usable. */
    NSError *recoveryError = nil;
    IRDecryptedMessage *recovered = [bob.messenger decryptMessage:genuine
                                                        inSession:link.responderSession
                                                            error:&recoveryError];
    IRNegNeed(recovered,
              @"the next legitimate message MUST still decrypt — the forgery desynchronised the "
              @"session: %@", recoveryError);

    result.selectedSession = @"S1";
    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
    result.outputs[@"recovery_plaintext"] = IRVectorHex(recovered.plaintext);
    result.error = error;

    return result;
}

#pragma mark - NEG-SKIP-RETAIN — §7.6, §15.4

/**
 "A skipped-key message with a corrupted tag; assert the key is **retained** and a later correct
 delivery succeeds."

 §7.6 is normative on the ordering: "A stored key MUST be removed ONLY after the AEAD decryption
 using it SUCCEEDS." v3 called `removeObjectForKey:` at `IRDoubleRatchetService.m:168` and
 `aeDecryptData:` at `:170` — in that order — so a message that failed to decrypt PERMANENTLY
 DESTROYED the only copy of its key and became unrecoverable. One corrupted byte in transit, one
 message lost forever.

 The fixture delivers A's second message first, which is what makes B derive and store the key for
 the first (§7.9 phase 3c). The corrupted delivery then takes §7.9 PHASE 3a — the stored-key path,
 which returns without a DH ratchet and without advancing `Nr` — so the only state that could change
 is the skipped store itself. That is why the blob comparison is the assertion: a port that removed
 the entry before the AEAD has a blob one 76-byte entry shorter, and §12.1's exact-length rule makes
 that visible rather than subtle.
 */
static IRNegResult *IRNegScenarioSkipRetain(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    NSData *first = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                   inSession:link.initiatorSession
                                       error:&error];
    IRNegNeed(first, @"encrypt N=0: %@", error);

    NSData *second = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_4")
                                    inSession:link.initiatorSession
                                        error:&error];
    IRNegNeed(second, @"encrypt N=1: %@", error);

    /* Out of order, so B derives and STORES the key for N = 0 (§7.9 phase 3c) rather than using it. */
    IRDecryptedMessage *outOfOrder = [bob.messenger decryptMessage:second
                                                         inSession:link.responderSession
                                                             error:&error];
    IRNegNeed(outOfOrder, @"the out-of-order delivery must succeed: %@", error);
    IRNegNeedTrue(link.responderSession.state.skipped.count == 1,
                  @"exactly one skipped key should be held, got %lu",
                  (unsigned long)link.responderSession.state.skipped.count);

    /* Inside the ciphertext, past the 56-byte type `0x01` header — so the header still gates clean
       and the stored key is still selected by `hdr.dh ‖ uint32_be(hdr.N)`. */
    NSData *corrupted = IRNegFlipByte(first,
                                      (NSUInteger)kIROffType01Ciphertext +
                                          IRNegU32(inputs, @"ciphertext_offset"),
                                      0x01);
    IRNegNeed(corrupted, @"ciphertext_offset is outside the message");

    NSDictionary *fixture = IRNegSessionFixture(link.responderSession);
    IRNegNeed(fixture, @"§12.1 blob before the corrupted delivery");
    result.sessions[@"S1"] = fixture;

    IRDecryptedMessage *rejected = [bob.messenger decryptMessage:corrupted
                                                       inSession:link.responderSession
                                                           error:&error];
    IRNegNeedTrue(rejected == nil, @"a corrupted tag must not produce a plaintext");

    NSData *after = IRNegStateBlob(link.responderSession);
    IRNegNeed(after, @"§12.1 blob after the corrupted delivery");

    NSError *recoveryError = nil;
    IRDecryptedMessage *recovered = [bob.messenger decryptMessage:first
                                                        inSession:link.responderSession
                                                            error:&recoveryError];
    IRNegNeed(recovered,
              @"the stored key MUST have been retained so the correct delivery still works: %@",
              recoveryError);

    result.selectedSession = @"S1";
    result.intermediates[@"skipped_count_before"] = @1;
    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
    result.outputs[@"recovery_plaintext"] = IRVectorHex(recovered.plaintext);
    result.outputs[@"skipped_count_after_recovery"] =
        @(link.responderSession.state.skipped.count);
    result.error = error;

    return result;
}

#pragma mark - NEG-COUNTER / NEG-SKIP-LIMIT — §10.1 checks 9–10, §7.6, §15.4

/**
 Two rows that differ only in the value written into §9.1's `N` slot at offset 36.

 `NEG-COUNTER` writes `0x80000000` — one above `MAX_COUNTER` — and is rejected by §10.1's ordered
 gate before any secret is touched, with `ERR_COUNTER_OVERFLOW`. The bound exists because `N` and
 `PN` are unsigned on the wire and signed on the JVM: a port reading them into a Java `int` sees
 `0x80000000` as -2147483648, and `until - state.Nr` in §7.6 then becomes an enormous positive
 `long` or a negative loop bound depending on where the widening happens.

 `NEG-SKIP-LIMIT` writes `Nr + 1001`, one past `MAX_SKIP_PER_MESSAGE`, and is rejected inside §7.9
 phase 3c by SkipMessageKeys with `ERR_TOO_MANY_SKIPPED`. §7.6 requires the state be LEFT UNMODIFIED
 on that path — the budget is checked against the whole span before the first key is derived, never
 per key — so this row also carries the blob comparison.

 BOTH FORGERIES BREAK THE TAG, AND BOTH MUST FAIL BEFORE IT. `N` is inside the AD (§8.5), so a port
 that evaluated the AEAD first would answer either row with `ERR_AEAD_AUTH_FAILED`, which is the
 wrong code and, for the skip bound, the wrong ORDER: §7.9 phase 3c runs SkipMessageKeys BEFORE the
 AEAD check precisely so that a forged counter cannot buy an attacker 1000 HMAC operations per
 message it did not have to authenticate (§17.6).
 */
static IRNegResult *IRNegScenarioForgedCounter(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint32_t forgedN = IRNegU32(inputs, @"forged_N");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    NSData *genuine = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                     inSession:link.initiatorSession
                                         error:&error];
    IRNegNeed(genuine, @"encrypt: %@", error);

    NSData *forged = IRNegSetUInt32(genuine, (NSUInteger)kIROffType01N, forgedN);
    IRNegNeed(forged, @"N does not fit at offset %d", (int)kIROffType01N);

    NSDictionary *fixture = IRNegSessionFixture(link.responderSession);
    IRNegNeed(fixture, @"§12.1 blob before the forged counter");
    result.sessions[@"S1"] = fixture;

    IRDecryptedMessage *rejected = [bob.messenger decryptMessage:forged
                                                       inSession:link.responderSession
                                                           error:&error];
    IRNegNeedTrue(rejected == nil, @"a forged N must not produce a plaintext");

    NSData *after = IRNegStateBlob(link.responderSession);
    IRNegNeed(after, @"§12.1 blob after the forged counter");

    result.selectedSession = @"S1";
    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
    result.outputs[@"skipped_count_after"] = @(link.responderSession.state.skipped.count);
    result.error = error;

    return result;
}

#pragma mark - NEG-REPLAY — §7.9 phase 3c, §11.4, §15.4

/**
 "`N < Nr` with no stored skipped key" → `ERR_REPLAY`.

 §7.9 is emphatic that this is an EXPLICIT CODE and not a silent AEAD failure, and §11.4's table
 makes it the first row of replay handling. The distinction matters at the API boundary rather than
 to security: both fail closed, but a host that cannot tell "you have already seen this" from "this
 did not authenticate" cannot deduplicate a retransmitting transport without a decryption attempt.

 §10.5's information-leakage rule is the counterweight and is why this code exists for LOCAL
 diagnosability only: telling a peer which of the two occurred tells an attacker whether a guessed
 counter sat in the skipped-key store.

 The replayed message is byte-identical to one already delivered, so `hdr.dh` is already `s.DHr`
 (no ratchet), `hdr.N` is 0 while `s.Nr` is 1, and the skipped store is empty because the message
 was consumed in order. Phase 3a misses, phase 3b is skipped, phase 3c fires.
 */
static IRNegResult *IRNegScenarioReplay(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    NSData *message = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                     inSession:link.initiatorSession
                                         error:&error];
    IRNegNeed(message, @"encrypt: %@", error);

    IRDecryptedMessage *firstDelivery = [bob.messenger decryptMessage:message
                                                            inSession:link.responderSession
                                                                error:&error];
    IRNegNeed(firstDelivery, @"the first delivery must succeed: %@", error);

    NSDictionary *fixture = IRNegSessionFixture(link.responderSession);
    IRNegNeed(fixture, @"§12.1 blob before the replay");
    result.sessions[@"S1"] = fixture;

    IRDecryptedMessage *replayed = [bob.messenger decryptMessage:message
                                                       inSession:link.responderSession
                                                           error:&error];
    IRNegNeedTrue(replayed == nil, @"a replayed message must not be delivered twice");

    NSData *after = IRNegStateBlob(link.responderSession);
    IRNegNeed(after, @"§12.1 blob after the replay");

    result.selectedSession = @"S1";
    result.intermediates[@"first_plaintext"] = IRVectorHex(firstDelivery.plaintext);
    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
    result.error = error;

    return result;
}

#pragma mark - NEG-NO-SESSION — §10.1 check 6, §11.5 rule 1, §13.4 clause 5, §15.4

/**
 "Type `0x01` submitted with no session handle, and again with a handle that does not resolve
 (§11.5 rule 1)" → `ERR_NO_SESSION`, both times.

 THE ABSENT HANDLE IS THE ONE ARGUMENT §13.4 DOES NOT GOVERN, and clause 5 says so explicitly. Every
 other `_Nonnull` parameter answers a null with a fail-fast trap that has no error code; this one is
 `_Nullable` in every port because §10.1 check 6 already specifies it, gives it code 7120, and this
 row requires it. A `_Nonnull` handle guarded by a trap would make `ERR_NO_SESSION` unreachable from
 Swift and contradict a required vector.

 THE SECOND CASE IS NOT A DUPLICATE OF THE FIRST. A torn-down session is a handle the host STILL
 HOLDS that names nothing live — §11.1.1's collapse is the mechanism that manufactures exactly that
 — and §11.6 requires every operation on one to fail this way. A port that checked only for nil
 would pass the first case and hand a torn-down, zeroized state to the ratchet on the second.

 The by-peer form is asserted too, since a torn-down session must leave the §11.1 peer index as
 well; a port that removed the handshake_id index and forgot the other would resurrect the session
 through the entry point §11.5 rule 2 exists for.

 CHECK 6 SITS AFTER THE GATE, NOT BEFORE IT. That ordering is why this vector's stimulus is a
 WELL-FORMED message: an implementation that resolved the session first would report every malformed
 input as `ERR_NO_SESSION` and turn the code into an oracle for which peers a receiver holds sessions
 with. `NEG-TRUNCATED` and `NEG-VERSION` pin the other side of that boundary.
 */
static IRNegResult *IRNegScenarioNoSession(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link = IRNegEstablishLink(alice,
                                         bob,
                                         published.bundleData,
                                         IRNegData(inputs, @"plaintext"),
                                         IRNegData(inputs, @"plaintext_2"),
                                         &failure);
    IRNegNeed(link, @"%@", failure);

    NSData *message = [alice.messenger encrypt:IRNegData(inputs, @"plaintext_3")
                                     inSession:link.initiatorSession
                                         error:&error];
    IRNegNeed(message, @"encrypt: %@", error);

    /* Case one — no handle at all. */
    NSError *nilHandleError = nil;
    IRDecryptedMessage *withoutHandle = [bob.messenger decryptMessage:message
                                                            inSession:nil
                                                                error:&nilHandleError];
    IRNegNeedTrue(withoutHandle == nil, @"a message with no handle must not be delivered");
    IRNegNeedTrue(nilHandleError.code == IRErrorNoSession,
                  @"§13.4 clause 5: an absent handle is ERR_NO_SESSION, never a trap and never "
                  @"ERR_STATE_CORRUPT; got %ld", (long)nilHandleError.code);

    /* Case two — a handle the host still holds that no longer resolves. */
    IRNegNeedTrue([bob.sessions tearDownSession:link.responderSession atTimeMs:nowMs error:&error],
                  @"tearDown: %@", error);

    error = nil;
    IRDecryptedMessage *withStaleHandle = [bob.messenger decryptMessage:message
                                                              inSession:link.responderSession
                                                                  error:&error];
    IRNegNeedTrue(withStaleHandle == nil, @"a torn-down handle must not resolve");

    NSError *byPeerError = nil;
    IRDecryptedMessage *byPeer =
        [bob.messenger decryptMessage:message
              fromPeerIdentityKeyPair:alice.identity.identityKeyPair
                                error:&byPeerError];
    IRNegNeedTrue(byPeer == nil, @"the peer index must not resurrect a torn-down session");
    IRNegNeedTrue(byPeerError.code == IRErrorNoSession,
                  @"the by-peer form must answer identically; got %ld", (long)byPeerError.code);

    result.intermediates[@"message_len"] = @(message.length);
    result.intermediates[@"session_count_after_teardown"] = @(bob.sessions.sessionCount);
    result.outputs[@"session_torn_down"] = @(link.responderSession.isTornDown);
    result.error = error;

    return result;
}

#pragma mark - NEG-DEMUX-WRONG-SESSION / NEG-DEMUX-WRONG-PEER — §11.5, §19.9, §15.4

/**
 The two rows that make a forbidden BEHAVIOUR observable rather than a forbidden VALUE.

 §15.4, restated by the gap work around a TWO-PEER fixture: receiver B holds two live sessions with
 two different peers, `S1` with `P1` and `S2` with `P2`, distinct identity pairs, both established
 through §10.7 against the SAME `spk_id` with distinct `opk_id`s. Two live sessions is
 §11.1.1-conformant because the bound is PER PEER — the vector says so explicitly, because a port
 that read it as a global cap cannot build the fixture at all, and that misreading is exactly what
 §19.9 was written to close.

 THE STIMULUS WOULD DECRYPT SOMEWHERE. `M` is the next legitimate type `0x01` message of `P1`'s
 current sending chain, offered against `S2`. In a single-peer setup "did not retry" is satisfied
 vacuously and a trial-decrypting port passes; here a port that retries returns `P1`'s plaintext
 where the vector requires an error, and a port that retries and then SUPPRESSES the result is caught
 by an advanced `Nr` and a rewritten `CKr` in `S1`'s blob.

 THE AEAD MUST BE THE UNIQUE FAILURE POINT, and §15.4 makes that a construction requirement rather
 than a hope: under `S2` every §10.1 check and every §7.9 phase-3 step has to succeed up to and
 including the AEAD call, or a port may legitimately return `ERR_TOO_MANY_SKIPPED` or
 `ERR_SMALL_ORDER_KEY` and the vector arbitrates nothing. It holds here because `M`'s `DHs` is novel
 to `S2` but is not `S2`'s own key (check 8 passes), and because `M`'s `PN` is 1 while `S2`'s `Nr` is
 already 1 and its `N` is 0 — so both SkipMessageKeys calls need zero derivations and the budget is
 untouched.

 `NEG-DEMUX-WRONG-PEER` is the same fixture and the same `M` through `decrypt_by_peer`. That entry
 point's signature is the one that invites a loop over the peer index, and it is the only place a
 "helpful" retry is natural to write; the handle-taking form structurally has one session to try.

 The recovery delivery at the end is §15.3's `DEMUX-NO-TRIAL`, and it catches the last shape: a port
 that trial-decrypted, COMMITTED, and reported the failure anyway would answer it with `ERR_REPLAY`.
 */
static IRNegResult *IRNegScenarioDemux(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint32_t spkId = IRNegU32(inputs, @"spk_id");
    BOOL byPeer = (IRNegU32(inputs, @"select_by_peer") != 0);

    IRNegActor *p1 = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(p1, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegActor *p2 = IRNegMakeActor(IRNegData(inputs, @"rng_C"), nowMs, @"C", &failure);
    IRNegNeed(p2, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               spkId,
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRNegLink *link1 = IRNegEstablishLink(p1,
                                          bob,
                                          published.bundleData,
                                          IRNegData(inputs, @"plaintext"),
                                          IRNegData(inputs, @"plaintext_2"),
                                          &failure);
    IRNegNeed(link1, @"P1: %@", failure);

    /* The SAME spk_id with a DISTINCT opk_id, per §15.4. Re-publishing would rotate the signed
       prekey and the two sessions would no longer share it. */
    IROneTimePreKeyRecord *secondOPK =
        [IROneTimePreKeyRecord generateWithOpkId:IRNegU32(inputs, @"opk_id_2")
                               createdAtUnixSecs:nowS
                                        provider:bob.provider
                                           error:&error];
    IRNegNeed(secondOPK, @"second one-time prekey: %@", error);
    IRNegNeedTrue([bob.preKeys storeOneTimePreKeyRecords:@[secondOPK] error:&error],
                  @"store second one-time prekey: %@", error);

    IRSignedPreKeyRecord *retainedRecord = [bob.preKeys signedPreKeyRecordForId:spkId error:&error];
    IRNegNeed(retainedRecord, @"spk_id %u must still resolve: %@", (unsigned)spkId, error);

    NSData *secondBundle = [IRPreKeyBundle serializeWithIdentity:bob.identity.publicIdentity
                                             signedPreKeyRecord:retainedRecord
                                           oneTimePreKeyRecords:@[secondOPK]
                                                          error:&error];
    IRNegNeed(secondBundle, @"second bundle: %@", error);

    IRNegLink *link2 = IRNegEstablishLink(p2,
                                          bob,
                                          secondBundle,
                                          IRNegData(inputs, @"plaintext_3"),
                                          IRNegData(inputs, @"plaintext_4"),
                                          &failure);
    IRNegNeed(link2, @"P2: %@", failure);

    IRNegNeedTrue(bob.sessions.sessionCount == 2,
                  @"§11.1.1's bound is per peer: B must hold two live sessions, got %lu",
                  (unsigned long)bob.sessions.sessionCount);
    IRNegNeedTrue(![link1.responderSession.handshakeId
                       isEqualToData:link2.responderSession.handshakeId],
                  @"the two fixtures must be distinct handshakes");

    NSData *stimulus = [p1.messenger encrypt:IRNegData(inputs, @"plaintext_5")
                                   inSession:link1.initiatorSession
                                       error:&error];
    IRNegNeed(stimulus, @"P1 encrypt: %@", error);
    IRNegNeedTrue([IRMessenger messageTypeOfMessage:stimulus error:NULL] == IRMessageTypeNormal,
                  @"the stimulus must be a type 0x01 message");

    NSDictionary *fixture1 = IRNegSessionFixture(link1.responderSession);
    IRNegNeed(fixture1, @"§12.1 blob for S1");
    NSDictionary *fixture2 = IRNegSessionFixture(link2.responderSession);
    IRNegNeed(fixture2, @"§12.1 blob for S2");

    result.sessions[@"S1"] = fixture1;
    result.sessions[@"S2"] = fixture2;
    result.selectedSession = @"S2";

    IRDecryptedMessage *misrouted = nil;
    if (byPeer) {
        misrouted = [bob.messenger decryptMessage:stimulus
                          fromPeerIdentityKeyPair:p2.identity.identityKeyPair
                                            error:&error];
    } else {
        misrouted = [bob.messenger decryptMessage:stimulus
                                        inSession:link2.responderSession
                                            error:&error];
    }
    IRNegNeedTrue(misrouted == nil,
                  @"§11.5 rule 3: a message that does not decrypt under the SELECTED session MUST "
                  @"NOT be retried against another, even one where it would succeed");

    NSData *after1 = IRNegStateBlob(link1.responderSession);
    IRNegNeed(after1, @"§12.1 blob for S1 after the misrouted delivery");
    NSData *after2 = IRNegStateBlob(link2.responderSession);
    IRNegNeed(after2, @"§12.1 blob for S2 after the misrouted delivery");

    /* §15.3 DEMUX-NO-TRIAL — the message must still be there to collect. A port that trial-
       decrypted and committed answers this with ERR_REPLAY. */
    NSError *recoveryError = nil;
    IRDecryptedMessage *recovered = [bob.messenger decryptMessage:stimulus
                                                        inSession:link1.responderSession
                                                            error:&recoveryError];
    IRNegNeed(recovered,
              @"DEMUX-NO-TRIAL: the message MUST still decrypt under its own session: %@",
              recoveryError);

    result.intermediates[@"stimulus"] = IRVectorHex(stimulus);
    result.intermediates[@"session_count"] = @2;
    result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after1);
    result.outputs[@"sessions.S2.state_blob_after"] = IRVectorHex(after2);
    result.outputs[@"recovery_plaintext"] = IRVectorHex(recovered.plaintext);
    result.error = error;

    return result;
}

#pragma mark - NEG-HANDSHAKE-TOMBSTONE — §10.7 step 4, §11.4, §15.4

/**
 "Type `0x02` whose `handshake_id` matches a tombstone inside `HANDSHAKE_CACHE_MS`, with an injected
 `inputs.now_ms` (§10.7 step 4)" → `ERR_REPLAY`.

 §11.4 requires a tombstone whenever a session is torn down FOR ANY REASON — eviction, explicit
 deletion, or §11.1.1's collapse — and §10.7 step 4 enforces it rather than leaving it implied. That
 is what bounds §17.3's no-OPK handshake replay to seven days by mechanism, and what stops a replayed
 handshake from displacing a live session at step 14.

 THE ORDERING IS THE POINT, AND IT IS OBSERVABLE. Step 4 runs BEFORE step 5's `spk_id` resolution and
 before step 7's `opk_id` resolution — and the one-time prekey this handshake named was consumed and
 zeroized by step 14a when the message was first delivered. So a port that resolved the prekeys first
 answers this input with `ERR_UNKNOWN_PREKEY_ID`, which is a different code for identical bytes.
 Every other detail of the message is genuine, so nothing but the ordering can distinguish the two.

 The teardown is explicit here, which is what §15.4 distinguishes from `NEG-COLLAPSE-LOSER-REPLAY`:
 that row's tombstone comes from a collapse of a session that was never committed to the store at
 all, and neither row is reachable from the other.
 */
static IRNegResult *IRNegScenarioHandshakeTombstone(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    uint64_t tearDownAtMs = IRNegU64(inputs, @"tear_down_at_ms");

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    IRNegPublication *published = IRNegPublish(bob,
                                               IRNegU32(inputs, @"spk_id"),
                                               IRNegU32(inputs, @"opk_id"),
                                               IRNegU64(inputs, @"not_before"),
                                               IRNegU64(inputs, @"not_after"),
                                               nowS,
                                               YES,
                                               &failure);
    IRNegNeed(published, @"%@", failure);

    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:published.bundleData
                                                                    error:&error];
    IRNegNeed(aliceSession, @"beginSession: %@", error);

    NSData *opener = [alice.messenger encrypt:IRNegData(inputs, @"plaintext")
                                    inSession:aliceSession
                                        error:&error];
    IRNegNeed(opener, @"encrypt: %@", error);

    IRDecryptedMessage *established = [bob.messenger decryptPreKeyMessage:opener error:&error];
    IRNegNeed(established, @"the first delivery must succeed: %@", error);
    IRNegNeedTrue(established.establishedNewSession, @"the first delivery must open the session");

    NSData *handshakeId = [established.session.handshakeId copy];

    IRNegNeedTrue([bob.sessions tearDownSession:established.session
                                       atTimeMs:tearDownAtMs
                                          error:&error],
                  @"tearDown: %@", error);
    IRNegNeedTrue([bob.sessions hasTombstoneForHandshakeId:handshakeId atTimeMs:nowMs],
                  @"§11.4: tearing a session down MUST leave a tombstone");
    IRNegNeedTrue(bob.preKeys.oneTimePreKeyCount == 0,
                  @"§10.7 step 14a: the one-time prekey must already be gone, so only the "
                  @"tombstone can distinguish the two codes");

    IRDecryptedMessage *replayed = [bob.messenger decryptPreKeyMessage:opener error:&error];
    IRNegNeedTrue(replayed == nil, @"a tombstoned handshake must not be re-established");

    /* Every `intermediates` and `outputs` value in this file is either a hex STRING or a JSON
       NUMBER, never a uint64 decimal string: §15.2's uint64 rule names six protocol fields and this
       is not one of them, and a decimal string here would be indistinguishable from hex to the
       type-dispatching checker below. */
    result.intermediates[@"handshake_id"] = IRVectorHex(handshakeId);
    result.intermediates[@"tombstone_present"] = @YES;
    result.outputs[@"session_count"] = @(bob.sessions.sessionCount);
    result.error = error;

    return result;
}

#pragma mark - NEG-COLLAPSE-LOSER-REPLAY / NEG-COLLAPSE-LOSER-HANDLE — §10.7 step 14, §11.1.1, §11.6

/**
 The two rows about §11.1.1's collapse, built on one concurrent-initiation fixture.

 BOTH PARTIES INITIATE AT THE SAME TIME, which is routine on a mobile transport and is why the
 invariant is not automatic: A then holds a session in which it is initiator and another in which it
 is responder, both with B, with distinct `handshake_id`s — and B holds the mirror image. §11.1.1
 collapses each pair by comparing the two ids as 64-byte UNSIGNED BIG-ENDIAN integers and keeping the
 GREATER, a pure function of public data both sides already hold, so both converge on the same
 survivor with no further message. ("Newest wins" was rejected because each side observes a different
 arrival order, so it is not a function and the two sides can diverge permanently.)

 WHICH SIDE IS WHICH IS DECIDED BY THE FIXTURE, NOT ASSUMED BY THE VECTOR. The generator computes the
 comparison with IRCompareHandshakeIds and selects the receiver the row needs — the one whose INCOMING
 handshake loses, for `NEG-COLLAPSE-LOSER-REPLAY`; the one whose incoming WINS, for
 `NEG-COLLAPSE-LOSER-HANDLE`. The scripts are fixed, so the answer is fixed too, and it is frozen as
 an intermediate rather than left implicit.

 `NEG-COLLAPSE-LOSER-REPLAY` — re-submit the identical type `0x02` whose session lost, inside
 `HANDSHAKE_CACHE_MS`. THIS IS WHAT STOPS §10.7 STEP 14d's DELIVERY RULE FROM BECOMING A
 PLAINTEXT-HARVESTING ORACLE. The first arrival IS delivered — it cleared `IKB_A`, four DHs, the
 transcript binding and Poly1305, and §19.7 records at length why dropping it would hand a purely
 network-level attacker a silent, permanent message-suppression primitive. Delivery is once per
 HANDSHAKE, never once per arrival, and step 14c's tombstone on a session that was never persisted is
 the mechanism. A port that delivers but forgets that tombstone fails here and nowhere else.

 `NEG-COLLAPSE-LOSER-HANDLE` — a valid type `0x01` against the handle for the session that LOST.
 §11.6 makes `torn_down_handshake_id` the observable, because a handle is an opaque object with no
 byte representation and a bare "a collapse occurred" boolean is true on both branches while the
 caller's obligation is opposite on each. This row is taken on the WINNING side, since that is the
 only branch where the loser is a handle the caller actually holds. Any well-formed type `0x01` will
 do: §10.1 check 6 fires before the message is looked at, which is the point.
 */
static IRNegResult *IRNegScenarioCollapse(NSDictionary *inputs) {
    NSError *error = nil;
    NSString *failure = nil;
    IRNegResult *result = [IRNegResult result];

    uint64_t nowS = IRNegU64(inputs, @"now_s");
    uint64_t nowMs = IRNegU64(inputs, @"now_ms");
    BOOL wantWinnerSide = [IRNegString(inputs, @"collapse_branch") isEqualToString:@"winner"];

    IRNegActor *alice = IRNegMakeActor(IRNegData(inputs, @"rng_A"), nowMs, @"A", &failure);
    IRNegNeed(alice, @"%@", failure);

    IRNegActor *bob = IRNegMakeActor(IRNegData(inputs, @"rng_B"), nowMs, @"B", &failure);
    IRNegNeed(bob, @"%@", failure);

    /* Both sides publish, because both sides initiate. */
    IRNegPublication *alicePublished = IRNegPublish(alice,
                                                    IRNegU32(inputs, @"spk_id"),
                                                    IRNegU32(inputs, @"opk_id"),
                                                    IRNegU64(inputs, @"not_before"),
                                                    IRNegU64(inputs, @"not_after"),
                                                    nowS,
                                                    YES,
                                                    &failure);
    IRNegNeed(alicePublished, @"A publishes: %@", failure);

    IRNegPublication *bobPublished = IRNegPublish(bob,
                                                  IRNegU32(inputs, @"spk_id"),
                                                  IRNegU32(inputs, @"opk_id_2"),
                                                  IRNegU64(inputs, @"not_before"),
                                                  IRNegU64(inputs, @"not_after"),
                                                  nowS,
                                                  YES,
                                                  &failure);
    IRNegNeed(bobPublished, @"B publishes: %@", failure);

    IRSession *aliceOwn = [alice.messenger beginSessionWithBundleData:bobPublished.bundleData
                                                                error:&error];
    IRNegNeed(aliceOwn, @"A beginSession: %@", error);

    NSData *aliceOpener = [alice.messenger encrypt:IRNegData(inputs, @"plaintext")
                                         inSession:aliceOwn
                                             error:&error];
    IRNegNeed(aliceOpener, @"A encrypt: %@", error);

    IRSession *bobOwn = [bob.messenger beginSessionWithBundleData:alicePublished.bundleData
                                                            error:&error];
    IRNegNeed(bobOwn, @"B beginSession: %@", error);

    NSData *bobOpener = [bob.messenger encrypt:IRNegData(inputs, @"plaintext_2")
                                     inSession:bobOwn
                                         error:&error];
    IRNegNeed(bobOpener, @"B encrypt: %@", error);

    /* §11.1.1's comparison, made here so the vector states which branch it froze rather than
       discovering it. `memcmp` is correct only because C compares as unsigned char; on the JVM
       `byte` is signed and the naive loop reads 0x80 as -128 and picks the wrong survivor — and
       because both sides must converge on the SAME survivor from the same public data, one port
       getting this backwards diverges the two permanently rather than failing loudly. */
    NSComparisonResult order = NSOrderedSame;
    IRNegNeedTrue(IRCompareHandshakeIds(aliceOwn.handshakeId, bobOwn.handshakeId, &order),
                  @"§11.1.1 comparison failed on two 64-byte ids");
    IRNegNeedTrue(order != NSOrderedSame, @"two distinct handshakes must not compare equal");

    /* When B receives A's opener the INCOMING handshake is A's. It wins iff A's id is the greater. */
    BOOL incomingWinsAtBob = (order == NSOrderedDescending);
    BOOL receiveAtBob = (wantWinnerSide == incomingWinsAtBob);

    IRNegActor *receiver = receiveAtBob ? bob : alice;
    IRNegActor *sender = receiveAtBob ? alice : bob;
    NSData *stimulus = receiveAtBob ? aliceOpener : bobOpener;
    IRSession *receiverOwn = receiveAtBob ? bobOwn : aliceOwn;

    NSDictionary *fixture = IRNegSessionFixture(receiverOwn);
    IRNegNeed(fixture, @"§12.1 blob for the receiver's own session");
    result.sessions[@"S1"] = fixture;
    result.selectedSession = @"S1";

    IRDecryptedMessage *delivered = [receiver.messenger decryptPreKeyMessage:stimulus error:&error];
    IRNegNeed(delivered,
              @"§10.7 step 14d: the plaintext MUST be delivered on BOTH collapse branches: %@",
              error);
    IRNegNeedTrue(delivered.establishedNewSession == wantWinnerSide,
                  @"§11.6: established_new_session is true iff the session this call built is the "
                  @"survivor; expected %@", wantWinnerSide ? @"YES" : @"NO");
    IRNegNeedTrue(delivered.tornDownHandshakeId != nil,
                  @"§11.1.1: a collapse occurred, so an id was destroyed");

    result.intermediates[@"receiver_is_B"] = @(receiveAtBob);
    result.intermediates[@"incoming_wins"] = @(wantWinnerSide);
    result.intermediates[@"torn_down_handshake_id"] = IRVectorHex(delivered.tornDownHandshakeId);
    result.outputs[@"delivered_plaintext"] = IRVectorHex(delivered.plaintext);
    result.outputs[@"established_new_session"] = @(delivered.establishedNewSession);

    if (!wantWinnerSide) {
        /* NEG-COLLAPSE-LOSER-REPLAY. The session this message built lost and was tombstoned without
           ever being persisted (§11.4), so the retransmission dies at §10.7 step 4. §10.7 step 14c
           also requires the SURVIVOR to be untouched by the losing message: no RK, CKs, CKr, Ns, Nr,
           PN, DHr, skipped key or SESSION_AD may be merged into it, and send_counter does not
           advance. The blob comparison is that requirement, byte for byte. */
        IRNegNeedTrue(![delivered.tornDownHandshakeId isEqualToData:receiverOwn.handshakeId],
                      @"on the losing branch the id destroyed is the INCOMING handshake's, never "
                      @"the caller's own — reporting the caller's would instruct it to discard the "
                      @"one handle it must keep (§11.6)");
        IRNegNeedTrue(!receiverOwn.isTornDown,
                      @"§10.7 step 14c: the existing session is the survivor and stays live");
        IRNegNeedTrue([delivered.session.handshakeId isEqualToData:receiverOwn.handshakeId],
                      @"§11.6: `session` is ALWAYS the survivor");

        NSData *after = IRNegStateBlob(receiverOwn);
        IRNegNeed(after, @"§12.1 blob for the survivor after the losing delivery");

        IRDecryptedMessage *replayed = [receiver.messenger decryptPreKeyMessage:stimulus
                                                                          error:&error];
        IRNegNeedTrue(replayed == nil,
                      @"a second delivery would make §10.7 step 14d a plaintext-harvesting oracle");

        result.outputs[@"sessions.S1.state_blob_after"] = IRVectorHex(after);
        result.outputs[@"survivor_torn_down"] = @(receiverOwn.isTornDown);
        result.error = error;

        return result;
    }

    /* NEG-COLLAPSE-LOSER-HANDLE. The incoming session won, so the handle the caller was holding —
       the receiver's own — is the one that died, and §11.6 named it. */
    IRNegNeedTrue([delivered.tornDownHandshakeId isEqualToData:receiverOwn.handshakeId],
                  @"§11.6: torn_down_handshake_id must name the handle the caller held");
    IRNegNeedTrue(receiverOwn.isTornDown, @"the loser must be torn down");

    NSData *followup = IRNegData(inputs, @"followup_message");
    IRNegNeedTrue(followup.length >= (NSUInteger)kIRLenType01Min,
                  @"followup_message must clear §10.0 row 1's %d-byte global floor",
                  (int)kIRLenType01Min);
    IRNegNeedTrue([IRMessenger messageTypeOfMessage:followup error:NULL] == IRMessageTypeNormal,
                  @"followup_message must be a well-formed type 0x01 so check 6 is what rejects it");

    IRDecryptedMessage *onDeadHandle = [receiver.messenger decryptMessage:followup
                                                                inSession:receiverOwn
                                                                    error:&error];
    IRNegNeedTrue(onDeadHandle == nil, @"§11.6: a torn-down handle MUST NOT resolve");

    /* The peer index now answers with the SURVIVOR, which is the handle §11.6 told the caller to
       adopt — so the by-peer form cannot resurrect the dead one either. */
    IRSession *resolved =
        [receiver.sessions sessionForPeerIdentityKeyPair:sender.identity.identityKeyPair];
    IRNegNeed(resolved, @"the peer index must resolve to the survivor");
    IRNegNeedTrue([resolved.handshakeId isEqualToData:delivered.session.handshakeId],
                  @"§11.6: `session` is ALWAYS the survivor");

    result.outputs[@"loser_torn_down"] = @YES;
    result.outputs[@"survivor_handshake_id"] = IRVectorHex(resolved.handshakeId);
    result.error = error;

    return result;
}

#pragma mark - Input builder

/**
 THE JSON FORM AND THE SCHEMA, BUILT IN LOCKSTEP.

 The generator needs `inputs` as it will be frozen — hex strings, JSON numbers, uint64 decimal
 strings — and the executor needs to know which typed IRVectorCase accessor to call for each key,
 because reading an input is what CONSUMES it and §15.5 rule 3 makes an unconsumed key a failure.
 Declaring the two separately is one list that can silently disagree with another; this declares
 them once, so a key that exists in the file always has a reader and a key that has a reader always
 exists in the file.
 */
@interface IRNegInputs : NSObject

@property (nonatomic, strong) NSMutableDictionary *json;
@property (nonatomic, strong) NSMutableDictionary *schema;

+ (instancetype)inputs;

- (void)hex:(NSString *)key value:(NSString *)hex;
- (void)u32:(NSString *)key value:(uint32_t)value;
- (void)u64:(NSString *)key value:(uint64_t)value;
- (void)str:(NSString *)key value:(NSString *)value;

@end

@implementation IRNegInputs

+ (instancetype)inputs {
    IRNegInputs *inputs = [[IRNegInputs alloc] init];
    inputs.json = [NSMutableDictionary dictionary];
    inputs.schema = [NSMutableDictionary dictionary];

    return inputs;
}

- (void)hex:(NSString *)key value:(NSString *)hex {
    IRVectorRequire(IRVectorHexIsWellFormed(hex), @"%@ is not lowercase even-length hex", key);
    self.json[key] = hex;
    self.schema[key] = @"hex";
}

- (void)u32:(NSString *)key value:(uint32_t)value {
    self.json[key] = @(value);
    self.schema[key] = @"u32";
}

- (void)u64:(NSString *)key value:(uint64_t)value {
    self.json[key] = IRVectorUInt64String(value);
    self.schema[key] = @"u64";
}

- (void)str:(NSString *)key value:(NSString *)value {
    self.json[key] = value;
    self.schema[key] = @"str";
}

@end

/// The shape almost every vector here shares: two actors, a published bundle, and a pinned clock.
static IRNegInputs *IRNegCommonInputs(NSString *_Nullable entryPoint) {
    IRNegInputs *inputs = [IRNegInputs inputs];

    if (entryPoint != nil) {
        [inputs str:@"entry_point" value:entryPoint];
    }

    [inputs hex:@"rng_A" value:kNegScriptA];
    [inputs hex:@"rng_B" value:kNegScriptB];
    [inputs u32:@"spk_id" value:kNegSpkId];
    [inputs u32:@"opk_id" value:kNegOpkId];
    [inputs u64:@"not_before" value:kNegNotBeforeS];
    [inputs u64:@"not_after" value:kNegNotAfterS];
    [inputs u64:@"now_s" value:kNegNowS];
    [inputs u64:@"now_ms" value:kNegNowMs];

    return inputs;
}

/**
 Removes inputs this vector's scenario genuinely does not read.

 §15.5 rule 3 makes an unrecognised `inputs` key an error rather than a forward-compatibility
 affordance, and the spirit of that rule is that a port must not quietly ignore a field another port
 acts on. Carrying a CSPRNG script for an actor that never appears, or a `now_ms` for a scenario whose
 only clock is `now_s`, would satisfy the letter — the executor consumes every declared key — while
 putting a kilobyte of hex in the frozen file that nothing depends on.
 */
static void IRNegDrop(IRNegInputs *inputs, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        [inputs.json removeObjectForKey:key];
        [inputs.schema removeObjectForKey:key];
    }
}

/* Short ASCII payloads. §10.4 makes any length legal including zero; these are readable so a
   failing diff shows which leg of a multi-message scenario moved. */
static NSString * const kNegPlaintext1 = @"68656c6c6f";        /* "hello" */
static NSString * const kNegPlaintext2 = @"61636b";            /* "ack"   */
static NSString * const kNegPlaintext3 = @"7468726565";        /* "three" */
static NSString * const kNegPlaintext4 = @"666f7572";          /* "four"  */
static NSString * const kNegPlaintext5 = @"66697665";          /* "five"  */

/// A 200-byte, structurally well-formed type `0x01` message. §10.1 check 6 rejects it on a dead
/// handle before anything looks at its contents, which is exactly what NEG-COLLAPSE-LOSER-HANDLE
/// needs: the handle must be what fails, not the bytes.
static NSString *IRNegFollowupMessageHex(void) {
    NSMutableData *message = [NSMutableData dataWithLength:200];
    uint8_t *raw = (uint8_t *)message.mutableBytes;

    raw[kIROffType01Version] = 0x04;
    raw[kIROffType01Type] = (uint8_t)IRMessageTypeNormal;

    return IRVectorHex(message);
}

/// The all-zero X25519 point: a VALID ENCODING under §4.4 checks 1–2, and a small-order element.
static NSString *IRNegAllZeroPublicHex(void) {
    return IRVectorHex([NSMutableData dataWithLength:(NSUInteger)kIRLenX25519Public]);
}

#pragma mark - Descriptors

typedef IRNegResult * _Nonnull (*IRNegScenarioFn)(NSDictionary *inputs);

/**
 One row of §15.4, as data: its identity, the code it must produce, the inputs the generator freezes,
 the schema the executor reads them back with, and the scenario both directions run.

 A table rather than a switch because the generator and the executor MUST agree on all five for
 every row, and a table cannot have a case in one that is missing in the other.
 */
static NSDictionary *IRNegDescriptor(NSString *identifier,
                                     NSString *kind,
                                     NSString *_Nullable errorName,
                                     NSString *summary,
                                     IRNegInputs *inputs,
                                     IRNegScenarioFn scenario) {
    NSMutableDictionary *descriptor = [NSMutableDictionary dictionary];

    descriptor[@"id"] = identifier;
    descriptor[@"kind"] = kind;
    descriptor[@"description"] = summary;
    descriptor[@"expect"] = (errorName != nil) ? @"error" : @"ok";
    descriptor[@"inputs"] = inputs.json;
    descriptor[@"schema"] = inputs.schema;
    descriptor[@"scenario"] = [NSValue valueWithPointer:(const void *)scenario];

    if (errorName != nil) {
        descriptor[@"error"] = errorName;
    }

    return descriptor;
}

static NSArray<NSDictionary *> *IRNegDescriptors(void) {
    NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];

    #pragma mark NEG-DH2-ALTERED / NEG-DH3-ALTERED / NEG-DH4-ALTERED

    NSArray<NSArray *> *ikmRows = @[
        @[@"NEG-DH2-ALTERED", @(kIROffIKMDH2), @"DH2 = X25519(EK_A, IK_B^d)"],
        @[@"NEG-DH3-ALTERED", @(kIROffIKMDH3), @"DH3 = X25519(EK_A, SPK_B)"],
        @[@"NEG-DH4-ALTERED", @(kIROffIKMDH4), @"DH4 = X25519(EK_A, OPK_B)"],
    ];

    for (NSArray *row in ikmRows) {
        IRNegInputs *inputs = IRNegCommonInputs(nil);
        IRNegDrop(inputs, @[@"now_ms"]);
        [inputs u32:@"ikm_offset" value:(uint32_t)[(NSNumber *)row[1] unsignedLongLongValue]];

        NSString *summary = [NSString stringWithFormat:
            @"%@ altered in isolation inside the 160-byte IKM, transcript hash held constant; SK "
            @"MUST change. v3 handed the IKM to an API that reads its first 32 bytes, so offset %@ "
            @"was never consumed and this flip produced an identical shared key on both sides.",
            row[2], row[1]];

        [rows addObject:IRNegDescriptor(row[0], @"x3dh", nil, summary,
                                        inputs, IRNegScenarioIKMAltered)];
    }

    #pragma mark NEG-RK-ALTERED

    {
        IRNegInputs *inputs = [IRNegInputs inputs];
        [inputs hex:@"RK" value:kNegRootKeyHex];
        [inputs hex:@"DH_out" value:kNegDHOutputHex];
        [inputs u32:@"altered_offset" value:0];

        [rows addObject:IRNegDescriptor(
            @"NEG-RK-ALTERED", @"primitive", nil,
            @"KDF_RK(RK, DH_out) against KDF_RK(RK', DH_out) with one bit of RK flipped: both "
            @"halves of the 64-byte output MUST differ. The previous root key is the SALT and is "
            @"mandatory; v3 derived from the DH output alone and discarded its predecessor, so the "
            @"root chain had no continuity and this flip changed nothing.",
            inputs, IRNegScenarioRootKeyAltered)];
    }

    #pragma mark NEG-SK-TAMPER

    {
        IRNegInputs *inputs = IRNegCommonInputs(nil);
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs u32:@"sk_offset" value:0];

        [rows addObject:IRNegDescriptor(
            @"NEG-SK-TAMPER", @"ratchet", @"ERR_AEAD_AUTH_FAILED",
            @"Both parties derive the same SK; one byte is flipped between B's derivation and B's "
            @"§7.5 ratchet initialization, so only the value reaching the root chain differs. "
            @"Poly1305 is the first thing that can notice, because every public value on the wire "
            @"is genuine.",
            inputs, IRNegScenarioSharedKeyTampered)];
    }

    #pragma mark NEG-ATOMIC

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs hex:@"forged_DHs_pub" value:kNegForeignRatchetPublic];

        [rows addObject:IRNegDescriptor(
            @"NEG-ATOMIC", @"ratchet", @"ERR_AEAD_AUTH_FAILED",
            @"A header-valid, tag-invalid type 0x01 message carrying a ratchet key the receiver has "
            @"never seen, so a port without §7.7's snapshot performs a real DH ratchet before "
            @"Poly1305 refuses. The session blob MUST be byte-identical afterwards and the genuine "
            @"message MUST still decrypt: this is the unauthenticated desynchronisation DoS, and it "
            @"is state corruption rather than a wrong plaintext, so no round-trip test sees it.",
            inputs, IRNegScenarioAtomic)];
    }

    #pragma mark NEG-SKIP-RETAIN

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs hex:@"plaintext_4" value:kNegPlaintext4];
        [inputs u32:@"ciphertext_offset" value:0];

        [rows addObject:IRNegDescriptor(
            @"NEG-SKIP-RETAIN", @"ratchet", @"ERR_AEAD_AUTH_FAILED",
            @"A message whose key is already in the skipped store, delivered with a corrupted tag. "
            @"§7.6: a stored key MUST be removed ONLY after the AEAD using it SUCCEEDS. v3 removed "
            @"it first, so one corrupted byte in transit destroyed the only copy of the key and lost "
            @"the message forever. The blob comparison catches it: §12.1's exact-length rule makes a "
            @"missing 76-byte entry visible.",
            inputs, IRNegScenarioSkipRetain)];
    }

    #pragma mark NEG-IKB-SWAP

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"rng_C" value:kNegScriptC];
        [inputs hex:@"plaintext" value:kNegPlaintext1];

        [rows addObject:IRNegDescriptor(
            @"NEG-IKB-SWAP", @"x3dh", @"ERR_BAD_SIGNATURE",
            @"The victim's genuine IK^s and IKB_A with an attacker-chosen IK^d spliced into "
            @"msg[36..68), no existing session. The spliced key is a real X25519 public so §10.2's "
            @"gate has nothing to say; only §10.7 step 3's verification of IKB_A over "
            @"IKBIND_MSG(IK_A^s, IK_A^d) — BEFORE any DH — can reject it. Without §5.5's rule that "
            @"identity is the pair, this attacker completes a sound session and is attributed to the "
            @"victim by anyone keying contacts on the signing key.",
            inputs, IRNegScenarioIKBSwap)];
    }

    #pragma mark NEG-IKB-RETRANS

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs u32:@"ikb_offset" value:13];

        [rows addObject:IRNegDescriptor(
            @"NEG-IKB-RETRANS", @"ratchet", @"ERR_BAD_SIGNATURE",
            @"A genuine §11.3 retransmission to an EXISTING session with one byte of IKB_A flipped. "
            @"Arbitrates §5.5 against §11.2: IKB_A sits inside the type 0x02 AD, so without §11.2's "
            @"check 2 the tampered binding reaches the AEAD and fails there instead. Both fail "
            @"closed; only one returns the code §15.4 requires, and it MUST NOT be "
            @"ERR_AEAD_AUTH_FAILED.",
            inputs, IRNegScenarioIKBRetrans)];
    }

    #pragma mark NEG-SPKSIG-BAD

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"parse_bundle");
        IRNegDrop(inputs, @[@"rng_A", @"now_ms"]);
        [inputs u32:@"sig_offset" value:0];

        [rows addObject:IRNegDescriptor(
            @"NEG-SPKSIG-BAD", @"x3dh", @"ERR_BAD_SIGNATURE",
            @"One byte flipped inside SPK_SIG at bundle offset 185; everything else genuine, so only "
            @"§5.3 rule 4 can reject. v3 never reached an equivalent check: it re-signed the peer's "
            @"prekey with the local identity key, overwriting the evidence with a signature later "
            @"code found valid.",
            inputs, IRNegScenarioSignedPreKeySignatureBad)];
    }

    #pragma mark NEG-SPK-EXPIRED

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"parse_bundle");
        IRNegDrop(inputs, @[@"rng_A", @"now_ms"]);
        [inputs u64:@"now_s" value:kNegNotAfterS + 86400ULL];

        [rows addObject:IRNegDescriptor(
            @"NEG-SPK-EXPIRED", @"x3dh", @"ERR_PREKEY_EXPIRED",
            @"Fixed not_before / not_after with an injected now_s one day PAST not_after, so §5.3 "
            @"rule 5 rejects a bundle that is otherwise entirely valid. The instant is supplied "
            @"rather than waited for: a vector that let the window lapse against the host clock "
            @"would pass on the day it was frozen and fail forever after, and §15.6 step 4 forbids "
            @"regenerating it.",
            inputs, IRNegScenarioValidityWindow)];
    }

    #pragma mark NEG-SPK-WINDOW-TOO-LONG

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"parse_bundle");
        IRNegDrop(inputs, @[@"rng_A", @"now_ms"]);
        [inputs u64:@"not_after"
                value:kNegNotBeforeS + (uint64_t)kIRMaxSPKValiditySeconds + 1ULL];

        [rows addObject:IRNegDescriptor(
            @"NEG-SPK-WINDOW-TOO-LONG", @"x3dh", @"ERR_PREKEY_EXPIRED",
            @"A window one second longer than MAX_SPK_VALIDITY_SECONDS with now_s INSIDE it, so "
            @"rule 5 passes and only rule 6 can reject. Rule 5 running first is what makes rule 6's "
            @"subtraction safe: not_before <= now < not_after implies not_before < not_after, so the "
            @"unsigned difference cannot wrap.",
            inputs, IRNegScenarioValidityWindow)];
    }

    #pragma mark NEG-SPK-SURVIVES-RATCHET

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"rng_C" value:kNegScriptC];
        [inputs u32:@"opk_id_2" value:kNegOpkId2];
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs hex:@"plaintext_4" value:kNegPlaintext4];

        [rows addObject:IRNegDescriptor(
            @"NEG-SPK-SURVIVES-RATCHET", @"ratchet", nil,
            @"Two initiators against one spk_id: initiator 1 completes, B ratchets past the signed "
            @"prekey, then initiator 2 handshakes against the same id and MUST succeed. The only "
            @"vector in the suite that distinguishes a port copying SPK_B_priv into ratchet state "
            @"from one aliasing the prekey store — §7.4 step 4 zeroizes DHs.priv on B's first "
            @"ratchet of EVERY session, and an aliasing port then reports ERR_AEAD_AUTH_FAILED, "
            @"misreading its own key destruction as an active man-in-the-middle.",
            inputs, IRNegScenarioSPKSurvivesRatchet)];
    }

    #pragma mark NEG-OPK-UNKNOWN / NEG-OPK-EXPIRED / NEG-OPK-NOFALLBACK

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs u64:@"opk_created_at_s" value:kNegNowS];
        [inputs u32:@"opk_retained" value:0];

        [rows addObject:IRNegDescriptor(
            @"NEG-OPK-UNKNOWN", @"x3dh", @"ERR_UNKNOWN_PREKEY_ID",
            @"A bundle advertising a one-time prekey the publisher never retained, so opk_id does "
            @"not resolve at §10.7 step 7. §6.6 rule 2 makes absence a HARD failure with no fallback "
            @"to the three-DH form: rejecting rather than falling back is what converts OPK "
            @"consumption into replay protection.",
            inputs, IRNegScenarioOPKUnresolvable)];
    }

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs u64:@"opk_created_at_s" value:kNegNowS - (uint64_t)kIROPKMaxAgeSeconds];
        [inputs u32:@"opk_retained" value:1];

        [rows addObject:IRNegDescriptor(
            @"NEG-OPK-EXPIRED", @"x3dh", @"ERR_UNKNOWN_PREKEY_ID",
            @"The prekey IS retained, with a responder-local creation timestamp exactly "
            @"OPK_MAX_AGE_S old at the injected now_s, so §5.3's sweep deletes and zeroizes it at "
            @"resolution time and the id resolves exactly as an unknown one does. The timestamp is "
            @"responder-local and is NOT on the wire — the 36-byte bundle entry has no room for it, "
            @"and the total-length rule 251 + 36 * opk_count depends on that width.",
            inputs, IRNegScenarioOPKUnresolvable)];
    }

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs u64:@"opk_created_at_s" value:kNegNowS - (uint64_t)kIROPKMaxAgeSeconds - 1ULL];
        [inputs u32:@"opk_retained" value:1];

        [rows addObject:IRNegDescriptor(
            @"NEG-OPK-NOFALLBACK", @"x3dh", @"ERR_UNKNOWN_PREKEY_ID",
            @"The same stimulus, asserting the consequence: NO session was created and the peer "
            @"index resolves to nothing. A port that degraded to the three-DH form when opk_id "
            @"failed to resolve would open a session and return a plaintext here, which is the "
            @"downgrade §6.6 rule 2 forecloses.",
            inputs, IRNegScenarioOPKUnresolvable)];
    }

    #pragma mark NEG-SMALLORDER

    {
        IRNegInputs *inputs = IRNegCommonInputs(nil);
        IRNegDrop(inputs, @[@"now_ms"]);
        [inputs hex:@"OPK_B_pub" value:IRNegAllZeroPublicHex()];

        [rows addObject:IRNegDescriptor(
            @"NEG-SMALLORDER", @"x3dh", @"ERR_SMALL_ORDER_KEY",
            @"A bundle whose one-time prekey is the all-zero point. THE BUNDLE PARSES: §5.3 rule 2 "
            @"is §4.4 checks 1–2 only, a length and a high bit, and the all-zero encoding passes "
            @"both. §4.4 check 3 on DH4's output is the only thing behind it, and it is reachable "
            @"precisely because §5.2 forbids inventing a per-OPK signature.",
            inputs, IRNegScenarioSmallOrder)];
    }

    #pragma mark NEG-COUNTER / NEG-SKIP-LIMIT

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs u32:@"forged_N" value:0x80000000u];

        [rows addObject:IRNegDescriptor(
            @"NEG-COUNTER", @"ratchet", @"ERR_COUNTER_OVERFLOW",
            @"N = 0x80000000, one above MAX_COUNTER, rejected by §10.1's ordered gate before any "
            @"secret is touched. N is inside the AD, so a port that ran the AEAD first would answer "
            @"ERR_AEAD_AUTH_FAILED. The bound exists because N is unsigned on the wire and signed on "
            @"the JVM, where 0x80000000 reads as -2147483648.",
            inputs, IRNegScenarioForgedCounter)];
    }

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs u32:@"forged_N" value:(uint32_t)kIRMaxSkipPerMessage + 1u];

        [rows addObject:IRNegDescriptor(
            @"NEG-SKIP-LIMIT", @"ratchet", @"ERR_TOO_MANY_SKIPPED",
            @"N = 1001 beyond Nr on the new receiving chain, one past MAX_SKIP_PER_MESSAGE. §7.9 "
            @"phase 3c runs SkipMessageKeys BEFORE the AEAD check precisely so a forged counter "
            @"cannot buy an attacker 1000 HMAC operations per unauthenticated message, and §7.6 "
            @"requires the state be left UNMODIFIED: the budget is checked against the whole span "
            @"before the first key is derived, never per key.",
            inputs, IRNegScenarioForgedCounter)];
    }

    #pragma mark NEG-REPLAY

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];

        [rows addObject:IRNegDescriptor(
            @"NEG-REPLAY", @"ratchet", @"ERR_REPLAY",
            @"A byte-identical redelivery of a message already consumed in order: N < Nr with an "
            @"empty skipped store, so phase 3a misses, phase 3b is skipped and phase 3c fires. §7.9 "
            @"makes this an EXPLICIT code and not a silent AEAD failure — and §10.5 makes the "
            @"distinction local-only, because telling a peer which occurred reveals whether a "
            @"guessed counter sat in the skipped-key store.",
            inputs, IRNegScenarioReplay)];
    }

    #pragma mark NEG-NO-SESSION

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];

        [rows addObject:IRNegDescriptor(
            @"NEG-NO-SESSION", @"ratchet", @"ERR_NO_SESSION",
            @"A well-formed type 0x01 message submitted with NO handle, and again with a handle the "
            @"host still holds that names a torn-down session — both ERR_NO_SESSION, and the "
            @"by-peer form too. §13.4 clause 5 makes this the one argument whose absence is a "
            @"specified protocol condition rather than a caller contract violation; a _Nonnull "
            @"handle guarded by a trap would make this code unreachable from Swift.",
            inputs, IRNegScenarioNoSession)];
    }

    #pragma mark NEG-DEMUX-WRONG-SESSION / NEG-DEMUX-WRONG-PEER

    NSString *wrongSessionTail =
        @"submitted with the handle for S2. A trial-decrypting port fails by returning P1's "
        @"plaintext, or — if it retries and suppresses the result — by an advanced Nr and a "
        @"rewritten CKr in S1's blob.";
    NSString *wrongPeerTail =
        @"submitted through the peer-resolving entry point naming P2. This is the signature that "
        @"invites a loop over the peer index, and the only place a helpful retry is natural to "
        @"write; the handle-taking form structurally has one session to try.";

    NSArray<NSArray *> *demuxRows = @[
        @[@"NEG-DEMUX-WRONG-SESSION", @"decrypt_with_handle", @0, wrongSessionTail],
        @[@"NEG-DEMUX-WRONG-PEER", @"decrypt_by_peer", @1, wrongPeerTail],
    ];

    for (NSArray *row in demuxRows) {
        IRNegInputs *inputs = IRNegCommonInputs(row[1]);
        [inputs hex:@"rng_C" value:kNegScriptC];
        [inputs u32:@"opk_id_2" value:kNegOpkId2];
        [inputs u32:@"select_by_peer" value:(uint32_t)[(NSNumber *)row[2] unsignedLongLongValue]];
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"plaintext_3" value:kNegPlaintext3];
        [inputs hex:@"plaintext_4" value:kNegPlaintext4];
        [inputs hex:@"plaintext_5" value:kNegPlaintext5];

        NSString *summary = [NSString stringWithFormat:
            @"Receiver B holds two live sessions with two DIFFERENT peers — §11.1.1's bound is per "
            @"peer, not global — both established through §10.7 against the same spk_id with "
            @"distinct opk_ids. The stimulus is the next legitimate type 0x01 message of P1's "
            @"current sending chain, so it WOULD decrypt under S1, %@ Both blobs MUST be "
            @"byte-identical afterwards, and the message MUST still be collectable under S1 "
            @"(DEMUX-NO-TRIAL).", row[3]];

        [rows addObject:IRNegDescriptor(row[0], @"ratchet", @"ERR_AEAD_AUTH_FAILED", summary,
                                        inputs, IRNegScenarioDemux)];
    }

    #pragma mark NEG-HANDSHAKE-TOMBSTONE

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs u64:@"tear_down_at_ms" value:kNegNowMs];

        [rows addObject:IRNegDescriptor(
            @"NEG-HANDSHAKE-TOMBSTONE", @"ratchet", @"ERR_REPLAY",
            @"A type 0x02 message whose handshake_id matches a tombstone written by an explicit "
            @"teardown, resubmitted inside HANDSHAKE_CACHE_MS. The ordering is the assertion: §10.7 "
            @"step 4 runs BEFORE step 5's spk_id resolution and step 7's opk_id resolution, and the "
            @"one-time prekey was already consumed and zeroized by step 14a — so a port that "
            @"resolved the prekeys first answers ERR_UNKNOWN_PREKEY_ID for identical bytes.",
            inputs, IRNegScenarioHandshakeTombstone)];
    }

    #pragma mark NEG-COLLAPSE-LOSER-REPLAY / NEG-COLLAPSE-LOSER-HANDLE

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_prekey");
        [inputs u32:@"opk_id_2" value:kNegOpkId2];
        [inputs str:@"collapse_branch" value:@"loser"];
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];

        [rows addObject:IRNegDescriptor(
            @"NEG-COLLAPSE-LOSER-REPLAY", @"ratchet", @"ERR_REPLAY",
            @"A concurrent initiation, delivered to the side whose INCOMING handshake loses the "
            @"§11.1.1 comparison. The first arrival IS delivered — §10.7 step 14d, and §19.7 records "
            @"why dropping it would hand a network-level attacker a permanent message-suppression "
            @"primitive — and the identical retransmission is then ERR_REPLAY, because step 14c "
            @"tombstoned a session that was never persisted. That tombstone is what stops the "
            @"delivery rule from becoming a plaintext-harvesting oracle. The survivor's blob MUST be "
            @"byte-identical: no value derived on the losing session may be merged into it.",
            inputs, IRNegScenarioCollapse)];
    }

    {
        IRNegInputs *inputs = IRNegCommonInputs(@"decrypt_with_handle");
        [inputs u32:@"opk_id_2" value:kNegOpkId2];
        [inputs str:@"collapse_branch" value:@"winner"];
        [inputs hex:@"plaintext" value:kNegPlaintext1];
        [inputs hex:@"plaintext_2" value:kNegPlaintext2];
        [inputs hex:@"followup_message" value:IRNegFollowupMessageHex()];

        [rows addObject:IRNegDescriptor(
            @"NEG-COLLAPSE-LOSER-HANDLE", @"ratchet", @"ERR_NO_SESSION",
            @"The same fixture taken on the side whose incoming handshake WINS, so the handle the "
            @"caller was holding is the one that died and §11.6's torn_down_handshake_id names it. "
            @"A well-formed type 0x01 against that handle is ERR_NO_SESSION at §10.1 check 6, before "
            @"the message is looked at. This is the only way the 'which handle comes back' half of "
            @"§10.7 step 14d is observable at all, since a handle is opaque and has no byte "
            @"representation.",
            inputs, IRNegScenarioCollapse)];
    }

    return rows;
}

static NSDictionary *_Nullable IRNegDescriptorForId(NSString *identifier) {
    for (NSDictionary *descriptor in IRNegDescriptors()) {
        if ([descriptor[@"id"] isEqualToString:identifier]) {
            return descriptor;
        }
    }

    return nil;
}

static IRNegResult *IRNegRunScenario(NSDictionary *descriptor, NSDictionary *decodedInputs) {
    NSValue *boxed = descriptor[@"scenario"];
    IRNegScenarioFn scenario = (IRNegScenarioFn)[boxed pointerValue];

    return scenario(decodedInputs);
}

#pragma mark - Generator

/// The generator's decode: the JSON form back into the plain values a scenario reads. The executor's
/// counterpart goes through IRVectorCase instead, so that reading an input CONSUMES it (rule 3).
static NSDictionary *IRNegDecodeForGeneration(NSDictionary *json, NSDictionary *schema) {
    NSMutableDictionary *decoded = [NSMutableDictionary dictionary];

    for (NSString *key in schema) {
        NSString *type = schema[key];
        id value = json[key];

        IRVectorRequire(value != nil, @"schema names `%@` but inputs does not carry it", key);

        if ([type isEqualToString:@"hex"]) {
            decoded[key] = IRVectorBytes(value);
        } else if ([type isEqualToString:@"u64"]) {
            decoded[key] = @(IRVectorUInt64FromString(value));
        } else {
            decoded[key] = value;
        }
    }

    IRVectorRequire(decoded.count == json.count,
                    @"inputs carries %lu keys but the schema declares %lu — every key MUST have a "
                    @"reader, or §15.5 rule 3 fails in the executor",
                    (unsigned long)json.count, (unsigned long)decoded.count);

    return decoded;
}

NSArray<NSDictionary *> *IRVectorsForNegativeCrypto(void) {
    NSMutableArray<NSDictionary *> *vectors = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    for (NSDictionary *descriptor in IRNegDescriptors()) {
        NSString *identifier = descriptor[@"id"];
        IRVectorRequire(![seen containsObject:identifier],
                        @"vector id %@ is declared twice; §15.5 makes ids unique across all files",
                        identifier);
        [seen addObject:identifier];

        NSMutableDictionary *json = [descriptor[@"inputs"] mutableCopy];
        NSDictionary *decoded = IRNegDecodeForGeneration(json, descriptor[@"schema"]);

        IRNegResult *result = IRNegRunScenario(descriptor, decoded);
        IRVectorRequire(result.failure == nil, @"[%@] %@", identifier, result.failure);

        /* §15.5's reserved input keys, filled from the replay rather than invented — see the file
           comment. `selected_session` is emitted only when an entry point actually took a handle. */
        if (result.sessions.count > 0) {
            json[@"sessions"] = [result.sessions copy];

            if (result.selectedSession != nil) {
                json[@"selected_session"] = result.selectedSession;
            }
        }

        NSMutableDictionary *vector = [NSMutableDictionary dictionary];
        vector[@"id"] = identifier;
        vector[@"kind"] = descriptor[@"kind"];
        vector[@"description"] = descriptor[@"description"];
        vector[@"expect"] = descriptor[@"expect"];
        vector[@"inputs"] = [json copy];

        NSString *expectedErrorName = descriptor[@"error"];

        if (expectedErrorName != nil) {
            vector[@"error"] = expectedErrorName;

            IRVectorRequire(result.error != nil,
                            @"[%@] expects %@ but the implementation returned no error",
                            identifier, expectedErrorName);
            IRVectorRequire([result.error.domain isEqualToString:IRErrorDomain],
                            @"[%@] error domain is %@, expected %@",
                            identifier, result.error.domain, IRErrorDomain);

            NSString *actualName = IRVectorNameForErrorCode((IRErrorCode)result.error.code);
            IRVectorRequire([actualName isEqualToString:expectedErrorName],
                            @"[%@] §15.4 requires %@, the implementation returned %@ (%ld)",
                            identifier, expectedErrorName, actualName, (long)result.error.code);
        } else {
            IRVectorRequire(result.error == nil,
                            @"[%@] expects success but the implementation returned %@",
                            identifier, result.error);
            IRVectorRequire(result.outputs.count > 0,
                            @"[%@] an `expect: \"ok\"` vector MUST carry outputs (§15.5)",
                            identifier);
        }

        if (result.intermediates.count > 0) {
            vector[@"intermediates"] = [result.intermediates copy];
        }

        if (result.outputs.count > 0) {
            vector[@"outputs"] = [result.outputs copy];
        }

        [vectors addObject:[vector copy]];
    }

    return [vectors copy];
}

#pragma mark - Executor

/**
 §15.5 rules 1 and 2, with the type chosen by the frozen value itself.

 Every value this module emits is a hex STRING or a JSON NUMBER — the file comment on
 NEG-HANDSHAKE-TOMBSTONE says why there are no uint64 decimal strings here — so a string is always
 bytes and a number is always a number, with `true`/`false` recognised by identity against the
 CFBoolean singletons rather than by @encode, which spells BOOL differently across architectures.
 */
static void IRNegCheckIntermediate(IRVectorCase *vectorCase, NSString *key, id _Nullable actual) {
    if (actual == nil) {
        /* Rule 2's reported skip: this implementation cannot expose the value. Never silent. */
        [vectorCase checkIntermediate:key data:nil];
        return;
    }

    if ([actual isKindOfClass:[NSString class]]) {
        [vectorCase checkIntermediate:key data:IRVectorBytes(actual)];
        return;
    }

    [vectorCase checkIntermediate:key number:actual];
}

static void IRNegCheckOutput(XCTestCase *testCase,
                             IRVectorCase *vectorCase,
                             NSString *key,
                             id _Nullable actual) {
    if (actual == nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] `outputs.%@` is in the frozen file and the runner produced no "
                              @"value for it; §15.5 rule 1 requires every output be checked",
                              vectorCase.identifier, key);
        return;
    }

    if ([actual isKindOfClass:[NSString class]]) {
        [vectorCase checkOutput:key data:IRVectorBytes(actual)];
        return;
    }

    if (actual == (id)kCFBooleanTrue || actual == (id)kCFBooleanFalse) {
        [vectorCase checkOutput:key boolean:[actual boolValue]];
        return;
    }

    [vectorCase checkOutput:key number:actual];
}

/// The `inputs.sessions` cross-check. A disagreement here is an interop failure in §12.1 or §6.5,
/// reported before the rule the vector is actually about — which is the point of freezing them.
static void IRNegCheckSessions(XCTestCase *testCase,
                               IRVectorCase *vectorCase,
                               NSDictionary *_Nullable frozen,
                               NSDictionary *produced) {
    if (frozen == nil && produced.count == 0) {
        return;
    }

    if (frozen == nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] the replay built %lu session fixture(s) but the frozen vector "
                              @"carries no `inputs.sessions`",
                              vectorCase.identifier, (unsigned long)produced.count);
        return;
    }

    if (frozen.count != produced.count) {
        IRVectorRecordFailure(testCase, @"[%@] `inputs.sessions` has %lu entries, the replay built "
                                        @"%lu",
                              vectorCase.identifier,
                              (unsigned long)frozen.count, (unsigned long)produced.count);
    }

    for (NSString *name in frozen) {
        NSDictionary *expected = frozen[name];
        NSDictionary *actual = produced[name];

        if (![expected isKindOfClass:[NSDictionary class]] || actual == nil) {
            IRVectorRecordFailure(testCase, @"[%@] session fixture `%@` is missing or malformed",
                                  vectorCase.identifier, name);
            continue;
        }

        for (NSString *field in @[@"handshake_id", @"state_blob"]) {
            if (![expected[field] isEqual:actual[field]]) {
                IRVectorRecordFailure(testCase,
                                      @"[%@] sessions.%@.%@ differs from the frozen fixture: "
                                      @"frozen %@, replay %@",
                                      vectorCase.identifier, name, field,
                                      expected[field], actual[field]);
            }
        }

        if (![expected[@"peer_identity"] isEqual:actual[@"peer_identity"]]) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] sessions.%@.peer_identity differs — §6.5 reads the pair "
                                  @"out of SESSION_AD by ROLE, so a port computing (self, peer) "
                                  @"diverges here: frozen %@, replay %@",
                                  vectorCase.identifier, name,
                                  expected[@"peer_identity"], actual[@"peer_identity"]);
        }
    }
}

void IRRunNegativeCryptoVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    NSDictionary *descriptor = IRNegDescriptorForId(vectorCase.identifier);
    if (descriptor == nil) {
        /* §15.6 step 5's "none are skipped without an explicit, reviewed reason": a runner that
           silently ignored an unrecognised vector would report green on a corpus it never ran. */
        IRVectorRecordFailure(testCase,
                              @"[%@] negative.json carries a `primitive`/`x3dh`/`ratchet` vector "
                              @"this module has no executor for",
                              vectorCase.identifier);
        return;
    }

    if (![vectorCase.kind isEqualToString:descriptor[@"kind"]]) {
        IRVectorRecordFailure(testCase, @"[%@] kind is \"%@\", this module emits \"%@\"",
                              vectorCase.identifier, vectorCase.kind, descriptor[@"kind"]);
    }

    /* Every declared input is read FIRST — through the typed accessors, which is what consumes it —
       so rule 3's bookkeeping is complete even on a path that then bails out. */
    NSDictionary *schema = descriptor[@"schema"];
    NSMutableDictionary *decoded = [NSMutableDictionary dictionary];

    for (NSString *key in schema) {
        NSString *type = schema[key];

        if ([type isEqualToString:@"hex"]) {
            decoded[key] = [vectorCase dataInput:key];
        } else if ([type isEqualToString:@"u32"]) {
            decoded[key] = @([vectorCase uint32Input:key]);
        } else if ([type isEqualToString:@"u64"]) {
            decoded[key] = @([vectorCase uint64Input:key]);
        } else {
            decoded[key] = [vectorCase stringInput:key];
        }
    }

    NSDictionary *frozenSessions = [vectorCase optionalDictionaryInput:@"sessions"];
    NSString *frozenSelected = [vectorCase optionalStringInput:@"selected_session"];

    IRNegResult *result = IRNegRunScenario(descriptor, decoded);

    if (result.failure != nil) {
        IRVectorRecordFailure(testCase, @"[%@] the fixture could not be built: %@",
                              vectorCase.identifier, result.failure);
        [vectorCase finish];
        return;
    }

    IRNegCheckSessions(testCase, vectorCase, frozenSessions, result.sessions);

    if (frozenSelected != nil && ![frozenSelected isEqualToString:result.selectedSession ?: @""]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] `selected_session` is \"%@\" but the runner used \"%@\"",
                              vectorCase.identifier, frozenSelected, result.selectedSession);
    }

    for (NSString *key in vectorCase.intermediates) {
        IRNegCheckIntermediate(vectorCase, key, result.intermediates[key]);
    }

    for (NSString *key in vectorCase.outputs) {
        IRNegCheckOutput(testCase, vectorCase, key, result.outputs[key]);
    }

    /* §15.4's whole point: the EXACT code, compared by name so a renumbering is a loud failure in
       all four ports rather than a silent mismatch. */
    [vectorCase checkResultError:result.error];

    [vectorCase finish];
}
