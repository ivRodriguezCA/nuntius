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
#import "IREnvironment.h"
#import "IREnvironment+Testing.h"
#import "IRErrors.h"
#import "IRIdentity.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRProtocolConstants.h"
#import "IRProtocolKDF.h"
#import "IRPublicIdentity.h"
#import "IRRatchet.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSkippedKeyStore.h"
#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

/**
 PROPERTY-BASED SPEC — the suite the v3 tests were not.

 WHY THIS FILE EXISTS, STATED PLAINLY. v3 shipped 23 passing tests over a protocol with thirteen
 confirmed defects (§14). Every one of those tests asserted the same thing: that a plaintext
 encrypted by one party came back out of the other. That assertion is satisfied by a protocol in
 which X3DH has collapsed to a single Diffie-Hellman (defect 1), in which the handshake output never
 reaches the ratchet at all (defect 2), in which the peer's signed prekey is re-signed with the
 LOCAL identity key instead of being verified (defect 3), and in which an RNG failure silently
 yields an all-zero key (defect 4). Both parties still agree. The round trip still closes. Round-trip
 tests cannot see any of it — and a suite that cannot fail is not evidence.

 The properties below are chosen for exactly one reason: each one is FALSE under a specific v3
 defect and TRUE under §-conformant v4. They are the discriminators, not the demonstrations.

   Property                                    v3 defect it would have caught
   ------------------------------------------  --------------------------------------------------
   1  SK depends on every DH input             1  — kdf_derive_from_key read 32 of 128 IKM bytes
   2  Session keys depend on the X3DH output   2  — sharedKey ignored by the ratchet setup
   3  Root key chaining                        2  — performDHRatchet discarded the previous RK
   4  Signature verification is sound          3  — prekey re-signed locally, never verified
   5  Ciphertext integrity                     5, 6, 13 — broken comparator, OOB reads, unvalidated
   6  Forward secrecy                          1, 9 — no FS from the handshake; counters wrapped
   7  Skipped-message bounds                   11 — unbounded store, pruned only on success
   8  Atomicity                                §14.1 — decrypt committed state before the MAC check
   9  KDF domain separation                    §8.1 — one label reused across three semantic roles

 HOW THESE DIFFER FROM THE LAYER GATES. The per-layer specs (IRX3DHSpec, IRRatchetSpec, …) assert
 fixed cases: a named vector, a hand-built input, one bit flipped at one offset. These assert
 UNIVERSALLY QUANTIFIED statements over randomized inputs — "for all handshakes, for every DH term,
 for every bit position". A fixed case proves the implementation handles that case. A property
 proves there is no case it fails to handle, up to the sample.

 DETERMINISM AND SEEDS. Every run is reproducible. IRPropertyRNG is a splitmix64 stream seeded from
 kIRPropertySeeds (the hexadecimal expansion of pi — a nothing-up-my-sleeve set), and it also backs
 the crypto provider's IRRandomSource, so ALL key material, ephemerals and nonces in this file are a
 pure function of the seed. Every assertion message carries `seed=0x...`; a failure therefore names
 the exact seed that produced it, and re-running that seed alone reproduces the input byte for byte.

 That determinism is also what makes property 2 expressible at all: it requires two sessions
 identical in every respect EXCEPT the shared key, including the ratchet key pair that §7.5 has the
 initiator generate internally. Two providers seeded alike generate the same pair, so the shared key
 is genuinely the only difference, and the test asserts that fact before relying on it.

 A property test using a deterministic PRNG for key material is safe here and nowhere else: these
 keys exist for the duration of one XCTest method and protect nothing. §13.1 governs production, and
 IREnvironment.production is the only path a shipping caller can reach.
 */

#pragma mark - Deterministic PRNG

/**
 splitmix64 — 20 lines, no state beyond a uint64, and a full 2^64 period. Statistical quality is
 irrelevant here; reproducibility is the entire requirement. Conforms to IRRandomSource so it can be
 injected into IRSodiumCryptoProvider through IREnvironment (§15.5 rule 6, §19.6).
 */
@interface IRPropertyRNG : NSObject <IRRandomSource>

+ (instancetype _Nonnull)rngWithSeed:(uint64_t)seed;

@property (nonatomic, readonly) uint64_t seed;

- (uint64_t)nextU64;
/// Uniform-enough over [0, bound). The modulo bias is immaterial for choosing a bit index.
- (uint32_t)nextU32Below:(uint32_t)bound;
- (NSData * _Nonnull)dataOfLength:(NSUInteger)length;
- (IRSecretBytes * _Nonnull)secretOfLength:(NSUInteger)length;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

@implementation IRPropertyRNG {
    uint64_t _state;
}

+ (instancetype _Nonnull)rngWithSeed:(uint64_t)seed {
    return [[self alloc] initWithSeed:seed];
}

- (instancetype _Nonnull)initWithSeed:(uint64_t)seed {
    self = [super init];
    if (self != nil) {
        _seed = seed;
        _state = seed;
    }
    return self;
}

- (uint64_t)nextU64 {
    uint64_t z = (_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

- (uint32_t)nextU32Below:(uint32_t)bound {
    NSParameterAssert(bound > 0);
    return (uint32_t)([self nextU64] % (uint64_t)bound);
}

- (BOOL)fillBytes:(void * _Nonnull)buffer
           length:(NSUInteger)length
            error:(NSError * _Nullable * _Nullable)error {
    uint8_t *out = (uint8_t *)buffer;
    NSUInteger i = 0;
    while (i < length) {
        uint64_t word = [self nextU64];
        for (NSUInteger b = 0; b < 8 && i < length; b++, i++) {
            out[i] = (uint8_t)(word >> (8 * b));
        }
    }
    return YES;
}

- (NSData * _Nonnull)dataOfLength:(NSUInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    [self fillBytes:[data mutableBytes] length:length error:NULL];
    return data;
}

- (IRSecretBytes * _Nonnull)secretOfLength:(NSUInteger)length {
    IRSecretBytes *secret = [[IRSecretBytes alloc] initWithLength:length];
    [self fillBytes:[secret mutableBytes] length:length error:NULL];
    return secret;
}

@end

#pragma mark - Deterministic world

/// Everything one seed determines: a provider whose randomness is the seed, two identities, B's
/// prekeys, and the bundle B published. Two worlds built from one seed are byte-identical.
@interface IRPropWorld : NSObject
@property (nonatomic, strong) IRPropertyRNG * _Nonnull rng;
@property (nonatomic, strong) IRSodiumCryptoProvider * _Nonnull provider;
@property (nonatomic, strong) IRIdentity * _Nonnull alice;
@property (nonatomic, strong) IRIdentity * _Nonnull bob;
@property (nonatomic, strong) IRSignedPreKeyRecord * _Nonnull spk;
@property (nonatomic, strong) IROneTimePreKeyRecord * _Nullable opk;
@property (nonatomic, copy) NSData * _Nonnull bundleData;
@property (nonatomic) uint64_t nowS;
@property (nonatomic) uint64_t nowMs;
@end

@implementation IRPropWorld
@end

#pragma mark - Spec

@interface IRPropertySpec : XCTestCase
@end

@implementation IRPropertySpec {
    uint64_t _seed;
}

/// Hexadecimal expansion of pi. Nothing up any sleeve; fixed forever so a failure is reproducible.
static const uint64_t kIRPropertySeeds[] = {
    0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL, 0xA4093822299F31D0ULL,
    0x082EFA98EC4E6C89ULL, 0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL,
    0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL, 0x9216D5D98979FB1BULL,
    0xD1310BA698DFB5ACULL, 0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL,
};
static const NSUInteger kIRPropertySeedCount = sizeof(kIRPropertySeeds) / sizeof(kIRPropertySeeds[0]);

static const uint32_t kSpkId = 0x11223344;
static const uint32_t kOpkId = 0x55667788;

/// Every assertion in this file carries this. A failure names the seed that produced it.
- (NSString * _Nonnull)ctx {
    return [NSString stringWithFormat:@"seed=0x%016llX", (unsigned long long)_seed];
}

#pragma mark - World construction

- (IRPropWorld * _Nullable)worldWithSeed:(uint64_t)seed useOPK:(BOOL)useOPK {
    NSError *error = nil;

    IRPropWorld *world = [[IRPropWorld alloc] init];
    world.nowS = 1700000000ULL;
    world.nowMs = world.nowS * 1000ULL;
    world.rng = [IRPropertyRNG rngWithSeed:seed];

    IREnvironment *environment = [IREnvironment environmentWithRandomSource:world.rng];
    world.provider = [IRSodiumCryptoProvider providerWithEnvironment:environment error:&error];
    XCTAssertNotNil(world.provider, @"%@ %@", self.ctx, error);
    if (world.provider == nil) {
        return nil;
    }

    world.alice = [IRIdentity generateWithProvider:world.provider error:&error];
    XCTAssertNotNil(world.alice, @"%@ %@", self.ctx, error);

    world.bob = [IRIdentity generateWithProvider:world.provider error:&error];
    XCTAssertNotNil(world.bob, @"%@ %@", self.ctx, error);

    world.spk = [IRSignedPreKeyRecord generateWithIdentity:world.bob
                                                    spkId:kSpkId
                                               notBeforeS:world.nowS - 100
                                                notAfterS:world.nowS + 100000
                                                 provider:world.provider
                                                    error:&error];
    XCTAssertNotNil(world.spk, @"%@ %@", self.ctx, error);

    NSArray<IROneTimePreKeyRecord *> *opks = @[];
    if (useOPK) {
        world.opk = [IROneTimePreKeyRecord generateWithOpkId:kOpkId
                                          createdAtUnixSecs:world.nowS
                                                   provider:world.provider
                                                      error:&error];
        XCTAssertNotNil(world.opk, @"%@ %@", self.ctx, error);
        opks = @[ world.opk ];
    }

    world.bundleData = [IRPreKeyBundle serializeWithIdentity:world.bob.publicIdentity
                                         signedPreKeyRecord:world.spk
                                       oneTimePreKeyRecords:opks
                                                      error:&error];
    XCTAssertNotNil(world.bundleData, @"%@ %@", self.ctx, error);

    return world;
}

- (IRPropWorld * _Nullable)worldWithSeed:(uint64_t)seed {
    return [self worldWithSeed:seed useOPK:YES];
}

#pragma mark - Handshake and ratchet harness

/// §6 initiator handshake against B's published bundle. `retainIKM` per §15.5 rule 2's generator mode.
- (IRX3DHResult * _Nullable)initiatorResultInWorld:(IRPropWorld * _Nonnull)world
                                            bundle:(IRPreKeyBundle * _Nullable * _Nullable)outBundle
                                         retainIKM:(BOOL)retainIKM
                                             error:(NSError * _Nullable * _Nullable)error {
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:world.bundleData
                                                   provider:world.provider
                                                      error:error];
    if (bundle == nil) {
        return nil;
    }
    if (outBundle != NULL) {
        *outBundle = bundle;
    }

    IRX25519KeyPair *ephemeral = [world.provider generateX25519KeyPairGuarded:NO error:error];
    if (ephemeral == nil) {
        return nil;
    }

    return [IRX3DH initiatorResultWithIdentity:world.alice
                                        bundle:bundle
                              ephemeralKeyPair:ephemeral
                                nowUnixSeconds:world.nowS
                                      provider:world.provider
                                     retainIKM:retainIKM
                                         error:error];
}

/// §6 + §7.5 initiator side, all the way to a live ratchet state.
- (IRRatchetState * _Nullable)aliceStateInWorld:(IRPropWorld * _Nonnull)world
                                         result:(IRX3DHResult * _Nullable * _Nullable)outResult
                                          error:(NSError * _Nullable * _Nullable)error {
    IRPreKeyBundle *bundle = nil;
    IRX3DHResult *result = [self initiatorResultInWorld:world bundle:&bundle retainIKM:NO error:error];
    if (result == nil) {
        return nil;
    }

    IRRatchetState *state = [IRRatchet initiatorStateWithSharedKey:result.sharedKey
                                             responderSignedPreKey:bundle.signedPreKey
                                                         sessionAD:result.sessionAD
                                                       handshakeId:result.handshakeId
                                                          prologue:result.prologue
                                                          provider:world.provider
                                                             error:error];
    if (outResult != NULL) {
        *outResult = result;
    }
    return state;
}

/**
 §10.7 steps 3, 5, 7, 8–11 plus §7.5's responder initialization, from an already-gated type `0x02`
 header. Step 3 is structural — IRPublicIdentity cannot exist without a verified IKB. Steps 5 and 7
 (resolve `spk_id` and `opk_id` against the store) are performed here rather than assumed, so a test
 that perturbs an id byte gets the failure the spec assigns rather than a transcript mismatch.
 */
- (IRRatchetState * _Nullable)bobStateInWorld:(IRPropWorld * _Nonnull)world
                                    forHeader:(IRMessageHeader * _Nonnull)header
                               sharedKeyOverride:(IRRootKey * _Nullable)sharedKeyOverride
                                        error:(NSError * _Nullable * _Nullable)error {
    IRPublicIdentity *verified = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                              binding:header.identityBinding
                                                             provider:world.provider
                                                                error:error];
    if (verified == nil) {
        return nil;
    }

    /* §10.7 step 5 — resolve spk_id. */
    if (header.spkId != world.spk.spkId) {
        IRSetError(error, IRErrorUnknownPreKeyId);
        return nil;
    }

    /* §10.7 step 7 — resolve opk_id. §6.6 rule 2: no silent fall back to the three-DH form. */
    IROneTimePreKeyRecord *opkRecord = nil;
    if (header.opkFlag == IROPKFlagPresent) {
        if (world.opk == nil || header.opkId != world.opk.opkId) {
            IRSetError(error, IRErrorUnknownPreKeyId);
            return nil;
        }
        opkRecord = world.opk;
    }

    IRX3DHResult *result = [IRX3DH responderResultWithIdentity:world.bob
                                             initiatorIdentity:verified
                                               ephemeralPublic:header.ephemeralPublic
                                              signedPreKeyPair:world.spk.keyPair
                                                         spkId:header.spkId
                                                       opkFlag:header.opkFlag
                                                         opkId:header.opkId
                                             oneTimePreKeyPair:opkRecord.keyPair
                                                      provider:world.provider
                                                     retainIKM:NO
                                                         error:error];
    if (result == nil) {
        return nil;
    }

    IRRatchetState *state = [IRRatchet responderStateWithSharedKey:(sharedKeyOverride ?: result.sharedKey)
                                                 signedPreKeyPair:world.spk.keyPair
                                                        sessionAD:result.sessionAD
                                                      handshakeId:result.handshakeId
                                                            error:error];

    /* §13.3 — SK dies immediately after ratchet initialization. IRRatchet copied rather than
       adopted it, and every end-to-end assertion below runs after this wipe. */
    [result zeroize];

    return state;
}

- (IRRatchetState * _Nullable)bobStateInWorld:(IRPropWorld * _Nonnull)world
                                    forHeader:(IRMessageHeader * _Nonnull)header
                                        error:(NSError * _Nullable * _Nullable)error {
    return [self bobStateInWorld:world forHeader:header sharedKeyOverride:nil error:error];
}

- (NSData * _Nullable)send:(NSData * _Nonnull)plaintext
                      from:(IRRatchetState * _Nonnull)state
                     world:(IRPropWorld * _Nonnull)world
                     error:(NSError * _Nullable * _Nullable)error {
    const BOOL prekey = state.shouldSendPreKeyMessage;
    return [IRRatchet encryptOnState:state
                           plaintext:plaintext
                         messageType:(prekey ? IRMessageTypePrekey : IRMessageTypeNormal)
                   initiatorIdentity:(prekey ? world.alice.identityKeyPair : nil)
                     identityBinding:(prekey ? world.alice.binding : nil)
                            provider:world.provider
                               error:error];
}

- (IRMessageHeader * _Nullable)gate:(NSData * _Nonnull)message
                           forState:(IRRatchetState * _Nullable)liveState
                              error:(NSError * _Nullable * _Nullable)error {
    const IRMessageType type = [IRMessageGate messageTypeOfMessage:message error:error];
    if (type == 0) {
        return nil;
    }
    if (type == IRMessageTypePrekey) {
        return [IRMessageGate parseType02Message:message error:error];
    }
    if (![IRMessageGate gateType01Prefix:message error:error]) {
        return nil;
    }
    return [IRMessageGate parseType01Message:message
                         ownRatchetPublicKey:liveState.DHs.publicKey
                                       error:error];
}

/// IRRatchet.h's four-step receive sequence, verbatim: gate, budget, snapshot, commit-or-discard.
- (NSData * _Nullable)receive:(NSData * _Nonnull)message
                         into:(IRRatchetState * __strong _Nonnull * _Nonnull)live
                        world:(IRPropWorld * _Nonnull)world
                     atTimeMs:(uint64_t)nowMs
                        error:(NSError * _Nullable * _Nullable)error {
    IRRatchetState *liveState = *live;

    IRMessageHeader *header = [self gate:message forState:liveState error:error];
    if (header == nil) {
        return nil;
    }

    IRSkipBudget *budget = [IRSkipBudget budget];

    IRRatchetState *snapshot = [liveState snapshot];
    if (snapshot == nil) {
        return nil;
    }

    NSData *plaintext = [IRRatchet decryptOnSnapshot:snapshot
                                             message:message
                                              header:header
                                              budget:budget
                                            atTimeMs:nowMs
                                            provider:world.provider
                                               error:error];
    if (plaintext == nil) {
        return nil;
    }

    [snapshot.skipped zeroizePendingRemovals];
    [liveState zeroizeAsSupersededState];
    *live = snapshot;

    return plaintext;
}

- (NSData * _Nullable)receive:(NSData * _Nonnull)message
                         into:(IRRatchetState * __strong _Nonnull * _Nonnull)live
                        world:(IRPropWorld * _Nonnull)world
                        error:(NSError * _Nullable * _Nullable)error {
    return [self receive:message into:live world:world atTimeMs:world.nowMs error:error];
}

/// A→B only. On return both sides hold a live session and A's first message has been delivered.
- (BOOL)establishInWorld:(IRPropWorld * _Nonnull)world
                   alice:(IRRatchetState * __strong _Nonnull * _Nonnull)outAlice
                     bob:(IRRatchetState * __strong _Nonnull * _Nonnull)outBob {
    NSError *error = nil;

    IRRatchetState *alice = [self aliceStateInWorld:world result:NULL error:&error];
    XCTAssertNotNil(alice, @"%@ %@", self.ctx, error);
    if (alice == nil) {
        return NO;
    }

    NSData *first = [self send:[self plaintext:@"establish"] from:alice world:world error:&error];
    XCTAssertNotNil(first, @"%@ %@", self.ctx, error);

    IRMessageHeader *header = [self gate:first forState:nil error:&error];
    XCTAssertNotNil(header, @"%@ %@", self.ctx, error);

    IRRatchetState *bob = [self bobStateInWorld:world forHeader:header error:&error];
    XCTAssertNotNil(bob, @"%@ %@", self.ctx, error);
    if (bob == nil) {
        return NO;
    }

    NSData *recovered = [self receive:first into:&bob world:world error:&error];
    XCTAssertEqualObjects(recovered, [self plaintext:@"establish"], @"%@ %@", self.ctx, error);

    *outAlice = alice;
    *outBob = bob;
    return recovered != nil;
}

/// As above, then B replies and A receives it — so A's prologue clears (§11.3) and A's next message
/// is a type `0x01`.
- (BOOL)establishBidirectionalInWorld:(IRPropWorld * _Nonnull)world
                                alice:(IRRatchetState * __strong _Nonnull * _Nonnull)outAlice
                                  bob:(IRRatchetState * __strong _Nonnull * _Nonnull)outBob {
    NSError *error = nil;

    IRRatchetState *alice = nil;
    IRRatchetState *bob = nil;
    if (![self establishInWorld:world alice:&alice bob:&bob]) {
        return NO;
    }

    NSData *reply = [self send:[self plaintext:@"reply"] from:bob world:world error:&error];
    XCTAssertNotNil(reply, @"%@ %@", self.ctx, error);

    NSData *recovered = [self receive:reply into:&alice world:world error:&error];
    XCTAssertEqualObjects(recovered, [self plaintext:@"reply"], @"%@ %@", self.ctx, error);

    XCTAssertFalse(alice.shouldSendPreKeyMessage, @"%@ §11.3 — prologue must clear", self.ctx);

    *outAlice = alice;
    *outBob = bob;
    return recovered != nil;
}

#pragma mark - Small helpers

- (NSData * _Nonnull)plaintext:(NSString * _Nonnull)text {
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData * _Nonnull)data:(NSData * _Nonnull)source withBitFlippedAt:(NSUInteger)bitIndex {
    NSMutableData *mutable = [source mutableCopy];
    uint8_t *bytes = (uint8_t *)[mutable mutableBytes];
    bytes[bitIndex / 8] ^= (uint8_t)(1u << (bitIndex % 8));
    return mutable;
}

- (IRSecretBytes * _Nonnull)secret:(IRSecretBytes * _Nonnull)source withBitFlippedAt:(NSUInteger)bitIndex {
    IRSecretBytes *copy = [[IRSecretBytes alloc] initWithBytes:[source constBytes] length:source.length];
    [copy mutableBytes][bitIndex / 8] ^= (uint8_t)(1u << (bitIndex % 8));
    return copy;
}

- (IRRootKey * _Nullable)rootKey:(IRRootKey * _Nonnull)source withBitFlippedAt:(NSUInteger)bitIndex {
    uint8_t bytes[kIRLenRootKey];
    memcpy(bytes, [source constBytes], sizeof(bytes));
    bytes[bitIndex / 8] ^= (uint8_t)(1u << (bitIndex % 8));

    NSError *error = nil;
    IRRootKey *key = [IRRootKey fromBytes:bytes guarded:NO error:&error];
    XCTAssertNotNil(key, @"%@ %@", self.ctx, error);

    IRZeroize(bytes, sizeof(bytes));
    return key;
}

/// §12.1 serialization, copied out for comparison. The blob is the whole of the mutable session
/// state, which is what makes it the right instrument for property 8.
- (NSData * _Nullable)stateBytes:(IRRatchetState * _Nonnull)state {
    NSError *error = nil;
    IRSecretBytes *blob = [IRSessionStateCodec serializeState:state error:&error];
    XCTAssertNotNil(blob, @"%@ %@", self.ctx, error);
    if (blob == nil) {
        return nil;
    }
    NSData *copy = [NSData dataWithBytes:[blob constBytes] length:blob.length];
    [blob zeroizeNow];
    return copy;
}

- (NSData * _Nonnull)bytesOfSecret:(IRSecretBytes * _Nonnull)secret {
    return [NSData dataWithBytes:[secret constBytes] length:secret.length];
}

#pragma mark - Property 1 — SK depends on every DH input (defect 1)

/**
 THE PROPERTY: for every handshake and every one of DH1…DH4, perturbing that term alone changes SK.

 THE DEFECT IT CATCHES: v3 passed the 128-byte IKM to `crypto_kdf_derive_from_key`, whose key
 parameter is `unsigned char k[32]`. Exactly 32 bytes were read; DH2, DH3 and DH4 were discarded and
 X3DH silently collapsed to a single Diffie-Hellman between two long-lived keys. Both parties still
 derived the same SK, so every round-trip test passed.

 WHY THE PERTURBATION IS AT THE IKM AND NOT AT THE KEYS. Changing a key changes the transcript hash
 too (§6.2 covers every key and id), so SK would move for two reasons and the test would no longer
 isolate the DH contribution. Perturbing one 32-byte slice of the retained IKM with TH held fixed is
 the only construction that isolates a single DH term — which is why §15.4 specifies
 NEG-DH{2,3,4}-ALTERED that way. Offset 0 (`F32`) is included: v3 computed that separator into a
 local and then commented out its use (IRTripleDHService.m:92-93, :112).
 */
- (void)testProperty1_SharedKeyDependsOnEveryDHInput_WithOPK {
    [self assertSharedKeyDependsOnEveryIKMRegionWithOPK:YES];
}

- (void)testProperty1_SharedKeyDependsOnEveryDHInput_NoOPK {
    [self assertSharedKeyDependsOnEveryIKMRegionWithOPK:NO];
}

- (void)assertSharedKeyDependsOnEveryIKMRegionWithOPK:(BOOL)useOPK {
    const NSUInteger regionOffsets[] = {
        kIROffIKMSeparator, kIROffIKMDH1, kIROffIKMDH2, kIROffIKMDH3, kIROffIKMDH4,
    };
    NSArray<NSString *> *regionNames = @[ @"F32", @"DH1", @"DH2", @"DH3", @"DH4" ];
    const NSUInteger regionCount = useOPK ? 5 : 4;

    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed useOPK:useOPK];
        NSError *error = nil;

        IRX3DHResult *result = [self initiatorResultInWorld:world bundle:NULL retainIKM:YES error:&error];
        XCTAssertNotNil(result, @"%@ %@", self.ctx, error);
        if (result == nil) {
            continue;
        }

        IRSecretBytes *ikm = result.ikm;
        XCTAssertNotNil(ikm, @"%@ retainIKM:YES must expose the IKM", self.ctx);

        const NSUInteger expectedIKMLength = useOPK ? (NSUInteger)kIRLenIKMOPK : (NSUInteger)kIRLenIKMNoOPK;
        XCTAssertEqual(ikm.length, expectedIKMLength,
                       @"%@ §6.3 — len(IKM) is 160 with an OPK and 128 without; DH4 is OMITTED, "
                       @"never zero-filled", self.ctx);

        NSData *transcriptHash = result.transcriptHash;

        /* Sanity: we are reproducing the real derivation, not a parallel one. */
        IRRootKey *baseline = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                                     transcriptHash:transcriptHash
                                                           provider:world.provider
                                                              error:&error];
        XCTAssertNotNil(baseline, @"%@ %@", self.ctx, error);
        XCTAssertTrue([baseline isEqualToSecretBytes:result.sharedKey],
                      @"%@ the re-derivation must reproduce IRX3DH's own SK", self.ctx);

        for (NSUInteger r = 0; r < regionCount; r++) {
            const uint32_t bitInRegion = [world.rng nextU32Below:(uint32_t)(kIRLenDHOutput * 8)];
            const NSUInteger absoluteBit = regionOffsets[r] * 8 + bitInRegion;

            IRSecretBytes *perturbed = [self secret:ikm withBitFlippedAt:absoluteBit];
            IRRootKey *perturbedSK = [IRProtocolKDF deriveSharedKeyWithIKM:perturbed
                                                            transcriptHash:transcriptHash
                                                                  provider:world.provider
                                                                     error:&error];
            XCTAssertNotNil(perturbedSK, @"%@ %@", self.ctx, error);

            XCTAssertFalse([perturbedSK isEqualToSecretBytes:baseline],
                           @"%@ region=%@ bit=%u — SK did not change. THIS IS DEFECT 1: the KDF is "
                           @"not reading the whole IKM.",
                           self.ctx, regionNames[r], bitInRegion);

            [perturbed zeroizeNow];
        }

        [result zeroize];
    }
}

/**
 The structural companion: which one-time prekey was consumed changes SK. Unlike the IKM
 perturbation this cannot isolate DH4 — §6.2 puts `OPK_B` and `opk_id` in the transcript too, so
 both the DH set and TH move — but it is the form the property takes in the real world, and under
 v3 it did not hold at all: only DH1 was read, and DH1 involves no one-time prekey.
 */
- (void)testProperty1_SharedKeyDependsOnWhichOneTimePreKeyWasUsed {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed useOPK:YES];
        NSError *error = nil;

        IRX3DHResult *withOPK = [self initiatorResultInWorld:world bundle:NULL retainIKM:NO error:&error];
        XCTAssertNotNil(withOPK, @"%@ %@", self.ctx, error);

        /* A second bundle from the same identity and SPK, carrying a DIFFERENT one-time prekey. */
        IROneTimePreKeyRecord *otherOPK = [IROneTimePreKeyRecord generateWithOpkId:kOpkId
                                                                createdAtUnixSecs:world.nowS
                                                                         provider:world.provider
                                                                            error:&error];
        XCTAssertNotNil(otherOPK, @"%@ %@", self.ctx, error);

        IRPropWorld *variant = [[IRPropWorld alloc] init];
        variant.rng = world.rng;
        variant.provider = world.provider;
        variant.alice = world.alice;
        variant.bob = world.bob;
        variant.spk = world.spk;
        variant.opk = otherOPK;
        variant.nowS = world.nowS;
        variant.nowMs = world.nowMs;
        variant.bundleData = [IRPreKeyBundle serializeWithIdentity:world.bob.publicIdentity
                                               signedPreKeyRecord:world.spk
                                             oneTimePreKeyRecords:@[ otherOPK ]
                                                            error:&error];
        XCTAssertNotNil(variant.bundleData, @"%@ %@", self.ctx, error);

        IRX3DHResult *withOtherOPK = [self initiatorResultInWorld:variant bundle:NULL retainIKM:NO error:&error];
        XCTAssertNotNil(withOtherOPK, @"%@ %@", self.ctx, error);

        XCTAssertFalse([withOPK.sharedKey isEqualToSecretBytes:withOtherOPK.sharedKey],
                       @"%@ two handshakes differing only in the consumed one-time prekey produced "
                       @"the SAME shared key — the OPK contributes nothing (defect 1)", self.ctx);

        /* And the no-OPK form differs from both: §6.3 omits DH4 rather than zero-filling it. */
        IRPropWorld *noOPKWorld = [self worldWithSeed:_seed useOPK:NO];
        IRX3DHResult *withoutOPK = [self initiatorResultInWorld:noOPKWorld bundle:NULL retainIKM:NO error:&error];
        XCTAssertNotNil(withoutOPK, @"%@ %@", self.ctx, error);
        XCTAssertFalse([withOPK.sharedKey isEqualToSecretBytes:withoutOPK.sharedKey],
                       @"%@ the three-DH and four-DH forms agreed", self.ctx);

        [withOPK zeroize];
        [withOtherOPK zeroize];
        [withoutOPK zeroize];
    }
}

#pragma mark - Property 2 — session keys depend on the X3DH output (defect 2)

/**
 THE PROPERTY: a responder whose shared key differs from the initiator's — by one bit — cannot
 decrypt. Equivalently: the ratchet is a function of SK.

 THE DEFECT IT CATCHES: v3's `setupRatchetForSendingWithSharedKey:andDHReceiverKey:`
 (IRDoubleRatchetService.m:80-102) never read its `sharedKey` argument. The two sides initialised
 asymmetrically and no message key was a function of the handshake at all. Under v3 THIS TEST'S
 ASSERTION IS FALSE: the wrong-SK responder decrypts happily, because SK was never consulted.

 Note the control at the end. Asserting only that the perturbed session fails would also pass if the
 session were broken for some unrelated reason; the same message must decrypt under the correct SK.
 */
- (void)testProperty2_ResponderWithAPerturbedSharedKeyCannotDecrypt {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = [self aliceStateInWorld:world result:NULL error:&error];
        XCTAssertNotNil(alice, @"%@ %@", self.ctx, error);

        NSData *message = [self send:[self plaintext:@"depends on SK"] from:alice world:world error:&error];
        XCTAssertNotNil(message, @"%@ %@", self.ctx, error);

        IRMessageHeader *header = [self gate:message forState:nil error:&error];
        XCTAssertNotNil(header, @"%@ %@", self.ctx, error);

        /* B's own handshake — the SK both sides agree on. */
        IRPublicIdentity *verified = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                                  binding:header.identityBinding
                                                                 provider:world.provider
                                                                    error:&error];
        XCTAssertNotNil(verified, @"%@ %@", self.ctx, error);

        IRX3DHResult *bobResult = [IRX3DH responderResultWithIdentity:world.bob
                                                    initiatorIdentity:verified
                                                      ephemeralPublic:header.ephemeralPublic
                                                     signedPreKeyPair:world.spk.keyPair
                                                                spkId:header.spkId
                                                              opkFlag:header.opkFlag
                                                                opkId:header.opkId
                                                    oneTimePreKeyPair:world.opk.keyPair
                                                             provider:world.provider
                                                            retainIKM:NO
                                                                error:&error];
        XCTAssertNotNil(bobResult, @"%@ %@", self.ctx, error);

        const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenSK * 8)];
        IRRootKey *perturbedSK = [self rootKey:bobResult.sharedKey withBitFlippedAt:bit];

        IRRatchetState *bobWrong = [IRRatchet responderStateWithSharedKey:perturbedSK
                                                        signedPreKeyPair:world.spk.keyPair
                                                               sessionAD:bobResult.sessionAD
                                                             handshakeId:bobResult.handshakeId
                                                                   error:&error];
        XCTAssertNotNil(bobWrong, @"%@ %@", self.ctx, error);

        error = nil;
        NSData *forged = [self receive:message into:&bobWrong world:world error:&error];
        XCTAssertNil(forged,
                     @"%@ bit=%u — a responder holding a ONE-BIT-DIFFERENT shared key decrypted the "
                     @"message. THIS IS DEFECT 2: the ratchet is ignoring the X3DH output.",
                     self.ctx, bit);
        XCTAssertEqual(error.code, (NSInteger)IRErrorAEADAuthFailed, @"%@ %@", self.ctx, error);

        /* Control: the identical message under the correct SK. */
        IRRatchetState *bobRight = [IRRatchet responderStateWithSharedKey:bobResult.sharedKey
                                                        signedPreKeyPair:world.spk.keyPair
                                                               sessionAD:bobResult.sessionAD
                                                             handshakeId:bobResult.handshakeId
                                                                   error:&error];
        XCTAssertNotNil(bobRight, @"%@ %@", self.ctx, error);

        NSData *recovered = [self receive:message into:&bobRight world:world error:&error];
        XCTAssertEqualObjects(recovered, [self plaintext:@"depends on SK"], @"%@ %@", self.ctx, error);

        [bobResult zeroize];
    }
}

/**
 The finer-grained form: hold EVERYTHING else fixed — including the ratchet key pair §7.5 has the
 initiator generate internally — and change only SK. Every derived message key must move.

 The two providers are seeded identically, so `initiatorStateWithSharedKey:` generates the same
 `DHs` in both runs. That is asserted rather than assumed: without it the test would be comparing
 two unrelated sessions and would pass for the wrong reason.
 */
- (void)testProperty2_EveryMessageKeyChangesWhenTheSharedKeyChanges {
    const NSUInteger chainDepth = 16;

    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRPreKeyBundle *bundle = nil;
        IRX3DHResult *result = [self initiatorResultInWorld:world bundle:&bundle retainIKM:NO error:&error];
        XCTAssertNotNil(result, @"%@ %@", self.ctx, error);

        const uint64_t pairedSeed = _seed ^ 0x5DEECE66DEECE66DULL;
        IREnvironment *envA = [IREnvironment environmentWithRandomSource:[IRPropertyRNG rngWithSeed:pairedSeed]];
        IREnvironment *envB = [IREnvironment environmentWithRandomSource:[IRPropertyRNG rngWithSeed:pairedSeed]];
        IRSodiumCryptoProvider *providerA = [IRSodiumCryptoProvider providerWithEnvironment:envA error:&error];
        IRSodiumCryptoProvider *providerB = [IRSodiumCryptoProvider providerWithEnvironment:envB error:&error];
        XCTAssertNotNil(providerA, @"%@ %@", self.ctx, error);
        XCTAssertNotNil(providerB, @"%@ %@", self.ctx, error);

        const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenSK * 8)];
        IRRootKey *skA = result.sharedKey;
        IRRootKey *skB = [self rootKey:skA withBitFlippedAt:bit];

        IRRatchetState *stateA = [IRRatchet initiatorStateWithSharedKey:skA
                                                 responderSignedPreKey:bundle.signedPreKey
                                                             sessionAD:result.sessionAD
                                                           handshakeId:result.handshakeId
                                                              prologue:result.prologue
                                                              provider:providerA
                                                                 error:&error];
        XCTAssertNotNil(stateA, @"%@ %@", self.ctx, error);

        IRRatchetState *stateB = [IRRatchet initiatorStateWithSharedKey:skB
                                                 responderSignedPreKey:bundle.signedPreKey
                                                             sessionAD:result.sessionAD
                                                           handshakeId:result.handshakeId
                                                              prologue:result.prologue
                                                              provider:providerB
                                                                 error:&error];
        XCTAssertNotNil(stateB, @"%@ %@", self.ctx, error);

        /* "Everything else fixed" is a claim, so it is checked. */
        XCTAssertTrue([stateA.DHs.publicKey isEqualToX25519Public:stateB.DHs.publicKey],
                      @"%@ the two sessions must differ ONLY in SK", self.ctx);

        XCTAssertFalse([stateA.RK isEqualToSecretBytes:stateB.RK],
                       @"%@ bit=%u — the root key did not change with SK (defect 2)", self.ctx, bit);
        XCTAssertFalse([stateA.CKs isEqualToSecretBytes:stateB.CKs],
                       @"%@ bit=%u — the sending chain key did not change with SK (defect 2)",
                       self.ctx, bit);

        IRChainKey *chainA = stateA.CKs;
        IRChainKey *chainB = stateB.CKs;
        for (NSUInteger i = 0; i < chainDepth; i++) {
            IRChainStep *stepA = [IRProtocolKDF deriveChainStepWithChainKey:chainA
                                                                   provider:world.provider
                                                                      error:&error];
            IRChainStep *stepB = [IRProtocolKDF deriveChainStepWithChainKey:chainB
                                                                   provider:world.provider
                                                                      error:&error];
            XCTAssertNotNil(stepA, @"%@ %@", self.ctx, error);
            XCTAssertNotNil(stepB, @"%@ %@", self.ctx, error);

            XCTAssertFalse([stepA.messageKey isEqualToSecretBytes:stepB.messageKey],
                           @"%@ bit=%u i=%lu — message key %lu is identical under two different "
                           @"shared keys (defect 2)",
                           self.ctx, bit, (unsigned long)i, (unsigned long)i);

            chainA = stepA.nextChainKey;
            chainB = stepB.nextChainKey;
        }

        [result zeroize];
    }
}

#pragma mark - Property 3 — root key chaining (defect 2)

/**
 THE PROPERTY: two DH ratchet steps driven by the identical DH output but starting from different
 root keys produce different results — at every step, in both outputs.

 THE DEFECT IT CATCHES: v3's `performDHRatchet:` derived from the DH output alone and discarded the
 previous root key, so the root chain carried no history. §7.2 makes the previous RK the MANDATORY
 HKDF salt, which is why the parameter is named `RootKeyAsSalt`: HKDF-Extract cannot be invoked
 without a salt argument, so "forgot to chain the previous root key" is not expressible.
 */
- (void)testProperty3_RootChainingTwoStepsWithIdenticalDHDifferByPriorRootKey {
    const NSUInteger stepCount = 2;

    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropertyRNG *rng = [IRPropertyRNG rngWithSeed:_seed];
        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* One fixed DH output sequence, shared by both chains. */
        NSMutableArray<IRSecretBytes *> *dhOutputs = [NSMutableArray array];
        for (NSUInteger i = 0; i < stepCount; i++) {
            [dhOutputs addObject:[rng secretOfLength:kIRLenDHOutput]];
        }

        IRSecretBytes *rootSeed = [rng secretOfLength:kIRLenRootKey];
        IRRootKey *rootA = [IRRootKey fromBytes:[rootSeed constBytes] guarded:NO error:&error];
        XCTAssertNotNil(rootA, @"%@ %@", self.ctx, error);

        const uint32_t bit = [rng nextU32Below:(uint32_t)(kIRLenRootKey * 8)];
        IRRootKey *rootB = [self rootKey:rootA withBitFlippedAt:bit];

        for (NSUInteger i = 0; i < stepCount; i++) {
            IRRootChainStep *stepA = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootA
                                                                           dhOutput:dhOutputs[i]
                                                                           provider:world.provider
                                                                              error:&error];
            IRRootChainStep *stepB = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootB
                                                                           dhOutput:dhOutputs[i]
                                                                           provider:world.provider
                                                                              error:&error];
            XCTAssertNotNil(stepA, @"%@ %@", self.ctx, error);
            XCTAssertNotNil(stepB, @"%@ %@", self.ctx, error);

            XCTAssertFalse([stepA.rootKey isEqualToSecretBytes:stepB.rootKey],
                           @"%@ bit=%u step=%lu — identical DH output and DIFFERENT prior root keys "
                           @"produced the same next root key. THIS IS DEFECT 2: the root chain is "
                           @"not chaining.",
                           self.ctx, bit, (unsigned long)i);
            XCTAssertFalse([stepA.chainKey isEqualToSecretBytes:stepB.chainKey],
                           @"%@ bit=%u step=%lu — same for the chain key", self.ctx, bit, (unsigned long)i);

            /* §7.2's split must not alias: okm[0..32) and okm[32..64) are different halves. */
            XCTAssertFalse([stepA.rootKey isEqualToSecretBytes:stepA.chainKey],
                           @"%@ step=%lu — KDF_RK returned the same 32 bytes twice", self.ctx,
                           (unsigned long)i);

            rootA = stepA.rootKey;
            rootB = stepB.rootKey;
        }
    }
}

/// The converse direction: with the root key held fixed, the DH output must still drive the result.
- (void)testProperty3_RootStepDependsOnTheDHOutputToo {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropertyRNG *rng = [IRPropertyRNG rngWithSeed:_seed];
        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRSecretBytes *rootSeed = [rng secretOfLength:kIRLenRootKey];
        IRRootKey *root = [IRRootKey fromBytes:[rootSeed constBytes] guarded:NO error:&error];
        XCTAssertNotNil(root, @"%@ %@", self.ctx, error);

        IRSecretBytes *dh = [rng secretOfLength:kIRLenDHOutput];
        const uint32_t bit = [rng nextU32Below:(uint32_t)(kIRLenDHOutput * 8)];
        IRSecretBytes *dhPerturbed = [self secret:dh withBitFlippedAt:bit];

        IRRootChainStep *base = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:root
                                                                      dhOutput:dh
                                                                      provider:world.provider
                                                                         error:&error];
        IRRootChainStep *moved = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:root
                                                                       dhOutput:dhPerturbed
                                                                       provider:world.provider
                                                                          error:&error];
        XCTAssertNotNil(base, @"%@ %@", self.ctx, error);
        XCTAssertNotNil(moved, @"%@ %@", self.ctx, error);

        XCTAssertFalse([base.rootKey isEqualToSecretBytes:moved.rootKey],
                       @"%@ bit=%u — the DH output does not reach the root key", self.ctx, bit);
        XCTAssertFalse([base.chainKey isEqualToSecretBytes:moved.chainKey],
                       @"%@ bit=%u — the DH output does not reach the chain key", self.ctx, bit);
    }
}

#pragma mark - Property 4 — signature verification is sound (defect 3)

/**
 THE PROPERTY: a tampered identity binding is always rejected, and a signature that is perfectly
 valid under the WRONG identity key is always rejected.

 THE DEFECT IT CATCHES: v3 never verified signed prekeys at all — `initWithData:`
 (IRTripleDHService.m:66-68) RE-SIGNED the peer's prekey with the LOCAL identity key. A round-trip
 test cannot see this: the local re-signature always verifies. The second half of this property is
 the sharp one, because "valid signature, wrong signer" is exactly the shape of that bug.
 */
- (void)testProperty4_TamperedIdentityBindingIsRejected {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* Control: the genuine binding verifies. */
        IRPublicIdentity *genuine = [IRPublicIdentity identityWithKeyPair:world.alice.identityKeyPair
                                                                 binding:world.alice.binding
                                                                provider:world.provider
                                                                   error:&error];
        XCTAssertNotNil(genuine, @"%@ %@", self.ctx, error);

        for (NSUInteger trial = 0; trial < 8; trial++) {
            const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenEd25519Signature * 8)];
            NSData *tampered = [self data:world.alice.binding.data withBitFlippedAt:bit];

            IREd25519Signature *signature = [IREd25519Signature fromData:tampered error:&error];
            XCTAssertNotNil(signature, @"%@ %@", self.ctx, error);

            error = nil;
            IRPublicIdentity *forged = [IRPublicIdentity identityWithKeyPair:world.alice.identityKeyPair
                                                                    binding:signature
                                                                   provider:world.provider
                                                                      error:&error];
            XCTAssertNil(forged, @"%@ bit=%u — a tampered IKB was accepted", self.ctx, bit);
            XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ bit=%u %@", self.ctx, bit, error);
        }
    }
}

- (void)testProperty4_ValidSignatureUnderTheWrongIdentityKeyIsRejected {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRIdentity *mallory = [IRIdentity generateWithProvider:world.provider error:&error];
        XCTAssertNotNil(mallory, @"%@ %@", self.ctx, error);

        /* (a) A signature over the CORRECT message, produced by the WRONG signer. Everything about
               it is well-formed; only the key that made it is wrong. */
        NSData *bindMessage = IRIKBindMessage(world.alice.identityKeyPair, &error);
        XCTAssertNotNil(bindMessage, @"%@ %@", self.ctx, error);
        XCTAssertEqual(bindMessage.length, (NSUInteger)kIRLenIKBindMsg, @"%@", self.ctx);

        IREd25519Signature *wrongSigner = [mallory signData:bindMessage error:&error];
        XCTAssertNotNil(wrongSigner, @"%@ %@", self.ctx, error);

        error = nil;
        IRPublicIdentity *forged = [IRPublicIdentity identityWithKeyPair:world.alice.identityKeyPair
                                                                binding:wrongSigner
                                                               provider:world.provider
                                                                  error:&error];
        XCTAssertNil(forged,
                     @"%@ a binding signed by the WRONG identity key was accepted. THIS IS DEFECT 3: "
                     @"the verifier is not checking the signer.", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ %@", self.ctx, error);

        /* (b) §5.5's attack run directly: a genuine binding presented beside another party's keys. */
        error = nil;
        IRPublicIdentity *swapped = [IRPublicIdentity identityWithKeyPair:world.alice.identityKeyPair
                                                                 binding:mallory.binding
                                                                provider:world.provider
                                                                   error:&error];
        XCTAssertNil(swapped, @"%@ a binding was accepted beside a foreign key pair", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ %@", self.ctx, error);

        /* (c) The victim's genuine IK^s beside an attacker's IK^d — §5.5's stated motivation for
               binding the PAIR rather than each key alone. */
        IRIdentityKeyPair *mixed = [IRIdentityKeyPair pairWithSigningKey:world.alice.identityKeyPair.signingKey
                                                           agreementKey:mallory.identityKeyPair.agreementKey
                                                                  error:&error];
        XCTAssertNotNil(mixed, @"%@ %@", self.ctx, error);

        error = nil;
        IRPublicIdentity *mixedIdentity = [IRPublicIdentity identityWithKeyPair:mixed
                                                                       binding:world.alice.binding
                                                                      provider:world.provider
                                                                         error:&error];
        XCTAssertNil(mixedIdentity,
                     @"%@ §5.5 — a genuine IK^s beside a foreign IK^d was accepted", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ %@", self.ctx, error);
    }
}

- (void)testProperty4_TamperedSignedPreKeySignatureIsRejected {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* Control. */
        IRPreKeyBundle *genuine = [IRPreKeyBundle bundleFromData:world.bundleData
                                                        provider:world.provider
                                                           error:&error];
        XCTAssertNotNil(genuine, @"%@ %@", self.ctx, error);

        /* (a) Flip a bit of SPK_SIG. Nothing else in §10.3/§5.3 inspects those 64 bytes, so the
               code is exactly ERR_BAD_SIGNATURE. */
        for (NSUInteger trial = 0; trial < 8; trial++) {
            const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenEd25519Signature * 8)];
            NSData *tampered = [self data:world.bundleData
                         withBitFlippedAt:(NSUInteger)kIROffBundleSPKSig * 8 + bit];

            error = nil;
            IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:tampered
                                                           provider:world.provider
                                                              error:&error];
            XCTAssertNil(bundle, @"%@ bit=%u — a tampered SPK_SIG was accepted", self.ctx, bit);
            XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ bit=%u %@", self.ctx, bit, error);
        }

        /* (b) Flip a bit of the signed prekey itself. The signature covers it (§5.2), so this is a
               signature failure — unless the flip lands on bit 255, which §5.3 rule 2 rejects first
               as an invalid public key. Both are rejections; the union is asserted. */
        for (NSUInteger trial = 0; trial < 8; trial++) {
            const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenX25519Public * 8)];
            NSData *tampered = [self data:world.bundleData
                         withBitFlippedAt:(NSUInteger)kIROffBundleSPK * 8 + bit];

            error = nil;
            IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:tampered
                                                           provider:world.provider
                                                              error:&error];
            XCTAssertNil(bundle, @"%@ bit=%u — a tampered SPK was accepted", self.ctx, bit);
            XCTAssertTrue(error.code == (NSInteger)IRErrorBadSignature ||
                          error.code == (NSInteger)IRErrorInvalidPublicKey,
                          @"%@ bit=%u unexpected code %ld", self.ctx, bit, (long)error.code);
        }

        /* (c) Flip a bit of IKB inside the bundle. */
        for (NSUInteger trial = 0; trial < 8; trial++) {
            const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenEd25519Signature * 8)];
            NSData *tampered = [self data:world.bundleData
                         withBitFlippedAt:(NSUInteger)kIROffBundleIKB * 8 + bit];

            error = nil;
            IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:tampered
                                                           provider:world.provider
                                                              error:&error];
            XCTAssertNil(bundle, @"%@ bit=%u — a tampered IKB was accepted in a bundle", self.ctx, bit);
            XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ bit=%u %@", self.ctx, bit, error);
        }
    }
}

/**
 The precise shape of defect 3: the signature is cryptographically valid, over a correctly formed
 §5.2 message naming the right identity keys, the right `spk_id` and the right prekey — and it was
 made by a different Ed25519 key. Nothing but checking the signer catches it.
 */
- (void)testProperty4_SignedPreKeySignedByTheWrongIdentityIsRejected {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRIdentity *mallory = [IRIdentity generateWithProvider:world.provider error:&error];
        XCTAssertNotNil(mallory, @"%@ %@", self.ctx, error);

        const uint64_t notBefore = world.nowS - 100;
        const uint64_t notAfter = world.nowS + 100000;

        /* The §5.2 message naming B's identity and B's signed prekey — signed by Mallory. */
        NSData *spkMessage = IRSPKSignMessage(world.bob.identityKeyPair,
                                              kSpkId,
                                              world.spk.keyPair.publicKey,
                                              notBefore,
                                              notAfter,
                                              &error);
        XCTAssertNotNil(spkMessage, @"%@ %@", self.ctx, error);
        XCTAssertEqual(spkMessage.length, (NSUInteger)kIRLenSPKSignMsg, @"%@", self.ctx);

        IREd25519Signature *wrongSigner = [mallory signData:spkMessage error:&error];
        XCTAssertNotNil(wrongSigner, @"%@ %@", self.ctx, error);

        NSData *forgedBundle = [IRPreKeyBundle serializeWithIdentity:world.bob.publicIdentity
                                                              spkId:kSpkId
                                                       signedPreKey:world.spk.keyPair.publicKey
                                                         notBeforeS:notBefore
                                                          notAfterS:notAfter
                                              signedPreKeySignature:wrongSigner
                                                         opkEntries:@[]
                                                              error:&error];
        XCTAssertNotNil(forgedBundle, @"%@ %@", self.ctx, error);

        error = nil;
        IRPreKeyBundle *parsed = [IRPreKeyBundle bundleFromData:forgedBundle
                                                       provider:world.provider
                                                          error:&error];
        XCTAssertNil(parsed,
                     @"%@ a signed prekey signed by the WRONG identity key was accepted. THIS IS "
                     @"DEFECT 3: the bundle is not verifying the signer.", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorBadSignature, @"%@ %@", self.ctx, error);

        /* And the same signature IS valid under Mallory's own identity — proving the rejection is
           about the signer and not about a malformed signature. */
        NSData *mallorySPKMessage = IRSPKSignMessage(mallory.identityKeyPair,
                                                     kSpkId,
                                                     world.spk.keyPair.publicKey,
                                                     notBefore,
                                                     notAfter,
                                                     &error);
        XCTAssertNotNil(mallorySPKMessage, @"%@ %@", self.ctx, error);

        IREd25519Signature *mallorySignature = [mallory signData:mallorySPKMessage error:&error];
        XCTAssertNotNil(mallorySignature, @"%@ %@", self.ctx, error);

        NSData *malloryBundle = [IRPreKeyBundle serializeWithIdentity:mallory.publicIdentity
                                                               spkId:kSpkId
                                                        signedPreKey:world.spk.keyPair.publicKey
                                                          notBeforeS:notBefore
                                                           notAfterS:notAfter
                                               signedPreKeySignature:mallorySignature
                                                          opkEntries:@[]
                                                               error:&error];
        XCTAssertNotNil(malloryBundle, @"%@ %@", self.ctx, error);

        error = nil;
        IRPreKeyBundle *malloryParsed = [IRPreKeyBundle bundleFromData:malloryBundle
                                                              provider:world.provider
                                                                 error:&error];
        XCTAssertNotNil(malloryParsed,
                        @"%@ the control bundle must parse — otherwise the rejection above proves "
                        @"nothing about the signer %@", self.ctx, error);
    }
}

#pragma mark - Property 5 — ciphertext integrity (defects 5, 6, 13)

/**
 THE PROPERTY: flipping ANY single bit of a message — header, ciphertext or tag — makes decryption
 fail. Every bit position, exhaustively, not a sample.

 THE DEFECTS IT CATCHES: v3's `consistentTimeEqual:` was neither constant-time nor correct (defect
 5); the header was read with `*(NSInteger *)` casts off possibly-shorter NSData (defect 6); and
 version and options bytes were read and then explicitly NOT validated — the check is present in the
 source, commented out (defect 13). Under v4 the version, type and flags bytes are covered twice:
 by the §10 ordered gate and, because §8.5 puts the entire header into the AEAD associated data, by
 the Poly1305 tag as well.

 The sweep asserts the sharp thing where it is available: a flip anywhere in the ciphertext or tag
 region has no gate to trip, so the code must be exactly ERR_AEAD_AUTH_FAILED. Header flips may
 legitimately fail earlier and for many different reasons, so those assert rejection plus a code
 from the §10.5 taxonomy.

 The final control matters as much as the sweep: after ~600 failed deliveries the untouched message
 must still decrypt. That is property 8 holding under load, and without it a session that had simply
 died would pass the whole sweep.
 */
- (void)testProperty5_EveryBitFlipInAType01MessageFailsToDecrypt {
    const NSUInteger seedCount = 3;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        NSData *body = [self plaintext:@"int"];
        NSData *message = [self send:body from:alice world:world error:&error];
        XCTAssertNotNil(message, @"%@ %@", self.ctx, error);
        XCTAssertEqual(message.length,
                       (NSUInteger)kIRLenType01Header + body.length + (NSUInteger)kIRLenAEADTag,
                       @"%@ §9.1 total = 56 + L + 16", self.ctx);

        const NSUInteger bitCount = message.length * 8;
        const NSUInteger ciphertextBitStart = (NSUInteger)kIRLenType01Header * 8;
        NSUInteger authFailures = 0;

        for (NSUInteger bit = 0; bit < bitCount; bit++) {
            NSData *corrupted = [self data:message withBitFlippedAt:bit];

            error = nil;
            NSData *plaintext = [self receive:corrupted into:&bob world:world error:&error];

            XCTAssertNil(plaintext,
                         @"%@ bit=%lu of %lu — a corrupted message DECRYPTED",
                         self.ctx, (unsigned long)bit, (unsigned long)bitCount);
            XCTAssertEqualObjects(error.domain, IRErrorDomain,
                                  @"%@ bit=%lu — failure outside the §10.5 taxonomy: %@",
                                  self.ctx, (unsigned long)bit, error);

            if (bit >= ciphertextBitStart) {
                XCTAssertEqual(error.code, (NSInteger)IRErrorAEADAuthFailed,
                               @"%@ bit=%lu is in the ciphertext/tag region, where the tag is the "
                               @"only check that can fire — got %ld",
                               self.ctx, (unsigned long)bit, (long)error.code);
                authFailures++;
            }
        }

        XCTAssertEqual(authFailures,
                       (body.length + (NSUInteger)kIRLenAEADTag) * 8,
                       @"%@ every ciphertext and tag bit must have been swept", self.ctx);

        /* A trailing byte lands inside the ciphertext (§9.1 derives L from the total length). */
        NSMutableData *extended = [message mutableCopy];
        [extended appendBytes:"\x00" length:1];
        error = nil;
        XCTAssertNil([self receive:extended into:&bob world:world error:&error],
                     @"%@ an appended byte was accepted", self.ctx);

        /* Control — the session survived every one of those attempts intact. */
        error = nil;
        NSData *recovered = [self receive:message into:&bob world:world error:&error];
        XCTAssertEqualObjects(recovered, body,
                              @"%@ after %lu rejected deliveries the GENUINE message no longer "
                              @"decrypts — the failures were corrupting live state %@",
                              self.ctx, (unsigned long)bitCount, error);
    }
}

- (void)testProperty5_EveryBitFlipInAType02MessageFailsToDecrypt {
    const NSUInteger seedCount = 2;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = [self aliceStateInWorld:world result:NULL error:&error];
        XCTAssertNotNil(alice, @"%@ %@", self.ctx, error);

        NSData *body = [self plaintext:@"int"];
        NSData *message = [self send:body from:alice world:world error:&error];
        XCTAssertNotNil(message, @"%@ %@", self.ctx, error);
        XCTAssertEqual(message.length,
                       (NSUInteger)kIRLenType02Header + body.length + (NSUInteger)kIRLenAEADTag,
                       @"%@ §9.2 total = 225 + L + 16", self.ctx);

        const NSUInteger bitCount = message.length * 8;
        const NSUInteger ciphertextBitStart = (NSUInteger)kIRLenType02Header * 8;

        for (NSUInteger bit = 0; bit < bitCount; bit++) {
            NSData *corrupted = [self data:message withBitFlippedAt:bit];

            error = nil;
            IRMessageHeader *header = [self gate:corrupted forState:nil error:&error];
            if (header == nil) {
                /* Rejected by the §10.2 ordered gate. */
                XCTAssertEqualObjects(error.domain, IRErrorDomain,
                                      @"%@ bit=%lu %@", self.ctx, (unsigned long)bit, error);
                XCTAssertTrue(bit < ciphertextBitStart,
                              @"%@ bit=%lu is past the header — the gate must not have opinions "
                              @"about ciphertext", self.ctx, (unsigned long)bit);
                continue;
            }

            error = nil;
            IRRatchetState *freshBob = [self bobStateInWorld:world forHeader:header error:&error];
            if (freshBob == nil) {
                /* Rejected by IKB verification, id resolution, or a small-order DH. */
                XCTAssertEqualObjects(error.domain, IRErrorDomain,
                                      @"%@ bit=%lu %@", self.ctx, (unsigned long)bit, error);
                XCTAssertTrue(bit < ciphertextBitStart,
                              @"%@ bit=%lu is past the header", self.ctx, (unsigned long)bit);
                continue;
            }

            error = nil;
            NSData *plaintext = [self receive:corrupted into:&freshBob world:world error:&error];
            XCTAssertNil(plaintext,
                         @"%@ bit=%lu of %lu — a corrupted type 0x02 message DECRYPTED",
                         self.ctx, (unsigned long)bit, (unsigned long)bitCount);
            XCTAssertEqualObjects(error.domain, IRErrorDomain,
                                  @"%@ bit=%lu %@", self.ctx, (unsigned long)bit, error);

            if (bit >= ciphertextBitStart) {
                XCTAssertEqual(error.code, (NSInteger)IRErrorAEADAuthFailed,
                               @"%@ bit=%lu is in the ciphertext/tag region — got %ld",
                               self.ctx, (unsigned long)bit, (long)error.code);
            }
        }

        /* Control: the untouched message still establishes a session and decrypts. */
        error = nil;
        IRMessageHeader *header = [self gate:message forState:nil error:&error];
        XCTAssertNotNil(header, @"%@ %@", self.ctx, error);

        IRRatchetState *bob = [self bobStateInWorld:world forHeader:header error:&error];
        XCTAssertNotNil(bob, @"%@ %@", self.ctx, error);

        NSData *recovered = [self receive:message into:&bob world:world error:&error];
        XCTAssertEqualObjects(recovered, body, @"%@ %@", self.ctx, error);
    }
}

#pragma mark - Property 6 — forward secrecy (defects 1, 9)

/**
 THE PROPERTY, STATED HONESTLY. Non-derivability cannot be tested — no test can demonstrate that
 HMAC-SHA256 is one-way. What IS testable, and what an implementation can actually get wrong, is
 everything around that assumption:

   (a) the chain genuinely advances — CK at message N differs from CK at every earlier message, so
       there is a preimage problem at all rather than a constant chain;
   (b) no message key repeats, so a key recovered at N is not also the key for some earlier message
       (v3's 1-byte counters, defect 9, made keys repeat every 256 messages);
   (c) forward derivation from the compromised chain key never reproduces an earlier message key;
   (d) THE OPERATIONAL STATEMENT: the full serialized state at message N — every byte an attacker
       who compromised the device would get — contains no earlier message key and no earlier chain
       key. If it did, forward secrecy would be lost regardless of how one-way the KDF is.

 (d) is where a real implementation fails: not by inverting a hash, but by keeping the old key.
 Messages are delivered strictly in order here so no key is legitimately retained under §7.6.
 */
- (void)testProperty6_CompromiseAtMessageNDoesNotYieldEarlierMessageKeys {
    const NSUInteger seedCount = 4;
    const NSUInteger messageCount = 24;
    const NSUInteger lookahead = 24;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* UNIDIRECTIONAL on purpose. If B replied, A would ratchet and every message below would
           belong to a chain B has not derived yet — the captured chain key would reconstruct a
           different chain, and every assertion here would pass without testing anything. */
        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        /* Capture the receiving chain key by VALUE. -duplicate is load-bearing: `bob.CKr` is a live
           object that §13.3 has the ratchet zeroize the moment a committed snapshot supersedes it,
           so holding the reference and reading it after the loop yields 32 zero bytes — which then
           "matches" the responder's zero-filled prologue region and reports a forward-secrecy break
           that is really a test bug. The all-zero guard below fails loudly if that ever recurs. */
        IRChainKey *chainAtZero = [bob.CKr duplicate];
        XCTAssertNotNil(chainAtZero, @"%@ B must have a receiving chain", self.ctx);
        XCTAssertFalse([chainAtZero isAllZero],
                       @"%@ the captured chain key is all-zero — it was zeroized before it was "
                       @"read, and every assertion below would be vacuous", self.ctx);
        NSData *chainAtZeroBytes = [self bytesOfSecret:chainAtZero];

        /* Deliver in order, so §7.6 stores nothing: every key is used and dropped. */
        NSMutableArray<NSData *> *ciphertexts = [NSMutableArray array];
        for (NSUInteger i = 0; i < messageCount; i++) {
            NSData *body = [self plaintext:[NSString stringWithFormat:@"fs-%lu", (unsigned long)i]];
            NSData *message = [self send:body from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [ciphertexts addObject:message];

            NSData *recovered = [self receive:message into:&bob world:world error:&error];
            XCTAssertEqualObjects(recovered, body, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
        }

        XCTAssertEqual(bob.skipped.count, (NSUInteger)0,
                       @"%@ in-order delivery must leave the skipped store empty", self.ctx);

        /* Everything an attacker compromising B at this instant obtains. */
        NSData *compromised = [self stateBytes:bob];
        XCTAssertNotNil(compromised, @"%@", self.ctx);

        /* Reconstruct the historical message keys from the chain key captured at message 0. */
        NSMutableArray<NSData *> *historicalKeys = [NSMutableArray array];
        NSMutableArray<NSData *> *historicalChains = [NSMutableArray array];
        IRChainKey *walk = chainAtZero;
        for (NSUInteger i = 0; i < messageCount; i++) {
            [historicalChains addObject:[self bytesOfSecret:walk]];
            IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:walk
                                                                  provider:world.provider
                                                                     error:&error];
            XCTAssertNotNil(step, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [historicalKeys addObject:[self bytesOfSecret:step.messageKey]];
            walk = step.nextChainKey;
        }

        /* (a) The chain advanced. */
        XCTAssertNotEqualObjects([self bytesOfSecret:bob.CKr], chainAtZeroBytes,
                                 @"%@ the receiving chain key never moved", self.ctx);

        /* (b) + (c) Forward derivation from the compromised chain key reproduces nothing earlier,
               and no two message keys in the whole run coincide. */
        NSMutableSet<NSData *> *forward = [NSMutableSet set];
        IRChainKey *future = bob.CKr;
        for (NSUInteger i = 0; i < lookahead; i++) {
            IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:future
                                                                  provider:world.provider
                                                                     error:&error];
            XCTAssertNotNil(step, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [forward addObject:[self bytesOfSecret:step.messageKey]];
            future = step.nextChainKey;
        }

        for (NSUInteger i = 0; i < historicalKeys.count; i++) {
            XCTAssertFalse([forward containsObject:historicalKeys[i]],
                           @"%@ message key %lu is re-derivable by running the compromised chain "
                           @"FORWARD — the chain repeats", self.ctx, (unsigned long)i);
        }

        NSSet<NSData *> *distinct = [NSSet setWithArray:historicalKeys];
        XCTAssertEqual(distinct.count, historicalKeys.count,
                       @"%@ message keys repeated within a single chain", self.ctx);

        /* (d) No earlier secret survives in the compromised state. */
        for (NSUInteger i = 0; i < historicalKeys.count; i++) {
            NSRange found = [compromised rangeOfData:historicalKeys[i]
                                             options:0
                                               range:NSMakeRange(0, compromised.length)];
            XCTAssertEqual(found.location, (NSUInteger)NSNotFound,
                           @"%@ message key %lu is still present in the serialized state at "
                           @"message %lu — FORWARD SECRECY IS LOST",
                           self.ctx, (unsigned long)i, (unsigned long)messageCount);
        }
        for (NSUInteger i = 0; i < historicalChains.count; i++) {
            NSRange found = [compromised rangeOfData:historicalChains[i]
                                             options:0
                                               range:NSMakeRange(0, compromised.length)];
            XCTAssertEqual(found.location, (NSUInteger)NSNotFound,
                           @"%@ the chain key from message %lu survives in the state at message %lu",
                           self.ctx, (unsigned long)i, (unsigned long)messageCount);
        }

        /* Replaying an already-delivered message is refused outright (§7.9 phase 3c). */
        error = nil;
        XCTAssertNil([self receive:ciphertexts[0] into:&bob world:world error:&error],
                     @"%@ a delivered message was accepted twice", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorReplay, @"%@ %@", self.ctx, error);
    }
}

/**
 Defect 9 in property form. v3 wrote the message counters into ONE BYTE
 (IRDoubleRatchetService.m:140-145), so `N` wrapped at 256 and message 256 collided with message 0 —
 key reuse on a stream cipher, which is a total break of confidentiality for both messages. §9.1
 makes the field `uint32_be`. Running a single chain past 256 is the only way to see it.
 */
- (void)testProperty6_MessageKeysNeverRepeatAcrossALongChain {
    const NSUInteger seedCount = 2;
    const NSUInteger messageCount = 300;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        NSMutableSet<NSData *> *ciphertexts = [NSMutableSet set];

        for (NSUInteger i = 0; i < messageCount; i++) {
            NSData *body = [self plaintext:[NSString stringWithFormat:@"long-%lu", (unsigned long)i]];

            const uint32_t expectedN = alice.Ns;
            NSData *message = [self send:body from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);

            IRMessageHeader *header = [self gate:message forState:bob error:&error];
            XCTAssertNotNil(header, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            XCTAssertEqual(header.N, expectedN,
                           @"%@ i=%lu — header N is %u, expected %u. THIS IS DEFECT 9: the counter "
                           @"is not 32 bits.", self.ctx, (unsigned long)i, header.N, expectedN);

            [ciphertexts addObject:message];

            NSData *recovered = [self receive:message into:&bob world:world error:&error];
            XCTAssertEqualObjects(recovered, body, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
        }

        XCTAssertEqual(ciphertexts.count, messageCount,
                       @"%@ two of %lu messages produced identical bytes — key or nonce reuse",
                       self.ctx, (unsigned long)messageCount);
        /* `messageCount`, not `messageCount + 1`: A ratcheted when she received B's reply during
           setup, so this burst is a NEW sending chain numbered from zero, and B's `Nr` counts
           within the corresponding receiving chain (§7.4 step 2 resets both). */
        XCTAssertEqual(bob.Nr, (uint32_t)messageCount,
                       @"%@ B's receive counter did not track the chain", self.ctx);
    }
}

#pragma mark - Property 7 — skipped messages (defect 11)

/**
 THE PROPERTY: within MAX_SKIP_PER_MESSAGE, any delivery order works; beyond it, the failure is
 closed and carries exactly ERR_TOO_MANY_SKIPPED; and the store never exceeds MAX_SKIPPED_STORED,
 evicting in insertion order.

 THE DEFECT IT CATCHES: v3's `skippedMessagesKeys` was an unbounded dictionary pruned only when a
 key was successfully used (IRDoubleRatchetService.m:212-237). A peer that never sent the skipped
 messages left them resident forever — unbounded memory growth driven by an attacker, with the
 message keys themselves as the payload.
 */
- (void)testProperty7_OutOfOrderDeliveryWithinTheBoundAlwaysSucceeds {
    const NSUInteger seedCount = 6;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        const NSUInteger count = 12 + [world.rng nextU32Below:20];

        NSMutableArray<NSData *> *messages = [NSMutableArray array];
        NSMutableArray<NSData *> *bodies = [NSMutableArray array];
        for (NSUInteger i = 0; i < count; i++) {
            NSData *body = [self plaintext:[NSString stringWithFormat:@"ooo-%lu", (unsigned long)i]];
            NSData *message = [self send:body from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [messages addObject:message];
            [bodies addObject:body];
        }

        /* Fisher-Yates over the seeded stream: a different arrival order per seed. */
        NSMutableArray<NSNumber *> *order = [NSMutableArray array];
        for (NSUInteger i = 0; i < count; i++) {
            [order addObject:@(i)];
        }
        for (NSUInteger i = count; i > 1; i--) {
            const uint32_t j = [world.rng nextU32Below:(uint32_t)i];
            [order exchangeObjectAtIndex:(i - 1) withObjectAtIndex:j];
        }

        for (NSUInteger k = 0; k < count; k++) {
            const NSUInteger index = order[k].unsignedIntegerValue;
            NSData *recovered = [self receive:messages[index] into:&bob world:world error:&error];
            XCTAssertEqualObjects(recovered, bodies[index],
                                  @"%@ arrival %lu of %lu (message %lu) failed out of order: %@",
                                  self.ctx, (unsigned long)k, (unsigned long)count,
                                  (unsigned long)index, error);
        }

        /* Every stored key was consumed; §7.6 removes on successful use. */
        XCTAssertEqual(bob.skipped.count, (NSUInteger)0,
                       @"%@ %lu keys remain stored after all messages arrived",
                       self.ctx, (unsigned long)bob.skipped.count);
    }
}

- (void)testProperty7_SkippingBeyondTheBoundFailsClosedWithTheExactCode {
    const NSUInteger seedCount = 3;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* A is built directly rather than through -establishInWorld:, so that `messages[i]` carries
           `N == i` exactly. A never receives here, so she never ratchets and never resets `Ns`. */
        IRRatchetState *alice = [self aliceStateInWorld:world result:NULL error:&error];
        XCTAssertNotNil(alice, @"%@ %@", self.ctx, error);
        if (alice == nil) {
            continue;
        }

        const uint32_t startNr = 1;  /* B's Nr once it has consumed messages[0] */
        const NSUInteger atBound = (NSUInteger)startNr + (NSUInteger)kIRMaxSkipPerMessage;
        const NSUInteger pastBound = atBound + 1;

        NSMutableArray<NSData *> *messages = [NSMutableArray array];
        for (NSUInteger i = 0; i <= pastBound; i++) {
            NSData *message = [self send:[self plaintext:@"skip"] from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [messages addObject:message];
        }

        /* Two independent B sessions from one handshake — X3DH consumes neither prekey record. */
        IRMessageHeader *firstHeader = [self gate:messages[0] forState:nil error:&error];
        XCTAssertNotNil(firstHeader, @"%@ %@", self.ctx, error);
        XCTAssertEqual(firstHeader.N, (uint32_t)0,
                       @"%@ the index-equals-N invariant this test's arithmetic rests on is broken",
                       self.ctx);

        IRRatchetState *bobAtBound = [self bobStateInWorld:world forHeader:firstHeader error:&error];
        IRRatchetState *bobPastBound = [self bobStateInWorld:world forHeader:firstHeader error:&error];
        XCTAssertNotNil(bobAtBound, @"%@ %@", self.ctx, error);
        XCTAssertNotNil(bobPastBound, @"%@ %@", self.ctx, error);
        if (bobAtBound == nil || bobPastBound == nil) {
            continue;
        }

        /* Establish both, consuming message 0 so Nr matches `startNr`. */
        XCTAssertNotNil([self receive:messages[0] into:&bobAtBound world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertNotNil([self receive:messages[0] into:&bobPastBound world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertEqual(bobAtBound.Nr, startNr, @"%@", self.ctx);

        /* Exactly at the bound: MAX_SKIP_PER_MESSAGE derivations, which is permitted. */
        error = nil;
        NSData *recovered = [self receive:messages[atBound] into:&bobAtBound world:world error:&error];
        XCTAssertNotNil(recovered,
                        @"%@ a message requiring exactly MAX_SKIP_PER_MESSAGE (%u) skips was "
                        @"refused: %@", self.ctx, (unsigned)kIRMaxSkipPerMessage, error);
        XCTAssertEqual(bobAtBound.skipped.count, (NSUInteger)kIRMaxSkipPerMessage,
                       @"%@ the store should now hold exactly the skipped keys", self.ctx);

        /* One past it: fails closed, with the exact code, leaving state untouched. */
        NSData *before = [self stateBytes:bobPastBound];
        error = nil;
        NSData *refused = [self receive:messages[pastBound] into:&bobPastBound world:world error:&error];
        XCTAssertNil(refused,
                     @"%@ a message requiring %lu skips was accepted past the bound of %u",
                     self.ctx, (unsigned long)pastBound, (unsigned)kIRMaxSkipPerMessage);
        XCTAssertEqual(error.code, (NSInteger)IRErrorTooManySkipped,
                       @"%@ expected ERR_TOO_MANY_SKIPPED (7110), got %ld", self.ctx, (long)error.code);

        NSData *after = [self stateBytes:bobPastBound];
        XCTAssertEqualObjects(before, after,
                              @"%@ §7.6 — an over-limit skip MUST leave state unmodified", self.ctx);
        XCTAssertEqual(bobPastBound.skipped.count, (NSUInteger)0,
                       @"%@ a refused skip must store nothing", self.ctx);
    }
}

/**
 The store's own invariants, over randomized insertion sequences with DELIBERATELY NON-MONOTONIC
 timestamps. §7.6 orders eviction "by insertion", while §12.1 persists `inserted_at_ms` — a port
 that sorts the FIFO by the stored timestamp (the obvious reading once the field exists) evicts the
 wrong entry. Feeding decreasing timestamps is what discriminates the two.
 */
- (void)testProperty7_StoreRespectsItsSizeBoundAndEvictsFIFO {
    const NSUInteger seedCount = 3;
    const NSUInteger insertCount = (NSUInteger)kIRMaxSkippedStored + 500;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRSkippedKeyStore *store = [IRSkippedKeyStore store];

        /* A handful of ratchet publics, so entries span chains as they would in a real session. */
        NSMutableArray<IRX25519Public *> *publics = [NSMutableArray array];
        for (NSUInteger i = 0; i < 4; i++) {
            IRX25519KeyPair *pair = [world.provider generateX25519KeyPairGuarded:NO error:&error];
            XCTAssertNotNil(pair, @"%@ %@", self.ctx, error);
            [publics addObject:pair.publicKey];
        }

        NSMutableArray<IRSkippedKeyEntry *> *expected = [NSMutableArray array];

        for (NSUInteger i = 0; i < insertCount; i++) {
            IRSecretBytes *raw = [world.rng secretOfLength:kIRLenMessageKey];
            IRMessageKey *messageKey = [IRMessageKey fromBytes:[raw constBytes] guarded:NO error:&error];
            XCTAssertNotNil(messageKey, @"%@ %@", self.ctx, error);

            IRX25519Public *dhPublic = publics[i % publics.count];
            const uint32_t N = (uint32_t)i;

            /* Timestamps run BACKWARDS. Insertion order and timestamp order disagree throughout. */
            const uint64_t timestamp = world.nowMs + (uint64_t)(insertCount - i) * 1000ULL;

            XCTAssertTrue([store insertMessageKey:messageKey dhPublic:dhPublic N:N atTimeMs:timestamp],
                          @"%@ insert %lu failed", self.ctx, (unsigned long)i);

            IRSkippedKeyEntry *entry = [store entryForDHPublic:dhPublic N:N];
            XCTAssertNotNil(entry, @"%@ insert %lu is not retrievable", self.ctx, (unsigned long)i);
            [expected addObject:entry];

            const NSUInteger cap = (NSUInteger)kIRMaxSkippedStored;
            XCTAssertEqual(store.count, MIN(i + 1, cap),
                           @"%@ after %lu inserts the store holds %lu, bound is %lu",
                           self.ctx, (unsigned long)(i + 1), (unsigned long)store.count,
                           (unsigned long)cap);
        }

        /* The survivors are exactly the last MAX_SKIPPED_STORED inserted, in insertion order. */
        NSArray<IRSkippedKeyEntry *> *survivors = [store entriesInInsertionOrder];
        XCTAssertEqual(survivors.count, (NSUInteger)kIRMaxSkippedStored, @"%@", self.ctx);

        const NSUInteger firstSurvivor = insertCount - (NSUInteger)kIRMaxSkippedStored;
        for (NSUInteger i = 0; i < survivors.count; i++) {
            XCTAssertEqual(survivors[i].N, (uint32_t)(firstSurvivor + i),
                           @"%@ position %lu holds N=%u, expected %lu — eviction is not FIFO by "
                           @"INSERTION (§7.6); a timestamp-ordered FIFO evicts the wrong entry",
                           self.ctx, (unsigned long)i, survivors[i].N,
                           (unsigned long)(firstSurvivor + i));
        }

        /* Everything evicted is gone from the index. */
        for (NSUInteger i = 0; i < firstSurvivor; i++) {
            IRX25519Public *dhPublic = publics[i % publics.count];
            XCTAssertNil([store entryForDHPublic:dhPublic N:(uint32_t)i],
                         @"%@ evicted entry %lu is still retrievable", self.ctx, (unsigned long)i);
        }

        [store zeroizeAll];
    }
}

/**
 The same bound reached the way an attacker would reach it — through the wire, over three received
 messages each skipping the per-message maximum — and the confirmation that evicted key material is
 actually wiped rather than merely unlinked.
 */
- (void)testProperty7_EndToEndOverfillEvictsAndZeroizesTheOldestEntries {
    const NSUInteger seedCount = 2;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        /* As above: A is built directly so that `messages[i]` carries `N == i`. */
        IRRatchetState *alice = [self aliceStateInWorld:world result:NULL error:&error];
        XCTAssertNotNil(alice, @"%@ %@", self.ctx, error);

        const NSUInteger step = (NSUInteger)kIRMaxSkipPerMessage;
        /* Each delivery skips exactly `step` keys: after receiving N, Nr becomes N+1, so the next
           target is (previous target + 1) + step. Three deliveries insert 3000 into a 2000 store. */
        const NSUInteger firstTarget = 1 + step;
        const NSUInteger secondTarget = firstTarget + 1 + step;
        const NSUInteger thirdTarget = secondTarget + 1 + step;

        NSMutableArray<NSData *> *messages = [NSMutableArray array];
        for (NSUInteger i = 0; i <= thirdTarget; i++) {
            NSData *message = [self send:[self plaintext:@"fill"] from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ i=%lu %@", self.ctx, (unsigned long)i, error);
            [messages addObject:message];
        }

        IRMessageHeader *firstHeader = [self gate:messages[0] forState:nil error:&error];
        XCTAssertNotNil(firstHeader, @"%@ %@", self.ctx, error);

        IRRatchetState *bob = [self bobStateInWorld:world forHeader:firstHeader error:&error];
        XCTAssertNotNil(bob, @"%@ %@", self.ctx, error);
        XCTAssertNotNil([self receive:messages[0] into:&bob world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertEqual(bob.Nr, (uint32_t)1, @"%@", self.ctx);

        XCTAssertNotNil([self receive:messages[firstTarget] into:&bob world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertEqual(bob.skipped.count, step, @"%@", self.ctx);

        /* Hold a reference to the oldest entries so their zeroization is observable after eviction. */
        NSArray<IRSkippedKeyEntry *> *oldest = [[bob.skipped entriesInInsertionOrder]
                                                subarrayWithRange:NSMakeRange(0, 16)];
        for (IRSkippedKeyEntry *entry in oldest) {
            XCTAssertFalse(entry.isZeroized, @"%@ entry N=%u is wiped while still live", self.ctx, entry.N);
        }

        XCTAssertNotNil([self receive:messages[secondTarget] into:&bob world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertEqual(bob.skipped.count, (NSUInteger)kIRMaxSkippedStored,
                       @"%@ the store should be exactly full", self.ctx);

        /* The third delivery pushes past the cap and must evict the oldest, not refuse the insert. */
        XCTAssertNotNil([self receive:messages[thirdTarget] into:&bob world:world error:&error],
                        @"%@ %@", self.ctx, error);
        XCTAssertEqual(bob.skipped.count, (NSUInteger)kIRMaxSkippedStored,
                       @"%@ the store exceeded MAX_SKIPPED_STORED (defect 11)", self.ctx);

        for (IRSkippedKeyEntry *entry in oldest) {
            XCTAssertNil([bob.skipped entryForDHPublic:entry.dhPublic N:entry.N],
                         @"%@ entry N=%u should have been evicted", self.ctx, entry.N);
            XCTAssertTrue(entry.isZeroized,
                          @"%@ evicted entry N=%u was unlinked but its key material was NOT zeroized "
                          @"(§7.6: keys MUST be zeroized on eviction)", self.ctx, entry.N);
        }

        /* A surviving skipped key still decrypts its message — eviction did not corrupt the store. */
        NSArray<IRSkippedKeyEntry *> *survivors = [bob.skipped entriesInInsertionOrder];
        const uint32_t survivingN = survivors.lastObject.N;
        error = nil;
        NSData *recovered = [self receive:messages[survivingN] into:&bob world:world error:&error];
        XCTAssertEqualObjects(recovered, [self plaintext:@"fill"],
                              @"%@ a surviving skipped key (N=%u) failed to decrypt: %@",
                              self.ctx, survivingN, error);
    }
}

#pragma mark - Property 8 — atomicity (§14.1)

/**
 THE PROPERTY: a message that fails authentication leaves session state BYTE-IDENTICAL. Not
 "recoverable", not "equivalent" — identical, compared through §12.1's serialization, which covers
 RK, DHs, DHr, CKs, CKr, Ns, Nr, PN, the send counter and every stored skipped key.

 THE DEFECT IT CATCHES: v3 inserted skipped keys, performed the DH ratchet, advanced the chain and
 incremented the receive counter at IRDoubleRatchetService.m:178-199, and only THEN called
 `aeDecryptData:` at :203. An attacker who could inject a well-formed but unauthenticated message
 carrying a novel ratchet key forced the receiver's ratchet forward and permanently desynchronised a
 live session. It is state corruption rather than a wrong plaintext, so no round-trip test detects
 it, and it is unauthenticated: the attacker needs no key material at all.

 The second test is that attack specifically, because it is the case where a naive implementation
 differs most: the forged message carries a DH key the receiver has never seen, so the tempting
 implementation ratchets first and authenticates second.
 */
- (void)testProperty8_FailedAuthenticationLeavesStateByteIdentical {
    const NSUInteger seedCount = 6;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        /* Advance to a random position, and leave some skipped keys resident so the comparison
           covers the store as well as the scalar fields. */
        const NSUInteger advance = [world.rng nextU32Below:6];
        for (NSUInteger i = 0; i < advance; i++) {
            NSData *message = [self send:[self plaintext:@"adv"] from:alice world:world error:&error];
            XCTAssertNotNil(message, @"%@ %@", self.ctx, error);
            XCTAssertNotNil([self receive:message into:&bob world:world error:&error], @"%@ %@", self.ctx, error);
        }

        NSData *skippedMessage = [self send:[self plaintext:@"skipped"] from:alice world:world error:&error];
        XCTAssertNotNil(skippedMessage, @"%@ %@", self.ctx, error);
        NSData *nextMessage = [self send:[self plaintext:@"next"] from:alice world:world error:&error];
        XCTAssertNotNil(nextMessage, @"%@ %@", self.ctx, error);

        /* Deliver the later one first, so `skippedMessage`'s key is stored. */
        XCTAssertNotNil([self receive:nextMessage into:&bob world:world error:&error], @"%@ %@", self.ctx, error);
        XCTAssertEqual(bob.skipped.count, (NSUInteger)1, @"%@", self.ctx);

        NSData *before = [self stateBytes:bob];
        XCTAssertNotNil(before, @"%@", self.ctx);

        /* Every failure mode we can drive from the network, each on the same live state. */
        NSData *futureMessage = [self send:[self plaintext:@"future"] from:alice world:world error:&error];
        XCTAssertNotNil(futureMessage, @"%@ %@", self.ctx, error);

        NSArray<NSData *> *forgeries = @[
            /* (i) the stored skipped key's own message, corrupted — §7.6's retain rule */
            [self data:skippedMessage withBitFlippedAt:(skippedMessage.length * 8 - 1 -
                                                        [world.rng nextU32Below:(uint32_t)(kIRLenAEADTag * 8)])],
            /* (ii) a fresh in-chain message, corrupted in the ciphertext */
            [self data:futureMessage withBitFlippedAt:(NSUInteger)kIRLenType01Header * 8 +
                                                      [world.rng nextU32Below:8]],
            /* (iii) a fresh in-chain message, corrupted in the header (covered by the AD) */
            [self data:futureMessage withBitFlippedAt:(NSUInteger)kIROffType01Nonce * 8 +
                                                      [world.rng nextU32Below:(uint32_t)(kIRLenNonce * 8)]],
        ];

        for (NSUInteger f = 0; f < forgeries.count; f++) {
            error = nil;
            NSData *plaintext = [self receive:forgeries[f] into:&bob world:world error:&error];
            XCTAssertNil(plaintext, @"%@ forgery %lu decrypted", self.ctx, (unsigned long)f);

            NSData *after = [self stateBytes:bob];
            XCTAssertEqualObjects(before, after,
                                  @"%@ forgery %lu MUTATED SESSION STATE. §7.7 requires the live "
                                  @"state be byte-identical after a failed decrypt.",
                                  self.ctx, (unsigned long)f);
        }

        /* The store still holds the skipped key, and it still works (§7.6 / NEG-SKIP-RETAIN). */
        XCTAssertEqual(bob.skipped.count, (NSUInteger)1,
                       @"%@ a failed decrypt consumed the stored key", self.ctx);

        error = nil;
        NSData *recovered = [self receive:skippedMessage into:&bob world:world error:&error];
        XCTAssertEqualObjects(recovered, [self plaintext:@"skipped"],
                              @"%@ the stored key was destroyed by the failed attempts: %@",
                              self.ctx, error);

        /* And the live chain is still synchronised. */
        error = nil;
        NSData *followUp = [self send:[self plaintext:@"after"] from:alice world:world error:&error];
        XCTAssertNotNil(followUp, @"%@ %@", self.ctx, error);
        XCTAssertNotNil([self receive:futureMessage into:&bob world:world error:&error], @"%@ %@", self.ctx, error);
        XCTAssertEqualObjects([self receive:followUp into:&bob world:world error:&error],
                              [self plaintext:@"after"], @"%@ the session desynchronised", self.ctx);
    }
}

- (void)testProperty8_FailedAuthenticationOfANovelRatchetKeyDoesNotDesynchronise {
    const NSUInteger seedCount = 6;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        /* B replies, so A ratchets; A's next message therefore carries a ratchet key B has never
           seen. That message, corrupted, is the desynchronisation attack. */
        NSData *bobReply = [self send:[self plaintext:@"b1"] from:bob world:world error:&error];
        XCTAssertNotNil(bobReply, @"%@ %@", self.ctx, error);
        XCTAssertNotNil([self receive:bobReply into:&alice world:world error:&error], @"%@ %@", self.ctx, error);

        NSData *novel = [self send:[self plaintext:@"novel"] from:alice world:world error:&error];
        XCTAssertNotNil(novel, @"%@ %@", self.ctx, error);

        IRMessageHeader *header = [self gate:novel forState:bob error:&error];
        XCTAssertNotNil(header, @"%@ %@", self.ctx, error);
        XCTAssertFalse([header.ratchetKey isEqualToX25519Public:bob.DHr],
                       @"%@ the test requires a ratchet key B has not seen", self.ctx);

        NSData *before = [self stateBytes:bob];
        NSData *dhrBefore = bob.DHr.data;

        /* Corrupt the tag. The header — including the novel ratchet key — stays intact, so an
           implementation that ratchets before authenticating adopts it. */
        const uint32_t tagBit = [world.rng nextU32Below:(uint32_t)(kIRLenAEADTag * 8)];
        NSData *forged = [self data:novel withBitFlippedAt:(novel.length - kIRLenAEADTag) * 8 + tagBit];

        error = nil;
        XCTAssertNil([self receive:forged into:&bob world:world error:&error],
                     @"%@ a forged message decrypted", self.ctx);
        XCTAssertEqual(error.code, (NSInteger)IRErrorAEADAuthFailed, @"%@ %@", self.ctx, error);

        NSData *after = [self stateBytes:bob];
        XCTAssertEqualObjects(before, after,
                              @"%@ an UNAUTHENTICATED message carrying a novel ratchet key mutated "
                              @"B's state. This is the §14.1 desynchronisation DoS.", self.ctx);
        XCTAssertEqualObjects(bob.DHr.data, dhrBefore,
                              @"%@ B adopted an unauthenticated ratchet key", self.ctx);

        /* The genuine message still arrives, which is what "fail closed" has to mean. */
        error = nil;
        NSData *recovered = [self receive:novel into:&bob world:world error:&error];
        XCTAssertEqualObjects(recovered, [self plaintext:@"novel"],
                              @"%@ the session was permanently desynchronised by the forgery: %@",
                              self.ctx, error);
    }
}

#pragma mark - Property 9 — KDF domain separation (§8.1)

/**
 THE PROPERTY: no two distinct labels or contexts produce equal output from equal input.

 THE DEFECT IT CATCHES: v3 derived three different values from one message key by re-invoking the
 SAME label at salts 1, 2 and 3 — one label across three semantic roles — and the 16-byte IV request
 silently hit `crypto_kdf_BYTES_MIN` and was widened. §8.1 replaces all of it with one HKDF under
 one label. The first test is nearly trivial and is included because a copy-paste error that makes
 two labels identical is invisible to every round-trip test in existence.
 */
- (void)testProperty9_ProtocolLabelsArePairwiseDistinct {
    NSArray<NSData *> *labels = [self protocolLabels];
    NSArray<NSString *> *names = [self protocolLabelNames];

    for (NSUInteger i = 0; i < labels.count; i++) {
        for (NSUInteger j = i + 1; j < labels.count; j++) {
            XCTAssertNotEqualObjects(labels[i], labels[j],
                                     @"labels %@ and %@ are byte-identical — the domain separation "
                                     @"they exist to provide does not exist", names[i], names[j]);
        }
    }
}

- (void)testProperty9_DistinctLabelsNeverProduceEqualOutputFromEqualInput {
    NSArray<NSData *> *labels = [self protocolLabels];
    NSArray<NSString *> *names = [self protocolLabelNames];

    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropertyRNG *rng = [IRPropertyRNG rngWithSeed:_seed];
        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRSecretBytes *salt = [rng secretOfLength:kIRLenHKDFPRK];
        IRSecretBytes *ikm = [rng secretOfLength:kIRLenDHOutput];

        NSMutableArray<NSData *> *outputs = [NSMutableArray array];
        for (NSUInteger i = 0; i < labels.count; i++) {
            IRSecretBytes *okm = [world.provider hkdfWithSalt:salt
                                                          ikm:ikm
                                                         info:labels[i]
                                                 outputLength:kIRLenHMACSHA256
                                                        error:&error];
            XCTAssertNotNil(okm, @"%@ %@ %@", self.ctx, names[i], error);
            [outputs addObject:[self bytesOfSecret:okm]];
        }

        for (NSUInteger i = 0; i < outputs.count; i++) {
            for (NSUInteger j = i + 1; j < outputs.count; j++) {
                XCTAssertNotEqualObjects(outputs[i], outputs[j],
                                         @"%@ labels %@ and %@ produced EQUAL output from equal "
                                         @"input", self.ctx, names[i], names[j]);
            }
        }
    }
}

/**
 §7.3's two HMAC inputs, 0x01 and 0x02, are the narrowest domain separation in the protocol — one
 byte — and the one v3 got wrong by using salt 0 and salt 1 under a single label. If these ever
 coincided the message key and the next chain key would be the same value, so every message key
 would be the next chain key: total collapse, invisible to a round trip.
 */
- (void)testProperty9_ChainKeyAndMessageKeyInputsAreSeparated {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropertyRNG *rng = [IRPropertyRNG rngWithSeed:_seed];
        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRSecretBytes *raw = [rng secretOfLength:kIRLenChainKey];
        IRChainKey *chainKey = [IRChainKey fromBytes:[raw constBytes] guarded:NO error:&error];
        XCTAssertNotNil(chainKey, @"%@ %@", self.ctx, error);

        IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                              provider:world.provider
                                                                 error:&error];
        XCTAssertNotNil(step, @"%@ %@", self.ctx, error);

        NSData *messageKeyBytes = [self bytesOfSecret:step.messageKey];
        NSData *nextChainBytes = [self bytesOfSecret:step.nextChainKey];
        NSData *inputBytes = [self bytesOfSecret:chainKey];

        XCTAssertNotEqualObjects(messageKeyBytes, nextChainBytes,
                                 @"%@ KDF_CK's 0x01 and 0x02 inputs produced the same output",
                                 self.ctx);
        XCTAssertNotEqualObjects(messageKeyBytes, inputBytes, @"%@ MK equals its own CK", self.ctx);
        XCTAssertNotEqualObjects(nextChainBytes, inputBytes, @"%@ the chain did not advance", self.ctx);

        /* §8.1's expansion is a third, distinct derivation from the same 32 bytes. */
        IRMessageKey *messageKey = step.messageKey;
        IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:messageKey
                                                         provider:world.provider
                                                            error:&error];
        XCTAssertNotNil(encKey, @"%@ %@", self.ctx, error);
        XCTAssertNotEqualObjects([self bytesOfSecret:encKey], messageKeyBytes,
                                 @"%@ KDF_MK returned its input — the AEAD key is the message key",
                                 self.ctx);

        /* Feeding the SAME 32 bytes to KDF_RK as a root key must give something else again: three
           roles, three labels, three outputs (§7.2, §7.3, §8.1). */
        IRRootKey *asRoot = [IRRootKey fromBytes:[raw constBytes] guarded:NO error:&error];
        XCTAssertNotNil(asRoot, @"%@ %@", self.ctx, error);
        IRSecretBytes *dh = [rng secretOfLength:kIRLenDHOutput];
        IRRootChainStep *rootStep = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:asRoot
                                                                          dhOutput:dh
                                                                          provider:world.provider
                                                                             error:&error];
        XCTAssertNotNil(rootStep, @"%@ %@", self.ctx, error);
        XCTAssertNotEqualObjects([self bytesOfSecret:rootStep.chainKey], nextChainBytes,
                                 @"%@ KDF_RK and KDF_CK agree on a chain key", self.ctx);
        XCTAssertNotEqualObjects([self bytesOfSecret:rootStep.rootKey], messageKeyBytes,
                                 @"%@ KDF_RK and KDF_CK agree on a key", self.ctx);
    }
}

/**
 §6.3's info string is `"nuntius:X3DH:v4" ‖ TH`, so the transcript hash is CONTEXT, not just an
 input. Two handshakes with an identical DH set but different transcripts must not agree — that is
 the whole mechanism binding SK to the identities and ids both parties saw, and it is what stops
 §5.5's attack (a victim's genuine IK^s advertised beside an attacker's IK^d, which leaves every DH
 term untouched because no DH involves IK^s).
 */
- (void)testProperty9_SharedKeyIsBoundToTheTranscriptHash {
    for (NSUInteger s = 0; s < kIRPropertySeedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRX3DHResult *result = [self initiatorResultInWorld:world bundle:NULL retainIKM:YES error:&error];
        XCTAssertNotNil(result, @"%@ %@", self.ctx, error);

        IRSecretBytes *ikm = result.ikm;
        XCTAssertNotNil(ikm, @"%@", self.ctx);

        NSData *transcriptHash = result.transcriptHash;
        XCTAssertEqual(transcriptHash.length, (NSUInteger)kIRLenTH, @"%@", self.ctx);

        const uint32_t bit = [world.rng nextU32Below:(uint32_t)(kIRLenTH * 8)];
        NSData *movedHash = [self data:transcriptHash withBitFlippedAt:bit];

        IRRootKey *base = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                                 transcriptHash:transcriptHash
                                                       provider:world.provider
                                                          error:&error];
        IRRootKey *moved = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                                  transcriptHash:movedHash
                                                        provider:world.provider
                                                           error:&error];
        XCTAssertNotNil(base, @"%@ %@", self.ctx, error);
        XCTAssertNotNil(moved, @"%@ %@", self.ctx, error);

        XCTAssertFalse([base isEqualToSecretBytes:moved],
                       @"%@ bit=%u — an identical DH set under a DIFFERENT transcript produced the "
                       @"same shared key; §6.2's binding is not reaching the KDF", self.ctx, bit);

        [result zeroize];
    }
}

- (NSArray<NSData *> * _Nonnull)protocolLabels {
    return @[
        [NSData dataWithBytes:kIRLabelIKBind length:kIRLenLabelIKBind],
        [NSData dataWithBytes:kIRLabelSPK length:kIRLenLabelSPK],
        [NSData dataWithBytes:kIRLabelTranscript length:kIRLenLabelTranscript],
        [NSData dataWithBytes:kIRLabelX3DH length:kIRLenLabelX3DH],
        [NSData dataWithBytes:kIRLabelRK length:kIRLenLabelRK],
        [NSData dataWithBytes:kIRLabelMK length:kIRLenLabelMK],
        [NSData dataWithBytes:kIRLabelAD length:kIRLenLabelAD],
        [NSData dataWithBytes:kIRLabelFP length:kIRLenLabelFP],
    ];
}

- (NSArray<NSString *> * _Nonnull)protocolLabelNames {
    return @[ @"IKBind", @"SPK", @"Transcript", @"X3DH", @"RK", @"MK", @"AD", @"FP" ];
}

#pragma mark - Additional v3 regressions in property form (defects 9, 10)

/**
 Defect 10: v3 wrote `Ns` into BOTH header counter fields (IRDoubleRatchetService.m:140-145), so
 `PN` — the length of the sender's previous sending chain — was never transmitted. The receiver
 could not know how many keys to skip across a chain boundary, so any message lost immediately
 before a ratchet was unrecoverable.

 The property holds `N` and `PN` to different sources across randomized turn-taking: `N` counts
 within the current chain, `PN` records what the previous chain reached. They coincide only in the
 degenerate case of one message per chain, which is why the turn lengths are randomized to be
 several messages long.
 */
- (void)testRegression_PNCarriesThePreviousChainLengthNotNs {
    const NSUInteger seedCount = 6;
    const NSUInteger turnCount = 6;

    for (NSUInteger s = 0; s < seedCount; s++) {
        _seed = kIRPropertySeeds[s];

        IRPropWorld *world = [self worldWithSeed:_seed];
        NSError *error = nil;

        IRRatchetState *alice = nil;
        IRRatchetState *bob = nil;
        if (![self establishBidirectionalInWorld:world alice:&alice bob:&bob]) {
            continue;
        }

        /* Both sides already have a previous chain of length ONE when the loop starts, and it is
           worth being explicit about why, because getting it wrong looks exactly like defect 10:
             - A sent one message ("establish") and then ratcheted on B's reply, so §7.4 step 2 set
               her PN to the Ns she had reached, which is 1.
             - B sent one message ("reply"); he ratchets when A's first burst arrives, setting his
               PN to his own Ns, also 1.
           Initialising these to zero makes the very first assertion fail against correct code. */
        BOOL aliceSends = YES;
        uint32_t alicePreviousChainLength = 1;
        uint32_t bobPreviousChainLength = 1;

        for (NSUInteger turn = 0; turn < turnCount; turn++) {
            IRRatchetState *sender = aliceSends ? alice : bob;
            const uint32_t expectedPN = aliceSends ? alicePreviousChainLength : bobPreviousChainLength;

            const NSUInteger burst = 2 + [world.rng nextU32Below:5];
            NSMutableArray<NSData *> *messages = [NSMutableArray array];

            for (NSUInteger i = 0; i < burst; i++) {
                NSData *body = [self plaintext:[NSString stringWithFormat:@"t%lu-%lu",
                                                (unsigned long)turn, (unsigned long)i]];
                NSData *message = [self send:body from:sender world:world error:&error];
                XCTAssertNotNil(message, @"%@ turn=%lu i=%lu %@",
                                self.ctx, (unsigned long)turn, (unsigned long)i, error);
                [messages addObject:message];

                IRRatchetState *receiver = aliceSends ? bob : alice;
                IRMessageHeader *header = [self gate:message forState:receiver error:&error];
                XCTAssertNotNil(header, @"%@ turn=%lu i=%lu %@",
                                self.ctx, (unsigned long)turn, (unsigned long)i, error);

                XCTAssertEqual(header.N, (uint32_t)i,
                               @"%@ turn=%lu — N must count within the CURRENT chain",
                               self.ctx, (unsigned long)turn);
                XCTAssertEqual(header.PN, expectedPN,
                               @"%@ turn=%lu i=%lu — PN is %u, expected %u (the previous chain's "
                               @"length). THIS IS DEFECT 10: Ns is being written into the PN slot.",
                               self.ctx, (unsigned long)turn, (unsigned long)i,
                               header.PN, expectedPN);

                /* When the burst is longer than one, N and PN genuinely differ — the case the
                   defect makes indistinguishable. */
                if (i > 0 && expectedPN != (uint32_t)i) {
                    XCTAssertNotEqual(header.N, header.PN,
                                      @"%@ turn=%lu i=%lu — N and PN coincide where they should not",
                                      self.ctx, (unsigned long)turn, (unsigned long)i);
                }
            }

            for (NSUInteger i = 0; i < burst; i++) {
                if (aliceSends) {
                    XCTAssertNotNil([self receive:messages[i] into:&bob world:world error:&error],
                                    @"%@ turn=%lu i=%lu %@", self.ctx, (unsigned long)turn,
                                    (unsigned long)i, error);
                } else {
                    XCTAssertNotNil([self receive:messages[i] into:&alice world:world error:&error],
                                    @"%@ turn=%lu i=%lu %@", self.ctx, (unsigned long)turn,
                                    (unsigned long)i, error);
                }
            }

            if (aliceSends) {
                alicePreviousChainLength = (uint32_t)burst;
            } else {
                bobPreviousChainLength = (uint32_t)burst;
            }
            aliceSends = !aliceSends;
        }
    }
}

@end
