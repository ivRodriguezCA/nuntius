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
#import "IRPublicIdentity.h"
#import "IRRatchet.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSession+Internal.h"
#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSessionStore.h"
#import "IRSkippedKeyStore.h"
#import "IRX3DH.h"

/**
 ratchet.json — SPEC §7 in full, §10.7, §11 in full, §15.3, §15.5.

 NINE VECTORS, exactly the set §15.3's ratchet.json table requires:

     RATCHET-INIT           A and B initial states; A.CKs == B.CKr AND A.RK != B.RK   (§7.5)
     RATCHET-LINEAR         ten messages A->B in one sending chain, no turn between them
     RATCHET-BIDI           A->B, B->A, A->B, B->A; SESSION_AD role ordering          (§6.5)
     RATCHET-SKIP           0,1,2,3 sent; 1 and 2 delivered last                      (§7.6)
     RATCHET-SKIP-XCHAIN    skipped keys recovered ACROSS a DH ratchet                (§7.4, §7.6)
     RATCHET-PREKEY-BURST   three type 0x02 messages, N = 0,1,2, before B replies     (§9.2, §11.3)
     RATCHET-RETRANSMIT     the same type 0x02 twice; the second is ERR_REPLAY        (§11.2, §11.4)
     SESSION-COLLAPSE       concurrent initiation, two-sided, per-side assertions     (§10.7, §11.1.1)
     DEMUX-NO-TRIAL         the NEG-DEMUX-WRONG-SESSION fixture's recovery step       (§11.5 rule 3)

 THE GENERATOR AND THE EXECUTOR ARE THE SAME CODE, and that is the single most important design
 decision in this file. Each vector has ONE run function, `IRRatchetRun<Name>(io)`. The IO object is
 in one of two modes:

     GENERATING   `inputs` are read out of a dictionary of LITERALS declared in this file, and every
                  read is RECORDED into the vector's `inputs` object in its JSON form. Every
                  `checkOutput:` RECORDS the produced value into `outputs`.
     EXECUTING    `inputs` are read out of the FROZEN file through IRVectorCase — which consumes
                  them, giving §15.5 rule 3 — and every `checkOutput:` ASSERTS.

 Written any other way, a generator and an executor drift: the generator emits a field the executor
 never reads (rule 3), or the executor asserts a value the generator computed a different way. Here
 the two cannot disagree, because there is only one expression of each.

 THE PRICE OF THAT SHARING IS THE FAILURE STYLE, and it is worth stating rather than discovering.
 IRVectorWire.m's executor records an XCTest issue and returns, so one malformed vector does not stop
 the rest; here a structural problem — a script that does not match the draw sequence, a session blob
 §12.2 rejects, a conversation that does not reach its own claim — goes through IRVectorRequire,
 which RAISES. XCTest turns that into a failure on the driver's test method, and the vectors after it
 in the run do not execute. That is the right trade for this module: every such condition means the
 fixture itself is wrong rather than one assertion inside it, and continuing past a party whose
 CSPRNG position has diverged would report a cascade of unrelated byte mismatches instead of the one
 line that explains them. VALUE mismatches — every `outputs` and `intermediates` comparison — still
 go through IRVectorCase and still accumulate.

 NOTHING IN THIS FILE READS THE HOST CLOCK. Every party's environment is built with
 IRVectorEnvironmentAtUnixMilliseconds from `inputs.now_ms`, and §15.6's ten-years-forward run is
 what proves it: a single [NSDate date] anywhere here produces different bytes on that run and fails
 the freeze comparison.

 EVERY RANDOM DRAW IS SCRIPTED, PER PARTY, IN DRAW ORDER (§15.5 rule 5). Each party gets its own
 IRScriptedRandomSource, so the two sides' draws do not interleave and each side's script can be read
 as a list. The draws this implementation makes, and their exact widths:

     +[IRIdentity generateWithProvider:]              32 (Ed25519 seed) then 32 (X25519 scalar)
     -generateX25519KeyPairGuarded:error:             32
     -randomNonceWithError:                           12
     +[IRRatchet initiatorStateWithSharedKey:...]     32  (the fresh DHs of §7.5)
     +[IRRatchet dhRatchetOnState:...] step 4         32  (the fresh DHs of §7.4)
     +[IRRatchet encryptOnState:...]                  12  (§8.3's per-seal nonce)

 THE SCRIPTED SOURCE FAILS ON EXHAUSTION RATHER THAN CYCLING, deliberately, so a miscounted script
 stops the generator with a named error instead of silently reusing a nonce. Every party asserts
 `bytesRemaining == 0` when its conversation ends, which catches the opposite mistake — a script with
 an entry nothing ever drew.

 THE RANDOMNESS IS NAMED, NOT A FLAT STREAM. `EK_A_scalar`, `DHs_A_scalars[i]`, `nonces_A[i]` are
 separate `inputs` keys because THE DRAW ORDER IS NOT NORMATIVE: nothing in this document fixes
 whether a port generates its ratchet key pair before or after some other value, so a port that
 received one opaque byte stream would have to reproduce Objective-C's call order to pass. A port
 reproduces the NAMES; the order in which it feeds them to its own CSPRNG seam is its own business.

 WHY TWO LAYERS. Six vectors drive IRRatchet directly, because that is the layer whose `CKs`, `CKr`,
 `RK` and skipped-key count the §15.3 table names. Three — RATCHET-RETRANSMIT, SESSION-COLLAPSE and
 DEMUX-NO-TRIAL — drive IRMessenger, because §11.2's three ordered checks, §10.7's fourteen steps and
 §11.5's handle rules exist only at that layer and no lower-layer construction can reach them.

 SESSION-COLLAPSE AND DEMUX-NO-TRIAL TAKE THEIR PRE-EXISTING SESSIONS AS LITERAL §12.1 BLOBS in
 `inputs.sessions`, which is what §15.5's reserved-key table requires: "Session fixtures are supplied
 as literal §12.1 blobs, never as 'replay these handshakes'". The generator produces those blobs in a
 PREPARE phase — a full conversation run once, from the same fixed scalars — and then the vector's
 run function consumes them exactly as a port will. §15.3's `sessions.<name>.state_blob_after` is
 emitted in that dotted form, and it is compared byte-for-byte against the matching input blob, which
 is the only expressible statement of §10.7 step 14c's "the surviving session's state MUST NOT be
 modified".
 */

#pragma mark - Deterministic byte material

/**
 The filler behind every fixed value in this file.

 Every scalar, seed and nonce is `<prefix> ‖ <filler truncated to width>`, so two values are distinct
 whenever their prefixes are, and no value is all-zero — §13.1's tripwire rejects an all-zero scalar
 inside the generator, which would fail the run rather than produce a wrong vector, but a fixture
 that could trip it at all is one nobody should have to reason about.
 */
static NSString * const kIRRatchetFiller =
    @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    @"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// `prefixHex` (even-length, lowercase) padded with the filler to exactly `length` bytes.
static NSData *IRRatchetFixedBytes(NSString *prefixHex, NSUInteger length) {
    IRVectorRequire(prefixHex.length % 2 == 0 && prefixHex.length <= length * 2,
                    @"prefix \"%@\" does not fit in %lu bytes", prefixHex, (unsigned long)length);

    NSMutableString *hex = [prefixHex mutableCopy];
    while (hex.length < length * 2) {
        NSUInteger want = length * 2 - hex.length;
        NSUInteger take = MIN(want, kIRRatchetFiller.length);
        [hex appendString:[kIRRatchetFiller substringToIndex:take]];
    }

    return IRVectorBytes(hex);
}

/// `prefixHex ‖ uint8(index)` padded to `length`. Distinct for distinct (prefix, index) pairs.
static NSData *IRRatchetIndexedBytes(NSString *prefixHex, NSUInteger index, NSUInteger length) {
    IRVectorRequire(index <= 0xFF, @"index %lu does not fit in one byte", (unsigned long)index);

    return IRRatchetFixedBytes([NSString stringWithFormat:@"%@%02x", prefixHex, (unsigned)index],
                               length);
}

/// `count` distinct 32-byte scalars under one role prefix, in index order.
static NSArray<NSData *> *IRRatchetScalarRun(NSString *prefixHex, NSUInteger count) {
    NSMutableArray<NSData *> *values = [NSMutableArray arrayWithCapacity:count];
    for (NSUInteger index = 0; index < count; index++) {
        [values addObject:IRRatchetIndexedBytes(prefixHex, index, (NSUInteger)kIRLenX25519Private)];
    }

    return values;
}

/// `count` distinct 12-byte nonces under one role prefix, in index order (§8.3).
static NSArray<NSData *> *IRRatchetNonceRun(NSString *prefixHex, NSUInteger count) {
    NSMutableArray<NSData *> *values = [NSMutableArray arrayWithCapacity:count];
    for (NSUInteger index = 0; index < count; index++) {
        [values addObject:IRRatchetIndexedBytes(prefixHex, index, (NSUInteger)kIRLenNonce)];
    }

    return values;
}

/* Long-lived identity material. §4.2: the Ed25519 private key is the 32-byte RFC 8032 SEED, never
   libsodium's 64-byte expanded sk; the X25519 scalar is stored CLAMPED, and the clamp is applied by
   +generateX25519KeyPairGuarded: rather than by this file, so the frozen public halves are whatever
   the implementation actually derives. */
#define kIRRatchetAliceSigningSeed     IRRatchetFixedBytes(@"a1", 32)
#define kIRRatchetAliceAgreement       IRRatchetFixedBytes(@"a2", 32)
#define kIRRatchetBobSigningSeed       IRRatchetFixedBytes(@"b1", 32)
#define kIRRatchetBobAgreement         IRRatchetFixedBytes(@"b2", 32)
#define kIRRatchetCarolSigningSeed     IRRatchetFixedBytes(@"c1", 32)
#define kIRRatchetCarolAgreement       IRRatchetFixedBytes(@"c2", 32)

/* Medium-term and one-time prekeys (§5.2). */
#define kIRRatchetBobSPKScalar         IRRatchetFixedBytes(@"51", 32)
#define kIRRatchetBobOPKScalar         IRRatchetFixedBytes(@"52", 32)
#define kIRRatchetBobOPK2Scalar        IRRatchetFixedBytes(@"53", 32)
#define kIRRatchetAliceSPKScalar       IRRatchetFixedBytes(@"54", 32)
#define kIRRatchetAliceOPKScalar       IRRatchetFixedBytes(@"55", 32)

/* Handshake ephemerals (§6.1). Used for exactly one X3DH and then wiped by IRX3DH. */
#define kIRRatchetAliceEphemeral       IRRatchetFixedBytes(@"e1", 32)
#define kIRRatchetBobEphemeral         IRRatchetFixedBytes(@"e2", 32)
#define kIRRatchetCarolEphemeral       IRRatchetFixedBytes(@"e3", 32)

/* Per-role ratchet-key and nonce prefixes. */
static NSString * const kIRRatchetScalarPrefixA = @"a3";
static NSString * const kIRRatchetScalarPrefixB = @"b3";
static NSString * const kIRRatchetScalarPrefixC = @"c3";
static NSString * const kIRRatchetNoncePrefixA  = @"a4";
static NSString * const kIRRatchetNoncePrefixB  = @"b4";
static NSString * const kIRRatchetNoncePrefixC  = @"c4";

/* Prekey ids. Deliberately not 0 and not 1: a port that defaulted either field would still pass a
   fixture built on small values. */
static const uint32_t kIRRatchetBobSpkId   = 0x11223344;
static const uint32_t kIRRatchetBobOpkId   = 0x55667788;
static const uint32_t kIRRatchetBobOpk2Id  = 0x55667789;
static const uint32_t kIRRatchetAliceSpkId = 0x21324354;
static const uint32_t kIRRatchetAliceOpkId = 0x65768798;

/* §5.2's validity window, and the injected clock inside it (§15.5 rule 6).
   2026-01-01T00:00:00Z .. 2026-03-30T00:00:00Z is 7603200 seconds, inside MAX_SPK_VALIDITY_SECONDS
   (7776000). `now` is 2026-01-08T00:00:00Z, comfortably inside. */
static const uint64_t kIRRatchetNotBeforeS = 1767225600ULL;
static const uint64_t kIRRatchetNotAfterS  = 1774828800ULL;
static const uint64_t kIRRatchetNowS       = 1767830400ULL;
static const uint64_t kIRRatchetNowMs      = 1767830400000ULL;

#pragma mark - Small conversions

/// A secret's bytes as NSData, for hex encoding. Nil in, nil out — an absent `CKr` is a legal state.
static NSData * _Nullable IRRatchetSecretData(IRSecretBytes * _Nullable secret) {
    if (secret == nil) {
        return nil;
    }

    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

/// The §12.1 blob of a live session, as plain bytes. The IRSecretBytes original is wiped here, per
/// §13.3's "serialized state buffer — after sealing, and after parsing".
static NSData *IRRatchetStateBlob(IRSession *session) {
    NSError *error = nil;
    IRSecretBytes *blob = [session serializedState:&error];
    IRVectorRequire(blob != nil, @"§12.1 serialization failed: %@", error);

    NSData *copy = [NSData dataWithBytes:blob.constBytes length:blob.length];
    [blob zeroizeNow];

    return copy;
}

/// `<stem>_<index>` — the indexed key naming used by every multi-message vector below.
static NSString *IRRatchetIndexedKey(NSString *stem, NSUInteger index) {
    return [NSString stringWithFormat:@"%@_%lu", stem, (unsigned long)index];
}

static NSData *IRRatchetText(NSString *text) {
    return [text dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - IRRatchetIO — one expression of each vector, two modes

/**
 THE GENERATOR/EXECUTOR SEAM. See this file's header comment for why it exists.

 In GENERATING mode `values` holds the literals a vector is built from, keyed exactly as the vector's
 `inputs` will be. Reading one records its JSON form; -requireEveryValueRead then fails the build if
 a literal was declared and never consumed, which is the generator-side mirror of §15.5 rule 3.

 In EXECUTING mode every accessor forwards to IRVectorCase, whose own bookkeeping enforces rules 1, 2
 and 3 at -finish.
 */
@interface IRRatchetIO : NSObject

+ (instancetype)generatorWithValues:(NSDictionary<NSString *, id> *)values;
+ (instancetype)executorWithCase:(IRVectorCase *)vectorCase;

@property (nonatomic, readonly) BOOL isGenerating;
@property (nonatomic, strong, readonly, nullable) IRVectorCase *vectorCase;

/// Populated in generating mode only; these three become the vector's three sections.
@property (nonatomic, strong, readonly) NSMutableDictionary *recordedInputs;
@property (nonatomic, strong, readonly) NSMutableDictionary *recordedIntermediates;
@property (nonatomic, strong, readonly) NSMutableDictionary *recordedOutputs;

#pragma mark Inputs — declaring, or consuming, one `inputs` key

/// A hex byte string.
- (NSData *)dataInput:(NSString *)key;

/// A uint8/uint16/uint32 protocol field: a JSON NUMBER (§15.2).
- (uint32_t)uint32Input:(NSString *)key;

/// A uint64-typed field: a JSON STRING holding the unsigned decimal value (§15.2, rule 7).
- (uint64_t)uint64Input:(NSString *)key;

- (NSString *)stringInput:(NSString *)key;

/// An ordered array of hex byte strings.
- (NSArray<NSData *> *)dataArrayInput:(NSString *)key;

/// §15.5's reserved `sessions` object, normalized to NSData in both modes.
- (NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *)sessionsInput;

/// Generating mode only: every declared literal was read. A no-op while executing, where
/// -[IRVectorCase finish] enforces the same rule from the other side.
- (void)requireEveryValueRead;

#pragma mark Intermediates (§15.5 rule 2)

- (void)intermediate:(NSString *)key data:(NSData * _Nullable)value;
- (void)intermediate:(NSString *)key number:(NSUInteger)value;

#pragma mark Outputs (§15.5 rule 1)

- (void)output:(NSString *)key data:(NSData * _Nullable)value;
- (void)output:(NSString *)key number:(NSUInteger)value;
- (void)output:(NSString *)key uint64:(uint64_t)value;
- (void)output:(NSString *)key boolean:(BOOL)value;
- (void)output:(NSString *)key string:(NSString *)value;

@end

@interface IRRatchetIO ()
@property (nonatomic, assign) BOOL generating;
@property (nonatomic, strong, nullable) NSDictionary<NSString *, id> *values;
@property (nonatomic, strong) NSMutableSet<NSString *> *readValues;
@property (nonatomic, strong, nullable) IRVectorCase *mutableCase;

/// The vector id, for diagnostics. Declared here rather than in the public interface because only
/// this file's own error messages use it.
@property (nonatomic, readonly) NSString *identifier;
@end

@implementation IRRatchetIO

@synthesize recordedInputs = _recordedInputs;
@synthesize recordedIntermediates = _recordedIntermediates;
@synthesize recordedOutputs = _recordedOutputs;

+ (instancetype)generatorWithValues:(NSDictionary<NSString *, id> *)values {
    IRRatchetIO *io = [[IRRatchetIO alloc] init];
    io.generating = YES;
    io.values = values;
    io.readValues = [NSMutableSet set];
    io->_recordedInputs = [NSMutableDictionary dictionary];
    io->_recordedIntermediates = [NSMutableDictionary dictionary];
    io->_recordedOutputs = [NSMutableDictionary dictionary];

    return io;
}

+ (instancetype)executorWithCase:(IRVectorCase *)vectorCase {
    IRRatchetIO *io = [[IRRatchetIO alloc] init];
    io.generating = NO;
    io.mutableCase = vectorCase;
    io->_recordedInputs = [NSMutableDictionary dictionary];
    io->_recordedIntermediates = [NSMutableDictionary dictionary];
    io->_recordedOutputs = [NSMutableDictionary dictionary];

    return io;
}

- (BOOL)isGenerating {
    return self.generating;
}

- (IRVectorCase *)vectorCase {
    return self.mutableCase;
}

/// The vector id, for diagnostics. A placeholder while generating, since the id is attached by the
/// wrapper that builds the vector object rather than by the run function.
- (NSString *)identifier {
    return self.generating ? @"<generating>" : self.mutableCase.identifier;
}

- (id)literalFor:(NSString *)key {
    id value = self.values[key];
    IRVectorRequire(value != nil, @"the generator has no literal for inputs.%@", key);
    [self.readValues addObject:key];

    return value;
}

#pragma mark Inputs

- (NSData *)dataInput:(NSString *)key {
    if (!self.generating) {
        return [self.mutableCase dataInput:key];
    }

    NSData *value = [self literalFor:key];
    IRVectorRequire([value isKindOfClass:[NSData class]], @"inputs.%@ literal is not NSData", key);
    self.recordedInputs[key] = IRVectorHex(value);

    return value;
}

- (uint32_t)uint32Input:(NSString *)key {
    if (!self.generating) {
        return [self.mutableCase uint32Input:key];
    }

    NSNumber *value = [self literalFor:key];
    IRVectorRequire([value isKindOfClass:[NSNumber class]], @"inputs.%@ literal is not a number", key);
    /* §15.2 — uint8/uint16/uint32 protocol fields are JSON NUMBERS. */
    self.recordedInputs[key] = value;

    return (uint32_t)value.unsignedLongLongValue;
}

- (uint64_t)uint64Input:(NSString *)key {
    if (!self.generating) {
        return [self.mutableCase uint64Input:key];
    }

    NSNumber *value = [self literalFor:key];
    IRVectorRequire([value isKindOfClass:[NSNumber class]], @"inputs.%@ literal is not a number", key);
    /* §15.2 — every uint64-typed field is a decimal STRING, irrespective of magnitude. */
    self.recordedInputs[key] = IRVectorUInt64String(value.unsignedLongLongValue);

    return value.unsignedLongLongValue;
}

- (NSString *)stringInput:(NSString *)key {
    if (!self.generating) {
        return [self.mutableCase stringInput:key];
    }

    NSString *value = [self literalFor:key];
    IRVectorRequire([value isKindOfClass:[NSString class]], @"inputs.%@ literal is not a string", key);
    self.recordedInputs[key] = value;

    return value;
}

- (NSArray<NSData *> *)dataArrayInput:(NSString *)key {
    if (self.generating) {
        NSArray *literals = [self literalFor:key];
        IRVectorRequire([literals isKindOfClass:[NSArray class]],
                        @"inputs.%@ literal is not an array", key);

        NSMutableArray<NSString *> *hexes = [NSMutableArray arrayWithCapacity:literals.count];
        for (id item in literals) {
            IRVectorRequire([item isKindOfClass:[NSData class]],
                            @"inputs.%@ holds a non-NSData element", key);
            [hexes addObject:IRVectorHex(item)];
        }
        self.recordedInputs[key] = hexes;

        return literals;
    }

    NSArray *raw = [self.mutableCase arrayInput:key];
    NSMutableArray<NSData *> *values = [NSMutableArray arrayWithCapacity:raw.count];
    for (id item in raw) {
        IRVectorRequire([item isKindOfClass:[NSString class]] && IRVectorHexIsWellFormed(item),
                        @"[%@] inputs.%@ holds a value that is not lowercase hex (§15.5 rule 4)",
                        self.identifier, key);
        [values addObject:IRVectorBytes(item)];
    }

    return values;
}

/**
 §15.5's reserved `sessions` input, normalized to NSData in both modes.

 The on-the-wire shape is `{ "<name>": { "handshake_id": hex, "peer_identity": hex,
 "state_blob": hex } }` — a map of fixture names to literal §12.1 blobs, which is what makes a
 multi-session vector reproducible without replaying a handshake.
 */
- (NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *)sessionsInput {
    NSMutableDictionary *normalized = [NSMutableDictionary dictionary];

    if (self.generating) {
        NSDictionary *literals = [self literalFor:@"sessions"];
        IRVectorRequire([literals isKindOfClass:[NSDictionary class]],
                        @"inputs.sessions literal is not a dictionary");

        NSMutableDictionary *recorded = [NSMutableDictionary dictionary];
        for (NSString *name in literals) {
            NSDictionary *fixture = literals[name];
            IRVectorRequire([fixture isKindOfClass:[NSDictionary class]],
                            @"inputs.sessions.%@ is not a dictionary", name);

            NSMutableDictionary *recordedFixture = [NSMutableDictionary dictionary];
            NSMutableDictionary *normalizedFixture = [NSMutableDictionary dictionary];
            for (NSString *field in fixture) {
                NSData *bytes = fixture[field];
                IRVectorRequire([bytes isKindOfClass:[NSData class]],
                                @"inputs.sessions.%@.%@ is not NSData", name, field);
                recordedFixture[field] = IRVectorHex(bytes);
                normalizedFixture[field] = bytes;
            }
            recorded[name] = recordedFixture;
            normalized[name] = normalizedFixture;
        }

        self.recordedInputs[@"sessions"] = recorded;

        return normalized;
    }

    NSDictionary *raw = [self.mutableCase optionalDictionaryInput:@"sessions"];
    IRVectorRequire(raw != nil, @"[%@] inputs.sessions is missing", self.identifier);

    for (NSString *name in raw) {
        NSDictionary *fixture = raw[name];
        IRVectorRequire([fixture isKindOfClass:[NSDictionary class]],
                        @"[%@] inputs.sessions.%@ is not an object", self.identifier, name);

        NSMutableDictionary *normalizedFixture = [NSMutableDictionary dictionary];
        for (NSString *field in fixture) {
            id value = fixture[field];
            IRVectorRequire([value isKindOfClass:[NSString class]] && IRVectorHexIsWellFormed(value),
                            @"[%@] inputs.sessions.%@.%@ is not lowercase hex",
                            self.identifier, name, field);
            normalizedFixture[field] = IRVectorBytes(value);
        }
        normalized[name] = normalizedFixture;
    }

    return normalized;
}

/// Generator-side mirror of §15.5 rule 3: a declared literal that no run function read would be a
/// field absent from `inputs` while the author believed it was pinned.
- (void)requireEveryValueRead {
    if (!self.generating) {
        return;
    }

    NSMutableSet<NSString *> *unread = [NSMutableSet setWithArray:self.values.allKeys];
    [unread minusSet:self.readValues];
    IRVectorRequire(unread.count == 0,
                    @"the generator declared literals nothing read: %@",
                    [[unread.allObjects sortedArrayUsingSelector:@selector(compare:)]
                        componentsJoinedByString:@", "]);
}

#pragma mark Intermediates (§15.5 rule 2)

- (void)intermediate:(NSString *)key data:(NSData * _Nullable)value {
    if (self.generating) {
        IRVectorRequire(value != nil, @"the generator produced no value for intermediates.%@", key);
        self.recordedIntermediates[key] = IRVectorHex(value);
        return;
    }

    [self.mutableCase checkIntermediate:key data:value];
}

- (void)intermediate:(NSString *)key number:(NSUInteger)value {
    if (self.generating) {
        self.recordedIntermediates[key] = @(value);
        return;
    }

    [self.mutableCase checkIntermediate:key number:@(value)];
}

#pragma mark Outputs (§15.5 rule 1)

- (void)output:(NSString *)key data:(NSData * _Nullable)value {
    if (self.generating) {
        IRVectorRequire(value != nil, @"the generator produced no value for outputs.%@", key);
        self.recordedOutputs[key] = IRVectorHex(value);
        return;
    }

    [self.mutableCase checkOutput:key data:value];
}

- (void)output:(NSString *)key number:(NSUInteger)value {
    if (self.generating) {
        self.recordedOutputs[key] = @(value);
        return;
    }

    [self.mutableCase checkOutput:key number:@(value)];
}

- (void)output:(NSString *)key uint64:(uint64_t)value {
    if (self.generating) {
        /* §15.2 — a uint64-typed output is a decimal STRING like a uint64-typed input. */
        self.recordedOutputs[key] = IRVectorUInt64String(value);
        return;
    }

    [self.mutableCase checkOutput:key uint64:value];
}

- (void)output:(NSString *)key boolean:(BOOL)value {
    if (self.generating) {
        /* §15.5 — "JSON booleans are permitted in `outputs`", and rule 7 does not apply to them. */
        self.recordedOutputs[key] = value ? @YES : @NO;
        return;
    }

    [self.mutableCase checkOutput:key boolean:value];
}

- (void)output:(NSString *)key string:(NSString *)value {
    if (self.generating) {
        self.recordedOutputs[key] = value;
        return;
    }

    [self.mutableCase checkOutput:key string:value];
}

@end

#pragma mark - Common input blocks

/**
 The clock (§15.5 rule 6), read by EVERY vector in this file.

 A ratchet vector cannot avoid a clock: §7.6 stamps every skipped key with `now_ms()`, §12.2 rule 9
 sweeps against it, §10.7 step 4 checks a tombstone window against it, and §5.3 rules 5–6 check the
 bundle window against `now_s`. §15.5 rule 6 makes a clock-reading vector that supplies no `now_*`
 MALFORMED, so both are always present and both are decimal strings.
 */
typedef struct {
    uint64_t nowS;
    uint64_t nowMs;
} IRRatchetClock;

static IRRatchetClock IRRatchetReadClock(IRRatchetIO *io) {
    IRRatchetClock clock;
    clock.nowS = [io uint64Input:@"now_s"];
    clock.nowMs = [io uint64Input:@"now_ms"];

    /* The two readings MUST agree about which second it is. IRFixedClock derives seconds from
       milliseconds by integer division precisely so a split instant cannot make a TTL test flaky;
       a vector that supplied inconsistent values would be testing a clock no implementation has. */
    IRVectorRequire(clock.nowMs / 1000ULL == clock.nowS,
                    @"now_ms %llu and now_s %llu disagree",
                    (unsigned long long)clock.nowMs, (unsigned long long)clock.nowS);

    return clock;
}

/// The `entry_point` of §15.5's reserved table, checked against what this vector actually calls.
static void IRRatchetReadEntryPoint(IRRatchetIO *io, NSString *expected) {
    NSString *entryPoint = [io stringInput:@"entry_point"];
    IRVectorRequire([entryPoint isEqualToString:expected],
                    @"entry_point is \"%@\", expected \"%@\"", entryPoint, expected);
}

#pragma mark - IRRatchetParty — one side of a ratchet-level conversation

/**
 A party at the IRRatchet layer: an identity, a scripted CSPRNG, a fixed clock, and one live state.

 The six §15.3 rows that name `CKs`, `CKr`, `RK` or the skipped-key count are driven from here rather
 than through IRMessenger, because those are the values the table asserts and the messenger does not
 expose them. -receive: below IS the four-step sequence IRRatchet.h prescribes — gate, budget,
 snapshot, decrypt-then-commit-or-discard — so a vector generated here exercises the same
 orchestration a conformant Layer 9 performs.
 */
@interface IRRatchetParty : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, strong) IRScriptedRandomSource *source;
@property (nonatomic, strong) IREnvironment *environment;
@property (nonatomic, strong) id<IRCryptoProvider> provider;
@property (nonatomic, strong) IRIdentity *identity;
@property (nonatomic, strong, nullable) IRRatchetState *state;
@property (nonatomic, assign) uint64_t nowS;
@property (nonatomic, assign) uint64_t nowMs;
@end

@implementation IRRatchetParty
@end

/// A signed prekey, its one-time prekeys, and the §5.4 bundle that publishes them.
@interface IRRatchetPreKeys : NSObject
@property (nonatomic, strong) IRSignedPreKeyRecord *signedPreKey;
@property (nonatomic, strong) NSArray<IROneTimePreKeyRecord *> *oneTimePreKeys;
@property (nonatomic, copy) NSData *bundleData;
@end

@implementation IRRatchetPreKeys
@end

/**
 A party whose identity is derived from the first two entries of `script`.

 +[IRIdentity generateWithProvider:] draws the Ed25519 SEED first and the X25519 scalar second, then
 signs IKBIND_MSG (§5.1). Scripting the two in that order reproduces a whole identity, `IKB`
 included, through the production constructor — there is no injection point that would let a test
 assemble one field by field, and there should not be.
 */
static IRRatchetParty *IRRatchetPartyCreate(NSString *name,
                                            NSArray<NSData *> *script,
                                            uint64_t nowS,
                                            uint64_t nowMs) {
    IRRatchetParty *party = [[IRRatchetParty alloc] init];
    party.name = name;
    party.nowS = nowS;
    party.nowMs = nowMs;
    party.source = [IRScriptedRandomSource sourceWithDataItems:script];

    /* §15.5 rule 6 — the clock is INJECTED, never ambient. §15.6's ten-years-forward run is what
       proves it: an ambient read here changes the frozen bytes on that run. */
    party.environment = IRVectorEnvironmentAtUnixMilliseconds(nowMs, party.source);
    party.provider = IRVectorProviderWithEnvironment(party.environment);

    NSError *error = nil;
    party.identity = [IRIdentity generateWithProvider:party.provider error:&error];
    IRVectorRequire(party.identity != nil, @"%@: identity generation failed: %@", name, error);

    return party;
}

/// Every scripted byte was drawn, and nothing drew past the end. Both directions are mistakes.
static void IRRatchetPartyRequireScriptExhausted(IRRatchetParty *party) {
    IRVectorRequire(party.source.bytesRemaining == 0,
                    @"%@ left %lu scripted byte(s) unread — the script does not match the draw "
                    @"sequence this implementation makes",
                    party.name, (unsigned long)party.source.bytesRemaining);
}

/**
 §5.2 / §5.4 — a signed prekey and `opkIds.count` one-time prekeys, then the published bundle.

 Built from the RECORD constructors rather than through -publishBundleWithSPKId:, so that the only
 CSPRNG draws are the key scalars themselves: the messenger's publisher additionally draws four
 bytes per `opk_id`, which would put an id-selection loop inside a script this file has to predict
 exactly. The ids are fixed literals here for the same reason §15.5 wants them pinned.

 `SPK_SIG` is a GENUINE §5.2 signature over the 130-byte SPK_SIGN_MSG. Ed25519 is deterministic
 (RFC 8032 §5.1.6), so it is reproducible across runs and across platforms.
 */
static IRRatchetPreKeys *IRRatchetPartyPublish(IRRatchetParty *party,
                                               uint32_t spkId,
                                               uint64_t notBeforeS,
                                               uint64_t notAfterS,
                                               NSArray<NSNumber *> *opkIds) {
    NSError *error = nil;

    IRX25519KeyPair *signedPreKeyPair = [party.provider generateX25519KeyPairGuarded:YES
                                                                               error:&error];
    IRVectorRequire(signedPreKeyPair != nil, @"%@: SPK generation: %@", party.name, error);

    NSData *signMessage = IRSPKSignMessage(party.identity.identityKeyPair,
                                           spkId,
                                           signedPreKeyPair.publicKey,
                                           notBeforeS,
                                           notAfterS,
                                           &error);
    IRVectorRequire(signMessage != nil, @"%@: SPK_SIGN_MSG: %@", party.name, error);

    IREd25519Signature *signature = [party.identity signData:signMessage error:&error];
    IRVectorRequire(signature != nil, @"%@: SPK_SIG: %@", party.name, error);

    IRSignedPreKeyRecord *signedPreKey = [IRSignedPreKeyRecord recordWithSpkId:spkId
                                                                      keyPair:signedPreKeyPair
                                                                   notBeforeS:notBeforeS
                                                                    notAfterS:notAfterS
                                                                    signature:signature
                                                                        error:&error];
    IRVectorRequire(signedPreKey != nil, @"%@: SPK record: %@", party.name, error);

    NSMutableArray<IROneTimePreKeyRecord *> *oneTimePreKeys =
        [NSMutableArray arrayWithCapacity:opkIds.count];

    for (NSNumber *opkId in opkIds) {
        IRX25519KeyPair *pair = [party.provider generateX25519KeyPairGuarded:YES error:&error];
        IRVectorRequire(pair != nil, @"%@: OPK generation: %@", party.name, error);

        IROneTimePreKeyRecord *record =
            [IROneTimePreKeyRecord recordWithOpkId:(uint32_t)opkId.unsignedLongLongValue
                                           keyPair:pair
                                 createdAtUnixSecs:party.nowS
                                             error:&error];
        IRVectorRequire(record != nil, @"%@: OPK record: %@", party.name, error);

        [oneTimePreKeys addObject:record];
    }

    NSData *bundleData = [IRPreKeyBundle serializeWithIdentity:party.identity.publicIdentity
                                           signedPreKeyRecord:signedPreKey
                                         oneTimePreKeyRecords:oneTimePreKeys
                                                        error:&error];
    IRVectorRequire(bundleData != nil, @"%@: bundle: %@", party.name, error);

    IRRatchetPreKeys *published = [[IRRatchetPreKeys alloc] init];
    published.signedPreKey = signedPreKey;
    published.oneTimePreKeys = oneTimePreKeys;
    published.bundleData = bundleData;

    return published;
}

/**
 §5.3 then §6 then §7.5's initiator half.

 Two draws, in this order: the handshake ephemeral `EK_A` (§6.1), then §7.5's fresh `DHs`. The
 bundle is re-parsed from its published bytes so that §10.3's structural gate and §5.3 rules 1–4 run
 exactly as they will at a real initiator; rules 5–6 run inside IRX3DH from the injected `now_s`.
 */
static void IRRatchetPartyBegin(IRRatchetParty *party, NSData *bundleData) {
    NSError *error = nil;

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleData
                                                   provider:party.provider
                                                      error:&error];
    IRVectorRequire(bundle != nil, @"%@: §10.3 rejected the bundle: %@", party.name, error);

    IRX25519KeyPair *ephemeral = [party.provider generateX25519KeyPairGuarded:NO error:&error];
    IRVectorRequire(ephemeral != nil, @"%@: EK_A generation: %@", party.name, error);

    IRX3DHResult *result = [IRX3DH initiatorResultWithIdentity:party.identity
                                                        bundle:bundle
                                              ephemeralKeyPair:ephemeral
                                                nowUnixSeconds:party.nowS
                                                      provider:party.provider
                                                     retainIKM:NO
                                                         error:&error];
    IRVectorRequire(result != nil, @"%@: X3DH as initiator: %@", party.name, error);

    IRRatchetState *state = [IRRatchet initiatorStateWithSharedKey:result.sharedKey
                                            responderSignedPreKey:bundle.signedPreKey
                                                        sessionAD:result.sessionAD
                                                      handshakeId:result.handshakeId
                                                         prologue:result.prologue
                                                         provider:party.provider
                                                            error:&error];
    IRVectorRequire(state != nil, @"%@: §7.5 initiator init: %@", party.name, error);

    /* §13.3 — SK dies immediately after ratchet initialization, and IRRatchet copied rather than
       adopted it, so this cannot reach the new session's root key. */
    [result zeroize];

    party.state = state;
}

/**
 §10.7 steps 3 and 8–11 plus §7.5's responder half, from an already-gated type `0x02` header.

 NO CSPRNG DRAW HAPPENS HERE. `DHs` is a session-owned COPY of the signed prekey pair (§7.5, §19.1);
 the fresh pair arrives on the first DH ratchet, which is the very next thing -receive: does.
 */
static void IRRatchetPartyEstablishResponder(IRRatchetParty *party,
                                             IRMessageHeader *header,
                                             IRRatchetPreKeys *preKeys) {
    NSError *error = nil;

    /* §10.7 step 3 — verify IKB_A BEFORE any DH. Structural: IRPublicIdentity has exactly one
       constructor and it performs the check, so an unverified identity cannot reach IRX3DH. */
    IRPublicIdentity *initiator = [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                                                binding:header.identityBinding
                                                               provider:party.provider
                                                                  error:&error];
    IRVectorRequire(initiator != nil, @"%@: §10.7 step 3, IKB_A: %@", party.name, error);

    IRVectorRequire(header.spkId == preKeys.signedPreKey.spkId,
                    @"%@: §10.7 step 5 — spk_id %u does not resolve",
                    party.name, (unsigned)header.spkId);

    IROneTimePreKeyRecord *oneTimePreKey = nil;
    if (header.opkFlag == IROPKFlagPresent) {
        for (IROneTimePreKeyRecord *record in preKeys.oneTimePreKeys) {
            if (record.opkId == header.opkId) {
                oneTimePreKey = record;
                break;
            }
        }
        IRVectorRequire(oneTimePreKey != nil,
                        @"%@: §10.7 step 7 — opk_id %u does not resolve",
                        party.name, (unsigned)header.opkId);
    }

    IRX3DHResult *result = [IRX3DH responderResultWithIdentity:party.identity
                                             initiatorIdentity:initiator
                                               ephemeralPublic:header.ephemeralPublic
                                              signedPreKeyPair:preKeys.signedPreKey.keyPair
                                                         spkId:header.spkId
                                                       opkFlag:header.opkFlag
                                                         opkId:header.opkId
                                             oneTimePreKeyPair:oneTimePreKey.keyPair
                                                      provider:party.provider
                                                     retainIKM:NO
                                                         error:&error];
    IRVectorRequire(result != nil, @"%@: X3DH as responder: %@", party.name, error);

    IRRatchetState *state = [IRRatchet responderStateWithSharedKey:result.sharedKey
                                                 signedPreKeyPair:preKeys.signedPreKey.keyPair
                                                        sessionAD:result.sessionAD
                                                      handshakeId:result.handshakeId
                                                            error:&error];
    IRVectorRequire(state != nil, @"%@: §7.5 responder init: %@", party.name, error);

    [result zeroize];

    party.state = state;
}

/// §7.8. One draw: §8.3's per-seal nonce. The type comes from the state (§11.3), never the caller.
static NSData *IRRatchetPartySend(IRRatchetParty *party, NSData *plaintext) {
    NSError *error = nil;

    const BOOL prekey = party.state.shouldSendPreKeyMessage;
    NSData *message = [IRRatchet encryptOnState:party.state
                                      plaintext:plaintext
                                    messageType:(prekey ? IRMessageTypePrekey : IRMessageTypeNormal)
                              initiatorIdentity:(prekey ? party.identity.identityKeyPair : nil)
                                identityBinding:(prekey ? party.identity.binding : nil)
                                       provider:party.provider
                                          error:&error];
    IRVectorRequire(message != nil, @"%@: §7.8 encrypt: %@", party.name, error);

    return message;
}

/// §10.0 then §10.1 / §10.2 — the gate for a message about to be delivered to `party`.
static IRMessageHeader * _Nullable IRRatchetGate(IRRatchetParty * _Nullable party,
                                                 NSData *message,
                                                 NSError **error) {
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

    /* §10.1 check 8 — the anti-reflection check, against OUR OWN current ratchet public. It is not
       optional and the parameter is _Nonnull, which is what stops a caller opting out of it. */
    return [IRMessageGate parseType01Message:message
                         ownRatchetPublicKey:party.state.DHs.publicKey
                                       error:error];
}

/**
 IRRatchet.h's four-step receive sequence, verbatim.

 On success the committed snapshot becomes the live state and the superseded one is zeroized; on
 failure the live state is left byte-identical (§7.7) and the caller sees the error. The snapshot has
 already been zeroized by IRRatchet on that path — committing it would install a session keyed with
 zeros, which is why it is discarded rather than inspected.
 */
static NSData * _Nullable IRRatchetPartyReceive(IRRatchetParty *party,
                                                NSData *message,
                                                NSError **error) {
    IRMessageHeader *header = IRRatchetGate(party, message, error);
    if (header == nil) {
        return nil;
    }

    /* Step 2 — ONCE PER RECEIVED MESSAGE. §7.6 makes MAX_SKIP_PER_MESSAGE an aggregate across both
       SkipMessageKeys calls of one message, and §11.5 rule 3 forbids a second session attempt so
       the bound cannot be multiplied by a candidate count. */
    IRSkipBudget *budget = [IRSkipBudget budget];

    IRRatchetState *liveState = party.state;
    IRRatchetState *snapshot = [liveState snapshot];
    IRVectorRequire(snapshot != nil, @"%@: §7.7 snapshot failed", party.name);

    NSData *plaintext = [IRRatchet decryptOnSnapshot:snapshot
                                             message:message
                                              header:header
                                              budget:budget
                                            atTimeMs:party.nowMs
                                            provider:party.provider
                                               error:error];
    if (plaintext == nil) {
        return nil;
    }

    [snapshot.skipped zeroizePendingRemovals];
    [liveState zeroizeAsSupersededState];
    party.state = snapshot;

    return plaintext;
}

/// -receive:, with the failure treated as a suite error. Used wherever a vector's own claim is that
/// the message decrypts.
static NSData *IRRatchetPartyReceiveOK(IRRatchetParty *party, NSData *message) {
    NSError *error = nil;
    NSData *plaintext = IRRatchetPartyReceive(party, message, &error);
    IRVectorRequire(plaintext != nil, @"%@: decrypt failed: %@", party.name, error);

    return plaintext;
}

#pragma mark - The shared two-party fixture

/**
 The material every ratchet-level vector needs before its own conversation begins.

 Read through IRRatchetIO, so the same twelve lines both DECLARE the vector's `inputs` (generating)
 and CONSUME them (executing). Nothing here is derived: §15.5 requires `inputs` to carry everything
 needed to reproduce, "including all private keys", and for a ratchet vector that is both identities'
 seeds and scalars, B's prekey scalars and ids, B's validity window, and A's handshake ephemeral.
 */
@interface IRRatchetBaseFixture : NSObject
@property (nonatomic, assign) uint64_t nowS;
@property (nonatomic, assign) uint64_t nowMs;
@property (nonatomic, copy) NSData *aliceSigningSeed;
@property (nonatomic, copy) NSData *aliceAgreementScalar;
@property (nonatomic, copy) NSData *bobSigningSeed;
@property (nonatomic, copy) NSData *bobAgreementScalar;
@property (nonatomic, assign) uint32_t spkId;
@property (nonatomic, copy) NSData *signedPreKeyScalar;
@property (nonatomic, assign) uint64_t notBeforeS;
@property (nonatomic, assign) uint64_t notAfterS;
@property (nonatomic, assign) uint32_t opkFlag;
@property (nonatomic, assign) uint32_t opkId;
@property (nonatomic, copy) NSData *oneTimePreKeyScalar;
@property (nonatomic, copy) NSData *ephemeralScalar;
@end

@implementation IRRatchetBaseFixture
@end

static IRRatchetBaseFixture *IRRatchetReadBase(IRRatchetIO *io) {
    IRRatchetBaseFixture *base = [[IRRatchetBaseFixture alloc] init];

    IRRatchetClock clock = IRRatchetReadClock(io);
    base.nowS = clock.nowS;
    base.nowMs = clock.nowMs;

    base.aliceSigningSeed = [io dataInput:@"IK_A_s_seed"];
    base.aliceAgreementScalar = [io dataInput:@"IK_A_d_scalar"];
    base.bobSigningSeed = [io dataInput:@"IK_B_s_seed"];
    base.bobAgreementScalar = [io dataInput:@"IK_B_d_scalar"];

    base.spkId = [io uint32Input:@"spk_id"];
    base.signedPreKeyScalar = [io dataInput:@"SPK_B_scalar"];
    base.notBeforeS = [io uint64Input:@"not_before"];
    base.notAfterS = [io uint64Input:@"not_after"];

    base.opkFlag = [io uint32Input:@"opk_flag"];
    base.opkId = [io uint32Input:@"opk_id"];
    base.oneTimePreKeyScalar = [io dataInput:@"OPK_B_scalar"];

    base.ephemeralScalar = [io dataInput:@"EK_A_scalar"];

    return base;
}

/// The literals behind IRRatchetReadBase, keyed identically. Every ratchet-level vector starts from
/// a mutable copy of this and adds its own conversation.
static NSMutableDictionary<NSString *, id> *IRRatchetBaseValues(void) {
    return [@{
        @"now_s"         : @(kIRRatchetNowS),
        @"now_ms"        : @(kIRRatchetNowMs),
        @"IK_A_s_seed"   : kIRRatchetAliceSigningSeed,
        @"IK_A_d_scalar" : kIRRatchetAliceAgreement,
        @"IK_B_s_seed"   : kIRRatchetBobSigningSeed,
        @"IK_B_d_scalar" : kIRRatchetBobAgreement,
        @"spk_id"        : @(kIRRatchetBobSpkId),
        @"SPK_B_scalar"  : kIRRatchetBobSPKScalar,
        @"not_before"    : @(kIRRatchetNotBeforeS),
        @"not_after"     : @(kIRRatchetNotAfterS),
        @"opk_flag"      : @(IROPKFlagPresent),
        @"opk_id"        : @(kIRRatchetBobOpkId),
        @"OPK_B_scalar"  : kIRRatchetBobOPKScalar,
        @"EK_A_scalar"   : kIRRatchetAliceEphemeral,
    } mutableCopy];
}

/// Alice's script prefix: identity, then the handshake ephemeral, in the order they are drawn.
static NSMutableArray<NSData *> *IRRatchetAliceScriptPrefix(IRRatchetBaseFixture *base) {
    return [@[base.aliceSigningSeed, base.aliceAgreementScalar, base.ephemeralScalar] mutableCopy];
}

/// Bob's script prefix: identity, then the signed prekey, then the one-time prekey.
static NSMutableArray<NSData *> *IRRatchetBobScriptPrefix(IRRatchetBaseFixture *base) {
    return [@[base.bobSigningSeed, base.bobAgreementScalar,
              base.signedPreKeyScalar, base.oneTimePreKeyScalar] mutableCopy];
}

/**
 The bootstrap every ratchet-level vector shares: B publishes, A opens, A sends one type `0x02`
 message, B establishes as responder and decrypts it.

 Returns the opener's bytes and writes the recovered plaintext through `outRecovered`. `bobPreKeys`
 comes back through `outPreKeys` because two vectors need it again afterwards.
 */
static NSData *IRRatchetBootstrap(IRRatchetParty *alice,
                                  IRRatchetParty *bob,
                                  IRRatchetBaseFixture *base,
                                  NSData *plaintext,
                                  NSData * __autoreleasing *outRecovered) {
    IRRatchetPreKeys *bobPreKeys = IRRatchetPartyPublish(bob,
                                                         base.spkId,
                                                         base.notBeforeS,
                                                         base.notAfterS,
                                                         @[@(base.opkId)]);

    IRRatchetPartyBegin(alice, bobPreKeys.bundleData);

    NSData *opener = IRRatchetPartySend(alice, plaintext);

    NSError *error = nil;
    IRMessageHeader *header = IRRatchetGate(nil, opener, &error);
    IRVectorRequire(header != nil, @"§10.2 rejected the opener: %@", error);
    IRVectorRequire(header.type == IRMessageTypePrekey, @"the opener is not type 0x02");
    IRVectorRequire((uint32_t)header.opkFlag == base.opkFlag,
                    @"opk_flag on the wire is %u, the vector declares %u",
                    (unsigned)header.opkFlag, (unsigned)base.opkFlag);
    IRVectorRequire(header.opkId == base.opkId,
                    @"opk_id on the wire is %u, the vector declares %u",
                    (unsigned)header.opkId, (unsigned)base.opkId);

    IRRatchetPartyEstablishResponder(bob, header, bobPreKeys);

    NSData *recovered = IRRatchetPartyReceiveOK(bob, opener);
    if (outRecovered != NULL) {
        *outRecovered = recovered;
    }

    return opener;
}

#pragma mark - RATCHET-INIT (§7.5)

/**
 §15.3: "A and B initial states; asserts `A.CKs == B.CKr` and EXPLICITLY asserts `A.RK != B.RK` at
 that instant (§7.5)."

 THE INEQUALITY IS THE POINT, and §7.5 says so in as many words: "B's `DHRatchet` performs two
 `KDF_RK` steps while A has performed one, so B's root key is legitimately one step ahead at that
 instant. An implementer who asserts root-key equality here will 'fix' working code." Both facts are
 emitted as BOOLEAN outputs rather than as raw key comparisons, because every port can compare two
 of its own internal values while not every port can hand them out; the raw keys are `intermediates`,
 which §15.5 rule 2 lets a runner skip and report.
 */
static void IRRatchetRunInit(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_prekey");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(aliceRatchet.count == 1 && bobRatchet.count == 1 &&
                    aliceNonces.count == 1 && plaintexts.count == 1,
                    @"RATCHET-INIT is a one-message fixture");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];      /* §7.5 — A's first DHs */
    [aliceScript addObject:aliceNonces[0]];       /* §8.3 — the opener's nonce */

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];          /* §7.4 step 4 — B's first ratchet */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *recovered = nil;
    NSData *opener = IRRatchetBootstrap(alice, bob, base, plaintexts[0], &recovered);

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    /* §6.5 — SESSION_AD is in ROLE order, A the initiator and B the responder, and both sides
       computed it independently. If they disagreed the AEAD would already have failed. */
    [io intermediate:@"SESSION_AD" data:alice.state.sessionAD.bytes];
    [io intermediate:@"A_RK" data:IRRatchetSecretData(alice.state.RK)];
    [io intermediate:@"A_CKs" data:IRRatchetSecretData(alice.state.CKs)];
    [io intermediate:@"B_RK" data:IRRatchetSecretData(bob.state.RK)];
    [io intermediate:@"B_CKr" data:IRRatchetSecretData(bob.state.CKr)];

    [io output:@"message" data:opener];
    [io output:@"plaintext" data:recovered];
    [io output:@"handshake_id" data:alice.state.handshakeId];

    /* §7.5's "correct conformance assertion". A's sending chain and B's receiving chain have each
       taken exactly one KDF_CK step for the delivered message, so the two chain keys are equal. */
    [io output:@"chain_keys_equal"
       boolean:[alice.state.CKs isEqualToSecretBytes:bob.state.CKr]];

    /* And the root keys are DELIBERATELY different, one KDF_RK step apart. */
    [io output:@"root_keys_differ"
       boolean:![alice.state.RK isEqualToSecretBytes:bob.state.RK]];

    /* §7.5 initialises A with `CKr` NONE and B with both chains none; §7.4 step 5 then gives B a
       sending chain on the DH ratchet it performs while decrypting this very message. So at this
       instant A still has no receiving chain — it has heard nothing from B — while B already has a
       sending one. A port that initialised either to zeros rather than to none, or that skipped
       §7.4 step 5's second KDF_RK, reports the opposite of one of these. */
    [io output:@"A_has_receiving_chain" boolean:(alice.state.CKr != nil)];
    [io output:@"B_has_sending_chain" boolean:(bob.state.CKs != nil)];

    [io output:@"A_role" number:(NSUInteger)alice.state.role];
    [io output:@"B_role" number:(NSUInteger)bob.state.role];
    [io output:@"handshake_ids_agree"
       boolean:[alice.state.handshakeId isEqualToData:bob.state.handshakeId]];
}

static NSDictionary<NSString *, id> *IRRatchetInitValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_prekey";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 1);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 1);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 1);
    values[@"plaintexts"] = @[IRRatchetText(@"ratchet-init")];

    return values;
}

#pragma mark - RATCHET-LINEAR

/**
 §15.3: "Ten messages A→B, no ratchet turn."

 The ten are TYPE `0x01`, which costs a three-message preamble: §11.3 keeps A emitting type `0x02`
 until A has decrypted something from B, so the fixture opens the session, has B reply, and lets A
 consume that reply — only then does A's sending chain produce ordinary ratchet messages. The ten
 then form ONE sending chain with no turn between them: B performs a single DH ratchet on the first
 (A's key changed when A consumed the reply) and none thereafter, so `Ns` and `Nr` both land on 10.

 A port that wrote `state.Ns` into the header's `PN` slot — defect 10 — diverges on the very first
 of the ten, whose `PN` is 1 (A's previous sending chain carried the opener alone) while its `N` is 0.
 */
static void IRRatchetRunLinear(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_with_handle");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *bobNonces = [io dataArrayInput:@"nonces_B"];
    NSData *openerPlaintext = [io dataInput:@"plaintext_opener"];
    NSData *replyPlaintext = [io dataInput:@"plaintext_reply"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    const NSUInteger count = plaintexts.count;
    IRVectorRequire(count == 10, @"RATCHET-LINEAR carries ten messages, not %lu",
                    (unsigned long)count);
    IRVectorRequire(aliceRatchet.count == 2 && bobRatchet.count == 2 &&
                    aliceNonces.count == count + 1 && bobNonces.count == 1,
                    @"RATCHET-LINEAR script widths do not match its conversation");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];                 /* §7.5 init */
    [aliceScript addObject:aliceNonces[0]];                  /* the opener */
    [aliceScript addObject:aliceRatchet[1]];                 /* §7.4 on consuming B's reply */
    for (NSUInteger index = 0; index < count; index++) {
        [aliceScript addObject:aliceNonces[index + 1]];      /* the ten */
    }

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];                     /* §7.4 on the opener */
    [bobScript addObject:bobNonces[0]];                      /* the reply */
    [bobScript addObject:bobRatchet[1]];                     /* §7.4 on the first of the ten */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *openerRecovered = nil;
    NSData *opener = IRRatchetBootstrap(alice, bob, base, openerPlaintext, &openerRecovered);
    IRVectorRequire([openerRecovered isEqualToData:openerPlaintext], @"the opener did not round-trip");

    NSData *reply = IRRatchetPartySend(bob, replyPlaintext);
    NSData *replyRecovered = IRRatchetPartyReceiveOK(alice, reply);
    IRVectorRequire([replyRecovered isEqualToData:replyPlaintext], @"the reply did not round-trip");

    /* §11.3 — A has now decrypted a message from B, so the prologue is cleared and every further
       message is type 0x01. That transition is a property of the ratchet state, not of the caller. */
    IRVectorRequire(!alice.state.shouldSendPreKeyMessage,
                    @"§11.3: A must stop sending type 0x02 once CKr exists");

    [io intermediate:@"setup_opener" data:opener];
    [io intermediate:@"setup_reply" data:reply];

    for (NSUInteger index = 0; index < count; index++) {
        NSData *message = IRRatchetPartySend(alice, plaintexts[index]);
        NSData *recovered = IRRatchetPartyReceiveOK(bob, message);

        [io output:IRRatchetIndexedKey(@"message", index) data:message];
        [io output:IRRatchetIndexedKey(@"recovered", index) data:recovered];
    }

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    [io output:@"final_Ns" number:(NSUInteger)alice.state.Ns];
    [io output:@"final_Nr" number:(NSUInteger)bob.state.Nr];
    [io output:@"skipped_final" number:bob.state.skipped.count];
}

static NSDictionary<NSString *, id> *IRRatchetLinearValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_with_handle";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 2);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 2);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 11);
    values[@"nonces_B"] = IRRatchetNonceRun(kIRRatchetNoncePrefixB, 1);
    values[@"plaintext_opener"] = IRRatchetText(@"linear-opener");
    values[@"plaintext_reply"] = IRRatchetText(@"linear-reply");

    NSMutableArray<NSData *> *plaintexts = [NSMutableArray arrayWithCapacity:10];
    for (NSUInteger index = 0; index < 10; index++) {
        [plaintexts addObject:IRRatchetText([NSString stringWithFormat:@"linear-%lu",
                                                                      (unsigned long)index])];
    }
    values[@"plaintexts"] = plaintexts;

    return values;
}

#pragma mark - RATCHET-BIDI (§6.5)

/**
 §15.3: "A→B, B→A, A→B, B→A. Exercises `SESSION_AD` role ordering (§6.5) — a port that recomputes AD
 as (self, peer) fails only here."

 THE FAILURE IS INVISIBLE ANYWHERE ELSE, which is why this row exists. §6.5 fixes SESSION_AD in ROLE
 order — A the initiator, B the responder — and both sides prefix the SAME 141 bytes to every AD.
 A port that instead builds it from its own point of view produces one AD at A and a different one at
 B, and both are self-consistent: A's own messages authenticate at A, B's at B. A one-directional
 fixture therefore passes. Only a message travelling in the SECOND direction is sealed under one
 party's AD and opened under the other's, and only then does the tag fail.

 Four messages are the minimum that exercises both directions twice, so the failure cannot be
 dismissed as a first-message artifact, and it forces two DH ratchets at each side.
 */
static void IRRatchetRunBidi(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_with_handle");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *bobNonces = [io dataArrayInput:@"nonces_B"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(plaintexts.count == 4 && aliceRatchet.count == 3 && bobRatchet.count == 2 &&
                    aliceNonces.count == 2 && bobNonces.count == 2,
                    @"RATCHET-BIDI is a four-message fixture");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];     /* §7.5 init */
    [aliceScript addObject:aliceNonces[0]];      /* message 0, A->B, type 0x02 */
    [aliceScript addObject:aliceRatchet[1]];     /* §7.4 on message 1 */
    [aliceScript addObject:aliceNonces[1]];      /* message 2, A->B, type 0x01 */
    [aliceScript addObject:aliceRatchet[2]];     /* §7.4 on message 3 */

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];         /* §7.4 on message 0 */
    [bobScript addObject:bobNonces[0]];          /* message 1, B->A */
    [bobScript addObject:bobRatchet[1]];         /* §7.4 on message 2 */
    [bobScript addObject:bobNonces[1]];          /* message 3, B->A */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *recovered0 = nil;
    NSData *message0 = IRRatchetBootstrap(alice, bob, base, plaintexts[0], &recovered0);

    NSData *message1 = IRRatchetPartySend(bob, plaintexts[1]);
    NSData *recovered1 = IRRatchetPartyReceiveOK(alice, message1);

    NSData *message2 = IRRatchetPartySend(alice, plaintexts[2]);
    NSData *recovered2 = IRRatchetPartyReceiveOK(bob, message2);

    NSData *message3 = IRRatchetPartySend(bob, plaintexts[3]);
    NSData *recovered3 = IRRatchetPartyReceiveOK(alice, message3);

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    /* §6.5 — the 141 bytes both sides prefix to every AD, in role order. Emitted as an intermediate
       because it localises the failure: without it a (self, peer) port sees only "message 1 does not
       authenticate", which reads as a chain-key bug. */
    [io intermediate:@"SESSION_AD" data:alice.state.sessionAD.bytes];
    [io intermediate:@"SESSION_AD_len" number:alice.state.sessionAD.bytes.length];

    [io output:@"message_0" data:message0];
    [io output:@"message_1" data:message1];
    [io output:@"message_2" data:message2];
    [io output:@"message_3" data:message3];
    [io output:@"recovered_0" data:recovered0];
    [io output:@"recovered_1" data:recovered1];
    [io output:@"recovered_2" data:recovered2];
    [io output:@"recovered_3" data:recovered3];

    /* Both sides agree on SESSION_AD, which is what a (self, peer) port cannot achieve. */
    [io output:@"session_ads_agree"
       boolean:[alice.state.sessionAD.bytes isEqualToData:bob.state.sessionAD.bytes]];
}

static NSDictionary<NSString *, id> *IRRatchetBidiValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_with_handle";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 3);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 2);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 2);
    values[@"nonces_B"] = IRRatchetNonceRun(kIRRatchetNoncePrefixB, 2);
    values[@"plaintexts"] = @[IRRatchetText(@"bidi-a-to-b-1"),
                              IRRatchetText(@"bidi-b-to-a-1"),
                              IRRatchetText(@"bidi-a-to-b-2"),
                              IRRatchetText(@"bidi-b-to-a-2")];

    return values;
}

#pragma mark - RATCHET-SKIP (§7.6)

/**
 §15.3: "Messages 0,1,2,3 sent; 1 and 2 delivered last. Exercises the skipped store within one
 chain."

 Delivery order is 0, 3, 1, 2. Receiving 3 while `Nr` is 1 derives and STORES the keys for 1 and 2
 (§7.6), and the two later deliveries are §7.9 phase 3a hits — which return WITHOUT performing a DH
 ratchet and WITHOUT advancing `Nr`, the two rules §7.9 calls out as divergence points.

 The store key is the raw 36-byte `DHr_pub ‖ uint32_be(N)` (§7.6). A port that used a base64 or
 `|`-separated composite still passes a round-trip test; what it cannot do is agree with another port
 on the §12.1 blob, which is where `state.json` picks the failure up.
 */
static void IRRatchetRunSkip(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_with_handle");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *bobNonces = [io dataArrayInput:@"nonces_B"];
    NSData *openerPlaintext = [io dataInput:@"plaintext_opener"];
    NSData *replyPlaintext = [io dataInput:@"plaintext_reply"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(plaintexts.count == 4 && aliceRatchet.count == 2 && bobRatchet.count == 2 &&
                    aliceNonces.count == 5 && bobNonces.count == 1,
                    @"RATCHET-SKIP is a four-message fixture with a two-message preamble");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];
    [aliceScript addObject:aliceNonces[0]];                  /* the opener */
    [aliceScript addObject:aliceRatchet[1]];                 /* §7.4 on consuming B's reply */
    for (NSUInteger index = 0; index < 4; index++) {
        [aliceScript addObject:aliceNonces[index + 1]];      /* the four */
    }

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];                     /* §7.4 on the opener */
    [bobScript addObject:bobNonces[0]];                      /* the reply */
    [bobScript addObject:bobRatchet[1]];                     /* §7.4 on message 0 of the four */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *opener = IRRatchetBootstrap(alice, bob, base, openerPlaintext, NULL);
    NSData *reply = IRRatchetPartySend(bob, replyPlaintext);
    IRRatchetPartyReceiveOK(alice, reply);

    [io intermediate:@"setup_opener" data:opener];
    [io intermediate:@"setup_reply" data:reply];

    NSMutableArray<NSData *> *messages = [NSMutableArray arrayWithCapacity:4];
    for (NSUInteger index = 0; index < 4; index++) {
        [messages addObject:IRRatchetPartySend(alice, plaintexts[index])];
        [io output:IRRatchetIndexedKey(@"message", index) data:messages[index]];
    }

    /* 0, then 3 — which is what fills the store — then the two that were held back. */
    NSData *recovered0 = IRRatchetPartyReceiveOK(bob, messages[0]);
    NSData *recovered3 = IRRatchetPartyReceiveOK(bob, messages[3]);

    const NSUInteger skippedAfterThird = bob.state.skipped.count;
    const uint32_t nrAfterThird = bob.state.Nr;

    NSData *recovered1 = IRRatchetPartyReceiveOK(bob, messages[1]);
    NSData *recovered2 = IRRatchetPartyReceiveOK(bob, messages[2]);

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    [io output:@"recovered_0" data:recovered0];
    [io output:@"recovered_1" data:recovered1];
    [io output:@"recovered_2" data:recovered2];
    [io output:@"recovered_3" data:recovered3];

    /* Receiving 3 stored exactly the two keys it skipped. */
    [io output:@"skipped_after_third_delivery" number:skippedAfterThird];

    /* §7.9 — a skipped-key hit does NOT advance `Nr`, so it is unchanged by the last two
       deliveries. A port that advanced it would report 6 here on a four-message chain. */
    [io output:@"Nr_after_third_delivery" number:(NSUInteger)nrAfterThird];
    [io output:@"Nr_final" number:(NSUInteger)bob.state.Nr];

    /* And a used key is removed, so the store drains to empty (§7.6). */
    [io output:@"skipped_final" number:bob.state.skipped.count];
}

static NSDictionary<NSString *, id> *IRRatchetSkipValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_with_handle";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 2);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 2);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 5);
    values[@"nonces_B"] = IRRatchetNonceRun(kIRRatchetNoncePrefixB, 1);
    values[@"plaintext_opener"] = IRRatchetText(@"skip-opener");
    values[@"plaintext_reply"] = IRRatchetText(@"skip-reply");
    values[@"plaintexts"] = @[IRRatchetText(@"skip-0"), IRRatchetText(@"skip-1"),
                              IRRatchetText(@"skip-2"), IRRatchetText(@"skip-3")];

    return values;
}

#pragma mark - RATCHET-SKIP-XCHAIN (§7.4, §7.6)

/**
 §15.3: "Skipped messages recovered ACROSS a DH ratchet — exactly what defect 10 was masking."

 The shape, and every step of it matters:

     A sends a0, a1, a2 in chain 2.  B receives only a0.
     B replies.  A consumes the reply and RATCHETS, so A's chain 2 is now the PREVIOUS chain
     and its length — 3 — becomes A's `PN`.
     A sends a3 as the first message of chain 3, carrying `N = 0` and `PN = 3`.
     B receives a3: §7.4 step 1 drains the OLD receiving chain to `header.PN` BEFORE `DHr` is
     replaced, which derives and stores the keys for a1 and a2 under the OLD `DHr`.
     a1 and a2 then decrypt from the store, one ratchet later.

 DEFECT 10 IS EXACTLY THIS ROW. v3 wrote `numberOfSentMessages` into both the `N` and `PN` header
 slots, so `PN` was never transmitted; §7.4 step 1 then had nothing to drain to and the keys for a1
 and a2 were never derived. Every single-chain test still passed. Here a3 carries `N = 0` and
 `PN = 3` — two different values in two different slots — so a port that conflates them derives
 nothing at step 1 and fails at the delivery of a1.
 */
static void IRRatchetRunSkipCrossChain(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_with_handle");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *bobNonces = [io dataArrayInput:@"nonces_B"];
    NSData *openerPlaintext = [io dataInput:@"plaintext_opener"];
    NSData *replyPlaintext = [io dataInput:@"plaintext_reply"];
    NSData *turnPlaintext = [io dataInput:@"plaintext_bob_turn"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(plaintexts.count == 4 && aliceRatchet.count == 3 && bobRatchet.count == 3 &&
                    aliceNonces.count == 5 && bobNonces.count == 2,
                    @"RATCHET-SKIP-XCHAIN script widths do not match its conversation");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];     /* §7.5 init */
    [aliceScript addObject:aliceNonces[0]];      /* the opener */
    [aliceScript addObject:aliceRatchet[1]];     /* §7.4 on B's reply — chain 2 begins */
    [aliceScript addObject:aliceNonces[1]];      /* a0 */
    [aliceScript addObject:aliceNonces[2]];      /* a1 */
    [aliceScript addObject:aliceNonces[3]];      /* a2 */
    [aliceScript addObject:aliceRatchet[2]];     /* §7.4 on B's turn — chain 3 begins, PN = 3 */
    [aliceScript addObject:aliceNonces[4]];      /* a3 */

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];         /* §7.4 on the opener */
    [bobScript addObject:bobNonces[0]];          /* the reply */
    [bobScript addObject:bobRatchet[1]];         /* §7.4 on a0 */
    [bobScript addObject:bobNonces[1]];          /* B's turn */
    [bobScript addObject:bobRatchet[2]];         /* §7.4 on a3 — the ratchet the skip crosses */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *opener = IRRatchetBootstrap(alice, bob, base, openerPlaintext, NULL);
    NSData *reply = IRRatchetPartySend(bob, replyPlaintext);
    IRRatchetPartyReceiveOK(alice, reply);

    [io intermediate:@"setup_opener" data:opener];
    [io intermediate:@"setup_reply" data:reply];

    /* Chain 2: three messages, of which B will see only the first for now. */
    NSMutableArray<NSData *> *messages = [NSMutableArray arrayWithCapacity:4];
    for (NSUInteger index = 0; index < 3; index++) {
        [messages addObject:IRRatchetPartySend(alice, plaintexts[index])];
    }

    NSData *recovered0 = IRRatchetPartyReceiveOK(bob, messages[0]);

    NSData *turn = IRRatchetPartySend(bob, turnPlaintext);
    IRRatchetPartyReceiveOK(alice, turn);
    [io intermediate:@"bob_turn" data:turn];

    /* Chain 3's first message. Its header is where `N` and `PN` are two different numbers. */
    [messages addObject:IRRatchetPartySend(alice, plaintexts[3])];

    NSError *error = nil;
    IRMessageHeader *crossHeader = IRRatchetGate(bob, messages[3], &error);
    IRVectorRequire(crossHeader != nil, @"§10.1 rejected a3: %@", error);
    [io intermediate:@"a3_N" number:(NSUInteger)crossHeader.N];
    [io intermediate:@"a3_PN" number:(NSUInteger)crossHeader.PN];

    NSData *recovered3 = IRRatchetPartyReceiveOK(bob, messages[3]);
    const NSUInteger skippedAcross = bob.state.skipped.count;

    /* The payoff: two keys derived in the OLD chain, retrieved after the ratchet. */
    NSData *recovered1 = IRRatchetPartyReceiveOK(bob, messages[1]);
    NSData *recovered2 = IRRatchetPartyReceiveOK(bob, messages[2]);

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    for (NSUInteger index = 0; index < 4; index++) {
        [io output:IRRatchetIndexedKey(@"message", index) data:messages[index]];
    }

    [io output:@"recovered_0" data:recovered0];
    [io output:@"recovered_1" data:recovered1];
    [io output:@"recovered_2" data:recovered2];
    [io output:@"recovered_3" data:recovered3];

    [io output:@"skipped_after_cross_chain_ratchet" number:skippedAcross];
    [io output:@"skipped_final" number:bob.state.skipped.count];
    [io output:@"Nr_final" number:(NSUInteger)bob.state.Nr];
}

static NSDictionary<NSString *, id> *IRRatchetSkipCrossChainValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_with_handle";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 3);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 3);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 5);
    values[@"nonces_B"] = IRRatchetNonceRun(kIRRatchetNoncePrefixB, 2);
    values[@"plaintext_opener"] = IRRatchetText(@"xchain-opener");
    values[@"plaintext_reply"] = IRRatchetText(@"xchain-reply");
    values[@"plaintext_bob_turn"] = IRRatchetText(@"xchain-bob-turn");
    values[@"plaintexts"] = @[IRRatchetText(@"xchain-a0"), IRRatchetText(@"xchain-a1"),
                              IRRatchetText(@"xchain-a2"), IRRatchetText(@"xchain-a3")];

    return values;
}

#pragma mark - RATCHET-PREKEY-BURST (§9.2, §11.3)

/**
 §15.3: "A sends three type `0x02` messages with `N` = 0, 1, 2 before B replies; all decrypt."

 §11.3 is what makes this legal and what makes it fixed: A emits type `0x02` for EVERY message until
 A has decrypted something from B, reusing the IDENTICAL prologue — the same `EK_A`, `spk_id`,
 `opk_flag` and `opk_id` — while only `N`, the nonce and the ciphertext vary. `DHs_pub` is constant
 too, because A's first sending chain does not turn.

 The three headers therefore differ in exactly one uint32, and §9.2's rule that `N` MAY be non-zero
 in a type `0x02` header is what this row pins. A port that hard-coded `N = 0` there — an easy
 reading of "initial message" — emits three headers that are byte-identical apart from the nonce, and
 B answers the second with ERR_REPLAY.
 */
static void IRRatchetRunPrekeyBurst(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_prekey");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(plaintexts.count == 3 && aliceRatchet.count == 1 && bobRatchet.count == 1 &&
                    aliceNonces.count == 3,
                    @"RATCHET-PREKEY-BURST is a three-message fixture");

    NSMutableArray<NSData *> *aliceScript = IRRatchetAliceScriptPrefix(base);
    [aliceScript addObject:aliceRatchet[0]];
    [aliceScript addObjectsFromArray:aliceNonces];

    NSMutableArray<NSData *> *bobScript = IRRatchetBobScriptPrefix(base);
    [bobScript addObject:bobRatchet[0]];         /* one ratchet, on the FIRST of the three */

    IRRatchetParty *alice = IRRatchetPartyCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetParty *bob = IRRatchetPartyCreate(@"B", bobScript, base.nowS, base.nowMs);

    NSData *recovered0 = nil;
    NSData *message0 = IRRatchetBootstrap(alice, bob, base, plaintexts[0], &recovered0);

    NSMutableArray<NSData *> *messages = [NSMutableArray arrayWithObject:message0];
    NSMutableArray<NSData *> *recovered = [NSMutableArray arrayWithObject:recovered0];

    for (NSUInteger index = 1; index < 3; index++) {
        /* §11.3 — still type 0x02, because A has decrypted nothing from B. */
        IRVectorRequire(alice.state.shouldSendPreKeyMessage,
                        @"§11.3: A must still be sending type 0x02 at message %lu",
                        (unsigned long)index);

        [messages addObject:IRRatchetPartySend(alice, plaintexts[index])];
        [recovered addObject:IRRatchetPartyReceiveOK(bob, messages[index])];
    }

    IRRatchetPartyRequireScriptExhausted(alice);
    IRRatchetPartyRequireScriptExhausted(bob);

    NSError *error = nil;
    for (NSUInteger index = 0; index < 3; index++) {
        IRMessageHeader *header = IRRatchetGate(nil, messages[index], &error);
        IRVectorRequire(header != nil, @"§10.2 rejected burst message %lu: %@",
                        (unsigned long)index, error);
        IRVectorRequire(header.type == IRMessageTypePrekey,
                        @"burst message %lu is not type 0x02", (unsigned long)index);

        [io output:IRRatchetIndexedKey(@"message", index) data:messages[index]];
        [io output:IRRatchetIndexedKey(@"recovered", index) data:recovered[index]];

        /* §9.2 — N is 0, 1, 2. This is the assertion the row exists for. */
        [io output:IRRatchetIndexedKey(@"N", index) number:(NSUInteger)header.N];

        /* §9.2 fixes PN at zero in a type 0x02 header; it is not a parameter of the builder. */
        [io output:IRRatchetIndexedKey(@"PN", index) number:(NSUInteger)header.PN];
    }

    /* §11.3 — the prologue is IDENTICAL across all three, which is what lets B route every one of
       them to the same handshake_id (§11.1, §11.2). */
    [io output:@"handshake_id" data:bob.state.handshakeId];
    [io output:@"Nr_final" number:(NSUInteger)bob.state.Nr];
    [io output:@"skipped_final" number:bob.state.skipped.count];
}

static NSDictionary<NSString *, id> *IRRatchetPrekeyBurstValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_prekey";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 1);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 1);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 3);
    values[@"plaintexts"] = @[IRRatchetText(@"burst-0"), IRRatchetText(@"burst-1"),
                              IRRatchetText(@"burst-2")];

    return values;
}

#pragma mark - IRRatchetHost — one side at the IRMessenger layer

/**
 A party at the consumer API: an identity, both stores, a scripted CSPRNG and the injected clock.

 The three rows that live here — RATCHET-RETRANSMIT, SESSION-COLLAPSE and DEMUX-NO-TRIAL — assert
 behaviour no lower layer owns. §11.2's three ordered checks need a session store to route into,
 §10.7's fourteen steps need a prekey store to consume an OPK from, and §11.5's handle rules are a
 property of the entry points themselves. IRRatchetParty above cannot reach any of it.
 */
@interface IRRatchetHost : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, strong) IRScriptedRandomSource *source;
@property (nonatomic, strong) IREnvironment *environment;
@property (nonatomic, strong) id<IRCryptoProvider> provider;
@property (nonatomic, strong) IRIdentity *identity;
@property (nonatomic, strong) IRInMemoryPreKeyStore *preKeys;
@property (nonatomic, strong) IRInMemorySessionStore *sessions;
@property (nonatomic, strong) IRMessenger *messenger;
@property (nonatomic, assign) uint64_t nowS;
@property (nonatomic, assign) uint64_t nowMs;
@end

@implementation IRRatchetHost
@end

static IRRatchetHost *IRRatchetHostCreate(NSString *name,
                                          NSArray<NSData *> *script,
                                          uint64_t nowS,
                                          uint64_t nowMs) {
    IRRatchetHost *host = [[IRRatchetHost alloc] init];
    host.name = name;
    host.nowS = nowS;
    host.nowMs = nowMs;
    host.source = [IRScriptedRandomSource sourceWithDataItems:script];
    host.environment = IRVectorEnvironmentAtUnixMilliseconds(nowMs, host.source);
    host.provider = IRVectorProviderWithEnvironment(host.environment);

    NSError *error = nil;
    host.identity = [IRIdentity generateWithProvider:host.provider error:&error];
    IRVectorRequire(host.identity != nil, @"%@: identity generation failed: %@", name, error);

    host.preKeys = [IRInMemoryPreKeyStore store];
    host.sessions = [IRInMemorySessionStore store];

    /* Full injection. `environment` is what §15.5 rule 6's clock and rule 5's randomness both come
       through, and IRMessenger reads every expiry, tombstone and TTL decision from it. */
    host.messenger = [[IRMessenger alloc] initWithIdentity:host.identity
                                              preKeyStore:host.preKeys
                                             sessionStore:host.sessions
                                                 provider:host.provider
                                              environment:host.environment
                                                    error:&error];
    IRVectorRequire(host.messenger != nil, @"%@: messenger: %@", name, error);

    return host;
}

static void IRRatchetHostRequireScriptExhausted(IRRatchetHost *host) {
    IRVectorRequire(host.source.bytesRemaining == 0,
                    @"%@ left %lu scripted byte(s) unread — the script does not match the draw "
                    @"sequence this implementation makes",
                    host.name, (unsigned long)host.source.bytesRemaining);
}

/**
 §5.2 / §5.4 — generate the prekeys, STORE them, and return the published bundle.

 Built through IRRatchetPartyPublish over a value shim rather than through
 -publishBundleWithSPKId:...: the messenger's publisher draws four CSPRNG bytes per `opk_id` inside a
 collision-redraw loop, which would put an id-selection loop inside a script this file must predict
 byte for byte. The ids are fixed literals instead, which is what §15.5 wants of them anyway.
 */
static IRRatchetPreKeys *IRRatchetHostPublish(IRRatchetHost *host,
                                              uint32_t spkId,
                                              uint64_t notBeforeS,
                                              uint64_t notAfterS,
                                              NSArray<NSNumber *> *opkIds) {
    IRRatchetParty *shim = [[IRRatchetParty alloc] init];
    shim.name = host.name;
    shim.provider = host.provider;
    shim.identity = host.identity;
    shim.nowS = host.nowS;
    shim.nowMs = host.nowMs;

    IRRatchetPreKeys *published = IRRatchetPartyPublish(shim, spkId, notBeforeS, notAfterS, opkIds);

    NSError *error = nil;
    IRVectorRequire([host.preKeys storeSignedPreKeyRecord:published.signedPreKey
                                              makeCurrent:YES
                                                    error:&error],
                    @"%@: storing the signed prekey: %@", host.name, error);
    IRVectorRequire([host.preKeys storeOneTimePreKeyRecords:published.oneTimePreKeys error:&error],
                    @"%@: storing one-time prekeys: %@", host.name, error);

    return published;
}

/// YES while `opkId` still resolves — §10.7 step 14a's "durably delete and zeroize" is FINAL, so
/// this reads NO on every path that reached step 14, including the losing collapse branch.
static BOOL IRRatchetHostHasOPK(IRRatchetHost *host, uint32_t opkId) {
    return [host.preKeys oneTimePreKeyRecordForId:opkId
                                    atUnixSeconds:host.nowS
                                            error:NULL] != nil;
}

/**
 Rehydrates one `inputs.sessions` fixture — a literal §12.1 blob — and files it under both §11.1
 indices.

 §15.5 requires session fixtures be supplied "as literal §12.1 blobs, never as 'replay these
 handshakes'", for the reproducibility reason `state.json` gives: a runner that reached the state by
 executing a handshake would write its own clock into the blob and would re-derive different key
 material on every port. The `handshake_id` and `peer_identity` fields are cross-checked against what
 the decoder recovers, so a blob whose SESSION_AD does not match its declared peer fails here rather
 than three steps later as a routing miss.
 */
static IRSession *IRRatchetLoadSession(IRRatchetHost *host,
                                       NSDictionary<NSString *, NSData *> *fixture,
                                       NSString *fixtureName) {
    NSData *blob = fixture[@"state_blob"];
    IRVectorRequire(blob != nil, @"inputs.sessions.%@.state_blob is missing", fixtureName);

    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                atTimeMs:host.nowMs
                                                                   error:&error];
    IRVectorRequire(state != nil, @"§12.2 rejected inputs.sessions.%@.state_blob: %@",
                    fixtureName, error);

    IRSession *session = [IRSession sessionWithState:state error:&error];
    IRVectorRequire(session != nil, @"inputs.sessions.%@ is not a usable session: %@",
                    fixtureName, error);

    NSData *declaredHandshakeId = fixture[@"handshake_id"];
    IRVectorRequire(declaredHandshakeId != nil,
                    @"inputs.sessions.%@.handshake_id is missing", fixtureName);
    IRVectorRequire([session.handshakeId isEqualToData:declaredHandshakeId],
                    @"inputs.sessions.%@.handshake_id does not match the blob", fixtureName);

    NSData *declaredPeer = fixture[@"peer_identity"];
    IRVectorRequire(declaredPeer != nil,
                    @"inputs.sessions.%@.peer_identity is missing", fixtureName);
    IRVectorRequire([session.peerIdentityKeyPair.rawPair isEqualToData:declaredPeer],
                    @"inputs.sessions.%@.peer_identity does not match SESSION_AD", fixtureName);

    IRSessionEstablishResult *result = [host.sessions establishSession:session
                                                              atTimeMs:host.nowMs
                                                                 error:&error];
    IRVectorRequire(result != nil, @"%@: filing inputs.sessions.%@: %@",
                    host.name, fixtureName, error);
    IRVectorRequire(!result.collapseOccurred,
                    @"%@: filing inputs.sessions.%@ collapsed a sibling; the fixture is malformed",
                    host.name, fixtureName);

    return result.survivingSession;
}

/// The three fields of one `inputs.sessions` fixture, as the generator declares them.
static NSDictionary<NSString *, NSData *> *IRRatchetSessionFixture(IRSession *session) {
    return @{
        @"handshake_id"  : session.handshakeId,
        @"peer_identity" : session.peerIdentityKeyPair.rawPair,
        @"state_blob"    : IRRatchetStateBlob(session),
    };
}

#pragma mark - RATCHET-RETRANSMIT (§11.2, §11.4)

/**
 §15.3: "The same type `0x02` message delivered twice; the second is `ERR_REPLAY`, and the session
 survives (§11.2)."

 THE SECOND DELIVERY MUST NOT RE-RUN X3DH, and §11.2 says why in as many words: "A responder that
 re-runs X3DH on a repeated prekey message destroys the live session." The one-time prekey was
 consumed by the first delivery (§10.7 step 14a), so a re-deriving port cannot reproduce `SK` and
 answers with ERR_UNKNOWN_PREKEY_ID or a wrecked session instead of the ERR_REPLAY this row requires.

 The replay is caught at §7.9 phase 3c — `hdr.N < s.Nr` with no matching skipped key — which §7.9
 makes an EXPLICIT code and "not a silent AEAD failure". Both wrong answers are fail-closed, and
 §15.4 is what makes the exact code a conformance requirement rather than a detail.

 The third message is the control: without it, an implementation that tore the session down on the
 replay would pass on the first two assertions alone.
 */
static void IRRatchetRunRetransmit(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_prekey");

    IRRatchetBaseFixture *base = IRRatchetReadBase(io);
    NSArray<NSData *> *aliceRatchet = [io dataArrayInput:@"DHs_A_scalars"];
    NSArray<NSData *> *bobRatchet = [io dataArrayInput:@"DHs_B_scalars"];
    NSArray<NSData *> *aliceNonces = [io dataArrayInput:@"nonces_A"];
    NSArray<NSData *> *plaintexts = [io dataArrayInput:@"plaintexts"];

    IRVectorRequire(plaintexts.count == 2 && aliceRatchet.count == 1 && bobRatchet.count == 1 &&
                    aliceNonces.count == 2,
                    @"RATCHET-RETRANSMIT is a two-message fixture");

    NSMutableArray<NSData *> *aliceScript =
        [@[base.aliceSigningSeed, base.aliceAgreementScalar] mutableCopy];
    [aliceScript addObject:base.ephemeralScalar];   /* -beginSessionWithBundleData: draws EK_A */
    [aliceScript addObject:aliceRatchet[0]];        /* then §7.5's fresh DHs */
    [aliceScript addObjectsFromArray:aliceNonces];

    NSMutableArray<NSData *> *bobScript =
        [@[base.bobSigningSeed, base.bobAgreementScalar,
           base.signedPreKeyScalar, base.oneTimePreKeyScalar] mutableCopy];
    [bobScript addObject:bobRatchet[0]];            /* §7.4 on the FIRST delivery only */

    IRRatchetHost *alice = IRRatchetHostCreate(@"A", aliceScript, base.nowS, base.nowMs);
    IRRatchetHost *bob = IRRatchetHostCreate(@"B", bobScript, base.nowS, base.nowMs);

    IRRatchetPreKeys *bobPreKeys = IRRatchetHostPublish(bob, base.spkId, base.notBeforeS,
                                                        base.notAfterS, @[@(base.opkId)]);

    NSError *error = nil;
    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:bobPreKeys.bundleData
                                                                   error:&error];
    IRVectorRequire(aliceSession != nil, @"A: §5.3 / §6 / §7.5: %@", error);

    NSData *message0 = [alice.messenger encrypt:plaintexts[0] inSession:aliceSession error:&error];
    IRVectorRequire(message0 != nil, @"A: encrypt: %@", error);

    IRDecryptedMessage *first = [bob.messenger decryptPreKeyMessage:message0 error:&error];
    IRVectorRequire(first != nil, @"B: the first delivery must succeed: %@", error);

    const BOOL opkPresentAfterFirst = IRRatchetHostHasOPK(bob, base.opkId);

    /* THE REPLAY. §11.2 routes it to the live session — the handshake_id is unchanged — and §7.9
       phase 3c answers `N = 0 < Nr = 1` with ERR_REPLAY. No CSPRNG draw happens: `hdr.dh` still
       equals `DHr`, so there is no DH ratchet, which is what leaves the session usable. */
    error = nil;
    IRDecryptedMessage *replay = [bob.messenger decryptPreKeyMessage:message0 error:&error];
    IRVectorRequire(replay == nil, @"B: the second delivery must NOT produce a plaintext");
    IRVectorRequire(error != nil, @"B: the second delivery must set an error");
    NSString *replayErrorName = IRVectorNameForErrorCode((IRErrorCode)error.code) ?: @"<unknown>";

    NSData *message1 = [alice.messenger encrypt:plaintexts[1] inSession:aliceSession error:&error];
    IRVectorRequire(message1 != nil, @"A: encrypt after the replay: %@", error);

    error = nil;
    IRDecryptedMessage *third = [bob.messenger decryptPreKeyMessage:message1 error:&error];
    IRVectorRequire(third != nil, @"B: the session did not survive the replay: %@", error);

    IRRatchetHostRequireScriptExhausted(alice);
    IRRatchetHostRequireScriptExhausted(bob);

    [io intermediate:@"handshake_id" data:aliceSession.handshakeId];

    [io output:@"message_0" data:message0];
    [io output:@"message_1" data:message1];
    [io output:@"plaintext_0" data:first.plaintext];
    [io output:@"plaintext_1" data:third.plaintext];

    /* §10.5 / §15.4 — the exact code, by name. */
    [io output:@"replay_error" string:replayErrorName];

    /* §11.6 — the first delivery ran §10.7 and its session survived; the third landed on an
       EXISTING session through §11.2 and therefore established nothing. */
    [io output:@"first_established_new_session" boolean:first.establishedNewSession];
    [io output:@"third_established_new_session" boolean:third.establishedNewSession];

    /* §6.6 step 4 / §10.7 step 14a — the one-time prekey is gone after the first delivery and stays
       gone. A port that restored it on the replay path reopens defect 7's window. */
    [io output:@"opk_present_after_first" boolean:opkPresentAfterFirst];
    [io output:@"opk_present_after_replay" boolean:IRRatchetHostHasOPK(bob, base.opkId)];

    [io output:@"session_survives" boolean:!third.session.isTornDown];
    [io output:@"live_session_count" number:bob.sessions.sessionCount];
}

static NSDictionary<NSString *, id> *IRRatchetRetransmitValues(void) {
    NSMutableDictionary<NSString *, id> *values = IRRatchetBaseValues();
    values[@"entry_point"] = @"decrypt_prekey";
    values[@"DHs_A_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixA, 1);
    values[@"DHs_B_scalars"] = IRRatchetScalarRun(kIRRatchetScalarPrefixB, 1);
    values[@"nonces_A"] = IRRatchetNonceRun(kIRRatchetNoncePrefixA, 2);
    values[@"plaintexts"] = @[IRRatchetText(@"retransmit-first"),
                              IRRatchetText(@"retransmit-second")];

    return values;
}

#pragma mark - SESSION-COLLAPSE (§10.7 step 14, §11.1.1, §11.6, §19.7)

/**
 §15.3, restated by the gap work and quoted here because the row changed:

   "A and B initiate concurrently, with fixed keys chosen so the comparison is decided in advance,
    and each receives the other's type `0x02`. TWO-SIDED, with per-side assertions, because the two
    sides exercise different branches of §10.7 step 14b. Both MUST converge on the same surviving
    `handshake_id` (the greater of the two, compared as a 64-byte unsigned big-endian value), with the
    loser torn down, zeroized and tombstoned. Each side's `outputs` carries `plaintext` (REQUIRED on
    both sides — its presence on the side whose incoming session LOSES is the assertion that resolves
    §10.7 step 14d, and the fixture MUST be constructed so exactly one side is that side),
    `surviving_handshake_id`, `established_new_session`, `torn_down_handshake_id`, and
    `sessions.<name>.state_blob_after`. On the losing side the surviving session's blob MUST be
    byte-identical to its pre-call value (§10.7 step 14c), and the consumed `opk_id` MUST be absent
    from the prekey store (step 14a is final). Reads a clock, so `inputs.now_ms` is REQUIRED."

 EVERY CLAUSE OF THAT IS AN OUTPUT BELOW, and three of them are the ones a port gets wrong:

 THE COMPARISON IS UNSIGNED (§11.1.1). `memcmp` is right in C only because it compares as
 `unsigned char`; on the JVM `byte` is signed, so a naive loop reads `0x80` as -128 and picks the
 other survivor. Because both sides must converge from the same public data, one port getting this
 backwards does not fail loudly — it diverges the two sides permanently.

 THE PLAINTEXT IS DELIVERED ON BOTH BRANCHES (§10.7 step 14d, §19.7). Dropping it on the losing side
 is not expressible in the return contract — §10.5 assigns no code to "your message authenticated and
 we discarded it" and forbids a null result with a null error — and it would hand an attacker who
 merely DELAYS one packet a silent, permanent message-suppression primitive, since §11.3 has the
 initiator retransmitting an identical prologue and therefore an identical `handshake_id`, which
 §10.7 step 4 then rejects as ERR_REPLAY forever.

 STEP 14a IS FINAL. The one-time prekey is consumed BEFORE the collapse and is not restored when the
 collapse goes against the session that consumed it. A port that reads "the session was torn down, so
 undo its side effects" reopens defect 7's replay window on the one path an attacker can drive by
 racing.

 The two pre-existing sessions arrive as literal §12.1 blobs in `inputs.sessions`, per §15.5. The
 generator's PREPARE phase below produces them by running the concurrent initiation once from the
 same fixed scalars; from then on the vector is exactly what a port sees.
 */
static void IRRatchetRunCollapse(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_prekey");

    IRRatchetClock clock = IRRatchetReadClock(io);

    NSData *aliceSigningSeed = [io dataInput:@"IK_A_s_seed"];
    NSData *aliceAgreement = [io dataInput:@"IK_A_d_scalar"];
    NSData *bobSigningSeed = [io dataInput:@"IK_B_s_seed"];
    NSData *bobAgreement = [io dataInput:@"IK_B_d_scalar"];

    const uint64_t notBeforeS = [io uint64Input:@"not_before"];
    const uint64_t notAfterS = [io uint64Input:@"not_after"];

    const uint32_t aliceSpkId = [io uint32Input:@"A_spk_id"];
    NSData *aliceSpkScalar = [io dataInput:@"A_SPK_scalar"];
    const uint32_t aliceOpkId = [io uint32Input:@"A_opk_id"];
    NSData *aliceOpkScalar = [io dataInput:@"A_OPK_scalar"];

    const uint32_t bobSpkId = [io uint32Input:@"B_spk_id"];
    NSData *bobSpkScalar = [io dataInput:@"B_SPK_scalar"];
    const uint32_t bobOpkId = [io uint32Input:@"B_opk_id"];
    NSData *bobOpkScalar = [io dataInput:@"B_OPK_scalar"];

    NSData *aliceReceiveScalar = [io dataInput:@"A_receive_ratchet_scalar"];
    NSData *bobReceiveScalar = [io dataInput:@"B_receive_ratchet_scalar"];

    NSData *messageToAlice = [io dataInput:@"message_to_alice"];
    NSData *messageToBob = [io dataInput:@"message_to_bob"];

    NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *sessions = [io sessionsInput];
    IRVectorRequire(sessions.count == 2 && sessions[@"A_own"] != nil && sessions[@"B_own"] != nil,
                    @"SESSION-COLLAPSE needs exactly the fixtures A_own and B_own");

    /* Each side draws its identity, its two prekeys, and then ONE ratchet key — §7.4 step 4, on the
       DH ratchet that §10.7 step 12 performs while decrypting the incoming type 0x02. That draw
       happens on BOTH branches: the losing side builds a complete session and then discards it, and
       a port that skipped the draw there would have a different CSPRNG position afterwards. */
    NSArray<NSData *> *aliceScript = @[aliceSigningSeed, aliceAgreement,
                                       aliceSpkScalar, aliceOpkScalar, aliceReceiveScalar];
    NSArray<NSData *> *bobScript = @[bobSigningSeed, bobAgreement,
                                     bobSpkScalar, bobOpkScalar, bobReceiveScalar];

    IRRatchetHost *alice = IRRatchetHostCreate(@"A", aliceScript, clock.nowS, clock.nowMs);
    IRRatchetHost *bob = IRRatchetHostCreate(@"B", bobScript, clock.nowS, clock.nowMs);

    IRRatchetHostPublish(alice, aliceSpkId, notBeforeS, notAfterS, @[@(aliceOpkId)]);
    IRRatchetHostPublish(bob, bobSpkId, notBeforeS, notAfterS, @[@(bobOpkId)]);

    IRSession *aliceOwn = IRRatchetLoadSession(alice, sessions[@"A_own"], @"A_own");
    IRSession *bobOwn = IRRatchetLoadSession(bob, sessions[@"B_own"], @"B_own");
    IRVectorRequire(![aliceOwn.handshakeId isEqualToData:bobOwn.handshakeId],
                    @"the two handshakes must be distinct or there is no collapse to resolve");

    NSError *error = nil;
    IRDecryptedMessage *atBob = [bob.messenger decryptPreKeyMessage:messageToBob error:&error];
    IRVectorRequire(atBob != nil, @"B: §10.7 must deliver a plaintext: %@", error);

    error = nil;
    IRDecryptedMessage *atAlice = [alice.messenger decryptPreKeyMessage:messageToAlice error:&error];
    IRVectorRequire(atAlice != nil, @"A: §10.7 must deliver a plaintext: %@", error);

    IRRatchetHostRequireScriptExhausted(alice);
    IRRatchetHostRequireScriptExhausted(bob);

    /* §11.1.1 — exactly one side's INCOMING session is the loser, and the fixture is required to be
       built so that is true (§15.3). If both or neither were, the row would not exercise step 14d. */
    IRVectorRequire(atAlice.establishedNewSession != atBob.establishedNewSession,
                    @"exactly one side's incoming session must lose the §11.1.1 comparison");

    const BOOL aliceIsLosingSide = !atAlice.establishedNewSession;
    IRSession *loserSideSurvivor = aliceIsLosingSide ? atAlice.session : atBob.session;
    IRSession *loserSideOwn = aliceIsLosingSide ? aliceOwn : bobOwn;
    NSString *loserSideFixtureName = aliceIsLosingSide ? @"A_own" : @"B_own";

    /* On the losing branch the survivor is the caller's PRE-EXISTING handle. §11.6 is emphatic that
       a bare "a collapse occurred" boolean is not enough precisely here: it is true on both branches
       while the obligation is opposite, and a port that told this caller to discard its handle would
       destroy the one session it must keep. */
    IRVectorRequire([loserSideSurvivor.handshakeId isEqualToData:loserSideOwn.handshakeId],
                    @"on the losing branch the survivor MUST be the pre-existing session");
    IRVectorRequire(!loserSideOwn.isTornDown,
                    @"on the losing branch the caller's own session MUST stay live");

    [io output:@"losing_side" string:(aliceIsLosingSide ? @"A" : @"B")];

    /* §10.7 step 14d — REQUIRED on both sides. */
    [io output:@"A_plaintext" data:atAlice.plaintext];
    [io output:@"B_plaintext" data:atBob.plaintext];

    /* §11.6 — true iff this call ran §10.7 AND the session it built is the survivor. */
    [io output:@"A_established_new_session" boolean:atAlice.establishedNewSession];
    [io output:@"B_established_new_session" boolean:atBob.establishedNewSession];

    /* §11.6 — the observable. A handle has no byte representation, so the id is the only way a
       caller can tell whether a handle IT holds is the one that died. */
    IRVectorRequire(atAlice.tornDownHandshakeId != nil && atBob.tornDownHandshakeId != nil,
                    @"both sides tear a session down; neither id may be absent");
    [io output:@"A_torn_down_handshake_id" data:atAlice.tornDownHandshakeId];
    [io output:@"B_torn_down_handshake_id" data:atBob.tornDownHandshakeId];

    /* §11.1.1 — both sides converge on the SAME survivor, with no negotiation and no dependence on
       arrival order, and it is the GREATER handshake_id read as a 64-byte unsigned big-endian
       integer. */
    IRVectorRequire([atAlice.session.handshakeId isEqualToData:atBob.session.handshakeId],
                    @"the two sides did not converge on one survivor");
    [io output:@"surviving_handshake_id" data:atAlice.session.handshakeId];

    /* §11.6 — the derived flag, which is the disjunction ONLY on the winning branch. */
    [io output:@"A_collapsed_existing_session" boolean:atAlice.collapsedExistingSession];
    [io output:@"B_collapsed_existing_session" boolean:atBob.collapsedExistingSession];

    /* §11.1.1 — one live session per peer, on each side, afterwards. */
    [io output:@"A_live_session_count" number:alice.sessions.sessionCount];
    [io output:@"B_live_session_count" number:bob.sessions.sessionCount];

    /* §10.7 step 14a is FINAL — the OPK each side consumed is gone, including on the side whose
       session then lost the collapse. */
    [io output:@"A_opk_present_after" boolean:IRRatchetHostHasOPK(alice, aliceOpkId)];
    [io output:@"B_opk_present_after" boolean:IRRatchetHostHasOPK(bob, bobOpkId)];

    /* §10.7 step 14c — "the surviving session's state MUST NOT be modified by this message in any
       way". Emitted under §15.5's reserved `sessions.<name>.state_blob_after` key, which is defined
       as a byte-for-byte comparison against `inputs.sessions.<name>.state_blob`; this is the only
       expressible form of the assertion, and §12.1 is byte-normative so that it exists at all.

       Only the LOSING side has such a key: on the winning side the survivor is the session this
       message built, which has no pre-call value to be identical to. Its blob is emitted below
       instead, so both sides' final states are still pinned byte for byte. */
    NSData *loserSideBlobAfter = IRRatchetStateBlob(loserSideSurvivor);
    [io output:[NSString stringWithFormat:@"sessions.%@.state_blob_after", loserSideFixtureName]
         data:loserSideBlobAfter];
    IRVectorRequire([loserSideBlobAfter isEqualToData:sessions[loserSideFixtureName][@"state_blob"]],
                    @"§10.7 step 14c: the surviving session was modified by the losing message");

    [io output:@"A_surviving_state_blob" data:IRRatchetStateBlob(atAlice.session)];
    [io output:@"B_surviving_state_blob" data:IRRatchetStateBlob(atBob.session)];
}

/**
 The generator-only PREPARE phase for SESSION-COLLAPSE.

 Runs the concurrent initiation once — both sides publish, both open a session against the other's
 bundle, both encrypt one message — and freezes the result as the vector's `inputs`: two literal
 §12.1 blobs and two type `0x02` messages. Nothing here appears in `inputs` except through those
 four artifacts and the key material that reproduces the two hosts.

 The receive-time ratchet scalars are NOT in these scripts: they are drawn by the run function, on
 both sides, when §10.7 step 12 ratchets. Each host's script is therefore asserted exhausted here,
 which is what catches a miscount before it becomes a frozen artifact.
 */
static NSDictionary<NSString *, id> *IRRatchetPrepareCollapseValues(void) {
    NSData *aliceRatchetInit = IRRatchetIndexedBytes(kIRRatchetScalarPrefixA, 0, 32);
    NSData *bobRatchetInit = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 0, 32);
    NSData *aliceNonce = IRRatchetIndexedBytes(kIRRatchetNoncePrefixA, 0, 12);
    NSData *bobNonce = IRRatchetIndexedBytes(kIRRatchetNoncePrefixB, 0, 12);
    NSData *aliceReceiveScalar = IRRatchetIndexedBytes(kIRRatchetScalarPrefixA, 9, 32);
    NSData *bobReceiveScalar = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 9, 32);

    NSArray<NSData *> *aliceScript = @[kIRRatchetAliceSigningSeed, kIRRatchetAliceAgreement,
                                       kIRRatchetAliceSPKScalar, kIRRatchetAliceOPKScalar,
                                       kIRRatchetAliceEphemeral, aliceRatchetInit, aliceNonce];
    NSArray<NSData *> *bobScript = @[kIRRatchetBobSigningSeed, kIRRatchetBobAgreement,
                                     kIRRatchetBobSPKScalar, kIRRatchetBobOPKScalar,
                                     kIRRatchetBobEphemeral, bobRatchetInit, bobNonce];

    IRRatchetHost *alice = IRRatchetHostCreate(@"A(prepare)", aliceScript,
                                               kIRRatchetNowS, kIRRatchetNowMs);
    IRRatchetHost *bob = IRRatchetHostCreate(@"B(prepare)", bobScript,
                                             kIRRatchetNowS, kIRRatchetNowMs);

    IRRatchetPreKeys *alicePreKeys = IRRatchetHostPublish(alice, kIRRatchetAliceSpkId,
                                                          kIRRatchetNotBeforeS, kIRRatchetNotAfterS,
                                                          @[@(kIRRatchetAliceOpkId)]);
    IRRatchetPreKeys *bobPreKeys = IRRatchetHostPublish(bob, kIRRatchetBobSpkId,
                                                        kIRRatchetNotBeforeS, kIRRatchetNotAfterS,
                                                        @[@(kIRRatchetBobOpkId)]);

    NSError *error = nil;
    IRSession *aliceOwn = [alice.messenger beginSessionWithBundleData:bobPreKeys.bundleData
                                                                error:&error];
    IRVectorRequire(aliceOwn != nil, @"prepare: A could not open a session: %@", error);

    IRSession *bobOwn = [bob.messenger beginSessionWithBundleData:alicePreKeys.bundleData
                                                            error:&error];
    IRVectorRequire(bobOwn != nil, @"prepare: B could not open a session: %@", error);

    NSData *messageToBob = [alice.messenger encrypt:IRRatchetText(@"alice opens")
                                          inSession:aliceOwn
                                              error:&error];
    IRVectorRequire(messageToBob != nil, @"prepare: A could not encrypt: %@", error);

    NSData *messageToAlice = [bob.messenger encrypt:IRRatchetText(@"bob opens")
                                          inSession:bobOwn
                                              error:&error];
    IRVectorRequire(messageToAlice != nil, @"prepare: B could not encrypt: %@", error);

    IRRatchetHostRequireScriptExhausted(alice);
    IRRatchetHostRequireScriptExhausted(bob);

    return @{
        @"entry_point"              : @"decrypt_prekey",
        @"now_s"                    : @(kIRRatchetNowS),
        @"now_ms"                   : @(kIRRatchetNowMs),
        @"IK_A_s_seed"              : kIRRatchetAliceSigningSeed,
        @"IK_A_d_scalar"            : kIRRatchetAliceAgreement,
        @"IK_B_s_seed"              : kIRRatchetBobSigningSeed,
        @"IK_B_d_scalar"            : kIRRatchetBobAgreement,
        @"not_before"               : @(kIRRatchetNotBeforeS),
        @"not_after"                : @(kIRRatchetNotAfterS),
        @"A_spk_id"                 : @(kIRRatchetAliceSpkId),
        @"A_SPK_scalar"             : kIRRatchetAliceSPKScalar,
        @"A_opk_id"                 : @(kIRRatchetAliceOpkId),
        @"A_OPK_scalar"             : kIRRatchetAliceOPKScalar,
        @"B_spk_id"                 : @(kIRRatchetBobSpkId),
        @"B_SPK_scalar"             : kIRRatchetBobSPKScalar,
        @"B_opk_id"                 : @(kIRRatchetBobOpkId),
        @"B_OPK_scalar"             : kIRRatchetBobOPKScalar,
        @"A_receive_ratchet_scalar" : aliceReceiveScalar,
        @"B_receive_ratchet_scalar" : bobReceiveScalar,
        @"message_to_alice"         : messageToAlice,
        @"message_to_bob"           : messageToBob,
        @"sessions"                 : @{
            @"A_own" : IRRatchetSessionFixture(aliceOwn),
            @"B_own" : IRRatchetSessionFixture(bobOwn),
        },
    };
}

#pragma mark - DEMUX-NO-TRIAL (§11.5 rule 3)

/**
 §15.3: "The `NEG-DEMUX-WRONG-SESSION` fixture, second step: after the wrong-handle submission has
 failed with `ERR_AEAD_AUTH_FAILED`, the SAME message under the CORRECT handle MUST decrypt to the
 original plaintext. A port that trial-decrypted and committed answers this with `ERR_REPLAY` and
 fails here; a port that trial-decrypted and RETURNED the plaintext already failed
 `NEG-DEMUX-WRONG-SESSION`'s `expect`. Together the two are the only pair in the suite that makes
 §11.5 rule 3 falsifiable."

 THE FIXTURE IS TWO-PEER, AND IT HAS TO BE. §11.1.1's bound is per PEER, so a single-peer setup has
 no sibling to retry against and "did not retry" is satisfied vacuously. Here B holds one live
 session with A and one with C, and the message offered against the wrong handle is a legitimate
 message of A's current sending chain — it genuinely WOULD decrypt under the other handle.

 THREE WRONG SHAPES, AND EACH FAILS A DIFFERENT ASSERTION HERE:

   - retry and return the plaintext      -> fails `NEG-DEMUX-WRONG-SESSION`'s `expect: error`
   - retry, commit, then report failure  -> A's session has consumed the message, so this row's
                                            recovery answers ERR_REPLAY instead of the plaintext
   - retry, then suppress the result     -> `sessions.B_with_alice.state_blob_after` differs from
                                            its input: `Nr` advanced and `CKr` was rewritten

 The third is why both blobs are outputs. §7.7 says a failed decrypt mutates nothing, and §12.1 is
 byte-normative precisely so that "nothing" is expressible rather than merely asserted in prose.

 §11.5 rule 3 also notes the COST a trial-decrypting port pays: §7.9 phase 3c runs SkipMessageKeys
 BEFORE the AEAD check, so every extra candidate is worth up to MAX_SKIP_PER_MESSAGE HMACs and as
 many snapshot insertions. On a conformant implementation the failed attempt leaves the wrong
 session's skipped store exactly as it was, which the unchanged blob also states.
 */
static void IRRatchetRunDemuxNoTrial(IRRatchetIO *io) {
    IRRatchetReadEntryPoint(io, @"decrypt_with_handle");

    IRRatchetClock clock = IRRatchetReadClock(io);

    NSData *bobSigningSeed = [io dataInput:@"IK_B_s_seed"];
    NSData *bobAgreement = [io dataInput:@"IK_B_d_scalar"];
    NSData *wrongAttemptScalar = [io dataInput:@"wrong_attempt_ratchet_scalar"];
    NSData *recoveryScalar = [io dataInput:@"recovery_ratchet_scalar"];
    NSData *message = [io dataInput:@"message"];

    NSString *selectedName = [io stringInput:@"selected_session"];
    NSString *recoveryName = [io stringInput:@"recovery_session"];

    NSDictionary<NSString *, NSDictionary<NSString *, NSData *> *> *sessions = [io sessionsInput];
    IRVectorRequire(sessions.count == 2, @"DEMUX-NO-TRIAL needs exactly two session fixtures");
    IRVectorRequire(sessions[selectedName] != nil && sessions[recoveryName] != nil,
                    @"selected_session and recovery_session must both name a fixture");
    IRVectorRequire(![selectedName isEqualToString:recoveryName],
                    @"the two handles must differ or there is no trial to forbid");

    /* B draws no prekey material here: this is a type 0x01 delivery and §10.1 touches neither
       store. Two ratchet keys are drawn, one per attempt — §7.9 phase 3b runs BEFORE the AEAD, so
       even the attempt that fails performs a DH ratchet on its snapshot and then discards it. */
    NSArray<NSData *> *bobScript = @[bobSigningSeed, bobAgreement,
                                     wrongAttemptScalar, recoveryScalar];

    IRRatchetHost *bob = IRRatchetHostCreate(@"B", bobScript, clock.nowS, clock.nowMs);

    IRSession *selected = IRRatchetLoadSession(bob, sessions[selectedName], selectedName);
    IRSession *recovery = IRRatchetLoadSession(bob, sessions[recoveryName], recoveryName);
    IRVectorRequire(bob.sessions.sessionCount == 2,
                    @"§11.1.1's bound is per PEER: B must hold both sessions at once");

    /* THE WRONG HANDLE. §11.5 rule 1 requires the handle to be supplied explicitly, and rule 2 puts
       its selection outside the message entirely — nothing in a type 0x01 header is authenticated
       before decryption, so routing on header bytes would let an attacker choose which session
       absorbs the cost of processing a forgery. */
    NSError *error = nil;
    IRDecryptedMessage *attempt = [bob.messenger decryptMessage:message
                                                      inSession:selected
                                                          error:&error];
    IRVectorRequire(attempt == nil,
                    @"§11.5 rule 3: the wrong handle MUST NOT produce a plaintext");
    IRVectorRequire(error != nil, @"the failed attempt must set an error");
    NSString *attemptErrorName = IRVectorNameForErrorCode((IRErrorCode)error.code) ?: @"<unknown>";

    [io output:@"first_attempt_error" string:attemptErrorName];

    /* §7.7 — NOTHING mutated, on EITHER session. Emitted under §15.5's reserved
       `sessions.<name>.state_blob_after`, which is defined as a byte-for-byte comparison against the
       matching input blob. */
    for (NSString *name in @[selectedName, recoveryName]) {
        IRSession *session = [name isEqualToString:selectedName] ? selected : recovery;
        NSData *blobAfter = IRRatchetStateBlob(session);

        [io output:[NSString stringWithFormat:@"sessions.%@.state_blob_after", name]
             data:blobAfter];
        IRVectorRequire([blobAfter isEqualToData:sessions[name][@"state_blob"]],
                        @"§7.7 / §11.5 rule 3: %@ was mutated by a failed decrypt", name);
    }

    /* THE RECOVERY, and the whole point of the row: the SAME bytes, under the CORRECT handle. */
    error = nil;
    IRDecryptedMessage *recovered = [bob.messenger decryptMessage:message
                                                        inSession:recovery
                                                            error:&error];
    IRVectorRequire(recovered != nil,
                    @"DEMUX-NO-TRIAL: the message MUST still decrypt under the correct handle; "
                    @"a port that trial-decrypted and committed answers this with a replay: %@",
                    error);

    IRRatchetHostRequireScriptExhausted(bob);

    [io output:@"plaintext" data:recovered.plaintext];

    /* §11.6 — a type 0x01 delivery never establishes a session and never tears one down. */
    [io output:@"established_new_session" boolean:recovered.establishedNewSession];
    [io output:@"torn_down_handshake_id_absent" boolean:(recovered.tornDownHandshakeId == nil)];

    /* The handle that came back is the one the caller supplied; nothing was collapsed. */
    [io output:@"recovery_handshake_id" data:recovered.session.handshakeId];
    [io output:@"live_session_count" number:bob.sessions.sessionCount];
}

/**
 The generator-only PREPARE phase for DEMUX-NO-TRIAL.

 Builds exactly the `NEG-DEMUX-WRONG-SESSION` fixture — B live with both A and C — and stops at the
 point the vector begins: a legitimate type 0x01 message from A, in hand, with both of B's sessions
 captured as literal §12.1 blobs.

 A publishes nothing; only B does. The two bundles advertise the SAME signed prekey and a DIFFERENT
 one-time prekey each, because §5.4 has a client fetching for one handshake use the FIRST OPK entry —
 giving A and C distinct DH4 terms without B rotating anything between them.
 */
static NSDictionary<NSString *, id> *IRRatchetPrepareDemuxValues(void) {
    NSData *aliceRatchetInit = IRRatchetIndexedBytes(kIRRatchetScalarPrefixA, 0, 32);
    NSData *aliceRatchetTurn = IRRatchetIndexedBytes(kIRRatchetScalarPrefixA, 1, 32);
    NSData *aliceNonce0 = IRRatchetIndexedBytes(kIRRatchetNoncePrefixA, 0, 12);
    NSData *aliceNonce1 = IRRatchetIndexedBytes(kIRRatchetNoncePrefixA, 1, 12);

    NSData *bobRatchetForAlice = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 0, 32);
    NSData *bobNonce0 = IRRatchetIndexedBytes(kIRRatchetNoncePrefixB, 0, 12);
    NSData *bobRatchetForCarol = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 1, 32);
    NSData *bobWrongAttemptScalar = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 8, 32);
    NSData *bobRecoveryScalar = IRRatchetIndexedBytes(kIRRatchetScalarPrefixB, 9, 32);

    NSData *carolRatchetInit = IRRatchetIndexedBytes(kIRRatchetScalarPrefixC, 0, 32);
    NSData *carolNonce0 = IRRatchetIndexedBytes(kIRRatchetNoncePrefixC, 0, 12);

    NSArray<NSData *> *aliceScript = @[kIRRatchetAliceSigningSeed, kIRRatchetAliceAgreement,
                                       kIRRatchetAliceEphemeral, aliceRatchetInit,
                                       aliceNonce0, aliceRatchetTurn, aliceNonce1];
    NSArray<NSData *> *bobScript = @[kIRRatchetBobSigningSeed, kIRRatchetBobAgreement,
                                     kIRRatchetBobSPKScalar,
                                     kIRRatchetBobOPKScalar, kIRRatchetBobOPK2Scalar,
                                     bobRatchetForAlice, bobNonce0, bobRatchetForCarol];
    NSArray<NSData *> *carolScript = @[kIRRatchetCarolSigningSeed, kIRRatchetCarolAgreement,
                                       kIRRatchetCarolEphemeral, carolRatchetInit, carolNonce0];

    IRRatchetHost *alice = IRRatchetHostCreate(@"A(prepare)", aliceScript,
                                               kIRRatchetNowS, kIRRatchetNowMs);
    IRRatchetHost *bob = IRRatchetHostCreate(@"B(prepare)", bobScript,
                                             kIRRatchetNowS, kIRRatchetNowMs);
    IRRatchetHost *carol = IRRatchetHostCreate(@"C(prepare)", carolScript,
                                               kIRRatchetNowS, kIRRatchetNowMs);

    IRRatchetPreKeys *bobPreKeys = IRRatchetHostPublish(bob, kIRRatchetBobSpkId,
                                                        kIRRatchetNotBeforeS, kIRRatchetNotAfterS,
                                                        @[@(kIRRatchetBobOpkId),
                                                          @(kIRRatchetBobOpk2Id)]);

    NSError *error = nil;
    NSData *bundleForAlice =
        [IRPreKeyBundle serializeWithIdentity:bob.identity.publicIdentity
                           signedPreKeyRecord:bobPreKeys.signedPreKey
                         oneTimePreKeyRecords:@[bobPreKeys.oneTimePreKeys[0]]
                                        error:&error];
    IRVectorRequire(bundleForAlice != nil, @"prepare: bundle for A: %@", error);

    NSData *bundleForCarol =
        [IRPreKeyBundle serializeWithIdentity:bob.identity.publicIdentity
                           signedPreKeyRecord:bobPreKeys.signedPreKey
                         oneTimePreKeyRecords:@[bobPreKeys.oneTimePreKeys[1]]
                                        error:&error];
    IRVectorRequire(bundleForCarol != nil, @"prepare: bundle for C: %@", error);

    IRSession *aliceSession = [alice.messenger beginSessionWithBundleData:bundleForAlice
                                                                    error:&error];
    IRVectorRequire(aliceSession != nil, @"prepare: A could not open a session: %@", error);

    NSData *aliceOpener = [alice.messenger encrypt:IRRatchetText(@"alice opens")
                                         inSession:aliceSession
                                             error:&error];
    IRVectorRequire(aliceOpener != nil, @"prepare: A could not encrypt: %@", error);

    IRDecryptedMessage *atBobFromAlice = [bob.messenger decryptPreKeyMessage:aliceOpener
                                                                       error:&error];
    IRVectorRequire(atBobFromAlice != nil, @"prepare: B could not open A's session: %@", error);

    NSData *ack = [bob.messenger encrypt:IRRatchetText(@"ack")
                               inSession:atBobFromAlice.session
                                   error:&error];
    IRVectorRequire(ack != nil, @"prepare: B could not encrypt: %@", error);

    /* §11.5 rule 2 — the peer comes from the transport. Here it is the fixture's own knowledge of
       who sent the packet, which is exactly the position a conformant host is in. */
    IRDecryptedMessage *atAlice =
        [alice.messenger decryptMessage:ack
                fromPeerIdentityKeyPair:bob.identity.identityKeyPair
                                  error:&error];
    IRVectorRequire(atAlice != nil, @"prepare: A could not read the ack: %@", error);

    /* §11.3 — A has now decrypted something from B, so this is a type 0x01 message. */
    NSData *message = [alice.messenger encrypt:IRRatchetText(@"for alices session")
                                     inSession:aliceSession
                                         error:&error];
    IRVectorRequire(message != nil, @"prepare: A could not encrypt the subject message: %@", error);

    IRSession *carolSession = [carol.messenger beginSessionWithBundleData:bundleForCarol
                                                                    error:&error];
    IRVectorRequire(carolSession != nil, @"prepare: C could not open a session: %@", error);

    NSData *carolOpener = [carol.messenger encrypt:IRRatchetText(@"carol here")
                                         inSession:carolSession
                                             error:&error];
    IRVectorRequire(carolOpener != nil, @"prepare: C could not encrypt: %@", error);

    IRDecryptedMessage *atBobFromCarol = [bob.messenger decryptPreKeyMessage:carolOpener
                                                                       error:&error];
    IRVectorRequire(atBobFromCarol != nil, @"prepare: B could not open C's session: %@", error);

    IRVectorRequire(bob.sessions.sessionCount == 2,
                    @"prepare: B must hold one session per peer, two in total");

    IRRatchetHostRequireScriptExhausted(alice);
    IRRatchetHostRequireScriptExhausted(bob);
    IRRatchetHostRequireScriptExhausted(carol);

    return @{
        @"entry_point"                  : @"decrypt_with_handle",
        @"now_s"                        : @(kIRRatchetNowS),
        @"now_ms"                       : @(kIRRatchetNowMs),
        @"IK_B_s_seed"                  : kIRRatchetBobSigningSeed,
        @"IK_B_d_scalar"                : kIRRatchetBobAgreement,
        @"wrong_attempt_ratchet_scalar" : bobWrongAttemptScalar,
        @"recovery_ratchet_scalar"      : bobRecoveryScalar,
        @"message"                      : message,
        @"selected_session"             : @"B_with_carol",
        @"recovery_session"             : @"B_with_alice",
        @"sessions"                     : @{
            @"B_with_alice" : IRRatchetSessionFixture(atBobFromAlice.session),
            @"B_with_carol" : IRRatchetSessionFixture(atBobFromCarol.session),
        },
    };
}

#pragma mark - Vector table

/// The shape of every run function: one pass over one vector, in whichever IO mode it was given.
typedef void (*IRRatchetRunFunction)(IRRatchetIO *io);

/**
 One row of ratchet.json — id, description, the literals it is built from, and the code that both
 builds and executes it.

 `values` is a BLOCK rather than a dictionary because two rows compute theirs by running a full
 conversation first (the PREPARE phases above), and doing that eagerly for every row would make a
 failure in one row's fixture look like a failure in another.
 */
typedef NSDictionary<NSString *, id> * (^IRRatchetValuesBlock)(void);

static NSDictionary *IRRatchetBuildVector(NSString *identifier,
                                          NSString *description,
                                          IRRatchetValuesBlock values,
                                          IRRatchetRunFunction run) {
    IRRatchetIO *io = [IRRatchetIO generatorWithValues:values()];

    run(io);

    /* The generator-side mirror of §15.5 rule 3: every literal declared was read, so `inputs` is
       exactly what the run function consumes and an executor cannot be handed a field it ignores. */
    [io requireEveryValueRead];

    IRVectorRequire(io.recordedInputs.count > 0, @"%@ recorded no inputs", identifier);
    IRVectorRequire(io.recordedOutputs.count > 0, @"%@ recorded no outputs", identifier);

    NSMutableDictionary *vector = [NSMutableDictionary dictionary];
    vector[@"id"] = identifier;
    vector[@"kind"] = @"ratchet";
    vector[@"description"] = description;
    vector[@"expect"] = @"ok";
    vector[@"inputs"] = io.recordedInputs;
    vector[@"outputs"] = io.recordedOutputs;

    /* §15.5 makes `intermediates` optional, and an empty object would be a key a runner must then
       check nothing against. */
    if (io.recordedIntermediates.count > 0) {
        vector[@"intermediates"] = io.recordedIntermediates;
    }

    return vector;
}

/// id -> run function, for the executor. The single table; the generator uses the same names.
static IRRatchetRunFunction IRRatchetRunFunctionForIdentifier(NSString *identifier) {
    if ([identifier isEqualToString:@"RATCHET-INIT"])          { return IRRatchetRunInit; }
    if ([identifier isEqualToString:@"RATCHET-LINEAR"])        { return IRRatchetRunLinear; }
    if ([identifier isEqualToString:@"RATCHET-BIDI"])          { return IRRatchetRunBidi; }
    if ([identifier isEqualToString:@"RATCHET-SKIP"])          { return IRRatchetRunSkip; }
    if ([identifier isEqualToString:@"RATCHET-SKIP-XCHAIN"])   { return IRRatchetRunSkipCrossChain; }
    if ([identifier isEqualToString:@"RATCHET-PREKEY-BURST"])  { return IRRatchetRunPrekeyBurst; }
    if ([identifier isEqualToString:@"RATCHET-RETRANSMIT"])    { return IRRatchetRunRetransmit; }
    if ([identifier isEqualToString:@"SESSION-COLLAPSE"])      { return IRRatchetRunCollapse; }
    if ([identifier isEqualToString:@"DEMUX-NO-TRIAL"])        { return IRRatchetRunDemuxNoTrial; }

    return NULL;
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForRatchet(void) {
    NSDictionary *init = IRRatchetBuildVector(
        @"RATCHET-INIT",
        @"§7.5 ratchet initialization on both sides, observed the instant A's first type 0x02 "
        @"message has been delivered. Asserts A.CKs == B.CKr, and EXPLICITLY asserts A.RK != B.RK: "
        @"B's DHRatchet performs two KDF_RK steps while A has performed one, so B's root key is "
        @"legitimately one step ahead and an implementer who asserts equality here will fix working "
        @"code.",
        ^{ return IRRatchetInitValues(); },
        IRRatchetRunInit);

    NSDictionary *linear = IRRatchetBuildVector(
        @"RATCHET-LINEAR",
        @"Ten messages A to B in a single sending chain with no ratchet turn between them, after a "
        @"two-message preamble that lets A stop sending type 0x02 (§11.3). The first of the ten "
        @"carries N = 0 with PN = 1, so a port that writes state.Ns into the PN slot — defect 10 — "
        @"diverges on it.",
        ^{ return IRRatchetLinearValues(); },
        IRRatchetRunLinear);

    NSDictionary *bidi = IRRatchetBuildVector(
        @"RATCHET-BIDI",
        @"A to B, B to A, A to B, B to A. The only row that fails a port which recomputes SESSION_AD "
        @"as (self, peer) instead of §6.5's role order: such a port is self-consistent in one "
        @"direction, so only a message sealed under one side's AD and opened under the other's "
        @"exposes it.",
        ^{ return IRRatchetBidiValues(); },
        IRRatchetRunBidi);

    NSDictionary *skip = IRRatchetBuildVector(
        @"RATCHET-SKIP",
        @"Messages 0,1,2,3 sent in one chain and delivered 0,3,1,2. Receiving 3 derives and stores "
        @"the keys for 1 and 2 (§7.6); the two late deliveries are §7.9 phase 3a hits, which return "
        @"WITHOUT a DH ratchet and WITHOUT advancing Nr, and which remove the stored key only after "
        @"the AEAD has succeeded.",
        ^{ return IRRatchetSkipValues(); },
        IRRatchetRunSkip);

    NSDictionary *skipCrossChain = IRRatchetBuildVector(
        @"RATCHET-SKIP-XCHAIN",
        @"Skipped message keys recovered ACROSS a DH ratchet. A sends three messages in chain 2, B "
        @"sees only the first, then both sides turn; A's next message carries N = 0 and PN = 3 and "
        @"§7.4 step 1 drains the OLD receiving chain to that PN before DHr is replaced. This is "
        @"exactly what defect 10 was masking: with PN never transmitted, the two held-back messages "
        @"are unrecoverable and every single-chain test still passes.",
        ^{ return IRRatchetSkipCrossChainValues(); },
        IRRatchetRunSkipCrossChain);

    NSDictionary *prekeyBurst = IRRatchetBuildVector(
        @"RATCHET-PREKEY-BURST",
        @"Three type 0x02 messages with N = 0, 1, 2 before B replies, all of which decrypt (§9.2, "
        @"§11.3). The prologue is identical across all three — same EK_A, spk_id, opk_flag, opk_id — "
        @"and only N, the nonce and the ciphertext vary. A port that hard-codes N = 0 in a type 0x02 "
        @"header emits three near-identical headers and answers the second with ERR_REPLAY.",
        ^{ return IRRatchetPrekeyBurstValues(); },
        IRRatchetRunPrekeyBurst);

    NSDictionary *retransmit = IRRatchetBuildVector(
        @"RATCHET-RETRANSMIT",
        @"The same type 0x02 message delivered twice. The second is ERR_REPLAY through §11.2's "
        @"existing-session branch — which MUST NOT re-run X3DH, since the one-time prekey is already "
        @"consumed — and a third message then proves the session survived. The consumed opk_id stays "
        @"absent across the replay (§10.7 step 14a is final).",
        ^{ return IRRatchetRetransmitValues(); },
        IRRatchetRunRetransmit);

    NSDictionary *collapse = IRRatchetBuildVector(
        @"SESSION-COLLAPSE",
        @"A and B initiate concurrently and each receives the other's type 0x02, from fixed keys so "
        @"the §11.1.1 comparison is decided in advance. Two-sided: both converge on the greater "
        @"handshake_id read as a 64-byte UNSIGNED big-endian integer, both deliver a plaintext "
        @"(§10.7 step 14d — the losing branch delivers too, or a packet delay becomes a permanent "
        @"message-suppression primitive), both report the id they tore down, the losing side's "
        @"surviving session is byte-identical to its pre-call blob (step 14c), and both consumed "
        @"one-time prekeys stay consumed (step 14a is final). The two pre-existing sessions are "
        @"supplied as literal §12.1 blobs per §15.5.",
        ^{ return IRRatchetPrepareCollapseValues(); },
        IRRatchetRunCollapse);

    NSDictionary *demuxNoTrial = IRRatchetBuildVector(
        @"DEMUX-NO-TRIAL",
        @"The NEG-DEMUX-WRONG-SESSION fixture's second step. B holds one live session with A and one "
        @"with C; a legitimate type 0x01 message from A is submitted against the handle for C, must "
        @"fail with ERR_AEAD_AUTH_FAILED, must leave BOTH session blobs byte-identical (§7.7), and "
        @"the SAME bytes must then decrypt under the correct handle. A port that trial-decrypted and "
        @"committed answers the recovery with ERR_REPLAY; one that trial-decrypted and returned the "
        @"plaintext already failed NEG-DEMUX-WRONG-SESSION. The pair is what makes §11.5 rule 3 "
        @"falsifiable.",
        ^{ return IRRatchetPrepareDemuxValues(); },
        IRRatchetRunDemuxNoTrial);

    /* THE ORDER IS PART OF THE FROZEN BYTES. It follows §15.3's table top to bottom. */
    return @[init, linear, bidi, skip, skipCrossChain, prekeyBurst, retransmit, collapse,
             demuxNoTrial];
}

#pragma mark - Executor

void IRRunRatchetVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    if (![vectorCase.kind isEqualToString:@"ratchet"]) {
        IRVectorRecordFailure(testCase, @"[%@] kind is \"%@\"; ratchet.json carries only \"ratchet\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    IRRatchetRunFunction run = IRRatchetRunFunctionForIdentifier(vectorCase.identifier);
    if (run == NULL) {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is what
           §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase, @"[%@] ratchet.json has no executor for this id",
                              vectorCase.identifier);
        return;
    }

    /* Every row in this file is `expect: "ok"`. The error-valued observations inside them — the
       replay of RATCHET-RETRANSMIT, the wrong-handle failure of DEMUX-NO-TRIAL — are intermediate
       steps of a successful conversation, not the vector's outcome, so each is checked as a NAMED
       output rather than through `expect`. §15.4 is where a vector's own outcome is an error. */
    if (vectorCase.expectsError) {
        IRVectorRecordFailure(testCase, @"[%@] ratchet.json carries no expect: \"error\" vectors",
                              vectorCase.identifier);
        [vectorCase finish];
        return;
    }

    run([IRRatchetIO executorWithCase:vectorCase]);

    [vectorCase checkResultError:nil];
    [vectorCase finish];
}
