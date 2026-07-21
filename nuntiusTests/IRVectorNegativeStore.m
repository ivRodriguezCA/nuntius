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
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSessionStateCodec.h"

/**
 negative.json, the STORE block — SPEC §5.4, §10.3, §12.1, §12.2, §15.4, §15.5, §19.4, §19.5.

 ELEVEN VECTORS, covering the two hand-written decoders that take bytes out of local or
 server-supplied STORAGE rather than off a live message: the state-blob parser of §12.2 and the
 prekey-bundle parser of §10.3. Both are §12.4 fuzz targets, and the bundle parser in particular is
 reachable from a hostile or compromised prekey-distribution server before any signature has been
 verified, because §5.3 orders parsing first.

     NEG-STATE-TRAILING        472-byte blob plus one byte      ERR_TRAILING_BYTES
     NEG-STATE-COUNT           skipped_count = 2001             ERR_STATE_CORRUPT
     NEG-STATE-UNCLAMPED-LOW   blob[243] & 0x07 != 0            ERR_STATE_CORRUPT
     NEG-STATE-UNCLAMPED-HIGH  blob[274] & 0xC0 != 0x40         ERR_STATE_CORRUPT
     NEG-BUNDLE-EMPTY          zero-length bundle               ERR_BUNDLE_MALFORMED
     NEG-BUNDLE-SHORT          250-byte bundle                  ERR_BUNDLE_MALFORMED
     NEG-BUNDLE-MAGIC          251 bytes, magic is not NTB4     ERR_BUNDLE_MALFORMED
     NEG-BUNDLE-VERSION        251 bytes, bundle[4] == 0x03     ERR_UNSUPPORTED_VERSION
     NEG-BUNDLE-OPKCOUNT       opk_count 1001, length agrees    ERR_BUNDLE_MALFORMED
     NEG-BUNDLE-LEN-LONG       one byte too long, opk_count 0   ERR_BUNDLE_MALFORMED
     NEG-BUNDLE-LEN-SHORT      one byte too short, opk_count 1  ERR_BUNDLE_MALFORMED

 FOUR §15.4 ROWS EXPAND INTO TWO VECTORS EACH OR NONE — the id suffixes are forced, not invented
 freely. §15.4 states `NEG-STATE-UNCLAMPED` as one row that requires "one vector with
 blob[243] & 0x07 != 0, one with blob[274] & 0xC0 != 0x40", and `NEG-BUNDLE-LEN` as one row for
 which "both directions are required". §15.5 makes `id` unique across all six files, so two vectors
 cannot share one id. The four suffixed ids below are therefore the row ids plus the discriminator
 the row itself names, in the style §15.4 already uses for `NEG-VERSION-SHORT` and
 `NEG-PUBKEY-REFLECT-02-EKA`. They are stable forever from here.

 THE TWO ROWS THAT ARE THE POINT OF THE BUNDLE BLOCK, per §15.4's closing notes:
 `NEG-BUNDLE-EMPTY` and `NEG-BUNDLE-SHORT` are "the only inputs that exercise the bundle parser's
 length floor, and the over-long direction that a test author writes naturally exercises the safe
 side". A bundle longer than 251 bytes always has readable bytes at offset 249; the two vectors that
 do not are the entire test of §10.3 step 1. §10.3 spells out the three divergent failures a missing
 floor produces — Objective-C reads adjacent heap and may then copy 36 * opk_count bytes from offset
 251, Swift `Data` slice subscripting traps, and the JVM throws an unchecked
 IndexOutOfBoundsException that escapes the ERR_BUNDLE_MALFORMED contract entirely.

 `NEG-BUNDLE-EMPTY` IS THE CONTENT CASE, NOT THE NULL CASE (§13.4 clause 6). Its input is a
 zero-length byte string that EXISTS. A null reference passed for a `_Nonnull` parameter is a caller
 contract violation with no §10.5 code and a mandatory fail-fast, is deliberately not covered by any
 vector, and would be uncompilable in Swift; §13.4 clause 6 names this row, `NEG-TRUNCATED` and
 §10.4's legal empty plaintext as exactly the adjacent legal cases that keep the two from being
 conflated. So this vector's `bundle` is the empty hex string, and the runner hands the parser a real
 empty NSData.

 `NEG-BUNDLE-VERSION` IS THE ONE BUNDLE-STRUCTURE VECTOR THAT IS NOT ERR_BUNDLE_MALFORMED. §10.3 step
 3 assigns ERR_UNSUPPORTED_VERSION to a wrong version byte deliberately: version is a distinguishable
 condition with its own code. Every OTHER bundle structural failure, in EITHER length direction, is
 ERR_BUNDLE_MALFORMED and never ERR_TRAILING_BYTES — §19.4 decided this and §10.5 code 7105 is now
 state-blob-only, which is why `NEG-STATE-TRAILING` is the only 7105 in this file and no bundle
 vector carries it.

 EVERY DEFECTIVE ARTIFACT IS BYTE SURGERY ON A VALID ONE. The generator builds a conformant blob and
 a conformant bundle, ASSERTS THAT EACH PARSES, and only then breaks exactly one thing. That is what
 makes the expected error code mean something: without the positive control, a vector that fails for
 an unrelated second reason still shows green. IRPreKeyBundle's encoder is deliberately conformant —
 it refuses to emit more than MAX_BUNDLE_OPK_COUNT entries — and §5.4's note that the negative
 artifacts are "constructed by byte surgery on a valid bundle rather than by weakening this method"
 is honoured here rather than worked around.

 CLOCKS AND RANDOMNESS (§15.5 rules 5–6, §15.6). The state vectors read a clock: §12.2 rule 9 sweeps
 skipped entries against SKIPPED_TTL_MS, so each supplies an `inputs.now_ms` and the executor passes
 it to the codec. Every such blob carries `skipped_count` 0, so the sweep has nothing to do and the
 value only has to exist — but a vector that read a clock and supplied none would be MALFORMED under
 rule 6, and the driver's ten-years-forward run is what would catch it. The bundle vectors read NO
 clock: §10.3 and §5.3 rules 2–4 are pure byte and signature tests, §5.3 rules 5–6 live in
 -validateValidityWindowAtUnixSeconds:error:, and none of these eleven inputs survives far enough to
 reach it. All randomness the generator consumes is scripted from the literals below through
 IRScriptedRandomSource, which fails on exhaustion rather than cycling.

 ON `kind`, AND THIS MODULE EMITS TWO OF THEM. The four state rows carry `kind: "state"`; the seven
 bundle rows carry `kind: "wire"`. That is not a module-router value, it is a CLASSIFICATION of the
 vector: a prekey bundle is a §5.4 WIRE structure parsed by a §10.3 gate, and it is not a §12.1
 state blob. An earlier revision froze the bundle rows as `"state"` because this module happened to
 emit them, and the consequence was concrete — a port runner that switched on `kind` to pick a
 parser would hand a 251-byte bundle to its state-blob parser.

 `kind` IS A PROPERTY OF THE VECTOR, NOT OF THE MODULE THAT PRODUCED IT, so the rows stay here and
 the driver routes on the reserved `inputs.entry_point` key instead — `parse_state` for the four
 state rows, `parse_bundle` for the seven bundle rows. §15.5 now says so in as many words: within
 negative.json `entry_point` is authoritative for selecting the API under test and `kind` is a
 classification, so where the two appear to disagree, `entry_point` governs. A port MUST switch on
 `entry_point`. IRVectorModules.h's partition comment lists the `NEG-BUNDLE-*` rows under
 IRVectorsForNegativeWire; they are implemented HERE, exactly once, and §15.5's id-uniqueness rule
 makes a double implementation a loud failure rather than a silent one.
 */

#pragma mark - Fixed key material

/* Ed25519 seed (§4.2: the 32-byte RFC 8032 seed, never libsodium's 64-byte expanded sk). */
static NSString * const kNegStoreResponderEd25519Seed =
    @"5b1b2c3d4e5f60718293a4b5c6d7e8f9202122232425262728292a2b2c2d2e2f";

/* Raw X25519 scalars as handed to the CSPRNG seam. The stored form is the §4.2 CLAMP of these, and
   the public halves are derived from the clamped scalar by the implementation, never by this file. */
static NSString * const kNegStoreResponderX25519Scalar =
    @"5c303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e";
static NSString * const kNegStoreSignedPreKeyScalar =
    @"5d505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e";
static NSString * const kNegStoreOneTimePreKeyScalar =
    @"5e707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e";

static const uint32_t kNegStoreSpkId = 11;
static const uint32_t kNegStoreOpkId = 77;

/* §5.2's window, as fixed literals that become part of the frozen bytes. 2026-01-01T00:00:00Z to
   2026-03-30T00:00:00Z is 7603200 seconds, inside MAX_SPK_VALIDITY_SECONDS (7776000). No vector here
   evaluates the window — every one of them is rejected by §10.3 before §5.3 rules 5–6 could run —
   but a value that could not pass rule 6 would be a trap for whoever reuses these bytes. */
static const uint64_t kNegStoreNotBeforeS = 1767225600ULL;
static const uint64_t kNegStoreNotAfterS  = 1774828800ULL;

/* §15.5 rule 6's injected clock for the state vectors: 2026-01-01T00:00:00Z in milliseconds. Every
   state blob here carries skipped_count 0, so §12.2 rule 9 sweeps nothing and the value is inert —
   it is supplied because the code path READS a clock, which is what rule 6 is about. */
static const uint64_t kNegStoreNowMs = 1767225600000ULL;

#pragma mark - Literal §12.1 blob construction

/**
 Deterministic filler. Distinct `seed` values give distinct regions, so a field read at the wrong
 offset produces a visibly wrong value rather than a plausible one.
 */
static void IRNegStoreFillPattern(uint8_t *buffer, NSUInteger length, uint8_t seed) {
    for (NSUInteger i = 0; i < length; i++) {
        buffer[i] = (uint8_t)((seed * 31u) + (i * 7u) + 1u);
    }
}

/// §4.4 check 2 — an X25519 u-coordinate has bit 255 clear.
static void IRNegStoreMakeX25519PublicShape(uint8_t *key) {
    key[31] &= 0x7F;
}

/// §4.2 — the clamped scalar form §12.2 rule 8 requires on read (§19.5: reject, never re-clamp).
static void IRNegStoreMakeClampedShape(uint8_t *scalar) {
    scalar[0] &= 0xF8;
    scalar[31] &= 0x7F;
    scalar[31] |= 0x40;
}

/**
 A structurally valid §12.1 blob, built byte by byte at the offsets in the field table.

 BUILT FROM LITERALS, NEVER BY EXECUTING A RATCHET AND SERIALIZING THE RESULT. §15.3 makes that the
 only reproducible form, and it matters even for a negative vector: a blob reached by ratcheting
 would carry the generator's own now_ms() in its `inserted_at_ms` fields and would decay against
 SKIPPED_TTL_MS a week after the freeze.

 The shape is role initiator, DHr / CKs / CKr all present, no prologue, `skipped_count` 0 — 472
 bytes exactly. `skipped_count` 0 is deliberate on every vector in this file: it keeps §12.2 rule 9's
 TTL sweep out of the picture, so each vector fails for the one reason it names.

 The public halves and the private scalar are unrelated filler, which the codec accepts: §12.2 lists
 no rule tying `DHs_pub` to `DHs_priv`, and imposing one would make this implementation reject blobs
 the other three ports accept.
 */
static NSMutableData *IRNegStoreValidStateBlob(void) {
    NSMutableData *blob = [NSMutableData dataWithLength:(NSUInteger)kIRLenStatePrefix];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    memcpy(raw + kIROffStateMagic, kIRStateMagic, (size_t)kIRLenMagic);
    raw[kIROffStateFormat] = (uint8_t)kIRStateFormat;
    raw[kIROffStateRole] = 0x01;                       /* initiator */

    /* SESSION_AD (§6.5), stored verbatim at offset 6: the 13-byte label then four identity keys in
       ROLE order. The two Ed25519 halves are NOT masked — §12.2 rule 7 excludes them, because bit
       255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is set in roughly half of
       all valid identities. */
    memcpy(raw + kIROffStateSessionAD, kIRLabelAD, (size_t)kIRLenLabelAD);
    IRNegStoreFillPattern(raw + kIROffStateInitiatorSigning, kIRLenEd25519Public, 11);
    IRNegStoreFillPattern(raw + kIROffStateInitiatorAgreement, kIRLenX25519Public, 22);
    IRNegStoreMakeX25519PublicShape(raw + kIROffStateInitiatorAgreement);
    IRNegStoreFillPattern(raw + kIROffStateResponderSigning, kIRLenEd25519Public, 33);
    IRNegStoreFillPattern(raw + kIROffStateResponderAgreement, kIRLenX25519Public, 44);
    IRNegStoreMakeX25519PublicShape(raw + kIROffStateResponderAgreement);

    IRNegStoreFillPattern(raw + kIROffStateHandshakeId, kIRLenHandshakeId, 55);
    IRNegStoreFillPattern(raw + kIROffStateRK, kIRLenRootKey, 66);

    IRNegStoreFillPattern(raw + kIROffStateDHsPriv, kIRLenX25519Private, 77);
    IRNegStoreMakeClampedShape(raw + kIROffStateDHsPriv);

    IRNegStoreFillPattern(raw + kIROffStateDHsPub, kIRLenX25519Public, 88);
    IRNegStoreMakeX25519PublicShape(raw + kIROffStateDHsPub);

    raw[kIROffStateDHrPresent] = 0x01;
    IRNegStoreFillPattern(raw + kIROffStateDHrPub, kIRLenX25519Public, 99);
    IRNegStoreMakeX25519PublicShape(raw + kIROffStateDHrPub);

    raw[kIROffStateCKsPresent] = 0x01;
    IRNegStoreFillPattern(raw + kIROffStateCKs, kIRLenChainKey, 110);

    raw[kIROffStateCKrPresent] = 0x01;
    IRNegStoreFillPattern(raw + kIROffStateCKr, kIRLenChainKey, 121);

    /* Ns = 7, Nr = 9, PN = 3 — three DIFFERENT values at three adjacent uint32 slots, so a port
       that transposes two of them diverges. send_counter = 0x0102030405060708 (§12.5). */
    raw[kIROffStateNs + 3] = 0x07;
    raw[kIROffStateNr + 3] = 0x09;
    raw[kIROffStatePN + 3] = 0x03;
    for (NSUInteger i = 0; i < 8; i++) {
        raw[kIROffStateSendCounter + i] = (uint8_t)(i + 1);
    }

    /* §12.1 — fixed-size optional fields are always present and zero-filled when absent. The
       prologue block stays 41 zero bytes under a clear flag. */
    raw[kIROffStateProloguePresent] = 0x00;

    /* skipped_count = 0. The four bytes are already zero; written out so the offset appears in the
       source at the place the field table puts it. */
    raw[kIROffStateSkippedCount + 0] = 0x00;
    raw[kIROffStateSkippedCount + 1] = 0x00;
    raw[kIROffStateSkippedCount + 2] = 0x00;
    raw[kIROffStateSkippedCount + 3] = 0x00;

    return blob;
}

/// The positive control: a blob this file did NOT break must parse, or every negative vector below
/// is asserting a rejection it would have got for free.
static void IRNegStoreAssertBlobParses(NSData *blob) {
    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:kNegStoreNowMs
                                                                    error:&error];
    IRVectorRequire(state != nil,
                    @"the UNMODIFIED §12.1 blob must parse, or the negative vectors built from it "
                    @"prove nothing: %@", error);

    /* §13.3 — the parsed state holds RK, DHs_priv, CKs and CKr. Nothing in this file needs them. */
    [state zeroize];
}

#pragma mark - Deterministic key construction

/**
 An X25519 pair derived from a fixed scalar through the REAL generator (§15.5 rule 5).

 A fresh IRScriptedRandomSource per pair, holding exactly the 32 bytes
 -generateX25519KeyPairWithError: draws. That source fails on exhaustion rather than cycling, so a
 generator that drew more than it scripted stops here instead of silently reusing bytes, and the
 §4.2 clamp is applied by the code under test rather than by this file.
 */
static IRX25519KeyPair *IRNegStoreX25519PairFromScalar(NSString *scalarHex) {
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
static IRIdentity *IRNegStoreIdentity(NSString *seedHex, NSString *scalarHex) {
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

/// The positive control for the bundle side. §10.3's gate then §5.3 rules 2–4; reads no clock.
static void IRNegStoreAssertBundleParses(NSData *bundle) {
    NSError *error = nil;
    IRPreKeyBundle *parsed = [IRPreKeyBundle bundleFromData:bundle
                                                   provider:IRVectorAmbientProvider()
                                                      error:&error];
    IRVectorRequire(parsed != nil,
                    @"the UNMODIFIED §5.4 bundle must parse, or the negative vectors built from it "
                    @"prove nothing: %@", error);
}

#pragma mark - Byte surgery helpers

static void IRNegStoreWriteUInt16BE(uint8_t *at, uint16_t value) {
    at[0] = (uint8_t)((value >> 8) & 0xFF);
    at[1] = (uint8_t)(value & 0xFF);
}

static void IRNegStoreWriteUInt32BE(uint8_t *at, uint32_t value) {
    at[0] = (uint8_t)((value >> 24) & 0xFF);
    at[1] = (uint8_t)((value >> 16) & 0xFF);
    at[2] = (uint8_t)((value >>  8) & 0xFF);
    at[3] = (uint8_t)(value & 0xFF);
}

static uint16_t IRNegStoreReadUInt16BE(const uint8_t *at) {
    return (uint16_t)(((uint16_t)at[0] << 8) | (uint16_t)at[1]);
}

static uint32_t IRNegStoreReadUInt32BE(const uint8_t *at) {
    return ((uint32_t)at[0] << 24) | ((uint32_t)at[1] << 16) |
           ((uint32_t)at[2] <<  8) | ((uint32_t)at[3]);
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForNegativeStore(void) {
    NSError *error = nil;

    NSMutableArray<NSDictionary *> *vectors = [NSMutableArray array];

    // ================================ §12.2 — state blobs ================================= //

    NSData *validBlob = IRNegStoreValidStateBlob();
    IRVectorRequire(validBlob.length == (NSUInteger)kIRLenStatePrefix,
                    @"the §12.1 fixed prefix is 472 bytes, built %lu",
                    (unsigned long)validBlob.length);
    IRNegStoreAssertBlobParses(validBlob);

    NSString *nowMsString = IRVectorUInt64String(kNegStoreNowMs);

    #pragma mark NEG-STATE-TRAILING

    /* §12.2 rule 6 — `len(blob) == 472 + 76 * skipped_count` EXACTLY. This is the ONLY rule in the
       whole of §12.2 that is not ERR_STATE_CORRUPT, and after §19.4 it is the only place in the
       entire protocol that produces 7105 at all: every bundle length failure, in either direction,
       became ERR_BUNDLE_MALFORMED so that this code means exactly one thing. */
    NSMutableData *trailingBlob = [validBlob mutableCopy];
    [trailingBlob appendBytes:(const uint8_t[]){0x00} length:1];

    [vectors addObject:@{
        @"id"          : @"NEG-STATE-TRAILING",
        @"kind"        : @"state",
        @"description" : @"A valid 472-byte state blob with skipped_count 0 and one extra trailing "
                         @"byte. Rules 1-5 all pass; rule 6's exact-length identity is the only "
                         @"thing wrong, and it is the sole producer of ERR_TRAILING_BYTES in the "
                         @"protocol after 19.4 moved every bundle length failure to "
                         @"ERR_BUNDLE_MALFORMED.",
        @"expect"      : @"error",
        @"error"       : @"ERR_TRAILING_BYTES",
        @"inputs"      : @{
            @"entry_point" : @"parse_state",
            @"state_blob"  : IRVectorHex(trailingBlob),
            @"now_ms"      : nowMsString,
        },
        @"intermediates" : @{
            @"blob_len"               : @(trailingBlob.length),
            @"declared_skipped_count" : @0,
            @"expected_len"           : @(kIRLenStatePrefix),
        },
    }];

    #pragma mark NEG-STATE-COUNT

    /* §12.2 rule 5 — `skipped_count <= 2000`, ERR_STATE_CORRUPT.

       THIS BLOB IS WRONG IN TWO WAYS AND THAT IS THE POINT. 2001 is over the cap AND the 472-byte
       length no longer satisfies rule 6's identity. Only an input wrong in both ways distinguishes
       rule 5 running before rule 6: a port that evaluated the length identity first returns
       ERR_TRAILING_BYTES and fails this vector. The cap must be checked first for a second reason —
       it is what bounds the `76 * skipped_count` multiplication rule 6 performs. */
    NSMutableData *countBlob = [validBlob mutableCopy];
    IRNegStoreWriteUInt32BE((uint8_t *)countBlob.mutableBytes + kIROffStateSkippedCount,
                            (uint32_t)(kIRMaxSkippedStored + 1));

    [vectors addObject:@{
        @"id"          : @"NEG-STATE-COUNT",
        @"kind"        : @"state",
        @"description" : @"skipped_count = 2001, one past MAX_SKIPPED_STORED, in a blob whose "
                         @"length is still 472. Wrong in two ways deliberately: rule 5's cap and "
                         @"rule 6's exact length both fail, so the vector arbitrates their order. A "
                         @"port that evaluates the length identity first answers "
                         @"ERR_TRAILING_BYTES. The cap also bounds the multiplication rule 6 "
                         @"performs.",
        @"expect"      : @"error",
        @"error"       : @"ERR_STATE_CORRUPT",
        @"inputs"      : @{
            @"entry_point" : @"parse_state",
            @"state_blob"  : IRVectorHex(countBlob),
            @"now_ms"      : nowMsString,
        },
        @"intermediates" : @{
            @"blob_len"               : @(countBlob.length),
            @"declared_skipped_count" : @(kIRMaxSkippedStored + 1),
        },
    }];

    #pragma mark NEG-STATE-UNCLAMPED-LOW / NEG-STATE-UNCLAMPED-HIGH

    /* §12.2 rule 8 / §19.5 — `DHs_priv` MUST be in §4.2 clamped form:
       `(blob[243] & 0x07) == 0` AND `(blob[274] & 0xC0) == 0x40`, else ERR_STATE_CORRUPT.

       REJECT, NEVER RE-CLAMP. §19.5 records the rejected alternative and why: silent re-clamping is
       functionally equivalent, since RFC 7748 §5 clamps internally and `X25519(s, P) ==
       X25519(clamp(s), P)`, but it lets a non-conformant writer's blobs circulate undetected and it
       breaks the exact-bytes property that makes §12.1 testable at all.

       THE TRAP THESE TWO VECTORS CATCH IS SPECIFIC AND IS INVISIBLE TO A ROUND-TRIP TEST. Every
       port's X25519 private type clamps at construction, so a rule-8 check placed AFTER that
       constructor accepts every unclamped blob and still passes its own parse-then-reserialize test,
       because the re-clamped bytes are exactly what a conformant writer would have produced. Only a
       check on the raw bytes, before construction, sees the difference. */
    NSMutableData *unclampedLow = [validBlob mutableCopy];
    uint8_t *unclampedLowRaw = (uint8_t *)unclampedLow.mutableBytes;
    unclampedLowRaw[kIROffStateDHsPrivFirstByte] |= 0x01;

    [vectors addObject:@{
        @"id"          : @"NEG-STATE-UNCLAMPED-LOW",
        @"kind"        : @"state",
        @"description" : @"DHs_priv is not in clamped form: bit 0 of blob[243] is set, so "
                         @"(blob[243] & 0x07) != 0. Rule 8 rejects rather than re-clamping (19.5). "
                         @"A port that checks clamping after constructing its X25519 private type "
                         @"accepts this blob and still passes its own round-trip, because that "
                         @"constructor clamps.",
        @"expect"      : @"error",
        @"error"       : @"ERR_STATE_CORRUPT",
        @"inputs"      : @{
            @"entry_point" : @"parse_state",
            @"state_blob"  : IRVectorHex(unclampedLow),
            @"now_ms"      : nowMsString,
        },
        @"intermediates" : @{
            @"blob_len"               : @(unclampedLow.length),
            @"declared_skipped_count" : @0,
            @"DHs_priv_first_byte"    : @(unclampedLowRaw[kIROffStateDHsPrivFirstByte]),
        },
    }];

    NSMutableData *unclampedHigh = [validBlob mutableCopy];
    uint8_t *unclampedHighRaw = (uint8_t *)unclampedHigh.mutableBytes;
    unclampedHighRaw[kIROffStateDHsPrivLastByte] &= (uint8_t)~0x40;

    [vectors addObject:@{
        @"id"          : @"NEG-STATE-UNCLAMPED-HIGH",
        @"kind"        : @"state",
        @"description" : @"DHs_priv is not in clamped form in the OTHER bit position: bit 6 of "
                         @"blob[274] is clear, so (blob[274] & 0xC0) is 0x00 rather than 0x40. The "
                         @"two halves of the clamp are separate predicates and 15.4 requires a "
                         @"vector for each; a port testing only the low bits passes the LOW vector "
                         @"and fails here.",
        @"expect"      : @"error",
        @"error"       : @"ERR_STATE_CORRUPT",
        @"inputs"      : @{
            @"entry_point" : @"parse_state",
            @"state_blob"  : IRVectorHex(unclampedHigh),
            @"now_ms"      : nowMsString,
        },
        @"intermediates" : @{
            @"blob_len"               : @(unclampedHigh.length),
            @"declared_skipped_count" : @0,
            @"DHs_priv_last_byte"     : @(unclampedHighRaw[kIROffStateDHsPrivLastByte]),
        },
    }];

    // =============================== §10.3 — prekey bundles ============================== //

    IRIdentity *responder = IRNegStoreIdentity(kNegStoreResponderEd25519Seed,
                                               kNegStoreResponderX25519Scalar);
    IRX25519KeyPair *signedPreKey = IRNegStoreX25519PairFromScalar(kNegStoreSignedPreKeyScalar);
    IRX25519KeyPair *oneTimePreKey = IRNegStoreX25519PairFromScalar(kNegStoreOneTimePreKeyScalar);

    /* §5.2 — SPK_SIG over the 130-byte SPK_SIGN_MSG under IK^s. Ed25519 is deterministic
       (RFC 8032 §5.1.6), so this is reproducible across runs and across platforms. */
    NSData *spkSignMessage = IRSPKSignMessage(responder.identityKeyPair,
                                              kNegStoreSpkId,
                                              signedPreKey.publicKey,
                                              kNegStoreNotBeforeS,
                                              kNegStoreNotAfterS,
                                              &error);
    IRVectorRequire(spkSignMessage != nil, @"SPK_SIGN_MSG: %@", error);

    IREd25519Signature *spkSignature = [responder signData:spkSignMessage error:&error];
    IRVectorRequire(spkSignature != nil, @"SPK_SIG: %@", error);

    NSData *validBundle0 = [IRPreKeyBundle serializeWithIdentity:responder.publicIdentity
                                                           spkId:kNegStoreSpkId
                                                    signedPreKey:signedPreKey.publicKey
                                                      notBeforeS:kNegStoreNotBeforeS
                                                       notAfterS:kNegStoreNotAfterS
                                           signedPreKeySignature:spkSignature
                                                      opkEntries:@[]
                                                           error:&error];
    IRVectorRequire(validBundle0 != nil, @"bundle, opk_count 0: %@", error);
    IRVectorRequire(validBundle0.length == (NSUInteger)kIRLenBundlePrefix,
                    @"the §5.4 fixed prefix is 251 bytes, built %lu",
                    (unsigned long)validBundle0.length);
    IRNegStoreAssertBundleParses(validBundle0);

    IRPreKeyBundleOPKEntry *opkEntry =
        [IRPreKeyBundleOPKEntry entryWithOpkId:kNegStoreOpkId
                                     publicKey:oneTimePreKey.publicKey
                                         error:&error];
    IRVectorRequire(opkEntry != nil, @"OPK entry: %@", error);

    NSData *validBundle1 = [IRPreKeyBundle serializeWithIdentity:responder.publicIdentity
                                                           spkId:kNegStoreSpkId
                                                    signedPreKey:signedPreKey.publicKey
                                                      notBeforeS:kNegStoreNotBeforeS
                                                       notAfterS:kNegStoreNotAfterS
                                           signedPreKeySignature:spkSignature
                                                      opkEntries:@[opkEntry]
                                                           error:&error];
    IRVectorRequire(validBundle1 != nil, @"bundle, opk_count 1: %@", error);
    IRVectorRequire(validBundle1.length ==
                        (NSUInteger)(kIRLenBundlePrefix + kIRLenBundleOPKEntry),
                    @"251 + 36 * 1 is 287 (§5.4), got %lu", (unsigned long)validBundle1.length);
    IRNegStoreAssertBundleParses(validBundle1);

    #pragma mark NEG-BUNDLE-EMPTY

    /* §10.3 step 1 — the length floor, ERR_BUNDLE_MALFORMED.

       §13.4 CLAUSE 6: THIS IS THE CONTENT CASE. A zero-length byte string that EXISTS is a value a
       vector can express and a parser must reject with a code. A NULL REFERENCE is a caller contract
       violation with no code and a mandatory fail-fast, is deliberately covered by no vector, and is
       uncompilable in Swift. §13.4 clause 6 names this row as one of the three that pin the adjacent
       legal case so the two are never conflated. */
    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-EMPTY",
        @"kind"        : @"wire",
        @"description" : @"A zero-length bundle. With NEG-BUNDLE-SHORT this is one of only two "
                         @"inputs in the entire corpus that exercise 10.3 step 1's length floor; "
                         @"every longer input has readable bytes at offset 249. This is the CONTENT "
                         @"case of 13.4 clause 6 - an empty byte string that exists, not a null "
                         @"reference, which has no error code and traps.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : @"",
        },
        @"intermediates" : @{
            @"bundle_len" : @0,
        },
    }];

    #pragma mark NEG-BUNDLE-SHORT

    /* 250 bytes: the EXACT boundary, one below the fixed prefix, so the two bytes of `opk_count` at
       offset 249 straddle the end of the buffer. §10.3 spells out the three divergent failures a
       missing floor produces here, one per port, for the same bytes. */
    NSData *shortBundle = [validBundle0 subdataWithRange:NSMakeRange(0, (NSUInteger)kIRLenBundlePrefix - 1)];

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-SHORT",
        @"kind"        : @"wire",
        @"description" : @"A 250-byte bundle: the exact boundary, one byte below the 251-byte fixed "
                         @"prefix, so opk_count at offset 249 is unreadable. Step 1 must precede "
                         @"step 4 because both structural rules are predicates over opk_count. "
                         @"Without the floor: Objective-C reads adjacent heap and may copy 36 * "
                         @"opk_count bytes from offset 251, Swift Data slice subscripting traps, "
                         @"and the JVM throws an unchecked IndexOutOfBoundsException that escapes "
                         @"the ERR_BUNDLE_MALFORMED contract.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(shortBundle),
        },
        @"intermediates" : @{
            @"bundle_len" : @(shortBundle.length),
        },
    }];

    #pragma mark NEG-BUNDLE-MAGIC

    /* §10.3 step 2 — `bundle[0..4) == "NTB4"`, ERR_BUNDLE_MALFORMED. §5.4 declared the magic a
       MUST-equal but no section assigned it an error code or a position in any order until §10.3.

       THE WRONG MAGIC IS THE STATE BLOB'S. "NTS4" is the likeliest real defect at this offset — a
       port that pasted the wrong four-byte constant — and it is far more informative than four
       arbitrary bytes, because a parser that accepted it would be one that never compared at all. */
    NSMutableData *magicBundle = [validBundle0 mutableCopy];
    memcpy((uint8_t *)magicBundle.mutableBytes + kIROffBundleMagic,
           kIRStateMagic, (size_t)kIRLenMagic);

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-MAGIC",
        @"kind"        : @"wire",
        @"description" : @"A 251-byte bundle whose first four bytes are NTS4, the STATE blob magic, "
                         @"rather than NTB4. Everything else in the bundle is conformant, including "
                         @"both signatures, so step 2 is the only thing that can reject it - and a "
                         @"port that pasted the wrong four-byte constant is the defect this "
                         @"particular wrong value models.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(magicBundle),
        },
        @"intermediates" : @{
            @"bundle_len"         : @(magicBundle.length),
            @"declared_opk_count" : @0,
        },
    }];

    #pragma mark NEG-BUNDLE-VERSION

    /* §10.3 step 3 — `bundle[4] == 0x04`, ERR_UNSUPPORTED_VERSION.

       THE ONE BUNDLE-STRUCTURE VECTOR THAT IS NOT ERR_BUNDLE_MALFORMED, and §15.4 says so in as many
       words. Version is a distinguishable condition with its own code and §10.3 assigns it
       deliberately. 0x03 is the v3 bundle version, which §10.6 and §17.9 make a permanent
       rejection: there is no downgrade path and no dual-stack mode. */
    NSMutableData *versionBundle = [validBundle0 mutableCopy];
    ((uint8_t *)versionBundle.mutableBytes)[kIROffBundleVersion] = 0x03;

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-VERSION",
        @"kind"        : @"wire",
        @"description" : @"A well-formed 251-byte bundle with bundle[4] == 0x03. This is the ONE "
                         @"bundle-structure vector that is not ERR_BUNDLE_MALFORMED: 10.3 step 3 "
                         @"gives a wrong version its own distinguishable code. 0x03 is the v3 "
                         @"bundle version, and 10.6 and 17.9 make that rejection permanent - there "
                         @"is no downgrade path.",
        @"expect"      : @"error",
        @"error"       : @"ERR_UNSUPPORTED_VERSION",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(versionBundle),
        },
        @"intermediates" : @{
            @"bundle_len"         : @(versionBundle.length),
            @"declared_opk_count" : @0,
            @"version_byte"       : @3,
        },
    }];

    #pragma mark NEG-BUNDLE-OPKCOUNT

    /* §10.3 step 4 — `opk_count <= 1000`, ERR_BUNDLE_MALFORMED.

       THE LENGTH IS CONSISTENT WITH THE DECLARED COUNT, AND §15.4 REQUIRES THAT. 251 + 36 * 1001 =
       36287 bytes. If the length disagreed, a port that omitted step 4 entirely would still reject
       at step 5 with the same code and the vector would arbitrate nothing; making the length agree
       is what leaves the cap as the unique failure.

       The 1001 appended entries are deterministic filler rather than real key pairs: §5.3 rule 2's
       public-key validation never runs, because the §10.3 gate rejects first and returns on the
       first failure. Their high bit is cleared anyway, so nothing here depends on a key that would
       fail §4.4 for a second, unintended reason. */
    const uint32_t kOverCount = (uint32_t)kIRMaxBundleOPKCount + 1;

    NSMutableData *opkCountBundle = [validBundle0 mutableCopy];
    for (uint32_t i = 0; i < kOverCount; i++) {
        uint8_t entry[kIRLenBundleOPKEntry];
        IRNegStoreWriteUInt32BE(entry + kIROffBundleOPKEntryId, i + 1);
        IRNegStoreFillPattern(entry + kIROffBundleOPKEntryKey, kIRLenX25519Public,
                              (uint8_t)(i & 0xFF));
        IRNegStoreMakeX25519PublicShape(entry + kIROffBundleOPKEntryKey);
        [opkCountBundle appendBytes:entry length:sizeof(entry)];
    }
    IRNegStoreWriteUInt16BE((uint8_t *)opkCountBundle.mutableBytes + kIROffBundleOPKCount,
                            (uint16_t)kOverCount);
    IRVectorRequire(opkCountBundle.length ==
                        (NSUInteger)kIRLenBundlePrefix +
                            ((NSUInteger)kIRLenBundleOPKEntry * (NSUInteger)kOverCount),
                    @"NEG-BUNDLE-OPKCOUNT must satisfy the length identity it violates the cap "
                    @"with, got %lu", (unsigned long)opkCountBundle.length);

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-OPKCOUNT",
        @"kind"        : @"wire",
        @"description" : @"opk_count = 1001, one past MAX_BUNDLE_OPK_COUNT, with a total length of "
                         @"36287 bytes that is exactly consistent with it. The consistency is "
                         @"required by 15.4: with a disagreeing length, a port that omitted step "
                         @"4's cap would still reject at step 5 with the same code and the vector "
                         @"would arbitrate nothing.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(opkCountBundle),
        },
        @"intermediates" : @{
            @"bundle_len"         : @(opkCountBundle.length),
            @"declared_opk_count" : @(kOverCount),
        },
    }];

    #pragma mark NEG-BUNDLE-LEN-LONG / NEG-BUNDLE-LEN-SHORT

    /* §10.3 step 5 — `len(bundle) == 251 + 36 * opk_count` EXACTLY, ERR_BUNDLE_MALFORMED IN BOTH
       DIRECTIONS.

       §15.4 requires both, and §15.4's closing note says why the pair is not redundant: "the
       over-long direction that a test author writes naturally exercises the safe side". Appending a
       byte leaves every declared field readable; REMOVING one from a bundle that declares an entry
       makes the parser's own arithmetic point past the end of the buffer, which is the direction
       that catches a port trusting `opk_count` to size a copy.

       NEITHER IS ERR_TRAILING_BYTES. §19.4 decided it: 7105 is state-blob-only, and splitting bundle
       parsing across two codes would fragment it for no diagnostic gain. A port that reasoned by
       analogy from §12.2 rule 6 answers 7105 here and fails both vectors. */
    NSMutableData *lenLongBundle = [validBundle0 mutableCopy];
    [lenLongBundle appendBytes:(const uint8_t[]){0x00} length:1];

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-LEN-LONG",
        @"kind"        : @"wire",
        @"description" : @"opk_count 0 with 252 bytes - one byte too long for the 251 + 36 * 0 "
                         @"identity of step 5. This is the direction a test author writes "
                         @"naturally, and it is the SAFE side: every declared field is still "
                         @"readable. ERR_BUNDLE_MALFORMED and never ERR_TRAILING_BYTES, per 19.4.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(lenLongBundle),
        },
        @"intermediates" : @{
            @"bundle_len"         : @(lenLongBundle.length),
            @"declared_opk_count" : @0,
            @"expected_len"       : @(kIRLenBundlePrefix),
        },
    }];

    NSData *lenShortBundle =
        [validBundle1 subdataWithRange:NSMakeRange(0, validBundle1.length - 1)];

    [vectors addObject:@{
        @"id"          : @"NEG-BUNDLE-LEN-SHORT",
        @"kind"        : @"wire",
        @"description" : @"opk_count 1 with 286 bytes - one byte SHORT of the 287 the identity "
                         @"requires. This is the dangerous direction: opk_count at offset 249 is "
                         @"readable and declares an entry the buffer does not contain, so a port "
                         @"that sizes a copy from it reads past the end. 15.4 requires both "
                         @"directions for exactly this reason.",
        @"expect"      : @"error",
        @"error"       : @"ERR_BUNDLE_MALFORMED",
        @"inputs"      : @{
            @"entry_point" : @"parse_bundle",
            @"bundle"      : IRVectorHex(lenShortBundle),
        },
        @"intermediates" : @{
            @"bundle_len"         : @(lenShortBundle.length),
            @"declared_opk_count" : @1,
            @"expected_len"       : @(kIRLenBundlePrefix + kIRLenBundleOPKEntry),
        },
    }];

    return vectors;
}

#pragma mark - Executor

/**
 THERE IS NO NIL GUARD IN THIS MODULE, AND ITS ABSENCE IS THE §13.4 POINT.

 Sibling executors construct nominal key types out of a vector's hex and must guard each result,
 because a nil handed on to a `_Nonnull` parameter traps through IRRequireArgument — a caller
 contract violation, not an error code, and one that would abort the whole test binary instead of
 naming the malformed vector. Nothing here does that: both executors hand the RAW BYTES straight to
 the decoder under test, which is exactly what these vectors are for. §13.4 clause 6 draws the same
 line from the other side — `NEG-BUNDLE-EMPTY` is the CONTENT case, a zero-length byte string that
 exists and has a code, never a null reference, which has neither.
 */

/**
 §15.5 rule 2 for a NEGATIVE vector, where the parse produced nothing to read fields out of.

 The intermediates in this file are structural facts about the INPUT BYTES — the two operands of an
 exact-length identity, the byte a clamp predicate reads — not values recovered from a parsed object,
 because on these inputs there is no parsed object. They still localise a bug: a port that reads
 `skipped_count` at the wrong offset, or `opk_count` at anything other than 249, diverges HERE with
 the offending number in the failure message, instead of merely returning some other error code and
 leaving the reader to guess which of §12.2's nine rules or §10.3's five steps misfired.

 A key this port cannot derive is reported as a skip rather than silently dropped, which is the half
 of rule 2 that is easy to miss.
 */
static void IRNegStoreCheckDerivedIntermediates(IRVectorCase *vectorCase,
                                                NSDictionary<NSString *, NSNumber *> *derived) {
    for (NSString *key in vectorCase.intermediates) {
        NSNumber *value = derived[key];

        if (value != nil) {
            [vectorCase checkIntermediate:key number:value];
        } else {
            [vectorCase skipIntermediate:key
                                 because:@"this runner derives no such structural fact from the "
                                         @"input bytes"];
        }
    }
}

#pragma mark NEG-STATE-*

static void IRNegStoreRunStateVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    /* Every input is read FIRST, so §15.5 rule 3's consumption bookkeeping is complete even on a
       path that then bails out. */
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *blob = [vectorCase dataInput:@"state_blob"];
    uint64_t nowMs = [vectorCase uint64Input:@"now_ms"];

    if (![entryPoint isEqualToString:@"parse_state"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"parse_state\"",
                              vectorCase.identifier, entryPoint);
    }

    /* The two operands of §12.2 rule 6's identity, read at the offsets the §12.1 field table names.
       `skipped_count` is only readable once rule 1's floor has passed, so a blob below 472 bytes
       contributes the length alone — the same discipline §10.3 imposes on the bundle. */
    NSMutableDictionary<NSString *, NSNumber *> *derived = [NSMutableDictionary dictionary];
    derived[@"blob_len"] = @(blob.length);

    const uint8_t *raw = (const uint8_t *)blob.bytes;

    if (blob.length >= (NSUInteger)kIRLenStatePrefix) {
        uint32_t skippedCount = IRNegStoreReadUInt32BE(raw + kIROffStateSkippedCount);
        derived[@"declared_skipped_count"] = @(skippedCount);
        derived[@"DHs_priv_first_byte"] = @(raw[kIROffStateDHsPrivFirstByte]);
        derived[@"DHs_priv_last_byte"] = @(raw[kIROffStateDHsPrivLastByte]);

        if (skippedCount <= (uint32_t)kIRMaxSkippedStored) {
            derived[@"expected_len"] =
                @((NSUInteger)kIRLenStatePrefix +
                  ((NSUInteger)kIRLenStateSkippedEntry * (NSUInteger)skippedCount));
        }
    }

    IRNegStoreCheckDerivedIntermediates(vectorCase, derived);

    /* §12.2's nine rules, in order. `nowMs` is the §15.5 rule 6 injected time source and is the ONLY
       clock this path may consult; the driver's ten-years-forward run is what proves it. */
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:nowMs
                                                                    error:&error];

    /* §12.2 — "A failure at any step MUST yield no partially-loaded state." A port that returned a
       state AND an error, or a state on an expect:"error" vector, is the failure mode this asserts;
       -checkResultError: alone would not see the first of those. */
    if (state != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §12.2 requires NO partially-loaded state on a failure, and "
                              @"this vector expects %@ — but a state was returned",
                              vectorCase.identifier, vectorCase.expectedErrorName);
        [state zeroize];
    }

    [vectorCase checkResultError:error];
    [vectorCase finish];
}

#pragma mark NEG-BUNDLE-*

static void IRNegStoreRunBundleVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *bundleBytes = [vectorCase dataInput:@"bundle"];

    if (![entryPoint isEqualToString:@"parse_bundle"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"parse_bundle\"",
                              vectorCase.identifier, entryPoint);
    }

    /* THE FLOOR IS EVALUATED HERE TOO, AND IN THE SAME ORDER. `opk_count` lives at fixed offset 249,
       so it is derived only when the buffer is at least 251 bytes long — which is precisely why
       NEG-BUNDLE-EMPTY and NEG-BUNDLE-SHORT carry `bundle_len` and nothing else. A runner that read
       offset 249 unconditionally would commit the very out-of-bounds read §10.3 step 1 exists to
       prevent, inside the test that is supposed to be checking for it. */
    NSMutableDictionary<NSString *, NSNumber *> *derived = [NSMutableDictionary dictionary];
    derived[@"bundle_len"] = @(bundleBytes.length);

    if (bundleBytes.length >= (NSUInteger)kIRLenBundlePrefix) {
        const uint8_t *raw = (const uint8_t *)bundleBytes.bytes;
        uint16_t opkCount = IRNegStoreReadUInt16BE(raw + kIROffBundleOPKCount);

        derived[@"declared_opk_count"] = @(opkCount);
        derived[@"version_byte"] = @(raw[kIROffBundleVersion]);

        if (opkCount <= (uint16_t)kIRMaxBundleOPKCount) {
            derived[@"expected_len"] =
                @((NSUInteger)kIRLenBundlePrefix +
                  ((NSUInteger)kIRLenBundleOPKEntry * (NSUInteger)opkCount));
        }
    }

    IRNegStoreCheckDerivedIntermediates(vectorCase, derived);

    /* §10.3's ordered gate, then §5.3 rules 2–4. READS NO CLOCK: §5.3 rules 5–6 live in
       -validateValidityWindowAtUnixSeconds:error:, which nothing here calls — none of these inputs
       survives the gate — so the AMBIENT environment is correct, and the driver's ten-years-forward
       run is what proves the claim rather than this comment. */
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleBytes
                                                   provider:provider
                                                      error:&error];

    if (bundle != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] the §10.3 gate ACCEPTED a bundle this vector expects it to "
                              @"reject with %@; %lu bytes were parsed into %lu OPK entries",
                              vectorCase.identifier, vectorCase.expectedErrorName,
                              (unsigned long)bundleBytes.length,
                              (unsigned long)bundle.opkEntries.count);
    }

    [vectorCase checkResultError:error];
    [vectorCase finish];
}

#pragma mark - Dispatch

/**
 `entry_point` selects the API; `kind` classifies the vector. The mapping is MANY-TO-ONE, and
 asserting it is one-to-one is a bug this assertion previously contained.

 §15.5 makes `entry_point` authoritative, so a runner can never be sent to the wrong parser. `kind`
 says what the vector is ABOUT, and more than one kind can legitimately reach the same parser:
 `parse_bundle` is reached both by §10.3's structural rejections, which are `kind: "wire"` because a
 §5.4 prekey bundle IS a wire structure, and by NEG-SPKSIG-BAD / NEG-SPK-EXPIRED /
 NEG-SPK-WINDOW-TOO-LONG, which are `kind: "x3dh"` because what they exercise is §5.3's signature
 and validity-window rules with an identity and a prekey store behind them. Both genuinely call
 -[IRPreKeyBundle bundleFromData:provider:error:].

 So this checks MEMBERSHIP in the permitted set, not equality against one value. The earlier
 equality form encoded `parse_bundle` -> `wire` and was false for those three vectors; it never
 fired only because the driver filters on `kind` before dispatching here. A port following §15.5's
 "switch on entry_point" literally, and adding the analogous sanity check, would have failed three
 vectors for no defect — which is the whole class of problem the corpus exists to prevent.
 */
static void IRNegStoreAssertKind(XCTestCase *testCase,
                                 IRVectorCase *vectorCase,
                                 NSArray<NSString *> *permittedKinds,
                                 NSString *entryPoint) {
    if (![permittedKinds containsObject:vectorCase.kind]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] entry_point \"%@\" permits kind %@, but the vector is "
                              @"kind \"%@\"",
                              vectorCase.identifier, entryPoint,
                              [permittedKinds componentsJoinedByString:@" or "], vectorCase.kind);
    }
}

void IRRunNegativeStoreVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    /* TWO KINDS, ONE MODULE. §12.2's state rows are `kind: "state"`; §10.3's bundle rows are
       `kind: "wire"`, because that is what a §5.4 prekey bundle IS — the module that happens to
       emit a vector does not decide its classification. The driver routes both here on
       `inputs.entry_point`, which §15.5 makes authoritative inside negative.json. */
    if (![vectorCase.kind isEqualToString:@"state"] && ![vectorCase.kind isEqualToString:@"wire"]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] kind is \"%@\"; this module carries only \"state\" (§12.2 blob "
                              @"rejections) and \"wire\" (§10.3 bundle rejections)",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    if (!vectorCase.expectsError) {
        IRVectorRecordFailure(testCase,
                              @"[%@] every §15.4 row is expect:\"error\"; this one is \"ok\"",
                              vectorCase.identifier);
        return;
    }

    /* DISPATCH IS ON `entry_point`, NOT ON THE ID AND NOT ON `kind`. §15.5 makes `entry_point` the
       reserved key that names which API was invoked, states outright that it is AUTHORITATIVE
       inside negative.json, and it is the only field in the envelope that says whether these bytes
       are a §12.1 blob or a §5.4 bundle. Keying off the id prefix would work here and would be
       wrong in the other three ports, which have to read the same file. */
    id rawEntryPoint = vectorCase.inputs[@"entry_point"];
    NSString *entryPoint =
        [rawEntryPoint isKindOfClass:[NSString class]] ? (NSString *)rawEntryPoint : nil;

    if ([entryPoint isEqualToString:@"parse_state"]) {
        IRNegStoreAssertKind(testCase, vectorCase, @[ @"state" ], entryPoint);
        IRNegStoreRunStateVector(testCase, vectorCase);
    } else if ([entryPoint isEqualToString:@"parse_bundle"]) {
        IRNegStoreAssertKind(testCase, vectorCase, @[ @"wire", @"x3dh" ], entryPoint);
        IRNegStoreRunBundleVector(testCase, vectorCase);
    } else {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is exactly
           what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase,
                              @"[%@] inputs.entry_point is %@; this module executes only "
                              @"parse_state and parse_bundle",
                              vectorCase.identifier,
                              entryPoint ? [NSString stringWithFormat:@"\"%@\"", entryPoint]
                                         : @"absent");
    }
}
