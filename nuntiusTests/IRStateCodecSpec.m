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

#import "IRErrors.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRProtocolConstants.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSkippedKeyStore.h"
#import "IRSodium.h"
#import "IRX3DH.h"

/**
 LAYER 8 GATE — SPEC §12.1, §12.2, §12.4, §13.3, §15.3, §15.4, §19.5.

 Named rows covered: NEG-STATE-TRAILING, NEG-STATE-COUNT, both NEG-STATE-UNCLAMPED variants, and
 the `state.json` positive shapes (`skipped_count` 0 and 3, both roles, prologue set and clear).

 EVERY BLOB HERE IS BUILT FROM LITERAL BYTES, never by executing a ratchet and serializing the
 result. §15.3 is explicit that this is the only reproducible form: a runner that reached the state
 by ratcheting would write its own `now_ms()` into the `inserted_at_ms` fields, and a runner loading
 such a blob more than seven days later would re-emit a 472-byte `skipped_count = 0` blob under
 §12.2 rule 9 — a MUST, in two places, that silently destroys the vector. Every test that has
 skipped entries therefore supplies an explicit `now_ms` placing them inside `SKIPPED_TTL_MS`.

 THE ORDERING TESTS ARE THE POINT. A round-trip proves the codec agrees with itself; only an input
 that is wrong in TWO ways distinguishes rule 5 running before rule 6, or rule 6 before rule 8. Each
 such test is named …Beats… and says which two rules it separates.
 */

#pragma mark - Literal blob construction

/// Deterministic filler. Distinct `seed` values give distinct regions, so a field read at the wrong
/// offset produces a visibly wrong value rather than a plausible one.
static void IRFillPattern(uint8_t *buffer, NSUInteger length, uint8_t seed) {
    for (NSUInteger i = 0; i < length; i++) {
        buffer[i] = (uint8_t)((seed * 31u) + (i * 7u) + 1u);
    }
}

/// §4.4 check 2 — an X25519 u-coordinate has bit 255 clear.
static void IRMakeX25519PublicShape(uint8_t *key) {
    key[31] &= 0x7F;
}

/// §4.2 — the clamped scalar form §12.2 rule 8 requires.
static void IRMakeClampedShape(uint8_t *scalar) {
    scalar[0] &= 0xF8;
    scalar[31] &= 0x7F;
    scalar[31] |= 0x40;
}

/**
 A structurally valid §12.1 blob, built byte by byte at the offsets in the field table.

 `baseMs` is the `inserted_at_ms` of the first skipped entry; later entries are 1000 ms apart, so a
 test can place the whole set inside or outside `SKIPPED_TTL_MS` with one number.
 */
static NSMutableData *IRStateBlob(uint8_t role,
                                  BOOL hasDHr,
                                  BOOL hasCKs,
                                  BOOL hasCKr,
                                  BOOL hasPrologue,
                                  uint32_t skippedCount,
                                  uint64_t baseMs) {
    NSUInteger total = (NSUInteger)kIRLenStatePrefix +
                       ((NSUInteger)kIRLenStateSkippedEntry * (NSUInteger)skippedCount);
    NSMutableData *blob = [NSMutableData dataWithLength:total];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    memcpy(raw + kIROffStateMagic, kIRStateMagic, (size_t)kIRLenMagic);
    raw[kIROffStateFormat] = (uint8_t)kIRStateFormat;
    raw[kIROffStateRole] = role;

    // SESSION_AD (§6.5), stored verbatim at offset 6.
    memcpy(raw + kIROffStateSessionAD, kIRLabelAD, (size_t)kIRLenLabelAD);
    IRFillPattern(raw + kIROffStateInitiatorSigning, kIRLenEd25519Public, 11);
    IRFillPattern(raw + kIROffStateInitiatorAgreement, kIRLenX25519Public, 22);
    IRMakeX25519PublicShape(raw + kIROffStateInitiatorAgreement);
    IRFillPattern(raw + kIROffStateResponderSigning, kIRLenEd25519Public, 33);
    IRFillPattern(raw + kIROffStateResponderAgreement, kIRLenX25519Public, 44);
    IRMakeX25519PublicShape(raw + kIROffStateResponderAgreement);

    IRFillPattern(raw + kIROffStateHandshakeId, kIRLenHandshakeId, 55);
    IRFillPattern(raw + kIROffStateRK, kIRLenRootKey, 66);

    IRFillPattern(raw + kIROffStateDHsPriv, kIRLenX25519Private, 77);
    IRMakeClampedShape(raw + kIROffStateDHsPriv);

    IRFillPattern(raw + kIROffStateDHsPub, kIRLenX25519Public, 88);
    IRMakeX25519PublicShape(raw + kIROffStateDHsPub);

    raw[kIROffStateDHrPresent] = hasDHr ? 0x01 : 0x00;
    if (hasDHr) {
        IRFillPattern(raw + kIROffStateDHrPub, kIRLenX25519Public, 99);
        IRMakeX25519PublicShape(raw + kIROffStateDHrPub);
    }

    raw[kIROffStateCKsPresent] = hasCKs ? 0x01 : 0x00;
    if (hasCKs) {
        IRFillPattern(raw + kIROffStateCKs, kIRLenChainKey, 110);
    }

    raw[kIROffStateCKrPresent] = hasCKr ? 0x01 : 0x00;
    if (hasCKr) {
        IRFillPattern(raw + kIROffStateCKr, kIRLenChainKey, 121);
    }

    // Ns = 0x00000007, Nr = 0x00000009, PN = 0x00000003, send_counter = 0x0102030405060708.
    raw[kIROffStateNs + 3] = 0x07;
    raw[kIROffStateNr + 3] = 0x09;
    raw[kIROffStatePN + 3] = 0x03;
    for (NSUInteger i = 0; i < 8; i++) {
        raw[kIROffStateSendCounter + i] = (uint8_t)(i + 1);
    }

    raw[kIROffStateProloguePresent] = hasPrologue ? 0x01 : 0x00;
    if (hasPrologue) {
        uint8_t *prologue = raw + kIROffStatePrologue;
        IRFillPattern(prologue + kIROffPrologueEK, kIRLenX25519Public, 132);
        IRMakeX25519PublicShape(prologue + kIROffPrologueEK);
        prologue[kIROffPrologueSPKId + 3] = 0x2A;          // spk_id = 42
        prologue[kIROffPrologueOPKFlag] = (uint8_t)IROPKFlagPresent;
        prologue[kIROffPrologueOPKId + 3] = 0x63;          // opk_id = 99
    }

    raw[kIROffStateSkippedCount + 0] = (uint8_t)((skippedCount >> 24) & 0xFF);
    raw[kIROffStateSkippedCount + 1] = (uint8_t)((skippedCount >> 16) & 0xFF);
    raw[kIROffStateSkippedCount + 2] = (uint8_t)((skippedCount >>  8) & 0xFF);
    raw[kIROffStateSkippedCount + 3] = (uint8_t)(skippedCount & 0xFF);

    for (uint32_t i = 0; i < skippedCount; i++) {
        uint8_t *entry = raw + kIROffStateSkippedEntries + (kIRLenStateSkippedEntry * i);

        IRFillPattern(entry + kIROffSkippedEntryDHPub, kIRLenX25519Public, (uint8_t)(140 + i));
        IRMakeX25519PublicShape(entry + kIROffSkippedEntryDHPub);

        entry[kIROffSkippedEntryN + 3] = (uint8_t)(i + 1);

        IRFillPattern(entry + kIROffSkippedEntryMK, kIRLenMessageKey, (uint8_t)(160 + i));

        uint64_t insertedAt = baseMs + ((uint64_t)i * 1000ull);
        for (NSUInteger b = 0; b < 8; b++) {
            entry[kIROffSkippedEntryInsertedAtMs + b] =
                (uint8_t)((insertedAt >> (8 * (7 - b))) & 0xFF);
        }
    }

    return blob;
}

/// A `now_ms` that places every entry of a blob built at `baseMs` comfortably inside the TTL.
static uint64_t IRNowInsideTTL(uint64_t baseMs) {
    return baseMs + 60000ull;
}

@interface IRStateCodecSpec : XCTestCase
@end

@implementation IRStateCodecSpec

- (void)setUp {
    [super setUp];

    NSError *error = nil;
    XCTAssertTrue([IRSodium ensureInitialized:&error], @"%@", error);
}

#pragma mark - Helpers

- (IRRatchetState *)parseBlob:(NSData *)blob atTimeMs:(uint64_t)nowMs {
    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:nowMs
                                                                    error:&error];
    XCTAssertNotNil(state, @"expected a parse, got %@", error);

    return state;
}

- (void)assertBlob:(NSData *)blob atTimeMs:(uint64_t)nowMs failsWith:(IRErrorCode)expected {
    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:nowMs
                                                                    error:&error];

    XCTAssertNil(state, @"expected no partially-loaded state");
    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.domain, IRErrorDomain);
    XCTAssertEqual((IRErrorCode)error.code, expected,
                   @"expected %@, got %@",
                   IRErrorNameForCode(expected), IRErrorNameForCode((IRErrorCode)error.code));
}

- (NSData *)reserialize:(IRRatchetState *)state {
    NSError *error = nil;
    IRSecretBytes *blob = [IRSessionStateCodec serializeState:state error:&error];
    XCTAssertNotNil(blob, @"%@", error);

    /* The one place a session's key material is deliberately copied into an unwipeable container.
       It is explicit here, at the call site, which is exactly why the codec has no NSData-returning
       serializer. */
    NSData *copy = [NSData dataWithBytes:blob.constBytes length:blob.length];
    [blob zeroizeNow];

    return copy;
}

#pragma mark - §18 — the constant itself

- (void)testStateFixedPrefixIsTheSumOfItsFieldTable {
    /* §12.2's implementer note: "derive 472 from the field table above and confirm it against the
       constant... an error in this constant would make every conformant implementation reject
       every other's blobs." */
    NSUInteger sum = 4 + 1 + 1 + 141 + 64 + 32 + 32 + 32 + 1 + 32 + 1 + 32 + 1 + 32 +
                     4 + 4 + 4 + 8 + 1 + 41 + 4;
    XCTAssertEqual(sum, (NSUInteger)kIRLenStatePrefix);
    XCTAssertEqual((NSUInteger)(32 + 4 + 32 + 8), (NSUInteger)kIRLenStateSkippedEntry);
    XCTAssertEqual((NSUInteger)(32 + 4 + 1 + 4), (NSUInteger)kIRLenStatePrologue);
}

- (void)testBlobLengthForSkippedCountMatchesTheFormulaAndRefusesOverTheBound {
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:0], (NSUInteger)472);
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:1], (NSUInteger)548);
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:3], (NSUInteger)700);
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:2000], (NSUInteger)152472);

    /* 0 rather than a wrapped product. Every caller checks it before allocating, which is what
       makes the multiplication unable to overflow. */
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:2001], (NSUInteger)0);
    XCTAssertEqual([IRSessionStateCodec blobLengthForSkippedCount:UINT32_MAX], (NSUInteger)0);
}

#pragma mark - §15.3 `state.json` positive shapes

- (void)testRoundTripInitiatorNoSkippedNoPrologue {
    NSData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    IRRatchetState *state = [self parseBlob:blob atTimeMs:1000];

    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testRoundTripInitiatorWithPrologue {
    NSData *blob = IRStateBlob(0x01, NO, YES, NO, YES, 0, 0);
    IRRatchetState *state = [self parseBlob:blob atTimeMs:1000];

    XCTAssertNotNil(state.prologue);
    XCTAssertEqual(state.prologue.spkId, (uint32_t)42);
    XCTAssertEqual(state.prologue.opkFlag, IROPKFlagPresent);
    XCTAssertEqual(state.prologue.opkId, (uint32_t)99);
    /* §11.3 — the prologue is present exactly while type 0x02 is still being sent, and an
       initiator that has not yet decrypted anything from B has no CKr. */
    XCTAssertTrue(state.shouldSendPreKeyMessage);

    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testRoundTripResponderNoSkipped {
    NSData *blob = IRStateBlob(0x02, YES, NO, YES, NO, 0, 0);
    IRRatchetState *state = [self parseBlob:blob atTimeMs:1000];

    XCTAssertEqual(state.role, IRSessionRoleResponder);
    XCTAssertNil(state.CKs);
    XCTAssertFalse(state.shouldSendPreKeyMessage);

    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testRoundTripWithThreeSkippedEntriesInsideTheTTL {
    const uint64_t base = 1700000000000ull;
    NSData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:IRNowInsideTTL(base)];
    XCTAssertEqual(state.skipped.count, (NSUInteger)3);

    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testEveryFieldLandsAtTheOffsetTheTableGivesIt {
    const uint64_t base = 1700000000000ull;
    NSData *blob = IRStateBlob(0x01, YES, YES, YES, YES, 3, base);
    const uint8_t *raw = (const uint8_t *)blob.bytes;

    IRRatchetState *state = [self parseBlob:blob atTimeMs:IRNowInsideTTL(base)];

    XCTAssertEqual(state.role, IRSessionRoleInitiator);
    XCTAssertEqual(state.Ns, (uint32_t)7);
    XCTAssertEqual(state.Nr, (uint32_t)9);
    XCTAssertEqual(state.PN, (uint32_t)3);
    XCTAssertEqual(state.sendCounter, (uint64_t)0x0102030405060708ull);

    XCTAssertEqualObjects(state.sessionAD.bytes,
                          [blob subdataWithRange:NSMakeRange(kIROffStateSessionAD, kIRLenSessionAD)]);
    XCTAssertEqualObjects(state.handshakeId,
                          [blob subdataWithRange:NSMakeRange(kIROffStateHandshakeId, kIRLenHandshakeId)]);

    XCTAssertEqual(memcmp(state.RK.constBytes, raw + kIROffStateRK, kIRLenRootKey), 0);
    XCTAssertEqual(memcmp(state.DHs.privateKey.constBytes,
                          raw + kIROffStateDHsPriv, kIRLenX25519Private), 0);
    XCTAssertEqual(memcmp(state.DHs.publicKey.constBytes,
                          raw + kIROffStateDHsPub, kIRLenX25519Public), 0);
    XCTAssertEqual(memcmp(state.DHr.constBytes, raw + kIROffStateDHrPub, kIRLenX25519Public), 0);
    XCTAssertEqual(memcmp(state.CKs.constBytes, raw + kIROffStateCKs, kIRLenChainKey), 0);
    XCTAssertEqual(memcmp(state.CKr.constBytes, raw + kIROffStateCKr, kIRLenChainKey), 0);

    /* §6.5's sub-offsets: the identity pairs are recoverable from the stored SESSION_AD alone,
       which is why §12.1 stores neither identity key anywhere else. */
    XCTAssertEqualObjects(state.sessionAD.initiatorIdentity.rawPair,
                          [blob subdataWithRange:NSMakeRange(kIROffStateInitiatorSigning,
                                                             kIRLenIdentityPair)]);
    XCTAssertEqualObjects(state.sessionAD.responderIdentity.rawPair,
                          [blob subdataWithRange:NSMakeRange(kIROffStateResponderSigning,
                                                             kIRLenIdentityPair)]);
}

- (void)testSkippedEntriesReserializeInInsertionOrder {
    const uint64_t base = 1700000000000ull;
    NSData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:IRNowInsideTTL(base)];
    NSArray<IRSkippedKeyEntry *> *entries = [state.skipped entriesInInsertionOrder];

    XCTAssertEqual(entries.count, (NSUInteger)3);
    XCTAssertEqual(entries[0].N, (uint32_t)1);
    XCTAssertEqual(entries[1].N, (uint32_t)2);
    XCTAssertEqual(entries[2].N, (uint32_t)3);
    XCTAssertEqual(entries[0].insertedAtMs, base);
    XCTAssertEqual(entries[1].insertedAtMs, base + 1000);
    XCTAssertEqual(entries[2].insertedAtMs, base + 2000);

    /* §12.1's serialization order IS §7.6's insertion order — one mechanism, so the two cannot
       drift. The round-trip is what proves it. */
    XCTAssertEqualObjects([self reserialize:state], blob);
}

#pragma mark - §12.2 rules 1–4

- (void)testRule1_ShorterThanTheFixedPrefixIsStateCorrupt {
    for (NSUInteger length = 0; length < (NSUInteger)kIRLenStatePrefix; length++) {
        NSData *blob = [IRStateBlob(0x01, YES, YES, YES, NO, 0, 0) subdataWithRange:NSMakeRange(0, length)];
        [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
    }
}

- (void)testRule1_ZeroLengthInput {
    [self assertBlob:[NSData data] atTimeMs:1000 failsWith:IRErrorStateCorrupt];
}

- (void)testRule2_BadMagic {
    for (NSUInteger i = 0; i < (NSUInteger)kIRLenMagic; i++) {
        NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
        ((uint8_t *)blob.mutableBytes)[kIROffStateMagic + i] ^= 0xFF;
        [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
    }
}

- (void)testRule3_UnknownStateFormat {
    for (unsigned value = 0; value <= 0xFF; value++) {
        if (value == (unsigned)kIRStateFormat) {
            continue;
        }
        NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
        ((uint8_t *)blob.mutableBytes)[kIROffStateFormat] = (uint8_t)value;
        [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
    }
}

- (void)testRule4_RoleOutsideItsDomain {
    for (unsigned value = 0; value <= 0xFF; value++) {
        if (value == 0x01 || value == 0x02) {
            continue;
        }
        NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
        ((uint8_t *)blob.mutableBytes)[kIROffStateRole] = (uint8_t)value;
        [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
    }
}

- (void)testRule4_EveryPresenceByteHasAClosedDomain {
    /* §12.1: "Readers MUST branch on the _present flag, never on whether the bytes happen to be
       zero." That is only safe once the flag's domain is closed, which is what rule 4 does — and
       it covers ALL FOUR flags, not just the first one a test author reaches for. */
    const NSUInteger offsets[] = {
        kIROffStateDHrPresent,
        kIROffStateCKsPresent,
        kIROffStateCKrPresent,
        kIROffStateProloguePresent,
    };

    for (NSUInteger i = 0; i < 4; i++) {
        for (unsigned value = 2; value <= 0xFF; value++) {
            NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, YES, 0, 0);
            ((uint8_t *)blob.mutableBytes)[offsets[i]] = (uint8_t)value;
            [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
        }
    }
}

#pragma mark - §12.2 rules 5 and 6 — NEG-STATE-COUNT, NEG-STATE-TRAILING

- (void)testNEG_STATE_COUNT {
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    // 2001 = 0x000007D1.
    raw[kIROffStateSkippedCount + 2] = 0x07;
    raw[kIROffStateSkippedCount + 3] = 0xD1;

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
}

- (void)testNEG_STATE_COUNT_AtTheExactBoundary {
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    // 2000 = 0x000007D0 — legal, so this must fail at rule 6 (length) and not at rule 5.
    raw[kIROffStateSkippedCount + 2] = 0x07;
    raw[kIROffStateSkippedCount + 3] = 0xD0;

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorTrailingBytes];
}

- (void)testNEG_STATE_TRAILING_OneByteTooLong {
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    [blob appendBytes:(const uint8_t[]){0x00} length:1];

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorTrailingBytes];
}

- (void)testNEG_STATE_TRAILING_OneByteTooShortWithEntries {
    /* The short direction is the one a test author does not write naturally, and it is the one that
       matters: 547 bytes still clears rule 1's floor, so only rule 6's EXACT comparison catches it.
       An implementation using `>=` here would read 76 bytes of an entry that is 75 bytes long. */
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 1, 1700000000000ull);
    [blob setLength:(blob.length - 1)];

    [self assertBlob:blob atTimeMs:1700000060000ull failsWith:IRErrorTrailingBytes];
}

- (void)testNEG_STATE_TRAILING_CountUnderstatesTheLength {
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 3, 1700000000000ull);
    ((uint8_t *)blob.mutableBytes)[kIROffStateSkippedCount + 3] = 0x02;

    [self assertBlob:blob atTimeMs:1700000060000ull failsWith:IRErrorTrailingBytes];
}

#pragma mark - §12.2 rule 7

- (void)testRule7_HighBitSetOnAnyStoredX25519PublicIsStateCorrupt {
    const uint64_t base = 1700000000000ull;

    NSDictionary<NSString *, NSNumber *> *offsets = @{
        @"SESSION_AD IK_A^d": @((NSUInteger)kIROffStateInitiatorAgreement),
        @"SESSION_AD IK_B^d": @((NSUInteger)kIROffStateResponderAgreement),
        @"DHs_pub":           @((NSUInteger)kIROffStateDHsPub),
        @"DHr_pub":           @((NSUInteger)kIROffStateDHrPub),
        @"prologue EK_A":     @((NSUInteger)(kIROffStatePrologue + kIROffPrologueEK)),
        @"skipped[0] dh_pub": @((NSUInteger)kIROffStateSkippedEntries),
        @"skipped[2] dh_pub": @((NSUInteger)(kIROffStateSkippedEntries + (2 * kIRLenStateSkippedEntry))),
    };

    for (NSString *name in offsets) {
        NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, YES, 3, base);
        NSUInteger keyOffset = offsets[name].unsignedIntegerValue;
        ((uint8_t *)blob.mutableBytes)[keyOffset + 31] |= 0x80;

        NSError *error = nil;
        IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                     atTimeMs:IRNowInsideTTL(base)
                                                                        error:&error];
        XCTAssertNil(state, @"%@ with bit 255 set must be rejected", name);
        XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt,
                       @"%@ must report ERR_STATE_CORRUPT, not the wire path's code", name);
    }
}

- (void)testRule7_DoesNotApplyToTheEd25519IdentityKeys {
    /* §4.4 SCOPING — the recurring finding, now in the state decoder.

       Checks 1–2 are RFC 7748 u-coordinate rules. Bit 255 of an Ed25519 public key is the sign of x
       (RFC 8032 §5.1.2) and is set in roughly half of all valid identities — RFC 8032 §7.1's
       SHA(abc) public key ends 0xbf. A decoder that applies check 2 to `IK^s` rejects about half of
       all conformant blobs, intermittently, and the symptom reads as a signature bug. */
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    raw[kIROffStateInitiatorSigning + 31] |= 0x80;
    raw[kIROffStateResponderSigning + 31] |= 0x80;

    IRRatchetState *state = [self parseBlob:blob atTimeMs:1000];
    XCTAssertNotNil(state);
    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testRule7_IgnoresAbsentOptionalPublicKeys {
    /* An absent DHr is 32 zero bytes, which passes checks 1–2 — so this is not testing that zeros
       are accepted, it is testing that the ABSENT field is not validated as a key at all. */
    NSMutableData *blob = IRStateBlob(0x01, NO, YES, YES, NO, 0, 0);
    ((uint8_t *)blob.mutableBytes)[kIROffStateDHrPub + 31] |= 0x80;

    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:1000
                                                                    error:&error];
    XCTAssertNotNil(state, @"%@", error);
    XCTAssertNil(state.DHr);
}

#pragma mark - §12.2 rule 8 — NEG-STATE-UNCLAMPED

- (void)testNEG_STATE_UNCLAMPED_LowBits {
    for (uint8_t bit = 0x01; bit <= 0x04; bit <<= 1) {
        NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
        ((uint8_t *)blob.mutableBytes)[kIROffStateDHsPrivFirstByte] |= bit;
        [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
    }
}

- (void)testNEG_STATE_UNCLAMPED_HighBits {
    NSMutableData *bitSet = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    ((uint8_t *)bitSet.mutableBytes)[kIROffStateDHsPrivLastByte] |= 0x80;
    [self assertBlob:bitSet atTimeMs:1000 failsWith:IRErrorStateCorrupt];

    NSMutableData *bitClear = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    ((uint8_t *)bitClear.mutableBytes)[kIROffStateDHsPrivLastByte] &= (uint8_t)~0x40;
    [self assertBlob:bitClear atTimeMs:1000 failsWith:IRErrorStateCorrupt];
}

- (void)testRule8_RejectsRatherThanReClamping {
    /* §19.5 — "Rejected: silently re-clamp on load. More forgiving, and functionally equivalent
       since clamping is idempotent — but it would let a non-conformant writer's blobs circulate
       undetected, and it breaks the exact-bytes property that makes §12.1 testable at all."

       The trap this pins is specific: IRX25519Private CLAMPS at construction, so a rule-8 check
       placed after that constructor accepts every unclamped blob AND still passes its own
       round-trip test, because the re-clamped bytes match what a conformant writer would have
       produced. Only an explicit pre-construction check catches it. */
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    ((uint8_t *)blob.mutableBytes)[kIROffStateDHsPrivFirstByte] |= 0x01;

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];

    // Sanity: clearing the offending bit makes the same blob parse.
    ((uint8_t *)blob.mutableBytes)[kIROffStateDHsPrivFirstByte] &= (uint8_t)~0x01;
    XCTAssertNotNil([self parseBlob:blob atTimeMs:1000]);
}

#pragma mark - ORDERING — inputs wrong in two ways

- (void)testOrder_Rule5BeatsRule6 {
    /* skipped_count = 2001 AND a length that matches no count at all. Rule 5 gives
       ERR_STATE_CORRUPT, rule 6 would give ERR_TRAILING_BYTES. Only this input separates them, and
       §15.4 makes the exact code a conformance requirement. */
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;
    raw[kIROffStateSkippedCount + 2] = 0x07;
    raw[kIROffStateSkippedCount + 3] = 0xD1;
    [blob appendBytes:(const uint8_t[]){0x00, 0x00, 0x00} length:3];

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
}

- (void)testOrder_Rule6BeatsRule7 {
    // One extra byte AND a high-bit DHs_pub. Rule 6 owns it.
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    ((uint8_t *)blob.mutableBytes)[kIROffStateDHsPub + 31] |= 0x80;
    [blob appendBytes:(const uint8_t[]){0x00} length:1];

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorTrailingBytes];
}

- (void)testOrder_Rule6BeatsRule8 {
    // One extra byte AND an unclamped DHs_priv. Rule 6 owns it.
    NSMutableData *blob = IRStateBlob(0x01, YES, YES, YES, NO, 0, 0);
    ((uint8_t *)blob.mutableBytes)[kIROffStateDHsPrivFirstByte] |= 0x01;
    [blob appendBytes:(const uint8_t[]){0x00} length:1];

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorTrailingBytes];
}

- (void)testOrder_Rule1BeatsEverythingIncludingTheCountRead {
    /* `skipped_count` sits at offset 468. A 100-byte blob has no count to read, so rule 1's floor
       is what stops the read — the §10.3 trap, in the one other structure it applies to. Wrong in
       three ways at once: too short, bad magic, bad format. */
    NSMutableData *blob = [[IRStateBlob(0x01, YES, YES, YES, NO, 0, 0)
                            subdataWithRange:NSMakeRange(0, 100)] mutableCopy];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;
    raw[kIROffStateMagic] = 0x00;
    raw[kIROffStateFormat] = 0xFF;

    [self assertBlob:blob atTimeMs:1000 failsWith:IRErrorStateCorrupt];
}

#pragma mark - §12.2 rule 9 — the TTL sweep

- (void)testRule9_EntriesOlderThanTheTTLAreDroppedAndTheBlobShrinks {
    const uint64_t base = 1000000ull;
    NSData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);

    // Well past SKIPPED_TTL_MS for all three.
    uint64_t nowMs = base + (uint64_t)kIRSkippedTTLMs + 100000ull;

    IRRatchetState *state = [self parseBlob:blob atTimeMs:nowMs];
    XCTAssertEqual(state.skipped.count, (NSUInteger)0);

    NSData *reserialized = [self reserialize:state];
    XCTAssertEqual(reserialized.length, (NSUInteger)kIRLenStatePrefix);
    XCTAssertNotEqualObjects(reserialized, blob);
}

- (void)testRule9_EntriesInsideTheTTLSurviveSoTheRoundTripIsByteIdentical {
    /* §15.3's requirement on every `state.json` vector, restated as a test: supply a `now_ms` that
       places all entries inside the TTL, or rule 9 destroys the artifact seven days after the
       freeze — and §15.6 step 4 forbids regenerating it. */
    const uint64_t base = 1700000000000ull;
    NSData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:(base + (uint64_t)kIRSkippedTTLMs - 1)];
    XCTAssertEqual(state.skipped.count, (NSUInteger)3);
    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testRule9_AFutureDatedEntryIsKeptRatherThanUnderflowing {
    /* The clock is injectable (§15.5 rule 6) and in production is a system clock that can be
       corrected backwards. An unsigned `now - inserted` would underflow to an enormous age and
       purge the entire store — a silent, total loss of every recoverable out-of-order message. */
    const uint64_t base = 1700000000000ull;
    NSData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:(base - 3600000ull)];
    XCTAssertEqual(state.skipped.count, (NSUInteger)3);
}

#pragma mark - Unspecified-but-reachable inputs (see the layer notes)

- (void)testDuplicateStoreKeysAreRejected {
    /* §7.6 keys the skipped store on `dh_pub ‖ uint32_be(N)` as a MAP, and two entries sharing that
       tuple do not describe one. Accepting them would collapse silently — `skipped_count` would
       fall by one on re-serialization and the blob would change LENGTH, breaking the exact total
       that rule 6 exists to enforce. §12.2 states no uniqueness rule; this is the fail-closed
       reading, and it is raised as a spec gap. */
    const uint64_t base = 1700000000000ull;
    NSMutableData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 2, base);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    uint8_t *first = raw + kIROffStateSkippedEntries;
    uint8_t *second = first + kIRLenStateSkippedEntry;
    memcpy(second + kIROffSkippedEntryDHPub, first + kIROffSkippedEntryDHPub, kIRLenX25519Public);
    memcpy(second + kIROffSkippedEntryN, first + kIROffSkippedEntryN, 4);

    [self assertBlob:blob atTimeMs:IRNowInsideTTL(base) failsWith:IRErrorStateCorrupt];
}

- (void)testSameKeyDifferentNIsNotADuplicate {
    const uint64_t base = 1700000000000ull;
    NSMutableData *blob = IRStateBlob(0x02, YES, YES, YES, NO, 2, base);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    uint8_t *first = raw + kIROffStateSkippedEntries;
    uint8_t *second = first + kIRLenStateSkippedEntry;
    memcpy(second + kIROffSkippedEntryDHPub, first + kIROffSkippedEntryDHPub, kIRLenX25519Public);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:IRNowInsideTTL(base)];
    XCTAssertEqual(state.skipped.count, (NSUInteger)2);
    XCTAssertEqualObjects([self reserialize:state], blob);
}

- (void)testNonZeroBytesUnderAClearPresenceFlagAreAcceptedAndNormalized {
    /* PINS CURRENT BEHAVIOUR ON AN UNSPECIFIED INPUT. §12.1 requires a writer to zero-fill an
       absent optional field, but §12.2 states no rule about a reader that meets non-zero bytes
       there, so no conformant writer can produce this blob. Accepting and normalizing is what a
       decoder branching on the flag does naturally, and is therefore the behaviour the other three
       ports are most likely to have.

       The consequence, stated so it is not discovered later: parse-then-reserialize is NOT
       byte-identity-preserving for such an input. Raised as a spec gap; if §12.2 gains a rule this
       test is where the decision lands. */
    NSMutableData *blob = IRStateBlob(0x01, NO, NO, NO, NO, 0, 0);
    uint8_t *raw = (uint8_t *)blob.mutableBytes;
    IRFillPattern(raw + kIROffStateDHrPub, kIRLenX25519Public, 200);
    IRMakeX25519PublicShape(raw + kIROffStateDHrPub);
    IRFillPattern(raw + kIROffStateCKs, kIRLenChainKey, 201);

    IRRatchetState *state = [self parseBlob:blob atTimeMs:1000];
    XCTAssertNil(state.DHr);
    XCTAssertNil(state.CKs);

    NSData *reserialized = [self reserialize:state];
    XCTAssertNotEqualObjects(reserialized, blob, @"normalized, not preserved");
    XCTAssertEqualObjects(reserialized, IRStateBlob(0x01, NO, NO, NO, NO, 0, 0));
}

#pragma mark - §12.1 encode-side refusals

- (void)testSerializeRefusesAZeroizedState {
    IRRatchetState *state = [self parseBlob:IRStateBlob(0x01, YES, YES, YES, NO, 0, 0) atTimeMs:1000];
    [state zeroize];

    NSError *error = nil;
    XCTAssertNil([IRSessionStateCodec serializeState:state error:&error]);
    XCTAssertEqual((IRErrorCode)error.code, IRErrorStateCorrupt);
}

- (void)testSerializeYieldsWipeableStorageRatherThanNSData {
    /* §13.3 — "serialized state buffer: after sealing, and after parsing". A blob holds RK,
       DHs_priv, CKs, CKr and every stored message key; an NSData return would place all of it in a
       copy-on-write container with no zeroizing hook. */
    IRRatchetState *state = [self parseBlob:IRStateBlob(0x01, YES, YES, YES, NO, 0, 0) atTimeMs:1000];

    NSError *error = nil;
    IRSecretBytes *blob = [IRSessionStateCodec serializeState:state error:&error];
    XCTAssertNotNil(blob, @"%@", error);
    XCTAssertEqual(blob.length, (NSUInteger)kIRLenStatePrefix);
    XCTAssertFalse([blob isAllZero]);

    [blob zeroizeNow];
    XCTAssertTrue([blob isAllZero]);
}

- (void)testParseThenReserializeIsStableAcrossRepeatedRounds {
    const uint64_t base = 1700000000000ull;
    NSData *original = IRStateBlob(0x02, YES, YES, YES, NO, 3, base);
    NSData *current = original;

    for (NSUInteger round = 0; round < 4; round++) {
        IRRatchetState *state = [self parseBlob:current atTimeMs:IRNowInsideTTL(base)];
        current = [self reserialize:state];
        XCTAssertEqualObjects(current, original, @"round %lu", (unsigned long)round);
    }
}

@end
