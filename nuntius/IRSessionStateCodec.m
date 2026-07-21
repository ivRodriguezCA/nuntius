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

#import "IRSessionStateCodec.h"

#import "IRByteReader.h"
#import "IRByteWriter.h"
#import "IRSessionAD.h"
#import "IRSkippedKeyStore.h"
#import "IRX3DH.h"

#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>

/* Declared rather than relied upon. Clang permits a later definition in the same @implementation,
   but an explicit extension keeps the private surface of this file readable in one place and makes
   a typo in a selector a compile error at the call site rather than at the definition. */
@interface IRSessionStateCodec ()

+ (IRRatchetState * _Nullable)decodeWithReader:(IRByteReader * _Nonnull)reader
                                      atTimeMs:(uint64_t)nowMs
                                         error:(NSError * _Nullable * _Nullable)error;

+ (IRFixedLengthSecret * _Nullable)secretOfClass:(Class _Nonnull)secretClass
                                        atOffset:(NSUInteger)offset
                                          reader:(IRByteReader * _Nonnull)reader
                                           error:(NSError * _Nullable * _Nullable)error;

+ (IRX25519Public * _Nullable)x25519PublicAtOffset:(NSUInteger)offset
                                             reader:(IRByteReader * _Nonnull)reader
                                              error:(NSError * _Nullable * _Nullable)error;

@end

@implementation IRSessionStateCodec

#pragma mark - Lengths

+ (NSUInteger)blobLengthForSkippedCount:(uint32_t)skippedCount {
    if (skippedCount > (uint32_t)kIRMaxSkippedStored) {
        return 0;
    }

    /* Bounded by the line above, so the product cannot exceed 472 + 76 * 2000 = 152472 and the
       addition cannot overflow NSUInteger on any supported platform. */
    return (NSUInteger)kIRLenStatePrefix + ((NSUInteger)kIRLenStateSkippedEntry * (NSUInteger)skippedCount);
}

#pragma mark - §12.1 encode

+ (IRSecretBytes * _Nullable)serializeState:(IRRatchetState * _Nonnull)state
                                      error:(NSError * _Nullable * _Nullable)error {
    if (state == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* A zeroized state is a discarded snapshot or a torn-down session. Serializing one would
       persist a session keyed with zeros, and the failure would not surface until the first
       message. IRRatchetState.isZeroized exists as this tripwire. */
    if (state.isZeroized) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (state.role != IRSessionRoleInitiator && state.role != IRSessionRoleResponder) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSArray<IRSkippedKeyEntry *> *entries = [state.skipped entriesInInsertionOrder];
    if (entries.count > (NSUInteger)kIRMaxSkippedStored) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSUInteger total = [self blobLengthForSkippedCount:(uint32_t)entries.count];
    if (total == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSData *sessionADBytes = state.sessionAD.bytes;
    if (sessionADBytes.length != (NSUInteger)kIRLenSessionAD ||
        state.handshakeId.length != (NSUInteger)kIRLenHandshakeId ||
        state.RK.length != (NSUInteger)kIRLenRootKey ||
        state.DHs.privateKey.length != (NSUInteger)kIRLenX25519Private ||
        state.DHs.publicKey.length != (NSUInteger)kIRLenX25519Public) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §4.2 / §12.2 rule 8. IRX25519Private clamps at construction so this cannot fail today; it is
       asserted anyway, because emitting a blob our own parser rejects is the one failure mode that
       would look like an interop bug in the OTHER three ports. */
    if (![IRX25519Private bytesAreClamped:state.DHs.privateKey.constBytes]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:total];

    [writer appendBytes:kIRStateMagic length:(NSUInteger)kIRLenMagic];
    [writer appendUInt8:(uint8_t)kIRStateFormat];
    [writer appendUInt8:(uint8_t)state.role];
    [writer appendData:sessionADBytes];
    [writer appendData:state.handshakeId];
    [writer appendSecretBytes:state.RK];
    [writer appendSecretBytes:state.DHs.privateKey];
    [writer appendData:state.DHs.publicKey.data];

    /* §12.1: fixed-size optional fields are ALWAYS present and zero-filled when absent, so the
       fixed region has no conditional structure and every offset below is a constant. */
    if (state.DHr != nil) {
        if (state.DHr.length != (NSUInteger)kIRLenX25519Public) {
            [writer zeroize];
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        [writer appendUInt8:(uint8_t)IRPresenceFlagPresent];
        [writer appendData:state.DHr.data];
    } else {
        [writer appendUInt8:(uint8_t)IRPresenceFlagAbsent];
        [writer appendZeros:(NSUInteger)kIRLenX25519Public];
    }

    if (state.CKs != nil) {
        if (state.CKs.length != (NSUInteger)kIRLenChainKey) {
            [writer zeroize];
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        [writer appendUInt8:(uint8_t)IRPresenceFlagPresent];
        [writer appendSecretBytes:state.CKs];
    } else {
        [writer appendUInt8:(uint8_t)IRPresenceFlagAbsent];
        [writer appendZeros:(NSUInteger)kIRLenChainKey];
    }

    if (state.CKr != nil) {
        if (state.CKr.length != (NSUInteger)kIRLenChainKey) {
            [writer zeroize];
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        [writer appendUInt8:(uint8_t)IRPresenceFlagPresent];
        [writer appendSecretBytes:state.CKr];
    } else {
        [writer appendUInt8:(uint8_t)IRPresenceFlagAbsent];
        [writer appendZeros:(NSUInteger)kIRLenChainKey];
    }

    [writer appendUInt32BE:state.Ns];
    [writer appendUInt32BE:state.Nr];
    [writer appendUInt32BE:state.PN];
    [writer appendUInt64BE:state.sendCounter];

    if (state.prologue != nil) {
        NSError *prologueError = nil;
        NSData *prologueBytes = [state.prologue serializedBytes:&prologueError];
        if (prologueBytes == nil || prologueBytes.length != (NSUInteger)kIRLenStatePrologue) {
            [writer zeroize];
            IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, prologueError);
            return nil;
        }
        [writer appendUInt8:(uint8_t)IRPresenceFlagPresent];
        [writer appendData:prologueBytes];
    } else {
        [writer appendUInt8:(uint8_t)IRPresenceFlagAbsent];
        [writer appendZeros:(NSUInteger)kIRLenStatePrologue];
    }

    [writer appendUInt32BE:(uint32_t)entries.count];

    for (IRSkippedKeyEntry *entry in entries) {
        if (entry.isZeroized ||
            entry.dhPublic.length != (NSUInteger)kIRLenX25519Public ||
            entry.messageKey.length != (NSUInteger)kIRLenMessageKey) {
            [writer zeroize];
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }

        [writer appendData:entry.dhPublic.data];
        [writer appendUInt32BE:entry.N];
        [writer appendSecretBytes:entry.messageKey];
        [writer appendUInt64BE:entry.insertedAtMs];
    }

    /* Zeroizes the writer's accumulator on BOTH the success and the mismatch path. */
    return [writer finishSecretExpectingLength:total guarded:NO error:error];
}

#pragma mark - §12.2 decode

+ (IRRatchetState * _Nullable)deserializeState:(IRSecretBytes * _Nonnull)blob
                                      atTimeMs:(uint64_t)nowMs
                                         error:(NSError * _Nullable * _Nullable)error {
    if (blob == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* No copy: the blob holds RK, DHs_priv, CKs, CKr and every stored message key, and the caller
       owns the only buffer §13.3 can schedule a wipe for. */
    IRByteReader *reader = [[IRByteReader alloc] initWithBytesNoCopy:blob.constBytes
                                                              length:blob.length];

    return [self decodeWithReader:reader atTimeMs:nowMs error:error];
}

+ (IRRatchetState * _Nullable)deserializeStateFromData:(NSData * _Nonnull)blob
                                              atTimeMs:(uint64_t)nowMs
                                                 error:(NSError * _Nullable * _Nullable)error {
    if (blob == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:blob];

    return [self decodeWithReader:reader atTimeMs:nowMs error:error];
}

/**
 §12.2 rules 1–9 in order.

 Every rule below is a byte test at a compile-time offset. The first object is allocated after
 rule 8, which is what makes "a failure at any step MUST yield NO partially-loaded state" a
 property of the control flow rather than a discipline about unwinding.
 */
+ (IRRatchetState * _Nullable)decodeWithReader:(IRByteReader * _Nonnull)reader
                                      atTimeMs:(uint64_t)nowMs
                                         error:(NSError * _Nullable * _Nullable)error {

    // ---- rule 1: length floor ------------------------------------------------------------- //
    // Before ANY field read. `skipped_count` sits at offset 468, so a blob shorter than the fixed
    // prefix cannot have its count read at all — the §10.3 trap, in the one other place it applies.
    if (reader.count < (NSUInteger)kIRLenStatePrefix) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // ---- rule 2: magic -------------------------------------------------------------------- //
    if (![reader matchLiteral:kIRStateMagic
                       length:(NSUInteger)kIRLenMagic
                     atOffset:(NSUInteger)kIROffStateMagic]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // ---- rule 3: state_format ------------------------------------------------------------- //
    uint8_t formatByte = 0;
    if (![reader readUInt8:&formatByte atOffset:(NSUInteger)kIROffStateFormat] ||
        formatByte != (uint8_t)kIRStateFormat) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // ---- rule 4: role and every presence byte --------------------------------------------- //
    uint8_t roleByte = 0;
    if (![reader readUInt8:&roleByte atOffset:(NSUInteger)kIROffStateRole]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }
    if (roleByte != (uint8_t)IRSessionRoleInitiator && roleByte != (uint8_t)IRSessionRoleResponder) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    const NSUInteger presenceOffsets[] = {
        (NSUInteger)kIROffStateDHrPresent,
        (NSUInteger)kIROffStateCKsPresent,
        (NSUInteger)kIROffStateCKrPresent,
        (NSUInteger)kIROffStateProloguePresent,
    };
    uint8_t presence[4] = {0, 0, 0, 0};
    for (NSUInteger i = 0; i < 4; i++) {
        if (![reader readUInt8:&presence[i] atOffset:presenceOffsets[i]]) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        /* "Readers MUST branch on the _present flag, never on whether the bytes happen to be
           zero" (§12.1) — which is only safe once the flag's domain is closed, here. */
        if (presence[i] != (uint8_t)IRPresenceFlagAbsent &&
            presence[i] != (uint8_t)IRPresenceFlagPresent) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
    }
    const BOOL hasDHr      = (presence[0] == (uint8_t)IRPresenceFlagPresent);
    const BOOL hasCKs      = (presence[1] == (uint8_t)IRPresenceFlagPresent);
    const BOOL hasCKr      = (presence[2] == (uint8_t)IRPresenceFlagPresent);
    const BOOL hasPrologue = (presence[3] == (uint8_t)IRPresenceFlagPresent);

    // ---- rule 5: skipped_count bound ------------------------------------------------------ //
    uint32_t skippedCount = 0;
    if (![reader readUInt32BE:&skippedCount atOffset:(NSUInteger)kIROffStateSkippedCount]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }
    if (skippedCount > (uint32_t)kIRMaxSkippedStored) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // ---- rule 6: exact total length ------------------------------------------------------- //
    // The multiplication is bounded by rule 5 and therefore cannot overflow. This is also the
    // §12.4 requirement that no allocation be sized from an unvalidated field: `skippedCount` has
    // been bounded AND cross-checked against the real length before anything is allocated from it.
    NSUInteger expectedLength = [self blobLengthForSkippedCount:skippedCount];
    if (expectedLength == 0 || reader.count != expectedLength) {
        IRSetError(error, IRErrorTrailingBytes);
        return nil;
    }

    // ---- rule 7: §4.4 checks 1–2 on every stored public key -------------------------------- //
    // X25519 ONLY. The two Ed25519 identity keys at blob offsets 19 and 83 are deliberately
    // absent: bit 255 there is the sign of x (RFC 8032 §5.1.2), set in ~half of valid identities.
    NSMutableArray<NSNumber *> *publicKeyOffsets = [NSMutableArray array];
    [publicKeyOffsets addObject:@((NSUInteger)kIROffStateInitiatorAgreement)];  // SESSION_AD IK_A^d
    [publicKeyOffsets addObject:@((NSUInteger)kIROffStateResponderAgreement)];  // SESSION_AD IK_B^d
    [publicKeyOffsets addObject:@((NSUInteger)kIROffStateDHsPub)];
    if (hasDHr) {
        [publicKeyOffsets addObject:@((NSUInteger)kIROffStateDHrPub)];
    }
    if (hasPrologue) {
        [publicKeyOffsets addObject:@((NSUInteger)kIROffStatePrologue + (NSUInteger)kIROffPrologueEK)];
    }
    for (uint32_t i = 0; i < skippedCount; i++) {
        NSUInteger entryOffset = (NSUInteger)kIROffStateSkippedEntries +
                                 ((NSUInteger)kIRLenStateSkippedEntry * (NSUInteger)i);
        [publicKeyOffsets addObject:@(entryOffset + (NSUInteger)kIROffSkippedEntryDHPub)];
    }

    for (NSNumber *offsetNumber in publicKeyOffsets) {
        NSUInteger offset = offsetNumber.unsignedIntegerValue;
        const uint8_t *keyBytes = [reader bytesAtOffset:offset length:(NSUInteger)kIRLenX25519Public];
        if (keyBytes == NULL || ![IRX25519Public highBitIsClear:keyBytes]) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
    }

    // ---- §12.1's zero-fill invariant is NOT enforced here, deliberately -------------------- //
    // §12.1: "Fixed-size optional fields are always present and zero-filled when absent... Readers
    // MUST branch on the `_present` flag, never on whether the bytes happen to be zero."
    //
    // That is a WRITER's obligation plus an instruction about how a reader determines presence. It
    // is not a reader-side validation rule, and §12.2 — which is the exhaustive list of reader
    // checks, each a MUST — states none. So no conformant writer can produce a blob with non-zero
    // bytes under a clear flag, and this decoder simply never reads those bytes.
    //
    // CONSEQUENCE, STATED SO IT IS NOT REDISCOVERED AS A BUG: parse-then-reserialize is not
    // byte-identity-preserving for such a blob. The decoder accepts it and the encoder then writes
    // zeros. Pinned by `testNonZeroBytesUnderAClearPresenceFlagAreAcceptedAndNormalized`.
    //
    // Rejecting instead was tried and reverted. It would make THIS port stricter than §12.2
    // enumerates while the other three ports, branching on the flag as §12.1 instructs, accept —
    // and a decoder that rejects a blob its peers accept is the divergence the exact-byte layout
    // exists to prevent. If §12.2 gains a tenth rule, this is where it lands, in all four ports at
    // once. Raised for SPEC.md §12.2 rather than resolved here.

    // ---- rule 8: DHs_priv is in clamped form ---------------------------------------------- //
    // REJECT, never silently re-clamp (§19.5). This MUST precede IRX25519Private's construction,
    // which clamps — a check placed after it would accept every unclamped blob and still pass its
    // own round-trip test. `NEG-STATE-UNCLAMPED`, both bit positions.
    uint8_t privFirst = 0;
    uint8_t privLast = 0;
    if (![reader readUInt8:&privFirst atOffset:(NSUInteger)kIROffStateDHsPrivFirstByte] ||
        ![reader readUInt8:&privLast atOffset:(NSUInteger)kIROffStateDHsPrivLastByte]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }
    if ((privFirst & 0x07) != 0x00 || (privLast & 0xC0) != 0x40) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // ---- construction: every rule has passed ----------------------------------------------- //

    NSError *underlying = nil;

    NSData *sessionADBytes = [reader dataAtOffset:(NSUInteger)kIROffStateSessionAD
                                           length:(NSUInteger)kIRLenSessionAD];
    if (sessionADBytes == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }
    IRSessionAD *sessionAD = [IRSessionAD adFromStoredBytes:sessionADBytes error:&underlying];
    if (sessionAD == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
        return nil;
    }

    NSData *handshakeId = [reader dataAtOffset:(NSUInteger)kIROffStateHandshakeId
                                        length:(NSUInteger)kIRLenHandshakeId];
    if (handshakeId == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRRootKey *rootKey = (IRRootKey *)[self secretOfClass:[IRRootKey class]
                                                 atOffset:(NSUInteger)kIROffStateRK
                                                   reader:reader
                                                    error:error];
    if (rootKey == nil) {
        return nil;
    }

    IRX25519Private *ratchetPrivate =
        (IRX25519Private *)[self secretOfClass:[IRX25519Private class]
                                      atOffset:(NSUInteger)kIROffStateDHsPriv
                                        reader:reader
                                         error:error];
    if (ratchetPrivate == nil) {
        [rootKey zeroizeNow];
        return nil;
    }

    IRX25519Public *ratchetPublic = [self x25519PublicAtOffset:(NSUInteger)kIROffStateDHsPub
                                                        reader:reader
                                                         error:error];
    if (ratchetPublic == nil) {
        [rootKey zeroizeNow];
        [ratchetPrivate zeroizeNow];
        return nil;
    }

    IRX25519KeyPair *ratchetKeyPair = [IRX25519KeyPair pairWithPublicKey:ratchetPublic
                                                              privateKey:ratchetPrivate
                                                                   error:&underlying];
    if (ratchetKeyPair == nil) {
        [rootKey zeroizeNow];
        [ratchetPrivate zeroizeNow];
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
        return nil;
    }

    IRX25519Public *peerRatchetPublic = nil;
    if (hasDHr) {
        peerRatchetPublic = [self x25519PublicAtOffset:(NSUInteger)kIROffStateDHrPub
                                                reader:reader
                                                 error:error];
        if (peerRatchetPublic == nil) {
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            return nil;
        }
    }

    IRChainKey *sendingChainKey = nil;
    if (hasCKs) {
        sendingChainKey = (IRChainKey *)[self secretOfClass:[IRChainKey class]
                                                   atOffset:(NSUInteger)kIROffStateCKs
                                                     reader:reader
                                                      error:error];
        if (sendingChainKey == nil) {
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            return nil;
        }
    }

    IRChainKey *receivingChainKey = nil;
    if (hasCKr) {
        receivingChainKey = (IRChainKey *)[self secretOfClass:[IRChainKey class]
                                                     atOffset:(NSUInteger)kIROffStateCKr
                                                       reader:reader
                                                        error:error];
        if (receivingChainKey == nil) {
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            [sendingChainKey zeroizeNow];
            return nil;
        }
    }

    uint32_t Ns = 0;
    uint32_t Nr = 0;
    uint32_t PN = 0;
    uint64_t sendCounter = 0;
    if (![reader readUInt32BE:&Ns atOffset:(NSUInteger)kIROffStateNs] ||
        ![reader readUInt32BE:&Nr atOffset:(NSUInteger)kIROffStateNr] ||
        ![reader readUInt32BE:&PN atOffset:(NSUInteger)kIROffStatePN] ||
        ![reader readUInt64BE:&sendCounter atOffset:(NSUInteger)kIROffStateSendCounter]) {
        [rootKey zeroizeNow];
        [ratchetKeyPair zeroize];
        [sendingChainKey zeroizeNow];
        [receivingChainKey zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSessionPrologue *prologue = nil;
    if (hasPrologue) {
        NSData *prologueBytes = [reader dataAtOffset:(NSUInteger)kIROffStatePrologue
                                              length:(NSUInteger)kIRLenStatePrologue];
        if (prologueBytes == nil) {
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            [sendingChainKey zeroizeNow];
            [receivingChainKey zeroizeNow];
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        prologue = [IRSessionPrologue prologueFromStoredBytes:prologueBytes error:&underlying];
        if (prologue == nil) {
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            [sendingChainKey zeroizeNow];
            [receivingChainKey zeroizeNow];
            IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
            return nil;
        }
    }

    IRSkippedKeyStore *skipped = [IRSkippedKeyStore store];
    for (uint32_t i = 0; i < skippedCount; i++) {
        NSUInteger entryOffset = (NSUInteger)kIROffStateSkippedEntries +
                                 ((NSUInteger)kIRLenStateSkippedEntry * (NSUInteger)i);

        IRX25519Public *entryPublic =
            [self x25519PublicAtOffset:(entryOffset + (NSUInteger)kIROffSkippedEntryDHPub)
                                reader:reader
                                 error:error];
        uint32_t entryN = 0;
        BOOL readN = [reader readUInt32BE:&entryN
                                 atOffset:(entryOffset + (NSUInteger)kIROffSkippedEntryN)];
        uint64_t insertedAtMs = 0;
        BOOL readTime = [reader readUInt64BE:&insertedAtMs
                                    atOffset:(entryOffset + (NSUInteger)kIROffSkippedEntryInsertedAtMs)];
        IRMessageKey *messageKey = nil;
        if (entryPublic != nil && readN && readTime) {
            messageKey = (IRMessageKey *)[self secretOfClass:[IRMessageKey class]
                                                    atOffset:(entryOffset + (NSUInteger)kIROffSkippedEntryMK)
                                                      reader:reader
                                                       error:error];
        }

        /* §7.6 keys the store on `dh_pub ‖ uint32_be(N)` as a MAP. Two entries sharing that tuple
           do not describe a map, and accepting them would collapse silently: `skipped_count` would
           fall by one on re-serialization and the blob would change LENGTH, breaking the exact
           total that §12.2 rule 6 exists to enforce. §12.2 states no uniqueness rule — see the
           layer notes; this is the fail-closed reading. */
        BOOL duplicate = (entryPublic != nil && readN &&
                          [skipped entryForDHPublic:entryPublic N:entryN] != nil);

        if (entryPublic == nil || !readN || !readTime || messageKey == nil || duplicate ||
            ![skipped insertMessageKey:messageKey
                              dhPublic:entryPublic
                                     N:entryN
                              atTimeMs:insertedAtMs]) {
            [messageKey zeroizeNow];
            [skipped zeroizeAll];
            [rootKey zeroizeNow];
            [ratchetKeyPair zeroize];
            [sendingChainKey zeroizeNow];
            [receivingChainKey zeroizeNow];
            /* Set unconditionally rather than only when unset: reading `*error` to decide would
               dereference an out-parameter this function did not initialize, and every failure
               reachable here is ERR_STATE_CORRUPT anyway. */
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }

        /* -insertMessageKey: copies nothing — the entry now owns `messageKey`, so releasing the
           local reference here must NOT wipe it. */
        messageKey = nil;
    }

    /* ---- rule 9: TTL sweep ------------------------------------------------------------------
       Routed through the store's own sweep so the age comparator and its backwards-clock guard
       have exactly one implementation in this framework. -zeroizePendingRemovals is documented as
       COMMIT-ONLY because a snapshot shares entries with its live store; this store was built two
       statements ago and is shared with nothing, so the wipe is unambiguously correct here and is
       what discharges rule 9's "drop AND zeroize". */
    [skipped dropEntriesExpiredAtTimeMs:nowMs];
    [skipped zeroizePendingRemovals];

    IRRatchetState *state = [IRRatchetState stateWithRole:(IRSessionRole)roleByte
                                                sessionAD:sessionAD
                                              handshakeId:handshakeId
                                                  rootKey:rootKey
                                           ratchetKeyPair:ratchetKeyPair
                                        peerRatchetPublic:peerRatchetPublic
                                          sendingChainKey:sendingChainKey
                                        receivingChainKey:receivingChainKey
                                                       Ns:Ns
                                                       Nr:Nr
                                                       PN:PN
                                              sendCounter:sendCounter
                                                 prologue:prologue
                                                  skipped:skipped
                                                    error:&underlying];
    if (state == nil) {
        [skipped zeroizeAll];
        [rootKey zeroizeNow];
        [ratchetKeyPair zeroize];
        [sendingChainKey zeroizeNow];
        [receivingChainKey zeroizeNow];
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
        return nil;
    }

    return state;
}

#pragma mark - Field readers

/// A fixed-length secret read in place and copied straight into wipeable storage — never through
/// an intermediate NSData.
+ (IRFixedLengthSecret * _Nullable)secretOfClass:(Class _Nonnull)secretClass
                                        atOffset:(NSUInteger)offset
                                          reader:(IRByteReader * _Nonnull)reader
                                           error:(NSError * _Nullable * _Nullable)error {
    NSUInteger length = [secretClass fixedLength];
    const uint8_t *bytes = [reader bytesAtOffset:offset length:length];
    if (bytes == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSError *underlying = nil;
    IRFixedLengthSecret *secret = [secretClass fromBytes:bytes guarded:NO error:&underlying];
    if (secret == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
        return nil;
    }

    return secret;
}

/**
 §12.2 rule 7's error code, not IRX25519Public's.

 The nominal constructor reports IRErrorInvalidPublicKey for these bytes, which is correct on the
 wire path and wrong here: rule 7 names ERR_STATE_CORRUPT for identical input. The encoding
 predicate has already run at rule 7's own position; this remaps the residual failure and threads
 the original through NSUnderlyingErrorKey for local diagnosis.
 */
+ (IRX25519Public * _Nullable)x25519PublicAtOffset:(NSUInteger)offset
                                             reader:(IRByteReader * _Nonnull)reader
                                              error:(NSError * _Nullable * _Nullable)error {
    const uint8_t *bytes = [reader bytesAtOffset:offset length:(NSUInteger)kIRLenX25519Public];
    if (bytes == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSError *underlying = nil;
    IRX25519Public *publicKey = [IRX25519Public fromBytes:bytes error:&underlying];
    if (publicKey == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, underlying);
        return nil;
    }

    return publicKey;
}

@end
