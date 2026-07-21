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

#import "IRMessageBuilder.h"

#import "IRByteWriter.h"
#import "IRMessageHeader.h"

/// Fields common to both header layouts, at the offsets §9.1 and §9.2 agree on. Written through one
/// function so the two builders cannot disagree about the constant prefix.
static void IRBuilderAppendPrefix(IRByteWriter * _Nonnull writer, IRMessageType type) {
    [writer appendUInt8:(uint8_t)kIRProtocolVersion];
    [writer appendUInt8:(uint8_t)type];

    /* §9.1 / §9.2 — reserved, and inside the AD (§8.5), so this is not merely a convention: a peer
       that received anything else would fail Poly1305 verification even if its gate let the value
       through. Written as a literal because there is nothing here for a caller to choose. */
    [writer appendUInt16BE:0x0000];
}

/// §10.1 checks 9–10 / §10.2 check 9, applied on the SEND side. Emitting a counter a conformant
/// peer must reject with ERR_COUNTER_OVERFLOW is a local bug, and §10.5 gives 7112 the second
/// meaning "or `Ns` exhausted" precisely so the sender can report it.
static BOOL IRBuilderCheckCounter(uint32_t value, NSError * _Nullable * _Nullable error) {
    if (value > (uint32_t)kIRMaxCounter) {
        IRSetError(error, IRErrorCounterOverflow);
        return NO;
    }

    return YES;
}

static BOOL IRBuilderCheckRatchetKey(IRX25519Public * _Nullable ratchetKey,
                                     NSError * _Nullable * _Nullable error) {
    /* The nominal type already carries §4.4 checks 1–2 — IRX25519Public has no constructor that
       skips them — so this is a nil and arity check, not a re-validation. */
    if (ratchetKey == nil || ratchetKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return NO;
    }

    return YES;
}

static BOOL IRBuilderCheckNonce(IRNonce * _Nullable nonce, NSError * _Nullable * _Nullable error) {
    if (nonce == nil || nonce.length != kIRLenNonce) {
        IRSetError(error, IRErrorMalformedHeader);
        return NO;
    }

    return YES;
}

@implementation IRMessageBuilder

#pragma mark - Bounds

+ (BOOL)validatePlaintextLength:(NSUInteger)plaintextLength
                          error:(NSError * _Nullable * _Nullable)error {
    /* §10.4. Note there is no lower bound: zero is legal and produces a 72-byte message. */
    if (plaintextLength > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return NO;
    }

    return YES;
}

#pragma mark - Headers

+ (NSData * _Nullable)type01HeaderWithRatchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                               N:(uint32_t)N
                                              PN:(uint32_t)PN
                                           nonce:(IRNonce * _Nonnull)nonce
                                           error:(NSError * _Nullable * _Nullable)error {
    if (!IRBuilderCheckRatchetKey(ratchetKey, error)) {
        return nil;
    }

    if (!IRBuilderCheckNonce(nonce, error)) {
        return nil;
    }

    if (!IRBuilderCheckCounter(N, error) || !IRBuilderCheckCounter(PN, error)) {
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:(NSUInteger)kIRLenType01Header];

    IRBuilderAppendPrefix(writer, IRMessageTypeNormal);
    [writer appendData:ratchetKey.data];

    /* The two counters, in §9.1's order, from two separately named parameters. Defect 10 was
       exactly this pair collapsing into one value. */
    [writer appendUInt32BE:N];
    [writer appendUInt32BE:PN];

    [writer appendData:nonce.data];

    return [writer finishExpectingLength:(NSUInteger)kIRLenType01Header
                       mismatchErrorCode:IRErrorMalformedHeader
                                   error:error];
}

+ (NSData * _Nullable)type02HeaderWithInitiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                                        identityBinding:(IREd25519Signature * _Nonnull)identityBinding
                                               prologue:(IRSessionPrologue * _Nonnull)prologue
                                             ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                                      N:(uint32_t)N
                                                  nonce:(IRNonce * _Nonnull)nonce
                                                  error:(NSError * _Nullable * _Nullable)error {
    if (initiatorIdentity == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (identityBinding == nil || identityBinding.length != kIRLenEd25519Signature) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    if (prologue == nil || prologue.ephemeralPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (!IRBuilderCheckRatchetKey(ratchetKey, error)) {
        return nil;
    }

    if (!IRBuilderCheckNonce(nonce, error)) {
        return nil;
    }

    if (!IRBuilderCheckCounter(N, error)) {
        return nil;
    }

    /* §10.2 check 11, mirrored at the source. IRSessionPrologue's own constructor has already
       established the `opk_flag` / `opk_id` / key consistency that §10.2 checks 6 and 7 verify on
       the wire, so this is the one receive-side structural rule the prologue does not already
       carry. */
    if ([ratchetKey isEqualToX25519Public:prologue.ephemeralPublic]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:(NSUInteger)kIRLenType02Header];

    IRBuilderAppendPrefix(writer, IRMessageTypePrekey);

    /* §9.2 offsets 4 and 36 — `IK_A^s ‖ IK_A^d`. `rawPair` is those 64 bytes in that order, the
       same slice §11.1 indexes on and §6.5 embeds in SESSION_AD, so the identity is written from
       one canonical encoding rather than reassembled from two halves. */
    [writer appendData:initiatorIdentity.rawPair];

    [writer appendData:identityBinding.data];

    /* §11.3 — the prologue, byte-identical on every prekey message of this session. */
    [writer appendData:prologue.ephemeralPublic.data];
    [writer appendUInt32BE:prologue.spkId];
    [writer appendUInt8:(uint8_t)prologue.opkFlag];
    [writer appendUInt32BE:prologue.opkId];

    [writer appendData:ratchetKey.data];
    [writer appendUInt32BE:N];

    /* §9.2 — `PN` is always zero here. It is a literal, not a parameter; see this class's header. */
    [writer appendUInt32BE:0];

    [writer appendData:nonce.data];

    return [writer finishExpectingLength:(NSUInteger)kIRLenType02Header
                       mismatchErrorCode:IRErrorMalformedHeader
                                   error:error];
}

#pragma mark - Assembly

+ (NSData * _Nullable)messageWithHeaderBytes:(NSData * _Nonnull)headerBytes
                            ciphertextAndTag:(NSData * _Nonnull)ciphertextAndTag
                                       error:(NSError * _Nullable * _Nullable)error {
    if (headerBytes == nil || ciphertextAndTag == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §9 in reverse: the header's length determines the type, exactly as the type determines the
       header's length on the way in. Anything else was not produced by a builder above. */
    IRMessageType type;
    if (headerBytes.length == (NSUInteger)kIRLenType01Header) {
        type = IRMessageTypeNormal;
    } else if (headerBytes.length == (NSUInteger)kIRLenType02Header) {
        type = IRMessageTypePrekey;
    } else {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §8.2 — `len(ct_and_tag) == len(pt) + 16`, and ChaCha20 is a stream cipher, so the shortest
       possible seal output is the bare 16-byte tag over an empty plaintext. Below that, the
       assembled message would sit under the type's minimum, which is what §10.5 code 7103 means. */
    if (ciphertextAndTag.length < (NSUInteger)kIRLenAEADTag) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    if (![self validatePlaintextLength:ciphertextAndTag.length - (NSUInteger)kIRLenAEADTag
                                 error:error]) {
        return nil;
    }

    NSUInteger total = headerBytes.length + ciphertextAndTag.length;

    /* Belt and braces against §10.4: the plaintext bound above already implies this, and the
       IR_STATIC_ASSERTs in IRProtocolConstants.m prove `max == header + MAX_PLAINTEXT + tag` for
       both types, so this can only fire if those two facts ever stop agreeing. */
    NSUInteger maximum = [IRMessageHeader maximumMessageLengthForType:type];
    if (maximum == 0 || total > maximum) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    NSMutableData *message = [NSMutableData dataWithCapacity:total];
    if (message == nil) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    [message appendData:headerBytes];
    [message appendData:ciphertextAndTag];

    if (message.length != total) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    return [message copy];
}

@end
