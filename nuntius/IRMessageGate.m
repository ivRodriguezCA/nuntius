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

#import "IRMessageGate.h"

#import "IRByteReader.h"
#import "IRMessageHeader+Internal.h"

/*
 ONE FUNCTION PER GATE ROW.

 Each check below is a separate, named, numbered function, and each gate is a straight-line sequence
 of calls in the specified order. Nothing is folded together for brevity and nothing is hoisted for
 efficiency, because the ORDER is the specification: §15.4 requires an exact error code for inputs
 that are wrong in more than one way, and this implementation generates the frozen vectors (§15.6).
 A reordering here would not produce a bug that a round-trip test can see — it would produce a
 conformance suite that legitimises the reordering for three other languages.

 THE READER COPIES THE MESSAGE. -[IRByteReader initWithData:] copies so that a caller mutating its
 buffer after submission cannot change what was parsed, which is a TOCTOU defence a parser wants. On
 a 16 MiB message that copy is real, but it is a constant factor on a path that is already linear in
 the message length (ChaCha20-Poly1305 traverses the same bytes), and the alternative — a raw
 `const uint8_t *` with hand-written bounds arithmetic — is exactly the construct §3.3 bans and
 defect 6 came from. If profiling ever justifies it, the fix is a non-copying IRByteReader
 initializer, never a raw pointer here.
*/

#pragma mark - Shared gate rows

/// §10.0 row 1 / §10.1 check 1 / §10.2 check 1 — the length floor.
///
/// `message` is _Nonnull and a nil is NOT folded into this check. §13.4 clause 2: a null reference
/// and a short byte string are different conditions with different remedies, and reporting the
/// former as ERR_TRUNCATED_MESSAGE sends a developer looking for a truncation that does not exist —
/// the identical complaint §19.8 raises about the entry-point mismatch. A zero-length NSData that
/// really exists still lands here, which is the case §12.4's fuzz corpus and `NEG-BUNDLE-EMPTY`
/// cover.
static BOOL IRGateCheckLengthFloor(NSData * _Nonnull message,
                                   NSUInteger minimum,
                                   NSError * _Nullable * _Nullable error) {
    IRRequireArgument(message);

    if (message.length < minimum) {
        IRSetError(error, IRErrorTruncatedMessage);
        return NO;
    }

    return YES;
}

/// §10.1 check 2 / §10.2 check 2 — the length cap. §10.4: "Bounds MUST be checked before any
/// allocation sized from the input."
static BOOL IRGateCheckLengthCap(NSData * _Nonnull message,
                                 NSUInteger maximum,
                                 NSError * _Nullable * _Nullable error) {
    if (message.length > maximum) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return NO;
    }

    return YES;
}

/// §10.1 check 3 / §10.2 check 3 — `msg[0] == 0x04`. This is also §10.6 in its entirety: a v3
/// message begins with `0x03` and dies here. There is no downgrade path and no dual-stack mode.
static BOOL IRGateCheckVersion(IRByteReader * _Nonnull reader,
                               NSUInteger versionOffset,
                               NSError * _Nullable * _Nullable error) {
    uint8_t version = 0;
    if (![reader readUInt8:&version atOffset:versionOffset] || version != kIRProtocolVersion) {
        IRSetError(error, IRErrorUnsupportedVersion);
        return NO;
    }

    return YES;
}

/// §10.1 check 4 / §10.2 check 4 — `msg[1]` is the expected type. §9.3: every other value,
/// including v3's `0x03` "simple" format, is ERR_UNKNOWN_MESSAGE_TYPE.
static BOOL IRGateCheckType(IRByteReader * _Nonnull reader,
                            NSUInteger typeOffset,
                            IRMessageType expectedType,
                            NSError * _Nullable * _Nullable error) {
    uint8_t type = 0;
    if (![reader readUInt8:&type atOffset:typeOffset] || type != (uint8_t)expectedType) {
        IRSetError(error, IRErrorUnknownMessageType);
        return NO;
    }

    return YES;
}

/// §10.1 check 5 / §10.2 check 5 — `msg[2..4) == 0x0000`, reserved.
///
/// The flags are inside the AD (§8.5), so they are cryptographically enforced as well as checked
/// here. This check exists so that the failure is a clean ERR_RESERVED_FLAGS_SET rather than an
/// ERR_AEAD_AUTH_FAILED that says nothing about what went wrong.
static BOOL IRGateCheckFlags(IRByteReader * _Nonnull reader,
                             NSUInteger flagsOffset,
                             NSError * _Nullable * _Nullable error) {
    uint16_t flags = 0;
    if (![reader readUInt16BE:&flags atOffset:flagsOffset] || flags != 0x0000) {
        IRSetError(error, IRErrorReservedFlagsSet);
        return NO;
    }

    return YES;
}

/// §4.4 checks 1–2 over a 32-byte field at a compile-time offset. Check 1 (the length) is
/// structural: the offset and width are constants and the buffer's extent was fixed by check 1 of
/// the gate. Check 2 (the high bit) is IRX25519Public's constructor, so there is exactly one
/// implementation of it in the framework.
static IRX25519Public * _Nullable IRGateReadX25519PublicAtOffset(IRByteReader * _Nonnull reader,
                                                                 NSUInteger offset,
                                                                 NSError * _Nullable * _Nullable error) {
    const uint8_t *bytes = [reader bytesAtOffset:offset length:kIRLenX25519Public];
    if (bytes == NULL) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [IRX25519Public fromBytes:bytes error:error];
}

/// A `uint32_be` bounded by §10.5 code 7112's domain — `N` and `PN` are capped at 0x7FFFFFFF so
/// that no counter arithmetic downstream can overflow a signed 32-bit type, which is what the JVM
/// and Swift ports have (§16.3, §16.4).
static BOOL IRGateReadBoundedCounter(IRByteReader * _Nonnull reader,
                                     NSUInteger offset,
                                     uint32_t * _Nonnull outValue,
                                     NSError * _Nullable * _Nullable error) {
    uint32_t value = 0;
    if (![reader readUInt32BE:&value atOffset:offset]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return NO;
    }

    if (value > (uint32_t)kIRMaxCounter) {
        IRSetError(error, IRErrorCounterOverflow);
        return NO;
    }

    *outValue = value;
    return YES;
}

@implementation IRMessageGate

#pragma mark - §10.0 — entry-point demultiplex

+ (IRMessageType)messageTypeOfMessage:(NSData * _Nonnull)message
                                error:(NSError * _Nullable * _Nullable)error {
    /* §10.0 row 1 — the GLOBAL floor. 72 is check 1 of BOTH gates, so no message that fails it
       could have reached either gate's check 4. Emitting ERR_UNKNOWN_MESSAGE_TYPE for a 3-byte
       input would contradict §10.1 and §10.2 simultaneously — and reading msg[0..2) before this
       floor is the out-of-bounds class §10.3 documents. */
    if (!IRGateCheckLengthFloor(message, (NSUInteger)kIRLenMessageMin, error)) {
        return (IRMessageType)0;
    }

    /* §10.0 row 2 — the LOOSER of the two caps. The tighter type `0x01` bound is that gate's own
       check 2 and is applied there, at its specified position — not here, where it would fire on a
       large type `0x02` message and return a correct-looking code for the wrong reason. */
    if (!IRGateCheckLengthCap(message, (NSUInteger)kIRLenMessageMax, error)) {
        return (IRMessageType)0;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    /* §10.0 ROW 3 — VERSION, BEFORE THE TYPE IS READ. This is §10.6 in its entirety: a v3 message
       dies here, before any type-dependent length floor, so the rejection is unconditional on
       length. Dispatching on msg[1] first — which is what this method used to do — let a 100-byte
       v3 message with msg[1] == 0x02 route as a prekey message and then hit §10.2's 241-byte
       floor, returning ERR_TRUNCATED_MESSAGE and making §10.6 false as written for every v3 input
       below the invoked gate's floor. `NEG-VERSION-SHORT` is the vector. */
    if (!IRGateCheckVersion(reader, (NSUInteger)kIROffType01Version, error)) {
        return (IRMessageType)0;
    }

    /* §10.0 row 4 — the type domain. */
    uint8_t type = 0;
    if (![reader readUInt8:&type atOffset:(NSUInteger)kIROffType01Type]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return (IRMessageType)0;
    }

    if (type == (uint8_t)IRMessageTypeNormal) {
        return IRMessageTypeNormal;
    }

    if (type == (uint8_t)IRMessageTypePrekey) {
        return IRMessageTypePrekey;
    }

    IRSetError(error, IRErrorUnknownMessageType);
    return (IRMessageType)0;
}

+ (BOOL)demultiplexMessage:(NSData * _Nonnull)message
              expectedType:(IRMessageType)expectedType
                     error:(NSError * _Nullable * _Nullable)error {
    /* §10.0 rows 1-4. */
    IRMessageType actual = [self messageTypeOfMessage:message error:error];
    if (actual == (IRMessageType)0) {
        return NO;   /* the router has already set the length, version or type code */
    }

    /* §10.0 ROW 5 — the entry-point match, and the whole reason this method exists rather than the
       gate's own floor running first. 7125, not 7101: byte 1 IS a valid type here, so 7101's
       predicate over the message alone does not describe the condition (§19.8).

       A REJECTION, NEVER A REDIRECT. Forwarding to the other entry point would put a type `0x01`
       through the self-routing prekey path, which takes no handle — §11.5 rule 1. */
    if (actual != expectedType) {
        IRSetError(error, IRErrorWrongEntryPoint);
        return NO;
    }

    return YES;
}

#pragma mark - Type 0x01

+ (BOOL)gateType01Prefix:(NSData * _Nonnull)message
                   error:(NSError * _Nullable * _Nullable)error {
    /* §10.1 check 1 */
    if (!IRGateCheckLengthFloor(message, (NSUInteger)kIRLenType01Min, error)) {
        return NO;
    }

    /* §10.1 check 2 */
    if (!IRGateCheckLengthCap(message, (NSUInteger)kIRLenType01Max, error)) {
        return NO;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    /* §10.1 check 3 */
    if (!IRGateCheckVersion(reader, (NSUInteger)kIROffType01Version, error)) {
        return NO;
    }

    /* §10.1 check 4 */
    if (!IRGateCheckType(reader, (NSUInteger)kIROffType01Type, IRMessageTypeNormal, error)) {
        return NO;
    }

    /* §10.1 check 5 */
    if (!IRGateCheckFlags(reader, (NSUInteger)kIROffType01Flags, error)) {
        return NO;
    }

    /* §10.1 check 6 — the caller's. See decision D1 and this class's REQUIRED CALL SEQUENCE. */
    return YES;
}

+ (IRMessageHeader * _Nullable)parseType01Message:(NSData * _Nonnull)message
                              ownRatchetPublicKey:(IRX25519Public * _Nonnull)ownRatchetPublicKey
                                            error:(NSError * _Nullable * _Nullable)error {
    /* §10.1 checks 1–5, re-run. Pure, idempotent, five bytes. Paying for them twice is what keeps
       check 6 in its specified position between them and check 7 (decision D1). */
    if (![self gateType01Prefix:message error:error]) {
        return nil;
    }

    /* Check 8 compares against this key, so its absence is not a condition this gate can recover
       from — a nil here means the caller skipped check 6 and has no session. */
    if (ownRatchetPublicKey == nil || ownRatchetPublicKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorNoSession);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    /* §10.1 check 7 — DHs_pub passes §4.4 checks 1–2. */
    IRX25519Public *ratchetKey = IRGateReadX25519PublicAtOffset(reader,
                                                                (NSUInteger)kIROffType01DHs,
                                                                error);
    if (ratchetKey == nil) {
        return nil;
    }

    /* §10.1 check 8 — anti-reflection against OUR OWN ratchet public.
       Both operands are public keys, so this branches on nothing secret and the §10.1 invariant
       ("steps 1–10 touch no secret and branch on no secret") survives. Reflecting our own DHs back
       at us would drive a DH ratchet against a key we hold the private half of. */
    if ([ratchetKey isEqualToX25519Public:ownRatchetPublicKey]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* §10.1 check 9 */
    uint32_t N = 0;
    if (!IRGateReadBoundedCounter(reader, (NSUInteger)kIROffType01N, &N, error)) {
        return nil;
    }

    /* §10.1 check 10 */
    uint32_t PN = 0;
    if (!IRGateReadBoundedCounter(reader, (NSUInteger)kIROffType01PN, &PN, error)) {
        return nil;
    }

    IRNonce *nonce = [IRNonce fromData:[reader dataAtOffset:(NSUInteger)kIROffType01Nonce
                                                     length:(NSUInteger)kIRLenNonce]
                                 error:error];
    if (nonce == nil) {
        return nil;
    }

    /* §8.5 — the verbatim header slice, retained rather than rebuilt. */
    NSData *headerBytes = [reader dataAtOffset:0 length:(NSUInteger)kIRLenType01Header];
    if (headerBytes == nil) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    return [IRMessageHeader type01HeaderWithHeaderBytes:headerBytes
                                             ratchetKey:ratchetKey
                                                      N:N
                                                     PN:PN
                                                  nonce:nonce
                                                  error:error];
}

#pragma mark - Type 0x02

+ (IRMessageHeader * _Nullable)parseType02Message:(NSData * _Nonnull)message
                                            error:(NSError * _Nullable * _Nullable)error {
    /* §10.2 check 1 */
    if (!IRGateCheckLengthFloor(message, (NSUInteger)kIRLenType02Min, error)) {
        return nil;
    }

    /* §10.2 check 2 */
    if (!IRGateCheckLengthCap(message, (NSUInteger)kIRLenType02Max, error)) {
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    /* §10.2 check 3 */
    if (!IRGateCheckVersion(reader, (NSUInteger)kIROffType02Version, error)) {
        return nil;
    }

    /* §10.2 check 4 */
    if (!IRGateCheckType(reader, (NSUInteger)kIROffType02Type, IRMessageTypePrekey, error)) {
        return nil;
    }

    /* §10.2 check 5 */
    if (!IRGateCheckFlags(reader, (NSUInteger)kIROffType02Flags, error)) {
        return nil;
    }

    /* §10.2 check 6 — `opk_flag = msg[168]` is exactly 0x00 or 0x01.
       §9.2: "any other value -> reject". This runs at offset 168 BEFORE anything at offset 4 is
       looked at; the gate is not in layout order and must not be reordered into it. */
    uint8_t opkFlagByte = 0;
    if (![reader readUInt8:&opkFlagByte atOffset:(NSUInteger)kIROffType02OPKFlag]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    if (opkFlagByte != (uint8_t)IROPKFlagAbsent && opkFlagByte != (uint8_t)IROPKFlagPresent) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    IROPKFlag opkFlag = (IROPKFlag)opkFlagByte;

    /* §10.2 check 7 — `opk_flag == 0x00` implies `opk_id == 0`.
       The flag, the id and (in the transcript) the key are one three-part statement; §6.2 hashes
       all three, so a message claiming "no OPK" while naming one would produce a transcript neither
       party can reproduce. Rejecting the encoding is cheaper than discovering it as an AEAD
       failure. Note the converse is NOT checked: `opk_flag == 0x01` with `opk_id == 0` is a legal
       encoding, because 0 is a permissible one-time prekey id and §10.7 step 7 resolves it. */
    uint32_t opkId = 0;
    if (![reader readUInt32BE:&opkId atOffset:(NSUInteger)kIROffType02OPKId]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    if (opkFlag == IROPKFlagAbsent && opkId != 0) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §10.2 check 8 — `PN == 0`, read at offset 209.
       §9.2: "PN is always zero in a type 0x02 header: a fresh session has no previous sending
       chain." This check reads a HIGHER offset than check 9 does, which is the clearest evidence in
       the specification that gate order and layout order are independent. */
    uint32_t PN = 0;
    if (![reader readUInt32BE:&PN atOffset:(NSUInteger)kIROffType02PN]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    if (PN != 0) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §10.2 check 9 — `N <= 0x7FFFFFFF`, read at offset 205.
       §9.2: "N MAY be non-zero in a type 0x02 header." A protocol that pinned it to zero would have
       no legal encoding for A's second message before B has replied, which is the ordinary send
       pattern, so this is a bound and not an equality. */
    uint32_t N = 0;
    if (!IRGateReadBoundedCounter(reader, (NSUInteger)kIROffType02N, &N, error)) {
        return nil;
    }

    /* §10.2 check 10 — IK_A^d, EK_A and DHs_pub each pass §4.4 checks 1–2.
       THREE KEYS, NOT FOUR: `IK_A^s` at offset 4 is Ed25519 and is deliberately excluded. See this
       method's declaration for why applying check 2 to it rejects half of all valid identities. */
    IRX25519Public *initiatorAgreementKey =
        IRGateReadX25519PublicAtOffset(reader, (NSUInteger)kIROffType02IdentityAgreement, error);
    if (initiatorAgreementKey == nil) {
        return nil;
    }

    IRX25519Public *ephemeralPublic =
        IRGateReadX25519PublicAtOffset(reader, (NSUInteger)kIROffType02EK, error);
    if (ephemeralPublic == nil) {
        return nil;
    }

    IRX25519Public *ratchetKey =
        IRGateReadX25519PublicAtOffset(reader, (NSUInteger)kIROffType02DHs, error);
    if (ratchetKey == nil) {
        return nil;
    }

    /* §10.2 check 11 — `DHs_pub != EK_A`, the anti-reflection comparison that CAN live in a gate
       because it compares two fields of the same message and needs no local state.
       §7.5 initializes the initiator's ratchet from a key pair distinct from the X3DH ephemeral; a
       sender that wired one key into both slots would have `DH(EK_A, ·)` and the first ratchet step
       collapse onto the same secret. */
    if ([ratchetKey isEqualToX25519Public:ephemeralPublic]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* Field extraction below this line. Every §10.2 check has passed. */

    /* §9.2 offsets 4 and 36 are `IK_A^s ‖ IK_A^d`, contiguous and in exactly the order §11.1
       indexes on, so the 64 bytes are lifted as one pair rather than reassembled. The X25519 half
       is re-validated by IRIdentityKeyPair's constructor (harmless, already done by check 10); the
       Ed25519 half is deliberately not. */
    const uint8_t *identityBytes = [reader bytesAtOffset:(NSUInteger)kIROffType02IdentitySigning
                                                  length:(NSUInteger)kIRLenIdentityPair];
    if (identityBytes == NULL) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    IRIdentityKeyPair *initiatorIdentity = [IRIdentityKeyPair pairFromBytes:identityBytes
                                                                      error:error];
    if (initiatorIdentity == nil) {
        return nil;
    }

    /* `IKB_A` is CARRIED, NOT VERIFIED. §10.7 step 3 and §11.2 own the verification, both "before
       any DH", and both produce an IRPublicIdentity — the type whose only constructor performs the
       check. A gate that verified here would have to return that type, and §10.2's no-secret prefix
       would have grown a signature verification it does not specify. */
    IREd25519Signature *identityBinding =
        [IREd25519Signature fromData:[reader dataAtOffset:(NSUInteger)kIROffType02IKB
                                                   length:(NSUInteger)kIRLenEd25519Signature]
                               error:error];
    if (identityBinding == nil) {
        return nil;
    }

    uint32_t spkId = 0;
    if (![reader readUInt32BE:&spkId atOffset:(NSUInteger)kIROffType02SPKId]) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    IRNonce *nonce = [IRNonce fromData:[reader dataAtOffset:(NSUInteger)kIROffType02Nonce
                                                     length:(NSUInteger)kIRLenNonce]
                                 error:error];
    if (nonce == nil) {
        return nil;
    }

    /* §8.5 — the verbatim header slice. */
    NSData *headerBytes = [reader dataAtOffset:0 length:(NSUInteger)kIRLenType02Header];
    if (headerBytes == nil) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    return [IRMessageHeader type02HeaderWithHeaderBytes:headerBytes
                                      initiatorIdentity:initiatorIdentity
                                        identityBinding:identityBinding
                                        ephemeralPublic:ephemeralPublic
                                                  spkId:spkId
                                                opkFlag:opkFlag
                                                  opkId:opkId
                                             ratchetKey:ratchetKey
                                                      N:N
                                                  nonce:nonce
                                                  error:error];
}

#pragma mark - Associated data and payload

+ (NSData * _Nullable)associatedDataWithSessionAD:(IRSessionAD * _Nonnull)sessionAD
                                           header:(IRMessageHeader * _Nonnull)header
                                            error:(NSError * _Nullable * _Nullable)error {
    if (sessionAD == nil || header == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §6.5 owns the concatenation; this is a forward, not a second implementation. */
    NSData *associatedData = [sessionAD associatedDataWithHeaderBytes:header.headerBytes
                                                                error:error];
    if (associatedData == nil) {
        return nil;
    }

    /* The cross-check that makes the forward worth having. IRSessionAD derives 197 or 366 from
       `headerBytes.length`; IRMessageHeader derives it from the type byte. Two independent tables
       agreeing is a stronger statement than either one alone, and if they ever diverge the failure
       is here rather than on a peer's machine as ERR_AEAD_AUTH_FAILED. */
    NSUInteger expectedLength = [IRMessageHeader associatedDataLengthForType:header.type];
    if (expectedLength == 0 || associatedData.length != expectedLength) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    return associatedData;
}

+ (NSData * _Nullable)ciphertextAndTagOfMessage:(NSData * _Nonnull)message
                                         header:(IRMessageHeader * _Nonnull)header
                                          error:(NSError * _Nullable * _Nullable)error {
    if (header == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    NSUInteger headerLength = header.headerLength;

    /* Safe to call on a message that never went through a gate: the floor is re-established here.
       §9's minimum totals ARE `headerLength + tag`, so this is the same bound as check 1. */
    if (!IRGateCheckLengthFloor(message, headerLength + (NSUInteger)kIRLenAEADTag, error)) {
        return nil;
    }

    NSUInteger maximum = [IRMessageHeader maximumMessageLengthForType:header.type];
    if (maximum == 0) {
        IRSetError(error, IRErrorUnknownMessageType);
        return nil;
    }

    if (!IRGateCheckLengthCap(message, maximum, error)) {
        return nil;
    }

    /* §9: "the only variable-length region is the ciphertext, whose extent is derived by
       subtraction from the total received length". The subtraction cannot underflow — the floor
       above is exactly `headerLength + 16`. */
    IRByteReader *reader = [[IRByteReader alloc] initWithData:message];

    NSData *ciphertextAndTag = [reader dataAtOffset:headerLength
                                             length:message.length - headerLength];
    if (ciphertextAndTag == nil) {
        IRSetError(error, IRErrorTruncatedMessage);
        return nil;
    }

    return ciphertextAndTag;
}

@end
