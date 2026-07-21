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

#import "IRX3DH.h"

#import "IRByteReader.h"
#import "IRByteWriter.h"
#import "IRProtocolKDF.h"
#import "IRTranscript.h"

#pragma mark - handshake_id

NSData * _Nullable IRHandshakeIdentifier(IRX25519Public * _Nonnull initiatorAgreementKey,
                                         IRX25519Public * _Nonnull ephemeralPublic,
                                         NSError * _Nullable * _Nullable error) {
    if (initiatorAgreementKey == nil || initiatorAgreementKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (ephemeralPublic == nil || ephemeralPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenHandshakeId];
    [writer appendData:initiatorAgreementKey.data];
    [writer appendData:ephemeralPublic.data];

    return [writer finishExpectingLength:kIRLenHandshakeId error:error];
}

#pragma mark - IRSessionPrologue

@interface IRSessionPrologue ()

- (instancetype _Nonnull)initWithEphemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                           spkId:(uint32_t)spkId
                                         opkFlag:(IROPKFlag)opkFlag
                                           opkId:(uint32_t)opkId;

@end

@implementation IRSessionPrologue

+ (instancetype _Nullable)prologueWithEphemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                                spkId:(uint32_t)spkId
                                              opkFlag:(IROPKFlag)opkFlag
                                                opkId:(uint32_t)opkId
                                                error:(NSError * _Nullable * _Nullable)error {
    if (ephemeralPublic == nil || ephemeralPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (opkFlag != IROPKFlagAbsent && opkFlag != IROPKFlagPresent) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §9.2: opk_id MUST be 0x00000000 when opk_flag == 0x00. The prologue is re-emitted verbatim
       into every subsequent type 0x02 header (§11.3), so an inconsistent pair stored here would
       become a header the peer rejects under §10.2 check 7 — caught at the source instead. */
    if (opkFlag == IROPKFlagAbsent && opkId != 0) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    return [[self alloc] initWithEphemeralPublic:ephemeralPublic
                                           spkId:spkId
                                         opkFlag:opkFlag
                                           opkId:opkId];
}

+ (instancetype _Nullable)prologueFromStoredBytes:(NSData * _Nonnull)bytes
                                             error:(NSError * _Nullable * _Nullable)error {
    if (bytes == nil || bytes.length != kIRLenStatePrologue) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:bytes];

    const uint8_t *raw = [reader bytesAtOffset:kIROffPrologueEK length:kIRLenX25519Public];
    if (raw == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §12.2 rule 7 — every stored public key passes §4.4 checks 1–2, reported as ERR_STATE_CORRUPT
       rather than the nominal type's ERR_INVALID_PUBLIC_KEY. */
    if (![IRX25519Public highBitIsClear:raw]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSError *inner = nil;
    IRX25519Public *ephemeralPublic = [IRX25519Public fromBytes:raw error:&inner];
    if (ephemeralPublic == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, inner);
        return nil;
    }

    uint32_t spkId = 0;
    uint8_t opkFlagByte = 0;
    uint32_t opkId = 0;

    if (![reader readUInt32BE:&spkId atOffset:kIROffPrologueSPKId] ||
        ![reader readUInt8:&opkFlagByte atOffset:kIROffPrologueOPKFlag] ||
        ![reader readUInt32BE:&opkId atOffset:kIROffPrologueOPKId]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (opkFlagByte != IROPKFlagAbsent && opkFlagByte != IROPKFlagPresent) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (opkFlagByte == IROPKFlagAbsent && opkId != 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[self alloc] initWithEphemeralPublic:ephemeralPublic
                                           spkId:spkId
                                         opkFlag:(IROPKFlag)opkFlagByte
                                           opkId:opkId];
}

- (instancetype _Nonnull)initWithEphemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                           spkId:(uint32_t)spkId
                                         opkFlag:(IROPKFlag)opkFlag
                                           opkId:(uint32_t)opkId {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _ephemeralPublic = ephemeralPublic;
    _spkId = spkId;
    _opkFlag = opkFlag;
    _opkId = opkId;

    return self;
}

- (NSData * _Nullable)serializedBytes:(NSError * _Nullable * _Nullable)error {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenStatePrologue];

    [writer appendData:_ephemeralPublic.data];
    [writer appendUInt32BE:_spkId];
    [writer appendUInt8:(uint8_t)_opkFlag];
    [writer appendUInt32BE:_opkId];

    return [writer finishExpectingLength:kIRLenStatePrologue error:error];
}

- (BOOL)isEqualToSessionPrologue:(IRSessionPrologue * _Nullable)other {
    if (other == nil) {
        return NO;
    }

    if (other == self) {
        return YES;
    }

    return (_spkId == other.spkId &&
            _opkFlag == other.opkFlag &&
            _opkId == other.opkId &&
            [_ephemeralPublic isEqualToX25519Public:other.ephemeralPublic]);
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; EK_A = %@; spk_id = %u; opk_flag = %u; opk_id = %u>",
            NSStringFromClass([self class]), (void *)self, [_ephemeralPublic hexString],
            (unsigned)_spkId, (unsigned)_opkFlag, (unsigned)_opkId];
}

@end

#pragma mark - IRX3DHResult

@interface IRX3DHResult ()

@property (nonatomic, strong) IRRootKey          * _Nonnull  sharedKey;
@property (nonatomic, strong) IRSessionAD        * _Nonnull  sessionAD;
@property (nonatomic, copy)   NSData             * _Nonnull  handshakeId;
@property (nonatomic)         IRSessionRole                  role;
@property (nonatomic, strong) IRSessionPrologue  * _Nullable prologue;
@property (nonatomic, copy)   NSData             * _Nonnull  transcript;
@property (nonatomic, copy)   NSData             * _Nonnull  transcriptHash;
@property (nonatomic, copy)   NSData             * _Nonnull  x3dhInfo;
@property (nonatomic, strong) IRSecretBytes      * _Nullable ikm;

/// The only initializer. -init is NS_UNAVAILABLE publicly: a result is meaningful only when every
/// field was set by one completed agreement, so nothing outside IRCompleteX3DH may build one.
- (instancetype _Nonnull)initInternal;

@end

@implementation IRX3DHResult

- (instancetype _Nonnull)initInternal {
    return [super init];
}

- (void)zeroize {
    [_sharedKey zeroizeNow];
    [_ikm zeroizeNow];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; role = %u; handshake_id = %@>",
            NSStringFromClass([self class]), (void *)self, (unsigned)_role,
            [_handshakeId description]];
}

@end

/* The four §15.5 intermediates are backed by the class extension above and their accessors are
   auto-synthesized into the primary @implementation. The category is declared in the header purely
   to document that they exist for the conformance runner and for nothing else, so it deliberately
   has no @implementation of its own. */

#pragma mark - The shared tail

/**
 Everything downstream of the four scalar multiplications — §6.2, §6.3, §6.5, §11.1.

 ONE implementation, reached from both directions. §6.1 specifies the responder's DH set as "the
 mirror image, in the identical order", so DH1–DH4 hold the same four values on both sides and every
 byte computed here is identical by construction rather than by two code paths agreeing. Defect 1
 lived precisely in the gap between two such paths.

 Takes ownership of dh1–dh4 and zeroizes all four before returning, on every path.
 */
static IRX3DHResult * _Nullable IRCompleteX3DH(IRIdentityKeyPair * _Nonnull initiatorPair,
                                               IRX25519Public * _Nonnull ephemeralPublic,
                                               IRIdentityKeyPair * _Nonnull responderPair,
                                               IRX25519Public * _Nonnull signedPreKey,
                                               uint32_t spkId,
                                               IROPKFlag opkFlag,
                                               uint32_t opkId,
                                               IRX25519Public * _Nullable oneTimePreKey,
                                               IRSecretBytes * _Nonnull dh1,
                                               IRSecretBytes * _Nonnull dh2,
                                               IRSecretBytes * _Nonnull dh3,
                                               IRSecretBytes * _Nullable dh4,
                                               IRSessionRole role,
                                               IRSessionPrologue * _Nullable prologue,
                                               id<IRCryptoProvider> _Nonnull provider,
                                               BOOL retainIKM,
                                               NSError * _Nullable * _Nullable error) {
    NSUInteger expectedIKMLength =
        (opkFlag == IROPKFlagPresent) ? (NSUInteger)kIRLenIKMOPK : (NSUInteger)kIRLenIKMNoOPK;

    /* §6.3 — IKM = F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4].

       F32 is X3DH §2.2's Curve25519 domain separator. v3 computed this exact constant into a local
       named `separation` and then commented out its use (IRTripleDHService.m:92-93, :112) — the
       intent was there, the wiring was not.

       DH4 IS OMITTED, NOT ZERO-FILLED, when no one-time prekey is used, which is why the two legal
       lengths are 128 and 160 and not one length with a hole in it. The opk_flag inside TH removes
       the ambiguity that omission could otherwise create. Note that this is the OPPOSITE convention
       from §6.2's transcript, where the absent OPK IS written as 32 zero bytes; the two structures
       differ deliberately and a port that unifies them breaks interoperation in one of the two. */
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:expectedIKMLength];
    [writer appendBytes:kIRF32 length:kIRLenF32];
    [writer appendSecretBytes:dh1];
    [writer appendSecretBytes:dh2];
    [writer appendSecretBytes:dh3];

    if (opkFlag == IROPKFlagPresent) {
        [writer appendSecretBytes:dh4];
    }

    IRSecretBytes *ikm = [writer finishSecretExpectingLength:expectedIKMLength
                                                     guarded:NO
                                                       error:error];

    /* §13.3 schedules DH1–DH4 for "immediately after SK is derived". They are wiped here instead —
       the moment their bytes are inside the IKM and nothing further reads them — which is strictly
       earlier than the schedule requires and puts the wipe on one line rather than on every exit
       path below. */
    [dh1 zeroizeNow];
    [dh2 zeroizeNow];
    [dh3 zeroizeNow];
    [dh4 zeroizeNow];

    if (ikm == nil) {
        return nil;
    }

    NSData *transcript = [IRTranscript transcriptWithInitiator:initiatorPair
                                                     ephemeral:ephemeralPublic
                                                     responder:responderPair
                                                  signedPreKey:signedPreKey
                                                         spkId:spkId
                                                       opkFlag:opkFlag
                                                         opkId:opkId
                                                 oneTimePreKey:oneTimePreKey
                                                         error:error];
    if (transcript == nil) {
        [ikm zeroizeNow];
        return nil;
    }

    NSData *transcriptHash = [IRTranscript transcriptHashOf:transcript provider:provider error:error];
    if (transcriptHash == nil) {
        [ikm zeroizeNow];
        return nil;
    }

    NSData *x3dhInfo = [IRTranscript x3dhInfoWithTranscriptHash:transcriptHash error:error];
    if (x3dhInfo == nil) {
        [ikm zeroizeNow];
        return nil;
    }

    /* §6.3 — SK = HKDF(salt = Z32, ikm = IKM, info = "nuntius:X3DH:v4" ‖ TH, L = 32). The length
       assertions §6.3 makes mandatory live inside this call. */
    IRRootKey *sharedKey = [IRProtocolKDF deriveSharedKeyWithIKM:ikm
                                                  transcriptHash:transcriptHash
                                                        provider:provider
                                                           error:error];

    /* §13.3 — "DH1–DH4, IKM: immediately after SK is derived". retainIKM:YES suppresses this one
       wipe for the §15.6 vector generator and is documented as such; no production path passes it. */
    if (!retainIKM) {
        [ikm zeroizeNow];
        ikm = nil;
    }

    if (sharedKey == nil) {
        [ikm zeroizeNow];
        return nil;
    }

    IRSessionAD *sessionAD = [IRSessionAD adWithInitiator:initiatorPair
                                                responder:responderPair
                                                    error:error];
    if (sessionAD == nil) {
        [sharedKey zeroizeNow];
        [ikm zeroizeNow];
        return nil;
    }

    NSData *handshakeId = IRHandshakeIdentifier(initiatorPair.agreementKey, ephemeralPublic, error);
    if (handshakeId == nil) {
        [sharedKey zeroizeNow];
        [ikm zeroizeNow];
        return nil;
    }

    IRX3DHResult *result = [[IRX3DHResult alloc] initInternal];
    result.sharedKey = sharedKey;
    result.sessionAD = sessionAD;
    result.handshakeId = handshakeId;
    result.role = role;
    result.prologue = prologue;
    result.transcript = transcript;
    result.transcriptHash = transcriptHash;
    result.x3dhInfo = x3dhInfo;
    result.ikm = ikm;

    return result;
}

#pragma mark - IRX3DH

@implementation IRX3DH

+ (IRX3DHResult * _Nullable)initiatorResultWithIdentity:(IRIdentity * _Nonnull)identity
                                                 bundle:(IRPreKeyBundle * _Nonnull)bundle
                                       ephemeralKeyPair:(IRX25519KeyPair * _Nonnull)ephemeralKeyPair
                                         nowUnixSeconds:(uint64_t)nowUnixSeconds
                                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                              retainIKM:(BOOL)retainIKM
                                                  error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    if (identity == nil || ephemeralKeyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (bundle == nil) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* §5.3 rules 5 and 6, and they run BEFORE any Diffie-Hellman because §5.3 says "Before
       performing any Diffie-Hellman with a fetched bundle, the initiator MUST, in this order". Rules
       1–4 were discharged by +[IRPreKeyBundle bundleFromData:provider:error:]; holding this bundle
       object is the proof. The parser reads no clock deliberately, so this is the one call site that
       supplies `now`. */
    if (![bundle validateValidityWindowAtUnixSeconds:nowUnixSeconds error:error]) {
        /* The ephemeral is consumed here too. §6.1 gives EK_A one handshake, and a bundle this
           client just rejected is not a reason to keep a scalar it has already committed to a
           specific peer — retrying with the same ephemeral against a second bundle is exactly the
           reuse §6.1 forbids. */
        [ephemeralKeyPair zeroize];
        return nil;
    }

    /* §5.4 — a bundle fetched for a single handshake carries 0 or 1 one-time prekeys and a client
       receiving more MUST use only the first. nil is not an error: opk_flag == 0x00 is a legitimate,
       weaker mode (§6.6) with the replay caveat of §17.3. */
    IRPreKeyBundleOPKEntry *opkEntry = [bundle firstUsableOPKEntry];
    IROPKFlag opkFlag = (opkEntry != nil) ? IROPKFlagPresent : IROPKFlagAbsent;
    uint32_t opkId = (opkEntry != nil) ? opkEntry.opkId : 0;
    IRX25519Public *opkPublic = opkEntry.publicKey;

    IRSessionPrologue *prologue =
        [IRSessionPrologue prologueWithEphemeralPublic:ephemeralKeyPair.publicKey
                                                 spkId:bundle.spkId
                                               opkFlag:opkFlag
                                                 opkId:opkId
                                                 error:error];
    if (prologue == nil) {
        [ephemeralKeyPair zeroize];
        return nil;
    }

    /* §6.1, initiator direction, in the specification's order. Every one of these is checked against
       §4.4 check 3 inside the provider: an all-zero output aborts the whole handshake with
       ERR_SMALL_ORDER_KEY, no session is created, and no OPK is consumed. */
    IRSecretBytes *dh1 = [provider x25519WithPrivateKey:identity.agreementKeyPair.privateKey
                                              publicKey:bundle.signedPreKey
                                                  error:error];
    IRSecretBytes *dh2 = nil;
    IRSecretBytes *dh3 = nil;
    IRSecretBytes *dh4 = nil;

    if (dh1 != nil) {
        dh2 = [provider x25519WithPrivateKey:ephemeralKeyPair.privateKey
                                   publicKey:bundle.identity.agreementKey
                                       error:error];
    }

    if (dh2 != nil) {
        dh3 = [provider x25519WithPrivateKey:ephemeralKeyPair.privateKey
                                   publicKey:bundle.signedPreKey
                                       error:error];
    }

    if (dh3 != nil && opkFlag == IROPKFlagPresent) {
        dh4 = [provider x25519WithPrivateKey:ephemeralKeyPair.privateKey
                                   publicKey:opkPublic
                                       error:error];
    }

    BOOL complete = (dh1 != nil && dh2 != nil && dh3 != nil &&
                     (opkFlag == IROPKFlagAbsent || dh4 != nil));

    IRX3DHResult *result = nil;

    if (complete) {
        result = IRCompleteX3DH(identity.identityKeyPair,
                                ephemeralKeyPair.publicKey,
                                bundle.identity.keyPair,
                                bundle.signedPreKey,
                                bundle.spkId,
                                opkFlag,
                                opkId,
                                opkPublic,
                                dh1, dh2, dh3, dh4,
                                IRSessionRoleInitiator,
                                prologue,
                                provider,
                                retainIKM,
                                error);
    } else {
        [dh1 zeroizeNow];
        [dh2 zeroizeNow];
        [dh3 zeroizeNow];
        [dh4 zeroizeNow];
    }

    /* §13.3 — "EK_A private half: immediately after SK is derived". This method OWNS the ephemeral
       from the moment its arguments validate: §6.1 says EK_A "is used for nothing else", so there is
       no path on which the caller may legitimately reuse it, and wiping on failure too removes the
       tempting retry-with-the-same-ephemeral. The public half survives untouched in
       result.prologue.ephemeralPublic, which is all §11.3 needs. */
    [ephemeralKeyPair zeroize];

    return result;
}

+ (IRX3DHResult * _Nullable)responderResultWithIdentity:(IRIdentity * _Nonnull)identity
                                      initiatorIdentity:(IRPublicIdentity * _Nonnull)initiatorIdentity
                                        ephemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                       signedPreKeyPair:(IRX25519KeyPair * _Nonnull)signedPreKeyPair
                                                  spkId:(uint32_t)spkId
                                                opkFlag:(IROPKFlag)opkFlag
                                                  opkId:(uint32_t)opkId
                                      oneTimePreKeyPair:(IRX25519KeyPair * _Nullable)oneTimePreKeyPair
                                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                              retainIKM:(BOOL)retainIKM
                                                  error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §10.7 step 3 — "Verify IKB_A over IKBIND_MSG(IK_A^s, IK_A^d) → else ERR_BAD_SIGNATURE. Before
       any DH." Discharged by the parameter TYPE: IRPublicIdentity has exactly one constructor and it
       verifies the binding, so an unverified identity cannot reach this method. */
    if (identity == nil || initiatorIdentity == nil || signedPreKeyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (ephemeralPublic == nil || ephemeralPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (opkFlag != IROPKFlagAbsent && opkFlag != IROPKFlagPresent) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    if (opkFlag == IROPKFlagPresent) {
        /* §6.6 rule 2 — "If absent → ERR_UNKNOWN_PREKEY_ID. THERE IS NO FALLBACK TO THE 3-DH
           DERIVATION. Rejecting rather than falling back is what converts OPK consumption into
           replay protection, and it forecloses a downgrade an implementer would otherwise be tempted
           to add." Structural here: with the flag set and no key pair there is no 128-byte IKM this
           method can produce. */
        if (oneTimePreKeyPair == nil) {
            IRSetError(error, IRErrorUnknownPreKeyId);
            return nil;
        }
    } else {
        if (oneTimePreKeyPair != nil || opkId != 0) {
            IRSetError(error, IRErrorMalformedHeader);
            return nil;
        }
    }

    /* §6.1, responder direction — "the mirror image, in the identical order". Same four values as
       the initiator computed, with the private and public halves exchanged. */
    IRSecretBytes *dh1 = [provider x25519WithPrivateKey:signedPreKeyPair.privateKey
                                              publicKey:initiatorIdentity.agreementKey
                                                  error:error];
    IRSecretBytes *dh2 = nil;
    IRSecretBytes *dh3 = nil;
    IRSecretBytes *dh4 = nil;

    if (dh1 != nil) {
        dh2 = [provider x25519WithPrivateKey:identity.agreementKeyPair.privateKey
                                   publicKey:ephemeralPublic
                                       error:error];
    }

    if (dh2 != nil) {
        dh3 = [provider x25519WithPrivateKey:signedPreKeyPair.privateKey
                                   publicKey:ephemeralPublic
                                       error:error];
    }

    if (dh3 != nil && opkFlag == IROPKFlagPresent) {
        dh4 = [provider x25519WithPrivateKey:oneTimePreKeyPair.privateKey
                                   publicKey:ephemeralPublic
                                       error:error];
    }

    if (dh1 == nil || dh2 == nil || dh3 == nil ||
        (opkFlag == IROPKFlagPresent && dh4 == nil)) {
        [dh1 zeroizeNow];
        [dh2 zeroizeNow];
        [dh3 zeroizeNow];
        [dh4 zeroizeNow];
        return nil;
    }

    /* Neither `signedPreKeyPair` nor `oneTimePreKeyPair` is retained, copied or zeroized here. §5.3
       gives SPK_B_priv exclusively to the prekey store; §7.5's session-owned copy is IRRatchet's to
       take; §6.6 step 4's zeroize-then-durably-delete of the OPK happens only after the AEAD
       succeeds, at §10.7 step 14. A responder that wipes the signed prekey here breaks every
       concurrent and future handshake against that spk_id, silently, and then reports
       ERR_AEAD_AUTH_FAILED — misdiagnosing its own key destruction as an active MITM (§7.5). */
    return IRCompleteX3DH(initiatorIdentity.keyPair,
                          ephemeralPublic,
                          identity.identityKeyPair,
                          signedPreKeyPair.publicKey,
                          spkId,
                          opkFlag,
                          opkId,
                          oneTimePreKeyPair.publicKey,
                          dh1, dh2, dh3, dh4,
                          IRSessionRoleResponder,
                          nil,
                          provider,
                          retainIKM,
                          error);
}

@end
