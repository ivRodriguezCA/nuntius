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

#import "IRMessageHeader+Internal.h"

#import "IRX3DH.h"

@implementation IRMessageHeader {
    IRMessageType _type;
    NSUInteger _headerLength;
    IRX25519Public *_ratchetKey;
    uint32_t _N;
    uint32_t _PN;
    IRNonce *_nonce;
    NSData *_headerBytes;

    IRIdentityKeyPair *_initiatorIdentity;
    IREd25519Signature *_identityBinding;
    IRX25519Public *_ephemeralPublic;
    uint32_t _spkId;
    IROPKFlag _opkFlag;
    uint32_t _opkId;
    NSData *_handshakeId;
}

#pragma mark - Type-derived constants

/* §9: "Header length is a constant determined SOLELY by the 1-byte type field at offset 1." These
   four tables are the single place that mapping exists. A gate that inlined `56` would be one
   edit away from disagreeing with the AD length that must accompany it. */

+ (NSUInteger)headerLengthForType:(IRMessageType)type {
    switch (type) {
        case IRMessageTypeNormal:
            return kIRLenType01Header;
        case IRMessageTypePrekey:
            return kIRLenType02Header;
    }

    /* §9.3: there is no type 0x03, and no default row anywhere in this framework returns a length
       for one. The switch is exhaustive over IRMessageType, so a future type added to the enum
       fails to compile here rather than silently inheriting a length. */
    return 0;
}

+ (NSUInteger)associatedDataLengthForType:(IRMessageType)type {
    switch (type) {
        case IRMessageTypeNormal:
            return kIRLenType01AD;
        case IRMessageTypePrekey:
            return kIRLenType02AD;
    }

    return 0;
}

+ (NSUInteger)minimumMessageLengthForType:(IRMessageType)type {
    switch (type) {
        case IRMessageTypeNormal:
            return kIRLenType01Min;
        case IRMessageTypePrekey:
            return kIRLenType02Min;
    }

    return 0;
}

+ (NSUInteger)maximumMessageLengthForType:(IRMessageType)type {
    switch (type) {
        case IRMessageTypeNormal:
            return kIRLenType01Max;
        case IRMessageTypePrekey:
            return kIRLenType02Max;
    }

    return 0;
}

#pragma mark - Construction

- (instancetype _Nullable)initWithType:(IRMessageType)type
                           headerBytes:(NSData * _Nonnull)headerBytes
                            ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                     N:(uint32_t)N
                                    PN:(uint32_t)PN
                                 nonce:(IRNonce * _Nonnull)nonce
                                 error:(NSError * _Nullable * _Nullable)error {
    NSUInteger expectedLength = [IRMessageHeader headerLengthForType:type];
    if (expectedLength == 0) {
        IRSetError(error, IRErrorUnknownMessageType);
        return nil;
    }

    /* §8.5's contract in one assertion: whatever the gate hands over IS the header, so its extent
       must be the extent the type dictates. A short slice here would silently shorten every AD in
       the session. */
    if (headerBytes == nil || headerBytes.length != expectedLength) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    if (ratchetKey == nil || ratchetKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (nonce == nil || nonce.length != kIRLenNonce) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §10.1 checks 9–10 in the gates; repeated here because this object's whole value to the
       ratchet is that its fields are already inside their domains. */
    if (N > (uint32_t)kIRMaxCounter || PN > (uint32_t)kIRMaxCounter) {
        IRSetError(error, IRErrorCounterOverflow);
        return nil;
    }

    self = [super init];
    if (self == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    _type = type;
    _headerLength = expectedLength;
    _headerBytes = [headerBytes copy];
    _ratchetKey = ratchetKey;
    _N = N;
    _PN = PN;
    _nonce = nonce;

    return self;
}

+ (instancetype _Nullable)type01HeaderWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                           ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                                    N:(uint32_t)N
                                                   PN:(uint32_t)PN
                                                nonce:(IRNonce * _Nonnull)nonce
                                                error:(NSError * _Nullable * _Nullable)error {
    return [[self alloc] initWithType:IRMessageTypeNormal
                          headerBytes:headerBytes
                           ratchetKey:ratchetKey
                                    N:N
                                   PN:PN
                                nonce:nonce
                                error:error];
}

+ (instancetype _Nullable)type02HeaderWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                    initiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                                      identityBinding:(IREd25519Signature * _Nonnull)identityBinding
                                      ephemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                                spkId:(uint32_t)spkId
                                              opkFlag:(IROPKFlag)opkFlag
                                                opkId:(uint32_t)opkId
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

    if (ephemeralPublic == nil || ephemeralPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* §10.2 checks 6 and 7 in the gate; the backstop here means a gate that dropped either one
       yields nil rather than a header whose flag/id triple disagrees with itself — the exact
       inconsistency IRTranscript would then bake into a transcript nobody can reproduce. */
    if (opkFlag != IROPKFlagAbsent && opkFlag != IROPKFlagPresent) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    if (opkFlag == IROPKFlagAbsent && opkId != 0) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §9.2: PN is always zero on this type, so it is passed as a literal rather than accepted as a
       parameter. §10.2 check 8 has already rejected any message claiming otherwise. */
    IRMessageHeader *header = [[self alloc] initWithType:IRMessageTypePrekey
                                             headerBytes:headerBytes
                                              ratchetKey:ratchetKey
                                                       N:N
                                                      PN:0
                                                   nonce:nonce
                                                   error:error];
    if (header == nil) {
        return nil;
    }

    /* §11.1 — one definition of `IK_A^d ‖ EK_A` in the framework, in IRX3DH where §11.1 put it. */
    NSData *handshakeId = IRHandshakeIdentifier(initiatorIdentity.agreementKey, ephemeralPublic, error);
    if (handshakeId == nil) {
        return nil;
    }

    header->_initiatorIdentity = initiatorIdentity;
    header->_identityBinding = identityBinding;
    header->_ephemeralPublic = ephemeralPublic;
    header->_spkId = spkId;
    header->_opkFlag = opkFlag;
    header->_opkId = opkId;
    header->_handshakeId = handshakeId;

    return header;
}

#pragma mark - Accessors

- (IRMessageType)type {
    return _type;
}

- (NSUInteger)headerLength {
    return _headerLength;
}

- (IRX25519Public * _Nonnull)ratchetKey {
    return _ratchetKey;
}

- (uint32_t)N {
    return _N;
}

- (uint32_t)PN {
    return _PN;
}

- (IRNonce * _Nonnull)nonce {
    return _nonce;
}

- (NSData * _Nonnull)headerBytes {
    return _headerBytes;
}

- (BOOL)isPreKeyMessage {
    return (_type == IRMessageTypePrekey);
}

- (IRIdentityKeyPair * _Nullable)initiatorIdentity {
    return _initiatorIdentity;
}

- (IREd25519Signature * _Nullable)identityBinding {
    return _identityBinding;
}

- (IRX25519Public * _Nullable)ephemeralPublic {
    return _ephemeralPublic;
}

- (uint32_t)spkId {
    return _spkId;
}

- (IROPKFlag)opkFlag {
    return _opkFlag;
}

- (uint32_t)opkId {
    return _opkId;
}

- (NSData * _Nullable)handshakeId {
    return _handshakeId;
}

#pragma mark - Description

- (NSString * _Nonnull)description {
    /* Public material only. Every field named here travels in cleartext on the wire; nothing
       secret reaches an IRMessageHeader, so there is no key material to leak into a log. */
    if (self.isPreKeyMessage) {
        return [NSString stringWithFormat:
                @"<IRMessageHeader 0x02 N=%u PN=%u spk_id=%u opk_flag=0x%02x opk_id=%u dh=%@ ek=%@>",
                _N, _PN, _spkId, (unsigned)_opkFlag, _opkId,
                _ratchetKey.hexString, _ephemeralPublic.hexString];
    }

    return [NSString stringWithFormat:@"<IRMessageHeader 0x01 N=%u PN=%u dh=%@>",
            _N, _PN, _ratchetKey.hexString];
}

@end
