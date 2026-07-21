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

#import "IRSessionAD.h"

#import "IRByteReader.h"
#import "IRByteWriter.h"
#import "IRSodium.h"

@interface IRSessionAD ()

- (instancetype _Nonnull)initWithBytes:(NSData * _Nonnull)bytes
                     initiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                     responderIdentity:(IRIdentityKeyPair * _Nonnull)responderIdentity;

@end

@implementation IRSessionAD

+ (instancetype _Nullable)adWithInitiator:(IRIdentityKeyPair * _Nonnull)initiator
                                responder:(IRIdentityKeyPair * _Nonnull)responder
                                    error:(NSError * _Nullable * _Nullable)error {
    if (initiator == nil || responder == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSessionAD];

    [writer appendBytes:kIRLabelAD length:kIRLenLabelAD];
    [writer appendData:initiator.signingKey.data];
    [writer appendData:initiator.agreementKey.data];
    [writer appendData:responder.signingKey.data];
    [writer appendData:responder.agreementKey.data];

    NSData *bytes = [writer finishExpectingLength:kIRLenSessionAD error:error];
    if (bytes == nil) {
        return nil;
    }

    return [[self alloc] initWithBytes:bytes
                     initiatorIdentity:initiator
                     responderIdentity:responder];
}

+ (instancetype _Nullable)adFromStoredBytes:(NSData * _Nonnull)bytes
                                      error:(NSError * _Nullable * _Nullable)error {
    if (bytes == nil || bytes.length != kIRLenSessionAD) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:bytes];

    if (![reader matchLiteral:kIRLabelAD length:kIRLenLabelAD]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    const uint8_t *raw = [reader constBytes];
    if (raw == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §12.2 rule 7 in its own words, applied to the two X25519 halves and to neither Ed25519 half.
       Run BEFORE construction so the nominal type's IRErrorInvalidPublicKey never surfaces from a
       state-blob parse — §15.4 makes the exact code a conformance requirement. */
    if (![IRX25519Public highBitIsClear:(raw + kIROffSessionADInitiatorAgreement)] ||
        ![IRX25519Public highBitIsClear:(raw + kIROffSessionADResponderAgreement)]) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSError *inner = nil;

    IRIdentityKeyPair *initiator =
        [IRIdentityKeyPair pairFromBytes:(raw + kIROffSessionADInitiatorPair) error:&inner];
    if (initiator == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, inner);
        return nil;
    }

    IRIdentityKeyPair *responder =
        [IRIdentityKeyPair pairFromBytes:(raw + kIROffSessionADResponderPair) error:&inner];
    if (responder == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, inner);
        return nil;
    }

    return [[self alloc] initWithBytes:bytes
                     initiatorIdentity:initiator
                     responderIdentity:responder];
}

- (instancetype _Nonnull)initWithBytes:(NSData * _Nonnull)bytes
                     initiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                     responderIdentity:(IRIdentityKeyPair * _Nonnull)responderIdentity {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _bytes = [bytes copy];
    _initiatorIdentity = initiatorIdentity;
    _responderIdentity = responderIdentity;

    return self;
}

- (IRIdentityKeyPair * _Nullable)peerIdentityForRole:(IRSessionRole)role {
    switch (role) {
        case IRSessionRoleInitiator:
            return _responderIdentity;
        case IRSessionRoleResponder:
            return _initiatorIdentity;
    }

    return nil;
}

- (IRIdentityKeyPair * _Nullable)ownIdentityForRole:(IRSessionRole)role {
    switch (role) {
        case IRSessionRoleInitiator:
            return _initiatorIdentity;
        case IRSessionRoleResponder:
            return _responderIdentity;
    }

    return nil;
}

- (NSData * _Nullable)associatedDataWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                              error:(NSError * _Nullable * _Nullable)error {
    if (headerBytes == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    NSUInteger expected = 0;
    if (headerBytes.length == kIRLenType01Header) {
        expected = kIRLenType01AD;
    } else if (headerBytes.length == kIRLenType02Header) {
        expected = kIRLenType02AD;
    } else {
        /* §9: header length is a constant determined SOLELY by the type byte, never by anything on
           the wire. Any other width means a caller assembled a header this protocol has no encoding
           for. */
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:expected];
    [writer appendData:_bytes];
    [writer appendData:headerBytes];

    return [writer finishExpectingLength:expected
                      mismatchErrorCode:IRErrorMalformedHeader
                                  error:error];
}

- (BOOL)isEqualToSessionAD:(IRSessionAD * _Nullable)other {
    if (other == nil) {
        return NO;
    }

    if (other == self) {
        return YES;
    }

    if (other.bytes.length != _bytes.length) {
        return NO;
    }

    /* Constant time. These bytes are public, so this is not a secrecy requirement — it is here
       because §11.2's identity comparison and §11.5's session selection both run over this value on
       an attacker-supplied path, and a timing-variable comparison there is a free oracle for how
       many leading bytes of an identity an attacker has guessed. */
    return IRConstantTimeEquals(_bytes.bytes, other.bytes.bytes, _bytes.length);
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; A = %@; B = %@>",
            NSStringFromClass([self class]), (void *)self, _initiatorIdentity, _responderIdentity];
}

@end
