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

#import "IRPreKeyRecords.h"

#import "IRByteWriter.h"
#import "IRProtocolConstants.h"

#pragma mark - SPK_SIGN_MSG

NSData * _Nullable IRSPKSignMessage(IRIdentityKeyPair * _Nonnull identity,
                                    uint32_t spkId,
                                    IRX25519Public * _Nonnull signedPreKey,
                                    uint64_t notBeforeS,
                                    uint64_t notAfterS,
                                    NSError * _Nullable * _Nullable error) {
    if (identity == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (signedPreKey == nil || signedPreKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenSPKSignMsg];
    [writer appendBytes:kIRLabelSPK length:kIRLenLabelSPK];
    [writer appendData:identity.signingKey.data];
    [writer appendData:identity.agreementKey.data];
    [writer appendUInt32BE:spkId];
    [writer appendData:signedPreKey.data];
    [writer appendUInt64BE:notBeforeS];
    [writer appendUInt64BE:notAfterS];

    return [writer finishExpectingLength:kIRLenSPKSignMsg error:error];
}

#pragma mark - IRSignedPreKeyRecord

@interface IRSignedPreKeyRecord ()

- (instancetype _Nonnull)initWithSpkId:(uint32_t)spkId
                               keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                            notBeforeS:(uint64_t)notBeforeS
                             notAfterS:(uint64_t)notAfterS
                             signature:(IREd25519Signature * _Nonnull)signature;

@end

@implementation IRSignedPreKeyRecord

+ (instancetype _Nullable)generateWithIdentity:(IRIdentity * _Nonnull)identity
                                         spkId:(uint32_t)spkId
                                    notBeforeS:(uint64_t)notBeforeS
                                     notAfterS:(uint64_t)notAfterS
                                      provider:(id<IRCryptoProvider> _Nonnull)provider
                                         error:(NSError * _Nullable * _Nullable)error {
    if (identity == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §13.3 retains this private for the rotation period plus one generation; guarded. */
    IRX25519KeyPair *keyPair = [provider generateX25519KeyPairGuarded:YES error:error];
    if (keyPair == nil) {
        return nil;
    }

    NSData *message = IRSPKSignMessage(identity.identityKeyPair,
                                       spkId,
                                       keyPair.publicKey,
                                       notBeforeS,
                                       notAfterS,
                                       error);
    if (message == nil) {
        return nil;
    }

    IREd25519Signature *signature = [identity signData:message error:error];
    if (signature == nil) {
        return nil;
    }

    return [self recordWithSpkId:spkId
                         keyPair:keyPair
                      notBeforeS:notBeforeS
                       notAfterS:notAfterS
                       signature:signature
                           error:error];
}

+ (instancetype _Nullable)recordWithSpkId:(uint32_t)spkId
                                  keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                               notBeforeS:(uint64_t)notBeforeS
                                notAfterS:(uint64_t)notAfterS
                                signature:(IREd25519Signature * _Nonnull)signature
                                    error:(NSError * _Nullable * _Nullable)error {
    if (keyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (signature == nil || signature.length != kIRLenEd25519Signature) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    return [[self alloc] initWithSpkId:spkId
                               keyPair:keyPair
                            notBeforeS:notBeforeS
                             notAfterS:notAfterS
                             signature:signature];
}

- (instancetype _Nonnull)initWithSpkId:(uint32_t)spkId
                               keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                            notBeforeS:(uint64_t)notBeforeS
                             notAfterS:(uint64_t)notAfterS
                             signature:(IREd25519Signature * _Nonnull)signature {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _spkId = spkId;
    _keyPair = keyPair;
    _notBeforeS = notBeforeS;
    _notAfterS = notAfterS;
    _signature = signature;

    return self;
}

- (BOOL)isExpiredAtUnixSeconds:(uint64_t)nowS {
    /* §5.3 rule 5 makes the window half-open — `not_before <= now < not_after` — so `now` exactly
       at `not_after` is already outside it. */
    return nowS >= _notAfterS;
}

- (void)zeroize {
    [_keyPair zeroize];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; spk_id = %u; SPK = %@; window = [%llu, %llu)>",
            NSStringFromClass([self class]), (void *)self, _spkId,
            [_keyPair.publicKey hexString],
            (unsigned long long)_notBeforeS, (unsigned long long)_notAfterS];
}

@end

#pragma mark - IROneTimePreKeyRecord

@interface IROneTimePreKeyRecord ()

- (instancetype _Nonnull)initWithOpkId:(uint32_t)opkId
                               keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                     createdAtUnixSecs:(uint64_t)createdAtUnixSecs;

@end

@implementation IROneTimePreKeyRecord

+ (instancetype _Nullable)generateWithOpkId:(uint32_t)opkId
                          createdAtUnixSecs:(uint64_t)createdAtUnixSecs
                                   provider:(id<IRCryptoProvider> _Nonnull)provider
                                      error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    IRX25519KeyPair *keyPair = [provider generateX25519KeyPairGuarded:YES error:error];
    if (keyPair == nil) {
        return nil;
    }

    return [self recordWithOpkId:opkId
                         keyPair:keyPair
               createdAtUnixSecs:createdAtUnixSecs
                           error:error];
}

+ (instancetype _Nullable)recordWithOpkId:(uint32_t)opkId
                                  keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                        createdAtUnixSecs:(uint64_t)createdAtUnixSecs
                                    error:(NSError * _Nullable * _Nullable)error {
    if (keyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [[self alloc] initWithOpkId:opkId
                              keyPair:keyPair
                    createdAtUnixSecs:createdAtUnixSecs];
}

- (instancetype _Nonnull)initWithOpkId:(uint32_t)opkId
                               keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                     createdAtUnixSecs:(uint64_t)createdAtUnixSecs {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _opkId = opkId;
    _keyPair = keyPair;
    _createdAtUnixSecs = createdAtUnixSecs;

    return self;
}

- (BOOL)isExpiredAtUnixSeconds:(uint64_t)nowS {
    if (nowS < _createdAtUnixSecs) {
        /* A clock earlier than creation is a rollback, not an age of ~2^64 seconds. Subtracting
           would wrap and expire every key in the store. */
        return NO;
    }

    return (nowS - _createdAtUnixSecs) >= (uint64_t)kIROPKMaxAgeSeconds;
}

- (void)zeroize {
    [_keyPair zeroize];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; opk_id = %u; OPK = %@; created = %llu>",
            NSStringFromClass([self class]), (void *)self, _opkId,
            [_keyPair.publicKey hexString], (unsigned long long)_createdAtUnixSecs];
}

@end
