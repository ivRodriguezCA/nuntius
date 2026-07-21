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

#import "IRIdentity.h"

#import "IRSodiumCryptoProvider.h"

@interface IRIdentity ()

@property (nonatomic, strong, readonly) id<IRCryptoProvider> _Nonnull provider;

- (instancetype _Nonnull)initWithSigningKeyPair:(IREd25519KeyPair * _Nonnull)signingKeyPair
                               agreementKeyPair:(IRX25519KeyPair * _Nonnull)agreementKeyPair
                                        binding:(IREd25519Signature * _Nonnull)binding
                                 publicIdentity:(IRPublicIdentity * _Nonnull)publicIdentity
                                       provider:(id<IRCryptoProvider> _Nonnull)provider;

@end

@implementation IRIdentity

#pragma mark - Construction

+ (instancetype _Nullable)generateWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                         error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §13.3 holds both privates for the identity's lifetime, which is exactly the case guarded
       allocation exists for. */
    IREd25519KeyPair *signingKeyPair = [provider generateEd25519KeyPairGuarded:YES error:error];
    if (signingKeyPair == nil) {
        return nil;
    }

    IRX25519KeyPair *agreementKeyPair = [provider generateX25519KeyPairGuarded:YES error:error];
    if (agreementKeyPair == nil) {
        return nil;
    }

    IRIdentityKeyPair *keyPair =
        [IRIdentityKeyPair pairWithSigningKey:signingKeyPair.publicKey
                                 agreementKey:agreementKeyPair.publicKey
                                        error:error];
    if (keyPair == nil) {
        return nil;
    }

    NSData *message = IRIKBindMessage(keyPair, error);
    if (message == nil) {
        return nil;
    }

    IREd25519Signature *binding = [provider ed25519SignMessage:message
                                                      withSeed:signingKeyPair.seed
                                                         error:error];
    if (binding == nil) {
        return nil;
    }

    return [self identityWithSigningKeyPair:signingKeyPair
                           agreementKeyPair:agreementKeyPair
                                    binding:binding
                                   provider:provider
                                      error:error];
}

+ (instancetype _Nullable)generate:(NSError * _Nullable * _Nullable)error {
    IRSodiumCryptoProvider *provider = [IRSodiumCryptoProvider productionProvider:error];
    if (provider == nil) {
        return nil;
    }

    return [self generateWithProvider:provider error:error];
}

+ (instancetype _Nullable)identityWithSigningKeyPair:(IREd25519KeyPair * _Nonnull)signingKeyPair
                                    agreementKeyPair:(IRX25519KeyPair * _Nonnull)agreementKeyPair
                                             binding:(IREd25519Signature * _Nonnull)binding
                                            provider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error {
    if (signingKeyPair == nil || agreementKeyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    IRIdentityKeyPair *keyPair =
        [IRIdentityKeyPair pairWithSigningKey:signingKeyPair.publicKey
                                 agreementKey:agreementKeyPair.publicKey
                                        error:error];
    if (keyPair == nil) {
        return nil;
    }

    /* The verifying constructor IS the check. On the generation path this is a self-test against
       §3.4's prehashed-API trap; on the restore path it is §5.5's "after state restore" ingest. */
    IRPublicIdentity *publicIdentity = [IRPublicIdentity identityWithKeyPair:keyPair
                                                                    binding:binding
                                                                   provider:provider
                                                                      error:error];
    if (publicIdentity == nil) {
        return nil;
    }

    return [[self alloc] initWithSigningKeyPair:signingKeyPair
                               agreementKeyPair:agreementKeyPair
                                        binding:binding
                                 publicIdentity:publicIdentity
                                       provider:provider];
}

- (instancetype _Nonnull)initWithSigningKeyPair:(IREd25519KeyPair * _Nonnull)signingKeyPair
                               agreementKeyPair:(IRX25519KeyPair * _Nonnull)agreementKeyPair
                                        binding:(IREd25519Signature * _Nonnull)binding
                                 publicIdentity:(IRPublicIdentity * _Nonnull)publicIdentity
                                       provider:(id<IRCryptoProvider> _Nonnull)provider {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _signingKeyPair = signingKeyPair;
    _agreementKeyPair = agreementKeyPair;
    _binding = binding;
    _publicIdentity = publicIdentity;
    _provider = provider;

    return self;
}

#pragma mark - Derived values

- (IRIdentityKeyPair * _Nonnull)identityKeyPair {
    return _publicIdentity.keyPair;
}

- (IRFingerprint * _Nullable)fingerprint:(NSError * _Nullable * _Nullable)error {
    return [self.identityKeyPair fingerprintWithProvider:_provider error:error];
}

#pragma mark - Signing

- (IREd25519Signature * _Nullable)signData:(NSData * _Nonnull)data
                                     error:(NSError * _Nullable * _Nullable)error {
    if (data == nil) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    return [_provider ed25519SignMessage:data withSeed:_signingKeyPair.seed error:error];
}

#pragma mark - Zeroization (§13.3)

- (void)zeroize {
    [_signingKeyPair zeroize];
    [_agreementKeyPair zeroize];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; identity = %@>",
            NSStringFromClass([self class]), (void *)self, self.identityKeyPair];
}

@end
