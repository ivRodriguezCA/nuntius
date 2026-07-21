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

#import "IRPublicIdentity.h"

#import "IRByteWriter.h"

#pragma mark - IKBIND_MSG

NSData * _Nullable IRIKBindMessage(IRIdentityKeyPair * _Nonnull keyPair,
                                   NSError * _Nullable * _Nullable error) {
    if (keyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenIKBindMsg];
    [writer appendBytes:kIRLabelIKBind length:kIRLenLabelIKBind];
    [writer appendData:keyPair.signingKey.data];
    [writer appendData:keyPair.agreementKey.data];

    /* §5.1 gives an exact total. A field omitted, duplicated or written at the wrong width fails
       here rather than on a peer's machine in another language. */
    return [writer finishExpectingLength:kIRLenIKBindMsg error:error];
}

/// §5.5 — the 77-byte fingerprint input, shared by both callers below.
static NSData * _Nullable IRFingerprintInput(IRIdentityKeyPair * _Nonnull keyPair,
                                             NSError * _Nullable * _Nullable error) {
    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenFPInput];
    [writer appendBytes:kIRLabelFP length:kIRLenLabelFP];
    [writer appendData:keyPair.signingKey.data];
    [writer appendData:keyPair.agreementKey.data];

    return [writer finishExpectingLength:kIRLenFPInput error:error];
}

#pragma mark - IRIdentityKeyPair

@interface IRIdentityKeyPair ()

- (instancetype _Nonnull)initWithSigningKey:(IREd25519Public * _Nonnull)signingKey
                               agreementKey:(IRX25519Public * _Nonnull)agreementKey
                                    rawPair:(NSData * _Nonnull)rawPair;

@end

@implementation IRIdentityKeyPair

+ (instancetype _Nullable)pairWithSigningKey:(IREd25519Public * _Nonnull)signingKey
                                agreementKey:(IRX25519Public * _Nonnull)agreementKey
                                       error:(NSError * _Nullable * _Nullable)error {
    if (signingKey == nil || signingKey.length != kIRLenEd25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (agreementKey == nil || agreementKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    NSMutableData *raw = [NSMutableData dataWithCapacity:kIRLenIdentityPair];
    [raw appendData:signingKey.data];
    [raw appendData:agreementKey.data];

    if (raw.length != kIRLenIdentityPair) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [[self alloc] initWithSigningKey:signingKey agreementKey:agreementKey rawPair:raw];
}

+ (instancetype _Nullable)pairFromBytes:(const uint8_t * _Nonnull)bytes
                                  error:(NSError * _Nullable * _Nullable)error {
    if (bytes == NULL) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IREd25519Public *signingKey = [IREd25519Public fromBytes:bytes error:error];
    if (signingKey == nil) {
        return nil;
    }

    /* §4.4 checks 1–2 are applied to the X25519 half alone, inside IRX25519Public. Applying check 2
       to the Ed25519 half would reject roughly half of all valid identities: there bit 255 is the
       sign of x (RFC 8032 §5.1.2), not a masked u-coordinate bit. */
    IRX25519Public *agreementKey = [IRX25519Public fromBytes:(bytes + kIRLenEd25519Public)
                                                       error:error];
    if (agreementKey == nil) {
        return nil;
    }

    NSData *raw = [NSData dataWithBytes:bytes length:kIRLenIdentityPair];

    return [[self alloc] initWithSigningKey:signingKey agreementKey:agreementKey rawPair:raw];
}

+ (instancetype _Nullable)pairFromData:(NSData * _Nonnull)data
                                 error:(NSError * _Nullable * _Nullable)error {
    if (data == nil || data.length != kIRLenIdentityPair) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [self pairFromBytes:(const uint8_t *)data.bytes error:error];
}

- (instancetype _Nonnull)initWithSigningKey:(IREd25519Public * _Nonnull)signingKey
                               agreementKey:(IRX25519Public * _Nonnull)agreementKey
                                    rawPair:(NSData * _Nonnull)rawPair {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _signingKey = signingKey;
    _agreementKey = agreementKey;
    _rawPair = [rawPair copy];

    return self;
}

- (IRFingerprint * _Nullable)fingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    NSData *input = IRFingerprintInput(self, error);
    if (input == nil) {
        return nil;
    }

    NSData *digest = [provider sha256OfData:input error:error];
    if (digest == nil) {
        return nil;
    }

    return [IRFingerprint fromData:digest error:error];
}

- (BOOL)isEqualToIdentityKeyPair:(IRIdentityKeyPair * _Nullable)other {
    if (other == nil) {
        return NO;
    }

    if (other == self) {
        return YES;
    }

    return [_rawPair isEqualToData:other.rawPair];
}

- (BOOL)isEqual:(id _Nullable)object {
    if (self == object) {
        return YES;
    }

    if (![object isKindOfClass:[IRIdentityKeyPair class]]) {
        return NO;
    }

    return [self isEqualToIdentityKeyPair:(IRIdentityKeyPair *)object];
}

- (NSUInteger)hash {
    /* Over the 64 public bytes, so the value works as an NSDictionary key for §11.1's
       peer-identity-keyed session index. Nothing secret is hashed here — both halves are public. */
    return _rawPair.hash;
}

- (id _Nonnull)copyWithZone:(NSZone * _Nullable)zone {
    /* Immutable, so the copy is the original. Conformance exists because NSDictionary copies its
       keys and §11.1 uses this type as one; without it the insertion raises at runtime with no
       compile-time warning, since the parameter is typed id<NSCopying>. */
    return self;
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; IK^s = %@; IK^d = %@>",
            NSStringFromClass([self class]), (void *)self,
            [_signingKey hexString], [_agreementKey hexString]];
}

@end

#pragma mark - IRPublicIdentity

@interface IRPublicIdentity ()

- (instancetype _Nonnull)initWithKeyPair:(IRIdentityKeyPair * _Nonnull)keyPair
                                 binding:(IREd25519Signature * _Nonnull)binding;

@end

@implementation IRPublicIdentity

+ (instancetype _Nullable)identityWithKeyPair:(IRIdentityKeyPair * _Nonnull)keyPair
                                      binding:(IREd25519Signature * _Nonnull)binding
                                     provider:(id<IRCryptoProvider> _Nonnull)provider
                                        error:(NSError * _Nullable * _Nullable)error {
    if (keyPair == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (binding == nil || binding.length != kIRLenEd25519Signature) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    NSData *message = IRIKBindMessage(keyPair, error);
    if (message == nil) {
        return nil;
    }

    /* §5.5: verified on EVERY ingest — bundle, type 0x02 header, cached contact record, and after
       state restore. Placing the check in the only constructor is what makes "every" mechanical
       rather than a matter of remembering four call sites. */
    if (![provider ed25519VerifySignature:binding ofMessage:message publicKey:keyPair.signingKey]) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    return [[self alloc] initWithKeyPair:keyPair binding:binding];
}

- (instancetype _Nonnull)initWithKeyPair:(IRIdentityKeyPair * _Nonnull)keyPair
                                 binding:(IREd25519Signature * _Nonnull)binding {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _keyPair = keyPair;
    _binding = binding;

    return self;
}

- (IREd25519Public * _Nonnull)signingKey {
    return _keyPair.signingKey;
}

- (IRX25519Public * _Nonnull)agreementKey {
    return _keyPair.agreementKey;
}

- (IRFingerprint * _Nullable)fingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error {
    return [_keyPair fingerprintWithProvider:provider error:error];
}

- (BOOL)isEqualToPublicIdentity:(IRPublicIdentity * _Nullable)other {
    if (other == nil) {
        return NO;
    }

    if (other == self) {
        return YES;
    }

    return [_keyPair isEqualToIdentityKeyPair:other.keyPair];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; keyPair = %@>",
            NSStringFromClass([self class]), (void *)self, _keyPair];
}

@end
