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

#import "IRCurve25519KeyPair.h"
#import "IRConstants.h"
#import <CommonCrypto/CommonCrypto.h>

static NSUInteger const kCurve25519KeyLength = 32;
static NSUInteger const kCurve25519SignatureLength = 64;

@interface IRCurve25519KeyPair ()

@property (nonatomic, strong) NSData * _Nonnull publicKey;
@property (nonatomic, strong) NSData * _Nullable privateKey;
@property (nonatomic, strong) NSData * _Nullable signature;

@end

@implementation IRCurve25519KeyPair

#pragma mark - Public

+ (NSUInteger)keyLength {
    return kCurve25519KeyLength;
}

+ (NSUInteger)signatureLength {
    return kCurve25519SignatureLength;
}

+ (IRCurve25519KeyPair * _Nonnull)keyPairWithPublicKey:(NSData * _Nonnull)publicKey
                                        privateKey:(NSData * _Nonnull)privateKey {
    IRCurve25519KeyPair *keyPair = [IRCurve25519KeyPair new];
    keyPair.publicKey = publicKey;
    keyPair.privateKey = privateKey;

    return keyPair;
}

+ (IRCurve25519KeyPair * _Nonnull)keyPairWithPublicKey:(NSData * _Nonnull)publicKey {
    IRCurve25519KeyPair *keyPair = [IRCurve25519KeyPair new];
    keyPair.publicKey = publicKey;
    keyPair.privateKey = nil;

    return keyPair;
}

+ (IRCurve25519KeyPair * _Nonnull)keyPairWithSerializedData:(NSDictionary<NSString *, NSString *> * _Nonnull)serializedData {
    IRCurve25519KeyPair *keyPair = [IRCurve25519KeyPair new];
    keyPair.publicKey = [keyPair base64DecodedString:serializedData[kDictionaryKeyCurve25519KeyPairPublicKey]];
    keyPair.privateKey = [keyPair base64DecodedString:serializedData[kDictionaryKeyCurve25519KeyPairPrivateKey]];
    keyPair.signature = [keyPair base64DecodedString:serializedData[kDictionaryKeyCurve25519KeyPairPublicKeySignature]];

    return keyPair;
}

- (NSString * _Nullable)keyID {
    return [self publicKeyID];
}

- (void)addKeyPairSignature:(NSData * _Nonnull)signature {
    self.signature = signature;
}

- (NSDictionary<NSString *, NSString *> * _Nullable)serializedForTransport {
    if (self.publicKey == nil) {
        return nil;
    }

    if (self.signature == nil) {
        return @{kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
                 kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID]};
    }

    return @{kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
             kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID],
             kDictionaryKeyCurve25519KeyPairPublicKeySignature:[self base64EncodedData:self.signature]};
}

- (NSDictionary<NSString *, NSString *> * _Nullable)serialized {
    if (self.publicKey == nil) {
        return nil;
    }

    if (self.privateKey == nil) {
        if (self.signature == nil) {
            return @{kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
                     kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID]};
        }

        return @{kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
                 kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID],
                 kDictionaryKeyCurve25519KeyPairPublicKeySignature:[self base64EncodedData:self.signature]};
    }

    if (self.signature == nil) {
        return @{kDictionaryKeyCurve25519KeyPairPrivateKey:[self base64PrivateKey],
                 kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
                 kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID]};
    }

    return @{kDictionaryKeyCurve25519KeyPairPrivateKey:[self base64PrivateKey],
             kDictionaryKeyCurve25519KeyPairPublicKey:[self base64PublicKey],
             kDictionaryKeyCurve25519KeyPairPublicKeyID:[self publicKeyID],
             kDictionaryKeyCurve25519KeyPairPublicKeySignature:[self base64EncodedData:self.signature]};
}

- (NSString * _Nullable)base64PublicKey {
    if (self.publicKey == nil) {
        return nil;
    }

    return [self base64EncodedData:self.publicKey];
}

- (NSString * _Nullable)base64PrivateKey {
    if (self.privateKey == nil) {
        return nil;
    }

    return [self base64EncodedData:self.privateKey];
}

#pragma mark - Private

- (NSString * _Nullable)publicKeyID {
    if (self.publicKey == nil) {
        return  nil;
    }

    uint8_t digestData[CC_SHA256_DIGEST_LENGTH];
    size_t digestLength = sizeof(digestData);

    CC_SHA256(self.publicKey.bytes,
              (CC_LONG)self.publicKey.length,
              digestData);

    return [self base64EncodedData:[NSData dataWithBytes:digestData length:digestLength]];
}

- (NSString * _Nullable)base64EncodedData:(NSData * _Nonnull)data {
    return [data base64EncodedStringWithOptions:0];
}

- (NSData * _Nullable)base64DecodedString:(NSString * _Nonnull)base64String {
    if (base64String == nil) {
        return nil;
    }
    
    return [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

#pragma mark - <NSObject>

- (NSString *)description {
    return [NSString stringWithFormat:@"\nP:%@ S:%@\n",self.publicKey, self.privateKey];
}

- (BOOL)isEqual:(IRCurve25519KeyPair *)object {
    if (![object isKindOfClass:[IRCurve25519KeyPair class]]) {
        return NO;
    }

    if (self.privateKey == nil && object.privateKey == nil) {
        return [self.publicKey isEqual:object.publicKey];
    }

    return [self.publicKey isEqual:object.publicKey] && [self.privateKey isEqual:object.privateKey];
}

@end
