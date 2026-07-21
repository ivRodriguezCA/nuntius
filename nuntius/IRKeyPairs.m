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

#import "IRKeyPairs.h"

#pragma mark - IRX25519KeyPair

@interface IRX25519KeyPair ()

- (instancetype _Nonnull)initWithPublicKey:(IRX25519Public * _Nonnull)publicKey
                                privateKey:(IRX25519Private * _Nonnull)privateKey;

@end

@implementation IRX25519KeyPair

+ (instancetype _Nullable)pairWithPublicKey:(IRX25519Public * _Nonnull)publicKey
                                 privateKey:(IRX25519Private * _Nonnull)privateKey
                                      error:(NSError * _Nullable * _Nullable)error {
    if (publicKey == nil || publicKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (privateKey == nil || privateKey.length != kIRLenX25519Private) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [[self alloc] initWithPublicKey:publicKey privateKey:privateKey];
}

- (instancetype _Nonnull)initWithPublicKey:(IRX25519Public * _Nonnull)publicKey
                                privateKey:(IRX25519Private * _Nonnull)privateKey {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _publicKey = publicKey;
    _privateKey = privateKey;

    return self;
}

- (IRX25519KeyPair * _Nullable)deepCopy {
    /* Fresh allocation of the private half; the public half is immutable and non-secret, so
       sharing the object is safe and free. */
    IRX25519Private *privateCopy = [_privateKey duplicate];
    if (privateCopy == nil) {
        return nil;
    }

    return [[IRX25519KeyPair alloc] initWithPublicKey:_publicKey privateKey:privateCopy];
}

- (void)zeroize {
    [_privateKey zeroizeNow];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; publicKey = %@>",
            NSStringFromClass([self class]), (void *)self, [_publicKey hexString]];
}

@end

#pragma mark - IREd25519KeyPair

@interface IREd25519KeyPair ()

- (instancetype _Nonnull)initWithPublicKey:(IREd25519Public * _Nonnull)publicKey
                                      seed:(IREd25519Private * _Nonnull)seed;

@end

@implementation IREd25519KeyPair

+ (instancetype _Nullable)pairWithPublicKey:(IREd25519Public * _Nonnull)publicKey
                                       seed:(IREd25519Private * _Nonnull)seed
                                      error:(NSError * _Nullable * _Nullable)error {
    if (publicKey == nil || publicKey.length != kIRLenEd25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (seed == nil || seed.length != kIRLenEd25519Private) {
        /* §4.2 — a 64-byte value here is libsodium's expanded `sk`, which MUST NOT reach an API
           boundary. The width check is what catches that substitution. */
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[self alloc] initWithPublicKey:publicKey seed:seed];
}

- (instancetype _Nonnull)initWithPublicKey:(IREd25519Public * _Nonnull)publicKey
                                      seed:(IREd25519Private * _Nonnull)seed {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _publicKey = publicKey;
    _seed = seed;

    return self;
}

- (IREd25519KeyPair * _Nullable)deepCopy {
    IREd25519Private *seedCopy = [_seed duplicate];
    if (seedCopy == nil) {
        return nil;
    }

    return [[IREd25519KeyPair alloc] initWithPublicKey:_publicKey seed:seedCopy];
}

- (void)zeroize {
    [_seed zeroizeNow];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; publicKey = %@>",
            NSStringFromClass([self class]), (void *)self, [_publicKey hexString]];
}

@end
