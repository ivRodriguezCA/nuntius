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

#import "IRSecretBytes.h"
#import "IRSodium.h"

#include <stdlib.h>
#include <string.h>

@implementation IRSecretBytes {
    uint8_t *_buffer;
    NSUInteger _length;
    BOOL _guarded;
}

#pragma mark - Designated initializers

- (instancetype _Nullable)initWithLength:(NSUInteger)length {
    if (length == 0) {
        return nil;
    }

    self = [super init];
    if (self == nil) {
        return nil;
    }

    /* calloc zero-fills. That is the correct starting state for a buffer a producer is about to
       overwrite, and it is precisely why §13.1 forbids handing a zero-filled buffer to a possibly
       failing fill without checking the fill's return value: the failure is invisible. */
    _buffer = (uint8_t *)calloc(1, (size_t)length);
    if (_buffer == NULL) {
        return nil;
    }

    _length = length;
    _guarded = NO;

    return self;
}

- (instancetype _Nullable)initGuardedWithLength:(NSUInteger)length {
    if (length == 0) {
        return nil;
    }

    self = [super init];
    if (self == nil) {
        return nil;
    }

    _buffer = (uint8_t *)IRGuardedAlloc((size_t)length);
    if (_buffer == NULL) {
        return nil;
    }

    IRZeroize(_buffer, (size_t)length);

    _length = length;
    _guarded = YES;

    return self;
}

#pragma mark - Convenience initializers

- (instancetype _Nullable)initWithBytes:(const void * _Nonnull)bytes length:(NSUInteger)length {
    if (bytes == NULL) {
        return nil;
    }

    self = [self initWithLength:length];
    if (self == nil) {
        return nil;
    }

    memcpy([self mutableBytes], bytes, (size_t)length);

    return self;
}

- (instancetype _Nullable)initGuardedWithBytes:(const void * _Nonnull)bytes length:(NSUInteger)length {
    if (bytes == NULL) {
        return nil;
    }

    self = [self initGuardedWithLength:length];
    if (self == nil) {
        return nil;
    }

    memcpy([self mutableBytes], bytes, (size_t)length);

    return self;
}

- (instancetype _Nullable)initWithData:(NSData * _Nonnull)data guarded:(BOOL)guarded {
    if (data == nil) {
        return nil;
    }

    if (guarded) {
        return [self initGuardedWithBytes:data.bytes length:data.length];
    }

    return [self initWithBytes:data.bytes length:data.length];
}

#pragma mark - Teardown

- (void)dealloc {
    /* §13.3 — unconditional. Every path out of this object's lifetime wipes the buffer, including
       the paths nobody remembered to put on the explicit schedule. */
    if (_buffer != NULL) {
        IRZeroize(_buffer, (size_t)_length);

        if (_guarded) {
            IRGuardedFree(_buffer);
        } else {
            free(_buffer);
        }

        _buffer = NULL;
    }

    _length = 0;
}

#pragma mark - Accessors

- (NSUInteger)length {
    return _length;
}

- (BOOL)isGuarded {
    return _guarded;
}

- (const uint8_t * _Nonnull)constBytes {
    return _buffer;
}

- (uint8_t * _Nonnull)mutableBytes {
    return _buffer;
}

#pragma mark - Zeroization

- (void)zeroizeNow {
    /* Idempotent, and the allocation survives, so a const pointer handed to a caller earlier in the
       same expression does not dangle. */
    IRZeroize(_buffer, (size_t)_length);
}

#pragma mark - Comparison

- (BOOL)isEqualToSecretBytes:(IRSecretBytes * _Nullable)other {
    if (other == nil) {
        return NO;
    }

    if (other == self) {
        return YES;
    }

    /* Length is not secret — it is a class invariant for every nominal type — so branching on it
       leaks nothing, and comparing different lengths in constant time is not meaningful. */
    if (other.length != _length) {
        return NO;
    }

    return IRConstantTimeEquals(_buffer, [other constBytes], (size_t)_length);
}

- (BOOL)isAllZero {
    return IRIsAllZero(_buffer, (size_t)_length);
}

#pragma mark - Description

- (NSString * _Nonnull)description {
    /* NEVER print the bytes. A secret that reaches a log, a crash report or an Xcode console has
       left the process's control. */
    return [NSString stringWithFormat:@"<%@: %p; length = %lu; guarded = %@>",
            NSStringFromClass([self class]), (void *)self,
            (unsigned long)_length, _guarded ? @"YES" : @"NO"];
}

@end

#pragma mark - Fixed-length secrets

@implementation IRFixedLengthSecret

+ (NSUInteger)fixedLength {
    /* A concrete nominal type MUST override this. The base value is unreachable in practice: every
       factory below rejects it. */
    return 0;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

+ (instancetype _Nullable)fromData:(NSData * _Nonnull)data
                           guarded:(BOOL)guarded
                             error:(NSError * _Nullable * _Nullable)error {
    if (data == nil) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    if (data.length != [self fixedLength]) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    return [self fromBytes:(const uint8_t *)data.bytes guarded:guarded error:error];
}

+ (instancetype _Nullable)fromBytes:(const uint8_t * _Nonnull)bytes
                            guarded:(BOOL)guarded
                              error:(NSError * _Nullable * _Nullable)error {
    NSUInteger length = [self fixedLength];
    if (length == 0 || bytes == NULL) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    id secret = guarded
        ? [[self alloc] initGuardedWithBytes:bytes length:length]
        : [[self alloc] initWithBytes:bytes length:length];

    if (secret == nil) {
        /* The only way to get here with a valid length is an allocation failure — including
           sodium_malloc refusing because libsodium never initialized. */
        IRSetError(error, guarded ? IRErrorNotInitialized : [self lengthErrorCode]);
        return nil;
    }

    [(IRFixedLengthSecret *)secret normalizeRepresentation];

    return secret;
}

+ (instancetype _Nullable)zeroValueGuarded:(BOOL)guarded
                                     error:(NSError * _Nullable * _Nullable)error {
    NSUInteger length = [self fixedLength];
    if (length == 0) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    id secret = guarded
        ? [[self alloc] initGuardedWithLength:length]
        : [[self alloc] initWithLength:length];

    if (secret == nil) {
        IRSetError(error, guarded ? IRErrorNotInitialized : [self lengthErrorCode]);
        return nil;
    }

    /* Deliberately NOT normalized. A zero buffer is not key material yet; a caller that fills it
       through -mutableBytes MUST call -normalizeRepresentation afterwards. */
    return secret;
}

- (instancetype _Nullable)duplicate {
    const uint8_t *bytes = [self constBytes];
    NSUInteger length = self.length;

    if (self.isGuarded) {
        return [[[self class] alloc] initGuardedWithBytes:bytes length:length];
    }

    return [[[self class] alloc] initWithBytes:bytes length:length];
}

- (void)normalizeRepresentation {
    /* No-op. IRX25519Private overrides this to apply the §4.2 clamp. */
}

#pragma mark Equality

- (BOOL)isEqual:(id _Nullable)object {
    if (object == self) {
        return YES;
    }

    /* §4.3 — the CLASS participates, so an IRRootKey and an IRChainKey holding identical bytes are
       not equal. Nominal typing is the point of these types; equality must not undo it. */
    if (![object isKindOfClass:[IRFixedLengthSecret class]]) {
        return NO;
    }

    if ([object class] != [self class]) {
        return NO;
    }

    return [self isEqualToSecretBytes:(IRFixedLengthSecret *)object];
}

- (NSUInteger)hash {
    /* Class and length only. Feeding secret bytes into a hash table would spread them across
       buckets the wipe schedule does not know about, and nothing in this protocol keys a
       collection on a secret. Equal objects hash equal, which is the whole contract. */
    return ((NSUInteger)(uintptr_t)[self class]) ^ self.length;
}

@end
