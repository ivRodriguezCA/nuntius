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

#import "IRByteWriter.h"
#import "IRSodium.h"

#include <stdlib.h>
#include <string.h>

@implementation IRByteWriter {
    uint8_t *_buffer;
    NSUInteger _length;
    NSUInteger _capacity;
    /// Set when an append could not be satisfied. A writer in this state can never produce a
    /// structure of the expected length, so -finish… reports the mismatch rather than a truncation
    /// that happens to hit the right total.
    BOOL _failed;
}

- (instancetype _Nonnull)initWithCapacity:(NSUInteger)capacity {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _buffer = NULL;
    _length = 0;
    _capacity = 0;
    _failed = NO;

    if (capacity > 0) {
        _buffer = (uint8_t *)calloc(1, (size_t)capacity);
        if (_buffer == NULL) {
            _failed = YES;
        } else {
            _capacity = capacity;
        }
    }

    return self;
}

- (void)dealloc {
    [self zeroize];
}

#pragma mark - Storage

/**
 Grows to hold at least `required` bytes.

 Deliberately NOT realloc: realloc may move the block and leave the old contents readable in freed
 heap, which would defeat the zeroization this type exists to guarantee for IKM. Allocate, copy,
 wipe the old block, free it.
 */
- (BOOL)ensureCapacity:(NSUInteger)required {
    if (_failed) {
        return NO;
    }

    if (required <= _capacity) {
        return YES;
    }

    NSUInteger grown = (_capacity == 0) ? 64 : _capacity;
    while (grown < required) {
        if (grown > (NSUIntegerMax / 2)) {
            grown = required;
            break;
        }
        grown *= 2;
    }

    uint8_t *replacement = (uint8_t *)calloc(1, (size_t)grown);
    if (replacement == NULL) {
        _failed = YES;
        return NO;
    }

    if (_buffer != NULL) {
        if (_length > 0) {
            memcpy(replacement, _buffer, (size_t)_length);
        }
        IRZeroize(_buffer, (size_t)_capacity);
        free(_buffer);
    }

    _buffer = replacement;
    _capacity = grown;

    return YES;
}

- (NSUInteger)length {
    return _length;
}

#pragma mark - Appending

- (void)appendBytes:(const void * _Nonnull)bytes length:(NSUInteger)length {
    if (length == 0) {
        return;
    }

    if (bytes == NULL) {
        _failed = YES;
        return;
    }

    if (_length > NSUIntegerMax - length) {
        _failed = YES;
        return;
    }

    if (![self ensureCapacity:_length + length]) {
        return;
    }

    memcpy(_buffer + _length, bytes, (size_t)length);
    _length += length;
}

- (void)appendUInt8:(uint8_t)value {
    [self appendBytes:&value length:1];
}

- (void)appendUInt16BE:(uint16_t)value {
    /* Explicit big-endian decomposition; §3.1 forbids memcpy of a native integer. */
    uint8_t encoded[2];
    encoded[0] = (uint8_t)((value >> 8) & 0xFF);
    encoded[1] = (uint8_t)((value >> 0) & 0xFF);

    [self appendBytes:encoded length:sizeof(encoded)];
}

- (void)appendUInt32BE:(uint32_t)value {
    uint8_t encoded[4];
    encoded[0] = (uint8_t)((value >> 24) & 0xFF);
    encoded[1] = (uint8_t)((value >> 16) & 0xFF);
    encoded[2] = (uint8_t)((value >>  8) & 0xFF);
    encoded[3] = (uint8_t)((value >>  0) & 0xFF);

    [self appendBytes:encoded length:sizeof(encoded)];
}

- (void)appendUInt64BE:(uint64_t)value {
    uint8_t encoded[8];
    encoded[0] = (uint8_t)((value >> 56) & 0xFF);
    encoded[1] = (uint8_t)((value >> 48) & 0xFF);
    encoded[2] = (uint8_t)((value >> 40) & 0xFF);
    encoded[3] = (uint8_t)((value >> 32) & 0xFF);
    encoded[4] = (uint8_t)((value >> 24) & 0xFF);
    encoded[5] = (uint8_t)((value >> 16) & 0xFF);
    encoded[6] = (uint8_t)((value >>  8) & 0xFF);
    encoded[7] = (uint8_t)((value >>  0) & 0xFF);

    [self appendBytes:encoded length:sizeof(encoded)];
}

- (void)appendData:(NSData * _Nonnull)data {
    if (data == nil) {
        _failed = YES;
        return;
    }

    [self appendBytes:data.bytes length:data.length];
}

- (void)appendSecretBytes:(IRSecretBytes * _Nonnull)secret {
    if (secret == nil) {
        _failed = YES;
        return;
    }

    [self appendBytes:[secret constBytes] length:secret.length];
}

- (void)appendZeros:(NSUInteger)count {
    if (count == 0) {
        return;
    }

    if (_length > NSUIntegerMax - count) {
        _failed = YES;
        return;
    }

    if (![self ensureCapacity:_length + count]) {
        return;
    }

    /* The freshly grown region is calloc'd, but a reused one may not be, so write the zeros. */
    memset(_buffer + _length, 0, (size_t)count);
    _length += count;
}

#pragma mark - Finishing

- (NSData * _Nullable)finishExpectingLength:(NSUInteger)expectedLength
                          mismatchErrorCode:(IRErrorCode)mismatchErrorCode
                                      error:(NSError * _Nullable * _Nullable)error {
    if (_failed || _length != expectedLength) {
        IRSetError(error, mismatchErrorCode);
        return nil;
    }

    if (expectedLength == 0) {
        return [NSData data];
    }

    return [NSData dataWithBytes:_buffer length:_length];
}

- (NSData * _Nullable)finishExpectingLength:(NSUInteger)expectedLength
                                      error:(NSError * _Nullable * _Nullable)error {
    return [self finishExpectingLength:expectedLength
                     mismatchErrorCode:IRErrorStateCorrupt
                                 error:error];
}

- (IRSecretBytes * _Nullable)finishSecretExpectingLength:(NSUInteger)expectedLength
                                                 guarded:(BOOL)guarded
                                                   error:(NSError * _Nullable * _Nullable)error {
    if (_failed || _length != expectedLength || expectedLength == 0) {
        [self zeroize];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSecretBytes *secret = guarded
        ? [[IRSecretBytes alloc] initGuardedWithBytes:_buffer length:_length]
        : [[IRSecretBytes alloc] initWithBytes:_buffer length:_length];

    /* §13.3 — the writer's copy dies here, whatever happens next. */
    [self zeroize];

    if (secret == nil) {
        IRSetError(error, guarded ? IRErrorNotInitialized : IRErrorStateCorrupt);
        return nil;
    }

    return secret;
}

- (void)zeroize {
    if (_buffer != NULL) {
        IRZeroize(_buffer, (size_t)_capacity);
        free(_buffer);
        _buffer = NULL;
    }

    _length = 0;
    _capacity = 0;
}

#pragma mark - Description

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; length = %lu; failed = %@>",
            NSStringFromClass([self class]), (void *)self,
            (unsigned long)_length, _failed ? @"YES" : @"NO"];
}

@end
