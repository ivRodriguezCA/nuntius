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

#import "IRByteReader.h"

#include <string.h>

@implementation IRByteReader {
    NSData *_data;
    const uint8_t *_bytes;
    NSUInteger _count;
    NSUInteger _offset;
}

- (instancetype _Nonnull)initWithData:(NSData * _Nonnull)data {
    self = [super init];
    if (self == nil) {
        return self;
    }

    /* -copy on an immutable NSData is free; on an NSMutableData it snapshots. Either way the bytes
       cannot change under the parser. */
    _data = [data copy];
    _bytes = (const uint8_t *)_data.bytes;
    _count = _data.length;
    _offset = 0;

    return self;
}

- (instancetype _Nonnull)initWithBytesNoCopy:(const uint8_t * _Nonnull)bytes
                                      length:(NSUInteger)length {
    self = [super init];
    if (self == nil) {
        return self;
    }

    /* No _data. Every read below already goes through _bytes; the ivar exists only to keep an
       -initWithData: buffer alive, and there is nothing here to keep alive — the caller owns it. */
    _data = nil;
    _bytes = bytes;
    _count = length;
    _offset = 0;

    return self;
}

#pragma mark - Bounds

- (NSUInteger)count {
    return _count;
}

- (NSUInteger)remaining {
    return _count - _offset;
}

- (NSUInteger)offset {
    return _offset;
}

- (BOOL)atEnd {
    return (_offset == _count);
}

- (BOOL)requireRemaining:(NSUInteger)count {
    return (count <= _count - _offset);
}

- (BOOL)hasBytesAtOffset:(NSUInteger)offset length:(NSUInteger)length {
    if (offset > _count) {
        return NO;
    }

    /* Subtraction rather than `offset + length <= _count`, so a length chosen to make the sum wrap
       cannot manufacture an in-bounds answer. */
    return (length <= _count - offset);
}

- (const uint8_t * _Nullable)constBytes {
    return _bytes;
}

#pragma mark - Absolute reads

- (BOOL)readUInt8:(uint8_t * _Nonnull)outValue atOffset:(NSUInteger)offset {
    if (outValue == NULL || ![self hasBytesAtOffset:offset length:1]) {
        return NO;
    }

    *outValue = _bytes[offset];

    return YES;
}

- (BOOL)readUInt16BE:(uint16_t * _Nonnull)outValue atOffset:(NSUInteger)offset {
    if (outValue == NULL || ![self hasBytesAtOffset:offset length:2]) {
        return NO;
    }

    /* Explicit shifts. Big-endian is the protocol's only integer encoding (§3.1) and this
       expression is byte-order independent on every host. */
    *outValue = (uint16_t)(((uint16_t)_bytes[offset + 0] << 8) |
                           ((uint16_t)_bytes[offset + 1]));

    return YES;
}

- (BOOL)readUInt32BE:(uint32_t * _Nonnull)outValue atOffset:(NSUInteger)offset {
    if (outValue == NULL || ![self hasBytesAtOffset:offset length:4]) {
        return NO;
    }

    *outValue = (((uint32_t)_bytes[offset + 0] << 24) |
                 ((uint32_t)_bytes[offset + 1] << 16) |
                 ((uint32_t)_bytes[offset + 2] <<  8) |
                 ((uint32_t)_bytes[offset + 3]));

    return YES;
}

- (BOOL)readUInt64BE:(uint64_t * _Nonnull)outValue atOffset:(NSUInteger)offset {
    if (outValue == NULL || ![self hasBytesAtOffset:offset length:8]) {
        return NO;
    }

    *outValue = (((uint64_t)_bytes[offset + 0] << 56) |
                 ((uint64_t)_bytes[offset + 1] << 48) |
                 ((uint64_t)_bytes[offset + 2] << 40) |
                 ((uint64_t)_bytes[offset + 3] << 32) |
                 ((uint64_t)_bytes[offset + 4] << 24) |
                 ((uint64_t)_bytes[offset + 5] << 16) |
                 ((uint64_t)_bytes[offset + 6] <<  8) |
                 ((uint64_t)_bytes[offset + 7]));

    return YES;
}

- (BOOL)readBytes:(void * _Nonnull)outBytes length:(NSUInteger)length atOffset:(NSUInteger)offset {
    if (![self hasBytesAtOffset:offset length:length]) {
        return NO;
    }

    if (length == 0) {
        return YES;
    }

    if (outBytes == NULL) {
        return NO;
    }

    memcpy(outBytes, _bytes + offset, (size_t)length);

    return YES;
}

- (NSData * _Nullable)dataAtOffset:(NSUInteger)offset length:(NSUInteger)length {
    if (![self hasBytesAtOffset:offset length:length]) {
        return nil;
    }

    if (length == 0) {
        return [NSData data];
    }

    return [NSData dataWithBytes:(_bytes + offset) length:length];
}

- (const uint8_t * _Nullable)bytesAtOffset:(NSUInteger)offset length:(NSUInteger)length {
    if (![self hasBytesAtOffset:offset length:length]) {
        return NULL;
    }

    return _bytes + offset;
}

- (BOOL)matchLiteral:(const uint8_t * _Nonnull)literal
              length:(NSUInteger)length
            atOffset:(NSUInteger)offset {
    if (literal == NULL || ![self hasBytesAtOffset:offset length:length]) {
        return NO;
    }

    if (length == 0) {
        return YES;
    }

    /* The literal's length always travels with it — never strlen (§3.1). */
    return (memcmp(_bytes + offset, literal, (size_t)length) == 0);
}

#pragma mark - Sequential reads

- (BOOL)readUInt8:(uint8_t * _Nonnull)outValue {
    if (![self readUInt8:outValue atOffset:_offset]) {
        return NO;
    }

    _offset += 1;

    return YES;
}

- (BOOL)readUInt16BE:(uint16_t * _Nonnull)outValue {
    if (![self readUInt16BE:outValue atOffset:_offset]) {
        return NO;
    }

    _offset += 2;

    return YES;
}

- (BOOL)readUInt32BE:(uint32_t * _Nonnull)outValue {
    if (![self readUInt32BE:outValue atOffset:_offset]) {
        return NO;
    }

    _offset += 4;

    return YES;
}

- (BOOL)readUInt64BE:(uint64_t * _Nonnull)outValue {
    if (![self readUInt64BE:outValue atOffset:_offset]) {
        return NO;
    }

    _offset += 8;

    return YES;
}

- (BOOL)readBytes:(void * _Nonnull)outBytes length:(NSUInteger)length {
    if (![self readBytes:outBytes length:length atOffset:_offset]) {
        return NO;
    }

    _offset += length;

    return YES;
}

- (NSData * _Nullable)readDataOfLength:(NSUInteger)length {
    NSData *slice = [self dataAtOffset:_offset length:length];
    if (slice == nil) {
        return nil;
    }

    _offset += length;

    return slice;
}

- (BOOL)matchLiteral:(const uint8_t * _Nonnull)literal length:(NSUInteger)length {
    if (![self matchLiteral:literal length:length atOffset:_offset]) {
        return NO;
    }

    _offset += length;

    return YES;
}

- (BOOL)skip:(NSUInteger)count {
    if (![self requireRemaining:count]) {
        return NO;
    }

    _offset += count;

    return YES;
}

- (BOOL)seekToOffset:(NSUInteger)offset {
    if (offset > _count) {
        return NO;
    }

    _offset = offset;

    return YES;
}

#pragma mark - Description

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; offset = %lu of %lu>",
            NSStringFromClass([self class]), (void *)self,
            (unsigned long)_offset, (unsigned long)_count];
}

@end
