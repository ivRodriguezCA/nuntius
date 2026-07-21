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

#import "IRKeyTypes.h"

#include <string.h>

#pragma mark - IRFixedLengthData

@interface IRFixedLengthData ()

/// The single ingress point. Every factory funnels here AFTER the length check and
/// +validateBytes:error:, so no path can construct a value that skipped either.
- (instancetype _Nonnull)initWithValidatedBytes:(const uint8_t * _Nonnull)bytes
                                         length:(NSUInteger)length;

@end

@implementation IRFixedLengthData {
    NSData *_data;
}

+ (NSUInteger)fixedLength {
    /* A concrete nominal type MUST override this. Every factory below rejects the base value. */
    return 0;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

+ (BOOL)validateBytes:(const uint8_t * _Nonnull)bytes
                error:(NSError * _Nullable * _Nullable)error {
    (void)bytes;
    (void)error;

    return YES;
}

+ (instancetype _Nullable)fromData:(NSData * _Nonnull)data
                             error:(NSError * _Nullable * _Nullable)error {
    if (data == nil || data.length != [self fixedLength]) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    return [self fromBytes:(const uint8_t *)data.bytes error:error];
}

+ (instancetype _Nullable)fromBytes:(const uint8_t * _Nonnull)bytes
                              error:(NSError * _Nullable * _Nullable)error {
    NSUInteger length = [self fixedLength];
    if (length == 0 || bytes == NULL) {
        IRSetError(error, [self lengthErrorCode]);
        return nil;
    }

    if (![self validateBytes:bytes error:error]) {
        return nil;
    }

    return [[self alloc] initWithValidatedBytes:bytes length:length];
}

- (instancetype _Nonnull)initWithValidatedBytes:(const uint8_t * _Nonnull)bytes
                                         length:(NSUInteger)length {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _data = [NSData dataWithBytes:bytes length:length];

    return self;
}

#pragma mark Accessors

- (NSData * _Nonnull)data {
    return _data;
}

- (NSUInteger)length {
    return _data.length;
}

- (const uint8_t * _Nonnull)constBytes {
    return (const uint8_t *)_data.bytes;
}

- (NSString * _Nonnull)hexString {
    static const char digits[] = "0123456789abcdef";

    NSUInteger length = _data.length;
    if (length == 0) {
        return @"";
    }

    const uint8_t *bytes = (const uint8_t *)_data.bytes;

    NSMutableData *scratch = [NSMutableData dataWithLength:(length * 2)];
    char *out = (char *)scratch.mutableBytes;

    for (NSUInteger index = 0; index < length; index++) {
        out[(index * 2) + 0] = digits[(bytes[index] >> 4) & 0x0F];
        out[(index * 2) + 1] = digits[bytes[index] & 0x0F];
    }

    return [[NSString alloc] initWithBytes:out length:(length * 2) encoding:NSASCIIStringEncoding];
}

#pragma mark Equality

- (BOOL)isEqualToFixedLengthData:(IRFixedLengthData * _Nullable)other {
    if (other == self) {
        return YES;
    }

    if (other == nil) {
        return NO;
    }

    /* §4.3 — the class participates. Nominal typing is the point of these types; equality must not
       undo it. These values are public, so a plain comparison leaks nothing. */
    if ([other class] != [self class]) {
        return NO;
    }

    return [_data isEqualToData:other.data];
}

- (BOOL)isEqual:(id _Nullable)object {
    if (object == self) {
        return YES;
    }

    if (![object isKindOfClass:[IRFixedLengthData class]]) {
        return NO;
    }

    return [self isEqualToFixedLengthData:(IRFixedLengthData *)object];
}

- (NSUInteger)hash {
    return _data.hash;
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %@>", NSStringFromClass([self class]), [self hexString]];
}

@end

#pragma mark - IREd25519Public

@implementation IREd25519Public

+ (NSUInteger)fixedLength {
    return kIRLenEd25519Public;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorInvalidPublicKey;
}

- (BOOL)isEqualToEd25519Public:(IREd25519Public * _Nullable)other {
    return [self isEqualToFixedLengthData:other];
}

@end

#pragma mark - IREd25519Signature

@implementation IREd25519Signature

+ (NSUInteger)fixedLength {
    return kIRLenEd25519Signature;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorBadSignature;
}

- (BOOL)isEqualToEd25519Signature:(IREd25519Signature * _Nullable)other {
    return [self isEqualToFixedLengthData:other];
}

@end

#pragma mark - IRX25519Public

@implementation IRX25519Public

+ (NSUInteger)fixedLength {
    return kIRLenX25519Public;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorInvalidPublicKey;
}

+ (BOOL)validateBytes:(const uint8_t * _Nonnull)bytes
                error:(NSError * _Nullable * _Nullable)error {
    /* §4.4 check 2. Check 1 — the length — is enforced by the factory before this runs. */
    if (![self highBitIsClear:bytes]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return NO;
    }

    return YES;
}

+ (BOOL)highBitIsClear:(const uint8_t * _Nonnull)bytes {
    if (bytes == NULL) {
        return NO;
    }

    return ((bytes[kIRLenX25519Public - 1] & 0x80) == 0);
}

+ (BOOL)dataIsValidEncoding:(NSData * _Nullable)data {
    if (data == nil || data.length != kIRLenX25519Public) {
        return NO;
    }

    return [self highBitIsClear:(const uint8_t *)data.bytes];
}

- (BOOL)isEqualToX25519Public:(IRX25519Public * _Nullable)other {
    return [self isEqualToFixedLengthData:other];
}

@end

#pragma mark - IRNonce

@implementation IRNonce

+ (NSUInteger)fixedLength {
    return kIRLenNonce;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorMalformedHeader;
}

- (BOOL)isEqualToNonce:(IRNonce * _Nullable)other {
    return [self isEqualToFixedLengthData:other];
}

@end

#pragma mark - IRFingerprint

@implementation IRFingerprint

+ (NSUInteger)fixedLength {
    return kIRLenFingerprint;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

- (BOOL)isEqualToFingerprint:(IRFingerprint * _Nullable)other {
    return [self isEqualToFixedLengthData:other];
}

@end

#pragma mark - IREd25519Private

@implementation IREd25519Private

+ (NSUInteger)fixedLength {
    return kIRLenEd25519Private;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

@end

#pragma mark - IRX25519Private

@implementation IRX25519Private

+ (NSUInteger)fixedLength {
    return kIRLenX25519Private;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

+ (void)clampBytes:(uint8_t * _Nonnull)bytes {
    if (bytes == NULL) {
        return;
    }

    /* §4.2, RFC 7748 §5. Idempotent: applying it twice yields the same scalar. */
    bytes[0] = (uint8_t)(bytes[0] & 0xF8);
    bytes[kIRLenX25519Private - 1] = (uint8_t)(bytes[kIRLenX25519Private - 1] & 0x7F);
    bytes[kIRLenX25519Private - 1] = (uint8_t)(bytes[kIRLenX25519Private - 1] | 0x40);
}

+ (BOOL)bytesAreClamped:(const uint8_t * _Nonnull)bytes {
    if (bytes == NULL) {
        return NO;
    }

    /* §12.2 rule 8, expressed over the scalar rather than over blob offsets 243 and 274 so the
       predicate has exactly one definition. */
    if ((bytes[0] & 0x07) != 0) {
        return NO;
    }

    return ((bytes[kIRLenX25519Private - 1] & 0xC0) == 0x40);
}

- (void)normalizeRepresentation {
    /* §4.2 — clamp at construction. This runs for generation, for state load and for vector input
       alike, which is what keeps the rule to a single site. It does NOT substitute for §12.2 rule
       8: the state decoder rejects an unclamped blob BEFORE it gets here (§19.5). */
    if (self.length != kIRLenX25519Private) {
        return;
    }

    [[self class] clampBytes:[self mutableBytes]];
}

@end

#pragma mark - IRRootKey

@implementation IRRootKey

+ (NSUInteger)fixedLength {
    return kIRLenRootKey;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

@end

#pragma mark - IRChainKey

@implementation IRChainKey

+ (NSUInteger)fixedLength {
    return kIRLenChainKey;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

@end

#pragma mark - IRMessageKey

@implementation IRMessageKey

+ (NSUInteger)fixedLength {
    return kIRLenMessageKey;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

@end

#pragma mark - IRMessageEncKey

@implementation IRMessageEncKey

+ (NSUInteger)fixedLength {
    return kIRLenMessageEncKey;
}

+ (IRErrorCode)lengthErrorCode {
    return IRErrorStateCorrupt;
}

@end
