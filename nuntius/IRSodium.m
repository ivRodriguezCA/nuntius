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

#import "IRSodium.h"

#include <Clibsodium/sodium.h>

/// Latched once by +ensureInitialized:. A failed sodium_init() is permanent for the process
/// lifetime: §13.2 forbids a silently degraded service, so there is no retry path.
static BOOL sIRSodiumInitialized = NO;

@implementation IRSodium

+ (BOOL)ensureInitialized:(NSError * _Nullable * _Nullable)error {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        /* sodium_init() returns 0 on first success, 1 if the library was already initialized, and
           a negative value on failure. v3 discarded this entirely. */
        int result = sodium_init();
        sIRSodiumInitialized = (result >= 0);
    });

    if (!sIRSodiumInitialized) {
        IRSetError(error, IRErrorNotInitialized);
        return NO;
    }

    return YES;
}

+ (BOOL)isInitialized {
    return sIRSodiumInitialized;
}

@end

#pragma mark - Memory hygiene

void IRZeroize(void * _Nullable buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return;
    }

    sodium_memzero(buffer, length);
}

void * _Nullable IRGuardedAlloc(size_t length) {
    if (length == 0) {
        return NULL;
    }

    /* sodium_malloc requires an initialized library. Failing closed here is what keeps a guarded
       allocation from silently becoming an unguarded one. */
    if (![IRSodium ensureInitialized:NULL]) {
        return NULL;
    }

    /* sodium_malloc already calls sodium_mlock on the region it returns and surrounds it with a
       guard page and canaries, so a separate sodium_mlock call would be redundant. */
    return sodium_malloc(length);
}

void IRGuardedFree(void * _Nullable buffer) {
    if (buffer == NULL) {
        return;
    }

    /* sodium_free zeroes the whole region and verifies the canary before unmapping. */
    sodium_free(buffer);
}

BOOL IRConstantTimeEquals(const void * _Nonnull a, const void * _Nonnull b, size_t length) {
    if (length == 0) {
        return YES;
    }

    if (a == NULL || b == NULL) {
        return NO;
    }

    return (sodium_memcmp(a, b, length) == 0);
}

BOOL IRIsAllZero(const void * _Nonnull buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return YES;
    }

    /* OR-accumulate every byte, exactly as §4.4 check 3 prescribes, so the running time does not
       depend on where the first non-zero byte sits. `volatile` keeps the accumulator from being
       optimized into an early exit. */
    const volatile uint8_t *bytes = (const volatile uint8_t *)buffer;
    volatile uint8_t accumulator = 0;

    for (size_t index = 0; index < length; index++) {
        accumulator = (uint8_t)(accumulator | bytes[index]);
    }

    return (accumulator == 0);
}

#pragma mark - Randomness

void IRRandomBytes(void * _Nonnull buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return;
    }

    /* randombytes_buf has a void return: libsodium aborts the process on entropy failure rather
       than reporting one, which is precisely why §13.1 prefers it to SecRandomCopyBytes. There is
       no status here to discard, and therefore no way to reproduce v3's all-zero-key failure. */
    randombytes_buf(buffer, length);
}
