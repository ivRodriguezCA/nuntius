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

#import "IREnvironment.h"
#import "IREnvironment+Testing.h"

#import "IRSodium.h"

#include <sys/time.h>

/* NOTE: this file does NOT include <Clibsodium/sodium.h>, and must not. The §3.3 lint admits exactly two
   such files — IRSodium.m and IRSodiumCryptoProvider.m — so that the §3.3 banned-API list is a
   one-command grep. The production random source below reaches randombytes_buf through
   IRRandomBytes() instead. */

#pragma mark - IRSystemClock

/// The production clock. Wall clock, not a monotonic one: every §13/§5.3/§7.6 quantity in the
/// specification is a Unix timestamp compared against timestamps minted on other devices, so a
/// monotonic uptime counter would be the wrong reading even though it is the more robust one.
@interface IRSystemClock : NSObject <IRClock>
@end

@implementation IRSystemClock

- (uint64_t)nowUnixMilliseconds {
    struct timeval now;

    /* gettimeofday rather than +[NSDate timeIntervalSince1970]: a double carries 53 mantissa bits
       and Unix milliseconds are already past 2^40, so the float path is representable today but
       loses sub-millisecond precision and would round differently across platforms. §12.1 stores
       inserted_at_ms as an exact uint64. */
    if (gettimeofday(&now, NULL) != 0) {
        /* Documented as unreachable on Darwin — gettimeofday fails only on EFAULT with a bad
           pointer. Returning 0 rather than a garbage stack value keeps the failure fail-closed:
           every TTL comparison in §7.6 and §12.2 rule 9 treats an epoch reading as "everything is
           in the future", so entries are retained rather than silently swept. */
        return 0;
    }

    return ((uint64_t)now.tv_sec * 1000ULL) + ((uint64_t)now.tv_usec / 1000ULL);
}

- (uint64_t)nowUnixSeconds {
    struct timeval now;

    if (gettimeofday(&now, NULL) != 0) {
        return 0;
    }

    return (uint64_t)now.tv_sec;
}

@end

#pragma mark - IRProductionRandomSource

/// The production CSPRNG. §13.1: libsodium's randombytes_buf, reached through IRRandomBytes.
@interface IRProductionRandomSource : NSObject <IRRandomSource>
@end

@implementation IRProductionRandomSource

- (BOOL)fillBytes:(void * _Nonnull)buffer
           length:(NSUInteger)length
            error:(NSError * _Nullable * _Nullable)error {
    if (length == 0) {
        return YES;
    }

    if (buffer == NULL) {
        IRSetError(error, IRErrorRNGFailure);
        return NO;
    }

    /* §13.2 — the initialization check lives here, where a BOOL and an NSError exist to carry the
       answer. IRRandomBytes returns void by design and cannot report it. */
    if (![IRSodium ensureInitialized:error]) {
        IRZeroize(buffer, length);
        return NO;
    }

    /* No return value to check: randombytes_buf aborts the process on entropy failure. That is
       exactly why §13.1 prefers it to SecRandomCopyBytes, whose OSStatus v3 discarded. */
    IRRandomBytes(buffer, length);

    return YES;
}

@end

#pragma mark - IREnvironment

@interface IREnvironment ()
@property (nonatomic, strong, readwrite) id<IRClock> _Nonnull clock;
@property (nonatomic, strong, readwrite) id<IRRandomSource> _Nonnull randomSource;
@end

@implementation IREnvironment

+ (IREnvironment * _Nonnull)production {
    static IREnvironment *shared = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        shared = [[IREnvironment alloc] initWithClock:[[IRSystemClock alloc] init]
                                         randomSource:[[IRProductionRandomSource alloc] init]];
    });

    return shared;
}

/* Declared in IREnvironment+Testing.h, defined here. Keeping the definition in the main
   @implementation rather than in a category means there is exactly one designated initializer and
   no partially initialized object can exist; the category header controls only who can SEE it. */
- (instancetype _Nonnull)initWithClock:(id<IRClock> _Nonnull)clock
                          randomSource:(id<IRRandomSource> _Nonnull)randomSource {
    /* §13.4 clause 3 / §3.3 — NOT NSParameterAssert, which is what these two lines used to be.
       NSParameterAssert and NSAssert compile out under NS_BLOCK_ASSERTIONS, the default in a Release
       build of a framework dependency, so the guard did nothing in the configuration consumers ship
       — and messaging a nil clock returns 0, which would silently place every expiry, tombstone and
       TTL decision in the framework at the Unix epoch. */
    IRRequireArgument(clock);
    IRRequireArgument(randomSource);

    self = [super init];
    if (self == nil) {
        return nil;
    }

    _clock = clock;
    _randomSource = randomSource;

    return self;
}

+ (IREnvironment * _Nonnull)environmentWithClock:(id<IRClock> _Nonnull)clock {
    return [[IREnvironment alloc] initWithClock:clock
                                   randomSource:[IREnvironment production].randomSource];
}

+ (IREnvironment * _Nonnull)environmentWithRandomSource:(id<IRRandomSource> _Nonnull)randomSource {
    return [[IREnvironment alloc] initWithClock:[IREnvironment production].clock
                                   randomSource:randomSource];
}

@end

#pragma mark - IRFixedClock

/// -init is NS_UNAVAILABLE on both test doubles so a caller cannot build one in an undefined state.
/// -initInternal is the private way past that, visible only inside this file.
@interface IRFixedClock ()
- (instancetype _Nonnull)initInternal;
@end

@implementation IRFixedClock

+ (instancetype _Nonnull)clockAtUnixMilliseconds:(uint64_t)milliseconds {
    IRFixedClock *clock = [[IRFixedClock alloc] initInternal];
    clock.unixMilliseconds = milliseconds;
    return clock;
}

+ (instancetype _Nonnull)clockAtUnixSeconds:(uint64_t)seconds {
    uint64_t milliseconds = (seconds > (UINT64_MAX / 1000ULL))
        ? UINT64_MAX
        : (seconds * 1000ULL);

    return [IRFixedClock clockAtUnixMilliseconds:milliseconds];
}

- (instancetype _Nonnull)initInternal {
    self = [super init];
    return self;
}

- (uint64_t)nowUnixMilliseconds {
    return self.unixMilliseconds;
}

- (uint64_t)nowUnixSeconds {
    /* Derived from the stored milliseconds rather than stored separately, so the two readings can
       never straddle a boundary. */
    return self.unixMilliseconds / 1000ULL;
}

- (void)advanceByMilliseconds:(uint64_t)delta {
    uint64_t current = self.unixMilliseconds;

    /* Saturate. Wrapping would land the clock in 1970 and invert every comparison the test was
       written to check, which reads as a protocol bug rather than as a test bug. */
    self.unixMilliseconds = (delta > (UINT64_MAX - current)) ? UINT64_MAX : (current + delta);
}

- (void)advanceBySeconds:(uint64_t)delta {
    if (delta > (UINT64_MAX / 1000ULL)) {
        self.unixMilliseconds = UINT64_MAX;
        return;
    }

    [self advanceByMilliseconds:(delta * 1000ULL)];
}

@end

#pragma mark - IRScriptedRandomSource

typedef NS_ENUM(NSUInteger, IRScriptedRandomMode) {
    IRScriptedRandomModeScript,
    IRScriptedRandomModeFail,
    IRScriptedRandomModeZero,
};

@interface IRScriptedRandomSource ()
@property (nonatomic, copy) NSData * _Nonnull script;
@property (nonatomic, assign) NSUInteger cursor;
@property (nonatomic, assign) IRScriptedRandomMode mode;
- (instancetype _Nonnull)initInternal;
@end

@implementation IRScriptedRandomSource

+ (instancetype _Nonnull)sourceWithData:(NSData * _Nonnull)data {
    IRScriptedRandomSource *source = [[IRScriptedRandomSource alloc] initInternal];
    source.script = (data != nil) ? data : [NSData data];
    source.mode = IRScriptedRandomModeScript;
    return source;
}

+ (instancetype _Nonnull)sourceWithDataItems:(NSArray<NSData *> * _Nonnull)dataItems {
    NSMutableData *joined = [NSMutableData data];

    for (NSData *item in dataItems) {
        [joined appendData:item];
    }

    return [IRScriptedRandomSource sourceWithData:joined];
}

+ (instancetype _Nonnull)failingSource {
    IRScriptedRandomSource *source = [[IRScriptedRandomSource alloc] initInternal];
    source.script = [NSData data];
    source.mode = IRScriptedRandomModeFail;
    return source;
}

+ (instancetype _Nonnull)zeroSource {
    IRScriptedRandomSource *source = [[IRScriptedRandomSource alloc] initInternal];
    source.script = [NSData data];
    source.mode = IRScriptedRandomModeZero;
    return source;
}

- (instancetype _Nonnull)initInternal {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _script = [NSData data];
    _cursor = 0;
    _mode = IRScriptedRandomModeScript;

    return self;
}

- (BOOL)fillBytes:(void * _Nonnull)buffer
           length:(NSUInteger)length
            error:(NSError * _Nullable * _Nullable)error {
    if (length == 0) {
        return YES;
    }

    if (buffer == NULL) {
        IRSetError(error, IRErrorRNGFailure);
        return NO;
    }

    switch (self.mode) {
        case IRScriptedRandomModeFail:
            /* Zeroize BEFORE reporting. A caller that ignores the return value must not find
               anything that looks like key material. */
            IRZeroize(buffer, length);
            IRSetError(error, IRErrorRNGFailure);
            return NO;

        case IRScriptedRandomModeZero:
            /* The silent break: succeeds, writes zeros. Only §13.1's all-zero tripwire catches it. */
            memset(buffer, 0, length);
            return YES;

        case IRScriptedRandomModeScript:
            break;
    }

    if (length > (self.script.length - self.cursor)) {
        /* Exhausted. Never wrap: reusing the script would hand the same nonce to two AEAD calls
           under one key, which is the (key, nonce) reuse §8.3 exists to prevent. */
        IRZeroize(buffer, length);
        IRSetError(error, IRErrorRNGFailure);
        return NO;
    }

    memcpy(buffer, ((const uint8_t *)self.script.bytes) + self.cursor, length);
    self.cursor += length;

    return YES;
}

- (NSUInteger)bytesRemaining {
    return self.script.length - self.cursor;
}

- (NSUInteger)bytesServed {
    return self.cursor;
}

@end
