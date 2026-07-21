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

#import <Foundation/Foundation.h>

#import "IREnvironment.h"

/**
 Test-only injection — SPEC §15.5 rules 5–6, §15.6, §19.6.

 PROJECT VISIBILITY, DELIBERATELY. This header has no PBXHeadersBuildPhase entry, is absent from
 nuntius.h, and does not ship in the built framework's interface. §15.5 rules 5 and 6 both require
 that "a production API MUST NOT expose" nonce, key, or clock injection, and header visibility is
 how that requirement is discharged. The test target reaches it through Xcode's generated project
 header map with no HEADER_SEARCH_PATHS work.

 What this buys, concretely: §15.5 rule 5 requires that vector-supplied ephemeral keys and nonces be
 injectable, and rule 6 the same for `now_s` / `now_ms`. §15.6 then requires CI to run the entire
 frozen suite with the clock ten years forward and see it pass unchanged. Neither is expressible
 against a wall clock and a real CSPRNG.
 */

#pragma mark - Injection

@interface IREnvironment (Testing)

/// The injecting initializer. Both members are retained as given, so a test may mutate an
/// IRFixedClock after handing it over and see the change take effect.
- (instancetype _Nonnull)initWithClock:(id<IRClock> _Nonnull)clock
                          randomSource:(id<IRRandomSource> _Nonnull)randomSource;

/// A production random source paired with a fixed clock — the common shape for a vector whose
/// randomness is genuinely irrelevant but whose evaluation reads a clock.
+ (IREnvironment * _Nonnull)environmentWithClock:(id<IRClock> _Nonnull)clock;

/// A system clock paired with a scripted random source — the common shape for a vector that
/// supplies ephemeral keys or nonces but reads no clock.
+ (IREnvironment * _Nonnull)environmentWithRandomSource:(id<IRRandomSource> _Nonnull)randomSource;

@end

#pragma mark - IRFixedClock

/**
 A clock that does not move unless told to.

 Milliseconds are the stored quantity and seconds are derived by integer division, so the two
 readings can never disagree about which side of a boundary they are on — a split-instant that would
 make a TTL test flaky in exactly the way a fixed clock exists to prevent.
 */
@interface IRFixedClock : NSObject <IRClock>

+ (instancetype _Nonnull)clockAtUnixMilliseconds:(uint64_t)milliseconds;

/// Convenience for §5.3's second-granularity windows. Stores `seconds * 1000`.
+ (instancetype _Nonnull)clockAtUnixSeconds:(uint64_t)seconds;

@property (nonatomic, assign) uint64_t unixMilliseconds;

/// Saturating: a test that advances past UINT64_MAX pins there rather than wrapping to 1970 and
/// silently inverting every comparison it was written to check.
- (void)advanceByMilliseconds:(uint64_t)delta;
- (void)advanceBySeconds:(uint64_t)delta;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRScriptedRandomSource

/**
 A random source that returns predetermined bytes, so a §15.5 rule 5 vector can pin the ephemeral
 keys and nonces that would otherwise make its output unreproducible.

 EXHAUSTION IS A FAILURE, NOT A WRAP. Running out of scripted bytes returns NO with
 IRErrorRNGFailure and zeroizes the caller's buffer. Cycling the script would silently hand the same
 nonce to two AEAD calls under one key — the (key, nonce) reuse §8.3 exists to prevent — and would
 do it in the test suite, which is the one place that failure must be loud.
 */
@interface IRScriptedRandomSource : NSObject <IRRandomSource>

/// Serves `data` in order, one fill consuming as many bytes as it asks for.
+ (instancetype _Nonnull)sourceWithData:(NSData * _Nonnull)data;

/// Serves the concatenation of `dataItems`, in order. Convenience for the usual shape of a vector:
/// an ephemeral private key, then a nonce.
+ (instancetype _Nonnull)sourceWithDataItems:(NSArray<NSData *> * _Nonnull)dataItems;

/// Fails every fill with IRErrorRNGFailure. This is the §13.1 regression: the caller MUST report
/// the failure rather than proceed with the zero-filled buffer it already holds.
+ (instancetype _Nonnull)failingSource;

/// Succeeds but writes zeros — a CSPRNG that has broken WITHOUT saying so, which no return-value
/// check can catch. §13.1's "every freshly generated private key SHOULD additionally be checked
/// with an all-zero test" is the only defence, and this is what proves it is wired up.
+ (instancetype _Nonnull)zeroSource;

@property (nonatomic, readonly) NSUInteger bytesRemaining;
@property (nonatomic, readonly) NSUInteger bytesServed;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
