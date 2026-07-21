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
#import <nuntius/IRErrors.h>

/**
 The two ambient inputs — SPEC §13.1, §15.5 rules 5–6, §19.6.

 Everything else in this framework is a pure function of its arguments. Time and randomness are not,
 and §15.6 turns that into a hard requirement rather than a testing convenience:

   "CI MUST additionally run the whole suite with the system clock set arbitrarily far in the
    future — ten years is sufficient — and the suite MUST pass unchanged."

 A frozen vector suite that reads the host wall clock has a shelf life. The bundle validity window
 caps at MAX_SPK_VALIDITY_SECONDS (90 days) and the skipped-key TTL at SKIPPED_TTL_MS (7 days), so a
 suite green on the day it is frozen goes red 7 days later — and §15.6 step 4 forbids the obvious
 workaround of regenerating it. ONE injectable source, threaded everywhere, is what makes the
 ten-years-forward run checkable.

 EVERY clock read in the specification routes through `clock`: §5.3 rules 5–6 (prekey validity
 window), §7.6's now_ms() and the SKIPPED_TTL_MS expiry it shares with §12.2 rule 9, §5.3's
 OPK_MAX_AGE_S, and the HANDSHAKE_CACHE_MS tombstone window of §10.7 step 4 and §11.4. A clock read
 that bypasses this property is a defect.

 INJECTION IS A TEST-ONLY AFFORDANCE. §15.5 rules 5 and 6 both say a production API MUST NOT expose
 nonce, key, or clock injection. The enforcement mechanism is header visibility: this header is
 Public and offers only +production, while IREnvironment+Testing.h — which declares the injecting
 initializer, IRFixedClock and IRScriptedRandomSource — is a PROJECT header with no
 PBXHeadersBuildPhase entry, so it is absent from the built framework's interface and from the
 umbrella. The test target still reaches it through Xcode's generated project header map.
 */

#pragma mark - IRClock

/**
 §15.5 rule 6 — Unix time, UTC. Both readings come from the same instant on a production clock; a
 test double is free to move them independently, which is what makes a TTL boundary testable.

 Neither method can fail. A clock that cannot be read is not a condition this protocol has a code
 for, and giving it one would put an error path on every prekey lookup.
 */
@protocol IRClock <NSObject>

/// Seconds since the Unix epoch. Feeds §5.3 rules 5–6 (`not_before` / `not_after`) and
/// OPK_MAX_AGE_S.
- (uint64_t)nowUnixSeconds;

/// Milliseconds since the Unix epoch. Feeds §7.6's `now_ms()`, SKIPPED_TTL_MS and
/// HANDSHAKE_CACHE_MS.
- (uint64_t)nowUnixMilliseconds;

@end

#pragma mark - IRRandomSource

/**
 §13.1 — the CSPRNG seam.

 The production implementation wraps randombytes_buf, which cannot fail. The BOOL and NSError exist
 for two other reasons: a port that must use SecRandomCopyBytes has an OSStatus to report (§13.1
 requires it be compared against errSecSuccess and a failure return ERR_RNG_FAILURE), and §15.5
 rule 5 requires an injectable source in tests, which must be able to run out of scripted bytes.

 A FAILING FILL MUST LEAVE NOTHING USABLE BEHIND. Implementations MUST zeroize `buffer` before
 returning NO. The caller's buffer is almost always a zero-filled allocation, so a fill that fails
 without saying so does not produce garbage — it produces an ALL-ZERO KEY that both parties agree
 on and that has no security whatsoever. That is v3's defect verbatim
 (IREncryptionService.m:476-481), and it is why this method returns a value at all.
 */
@protocol IRRandomSource <NSObject>

/// Fills `length` bytes at `buffer` from the CSPRNG. Returns NO with IRErrorRNGFailure on failure,
/// having first zeroized `buffer`. A zero length succeeds trivially.
- (BOOL)fillBytes:(void * _Nonnull)buffer
           length:(NSUInteger)length
            error:(NSError * _Nullable * _Nullable)error;

@end

#pragma mark - IREnvironment

/// The pair, carried as one object so a call site takes a single parameter and cannot pick up a
/// production clock with a scripted RNG by accident.
@interface IREnvironment : NSObject

/**
 The system clock and libsodium's randombytes_buf. Shared and immutable; both members are
 stateless, so the single instance is safe to use from any thread.

 This is the ONLY environment a production caller can construct.
 */
+ (IREnvironment * _Nonnull)production;

@property (nonatomic, strong, readonly) id<IRClock> _Nonnull clock;
@property (nonatomic, strong, readonly) id<IRRandomSource> _Nonnull randomSource;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
