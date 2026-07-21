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
 libsodium lifecycle and memory hygiene — SPEC §13.2, §13.3.

 IRSodium.m is one of exactly TWO files in this framework permitted to include
 <Clibsodium/sodium.h>; the other is IRSodiumCryptoProvider.m. That single property is what turns
 the §3.3 banned-API list into a one-command grep instead of reviewer discipline
 (§3.3, §16.2; tools/lint_banned_apis.py).

 Nothing here is a cryptographic primitive. Zeroization, guarded allocation and constant-time
 comparison are memory hygiene, so routing them through the id<IRCryptoProvider> seam would put a
 service dependency inside every value type.
 */
@interface IRSodium : NSObject

/**
 §13.2 — calls sodium_init() exactly once via dispatch_once and CHECKS its return value. 0 and 1
 are both success; a negative return is fatal and is LATCHED, so every subsequent call returns NO
 with IRErrorNotInitialized rather than degrading into a silently insecure service.

 v3 wrote `__unused int result = sodium_init();` in -[IREncryptionService init].
 */
+ (BOOL)ensureInitialized:(NSError * _Nullable * _Nullable)error;

/// Non-throwing predicate form, for the `[IRSodium isInitialized]` guard every crypto entry point
/// runs before touching a primitive.
+ (BOOL)isInitialized;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - Memory hygiene

/**
 §13.3 — sodium_memzero. Non-elidable: the toolchain is required to respect it, unlike a plain loop
 or a memset the optimizer may delete as a dead store.

 Safe with a NULL buffer or a zero length. Do NOT re-enable v3's commented-out memset blocks: they
 mutate a caller-owned NSData's backing store through a const pointer, which is both a
 const-correctness violation and legitimately optimizable away.
 */
void IRZeroize(void * _Nullable buffer, size_t length);

/**
 §13.3 — sodium_malloc. The region is placed against a guard page, surrounded by canaries, and is
 already mlock'd by libsodium, so no separate sodium_mlock call is needed or made.

 Guarded allocation is page-granular with guard pages, and iOS arm64 uses 16 KiB pages. It is
 therefore OPT-IN, not the default: a full MAX_SKIPPED_STORED (2000) skipped-key store allocated
 this way would cost thousands of guarded pages and thousands of mlock reservations against
 RLIMIT_MEMLOCK for 64 KB of keys. Reserve it for the few long-lived identity and prekey privates
 that §13.3's "Consider sodium_malloc" sentence actually scopes.

 Returns NULL if sodium is not initialized or the allocation fails. Free with IRGuardedFree, never
 with free().
 */
void * _Nullable IRGuardedAlloc(size_t length);

/// Frees a region obtained from IRGuardedAlloc. libsodium zeroes the region itself before
/// unmapping it. Safe with NULL.
void IRGuardedFree(void * _Nullable buffer);

/**
 Constant-time equality over `length` bytes, via sodium_memcmp.

 This is the replacement for v3's `consistentTimeEqual:hmachToCompare:`, which truncated the length
 difference to uint8_t and indexed with `i % hmacLength`, so mismatched-length inputs could compare
 equal and a zero-length input divided by zero. Note that v4's AEAD leaves nothing to compare in
 the message path (§8.2): the surviving callers are secret-value equality checks, not MAC checks.

 Both pointers MUST address at least `length` readable bytes. A zero length compares equal.
 */
BOOL IRConstantTimeEquals(const void * _Nonnull a, const void * _Nonnull b, size_t length);

/**
 §13.1 tripwire — constant-time all-zero test over `length` bytes, by OR-accumulating every byte
 and comparing the accumulator to zero.

 This is the same construction §4.4 check 3 mandates for the X25519 output. Because
 NSMutableData -dataWithLength: and calloc both zero-fill, an unchecked RNG failure yields an
 ALL-ZERO KEY that works perfectly for both parties and provides no security at all; this is the
 cheap test that catches it.
 */
BOOL IRIsAllZero(const void * _Nonnull buffer, size_t length);

#pragma mark - Randomness

/**
 §13.1 — the platform CSPRNG, via libsodium's randombytes_buf.

 THERE IS NO RETURN VALUE BECAUSE THERE IS NOTHING TO CHECK. randombytes_buf cannot fail: on
 entropy failure libsodium aborts the process. §13.1 prefers it over SecRandomCopyBytes for exactly
 that reason — SecRandomCopyBytes returns an OSStatus that v3 discarded at
 IREncryptionService.m:478, and because NSMutableData -dataWithLength: zero-fills, that discarded
 status turned an RNG failure into an ALL-ZERO KEY.

 WHY THIS LIVES HERE rather than in IREnvironment.m. The §3.3 lint requires <Clibsodium/sodium.h> to appear
 in exactly two files — IRSodium.m and IRSodiumCryptoProvider.m — so that the §3.3 banned-API list
 is a one-command grep instead of reviewer discipline. IREnvironment's production random source
 needs randombytes_buf and would have been a third. Routing it through IRSodium keeps §13.1's
 preferred primitive AND the grep rule; it is the same move IRConstantTimeEquals makes for
 sodium_memcmp.

 A zero length is a no-op. `buffer` MUST address at least `length` writable bytes.

 THIS FUNCTION DOES NOT CHECK INITIALIZATION, deliberately. It has no way to report a failure, and a
 guard that returned early would leave the caller's buffer at whatever it already held — a
 zero-filled allocation, i.e. the exact v3 failure. The initialization check belongs one level up,
 where a BOOL and an NSError exist to carry it: IREnvironment's production random source runs
 +[IRSodium ensureInitialized:] and reports IRErrorNotInitialized before ever reaching here.
 */
void IRRandomBytes(void * _Nonnull buffer, size_t length);
