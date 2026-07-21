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
 The zeroizing secret container — SPEC §13.3.

 EVERY private key and derived secret this protocol handles lives in an IRSecretBytes (or a
 subclass). Secrets are NEVER held in NSData: §13.3's copy-on-write warning applies to NSData
 verbatim — a wipe may zero one buffer while another copy survives — and NSData offers no hook
 that runs on deallocation.

 -copy and -mutableCopy are NS_UNAVAILABLE so that a secret cannot silently multiply. Duplication
 has to be written on purpose, through an explicit initializer.

 ALLOCATION STRATEGY. Two designated initializers, and the guarded one is opt-in:

   -initWithLength: / -initWithBytes:length:
       calloc, zeroized in -dealloc. THE DEFAULT, used by every derived secret — root keys, chain
       keys, message keys, encryption keys, ratchet privates, DH outputs, and every entry in the
       skipped-key store.

   -initGuardedWithLength: / -initGuardedWithBytes:length:
       sodium_malloc, guard-paged and mlock'd. Used ONLY for the few long-lived identity and prekey
       privates: IK^s_priv, IK^d_priv, SPK privates, OPK privates. §13.3 says "Consider
       sodium_malloc"; taking it as the default does not survive contact with §7.6, where
       MAX_SKIPPED_STORED is 2000 and iOS arm64 pages are 16 KiB.
 */
@interface IRSecretBytes : NSObject

/// Allocates `length` zero bytes. Returns nil when `length` is 0 or the allocation fails.
- (instancetype _Nullable)initWithLength:(NSUInteger)length NS_DESIGNATED_INITIALIZER;

/// As -initWithLength:, in guard-paged, mlock'd memory. Returns nil if libsodium is not
/// initialized, `length` is 0, or the allocation fails.
- (instancetype _Nullable)initGuardedWithLength:(NSUInteger)length NS_DESIGNATED_INITIALIZER;

/// Copies `length` bytes from `bytes`. The source buffer remains the caller's to zeroize.
- (instancetype _Nullable)initWithBytes:(const void * _Nonnull)bytes length:(NSUInteger)length;

/// As -initWithBytes:length:, in guard-paged, mlock'd memory.
- (instancetype _Nullable)initGuardedWithBytes:(const void * _Nonnull)bytes length:(NSUInteger)length;

/// Copies the contents of `data`. Provided for the boundary where non-secret transport hands over
/// bytes that become secret; the caller is responsible for the NSData's own lifetime, which this
/// class cannot control.
- (instancetype _Nullable)initWithData:(NSData * _Nonnull)data guarded:(BOOL)guarded;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;
- (id _Nonnull)copy NS_UNAVAILABLE;
- (id _Nonnull)mutableCopy NS_UNAVAILABLE;

@property (nonatomic, readonly) NSUInteger length;

/// YES when the backing store came from IRGuardedAlloc. Carried so that a deliberate duplication
/// preserves the original's allocation class.
@property (nonatomic, readonly) BOOL isGuarded;

- (const uint8_t * _Nonnull)constBytes;

/// Mutable access for the few producers that must write in place — an HKDF output buffer, a
/// clamped scalar. The buffer is NOT reallocated and its length never changes.
- (uint8_t * _Nonnull)mutableBytes;

/**
 Zeroizes the buffer at an explicit §13.3 schedule point. Idempotent, and the buffer stays
 allocated and readable (all zero) afterwards, so a pointer previously handed out never dangles.

 -dealloc zeroizes unconditionally, so this method is for the schedule rows that require the wipe
 to happen at a specific moment — "immediately after SK is derived", "immediately after KDF_CK
 produces its successor", "immediately after the AEAD call returns, success AND failure paths" —
 rather than whenever the last reference happens to go away.
 */
- (void)zeroizeNow;

/// Constant-time value equality. Different lengths compare unequal without inspecting contents.
- (BOOL)isEqualToSecretBytes:(IRSecretBytes * _Nullable)other;

/// §13.1 tripwire, in constant time. A freshly generated private key that answers YES here is the
/// signature of an unchecked RNG failure against a zero-filled buffer.
- (BOOL)isAllZero;

@end

#pragma mark - Fixed-length secrets

/**
 Base class for the fixed-width nominal secret types of §4.3.

 §4.3 requires every key kind to be a distinct type with a compile-time-fixed length whose
 constructor rejects a wrong-length input. Subclasses supply +fixedLength and +lengthErrorCode;
 everything else — validation, allocation, equality, hashing — is inherited, so a new nominal type
 cannot be introduced with the length check accidentally omitted.

 EQUALITY compares the CLASS as well as the bytes, so an IRRootKey and an IRChainKey holding
 identical bytes are NOT equal. -hash deliberately derives from the class and length only and never
 from the key bytes: secret material must not be fed into a hash table, and nothing in this
 protocol uses a secret as a collection key (the skipped-key store is keyed on the public 36-byte
 DHr_pub ‖ uint32_be(N) tuple, §7.6).
 */
@interface IRFixedLengthSecret : IRSecretBytes

/// The class invariant width, in bytes. Overridden by every concrete type.
+ (NSUInteger)fixedLength;

/// The code reported when a construction is offered the wrong number of bytes.
///
/// THE ORDERED GATES OF §10 REMAIN THE SOLE AUTHORITY FOR THE CODE A PARSE RETURNS. A gate that
/// needs a different code for the same condition performs its own explicit check first and never
/// relies on this constructor's nil.
+ (IRErrorCode)lengthErrorCode;

+ (instancetype _Nullable)fromData:(NSData * _Nonnull)data
                           guarded:(BOOL)guarded
                             error:(NSError * _Nullable * _Nullable)error;

+ (instancetype _Nullable)fromBytes:(const uint8_t * _Nonnull)bytes
                            guarded:(BOOL)guarded
                              error:(NSError * _Nullable * _Nullable)error;

/// Allocates a zero-filled secret of exactly +fixedLength bytes, for a producer that writes
/// in place through -mutableBytes.
+ (instancetype _Nullable)zeroValueGuarded:(BOOL)guarded
                                     error:(NSError * _Nullable * _Nullable)error;

/// A fresh, independent allocation with the same bytes and the same allocation class. Named
/// -duplicate rather than -copy because §13.3 makes multiplying a secret something that must be
/// written on purpose. Returns nil on allocation failure.
- (instancetype _Nullable)duplicate;

/**
 §4.2 representation normalization hook. A no-op in this class; IRX25519Private overrides it to
 apply the clamp `k[0] &= 0xF8; k[31] &= 0x7F; k[31] |= 0x40`.

 +fromData:guarded:error: and +fromBytes:guarded:error: invoke it automatically, which is what
 turns §4.2's "clamp at generation" into "clamp at construction" and covers generation, state load
 and vector input in one place. +zeroValueGuarded:error: does NOT invoke it — a zero buffer is not
 key material — so a caller that fills a zero value through -mutableBytes MUST call this afterwards.

 NORMALIZATION IS NOT VALIDATION. §12.2 rule 8 REJECTS an unclamped scalar read from a state blob
 rather than silently re-clamping it (§19.5), so the state decoder MUST run its own clamp check
 BEFORE constructing the type. Use +[IRX25519Private bytesAreClamped:] for that.
 */
- (void)normalizeRepresentation;

@end
