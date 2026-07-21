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
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRSecretBytes.h>

#import "IRRatchetState.h"

/**
 The session state blob — SPEC §12.1, §12.2, §12.4, §19.5.

 WHAT THIS REPLACES. v3 restored session state with `NSKeyedUnarchiver unarchiveObjectWithData:`
 (IRDoubleRatchetService.m:315, :410) — defect 12, and §3.3 bans the whole family for key material
 and session state. Two separate problems: the deserialization-gadget surface, and the fact that no
 two runtimes agree byte-for-byte on a native serializer, so `NSKeyedArchiver`, Java
 `Serializable`, Kotlin `@Serializable` and Swift `Codable` cannot interoperate by construction.

 THE LAYOUT IS BYTE-NORMATIVE AND THE EXACT-LENGTH RULE IS ITS ENFORCEMENT MECHANISM.

     total = 472 + 76 * skipped_count,  exactly

 §12.2's implementer note is emphatic that 472 must be DERIVED from the field table rather than
 copied: "an error in this constant would make every conformant implementation reject every other's
 blobs". kIRLenStatePrefix carries a §18 static assertion of the full sum, so the derivation is
 checked at compile time rather than trusted.

 SECRETS DO NOT TRAVEL IN NSData HERE. The blob contains `RK`, `DHs_priv`, `CKs`, `CKr` and every
 stored message key, and §13.3 schedules the serialized buffer for zeroization "after sealing, and
 after parsing". An NSData return would put all of that into a copy-on-write container with no
 zeroizing hook — the same correction Layer 0 made for IRByteWriter's IKM path and Layer 2 made for
 the HKDF outputs, arrived at here for the third time from a different direction. So:

   - +serializeState:error: yields IRSecretBytes, and the CALLER zeroizes it once sealed.
   - +deserializeState:atTimeMs:error: takes IRSecretBytes and reads it WITHOUT copying, via
     -[IRByteReader initWithBytesNoCopy:length:].
   - +deserializeStateFromData:atTimeMs:error: exists for the §15.3 `state.json` path only, where
     the blob is a literal in a vector file and there is nothing secret to protect.

 There is deliberately NO NSData-returning serializer. A test that needs bytes copies them out
 explicitly, so the one place a session's key material can enter an unwipeable container is visible
 at its call site.

 NOTHING IS CONSTRUCTED UNTIL EVERY RULE HAS PASSED. §12.2's "a failure at any step MUST yield no
 partially-loaded state" is met structurally rather than by unwinding: rules 1–8 are byte tests at
 fixed offsets, and the first object is allocated only after rule 8 returns.
 */
@interface IRSessionStateCodec : NSObject

#pragma mark - §12.1 encode

/**
 Emits exactly `472 + 76 * skipped_count` bytes, asserted through
 -[IRByteWriter finishSecretExpectingLength:guarded:error:].

 Skipped entries are written in the store's INSERTION order (§7.6's global FIFO), which §12.1 fixes
 as the serialization order — one mechanism, not two that can drift.

 Refuses, with IRErrorStateCorrupt, to emit a blob its own parser would reject: a zeroized state, a
 role outside {0x01, 0x02}, a `skipped_count` above `MAX_SKIPPED_STORED`, or a `DHs_priv` that is
 not in §4.2 clamped form. The last cannot arise through IRX25519Private, which clamps at
 construction — it is checked anyway so that a future path which bypasses that constructor fails
 here rather than producing blobs every other port rejects under §12.2 rule 8.

 The result is NOT guarded (`sodium_malloc`) storage. It is short-lived by construction — §12.3
 requires it be sealed and then wiped — and a guarded allocation rounds up to a page per call.
 */
+ (IRSecretBytes * _Nullable)serializeState:(IRRatchetState * _Nonnull)state
                                      error:(NSError * _Nullable * _Nullable)error;

#pragma mark - §12.2 decode

/**
 §12.2 rules 1–9, IN ORDER.

     1  len(blob) >= 472                                    -> ERR_STATE_CORRUPT
     2  magic == "NTS4"                                     -> ERR_STATE_CORRUPT
     3  state_format == 0x01                                -> ERR_STATE_CORRUPT
     4  role ∈ {0x01,0x02}; every _present byte ∈ {0x00,0x01} -> ERR_STATE_CORRUPT
     5  skipped_count <= 2000                               -> ERR_STATE_CORRUPT
     6  len == 472 + 76 * skipped_count EXACTLY             -> ERR_TRAILING_BYTES
     7  every stored public key passes §4.4 checks 1–2      -> ERR_STATE_CORRUPT
     8  (blob[243] & 0x07) == 0 and (blob[274] & 0xC0) == 0x40 -> ERR_STATE_CORRUPT
     9  drop and zeroize entries older than SKIPPED_TTL_MS against `nowMs`

 RULE 6 IS THE ONLY ONE THAT IS NOT ERR_STATE_CORRUPT, in either length direction. 7105 is
 state-blob-only: §19.4 moved every bundle length failure to ERR_BUNDLE_MALFORMED precisely so that
 this code means one thing.

 RULE 7 EXCLUDES THE TWO Ed25519 IDENTITY KEYS at blob offsets 19 and 83. §4.4 check 2 masks an
 RFC 7748 u-coordinate; bit 255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is
 set in roughly half of all valid identities. Applying it there rejects half of all conformant
 blobs, intermittently, in a way that reads as a signature bug. The keys it DOES cover are
 `DHs_pub`, `DHr_pub` when present, the two `IK^d` inside SESSION_AD, the prologue's `EK_A` when
 present, and every skipped entry's `dh_pub`.

 RULE 8 REJECTS RATHER THAN RE-CLAMPING (§19.5), and it runs BEFORE IRX25519Private is constructed
 — that constructor clamps, so a check placed after it would silently accept every unclamped blob
 and pass its own round-trip test. `NEG-STATE-UNCLAMPED` is the vector, in both bit positions.

 RULE 9 IS PERFORMED THROUGH THE STORE'S OWN TTL SWEEP, so the age comparator and the
 backwards-clock guard have exactly one implementation. `nowMs` is the §15.5 rule 6 injectable time
 source; §15.3 requires every `state.json` vector to supply an `inputs.now_ms` placing all entries
 inside the TTL, or the artifact destroys itself seven days after the freeze.

 `blob` is read in place and is neither copied nor retained. The caller owns it and MUST zeroize it
 (§13.3, "serialized state buffer — after sealing, and after parsing").
 */
+ (IRRatchetState * _Nullable)deserializeState:(IRSecretBytes * _Nonnull)blob
                                      atTimeMs:(uint64_t)nowMs
                                         error:(NSError * _Nullable * _Nullable)error;

/// As -deserializeState:atTimeMs:error:, for the §15.3 `state.json` vectors — where the blob is a
/// literal in a vector file, is already public, and has no zeroization schedule to honour.
+ (IRRatchetState * _Nullable)deserializeStateFromData:(NSData * _Nonnull)blob
                                              atTimeMs:(uint64_t)nowMs
                                                 error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Lengths

/// `472 + 76 * skippedCount`, or 0 when `skippedCount` exceeds `MAX_SKIPPED_STORED` — which is
/// what makes the multiplication unable to overflow at every call site that consults it first.
+ (NSUInteger)blobLengthForSkippedCount:(uint32_t)skippedCount;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
