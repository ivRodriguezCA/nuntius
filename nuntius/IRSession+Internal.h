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
#import <nuntius/IRSecretBytes.h>
#import <nuntius/IRSession.h>

#import "IRRatchetState.h"

/**
 IRSession's ratchet-facing half — PROJECT visibility, absent from the built framework.

 IRSession.h is Public and mentions no Project type. This extension is where the state lives, and
 it is imported by the session stores, by IRSessionDispatch, by the layer above, and by the specs.
 A host linking the framework cannot reach any of it.

 THE COMMIT PROTOCOL IS §7.7'S ATOMICITY RULE, and the two methods are not interchangeable:

     snapshot = [session snapshot]
     pt = [IRRatchet decryptOnSnapshot:snapshot ...]
     pt != nil  ->  [session commitSnapshot:snapshot error:&e]     then persist
     pt == nil  ->  [session discardSnapshot:snapshot]             and persist NOTHING

 -commitSnapshot: performs the three steps of the sequence documented on IRRatchet in the one order
 that is correct — zeroize the snapshot store's pending removals, swap the pointer, then zeroize
 the superseded state — so a caller cannot get the order wrong by writing them out itself.
 */
@interface IRSession ()

/// The live state. Replaced wholesale by -commitSnapshot:; never mutated field by field from
/// outside, because a partial update is exactly what §7.7 forbids.
@property (nonatomic, strong, readonly) IRRatchetState * _Nonnull state;

/// Wraps a freshly initialized or freshly decoded state. Fails with IRErrorStateCorrupt for a
/// zeroized state, a role outside {0x01, 0x02}, or a SESSION_AD whose peer half does not resolve.
+ (instancetype _Nullable)sessionWithState:(IRRatchetState * _Nonnull)state
                                     error:(NSError * _Nullable * _Nullable)error;

/// §7.7 — a copy to decrypt against. Returns nil on allocation failure, which the caller MUST
/// treat as a failed decrypt: a state that could not be copied is one whose secrets must not be
/// touched.
- (IRRatchetState * _Nullable)snapshot;

/**
 §7.7 commit. Zeroizes the committed store's pending removals, installs `snapshot` as the live
 state, then zeroizes the state it replaced.

 The last step is safe ONLY because -[IRRatchetState snapshot] deep-copies `RK`, `CKs`, `CKr` and
 `DHs.priv`: on a message that performs no DH ratchet the committed state's `RK` holds the same
 bytes as its predecessor, and had they shared one object this would wipe the live root key on the
 commit path of MOST messages while every single-message round-trip test still passed.

 Refuses a zeroized snapshot with IRErrorStateCorrupt — committing a discarded one would install a
 session keyed with zeros, and the failure would not surface until the next message.
 */
- (BOOL)commitSnapshot:(IRRatchetState * _Nonnull)snapshot
                 error:(NSError * _Nullable * _Nullable)error;

/// §7.7 discard. Idempotent, and safe to call after IRRatchet has already zeroized the snapshot on
/// its own failure path. NEVER calls -zeroizePendingRemovals: the live store still owns every entry
/// this attempt removed, and wiping them here is the `NEG-SKIP-RETAIN` failure.
- (void)discardSnapshot:(IRRatchetState * _Nonnull)snapshot;

/// §12.1 — the 472 + 76n byte blob. The caller owns the result and MUST zeroize it once sealed.
- (IRSecretBytes * _Nullable)serializedState:(NSError * _Nullable * _Nullable)error;

/// §11.1.1 / §11.4 — zeroizes every secret this session holds and marks it torn down. The CALLER
/// is responsible for writing the tombstone; -[IRSessionStore tearDownSession:atTimeMs:error:]
/// does both, and is the only path that should be used from outside a store.
- (void)tearDown;

@end
