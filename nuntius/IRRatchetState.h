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
#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>

#import "IRSessionAD.h"
#import "IRSkippedKeyStore.h"
#import "IRX3DH.h"

#pragma mark - IRSkipBudget

/**
 §7.6's `skip_budget` — the AGGREGATE bound on message keys one RECEIVED MESSAGE may derive.

 "Deliberately specified as an aggregate per received message, not a per-call bound. A DH-ratchet
 message skips `header.PN` keys in the old chain and then `header.N` in the new one; a per-call bound
 of 1000 would permit 2000 derivations per message and let a single message evict the entire store."

 It is an OBJECT rather than a counter on the state for two reasons. §7.6 says it is "not persisted",
 so putting it on IRRatchetState would place a non-persisted field beside eighteen persisted ones
 and invite a state codec to serialize it. And it is created ONCE PER RECEIVED MESSAGE, not once per
 decryption attempt — §11.5 rule 3 forbids trying a second session precisely so that this bound
 cannot be multiplied — which is a lifetime an object expresses and an integer does not.
 */
@interface IRSkipBudget : NSObject

/// A budget of `MAX_SKIP_PER_MESSAGE` (1000). The only spelling protocol code should use.
+ (instancetype _Nonnull)budget;

/// An explicit limit, for tests that need to reach the boundary without deriving 1000 keys.
+ (instancetype _Nonnull)budgetWithLimit:(uint32_t)limit;

/// Remaining allowance.
@property (nonatomic, readonly) uint32_t remaining;

/**
 Deducts `count`, or returns NO leaving the budget untouched.

 §7.6 checks the budget BEFORE deriving anything ("state MUST be left unmodified"), so this is
 called with the whole requested span and never once per key.
 */
- (BOOL)consume:(uint32_t)count;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRRatchetState

/**
 The §7.1 state variables, and nothing else — SPEC §7.1, §7.5, §7.7, §12.1.

 §7.7's implementation note says ports "SHOULD NOT mirror v3's class-with-mutable-properties shape",
 and recommends a value type so the snapshot is free. Objective-C has no value type that can hold a
 zeroizing secret — a `struct` of object pointers copies the pointers, which is the aliasing bug, not
 a fix for it. So the snapshot is explicit, and -snapshot's contract is the whole of §7.7 for this
 port.

 WHAT -snapshot COPIES, AND WHY THE SPLIT IS NOT ARBITRARY.

   DEEP-COPIED (fresh allocations): RK, CKs, CKr, and DHs.priv.
   SHARED (immutable objects):      DHs.pub, DHr, sessionAD, handshakeId, prologue.
   CONTAINER-COPIED:                skipped, via -copyForSnapshot (§7.7's D4).

 The four deep copies are what make -zeroizeAsSupersededState unconditionally correct. Consider a
 decrypt that performs no DH ratchet: the committed state's RK holds the same 32 bytes as the state
 it replaced. If the two shared one object, wiping the superseded state would wipe the live root key
 — and the bug appears only on the commit path of a NON-ratcheting message, which is most messages,
 while every single-message round-trip test still passes. Copying 128 bytes per received message
 buys that away entirely.

 The skipped store is the one place where copying does NOT win: 2000 entries is 64 KB per received
 message, so it shares entry objects and tracks ownership instead. IRSkippedKeyStore's header
 documents the resulting three-way zeroization schedule; it is the reason there are two zeroize
 methods here rather than one.

 THE PROPERTY NAMES ARE §7.1'S NAMES. `RK`, `DHs`, `DHr`, `CKs`, `CKr`, `Ns`, `Nr`, `PN` read
 oddly against Cocoa conventions and are kept anyway: every line of §7.4, §7.6, §7.8 and §7.9
 transliterates directly, so a reviewer comparing code against the specification is comparing like
 with like. The constructor uses descriptive names because a fifteen-argument call site is where
 that trade runs the other way.
 */
@interface IRRatchetState : NSObject

/**
 Every §12.1 field at once. Used by §7.5's two initializers and by the Layer 8 state decoder, which
 is why it takes the optionals as optionals rather than offering four convenience overloads.

 `skipped` may be nil, meaning an empty store.

 NOTE ON WHAT IS *NOT* VALIDATED: `Ns`, `Nr` and `PN` are accepted at any uint32 value. §12.2 lists
 no bound on them, so imposing one would make this implementation reject blobs the other three ports
 accept. It is safe: §7.8 refuses to encrypt at `Ns >= 0x7FFFFFFF`, and a restored `Nr` above the
 gate's `0x7FFFFFFF` ceiling makes every arriving `N` compare low and take §7.9 phase 3c's
 ERR_REPLAY exit, so neither counter can be driven to overflow.
 */
+ (instancetype _Nullable)stateWithRole:(IRSessionRole)role
                               sessionAD:(IRSessionAD * _Nonnull)sessionAD
                             handshakeId:(NSData * _Nonnull)handshakeId
                                 rootKey:(IRRootKey * _Nonnull)rootKey
                          ratchetKeyPair:(IRX25519KeyPair * _Nonnull)ratchetKeyPair
                       peerRatchetPublic:(IRX25519Public * _Nullable)peerRatchetPublic
                         sendingChainKey:(IRChainKey * _Nullable)sendingChainKey
                       receivingChainKey:(IRChainKey * _Nullable)receivingChainKey
                                      Ns:(uint32_t)Ns
                                      Nr:(uint32_t)Nr
                                      PN:(uint32_t)PN
                             sendCounter:(uint64_t)sendCounter
                                prologue:(IRSessionPrologue * _Nullable)prologue
                                 skipped:(IRSkippedKeyStore * _Nullable)skipped
                                   error:(NSError * _Nullable * _Nullable)error;

#pragma mark - §7.1 state variables

/// Root key. Replaced wholesale by each KDF_RK step; never mutated in place.
@property (nonatomic, strong) IRRootKey * _Nonnull RK;

/// Our current ratchet key pair. For a responder before its first ratchet this is a session-owned
/// COPY of the signed prekey pair (§7.5) — §7.4 step 4 destroys the private half, and if it were an
/// alias into the prekey store that step would destroy the live medium-term key.
@property (nonatomic, strong) IRX25519KeyPair * _Nonnull DHs;

/// The peer's current ratchet public, or nil before the first receive.
@property (nonatomic, strong) IRX25519Public * _Nullable DHr;

/// Sending chain key, or nil — a responder has none until its first ratchet, and §7.8 answers a
/// send attempt in that window with ERR_NO_SENDING_CHAIN.
@property (nonatomic, strong) IRChainKey * _Nullable CKs;

/// Receiving chain key, or nil — an initiator has none until B replies.
@property (nonatomic, strong) IRChainKey * _Nullable CKr;

/// Messages sent in the current sending chain.
@property (nonatomic) uint32_t Ns;

/// Messages received in the current receiving chain.
@property (nonatomic) uint32_t Nr;

/// Length of the PREVIOUS sending chain. Distinct storage from `Ns`, and §9.1 is emphatic that the
/// header's PN field comes from here "never from state.Ns" — defect 10, which v3 committed by
/// writing `numberOfSentMessages` into both header slots so the previous-chain count was never
/// transmitted and cross-chain recovery could not work.
@property (nonatomic) uint32_t PN;

/// §7.6's bounded store.
@property (nonatomic, strong) IRSkippedKeyStore * _Nonnull skipped;

#pragma mark - Session scope (fixed at handshake)

@property (nonatomic, readonly) IRSessionRole role;

/// §6.5's 141 bytes, in role order, prefixed to the AD of every AEAD operation in the session.
@property (nonatomic, strong, readonly) IRSessionAD * _Nonnull sessionAD;

/// §11.1 — `IK_A^d ‖ EK_A`, 64 bytes.
@property (nonatomic, copy, readonly) NSData * _Nonnull handshakeId;

#pragma mark - §12.5 and §11.3

/// Incremented on every successful RatchetEncrypt and persisted before the message is emitted.
/// §12.5's rollback tripwire compares it against a backup-excluded record on load.
@property (nonatomic) uint64_t sendCounter;

/// §11.3 — the initiator's stored prologue, non-nil exactly while type `0x02` is still being sent.
/// Cleared automatically by IRRatchet on the first successful decrypt, so "A stops sending prekey
/// messages once CKr exists" is a property of the data flow rather than of the caller remembering.
@property (nonatomic, strong) IRSessionPrologue * _Nullable prologue;

/// §11.3 — YES when the next outbound message must be type `0x02`: an initiator that has not yet
/// decrypted anything from B and still holds the prologue needed to build one.
@property (nonatomic, readonly) BOOL shouldSendPreKeyMessage;

#pragma mark - §7.7 snapshotting

/**
 A snapshot per the split documented on the class.

 Returns nil on allocation failure, which a caller MUST treat as a failed decrypt. The plan typed
 this `_Nonnull`; a state that could not be copied is one whose live secrets must not be touched, so
 the honest nil is the fail-closed direction.
 */
- (IRRatchetState * _Nullable)snapshot;

/// YES once any zeroize method has run. IRRatchet refuses to operate on such a state with
/// IRErrorStateCorrupt, so a caller that commits a discarded snapshot gets a loud error on its next
/// operation instead of a session silently keyed with zeros.
@property (nonatomic, readonly) BOOL isZeroized;

#pragma mark - §13.3 zeroization — three call sites, and they are not interchangeable

/**
 DISCARD (§7.7). Wipes this snapshot's own RK, CKs, CKr and DHs.priv copies, and the skipped-key
 entries this attempt DERIVED. Leaves shared entries alone: the live store still owns them, and
 wiping them here is exactly the `NEG-SKIP-RETAIN` failure.
 */
- (void)zeroizeAsDiscardedSnapshot;

/**
 COMMIT. Call on the state the committed snapshot REPLACED, after calling
 -zeroizePendingRemovals on the committed store.

 Wipes the superseded RK, CKs, CKr and DHs.priv — §13.3's rows for `CK` ("immediately after KDF_CK
 produces its successor"), for the root key, and for "ratchet private keys, session-owned copies
 only". Those schedule points all land HERE rather than inside the KDFs, because a KDF that wiped
 its input would destroy the live session's CKr on every forged message; §7.7's atomicity rule is
 what moves them.

 Does not touch skipped entries — the committed store shares them.
 */
- (void)zeroizeAsSupersededState;

/// TEARDOWN. Everything, including every entry in the skipped store. MUST NOT be called on a
/// snapshot or on a state that shares a store with a live session.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
