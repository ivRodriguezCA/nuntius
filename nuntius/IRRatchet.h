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
#import <nuntius/IRCryptoProvider.h>
#import <nuntius/IREnvironment.h>
#import <nuntius/IRErrors.h>
#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>

#import "IRMessageHeader.h"
#import "IRRatchetState.h"

/**
 The Double Ratchet — SPEC §7.2–§7.9, §8.1, §8.5, §10.4, §11.3.

 PURE FUNCTIONS OVER IRRatchetState. No instance state, no I/O, no store access, no clock. The
 caller supplies the snapshot, the budget and the time; the caller performs the commit. That is what
 lets §7.7's atomicity rule be a property of a data flow rather than a discipline: this class cannot
 reach the live session, so it cannot half-mutate it.

 THE FOUR-STEP RECEIVE SEQUENCE Layer 9 MUST FOLLOW, and the reason each step is separate:

     1. gate the bytes          §10.1 / §10.2 — IRMessageGate, touches no secret
     2. budget = [IRSkipBudget budget]                ONCE PER RECEIVED MESSAGE, not per attempt
     3. snapshot = [live snapshot]                    §7.7
     4. pt = [IRRatchet decryptOnSnapshot:...]
        - pt != nil  -> [snapshot.skipped zeroizePendingRemovals];
                        commit snapshot as the live state;
                        [oldLive zeroizeAsSupersededState];
                        persist
        - pt == nil  -> DISCARD the snapshot. It has already been zeroized here; do NOT commit it.

 Step 2 is separate from step 4 because §7.6 makes `MAX_SKIP_PER_MESSAGE` an AGGREGATE across both
 SkipMessageKeys calls of one message, and §11.5 rule 3 forbids trying a second session so that the
 bound cannot be multiplied. A budget created inside decrypt would silently restore the per-call
 semantics §7.6 rejects.

 ZEROIZATION ON THE FAILURE PATH IS PERFORMED HERE. Every non-success exit from -decryptOnSnapshot:
 calls -zeroizeAsDiscardedSnapshot before returning, so §7.7's "every intermediate secret derived
 during the attempt MUST be zeroized" cannot be lost by a caller that forgets. The consequence is
 that a discarded snapshot is inert: IRRatchetState.isZeroized reads YES, and every method here
 refuses such a state with IRErrorStateCorrupt. A caller that commits one gets a loud error on its
 next operation rather than a session silently keyed with zeros.

 THIS CLASS NEVER ZEROIZES AN ARGUMENT IT DID NOT CREATE — the convention IRProtocolKDF and
 IRCryptoProvider already follow. See -initiatorStateWithSharedKey: for the one place where §13.3
 assigns a wipe to the caller as a result.
 */
@interface IRRatchet : NSObject

#pragma mark - §7.5 Ratchet initialization

/**
 §7.5, initiator A, after computing `SK` (§6.3) and verifying B's bundle (§5.3):

     RK        = SK
     DHr       = SPK_B
     DHs       = generate_X25519_keypair()
     dh        = X25519(DHs.priv, DHr)          §4.4 check 3
     (RK, CKs) = KDF_RK(RK, dh)
     CKr       = none;  Ns = Nr = PN = 0;  skipped = {};  role = initiator

 `sharedKey` IS NON-OPTIONAL AND NOMINALLY TYPED, which is the structural answer to defect 2. v3's
 `setupRatchetForSendingWithSharedKey:andDHReceiverKey:` never read its `sharedKey` argument while
 the receiving counterpart assigned it straight to `rootKey`; the two sides initialised
 asymmetrically and no message key was a function of the handshake. There is no code path here that
 constructs a ratchet without one.

 THE SHARED KEY IS COPIED, NOT ADOPTED. §13.3 requires `SK` be zeroized "immediately after ratchet
 initialization" and IRX3DHResult owns that wipe — so if the state retained the caller's object,
 the caller honouring its own schedule would wipe the new session's root key. The caller MUST still
 call -[IRX3DHResult zeroize] after this returns; doing so is now safe rather than fatal.

 `prologue` is retained for §11.3's rule that A reuses the identical `EK_A`, `spk_id`, `opk_flag`
 and `opk_id` on every type `0x02` message until B replies.
 */
+ (IRRatchetState * _Nullable)initiatorStateWithSharedKey:(IRRootKey * _Nonnull)sharedKey
                                    responderSignedPreKey:(IRX25519Public * _Nonnull)responderSignedPreKey
                                                sessionAD:(IRSessionAD * _Nonnull)sessionAD
                                              handshakeId:(NSData * _Nonnull)handshakeId
                                                 prologue:(IRSessionPrologue * _Nonnull)prologue
                                                 provider:(id<IRCryptoProvider> _Nonnull)provider
                                                    error:(NSError * _Nullable * _Nullable)error;

/**
 §7.5, responder B, on first receiving a type `0x02` message and computing the same `SK`:

     RK  = SK
     DHs = COPY of the SPK_B key pair          both halves
     DHr = CKs = CKr = none;  Ns = Nr = PN = 0;  skipped = {};  role = responder

 B then processes the header normally: `header.dh != DHr` because `DHr` is none, so B runs
 DHRatchet, which produces a `CKr` equal to A's `CKs`.

 THE COPY IS MADE HERE, and that is a deliberate departure from the plan's `signedPreKeyPairCopy:`
 parameter name. §7.5 calls aliasing the prekey store "the single easiest way to brick a live
 deployment": §7.4 step 4 zeroizes `DHs.priv` unconditionally on B's FIRST ratchet of EVERY session,
 so an alias destroys `SPK_B_priv` itself and breaks every concurrent and future handshake against
 that `spk_id` until rotation. The failure is silent and misattributed — X25519 clamping maps an
 all-zero scalar to 2^254, so DH1 and DH3 against the wiped key produce non-zero garbage, §4.4
 check 3 does NOT fire, `spk_id` still resolves, and B reports ERR_AEAD_AUTH_FAILED, the code §1.2
 defines as an active man-in-the-middle. B misdiagnoses its own key destruction as an attack.

 A parameter name is a comment; taking the copy here is a mechanism. Passing an already-copied pair
 remains correct — the second copy costs 32 bytes and nothing else.

 As above, `sharedKey` is copied rather than adopted, and the caller still owns its wipe.
 */
+ (IRRatchetState * _Nullable)responderStateWithSharedKey:(IRRootKey * _Nonnull)sharedKey
                                         signedPreKeyPair:(IRX25519KeyPair * _Nonnull)signedPreKeyPair
                                                sessionAD:(IRSessionAD * _Nonnull)sessionAD
                                              handshakeId:(NSData * _Nonnull)handshakeId
                                                    error:(NSError * _Nullable * _Nullable)error;

#pragma mark - §7.4 / §7.6 — exposed for the gate, normally reached through -decryptOnSnapshot:

/**
 §7.4's five steps, in order, on a snapshot.

 Step 1 drains the OLD receiving chain to `header.PN` BEFORE `DHr` is replaced, and is a no-op when
 `CKr` is none — the responder's very first receive, where a port that dereferenced the null chain
 key would trap.

 Step 4 (`zeroize(DHs.priv)`, then a fresh pair) is UNCONDITIONAL AND IDENTICAL FOR BOTH ROLES. It is
 safe on the responder's first ratchet only because the state holds a session-owned copy of the
 signed prekey scalar — see +responderStateWithSharedKey:.

 The two KDF_RK calls are STRICTLY SEQUENTIAL: the second consumes the `RK` the first produced. The
 root chain advances twice per ratchet and never restarts. v3's `performDHRatchet:` assigned
 `self.rootKey` twice from two INDEPENDENT derivations of the DH output alone, discarding the
 previous root key both times, so the root chain had no continuity at all.

 May return IRErrorTooManySkipped (from step 1) or IRErrorSmallOrderKey (from either DH).
 */
+ (BOOL)dhRatchetOnState:(IRRatchetState * _Nonnull)state
                   header:(IRMessageHeader * _Nonnull)header
                   budget:(IRSkipBudget * _Nonnull)budget
                 atTimeMs:(uint64_t)nowMs
                 provider:(id<IRCryptoProvider> _Nonnull)provider
                    error:(NSError * _Nullable * _Nullable)error;

/**
 §7.6 SkipMessageKeys — derive and store the message keys for `[state.Nr, until)`.

 Returns YES without touching anything when `CKr` is none or `until < state.Nr` (the latter is the
 caller's replay case, §7.9 phase 3c). On IRErrorTooManySkipped THE STATE IS LEFT UNMODIFIED — the
 budget is checked against the whole span before the first key is derived, never per key.

 `budget` is the aggregate for one RECEIVED MESSAGE and is shared with the call §7.4 step 1 makes,
 so a DH-ratchet message cannot derive 1000 keys in the old chain and 1000 more in the new one.
 v3 additionally DISCARDED the error from its second `addSkippedMessages:` call
 (IRDoubleRatchetService.m:188), so an over-limit skip on the post-ratchet path was ignored outright.

 Keys land in the store keyed by `state.DHr ‖ uint32_be(state.Nr)` — the CURRENT `DHr`, which during
 §7.4 step 1 is still the OLD one. `Nr` advances once per derived key, whether that key is stored as
 skipped or used immediately.
 */
+ (BOOL)skipMessageKeysOnState:(IRRatchetState * _Nonnull)state
                          until:(uint32_t)until
                         budget:(IRSkipBudget * _Nonnull)budget
                       atTimeMs:(uint64_t)nowMs
                       provider:(id<IRCryptoProvider> _Nonnull)provider
                          error:(NSError * _Nullable * _Nullable)error;

#pragma mark - §7.8 RatchetEncrypt

/**
 §7.8 — returns the complete `header ‖ ciphertext ‖ tag`.

 Guards, in order: `len(plaintext) > MAX_PLAINTEXT` -> IRErrorPlaintextTooLarge; `CKs` is none ->
 IRErrorNoSendingChain; `Ns >= 0x7FFFFFFF` -> IRErrorCounterOverflow. EMPTY PLAINTEXT IS LEGAL and
 produces a 72-byte type `0x01` message (§10.4) — v3 returned nil when the CBC output was
 zero-length, conflating "empty input" with "encryption failed".

 `initiatorIdentity` and `identityBinding` are required for, and only for, type `0x02`. `IKB_A` is
 PASSED IN AND NEVER RE-SIGNED: §11.3 notes Ed25519 signing is not contractually deterministic
 across the four platforms, and since nothing in the receive path compares `IKB_A` across messages a
 port that re-signed would emit a different 64-byte value per message, decrypt correctly, and never
 be caught. The prologue comes from the state rather than the caller, which is what makes §11.3's
 "identical field values on every type `0x02` message" a property of the data flow.

 STRONGER THAN §7.8 ON ONE POINT, deliberately. The pseudocode advances `CKs` before the AEAD; this
 implementation derives everything first and mutates the state only once the seal has succeeded. A
 seal failure is an internal error (allocation, libsodium), never peer-triggerable, and §7.7's
 atomicity rule covers only decrypt — but leaving a failed send having consumed a chain-key step and
 destroyed its predecessor makes an unrecoverable message out of a recoverable one. The emitted
 bytes are identical either way, so no vector can observe the difference.

 Advances `Ns` and `send_counter`; zeroizes `mk` and `enc_key` on both paths. Does NOT persist —
 §7.8's `persist(state)` belongs to the caller and MUST complete before the message is emitted.
 */
+ (NSData * _Nullable)encryptOnState:(IRRatchetState * _Nonnull)state
                            plaintext:(NSData * _Nonnull)plaintext
                          messageType:(IRMessageType)messageType
                    initiatorIdentity:(IRIdentityKeyPair * _Nullable)initiatorIdentity
                      identityBinding:(IREd25519Signature * _Nullable)identityBinding
                             provider:(id<IRCryptoProvider> _Nonnull)provider
                                error:(NSError * _Nullable * _Nullable)error;

#pragma mark - §7.9 RatchetDecrypt

/**
 §7.9 phases 2–3d, verbatim, on a snapshot. Never touches live state — it has no way to reach it.

   phase 2   drop TTL-expired skipped entries; `ad = SESSION_AD ‖ message[0 .. HDR_LEN)`;
             `ct = message[HDR_LEN .. end)`
   phase 3a  a stored key for `hdr.dh ‖ uint32_be(hdr.N)` -> expand, open, and return WITHOUT a DH
             ratchet and WITHOUT advancing `Nr`. On AEAD failure THE STORED KEY IS RETAINED: v3
             called `removeObjectForKey:` at IRDoubleRatchetService.m:168 and `aeDecryptData:` at
             :170, in that order, so a corrupted tag permanently destroyed the only copy of the key
             and the message became unrecoverable. `NEG-SKIP-RETAIN` is the vector.
   phase 3b  DH ratchet when `s.DHr` is none or `hdr.dh != s.DHr`
   phase 3c  `hdr.N < s.Nr` -> IRErrorReplay, an explicit code and not a silent AEAD failure; then
             SkipMessageKeys to `hdr.N` on the NEW chain
   phase 3d  derive, advance `Nr`, expand, open; zeroize `mk` and `enc_key` on BOTH paths

 ON ANY FAILURE the snapshot is zeroized and nil is returned with the error; the caller discards it.
 ON SUCCESS the caller commits it — see the four-step sequence on the class. An ERR_AEAD_AUTH_FAILED
 MUST NOT leave behind a performed DH ratchet, an advanced `Nr`, a consumed one-time prekey, or
 newly inserted skipped keys; since all of those live on the discarded snapshot, none can.

 v3 had no such rule: it inserted skipped keys, ratcheted, advanced the chain and incremented the
 receive counter, and only then called `aeDecryptData:`. An attacker able to inject a well-formed
 but unauthenticated message carrying a novel ratchet key could force the receiver's ratchet forward
 and PERMANENTLY DESYNCHRONISE a live session — an unauthenticated denial of service that is state
 corruption rather than a wrong plaintext, so no round-trip test detects it. `NEG-ATOMIC`.

 `header` MUST be the one IRMessageGate parsed from `message`; the prefix is re-checked here so a
 mismatched pair reports IRErrorStateCorrupt rather than authenticating one header and decrypting
 under another.

 Handles both wire types. §11.2 routes a type `0x02` message that resolves to an EXISTING session
 through this same path, and the ratchet consumes the union `(dh, N, PN, nonce)` identically; only
 the header length, and therefore the AD length, differ.
 */
+ (NSData * _Nullable)decryptOnSnapshot:(IRRatchetState * _Nonnull)snapshot
                                message:(NSData * _Nonnull)message
                                 header:(IRMessageHeader * _Nonnull)header
                                 budget:(IRSkipBudget * _Nonnull)budget
                               atTimeMs:(uint64_t)nowMs
                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                  error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
