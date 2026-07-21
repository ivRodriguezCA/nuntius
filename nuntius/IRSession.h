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
#import <nuntius/IRErrors.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>

/**
 One live session with one peer — SPEC §7.7, §11.1, §11.3, §12.5.

 The consumer-facing handle. Everything a host needs to route, display and persist a session, and
 nothing it could use to reach the ratchet: `RK`, `CKs`, `CKr` and the skipped-key store are behind
 IRSession+Internal.h, at Project visibility, which is absent from the built framework.

 THIS IS THE ONLY MUTABLE OBJECT IN THE PROTOCOL LAYER, and it holds exactly one mutable field —
 the current IRRatchetState. §7.7 requires that a failed decrypt mutate nothing, so a receive works
 on a SNAPSHOT and commits by replacing that single pointer. Commit is therefore atomic by
 construction rather than by ordering discipline: there is no window in which half a decrypt is
 visible, because there is no second field to update.

 §11.1's TWO INDICES ARE BOTH DERIVED FROM THIS OBJECT — `handshakeId` for type `0x02` dispatch
 (§11.2), `peerIdentityKeyPair` for type `0x01` selection (§11.5). Neither is stored twice: the
 identity pair is read from the stored SESSION_AD at §6.5's offsets, which is exactly why §12.1
 stores no identity key of its own.

 NOT THREAD-SAFE, deliberately. §7.7's atomicity is about failure, not about concurrency, and a
 lock here would give a false sense of the second. A host that receives on more than one queue MUST
 serialize access to a session and to its store; two concurrent decrypts against one session are
 two snapshots of the same state, and whichever commits second silently discards the first.
 */
@interface IRSession : NSObject

/// §11.1 — `IK_A^d ‖ EK_A`, 64 bytes. Fixed at handshake time and never changes; it is the key of
/// the type `0x02` dispatch index and the value §11.1.1 compares to collapse a race.
@property (nonatomic, copy, readonly) NSData * _Nonnull handshakeId;

/// §12.1's role byte. `IRSessionRoleInitiator` means WE ran §6.1's initiator half — it is not a
/// statement about who spoke first at the application layer.
@property (nonatomic, readonly) IRSessionRole role;

/// §6.5 — the peer's `(IK^s, IK^d)` pair, read from the stored SESSION_AD. §11.1.1 permits at most
/// one live session per value of this property, which is what makes §11.5's index a function and
/// what lets §11.5 rule 3 forbid trial decryption.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull peerIdentityKeyPair;

/// Our own pair, from the other half of SESSION_AD. Exposed because a host holding several local
/// identities needs to know which one a restored session belongs to, and the blob is the only
/// record of it.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull ownIdentityKeyPair;

/// §12.5 — incremented on every successful RatchetEncrypt, persisted before the message is
/// emitted. The rollback tripwire compares it against a backup-excluded record on load.
@property (nonatomic, readonly) uint64_t sendCounter;

/**
 §11.3 — YES while the next outbound message must be type `0x02`.

 An initiator sends type `0x02` for every message until it has successfully decrypted ANY message
 from the responder — equivalently, until `CKr` becomes non-none — reusing the IDENTICAL prologue
 field values each time. This flag is DERIVED from the ratchet state rather than set by a caller, so
 the transition cannot be missed: the first successful decrypt clears the stored prologue and this
 property reads NO from then on.

 Always NO for a responder, which never sends type `0x02` and has no prologue to re-emit.
 */
@property (nonatomic, readonly) BOOL sendsPreKeyMessages;

/// YES once the session has been torn down (§11.1.1's collapse, eviction, or explicit deletion).
/// A torn-down session's key material is zeroized; every operation on it fails.
@property (nonatomic, readonly) BOOL isTornDown;

/**
 §5.5 — the peer's identity fingerprint, `SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d)`.

 §5.5 requires applications key identity lookup, trust-store entries, pinning and any displayed
 safety number on the PAIR or on this value. An application that keys on `IK^s` alone is not
 conformant: an attacker presenting a victim's genuine `IK^s` beside its own `IK^d` would otherwise
 be displayed as the victim.

 Takes the provider explicitly rather than holding one. A session is a state record; giving it a
 crypto provider would make the object graph a cycle with IRMessenger and would put a second
 randomness source inside the type that persists to disk.
 */
- (IRFingerprint * _Nullable)peerFingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                                   error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
