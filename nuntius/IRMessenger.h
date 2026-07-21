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
#import <nuntius/IRIdentity.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRPreKeyStore.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>
#import <nuntius/IRSession.h>
#import <nuntius/IRSessionStore.h>

/**
 The consumer-facing composition — SPEC §5.3, §6.6, §10.7, §11.1.1, §11.2, §11.3, §11.5.

 Everything below this object is a pure function of its arguments. IRMessenger is where the four
 stores meet: the long-lived identity (§5.1), the prekey store (§5.3), the session store (§11.1),
 and the crypto provider. It owns exactly two orderings that no lower layer can enforce because no
 lower layer sees enough state — §10.7's fourteen steps for a type `0x02` message that opens a new
 session, and §11.2's three checks for one that lands on an existing session.

 THE RECEIVE API IS SPLIT IN TWO, AND THE SPLIT IS §11.5. There is deliberately no
 `-decrypt:error:` taking only a message: rule 1 requires an explicit handle for type `0x01`, and
 not writing the convenience method is the cleanest way to enforce it. -decryptMessage: variants
 take either a session or a peer identity, so a host is forced to confront rule 2 — the sender
 identity comes from the TRANSPORT, never from the message, because nothing in a type `0x01` header
 is authenticated before decryption. A message that fails under the selected session returns
 IRErrorAEADAuthFailed and is NEVER retried against another (rule 3); there is no loop over
 candidate sessions anywhere in this file, and `NEG-DEMUX-WRONG-SESSION` is the vector.

 NOT THREAD-SAFE, deliberately, for the reason given on IRSession: §7.7's atomicity is about
 failure, not concurrency. A host receiving on more than one queue MUST serialize access.
 */

#pragma mark - IRDecryptedMessage

/**
 §11.6 — what a successful decrypt returns. Four fields, and the shape is normative.

 `session` is ALWAYS the survivor and is the handle the caller MUST use from now on: §10.7 step 14b's
 collapse may have replaced any previous handle the caller held for this peer, and it may equally
 have destroyed the session the message just arrived on while leaving the caller's cached handle
 alive. Both branches deliver a plaintext (§10.7 step 14d) — a message that completed X3DH and passed
 Poly1305 is the most strongly authenticated artifact this protocol produces, and dropping it because
 of a race would hand an attacker who merely DELAYS one packet a silent, permanent message-suppression
 primitive (§19.7).
 */
@interface IRDecryptedMessage : NSObject

@property (nonatomic, copy, readonly) NSData * _Nonnull plaintext;
@property (nonatomic, strong, readonly) IRSession * _Nonnull session;

/// §11.6 — YES iff this call ran §10.7 AND the session it built is the survivor. NO on every §11.2
/// path, every §10.1 path, and on §10.7 step 14b's LOSING branch, where a session was established
/// and then immediately torn down.
@property (nonatomic, readonly) BOOL establishedNewSession;

/**
 §11.6 — the 64-byte `handshake_id` destroyed by this call, or nil when nothing was destroyed.

 THIS IS THE OBSERVABLE, and a bare "a collapse occurred" boolean is explicitly NOT sufficient: a
 handle is an opaque object with no byte representation, so the id is the only way a caller can tell
 whether a handle it holds is the one that died. Compare any cached handle's `handshakeId` against
 this and discard on a match; every operation on a torn-down handle fails with IRErrorNoSession.
 */
@property (nonatomic, copy, readonly) NSData * _Nullable tornDownHandshakeId;

/**
 §11.1.1 — YES when establishing this session tore down a DIFFERENT live session with the same peer.
 A caller holding that torn-down handle MUST discard it; every operation on it now fails.

 DERIVED, and the derivation is load-bearing: `tornDownHandshakeId != nil` AND `establishedNewSession`.
 The disjunction alone — "a collapse occurred" — is YES on BOTH branches of §10.7 step 14b while the
 caller's obligation is opposite on each. On the losing branch the session torn down is the one this
 message arrived on, which the caller never saw, and the caller's cached handle is the SURVIVOR. A
 port reporting the disjunction under this name instructs the caller to discard the one handle it must
 keep, and an attacker triggers that by delaying a single packet during a concurrent initiation.
 */
@property (nonatomic, readonly) BOOL collapsedExistingSession;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRMessenger

@interface IRMessenger : NSObject

/**
 Full injection. `environment` supplies §15.5 rule 6's clock, which every expiry, tombstone and TTL
 decision below reads — the frozen conformance suite has a shelf life without it (§19.6).
 */
- (instancetype _Nullable)initWithIdentity:(IRIdentity * _Nonnull)identity
                               preKeyStore:(id<IRPreKeyStore> _Nonnull)preKeyStore
                              sessionStore:(id<IRSessionStore> _Nonnull)sessionStore
                                  provider:(id<IRCryptoProvider> _Nonnull)provider
                               environment:(IREnvironment * _Nonnull)environment
                                     error:(NSError * _Nullable * _Nullable)error
    NS_DESIGNATED_INITIALIZER;

/// Production convenience — builds IRSodiumCryptoProvider over IREnvironment.production, so the
/// common path names neither.
- (instancetype _Nullable)initWithIdentity:(IRIdentity * _Nonnull)identity
                               preKeyStore:(id<IRPreKeyStore> _Nonnull)preKeyStore
                              sessionStore:(id<IRSessionStore> _Nonnull)sessionStore
                                     error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IRIdentity * _Nonnull identity;
@property (nonatomic, strong, readonly) id<IRPreKeyStore> _Nonnull preKeyStore;
@property (nonatomic, strong, readonly) id<IRSessionStore> _Nonnull sessionStore;
@property (nonatomic, strong, readonly) id<IRCryptoProvider> _Nonnull provider;
@property (nonatomic, strong, readonly) IREnvironment * _Nonnull environment;

#pragma mark - Identity

@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull identityKeyPair;

/// §5.5 — our own fingerprint, for display beside the peer's.
- (IRFingerprint * _Nullable)fingerprint:(NSError * _Nullable * _Nullable)error;

#pragma mark - Responder: publish a bundle (§5.2, §5.4)

/**
 Generates and STORES a signed prekey and `opkCount` one-time prekeys, then emits exactly
 `251 + 36 * opkCount` bytes.

 The private halves stay in the prekey store; only public components reach the wire. §5.3 rule 6
 caps `notAfterS - notBeforeS` at MAX_SPK_VALIDITY_SECONDS, and a window exceeding it is refused
 here rather than at the peer, so a misconfigured publisher fails at home.
 */
- (NSData * _Nullable)publishBundleWithSPKId:(uint32_t)spkId
                                  notBeforeS:(uint64_t)notBeforeS
                                   notAfterS:(uint64_t)notAfterS
                                    opkCount:(uint16_t)opkCount
                                       error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Initiator: open a session (§5.3, §6, §7.5, §11.1.1)

/**
 Parses and fully verifies a bundle (§10.3 then §5.3's six rules, including the validity window
 against the injected clock), runs X3DH as initiator, initializes the ratchet, and files the
 session under both §11.1 indices.

 The returned session sends type `0x02` until it decrypts something from the peer (§11.3). If a
 live session already existed with this peer, §11.1.1 collapses the pair here and the survivor is
 what comes back — which may be the EXISTING session, not the one just built.
 */
- (IRSession * _Nullable)beginSessionWithBundleData:(NSData * _Nonnull)bundleData
                                              error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Send (§7.8, §11.3)

/**
 Encrypts in `session`, choosing type `0x02` vs `0x01` from `session.sendsPreKeyMessages` — the
 caller never chooses, because §11.3's transition is a property of the ratchet state and a caller
 that got it wrong would emit a prekey message the peer routes to §10.7.

 Every type `0x02` reuses the IDENTICAL stored prologue and reads `IKB_A` from the long-lived
 identity record. §11.3 forbids re-signing it at send time: Ed25519 is not contractually
 deterministic across all four platforms, nothing in the receive path compares `IKB_A` across
 messages, so a re-signing port would emit a different 64 bytes per message and never be caught.
 */
- (NSData * _Nullable)encrypt:(NSData * _Nonnull)plaintext
                    inSession:(IRSession * _Nullable)session
                        error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Receive (§10.7, §11.2, §11.5)

/**
 Type `0x02` ONLY. Self-routing: §11.1's `handshake_id` is computed from the header, so no handle
 is needed and none is accepted. Routes to §11.2's existing-session branch or to §10.7's fourteen
 steps.

 A type `0x01` message here reports IRErrorWrongEntryPoint (7125, §10.0 row 5) rather than being
 silently forwarded — the two entry points are not interchangeable, the split is what §11.5 rule 1
 is, and forwarding would put a type `0x01` through a path that accepts no handle. §10.0 runs BEFORE
 §10.2's 241-byte floor, so a short type `0x01` submitted here is reported as the misrouted call it
 is rather than as a truncation that does not exist.
 */
- (IRDecryptedMessage * _Nullable)decryptPreKeyMessage:(NSData * _Nonnull)message
                                                 error:(NSError * _Nullable * _Nullable)error;

/**
 Type `0x01` with a handle the host already resolved (§11.5 rule 1).

 A message that does not decrypt under `session` returns IRErrorAEADAuthFailed and is NOT retried
 against another (rule 3); per §7.7 nothing mutated.

 `session` IS _Nullable, deliberately, and §13.4 clause 5 requires it to be. Absence of a handle is
 not a caller contract violation but a SPECIFIED protocol condition: §10.1 check 6 answers it with
 IRErrorNoSession and `NEG-NO-SESSION`'s first case is "no handle at all". A handle naming a session
 torn down by a §11.1.1 collapse is stale and resolves the same way — and that collapse is the
 mechanism which manufactures stale handles, so this is the one parameter the outside world can
 legitimately render absent. Reported at CHECK 6'S POSITION: after the gate, never before it.
 */
- (IRDecryptedMessage * _Nullable)decryptMessage:(NSData * _Nonnull)message
                                       inSession:(IRSession * _Nullable)session
                                           error:(NSError * _Nullable * _Nullable)error;

/**
 Type `0x01`, resolving the handle through §11.1's peer index.

 `peer` MUST come from a sender identity the TRANSPORT authenticated, never from any field of the
 message (§11.5 rule 2) — nothing in a type `0x01` header is authenticated before decryption, so
 routing on header bytes lets an attacker choose which session absorbs a forgery. The library
 cannot check this; it is a host obligation, and the parameter exists to make it explicit.

 An unresolvable peer is IRErrorNoSession (rule 1). Because §11.1.1 permits at most one live
 session per peer, this lookup is a FUNCTION and there is no candidate set to iterate.
 */
- (IRDecryptedMessage * _Nullable)decryptMessage:(NSData * _Nonnull)message
                         fromPeerIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)peer
                                           error:(NSError * _Nullable * _Nullable)error;

/**
 §10.0 rows 1–4, and §11.5 RULE 5 MAKES THIS REQUIRED API rather than a convenience: a host holding
 bytes off a transport MUST be able to select an entry point rather than calling one at random and
 interpreting the resulting code. It is what keeps IRErrorWrongEntryPoint a diagnosable bug that a
 conformant host never reaches.

 Reads byte 1 only after the global length floor and the VERSION check pass, so a v3 message is
 rejected here — before the type is read and before either gate's type-dependent floor — which is
 §10.6's guarantee made unconditional on length. This helper never decrypts, never resolves a
 session, and takes no handle.
 */
+ (IRMessageType)messageTypeOfMessage:(NSData * _Nonnull)message
                                error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
