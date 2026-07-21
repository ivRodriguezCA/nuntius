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

#import "IRMessenger.h"

#import "IRKeyPairs.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRPreKeyBundle.h"
#import "IRPreKeyRecords.h"
#import "IRRatchet.h"
#import "IRRatchetState.h"
#import "IRSession+Internal.h"
#import "IRSessionAD.h"
#import "IRSessionDispatch.h"
#import "IRSodiumCryptoProvider.h"
#import "IRX3DH.h"

#pragma mark - IRDecryptedMessage

@interface IRDecryptedMessage ()
@property (nonatomic, copy, readwrite) NSData * _Nonnull plaintext;
@property (nonatomic, strong, readwrite) IRSession * _Nonnull session;
@property (nonatomic, readwrite) BOOL establishedNewSession;
@property (nonatomic, copy, readwrite) NSData * _Nullable tornDownHandshakeId;
@end

@implementation IRDecryptedMessage

/**
 §11.6's four-field result. `tornDownHandshakeId` is passed rather than a "a collapse occurred"
 boolean, and -collapsedExistingSession is DERIVED from it below, because the disjunction is true on
 both branches of §10.7 step 14b while the caller's obligation is opposite on each.
 */
+ (instancetype)messageWithPlaintext:(NSData *)plaintext
                             session:(IRSession *)session
               establishedNewSession:(BOOL)establishedNewSession
                 tornDownHandshakeId:(NSData * _Nullable)tornDownHandshakeId {
    IRDecryptedMessage *result = [[IRDecryptedMessage alloc] initInternal];
    result.plaintext = plaintext;
    result.session = session;
    result.establishedNewSession = establishedNewSession;
    result.tornDownHandshakeId = (tornDownHandshakeId != nil) ? [tornDownHandshakeId copy] : nil;
    return result;
}

- (BOOL)collapsedExistingSession {
    /* §11.6 — "a handle you may previously have held for this peer is now dead", which is true ONLY
       when a DIFFERENT, pre-existing session was destroyed. On §10.7 step 14b's losing branch a
       session was also torn down, but it is the one this message arrived on: the caller never held
       it, and the caller's cached handle is the survivor. Returning the bare "something was torn
       down" disjunction here would tell that caller to discard its live session, which an attacker
       triggers by delaying a single packet during a concurrent initiation. */
    return (self.tornDownHandshakeId != nil && self.establishedNewSession);
}

- (instancetype)initInternal {
    return [super init];
}

@end

#pragma mark - IRMessenger

@implementation IRMessenger

#pragma mark - Construction

- (instancetype)initWithIdentity:(IRIdentity *)identity
                     preKeyStore:(id<IRPreKeyStore>)preKeyStore
                    sessionStore:(id<IRSessionStore>)sessionStore
                        provider:(id<IRCryptoProvider>)provider
                     environment:(IREnvironment *)environment
                           error:(NSError * _Nullable * _Nullable)error {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    /* Every parameter is _Nonnull, so nil here is a violated contract rather than a protocol
       condition — there is no §10.5 code for it. IRErrorStateCorrupt is the closest honest
       reading ("this object could not be brought into a valid state") and keeps the failure
       greppable instead of trapping in a release build. */
    if (identity == nil || preKeyStore == nil || sessionStore == nil ||
        provider == nil || environment == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    _identity = identity;
    _preKeyStore = preKeyStore;
    _sessionStore = sessionStore;
    _provider = provider;
    _environment = environment;

    return self;
}

- (instancetype)initWithIdentity:(IRIdentity *)identity
                     preKeyStore:(id<IRPreKeyStore>)preKeyStore
                    sessionStore:(id<IRSessionStore>)sessionStore
                           error:(NSError * _Nullable * _Nullable)error {
    IREnvironment *environment = [IREnvironment production];
    IRSodiumCryptoProvider *provider = [IRSodiumCryptoProvider providerWithEnvironment:environment
                                                                                error:error];
    if (provider == nil) {
        return nil;
    }

    return [self initWithIdentity:identity
                      preKeyStore:preKeyStore
                     sessionStore:sessionStore
                         provider:provider
                      environment:environment
                            error:error];
}

#pragma mark - Identity

- (IRIdentityKeyPair *)identityKeyPair {
    return self.identity.identityKeyPair;
}

- (IRFingerprint * _Nullable)fingerprint:(NSError * _Nullable * _Nullable)error {
    return [self.identity.publicIdentity fingerprintWithProvider:self.provider error:error];
}

#pragma mark - Clock

/// Every clock read in this file goes through these two, so §15.6's ten-years-forward run has
/// exactly one place to be injected and no path can quietly reach a system clock (§19.6).
- (uint64_t)nowUnixSeconds {
    return [self.environment.clock nowUnixSeconds];
}

- (uint64_t)nowUnixMilliseconds {
    return [self.environment.clock nowUnixMilliseconds];
}

#pragma mark - Responder: publish (§5.2, §5.4)

- (NSData * _Nullable)publishBundleWithSPKId:(uint32_t)spkId
                                  notBeforeS:(uint64_t)notBeforeS
                                   notAfterS:(uint64_t)notAfterS
                                    opkCount:(uint16_t)opkCount
                                       error:(NSError * _Nullable * _Nullable)error {
    if (opkCount > (uint16_t)kIRMaxBundleOPKCount) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* §5.3 rules 5-6 are the PEER's obligation on ingest, but a window that can never satisfy them
       is a local misconfiguration and is refused here — at the publisher, where the operator can
       see it — rather than becoming an inexplicable ERR_PREKEY_EXPIRED at every initiator. */
    if (notAfterS <= notBeforeS ||
        (notAfterS - notBeforeS) > (uint64_t)kIRMaxSPKValiditySeconds) {
        IRSetError(error, IRErrorPreKeyExpired);
        return nil;
    }

    IRSignedPreKeyRecord *signedPreKey =
        [self.preKeyStore rotateSignedPreKeyWithIdentity:self.identity
                                                   spkId:spkId
                                              notBeforeS:notBeforeS
                                               notAfterS:notAfterS
                                                provider:self.provider
                                                   error:error];
    if (signedPreKey == nil) {
        return nil;
    }

    uint64_t nowS = [self nowUnixSeconds];

    NSMutableArray<IROneTimePreKeyRecord *> *generated =
        [NSMutableArray arrayWithCapacity:opkCount];

    /* opk_ids MUST BE DISTINCT — within this batch and against what the store already holds.

       They are drawn from 4 CSPRNG bytes, so a collision is unlikely but not negligible: at the
       1000-OPK ceiling of §5.4 the birthday probability against a 32-bit space is around 1 in
       8600 per batch, and a replenishing responder draws many batches over an installation's life.
       An id is the ONLY handle an initiator has on a one-time prekey (§10.7 step 6), so a duplicate
       makes one of the two colliding keys unreachable and the handshake against it unopenable.

       Redrawn rather than refused: the caller asked for `opkCount` keys and a collision is the
       RNG's business, not theirs. The store refuses duplicates independently — this loop is what
       keeps that refusal from ever being reached. */
    NSMutableSet<NSNumber *> *usedIds = [NSMutableSet setWithCapacity:opkCount];
    for (uint16_t index = 0; index < opkCount; index++) {
        uint32_t opkId = 0;
        NSNumber *key = nil;

        /* Bounded, so an RNG stuck on one value cannot spin forever. 64 consecutive collisions
           against a set of at most 1000 ids is not a collision, it is a broken CSPRNG, and §13.1's
           whole point is that a broken CSPRNG must surface as an error rather than as key
           material. */
        NSUInteger attempts = 0;
        do {
            if (attempts++ >= 64) {
                IRSetError(error, IRErrorRNGFailure);
                return nil;
            }

            NSData *idBytes = [self.provider randomBytesOfLength:4 error:error];
            if (idBytes == nil) {
                return nil;
            }

            opkId = 0;
            [idBytes getBytes:&opkId length:sizeof(opkId)];
            key = @(opkId);
        } while ([usedIds containsObject:key] ||
                 [self.preKeyStore oneTimePreKeyRecordForId:opkId
                                              atUnixSeconds:nowS
                                                      error:NULL] != nil);

        [usedIds addObject:key];

        IROneTimePreKeyRecord *record = [IROneTimePreKeyRecord generateWithOpkId:opkId
                                                              createdAtUnixSecs:nowS
                                                                       provider:self.provider
                                                                          error:error];
        if (record == nil) {
            return nil;
        }
        [generated addObject:record];
    }

    if (![self.preKeyStore storeOneTimePreKeyRecords:generated error:error]) {
        return nil;
    }

    return [IRPreKeyBundle serializeWithIdentity:self.identity.publicIdentity
                             signedPreKeyRecord:signedPreKey
                           oneTimePreKeyRecords:generated
                                          error:error];
}

#pragma mark - Initiator: begin (§5.3, §6, §7.5, §11.1.1)

- (IRSession * _Nullable)beginSessionWithBundleData:(NSData *)bundleData
                                              error:(NSError * _Nullable * _Nullable)error {
    /* §13.4 clauses 1 and 6 — a nil reference is a CALLER CONTRACT VIOLATION, not malformed
       content, and the two must stay distinguishable. NEG-BUNDLE-EMPTY is the content case: a
       zero-length NSData that EXISTS, which reaches IRPreKeyBundle below and fails §10.3's length
       floor as ERR_BUNDLE_MALFORMED. Reporting nil through the same code, which this method used
       to do, collapses the two into one observation and hands the taxonomy a condition clause 1
       says it must not carry. */
    IRRequireArgument(bundleData);

    /* §10.3 then §5.3 rules 1-4. Rules 5-6 read a clock and are run inside IRX3DH, which is where
       the spec's "before performing any Diffie-Hellman" can be enforced structurally. */
    IRPreKeyBundle *bundle = [IRPreKeyBundle bundleFromData:bundleData
                                                   provider:self.provider
                                                      error:error];
    if (bundle == nil) {
        return nil;
    }

    /* §13.3 — EK_A is ephemeral and unguarded; its private half is wiped by IRX3DH once SK exists,
       and only the public half survives, in the prologue (§11.3). */
    IRX25519KeyPair *ephemeral = [self.provider generateX25519KeyPairGuarded:NO error:error];
    if (ephemeral == nil) {
        return nil;
    }

    IRX3DHResult *x3dh = [IRX3DH initiatorResultWithIdentity:self.identity
                                                      bundle:bundle
                                            ephemeralKeyPair:ephemeral
                                              nowUnixSeconds:[self nowUnixSeconds]
                                                    provider:self.provider
                                                   retainIKM:NO
                                                       error:error];
    if (x3dh == nil) {
        return nil;
    }

    IRSession *session = nil;
    IRRatchetState *state = [IRRatchet initiatorStateWithSharedKey:x3dh.sharedKey
                                            responderSignedPreKey:bundle.signedPreKey
                                                        sessionAD:x3dh.sessionAD
                                                      handshakeId:x3dh.handshakeId
                                                         prologue:x3dh.prologue
                                                         provider:self.provider
                                                            error:error];
    /* §13.3 — SK is zeroized immediately after ratchet initialization, on BOTH paths.
       IRRatchet copies it rather than adopting it, so this cannot reach the live root key. */
    [x3dh zeroize];

    if (state == nil) {
        return nil;
    }

    session = [IRSession sessionWithState:state error:error];
    if (session == nil) {
        /* §13.3 wants a DETERMINISTIC wipe point for every derived secret. `state` already holds
           RK — derived from SK — and this session's fresh ratchet private. Falling through to
           -[IRSecretBytes dealloc] would still wipe them eventually, but "eventually, when ARC
           gets to it" is not a schedule, and it is not a schedule the Java and Kotlin ports can
           reproduce at all: they have no deterministic destructor. Every abandoned-state exit in
           this file wipes explicitly so the ports have one shape to copy. */
        [state zeroize];
        return nil;
    }

    IRSessionEstablishResult *establish = [self.sessionStore establishSession:session
                                                                    atTimeMs:[self nowUnixMilliseconds]
                                                                       error:error];
    if (establish == nil) {
        [session tearDown];
        return nil;
    }

    return establish.survivingSession;
}

#pragma mark - Send (§7.8, §11.3)

- (NSData * _Nullable)encrypt:(NSData *)plaintext
                    inSession:(IRSession *)session
                        error:(NSError * _Nullable * _Nullable)error {
    /* §13.4 clause 2 — a nil plaintext is a caller contract violation, and IRErrorStateCorrupt
       (7117, "state blob failed structural validation") is not what happened. §10.4 makes a
       ZERO-LENGTH plaintext legal and it produces a 72-byte type `0x01` message, so coercing nil to
       empty here would be indistinguishable from that legal case downstream — clause 2's whole
       subject. */
    IRRequireArgument(plaintext);

    /* A nil session is not a contract violation on the receive path (§13.4 clause 5), and reporting
       it as anything other than ERR_NO_SESSION here would disagree with the isTornDown branch one
       line below, which is the same condition: a handle that names nothing live. */
    if (session == nil || session.isTornDown) {
        IRSetError(error, IRErrorNoSession);
        return nil;
    }

    /* §11.3 — the TYPE IS DERIVED, never chosen by the caller. `sendsPreKeyMessages` reads the
       ratchet state's prologue, which the first successful decrypt clears, so the transition
       cannot be missed or repeated. */
    BOOL prekey = session.sendsPreKeyMessages;

    NSData *message =
        [IRRatchet encryptOnState:session.state
                        plaintext:plaintext
                      messageType:(prekey ? IRMessageTypePrekey : IRMessageTypeNormal)
                initiatorIdentity:(prekey ? self.identity.identityKeyPair : nil)
                  identityBinding:(prekey ? self.identity.binding : nil)
                         provider:self.provider
                            error:error];
    if (message == nil) {
        return nil;
    }

    /* §12.5 — send_counter has already advanced inside encryptOnState:. Persist BEFORE the message
       is handed back, so a crash cannot emit a message whose counter was never recorded. */
    if (![self.sessionStore persistSession:session error:error]) {
        return nil;
    }

    return message;
}

#pragma mark - Receive — routing

+ (IRMessageType)messageTypeOfMessage:(NSData *)message
                                error:(NSError * _Nullable * _Nullable)error {
    IRRequireArgument(message);
    return [IRMessageGate messageTypeOfMessage:message error:error];
}

#pragma mark - Receive — type 0x01 (§11.5)

- (IRDecryptedMessage * _Nullable)decryptMessage:(NSData *)message
                         fromPeerIdentityKeyPair:(IRIdentityKeyPair *)peer
                                           error:(NSError * _Nullable * _Nullable)error {
    /* §13.4 clauses 1 and 3 — `peer` is _Nonnull and is NOT a session handle, so clause 5's
       nullable carve-out does not reach it. A nil here used to be folded into the unresolvable-peer
       path and surfaced as ERR_NO_SESSION, which is a §10.5 code standing in for a contract
       violation — exactly what clause 1 forbids, and unrepresentable in the Swift and Kotlin
       ports. Trap instead. */
    IRRequireArgument(peer);

    /* §11.5 rule 4 — because §11.1.1 permits at most one live session per peer, this lookup is a
       FUNCTION and there is no candidate set to walk. An unresolvable peer yields nil, which the
       method below reports at §10.1 CHECK 6'S POSITION — after the gate, never before it. */
    IRSession *session = [self.sessionStore sessionForPeerIdentityKeyPair:peer];

    return [self decryptMessage:message inSession:session error:error];
}

- (IRDecryptedMessage * _Nullable)decryptMessage:(NSData *)message
                                       inSession:(IRSession * _Nullable)session
                                           error:(NSError * _Nullable * _Nullable)error {
    /* §13.4 clause 2 — a nil message is a CALLER CONTRACT VIOLATION, not a short message. Mapping
       it to ERR_TRUNCATED_MESSAGE, which this method used to do, reports a truncation that does not
       exist and is the coercion clause 2 bans; in Objective-C it happens by itself, because
       [nilData length] is 0. `session` is the one parameter that is legitimately absent (clause 5):
       §10.1 check 6 specifies that as ERR_NO_SESSION and NEG-NO-SESSION's first case is exactly
       "no handle at all". */
    IRRequireArgument(message);

    /* §10.0, then §10.1 checks 1-5, and ONLY THEN the session. §10.1 puts the handle at CHECK 6,
       after the length, version, type and flag checks — decision D1, and the ordering is
       observable: resolving first would report a 10-byte input as ERR_NO_SESSION and turn the code
       into an oracle for which peers the receiver holds sessions with. Every input that fails the
       gate must fail identically whether or not a session exists. */
    if (![IRMessageGate demultiplexMessage:message
                              expectedType:IRMessageTypeNormal
                                     error:error]) {
        return nil;
    }

    if (![IRMessageGate gateType01Prefix:message error:error]) {
        return nil;
    }

    /* §10.1 check 6 — "the caller supplied a session handle and it resolves" (§11.5 rule 1). A nil
       handle and a torn-down one are the two ways that fails. */
    if (session == nil || session.isTornDown) {
        IRSetError(error, IRErrorNoSession);
        return nil;
    }

    /* §10.1 checks 7-10. */
    IRMessageHeader *header =
        [IRMessageGate parseType01Message:message
                      ownRatchetPublicKey:session.state.DHs.publicKey
                                    error:error];
    if (header == nil) {
        return nil;
    }

    NSData *plaintext = [self decryptGatedMessage:message
                                           header:header
                                        inSession:session
                                          persist:YES
                                            error:error];
    if (plaintext == nil) {
        return nil;
    }

    return [IRDecryptedMessage messageWithPlaintext:plaintext
                                            session:session
                              establishedNewSession:NO
                                tornDownHandshakeId:nil];
}

#pragma mark - Receive — type 0x02 (§10.7, §11.2)

- (IRDecryptedMessage * _Nullable)decryptPreKeyMessage:(NSData *)message
                                                 error:(NSError * _Nullable * _Nullable)error {
    IRRequireArgument(message);   /* §13.4 — see -decryptMessage:inSession:error: */

    /* §10.0 BEFORE §10.2, so a caller that used the wrong entry point is told so with 7125.
       §10.2's own check 1 is the 241-byte floor, which fires BEFORE its check 4 reads the type
       byte — so delegating straight to the gate reports a 200-byte type `0x01` message as
       ERR_TRUNCATED_MESSAGE, sending a developer looking for a truncation that is not there. A
       length floor is a FUNCTION OF THE TYPE; evaluating one before the type is read asserts a
       property the message does not have.

       This cannot weaken §10.2 for a message that really is type `0x02`: §10.0 applies only the
       GLOBAL floor of 72 and the looser cap, both of which §10.2's checks 1-2 then re-apply at
       their own, tighter, specified values. */
    if (![IRMessageGate demultiplexMessage:message
                              expectedType:IRMessageTypePrekey
                                     error:error]) {
        return nil;
    }

    /* §10.2 checks 1-11. */
    IRMessageHeader *header = [IRMessageGate parseType02Message:message error:error];
    if (header == nil) {
        return nil;
    }

    /* §11.2 — hid = IK_A^d ‖ EK_A, computed by the gate from the header. */
    NSData *handshakeId = header.handshakeId;
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    IRSession *existing = [self.sessionStore sessionForHandshakeId:handshakeId];
    if (existing != nil && !existing.isTornDown) {
        return [self decryptPreKeyMessage:message
                                   header:header
                       againstLiveSession:existing
                                    error:error];
    }

    return [self establishSessionWithPreKeyMessage:message header:header error:error];
}

/// §11.2's existing-session branch: three ordered checks, then a NORMAL ratchet message.
/// Do NOT re-run X3DH. Do NOT re-initialize the ratchet. Do NOT touch the OPK.
- (IRDecryptedMessage * _Nullable)decryptPreKeyMessage:(NSData *)message
                                                header:(IRMessageHeader *)header
                                    againstLiveSession:(IRSession *)session
                                                 error:(NSError * _Nullable * _Nullable)error {
    if (![IRSessionDispatch validatePreKeyMessageHeader:header
                                         againstSession:session
                                               provider:self.provider
                                                  error:error]) {
        return nil;
    }

    NSData *plaintext = [self decryptGatedMessage:message
                                           header:header
                                        inSession:session
                                          persist:YES
                                            error:error];
    if (plaintext == nil) {
        return nil;
    }

    return [IRDecryptedMessage messageWithPlaintext:plaintext
                                            session:session
                              establishedNewSession:NO
                                tornDownHandshakeId:nil];
}

/**
 §10.7's fourteen steps, in order. The numbered comments are the spec's own numbering; every
 reordering of them is a defect the spec names explicitly, so they are kept literal rather than
 rearranged for efficiency.
 */
- (IRDecryptedMessage * _Nullable)establishSessionWithPreKeyMessage:(NSData *)message
                                                             header:(IRMessageHeader *)header
                                                              error:(NSError * _Nullable * _Nullable)error {
    /* Step 1 — §10.2 has passed. Step 2 — handshake_id, from the header. */
    NSData *handshakeId = header.handshakeId;

    /* Step 3 — verify IKB_A, BEFORE ANY DH. IRPublicIdentity has exactly one constructor and it
       verifies the binding, so this is structural: there is no unverified route to the DH below.
       This is the fix for defect 3 in the responder direction. */
    IRPublicIdentity *initiatorIdentity =
        [IRPublicIdentity identityWithKeyPair:header.initiatorIdentity
                                      binding:header.identityBinding
                                     provider:self.provider
                                        error:error];
    if (initiatorIdentity == nil) {
        return nil;
    }

    uint64_t nowMs = [self nowUnixMilliseconds];
    uint64_t nowS = [self nowUnixSeconds];

    /* Step 4 — tombstone. Bounds the no-OPK handshake replay of §17.3 to HANDSHAKE_CACHE_MS by
       enforcement rather than by implication, and stops a replayed handshake from displacing a
       live session at step 14. */
    if ([self.sessionStore hasTombstoneForHandshakeId:handshakeId atTimeMs:nowMs]) {
        IRSetError(error, IRErrorReplay);
        return nil;
    }

    /* Step 5 — resolve spk_id to a RETAINED signed prekey private key. */
    IRSignedPreKeyRecord *signedPreKey = [self.preKeyStore signedPreKeyRecordForId:header.spkId
                                                                             error:error];
    if (signedPreKey == nil) {
        return nil;
    }

    /* Step 6 — anti-reflection against the resolved SPK_B public, BEFORE ANY DH. The responder's
       initial DHs IS that key pair (§7.5), so a sender reflecting it back would drive the receiver
       into a DH with itself. It sits here rather than in §10.2 because spk_id is not resolved
       until step 5, which is why no gate can perform it. */
    if ([header.ratchetKey isEqualToX25519Public:signedPreKey.keyPair.publicKey]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* Step 7 — resolve opk_id. NO FALLBACK to the 3-DH form: rejecting rather than falling back is
       what converts OPK consumption into replay protection (§6.6 rule 2). */
    IROneTimePreKeyRecord *oneTimePreKey = nil;
    if (header.opkFlag == IROPKFlagPresent) {
        oneTimePreKey = [self.preKeyStore oneTimePreKeyRecordForId:header.opkId
                                                     atUnixSeconds:nowS
                                                             error:error];
        if (oneTimePreKey == nil) {
            return nil;
        }
    }

    /* Steps 8, 9, 10 — DH1..DH4 with §4.4 check 3 on each, TRANSCRIPT/TH/IKM/SK with the length
       assertions, then SESSION_AD with A = the header's identity and B = ourselves. */
    IRX3DHResult *x3dh = [IRX3DH responderResultWithIdentity:self.identity
                                          initiatorIdentity:initiatorIdentity
                                            ephemeralPublic:header.ephemeralPublic
                                           signedPreKeyPair:signedPreKey.keyPair
                                                      spkId:header.spkId
                                                    opkFlag:header.opkFlag
                                                      opkId:header.opkId
                                          oneTimePreKeyPair:oneTimePreKey.keyPair
                                                   provider:self.provider
                                                  retainIKM:NO
                                                      error:error];
    if (x3dh == nil) {
        return nil;
    }

    /* Step 11 — initialize the ratchet as responder ON A SNAPSHOT, copying the signed prekey
       private half rather than aliasing the prekey store. IRRatchet takes that copy internally
       (§7.5, §19.1); nothing here may zeroize signedPreKey.keyPair. */
    IRRatchetState *state = [IRRatchet responderStateWithSharedKey:x3dh.sharedKey
                                                 signedPreKeyPair:signedPreKey.keyPair
                                                        sessionAD:x3dh.sessionAD
                                                      handshakeId:x3dh.handshakeId
                                                            error:error];
    [x3dh zeroize];   /* §13.3 — SK, immediately after ratchet initialization, on both paths. */

    if (state == nil) {
        return nil;
    }

    IRSession *session = [IRSession sessionWithState:state error:error];
    if (session == nil) {
        /* §13.3 — RK is already derived and `state` also holds this session's copy of SPK_B_priv
           (§7.5). The copy is the session's to destroy; the prekey store's original is governed by
           §5.3 and is untouched by -zeroize on this state. */
        [state zeroize];
        return nil;
    }

    /* Step 12 — RatchetDecrypt phases 3b-3d on that snapshot.
       Step 13 — on AEAD failure: discard, do NOT commit the session, do NOT delete the OPK. The
       one-time prekey is still unconsumed at this point precisely so that a forged message cannot
       burn it; that ordering is the fix for defect 7's replay window.

       EVERY FAILURE EXIT FROM HERE ON TEARS THE SESSION DOWN. It was built one line ago, is filed
       nowhere, and is unreachable the moment this method returns nil — but it holds RK and the
       §7.5 duplicate of SPK_B_priv, and IRRatchet only zeroizes the SNAPSHOT it decrypted on.
       Nothing else would ever wipe the parent state on these paths. That matters most for an
       AEAD failure, which is the exit an attacker can drive at will: an unauthenticated message
       would otherwise leave a fresh root key in the heap on every attempt. */
    NSData *plaintext = [self decryptGatedMessage:message
                                           header:header
                                        inSession:session
                                          persist:NO
                                            error:error];
    if (plaintext == nil) {
        [session tearDown];
        return nil;
    }

    /* STEP 14a — AEAD SUCCESS ONLY. Durably delete and zeroize opk_id, BEFORE the collapse.
       THIS DELETION IS FINAL and is not undone by 14b going against this session (§10.7). A port
       that reads "the session was torn down, so undo its side effects" and restores the one-time
       prekey reopens defect 7's replay window on the one path where an attacker can drive a
       teardown by racing — and each replay then costs the receiver a full X3DH, one Ed25519
       verification and four X25519 operations, while re-delivering the same plaintext. */
    if (oneTimePreKey != nil) {
        if (![self.preKeyStore consumeOneTimePreKeyId:header.opkId error:error]) {
            [session tearDown];
            return nil;
        }
    }

    /* STEPS 14b and 14c — apply §11.1.1's collapse, then durably commit its outcome: the survivor's
       state AND the loser's teardown, zeroization and tombstone, before anything is returned. The
       store owns both halves precisely so that no caller can commit one without the other; a crash
       between returning the plaintext and committing the teardown would resurrect a session the
       collapse already killed, and the two parties would then hold different survivors permanently.
       When the EXISTING session wins, the session built above is never persisted — only its
       tombstone is — and the survivor's state is not modified by this message in any way. */
    IRSessionEstablishResult *establish = [self.sessionStore establishSession:session
                                                                    atTimeMs:nowMs
                                                                       error:error];
    if (establish == nil) {
        [session tearDown];
        return nil;
    }

    /* STEP 14d — §10.7: "The plaintext is delivered on every path that reaches this step, including
       the path on which the session just established is the loser of 14b." Step 13 is the only AEAD
       outcome that produces no plaintext.

       Dropping it here would discard a message that completed X3DH and passed Poly1305 — the
       strongest authentication the protocol has — purely because of a race on which of two
       handshakes gets to persist, and the taxonomy cannot even express that outcome: §10.5 has no
       code for "your message authenticated and we discarded it" and forbids a null result with a
       null error. It is also attacker-reachable without any forgery: DELAYING one packet during a
       legitimate concurrent initiation would become a silent, permanent message-suppression
       primitive, since §11.3 has the initiator retransmitting an identical prologue and therefore an
       identical handshake_id, which step 4 now rejects as ERR_REPLAY forever (§19.7).

       `session` carries the SURVIVING handle, which may be a different object than the message
       arrived on; `establishedNewSession` says whether the incoming one is what survived; and
       `tornDownHandshakeId` is the observable that lets the caller decide whether a handle IT holds
       is the one that died. See -collapsedExistingSession for why a bare boolean is not enough. */
    return [IRDecryptedMessage messageWithPlaintext:plaintext
                                            session:establish.survivingSession
                              establishedNewSession:establish.incomingSessionSurvived
                                tornDownHandshakeId:establish.tornDownHandshakeId];
}

#pragma mark - Receive — the four-step sequence (§7.7)

/**
 IRRatchet.h's four-step receive sequence, verbatim, for an ALREADY GATED message.

 Step 1 (gate) has happened in the caller, because §10.1 and §10.2 need different inputs — the type
 `0x01` gate needs our own ratchet public key for check 8, the type `0x02` gate needs none. Steps
 2-4 are identical for both and live here so there is exactly one commit path in the file.
 */
- (NSData * _Nullable)decryptGatedMessage:(NSData *)message
                                   header:(IRMessageHeader *)header
                                inSession:(IRSession *)session
                                  persist:(BOOL)persist
                                    error:(NSError * _Nullable * _Nullable)error {
    /* Step 2 — ONCE PER RECEIVED MESSAGE, not once per attempt. §7.6 makes MAX_SKIP_PER_MESSAGE an
       aggregate across both SkipMessageKeys calls of one message; §11.5 rule 3 forbids a second
       session attempt so the bound cannot be multiplied by a candidate count. */
    IRSkipBudget *budget = [IRSkipBudget budget];

    /* Step 3 — §7.7. A state that could not be copied is one whose live secrets must not be
       touched, so a nil snapshot is a failed decrypt and not a fall-through to the live state. */
    IRRatchetState *snapshot = [session snapshot];
    if (snapshot == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* Step 4. */
    NSData *plaintext = [IRRatchet decryptOnSnapshot:snapshot
                                             message:message
                                              header:header
                                              budget:budget
                                            atTimeMs:[self nowUnixMilliseconds]
                                            provider:self.provider
                                               error:error];
    if (plaintext == nil) {
        /* DISCARD. §7.7: nothing mutated, so there is nothing to unwind — and per §11.5 rule 3
           this message is NOT retried against any other session. */
        [session discardSnapshot:snapshot];
        return nil;
    }

    if (![session commitSnapshot:snapshot error:error]) {
        /* §7.7 — "every intermediate secret derived during the attempt MUST be zeroized". A failed
           commit is a failed attempt, so the snapshot's own derived material goes the same way it
           does on the plaintext == nil branch three lines above and on IRRatchet's own failure
           exits. -discardSnapshot: is a no-op if the commit already adopted it, so this is safe
           whichever side of the swap the failure came from. */
        [session discardSnapshot:snapshot];
        return nil;
    }

    /* `persist:NO` is the §10.7 step 14 path only: a brand-new session is not in the store yet, it
       is filed by -establishSession: AFTER the one-time prekey is durably deleted, and persisting
       it here would introduce it under the wrong ordering. */
    if (persist) {
        if (![self.sessionStore persistSession:session error:error]) {
            return nil;
        }
    }

    return plaintext;
}

@end
