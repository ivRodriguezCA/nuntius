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

#import "IRRatchet.h"

#import "IRMessageBuilder.h"
#import "IRMessageGate.h"
#import "IRProtocolKDF.h"

@implementation IRRatchet

#pragma mark - §7.5 Ratchet initialization

+ (IRRatchetState * _Nullable)initiatorStateWithSharedKey:(IRRootKey * _Nonnull)sharedKey
                                    responderSignedPreKey:(IRX25519Public * _Nonnull)responderSignedPreKey
                                                sessionAD:(IRSessionAD * _Nonnull)sessionAD
                                              handshakeId:(NSData * _Nonnull)handshakeId
                                                 prologue:(IRSessionPrologue * _Nonnull)prologue
                                                 provider:(id<IRCryptoProvider> _Nonnull)provider
                                                    error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    if (sharedKey == nil || sharedKey.length != kIRLenRootKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (sessionAD == nil || prologue == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (responderSignedPreKey == nil || responderSignedPreKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* §4.4 checks 1–2 on SPK_B before it becomes DHr. The bundle parser already applied them
       (§5.3 rule 2), so this is a second line rather than the first — but `DHr` is a stored field
       and §12.2 rule 7 will demand the property of it forever, so it is verified at the boundary
       where it enters ratchet state rather than assumed from a caller two layers up. */
    if (![IRX25519Public highBitIsClear:responderSignedPreKey.constBytes]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    /* RK = SK, AS A COPY. §13.3 puts SK's wipe "immediately after ratchet initialization" and
       IRX3DHResult owns it, so adopting the caller's object would mean the caller honouring its own
       schedule wiped this session's root key. The copy makes -[IRX3DHResult zeroize] safe and still
       required. */
    IRRootKey *rootKey = [sharedKey duplicate];
    if (rootKey == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* DHs = generate_X25519_keypair(). Unguarded: §13.3 reserves sodium_malloc's guarded pages for
       long-lived identity and prekey privates, and a ratchet private is replaced on every DH step. */
    IRX25519KeyPair *ratchetPair = [provider generateX25519KeyPairGuarded:NO error:error];
    if (ratchetPair == nil) {
        [rootKey zeroizeNow];
        return nil;
    }

    IRSecretBytes *dh = [provider x25519WithPrivateKey:ratchetPair.privateKey
                                             publicKey:responderSignedPreKey
                                                 error:error];
    if (dh == nil) {
        [rootKey zeroizeNow];
        [ratchetPair zeroize];
        return nil;
    }

    /* (RK, CKs) = KDF_RK(RK, dh). The initiator takes ONE root-chain step here; the responder takes
       none until its first DHRatchet, which then takes two. §7.5's conformance note exists because
       of that asymmetry: assert `A.CKs == B.CKr` after B's first message, and do NOT assert
       `A.RK == B.RK` — B is legitimately one step ahead at that instant, and an implementer who
       asserts root-key equality here will "fix" working code. */
    IRRootChainStep *step = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                  dhOutput:dh
                                                                  provider:provider
                                                                     error:error];

    /* §13.3 — the DH output dies with the derivation that consumed it, on both paths. */
    [dh zeroizeNow];

    if (step == nil) {
        [rootKey zeroizeNow];
        [ratchetPair zeroize];
        return nil;
    }

    /* The SK copy is superseded by the KDF_RK output. */
    [rootKey zeroizeNow];

    IRRatchetState *state = [IRRatchetState stateWithRole:IRSessionRoleInitiator
                                                sessionAD:sessionAD
                                              handshakeId:handshakeId
                                                  rootKey:step.rootKey
                                           ratchetKeyPair:ratchetPair
                                        peerRatchetPublic:responderSignedPreKey
                                          sendingChainKey:step.chainKey
                                        receivingChainKey:nil
                                                       Ns:0
                                                       Nr:0
                                                       PN:0
                                              sendCounter:0
                                                 prologue:prologue
                                                  skipped:nil
                                                    error:error];
    if (state == nil) {
        /* Only on this path: on success the state HOLDS these two objects and wiping the step would
           wipe the session. */
        [step zeroize];
        [ratchetPair zeroize];
        return nil;
    }

    return state;
}

+ (IRRatchetState * _Nullable)responderStateWithSharedKey:(IRRootKey * _Nonnull)sharedKey
                                         signedPreKeyPair:(IRX25519KeyPair * _Nonnull)signedPreKeyPair
                                                sessionAD:(IRSessionAD * _Nonnull)sessionAD
                                              handshakeId:(NSData * _Nonnull)handshakeId
                                                    error:(NSError * _Nullable * _Nullable)error {
    if (sharedKey == nil || sharedKey.length != kIRLenRootKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (sessionAD == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (signedPreKeyPair == nil ||
        signedPreKeyPair.publicKey.length != kIRLenX25519Public ||
        signedPreKeyPair.privateKey.length != kIRLenX25519Private) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRRootKey *rootKey = [sharedKey duplicate];
    if (rootKey == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* THE COPY THAT KEEPS THE DEPLOYMENT ALIVE — §7.5, §19.1.

       -deepCopy reallocates the private half and shares the immutable public half. §7.4 step 4
       zeroizes `DHs.priv` unconditionally on B's first ratchet of every session, so without this
       line that step would destroy SPK_B_priv inside the prekey store and break every concurrent
       and future handshake against that spk_id until rotation — silently, and misreported as
       ERR_AEAD_AUTH_FAILED because clamping maps the wiped all-zero scalar to 2^254 and §4.4
       check 3 therefore never fires.

       Taking the copy here rather than trusting the caller to pass one is the departure from the
       plan's `signedPreKeyPairCopy:` parameter name. `NEG-SPK-SURVIVES-RATCHET` is the only vector
       that distinguishes the two, and it is worth not depending on it. */
    IRX25519KeyPair *sessionOwnedPair = [signedPreKeyPair deepCopy];
    if (sessionOwnedPair == nil) {
        [rootKey zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* RK = SK and NOTHING ELSE. No root-chain step, no chain keys: B's first DHRatchet takes both
       steps, producing a CKr equal to A's CKs and then a CKs of its own. DHr is none, which is
       exactly what drives §7.9 phase 3b to ratchet on B's first received message. */
    IRRatchetState *state = [IRRatchetState stateWithRole:IRSessionRoleResponder
                                                sessionAD:sessionAD
                                              handshakeId:handshakeId
                                                  rootKey:rootKey
                                           ratchetKeyPair:sessionOwnedPair
                                        peerRatchetPublic:nil
                                          sendingChainKey:nil
                                        receivingChainKey:nil
                                                       Ns:0
                                                       Nr:0
                                                       PN:0
                                              sendCounter:0
                                                 prologue:nil
                                                  skipped:nil
                                                    error:error];
    if (state == nil) {
        [rootKey zeroizeNow];
        [sessionOwnedPair zeroize];
        return nil;
    }

    return state;
}

#pragma mark - §7.6 SkipMessageKeys

+ (BOOL)skipMessageKeysOnState:(IRRatchetState * _Nonnull)state
                          until:(uint32_t)until
                         budget:(IRSkipBudget * _Nonnull)budget
                       atTimeMs:(uint64_t)nowMs
                       provider:(id<IRCryptoProvider> _Nonnull)provider
                          error:(NSError * _Nullable * _Nullable)error {
    if (state == nil || state.isZeroized || budget == nil || provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* §7.6 guard 1 — "nothing to skip; responder's first receive". §7.4 step 1 depends on this
       being a no-op rather than a null dereference. */
    if (state.CKr == nil) {
        return YES;
    }

    /* §7.6 guard 2 — "handled as replay by the caller". Returning OK here rather than an error is
       what lets §7.9 phase 3c own the ERR_REPLAY decision, and it also makes the unsigned
       subtraction below safe: `until >= state.Nr` is established before it is evaluated. */
    if (until < state.Nr) {
        return YES;
    }

    const uint32_t needed = until - state.Nr;
    if (needed == 0) {
        return YES;
    }

    /* An invariant, not a parse rule: CKr becomes non-nil only inside §7.4, which sets DHr in the
       same step. A store key built from a nil DHr would be unformable, so this fails loudly. */
    if (state.DHr == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* §7.6 — the whole span is checked against the AGGREGATE budget before a single key is derived,
       so ERR_TOO_MANY_SKIPPED leaves the state untouched. `needed` can be as large as 0x7FFFFFFF
       (the gate's ceiling on N) and is compared, never allocated against. */
    if (![budget consume:needed]) {
        IRSetError(error, IRErrorTooManySkipped);
        return NO;
    }

    while (state.Nr < until) {
        IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:state.CKr
                                                               provider:provider
                                                                  error:error];
        if (step == nil) {
            return NO;
        }

        /* §13.3 — "CK (each): immediately after KDF_CK produces its successor". The wipe lands here
           at the assignment rather than inside IRProtocolKDF, because this loop runs on a §7.7
           SNAPSHOT: a KDF that wiped its own input would destroy the live session's CKr on every
           forged message, which is precisely the desynchronisation DoS NEG-ATOMIC exists to catch.
           On a snapshot this chain key is a copy the snapshot owns outright. */
        IRChainKey *supersededChainKey = state.CKr;
        state.CKr = step.nextChainKey;
        [supersededChainKey zeroizeNow];

        /* The store key uses state.DHr — the CURRENT one, which during §7.4 step 1 is still the OLD
           peer key, and that is what lets a key skipped in the previous chain be found after the
           ratchet has moved on. */
        if (![state.skipped insertMessageKey:step.messageKey
                                    dhPublic:state.DHr
                                           N:state.Nr
                                    atTimeMs:nowMs]) {
            [step.messageKey zeroizeNow];
            IRSetError(error, IRErrorStateCorrupt);
            return NO;
        }

        /* "Nr advances once per derived key, whether that key is stored as skipped or used
           immediately" — §7.9's rule list. */
        state.Nr = state.Nr + 1;
    }

    return YES;
}

#pragma mark - §7.4 DH ratchet step

+ (BOOL)dhRatchetOnState:(IRRatchetState * _Nonnull)state
                   header:(IRMessageHeader * _Nonnull)header
                   budget:(IRSkipBudget * _Nonnull)budget
                 atTimeMs:(uint64_t)nowMs
                 provider:(id<IRCryptoProvider> _Nonnull)provider
                    error:(NSError * _Nullable * _Nullable)error {
    if (state == nil || state.isZeroized || header == nil || budget == nil || provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* header.ratchetKey has already passed §4.4 checks 1–2 and the anti-reflection check — §10.1
       checks 7–8 for type `0x01`, §10.2 checks 10–11 for type `0x02`. IRMessageHeader has no public
       initializer, so there is no route to one of these objects that did not run the ordered gate,
       and re-validating here would be duplicating an authority rather than adding one. */

    /* STEP 1 — drain the OLD receiving chain to the peer's stated previous-chain length, BEFORE
       DHr is replaced and BEFORE Nr is reset. No-op when CKr is none. */
    if (![self skipMessageKeysOnState:state
                                until:header.PN
                               budget:budget
                             atTimeMs:nowMs
                             provider:provider
                                error:error]) {
        return NO;
    }

    /* STEP 2 — roll the chains. PN takes the OUTGOING count, which is the value §9.1 requires the
       next header's PN field to carry; v3 never stored it and transmitted numberOfSentMessages in
       both slots instead (defect 10), which is why cross-chain recovery could not work at all. */
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.ratchetKey;

    /* STEP 3 — first root-chain step: the new RECEIVING chain. */
    IRSecretBytes *dh1 = [provider x25519WithPrivateKey:state.DHs.privateKey
                                              publicKey:state.DHr
                                                  error:error];
    if (dh1 == nil) {
        return NO;
    }

    IRRootChainStep *receiving = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:state.RK
                                                                       dhOutput:dh1
                                                                       provider:provider
                                                                          error:error];
    [dh1 zeroizeNow];

    if (receiving == nil) {
        return NO;
    }

    IRRootKey *supersededRootKey = state.RK;
    state.RK = receiving.rootKey;
    [supersededRootKey zeroizeNow];

    IRChainKey *supersededReceivingChain = state.CKr;
    state.CKr = receiving.chainKey;
    [supersededReceivingChain zeroizeNow];

    /* STEP 4 — fresh ratchet key. UNCONDITIONAL AND IDENTICAL FOR BOTH ROLES, which is only safe
       because the private half being destroyed is a session-owned copy (§7.5). Copy semantics were
       chosen over making this step conditional so the ratchet stays branch-free, so the intended
       forward secrecy is real (the session copy genuinely is wiped at the first ratchet), and so
       that §12.1 offset 243 means exactly one thing: a scalar this session owns and may destroy. */
    [state.DHs zeroize];

    IRX25519KeyPair *freshPair = [provider generateX25519KeyPairGuarded:NO error:error];
    if (freshPair == nil) {
        return NO;
    }

    state.DHs = freshPair;

    /* STEP 5 — second root-chain step: the new SENDING chain. STRICTLY SEQUENTIAL with step 3 —
       this KDF_RK consumes the RK that one produced. The root chain advances twice per ratchet and
       never restarts. */
    IRSecretBytes *dh2 = [provider x25519WithPrivateKey:state.DHs.privateKey
                                              publicKey:state.DHr
                                                  error:error];
    if (dh2 == nil) {
        return NO;
    }

    IRRootChainStep *sending = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:state.RK
                                                                     dhOutput:dh2
                                                                     provider:provider
                                                                        error:error];
    [dh2 zeroizeNow];

    if (sending == nil) {
        return NO;
    }

    IRRootKey *supersededIntermediateRootKey = state.RK;
    state.RK = sending.rootKey;
    [supersededIntermediateRootKey zeroizeNow];

    IRChainKey *supersededSendingChain = state.CKs;
    state.CKs = sending.chainKey;
    [supersededSendingChain zeroizeNow];

    return YES;
}

#pragma mark - §7.8 RatchetEncrypt

+ (NSData * _Nullable)encryptOnState:(IRRatchetState * _Nonnull)state
                            plaintext:(NSData * _Nonnull)plaintext
                          messageType:(IRMessageType)messageType
                    initiatorIdentity:(IRIdentityKeyPair * _Nullable)initiatorIdentity
                      identityBinding:(IREd25519Signature * _Nullable)identityBinding
                             provider:(id<IRCryptoProvider> _Nonnull)provider
                                error:(NSError * _Nullable * _Nullable)error {
    if (state == nil || state.isZeroized || plaintext == nil || provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §10.4 — "bounds MUST be checked before any allocation sized from the input". First guard, and
       it delegates so that MAX_PLAINTEXT has one owner. Length 0 is LEGAL and yields a 72-byte
       type `0x01` message. */
    if (![IRMessageBuilder validatePlaintextLength:plaintext.length error:error]) {
        return nil;
    }

    /* §7.8 guard 2 — a responder before its first ratchet, or any state whose sending chain does
       not yet exist. */
    if (state.CKs == nil) {
        IRSetError(error, IRErrorNoSendingChain);
        return nil;
    }

    /* §7.8 guard 3 — the same 0x7FFFFFFF ceiling the receive gates apply to N and PN, so this
       framework can never emit a message its own parser would reject. */
    if (state.Ns >= (uint32_t)kIRMaxCounter) {
        IRSetError(error, IRErrorCounterOverflow);
        return nil;
    }

    IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:state.CKs
                                                           provider:provider
                                                              error:error];
    if (step == nil) {
        return nil;
    }

    IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:step.messageKey
                                                      provider:provider
                                                         error:error];

    /* §8.1 — "MK MUST be zeroized immediately after expansion"; §13.3's MK row says the same.
       AT THE EXPANSION SITE, not after the AEAD call: `step` came from KDF_CK moments ago and is
       uniquely owned here — unlike the phase 3a skipped-key path, where the key is shared with the
       live store and NEG-SKIP-RETAIN requires it survive a failed decrypt. Nothing between here
       and the seal needs MK, so there is no reason for it to be resident across the nonce draw,
       the header build, the AD build and the AEAD call. IRProtocolKDF explicitly declines to wipe
       its argument, so this is the scheduled site. */
    [step.messageKey zeroizeNow];

    if (encKey == nil) {
        [step zeroize];
        return nil;
    }

    /* §8.3 — a fresh CSPRNG nonce for every seal, carried on the wire. Never a counter, never
       derived from the message key: this library persists and restores ratchet state, and a derived
       nonce would repeat (key, nonce) after any restore or fork, which under ChaCha20-Poly1305
       discloses the keystream XOR and leaks the Poly1305 one-time key, permitting forgery. */
    IRNonce *nonce = [provider randomNonceWithError:error];
    if (nonce == nil) {
        [step zeroize];
        [encKey zeroizeNow];
        return nil;
    }

    NSData *headerBytes = [self headerBytesForState:state
                                        messageType:messageType
                                  initiatorIdentity:initiatorIdentity
                                    identityBinding:identityBinding
                                              nonce:nonce
                                              error:error];
    if (headerBytes == nil) {
        [step zeroize];
        [encKey zeroizeNow];
        return nil;
    }

    /* §8.5 — AD is SESSION_AD ‖ the complete header, so version, type and flags are
       cryptographically enforced rather than merely checked by an `if`. */
    NSData *associatedData = [state.sessionAD associatedDataWithHeaderBytes:headerBytes error:error];
    if (associatedData == nil) {
        [step zeroize];
        [encKey zeroizeNow];
        return nil;
    }

    NSData *ciphertextAndTag = [provider aeadSealPlaintext:plaintext
                                                        key:encKey
                                                      nonce:nonce
                                             associatedData:associatedData
                                                      error:error];

    /* §13.3 — enc_key dies "immediately after the AEAD call returns, success AND failure paths".
       MK is already gone, at the expansion site above. IRCryptoProvider declines to wipe arguments
       it was handed, so this is the scheduled site. */
    [encKey zeroizeNow];

    if (ciphertextAndTag == nil) {
        [step zeroize];
        return nil;
    }

    NSData *message = [IRMessageBuilder messageWithHeaderBytes:headerBytes
                                              ciphertextAndTag:ciphertextAndTag
                                                         error:error];
    if (message == nil) {
        [step zeroize];
        return nil;
    }

    /* COMMIT — deliberately after the seal rather than before it, see the header. Everything above
       this line is derivation; nothing above it has touched the state. */
    IRChainKey *supersededChainKey = state.CKs;
    state.CKs = step.nextChainKey;
    [supersededChainKey zeroizeNow];

    state.Ns = state.Ns + 1;
    state.sendCounter = state.sendCounter + 1;

    return message;
}

#pragma mark - §7.9 RatchetDecrypt

+ (NSData * _Nullable)decryptOnSnapshot:(IRRatchetState * _Nonnull)snapshot
                                message:(NSData * _Nonnull)message
                                 header:(IRMessageHeader * _Nonnull)header
                                 budget:(IRSkipBudget * _Nonnull)budget
                               atTimeMs:(uint64_t)nowMs
                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                  error:(NSError * _Nullable * _Nullable)error {
    /* Argument validation runs BEFORE the discard helper is usable: with a nil or already-zeroized
       snapshot there is nothing meaningful to zeroize, and calling into one would mask the real
       fault. Every exit below this block goes through -failWithSnapshot:. */
    if (snapshot == nil || snapshot.isZeroized || message == nil || header == nil ||
        budget == nil || provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* `header` MUST be the one IRMessageGate parsed from `message`. Nothing in the type system says
       so, and a mismatched pair would authenticate one byte string while decrypting another — the
       AD comes from header.headerBytes and the ciphertext from `message`. Comparing them is cheap
       and both are public, so no constant-time treatment is required. */
    if (message.length < header.headerLength ||
        ![[message subdataWithRange:NSMakeRange(0, header.headerLength)] isEqualToData:header.headerBytes]) {
        IRSetError(error, IRErrorStateCorrupt);
        return [self failWithSnapshot:snapshot];
    }

    /* ---- Phase 2 ------------------------------------------------------------------------ */

    /* §7.6 / §12.2 rule 9 — TTL sweep. On the snapshot, so a failed decrypt does not drop entries
       from the live store; they are swept again on the next attempt. */
    [snapshot.skipped dropEntriesExpiredAtTimeMs:nowMs];

    NSData *associatedData = [IRMessageGate associatedDataWithSessionAD:snapshot.sessionAD
                                                                 header:header
                                                                  error:error];
    if (associatedData == nil) {
        return [self failWithSnapshot:snapshot];
    }

    NSData *ciphertextAndTag = [IRMessageGate ciphertextAndTagOfMessage:message
                                                                 header:header
                                                                  error:error];
    if (ciphertextAndTag == nil) {
        return [self failWithSnapshot:snapshot];
    }

    /* ---- Phase 3a: a skipped key, if we have one ----------------------------------------- */

    IRSkippedKeyEntry *entry = [snapshot.skipped entryForDHPublic:header.ratchetKey N:header.N];
    if (entry != nil) {
        if (entry.isZeroized) {
            /* Unreachable through this layer's own schedule; a wiped entry still resident in a live
               container means some other code zeroized out of turn, and decrypting under a
               all-zero key would be worse than failing. */
            IRSetError(error, IRErrorStateCorrupt);
            return [self failWithSnapshot:snapshot];
        }

        IRMessageEncKey *skippedEncKey = [IRProtocolKDF expandMessageKey:entry.messageKey
                                                                 provider:provider
                                                                    error:error];
        if (skippedEncKey == nil) {
            return [self failWithSnapshot:snapshot];
        }

        NSData *skippedPlaintext = [provider aeadOpenCiphertextAndTag:ciphertextAndTag
                                                                   key:skippedEncKey
                                                                 nonce:header.nonce
                                                        associatedData:associatedData
                                                                 error:error];
        [skippedEncKey zeroizeNow];

        if (skippedPlaintext == nil) {
            /* THE STORED KEY IS RETAINED. The entry is untouched and the snapshot is discarded, so
               a later correct delivery of the same message still succeeds. `NEG-SKIP-RETAIN`.
               Note that entry.messageKey is NOT wiped here — it is shared with the live store. */
            return [self failWithSnapshot:snapshot];
        }

        /* Only on success, and only as a deferred wipe: the live store still references this entry
           until the caller commits, at which point -zeroizePendingRemovals runs. */
        [snapshot.skipped removeEntryForDHPublic:header.ratchetKey N:header.N];

        /* "Returns WITHOUT performing a DH ratchet and WITHOUT advancing Nr" — §7.9's rule list. */
        [self clearPrologueIfSessionEstablished:snapshot];

        return skippedPlaintext;
    }

    /* ---- Phase 3b: DH ratchet if the peer moved ------------------------------------------ */

    if (snapshot.DHr == nil || ![snapshot.DHr isEqualToX25519Public:header.ratchetKey]) {
        if (![self dhRatchetOnState:snapshot
                             header:header
                             budget:budget
                           atTimeMs:nowMs
                           provider:provider
                              error:error]) {
            return [self failWithSnapshot:snapshot];
        }
    }

    /* ---- Phase 3c: skip forward within the current chain --------------------------------- */

    /* An explicit code, not a silent AEAD failure: the message is a duplicate or a replay and no
       skipped key is held for it, which is a different fact about the session than a bad tag. */
    if (header.N < snapshot.Nr) {
        IRSetError(error, IRErrorReplay);
        return [self failWithSnapshot:snapshot];
    }

    if (![self skipMessageKeysOnState:snapshot
                                until:header.N
                               budget:budget
                             atTimeMs:nowMs
                             provider:provider
                                error:error]) {
        return [self failWithSnapshot:snapshot];
    }

    /* ---- Phase 3d: derive and decrypt ---------------------------------------------------- */

    if (snapshot.CKr == nil) {
        /* Unreachable: phase 3b runs a ratchet whenever DHr does not match, and a ratchet always
           produces a CKr. Checked because the alternative to an explicit failure is a nil-keyed
           KDF call. */
        IRSetError(error, IRErrorStateCorrupt);
        return [self failWithSnapshot:snapshot];
    }

    IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:snapshot.CKr
                                                           provider:provider
                                                              error:error];
    if (step == nil) {
        return [self failWithSnapshot:snapshot];
    }

    IRChainKey *supersededChainKey = snapshot.CKr;
    snapshot.CKr = step.nextChainKey;
    [supersededChainKey zeroizeNow];

    snapshot.Nr = snapshot.Nr + 1;

    IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:step.messageKey
                                                      provider:provider
                                                         error:error];

    /* §8.1 / §13.3 — MK dies at the expansion site. `step` is this call's own chain step, not an
       entry borrowed from the skipped store, so unlike phase 3a nothing else holds a reference and
       nothing later needs it. Phase 3a's key MUST outlive a failed open (NEG-SKIP-RETAIN); this
       one must not. */
    [step.messageKey zeroizeNow];

    if (encKey == nil) {
        return [self failWithSnapshot:snapshot];
    }

    NSData *plaintext = [provider aeadOpenCiphertextAndTag:ciphertextAndTag
                                                        key:encKey
                                                      nonce:header.nonce
                                             associatedData:associatedData
                                                      error:error];

    /* §13.3 — enc_key, on both the success and the failure path. */
    [encKey zeroizeNow];

    if (plaintext == nil) {
        /* §7.7 — the live state is byte-identical to what it was before the call. The DH ratchet
           this attempt may have performed, the advanced Nr, and every skipped key it inserted all
           live on the snapshot, which is zeroized and dropped. This is the desynchronisation DoS
           v3 permitted: it ratcheted, advanced and inserted BEFORE calling aeDecryptData:. */
        return [self failWithSnapshot:snapshot];
    }

    [self clearPrologueIfSessionEstablished:snapshot];

    return plaintext;
}

#pragma mark - Internals

/// §7.7's discard, performed here so a caller cannot lose it. Always returns nil, so every failure
/// exit in -decryptOnSnapshot: reads as a single statement and none can forget the zeroize.
+ (NSData * _Nullable)failWithSnapshot:(IRRatchetState * _Nonnull)snapshot {
    [snapshot zeroizeAsDiscardedSnapshot];
    return nil;
}

/// §11.3 — A stops sending type `0x02` once it has successfully decrypted ANY message from B,
/// equivalently once CKr is non-none. Applied at every successful decrypt rather than left to the
/// caller, so the rule holds by construction; it is a no-op for a responder and after the first hit.
+ (void)clearPrologueIfSessionEstablished:(IRRatchetState * _Nonnull)state {
    if (state.role == IRSessionRoleInitiator && state.CKr != nil) {
        state.prologue = nil;
    }
}

+ (NSData * _Nullable)headerBytesForState:(IRRatchetState * _Nonnull)state
                               messageType:(IRMessageType)messageType
                         initiatorIdentity:(IRIdentityKeyPair * _Nullable)initiatorIdentity
                           identityBinding:(IREd25519Signature * _Nullable)identityBinding
                                     nonce:(IRNonce * _Nonnull)nonce
                                     error:(NSError * _Nullable * _Nullable)error {
    switch (messageType) {
        case IRMessageTypeNormal:
            /* §9.1 — N from state.Ns and PN from state.PN, two distinct stored variables. The
               builder names them separately for exactly this reason (defect 10). */
            return [IRMessageBuilder type01HeaderWithRatchetKey:state.DHs.publicKey
                                                              N:state.Ns
                                                             PN:state.PN
                                                          nonce:nonce
                                                          error:error];

        case IRMessageTypePrekey: {
            /* §11.3 — only an initiator that still holds its prologue can emit one of these, since
               EK_A, spk_id, opk_flag and opk_id must be IDENTICAL across every type `0x02` message
               of the session and the prologue is the single stored record of them. */
            if (state.role != IRSessionRoleInitiator || state.prologue == nil) {
                IRSetError(error, IRErrorStateCorrupt);
                return nil;
            }

            if (initiatorIdentity == nil || identityBinding == nil) {
                IRSetError(error, IRErrorStateCorrupt);
                return nil;
            }

            /* The header's IK_A pair and the pair SESSION_AD was built from MUST be the same
               identity. If they diverge, every receiver computes a different AD and reports
               ERR_AEAD_AUTH_FAILED — §1.2's code for an active man-in-the-middle — for what is
               really a local wiring mistake. Naming it here costs one comparison. */
            if (![state.sessionAD.initiatorIdentity isEqualToIdentityKeyPair:initiatorIdentity]) {
                IRSetError(error, IRErrorIdentityMismatch);
                return nil;
            }

            return [IRMessageBuilder type02HeaderWithInitiatorIdentity:initiatorIdentity
                                                       identityBinding:identityBinding
                                                              prologue:state.prologue
                                                            ratchetKey:state.DHs.publicKey
                                                                     N:state.Ns
                                                                 nonce:nonce
                                                                 error:error];
        }
    }

    IRSetError(error, IRErrorUnknownMessageType);
    return nil;
}

@end
