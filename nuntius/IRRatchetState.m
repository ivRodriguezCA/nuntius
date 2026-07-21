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

#import "IRRatchetState.h"

#pragma mark - IRSkipBudget

@implementation IRSkipBudget {
    uint32_t _remaining;
}

+ (instancetype _Nonnull)budget {
    return [[self alloc] initWithLimit:(uint32_t)kIRMaxSkipPerMessage];
}

+ (instancetype _Nonnull)budgetWithLimit:(uint32_t)limit {
    return [[self alloc] initWithLimit:limit];
}

- (instancetype _Nonnull)initWithLimit:(uint32_t)limit {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _remaining = limit;

    return self;
}

- (uint32_t)remaining {
    return _remaining;
}

- (BOOL)consume:(uint32_t)count {
    /* §7.6: "if state.skip_budget < needed: return ERR_TOO_MANY_SKIPPED — state MUST be left
       unmodified". The deduction happens only once the whole span is known to fit, so a rejected
       call leaves the budget as well as the state untouched, and the two SkipMessageKeys calls of
       one received message really do share one allowance. */
    if (count > _remaining) {
        return NO;
    }

    _remaining -= count;

    return YES;
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; remaining = %u>",
            NSStringFromClass([self class]), (void *)self, _remaining];
}

@end

#pragma mark - IRRatchetState

@implementation IRRatchetState

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
                                   error:(NSError * _Nullable * _Nullable)error {
    /* §12.2 rule 4 — role is a closed domain, and a session filed under a role outside it would
       read SESSION_AD's two identity halves the wrong way round for the rest of its life. */
    if (role != IRSessionRoleInitiator && role != IRSessionRoleResponder) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (sessionAD == nil || sessionAD.bytes.length != kIRLenSessionAD) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (handshakeId == nil || handshakeId.length != kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (rootKey == nil || rootKey.length != kIRLenRootKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (ratchetKeyPair == nil ||
        ratchetKeyPair.publicKey.length != kIRLenX25519Public ||
        ratchetKeyPair.privateKey.length != kIRLenX25519Private) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (peerRatchetPublic != nil && peerRatchetPublic.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (sendingChainKey != nil && sendingChainKey.length != kIRLenChainKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (receivingChainKey != nil && receivingChainKey.length != kIRLenChainKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRRatchetState *state = [[IRRatchetState alloc] initInternal];
    if (state == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    state->_role = role;
    state->_sessionAD = sessionAD;
    state->_handshakeId = [handshakeId copy];
    state->_RK = rootKey;
    state->_DHs = ratchetKeyPair;
    state->_DHr = peerRatchetPublic;
    state->_CKs = sendingChainKey;
    state->_CKr = receivingChainKey;
    state->_Ns = Ns;
    state->_Nr = Nr;
    state->_PN = PN;
    state->_sendCounter = sendCounter;
    state->_prologue = prologue;
    state->_skipped = (skipped != nil) ? skipped : [IRSkippedKeyStore store];
    state->_isZeroized = NO;

    return state;
}

- (instancetype _Nonnull)initInternal {
    return [super init];
}

#pragma mark - Derived

- (BOOL)shouldSendPreKeyMessage {
    /* §11.3 — "A sends type 0x02 for every message until A has successfully decrypted ANY message
       from B — equivalently, until CKr becomes non-none."

       The prologue is part of the conjunction rather than an implied consequence: it is what a
       type `0x02` header is BUILT from, so a state that satisfies the first two clauses without it
       cannot emit one, and reporting YES would send the caller into a guaranteed error. */
    return (_role == IRSessionRoleInitiator) && (_CKr == nil) && (_prologue != nil);
}

#pragma mark - §7.7 snapshotting

- (IRRatchetState * _Nullable)snapshot {
    if (_isZeroized) {
        return nil;
    }

    /* FRESH ALLOCATIONS for every secret this state owns outright. See the class comment: sharing
       them would make -zeroizeAsSupersededState destroy the live root key on the commit path of any
       message that did not ratchet, which is most messages. */
    IRRootKey *rootKeyCopy = (IRRootKey *)[_RK duplicate];
    if (rootKeyCopy == nil) {
        return nil;
    }

    /* -deepCopy reallocates the private half and shares the immutable public half — the §7.5 /
       §19.1 ownership rule, applied here between a snapshot and its live state for the same reason
       it applies between a session and the prekey store. */
    IRX25519KeyPair *ratchetCopy = [_DHs deepCopy];
    if (ratchetCopy == nil) {
        [rootKeyCopy zeroizeNow];
        return nil;
    }

    IRChainKey *sendingCopy = nil;
    if (_CKs != nil) {
        sendingCopy = (IRChainKey *)[_CKs duplicate];
        if (sendingCopy == nil) {
            [rootKeyCopy zeroizeNow];
            [ratchetCopy zeroize];
            return nil;
        }
    }

    IRChainKey *receivingCopy = nil;
    if (_CKr != nil) {
        receivingCopy = (IRChainKey *)[_CKr duplicate];
        if (receivingCopy == nil) {
            [rootKeyCopy zeroizeNow];
            [ratchetCopy zeroize];
            [sendingCopy zeroizeNow];
            return nil;
        }
    }

    /* DHr, sessionAD, handshakeId and prologue are immutable and are shared. The skipped store
       shares its ENTRIES but not its containers (D4). */
    return [IRRatchetState stateWithRole:_role
                               sessionAD:_sessionAD
                             handshakeId:_handshakeId
                                 rootKey:rootKeyCopy
                          ratchetKeyPair:ratchetCopy
                       peerRatchetPublic:_DHr
                         sendingChainKey:sendingCopy
                       receivingChainKey:receivingCopy
                                      Ns:_Ns
                                      Nr:_Nr
                                      PN:_PN
                             sendCounter:_sendCounter
                                prologue:_prologue
                                 skipped:[_skipped copyForSnapshot]
                                   error:NULL];
}

#pragma mark - §13.3 zeroization

- (void)zeroizeAsDiscardedSnapshot {
    [self zeroizeOwnedSecrets];

    /* Only what THIS attempt derived. The inherited entries belong to the live store, and wiping
       them is precisely the failure `NEG-SKIP-RETAIN` exists to catch: a corrupted tag on a
       skipped-key message would destroy the only copy of a key whose message may still arrive
       intact. */
    [_skipped zeroizeDerivedInsertions];

    _isZeroized = YES;
}

- (void)zeroizeAsSupersededState {
    [self zeroizeOwnedSecrets];

    /* Deliberately no store call. The committed store shares these entry objects, and its own
       -zeroizePendingRemovals has already wiped exactly the ones that left it. */

    _isZeroized = YES;
}

- (void)zeroize {
    [self zeroizeOwnedSecrets];
    [_skipped zeroizeAll];

    _isZeroized = YES;
}

- (void)zeroizeOwnedSecrets {
    [_RK zeroizeNow];
    [_CKs zeroizeNow];
    [_CKr zeroizeNow];

    /* -zeroize on the pair wipes the private half only; the public is not secret and remains
       readable, which matters because a superseded state may still be inspected for diagnostics. */
    [_DHs zeroize];
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:
            @"<%@: %p; role = %@; Ns = %u; Nr = %u; PN = %u; CKs = %@; CKr = %@; DHr = %@; "
            @"skipped = %lu; sendCounter = %llu; prologue = %@; zeroized = %@>",
            NSStringFromClass([self class]), (void *)self,
            (_role == IRSessionRoleInitiator) ? @"initiator" : @"responder",
            _Ns, _Nr, _PN,
            (_CKs != nil) ? @"present" : @"none",
            (_CKr != nil) ? @"present" : @"none",
            (_DHr != nil) ? [_DHr hexString] : @"none",
            (unsigned long)_skipped.count,
            (unsigned long long)_sendCounter,
            (_prologue != nil) ? @"present" : @"none",
            _isZeroized ? @"YES" : @"NO"];
}

@end
