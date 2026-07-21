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

#import "IRSession+Internal.h"

#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSkippedKeyStore.h"

/* A second class extension, alongside the one in IRSession+Internal.h. Both are legal; this one
   holds what nothing outside this file may call. */
@interface IRSession ()

- (instancetype _Nullable)initWithState:(IRRatchetState * _Nonnull)state
                    peerIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)peer
                     ownIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)own;

@end

@implementation IRSession {
    IRIdentityKeyPair *_peerIdentityKeyPair;
    IRIdentityKeyPair *_ownIdentityKeyPair;
    NSData *_handshakeId;
    IRSessionRole _role;
    BOOL _tornDown;
}

#pragma mark - Construction

+ (instancetype _Nullable)sessionWithState:(IRRatchetState * _Nonnull)state
                                     error:(NSError * _Nullable * _Nullable)error {
    if (state == nil || state.isZeroized) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (state.role != IRSessionRoleInitiator && state.role != IRSessionRoleResponder) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §6.5 — both identities come from the stored SESSION_AD, at the sub-offsets §6.5 states
       normatively. -peerIdentityForRole: returns nil only for a role outside {0x01, 0x02}, which
       the check above has already excluded; it is threaded anyway because a session filed under
       the wrong peer is a failure that must be loud rather than defaulted. */
    IRIdentityKeyPair *peer = [state.sessionAD peerIdentityForRole:state.role];
    IRIdentityKeyPair *own = [state.sessionAD ownIdentityForRole:state.role];
    if (peer == nil || own == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (state.handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSession *session = [[IRSession alloc] initWithState:state
                                     peerIdentityKeyPair:peer
                                      ownIdentityKeyPair:own];
    if (session == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return session;
}

- (instancetype _Nullable)initWithState:(IRRatchetState * _Nonnull)state
                    peerIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)peer
                     ownIdentityKeyPair:(IRIdentityKeyPair * _Nonnull)own {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _state = state;
    _peerIdentityKeyPair = peer;
    _ownIdentityKeyPair = own;

    /* Copied out of the state once. The handshake id and the role are fixed at handshake time, so
       caching them keeps every routing decision independent of the mutable half of this object. */
    _handshakeId = [state.handshakeId copy];
    _role = state.role;
    _tornDown = NO;

    return self;
}

#pragma mark - Public

- (NSData * _Nonnull)handshakeId {
    return _handshakeId;
}

- (IRSessionRole)role {
    return _role;
}

- (IRIdentityKeyPair * _Nonnull)peerIdentityKeyPair {
    return _peerIdentityKeyPair;
}

- (IRIdentityKeyPair * _Nonnull)ownIdentityKeyPair {
    return _ownIdentityKeyPair;
}

- (uint64_t)sendCounter {
    return _state.sendCounter;
}

- (BOOL)sendsPreKeyMessages {
    if (_tornDown) {
        return NO;
    }

    return _state.shouldSendPreKeyMessage;
}

- (BOOL)isTornDown {
    return _tornDown;
}

- (IRFingerprint * _Nullable)peerFingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                                   error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [_peerIdentityKeyPair fingerprintWithProvider:provider error:error];
}

#pragma mark - §7.7 snapshot / commit / discard

- (IRRatchetState * _Nullable)snapshot {
    if (_tornDown) {
        return nil;
    }

    return [_state snapshot];
}

- (BOOL)commitSnapshot:(IRRatchetState * _Nonnull)snapshot
                 error:(NSError * _Nullable * _Nullable)error {
    if (_tornDown) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (snapshot == nil || snapshot.isZeroized) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (snapshot == _state) {
        /* Committing the live state over itself would zeroize it two statements below. Nothing in
           the framework does this; it is refused rather than tolerated because the symptom would
           be an all-zero root key with no other trace. */
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* The order below is the whole of §7.7's commit half, and none of the three steps commutes.

       1. The snapshot's store inherited its entries from the live store, so entries it REMOVED,
          EVICTED or EXPIRED are still referenced by the state we are about to supersede. Wiping
          them at removal time would have destroyed a live key; this is the first instant at which
          the wipe is true, and it is §13.3's "skipped message keys: on use, on eviction, and on
          TTL expiry" deferred to it.
       2. One pointer assignment. There is no window in which half a decrypt is visible.
       3. The superseded state's own RK, CKs, CKr and DHs.priv are distinct allocations (see
          -[IRRatchetState snapshot]), so wiping them cannot reach the live session. */
    [snapshot.skipped zeroizePendingRemovals];

    IRRatchetState *superseded = _state;
    _state = snapshot;

    [superseded zeroizeAsSupersededState];

    return YES;
}

- (void)discardSnapshot:(IRRatchetState * _Nonnull)snapshot {
    if (snapshot == nil || snapshot == _state) {
        return;
    }

    /* Idempotent: IRRatchet already zeroizes on every one of its own failure exits, so this is a
       backstop for a caller that abandoned a snapshot without reaching a decrypt at all.

       -zeroizeAsDiscardedSnapshot wipes this snapshot's OWN copies and the entries THIS attempt
       derived. It deliberately does not touch inherited entries the attempt removed: the live
       store still owns those, and wiping them is exactly the `NEG-SKIP-RETAIN` failure. */
    [snapshot zeroizeAsDiscardedSnapshot];
}

#pragma mark - §12.1 persistence

- (IRSecretBytes * _Nullable)serializedState:(NSError * _Nullable * _Nullable)error {
    if (_tornDown) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [IRSessionStateCodec serializeState:_state error:error];
}

#pragma mark - §11.1.1 / §11.4 teardown

- (void)tearDown {
    if (_tornDown) {
        return;
    }

    _tornDown = YES;

    /* Full teardown, including every entry in the skipped store — correct here and nowhere else,
       because a torn-down session shares its store with nothing. */
    [_state zeroize];
}

#pragma mark - Description

- (NSString * _Nonnull)description {
    /* The handshake id is public (§11.1) and is the value a log needs to correlate two sides of a
       race. No key material, no counters that would narrow a nonce search. */
    NSMutableString *hex = [NSMutableString stringWithCapacity:(_handshakeId.length * 2)];
    const uint8_t *bytes = (const uint8_t *)_handshakeId.bytes;
    for (NSUInteger i = 0; i < _handshakeId.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }

    return [NSString stringWithFormat:@"<%@: %p; role = %@; handshake_id = %@%@>",
            NSStringFromClass([self class]), (void *)self,
            (_role == IRSessionRoleInitiator ? @"initiator" : @"responder"),
            hex,
            (_tornDown ? @"; torn down" : @"")];
}

@end
