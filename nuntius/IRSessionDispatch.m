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

#import "IRSessionDispatch.h"

#import "IRRatchetState.h"
#import "IRSession+Internal.h"
#import "IRSessionAD.h"

#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRPublicIdentity.h>

#include <string.h>

#pragma mark - §11.1.1 handshake_id ordering

BOOL IRCompareHandshakeIds(NSData * _Nullable a,
                           NSData * _Nullable b,
                           NSComparisonResult * _Nonnull outResult) {
    if (outResult == NULL) {
        return NO;
    }

    if (a.length != (NSUInteger)kIRLenHandshakeId || b.length != (NSUInteger)kIRLenHandshakeId) {
        return NO;
    }

    /* memcmp compares as `unsigned char`, which IS the 64-byte unsigned big-endian comparison
       §11.1.1 asks for: big-endian means the most significant byte comes first, so the first
       differing byte decides, and comparing those two bytes as unsigned decides correctly. A port
       whose byte type is signed cannot reuse this reasoning — see the header. */
    int result = memcmp(a.bytes, b.bytes, (size_t)kIRLenHandshakeId);

    if (result < 0) {
        *outResult = NSOrderedAscending;
    } else if (result > 0) {
        *outResult = NSOrderedDescending;
    } else {
        *outResult = NSOrderedSame;
    }

    return YES;
}

@implementation IRSessionDispatch

#pragma mark - §11.2

+ (BOOL)validatePreKeyMessageHeader:(IRMessageHeader * _Nonnull)header
                     againstSession:(IRSession * _Nonnull)session
                           provider:(id<IRCryptoProvider> _Nonnull)provider
                              error:(NSError * _Nullable * _Nullable)error {
    if (header == nil || session == nil || provider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (session.isTornDown) {
        /* A torn-down session's key material is gone. §11.4 keeps its handshake_id as a tombstone
           precisely so that a message naming it is answered before it reaches here. */
        IRSetError(error, IRErrorNoSession);
        return NO;
    }

    if (header.type != IRMessageTypePrekey || !header.isPreKeyMessage) {
        IRSetError(error, IRErrorMalformedHeader);
        return NO;
    }

    IRIdentityKeyPair *headerIdentity = header.initiatorIdentity;
    IREd25519Signature *headerBinding = header.identityBinding;
    if (headerIdentity == nil || headerBinding == nil) {
        IRSetError(error, IRErrorMalformedHeader);
        return NO;
    }

    // ---- check 1: identity ---------------------------------------------------------------- //
    // `s.IK_A^s` and `s.IK_A^d` are the session's INITIATOR pair, whatever OUR role is. For a
    // responder that is the peer. For an initiator it is us, and this rejects a peer replaying our
    // own handshake back at us before any signature work is done.
    IRIdentityKeyPair *sessionInitiator = session.state.sessionAD.initiatorIdentity;
    if (![headerIdentity isEqualToIdentityKeyPair:sessionInitiator]) {
        IRSetError(error, IRErrorIdentityMismatch);
        return NO;
    }

    // ---- check 2: IKB_A ------------------------------------------------------------------- //
    // Routed through IRPublicIdentity's only constructor, which verifies. That keeps §5.5's
    // "every identity ingest" MUST discharged by the type system here exactly as it is on the
    // §10.7 step 3 path, rather than by a second hand-rolled verification that could drift.
    NSError *bindingError = nil;
    IRPublicIdentity *verified = [IRPublicIdentity identityWithKeyPair:headerIdentity
                                                               binding:headerBinding
                                                              provider:provider
                                                                 error:&bindingError];
    if (verified == nil) {
        /* §11.2 is explicit that a failure here MUST be the signature code and never the AEAD
           code, "even though the AD covers those bytes". `NEG-IKB-RETRANS` arbitrates it. Any
           non-signature failure from the constructor (an uninitialized sodium, say) is surfaced
           through NSUnderlyingErrorKey rather than being collapsed. */
        IRSetErrorWithUnderlying(error, IRErrorBadSignature, bindingError);
        return NO;
    }

    // ---- check 3: anti-reflection --------------------------------------------------------- //
    // A peer echoing our own ratchet public back at us would otherwise drive a DH ratchet against
    // our own key. §10.1 check 8 is the type `0x01` form of this; §10.2 cannot perform it because
    // a gate has no session.
    if ([header.ratchetKey isEqualToX25519Public:session.state.DHs.publicKey]) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return NO;
    }

    return YES;
}

#pragma mark - §11.1.1

+ (BOOL)resolveCollapseForIncomingSession:(IRSession * _Nonnull)incoming
                          againstExisting:(IRSession * _Nonnull)existing
                             incomingWins:(BOOL * _Nonnull)outIncomingWins
                                    error:(NSError * _Nullable * _Nullable)error {
    if (incoming == nil || existing == nil || outIncomingWins == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    NSComparisonResult order = NSOrderedSame;
    if (!IRCompareHandshakeIds(incoming.handshakeId, existing.handshakeId, &order)) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    if (order == NSOrderedSame) {
        /* Two handles naming one handshake. §11.2 routes a repeated prekey message to the existing
           session long before this point, so reaching here means the caller resolved the same
           session twice — a bug that "keep the existing one" would hide. */
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    *outIncomingWins = (order == NSOrderedDescending);

    return YES;
}

@end
