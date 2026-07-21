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

#import "IRErrors.h"

NSErrorDomain _Nonnull const IRErrorDomain = @"com.ivrodriguez.nuntius";

/// The lowest and highest codes §10.5 places in the mandatory peer-opaque range.
static IRErrorCode const kIROpaqueToPeerLowestCode = IRErrorUnsupportedVersion;   // 7100
static IRErrorCode const kIROpaqueToPeerHighestCode = IRErrorCounterOverflow;     // 7112

#pragma mark - Argument contracts (§13.4)

void IRRequireNonNil(id _Nullable value,
                     const char * _Nonnull parameter,
                     const char * _Nonnull function) {
    if (value != nil) {
        return;
    }

    /* §13.4 clause 1 — this is NOT reported through the §10.5 taxonomy, so there is deliberately no
       IRSetError here and no code to return. Clause 3 requires a check that survives Release, so
       this is outside any #if and is not NSParameterAssert (§3.3, §16.2).

       NSLog rather than nothing: the abort is otherwise a bare SIGABRT with no indication of which
       argument was missing, and §13.4's whole value to a host is that the failure is attributable
       to the caller at the call site. */
    NSLog(@"nuntius: SPEC §13.4 — required argument '%s' was nil in %s. A null passed for a "
          @"_Nonnull parameter is a caller contract violation, not a protocol condition: it has no "
          @"§10.5 code and MUST NOT be normalized to an empty or default value.",
          parameter, function);

    abort();
}

#pragma mark - Names

NSString * _Nonnull IRErrorNameForCode(IRErrorCode code) {
    switch (code) {
        case IRErrorUnsupportedVersion: return @"ERR_UNSUPPORTED_VERSION";
        case IRErrorUnknownMessageType: return @"ERR_UNKNOWN_MESSAGE_TYPE";
        case IRErrorReservedFlagsSet:   return @"ERR_RESERVED_FLAGS_SET";
        case IRErrorTruncatedMessage:   return @"ERR_TRUNCATED_MESSAGE";
        case IRErrorMalformedHeader:    return @"ERR_MALFORMED_HEADER";
        case IRErrorTrailingBytes:      return @"ERR_TRAILING_BYTES";
        case IRErrorInvalidPublicKey:   return @"ERR_INVALID_PUBLIC_KEY";
        case IRErrorSmallOrderKey:      return @"ERR_SMALL_ORDER_KEY";
        case IRErrorBadSignature:       return @"ERR_BAD_SIGNATURE";
        case IRErrorAEADAuthFailed:     return @"ERR_AEAD_AUTH_FAILED";
        case IRErrorTooManySkipped:     return @"ERR_TOO_MANY_SKIPPED";
        case IRErrorReplay:             return @"ERR_REPLAY";
        case IRErrorCounterOverflow:    return @"ERR_COUNTER_OVERFLOW";
        case IRErrorRNGFailure:         return @"ERR_RNG_FAILURE";
        case IRErrorUnknownPreKeyId:    return @"ERR_UNKNOWN_PREKEY_ID";
        case IRErrorOPKAlreadyConsumed: return @"ERR_OPK_ALREADY_CONSUMED";
        case IRErrorPreKeyExpired:      return @"ERR_PREKEY_EXPIRED";
        case IRErrorStateCorrupt:       return @"ERR_STATE_CORRUPT";
        case IRErrorNotInitialized:     return @"ERR_NOT_INITIALIZED";
        case IRErrorPlaintextTooLarge:  return @"ERR_PLAINTEXT_TOO_LARGE";
        case IRErrorNoSession:          return @"ERR_NO_SESSION";
        case IRErrorNoSendingChain:     return @"ERR_NO_SENDING_CHAIN";
        case IRErrorBundleMalformed:    return @"ERR_BUNDLE_MALFORMED";
        case IRErrorIdentityMismatch:   return @"ERR_IDENTITY_MISMATCH";
        case IRErrorStateRollback:      return @"ERR_STATE_ROLLBACK";
        case IRErrorWrongEntryPoint:    return @"ERR_WRONG_ENTRY_POINT";
    }

    return @"ERR_UNSPECIFIED";
}

BOOL IRErrorCodeFromName(NSString * _Nonnull name, IRErrorCode * _Nonnull outCode) {
    if (name == nil || outCode == NULL) {
        return NO;
    }

    for (NSInteger raw = IRErrorUnsupportedVersion; raw <= IRErrorWrongEntryPoint; raw++) {
        IRErrorCode candidate = (IRErrorCode)raw;
        if ([IRErrorNameForCode(candidate) isEqualToString:name]) {
            *outCode = candidate;
            return YES;
        }
    }

    return NO;
}

NSString * _Nonnull IRErrorMessageForCode(IRErrorCode code) {
    switch (code) {
        case IRErrorUnsupportedVersion: return @"Byte 0 is not 0x04.";
        case IRErrorUnknownMessageType: return @"Byte 1 is not 0x01 or 0x02.";
        case IRErrorReservedFlagsSet:   return @"Flags are not 0x0000.";
        case IRErrorTruncatedMessage:   return @"Below the message type's minimum length.";
        case IRErrorMalformedHeader:    return @"A header field is outside its permitted domain.";
        case IRErrorTrailingBytes:      return @"A state blob has bytes beyond its declared extent.";
        case IRErrorInvalidPublicKey:   return @"Wrong length, high bit set, or reflected own key.";
        case IRErrorSmallOrderKey:      return @"A Diffie-Hellman operation produced an all-zero output.";
        case IRErrorBadSignature:       return @"An identity binding or signed prekey signature failed to verify.";
        case IRErrorAEADAuthFailed:     return @"Poly1305 tag mismatch.";
        case IRErrorTooManySkipped:     return @"The per-message skipped key budget was exceeded.";
        case IRErrorReplay:             return @"Message number is below the receive counter with no matching skipped key.";
        case IRErrorCounterOverflow:    return @"A message counter exceeded its maximum.";
        case IRErrorRNGFailure:         return @"The cryptographic random number generator failed.";
        case IRErrorUnknownPreKeyId:    return @"A signed prekey or one-time prekey id does not resolve.";
        case IRErrorOPKAlreadyConsumed: return @"The one-time prekey was already used.";
        case IRErrorPreKeyExpired:      return @"Outside the prekey validity window, or the window is too long.";
        case IRErrorStateCorrupt:       return @"State blob failed structural validation.";
        case IRErrorNotInitialized:     return @"The cryptographic backend is not initialized.";
        case IRErrorPlaintextTooLarge:  return @"Above the maximum plaintext or message size.";
        case IRErrorNoSession:          return @"No session handle was supplied, or it does not resolve.";
        case IRErrorNoSendingChain:     return @"Encryption was attempted with no sending chain key.";
        case IRErrorBundleMalformed:    return @"Prekey bundle failed structural validation.";
        case IRErrorIdentityMismatch:   return @"Header identity keys disagree with the cached session.";
        case IRErrorStateRollback:      return @"The persisted send counter went backwards.";
        case IRErrorWrongEntryPoint:    return @"A message of one type was submitted to the entry point for the other type.";
    }

    return @"Unspecified nuntius failure.";
}

#pragma mark - Construction

NSError * _Nonnull IRErrorWithCode(IRErrorCode code) {
    NSDictionary<NSErrorUserInfoKey, id> *userInfo = @{
        NSLocalizedDescriptionKey: IRErrorMessageForCode(code),
        NSLocalizedFailureReasonErrorKey: IRErrorNameForCode(code),
    };

    return [NSError errorWithDomain:IRErrorDomain code:(NSInteger)code userInfo:userInfo];
}

void IRSetError(NSError * _Nullable * _Nullable outError, IRErrorCode code) {
    /* §10.5: MUST NOT dereference a null out-parameter. This branch is the whole reason this
       function exists, and it is why no other file in the framework writes `*error = ...`. */
    if (outError == NULL) {
        return;
    }

    *outError = IRErrorWithCode(code);
}

void IRSetErrorWithUnderlying(NSError * _Nullable * _Nullable outError,
                              IRErrorCode code,
                              NSError * _Nullable underlying) {
    if (outError == NULL) {
        return;
    }

    if (underlying == nil) {
        *outError = IRErrorWithCode(code);
        return;
    }

    NSDictionary<NSErrorUserInfoKey, id> *userInfo = @{
        NSLocalizedDescriptionKey: IRErrorMessageForCode(code),
        NSLocalizedFailureReasonErrorKey: IRErrorNameForCode(code),
        NSUnderlyingErrorKey: underlying,
    };

    *outError = [NSError errorWithDomain:IRErrorDomain code:(NSInteger)code userInfo:userInfo];
}

#pragma mark - Peer disclosure

BOOL IRErrorMustBeOpaqueToPeer(IRErrorCode code) {
    /* §10.5 names "codes 7100-7112 AND 7125". 7125 is not contiguous with the band and is listed
       separately rather than by widening it: it is remotely triggerable through a transport that
       flips the inner type byte, and telling a peer which entry point a host used discloses host
       routing structure for no benefit. Everything between 7113 and 7124 stays outside. */
    if (code == IRErrorWrongEntryPoint) {
        return YES;
    }

    return (code >= kIROpaqueToPeerLowestCode && code <= kIROpaqueToPeerHighestCode);
}
