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

/**
 nuntius v4 error taxonomy — SPEC §10.5.

 The v3 codes 7001–7003 are RETIRED and MUST NOT be reused: a v3 consumer that still switches on
 them would silently mis-handle a v4 failure.

 INFORMATION LEAKAGE (§10.5). These distinct codes exist for LOCAL DIAGNOSABILITY ONLY. An
 application MUST NOT reveal which code occurred to the network peer and MUST NOT vary its response
 timing by code; codes 7100–7112 surface to a peer, if at all, as a single opaque "undecryptable"
 signal. Distinguishing ERR_REPLAY from ERR_AEAD_AUTH_FAILED to a peer tells an attacker whether a
 guessed counter sat in the skipped-key store. Use IRErrorMustBeOpaqueToPeer() to classify.
 */

/// §10.5 — the one and only error domain in this framework. v3 spelled a `com.ivrodriguez.*`
/// literal at each throw site; there is now exactly one.
extern NSErrorDomain _Nonnull const IRErrorDomain;

typedef NS_ERROR_ENUM(IRErrorDomain, IRErrorCode) {
    /// Byte 0 is not 0x04. A v3 message begins 0x03 and lands here (§10.6): there is no downgrade
    /// path and no dual-stack mode.
    IRErrorUnsupportedVersion = 7100,
    /// Byte 1 is not 0x01 or 0x02.
    IRErrorUnknownMessageType = 7101,
    /// Flags are not 0x0000.
    IRErrorReservedFlagsSet = 7102,
    /// Below the type's minimum length.
    IRErrorTruncatedMessage = 7103,
    /// A header field is outside its permitted domain.
    IRErrorMalformedHeader = 7104,
    /// A STATE BLOB has bytes beyond its declared extent. NEVER a bundle: every bundle structural
    /// failure, including a wrong total length in either direction, is IRErrorBundleMalformed
    /// (§10.3, §19.4).
    IRErrorTrailingBytes = 7105,
    /// Wrong length, high bit set, or reflected own key (§4.4 checks 1–2).
    IRErrorInvalidPublicKey = 7106,
    /// A DH produced an all-zero output (§4.4 check 3).
    IRErrorSmallOrderKey = 7107,
    /// IKB or SPK_SIG failed to verify.
    IRErrorBadSignature = 7108,
    /// Poly1305 tag mismatch.
    IRErrorAEADAuthFailed = 7109,
    /// MAX_SKIP_PER_MESSAGE exceeded.
    IRErrorTooManySkipped = 7110,
    /// N < Nr with no matching skipped key.
    IRErrorReplay = 7111,
    /// N or PN above 0x7FFFFFFF, or Ns exhausted.
    IRErrorCounterOverflow = 7112,
    /// The CSPRNG failed.
    IRErrorRNGFailure = 7113,
    /// spk_id or opk_id does not resolve.
    IRErrorUnknownPreKeyId = 7114,
    /// The one-time prekey was already used.
    ///
    /// UNREACHABLE AS SPECIFIED, and deliberately never emitted by this implementation. §6.6 step 4
    /// requires the consumed entry to be zeroized and unlinked, and no section requires a
    /// per-opk_id tombstone, so after consumption a used OPK is byte-indistinguishable from one
    /// that never existed. §11.4's replay table maps the consumed case to
    /// IRErrorUnknownPreKeyId in every row and §15.4 has no vector for 7115. Raised as spec gap G1;
    /// the interim behaviour is to emit IRErrorUnknownPreKeyId.
    IRErrorOPKAlreadyConsumed = 7115,
    /// Outside the validity window, or the window is longer than MAX_SPK_VALIDITY_SECONDS.
    IRErrorPreKeyExpired = 7116,
    /// State blob failed structural validation.
    IRErrorStateCorrupt = 7117,
    /// sodium_init() failed or was not called.
    IRErrorNotInitialized = 7118,
    /// Above MAX_PLAINTEXT, or a message above its type's maximum.
    IRErrorPlaintextTooLarge = 7119,
    /// A type 0x01 message was submitted with no session handle, or with one that does not
    /// resolve (§11.5).
    IRErrorNoSession = 7120,
    /// Encrypt attempted with CKs unset.
    IRErrorNoSendingChain = 7121,
    /// Bundle failed structural validation.
    IRErrorBundleMalformed = 7122,
    /// Header identity keys disagree with the cached session.
    IRErrorIdentityMismatch = 7123,
    /// send_counter went backwards (§12.5).
    IRErrorStateRollback = 7124,
    /// A well-formed message of one type was submitted to the entry point for the other type
    /// (§10.0 row 5).
    ///
    /// NOT IRErrorUnknownMessageType. 7101's meaning is a predicate over the MESSAGE alone — "byte
    /// 1 is not 0x01 or 0x02" — and here byte 1 genuinely is a valid type. This condition is a
    /// predicate over (message, entry point), and the two have different remedies: 7101 means a
    /// peer sent bytes that are not a message type and the message should be dropped, 7125 means
    /// the host routed a genuine message to the wrong call and the host's demultiplexer should be
    /// fixed. §11.5 rule 5's router is what lets a conformant host avoid it entirely (§19.8).
    IRErrorWrongEntryPoint = 7125,
};

#pragma mark - Argument contracts (§13.4)

/**
 §13.4 — the ONLY permitted response to a null passed for a _Nonnull parameter of a specified
 operation. Aborts. It never returns.

 A null reference where the API declares _Nonnull is a CALLER CONTRACT VIOLATION, not a protocol
 condition: it has no §10.5 code, it is never reported through the error out-parameter, and §13.4
 clause 2 forbids substituting a default for it. That clause is the whole point. §10.4 makes a
 ZERO-LENGTH plaintext legal, so coercing nil to an empty NSData is indistinguishable downstream
 from a legitimate empty input — and in Objective-C the coercion happens without anyone writing it,
 because `[nilData length]` is 0 and `[nilData bytes]` is NULL. An empty IKM reaching HKDF-Extract
 yields a 32-byte SK both parties agree on that has no key material in it; that is §13.1's
 failing-open pattern reached through the argument list instead of the RNG.

 NOT NSParameterAssert / NSAssert, which §3.3 bans as a sole guard: both compile out under
 NS_BLOCK_ASSERTIONS, which is the default in a Release build of a framework dependency, so a
 precondition written with them does nothing in the configuration consumers actually ship. This
 function is outside any #if and survives Release.

 Absence of a SESSION HANDLE is deliberately NOT this (§13.4 clause 5). §10.1 check 6 specifies it
 as IRErrorNoSession and `NEG-NO-SESSION`'s first case is "no handle at all", so that one parameter
 is _Nullable and reports through the taxonomy.
 */
void IRRequireNonNil(id _Nullable value,
                     const char * _Nonnull parameter,
                     const char * _Nonnull function) __attribute__((nonnull(2, 3)));

/// Call-site sugar for IRRequireNonNil that captures the enclosing function name.
#define IRRequireArgument(value) IRRequireNonNil((value), #value, __PRETTY_FUNCTION__)

#pragma mark - Error out-parameter helpers

/**
 The ONLY permitted way to write an NSError out-parameter anywhere in this framework.

 No-ops when `outError` is NULL. This discharges §10.5's "Every failure path MUST set the error
 out-parameter, and MUST NOT dereference a null one" once, here, instead of at every call site.
 v3 wrote `*error = err` with no null check in `aeEncryptSimpleData:` and `aeDecryptSimpleData:`,
 crashing every caller that passed NULL — which every test in the repository did.

 A raw `*error = ...` anywhere outside IRErrors.m is a lint failure
 (tools/lint_banned_apis.py).
 */
void IRSetError(NSError * _Nullable * _Nullable outError, IRErrorCode code);

/// As IRSetError, additionally threading `underlying` through NSUnderlyingErrorKey. The underlying
/// error is for local diagnosis only and MUST NOT be surfaced to a peer.
void IRSetErrorWithUnderlying(NSError * _Nullable * _Nullable outError,
                              IRErrorCode code,
                              NSError * _Nullable underlying);

/// Builds the error value without an out-parameter, for the few call sites that must return an
/// NSError rather than assign one.
NSError * _Nonnull IRErrorWithCode(IRErrorCode code);

#pragma mark - Names

/**
 The SPEC §10.5 symbolic name, e.g. `ERR_UNSUPPORTED_VERSION`.

 §15.5 requires the conformance-vector runner to compare error NAMES rather than numbers, so that a
 renumbering is a loud failure in all four ports rather than a silent mismatch. Returns
 `ERR_UNSPECIFIED` for a code outside the taxonomy.
 */
NSString * _Nonnull IRErrorNameForCode(IRErrorCode code);

/// Inverse of IRErrorNameForCode, for reading the `error:` field of a §15.5 vector file.
/// Returns NO and leaves `outCode` untouched when `name` is not a §10.5 name.
BOOL IRErrorCodeFromName(NSString * _Nonnull name, IRErrorCode * _Nonnull outCode);

/// The §10.5 table's "Meaning" column. Local diagnostics only — never transmit it.
NSString * _Nonnull IRErrorMessageForCode(IRErrorCode code);

#pragma mark - Peer disclosure

/**
 §10.5 information leakage: YES for codes 7100–7112, which an application MUST collapse into a
 single opaque "undecryptable" signal before any value reaches a network peer.

 Returning NO does NOT mean a code is safe to transmit — it means only that §10.5 does not name it
 in the mandatory-collapse range. Disclosure remains an application decision.
 */
BOOL IRErrorMustBeOpaqueToPeer(IRErrorCode code);
