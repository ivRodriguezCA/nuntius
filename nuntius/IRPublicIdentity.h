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

/**
 Peer identity — SPEC §5.1, §5.5, §6.5, §11.1.

 §5.5 IS NORMATIVE AND IS THE SHARPEST EDGE IN THE DESIGN: "An identity in nuntius v4 IS the pair
 (IK^s, IK^d), not either key alone." Splitting the identity into a signing key and a DH key means
 the DH operations prove possession of IK^d ONLY. Without IKB covering both keys, an attacker could
 present a victim's genuine IK^s alongside an attacker-controlled IK^d, complete a cryptographically
 sound session, and be attributed to the victim by any implementation that looks up contacts by the
 signing key.

 TWO TYPES, AND THE SPLIT IS THE POINT.

   IRIdentityKeyPair  the raw pair. NO signature. This is the §11.1 index key and the value §6.5
                      stores inside SESSION_AD, so it MUST be constructible from bytes that carry no
                      signature — SESSION_AD itself, a restored state blob, a host contact record.

   IRPublicIdentity   the INGEST type. Its only constructor verifies IKB before returning, so an
                      unverified identity value cannot exist in this process. That is how §5.5's
                      "MUST be verified on EVERY identity ingest — from a fetched bundle, from a type
                      0x02 message header, from a cached contact record, and after state restore.
                      Not only on first contact" is discharged: by construction, rather than at four
                      call sites someone has to remember.

 A method that needs a verified peer takes IRPublicIdentity. A method that merely needs to look a
 peer up — §11.1's single-live-session rule, keyed on the peer identity pair recovered from
 SESSION_AD — takes IRIdentityKeyPair, because at that point there is no signature to check against.
 */

#pragma mark - IRIdentityKeyPair

/**
 The 64-byte identity pair `IK^s ‖ IK^d`, §5.5's unit of identity.

 -isEqual: and -hash are defined over the 64 raw bytes, so this is a usable NSDictionary key. §11.1
 keys the single-live-session invariant on the peer identity pair and §6.5 recovers that pair from
 SESSION_AD[13..77) or SESSION_AD[77..141) depending on role; both need a hashable value with byte
 equality, and neither has a signature available at the point of comparison.

 NSCopying CONFORMANCE IS LOAD-BEARING, NOT DECORATION. NSDictionary COPIES its keys, so a type used
 as one must conform or the insertion raises "unrecognized selector sent to instance" at runtime —
 there is no compile-time diagnostic, because the parameter is typed id<NSCopying>. The instance is
 immutable, so -copyWithZone: returns self.
 */
@interface IRIdentityKeyPair : NSObject <NSCopying>

/// The X25519 half is validated per §4.4 checks 1–2 by IRX25519Public's own constructor. The
/// Ed25519 half is NOT: §4.4 check 2 is an RFC 7748 u-coordinate rule, and bit 255 of an Ed25519
/// public key is the sign of x (RFC 8032 §5.1.2) and is set in roughly half of all valid keys.
/// §5.3 rule 2 lists only IK^d, SPK and OPK for that reason.
+ (instancetype _Nullable)pairWithSigningKey:(IREd25519Public * _Nonnull)signingKey
                                agreementKey:(IRX25519Public * _Nonnull)agreementKey
                                       error:(NSError * _Nullable * _Nullable)error;

/// `bytes` MUST address at least 64 readable bytes: `IK^s` (32) then `IK^d` (32). There is no length
/// to check here, so a caller reading from the wire or from a state blob MUST bound-check first —
/// use IRByteReader.
+ (instancetype _Nullable)pairFromBytes:(const uint8_t * _Nonnull)bytes
                                  error:(NSError * _Nullable * _Nullable)error;

/// As +pairFromBytes:error:, requiring `data` to be exactly 64 bytes.
+ (instancetype _Nullable)pairFromData:(NSData * _Nonnull)data
                                 error:(NSError * _Nullable * _Nullable)error;

/// `IK^s` — Ed25519, signing ONLY. Never used for DH (§4.1).
@property (nonatomic, strong, readonly) IREd25519Public * _Nonnull signingKey;

/// `IK^d` — X25519, ECDH ONLY. Never used for signing (§4.1).
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull agreementKey;

/// The 64 bytes `IK^s ‖ IK^d`, in that order. This is the value §11.1 indexes on and the slice §6.5
/// embeds in SESSION_AD.
@property (nonatomic, copy, readonly) NSData * _Nonnull rawPair;

/**
 §5.5 — `FP = SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d)`, a 77-byte input and a 32-byte output.

 The public fingerprint / safety number. §5.5 requires applications key identity lookup, contact
 registration, trust-store entries, pinning and any displayed identity on the PAIR, or equivalently
 on this value. An application that keys on IK^s alone is not conformant.
 */
- (IRFingerprint * _Nullable)fingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error;

/// Byte equality over the 64-byte pair.
- (BOOL)isEqualToIdentityKeyPair:(IRIdentityKeyPair * _Nullable)other;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRPublicIdentity

/**
 A peer identity whose `IKB` self-signature HAS BEEN VERIFIED — §5.1, §5.5.

 There is exactly one constructor and it verifies. An instance of this class is therefore a proof
 that `Ed25519-Verify(IK^s, IKBIND_MSG(IK^s, IK^d), IKB)` succeeded, which is what lets the rest of
 the framework state its requirement in the type system: §5.1's "A party MUST verify a peer's IKB
 BEFORE performing any DH with any of that peer's keys" becomes "the DH entry points take an
 IRPublicIdentity".
 */
@interface IRPublicIdentity : NSObject

/// Verifies `binding` over the §5.1 IKBIND_MSG for `keyPair`. Returns nil with ERR_BAD_SIGNATURE on
/// failure, which §5.1 makes a hard abort with no fallback and no "verify later" path.
+ (instancetype _Nullable)identityWithKeyPair:(IRIdentityKeyPair * _Nonnull)keyPair
                                      binding:(IREd25519Signature * _Nonnull)binding
                                     provider:(id<IRCryptoProvider> _Nonnull)provider
                                        error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull keyPair;

/// `IKB` — the §5.1 self-signature. §5.1 requires it be STORED alongside the identity, not
/// recomputed on demand; only the holder of IK^s_priv could recompute it in any case.
@property (nonatomic, strong, readonly) IREd25519Signature * _Nonnull binding;

/// Convenience passthroughs to -keyPair, so a call site that needs one key need not spell the
/// intermediate.
@property (nonatomic, strong, readonly) IREd25519Public * _Nonnull signingKey;
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull agreementKey;

- (IRFingerprint * _Nullable)fingerprintWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error;

/// Compares the identity PAIRS. Two IRPublicIdentity values for the same pair are equal even if
/// their IKB bytes differ, because Ed25519 signing is not contractually deterministic on every
/// platform (§6.2 says so of CryptoKit) — comparing signatures would make identity equality depend
/// on which port produced the record.
- (BOOL)isEqualToPublicIdentity:(IRPublicIdentity * _Nullable)other;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IKBIND_MSG

/**
 §5.1 — the 81-byte identity binding message.

     IKBIND_MSG = "nuntius:IKBIND:v4"   (17)
                ‖ IK^s                   (32, Ed25519 public)
                ‖ IK^d                   (32, X25519 public)
                                         = 81 bytes

 ONE function, shared by the signer (§5.1) and both verifiers (§5.3 rule 3 for the bundle, §10.7
 step 3 for the type 0x02 header), so the two cannot drift apart. The length is asserted against
 kIRLenIKBindMsg before it is returned.
 */
NSData * _Nullable IRIKBindMessage(IRIdentityKeyPair * _Nonnull keyPair,
                                   NSError * _Nullable * _Nullable error);
