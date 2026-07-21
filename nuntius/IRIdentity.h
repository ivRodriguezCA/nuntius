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
#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRPublicIdentity.h>

/**
 The LOCAL identity — SPEC §4.1, §5.1, §5.5, §11.3, §13.3.

 Two independently generated key pairs, per §4.1:

     IK^s   Ed25519, 32-byte SEED private   signing ONLY, never used for DH
     IK^d   X25519,  32-byte private        ECDH ONLY, never used for signing

 The Ed25519→X25519 conversion trick of v3 is GONE. Three reasons, any one decisive (§4.1):
 crypto_sign_ed25519_pk_to_curve25519 has no JDK equivalent at any version and CryptoKit models the
 two key kinds as deliberately unbridged types, so keeping the trick would put hand-rolled curve
 arithmetic in two of four trusted computing bases; v3 discarded the conversion return values,
 leaving stack buffers UNINITIALIZED and feeding them to ECDH; and using one key pair for both a
 signature scheme and a key-agreement scheme is a documented cross-protocol hazard.

 The split's cost is a new obligation — something must attest that a given IK^s and IK^d belong to
 the same identity — and `binding` discharges it. See IRPublicIdentity.h.

 BOTH PRIVATE HALVES ARE ALLOCATED GUARDED (sodium_malloc: guard-paged, canaried, mlock'd). §13.3
 holds them for the identity's lifetime, which is precisely the case where the page-granular cost of
 guarded allocation is worth paying — unlike the skipped-key store, where MAX_SKIPPED_STORED is 2000
 and iOS arm64 pages are 16 KiB.
 */
@interface IRIdentity : NSObject

/**
 A fresh identity: two key pairs, then `IKB` over §5.1's IKBIND_MSG.

 The freshly produced signature is VERIFIED before this method returns. That costs one Ed25519
 verification once per identity and buys a self-test at the exact place §3.4's trap bites: a port
 wired to libsodium's multi-part crypto_sign_init/_update/_final_create is signing Ed25519**ph**
 (prehashed), and fails here at generation rather than months later against a peer, where the
 failure would present as ERR_BAD_SIGNATURE — that is, disguised as an active MITM (§1.2).
 */
+ (instancetype _Nullable)generateWithProvider:(id<IRCryptoProvider> _Nonnull)provider
                                         error:(NSError * _Nullable * _Nullable)error;

/// +generateWithProvider:error: against a production libsodium provider (system clock,
/// randombytes_buf). The only form a production caller needs.
+ (instancetype _Nullable)generate:(NSError * _Nullable * _Nullable)error;

/**
 Rehydrates an identity from storage. `binding` is the STORED `IKB` (§5.1: "It MUST be stored, not
 recomputed on demand").

 It is verified here, which is §5.5's "after state restore" ingest point. Re-signing instead of
 verifying would defeat the purpose entirely — that is v3's defect at IRTripleDHService.m:66-68,
 where a peer's signature was overwritten with a locally manufactured one that later code then
 found "valid", destroying the evidence rather than merely skipping the check.
 */
+ (instancetype _Nullable)identityWithSigningKeyPair:(IREd25519KeyPair * _Nonnull)signingKeyPair
                                    agreementKeyPair:(IRX25519KeyPair * _Nonnull)agreementKeyPair
                                             binding:(IREd25519Signature * _Nonnull)binding
                                            provider:(id<IRCryptoProvider> _Nonnull)provider
                                               error:(NSError * _Nullable * _Nullable)error;

/// `IK^s` — the private half is the 32-byte RFC 8032 seed (§4.2), never libsodium's 64-byte
/// expanded `sk`.
@property (nonatomic, strong, readonly) IREd25519KeyPair * _Nonnull signingKeyPair;

/// `IK^d` — the private half is stored clamped (§4.2).
@property (nonatomic, strong, readonly) IRX25519KeyPair * _Nonnull agreementKeyPair;

/**
 `IKB` — computed ONCE, at generation, and immutable thereafter.

 §5.1 requires it be stored rather than recomputed, and §11.3 requires it not be re-signed at send
 time: the type 0x02 header re-emits these exact bytes on every prekey message. There is
 deliberately no -regenerateBinding.
 */
@property (nonatomic, strong, readonly) IREd25519Signature * _Nonnull binding;

/// This identity as a peer would hold it. Non-null: the binding was verified at construction, so
/// the verifying constructor of IRPublicIdentity cannot fail here.
@property (nonatomic, strong, readonly) IRPublicIdentity * _Nonnull publicIdentity;

/// The 64-byte `IK^s ‖ IK^d` index key of §11.1 / §6.5.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nonnull identityKeyPair;

/// §5.5 — `SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d)`.
- (IRFingerprint * _Nullable)fingerprint:(NSError * _Nullable * _Nullable)error;

/**
 Pure Ed25519 detached signing under `IK^s_priv` (§3.4).

 The only two things this protocol signs are IKBIND_MSG (§5.1) and SPK_SIGN_MSG (§5.2). One-time
 prekeys are NOT individually signed — §5.2 is explicit that implementations MUST NOT invent a
 per-OPK signature, because doing so would diverge from every other port; OPKs are authenticated
 transitively, since a wrong OPK simply yields a different SK and an AEAD failure.
 */
- (IREd25519Signature * _Nullable)signData:(NSData * _Nonnull)data
                                     error:(NSError * _Nullable * _Nullable)error;

/**
 Zeroizes `IK^s_priv` and `IK^d_priv` in place.

 §13.3 schedules this for identity deletion or application data erasure ONLY — otherwise both are
 held for the identity's lifetime. Zeroizing them invalidates every future handshake for this
 identity; it does not invalidate live sessions, whose ratchet state no longer depends on the
 identity privates.
 */
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
