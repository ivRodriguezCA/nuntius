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
#import <nuntius/IRIdentity.h>
#import <nuntius/IRKeyPairs.h>
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRPreKeyBundle.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>
#import <nuntius/IRSecretBytes.h>

/* Quoted, not <nuntius/...>: IRSessionAD is a PROJECT-visibility header and so is absent from the
   built framework's Headers/ and from its module map. It resolves through the target's generated
   header map, for this target and for nuntiusTests alike. */
#import "IRSessionAD.h"

/**
 X3DH key agreement — SPEC §6.1–§6.6, §5.3, §10.7 steps 8–10, §11.1.

 WHAT THIS REPLACES. v3's IRTripleDHService concatenated dh1‖dh2‖dh3[‖dh4] into a 96–128 byte buffer
 and handed it to `crypto_kdf_derive_from_key`, whose key parameter is `const unsigned char
 k[crypto_kdf_KEYBYTES]` — exactly 32 bytes. Only DH1 was ever read. DH1 is
 `X25519(IK_A^d, SPK_B)`, both long-lived, so the handshake had NO forward secrecy and the one-time
 prekey contributed nothing at all. Both parties still agreed, so every v3 test passed. HKDF-Extract's
 `(ikm, ikm_len)` signature cannot express that mistake — the length travels with the pointer — which
 is why §6.4 calls this fix structural rather than a corrected length.

 THE TWO DIRECTIONS SHARE ONE TAIL. §6.1 specifies the responder's DH set as "the mirror image, in
 the identical order", so DH1–DH4 hold the same four values on both sides. Everything downstream of
 them — TRANSCRIPT, TH, IKM, SK, SESSION_AD — is therefore byte-identical by construction here, not
 by two implementations agreeing. The two entry points differ only in which private and public
 halves feed the four scalar multiplications.

 WHAT THIS CLASS DOES NOT DO, AND MUST NOT.

   - It does NOT verify IKB. It cannot be reached without a verified one: both entry points take the
     peer as an IRPublicIdentity (directly, or as `bundle.identity`), and that type's only
     constructor verifies the binding. §10.7 step 3 requires the verification "before any DH", and
     making the verified type the only admissible parameter is what turns that ordering requirement
     into something a caller cannot get wrong. §5.5's rationale is the whole reason: an attacker
     presenting a victim's genuine IK^s beside an attacker-controlled IK^d would otherwise complete a
     cryptographically sound session and be attributed to the victim.
   - It does NOT resolve `spk_id` or `opk_id`, check tombstones, or consume a one-time prekey. Those
     are §10.7 steps 4, 5 and 14, and step 14 is ordered AFTER the AEAD succeeds — a fact no code at
     this layer can observe.
   - It does NOT touch the prekey store's key material. `signedPreKeyPair` and `oneTimePreKeyPair`
     are READ and never retained, copied into ratchet state, or zeroized. §5.3 gives `SPK_B_priv`
     exclusively to the prekey store, §7.5 requires the responder's ratchet to hold its own COPY,
     and §7.5 spells out what wiping the original costs: every concurrent and future handshake
     against that `spk_id` breaks, silently, and B reports ERR_AEAD_AUTH_FAILED — the code §1.2
     defines as "active man-in-the-middle". B misdiagnoses its own key destruction as an attack.

 NO 3-DH FALLBACK EXISTS. §6.6 rule 2: a one-time prekey that does not resolve is
 ERR_UNKNOWN_PREKEY_ID, and "rejecting rather than falling back is what converts OPK consumption
 into replay protection". Here that is structural — an IROPKFlagPresent handshake with no key pair
 is an error, never a silent 128-byte IKM.
 */

#pragma mark - handshake_id

/**
 §11.1 — `handshake_id = IK_A^d (32) ‖ EK_A (32)`, 64 bytes.

 Both components are public and both travel in every type `0x02` header, which is what makes a type
 `0x02` message self-routing (§11.2). A type `0x01` message carries neither and is NOT self-routing;
 §11.5 specifies how it is delivered instead.
 */
NSData * _Nullable IRHandshakeIdentifier(IRX25519Public * _Nonnull initiatorAgreementKey,
                                         IRX25519Public * _Nonnull ephemeralPublic,
                                         NSError * _Nullable * _Nullable error);

#pragma mark - IRSessionPrologue

/**
 §12.1's 41-byte prologue block — the fields an initiator must re-emit unchanged on every type
 `0x02` message until it has decrypted one from B (§11.3).

     +0   32  EK_A_pub     public half only; the private half is zeroized after SK
     +32  4   spk_id       uint32_be
     +36  1   opk_flag
     +37  4   opk_id       uint32_be

 §11.3: A MUST reuse the IDENTICAL prologue values across all its type `0x02` messages; only
 `DHs_pub`, `N`, the nonce and the ciphertext vary. The block is 41 bytes and not larger because the
 remaining header fields are not session state: `IK_A^s` and `IK_A^d` are recovered from the stored
 SESSION_AD at §6.5's offsets, and `IKB_A` is read from the long-lived identity record — it is a
 per-identity value and MUST NOT be re-signed at send time, since Ed25519 signing is not
 contractually deterministic on all four platforms and nothing in the receive path compares `IKB_A`
 across messages, so a re-signing port would diverge and never be caught.
 */
@interface IRSessionPrologue : NSObject

+ (instancetype _Nullable)prologueWithEphemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                                spkId:(uint32_t)spkId
                                              opkFlag:(IROPKFlag)opkFlag
                                                opkId:(uint32_t)opkId
                                                error:(NSError * _Nullable * _Nullable)error;

/// Rehydrates from §12.1 offset 427. Every failure is IRErrorStateCorrupt (§12.2).
+ (instancetype _Nullable)prologueFromStoredBytes:(NSData * _Nonnull)bytes
                                             error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull ephemeralPublic;
@property (nonatomic, readonly) uint32_t spkId;
@property (nonatomic, readonly) IROPKFlag opkFlag;
@property (nonatomic, readonly) uint32_t opkId;

/// The 41 bytes as §12.1 stores them.
- (NSData * _Nullable)serializedBytes:(NSError * _Nullable * _Nullable)error;

- (BOOL)isEqualToSessionPrologue:(IRSessionPrologue * _Nullable)other;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRX3DHResult

/// Everything a completed X3DH hands to the ratchet (§7.5) and to the session record (§12.1).
@interface IRX3DHResult : NSObject

/// §6.3's SK. Becomes the ratchet's initial RK, and §13.3 requires it be zeroized "immediately
/// after ratchet initialization" — call -zeroize at that point.
@property (nonatomic, strong, readonly) IRRootKey * _Nonnull sharedKey;

/// §6.5, in role order, computed once and never recomputed.
@property (nonatomic, strong, readonly) IRSessionAD * _Nonnull sessionAD;

/// §11.1 — 64 bytes.
@property (nonatomic, copy, readonly) NSData * _Nonnull handshakeId;

/// §12.1's role byte for the session this result seeds.
@property (nonatomic, readonly) IRSessionRole role;

/// §11.3 — present for an initiator, always nil for a responder. A responder never sends type
/// `0x02` and so has no prologue to re-emit.
@property (nonatomic, strong, readonly) IRSessionPrologue * _Nullable prologue;

/// §13.3 — wipes SK and any retained IKM. Idempotent.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

/**
 §15.5 runner rule 2 makes TRANSCRIPT, TH, IKM and the X3DH info REQUIRED intermediates of the
 `X3DH-OPK` and `X3DH-NOOPK` vectors, so they must be observable somewhere.

 The three public ones are always present: every byte of a transcript, of its hash and of the HKDF
 info is a public key, a key id or a fixed label, so retaining them costs no secrecy.

 `ikm` IS SECRET AND IS THEREFORE NIL UNLESS EXPLICITLY REQUESTED. §13.3 requires
 `F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]` be zeroized immediately after SK is derived, which is flatly
 incompatible with holding it for a caller to read. `retainIKM:YES` suppresses that one wipe and
 exists for the §15.6 vector generator alone; production call sites pass NO, and the value is
 returned in an IRSecretBytes even then so that the exception is bounded to WHEN the wipe happens
 and never to WHETHER the container can perform one.
 */
@interface IRX3DHResult (Intermediates)

@property (nonatomic, copy, readonly) NSData * _Nonnull transcript;      ///< §6.2 — 259 bytes
@property (nonatomic, copy, readonly) NSData * _Nonnull transcriptHash;  ///< §6.2 — 32 bytes
@property (nonatomic, copy, readonly) NSData * _Nonnull x3dhInfo;        ///< §6.3 — 47 bytes

/// §6.3 — 128 bytes without an OPK, 160 with. Nil unless `retainIKM:YES` was passed.
@property (nonatomic, strong, readonly) IRSecretBytes * _Nullable ikm;

@end

#pragma mark - IRX3DH

@interface IRX3DH : NSObject

/**
 The initiator's half of §6.1–§6.5.

     DH1 = X25519(IK_A^d_priv, SPK_B)      both long-lived-ish: authenticates A to B
     DH2 = X25519(EK_A_priv,   IK_B^d)     authenticates B to A
     DH3 = X25519(EK_A_priv,   SPK_B)      forward secrecy
     DH4 = X25519(EK_A_priv,   OPK_B)      only when a one-time prekey is used

 `bundle` MUST already have passed §10.3 and §5.3 rules 1–4, which +[IRPreKeyBundle
 bundleFromData:provider:error:] performs and which holding this object is proof of. THIS METHOD
 RUNS §5.3 RULES 5 AND 6 ITSELF, from `nowUnixSeconds`, because §5.3 places all six "before
 performing any Diffie-Hellman with a fetched bundle" and the parser deliberately reads no clock.
 `nowUnixSeconds` is Unix seconds UTC and MUST come from the single injectable time source of §15.5
 rule 6 — the system clock in production, `inputs.now_s` in the conformance suite. §15.3 requires
 `X3DH-OPK` and `X3DH-NOOPK` to supply one, or those two `expect: "ok"` vectors begin returning
 ERR_PREKEY_EXPIRED within 90 days of the freeze and §15.6 forbids regenerating them.

 THE ONE-TIME PREKEY IS CHOSEN HERE, from -[IRPreKeyBundle firstUsableOPKEntry]: §5.4 permits a
 published bundle to carry many but requires a client fetching for one handshake to use only the
 first. v3's `ephemeralKeyPairs.firstObject` (IRTripleDHService.m:98) has no counterpart in v4 — in
 v3 the "one-time" key was neither one-time nor selected, so every session with a given peer reused
 the same ephemeral, the exact property OPKs exist to prevent. A bundle with no OPK is not an error:
 `opk_flag == 0x00` is a legitimate, weaker mode with the replay caveat of §17.3.

 THIS METHOD CONSUMES `ephemeralKeyPair` AND ZEROIZES ITS PRIVATE HALF BEFORE RETURNING — on the
 success path and on EVERY failure path once the arguments have validated, including a bundle that
 fails rules 5–6. §13.3 schedules that wipe for "immediately after SK is derived" and §6.1 says
 EK_A "is used for nothing else", so there is no path on which a caller may reuse it; wiping on
 failure too is what removes the tempting retry-with-the-same-ephemeral. The public half survives
 untouched in `result.prologue.ephemeralPublic`, which is all §11.3 needs to re-emit the prologue.
 Generate it with
 -[IRCryptoProvider generateX25519KeyPairGuarded:NO error:] — a handshake ephemeral is not one of
 §13.3's long-lived privates.
 */
+ (IRX3DHResult * _Nullable)initiatorResultWithIdentity:(IRIdentity * _Nonnull)identity
                                                 bundle:(IRPreKeyBundle * _Nonnull)bundle
                                       ephemeralKeyPair:(IRX25519KeyPair * _Nonnull)ephemeralKeyPair
                                         nowUnixSeconds:(uint64_t)nowUnixSeconds
                                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                              retainIKM:(BOOL)retainIKM
                                                  error:(NSError * _Nullable * _Nullable)error;

/**
 The responder's half — §10.7 steps 8, 9 and 10, and nothing else.

     DH1 = X25519(SPK_B_priv,  IK_A^d)
     DH2 = X25519(IK_B^d_priv, EK_A)
     DH3 = X25519(SPK_B_priv,  EK_A)
     DH4 = X25519(OPK_B_priv,  EK_A)

 The caller has already performed §10.2's gate and §10.7 steps 1–7 in order: the tombstone check
 (step 4), `spk_id` resolution (step 5), the anti-reflection comparison against the resolved signed
 prekey public (step 6), and `opk_id` resolution (step 7). Step 3 — verify `IKB_A` before any DH —
 is discharged by `initiatorIdentity` being an IRPublicIdentity, which cannot exist without it.

 `oneTimePreKeyPair` MUST be non-nil exactly when `opkFlag` is IROPKFlagPresent. Nil with the flag
 set is IRErrorUnknownPreKeyId and never a silent fall back to the three-DH form (§6.6 rule 2);
 non-nil with the flag clear, or a non-zero `opkId` with the flag clear, is IRErrorMalformedHeader —
 the code §10.2 check 7 assigns the wire-side form of the same inconsistency.

 NEITHER PREKEY PAIR IS RETAINED, COPIED OR ZEROIZED. See the class comment: §7.5's session-owned
 copy is IRRatchet's to take, and §6.6 step 4's zeroize-then-durably-delete of the one-time prekey
 happens only on the AEAD-success path, which is §10.7 step 14.
 */
+ (IRX3DHResult * _Nullable)responderResultWithIdentity:(IRIdentity * _Nonnull)identity
                                      initiatorIdentity:(IRPublicIdentity * _Nonnull)initiatorIdentity
                                        ephemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                       signedPreKeyPair:(IRX25519KeyPair * _Nonnull)signedPreKeyPair
                                                  spkId:(uint32_t)spkId
                                                opkFlag:(IROPKFlag)opkFlag
                                                  opkId:(uint32_t)opkId
                                      oneTimePreKeyPair:(IRX25519KeyPair * _Nullable)oneTimePreKeyPair
                                               provider:(id<IRCryptoProvider> _Nonnull)provider
                                              retainIKM:(BOOL)retainIKM
                                                  error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
