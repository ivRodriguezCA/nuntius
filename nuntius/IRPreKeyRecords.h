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
#import <nuntius/IRPublicIdentity.h>

/**
 The responder's prekey records — SPEC §5.2, §5.3, §13.3.

 These are the RESPONDER-SIDE objects, holding private key material. What the initiator sees is the
 published subset in IRPreKeyBundle: an OPK record's local creation timestamp, in particular, is
 responder-local and MUST NOT appear in a bundle (§5.3).

 Both private halves are allocated GUARDED. §13.3 gives SPK and OPK privates lifetimes measured in
 days-to-months, and §5.6 makes their at-rest sealing normative for a blunt reason: a device backup
 image that yields SPK_B_priv and the unconsumed OPK privates collapses the forward secrecy §1.2
 claims, because an adversary who images at t0 and records A's handshake at t1 > t0 computes DH1,
 DH2 and DH3 directly and needs only DH4 — whose private half is sitting in that same store.
 */

#pragma mark - SPK_SIGN_MSG

/**
 §5.2 — the 130-byte signed-prekey signing message.

     SPK_SIGN_MSG = "nuntius:SPK:v4"       (14)
                  ‖ IK^s                    (32)
                  ‖ IK^d                    (32)
                  ‖ uint32_be(spk_id)       (4)
                  ‖ SPK                     (32, X25519 public)
                  ‖ uint64_be(not_before)   (8, Unix seconds UTC)
                  ‖ uint64_be(not_after)    (8, Unix seconds UTC)
                                            = 130 bytes

 ONE function, shared by the signer (§5.2) and the verifier (§5.3 rule 4), so the two cannot drift.

 Binding `spk_id` prevents transplanting a signature onto a different prekey slot. Binding BOTH
 identity keys ties the prekey to the whole identity rather than to its signing half alone. Both
 timestamps sit inside the signature, so an intermediary cannot extend the validity window.
 */
NSData * _Nullable IRSPKSignMessage(IRIdentityKeyPair * _Nonnull identity,
                                    uint32_t spkId,
                                    IRX25519Public * _Nonnull signedPreKey,
                                    uint64_t notBeforeS,
                                    uint64_t notAfterS,
                                    NSError * _Nullable * _Nullable error);

#pragma mark - IRSignedPreKeyRecord

/**
 A signed prekey and its private half — §5.2, §5.3.

 OWNERSHIP. §5.3: "SPK_B_priv is owned EXCLUSIVELY by the prekey store and its lifetime is governed
 by this paragraph alone. No ratchet operation may shorten it." The responder's initial ratchet DHs
 is a COPY of this pair (§7.5) taken with -[IRX25519KeyPair deepCopy], and §7.4 step 4 zeroizes only
 that copy. A caller that aliases `keyPair` into ratchet state destroys, on the first routine ratchet
 step, a key that messages still in flight need — and `NEG-SPK-SURVIVES-RATCHET` (§15.4) is the only
 vector in the whole suite that catches it.
 */
@interface IRSignedPreKeyRecord : NSObject

/**
 Generates a fresh X25519 pair and signs §5.2's SPK_SIGN_MSG with `identity`.

 THE VALIDITY WINDOW IS NOT VALIDATED HERE, DELIBERATELY. §5.3 places all six bundle rules on the
 INITIATOR's ingest path; rules 5 and 6 (`not_before ≤ now < not_after` and
 `not_after - not_before ≤ MAX_SPK_VALIDITY_SECONDS`) are parse-side checks with parse-side error
 codes. Enforcing rule 6 at generation would also make `NEG-SPK-WINDOW-TOO-LONG` (§15.4)
 unconstructible: that vector requires a bundle whose window exceeds the cap, and the generator has
 to be able to produce one.
 */
+ (instancetype _Nullable)generateWithIdentity:(IRIdentity * _Nonnull)identity
                                         spkId:(uint32_t)spkId
                                    notBeforeS:(uint64_t)notBeforeS
                                     notAfterS:(uint64_t)notAfterS
                                      provider:(id<IRCryptoProvider> _Nonnull)provider
                                         error:(NSError * _Nullable * _Nullable)error;

/// Rehydrates a record from the responder's sealed store (§5.6). The signature is stored, not
/// recomputed — the same rule §5.1 states for IKB, and for the same reason.
+ (instancetype _Nullable)recordWithSpkId:(uint32_t)spkId
                                  keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                               notBeforeS:(uint64_t)notBeforeS
                                notAfterS:(uint64_t)notAfterS
                                signature:(IREd25519Signature * _Nonnull)signature
                                    error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, readonly) uint32_t spkId;

/// The store owns this. Callers heading for ratchet state MUST -deepCopy it (§7.5, §19.1).
@property (nonatomic, strong, readonly) IRX25519KeyPair * _Nonnull keyPair;

@property (nonatomic, readonly) uint64_t notBeforeS;
@property (nonatomic, readonly) uint64_t notAfterS;

/// `SPK_SIG` — Ed25519 over §5.2's SPK_SIGN_MSG, under `IK^s_priv`.
@property (nonatomic, strong, readonly) IREd25519Signature * _Nonnull signature;

/// YES once `not_after` has passed. §13.3 makes that the LATEST moment the private half may be
/// retained, whether or not the key is still the current one.
- (BOOL)isExpiredAtUnixSeconds:(uint64_t)nowS;

/// Zeroizes the private half in place (§13.3's `SPK` private row). Called by the prekey store when
/// §5.3 retention ends; never by a ratchet operation.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IROneTimePreKeyRecord

/**
 A one-time prekey and its private half — §5.2, §5.3, §6.6.

 One-time prekeys are NOT individually signed. §5.2: implementations MUST NOT invent a per-OPK
 signature, because doing so would diverge from every other port. They are authenticated
 transitively — a wrong OPK simply yields a different SK and an AEAD failure.
 */
@interface IROneTimePreKeyRecord : NSObject

+ (instancetype _Nullable)generateWithOpkId:(uint32_t)opkId
                          createdAtUnixSecs:(uint64_t)createdAtUnixSecs
                                   provider:(id<IRCryptoProvider> _Nonnull)provider
                                      error:(NSError * _Nullable * _Nullable)error;

/// Rehydrates a record from the responder's sealed store (§5.6).
+ (instancetype _Nullable)recordWithOpkId:(uint32_t)opkId
                                  keyPair:(IRX25519KeyPair * _Nonnull)keyPair
                        createdAtUnixSecs:(uint64_t)createdAtUnixSecs
                                    error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, readonly) uint32_t opkId;
@property (nonatomic, strong, readonly) IRX25519KeyPair * _Nonnull keyPair;

/**
 §5.3 — RESPONDER-LOCAL, and it MUST NOT be added to the §5.4 bundle OPK entry.

 That entry is 36 bytes and the total-length rule `251 + 36 * opk_count` depends on it, so widening
 it would break every bundle parser in every port. Published OPK expiry, if it is ever wanted,
 belongs in a batched format revision.
 */
@property (nonatomic, readonly) uint64_t createdAtUnixSecs;

/**
 YES once `OPK_MAX_AGE_S` (§18: 7776000, 90 days) has elapsed since creation.

 §5.3 requires an expired, unconsumed OPK be deleted and zeroized, and an `opk_id` naming a deleted
 entry to resolve to ERR_UNKNOWN_PREKEY_ID like any other unknown id. This bounds §1.2's
 "identity AND signed prekey compromised" row: at that point DH4 is the only remaining
 forward-secrecy term, and an OPK private no initiator ever selects would otherwise stay recoverable
 from a device image forever.

 Computed as `nowS - createdAtUnixSecs >= OPK_MAX_AGE_S`, with a clock earlier than creation
 treated as not expired rather than as an enormous positive age.
 */
- (BOOL)isExpiredAtUnixSeconds:(uint64_t)nowS;

/// Zeroizes the private half in place. §6.6 step 4 requires this happen BEFORE the map entry is
/// unlinked: an unlink alone releases the reference and leaves the scalar resident in the heap.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
