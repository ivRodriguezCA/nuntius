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
#import <nuntius/IRPreKeyRecords.h>
#import <nuntius/IRPublicIdentity.h>

/**
 The prekey bundle — SPEC §5.3, §5.4, §10.3.

 What B publishes and A fetches. It has a byte-exact encoding because all four implementations must
 parse each other's bundles:

     off   len   field
     ----  ----  -----------------------------------------------
     0     4     magic = "NTB4"      4E 54 42 34
     4     1     version = 0x04
     5     32    IK^s                Ed25519 identity public
     37    32    IK^d                X25519 identity public
     69    64    IKB                 Ed25519 over IKBIND_MSG (§5.1)
     133   4     spk_id              uint32_be
     137   32    SPK                 X25519 signed prekey public
     169   8     not_before          uint64_be, Unix seconds UTC
     177   8     not_after           uint64_be, Unix seconds UTC
     185   64    SPK_SIG             Ed25519 over SPK_SIGN_MSG (§5.2)
     249   2     opk_count           uint16_be
     ---- fixed prefix ends: 251 bytes ----
     251   36*n  opk entries         +0 opk_id (uint32_be), +4 OPK (X25519 public)

     total length MUST equal exactly 251 + 36 * opk_count, with no trailing bytes.

 THIS IS THE ONLY STRUCTURE IN THE PROTOCOL WHOSE LENGTH RULE IS EXPRESSED IN TERMS OF A VALUE
 CARRIED INSIDE IT, which is why §10.3 gives it an explicit ordered gate with a length floor.
 `opk_count` sits at fixed offset 249, but BOTH structural rules — the `<= 1000` cap and the
 exact-length identity — are predicates over `opk_count`, so neither can be evaluated without first
 loading two bytes at 249. On a 5-byte or 0-byte input that load is out of bounds, and the ports fail
 three different ways: Objective-C reads adjacent heap silently and may then copy `36 * opk_count`
 bytes from offset 251; Swift `Data` subscripting on a slice TRAPS, an uncatchable remote DoS from a
 bundle fetch; the JVM raises an unchecked IndexOutOfBoundsException that escapes the
 ERR_BUNDLE_MALFORMED contract entirely. Three observable behaviours for the same bytes, in the one
 structure §5.4 requires all four implementations to parse for each other.
 */

#pragma mark - IRPreKeyBundleOPKEntry

/// One 36-byte published one-time prekey: `opk_id` and the public half. The responder-local creation
/// timestamp of IROneTimePreKeyRecord is deliberately NOT here — §5.3 forbids widening this entry,
/// because the `251 + 36 * opk_count` rule depends on its width.
@interface IRPreKeyBundleOPKEntry : NSObject

+ (instancetype _Nullable)entryWithOpkId:(uint32_t)opkId
                               publicKey:(IRX25519Public * _Nonnull)publicKey
                                   error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, readonly) uint32_t opkId;
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull publicKey;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRPreKeyBundle

@interface IRPreKeyBundle : NSObject

/**
 The §10.3 ordered gate, then §5.3 rules 2–4. Returns on the FIRST failure.

     §10.3  1  len(bundle) >= 251                  -> ERR_BUNDLE_MALFORMED
            2  bundle[0..4) == "NTB4"              -> ERR_BUNDLE_MALFORMED
            3  bundle[4] == 0x04                   -> ERR_UNSUPPORTED_VERSION
            4  opk_count = be16(bundle[249..251))
                          <= 1000                  -> ERR_BUNDLE_MALFORMED
            5  len == 251 + 36 * opk_count exactly -> ERR_BUNDLE_MALFORMED
     §5.3   2  IK^d, SPK and EVERY OPK pass
               §4.4 checks 1–2                     -> ERR_INVALID_PUBLIC_KEY
            3  Ed25519-Verify(IK^s, IKBIND_MSG,
                              IKB)                 -> ERR_BAD_SIGNATURE
            4  Ed25519-Verify(IK^s, SPK_SIGN_MSG,
                              SPK_SIG)             -> ERR_BAD_SIGNATURE

 STEP 1 IS LOAD-BEARING AND MUST PRECEDE STEP 4 — see the class comment.

 RULE 2 COVERS EVERY OPK AND MUST PRECEDE RULES 3–4. A parser that verifies the two signatures first,
 because they are the cheaper early exit, returns ERR_BAD_SIGNATURE where the specification requires
 ERR_INVALID_PUBLIC_KEY on a bundle that is wrong in both ways.

 RULE 2 DOES NOT COVER `IK^s`. §4.4 checks 1–2 are RFC 7748 u-coordinate rules; bit 255 of an
 Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is set in roughly half of all valid keys.
 §5.3 rule 2 lists only IK^d, SPK and OPK, and this parser follows it exactly.

 READS NO CLOCK. §5.3 rules 5–6 are split into
 -validateValidityWindowAtUnixSeconds:error: so that §15.3's encoding-only `wire.json` bundle
 vectors — which assert the byte layout and the structural gate and supply no `now_s` — can use this
 method directly.

 A wrong total length in EITHER direction is ERR_BUNDLE_MALFORMED, never ERR_TRAILING_BYTES: code
 7105 is for state blobs alone (§10.5, §19.4).
 */
+ (instancetype _Nullable)bundleFromData:(NSData * _Nonnull)data
                                provider:(id<IRCryptoProvider> _Nonnull)provider
                                   error:(NSError * _Nullable * _Nullable)error;

/**
 §5.3 rules 5–6, the two checks that read a clock:

     5  not_before <= now < not_after                        -> ERR_PREKEY_EXPIRED
     6  not_after - not_before <= MAX_SPK_VALIDITY_SECONDS   -> ERR_PREKEY_EXPIRED

 Both are hard aborts. There is no fallback and no "verify later" path.

 `nowS` is Unix seconds UTC and MUST come from the single injectable time source of §15.5 rule 6 —
 in production the system clock, in the conformance suite `inputs.now_s`. Every clock read in this
 protocol routes through that one source; otherwise the frozen vectors of §15.6 are not reproducible,
 and §15.6 step 4 forbids regenerating them.

 RULE 5 IS EVALUATED BEFORE RULE 6, AND THAT ORDER IS WHAT MAKES RULE 6'S SUBTRACTION SAFE:
 `not_before <= now < not_after` implies `not_before < not_after`, so the unsigned difference cannot
 wrap. A port that reorders them, or that evaluates rule 6 on a bundle rule 5 already rejected, is
 subtracting unsigned quantities in the wrong order — silently enormous in C and Go, an exception in
 a checked-arithmetic language.
 */
- (BOOL)validateValidityWindowAtUnixSeconds:(uint64_t)nowS
                                      error:(NSError * _Nullable * _Nullable)error;

/**
 Encodes a bundle from the responder's own records. `opks` MAY be empty.

 THIS IS A CONFORMANT ENCODER: it refuses to emit more than MAX_BUNDLE_OPK_COUNT (1000) entries,
 because a bundle above the cap is one no conformant parser will accept (§10.3 step 4). The §15.4
 negative artifacts that must violate a structural rule — `NEG-BUNDLE-OPKCOUNT`, `NEG-BUNDLE-LEN`,
 `NEG-BUNDLE-MAGIC`, `NEG-BUNDLE-VERSION` — are constructed by byte surgery on a valid bundle rather
 than by weakening this method.
 */
+ (NSData * _Nullable)serializeWithIdentity:(IRPublicIdentity * _Nonnull)identity
                         signedPreKeyRecord:(IRSignedPreKeyRecord * _Nonnull)signedPreKeyRecord
                       oneTimePreKeyRecords:(NSArray<IROneTimePreKeyRecord *> * _Nonnull)opks
                                      error:(NSError * _Nullable * _Nullable)error;

/// The same encoder over PUBLIC components only, so a parsed bundle can be re-emitted without the
/// private halves a record carries. Parse → re-encode → compare is what proves a decoder reads every
/// field at the offset the encoder wrote it to.
+ (NSData * _Nullable)serializeWithIdentity:(IRPublicIdentity * _Nonnull)identity
                                      spkId:(uint32_t)spkId
                               signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                                 notBeforeS:(uint64_t)notBeforeS
                                  notAfterS:(uint64_t)notAfterS
                      signedPreKeySignature:(IREd25519Signature * _Nonnull)signedPreKeySignature
                                 opkEntries:(NSArray<IRPreKeyBundleOPKEntry *> * _Nonnull)opkEntries
                                      error:(NSError * _Nullable * _Nullable)error;

/// Re-emits this bundle from its parsed components. Byte-identical to -encodedData for any bundle
/// this parser accepted.
- (NSData * _Nullable)serializedData:(NSError * _Nullable * _Nullable)error;

/// The peer identity, with `IKB` ALREADY VERIFIED — holding this value is proof that §5.3 rule 3
/// passed.
@property (nonatomic, strong, readonly) IRPublicIdentity * _Nonnull identity;

@property (nonatomic, readonly) uint32_t spkId;
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull signedPreKey;
@property (nonatomic, readonly) uint64_t notBeforeS;
@property (nonatomic, readonly) uint64_t notAfterS;
@property (nonatomic, strong, readonly) IREd25519Signature * _Nonnull signedPreKeySignature;

/// Every published entry, in wire order. A PUBLISHED bundle MAY carry many.
@property (nonatomic, copy, readonly) NSArray<IRPreKeyBundleOPKEntry *> * _Nonnull opkEntries;

/// The exact bytes this bundle was parsed from.
@property (nonatomic, copy, readonly) NSData * _Nonnull encodedData;

/**
 §5.4 — the ONLY entry a single handshake may use, or nil when the bundle carries none.

 "A bundle fetched for a single handshake MUST carry `opk_count` of 0 or 1; a fetching client that
 receives more MUST use only the first entry, and MUST NOT treat additional entries as usable." The
 distribution server is responsible for handing out each OPK at most once; a server that reissues one
 degrades that handshake to the 3-DH case in effect and MUST be treated as a bug.

 nil here is NOT an error — `opk_flag == 0x00` is a legitimate, weaker mode (§6.6), with the replay
 caveat of §17.3.
 */
- (IRPreKeyBundleOPKEntry * _Nullable)firstUsableOPKEntry;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
