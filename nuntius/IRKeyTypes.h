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
#import <nuntius/IRErrors.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRSecretBytes.h>

/**
 The REQUIRED nominal key types — SPEC §4.2, §4.3, §4.4.

 §4.3: "Every implementation MUST represent each key kind as a distinct type with a
 compile-time-fixed length whose constructor rejects a wrong-length input. No API in the crypto
 layer may accept or return a bare NSData / byte[] / Data for key material."

 This is not style. Defect 1 was a length mismatch no type system was asked to catch, and defect 2
 was an ignored argument. A RootKey parameter that cannot be omitted and cannot be the wrong length
 turns both into construction-time failures. The mistake these types exist to prevent — passing a
 ChainKey where a RootKey belongs — is the one that produces a working, self-consistent,
 INCOMPATIBLE port.

 Ten types are required by §4.3; IRFingerprint is added for §5.5.

     NON-SECRET, NSData-backed        SECRET, IRSecretBytes-backed
     IREd25519Public       32         IREd25519Private     32  (the RFC 8032 SEED)
     IREd25519Signature    64         IRX25519Private      32  (stored CLAMPED)
     IRX25519Public        32         IRRootKey            32
     IRNonce               12         IRChainKey           32
     IRFingerprint         32         IRMessageKey         32
                                      IRMessageEncKey      32

 WRONG-LENGTH ERROR CODES. Each type names the code its constructor reports, chosen for the place
 that type is actually parsed from. THE ORDERED GATES OF §10 REMAIN THE SOLE AUTHORITY for the code
 a parse returns: a gate needing a different code for the same condition performs its own explicit
 check first and never relies on a constructor's nil.

 EQUALITY compares raw bytes AND the class. An IRRootKey and an IRChainKey holding identical bytes
 are not equal, and — per §4.3 — the header ratchet key is compared as raw 32 bytes and nothing
 else. v3's IRCurve25519KeyPair -isEqual: returned NO whenever one side had a private key and the
 other did not, which is why its header-key comparison behaved according to how a field had been
 populated rather than according to the key bytes.
 */

#pragma mark - Fixed-length non-secret values

/**
 Base class for the fixed-width, NON-SECRET nominal types.

 Subclasses supply +fixedLength and +lengthErrorCode, and may override +validateBytes:error: to add
 an encoding rule. Everything else is inherited, so a new nominal type cannot be introduced with
 its length check accidentally omitted.
 */
@interface IRFixedLengthData : NSObject

/// The class invariant width, in bytes.
+ (NSUInteger)fixedLength;

/// The code reported when a construction is offered the wrong number of bytes, or when
/// +validateBytes:error: rejects the encoding.
+ (IRErrorCode)lengthErrorCode;

/// Encoding rule applied after the length check. The base implementation accepts everything;
/// IRX25519Public overrides it with §4.4 check 2.
+ (BOOL)validateBytes:(const uint8_t * _Nonnull)bytes
                error:(NSError * _Nullable * _Nullable)error;

+ (instancetype _Nullable)fromData:(NSData * _Nonnull)data
                             error:(NSError * _Nullable * _Nullable)error;

/// `bytes` MUST address at least +fixedLength readable bytes. There is no length to check here, so
/// callers reading from the wire MUST bound-check first — use IRByteReader.
+ (instancetype _Nullable)fromBytes:(const uint8_t * _Nonnull)bytes
                              error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, copy, readonly) NSData * _Nonnull data;

/// Always equal to +fixedLength. Present so a caller need not know which class it holds.
@property (nonatomic, readonly) NSUInteger length;

- (const uint8_t * _Nonnull)constBytes;

/// Byte equality that also requires an identical class.
- (BOOL)isEqualToFixedLengthData:(IRFixedLengthData * _Nullable)other;

/// Lowercase hex, for fingerprints and for diagnostics. Never call this on secret material — these
/// types are non-secret by construction, which is why it lives here and not on IRSecretBytes.
- (NSString * _Nonnull)hexString;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - Non-secret nominal types

/// §4.2 — the raw 32-byte RFC 8032 §5.1.2 encoding. Wrong length reports ERR_INVALID_PUBLIC_KEY.
@interface IREd25519Public : IRFixedLengthData
- (BOOL)isEqualToEd25519Public:(IREd25519Public * _Nullable)other;
@end

/// §4.2 — the raw 64-byte RFC 8032 §5.1.6 encoding. Wrong length reports ERR_BAD_SIGNATURE: a
/// signature of the wrong width can never verify, and every wire source of one sits at a fixed
/// offset where the gate has already bounded the read.
@interface IREd25519Signature : IRFixedLengthData
- (BOOL)isEqualToEd25519Signature:(IREd25519Signature * _Nullable)other;
@end

/**
 §4.2 — the raw 32-byte little-endian u-coordinate of RFC 7748.

 The constructor performs §4.4 checks 1 AND 2, so the high-bit check cannot be forgotten at a call
 site. Check 2 exists because RFC 7748 has X25519 ignore bit 255 of the u-coordinate and every
 implementation masks it internally: without the check a single ratchet key would have TWO distinct
 wire encodings producing identical DH output, breaking the injectivity that the transcript hash,
 SESSION_AD and the skipped-key map key all depend on. An attacker could flip that bit to mint a
 second distinct map key, or a second distinct DHr for the same actual key, forcing spurious DH
 ratchets and state growth. Canonical encodings never set the bit, so rejecting is free.

 Wrong length or high bit set reports ERR_INVALID_PUBLIC_KEY.
 */
@interface IRX25519Public : IRFixedLengthData

/// §4.4 checks 1–2 as a pure predicate that assigns no error, for a gate that must impose its own
/// code.
+ (BOOL)dataIsValidEncoding:(NSData * _Nullable)data;

/// §4.4 check 2 alone, over exactly 32 readable bytes.
+ (BOOL)highBitIsClear:(const uint8_t * _Nonnull)bytes;

/// §4.3 — raw 32 bytes and nothing else.
- (BOOL)isEqualToX25519Public:(IRX25519Public * _Nullable)other;

@end

/// §8.2 — the 12-byte IETF ChaCha20-Poly1305 nonce, random per message and carried on the wire
/// (§8.3). Wrong length reports ERR_MALFORMED_HEADER, the code for a header field outside its
/// permitted domain.
@interface IRNonce : IRFixedLengthData
- (BOOL)isEqualToNonce:(IRNonce * _Nullable)other;
@end

/// §5.5 — the 32-byte public fingerprint / safety number,
/// SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d). Derived, never parsed from a peer; a wrong length is an
/// internal invariant violation and reports ERR_STATE_CORRUPT.
@interface IRFingerprint : IRFixedLengthData
- (BOOL)isEqualToFingerprint:(IRFingerprint * _Nullable)other;
@end

#pragma mark - Secret nominal types

/**
 §4.2 — the raw 32-byte RFC 8032 SEED.

 NEVER libsodium's 64-byte expanded `sk` (= seed ‖ pk), which §4.2 forbids from appearing in any
 nominal type, vector file, serialized structure, or API boundary. A libsodium port MUST expand the
 seed with crypto_sign_seed_keypair immediately before crypto_sign_detached and zeroize the
 expansion immediately after (§3.4) — passing a 32-byte seed straight to crypto_sign_detached is a
 32-byte OUT-OF-BOUNDS READ that surfaces disguised as ERR_BAD_SIGNATURE, i.e. as an attack.

 Ed25519 seeds are stored VERBATIM: Ed25519 clamps the SHA-512 hash of the seed, not the seed
 itself, so §4.2's clamping rule does not apply here.
 */
@interface IREd25519Private : IRFixedLengthSecret
@end

/**
 §4.2 — the 32-byte X25519 scalar, stored in CLAMPED form:
 `k[0] &= 0xF8; k[31] &= 0x7F; k[31] |= 0x40`.

 The clamp is applied UNCONDITIONALLY at construction, which turns §4.2's "normalize at generation"
 into "normalize at construction" and covers generation, state load and vector input in one place.
 Clamping is idempotent and RFC 7748 §5 clamps internally, so X25519(s, P) == X25519(clamp(s), P)
 for every s: this normalizes the stored representation and changes NO cryptographic output. It
 matters because libsodium and CryptoKit store the raw CSPRNG bytes while BouncyCastle clamps at
 generation, so without the rule two ports write different bytes at state-blob offsets 243 and 274
 for cryptographically identical state.

 §12.2 rule 8 REJECTS an unclamped scalar read from a state blob rather than silently re-clamping
 it (§19.5). The state decoder MUST therefore call +bytesAreClamped: BEFORE constructing this type,
 never after — construction would mask the violation.
 */
@interface IRX25519Private : IRFixedLengthSecret

/// §4.2 — applies the clamp in place over exactly 32 writable bytes. Idempotent.
+ (void)clampBytes:(uint8_t * _Nonnull)bytes;

/// §12.2 rule 8 — `(k[0] & 0x07) == 0 && (k[31] & 0xC0) == 0x40`, the exact predicate the state
/// parser applies at blob offsets 243 and 274. Reads exactly 32 bytes.
+ (BOOL)bytesAreClamped:(const uint8_t * _Nonnull)bytes;

@end

/// §7.1 — the 32-byte Double Ratchet root key. Seeded by SK (§7.5) and advanced only by KDF_RK.
@interface IRRootKey : IRFixedLengthSecret
@end

/// §7.1 — a 32-byte symmetric chain key, CKs or CKr. Advanced only by KDF_CK.
@interface IRChainKey : IRFixedLengthSecret
@end

/// §7.3 — the 32-byte per-message key, MK = HMAC(CK, 0x01). Zeroized immediately after KDF_MK
/// expands it (§13.3).
@interface IRMessageKey : IRFixedLengthSecret
@end

/// §8.1 — the 32-byte AEAD key, HKDF(salt = Z32, ikm = MK, info = "nuntius:MK:v4", L = 32).
/// Zeroized immediately after the AEAD call returns, on the success AND failure paths (§13.3).
@interface IRMessageEncKey : IRFixedLengthSecret
@end
