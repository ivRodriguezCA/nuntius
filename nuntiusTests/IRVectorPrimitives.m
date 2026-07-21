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

#import "IRVectorModules.h"
#import "IRVectorIO.h"

#import "IRErrors.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRProtocolConstants.h"
#import "IRProtocolKDF.h"
#import "IRSecretBytes.h"

/**
 primitives.json — SPEC §3.2, §4.2, §4.4, §7.2, §7.3, §8.1, §15.3, §15.5.

 THIRTEEN VECTORS UNDER §15.3's ELEVEN ROWS. `RFC5869-A1…A3` is one row naming three ids, and ids
 are what the corpus is indexed by, so the array below has thirteen entries:

     RFC5869-A1           RFC 5869 A.1 — basic case, 42-byte OKM              TRANSCRIBED
     RFC5869-A2           RFC 5869 A.2 — 80-byte inputs, 82-byte OKM          TRANSCRIBED
     RFC5869-A3           RFC 5869 A.3 — zero-length salt and info            TRANSCRIBED
     HKDF-SALT-EQUIV      Extract(Z32, ikm) == Extract(empty, ikm)            generated
     HKDF-EXPAND-64       the two-block T(i) loop KDF_RK needs                generated
     RFC7748-X25519       RFC 7748 §5.2, both scalar multiplications          TRANSCRIBED
     X25519-ZERO          small-order inputs, REJECTED not zero-returned      literal inputs
     RFC8032-ED25519      RFC 8032 §7.1, all four pure-Ed25519 vectors        TRANSCRIBED
     ED25519-SEED-EXPAND  seed -> published IK^s; signature verify-side only  generated
     RFC8439-AEAD         RFC 8439 §2.8.2, tag appended                       TRANSCRIBED
     KDF-CK-1             §7.3 over a fixed chain key                         generated
     KDF-RK-1             §7.2 — THE SALT/IKM ARGUMENT-ORDER CHECKPOINT       generated
     KDF-MK-1             §8.1 over a fixed message key                       generated

 THE SIX TRANSCRIBED ROWS ARE NOT GENERATED, AND THAT IS WHAT MAKES THE OTHER FIVE FILES MEAN
 ANYTHING. Every expected output on an RFC row below is a literal in this file, copied from the RFC
 text at rfc-editor.org. A corpus generated end to end by the implementation under test proves
 self-consistency and nothing else — it is exactly the state v3 was in, with twenty-three green
 tests over an X3DH that had silently collapsed to a single DH. Producing one of those expected
 values by running our own code destroys the only external check in the suite, so the generator
 never computes them and never even cross-checks them: the EXECUTOR is what runs the frozen bytes
 through the implementation, and a mismatch must be reported as a failing vector rather than
 aborting corpus construction through IRVectorFail.

 THE FIVE GENERATED ROWS ARE THE nuntius-SPECIFIC ONES, and each exists because no RFC covers it:
 §7.2's KDF_RK, §7.3's KDF_CK and §8.1's KDF_MK are this protocol's own compositions, HKDF-EXPAND-64
 pins the second Expand block that §3.2 calls the most common hand-rolled-HKDF bug, and
 HKDF-SALT-EQUIV records that Z32 and an empty salt are the same HMAC key so that no reviewer in
 another port ever "fixes" one spelling into the other. ED25519-SEED-EXPAND is generated but is
 anchored: its seed is RFC 8032 TEST 1's, and the generator hard-fails unless the derived public key
 is byte-identical to the RFC's published one.

 KDF-RK-1 IS THE SINGLE MOST VALUABLE VECTOR IN THIS FILE. §7.2 calls the salt/IKM argument order
 "the single highest-risk divergence point in this protocol": libsodium's
 crypto_kdf_hkdf_sha256_extract takes the salt first, BouncyCastle's HKDFParameters(ikm, salt, info)
 and CryptoKit's deriveKey(inputKeyMaterial:salt:info:) take the IKM first, and a port that swaps
 them is working, self-consistent and completely incompatible. So KDF-RK-1 carries an extra
 intermediate, `OKM_if_salt_and_ikm_swapped`, which is what a swapped port WOULD produce: a port
 whose output matches that value has the arguments the wrong way round, and it learns so from the
 vector instead of from a field incident.

 NO VECTOR HERE READS A CLOCK OR CONSUMES RANDOMNESS. Every primitive is a pure function of its
 inputs, so there is no `now_s`, no `now_ms` and no IRScriptedRandomSource anywhere in this file —
 IRVectorAmbientProvider() throughout, which is what makes the driver's ten-years-forward run
 (§15.6) a real check rather than a formality. There is likewise no `entry_point`: §15.5 requires it
 only of a vector whose evaluation calls one of the seven named APIs, and a primitive calls none.

 EVERY SIGNATURE IN THIS FILE IS AN `inputs` FIELD, AND NO `outputs` FIELD ANYWHERE HOLDS ONE
 (§3.4, §15.5 rule 8). Ed25519 signature GENERATION is not byte-reproducible across platforms: RFC
 8032 §5.1.6 derives the nonce deterministically but §8.2 explicitly permits extra randomness, and
 CryptoKit / swift-crypto takes that option — signing RFC 8032 TEST 1's empty message three times
 under its published seed yields three distinct signatures, all valid, none equal to the RFC's.
 An `outputs` comparison would therefore fail a conformant Swift port for no defect at all, and
 §15.6 step 4 would freeze that failure into the contract. So both Ed25519 rows below assert the
 same two things instead: the runner VERIFIES the vector's published signature against the
 published public key and message, and then ADDITIONALLY signs the message itself and verifies
 that signature — exercising the signing path, including the §3.4 seed expansion, without
 depending on its output being canonical. The two signatures are never compared to each other.
 What IS byte-normative, and the reason ED25519-SEED-EXPAND still exists, is seed -> public key:
 that is identical on libsodium, the JDK and CryptoKit, it stays an `outputs` field, and it is the
 only Ed25519 quantity this specification is allowed to depend on.

 X25519-ZERO IS THE ONE `expect: "error"` ROW IN THIS FILE. §15.3 words it precisely — a small-order
 input "MUST produce the all-zero output and be REJECTED" — and the two halves are in tension for a
 conformance file: the all-zero output is exactly what §4.4 check 3 refuses to return, so it is not
 observable through a conformant API. It is carried as the `dh_output_unchecked` intermediate and
 this runner declares it skipped, with a reason, through §15.5 rule 2's reporting path. That is what
 rule 2's skip mechanism is for, and it leaves the value in the frozen file where a port debugging
 its own accumulator can read it.
 */

#pragma mark - RFC 5869 Appendix A — HKDF-SHA256 (TRANSCRIBED)

/* A.1 — basic case. */
static NSString * const kRFC5869A1IKM  = @"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
static NSString * const kRFC5869A1Salt = @"000102030405060708090a0b0c";
static NSString * const kRFC5869A1Info = @"f0f1f2f3f4f5f6f7f8f9";
static NSString * const kRFC5869A1PRK  =
    @"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
static NSString * const kRFC5869A1OKM  =
    @"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    @"34007208d5b887185865";

/* A.2 — 80-byte inputs, and an 82-byte OKM that spans THREE Expand blocks. */
static NSString * const kRFC5869A2IKM =
    @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    @"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    @"404142434445464748494a4b4c4d4e4f";
static NSString * const kRFC5869A2Salt =
    @"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    @"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    @"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
static NSString * const kRFC5869A2Info =
    @"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    @"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    @"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
static NSString * const kRFC5869A2PRK =
    @"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
static NSString * const kRFC5869A2OKM =
    @"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
    @"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
    @"cc30c58179ec3e87c14c01d5c1f3434f1d87";

/* A.3 — zero-length salt and zero-length info. The RFC writes both as "not provided (0 octets)";
   this file writes them as the empty hex string, which is the same thing said in the corpus's own
   vocabulary and is far harder to misread than an absent key. */
static NSString * const kRFC5869A3IKM  = @"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
static NSString * const kRFC5869A3Salt = @"";
static NSString * const kRFC5869A3Info = @"";
static NSString * const kRFC5869A3PRK  =
    @"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
static NSString * const kRFC5869A3OKM  =
    @"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    @"9d201395faa4b61a96c8";

#pragma mark - RFC 7748 §5.2 — X25519 (TRANSCRIBED)

static NSString * const kRFC7748Scalar1 =
    @"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
static NSString * const kRFC7748U1 =
    @"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
static NSString * const kRFC7748Shared1 =
    @"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

static NSString * const kRFC7748Scalar2 =
    @"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
static NSString * const kRFC7748U2 =
    @"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
static NSString * const kRFC7748Shared2 =
    @"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

/* §4.2's clamp, `k[0] &= 0xF8; k[31] &= 0x7F; k[31] |= 0x40`, applied to the two RFC scalars by
   hand. These are transcribed rather than generated for the same reason the outputs are: they are
   defined by RFC 7748 §5's decodeScalar25519, not by us. Scalar 1 is the value §15.5's worked
   example names as `IK_A_d_priv`, and scalar 2 is the one it names as `EK_A_priv` — a546…9ac4
   clamps to a046…9a44, and 4b66…ba0d clamps to 4866…ba4d. */
static NSString * const kRFC7748Scalar1Clamped =
    @"a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44";
static NSString * const kRFC7748Scalar2Clamped =
    @"4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d";

/* RFC 7748 §5's decodeUCoordinate masks bit 255 of the u-coordinate, so the second vector's
   published encoding — which ENDS 0x93, i.e. with that bit set — and this masked spelling are one
   key with two wire encodings. §4.4 check 2 refuses the published encoding at the type boundary
   precisely to close that injectivity break, and the masked form reproduces the RFC's published
   output, which is how this file demonstrates rather than merely asserts why the check exists. */
static NSString * const kRFC7748U2Masked =
    @"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413";

/* §4.4 check 3. Every one of these drives the X25519 output to all zero, and THE LIST IS
   EXHAUSTIVE for the encodings this vector is allowed to carry — points whose encoding has bit 255
   SET are unreachable past check 2, which is a different rejection with a different code and
   belongs to a different vector.

   THERE ARE SEVEN, NOT SIX. Solving the curve arithmetic rather than transcribing a blacklist:
   over F_p the u-coordinates whose point has order dividing 8 are exactly five — 0 (order 1 and
   the order-2 point), 1 (order 4), the two roots of the order-8 condition dbl(u) == 1, and p-1
   (order 4, on the twist). Bit-255-clear 32-byte encodings that reduce to one of those five add
   the two non-canonical spellings p and p+1, which decode to 0 and 1 after RFC 7748's mask,
   giving seven. An earlier revision of this file listed only one of the two order-8 roots and
   silently dropped 5f9c…5157, whose last byte is 0x57 — bit 255 CLEAR, so it reaches check 3 like
   every other row here rather than being caught earlier by check 2. */
static NSString * const kX25519SmallOrderOrder1 =
    @"0000000000000000000000000000000000000000000000000000000000000000";
static NSString * const kX25519SmallOrderOrder4 =
    @"0100000000000000000000000000000000000000000000000000000000000000";
static NSString * const kX25519SmallOrderOrder8A =
    @"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800";

/* The second order-8 root. It is the one a hand-copied blacklist loses, because libsodium's own
   table interleaves it with the bit-255-SET variants and it is the only entry whose high byte is
   neither 0x00 nor 0x7f. */
static NSString * const kX25519SmallOrderOrder8B =
    @"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157";

static NSString * const kX25519SmallOrderPMinus1 =
    @"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
static NSString * const kX25519SmallOrderP =
    @"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
static NSString * const kX25519SmallOrderPPlus1 =
    @"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

/* The DH output a port that skipped §4.4 check 3 would obtain. Definitional — RFC 7748 §6.1's
   contributory-behaviour note — not produced by any implementation, and unobservable through a
   conformant API, which is why the runner declares it a rule 2 skip. */
static NSString * const kX25519ZeroOutput =
    @"0000000000000000000000000000000000000000000000000000000000000000";

#pragma mark - RFC 8032 §7.1 — pure Ed25519 (TRANSCRIBED)

/* SECRET KEY is the 32-byte RFC 8032 SEED (§4.2), never libsodium's 64-byte expanded sk. A
   libsodium port MUST run crypto_sign_seed_keypair first; handing the seed straight to
   crypto_sign_detached is a 32-byte out-of-bounds read that surfaces as ERR_BAD_SIGNATURE, i.e.
   disguised as the active MITM §1.2 defines that code to mean. A port using the PREHASHED
   multi-part API fails all four of these (§3.4). */
static NSString * const kRFC8032Seed1 =
    @"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static NSString * const kRFC8032Public1 =
    @"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static NSString * const kRFC8032Message1 = @"";
static NSString * const kRFC8032Signature1 =
    @"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    @"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

static NSString * const kRFC8032Seed2 =
    @"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
static NSString * const kRFC8032Public2 =
    @"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
static NSString * const kRFC8032Message2 = @"72";
static NSString * const kRFC8032Signature2 =
    @"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    @"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

static NSString * const kRFC8032Seed3 =
    @"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
static NSString * const kRFC8032Public3 =
    @"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
static NSString * const kRFC8032Message3 = @"af82";
static NSString * const kRFC8032Signature3 =
    @"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
    @"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

/* RFC 8032's TEST SHA(abc). ITS PUBLIC KEY ENDS 0xbf — bit 255 SET — and that is legal and
   ordinary: for Ed25519 that bit is the sign of x (RFC 8032 §5.1.2), NOT the RFC 7748 u-coordinate
   masking bit. A port that applied §4.4 checks 1–2 to Ed25519 keys as well as X25519 ones rejects
   roughly half of all valid identities, an intermittent failure that looks exactly like a signature
   bug. This case is the scoping regression, and it is why the row carries four vectors and not one. */
static NSString * const kRFC8032Seed4 =
    @"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
static NSString * const kRFC8032Public4 =
    @"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
static NSString * const kRFC8032Message4 =
    @"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    @"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
static NSString * const kRFC8032Signature4 =
    @"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
    @"09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";

/* ED25519-SEED-EXPAND signs a nuntius-chosen message under RFC 8032 TEST 1's seed, so the SIGNATURE
   is generated while the PUBLIC KEY is anchored to the RFC's published value. The message is the
   seven ASCII bytes of `nuntius`; nothing about it is protocol-specific, and it is deliberately
   different from all four RFC messages so the vector cannot be satisfied by echoing one of them. */
static NSString * const kSeedExpandMessage = @"6e756e74697573";

#pragma mark - RFC 8439 §2.8.2 — ChaCha20-Poly1305 IETF (TRANSCRIBED)

static NSString * const kRFC8439Key =
    @"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

/* The 12-byte IETF nonce: RFC 8439's 4-byte fixed-common part 07 00 00 00 followed by its 8-byte
   IV. The width is the point — the non-IETF libsodium spelling takes EIGHT bytes and is a silent
   incompatibility (§3.3), so this vector is what turns picking it up by autocomplete into a test
   failure rather than a field incident. */
static NSString * const kRFC8439Nonce = @"070000004041424344454647";

static NSString * const kRFC8439AAD = @"50515253c0c1c2c3c4c5c6c7";

static NSString * const kRFC8439Plaintext =
    @"4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    @"73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    @"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    @"637265656e20776f756c642062652069742e";

static NSString * const kRFC8439Ciphertext =
    @"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    @"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    @"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    @"3ff4def08e4b7a9de576d26586cec64b6116";

static NSString * const kRFC8439Tag = @"1ae10b594f09e26a7e902ecbd0600691";

#pragma mark - Fixed key material for the generated protocol-KDF rows

/* Three distinct, non-repeating 32-byte patterns. Distinctness is load-bearing on KDF-RK-1: if RK
   and DH_out were equal, swapping the HKDF salt and IKM would produce the SAME output and the
   argument-order checkpoint would arbitrate nothing. */
static NSString * const kKDFChainKey =
    @"c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0";
static NSString * const kKDFRootKey =
    @"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
static NSString * const kKDFDHOutput =
    @"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
static NSString * const kKDFMessageKey =
    @"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/* §18 and §7.3: the KDF_CK inputs are the single bytes 0x01 (message key) and 0x02 (chain key), and
   they MUST NOT be renumbered. v3 used salt 0 for the message key and salt 1 for the chain key, so
   a port that carried those numbers over is self-consistent and incompatible; carrying the two
   bytes as intermediates is what makes that visible in the artifact rather than only in prose. */
static NSString * const kKDFCKMessageKeyInputByte = @"01";
static NSString * const kKDFCKChainKeyInputByte   = @"02";

#pragma mark - Small helpers

/// A NON-SECRET copy of a secret's bytes, for hex encoding into the artifact. Every value that
/// reaches a vector file is by definition published, so there is nothing left for §13.3 to protect
/// at this point — but the copy is explicit rather than implicit so that no reader mistakes an
/// IRSecretBytes for something an NSData API may be pointed at directly.
static NSData *IRPrimitiveDataFromSecret(IRSecretBytes *secret) {
    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

/**
 An IRSecretBytes over `data`, or nil when `data` is empty.

 THE nil IS NOT A FAILURE PATH, IT IS THE ZERO-LENGTH SPELLING. IRSecretBytes cannot represent a
 zero-length buffer — -initWithLength: returns nil for 0 — and it does not need to: §3.2 records
 that HMAC pads any key shorter than its 64-byte block with zeros, so a zero-length HKDF salt and a
 32-zero-byte salt are the SAME HMAC key, and -hkdfExtractWithSalt: takes a _Nullable salt for
 exactly this reason. RFC5869-A3's empty salt therefore arrives here as an empty NSData and leaves
 as nil, and HKDF-SALT-EQUIV is the vector that records that the two spellings agree.
 */
static IRSecretBytes *_Nullable IRPrimitiveSecretFromData(NSData *data) {
    if (data.length == 0) {
        return nil;
    }

    return [[IRSecretBytes alloc] initWithData:data guarded:NO];
}

/// Generator-side: as above, but a nil is a corpus that cannot be built.
static IRSecretBytes *IRPrimitiveRequiredSecretFromHex(NSString *hex) {
    IRSecretBytes *secret = IRPrimitiveSecretFromData(IRVectorBytes(hex));
    IRVectorRequire(secret != nil, @"cannot hold %@ as a secret", hex);

    return secret;
}

/// §18's Z32 — 32 × 0x00 — as the NSData the artifact publishes and as the salt §8.1 names.
static NSData *IRPrimitiveZ32Data(void) {
    return [NSData dataWithBytes:kIRZ32 length:(NSUInteger)kIRLenZ32];
}

/// §18's `nuntius:RK:v4` (13 bytes) and `nuntius:MK:v4` (13 bytes), read from the one definition
/// the framework has rather than retyped as hex. A vector file that disagreed with
/// IRProtocolConstants.m would be worse than useless.
static NSData *IRPrimitiveRKLabel(void) {
    return [NSData dataWithBytes:kIRLabelRK length:(NSUInteger)kIRLenLabelRK];
}

static NSData *IRPrimitiveMKLabel(void) {
    return [NSData dataWithBytes:kIRLabelMK length:(NSUInteger)kIRLenLabelMK];
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForPrimitives(void) {
    NSError *error = nil;
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    #pragma mark RFC5869-A1 / A2 / A3 — transcribed

    /* Not a line of these three is computed. `L` is a uint32-typed protocol field and so is a JSON
       number (§15.2); `PRK` is an intermediate because the RFC publishes it and because a port that
       gets Extract right and Expand wrong fails only on the OKM, which is a far harder bug to
       localise from the OKM alone. */
    NSDictionary *rfc5869A1 = @{
        @"id"          : @"RFC5869-A1",
        @"kind"        : @"primitive",
        @"description" : @"RFC 5869 Appendix A.1, HKDF-SHA256 basic case: 22-byte IKM, 13-byte "
                         @"salt, 10-byte info, 42-byte OKM. Expected values transcribed from the "
                         @"RFC text, never generated. Run this first: nothing else in the corpus "
                         @"is trustworthy until it passes.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"ikm"  : kRFC5869A1IKM,
            @"salt" : kRFC5869A1Salt,
            @"info" : kRFC5869A1Info,
            @"L"    : @42,
        },
        @"intermediates" : @{ @"PRK" : kRFC5869A1PRK },
        @"outputs"       : @{
            @"OKM"     : kRFC5869A1OKM,
            @"OKM_len" : @42,
        },
    };

    NSDictionary *rfc5869A2 = @{
        @"id"          : @"RFC5869-A2",
        @"kind"        : @"primitive",
        @"description" : @"RFC 5869 Appendix A.2: 80-byte IKM, 80-byte salt, 80-byte info and an "
                         @"82-byte OKM, which spans three Expand blocks. The multi-block case that "
                         @"§7.2 needs at L = 64, exercised past the boundary where a hand-rolled "
                         @"T(i) loop that emits only T(1) still looks correct.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"ikm"  : kRFC5869A2IKM,
            @"salt" : kRFC5869A2Salt,
            @"info" : kRFC5869A2Info,
            @"L"    : @82,
        },
        @"intermediates" : @{ @"PRK" : kRFC5869A2PRK },
        @"outputs"       : @{
            @"OKM"     : kRFC5869A2OKM,
            @"OKM_len" : @82,
        },
    };

    NSDictionary *rfc5869A3 = @{
        @"id"          : @"RFC5869-A3",
        @"kind"        : @"primitive",
        @"description" : @"RFC 5869 Appendix A.3: zero-length salt and zero-length info. Both are "
                         @"written as the empty hex string rather than as absent keys, so a runner "
                         @"reads them through the same accessor as every other byte string. Its "
                         @"PRK is the value HKDF-SALT-EQUIV proves a 32-zero-byte salt reproduces.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"ikm"  : kRFC5869A3IKM,
            @"salt" : kRFC5869A3Salt,
            @"info" : kRFC5869A3Info,
            @"L"    : @42,
        },
        @"intermediates" : @{ @"PRK" : kRFC5869A3PRK },
        @"outputs"       : @{
            @"OKM"     : kRFC5869A3OKM,
            @"OKM_len" : @42,
        },
    };

    #pragma mark HKDF-SALT-EQUIV — generated

    IRSecretBytes *saltEquivIKM = IRPrimitiveRequiredSecretFromHex(kRFC5869A3IKM);

    /* §18's Z32 taken from the framework's own definition rather than retyped, for the same reason
       the two labels are: a vector file that disagreed with IRProtocolConstants.m would be worse
       than no vector file at all. */
    IRSecretBytes *z32Salt = IRPrimitiveSecretFromData(IRPrimitiveZ32Data());
    IRVectorRequire(z32Salt != nil, @"cannot hold Z32 as a secret");

    IRSecretBytes *prkWithZ32 = [provider hkdfExtractWithSalt:z32Salt ikm:saltEquivIKM error:&error];
    IRVectorRequire(prkWithZ32 != nil, @"HKDF-Extract(Z32, ikm): %@", error);

    IRSecretBytes *prkWithEmpty = [provider hkdfExtractWithSalt:nil ikm:saltEquivIKM error:&error];
    IRVectorRequire(prkWithEmpty != nil, @"HKDF-Extract(empty, ikm): %@", error);

    IRVectorRequire([prkWithZ32 isEqualToSecretBytes:prkWithEmpty],
                    @"§3.2: Z32 and an empty salt MUST produce an identical PRK");

    /* AND IT REALLY IS RFC 5869 A.3's PRK, so "the two agree" is not two identical wrong answers.
       Comparing a generated value against a TRANSCRIBED one is the right direction of dependency:
       the RFC constrains us, we never constrain the RFC. */
    IRVectorRequire([IRVectorHex(IRPrimitiveDataFromSecret(prkWithZ32))
                        isEqualToString:kRFC5869A3PRK],
                    @"HKDF-SALT-EQUIV must reproduce RFC 5869 A.3's PRK, got %@",
                    IRVectorHex(IRPrimitiveDataFromSecret(prkWithZ32)));

    NSDictionary *hkdfSaltEquiv = @{
        @"id"          : @"HKDF-SALT-EQUIV",
        @"kind"        : @"primitive",
        @"description" : @"HKDF-Extract(Z32, ikm) equals HKDF-Extract(empty, ikm), because HMAC "
                         @"pads any key shorter than its 64-byte block with zeros. Wherever this "
                         @"specification writes salt = Z32 an implementation MAY pass a zero-length "
                         @"salt; §3.2 says so, and this vector exists so that no reviewer in "
                         @"another port ever corrects one spelling into the other. Not a "
                         @"divergence point.",
        @"expect"      : @"ok",
        @"inputs"      : @{ @"ikm" : kRFC5869A3IKM },
        @"intermediates" : @{
            @"salt_Z32"            : IRVectorHex(IRPrimitiveZ32Data()),
            @"PRK_with_Z32_salt"   : IRVectorHex(IRPrimitiveDataFromSecret(prkWithZ32)),
            @"PRK_with_empty_salt" : IRVectorHex(IRPrimitiveDataFromSecret(prkWithEmpty)),
        },
        @"outputs" : @{
            @"PRK"     : IRVectorHex(IRPrimitiveDataFromSecret(prkWithZ32)),
            @"PRK_len" : @(prkWithZ32.length),
        },
    };

    #pragma mark HKDF-EXPAND-64 — generated

    /* The exact shape §7.2's KDF_RK uses: a Z32-equivalent salt, the `nuntius:RK:v4` info label,
       and L = 64. Splitting the output into T(1) and T(2) is what localises the failure — an
       implementation that emits only the first block produces a plausible 32-byte RK and a wrong or
       absent chain key, and the symptom is "the second message does not decrypt", arbitrarily far
       from the cause. */
    IRSecretBytes *expand64PRK = [provider hkdfExtractWithSalt:z32Salt
                                                          ikm:saltEquivIKM
                                                        error:&error];
    IRVectorRequire(expand64PRK != nil, @"HKDF-EXPAND-64 extract: %@", error);

    IRSecretBytes *expand64OKM = [provider hkdfExpandWithPRK:expand64PRK
                                                        info:IRPrimitiveRKLabel()
                                                outputLength:(NSUInteger)kIRLenKDFRKOutput
                                                       error:&error];
    IRVectorRequire(expand64OKM != nil, @"HKDF-EXPAND-64 expand: %@", error);
    IRVectorRequire(expand64OKM.length == 64, @"§18: KDF_RK output is 64 bytes, got %lu",
                    (unsigned long)expand64OKM.length);

    IRSecretBytes *expand32OKM = [provider hkdfExpandWithPRK:expand64PRK
                                                        info:IRPrimitiveRKLabel()
                                                outputLength:(NSUInteger)kIRLenHMACSHA256
                                                       error:&error];
    IRVectorRequire(expand32OKM != nil, @"HKDF-EXPAND-64 32-byte expand: %@", error);

    NSData *expand64Bytes = IRPrimitiveDataFromSecret(expand64OKM);
    NSData *expand64T1 = [expand64Bytes subdataWithRange:NSMakeRange(0, 32)];
    NSData *expand64T2 = [expand64Bytes subdataWithRange:NSMakeRange(32, 32)];

    IRVectorRequire([expand64T1 isEqualToData:IRPrimitiveDataFromSecret(expand32OKM)],
                    @"T(1) MUST be identical whether L is 32 or 64");
    IRVectorRequire(![expand64T1 isEqualToData:expand64T2],
                    @"T(2) MUST be computed, not a repeat of T(1) (§3.2)");

    NSDictionary *hkdfExpand64 = @{
        @"id"          : @"HKDF-EXPAND-64",
        @"kind"        : @"primitive",
        @"description" : @"A 64-byte HKDF-Expand under the nuntius:RK:v4 label, exercising the "
                         @"two-block T(i) counter loop §7.2's KDF_RK requires. §3.2 names omitting "
                         @"the second block the most common hand-rolled-HKDF bug. T(1) MUST equal a "
                         @"32-byte expansion under the same PRK and info, and T(2) MUST differ from "
                         @"T(1) rather than repeat it.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"ikm"  : kRFC5869A3IKM,
            @"salt" : IRVectorHex(IRPrimitiveZ32Data()),
            @"info" : IRVectorHex(IRPrimitiveRKLabel()),
            @"L"    : @(kIRLenKDFRKOutput),
        },
        @"intermediates" : @{
            @"PRK"    : IRVectorHex(IRPrimitiveDataFromSecret(expand64PRK)),
            @"T1"     : IRVectorHex(expand64T1),
            @"T2"     : IRVectorHex(expand64T2),
            @"OKM_32" : IRVectorHex(IRPrimitiveDataFromSecret(expand32OKM)),
        },
        @"outputs" : @{
            @"OKM"     : IRVectorHex(expand64Bytes),
            @"OKM_len" : @(expand64Bytes.length),
        },
    };

    #pragma mark RFC7748-X25519 — transcribed

    NSDictionary *rfc7748 = @{
        @"id"          : @"RFC7748-X25519",
        @"kind"        : @"primitive",
        @"description" : @"Both RFC 7748 §5.2 scalar multiplications, with expected outputs "
                         @"transcribed from the RFC text. Also pins §4.2's clamp, which is a "
                         @"representation rule and changes no cryptographic output, and §4.4 check "
                         @"2: the second vector's published u-coordinate ends 0x93, so bit 255 is "
                         @"SET, and that encoding MUST be refused at the type boundary. Masking "
                         @"the bit yields a different 32-byte encoding of the SAME key that "
                         @"reproduces the RFC output, which is the injectivity break check 2 "
                         @"closes.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"scalar_1" : kRFC7748Scalar1,
            @"u_1"      : kRFC7748U1,
            @"scalar_2" : kRFC7748Scalar2,
            @"u_2"      : kRFC7748U2,
        },
        @"intermediates" : @{
            @"scalar_1_clamped" : kRFC7748Scalar1Clamped,
            @"scalar_2_clamped" : kRFC7748Scalar2Clamped,
            @"u_2_masked"       : kRFC7748U2Masked,
        },
        @"outputs" : @{
            @"shared_1"                : kRFC7748Shared1,
            @"shared_2"                : kRFC7748Shared2,
            @"u_2_high_bit_rejected"   : @YES,
        },
    };

    #pragma mark X25519-ZERO — literal inputs, expect error

    NSDictionary *x25519Zero = @{
        @"id"          : @"X25519-ZERO",
        @"kind"        : @"primitive",
        @"description" : @"Seven small-order u-coordinates, each of which drives the X25519 output "
                         @"to all zero. Every one MUST be REJECTED with ERR_SMALL_ORDER_KEY rather "
                         @"than returning that output. §4.4 requires the implementation itself to "
                         @"run the OR-accumulator check, not to delegate it: libsodium returns -1, "
                         @"BouncyCastle and the JDK throw, and CryptoKit does nothing at all, so on "
                         @"one of the four ports the accumulator is the only defence there is. A "
                         @"hard-coded blacklist of the twelve small-order points is forbidden as "
                         @"the sole check. Only encodings with bit 255 clear appear here, because "
                         @"the rest are unreachable past §4.4 check 2 — a different rejection with "
                         @"a different code — and SEVEN is the complete count of those, not six: "
                         @"F_p holds five u-coordinates of order dividing 8 (0, 1, the two order-8 "
                         @"roots e0eb…b800 and 5f9c…5157, and p-1), and the non-canonical "
                         @"spellings p and p+1 reduce to 0 and 1 under RFC 7748's bit-255 mask. A "
                         @"port that transcribed a partial blacklist loses 5f9c…5157 first, since "
                         @"it is the only bit-255-clear entry whose high byte is neither 00 nor 7f.",
        @"expect"      : @"error",
        @"error"       : @"ERR_SMALL_ORDER_KEY",
        @"inputs"      : @{
            @"scalar"   : kRFC7748Scalar1,
            @"u_points" : @[
                kX25519SmallOrderOrder1,
                kX25519SmallOrderOrder4,
                kX25519SmallOrderOrder8A,
                kX25519SmallOrderOrder8B,
                kX25519SmallOrderPMinus1,
                kX25519SmallOrderP,
                kX25519SmallOrderPPlus1,
            ],
        },
        @"intermediates" : @{ @"dh_output_unchecked" : kX25519ZeroOutput },
    };

    #pragma mark RFC8032-ED25519 — transcribed

    NSDictionary *rfc8032 = @{
        @"id"          : @"RFC8032-ED25519",
        @"kind"        : @"primitive",
        @"description" : @"All four RFC 8032 §7.1 pure-Ed25519 vectors, with public keys and "
                         @"signatures transcribed from the RFC text. THE SIGNATURES ARE INPUTS, "
                         @"NEVER OUTPUTS (§3.4, §15.5 rule 8): a runner MUST verify each published "
                         @"signature against the published public key and message, and MUST NOT "
                         @"sign and compare its own bytes, because Ed25519 signing is not "
                         @"byte-reproducible across platforms — RFC 8032 §8.2 permits a randomized "
                         @"nonce and CryptoKit takes that option, so the same seed and message "
                         @"yield a different valid signature every time. A runner SHOULD also sign "
                         @"the message itself and verify THAT signature, which exercises the "
                         @"signing path without depending on its output being canonical. A port "
                         @"using the PREHASHED multi-part API fails here, on the verify of the "
                         @"published signature, which is where the failure belongs: libsodium's "
                         @"crypto_sign_init / _update / _final_create is Ed25519ph, a different "
                         @"signature scheme neither the JDK nor CryptoKit can verify, and v3 signed "
                         @"with it. The private key inputs are 32-byte SEEDS (§4.2), so this also "
                         @"exercises the seed expansion §3.4 requires. Case 4 is the RFC SHA(abc) "
                         @"case, whose public key ends 0xbf with bit 255 SET: for Ed25519 that bit "
                         @"is the sign of x and is ordinary, and applying §4.4 checks 1 and 2 to an "
                         @"Ed25519 key would reject about half of all valid identities.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"seed_1"      : kRFC8032Seed1,
            @"message_1"   : kRFC8032Message1,
            @"signature_1" : kRFC8032Signature1,
            @"seed_2"      : kRFC8032Seed2,
            @"message_2"   : kRFC8032Message2,
            @"signature_2" : kRFC8032Signature2,
            @"seed_3"      : kRFC8032Seed3,
            @"message_3"   : kRFC8032Message3,
            @"signature_3" : kRFC8032Signature3,
            @"seed_4"      : kRFC8032Seed4,
            @"message_4"   : kRFC8032Message4,
            @"signature_4" : kRFC8032Signature4,
        },
        @"intermediates" : @{
            @"public_key_1" : kRFC8032Public1,
            @"public_key_2" : kRFC8032Public2,
            @"public_key_3" : kRFC8032Public3,
            @"public_key_4" : kRFC8032Public4,
        },
        /* The assertion is the VERIFY, and the boolean is the whole of it. §15.5 rule 8's closing
           sentence — "this rule is the reason no `outputs` field anywhere in §15.3 holds a
           signature" — is what these four flags replace the four signature bytes with. */
        @"outputs" : @{
            @"verified_1"  : @YES,
            @"verified_2"  : @YES,
            @"verified_3"  : @YES,
            @"verified_4"  : @YES,
        },
    };

    #pragma mark ED25519-SEED-EXPAND — generated, anchored to RFC 8032 TEST 1

    IREd25519Private *seedExpandSeed = [IREd25519Private fromData:IRVectorBytes(kRFC8032Seed1)
                                                          guarded:NO
                                                            error:&error];
    IRVectorRequire(seedExpandSeed != nil, @"ED25519-SEED-EXPAND seed: %@", error);

    IREd25519Public *seedExpandPublic = [provider ed25519PublicKeyForSeed:seedExpandSeed
                                                                    error:&error];
    IRVectorRequire(seedExpandPublic != nil, @"ED25519-SEED-EXPAND public key: %@", error);

    /* THE ANCHOR. This row's signature is generated, but its public key is not free to be whatever
       our expansion happens to produce: the seed is RFC 8032 TEST 1's, so the derived key MUST be
       the RFC's published one, and a corpus that could not reproduce it has no business being
       frozen. */
    IRVectorRequire([[seedExpandPublic hexString] isEqualToString:kRFC8032Public1],
                    @"crypto_sign_seed_keypair over RFC 8032 TEST 1's seed must reproduce its "
                    @"published public key; got %@", [seedExpandPublic hexString]);

    NSData *seedExpandMessage = IRVectorBytes(kSeedExpandMessage);
    IREd25519Signature *seedExpandSignature = [provider ed25519SignMessage:seedExpandMessage
                                                                  withSeed:seedExpandSeed
                                                                     error:&error];
    IRVectorRequire(seedExpandSignature != nil, @"ED25519-SEED-EXPAND signature: %@", error);

    NSDictionary *seedExpand = @{
        @"id"          : @"ED25519-SEED-EXPAND",
        @"kind"        : @"primitive",
        @"description" : @"RFC 8032 TEST 1's seed, asserting that expanding it reproduces the "
                         @"published identity public key BYTE FOR BYTE. That single assertion is "
                         @"this vector's remaining purpose and it is the only Ed25519 quantity this "
                         @"specification is allowed to depend on: seed → public key is deterministic "
                         @"and identical on libsodium, the JDK and CryptoKit, and it is what makes "
                         @"an identity key portable at all. It asserts NOTHING about signature "
                         @"bytes. The signature here is an INPUT (§3.4, §15.5 rule 8), to be "
                         @"verified against the public key and message and never regenerated for "
                         @"comparison — RFC 8032 §8.2 permits a randomized nonce, CryptoKit takes "
                         @"that option, and three signings of one message under one seed there give "
                         @"three different valid signatures, none of them the RFC's. A runner "
                         @"SHOULD additionally sign the message itself and verify that signature. "
                         @"seed_len is 32 because §4.2 makes the nominal private key the seed and "
                         @"forbids the 64-byte expanded sk from appearing at any API boundary, in "
                         @"any serialized structure, or in any vector file.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"seed"      : kRFC8032Seed1,
            @"message"   : kSeedExpandMessage,
            @"signature" : [seedExpandSignature hexString],
        },
        @"intermediates" : @{ @"seed_len" : @(seedExpandSeed.length) },
        @"outputs"       : @{
            @"public_key" : [seedExpandPublic hexString],
            @"verified"   : @YES,
        },
    };

    #pragma mark RFC8439-AEAD — transcribed

    NSDictionary *rfc8439 = @{
        @"id"          : @"RFC8439-AEAD",
        @"kind"        : @"primitive",
        @"description" : @"RFC 8439 §2.8.2's published ChaCha20-Poly1305 AEAD example, with the "
                         @"16-byte Poly1305 tag APPENDED to the 114-byte ciphertext, giving 130 "
                         @"bytes: ChaCha20 is a stream cipher, so there is no padding and "
                         @"len(sealed) is exactly len(plaintext) + 16. The 12-byte nonce pins the "
                         @"IETF construction; the non-IETF libsodium spelling takes 8 bytes and is "
                         @"a silent incompatibility. The vector also runs the inverse direction, "
                         @"because a port whose seal is right and whose open is wrong passes every "
                         @"encoding assertion in the file.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"key"       : kRFC8439Key,
            @"nonce"     : kRFC8439Nonce,
            @"plaintext" : kRFC8439Plaintext,
            @"aad"       : kRFC8439AAD,
        },
        @"intermediates" : @{
            @"ciphertext" : kRFC8439Ciphertext,
            @"tag"        : kRFC8439Tag,
        },
        @"outputs" : @{
            @"ciphertext_and_tag"     : [kRFC8439Ciphertext stringByAppendingString:kRFC8439Tag],
            @"ciphertext_and_tag_len" : @(130),
            @"opened_plaintext"       : kRFC8439Plaintext,
        },
    };

    #pragma mark KDF-CK-1 — generated

    IRChainKey *chainKey = [IRChainKey fromData:IRVectorBytes(kKDFChainKey) guarded:NO error:&error];
    IRVectorRequire(chainKey != nil, @"KDF-CK-1 chain key: %@", error);

    IRChainStep *chainStep = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                               provider:provider
                                                                  error:&error];
    IRVectorRequire(chainStep != nil, @"KDF-CK-1: %@", error);
    IRVectorRequire(![chainStep.messageKey isEqualToSecretBytes:chainStep.nextChainKey],
                    @"§7.3: MK and CK' come from different message bytes and MUST differ");

    NSDictionary *kdfCK1 = @{
        @"id"          : @"KDF-CK-1",
        @"kind"        : @"primitive",
        @"description" : @"§7.3 KDF_CK over a fixed chain key: MK = HMAC(key = CK, message = 0x01) "
                         @"and CK-next = HMAC(key = CK, message = 0x02), both 32 bytes. HKDF is "
                         @"deliberately NOT used here — two raw HMACs need no salt, no info, no "
                         @"length and no truncation, so there is nothing for four ports to agree "
                         @"on. The two message bytes MUST NOT be renumbered: v3 used salt 0 for the "
                         @"message key and salt 1 for the chain key, and a port that carried those "
                         @"numbers over is self-consistent and incompatible.",
        @"expect"      : @"ok",
        @"inputs"      : @{ @"CK" : kKDFChainKey },
        @"intermediates" : @{
            @"mk_input_byte" : kKDFCKMessageKeyInputByte,
            @"ck_input_byte" : kKDFCKChainKeyInputByte,
        },
        @"outputs" : @{
            @"MK"      : IRVectorHex(IRPrimitiveDataFromSecret(chainStep.messageKey)),
            @"CK_next" : IRVectorHex(IRPrimitiveDataFromSecret(chainStep.nextChainKey)),
        },
    };

    #pragma mark KDF-RK-1 — generated, and the argument-order checkpoint

    IRRootKey *rootKey = [IRRootKey fromData:IRVectorBytes(kKDFRootKey) guarded:NO error:&error];
    IRVectorRequire(rootKey != nil, @"KDF-RK-1 root key: %@", error);

    IRSecretBytes *dhOutput = IRPrimitiveRequiredSecretFromHex(kKDFDHOutput);
    IRVectorRequire(![rootKey isEqualToSecretBytes:dhOutput],
                    @"KDF-RK-1's RK and DH_out MUST differ, or swapping the HKDF salt and IKM "
                    @"produces the same output and the vector arbitrates nothing");

    IRRootChainStep *rootStep = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                      dhOutput:dhOutput
                                                                      provider:provider
                                                                         error:&error];
    IRVectorRequire(rootStep != nil, @"KDF-RK-1: %@", error);

    /* The full 64-byte OKM, so a port can see whether it split the halves the right way round
       independently of whether it derived them correctly. */
    IRSecretBytes *rootOKM = [provider hkdfWithSalt:rootKey
                                                ikm:dhOutput
                                               info:IRPrimitiveRKLabel()
                                       outputLength:(NSUInteger)kIRLenKDFRKOutput
                                              error:&error];
    IRVectorRequire(rootOKM != nil, @"KDF-RK-1 OKM: %@", error);

    NSData *rootOKMBytes = IRPrimitiveDataFromSecret(rootOKM);
    IRVectorRequire([[rootOKMBytes subdataWithRange:NSMakeRange(0, 32)]
                        isEqualToData:IRPrimitiveDataFromSecret(rootStep.rootKey)],
                    @"§7.2: RK-next is okm[0..32)");
    IRVectorRequire([[rootOKMBytes subdataWithRange:NSMakeRange(32, 32)]
                        isEqualToData:IRPrimitiveDataFromSecret(rootStep.chainKey)],
                    @"§7.2: CK is okm[32..64)");

    /* THE DIAGNOSTIC. This is what a port that passed DH_out as the salt and RK as the IKM would
       produce — a working, self-consistent, completely incompatible answer. Publishing it turns the
       highest-risk divergence in the protocol from "your ciphertext differs" into a named
       condition a port can test for directly. */
    IRSecretBytes *swappedOKM = [provider hkdfWithSalt:dhOutput
                                                   ikm:rootKey
                                                  info:IRPrimitiveRKLabel()
                                          outputLength:(NSUInteger)kIRLenKDFRKOutput
                                                 error:&error];
    IRVectorRequire(swappedOKM != nil, @"KDF-RK-1 swapped OKM: %@", error);
    IRVectorRequire(![swappedOKM isEqualToSecretBytes:rootOKM],
                    @"the swapped-argument OKM must differ from the correct one, or this vector "
                    @"cannot detect the swap it exists to detect");

    NSDictionary *kdfRK1 = @{
        @"id"          : @"KDF-RK-1",
        @"kind"        : @"primitive",
        @"description" : @"§7.2 KDF_RK over a fixed (RK, DH_out): HKDF with salt = RK, ikm = "
                         @"DH_out, info = nuntius:RK:v4 and L = 64, split RK-next = okm[0..32) and "
                         @"CK = okm[32..64). THE SALT/IKM ARGUMENT-ORDER CHECKPOINT, and §7.2 calls "
                         @"that the single highest-risk divergence point in this protocol: "
                         @"libsodium takes the salt first, BouncyCastle and CryptoKit take the IKM "
                         @"first, and swapping them produces a working, self-consistent, "
                         @"completely incompatible implementation. A port whose 64-byte output "
                         @"matches OKM_if_salt_and_ikm_swapped has the two the wrong way round. "
                         @"The previous root key is the salt and is MANDATORY: HKDF-Extract cannot "
                         @"be invoked without one, which is what makes forgetting to chain it "
                         @"inexpressible rather than merely forbidden.",
        @"expect"      : @"ok",
        @"inputs"      : @{
            @"RK"     : kKDFRootKey,
            @"DH_out" : kKDFDHOutput,
        },
        @"intermediates" : @{
            @"info"                        : IRVectorHex(IRPrimitiveRKLabel()),
            @"OKM"                         : IRVectorHex(rootOKMBytes),
            @"OKM_len"                     : @(rootOKMBytes.length),
            @"OKM_if_salt_and_ikm_swapped" : IRVectorHex(IRPrimitiveDataFromSecret(swappedOKM)),
        },
        @"outputs" : @{
            @"RK_next" : IRVectorHex(IRPrimitiveDataFromSecret(rootStep.rootKey)),
            @"CK"      : IRVectorHex(IRPrimitiveDataFromSecret(rootStep.chainKey)),
        },
    };

    #pragma mark KDF-MK-1 — generated

    IRMessageKey *messageKey = [IRMessageKey fromData:IRVectorBytes(kKDFMessageKey)
                                              guarded:NO
                                                error:&error];
    IRVectorRequire(messageKey != nil, @"KDF-MK-1 message key: %@", error);

    IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:messageKey
                                                      provider:provider
                                                         error:&error];
    IRVectorRequire(encKey != nil, @"KDF-MK-1: %@", error);
    IRVectorRequire(encKey.length == (NSUInteger)kIRLenKDFMKOutput,
                    @"§18: KDF_MK output is 32 bytes, got %lu", (unsigned long)encKey.length);

    NSDictionary *kdfMK1 = @{
        @"id"          : @"KDF-MK-1",
        @"kind"        : @"primitive",
        @"description" : @"§8.1 KDF_MK over a fixed message key: enc_key = HKDF(salt = Z32, ikm = "
                         @"MK, info = nuntius:MK:v4, L = 32). ONE derived value and no others — "
                         @"there is no HMAC key and no derived IV, because under an AEAD there is "
                         @"nothing left to MAC separately and the nonce is random and travels on "
                         @"the wire (§8.3). v3 derived three values from one message key by "
                         @"re-invoking a single label at three salts, with the 16-byte IV request "
                         @"silently widened by a library minimum; all of that is gone.",
        @"expect"      : @"ok",
        @"inputs"      : @{ @"MK" : kKDFMessageKey },
        @"intermediates" : @{
            @"salt" : IRVectorHex(IRPrimitiveZ32Data()),
            @"info" : IRVectorHex(IRPrimitiveMKLabel()),
        },
        @"outputs" : @{
            @"enc_key"     : IRVectorHex(IRPrimitiveDataFromSecret(encKey)),
            @"enc_key_len" : @(encKey.length),
        },
    };

    /* §15.3's table order. The order is part of the frozen bytes. */
    return @[
        rfc5869A1,
        rfc5869A2,
        rfc5869A3,
        hkdfSaltEquiv,
        hkdfExpand64,
        rfc7748,
        x25519Zero,
        rfc8032,
        seedExpand,
        rfc8439,
        kdfCK1,
        kdfRK1,
        kdfMK1,
    ];
}

#pragma mark - Executor

/**
 THE GUARD IS NOT DEFENSIVE PROGRAMMING, IT IS §13.4.

 A nil passed for a `_Nonnull` parameter is a caller contract violation that traps through
 IRRequireArgument — it is not an error code and it is not recoverable (§17.11 puts it outside the
 taxonomy and outside this suite entirely). A vector whose hex is the wrong width produces a nil
 nominal type, and passing that on would abort the whole test binary with a trap instead of
 reporting which vector was malformed. Every constructed value is therefore checked before it is
 handed to the implementation.

 `testCase` and `vectorCase` must be in scope, which they are in every executor below.
 */
#define IRPrimitiveGuard(value, ...)                                                               \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRVectorRecordFailure(testCase, __VA_ARGS__);                                          \
            [vectorCase finish];                                                                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#pragma mark RFC5869-A1 / A2 / A3

static void IRPrimitiveRunHKDFVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    /* Every input is read FIRST, so §15.5 rule 3's consumption bookkeeping is complete even on a
       path that then bails out. */
    NSData *ikmBytes = [vectorCase dataInput:@"ikm"];
    NSData *saltBytes = [vectorCase dataInput:@"salt"];
    NSData *info = [vectorCase dataInput:@"info"];
    uint32_t outputLength = [vectorCase uint32Input:@"L"];

    IRSecretBytes *ikm = IRPrimitiveSecretFromData(ikmBytes);
    IRPrimitiveGuard(ikm, @"[%@] ikm is empty; HKDF-Extract has no zero-length IKM case",
                     vectorCase.identifier);

    /* A ZERO-LENGTH SALT IS SPELLED nil, AND THAT IS NOT A SUBSTITUTION. §3.2: HMAC pads any key
       shorter than its 64-byte block with zeros, so an absent salt, an empty salt and Z32 are one
       HMAC key. HKDF-SALT-EQUIV is the vector that records it; RFC5869-A3 is the vector that
       exercises it. */
    IRSecretBytes *salt = IRPrimitiveSecretFromData(saltBytes);

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRSecretBytes *prk = [provider hkdfExtractWithSalt:salt ikm:ikm error:&error];
    IRPrimitiveGuard(prk, @"[%@] HKDF-Extract failed: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"PRK" data:IRPrimitiveDataFromSecret(prk)];

    IRSecretBytes *okm = [provider hkdfExpandWithPRK:prk
                                                info:info
                                        outputLength:(NSUInteger)outputLength
                                               error:&error];
    IRPrimitiveGuard(okm, @"[%@] HKDF-Expand failed: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"OKM" data:IRPrimitiveDataFromSecret(okm)];
    [vectorCase checkOutput:@"OKM_len" number:@(okm.length)];
    [vectorCase checkResultError:nil];

    /* §3.2's composition, checked rather than assumed: every protocol call site is the one-shot
       form, while the RFC publishes the intermediate PRK. A port whose one-shot disagrees with its
       own two-step has two HKDFs, and only one of them is under test anywhere else. */
    IRSecretBytes *oneShot = [provider hkdfWithSalt:salt
                                                ikm:ikm
                                               info:info
                                       outputLength:(NSUInteger)outputLength
                                              error:&error];
    if (oneShot == nil || ![oneShot isEqualToSecretBytes:okm]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] HKDF(salt, ikm, info, L) must equal "
                              @"Expand(Extract(salt, ikm), info, L): %@",
                              vectorCase.identifier,
                              oneShot ? IRVectorHex(IRPrimitiveDataFromSecret(oneShot)) : error);
    }

    [vectorCase finish];
}

#pragma mark HKDF-SALT-EQUIV

static void IRPrimitiveRunSaltEquivVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *ikmBytes = [vectorCase dataInput:@"ikm"];

    IRSecretBytes *ikm = IRPrimitiveSecretFromData(ikmBytes);
    IRPrimitiveGuard(ikm, @"[%@] ikm is empty", vectorCase.identifier);

    NSData *z32 = IRPrimitiveZ32Data();
    [vectorCase checkIntermediate:@"salt_Z32" data:z32];

    IRSecretBytes *z32Salt = IRPrimitiveSecretFromData(z32);
    IRPrimitiveGuard(z32Salt, @"[%@] cannot hold Z32 as a secret", vectorCase.identifier);

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRSecretBytes *withZ32 = [provider hkdfExtractWithSalt:z32Salt ikm:ikm error:&error];
    IRPrimitiveGuard(withZ32, @"[%@] HKDF-Extract(Z32, ikm): %@", vectorCase.identifier, error);

    IRSecretBytes *withEmpty = [provider hkdfExtractWithSalt:nil ikm:ikm error:&error];
    IRPrimitiveGuard(withEmpty, @"[%@] HKDF-Extract(empty, ikm): %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"PRK_with_Z32_salt" data:IRPrimitiveDataFromSecret(withZ32)];
    [vectorCase checkIntermediate:@"PRK_with_empty_salt" data:IRPrimitiveDataFromSecret(withEmpty)];

    if (![withZ32 isEqualToSecretBytes:withEmpty]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §3.2: Z32 and an empty salt MUST produce an identical PRK",
                              vectorCase.identifier);
    }

    [vectorCase checkOutput:@"PRK" data:IRPrimitiveDataFromSecret(withZ32)];
    [vectorCase checkOutput:@"PRK_len" number:@(withZ32.length)];
    [vectorCase checkResultError:nil];

    [vectorCase finish];
}

#pragma mark HKDF-EXPAND-64

static void IRPrimitiveRunExpand64Vector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *ikmBytes = [vectorCase dataInput:@"ikm"];
    NSData *saltBytes = [vectorCase dataInput:@"salt"];
    NSData *info = [vectorCase dataInput:@"info"];
    uint32_t outputLength = [vectorCase uint32Input:@"L"];

    IRSecretBytes *ikm = IRPrimitiveSecretFromData(ikmBytes);
    IRPrimitiveGuard(ikm, @"[%@] ikm is empty", vectorCase.identifier);

    IRSecretBytes *salt = IRPrimitiveSecretFromData(saltBytes);

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRSecretBytes *prk = [provider hkdfExtractWithSalt:salt ikm:ikm error:&error];
    IRPrimitiveGuard(prk, @"[%@] HKDF-Extract failed: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"PRK" data:IRPrimitiveDataFromSecret(prk)];

    IRSecretBytes *okm = [provider hkdfExpandWithPRK:prk
                                                info:info
                                        outputLength:(NSUInteger)outputLength
                                               error:&error];
    IRPrimitiveGuard(okm, @"[%@] HKDF-Expand(L = %u) failed: %@",
                     vectorCase.identifier, (unsigned)outputLength, error);

    if (okm.length != 64) {
        IRVectorRecordFailure(testCase, @"[%@] expected a 64-byte OKM, got %lu",
                              vectorCase.identifier, (unsigned long)okm.length);
        [vectorCase finish];
        return;
    }

    NSData *okmBytes = IRPrimitiveDataFromSecret(okm);
    NSData *t1 = [okmBytes subdataWithRange:NSMakeRange(0, 32)];
    NSData *t2 = [okmBytes subdataWithRange:NSMakeRange(32, 32)];

    [vectorCase checkIntermediate:@"T1" data:t1];
    [vectorCase checkIntermediate:@"T2" data:t2];

    /* The load-bearing pair. T(1) is shared with a 32-byte expansion, so an implementation that
       emits only the first block matches on the first assertion and fails on the second — which is
       exactly the shape of the bug §3.2 names, and exactly why both are checked. */
    IRSecretBytes *short32 = [provider hkdfExpandWithPRK:prk
                                                    info:info
                                            outputLength:(NSUInteger)kIRLenHMACSHA256
                                                   error:&error];
    IRPrimitiveGuard(short32, @"[%@] 32-byte HKDF-Expand failed: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"OKM_32" data:IRPrimitiveDataFromSecret(short32)];

    if (![t1 isEqualToData:IRPrimitiveDataFromSecret(short32)]) {
        IRVectorRecordFailure(testCase, @"[%@] T(1) must be identical whether L is 32 or 64",
                              vectorCase.identifier);
    }

    if ([t1 isEqualToData:t2]) {
        IRVectorRecordFailure(testCase, @"[%@] T(2) must be computed, not a repeat of T(1) (§3.2)",
                              vectorCase.identifier);
    }

    [vectorCase checkOutput:@"OKM" data:okmBytes];
    [vectorCase checkOutput:@"OKM_len" number:@(okmBytes.length)];
    [vectorCase checkResultError:nil];

    [vectorCase finish];
}

#pragma mark RFC7748-X25519

static void IRPrimitiveRunX25519Vector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *scalar1Bytes = [vectorCase dataInput:@"scalar_1"];
    NSData *u1Bytes = [vectorCase dataInput:@"u_1"];
    NSData *scalar2Bytes = [vectorCase dataInput:@"scalar_2"];
    NSData *u2Bytes = [vectorCase dataInput:@"u_2"];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    /* §4.2 — the clamp is applied UNCONDITIONALLY at construction, so the stored representation is
       normalized whatever the caller handed over. It changes no cryptographic output (RFC 7748 §5
       clamps internally), and it matters only because libsodium and CryptoKit store the raw bytes
       while BouncyCastle clamps at generation: without the rule two ports write different bytes at
       state-blob offsets 243 and 274 for cryptographically identical state. */
    IRX25519Private *scalar1 = [IRX25519Private fromData:scalar1Bytes guarded:NO error:&error];
    IRPrimitiveGuard(scalar1, @"[%@] scalar_1: %@", vectorCase.identifier, error);

    IRX25519Private *scalar2 = [IRX25519Private fromData:scalar2Bytes guarded:NO error:&error];
    IRPrimitiveGuard(scalar2, @"[%@] scalar_2: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"scalar_1_clamped" data:IRPrimitiveDataFromSecret(scalar1)];
    [vectorCase checkIntermediate:@"scalar_2_clamped" data:IRPrimitiveDataFromSecret(scalar2)];

    IRX25519Public *u1 = [IRX25519Public fromData:u1Bytes error:&error];
    IRPrimitiveGuard(u1, @"[%@] u_1: %@", vectorCase.identifier, error);

    IRSecretBytes *shared1 = [provider x25519WithPrivateKey:scalar1 publicKey:u1 error:&error];
    IRPrimitiveGuard(shared1, @"[%@] X25519 over vector 1: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"shared_1" data:IRPrimitiveDataFromSecret(shared1)];

    /* §4.4 CHECK 2. RFC 7748's second u-coordinate ends 0x93, so bit 255 is set, and that encoding
       MUST be refused BEFORE any scalar multiplication. The check exists because RFC 7748 §5 has
       X25519 ignore that bit: one key would otherwise have two wire encodings, and the transcript
       hash, SESSION_AD and the §7.6 skipped-key map key are all keyed on the raw bytes, so an
       attacker could mint a second distinct DHr for the same key and force spurious DH ratchets. */
    error = nil;
    IRX25519Public *u2Raw = [IRX25519Public fromData:u2Bytes error:&error];
    BOOL highBitRejected = (u2Raw == nil) && (error.code == IRErrorInvalidPublicKey);

    if (u2Raw != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §4.4 check 2: an encoding with pk[31] & 0x80 set was accepted",
                              vectorCase.identifier);
    } else if (!highBitRejected) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §4.4 check 2 rejected u_2 with %@ (%ld), expected "
                              @"ERR_INVALID_PUBLIC_KEY",
                              vectorCase.identifier, error.domain, (long)error.code);
    }

    [vectorCase checkOutput:@"u_2_high_bit_rejected" boolean:highBitRejected];

    if (u2Bytes.length != (NSUInteger)kIRLenX25519Public) {
        IRVectorRecordFailure(testCase, @"[%@] u_2 is %lu bytes, expected 32",
                              vectorCase.identifier, (unsigned long)u2Bytes.length);
        [vectorCase finish];
        return;
    }

    NSMutableData *maskedBytes = [u2Bytes mutableCopy];
    ((uint8_t *)maskedBytes.mutableBytes)[31] &= 0x7f;

    [vectorCase checkIntermediate:@"u_2_masked" data:maskedBytes];

    error = nil;
    IRX25519Public *u2Masked = [IRX25519Public fromData:maskedBytes error:&error];
    IRPrimitiveGuard(u2Masked, @"[%@] the masked u_2 was rejected too: %@",
                     vectorCase.identifier, error);

    IRSecretBytes *shared2 = [provider x25519WithPrivateKey:scalar2 publicKey:u2Masked error:&error];
    IRPrimitiveGuard(shared2, @"[%@] X25519 over vector 2: %@", vectorCase.identifier, error);

    /* AND THIS IS THE DEMONSTRATION RATHER THAN THE ASSERTION: the masked encoding — a DIFFERENT 32
       bytes from the one the RFC prints — reproduces the RFC's published output exactly, which is
       why two spellings of one key had to be refused at the boundary. */
    [vectorCase checkOutput:@"shared_2" data:IRPrimitiveDataFromSecret(shared2)];
    [vectorCase checkResultError:nil];

    [vectorCase finish];
}

#pragma mark X25519-ZERO

static void IRPrimitiveRunX25519ZeroVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *scalarBytes = [vectorCase dataInput:@"scalar"];
    NSArray *points = [vectorCase arrayInput:@"u_points"];

    IRX25519Private *scalar = [IRX25519Private fromData:scalarBytes guarded:NO error:&error];
    IRPrimitiveGuard(scalar, @"[%@] scalar: %@", vectorCase.identifier, error);

    if (points.count == 0) {
        IRVectorRecordFailure(testCase, @"[%@] u_points is empty; there is nothing to reject",
                              vectorCase.identifier);
        [vectorCase finish];
        return;
    }

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    for (id raw in points) {
        if (!IRVectorHexIsWellFormed(raw)) {
            IRVectorRecordFailure(testCase, @"[%@] malformed u_points entry: %@",
                                  vectorCase.identifier, raw);
            continue;
        }

        error = nil;
        IRX25519Public *point = [IRX25519Public fromData:IRVectorBytes(raw) error:&error];
        if (point == nil) {
            /* Every point in this vector has bit 255 clear, so §4.4 check 2 must not fire here. A
               point that failed check 2 would be rejected for the wrong reason and would make the
               vector agree with a port that never implemented check 3 at all. */
            IRVectorRecordFailure(testCase,
                                  @"[%@] %@ was refused at the type boundary (%ld); every point "
                                  @"here has bit 255 clear and must reach §4.4 check 3",
                                  vectorCase.identifier, raw, (long)error.code);
            continue;
        }

        error = nil;
        IRSecretBytes *shared = [provider x25519WithPrivateKey:scalar publicKey:point error:&error];

        if (shared != nil) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] the small-order point %@ produced %@ instead of being "
                                  @"rejected",
                                  vectorCase.identifier, raw,
                                  IRVectorHex(IRPrimitiveDataFromSecret(shared)));
            continue;
        }

        [vectorCase checkResultError:error];
    }

    /* §15.5 RULE 2, AND THIS IS THE CASE THE RULE WAS WRITTEN FOR. §15.3 requires the small-order
       input to "produce the all-zero output and be rejected", but §4.4 check 3 refuses BEFORE
       returning anything, so the all-zero output is not observable through any conformant API. It
       stays in the frozen file — where a port debugging its own accumulator can read it — and this
       runner declares the skip with a reason rather than silently ignoring the key. */
    [vectorCase skipIntermediate:@"dh_output_unchecked"
                         because:@"§4.4 check 3 rejects before the DH output is returned, so the "
                                 @"all-zero result is unobservable through a conformant API"];

    [vectorCase finish];
}

#pragma mark RFC8032-ED25519

static void IRPrimitiveRunEd25519Vector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    for (NSUInteger index = 1; index <= 4; index++) {
        NSError *error = nil;

        NSString *seedKey = [NSString stringWithFormat:@"seed_%lu", (unsigned long)index];
        NSString *messageKey = [NSString stringWithFormat:@"message_%lu", (unsigned long)index];
        NSString *publicKeyKey = [NSString stringWithFormat:@"public_key_%lu", (unsigned long)index];
        NSString *signatureKey = [NSString stringWithFormat:@"signature_%lu", (unsigned long)index];
        NSString *verifiedKey = [NSString stringWithFormat:@"verified_%lu", (unsigned long)index];

        NSData *seedBytes = [vectorCase dataInput:seedKey];
        /* A ZERO-LENGTH MESSAGE IS LEGAL AND IS RFC 8032 TEST 1. It arrives as an empty NSData,
           which is a real object with a real length — not nil, which §13.4 makes a trap rather
           than a value. */
        NSData *message = [vectorCase dataInput:messageKey];

        /* §15.5 RULE 8 — THE SIGNATURE IS AN INPUT. It is read here, verified below, and never
           compared against anything this process produces. */
        NSData *publishedSignatureBytes = [vectorCase dataInput:signatureKey];

        IREd25519Private *seed = [IREd25519Private fromData:seedBytes guarded:NO error:&error];
        IRPrimitiveGuard(seed, @"[%@] %@: %@", vectorCase.identifier, seedKey, error);

        /* §4.2 — the private key is the 32-byte SEED. A libsodium port MUST expand it with
           crypto_sign_seed_keypair; handing the seed straight to crypto_sign_detached reads 32
           bytes out of bounds, hashes whatever is adjacent into the RFC 8032 challenge, and
           surfaces as ERR_BAD_SIGNATURE — the code §1.2 defines to mean an active MITM. */
        IREd25519Public *publicKey = [provider ed25519PublicKeyForSeed:seed error:&error];
        IRPrimitiveGuard(publicKey, @"[%@] %@: %@", vectorCase.identifier, publicKeyKey, error);

        [vectorCase checkIntermediate:publicKeyKey data:publicKey.data];

        IREd25519Signature *publishedSignature =
            [IREd25519Signature fromData:publishedSignatureBytes error:&error];
        IRPrimitiveGuard(publishedSignature, @"[%@] %@: %@",
                         vectorCase.identifier, signatureKey, error);

        /* (a) A PREHASHED IMPLEMENTATION FAILS ON THIS LINE, and this is where the failure belongs.
           Ed25519ph is a different signature scheme, so a verifier wired to it rejects the RFC's own
           published signature — a verification failure in exactly the place failure is defined to
           mean an attack. What this line does NOT do is compare bytes: RFC 8032 §8.2 permits a
           randomized nonce, CryptoKit takes that option, and a byte comparison would fail a
           conformant port for no defect at all (§3.4, §15.5 rule 8). */
        BOOL verified = [provider ed25519VerifySignature:publishedSignature
                                               ofMessage:message
                                               publicKey:publicKey];
        [vectorCase checkOutput:verifiedKey boolean:verified];

        /* (b) The SHOULD half of rule 8: sign the message with this implementation and verify THAT
           signature. It exercises the signing path — including the seed expansion — without
           depending on its output being canonical, and the two signatures are never compared to
           each other. */
        IREd25519Signature *ownSignature = [provider ed25519SignMessage:message
                                                              withSeed:seed
                                                                 error:&error];
        IRPrimitiveGuard(ownSignature, @"[%@] signing %@ locally: %@",
                         vectorCase.identifier, messageKey, error);

        if (![provider ed25519VerifySignature:ownSignature
                                    ofMessage:message
                                    publicKey:publicKey]) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] this implementation produced a signature over %@ that it "
                                  @"cannot verify against its own public key; the signing path is "
                                  @"broken independently of whether its bytes match the RFC's",
                                  vectorCase.identifier, messageKey);
        }
    }

    [vectorCase checkResultError:nil];
    [vectorCase finish];
}

#pragma mark ED25519-SEED-EXPAND

static void IRPrimitiveRunSeedExpandVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *seedBytes = [vectorCase dataInput:@"seed"];
    NSData *message = [vectorCase dataInput:@"message"];

    /* §15.5 rule 8 — an INPUT, verified below and never compared against our own signing. */
    NSData *publishedSignatureBytes = [vectorCase dataInput:@"signature"];

    IREd25519Private *seed = [IREd25519Private fromData:seedBytes guarded:NO error:&error];
    IRPrimitiveGuard(seed, @"[%@] seed: %@", vectorCase.identifier, error);

    /* §4.2 — 32, never 64. The 64-byte libsodium expansion is `seed ‖ pk` and MUST NOT appear at
       any API boundary, in any nominal type, in any serialized structure, or in a vector file; a
       port that stored it here would leak the public key into what is supposed to be the private
       half and would silently change every state-blob offset downstream of it. */
    [vectorCase checkIntermediate:@"seed_len" number:@(seed.length)];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IREd25519Public *publicKey = [provider ed25519PublicKeyForSeed:seed error:&error];
    IRPrimitiveGuard(publicKey, @"[%@] public key from seed: %@", vectorCase.identifier, error);

    /* THE ONE BYTE-NORMATIVE ED25519 QUANTITY IN THE WHOLE SPECIFICATION. Seed → public key is
       deterministic and identical on libsodium, the JDK and CryptoKit (§3.4), and it is what makes
       an identity key portable at all; everything else about Ed25519 here is asserted verify-side. */
    [vectorCase checkOutput:@"public_key" data:publicKey.data];

    IREd25519Signature *publishedSignature =
        [IREd25519Signature fromData:publishedSignatureBytes error:&error];
    IRPrimitiveGuard(publishedSignature, @"[%@] signature: %@", vectorCase.identifier, error);

    BOOL verified = [provider ed25519VerifySignature:publishedSignature
                                           ofMessage:message
                                           publicKey:publicKey];
    [vectorCase checkOutput:@"verified" boolean:verified];
    [vectorCase checkResultError:nil];

    /* §15.5 rule 8's SHOULD: sign locally and verify that signature, exercising the seed expansion
       and the signing path without asserting anything about the bytes it produced. The frozen
       signature and this one are NEVER compared. */
    IREd25519Signature *ownSignature = [provider ed25519SignMessage:message
                                                          withSeed:seed
                                                             error:&error];
    IRPrimitiveGuard(ownSignature, @"[%@] local signature: %@", vectorCase.identifier, error);

    if (![provider ed25519VerifySignature:ownSignature ofMessage:message publicKey:publicKey]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] this implementation produced a signature it cannot verify "
                              @"against the public key it derived from the same seed",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark RFC8439-AEAD

static void IRPrimitiveRunAEADVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *keyBytes = [vectorCase dataInput:@"key"];
    NSData *nonceBytes = [vectorCase dataInput:@"nonce"];
    NSData *plaintext = [vectorCase dataInput:@"plaintext"];
    NSData *associatedData = [vectorCase dataInput:@"aad"];

    IRMessageEncKey *key = [IRMessageEncKey fromData:keyBytes guarded:NO error:&error];
    IRPrimitiveGuard(key, @"[%@] key: %@", vectorCase.identifier, error);

    IRNonce *nonce = [IRNonce fromData:nonceBytes error:&error];
    IRPrimitiveGuard(nonce, @"[%@] nonce: %@", vectorCase.identifier, error);

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    NSData *sealed = [provider aeadSealPlaintext:plaintext
                                             key:key
                                           nonce:nonce
                                  associatedData:associatedData
                                           error:&error];
    IRPrimitiveGuard(sealed, @"[%@] AEAD-Seal: %@", vectorCase.identifier, error);

    /* §8.2 — the tag is APPENDED, and len(sealed) is exactly len(pt) + 16 because ChaCha20 is a
       stream cipher with no padding. The RFC publishes the two halves separately, so both are
       carried as intermediates: a port whose tag is right and whose ciphertext is wrong, or the
       reverse, is told which. */
    if (sealed.length != plaintext.length + (NSUInteger)kIRLenAEADTag) {
        IRVectorRecordFailure(testCase, @"[%@] sealed length is %lu, expected %lu",
                              vectorCase.identifier, (unsigned long)sealed.length,
                              (unsigned long)(plaintext.length + (NSUInteger)kIRLenAEADTag));
        [vectorCase finish];
        return;
    }

    NSData *ciphertext = [sealed subdataWithRange:NSMakeRange(0, plaintext.length)];
    NSData *tag = [sealed subdataWithRange:NSMakeRange(plaintext.length,
                                                       (NSUInteger)kIRLenAEADTag)];

    [vectorCase checkIntermediate:@"ciphertext" data:ciphertext];
    [vectorCase checkIntermediate:@"tag" data:tag];

    [vectorCase checkOutput:@"ciphertext_and_tag" data:sealed];
    [vectorCase checkOutput:@"ciphertext_and_tag_len" number:@(sealed.length)];

    NSData *opened = [provider aeadOpenCiphertextAndTag:sealed
                                                    key:key
                                                  nonce:nonce
                                         associatedData:associatedData
                                                  error:&error];
    IRPrimitiveGuard(opened, @"[%@] AEAD-Open of our own sealing failed: %@",
                     vectorCase.identifier, error);

    [vectorCase checkOutput:@"opened_plaintext" data:opened];
    [vectorCase checkResultError:nil];

    [vectorCase finish];
}

#pragma mark KDF-CK-1

static void IRPrimitiveRunKDFCKVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *chainKeyBytes = [vectorCase dataInput:@"CK"];

    IRChainKey *chainKey = [IRChainKey fromData:chainKeyBytes guarded:NO error:&error];
    IRPrimitiveGuard(chainKey, @"[%@] CK: %@", vectorCase.identifier, error);

    /* §7.3 and §18 — the two message bytes, checked against what this implementation believes
       rather than merely restated. A port that carried v3's salt 0 / salt 1 numbering over
       diverges here instead of three layers up, where the symptom is an undecryptable message. */
    uint8_t messageKeyByte = 0x01;
    uint8_t chainKeyByte = 0x02;
    [vectorCase checkIntermediate:@"mk_input_byte"
                             data:[NSData dataWithBytes:&messageKeyByte length:1]];
    [vectorCase checkIntermediate:@"ck_input_byte"
                             data:[NSData dataWithBytes:&chainKeyByte length:1]];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRChainStep *step = [IRProtocolKDF deriveChainStepWithChainKey:chainKey
                                                          provider:provider
                                                             error:&error];
    IRPrimitiveGuard(step, @"[%@] KDF_CK: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"MK" data:IRPrimitiveDataFromSecret(step.messageKey)];
    [vectorCase checkOutput:@"CK_next" data:IRPrimitiveDataFromSecret(step.nextChainKey)];
    [vectorCase checkResultError:nil];

    /* §7.3's closing note, and it is not decoration: KDF_CK MUST NOT wipe its input. §7.6's
       SkipMessageKeys advances the receiving chain on a §7.7 snapshot that is discarded whenever
       the AEAD tag fails, so a KDF that zeroized CK would destroy the live session's CKr on every
       forged message — the desynchronisation DoS NEG-ATOMIC exists to catch. */
    if (![IRPrimitiveDataFromSecret(chainKey) isEqualToData:chainKeyBytes]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] KDF_CK mutated its input chain key; §7.3 forbids it and "
                              @"NEG-ATOMIC is the vector that would fail",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark KDF-RK-1

static void IRPrimitiveRunKDFRKVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *rootKeyBytes = [vectorCase dataInput:@"RK"];
    NSData *dhOutputBytes = [vectorCase dataInput:@"DH_out"];

    IRRootKey *rootKey = [IRRootKey fromData:rootKeyBytes guarded:NO error:&error];
    IRPrimitiveGuard(rootKey, @"[%@] RK: %@", vectorCase.identifier, error);

    IRSecretBytes *dhOutput = IRPrimitiveSecretFromData(dhOutputBytes);
    IRPrimitiveGuard(dhOutput, @"[%@] DH_out is empty", vectorCase.identifier);

    NSData *info = IRPrimitiveRKLabel();
    [vectorCase checkIntermediate:@"info" data:info];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    /* THE ARGUMENT ORDER IS THE VECTOR. -deriveRootStepWithRootKeyAsSalt:dhOutput: spells it in the
       selector so it cannot be written the wrong way round by accident here — but the frozen bytes
       are what hold the OTHER three ports to it, and OKM_if_salt_and_ikm_swapped below is what
       tells a failing port which of the two mistakes it made. */
    IRRootChainStep *step = [IRProtocolKDF deriveRootStepWithRootKeyAsSalt:rootKey
                                                                  dhOutput:dhOutput
                                                                  provider:provider
                                                                     error:&error];
    IRPrimitiveGuard(step, @"[%@] KDF_RK: %@", vectorCase.identifier, error);

    IRSecretBytes *okm = [provider hkdfWithSalt:rootKey
                                            ikm:dhOutput
                                           info:info
                                   outputLength:(NSUInteger)kIRLenKDFRKOutput
                                          error:&error];
    IRPrimitiveGuard(okm, @"[%@] the 64-byte OKM: %@", vectorCase.identifier, error);

    NSData *okmBytes = IRPrimitiveDataFromSecret(okm);
    [vectorCase checkIntermediate:@"OKM" data:okmBytes];
    [vectorCase checkIntermediate:@"OKM_len" number:@(okmBytes.length)];

    IRSecretBytes *swapped = [provider hkdfWithSalt:dhOutput
                                                ikm:rootKey
                                               info:info
                                       outputLength:(NSUInteger)kIRLenKDFRKOutput
                                              error:&error];
    IRPrimitiveGuard(swapped, @"[%@] the swapped-argument OKM: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"OKM_if_salt_and_ikm_swapped"
                             data:IRPrimitiveDataFromSecret(swapped)];

    if ([swapped isEqualToSecretBytes:okm]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] the swapped OKM equals the correct one, so this vector cannot "
                              @"detect the swap it exists to detect",
                              vectorCase.identifier);
    }

    if (okmBytes.length == 64) {
        if (![[okmBytes subdataWithRange:NSMakeRange(0, 32)]
                isEqualToData:IRPrimitiveDataFromSecret(step.rootKey)]) {
            IRVectorRecordFailure(testCase, @"[%@] §7.2: RK-next must be okm[0..32)",
                                  vectorCase.identifier);
        }

        if (![[okmBytes subdataWithRange:NSMakeRange(32, 32)]
                isEqualToData:IRPrimitiveDataFromSecret(step.chainKey)]) {
            IRVectorRecordFailure(testCase, @"[%@] §7.2: CK must be okm[32..64)",
                                  vectorCase.identifier);
        }
    }

    [vectorCase checkOutput:@"RK_next" data:IRPrimitiveDataFromSecret(step.rootKey)];
    [vectorCase checkOutput:@"CK" data:IRPrimitiveDataFromSecret(step.chainKey)];
    [vectorCase checkResultError:nil];

    /* §7.2's zeroization note: neither argument is touched. The caller owns the old root key's
       wipe, and §13.3 places it at the moment its successor replaces it in COMMITTED state — not
       when this call returns, because a §7.7 snapshot that is later discarded must leave the live
       root key intact. */
    if (![IRPrimitiveDataFromSecret(rootKey) isEqualToData:rootKeyBytes]) {
        IRVectorRecordFailure(testCase, @"[%@] KDF_RK mutated its root key argument",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark KDF-MK-1

static void IRPrimitiveRunKDFMKVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSError *error = nil;

    NSData *messageKeyBytes = [vectorCase dataInput:@"MK"];

    IRMessageKey *messageKey = [IRMessageKey fromData:messageKeyBytes guarded:NO error:&error];
    IRPrimitiveGuard(messageKey, @"[%@] MK: %@", vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"salt" data:IRPrimitiveZ32Data()];
    [vectorCase checkIntermediate:@"info" data:IRPrimitiveMKLabel()];

    id<IRCryptoProvider> provider = IRVectorAmbientProvider();

    IRMessageEncKey *encKey = [IRProtocolKDF expandMessageKey:messageKey
                                                     provider:provider
                                                        error:&error];
    IRPrimitiveGuard(encKey, @"[%@] KDF_MK: %@", vectorCase.identifier, error);

    [vectorCase checkOutput:@"enc_key" data:IRPrimitiveDataFromSecret(encKey)];
    [vectorCase checkOutput:@"enc_key_len" number:@(encKey.length)];
    [vectorCase checkResultError:nil];

    /* §8.1 — the message key is NOT wiped here, and the consequence is sharper than for KDF_CK: a
       key drawn from the §7.6 skipped store is expanded BEFORE the AEAD runs, and NEG-SKIP-RETAIN
       requires a corrupted tag to leave that stored key intact so a later correct delivery still
       succeeds. Wiping here fails that vector. */
    if (![IRPrimitiveDataFromSecret(messageKey) isEqualToData:messageKeyBytes]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] KDF_MK mutated its message key argument; §8.1 forbids it and "
                              @"NEG-SKIP-RETAIN is the vector that would fail",
                              vectorCase.identifier);
    }

    [vectorCase finish];
}

#pragma mark - Dispatch

void IRRunPrimitiveVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    if (![vectorCase.kind isEqualToString:@"primitive"]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] kind is \"%@\"; primitives.json carries only \"primitive\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    NSString *identifier = vectorCase.identifier;

    if ([identifier hasPrefix:@"RFC5869-"]) {
        IRPrimitiveRunHKDFVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"HKDF-SALT-EQUIV"]) {
        IRPrimitiveRunSaltEquivVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"HKDF-EXPAND-64"]) {
        IRPrimitiveRunExpand64Vector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"RFC7748-X25519"]) {
        IRPrimitiveRunX25519Vector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"X25519-ZERO"]) {
        IRPrimitiveRunX25519ZeroVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"RFC8032-ED25519"]) {
        IRPrimitiveRunEd25519Vector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"ED25519-SEED-EXPAND"]) {
        IRPrimitiveRunSeedExpandVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"RFC8439-AEAD"]) {
        IRPrimitiveRunAEADVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"KDF-CK-1"]) {
        IRPrimitiveRunKDFCKVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"KDF-RK-1"]) {
        IRPrimitiveRunKDFRKVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"KDF-MK-1"]) {
        IRPrimitiveRunKDFMKVector(testCase, vectorCase);
    } else {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is exactly
           what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase, @"[%@] primitives.json has no executor for this id",
                              identifier);
    }
}
