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
 nuntius v4 protocol constants — SPEC §18, §3.1, §5.1, §5.2, §5.4, §6.2, §6.3, §6.5, §7.6, §9,
 §10.4, §11.1, §12.1.

 NOTHING ELSE IN THIS FRAMEWORK MAY HARD-CODE A LENGTH OR AN OFFSET. Every value here is frozen
 by SPEC §15.6 and is normative for the Java, Kotlin and Swift ports; the `_Static_assert` block in
 IRProtocolConstants.m proves each derived length against its field decomposition at compile time,
 so the table is checked by the compiler rather than by review.

 ASCII literals are declared as SIZED BYTE ARRAYS, never as `NSString` or `char *`. SPEC §3.1
 requires that every literal be passed with an explicit length and forbids `strlen` on a literal
 embedded in a longer buffer; a `uint8_t[N]` with no NUL terminator makes that mistake
 inexpressible.

 ALL MULTI-BYTE INTEGERS IN THIS PROTOCOL ARE BIG-ENDIAN (§3.1). No implementation may `memcpy` a
 native integer into a protocol buffer; use IRByteWriter / IRByteReader.
 */

#pragma mark - Compile-time assertion

#if defined(__has_feature)
#  if __has_feature(c_static_assert)
#    define IR_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#  endif
#endif
#ifndef IR_STATIC_ASSERT
#  define IR_CONCAT_INNER(a, b) a##b
#  define IR_CONCAT(a, b) IR_CONCAT_INNER(a, b)
#  define IR_STATIC_ASSERT(cond, msg) typedef char IR_CONCAT(IRStaticAssert_, __COUNTER__)[(cond) ? 1 : -1]
#endif

#pragma mark - ASCII literals

/// "nuntius:IKBIND:v4" — §5.1 IKBIND_MSG prefix.
extern const uint8_t kIRLabelIKBind[17];
/// "nuntius:SPK:v4" — §5.2 SPK_SIGN_MSG prefix.
extern const uint8_t kIRLabelSPK[14];
/// "nuntius:X3DH:transcript:v4" — §6.2 TRANSCRIPT prefix.
extern const uint8_t kIRLabelTranscript[26];
/// "nuntius:X3DH:v4" — §6.3 X3DH HKDF info prefix.
extern const uint8_t kIRLabelX3DH[15];
/// "nuntius:RK:v4" — §7.2 KDF_RK info.
extern const uint8_t kIRLabelRK[13];
/// "nuntius:MK:v4" — §8.1 KDF_MK info.
extern const uint8_t kIRLabelMK[13];
/// "nuntius:AD:v4" — §6.5 SESSION_AD prefix.
extern const uint8_t kIRLabelAD[13];
/// "nuntius:FP:v4" — §5.5 fingerprint prefix.
extern const uint8_t kIRLabelFP[13];
/// "NTB4" — §5.4 prekey bundle magic.
extern const uint8_t kIRBundleMagic[4];
/// "NTS4" — §12.1 session state magic.
extern const uint8_t kIRStateMagic[4];

#pragma mark - Byte constants

/// 32 × 0xFF — the X3DH Curve25519 domain separator, §6.3.
extern const uint8_t kIRF32[32];
/// 32 × 0x00 — the default HKDF salt, §3.2 / §6.3 / §8.1.
extern const uint8_t kIRZ32[32];

#pragma mark - Protocol enumerations

/// §9 — the message type byte at offset 1. It alone selects the header length.
typedef NS_ENUM(uint8_t, IRMessageType) {
    IRMessageTypeNormal = 0x01,
    IRMessageTypePrekey = 0x02,
};

/// §6.5, §12.1 — A is ALWAYS the initiator and B ALWAYS the responder in SESSION_AD, fixed at
/// handshake time and never reordered. The state blob stores this byte precisely so a restored
/// session cannot recompute SESSION_AD as (self, peer).
typedef NS_ENUM(uint8_t, IRSessionRole) {
    IRSessionRoleInitiator = 0x01,
    IRSessionRoleResponder = 0x02,
};

/// §9.2 offset 168, §6.2 — whether a one-time prekey participates in the handshake.
typedef NS_ENUM(uint8_t, IROPKFlag) {
    IROPKFlagAbsent  = 0x00,
    IROPKFlagPresent = 0x01,
};

/// §12.1 — the `_present` discriminators. Readers MUST branch on this byte, never on whether the
/// payload bytes happen to be zero.
typedef NS_ENUM(uint8_t, IRPresenceFlag) {
    IRPresenceFlagAbsent  = 0x00,
    IRPresenceFlagPresent = 0x01,
};

/// §18 — single-valued protocol bytes.
typedef NS_ENUM(uint8_t, IRProtocolByte) {
    /// §9 — byte 0 of every message. v3 traffic begins 0x03 and is rejected by §10.6.
    kIRProtocolVersion = 0x04,
    /// §12.1 — state blob format discriminator.
    kIRStateFormat = 0x01,
    /// §7.3 — KDF_CK message-key input: MK = HMAC(CK, 0x01).
    kIRKDFCKMessageKeyInput = 0x01,
    /// §7.3 — KDF_CK chain-key input: CK' = HMAC(CK, 0x02).
    kIRKDFCKChainKeyInput = 0x02,
};

/**
 §18 — the frozen numeric constant table: primitive widths, derived structure lengths, every field
 offset, and every protocol bound.

 One enumeration type deliberately holds all three groups. Splitting lengths from offsets makes
 expressions such as `kIROffType01Nonce + kIRLenNonce` arithmetic between two distinct enumeration
 types, which clang diagnoses under -Wenum-enum-conversion; a single type keeps every offset/length
 expression well-formed while remaining an integer constant expression usable in _Static_assert,
 in array bounds, and in switch labels.
 */
typedef NS_ENUM(NSUInteger, IRProtocolConstant) {

#pragma mark Primitive widths

    /// §4.2 — raw 32-byte little-endian u-coordinate, RFC 7748.
    kIRLenX25519Public = 32,
    /// §4.2 — 32-byte scalar, stored CLAMPED.
    kIRLenX25519Private = 32,
    /// §4.2 — raw 32-byte encoding, RFC 8032 §5.1.2.
    kIRLenEd25519Public = 32,
    /// §4.2 — the RFC 8032 SEED. NEVER libsodium's 64-byte expanded `sk` (§3.4).
    kIRLenEd25519Private = 32,
    /// §4.2 — raw 64-byte encoding, RFC 8032 §5.1.6.
    kIRLenEd25519Signature = 64,
    /// §8.2 — ChaCha20-Poly1305 IETF nonce. The 8-byte non-IETF variant is banned (§3.3).
    kIRLenNonce = 12,
    /// §8.2 — Poly1305 tag.
    kIRLenAEADTag = 16,
    /// §3.2 — SHA-256 output.
    kIRLenSHA256 = 32,
    /// §3.2 — HMAC-SHA256 output.
    kIRLenHMACSHA256 = 32,
    /// §3.2 — HKDF-Extract output (the PRK).
    kIRLenHKDFPRK = 32,
    /// §4.4 check 3 — X25519 output width.
    kIRLenDHOutput = 32,
    /// §7.1
    kIRLenRootKey = 32,
    /// §7.1
    kIRLenChainKey = 32,
    /// §7.3
    kIRLenMessageKey = 32,
    /// §8.1
    kIRLenMessageEncKey = 32,
    /// §5.5
    kIRLenFingerprint = 32,
    /// §3.1
    kIRLenZ32 = 32,
    /// §3.1
    kIRLenF32 = 32,

#pragma mark Literal widths

    kIRLenLabelIKBind = 17,
    kIRLenLabelSPK = 14,
    kIRLenLabelTranscript = 26,
    kIRLenLabelX3DH = 15,
    kIRLenLabelRK = 13,
    kIRLenLabelMK = 13,
    kIRLenLabelAD = 13,
    kIRLenLabelFP = 13,
    kIRLenMagic = 4,

#pragma mark Derived structure lengths - every one asserted in IRProtocolConstants.m

    /// §5.1 — 17 + 32 + 32.
    kIRLenIKBindMsg = 81,
    /// §5.2 — 14 + 32 + 32 + 4 + 32 + 8 + 8.
    kIRLenSPKSignMsg = 130,
    /// §6.2 — 26 + 32*6 + 4 + 1 + 4 + 32. ALWAYS 259, in both the OPK and no-OPK cases.
    kIRLenTranscript = 259,
    /// §6.2 — SHA256(TRANSCRIPT).
    kIRLenTH = 32,
    /// §6.3 — "nuntius:X3DH:v4" ‖ TH.
    kIRLenX3DHInfo = 47,
    /// §6.3 — F32 ‖ DH1 ‖ DH2 ‖ DH3, opk_flag == 0x00.
    kIRLenIKMNoOPK = 128,
    /// §6.3 — F32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4, opk_flag == 0x01.
    kIRLenIKMOPK = 160,
    /// §6.3 — the X3DH output; seeds the ratchet root key.
    kIRLenSK = 32,
    /// §6.5 — 13 + 32*4. Stored verbatim in state and prefixed to EVERY AEAD associated data.
    kIRLenSessionAD = 141,
    /// §5.5 — 13 + 32 + 32.
    kIRLenFPInput = 77,
    /// §7.2 — RK' ‖ CK. Spans two HKDF-Expand blocks; see §3.2's note.
    kIRLenKDFRKOutput = 64,
    /// §8.1
    kIRLenKDFMKOutput = 32,
    /// §9.1 — 1 + 1 + 2 + 32 + 4 + 4 + 12.
    kIRLenType01Header = 56,
    /// §9.1 — SESSION_AD ‖ msg[0..56).
    kIRLenType01AD = 197,
    /// §10.1 check 1 — header + empty plaintext + tag. Empty plaintext is LEGAL (§10.4).
    kIRLenType01Min = 72,
    /// §10.1 check 2 — 56 + 2^24 + 16.
    kIRLenType01Max = 16777288,
    /// §9.2 — 1 + 1 + 2 + 32 + 32 + 64 + 32 + 4 + 1 + 4 + 32 + 4 + 4 + 12.
    kIRLenType02Header = 225,
    /// §9.2 — SESSION_AD ‖ msg[0..225).
    kIRLenType02AD = 366,
    /// §10.2 check 1 — 225 + 0 + 16.
    kIRLenType02Min = 241,
    /// §10.2 check 2 — 225 + 2^24 + 16.
    kIRLenType02Max = 16777457,
    /// §5.4 — 4 + 1 + 32 + 32 + 64 + 4 + 32 + 8 + 8 + 64 + 2.
    kIRLenBundlePrefix = 251,
    /// §5.4 — opk_id (4) ‖ OPK (32). Widening this breaks the total-length rule in every port.
    kIRLenBundleOPKEntry = 36,
    /// §12.1 — 4+1+1+141+64+32+32+32+1+32+1+32+1+32+4+4+4+8+1+41+4.
    kIRLenStatePrefix = 472,
    /// §12.1 — dh_pub (32) ‖ N (4) ‖ mk (32) ‖ inserted_at_ms (8).
    kIRLenStateSkippedEntry = 76,
    /// §12.1 — EK_A_pub (32) ‖ spk_id (4) ‖ opk_flag (1) ‖ opk_id (4).
    kIRLenStatePrologue = 41,
    /// §7.6 — the raw store key DHr_pub (32) ‖ uint32_be(N) (4). Not base64, not separator-joined.
    kIRLenSkippedMapKey = 36,
    /// §11.1 — IK_A^d (32) ‖ EK_A (32).
    kIRLenHandshakeId = 64,

    /// Global routing floor: no message of EITHER type can be shorter, so check 1 of whichever
    /// gate applies would have fired. Lets a host that holds bytes but not a type read msg[1]
    /// safely without pre-empting either gate's ordering.
    kIRLenMessageMin = 72,
    /// Global routing cap: the LOOSER of the two check-2 caps. The tighter type-0x01 cap is
    /// applied inside that gate at its own position 2.
    kIRLenMessageMax = 16777457,

#pragma mark Type 0x01 field offsets

    kIROffType01Version = 0,
    kIROffType01Type = 1,
    kIROffType01Flags = 2,
    kIROffType01DHs = 4,
    kIROffType01N = 36,
    kIROffType01PN = 40,
    kIROffType01Nonce = 44,
    kIROffType01Ciphertext = 56,

#pragma mark Type 0x02 field offsets

    kIROffType02Version = 0,
    kIROffType02Type = 1,
    kIROffType02Flags = 2,
    kIROffType02IdentitySigning = 4,       // IK_A^s
    kIROffType02IdentityAgreement = 36,    // IK_A^d
    kIROffType02IKB = 68,                  // IKB_A
    kIROffType02EK = 132,                  // EK_A
    kIROffType02SPKId = 164,
    kIROffType02OPKFlag = 168,
    kIROffType02OPKId = 169,
    kIROffType02DHs = 173,
    kIROffType02N = 205,
    kIROffType02PN = 209,
    kIROffType02Nonce = 213,
    kIROffType02Ciphertext = 225,

#pragma mark Prekey bundle offsets

    kIROffBundleMagic = 0,
    kIROffBundleVersion = 4,
    kIROffBundleIdentitySigning = 5,       // IK^s
    kIROffBundleIdentityAgreement = 37,    // IK^d
    kIROffBundleIKB = 69,
    kIROffBundleSPKId = 133,
    kIROffBundleSPK = 137,
    kIROffBundleNotBefore = 169,
    kIROffBundleNotAfter = 177,
    kIROffBundleSPKSig = 185,
    kIROffBundleOPKCount = 249,
    kIROffBundleOPKEntries = 251,
    /// Within one 36-byte OPK entry.
    kIROffBundleOPKEntryId = 0,
    kIROffBundleOPKEntryKey = 4,

#pragma mark SESSION_AD sub-offsets

    kIROffSessionADLabel = 0,
    kIROffSessionADInitiatorSigning = 13,     // IK_A^s
    kIROffSessionADInitiatorAgreement = 45,   // IK_A^d
    kIROffSessionADResponderSigning = 77,     // IK_B^s
    kIROffSessionADResponderAgreement = 109,  // IK_B^d
    /// §6.5 — the PEER identity pair is SESSION_AD[77..141) when role == initiator and
    /// SESSION_AD[13..77) when role == responder. §11.1 keys the single-live-session invariant
    /// on that pair.
    kIROffSessionADInitiatorPair = 13,
    kIROffSessionADResponderPair = 77,
    /// Width of one identity pair (IK^s ‖ IK^d) inside SESSION_AD.
    kIRLenIdentityPair = 64,

#pragma mark State blob offsets

    kIROffStateMagic = 0,
    kIROffStateFormat = 4,
    kIROffStateRole = 5,
    kIROffStateSessionAD = 6,
    kIROffStateHandshakeId = 147,
    kIROffStateRK = 211,
    kIROffStateDHsPriv = 243,
    kIROffStateDHsPub = 275,
    kIROffStateDHrPresent = 307,
    kIROffStateDHrPub = 308,
    kIROffStateCKsPresent = 340,
    kIROffStateCKs = 341,
    kIROffStateCKrPresent = 373,
    kIROffStateCKr = 374,
    kIROffStateNs = 406,
    kIROffStateNr = 410,
    kIROffStatePN = 414,
    kIROffStateSendCounter = 418,
    kIROffStateProloguePresent = 426,
    kIROffStatePrologue = 427,
    kIROffStateSkippedCount = 468,
    kIROffStateSkippedEntries = 472,

    /// §6.5 — the identity keys as they land in the blob (kIROffStateSessionAD + the SESSION_AD
    /// sub-offset). Stated normatively so the stored bytes are readable rather than opaque;
    /// neither identity key is duplicated elsewhere in the blob.
    kIROffStateInitiatorSigning = 19,
    kIROffStateInitiatorAgreement = 51,
    kIROffStateResponderSigning = 83,
    kIROffStateResponderAgreement = 115,

    /// Within the 41-byte prologue block.
    kIROffPrologueEK = 0,
    kIROffPrologueSPKId = 32,
    kIROffPrologueOPKFlag = 36,
    kIROffPrologueOPKId = 37,

    /// Within one 76-byte skipped entry.
    kIROffSkippedEntryDHPub = 0,
    kIROffSkippedEntryN = 32,
    kIROffSkippedEntryMK = 36,
    kIROffSkippedEntryInsertedAtMs = 68,

    /// §12.2 rule 8 — the two bytes of DHs_priv the clamp check inspects, as blob offsets.
    kIROffStateDHsPrivFirstByte = 243,
    kIROffStateDHsPrivLastByte = 274,

#pragma mark TRANSCRIPT offsets

    kIROffTranscriptLabel = 0,
    kIROffTranscriptInitiatorSigning = 26,     // IK_A^s
    kIROffTranscriptInitiatorAgreement = 58,   // IK_A^d
    kIROffTranscriptEK = 90,                   // EK_A
    kIROffTranscriptResponderSigning = 122,    // IK_B^s
    kIROffTranscriptResponderAgreement = 154,  // IK_B^d
    kIROffTranscriptSPK = 186,
    kIROffTranscriptSPKId = 218,
    kIROffTranscriptOPKFlag = 222,
    kIROffTranscriptOPKId = 223,
    kIROffTranscriptOPK = 227,

#pragma mark IKBIND_MSG / SPK_SIGN_MSG / FP / IKM / info / handshake_id offsets

    kIROffIKBindLabel = 0,
    kIROffIKBindSigning = 17,
    kIROffIKBindAgreement = 49,

    kIROffSPKSignLabel = 0,
    kIROffSPKSignSigning = 14,
    kIROffSPKSignAgreement = 46,
    kIROffSPKSignSPKId = 78,
    kIROffSPKSignSPK = 82,
    kIROffSPKSignNotBefore = 114,
    kIROffSPKSignNotAfter = 122,

    kIROffFPLabel = 0,
    kIROffFPSigning = 13,
    kIROffFPAgreement = 45,

    kIROffIKMSeparator = 0,
    kIROffIKMDH1 = 32,
    kIROffIKMDH2 = 64,
    kIROffIKMDH3 = 96,
    kIROffIKMDH4 = 128,

    kIROffX3DHInfoLabel = 0,
    kIROffX3DHInfoTH = 15,

    kIROffHandshakeIdIdentityAgreement = 0,   // IK_A^d
    kIROffHandshakeIdEK = 32,                 // EK_A

    kIROffSkippedMapKeyDHPub = 0,
    kIROffSkippedMapKeyN = 32,

#pragma mark Bounds

    /// §10.4 — 2^24 bytes = 16 MiB. Bounds MUST be checked BEFORE any allocation sized from input.
    kIRMaxPlaintext = 16777216,
    /// §7.6 — maximum keys a SINGLE received message may cause to be derived, summed across BOTH
    /// SkipMessageKeys calls in that message's processing. Deliberately an aggregate, not a
    /// per-call bound: a per-call 1000 would permit 2000 derivations per message.
    kIRMaxSkipPerMessage = 1000,
    /// §7.6 — maximum entries in the skipped store across the whole session. Global FIFO eviction.
    kIRMaxSkippedStored = 2000,
    /// §7.6 — 7 days.
    kIRSkippedTTLMs = 604800000,
    /// §11.4 — 7 days; the handshake_id tombstone window.
    kIRHandshakeCacheMs = 604800000,
    /// §10.1 checks 9–10, §10.2 check 9.
    kIRMaxCounter = 0x7FFFFFFF,
    /// §5.3 rule 6 — 90 days.
    kIRMaxSPKValiditySeconds = 7776000,
    /// §5.3 — responder-local unconsumed-OPK lifetime. NOT a wire field.
    kIROPKMaxAgeSeconds = 7776000,
    /// §5.4, §10.3 check 4.
    kIRMaxBundleOPKCount = 1000,
    /// §10.3 check 1 — identical to the bundle fixed prefix.
    kIRMinBundleLength = 251,
};
