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

#import "IRProtocolConstants.h"

#pragma mark - ASCII literals

/*
 Each literal is written as its SPEC Sec 18 hex encoding rather than as a C string, so the bytes in
 this file are the bytes the specification names. There is no NUL terminator and no length prefix
 (Sec 3.1); the companion length constant is asserted against sizeof below.
 */

/* "nuntius:IKBIND:v4" */
const uint8_t kIRLabelIKBind[17] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x49, 0x4b, 0x42, 0x49, 0x4e, 0x44, 0x3a, 0x76,
    0x34
};

/* "nuntius:SPK:v4" */
const uint8_t kIRLabelSPK[14] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x53, 0x50, 0x4b, 0x3a, 0x76, 0x34
};

/* "nuntius:X3DH:transcript:v4" */
const uint8_t kIRLabelTranscript[26] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x58, 0x33, 0x44, 0x48, 0x3a, 0x74, 0x72, 0x61,
    0x6e, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3a, 0x76, 0x34
};

/* "nuntius:X3DH:v4" */
const uint8_t kIRLabelX3DH[15] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x58, 0x33, 0x44, 0x48, 0x3a, 0x76, 0x34
};

/* "nuntius:RK:v4" */
const uint8_t kIRLabelRK[13] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x52, 0x4b, 0x3a, 0x76, 0x34
};

/* "nuntius:MK:v4" */
const uint8_t kIRLabelMK[13] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x4d, 0x4b, 0x3a, 0x76, 0x34
};

/* "nuntius:AD:v4" */
const uint8_t kIRLabelAD[13] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x41, 0x44, 0x3a, 0x76, 0x34
};

/* "nuntius:FP:v4" */
const uint8_t kIRLabelFP[13] = {
    0x6e, 0x75, 0x6e, 0x74, 0x69, 0x75, 0x73, 0x3a, 0x46, 0x50, 0x3a, 0x76, 0x34
};

/* "NTB4" */
const uint8_t kIRBundleMagic[4] = { 0x4e, 0x54, 0x42, 0x34 };

/* "NTS4" */
const uint8_t kIRStateMagic[4] = { 0x4e, 0x54, 0x53, 0x34 };

const uint8_t kIRF32[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const uint8_t kIRZ32[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#pragma mark - Literal widths

IR_STATIC_ASSERT(sizeof(kIRLabelIKBind)     == kIRLenLabelIKBind,     "IKBIND label is not 17 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelSPK)        == kIRLenLabelSPK,        "SPK label is not 14 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelTranscript) == kIRLenLabelTranscript, "transcript label is not 26 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelX3DH)       == kIRLenLabelX3DH,       "X3DH label is not 15 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelRK)         == kIRLenLabelRK,         "RK label is not 13 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelMK)         == kIRLenLabelMK,         "MK label is not 13 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelAD)         == kIRLenLabelAD,         "AD label is not 13 bytes");
IR_STATIC_ASSERT(sizeof(kIRLabelFP)         == kIRLenLabelFP,         "FP label is not 13 bytes");
IR_STATIC_ASSERT(sizeof(kIRBundleMagic)     == kIRLenMagic,           "bundle magic is not 4 bytes");
IR_STATIC_ASSERT(sizeof(kIRStateMagic)      == kIRLenMagic,           "state magic is not 4 bytes");
IR_STATIC_ASSERT(sizeof(kIRF32)             == kIRLenF32,             "F32 is not 32 bytes");
IR_STATIC_ASSERT(sizeof(kIRZ32)             == kIRLenZ32,             "Z32 is not 32 bytes");

#pragma mark - Derived lengths proved against their field decomposition

/*
 SPEC Sec 12.2's implementer note, generalized to every row of the Sec 18 derived-length table:
 "derive the value from the field table above and confirm it against the constant". These are the
 compiler's proof. An error in any one of them would make every conformant implementation reject
 every other's bytes, and Sec 15.6 freezes them before the ports are written.
 */

/* Sec 5.1 IKBIND_MSG = label(17) || IK^s(32) || IK^d(32) */
IR_STATIC_ASSERT(kIRLenIKBindMsg ==
                 kIRLenLabelIKBind + kIRLenEd25519Public + kIRLenX25519Public,
                 "IKBIND_MSG != 81");
IR_STATIC_ASSERT(kIRLenIKBindMsg == 81, "IKBIND_MSG != 81");
IR_STATIC_ASSERT(kIROffIKBindSigning   == kIROffIKBindLabel   + kIRLenLabelIKBind,   "IKBIND IK^s offset");
IR_STATIC_ASSERT(kIROffIKBindAgreement == kIROffIKBindSigning + kIRLenEd25519Public, "IKBIND IK^d offset");
IR_STATIC_ASSERT(kIROffIKBindAgreement + kIRLenX25519Public == kIRLenIKBindMsg,      "IKBIND total");

/* Sec 5.2 SPK_SIGN_MSG = label(14) || IK^s(32) || IK^d(32) || spk_id(4) || SPK(32) || nb(8) || na(8) */
IR_STATIC_ASSERT(kIRLenSPKSignMsg ==
                 kIRLenLabelSPK + kIRLenEd25519Public + kIRLenX25519Public + 4 +
                 kIRLenX25519Public + 8 + 8,
                 "SPK_SIGN_MSG != 130");
IR_STATIC_ASSERT(kIRLenSPKSignMsg == 130, "SPK_SIGN_MSG != 130");
IR_STATIC_ASSERT(kIROffSPKSignSigning   == kIROffSPKSignLabel     + kIRLenLabelSPK,      "SPK_SIGN IK^s offset");
IR_STATIC_ASSERT(kIROffSPKSignAgreement == kIROffSPKSignSigning   + kIRLenEd25519Public, "SPK_SIGN IK^d offset");
IR_STATIC_ASSERT(kIROffSPKSignSPKId     == kIROffSPKSignAgreement + kIRLenX25519Public,  "SPK_SIGN spk_id offset");
IR_STATIC_ASSERT(kIROffSPKSignSPK       == kIROffSPKSignSPKId     + 4,                   "SPK_SIGN SPK offset");
IR_STATIC_ASSERT(kIROffSPKSignNotBefore == kIROffSPKSignSPK       + kIRLenX25519Public,  "SPK_SIGN not_before offset");
IR_STATIC_ASSERT(kIROffSPKSignNotAfter  == kIROffSPKSignNotBefore + 8,                   "SPK_SIGN not_after offset");
IR_STATIC_ASSERT(kIROffSPKSignNotAfter  + 8 == kIRLenSPKSignMsg,                         "SPK_SIGN total");

/* Sec 6.2 TRANSCRIPT = label(26) || 6 x 32 || spk_id(4) || opk_flag(1) || opk_id(4) || OPK(32) */
IR_STATIC_ASSERT(kIRLenTranscript ==
                 kIRLenLabelTranscript + kIRLenEd25519Public + kIRLenX25519Public +
                 kIRLenX25519Public + kIRLenEd25519Public + kIRLenX25519Public +
                 kIRLenX25519Public + 4 + 1 + 4 + kIRLenX25519Public,
                 "TRANSCRIPT != 259");
IR_STATIC_ASSERT(kIRLenTranscript == 259, "TRANSCRIPT != 259");
IR_STATIC_ASSERT(kIROffTranscriptInitiatorSigning    == kIROffTranscriptLabel                + kIRLenLabelTranscript, "transcript IK_A^s offset");
IR_STATIC_ASSERT(kIROffTranscriptInitiatorAgreement  == kIROffTranscriptInitiatorSigning     + kIRLenEd25519Public,   "transcript IK_A^d offset");
IR_STATIC_ASSERT(kIROffTranscriptEK                  == kIROffTranscriptInitiatorAgreement   + kIRLenX25519Public,    "transcript EK_A offset");
IR_STATIC_ASSERT(kIROffTranscriptResponderSigning    == kIROffTranscriptEK                   + kIRLenX25519Public,    "transcript IK_B^s offset");
IR_STATIC_ASSERT(kIROffTranscriptResponderAgreement  == kIROffTranscriptResponderSigning     + kIRLenEd25519Public,   "transcript IK_B^d offset");
IR_STATIC_ASSERT(kIROffTranscriptSPK                 == kIROffTranscriptResponderAgreement   + kIRLenX25519Public,    "transcript SPK_B offset");
IR_STATIC_ASSERT(kIROffTranscriptSPKId               == kIROffTranscriptSPK                  + kIRLenX25519Public,    "transcript spk_id offset");
IR_STATIC_ASSERT(kIROffTranscriptOPKFlag             == kIROffTranscriptSPKId                + 4,                     "transcript opk_flag offset");
IR_STATIC_ASSERT(kIROffTranscriptOPKId               == kIROffTranscriptOPKFlag              + 1,                     "transcript opk_id offset");
IR_STATIC_ASSERT(kIROffTranscriptOPK                 == kIROffTranscriptOPKId                + 4,                     "transcript OPK_B offset");
IR_STATIC_ASSERT(kIROffTranscriptOPK + kIRLenX25519Public == kIRLenTranscript,                                        "transcript total");

/* Sec 6.3 SK derivation inputs */
IR_STATIC_ASSERT(kIRLenTH == kIRLenSHA256, "TH is not a SHA-256 output");
IR_STATIC_ASSERT(kIRLenX3DHInfo == kIRLenLabelX3DH + kIRLenTH, "X3DH info != 47");
IR_STATIC_ASSERT(kIRLenX3DHInfo == 47, "X3DH info != 47");
IR_STATIC_ASSERT(kIROffX3DHInfoTH == kIROffX3DHInfoLabel + kIRLenLabelX3DH, "X3DH info TH offset");
IR_STATIC_ASSERT(kIRLenIKMNoOPK == kIRLenF32 + 3 * kIRLenDHOutput, "IKM (no OPK) != 128");
IR_STATIC_ASSERT(kIRLenIKMOPK   == kIRLenF32 + 4 * kIRLenDHOutput, "IKM (OPK) != 160");
IR_STATIC_ASSERT(kIRLenIKMNoOPK == 128, "IKM (no OPK) != 128");
IR_STATIC_ASSERT(kIRLenIKMOPK   == 160, "IKM (OPK) != 160");
IR_STATIC_ASSERT(kIROffIKMDH1 == kIROffIKMSeparator + kIRLenF32,     "IKM DH1 offset");
IR_STATIC_ASSERT(kIROffIKMDH2 == kIROffIKMDH1       + kIRLenDHOutput, "IKM DH2 offset");
IR_STATIC_ASSERT(kIROffIKMDH3 == kIROffIKMDH2       + kIRLenDHOutput, "IKM DH3 offset");
IR_STATIC_ASSERT(kIROffIKMDH4 == kIROffIKMDH3       + kIRLenDHOutput, "IKM DH4 offset");
IR_STATIC_ASSERT(kIROffIKMDH4 == kIRLenIKMNoOPK,                      "IKM DH4 begins where the no-OPK form ends");
IR_STATIC_ASSERT(kIROffIKMDH4 + kIRLenDHOutput == kIRLenIKMOPK,       "IKM (OPK) total");
IR_STATIC_ASSERT(kIRLenSK == 32, "SK != 32");

/* Sec 6.5 SESSION_AD = label(13) || IK_A^s || IK_A^d || IK_B^s || IK_B^d */
IR_STATIC_ASSERT(kIRLenSessionAD ==
                 kIRLenLabelAD + kIRLenEd25519Public + kIRLenX25519Public +
                 kIRLenEd25519Public + kIRLenX25519Public,
                 "SESSION_AD != 141");
IR_STATIC_ASSERT(kIRLenSessionAD == 141, "SESSION_AD != 141");
IR_STATIC_ASSERT(kIROffSessionADInitiatorSigning   == kIROffSessionADLabel               + kIRLenLabelAD,       "SESSION_AD IK_A^s offset");
IR_STATIC_ASSERT(kIROffSessionADInitiatorAgreement == kIROffSessionADInitiatorSigning    + kIRLenEd25519Public, "SESSION_AD IK_A^d offset");
IR_STATIC_ASSERT(kIROffSessionADResponderSigning   == kIROffSessionADInitiatorAgreement  + kIRLenX25519Public,  "SESSION_AD IK_B^s offset");
IR_STATIC_ASSERT(kIROffSessionADResponderAgreement == kIROffSessionADResponderSigning    + kIRLenEd25519Public, "SESSION_AD IK_B^d offset");
IR_STATIC_ASSERT(kIROffSessionADResponderAgreement + kIRLenX25519Public == kIRLenSessionAD, "SESSION_AD total");
IR_STATIC_ASSERT(kIRLenIdentityPair == kIRLenEd25519Public + kIRLenX25519Public, "identity pair != 64");
IR_STATIC_ASSERT(kIROffSessionADInitiatorPair == kIROffSessionADInitiatorSigning, "initiator pair offset");
IR_STATIC_ASSERT(kIROffSessionADResponderPair == kIROffSessionADResponderSigning, "responder pair offset");
IR_STATIC_ASSERT(kIROffSessionADResponderPair + kIRLenIdentityPair == kIRLenSessionAD, "responder pair extent");

/* Sec 5.5 FP input = label(13) || IK^s(32) || IK^d(32) */
IR_STATIC_ASSERT(kIRLenFPInput == kIRLenLabelFP + kIRLenEd25519Public + kIRLenX25519Public, "FP input != 77");
IR_STATIC_ASSERT(kIRLenFPInput == 77, "FP input != 77");
IR_STATIC_ASSERT(kIROffFPSigning   == kIROffFPLabel   + kIRLenLabelFP,       "FP IK^s offset");
IR_STATIC_ASSERT(kIROffFPAgreement == kIROffFPSigning + kIRLenEd25519Public, "FP IK^d offset");
IR_STATIC_ASSERT(kIROffFPAgreement + kIRLenX25519Public == kIRLenFPInput,    "FP input total");
IR_STATIC_ASSERT(kIRLenFingerprint == kIRLenSHA256, "FP output is not a SHA-256 output");

/* Sec 7.2 / Sec 8.1 KDF outputs */
IR_STATIC_ASSERT(kIRLenKDFRKOutput == kIRLenRootKey + kIRLenChainKey, "KDF_RK output != 64");
IR_STATIC_ASSERT(kIRLenKDFRKOutput == 64, "KDF_RK output != 64");
IR_STATIC_ASSERT(kIRLenKDFRKOutput > kIRLenHMACSHA256,
                 "KDF_RK must span two HKDF-Expand blocks; a single-block Expand is non-conformant");
IR_STATIC_ASSERT(kIRLenKDFMKOutput == kIRLenMessageEncKey, "KDF_MK output != 32");

/* Sec 9.1 type 0x01 */
IR_STATIC_ASSERT(kIRLenType01Header == 1 + 1 + 2 + kIRLenX25519Public + 4 + 4 + kIRLenNonce, "0x01 header != 56");
IR_STATIC_ASSERT(kIRLenType01Header == 56, "0x01 header != 56");
IR_STATIC_ASSERT(kIROffType01Type       == kIROffType01Version + 1,                  "0x01 type offset");
IR_STATIC_ASSERT(kIROffType01Flags      == kIROffType01Type    + 1,                  "0x01 flags offset");
IR_STATIC_ASSERT(kIROffType01DHs        == kIROffType01Flags   + 2,                  "0x01 DHs offset");
IR_STATIC_ASSERT(kIROffType01N          == kIROffType01DHs     + kIRLenX25519Public, "0x01 N offset");
IR_STATIC_ASSERT(kIROffType01PN         == kIROffType01N       + 4,                  "0x01 PN offset");
IR_STATIC_ASSERT(kIROffType01Nonce      == kIROffType01PN      + 4,                  "0x01 nonce offset");
IR_STATIC_ASSERT(kIROffType01Ciphertext == kIROffType01Nonce   + kIRLenNonce,        "0x01 ciphertext offset");
IR_STATIC_ASSERT(kIROffType01Ciphertext == kIRLenType01Header,                       "0x01 header ends at the ciphertext");
IR_STATIC_ASSERT(kIRLenType01AD  == kIRLenSessionAD + kIRLenType01Header,             "0x01 AD != 197");
IR_STATIC_ASSERT(kIRLenType01AD  == 197,                                              "0x01 AD != 197");
IR_STATIC_ASSERT(kIRLenType01Min == kIRLenType01Header + 0 + kIRLenAEADTag,           "0x01 minimum != 72");
IR_STATIC_ASSERT(kIRLenType01Min == 72,                                               "0x01 minimum != 72");
IR_STATIC_ASSERT(kIRLenType01Max == kIRLenType01Header + kIRMaxPlaintext + kIRLenAEADTag, "0x01 maximum != 16777288");
IR_STATIC_ASSERT(kIRLenType01Max == 16777288,                                             "0x01 maximum != 16777288");

/* Sec 9.2 type 0x02 */
IR_STATIC_ASSERT(kIRLenType02Header ==
                 1 + 1 + 2 + kIRLenEd25519Public + kIRLenX25519Public + kIRLenEd25519Signature +
                 kIRLenX25519Public + 4 + 1 + 4 + kIRLenX25519Public + 4 + 4 + kIRLenNonce,
                 "0x02 header != 225");
IR_STATIC_ASSERT(kIRLenType02Header == 225, "0x02 header != 225");
IR_STATIC_ASSERT(kIROffType02Type              == kIROffType02Version           + 1,                       "0x02 type offset");
IR_STATIC_ASSERT(kIROffType02Flags             == kIROffType02Type              + 1,                       "0x02 flags offset");
IR_STATIC_ASSERT(kIROffType02IdentitySigning   == kIROffType02Flags             + 2,                       "0x02 IK_A^s offset");
IR_STATIC_ASSERT(kIROffType02IdentityAgreement == kIROffType02IdentitySigning   + kIRLenEd25519Public,     "0x02 IK_A^d offset");
IR_STATIC_ASSERT(kIROffType02IKB               == kIROffType02IdentityAgreement + kIRLenX25519Public,      "0x02 IKB_A offset");
IR_STATIC_ASSERT(kIROffType02EK                == kIROffType02IKB               + kIRLenEd25519Signature,  "0x02 EK_A offset");
IR_STATIC_ASSERT(kIROffType02SPKId             == kIROffType02EK                + kIRLenX25519Public,      "0x02 spk_id offset");
IR_STATIC_ASSERT(kIROffType02OPKFlag           == kIROffType02SPKId             + 4,                       "0x02 opk_flag offset");
IR_STATIC_ASSERT(kIROffType02OPKId             == kIROffType02OPKFlag           + 1,                       "0x02 opk_id offset");
IR_STATIC_ASSERT(kIROffType02DHs               == kIROffType02OPKId             + 4,                       "0x02 DHs offset");
IR_STATIC_ASSERT(kIROffType02N                 == kIROffType02DHs               + kIRLenX25519Public,      "0x02 N offset");
IR_STATIC_ASSERT(kIROffType02PN                == kIROffType02N                 + 4,                       "0x02 PN offset");
IR_STATIC_ASSERT(kIROffType02Nonce             == kIROffType02PN                + 4,                       "0x02 nonce offset");
IR_STATIC_ASSERT(kIROffType02Ciphertext        == kIROffType02Nonce             + kIRLenNonce,             "0x02 ciphertext offset");
IR_STATIC_ASSERT(kIROffType02Ciphertext == kIRLenType02Header,                                             "0x02 header ends at the ciphertext");
IR_STATIC_ASSERT(kIRLenType02AD  == kIRLenSessionAD + kIRLenType02Header,                                  "0x02 AD != 366");
IR_STATIC_ASSERT(kIRLenType02AD  == 366,                                                                   "0x02 AD != 366");
IR_STATIC_ASSERT(kIRLenType02Min == kIRLenType02Header + 0 + kIRLenAEADTag,                                "0x02 minimum != 241");
IR_STATIC_ASSERT(kIRLenType02Min == 241,                                                                   "0x02 minimum != 241");
IR_STATIC_ASSERT(kIRLenType02Max == kIRLenType02Header + kIRMaxPlaintext + kIRLenAEADTag,                  "0x02 maximum != 16777457");
IR_STATIC_ASSERT(kIRLenType02Max == 16777457,                                                              "0x02 maximum != 16777457");

/* Sec 11.1 handshake_id = IK_A^d || EK_A. Sec 11.2 reads it straight out of the 0x02 header. */
IR_STATIC_ASSERT(kIRLenHandshakeId == kIRLenX25519Public + kIRLenX25519Public, "handshake_id != 64");
IR_STATIC_ASSERT(kIRLenHandshakeId == 64, "handshake_id != 64");
IR_STATIC_ASSERT(kIROffHandshakeIdEK == kIROffHandshakeIdIdentityAgreement + kIRLenX25519Public, "handshake_id EK_A offset");
IR_STATIC_ASSERT(kIROffHandshakeIdEK + kIRLenX25519Public == kIRLenHandshakeId, "handshake_id total");

/* The global routing floor and cap of the type dispatcher. The floor MUST be the tighter of the
   two check-1 minima and the cap MUST be the looser of the two check-2 maxima, or the dispatcher
   would pre-empt a gate's own ordered check and return the wrong code. */
IR_STATIC_ASSERT(kIRLenMessageMin <= kIRLenType01Min, "routing floor exceeds the 0x01 minimum");
IR_STATIC_ASSERT(kIRLenMessageMin <= kIRLenType02Min, "routing floor exceeds the 0x02 minimum");
IR_STATIC_ASSERT(kIRLenMessageMin == (kIRLenType01Min < kIRLenType02Min ? kIRLenType01Min : kIRLenType02Min),
                 "routing floor is not the tighter of the two minima");
IR_STATIC_ASSERT(kIRLenMessageMax >= kIRLenType01Max, "routing cap is below the 0x01 maximum");
IR_STATIC_ASSERT(kIRLenMessageMax >= kIRLenType02Max, "routing cap is below the 0x02 maximum");
IR_STATIC_ASSERT(kIRLenMessageMax == (kIRLenType01Max > kIRLenType02Max ? kIRLenType01Max : kIRLenType02Max),
                 "routing cap is not the looser of the two maxima");
IR_STATIC_ASSERT(kIROffType01Type == kIROffType02Type,
                 "the type byte must sit at the same offset in both formats for routing to be legal");

/* Sec 5.4 prekey bundle */
IR_STATIC_ASSERT(kIRLenBundlePrefix ==
                 kIRLenMagic + 1 + kIRLenEd25519Public + kIRLenX25519Public + kIRLenEd25519Signature +
                 4 + kIRLenX25519Public + 8 + 8 + kIRLenEd25519Signature + 2,
                 "bundle prefix != 251");
IR_STATIC_ASSERT(kIRLenBundlePrefix == 251, "bundle prefix != 251");
IR_STATIC_ASSERT(kIROffBundleVersion           == kIROffBundleMagic             + kIRLenMagic,             "bundle version offset");
IR_STATIC_ASSERT(kIROffBundleIdentitySigning   == kIROffBundleVersion           + 1,                       "bundle IK^s offset");
IR_STATIC_ASSERT(kIROffBundleIdentityAgreement == kIROffBundleIdentitySigning   + kIRLenEd25519Public,     "bundle IK^d offset");
IR_STATIC_ASSERT(kIROffBundleIKB               == kIROffBundleIdentityAgreement + kIRLenX25519Public,      "bundle IKB offset");
IR_STATIC_ASSERT(kIROffBundleSPKId             == kIROffBundleIKB               + kIRLenEd25519Signature,  "bundle spk_id offset");
IR_STATIC_ASSERT(kIROffBundleSPK               == kIROffBundleSPKId             + 4,                       "bundle SPK offset");
IR_STATIC_ASSERT(kIROffBundleNotBefore         == kIROffBundleSPK               + kIRLenX25519Public,      "bundle not_before offset");
IR_STATIC_ASSERT(kIROffBundleNotAfter          == kIROffBundleNotBefore         + 8,                       "bundle not_after offset");
IR_STATIC_ASSERT(kIROffBundleSPKSig            == kIROffBundleNotAfter          + 8,                       "bundle SPK_SIG offset");
IR_STATIC_ASSERT(kIROffBundleOPKCount          == kIROffBundleSPKSig            + kIRLenEd25519Signature,  "bundle opk_count offset");
IR_STATIC_ASSERT(kIROffBundleOPKEntries        == kIROffBundleOPKCount          + 2,                       "bundle opk entries offset");
IR_STATIC_ASSERT(kIROffBundleOPKEntries == kIRLenBundlePrefix, "bundle prefix ends at the first OPK entry");
IR_STATIC_ASSERT(kIRLenBundleOPKEntry == 4 + kIRLenX25519Public, "bundle OPK entry != 36");
IR_STATIC_ASSERT(kIRLenBundleOPKEntry == 36, "bundle OPK entry != 36");
IR_STATIC_ASSERT(kIROffBundleOPKEntryKey == kIROffBundleOPKEntryId + 4, "bundle OPK entry key offset");
IR_STATIC_ASSERT(kIROffBundleOPKEntryKey + kIRLenX25519Public == kIRLenBundleOPKEntry, "bundle OPK entry total");
IR_STATIC_ASSERT(kIRMinBundleLength == kIRLenBundlePrefix, "MIN_BUNDLE_LENGTH must equal the fixed prefix");

/* Sec 12.1 session state blob */
IR_STATIC_ASSERT(kIRLenStatePrefix ==
                 kIRLenMagic + 1 + 1 + kIRLenSessionAD + kIRLenHandshakeId + kIRLenRootKey +
                 kIRLenX25519Private + kIRLenX25519Public + 1 + kIRLenX25519Public + 1 +
                 kIRLenChainKey + 1 + kIRLenChainKey + 4 + 4 + 4 + 8 + 1 + kIRLenStatePrologue + 4,
                 "state prefix != 472");
IR_STATIC_ASSERT(kIRLenStatePrefix == 472, "state prefix != 472");
IR_STATIC_ASSERT(kIROffStateFormat           == kIROffStateMagic            + kIRLenMagic,          "state format offset");
IR_STATIC_ASSERT(kIROffStateRole             == kIROffStateFormat           + 1,                    "state role offset");
IR_STATIC_ASSERT(kIROffStateSessionAD        == kIROffStateRole             + 1,                    "state SESSION_AD offset");
IR_STATIC_ASSERT(kIROffStateHandshakeId      == kIROffStateSessionAD        + kIRLenSessionAD,      "state handshake_id offset");
IR_STATIC_ASSERT(kIROffStateRK               == kIROffStateHandshakeId      + kIRLenHandshakeId,    "state RK offset");
IR_STATIC_ASSERT(kIROffStateDHsPriv          == kIROffStateRK               + kIRLenRootKey,        "state DHs_priv offset");
IR_STATIC_ASSERT(kIROffStateDHsPub           == kIROffStateDHsPriv          + kIRLenX25519Private,  "state DHs_pub offset");
IR_STATIC_ASSERT(kIROffStateDHrPresent       == kIROffStateDHsPub           + kIRLenX25519Public,   "state DHr_present offset");
IR_STATIC_ASSERT(kIROffStateDHrPub           == kIROffStateDHrPresent       + 1,                    "state DHr_pub offset");
IR_STATIC_ASSERT(kIROffStateCKsPresent       == kIROffStateDHrPub           + kIRLenX25519Public,   "state CKs_present offset");
IR_STATIC_ASSERT(kIROffStateCKs              == kIROffStateCKsPresent       + 1,                    "state CKs offset");
IR_STATIC_ASSERT(kIROffStateCKrPresent       == kIROffStateCKs              + kIRLenChainKey,       "state CKr_present offset");
IR_STATIC_ASSERT(kIROffStateCKr              == kIROffStateCKrPresent       + 1,                    "state CKr offset");
IR_STATIC_ASSERT(kIROffStateNs               == kIROffStateCKr              + kIRLenChainKey,       "state Ns offset");
IR_STATIC_ASSERT(kIROffStateNr               == kIROffStateNs               + 4,                    "state Nr offset");
IR_STATIC_ASSERT(kIROffStatePN               == kIROffStateNr               + 4,                    "state PN offset");
IR_STATIC_ASSERT(kIROffStateSendCounter      == kIROffStatePN               + 4,                    "state send_counter offset");
IR_STATIC_ASSERT(kIROffStateProloguePresent  == kIROffStateSendCounter      + 8,                    "state prologue_present offset");
IR_STATIC_ASSERT(kIROffStatePrologue         == kIROffStateProloguePresent  + 1,                    "state prologue offset");
IR_STATIC_ASSERT(kIROffStateSkippedCount     == kIROffStatePrologue         + kIRLenStatePrologue,  "state skipped_count offset");
IR_STATIC_ASSERT(kIROffStateSkippedEntries   == kIROffStateSkippedCount     + 4,                    "state skipped entries offset");
IR_STATIC_ASSERT(kIROffStateSkippedEntries == kIRLenStatePrefix, "state prefix ends at the first skipped entry");

/* Sec 6.5: both identities of a session are recoverable from the stored SESSION_AD alone, which is
   why neither identity key is duplicated elsewhere in the blob. */
IR_STATIC_ASSERT(kIROffStateInitiatorSigning    == kIROffStateSessionAD + kIROffSessionADInitiatorSigning,   "blob IK_A^s offset != 19");
IR_STATIC_ASSERT(kIROffStateInitiatorAgreement  == kIROffStateSessionAD + kIROffSessionADInitiatorAgreement, "blob IK_A^d offset != 51");
IR_STATIC_ASSERT(kIROffStateResponderSigning    == kIROffStateSessionAD + kIROffSessionADResponderSigning,   "blob IK_B^s offset != 83");
IR_STATIC_ASSERT(kIROffStateResponderAgreement  == kIROffStateSessionAD + kIROffSessionADResponderAgreement, "blob IK_B^d offset != 115");
IR_STATIC_ASSERT(kIROffStateInitiatorSigning   == 19,  "blob IK_A^s offset != 19");
IR_STATIC_ASSERT(kIROffStateInitiatorAgreement == 51,  "blob IK_A^d offset != 51");
IR_STATIC_ASSERT(kIROffStateResponderSigning   == 83,  "blob IK_B^s offset != 83");
IR_STATIC_ASSERT(kIROffStateResponderAgreement == 115, "blob IK_B^d offset != 115");

/* Sec 12.1 prologue block */
IR_STATIC_ASSERT(kIRLenStatePrologue == kIRLenX25519Public + 4 + 1 + 4, "prologue != 41");
IR_STATIC_ASSERT(kIRLenStatePrologue == 41, "prologue != 41");
IR_STATIC_ASSERT(kIROffPrologueSPKId   == kIROffPrologueEK      + kIRLenX25519Public, "prologue spk_id offset");
IR_STATIC_ASSERT(kIROffPrologueOPKFlag == kIROffPrologueSPKId   + 4,                  "prologue opk_flag offset");
IR_STATIC_ASSERT(kIROffPrologueOPKId   == kIROffPrologueOPKFlag + 1,                  "prologue opk_id offset");
IR_STATIC_ASSERT(kIROffPrologueOPKId + 4 == kIRLenStatePrologue,                      "prologue total");

/* Sec 12.1 skipped entry */
IR_STATIC_ASSERT(kIRLenStateSkippedEntry == kIRLenX25519Public + 4 + kIRLenMessageKey + 8, "skipped entry != 76");
IR_STATIC_ASSERT(kIRLenStateSkippedEntry == 76, "skipped entry != 76");
IR_STATIC_ASSERT(kIROffSkippedEntryN            == kIROffSkippedEntryDHPub + kIRLenX25519Public, "skipped entry N offset");
IR_STATIC_ASSERT(kIROffSkippedEntryMK           == kIROffSkippedEntryN     + 4,                  "skipped entry mk offset");
IR_STATIC_ASSERT(kIROffSkippedEntryInsertedAtMs == kIROffSkippedEntryMK    + kIRLenMessageKey,   "skipped entry inserted_at_ms offset");
IR_STATIC_ASSERT(kIROffSkippedEntryInsertedAtMs + 8 == kIRLenStateSkippedEntry,                  "skipped entry total");

/* Sec 12.2 rule 8 inspects the first and last byte of DHs_priv, expressed as blob offsets. */
IR_STATIC_ASSERT(kIROffStateDHsPrivFirstByte == kIROffStateDHsPriv, "clamp check first byte offset");
IR_STATIC_ASSERT(kIROffStateDHsPrivLastByte  == kIROffStateDHsPriv + kIRLenX25519Private - 1, "clamp check last byte offset");
IR_STATIC_ASSERT(kIROffStateDHsPrivFirstByte == 243, "clamp check first byte offset != 243");
IR_STATIC_ASSERT(kIROffStateDHsPrivLastByte  == 274, "clamp check last byte offset != 274");

/* Sec 7.6 skipped-key store key */
IR_STATIC_ASSERT(kIRLenSkippedMapKey == kIRLenX25519Public + 4, "skipped map key != 36");
IR_STATIC_ASSERT(kIRLenSkippedMapKey == 36, "skipped map key != 36");
IR_STATIC_ASSERT(kIROffSkippedMapKeyN == kIROffSkippedMapKeyDHPub + kIRLenX25519Public, "skipped map key N offset");
IR_STATIC_ASSERT(kIROffSkippedMapKeyN + 4 == kIRLenSkippedMapKey, "skipped map key total");

#pragma mark - Bounds

IR_STATIC_ASSERT(kIRMaxPlaintext == 16777216, "MAX_PLAINTEXT != 2^24");
IR_STATIC_ASSERT(kIRMaxSkipPerMessage == 1000, "MAX_SKIP_PER_MESSAGE != 1000");
IR_STATIC_ASSERT(kIRMaxSkippedStored == 2000, "MAX_SKIPPED_STORED != 2000");
IR_STATIC_ASSERT(kIRMaxSkipPerMessage <= kIRMaxSkippedStored,
                 "a single message must not be able to evict the entire skipped store");
IR_STATIC_ASSERT(kIRSkippedTTLMs == 604800000, "SKIPPED_TTL_MS != 7 days");
IR_STATIC_ASSERT(kIRHandshakeCacheMs == 604800000, "HANDSHAKE_CACHE_MS != 7 days");
IR_STATIC_ASSERT(kIRMaxCounter == 0x7FFFFFFF, "MAX_COUNTER != 0x7FFFFFFF");
IR_STATIC_ASSERT(kIRMaxSPKValiditySeconds == 7776000, "MAX_SPK_VALIDITY_SECONDS != 90 days");
IR_STATIC_ASSERT(kIROPKMaxAgeSeconds == 7776000, "OPK_MAX_AGE_S != 90 days");
IR_STATIC_ASSERT(kIRMaxBundleOPKCount == 1000, "MAX_BUNDLE_OPK_COUNT != 1000");

#pragma mark - Byte constants

IR_STATIC_ASSERT(kIRProtocolVersion == 0x04, "version byte != 0x04");
IR_STATIC_ASSERT(kIRStateFormat == 0x01, "state_format != 0x01");
IR_STATIC_ASSERT(kIRKDFCKMessageKeyInput == 0x01, "KDF_CK message-key input != 0x01");
IR_STATIC_ASSERT(kIRKDFCKChainKeyInput == 0x02, "KDF_CK chain-key input != 0x02");
IR_STATIC_ASSERT(kIRKDFCKMessageKeyInput != kIRKDFCKChainKeyInput,
                 "KDF_CK inputs must differ or the chain and the message key collide");
IR_STATIC_ASSERT(IRMessageTypeNormal == 0x01, "type normal != 0x01");
IR_STATIC_ASSERT(IRMessageTypePrekey == 0x02, "type prekey != 0x02");
IR_STATIC_ASSERT(IRSessionRoleInitiator == 0x01, "role initiator != 0x01");
IR_STATIC_ASSERT(IRSessionRoleResponder == 0x02, "role responder != 0x02");
IR_STATIC_ASSERT(IROPKFlagAbsent == 0x00, "opk_flag absent != 0x00");
IR_STATIC_ASSERT(IROPKFlagPresent == 0x01, "opk_flag present != 0x01");

#pragma mark - Cross-checks that catch a whole class of transcription error

/* Every X25519 and Ed25519 public key on the wire is 32 bytes; a port that widened one of them
   would silently shift every offset after it. */
IR_STATIC_ASSERT(kIRLenX25519Public == 32 && kIRLenEd25519Public == 32, "public key width changed");
IR_STATIC_ASSERT(kIRLenEd25519Private == 32,
                 "Ed25519Private is the RFC 8032 SEED; libsodium's 64-byte sk must never be nominal");
IR_STATIC_ASSERT(kIRLenEd25519Signature == 64, "signature width changed");
IR_STATIC_ASSERT(kIRLenNonce == 12, "the IETF ChaCha20-Poly1305 nonce is 12 bytes, not 8");
IR_STATIC_ASSERT(kIRLenAEADTag == 16, "Poly1305 tag width changed");
