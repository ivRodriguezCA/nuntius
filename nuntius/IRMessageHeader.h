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
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRPublicIdentity.h>

/**
 A parsed, ALREADY-VALIDATED message header — SPEC §9.1, §9.2, §8.5.

 One type covers both wire types, because the ratchet consumes the union `(DHs_pub, N, PN, nonce)`
 identically whether it arrived in a 56-byte or a 225-byte header. The type `0x02` extras hang off
 the same object behind -isPreKeyMessage.

 THERE IS NO PUBLIC INITIALIZER. Every constructor lives in IRMessageHeader+Internal.h, which only
 IRMessageGate.m imports, so an IRMessageHeader that did not come through the §10.1 / §10.2 ordered
 gates cannot be spelled. That is the point of the type: downstream code (the ratchet, the
 messenger) can treat every field as already inside its permitted domain, because the only path to
 one of these ran the gate.

 WHAT THIS TYPE DELIBERATELY DOES **NOT** GUARANTEE. The gates are the no-secret prefix of the
 protocol — §10.1 steps 1–10 and §10.2 steps 1–11 "touch no secret and branch on no secret". So:

   - `identityBinding` (IKB_A) is CARRIED, NOT VERIFIED. §10.7 step 3 and §11.2 own that, and both
     say "before any DH". This is why -initiatorIdentity is an IRIdentityKeyPair (the raw §11.1
     index key, decision D5) and NOT an IRPublicIdentity: the verified type has exactly one
     constructor and it checks the binding, so the only way to obtain one is to perform the check.
     A gate that could mint an IRPublicIdentity would make §5.5's blanket MUST a matter of the
     caller remembering.
   - `spkId` and `opkId` are NOT RESOLVED. §10.7 steps 5 and 7 own that.
   - The type `0x02` anti-reflection checks against the RESPONDER's own keys are not applied. Only
     the self-contained one — `DHs_pub != EK_A`, §10.2 check 11 — is, because it compares two
     fields of the same message. The other two need state the gate has not loaded: the resolved
     `SPK_B` (§10.7 step 6) and the session's `DHs` (§11.2).

 `headerLength` COMES FROM THE TYPE BYTE, NEVER FROM THE WIRE. §9's opening sentence: "Header length
 is a constant determined solely by the 1-byte type field at offset 1." There is no length field
 anywhere in this format, which is what makes defect 6 — the `*(NSInteger *)` read of a 1-byte
 NSData at three sites in v3's IREncryptionService — unreachable rather than merely fixed.
 */
@interface IRMessageHeader : NSObject

#pragma mark - Type-derived constants

/// §9 — 56 for type `0x01`, 225 for type `0x02`. Returns 0 for any other value, which the gates
/// treat as ERR_UNKNOWN_MESSAGE_TYPE.
+ (NSUInteger)headerLengthForType:(IRMessageType)type;

/// §8.5 — 197 for type `0x01`, 366 for type `0x02`. Returns 0 for any other value.
+ (NSUInteger)associatedDataLengthForType:(IRMessageType)type;

/// §10.1 check 1 / §10.2 check 1 — 72 and 241. Returns 0 for any other value.
+ (NSUInteger)minimumMessageLengthForType:(IRMessageType)type;

/// §10.1 check 2 / §10.2 check 2 — 16777288 and 16777457. Returns 0 for any other value.
+ (NSUInteger)maximumMessageLengthForType:(IRMessageType)type;

#pragma mark - Both types

@property (nonatomic, readonly) IRMessageType type;

/// 56 or 225. Always equals +headerLengthForType: of -type and always equals -headerBytes.length.
@property (nonatomic, readonly) NSUInteger headerLength;

/// `DHs_pub` — the sender's current X25519 ratchet public key. §9.1 offset 4, §9.2 offset 173.
@property (nonatomic, strong, readonly) IRX25519Public * _Nonnull ratchetKey;

/// Message number in the sender's current sending chain. Gate-checked `<= 0x7FFFFFFF`.
@property (nonatomic, readonly) uint32_t N;

/// Length of the sender's PREVIOUS sending chain. Gate-checked `<= 0x7FFFFFFF` for type `0x01`, and
/// gate-checked `== 0` for type `0x02` (§9.2), so this reads 0 on every prekey message.
///
/// §9.1 is emphatic that this comes "from state.PN — never from state.Ns". That is defect 10: v3
/// wrote `numberOfSentMessages` into both slots. IRMessageBuilder answers it structurally by naming
/// the two parameters separately for type `0x01` and by not accepting a `PN` at all for type `0x02`.
@property (nonatomic, readonly) uint32_t PN;

/// The random per-message AEAD nonce (§8.3). It is both the nonce and part of the AD (§8.5).
@property (nonatomic, strong, readonly) IRNonce * _Nonnull nonce;

/**
 §8.5 — the VERBATIM `message[0 .. headerLength)` slice, retained at parse time.

 AD is "everything before the ciphertext". Re-serializing a parsed header to recompute the AD is how
 a port drifts: every valid header re-serializes identically, so the bug is invisible in every test
 that round-trips through one implementation and appears only as an interop failure against another.
 Keeping the received bytes removes the opportunity.
 */
@property (nonatomic, copy, readonly) NSData * _Nonnull headerBytes;

#pragma mark - Type 0x02 only

/// YES exactly when -type is IRMessageTypePrekey. Every property below is non-nil / meaningful only
/// then; on a type `0x01` header the object properties are nil and the scalars are 0.
@property (nonatomic, readonly) BOOL isPreKeyMessage;

/// `IK_A^s ‖ IK_A^d` from §9.2 offsets 4 and 36 — the RAW pair (decision D5), NOT a verified
/// identity. See the class comment: the binding below is unverified at this point.
@property (nonatomic, strong, readonly) IRIdentityKeyPair * _Nullable initiatorIdentity;

/// `IKB_A`, §9.2 offset 68. CARRIED, NOT VERIFIED — §10.7 step 3 / §11.2 own the verification.
@property (nonatomic, strong, readonly) IREd25519Signature * _Nullable identityBinding;

/// `EK_A`, §9.2 offset 132 — the initiator's X3DH handshake ephemeral.
@property (nonatomic, strong, readonly) IRX25519Public * _Nullable ephemeralPublic;

/// Which of B's signed prekeys the initiator used. UNRESOLVED — §10.7 step 5 owns that.
@property (nonatomic, readonly) uint32_t spkId;

/// Gate-checked to be exactly IROPKFlagAbsent or IROPKFlagPresent (§10.2 check 6), which is why
/// this is the enum rather than a raw byte: by the time a header exists the domain is closed, so a
/// downstream `switch` over it is exhaustive and the compiler can say so.
@property (nonatomic, readonly) IROPKFlag opkFlag;

/// Gate-checked to be 0 when -opkFlag is IROPKFlagAbsent (§10.2 check 7). UNRESOLVED — §10.7 step 7.
@property (nonatomic, readonly) uint32_t opkId;

/// §11.1 — `IK_A^d ‖ EK_A`, 64 bytes. nil for type `0x01`, which carries no session identifier by
/// design and is routed by §11.5's out-of-band rules instead.
@property (nonatomic, copy, readonly) NSData * _Nullable handshakeId;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
