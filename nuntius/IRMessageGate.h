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

#import "IRMessageHeader.h"
#import "IRSessionAD.h"

/**
 The §10.1 and §10.2 ordered gates — SPEC §10.1, §10.2, §10.4, §9.3.

 §10 opens with the contract every method here keeps: "Every check below is a MUST. Every failure
 returns the specified error, produces no plaintext, and mutates no state. There is no partial
 success and no 'best effort' path."

 THE ORDER OF THE CHECKS IS ITSELF NORMATIVE, not an implementation detail. §15.4 makes the exact
 error code a conformance requirement for inputs that are wrong in more than one way, and this
 implementation generates the frozen vectors (§15.6), so an order that differs from the tables below
 does not merely return a surprising code — it freezes the wrong code for Java, Kotlin and Swift.
 Every check is therefore its own numbered step in the implementation, executed top to bottom, with
 no reordering for efficiency.

 NO OFFSET HERE IS DERIVED FROM THE MESSAGE. §10: "No field is ever read at an offset derived from a
 value carried in the message. Every offset in §9 is a compile-time constant." Every read goes
 through IRByteReader at a `kIROffType0*` constant, so the class of bug behind defect 6 — v3's
 `*(NSInteger *)data.bytes` over a 1-byte NSData at three sites — has no expression here.

 ═══════════════════════════════════════════════════════════════════════════════════════════════
 §10.0 RUNS FIRST, ALWAYS.
 ═══════════════════════════════════════════════════════════════════════════════════════════════

 +demultiplexMessage:expectedType:error: is the entry-point demultiplex, and NEITHER gate below may
 be entered before it has passed. Its floor and cap are the GLOBAL ones (72 and 16777457), not
 either type's, because a type-dependent floor evaluated against a message whose type has not been
 read asserts a property the message does not have. See that method's comment.

 ═══════════════════════════════════════════════════════════════════════════════════════════════
 REQUIRED CALL SEQUENCE — decision D1. Getting this wrong is vector-visible.
 ═══════════════════════════════════════════════════════════════════════════════════════════════

 §10.1 check 6 sits in the MIDDLE of the type `0x01` gate: (1) length floor, (2) length cap,
 (3) version, (4) type, (5) flags, **(6) the caller's session handle resolves**, (7) public-key
 encoding, (8) anti-reflection against OUR OWN `DHs` public, (9) `N` bound, (10) `PN` bound.

 Check 8 needs the session's own ratchet key, which does not exist until check 6 has succeeded. A
 single entry point taking `ownRatchetPublicKey:` would therefore force the caller to resolve the
 session BEFORE checks 1–5 ran, and a 10-byte input with no session would return `ERR_NO_SESSION`
 where §10.1 mandates `ERR_TRUNCATED_MESSAGE`. So the type `0x01` gate is split, and the caller
 MUST run it in this order:

     1.  +demultiplexMessage:expectedType:error:           -> §10.0 rows 1–5
     2.  +gateType01Prefix:error:                          -> §10.1 checks 1–5
     3.  the CALLER resolves the session handle (§11.5)    -> §10.1 check 6, ERR_NO_SESSION
     4.  +parseType01Message:ownRatchetPublicKey:error:    -> §10.1 checks 1–5 again, then 7–10

 Step 4 re-runs checks 1–5. They are pure, idempotent, and read five bytes; paying for them twice
 is the price of keeping check 6 in its specified position.

 Type `0x02` needs no such split. §10.2 checks 1–11 are entirely self-contained — check 11 compares
 two fields of the SAME message — so +parseType02Message:error: is one call, and session dispatch
 (§11.2) happens after it on the header it returns.
 */
@interface IRMessageGate : NSObject

#pragma mark - §10.0 — entry-point demultiplex

/**
 §10.0, rows 1–4 — resolve the message type. This is §11.5 rule 5's REQUIRED router: a host holding
 bytes off a transport calls this to choose an entry point, rather than calling one at random and
 interpreting the error.

     1  len(msg) >= 72         -> ERR_TRUNCATED_MESSAGE     (check 1 of BOTH gates)
     2  len(msg) <= 16777457   -> ERR_PLAINTEXT_TOO_LARGE   (the LOOSER of the two check-2 caps)
     3  msg[0] == 0x04         -> ERR_UNSUPPORTED_VERSION
     4  msg[1] in {0x01, 0x02} -> ERR_UNKNOWN_MESSAGE_TYPE

 ROW 3 PRECEDES ROW 4, and that ordering is §10.6 in its entirety. A v3 message (`msg[0] == 0x03`)
 dies HERE, before the type is read and before either gate's type-dependent length floor — so the
 rejection is unconditional on length. Under the previous ordering the router dispatched on `msg[1]`
 first, so a 100-byte v3 message with `msg[1] == 0x02` reached §10.2's 241-byte floor and came back
 as ERR_TRUNCATED_MESSAGE, making §10.6's guarantee silently conditional on message length.
 `NEG-VERSION-SHORT` is the vector.

 Rows 1 and 2 are NOT type-dependent and legitimately precede the demultiplex. 72 is check 1 of both
 gates, so no message failing it could have reached either gate's check 4; 16777457 is the looser of
 the two caps, so this can never pre-empt a code the applicable gate would have produced. The tighter
 type `0x01` cap of 16777288 is deliberately NOT applied here — it is that gate's own check 2, and
 applying it during routing would return the right code for the wrong reason on a 16777300-byte type
 `0x02` message. Keeping row 1 first is also what keeps this inside §1.3 property 5: reading
 `msg[0..2)` on a zero-byte input is the out-of-bounds class §10.3 documents.

 @return IRMessageTypeNormal or IRMessageTypePrekey. On failure returns 0 — NOT a member of
         IRMessageType — and sets `error`. Callers MUST branch on the error, not on the value.
 */
+ (IRMessageType)messageTypeOfMessage:(NSData * _Nonnull)message
                                error:(NSError * _Nullable * _Nullable)error;

/**
 §10.0 in full — rows 1–4 as above, then row 5: `msg[1]` equals the type this entry point accepts,
 else ERR_WRONG_ENTRY_POINT (7125).

 BOTH RECEIVE ENTRY POINTS MUST CALL THIS BEFORE §10.1 OR §10.2, and the reason is that a length
 floor is a FUNCTION OF THE TYPE. §10.2's floor of 241 fires before its own check 4 reads the type
 byte, so a 200-byte message that is genuinely a type `0x01` used to come back out of the prekey
 entry point as ERR_TRUNCATED_MESSAGE — a truncation that does not exist, sending an implementer
 looking for a short read instead of a misrouted call. The asymmetry was an artifact of the two
 gates having different floors, not a statement about the input.

 7125 rather than 7101 (§19.8): byte 1 genuinely IS a valid type here, so 7101's meaning — a
 predicate over the message alone — does not describe it. This is a predicate over (message, entry
 point), and the remedies differ: drop the message versus fix the host's demultiplexer.

 ENTRY POINTS MUST NOT FORWARD. §10.0 is a rejection, never a redirect. Auto-forwarding a type
 `0x01` to the self-routing prekey entry point is a §11.5 rule 1 violation in disguise — that entry
 point takes no handle, so a forwarded message has none and the implementation must either fabricate
 one or trial-decrypt, both rejected in §19.2.
 */
+ (BOOL)demultiplexMessage:(NSData * _Nonnull)message
              expectedType:(IRMessageType)expectedType
                     error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Type 0x01

/**
 §10.1 checks 1–5 ONLY. Touches no session, no secret, and no key material.

     1  len(msg) >= 72          -> ERR_TRUNCATED_MESSAGE
     2  len(msg) <= 16777288    -> ERR_PLAINTEXT_TOO_LARGE
     3  msg[0] == 0x04          -> ERR_UNSUPPORTED_VERSION
     4  msg[1] == 0x01          -> ERR_UNKNOWN_MESSAGE_TYPE
     5  msg[2..4) == 0x0000     -> ERR_RESERVED_FLAGS_SET

 MUST be called BEFORE the caller resolves a session (check 6). See the class comment.
 */
+ (BOOL)gateType01Prefix:(NSData * _Nonnull)message
                   error:(NSError * _Nullable * _Nullable)error;

/**
 §10.1 checks 1–5 (re-run) then 7–10. Check 6 — session resolution — is the CALLER's, and MUST
 already have succeeded.

     7   DHs_pub = msg[4..36) passes §4.4 checks 1–2      -> ERR_INVALID_PUBLIC_KEY
     8   DHs_pub != `ownRatchetPublicKey`                 -> ERR_INVALID_PUBLIC_KEY
     9   N  = be32(msg[36..40)) <= 0x7FFFFFFF             -> ERR_COUNTER_OVERFLOW
     10  PN = be32(msg[40..44)) <= 0x7FFFFFFF             -> ERR_COUNTER_OVERFLOW

 `ownRatchetPublicKey` is `_Nonnull` on purpose: check 8 is not optional, and a nullable parameter
 would let a caller opt out of an anti-reflection check by passing nil. Pass the loaded session's
 `DHs` public half.

 Checks 11–13 of §10.1 — the snapshot ratchet, the AEAD, and the commit — belong to Layer 7 and
 Layer 9. This method returns at the end of the no-secret prefix.
 */
+ (IRMessageHeader * _Nullable)parseType01Message:(NSData * _Nonnull)message
                              ownRatchetPublicKey:(IRX25519Public * _Nonnull)ownRatchetPublicKey
                                            error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Type 0x02

/**
 §10.2 checks 1–11, complete and self-contained.

     1   len(msg) >= 241                                  -> ERR_TRUNCATED_MESSAGE
     2   len(msg) <= 16777457                             -> ERR_PLAINTEXT_TOO_LARGE
     3   msg[0] == 0x04                                   -> ERR_UNSUPPORTED_VERSION
     4   msg[1] == 0x02                                   -> ERR_UNKNOWN_MESSAGE_TYPE
     5   msg[2..4) == 0x0000                              -> ERR_RESERVED_FLAGS_SET
     6   opk_flag = msg[168] in {0x00, 0x01}              -> ERR_MALFORMED_HEADER
     7   opk_flag == 0x00 implies be32(msg[169..173)) == 0 -> ERR_MALFORMED_HEADER
     8   PN = be32(msg[209..213)) == 0                    -> ERR_MALFORMED_HEADER
     9   N  = be32(msg[205..209)) <= 0x7FFFFFFF           -> ERR_COUNTER_OVERFLOW
     10  IK_A^d, EK_A, DHs_pub each pass §4.4 checks 1–2  -> ERR_INVALID_PUBLIC_KEY
     11  DHs_pub = msg[173..205) != EK_A = msg[132..164)  -> ERR_INVALID_PUBLIC_KEY

 CHECK 8 READS OFFSET 209 BEFORE CHECK 9 READS OFFSET 205. The gate is not in layout order, which is
 why IRByteReader has absolute, cursor-preserving reads; a purely sequential reader cannot express
 this table.

 CHECK 10 COVERS THREE KEYS, NOT FOUR. `IK_A^s` at offset 4 is Ed25519, and §4.4 check 2 is an RFC
 7748 u-coordinate rule: bit 255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2) and is
 set in roughly half of all valid identities. Applying check 2 to it would reject about half of all
 legitimate senders, intermittently, in a way that reads as a signature bug.

 §10.2 check 12 — dispatch on session existence — is §11.2's and belongs to Layer 9. So do the two
 anti-reflection checks that cannot live in a gate: against the resolved `SPK_B` (§10.7 step 6, which
 needs `spk_id` resolved) and against the session's `DHs` (§11.2, which needs the session loaded).

 The returned header carries `IKB_A` UNVERIFIED — see IRMessageHeader's class comment.
 */
+ (IRMessageHeader * _Nullable)parseType02Message:(NSData * _Nonnull)message
                                            error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Associated data and payload

/**
 §8.5 — `AD = SESSION_AD (141) ‖ the complete message header`, so 197 bytes for a type `0x01` and
 366 for a type `0x02`.

 The construction itself belongs to IRSessionAD (Layer 5) and this method forwards to it rather than
 rebuilding the concatenation, for the same reason IRTranscript does not own a second copy of the
 fingerprint input: two builders for one structure is precisely how ports drift. What this adds is a
 cross-check — IRSessionAD derives the expected total from `headerBytes.length` while
 IRMessageHeader derives it from the type byte, and the two tables are asserted to agree.
 */
+ (NSData * _Nullable)associatedDataWithSessionAD:(IRSessionAD * _Nonnull)sessionAD
                                           header:(IRMessageHeader * _Nonnull)header
                                            error:(NSError * _Nullable * _Nullable)error;

/**
 `message[headerLength .. end)` — the ciphertext with its appended 16-byte Poly1305 tag (§8.2).

 §9: "The only variable-length region is the ciphertext, whose extent is derived by subtraction from
 the total received length." There is no `ciphertext_len` on the wire to misparse, deliberately —
 §9 rejects a redundant length field because it would put an attacker-controlled length back into
 the format and rely on prose to stop implementations using it.

 `header` MUST be the header parsed from THIS `message`. Fails with `ERR_TRUNCATED_MESSAGE` if the
 remainder cannot hold a tag, and with `ERR_PLAINTEXT_TOO_LARGE` above the type's maximum, so this
 is safe to call even on a message that never went through a gate.
 */
+ (NSData * _Nullable)ciphertextAndTagOfMessage:(NSData * _Nonnull)message
                                         header:(IRMessageHeader * _Nonnull)header
                                          error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
