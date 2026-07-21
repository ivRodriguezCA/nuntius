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
#import "IRIdentity.h"
#import "IRInMemoryPreKeyStore.h"
#import "IRInMemorySessionStore.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRMessageBuilder.h"
#import "IRMessageGate.h"
#import "IRMessageHeader.h"
#import "IRMessenger.h"
#import "IRPreKeyRecords.h"
#import "IRPreKeyStore.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSession.h"
#import "IRSession+Internal.h"
#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSessionStore.h"
#import "IRX3DH.h"

/**
 negative.json, block 2 of 3 — the `wire` kind. SPEC §9.1, §9.2, §10.0, §10.1, §10.2, §10.5, §10.6,
 §10.7, §11.2, §15.4, §15.5.

 IRVectorWire.m is the worked example and this file copies its shape: the same helpers, the same
 guard macro, the same "read every input first" discipline in the executors, and the same rule that
 every byte in `inputs` is a literal here or is derived from one.

 WHAT THIS MODULE COVERS — the §15.4 rows a PARSER reaches from bytes alone, plus the two type
 `0x02` anti-reflection rows that no gate can perform:

     NEG-VERSION                  §10.0 row 3, at or above the 72-byte global floor
     NEG-VERSION-SHORT            §10.0 row 3 ahead of §10.2's 241-byte floor — §10.6's teeth
     NEG-TYPE                     §10.0 row 4
     NEG-ENTRYPOINT-01-TO-02      §10.0 row 5, 72 bytes, BELOW §10.2's floor
     NEG-ENTRYPOINT-02-TO-01      §10.0 row 5, with a handle that RESOLVES
     NEG-FLAGS                    §10.1 check 5
     NEG-TRUNCATED                §10.0 row 1, 71 bytes
     NEG-PUBKEY-HIGHBIT           §10.1 check 7 / §4.4 check 2
     NEG-PUBKEY-REFLECT-01        §10.1 check 8
     NEG-PUBKEY-REFLECT-02-EKA    §10.2 check 11
     NEG-PUBKEY-REFLECT-02-SPK    §10.7 step 6      (needs a prekey store — see below)
     NEG-PUBKEY-REFLECT-02-DHS    §11.2 check 3     (needs a live session — see below)
     NEG-PREKEY-PN                §10.2 check 8
     NEG-OPKFLAG-ID               §10.2 check 7

 NINE §15.4 ROWS THAT LOOK LIKE THEY BELONG HERE ARE DELIBERATELY ELSEWHERE, and `id` is unique
 across all six files (§15.5), so two modules emitting one would freeze a corpus with duplicate ids.

   - The six bundle rows of §10.3 — `NEG-BUNDLE-EMPTY`, `-SHORT`, `-MAGIC`, `-VERSION`, `-OPKCOUNT`
     and `-LEN` — are in IRVectorNegativeStore.m, beside the other hand-written decoder, and they
     carry `kind: "wire"` because that is what a §5.4 prekey bundle is. The driver routes them to
     that module on `inputs.entry_point == "parse_bundle"`, not on `kind`. IRVectorModules.h's
     partition comment lists them here; the implementation is there, and the two are reconciled in
     that header's integration note.
   - `NEG-SMALLORDER`, `NEG-COUNTER` and `NEG-SKIP-LIMIT` are in IRVectorNegativeCrypto.m.
     `NEG-SMALLORDER` and `NEG-SKIP-LIMIT` are not parser-reachable at all — §4.4 check 3 fires
     inside a DH and `MAX_SKIP_PER_MESSAGE` inside §7.9 phase 3, both of which need a live ratchet
     this module has no business building. `NEG-COUNTER` IS parser-reachable (§10.1 check 9), and it
     sits there rather than here only so that the three counter-and-DH rows stay together.

 This note exists so the next reader does not "fix" the omissions.

 THE GATE ORDER IS NORMATIVE, AND IT IS THE WHOLE DESIGN CONSTRAINT ON THIS FILE. Every fixture
 below is built so that the check it names is the FIRST one that can fire; a vector that is wrong in
 two ways silently tests whichever rule the implementation happens to evaluate first, and then
 freezes that accident for Java, Kotlin and Swift. Each vector's `description` states which check it
 pins and, where the distinction is load-bearing, which code a wrongly ordered port returns instead.

 THREE LENGTH BANDS ARE NORMATIVE AND MUST NOT BE WIDENED:

   - `NEG-TRUNCATED` is 71 bytes — exactly one below §18's 72-byte floor, which is check 1 of BOTH
     gates and therefore §10.0 row 1.
   - `NEG-ENTRYPOINT-01-TO-02` is 72 bytes — a complete, otherwise valid type `0x01` message that
     sits BELOW §10.2's floor of 241. A port that evaluated the type `0x02` floor before the
     demultiplex answers `ERR_TRUNCATED_MESSAGE`; a ≥241-byte fixture cannot tell the two orderings
     apart. Error code 7125 `ERR_WRONG_ENTRY_POINT` is new in this revision (§19.8).
   - `NEG-VERSION-SHORT` is 100 bytes with `msg[0] == 0x03` and `msg[1] == 0x02` — also below 241,
     which is what makes §10.6's "no downgrade path, unconditional on length" testable at all.

 WHY TWO VECTORS RUN THE CONSUMER API. `NEG-PUBKEY-REFLECT-02-SPK` and `NEG-PUBKEY-REFLECT-02-DHS`
 are the two anti-reflection comparisons §10.2 explicitly refuses to host, because at gate time the
 responder has resolved neither `spk_id` (that is §10.7 step 5) nor the session's `DHs` (that is
 §11.2's load). Evaluating them through IRMessageGate alone would assert nothing: the gate ACCEPTS
 both messages, and each vector records that acceptance as the intermediate `type02_gate_passed`.
 They therefore run through IRMessenger over the reference stores, and their `inputs` carry the
 responder-side material a runner needs to rebuild the fixture — a §12.1 state blob for the session
 (§15.5's reserved `sessions` key), and the signed-prekey and one-time-prekey material for the
 store. `NEG-ENTRYPOINT-02-TO-01` runs the same session fixture, because §15.4 makes the resolving
 handle load-bearing for that row: without one, a port that evaluates §10.1 check 6 too early
 returns `ERR_NO_SESSION` and passes for the wrong reason.

 THE CLOCK. The twelve parser vectors read NO clock and supply no `now_*`; IRMessageGate is a pure
 function of the bytes, and the driver's ten-years-forward run is what proves that claim (§15.6).
 The three messenger vectors DO read one — §10.7 step 4 and §11.4 consult the tombstone window, and
 the prekey store sweeps `OPK_MAX_AGE_S` — so each supplies `now_ms` and the executor injects it
 through IRVectorEnvironmentAtUnixMilliseconds. §15.5 rule 6 makes a clock-reading vector without a
 `now_*` malformed, not merely fragile.

 RANDOMNESS. Every X25519 scalar below is fed to the REAL key generator through
 IRScriptedRandomSource (§15.5 rule 5) rather than being hand-clamped, so the public halves in the
 frozen file are whatever the implementation derives and §4.2's clamp is applied by the code under
 test. Identities are reproduced the same way: +[IRIdentity generateWithProvider:] draws the Ed25519
 seed first and the X25519 scalar second, then signs `IKBIND_MSG`, so scripting those two in that
 order reproduces a whole identity, `IKB` included, through an API that exposes no injection point.
 That source FAILS on exhaustion rather than cycling, and every helper asserts it was drained.

 THE CIPHERTEXT IS OPAQUE, on the same terms as wire.json: `ciphertext_and_tag` is a fixed 16-byte
 literal — the tag of an empty plaintext, which §10.4 makes legal — rather than the output of a real
 seal. Every rejection in this file happens strictly before the AEAD, so a real seal would add a
 dependency on the ratchet without adding a single assertion. The 16-byte payload is also what makes
 the two base messages exactly 72 and 241 bytes: §18's two minima, which three of these vectors need
 to hit on the nose.
 */

#pragma mark - Fixed key material

/* Ed25519 seeds (§4.2: the 32-byte RFC 8032 seed, never libsodium's 64-byte expanded sk). */
static NSString * const kNegWireAliceEd25519Seed =
    @"c1102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f001";
static NSString * const kNegWireBobEd25519Seed =
    @"c2112131415161718191a1b1c1d1e1f1112131415161718191a1b1c1d1e1f101";

/* Raw X25519 scalars as handed to the CSPRNG seam. The stored form is the §4.2 CLAMP of these, and
   the public halves are derived from the clamped scalar by the implementation. */
static NSString * const kNegWireAliceX25519Scalar =
    @"c3122232425262728292a2b2c2d2e2f2122232425262728292a2b2c2d2e2f202";
static NSString * const kNegWireBobX25519Scalar =
    @"c4132333435363738393a3b3c3d3e3f3132333435363738393a3b3c3d3e3f303";

/// `EK_A` — the handshake ephemeral carried in the type `0x02` prologue.
static NSString * const kNegWireEphemeralScalar =
    @"c5142434445464748494a4b4c4d4e4f4142434445464748494a4b4c4d4e4f404";

/// `DHs_pub` as it travels on the wire, in BOTH base messages. Distinct from `EK_A`, so §10.2
/// check 11 passes on the unmodified type `0x02` base and only fires on the spliced variant.
static NSString * const kNegWireSenderRatchetScalar =
    @"c6152535455565758595a5b5c5d5e5f5152535455565758595a5b5c5d5e5f505";

/// The RECEIVER's own `DHs` public — §10.1 check 8's operand. Distinct from the sender's, except in
/// `NEG-PUBKEY-REFLECT-01` where the vector deliberately supplies the sender's.
static NSString * const kNegWireOwnRatchetScalar =
    @"c7162636465666768696a6b6c6d6e6f6162636465666768696a6b6c6d6e6f606";

/// `SPK_B` — B's signed prekey, and §10.7 step 6's operand.
static NSString * const kNegWireSignedPreKeyScalar =
    @"c8172737475767778797a7b7c7d7e7f7172737475767778797a7b7c7d7e7f707";

/// `OPK_B` — present in B's store purely so that §10.7 step 7 cannot be the check that fires.
static NSString * const kNegWireOneTimePreKeyScalar =
    @"c9182838485868788898a8b8c8d8e8f8182838485868788898a8b8c8d8e8f808";

/// The live session's own `DHs` — §11.2 check 3's operand.
static NSString * const kNegWireSessionRatchetScalar =
    @"ca192939495969798999a9b9c9d9e9f9192939495969798999a9b9c9d9e9f909";

/// The live session's `DHr`, so the fixture is the shape a responder actually holds after its first
/// ratchet rather than the §7.5 initial shape.
static NSString * const kNegWireSessionPeerRatchetScalar =
    @"cb1a2a3a4a5a6a7a8a9aaabacadaeafa1a2a3a4a5a6a7a8a9aaabacadaeafa0a";

#pragma mark - Fixed non-key material

static NSString * const kNegWireNonceType01 = @"0102030405060708090a0b0c";
static NSString * const kNegWireNonceType02 = @"1112131415161718191a1b1c";

/**
 A 16-byte Poly1305 tag and nothing else — the empty plaintext §10.4 declares legal.

 This is what makes the type `0x01` base exactly 72 bytes and the type `0x02` base exactly 241: the
 two minima of §18, which `NEG-TRUNCATED`, `NEG-ENTRYPOINT-01-TO-02` and `NEG-VERSION-SHORT` all
 need to sit on or just below. A longer payload would still be a valid message and would still be
 rejected for the right reason, but the length bands §15.4 fixes would no longer be expressible.
 */
static NSString * const kNegWireCiphertextAndTag = @"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

/// The live session's `RK` and `CKr`. Opaque 32-byte literals: no vector here advances a chain.
static NSString * const kNegWireSessionRootKey =
    @"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef";
static NSString * const kNegWireSessionReceivingChainKey =
    @"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf";

static const uint32_t kNegWireSpkId = 7;
static const uint32_t kNegWireOpkId = 42;

/* §9.1: N is this message's number in the current sending chain, PN the length of the PREVIOUS
   sending chain. Deliberately different, and deliberately both below MAX_COUNTER, so that
   `NEG-COUNTER` is the only vector in this file whose counters are out of range. */
static const uint32_t kNegWireType01N  = 5;
static const uint32_t kNegWireType01PN = 2;

/// §9.2 — `N` MAY be non-zero in a type `0x02` header; zero here keeps the base message the
/// plainest possible legal one, so `NEG-PREKEY-PN` and `NEG-OPKFLAG-ID` each differ from it in
/// exactly one field.
static const uint32_t kNegWireType02N = 0;

/* §5.2's window, as fixed literals that are part of the frozen bytes. 2026-01-01T00:00:00Z to
   2026-03-30T00:00:00Z: 7603200 seconds, inside MAX_SPK_VALIDITY_SECONDS (7776000). No vector in
   this file evaluates the window — §5.3 rules 5–6 are carried by `NEG-SPK-EXPIRED` and
   `NEG-SPK-WINDOW-TOO-LONG` — but a value that could not pass rule 6 would be a trap for whoever
   reuses these bytes. */
static const uint64_t kNegWireNotBeforeS = 1767225600ULL;
static const uint64_t kNegWireNotAfterS  = 1774828800ULL;

/// The injected clock for the three vectors that read one: 2026-01-08T00:00:00Z, inside the window
/// above and 604800 s after the OPK's creation, which is well inside `OPK_MAX_AGE_S` (7776000).
static const uint64_t kNegWireNowMs = 1767830400000ULL;
static const uint64_t kNegWireOpkCreatedAtS = 1767225600ULL;

#pragma mark - Deterministic construction helpers

/**
 An X25519 pair derived from a fixed scalar through the REAL generator (§15.5 rule 5).

 A fresh IRScriptedRandomSource per pair, holding exactly the 32 bytes
 -generateX25519KeyPairWithError: draws. That source fails on exhaustion rather than cycling, so a
 generator that drew more than it scripted stops here instead of silently reusing bytes.
 */
static IRX25519KeyPair *IRNegWireX25519PairFromScalar(NSString *scalarHex) {
    NSData *scalar = IRVectorBytes(scalarHex);
    IRVectorRequire(scalar.length == 32, @"X25519 scalar must be 32 bytes, got %lu",
                    (unsigned long)scalar.length);

    IRScriptedRandomSource *source = [IRScriptedRandomSource sourceWithData:scalar];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IRX25519KeyPair *pair = [provider generateX25519KeyPairWithError:&error];
    IRVectorRequire(pair != nil, @"X25519 generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"scripted %lu bytes for one X25519 pair and %lu were left over",
                    (unsigned long)scalar.length, (unsigned long)source.bytesRemaining);

    return pair;
}

/// An identity from a fixed Ed25519 seed and a fixed X25519 scalar, with a GENUINE `IKB` (§5.1).
static IRIdentity *IRNegWireIdentity(NSString *seedHex, NSString *scalarHex) {
    NSData *seedBytes = IRVectorBytes(seedHex);
    NSData *scalarBytes = IRVectorBytes(scalarHex);
    IRVectorRequire(seedBytes.length == 32, @"Ed25519 seed must be 32 bytes");
    IRVectorRequire(scalarBytes.length == 32, @"X25519 scalar must be 32 bytes");

    /* +generateWithProvider: draws the Ed25519 seed first and the X25519 scalar second, then signs
       IKBIND_MSG. Scripting the two in that order reproduces a whole identity, IKB included, with
       no injection point the production API exposes. */
    IRScriptedRandomSource *source =
        [IRScriptedRandomSource sourceWithDataItems:@[seedBytes, scalarBytes]];
    id<IRCryptoProvider> provider =
        IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source));

    NSError *error = nil;
    IRIdentity *identity = [IRIdentity generateWithProvider:provider error:&error];
    IRVectorRequire(identity != nil, @"identity generation failed: %@", error);
    IRVectorRequire(source.bytesRemaining == 0,
                    @"identity generation left %lu scripted bytes unread",
                    (unsigned long)source.bytesRemaining);

    return identity;
}

/// An identity rebuilt inside an EXECUTOR, where a malformed vector must be a recorded failure
/// rather than a raise. Returns nil and leaves the diagnosis to the caller's guard.
static IRIdentity *_Nullable IRNegWireIdentityFromBytes(NSData *seedBytes,
                                                        NSData *scalarBytes,
                                                        NSError **error) {
    if (seedBytes.length != 32 || scalarBytes.length != 32) {
        return nil;
    }

    IRScriptedRandomSource *source =
        [IRScriptedRandomSource sourceWithDataItems:@[seedBytes, scalarBytes]];

    return [IRIdentity generateWithProvider:
                IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(source))
                                      error:error];
}

static IRNonce *IRNegWireNonce(NSString *hex) {
    NSError *error = nil;
    IRNonce *nonce = [IRNonce fromData:IRVectorBytes(hex) error:&error];
    IRVectorRequire(nonce != nil, @"nonce %@: %@", hex, error);

    return nonce;
}

#pragma mark - Byte surgery

/**
 BYTE SURGERY IS THE ONLY WAY TO BUILD MOST OF THESE FIXTURES, and that is deliberate.

 IRMessageBuilder IS A CONFORMANT ENCODER: it refuses `DHs_pub == EK_A` (§10.2 check 11, applied on
 the send side so a sender's own bug names itself instead of surfacing on a peer), and it does not
 expose `PN` for a type `0x02` header at all, because §9.2 fixes it at zero and making a field
 unwritable is stronger than validating it. Weakening either to let a negative vector through would
 delete a real check from the send path in order to test one on the receive path. So every fixture
 starts as a valid message the real encoder produced and then has exactly one field overwritten at a
 §9 offset — which also documents, in the call, precisely which field the vector attacks.
 */
static NSData *IRNegWireSplice(NSData *original, NSUInteger offset, NSData *replacement) {
    IRVectorRequire(offset + replacement.length <= original.length,
                    @"splice of %lu bytes at offset %lu exceeds the %lu-byte artifact",
                    (unsigned long)replacement.length, (unsigned long)offset,
                    (unsigned long)original.length);

    NSMutableData *forged = [original mutableCopy];
    [forged replaceBytesInRange:NSMakeRange(offset, replacement.length)
                      withBytes:replacement.bytes];

    return forged;
}

static NSData *IRNegWireByte(uint8_t value) {
    return [NSData dataWithBytes:&value length:1];
}

static NSData *IRNegWireBE16(uint16_t value) {
    uint8_t bytes[2] = { (uint8_t)(value >> 8), (uint8_t)value };

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

static NSData *IRNegWireBE32(uint32_t value) {
    uint8_t bytes[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8), (uint8_t)value
    };

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

/// §4.4 check 2 — sets bit 255 of the X25519 public key at `offset`, which is the ONE bit that
/// distinguishes an invalid encoding from a valid one without changing anything else about it.
static NSData *IRNegWireSetHighBit(NSData *original, NSUInteger keyOffset) {
    IRVectorRequire(keyOffset + 32 <= original.length, @"high-bit splice is out of bounds");

    NSMutableData *forged = [original mutableCopy];
    uint8_t *raw = [forged mutableBytes];
    raw[keyOffset + 31] = (uint8_t)(raw[keyOffset + 31] | 0x80);

    return forged;
}

#pragma mark - Evaluation — the parser pipeline (§10.0, §10.1, §10.2)

/**
 One evaluation, shared by the generator's self-check and by the executor.

 THE SEQUENCE IS §10.0 THEN THE GATE, IN THAT ORDER AND NEVER THE OTHER WAY. IRMessageGate's class
 comment fixes the required call sequence for type `0x01` — demultiplex, prefix gate, the caller's
 session resolution (check 6), then the rest — and this function reproduces it exactly, minus
 check 6, which a parser-level vector has no session to perform. The three rows that DO need a
 resolving handle run through IRMessenger instead; see IRNegWireEvaluateSessionVector.

 `outRoutedType` receives §11.5 rule 5's routing helper result whenever rows 1–4 pass, EVEN IF row 5
 then fails. That is the whole observable behind `NEG-ENTRYPOINT-*`: the type was resolved
 successfully and the rejection is a property of *(message, entry point)*, not of the message —
 which is §19.8's argument for 7125 rather than 7101 in one field.

 `ownRatchetPublic` is §10.1 check 8's operand and is REQUIRED for `decrypt_with_handle`. It is
 `_Nonnull` on +parseType01Message:ownRatchetPublicKey:error: on purpose, so passing nil there would
 trap through IRRequireArgument (§13.4) rather than report; callers guard before entering.
 */
static BOOL IRNegWireEvaluateParser(NSString *entryPointName,
                                    NSData *message,
                                    IRX25519Public *_Nullable ownRatchetPublic,
                                    IRMessageType *_Nullable outRoutedType,
                                    NSError **error) {
    if ([entryPointName isEqualToString:@"message_type"]) {
        /* §10.0 rows 1–4 alone — the routing helper §11.5 rule 5 makes REQUIRED API. It has no
           expected type, so row 5 cannot apply to it. */
        IRMessageType routed = [IRMessageGate messageTypeOfMessage:message error:error];
        if (routed == 0) {
            return NO;
        }

        if (outRoutedType != NULL) {
            *outRoutedType = routed;
        }

        return YES;
    }

    BOOL prekeyEntryPoint = [entryPointName isEqualToString:@"decrypt_prekey"];
    IRMessageType expectedType = prekeyEntryPoint ? IRMessageTypePrekey : IRMessageTypeNormal;

    /* Rows 1–4 first, so `routed_type` is observable on a row-5 failure. This costs one extra pass
       over five bytes and buys the only intermediate that distinguishes "the type could not be
       read" from "the type was read and the host called the wrong entry point". */
    NSError *routeError = nil;
    IRMessageType routed = [IRMessageGate messageTypeOfMessage:message error:&routeError];
    if (routed != 0 && outRoutedType != NULL) {
        *outRoutedType = routed;
    }

    /* §10.0 in full — rows 1–4 again, then row 5. Entry points do NOT forward. */
    if (![IRMessageGate demultiplexMessage:message expectedType:expectedType error:error]) {
        return NO;
    }

    if (prekeyEntryPoint) {
        /* §10.2 checks 1–11, complete and self-contained. */
        return [IRMessageGate parseType02Message:message error:error] != nil;
    }

    /* §10.1 checks 1–5, then — check 6 being the caller's — checks 7–10. */
    if (![IRMessageGate gateType01Prefix:message error:error]) {
        return NO;
    }

    /* §13.4 — unreachable, and asserted rather than coerced. Every caller guards `own_DHs_pub`
       before entering, because passing nil for `ownRatchetPublicKey:` would TRAP through
       IRRequireArgument rather than report, and a trap takes the whole test binary with it. */
    IRVectorRequire(ownRatchetPublic != nil,
                    @"§10.1 check 8 has no operand: a decrypt_with_handle evaluation requires "
                    @"own_DHs_pub");

    return [IRMessageGate parseType01Message:message
                         ownRatchetPublicKey:(IRX25519Public * _Nonnull)ownRatchetPublic
                                       error:error] != nil;
}

#pragma mark - The responder fixture

/**
 Everything a §10.7 or §11.2 evaluation needs, held together so an executor can assert against the
 stores after the call as well as against the error code.
 */
@interface IRNegWireResponder : NSObject
@property (nonatomic, strong) IRMessenger *messenger;
@property (nonatomic, strong) IRInMemoryPreKeyStore *preKeys;
@property (nonatomic, strong) IRInMemorySessionStore *sessions;
/// The one live session, for the two vectors that install one. Nil otherwise.
@property (nonatomic, strong, nullable) IRSession *session;
@end

@implementation IRNegWireResponder
@end

/// B's messenger over empty reference stores, with the clock pinned to `nowMs` (§15.5 rule 6).
static IRNegWireResponder *_Nullable IRNegWireResponderWithIdentity(IRIdentity *identity,
                                                                    uint64_t nowMs,
                                                                    NSError **error) {
    IRNegWireResponder *responder = [[IRNegWireResponder alloc] init];
    responder.preKeys = [IRInMemoryPreKeyStore store];
    responder.sessions = [IRInMemorySessionStore store];

    /* The environment carries the injected clock; the provider is built OVER it, so every expiry,
       tombstone and TTL decision below reads the vector's `now_ms` and none reads the host's. The
       random source is the production one: no path reached by these vectors draws a byte, and if
       one ever did, the vector's frozen bytes do not depend on it. */
    IREnvironment *environment = IRVectorEnvironmentAtUnixMilliseconds(nowMs, nil);

    id<IRCryptoProvider> provider = IRVectorProviderWithEnvironment(environment);

    responder.messenger = [[IRMessenger alloc] initWithIdentity:identity
                                                    preKeyStore:responder.preKeys
                                                   sessionStore:responder.sessions
                                                       provider:provider
                                                    environment:environment
                                                          error:error];
    if (responder.messenger == nil) {
        return nil;
    }

    return responder;
}

/**
 B's messenger with `spk_id` and `opk_id` resolvable — the §10.7 steps 5 and 7 fixture.

 THE ONE-TIME PREKEY IS PRESENT ON PURPOSE. `NEG-PUBKEY-REFLECT-02-SPK` pins §10.7 step 6, and step
 7 is the very next check; a fixture with no OPK would return `ERR_UNKNOWN_PREKEY_ID` under a port
 that had the two transposed, and the vector would silently be testing step 7 instead. With both
 resolvable, step 6 is the only step that can fail.
 */
static IRNegWireResponder *_Nullable IRNegWirePreKeyResponder(IRIdentity *identity,
                                                              uint64_t nowMs,
                                                              uint32_t spkId,
                                                              IRX25519KeyPair *signedPreKey,
                                                              uint64_t notBeforeS,
                                                              uint64_t notAfterS,
                                                              IREd25519Signature *spkSignature,
                                                              uint32_t opkId,
                                                              IRX25519KeyPair *oneTimePreKey,
                                                              uint64_t opkCreatedAtS,
                                                              NSError **error) {
    IRNegWireResponder *responder = IRNegWireResponderWithIdentity(identity, nowMs, error);
    if (responder == nil) {
        return nil;
    }

    /* Rehydrated, not generated: §5.6's restore-from-storage constructor keeps the STORED signature
       rather than recomputing it, which is the same rule §5.1 states for IKB and the reason this
       fixture is reproducible from the vector's bytes at all. */
    IRSignedPreKeyRecord *spkRecord = [IRSignedPreKeyRecord recordWithSpkId:spkId
                                                                   keyPair:signedPreKey
                                                                notBeforeS:notBeforeS
                                                                 notAfterS:notAfterS
                                                                 signature:spkSignature
                                                                     error:error];
    if (spkRecord == nil) {
        return nil;
    }

    if (![responder.preKeys storeSignedPreKeyRecord:spkRecord makeCurrent:YES error:error]) {
        return nil;
    }

    IROneTimePreKeyRecord *opkRecord = [IROneTimePreKeyRecord recordWithOpkId:opkId
                                                                     keyPair:oneTimePreKey
                                                           createdAtUnixSecs:opkCreatedAtS
                                                                       error:error];
    if (opkRecord == nil) {
        return nil;
    }

    if (![responder.preKeys storeOneTimePreKeyRecords:@[opkRecord] error:error]) {
        return nil;
    }

    return responder;
}

/**
 B's messenger with ONE live session, restored from a literal §12.1 blob — the §11.2 fixture.

 THE SESSION IS SUPPLIED AS A BLOB, NEVER AS "REPLAY THIS HANDSHAKE", which is §15.5's reserved
 `sessions` key and the same reproducibility rule state.json is built on: a handshake replayed by
 four ports is four sequences of RNG draws, while a blob is 472 bytes that either parse or do not.

 The blob goes through §12.2's nine rules on the way in, so a vector whose fixture is malformed
 fails here — loudly, with `ERR_STATE_CORRUPT` — rather than turning into a mysterious
 `ERR_NO_SESSION` from the routing index.
 */
static IRNegWireResponder *_Nullable IRNegWireSessionResponder(IRIdentity *identity,
                                                               uint64_t nowMs,
                                                               NSData *stateBlob,
                                                               NSError **error) {
    IRNegWireResponder *responder = IRNegWireResponderWithIdentity(identity, nowMs, error);
    if (responder == nil) {
        return nil;
    }

    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:stateBlob
                                                                 atTimeMs:nowMs
                                                                    error:error];
    if (state == nil) {
        return nil;
    }

    IRSession *session = [IRSession sessionWithState:state error:error];
    if (session == nil) {
        return nil;
    }

    /* §11.1.1's only entry point. The store is empty, so nothing is displaced and the survivor is
       the session just installed. */
    IRSessionEstablishResult *result = [responder.sessions establishSession:session
                                                                   atTimeMs:nowMs
                                                                      error:error];
    if (result == nil) {
        return nil;
    }

    responder.session = result.survivingSession;

    return responder;
}

/// The §12.1 blob a session currently holds, as plain bytes. §7.7's "nothing mutated" assertion is
/// expressible only because §12.1 is byte-normative (§15.5's `state_blob_after`).
static NSData *_Nullable IRNegWireSerializedState(IRSession *session, NSError **error) {
    IRSecretBytes *blob = [session serializedState:error];
    if (blob == nil) {
        return nil;
    }

    return [NSData dataWithBytes:[blob constBytes] length:blob.length];
}

#pragma mark - The base artifacts

/**
 Everything the generator builds once and then mutates one field at a time.

 Kept in one object rather than rebuilt per vector so that "the base is valid" is established ONCE:
 IRNegWireBuildFixture ends by asserting that the unmodified type `0x01` and type `0x02` messages
 both pass their gates. Without that, a fixture rejected for an unintended reason — say a base
 message that was malformed all along — would look exactly like a fixture rejected for the intended
 one, and every vector in the file would be green for the wrong reason.
 */
@interface IRNegWireFixture : NSObject

@property (nonatomic, strong) IRIdentity *alice;               ///< A, the initiator
@property (nonatomic, strong) IRIdentity *bob;                 ///< B, the responder

@property (nonatomic, strong) IRX25519KeyPair *ephemeral;      ///< EK_A
@property (nonatomic, strong) IRX25519KeyPair *senderRatchet;  ///< the DHs_pub that travels
@property (nonatomic, strong) IRX25519KeyPair *ownRatchet;     ///< §10.1 check 8's operand
@property (nonatomic, strong) IRX25519KeyPair *signedPreKey;   ///< SPK_B
@property (nonatomic, strong) IRX25519KeyPair *oneTimePreKey;  ///< OPK_B
@property (nonatomic, strong) IRX25519KeyPair *sessionRatchet; ///< the live session's DHs
@property (nonatomic, strong) IRX25519KeyPair *sessionPeerRatchet;  ///< the live session's DHr

@property (nonatomic, strong) IREd25519Signature *spkSignature;
@property (nonatomic, strong) IRSessionPrologue *prologue;

@property (nonatomic, copy) NSData *type01Message;   ///< 72 bytes, valid
@property (nonatomic, copy) NSData *type02Message;   ///< 241 bytes, valid

@property (nonatomic, copy) NSData *sessionStateBlob;   ///< §12.1, the live responder session
@property (nonatomic, copy) NSData *sessionHandshakeId; ///< §11.1 — IK_A^d ‖ EK_A

@end

@implementation IRNegWireFixture
@end

static IRNegWireFixture *IRNegWireBuildFixture(void) {
    NSError *error = nil;
    IRNegWireFixture *f = [[IRNegWireFixture alloc] init];

    f.alice = IRNegWireIdentity(kNegWireAliceEd25519Seed, kNegWireAliceX25519Scalar);
    f.bob = IRNegWireIdentity(kNegWireBobEd25519Seed, kNegWireBobX25519Scalar);

    f.ephemeral = IRNegWireX25519PairFromScalar(kNegWireEphemeralScalar);
    f.senderRatchet = IRNegWireX25519PairFromScalar(kNegWireSenderRatchetScalar);
    f.ownRatchet = IRNegWireX25519PairFromScalar(kNegWireOwnRatchetScalar);
    f.signedPreKey = IRNegWireX25519PairFromScalar(kNegWireSignedPreKeyScalar);
    f.oneTimePreKey = IRNegWireX25519PairFromScalar(kNegWireOneTimePreKeyScalar);
    f.sessionRatchet = IRNegWireX25519PairFromScalar(kNegWireSessionRatchetScalar);
    f.sessionPeerRatchet = IRNegWireX25519PairFromScalar(kNegWireSessionPeerRatchetScalar);

    /* Distinctness is a PRECONDITION of half this file, not a coincidence: if the sender's ratchet
       key happened to equal the receiver's own, `NEG-FLAGS` would be rejected by §10.1 check 8
       instead of check 5 and would freeze the wrong code. */
    IRVectorRequire(![f.senderRatchet.publicKey isEqualToX25519Public:f.ownRatchet.publicKey],
                    @"the sender's DHs and the receiver's own DHs must differ");
    IRVectorRequire(![f.senderRatchet.publicKey isEqualToX25519Public:f.ephemeral.publicKey],
                    @"§10.2 check 11: DHs_pub and EK_A must differ in the base message");
    IRVectorRequire(![f.senderRatchet.publicKey isEqualToX25519Public:f.signedPreKey.publicKey],
                    @"§10.7 step 6: DHs_pub and SPK_B must differ in the base message");
    IRVectorRequire(![f.senderRatchet.publicKey isEqualToX25519Public:f.sessionRatchet.publicKey],
                    @"§11.2 check 3: DHs_pub and the session's DHs must differ in the base "
                    @"message");

    #pragma mark The 72-byte type 0x01 base

    NSData *type01Header =
        [IRMessageBuilder type01HeaderWithRatchetKey:f.senderRatchet.publicKey
                                                   N:kNegWireType01N
                                                  PN:kNegWireType01PN
                                               nonce:IRNegWireNonce(kNegWireNonceType01)
                                               error:&error];
    IRVectorRequire(type01Header != nil, @"type 0x01 header: %@", error);

    f.type01Message =
        [IRMessageBuilder messageWithHeaderBytes:type01Header
                                ciphertextAndTag:IRVectorBytes(kNegWireCiphertextAndTag)
                                           error:&error];
    IRVectorRequire(f.type01Message != nil, @"type 0x01 message: %@", error);
    IRVectorRequire(f.type01Message.length == (NSUInteger)kIRLenType01Min,
                    @"the type 0x01 base must be exactly %lu bytes (§18), got %lu",
                    (unsigned long)kIRLenType01Min, (unsigned long)f.type01Message.length);

    #pragma mark The 241-byte type 0x02 base

    f.prologue = [IRSessionPrologue prologueWithEphemeralPublic:f.ephemeral.publicKey
                                                          spkId:kNegWireSpkId
                                                        opkFlag:IROPKFlagPresent
                                                          opkId:kNegWireOpkId
                                                          error:&error];
    IRVectorRequire(f.prologue != nil, @"prologue: %@", error);

    NSData *type02Header =
        [IRMessageBuilder type02HeaderWithInitiatorIdentity:f.alice.identityKeyPair
                                            identityBinding:f.alice.binding
                                                   prologue:f.prologue
                                                 ratchetKey:f.senderRatchet.publicKey
                                                          N:kNegWireType02N
                                                      nonce:IRNegWireNonce(kNegWireNonceType02)
                                                      error:&error];
    IRVectorRequire(type02Header != nil, @"type 0x02 header: %@", error);

    f.type02Message =
        [IRMessageBuilder messageWithHeaderBytes:type02Header
                                ciphertextAndTag:IRVectorBytes(kNegWireCiphertextAndTag)
                                           error:&error];
    IRVectorRequire(f.type02Message != nil, @"type 0x02 message: %@", error);
    IRVectorRequire(f.type02Message.length == (NSUInteger)kIRLenType02Min,
                    @"the type 0x02 base must be exactly %lu bytes (§18), got %lu",
                    (unsigned long)kIRLenType02Min, (unsigned long)f.type02Message.length);

    #pragma mark SPK_SIG — genuine, because §10.7 step 5 has to resolve the record

    /* §5.2 — SPK_SIG over the 130-byte SPK_SIGN_MSG, under B's IK^s. Ed25519 is deterministic
       (RFC 8032 §5.1.6), so this is reproducible across runs and across platforms, which is what
       lets `NEG-PUBKEY-REFLECT-02-SPK` carry it as a literal in `inputs` and have every port
       rebuild the same prekey record from it. */
    NSData *spkSignMessage = IRSPKSignMessage(f.bob.identityKeyPair,
                                              kNegWireSpkId,
                                              f.signedPreKey.publicKey,
                                              kNegWireNotBeforeS,
                                              kNegWireNotAfterS,
                                              &error);
    IRVectorRequire(spkSignMessage != nil, @"SPK_SIGN_MSG: %@", error);

    f.spkSignature = [f.bob signData:spkSignMessage error:&error];
    IRVectorRequire(f.spkSignature != nil, @"SPK_SIG: %@", error);

    #pragma mark The live responder session (§12.1)

    /* §11.1 — `handshake_id = IK_A^d ‖ EK_A`, and it MUST equal what the type `0x02` header yields,
       or §11.2's dispatch finds nothing and the vector silently becomes a §10.7 vector. Built from
       the same two public keys the header carries, rather than sliced out of the message, so the
       two derivations are compared rather than assumed. */
    NSMutableData *handshakeId = [NSMutableData data];
    [handshakeId appendData:f.alice.identityKeyPair.agreementKey.data];
    [handshakeId appendData:f.ephemeral.publicKey.data];
    IRVectorRequire(handshakeId.length == (NSUInteger)kIRLenHandshakeId,
                    @"handshake_id is %lu bytes (§18), got %lu",
                    (unsigned long)kIRLenHandshakeId, (unsigned long)handshakeId.length);

    NSData *headerHandshakeId =
        [f.type02Message subdataWithRange:NSMakeRange(kIROffType02IdentityAgreement, 32)];
    NSMutableData *headerDerived = [headerHandshakeId mutableCopy];
    [headerDerived appendData:[f.type02Message subdataWithRange:NSMakeRange(kIROffType02EK, 32)]];
    IRVectorRequire([headerDerived isEqualToData:handshakeId],
                    @"the fixture's handshake_id does not match the type 0x02 header's");

    f.sessionHandshakeId = handshakeId;

    /* §6.5 — BY ROLE. A is the initiator, B the responder; a fixture that spelled this (self, peer)
       would build a SESSION_AD whose peer half resolves to the wrong identity and §11.2 check 1
       would fire instead of check 3. */
    IRSessionAD *sessionAD = [IRSessionAD adWithInitiator:f.alice.identityKeyPair
                                                responder:f.bob.identityKeyPair
                                                    error:&error];
    IRVectorRequire(sessionAD != nil, @"SESSION_AD: %@", error);

    /* `guarded:NO`: these are vector literals that are already public, they live for the length of
       one generator run, and §13.3's guarded allocation rounds up to a page per call. */
    IRRootKey *rootKey = [IRRootKey fromData:IRVectorBytes(kNegWireSessionRootKey)
                                     guarded:NO
                                       error:&error];
    IRVectorRequire(rootKey != nil, @"RK: %@", error);

    IRChainKey *receivingChainKey =
        [IRChainKey fromData:IRVectorBytes(kNegWireSessionReceivingChainKey)
                     guarded:NO
                       error:&error];
    IRVectorRequire(receivingChainKey != nil, @"CKr: %@", error);

    /* The shape a responder actually holds after its first ratchet: a receiving chain and no
       sending chain. Nothing here is advanced by any vector in this file — every rejection lands
       before the ratchet is touched — so the values are opaque literals and the blob is what
       matters. */
    IRRatchetState *state = [IRRatchetState stateWithRole:IRSessionRoleResponder
                                                sessionAD:sessionAD
                                              handshakeId:f.sessionHandshakeId
                                                  rootKey:rootKey
                                           ratchetKeyPair:f.sessionRatchet
                                        peerRatchetPublic:f.sessionPeerRatchet.publicKey
                                          sendingChainKey:nil
                                        receivingChainKey:receivingChainKey
                                                       Ns:0
                                                       Nr:1
                                                       PN:0
                                              sendCounter:0
                                                 prologue:nil
                                                  skipped:nil
                                                    error:&error];
    IRVectorRequire(state != nil, @"responder ratchet state: %@", error);

    IRSecretBytes *blob = [IRSessionStateCodec serializeState:state error:&error];
    IRVectorRequire(blob != nil, @"§12.1 serialization: %@", error);
    IRVectorRequire(blob.length == (NSUInteger)kIRLenStatePrefix,
                    @"a blob with no skipped keys is %lu bytes (§18), got %lu",
                    (unsigned long)kIRLenStatePrefix, (unsigned long)blob.length);

    f.sessionStateBlob = [NSData dataWithBytes:[blob constBytes] length:blob.length];

    /* PARSE → RESERIALIZE MUST BE THE IDENTITY, and it is asserted at GENERATION time rather than
       left for the executor: `state_blob_after` in every session vector's `outputs` is the input
       blob, so if the codec were not an identity here, every one of those vectors would fail with a
       message about §7.7 atomicity when the real defect is in the codec. */
    IRNegWireResponder *roundTrip = IRNegWireSessionResponder(f.bob,
                                                              kNegWireNowMs,
                                                              f.sessionStateBlob,
                                                              &error);
    IRVectorRequire(roundTrip != nil, @"the session fixture does not restore: %@", error);

    NSData *reserialized = IRNegWireSerializedState(roundTrip.session, &error);
    IRVectorRequire([reserialized isEqualToData:f.sessionStateBlob],
                    @"§12.1 parse-then-reserialize is not the identity: %@",
                    reserialized ? IRVectorHex(reserialized) : @"nil");

    #pragma mark Every base artifact is valid — asserted, not assumed

    error = nil;
    IRVectorRequire(IRNegWireEvaluateParser(@"decrypt_with_handle",
                                            f.type01Message,
                                            f.ownRatchet.publicKey,
                                            NULL,
                                            &error),
                    @"the type 0x01 base does not pass its own gate: %@", error);

    error = nil;
    IRVectorRequire(IRNegWireEvaluateParser(@"decrypt_prekey",
                                            f.type02Message,
                                            nil,
                                            NULL,
                                            &error),
                    @"the type 0x02 base does not pass its own gate: %@", error);

    return f;
}

#pragma mark - Generator-side self-check

/// Runs a parser vector at generation time and hard-fails unless the FIRST error is `expected`.
static void IRNegWireRequireParserError(NSString *identifier,
                                        NSString *entryPoint,
                                        NSData *message,
                                        IRX25519Public *_Nullable ownRatchetPublic,
                                        IRErrorCode expected) {
    NSError *error = nil;
    BOOL ok = IRNegWireEvaluateParser(entryPoint, message, ownRatchetPublic, NULL, &error);

    IRVectorRequire(!ok, @"[%@] the implementation ACCEPTED a vector that must be rejected with %@",
                    identifier, IRErrorNameForCode(expected));
    IRVectorRequire(error != nil, @"[%@] rejected with no error set — §10.5 forbids it",
                    identifier);
    IRVectorRequire([error.domain isEqualToString:IRErrorDomain],
                    @"[%@] error domain is %@", identifier, error.domain);
    IRVectorRequire((IRErrorCode)error.code == expected,
                    @"[%@] expected %@ (%ld), got %@ (%ld) — the gate order is normative and this "
                    @"vector is testing a different rule than it claims",
                    identifier, IRErrorNameForCode(expected), (long)expected,
                    IRErrorNameForCode((IRErrorCode)error.code), (long)error.code);
}

/// The same, for the three vectors that run the consumer API.
static void IRNegWireRequireResponderError(NSString *identifier,
                                           NSError *_Nullable error,
                                           id _Nullable result,
                                           IRErrorCode expected) {
    IRVectorRequire(result == nil,
                    @"[%@] the implementation ACCEPTED a message that must be rejected with %@",
                    identifier, IRErrorNameForCode(expected));
    IRVectorRequire(error != nil, @"[%@] rejected with no error set", identifier);
    IRVectorRequire((IRErrorCode)error.code == expected,
                    @"[%@] expected %@, got %@",
                    identifier, IRErrorNameForCode(expected),
                    IRErrorNameForCode((IRErrorCode)error.code));
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForNegativeWire(void) {
    NSError *error = nil;
    IRNegWireFixture *f = IRNegWireBuildFixture();

    NSString *ownRatchetHex = IRVectorHex(f.ownRatchet.publicKey.data);
    NSString *senderRatchetHex = IRVectorHex(f.senderRatchet.publicKey.data);

    #pragma mark NEG-VERSION

    /* §10.0 row 3. 72 bytes — at the global floor, so rows 1 and 2 cannot pre-empt it, and the
       rejection is about the version byte and nothing else. */
    NSData *v3Message = IRNegWireSplice(f.type01Message,
                                        kIROffType01Version,
                                        IRNegWireByte(0x03));
    IRNegWireRequireParserError(@"NEG-VERSION", @"message_type", v3Message, nil,
                                IRErrorUnsupportedVersion);

    NSDictionary *negVersion = @{
        @"id"          : @"NEG-VERSION",
        @"kind"        : @"wire",
        @"description" : @"A v3 message — msg[0] == 0x03 — at the 72-byte global floor, submitted "
                         @"to §11.5 rule 5's routing helper. §10.6: there is no downgrade path and "
                         @"no dual-stack mode, and §10.0 row 3 rejects it before the type byte at "
                         @"msg[1] is even read.",
        @"expect"      : @"error",
        @"error"       : @"ERR_UNSUPPORTED_VERSION",
        @"inputs"      : @{
            @"entry_point" : @"message_type",
            @"message"     : IRVectorHex(v3Message),
        },
        @"intermediates" : @{ @"message_len" : @(v3Message.length) },
    };

    #pragma mark NEG-VERSION-SHORT

    /* §15.4 — "a 100-byte message with msg[0] == 0x03 and msg[1] == 0x02, i.e. BELOW §10.2's floor
       of 241, submitted with entry_point decrypt_prekey". This is the row that makes §10.6's
       guarantee unconditional on length: an implementation that kept a type-dependent floor ahead
       of the version check answers ERR_TRUNCATED_MESSAGE and fails. */
    NSData *shortV3 = [f.type02Message subdataWithRange:NSMakeRange(0, 100)];
    shortV3 = IRNegWireSplice(shortV3, kIROffType02Version, IRNegWireByte(0x03));
    IRVectorRequire(shortV3.length == 100, @"NEG-VERSION-SHORT must be exactly 100 bytes");
    IRVectorRequire(((const uint8_t *)shortV3.bytes)[kIROffType02Type] == 0x02,
                    @"NEG-VERSION-SHORT must keep msg[1] == 0x02");
    IRNegWireRequireParserError(@"NEG-VERSION-SHORT", @"decrypt_prekey", shortV3, nil,
                                IRErrorUnsupportedVersion);

    NSDictionary *negVersionShort = @{
        @"id"          : @"NEG-VERSION-SHORT",
        @"kind"        : @"wire",
        @"description" : @"100 bytes with msg[0] == 0x03 and msg[1] == 0x02, submitted to the "
                         @"prekey entry point. 100 is BELOW §10.2's floor of 241 and the length is "
                         @"normative: it pins §10.0 row 3 ahead of every type-dependent floor, "
                         @"which is what makes §10.6 testable. A gate-first port returns "
                         @"ERR_TRUNCATED_MESSAGE.",
        @"expect"      : @"error",
        @"error"       : @"ERR_UNSUPPORTED_VERSION",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(shortV3),
        },
        @"intermediates" : @{ @"message_len" : @(shortV3.length) },
    };

    #pragma mark NEG-TYPE

    /* §10.0 row 4 — byte 1 outside the DOMAIN {0x01, 0x02}. This code and 7125 must stay distinct:
       7101 is a predicate over the MESSAGE, 7125 over (message, entry point). */
    NSData *unknownType = IRNegWireSplice(f.type01Message, kIROffType01Type, IRNegWireByte(0x03));
    IRNegWireRequireParserError(@"NEG-TYPE", @"decrypt_prekey", unknownType, nil,
                                IRErrorUnknownMessageType);

    NSDictionary *negType = @{
        @"id"          : @"NEG-TYPE",
        @"kind"        : @"wire",
        @"description" : @"Type byte 0x03 (§9.3: there is no type 0x03), submitted to the prekey "
                         @"entry point. §10.0 row 4 fires before row 5, so this is "
                         @"ERR_UNKNOWN_MESSAGE_TYPE and NOT ERR_WRONG_ENTRY_POINT — byte 1 is not "
                         @"a message type at all, so 7125's meaning does not describe it (§19.8).",
        @"expect"      : @"error",
        @"error"       : @"ERR_UNKNOWN_MESSAGE_TYPE",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(unknownType),
        },
        @"intermediates" : @{ @"message_len" : @(unknownType.length) },
    };

    #pragma mark NEG-ENTRYPOINT-01-TO-02

    IRMessageType routed01 = 0;
    error = nil;
    BOOL accepted01 = IRNegWireEvaluateParser(@"decrypt_prekey",
                                              f.type01Message,
                                              nil,
                                              &routed01,
                                              &error);
    IRVectorRequire(!accepted01,
                    @"[NEG-ENTRYPOINT-01-TO-02] the entry point ACCEPTED the wrong type");
    IRVectorRequire((IRErrorCode)error.code == IRErrorWrongEntryPoint,
                    @"[NEG-ENTRYPOINT-01-TO-02] expected ERR_WRONG_ENTRY_POINT, got %@ — a port "
                    @"that evaluated §10.2's 241-byte floor before the demultiplex returns "
                    @"ERR_TRUNCATED_MESSAGE here",
                    IRErrorNameForCode((IRErrorCode)error.code));
    IRVectorRequire(routed01 == IRMessageTypeNormal,
                    @"[NEG-ENTRYPOINT-01-TO-02] the router must still resolve the type to 0x01");

    NSDictionary *negEntryPoint01To02 = @{
        @"id"          : @"NEG-ENTRYPOINT-01-TO-02",
        @"kind"        : @"wire",
        @"description" : @"A 72-byte, otherwise entirely valid type 0x01 message submitted to the "
                         @"prekey entry point. THE LENGTH BAND IS NORMATIVE AND MUST NOT BE "
                         @"WIDENED: 72 sits below §10.2's floor of 241, so a port that evaluated "
                         @"that floor before §10.0's demultiplex answers ERR_TRUNCATED_MESSAGE — a "
                         @"truncation that is not there. A ≥241-byte fixture cannot tell the two "
                         @"orderings apart. `routed_type` records that rows 1–4 succeeded and only "
                         @"row 5 failed.",
        @"expect"      : @"error",
        @"error"       : @"ERR_WRONG_ENTRY_POINT",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(f.type01Message),
        },
        @"intermediates" : @{
            @"message_len" : @(f.type01Message.length),
            @"routed_type" : @((unsigned)IRMessageTypeNormal),
        },
    };

    #pragma mark NEG-FLAGS

    NSData *flagsSet = IRNegWireSplice(f.type01Message, kIROffType01Flags, IRNegWireBE16(0x0001));
    IRNegWireRequireParserError(@"NEG-FLAGS", @"decrypt_with_handle", flagsSet,
                                f.ownRatchet.publicKey, IRErrorReservedFlagsSet);

    NSDictionary *negFlags = @{
        @"id"          : @"NEG-FLAGS",
        @"kind"        : @"wire",
        @"description" : @"Flags 0x0001 in a type 0x01 header — §10.1 check 5. The reserved field "
                         @"is a MUST-be-zero rather than an ignored one, so a port that skipped it "
                         @"for forward compatibility would accept traffic every conformant peer "
                         @"rejects. Every other field of this message is valid, so check 5 is the "
                         @"only check that can fire.",
        @"expect"      : @"error",
        @"error"       : @"ERR_RESERVED_FLAGS_SET",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_with_handle",
            @"message"     : IRVectorHex(flagsSet),
            @"own_DHs_pub" : ownRatchetHex,
        },
        @"intermediates" : @{ @"message_len" : @(flagsSet.length) },
    };

    #pragma mark NEG-TRUNCATED

    NSData *truncated =
        [f.type01Message subdataWithRange:NSMakeRange(0, (NSUInteger)kIRLenType01Min - 1)];
    IRVectorRequire(truncated.length == 71, @"NEG-TRUNCATED must be exactly 71 bytes");
    IRNegWireRequireParserError(@"NEG-TRUNCATED", @"decrypt_with_handle", truncated,
                                f.ownRatchet.publicKey, IRErrorTruncatedMessage);

    NSDictionary *negTruncated = @{
        @"id"          : @"NEG-TRUNCATED",
        @"kind"        : @"wire",
        @"description" : @"71 bytes — one below §18's 72-byte floor, which is check 1 of BOTH "
                         @"gates and therefore §10.0 row 1. The length is normative. Row 1 "
                         @"precedes the version and type reads deliberately: reading msg[0..2) on "
                         @"a shorter input is the out-of-bounds class §10.3 documents, and it "
                         @"traps in Swift and escapes the taxonomy on the JVM.",
        @"expect"      : @"error",
        @"error"       : @"ERR_TRUNCATED_MESSAGE",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_with_handle",
            @"message"     : IRVectorHex(truncated),
            @"own_DHs_pub" : ownRatchetHex,
        },
        @"intermediates" : @{ @"message_len" : @(truncated.length) },
    };

    #pragma mark NEG-PUBKEY-HIGHBIT

    NSData *highBit = IRNegWireSetHighBit(f.type01Message, kIROffType01DHs);
    IRNegWireRequireParserError(@"NEG-PUBKEY-HIGHBIT", @"decrypt_with_handle", highBit,
                                f.ownRatchet.publicKey, IRErrorInvalidPublicKey);

    NSDictionary *negPubkeyHighBit = @{
        @"id"          : @"NEG-PUBKEY-HIGHBIT",
        @"kind"        : @"wire",
        @"description" : @"A type 0x01 header whose DHs_pub has bit 255 set — §10.1 check 7 over "
                         @"§4.4 check 2, the RFC 7748 rule that the top bit of a u-coordinate is "
                         @"not part of the value. Exactly one bit differs from the valid base "
                         @"message, so nothing else about the key changed.",
        @"expect"      : @"error",
        @"error"       : @"ERR_INVALID_PUBLIC_KEY",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_with_handle",
            @"message"     : IRVectorHex(highBit),
            @"own_DHs_pub" : ownRatchetHex,
        },
        @"intermediates" : @{ @"message_len" : @(highBit.length) },
    };

    #pragma mark NEG-PUBKEY-REFLECT-01

    /* §10.1 check 8. The message is the UNMODIFIED base; what changes is `own_DHs_pub`, which is
       the receiving session's own ratchet public. Reflection is a property of the pair, not of the
       message, which is why this is the one vector in the file whose message is byte-identical to
       a valid one. */
    IRNegWireRequireParserError(@"NEG-PUBKEY-REFLECT-01", @"decrypt_with_handle", f.type01Message,
                                f.senderRatchet.publicKey, IRErrorInvalidPublicKey);

    NSDictionary *negPubkeyReflect01 = @{
        @"id"          : @"NEG-PUBKEY-REFLECT-01",
        @"kind"        : @"wire",
        @"description" : @"§10.1 check 8 — the header's DHs_pub equals OUR OWN DHs public. The "
                         @"message is byte-identical to a valid one; what makes it a rejection is "
                         @"`own_DHs_pub`, so this is the vector that proves check 8 exists at all. "
                         @"+parseType01Message: takes that key as _Nonnull precisely so a caller "
                         @"cannot opt out of the check by omitting it.",
        @"expect"      : @"error",
        @"error"       : @"ERR_INVALID_PUBLIC_KEY",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_with_handle",
            @"message"     : IRVectorHex(f.type01Message),
            @"own_DHs_pub" : senderRatchetHex,
        },
        @"intermediates" : @{ @"message_len" : @(f.type01Message.length) },
    };

    #pragma mark NEG-PUBKEY-REFLECT-02-EKA

    NSData *ekaBytes = [f.type02Message subdataWithRange:NSMakeRange(kIROffType02EK, 32)];
    NSData *reflectEKA = IRNegWireSplice(f.type02Message, kIROffType02DHs, ekaBytes);
    IRNegWireRequireParserError(@"NEG-PUBKEY-REFLECT-02-EKA", @"decrypt_prekey", reflectEKA, nil,
                                IRErrorInvalidPublicKey);

    NSDictionary *negPubkeyReflect02EKA = @{
        @"id"          : @"NEG-PUBKEY-REFLECT-02-EKA",
        @"kind"        : @"wire",
        @"description" : @"§10.2 check 11 — DHs_pub at offset 173 equals EK_A at offset 132. This "
                         @"is the only anti-reflection comparison a type 0x02 gate CAN perform, "
                         @"because it compares two fields of the same message and so touches no "
                         @"local state. Checks 6–10 all pass first: opk_flag is 0x01, opk_id is "
                         @"non-zero, PN is zero, N is in range, and EK_A is a valid encoding.",
        @"expect"      : @"error",
        @"error"       : @"ERR_INVALID_PUBLIC_KEY",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(reflectEKA),
        },
        @"intermediates" : @{ @"message_len" : @(reflectEKA.length) },
    };

    #pragma mark NEG-PREKEY-PN

    NSData *nonZeroPN = IRNegWireSplice(f.type02Message, kIROffType02PN, IRNegWireBE32(1));
    IRNegWireRequireParserError(@"NEG-PREKEY-PN", @"decrypt_prekey", nonZeroPN, nil,
                                IRErrorMalformedHeader);

    NSDictionary *negPrekeyPN = @{
        @"id"          : @"NEG-PREKEY-PN",
        @"kind"        : @"wire",
        @"description" : @"PN = 1 in a type 0x02 header — §10.2 check 8. §9.2 fixes PN at zero "
                         @"because a fresh session has no previous sending chain, and "
                         @"IRMessageBuilder does not expose PN for this type at all, so this "
                         @"fixture is byte surgery on a valid message. Check 8 reads offset 209 "
                         @"BEFORE check 9 reads offset 205: the gate is not in layout order.",
        @"expect"      : @"error",
        @"error"       : @"ERR_MALFORMED_HEADER",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(nonZeroPN),
        },
        @"intermediates" : @{ @"message_len" : @(nonZeroPN.length) },
    };

    #pragma mark NEG-OPKFLAG-ID

    /* Only the FLAG changes: the base message already carries opk_id 42, so the result is
       `opk_flag == 0x00` with a non-zero `opk_id`, which is check 7 and not check 6. */
    NSData *opkFlagMismatch = IRNegWireSplice(f.type02Message,
                                              kIROffType02OPKFlag,
                                              IRNegWireByte((uint8_t)IROPKFlagAbsent));
    IRNegWireRequireParserError(@"NEG-OPKFLAG-ID", @"decrypt_prekey", opkFlagMismatch, nil,
                                IRErrorMalformedHeader);

    NSDictionary *negOPKFlagId = @{
        @"id"          : @"NEG-OPKFLAG-ID",
        @"kind"        : @"wire",
        @"description" : @"opk_flag == 0x00 with opk_id == 42 — §10.2 check 7. Only the flag byte "
                         @"at offset 168 differs from the valid base, so check 6 (the flag is in "
                         @"{0x00, 0x01}) passes and check 7 is the first that can fire. An "
                         @"implementation that merely ignored opk_id when the flag is clear would "
                         @"accept two different encodings of the same handshake.",
        @"expect"      : @"error",
        @"error"       : @"ERR_MALFORMED_HEADER",
        @"inputs"      : @{
            @"entry_point" : @"decrypt_prekey",
            @"message"     : IRVectorHex(opkFlagMismatch),
        },
        @"intermediates" : @{ @"message_len" : @(opkFlagMismatch.length) },
    };

    #pragma mark NEG-PUBKEY-REFLECT-02-SPK — §10.7 step 6

    NSData *reflectSPK = IRNegWireSplice(f.type02Message,
                                         kIROffType02DHs,
                                         f.signedPreKey.publicKey.data);

    /* The GATE accepts this message, and the vector records that as an intermediate. §10.2 says so
       in as many words: at gate time B has not resolved `spk_id`, so it does not know what SPK_B
       is. Everything after the gate is §10.7's ordered fourteen steps. */
    error = nil;
    IRVectorRequire([IRMessageGate parseType02Message:reflectSPK error:&error] != nil,
                    @"[NEG-PUBKEY-REFLECT-02-SPK] §10.2 must ACCEPT this message: %@", error);

    error = nil;
    IRNegWireResponder *spkResponder = IRNegWirePreKeyResponder(f.bob,
                                                                kNegWireNowMs,
                                                                kNegWireSpkId,
                                                                f.signedPreKey,
                                                                kNegWireNotBeforeS,
                                                                kNegWireNotAfterS,
                                                                f.spkSignature,
                                                                kNegWireOpkId,
                                                                f.oneTimePreKey,
                                                                kNegWireOpkCreatedAtS,
                                                                &error);
    IRVectorRequire(spkResponder != nil, @"the §10.7 prekey fixture: %@", error);

    error = nil;
    IRDecryptedMessage *spkResult = [spkResponder.messenger decryptPreKeyMessage:reflectSPK
                                                                           error:&error];
    IRNegWireRequireResponderError(@"NEG-PUBKEY-REFLECT-02-SPK", error, spkResult,
                                   IRErrorInvalidPublicKey);
    IRVectorRequire(spkResponder.sessions.sessionCount == 0,
                    @"[NEG-PUBKEY-REFLECT-02-SPK] no session may be created");
    IRVectorRequire(spkResponder.preKeys.oneTimePreKeyCount == 1,
                    @"[NEG-PUBKEY-REFLECT-02-SPK] the one-time prekey MUST be untouched: §10.7 "
                    @"step 14a is the only place it is consumed and this run never reached it");

    NSDictionary *negPubkeyReflect02SPK = @{
        @"id"          : @"NEG-PUBKEY-REFLECT-02-SPK",
        @"kind"        : @"wire",
        @"description" : @"§10.7 step 6 — a type 0x02 opening a NEW session with DHs_pub equal to "
                         @"the SPK_B public for the referenced spk_id, a value any client can "
                         @"fetch from the bundle. The responder's initial DHs IS that key pair "
                         @"(§7.5), so accepting it would drive B into a DH with itself. NO GATE "
                         @"CAN PERFORM THIS CHECK: §10.2 accepts the message, which the "
                         @"`type02_gate_passed` intermediate records. Rejected BEFORE any DH, so "
                         @"no session exists and the one-time prekey is untouched.",
        @"expect"      : @"error",
        @"error"       : @"ERR_INVALID_PUBLIC_KEY",
        @"inputs"      : @{
            @"entry_point"      : @"decrypt_prekey",
            @"message"          : IRVectorHex(reflectSPK),
            @"now_ms"           : IRVectorUInt64String(kNegWireNowMs),
            @"IK_B_s_seed"      : kNegWireBobEd25519Seed,
            @"IK_B_d_scalar"    : kNegWireBobX25519Scalar,
            @"spk_id"           : @(kNegWireSpkId),
            @"SPK_B_scalar"     : kNegWireSignedPreKeyScalar,
            @"SPK_B_pub"        : IRVectorHex(f.signedPreKey.publicKey.data),
            @"SPK_SIG"          : IRVectorHex(f.spkSignature.data),
            @"not_before"       : IRVectorUInt64String(kNegWireNotBeforeS),
            @"not_after"        : IRVectorUInt64String(kNegWireNotAfterS),
            @"opk_id"           : @(kNegWireOpkId),
            @"OPK_B_scalar"     : kNegWireOneTimePreKeyScalar,
            @"opk_created_at_s" : IRVectorUInt64String(kNegWireOpkCreatedAtS),
        },
        @"intermediates" : @{
            @"message_len"       : @(reflectSPK.length),
            @"routed_type"       : @((unsigned)IRMessageTypePrekey),
            @"type02_gate_passed": @1,
        },
        @"outputs" : @{
            @"session_count_after" : @0,
            @"opk_count_after"     : @1,
        },
    };

    #pragma mark NEG-PUBKEY-REFLECT-02-DHS — §11.2 check 3

    NSData *reflectDHS = IRNegWireSplice(f.type02Message,
                                         kIROffType02DHs,
                                         f.sessionRatchet.publicKey.data);

    error = nil;
    IRVectorRequire([IRMessageGate parseType02Message:reflectDHS error:&error] != nil,
                    @"[NEG-PUBKEY-REFLECT-02-DHS] §10.2 must ACCEPT this message: %@", error);

    error = nil;
    IRNegWireResponder *dhsResponder = IRNegWireSessionResponder(f.bob,
                                                                 kNegWireNowMs,
                                                                 f.sessionStateBlob,
                                                                 &error);
    IRVectorRequire(dhsResponder != nil, @"the §11.2 session fixture: %@", error);

    error = nil;
    IRDecryptedMessage *dhsResult = [dhsResponder.messenger decryptPreKeyMessage:reflectDHS
                                                                           error:&error];
    IRNegWireRequireResponderError(@"NEG-PUBKEY-REFLECT-02-DHS", error, dhsResult,
                                   IRErrorInvalidPublicKey);

    error = nil;
    NSData *dhsBlobAfter = IRNegWireSerializedState(dhsResponder.session, &error);
    IRVectorRequire([dhsBlobAfter isEqualToData:f.sessionStateBlob],
                    @"[NEG-PUBKEY-REFLECT-02-DHS] §7.7: the session state changed: %@",
                    dhsBlobAfter ? IRVectorHex(dhsBlobAfter) : @"nil");

    NSDictionary *sessionFixture = @{
        @"S1" : @{
            @"handshake_id"  : IRVectorHex(f.sessionHandshakeId),
            @"peer_identity" : IRVectorHex(f.alice.identityKeyPair.rawPair),
            @"state_blob"    : IRVectorHex(f.sessionStateBlob),
        },
    };

    NSDictionary *negPubkeyReflect02DHS = @{
        @"id"          : @"NEG-PUBKEY-REFLECT-02-DHS",
        @"kind"        : @"wire",
        @"description" : @"§11.2 check 3 — a retransmitted type 0x02 landing on an EXISTING "
                         @"session with DHs_pub equal to that session's own DHs public. §11.2's "
                         @"three checks are ordered — identity, then IKB_A, then anti-reflection — "
                         @"so the header's IK_A pair matches the session's SESSION_AD and IKB_A is "
                         @"genuine, leaving check 3 as the only one that can fire. The session is "
                         @"supplied as a literal §12.1 blob rather than as a handshake to replay, "
                         @"and `state_blob_after` asserts §7.7: the failed decrypt mutated "
                         @"nothing.",
        @"expect"      : @"error",
        @"error"       : @"ERR_INVALID_PUBLIC_KEY",
        @"inputs"      : @{
            @"entry_point"   : @"decrypt_prekey",
            @"message"       : IRVectorHex(reflectDHS),
            @"now_ms"        : IRVectorUInt64String(kNegWireNowMs),
            @"IK_B_s_seed"   : kNegWireBobEd25519Seed,
            @"IK_B_d_scalar" : kNegWireBobX25519Scalar,
            @"sessions"      : sessionFixture,
        },
        @"intermediates" : @{
            @"message_len"        : @(reflectDHS.length),
            @"routed_type"        : @((unsigned)IRMessageTypePrekey),
            @"type02_gate_passed" : @1,
        },
        @"outputs" : @{
            @"sessions.S1.state_blob_after" : IRVectorHex(f.sessionStateBlob),
        },
    };

    #pragma mark NEG-ENTRYPOINT-02-TO-01

    error = nil;
    IRNegWireResponder *entryResponder = IRNegWireSessionResponder(f.bob,
                                                                   kNegWireNowMs,
                                                                   f.sessionStateBlob,
                                                                   &error);
    IRVectorRequire(entryResponder != nil, @"the §10.0 row 5 session fixture: %@", error);

    error = nil;
    IRSession *entrySession = entryResponder.session;
    IRDecryptedMessage *entryResult = [entryResponder.messenger decryptMessage:f.type02Message
                                                                    inSession:entrySession
                                                                        error:&error];
    IRNegWireRequireResponderError(@"NEG-ENTRYPOINT-02-TO-01", error, entryResult,
                                   IRErrorWrongEntryPoint);

    error = nil;
    NSData *entryBlobAfter = IRNegWireSerializedState(entryResponder.session, &error);
    IRVectorRequire([entryBlobAfter isEqualToData:f.sessionStateBlob],
                    @"[NEG-ENTRYPOINT-02-TO-01] §7.7: the session state changed");

    NSDictionary *negEntryPoint02To01 = @{
        @"id"          : @"NEG-ENTRYPOINT-02-TO-01",
        @"kind"        : @"wire",
        @"description" : @"A valid, complete type 0x02 message submitted to the handle-taking "
                         @"entry point WITH A HANDLE THAT RESOLVES. The handle is load-bearing: "
                         @"without it a port that evaluated §10.1 check 6 too early returns "
                         @"ERR_NO_SESSION and passes for the wrong reason. This is also the "
                         @"direction that catches auto-forwarding — a forwarding port SUCCEEDS and "
                         @"returns a plaintext against an expect-error vector. §10.0 is a "
                         @"rejection, never a redirect.",
        @"expect"      : @"error",
        @"error"       : @"ERR_WRONG_ENTRY_POINT",
        @"inputs"      : @{
            @"entry_point"      : @"decrypt_with_handle",
            @"message"          : IRVectorHex(f.type02Message),
            @"now_ms"           : IRVectorUInt64String(kNegWireNowMs),
            @"IK_B_s_seed"      : kNegWireBobEd25519Seed,
            @"IK_B_d_scalar"    : kNegWireBobX25519Scalar,
            @"sessions"         : sessionFixture,
            @"selected_session" : @"S1",
        },
        @"intermediates" : @{
            @"message_len" : @(f.type02Message.length),
            @"routed_type" : @((unsigned)IRMessageTypePrekey),
        },
        @"outputs" : @{
            @"sessions.S1.state_blob_after" : IRVectorHex(f.sessionStateBlob),
        },
    };

    return @[
        negVersion,
        negVersionShort,
        negType,
        negEntryPoint01To02,
        negEntryPoint02To01,
        negFlags,
        negTruncated,
        negPubkeyHighBit,
        negPubkeyReflect01,
        negPubkeyReflect02EKA,
        negPubkeyReflect02SPK,
        negPubkeyReflect02DHS,
        negPrekeyPN,
        negOPKFlagId,
    ];
}

#pragma mark - Executor

/**
 THE GUARD IS NOT DEFENSIVE PROGRAMMING, IT IS §13.4.

 A nil passed for a `_Nonnull` parameter is a caller contract violation that traps through
 IRRequireArgument — it is not an error code and it is not recoverable. A vector whose hex is the
 wrong width produces a nil nominal type, and passing that on would abort the whole test binary with
 a trap instead of reporting which vector was malformed. Every constructed value is therefore
 checked before it is handed to the implementation.

 `testCase` and `vectorCase` must be in scope, which they are in every executor below.
 */
#define IRNegWireGuard(value, ...)                                                                 \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRVectorRecordFailure(testCase, __VA_ARGS__);                                          \
            [vectorCase finish];                                                                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

/// Every §15.4 row this module owns whose evaluation is the parser pipeline alone.
static NSSet<NSString *> *IRNegWireParserIdentifiers(void) {
    static NSSet<NSString *> *identifiers = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        identifiers = [NSSet setWithArray:@[
            @"NEG-VERSION",
            @"NEG-VERSION-SHORT",
            @"NEG-TYPE",
            @"NEG-ENTRYPOINT-01-TO-02",
            @"NEG-FLAGS",
            @"NEG-TRUNCATED",
            @"NEG-PUBKEY-HIGHBIT",
            @"NEG-PUBKEY-REFLECT-01",
            @"NEG-PUBKEY-REFLECT-02-EKA",
            @"NEG-PREKEY-PN",
            @"NEG-OPKFLAG-ID",
        ]];
    });

    return identifiers;
}

/// Reads `sessions.S1` and validates its three fields, or records a failure and returns nil.
static NSDictionary *_Nullable IRNegWireSessionFixtureFrom(XCTestCase *testCase,
                                                           IRVectorCase *vectorCase,
                                                           NSDictionary *_Nullable sessions) {
    if (![sessions isKindOfClass:[NSDictionary class]]) {
        IRVectorRecordFailure(testCase, @"[%@] inputs.sessions is missing", vectorCase.identifier);
        return nil;
    }

    id fixture = sessions[@"S1"];
    if (![fixture isKindOfClass:[NSDictionary class]]) {
        IRVectorRecordFailure(testCase, @"[%@] inputs.sessions.S1 is missing or not an object",
                              vectorCase.identifier);
        return nil;
    }

    for (NSString *key in @[@"handshake_id", @"peer_identity", @"state_blob"]) {
        if (!IRVectorHexIsWellFormed(fixture[key])) {
            IRVectorRecordFailure(testCase, @"[%@] inputs.sessions.S1.%@ is not well-formed hex",
                                  vectorCase.identifier, key);
            return nil;
        }
    }

    return fixture;
}

#pragma mark The parser rows

static void IRNegWireRunParserVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    /* Every input is read FIRST, so §15.5 rule 3's consumption bookkeeping is complete even on a
       path that then bails out. */
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *message = [vectorCase dataInput:@"message"];
    NSData *ownRatchetBytes = [vectorCase optionalDataInput:@"own_DHs_pub"];

    NSError *error = nil;
    IRX25519Public *ownRatchetPublic = nil;

    /* §15.5's reserved `entry_point` is an ENUM, and the three names below are the only ones a
       parser-level row can carry. An unrecognised value is a malformed vector, not a value to guess
       at: §10.0 row 5 is a predicate over (message, entry point), so guessing the entry point would
       silently decide the expected code. */
    if (![entryPoint isEqualToString:@"message_type"] &&
        ![entryPoint isEqualToString:@"decrypt_prekey"] &&
        ![entryPoint isEqualToString:@"decrypt_with_handle"]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] entry_point \"%@\" is not one of message_type, "
                              @"decrypt_prekey, decrypt_with_handle",
                              vectorCase.identifier, entryPoint);
        [vectorCase finish];
        return;
    }

    if ([entryPoint isEqualToString:@"decrypt_with_handle"]) {
        /* §10.1 check 8's operand. A type `0x01` vector without it cannot reach check 8 at all, and
           passing nil to a `_Nonnull` parameter would trap rather than report (§13.4). */
        if (ownRatchetBytes == nil) {
            IRVectorRecordFailure(testCase,
                                  @"[%@] entry_point is \"decrypt_with_handle\" but inputs carries "
                                  @"no own_DHs_pub — §10.1 check 8 would be unreachable",
                                  vectorCase.identifier);
            [vectorCase finish];
            return;
        }

        ownRatchetPublic = [IRX25519Public fromData:ownRatchetBytes error:&error];
        IRNegWireGuard(ownRatchetPublic, @"[%@] own_DHs_pub is not a valid X25519 public key: %@",
                       vectorCase.identifier, error);
    } else if (ownRatchetBytes != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] own_DHs_pub is only meaningful for \"decrypt_with_handle\"",
                              vectorCase.identifier);
    }

    if (!vectorCase.expectsError) {
        IRVectorRecordFailure(testCase, @"[%@] every vector in this module is expect: \"error\"",
                              vectorCase.identifier);
    }

    [vectorCase checkIntermediate:@"message_len" number:@(message.length)];

    IRMessageType routedType = 0;
    error = nil;
    BOOL accepted = IRNegWireEvaluateParser(entryPoint,
                                            message,
                                            ownRatchetPublic,
                                            &routedType,
                                            &error);

    /* §15.5 rule 2 — `routed_type` is present only on the rows where §10.0 rows 1–4 succeed, and on
       those rows it is the observable that separates "the type could not be read" from "the host
       called the wrong entry point". */
    if (vectorCase.intermediates[@"routed_type"] != nil) {
        [vectorCase checkIntermediate:@"routed_type"
                               number:(routedType == 0 ? nil : @((unsigned)routedType))];
    }

    if (accepted) {
        IRVectorRecordFailure(testCase,
                              @"[%@] the implementation ACCEPTED a message that MUST be rejected "
                              @"with %@",
                              vectorCase.identifier, vectorCase.expectedErrorName);
    }

    [vectorCase checkResultError:error];
    [vectorCase finish];
}

#pragma mark NEG-PUBKEY-REFLECT-02-SPK — the §10.7 prekey-store row

static void IRNegWireRunPreKeyStoreVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *message = [vectorCase dataInput:@"message"];
    uint64_t nowMs = [vectorCase uint64Input:@"now_ms"];
    NSData *bobSeed = [vectorCase dataInput:@"IK_B_s_seed"];
    NSData *bobScalar = [vectorCase dataInput:@"IK_B_d_scalar"];
    uint32_t spkId = [vectorCase uint32Input:@"spk_id"];
    NSData *spkScalar = [vectorCase dataInput:@"SPK_B_scalar"];
    NSData *spkPublicBytes = [vectorCase dataInput:@"SPK_B_pub"];
    NSData *spkSignatureBytes = [vectorCase dataInput:@"SPK_SIG"];
    uint64_t notBeforeS = [vectorCase uint64Input:@"not_before"];
    uint64_t notAfterS = [vectorCase uint64Input:@"not_after"];
    uint32_t opkId = [vectorCase uint32Input:@"opk_id"];
    NSData *opkScalar = [vectorCase dataInput:@"OPK_B_scalar"];
    uint64_t opkCreatedAtS = [vectorCase uint64Input:@"opk_created_at_s"];

    if (![entryPoint isEqualToString:@"decrypt_prekey"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"decrypt_prekey\"",
                              vectorCase.identifier, entryPoint);
    }

    NSError *error = nil;

    IRIdentity *bob = IRNegWireIdentityFromBytes(bobSeed, bobScalar, &error);
    IRNegWireGuard(bob, @"[%@] B's identity does not reproduce from its seed and scalar: %@",
                   vectorCase.identifier, error);

    /* §15.5 rule 5 — the scalars are fed to the REAL generator, so the §4.2 clamp is applied by the
       code under test and the public halves are whatever it derives. `SPK_B_pub` is then compared
       against that derivation rather than trusted, which is what makes the input pair a check
       instead of two values that could quietly disagree. */
    IRX25519KeyPair *signedPreKey = nil;
    IRX25519KeyPair *oneTimePreKey = nil;

    if (spkScalar.length == 32 && opkScalar.length == 32) {
        signedPreKey = IRNegWireX25519PairFromScalar(IRVectorHex(spkScalar));
        oneTimePreKey = IRNegWireX25519PairFromScalar(IRVectorHex(opkScalar));
    }

    IRNegWireGuard(signedPreKey, @"[%@] SPK_B_scalar is not a 32-byte scalar",
                   vectorCase.identifier);
    IRNegWireGuard(oneTimePreKey, @"[%@] OPK_B_scalar is not a 32-byte scalar",
                   vectorCase.identifier);

    if (![signedPreKey.publicKey.data isEqualToData:spkPublicBytes]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] SPK_B_pub disagrees with the key derived from SPK_B_scalar",
                              vectorCase.identifier);
    }

    IREd25519Signature *spkSignature = [IREd25519Signature fromData:spkSignatureBytes error:&error];
    IRNegWireGuard(spkSignature, @"[%@] SPK_SIG: %@", vectorCase.identifier, error);

    error = nil;
    IRNegWireResponder *responder = IRNegWirePreKeyResponder(bob,
                                                             nowMs,
                                                             spkId,
                                                             signedPreKey,
                                                             notBeforeS,
                                                             notAfterS,
                                                             spkSignature,
                                                             opkId,
                                                             oneTimePreKey,
                                                             opkCreatedAtS,
                                                             &error);
    IRNegWireGuard(responder, @"[%@] the §10.7 prekey fixture could not be built: %@",
                   vectorCase.identifier, error);

    [vectorCase checkIntermediate:@"message_len" number:@(message.length)];

    error = nil;
    IRMessageType routedType = [IRMessageGate messageTypeOfMessage:message error:&error];
    [vectorCase checkIntermediate:@"routed_type"
                           number:(routedType == 0 ? nil : @((unsigned)routedType))];

    /* §10.2 ACCEPTS this message — the gate has not resolved `spk_id` and cannot know what SPK_B
       is. Recording that as an intermediate is what stops the vector from being satisfied by a port
       that rejects it at the gate for some unrelated reason. */
    error = nil;
    BOOL gatePassed = [IRMessageGate parseType02Message:message error:&error] != nil;
    [vectorCase checkIntermediate:@"type02_gate_passed" number:@(gatePassed ? 1 : 0)];

    error = nil;
    IRDecryptedMessage *decrypted = [responder.messenger decryptPreKeyMessage:message error:&error];
    if (decrypted != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §10.7 step 6 ACCEPTED a reflected DHs_pub and returned a "
                              @"plaintext", vectorCase.identifier);
    }

    [vectorCase checkResultError:error];

    /* §10.7 step 13 — rejected before any DH, so nothing was committed and nothing was consumed.
       Step 14a is the only place the one-time prekey is deleted and this run never reached it. */
    [vectorCase checkOutput:@"session_count_after" number:@(responder.sessions.sessionCount)];
    [vectorCase checkOutput:@"opk_count_after" number:@(responder.preKeys.oneTimePreKeyCount)];

    [vectorCase finish];
}

#pragma mark NEG-PUBKEY-REFLECT-02-DHS / NEG-ENTRYPOINT-02-TO-01 — the live-session rows

static void IRNegWireRunSessionVector(XCTestCase *testCase, IRVectorCase *vectorCase) {
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *message = [vectorCase dataInput:@"message"];
    uint64_t nowMs = [vectorCase uint64Input:@"now_ms"];
    NSData *bobSeed = [vectorCase dataInput:@"IK_B_s_seed"];
    NSData *bobScalar = [vectorCase dataInput:@"IK_B_d_scalar"];
    NSDictionary *sessions = [vectorCase optionalDictionaryInput:@"sessions"];
    NSString *selectedSession = [vectorCase optionalStringInput:@"selected_session"];

    BOOL handleEntryPoint = [entryPoint isEqualToString:@"decrypt_with_handle"];

    if (!handleEntryPoint && ![entryPoint isEqualToString:@"decrypt_prekey"]) {
        IRVectorRecordFailure(testCase, @"[%@] unexpected entry_point \"%@\"",
                              vectorCase.identifier, entryPoint);
    }

    /* §15.5 — `selected_session` is present exactly when `sessions` is present AND the entry point
       takes a handle. The prekey entry point is SELF-ROUTING (§11.2 computes handshake_id from the
       header), so naming a fixture there would suggest a handle it does not accept. */
    if (handleEntryPoint && ![selectedSession isEqualToString:@"S1"]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] a handle-taking entry point requires selected_session \"S1\", "
                              @"got %@", vectorCase.identifier, selectedSession ?: @"(absent)");
    }

    if (!handleEntryPoint && selectedSession != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] \"decrypt_prekey\" is self-routing and takes no handle, so "
                              @"selected_session must be absent", vectorCase.identifier);
    }

    NSDictionary *fixture = IRNegWireSessionFixtureFrom(testCase, vectorCase, sessions);
    IRNegWireGuard(fixture, @"[%@] inputs.sessions.S1 is unusable", vectorCase.identifier);

    NSString *handshakeIdHex = fixture[@"handshake_id"];
    NSString *peerIdentityHex = fixture[@"peer_identity"];
    NSString *stateBlobHex = fixture[@"state_blob"];

    NSData *expectedHandshakeId = IRVectorBytes(handshakeIdHex);
    NSData *expectedPeerIdentity = IRVectorBytes(peerIdentityHex);
    NSData *stateBlob = IRVectorBytes(stateBlobHex);

    NSError *error = nil;

    IRIdentity *bob = IRNegWireIdentityFromBytes(bobSeed, bobScalar, &error);
    IRNegWireGuard(bob, @"[%@] B's identity does not reproduce from its seed and scalar: %@",
                   vectorCase.identifier, error);

    error = nil;
    IRNegWireResponder *responder = IRNegWireSessionResponder(bob, nowMs, stateBlob, &error);
    IRNegWireGuard(responder, @"[%@] the §12.1 session blob did not restore: %@",
                   vectorCase.identifier, error);

    IRSession *session = responder.session;
    IRNegWireGuard(session, @"[%@] the restored fixture holds no session", vectorCase.identifier);

    /* The fixture's two index keys are asserted rather than assumed: a blob whose handshake_id did
       not match the message's would route to §10.7 instead of §11.2 and the vector would silently
       be testing a different section. */
    if (![session.handshakeId isEqualToData:expectedHandshakeId]) {
        IRVectorRecordFailure(testCase, @"[%@] the restored session's handshake_id is %@, not %@",
                              vectorCase.identifier,
                              IRVectorHex(session.handshakeId),
                              IRVectorHex(expectedHandshakeId));
    }

    if (![session.peerIdentityKeyPair.rawPair isEqualToData:expectedPeerIdentity]) {
        IRVectorRecordFailure(testCase, @"[%@] the restored session's peer identity is %@, not %@",
                              vectorCase.identifier,
                              IRVectorHex(session.peerIdentityKeyPair.rawPair),
                              IRVectorHex(expectedPeerIdentity));
    }

    [vectorCase checkIntermediate:@"message_len" number:@(message.length)];

    error = nil;
    IRMessageType routedType = [IRMessageGate messageTypeOfMessage:message error:&error];
    [vectorCase checkIntermediate:@"routed_type"
                           number:(routedType == 0 ? nil : @((unsigned)routedType))];

    if (vectorCase.intermediates[@"type02_gate_passed"] != nil) {
        error = nil;
        BOOL gatePassed = [IRMessageGate parseType02Message:message error:&error] != nil;
        [vectorCase checkIntermediate:@"type02_gate_passed" number:@(gatePassed ? 1 : 0)];
    }

    error = nil;
    IRDecryptedMessage *decrypted = nil;

    if (handleEntryPoint) {
        /* §10.0 row 5 — the handle RESOLVES, so a port that answers ERR_NO_SESSION here has
           evaluated §10.1 check 6 before the demultiplex, and a port that AUTO-FORWARDS returns a
           plaintext against an expect: "error" vector. */
        decrypted = [responder.messenger decryptMessage:message
                                              inSession:session
                                                  error:&error];
    } else {
        decrypted = [responder.messenger decryptPreKeyMessage:message error:&error];
    }

    if (decrypted != nil) {
        IRVectorRecordFailure(testCase,
                              @"[%@] the implementation ACCEPTED a message that MUST be rejected "
                              @"with %@ and returned a plaintext",
                              vectorCase.identifier, vectorCase.expectedErrorName);
    }

    [vectorCase checkResultError:error];

    /* §7.7 / §15.5's `state_blob_after` — the only expressible form of "no state mutated", and
       §12.1 is byte-normative precisely so it is expressible. A port that processed the message
       against the session and then suppressed the result is caught here by an advanced Nr and a
       rewritten CKr, not by the error code. */
    error = nil;
    NSData *blobAfter = IRNegWireSerializedState(session, &error);
    if (blobAfter == nil) {
        IRVectorRecordFailure(testCase, @"[%@] the session state could not be re-serialized: %@",
                              vectorCase.identifier, error);
        [vectorCase finish];
        return;
    }

    [vectorCase checkOutput:@"sessions.S1.state_blob_after" data:blobAfter];

    [vectorCase finish];
}

#pragma mark - Dispatch

void IRRunNegativeWireVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    /* The driver routes negative.json by `kind` with no table to maintain, so a module that emitted
       a kind outside its row would land in another module's executor. Rejecting it here is what
       makes that loud instead of silent. */
    if (![vectorCase.kind isEqualToString:@"wire"]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] kind is \"%@\"; this module carries only \"wire\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    NSString *identifier = vectorCase.identifier;

    if ([IRNegWireParserIdentifiers() containsObject:identifier]) {
        IRNegWireRunParserVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"NEG-PUBKEY-REFLECT-02-SPK"]) {
        IRNegWireRunPreKeyStoreVector(testCase, vectorCase);
    } else if ([identifier isEqualToString:@"NEG-PUBKEY-REFLECT-02-DHS"] ||
               [identifier isEqualToString:@"NEG-ENTRYPOINT-02-TO-01"]) {
        IRNegWireRunSessionVector(testCase, vectorCase);
    } else {
        /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that
           silently skipped one would report green on a corpus it never executed, which is exactly
           what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
        IRVectorRecordFailure(testCase, @"[%@] the wire block of negative.json has no executor for "
                              @"this id", identifier);
    }
}
