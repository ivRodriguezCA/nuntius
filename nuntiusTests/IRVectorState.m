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

#import "IRIdentity.h"
#import "IRKeyPairs.h"
#import "IRKeyTypes.h"
#import "IRProtocolConstants.h"
#import "IRPublicIdentity.h"
#import "IRRatchetState.h"
#import "IRSecretBytes.h"
#import "IRSessionAD.h"
#import "IRSessionStateCodec.h"
#import "IRSkippedKeyStore.h"
#import "IRX3DH.h"

/**
 state.json — SPEC §12.1, §12.2, §15.3, §15.5, §18.

 FOUR VECTORS, exactly the set §15.3 requires of state.json — "a state blob with `skipped_count` 0,
 one with `skipped_count` 3, initiator and responder roles, and `prologue_present` both set and
 clear" — arranged as the full role × skipped_count cross:

     STATE-INIT-SKIP0   role 0x01, prologue PRESENT, skipped_count 0, 472 bytes
     STATE-INIT-SKIP3   role 0x01, prologue clear,   skipped_count 3, 700 bytes
     STATE-RESP-SKIP0   role 0x02, prologue clear,   skipped_count 0, 472 bytes
     STATE-RESP-SKIP3   role 0x02, prologue clear,   skipped_count 3, 700 bytes

 `prologue_present` is set on exactly one vector because §11.3 makes the prologue an INITIATOR-only
 field held only while type `0x02` is still being sent — a responder never has one — and
 STATE-INIT-SKIP0 is the only blob in the set that is in that window (no `CKr`, nothing decrypted
 from B yet). The other three carry the 41 zero bytes §12.1 mandates when it is absent, which is
 what makes "readers MUST branch on the `_present` flag, never on whether the bytes happen to be
 zero" a testable claim rather than an exhortation.

 THESE ARE PARSE-THEN-RESERIALIZE ROUND-TRIPS OVER THE LITERAL BLOB BYTES IN `inputs`. They are
 never "execute RATCHET-SKIP, then serialize", and §15.3 spells out why in two sentences that are
 both MUSTs:

   - A runner that reached the state by executing a ratchet would write its own `now_ms()` into
     blob offsets 540–548, 616–624 and 692–700 — the three `inserted_at_ms` fields of the
     `skipped_count = 3` blobs — so the artifact would differ on every run and could never be frozen.

   - A runner loading the frozen blob more than seven days after the freeze would find every entry
     older than `SKIPPED_TTL_MS` and drop it under §12.2 rule 9, re-emitting a 472-byte
     `skipped_count = 0` blob. The round-trip would still "pass" against itself while silently
     testing nothing.

 So the three `inserted_at_ms` values are FIXED LITERALS, and EVERY vector — including the two with
 no skipped entries at all — supplies an `inputs.now_ms` that places all entries comfortably inside
 the TTL. The gap is 60 seconds against a 604800000 ms window, which is inside it by four orders of
 magnitude and cannot be reached by any clock drift a runner might have. `now_ms` is carried on the
 count-0 vectors too because §12.2 rule 9 runs unconditionally: `parse_state` takes the time source
 whether or not there is anything for it to expire, and a vector that reaches a clock read without
 supplying `now_*` is malformed under §15.5 rule 6 regardless of what the read then does.

 THE CLOCK IS INJECTED AS AN ARGUMENT, NOT AS AN ENVIRONMENT. `nowMs` is a parameter of
 +deserializeStateFromData:atTimeMs:error:, which IS the §15.5 rule 6 injectable time source for
 this layer, so neither the generator nor the executor constructs an IREnvironment at all and
 neither can read the host wall clock. The driver's ten-years-forward run (§15.6) proves it.

 EVERY BYTE OF EVERY BLOB IS A LITERAL IN THIS FILE OR IS DERIVED FROM ONE, and the derivations run
 through the REAL implementation:

   - The two identities come from fixed Ed25519 seeds and fixed X25519 scalars through
     +[IRIdentity generateWithProvider:error:] over IRScriptedRandomSource (§15.5 rule 5), so
     SESSION_AD is built by +[IRSessionAD adWithInitiator:responder:] in ROLE order (§6.5) rather
     than by concatenating bytes here.
   - Every X25519 public in a blob — `DHs_pub`, `DHr_pub`, the prologue's `EK_A`, and each skipped
     entry's `dh_pub` — is the genuine public half of a fixed scalar, and `DHs_priv` is that
     scalar in the §4.2 CLAMPED form the implementation stores. Both matter: §12.2 rule 7 rejects a
     public with bit 255 set and rule 8 rejects an unclamped scalar, so a hand-written byte pattern
     would have to reproduce both encodings by hand, and a port that (wrongly) recomputed `DHs_pub`
     from `DHs_priv` on load would diverge from a blob whose halves did not actually correspond.
   - `handshake_id` is genuinely §11.1's `IK_A^d ‖ EK_A`, not 64 bytes of filler, so a port that
     recomputes it from the stored state agrees with the frozen bytes.
   - `RK`, `CKs`, `CKr` and the three `mk` values are opaque 32-byte literals. Nothing in §12
     constrains them, and deriving them from a real ratchet is exactly the unreproducibility §15.3
     forbids.

 `send_counter` IS THE §15.2 CORRUPTION PATH, ON PURPOSE. STATE-RESP-SKIP3 carries
 9007199254740993 — 2^53 + 1, the value §15.2 names — as the decimal STRING `"9007199254740993"`.
 A port whose JSON layer coerces uint64 fields to a double writes `00 20 00 00 00 00 00 00` at blob
 offset 418 where every other port writes `00 20 00 00 00 00 00 01`, and the reserialized blob
 differs in one byte inside a structure §12 declares byte-normative. STATE-RESP-SKIP0 carries `"0"`
 at the other end of the range, pinning §15.2's "no leading zeros except the single digit `0`".

 THE FOUR BLOBS DELIBERATELY SHARE THEIR KEY MATERIAL. STATE-INIT-SKIP3 and STATE-RESP-SKIP3 differ
 only in the `role` byte and in `Ns` / `Nr` / `PN` / `send_counter`, so a diff between the two
 frozen blobs is exactly the dimension under test and nothing else. Distinctness that matters is
 distinctness ACROSS FIELDS — every field has a visibly different literal, so a value read at the
 wrong offset is obviously wrong rather than plausibly right.
 */

#pragma mark - Fixed key material

/* Ed25519 seeds (§4.2: the 32-byte RFC 8032 seed, never libsodium's 64-byte expanded sk). */
static NSString * const kIRStateAliceEd25519Seed =
    @"5a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static NSString * const kIRStateBobEd25519Seed =
    @"b04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

/* Raw X25519 scalars as handed to the CSPRNG seam. The stored form is the §4.2 CLAMP of these, and
   the public halves are derived from the clamped scalar by the implementation. */
static NSString * const kIRStateAliceX25519Scalar =
    @"5b2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
static NSString * const kIRStateBobX25519Scalar =
    @"b16162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";

/* The session's own ratchet pair: `DHs_priv` at offset 243 and `DHs_pub` at 275. */
static NSString * const kIRStateDHsScalar =
    @"d08182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

/* The peer's CURRENT ratchet public, at offset 308 behind the `DHr_present` flag. */
static NSString * const kIRStateDHrScalar =
    @"d1a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

/* The peer's PREVIOUS ratchet public. Two of the three skipped entries are stored under it and one
   under the current DHr, so the frozen store spans a DH ratchet turn — §7.6's map key is
   `dh_pub ‖ N`, and a store keyed on N alone would collapse entries that must stay distinct. */
static NSString * const kIRStateOldDHrScalar =
    @"d2c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";

/* `EK_A` — the prologue's ephemeral public (block offset +0) and the second half of §11.1's
   `handshake_id`. Only the public half survives into state; §13.3 zeroizes the private after SK. */
static NSString * const kIRStateEphemeralScalar =
    @"e01114171a1d202326292c2f3235383b3e4144474a4d505356595c5f6265686b";

#pragma mark - Fixed secret material

/* Opaque by design — see the file comment. §12 constrains none of these, and deriving them from a
   real ratchet is precisely the unreproducibility §15.3 forbids. */
static NSString * const kIRStateRootKey =
    @"4b02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e9398";
static NSString * const kIRStateSendingChainKey =
    @"5c03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f9499";
static NSString * const kIRStateReceivingChainKey =
    @"5d04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a";
static NSString * const kIRStateMessageKey0 =
    @"6d050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969b";
static NSString * const kIRStateMessageKey1 =
    @"6e060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979c";
static NSString * const kIRStateMessageKey2 =
    @"6f070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989d";

#pragma mark - Fixed non-key material

/* §12.1's 41-byte prologue block. Values distinct from wire.json's `spk_id` 7 / `opk_id` 42 so that
   a cross-file copy of the wrong fixture is visible rather than plausible. */
static const uint32_t kIRStateSpkId = 11;
static const uint32_t kIRStateOpkId = 4242;

/**
 THE THREE `inserted_at_ms` LITERALS AND THE ONE `now_ms`, AND THIS IS THE MOST FRAGILE PAIR OF
 NUMBERS IN THE CORPUS.

 They land at blob offsets 540–548, 616–624 and 692–700. `now_ms` is 60 s past the newest of them
 and `SKIPPED_TTL_MS` is 604800000 ms, so every entry's age is under 0.01% of the window. §12.2
 rule 9 therefore drops nothing and the reserialized blob is byte-identical to the input.

 Raising `now_ms` past `kIRStateSkippedInsertedAtMs0 + 604800000` silently converts both
 `skipped_count = 3` vectors into 472-byte `skipped_count = 0` round-trips that still pass. That is
 the failure §15.3 calls out, and it is why the value is a literal here rather than anything
 computed from a clock.
 */
static const uint64_t kIRStateSkippedInsertedAtMs0 = 1767225600000ULL;  /* 2026-01-01T00:00:00Z */
static const uint64_t kIRStateSkippedInsertedAtMs1 = 1767225601500ULL;
static const uint64_t kIRStateSkippedInsertedAtMs2 = 1767225603000ULL;
static const uint64_t kIRStateNowMs                = 1767225660000ULL;  /* 2026-01-01T00:01:00Z */

/* §12.1's counters, chosen distinct per blob so that a field read at a neighbouring offset — 406,
   410, 414 are consecutive uint32s — produces a visibly wrong value. */
static const uint32_t kIRStateInitSkip0Ns = 3;
static const uint32_t kIRStateInitSkip0Nr = 0;
static const uint32_t kIRStateInitSkip0PN = 0;
static const uint64_t kIRStateInitSkip0SendCounter = 3ULL;

static const uint32_t kIRStateInitSkip3Ns = 5;
static const uint32_t kIRStateInitSkip3Nr = 9;
static const uint32_t kIRStateInitSkip3PN = 4;
static const uint64_t kIRStateInitSkip3SendCounter = 17ULL;

static const uint32_t kIRStateRespSkip0Ns = 0;
static const uint32_t kIRStateRespSkip0Nr = 6;
static const uint32_t kIRStateRespSkip0PN = 0;
static const uint64_t kIRStateRespSkip0SendCounter = 0ULL;

static const uint32_t kIRStateRespSkip3Ns = 2;
static const uint32_t kIRStateRespSkip3Nr = 11;
static const uint32_t kIRStateRespSkip3PN = 7;

/* 2^53 + 1 — the exact value §15.2 names as the JVM/Swift split. See the file comment. */
static const uint64_t kIRStateRespSkip3SendCounter = 9007199254740993ULL;

/* §7.6's map key is `dh_pub ‖ N`, so the three entries are distinct in both components. */
static const uint32_t kIRStateSkippedN0 = 4;
static const uint32_t kIRStateSkippedN1 = 5;
static const uint32_t kIRStateSkippedN2 = 2;

#pragma mark - Deterministic construction helpers

/**
 An X25519 pair derived from a fixed scalar through the REAL generator (§15.5 rule 5).

 A fresh IRScriptedRandomSource per pair, holding exactly the 32 bytes
 -generateX25519KeyPairWithError: draws. That source fails on exhaustion rather than cycling, so a
 generator that drew more than it scripted stops here instead of silently reusing bytes.

 The pair comes back with the private half already in §4.2 clamped form, which is the form §12.2
 rule 8 demands at blob offsets 243 and 274 — the clamp is applied by the code under test, never by
 this test.
 */
static IRX25519KeyPair *IRStateX25519PairFromScalar(NSString *scalarHex) {
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

/// An identity from a fixed Ed25519 seed and a fixed X25519 scalar (§5.1).
static IRIdentity *IRStateIdentity(NSString *seedHex, NSString *scalarHex) {
    NSData *seedBytes = IRVectorBytes(seedHex);
    NSData *scalarBytes = IRVectorBytes(scalarHex);
    IRVectorRequire(seedBytes.length == 32, @"Ed25519 seed must be 32 bytes");
    IRVectorRequire(scalarBytes.length == 32, @"X25519 scalar must be 32 bytes");

    /* +generateWithProvider: draws the Ed25519 seed first and the X25519 scalar second, then signs
       IKBIND_MSG. Scripting the two in that order reproduces a whole identity with no injection
       point the production API exposes. The binding is not stored in a state blob — §12.1 keeps no
       IKB — but generating a real identity is what makes `IK^s` and `IK^d` a genuine pair rather
       than two unrelated byte patterns that happen to sit next to each other in SESSION_AD. */
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

/**
 A COPY of a secret's bytes into an unwipeable container.

 §13.3 schedules `RK`, `CKs`, `CKr`, `DHs_priv` and every stored message key for zeroization, and
 IRSecretBytes exists so they never enter a copy-on-write container by accident. Here the copy is
 deliberate and the material is not secret in any meaningful sense: every one of these values is
 already a public literal in `spec/vectors/state.json`. Keeping the copy in one named function
 rather than open-coding -constBytes at nine call sites is what makes that judgement reviewable.
 */
static NSData *IRStateSecretData(IRSecretBytes *secret) {
    IRVectorRequire(secret != nil, @"a secret to copy");

    return [NSData dataWithBytes:secret.constBytes length:secret.length];
}

static void IRStateWriteBE32(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)((value >> 24) & 0xFF);
    destination[1] = (uint8_t)((value >> 16) & 0xFF);
    destination[2] = (uint8_t)((value >>  8) & 0xFF);
    destination[3] = (uint8_t)(value & 0xFF);
}

static void IRStateWriteBE64(uint8_t *destination, uint64_t value) {
    for (NSUInteger i = 0; i < 8; i++) {
        destination[i] = (uint8_t)((value >> (8 * (7 - i))) & 0xFF);
    }
}

/// memcpy with the field width asserted, so a wrong-width literal fails here and not 300 bytes later.
static void IRStateWriteField(uint8_t *blob,
                              NSUInteger offset,
                              NSData *value,
                              NSUInteger expectedLength,
                              NSString *name) {
    IRVectorRequire(value.length == expectedLength,
                    @"%@ must be %lu bytes, got %lu",
                    name, (unsigned long)expectedLength, (unsigned long)value.length);
    memcpy(blob + offset, value.bytes, expectedLength);
}

/**
 A §12.1 blob, assembled byte by byte at the offsets in the field table.

 `dhrPub`, `cks`, `ckr` and `prologue` are nil when absent, and the corresponding `_present` byte is
 written 0x00 with the payload left as the zeros §12.1 requires: "fixed-size optional fields are
 always present and zero-filled when absent, so the fixed region has no conditional structure".

 `skipped` is an array of dictionaries with the keys `dh_pub` (NSData), `N` (NSNumber), `mk`
 (NSData) and `inserted_at_ms` (NSNumber). Entries are written in ARRAY ORDER, which §12.1 fixes as
 §7.6's global FIFO insertion order — one ordering, not two that can drift.
 */
static NSData *IRStateBlobBytes(uint8_t role,
                                NSData *sessionAD,
                                NSData *handshakeId,
                                NSData *rootKey,
                                NSData *dhsPriv,
                                NSData *dhsPub,
                                NSData *_Nullable dhrPub,
                                NSData *_Nullable cks,
                                NSData *_Nullable ckr,
                                uint32_t Ns,
                                uint32_t Nr,
                                uint32_t PN,
                                uint64_t sendCounter,
                                NSData *_Nullable prologue,
                                NSArray<NSDictionary *> *skipped) {
    const uint32_t skippedCount = (uint32_t)skipped.count;
    const NSUInteger total = [IRSessionStateCodec blobLengthForSkippedCount:skippedCount];
    IRVectorRequire(total > 0, @"skipped_count %u exceeds MAX_SKIPPED_STORED", (unsigned)skippedCount);

    NSMutableData *blob = [NSMutableData dataWithLength:total];
    uint8_t *raw = (uint8_t *)blob.mutableBytes;

    memcpy(raw + kIROffStateMagic, kIRStateMagic, (size_t)kIRLenMagic);
    raw[kIROffStateFormat] = (uint8_t)kIRStateFormat;
    raw[kIROffStateRole] = role;

    IRStateWriteField(raw, kIROffStateSessionAD, sessionAD, kIRLenSessionAD, @"SESSION_AD");
    IRStateWriteField(raw, kIROffStateHandshakeId, handshakeId, kIRLenHandshakeId, @"handshake_id");
    IRStateWriteField(raw, kIROffStateRK, rootKey, kIRLenRootKey, @"RK");
    IRStateWriteField(raw, kIROffStateDHsPriv, dhsPriv, kIRLenX25519Private, @"DHs_priv");
    IRStateWriteField(raw, kIROffStateDHsPub, dhsPub, kIRLenX25519Public, @"DHs_pub");

    raw[kIROffStateDHrPresent] =
        (uint8_t)(dhrPub != nil ? IRPresenceFlagPresent : IRPresenceFlagAbsent);
    if (dhrPub != nil) {
        IRStateWriteField(raw, kIROffStateDHrPub, dhrPub, kIRLenX25519Public, @"DHr_pub");
    }

    raw[kIROffStateCKsPresent] =
        (uint8_t)(cks != nil ? IRPresenceFlagPresent : IRPresenceFlagAbsent);
    if (cks != nil) {
        IRStateWriteField(raw, kIROffStateCKs, cks, kIRLenChainKey, @"CKs");
    }

    raw[kIROffStateCKrPresent] =
        (uint8_t)(ckr != nil ? IRPresenceFlagPresent : IRPresenceFlagAbsent);
    if (ckr != nil) {
        IRStateWriteField(raw, kIROffStateCKr, ckr, kIRLenChainKey, @"CKr");
    }

    IRStateWriteBE32(raw + kIROffStateNs, Ns);
    IRStateWriteBE32(raw + kIROffStateNr, Nr);
    IRStateWriteBE32(raw + kIROffStatePN, PN);
    IRStateWriteBE64(raw + kIROffStateSendCounter, sendCounter);

    raw[kIROffStateProloguePresent] =
        (uint8_t)(prologue != nil ? IRPresenceFlagPresent : IRPresenceFlagAbsent);
    if (prologue != nil) {
        IRStateWriteField(raw, kIROffStatePrologue, prologue, kIRLenStatePrologue, @"prologue");
    }

    IRStateWriteBE32(raw + kIROffStateSkippedCount, skippedCount);

    for (uint32_t i = 0; i < skippedCount; i++) {
        NSDictionary *descriptor = skipped[i];
        uint8_t *entry = raw + kIROffStateSkippedEntries + ((NSUInteger)kIRLenStateSkippedEntry * i);

        IRStateWriteField(entry, kIROffSkippedEntryDHPub, descriptor[@"dh_pub"],
                          kIRLenX25519Public, @"skipped dh_pub");
        IRStateWriteBE32(entry + kIROffSkippedEntryN,
                         (uint32_t)[descriptor[@"N"] unsignedLongLongValue]);
        IRStateWriteField(entry, kIROffSkippedEntryMK, descriptor[@"mk"],
                          kIRLenMessageKey, @"skipped mk");
        IRStateWriteBE64(entry + kIROffSkippedEntryInsertedAtMs,
                         [descriptor[@"inserted_at_ms"] unsignedLongLongValue]);
    }

    return [blob copy];
}

/**
 §12.1 encode, with the one deliberate copy out of IRSecretBytes.

 There is no NSData-returning serializer on the codec, precisely so that this copy is visible at
 every call site. The IRSecretBytes buffer is wiped before returning — §13.3's "serialized state
 buffer — after sealing, and after parsing".
 */
static NSData *_Nullable IRStateReserialize(IRRatchetState *state, NSError **error) {
    IRSecretBytes *serialized = [IRSessionStateCodec serializeState:state error:error];
    if (serialized == nil) {
        return nil;
    }

    NSData *copy = [NSData dataWithBytes:serialized.constBytes length:serialized.length];
    [serialized zeroizeNow];

    return copy;
}

#pragma mark - Vector assembly

/// The `inputs` every state vector carries, and the only three keys it carries.
static NSDictionary *IRStateInputs(NSData *blob) {
    return @{
        @"entry_point" : @"parse_state",
        @"state_blob"  : IRVectorHex(blob),
        /* §15.2 — a uint64-typed field is ALWAYS a decimal string, irrespective of magnitude. */
        @"now_ms"      : IRVectorUInt64String(kIRStateNowMs),
    };
}

/**
 The `intermediates` for one parsed state — §15.5 rule 2's "where interop actually breaks".

 Every field of §12.1 that survives the parse is exposed individually, because the whole point of
 rule 2 is to localise a divergence to one construction instead of leaving a port with "the
 reserialized blob differs at byte 411". The four SESSION_AD sub-slices are here for the same
 reason: §6.5's role ordering is the divergence the specification calls the most likely in the
 protocol, and a port that recomputed SESSION_AD as (self, peer) fails on `IK_A_s_pub` rather than
 on 141 anonymous bytes.

 Optional fields appear ONLY when present, which makes rule 1/2 bookkeeping a two-way check: the
 executor emits a check for `DHr_pub` exactly when the parsed state has a `DHr`, so a vector with
 the key and a state without it fails -finish's untouched-intermediates rule, and a state with it
 and a vector without fails -checkIntermediate:'s "not in the vector".
 */
static NSDictionary *IRStateIntermediates(IRRatchetState *state) {
    NSMutableDictionary *intermediates = [NSMutableDictionary dictionary];

    intermediates[@"blob_len"] =
        @([IRSessionStateCodec blobLengthForSkippedCount:(uint32_t)state.skipped.count]);
    intermediates[@"role"] = @((uint32_t)state.role);

    intermediates[@"SESSION_AD"] = IRVectorHex(state.sessionAD.bytes);
    intermediates[@"IK_A_s_pub"] = IRVectorHex(state.sessionAD.initiatorIdentity.signingKey.data);
    intermediates[@"IK_A_d_pub"] = IRVectorHex(state.sessionAD.initiatorIdentity.agreementKey.data);
    intermediates[@"IK_B_s_pub"] = IRVectorHex(state.sessionAD.responderIdentity.signingKey.data);
    intermediates[@"IK_B_d_pub"] = IRVectorHex(state.sessionAD.responderIdentity.agreementKey.data);

    intermediates[@"handshake_id"] = IRVectorHex(state.handshakeId);
    intermediates[@"RK"] = IRVectorHex(IRStateSecretData(state.RK));
    intermediates[@"DHs_priv"] = IRVectorHex(IRStateSecretData(state.DHs.privateKey));
    intermediates[@"DHs_pub"] = IRVectorHex(state.DHs.publicKey.data);

    intermediates[@"DHr_present"] = @(state.DHr != nil ? 1 : 0);
    if (state.DHr != nil) {
        intermediates[@"DHr_pub"] = IRVectorHex(state.DHr.data);
    }

    intermediates[@"CKs_present"] = @(state.CKs != nil ? 1 : 0);
    if (state.CKs != nil) {
        intermediates[@"CKs"] = IRVectorHex(IRStateSecretData(state.CKs));
    }

    intermediates[@"CKr_present"] = @(state.CKr != nil ? 1 : 0);
    if (state.CKr != nil) {
        intermediates[@"CKr"] = IRVectorHex(IRStateSecretData(state.CKr));
    }

    intermediates[@"Ns"] = @(state.Ns);
    intermediates[@"Nr"] = @(state.Nr);
    intermediates[@"PN"] = @(state.PN);

    /* §15.2 — `send_counter` is uint64-typed and therefore a decimal STRING, always. */
    intermediates[@"send_counter"] = IRVectorUInt64String(state.sendCounter);

    intermediates[@"prologue_present"] = @(state.prologue != nil ? 1 : 0);
    if (state.prologue != nil) {
        intermediates[@"EK_A_pub"] = IRVectorHex(state.prologue.ephemeralPublic.data);
        intermediates[@"spk_id"] = @(state.prologue.spkId);
        intermediates[@"opk_flag"] = @((uint32_t)state.prologue.opkFlag);
        intermediates[@"opk_id"] = @(state.prologue.opkId);
    }

    NSArray<IRSkippedKeyEntry *> *entries = [state.skipped entriesInInsertionOrder];
    intermediates[@"skipped_count"] = @(entries.count);

    for (NSUInteger i = 0; i < entries.count; i++) {
        IRSkippedKeyEntry *entry = entries[i];

        intermediates[[NSString stringWithFormat:@"skipped_%lu_dh_pub", (unsigned long)i]] =
            IRVectorHex(entry.dhPublic.data);
        intermediates[[NSString stringWithFormat:@"skipped_%lu_N", (unsigned long)i]] = @(entry.N);
        intermediates[[NSString stringWithFormat:@"skipped_%lu_mk", (unsigned long)i]] =
            IRVectorHex(IRStateSecretData(entry.messageKey));
        /* uint64-typed, and it is the field §15.3 says destroys the vector if a runner writes its
           own clock into it. A decimal string, like every other uint64 in the corpus. */
        intermediates[[NSString stringWithFormat:@"skipped_%lu_inserted_at_ms", (unsigned long)i]] =
            IRVectorUInt64String(entry.insertedAtMs);
    }

    return intermediates;
}

/**
 One state vector: parse the literal blob at the fixed `now_ms`, reserialize, and freeze all three.

 The generator asserts the round-trip HERE as well, because a generator that emitted a
 `reserialized_blob` differing from its own `state_blob` would freeze a vector that no conformant
 port could ever satisfy — and would do it silently, since the executor only ever compares against
 the frozen bytes.
 */
static NSDictionary *IRStateVector(NSString *identifier, NSString *description, NSData *blob) {
    NSError *error = nil;

    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:kIRStateNowMs
                                                                    error:&error];
    IRVectorRequire(state != nil, @"%@: §12.2 rejected its own fixture: %@", identifier, error);

    NSData *reserialized = IRStateReserialize(state, &error);
    IRVectorRequire(reserialized != nil, @"%@: §12.1 encode failed: %@", identifier, error);
    IRVectorRequire([reserialized isEqualToData:blob],
                    @"%@: parse-then-reserialize is not the identity. Either §12.2 rule 9 dropped a "
                    @"skipped entry — check kIRStateNowMs against SKIPPED_TTL_MS — or the codec "
                    @"drifted from §12.1.\n  in  %@\n  out %@",
                    identifier, IRVectorHex(blob), IRVectorHex(reserialized));

    NSDictionary *vector = @{
        @"id"            : identifier,
        @"kind"          : @"state",
        @"description"   : description,
        @"expect"        : @"ok",
        @"inputs"        : IRStateInputs(blob),
        @"intermediates" : IRStateIntermediates(state),
        @"outputs"       : @{
            @"reserialized_blob"     : IRVectorHex(reserialized),
            @"reserialized_blob_len" : @(reserialized.length),
        },
    };

    /* §13.3 teardown. Everything above is already an independent copy in the dictionary. */
    [state zeroize];

    return vector;
}

#pragma mark - Generator

NSArray<NSDictionary *> *IRVectorsForState(void) {
    NSError *error = nil;

    IRIdentity *alice = IRStateIdentity(kIRStateAliceEd25519Seed, kIRStateAliceX25519Scalar);
    IRIdentity *bob = IRStateIdentity(kIRStateBobEd25519Seed, kIRStateBobX25519Scalar);

    IRX25519KeyPair *ownRatchet = IRStateX25519PairFromScalar(kIRStateDHsScalar);
    IRX25519KeyPair *peerRatchet = IRStateX25519PairFromScalar(kIRStateDHrScalar);
    IRX25519KeyPair *previousPeerRatchet = IRStateX25519PairFromScalar(kIRStateOldDHrScalar);
    IRX25519KeyPair *ephemeral = IRStateX25519PairFromScalar(kIRStateEphemeralScalar);

    /* §6.5 — `initiator:` and `responder:`, BY ROLE. Alice initiates in all four fixtures, so the
       141 bytes at offset 6 are identical in every blob including the two responder ones. That is
       the property: the responder stores the SAME role-ordered AD as the initiator, and §12.1
       stores the `role` byte separately precisely so a restored session cannot recompute it as
       (self, peer). */
    IRSessionAD *sessionAD = [IRSessionAD adWithInitiator:alice.identityKeyPair
                                                responder:bob.identityKeyPair
                                                    error:&error];
    IRVectorRequire(sessionAD != nil, @"SESSION_AD: %@", error);
    IRVectorRequire(sessionAD.bytes.length == 141, @"SESSION_AD is 141 bytes (§18), got %lu",
                    (unsigned long)sessionAD.bytes.length);

    /* §11.1 — `handshake_id` is `IK_A^d ‖ EK_A`, 64 bytes, and it is genuinely that here so a port
       which recomputes it from the stored state agrees with the frozen bytes. */
    NSMutableData *handshakeId = [NSMutableData data];
    [handshakeId appendData:alice.identityKeyPair.agreementKey.data];
    [handshakeId appendData:ephemeral.publicKey.data];
    IRVectorRequire(handshakeId.length == (NSUInteger)kIRLenHandshakeId,
                    @"handshake_id is 64 bytes (§18), got %lu", (unsigned long)handshakeId.length);

    IRSessionPrologue *prologue =
        [IRSessionPrologue prologueWithEphemeralPublic:ephemeral.publicKey
                                                 spkId:kIRStateSpkId
                                               opkFlag:IROPKFlagPresent
                                                 opkId:kIRStateOpkId
                                                 error:&error];
    IRVectorRequire(prologue != nil, @"prologue: %@", error);

    NSData *prologueBytes = [prologue serializedBytes:&error];
    IRVectorRequire(prologueBytes != nil, @"prologue bytes: %@", error);
    IRVectorRequire(prologueBytes.length == (NSUInteger)kIRLenStatePrologue,
                    @"the prologue block is 41 bytes (§18), got %lu",
                    (unsigned long)prologueBytes.length);

    NSData *rootKey = IRVectorBytes(kIRStateRootKey);
    NSData *sendingChainKey = IRVectorBytes(kIRStateSendingChainKey);
    NSData *receivingChainKey = IRVectorBytes(kIRStateReceivingChainKey);
    NSData *ownRatchetPrivate = IRStateSecretData(ownRatchet.privateKey);

    /* Two entries under the PREVIOUS peer ratchet key and one under the current — the store spans a
       DH ratchet turn, which is what makes §7.6's `dh_pub ‖ N` map key load-bearing rather than
       decorative. Insertion order is entry 0, 1, 2 and §12.1 fixes serialization order to match. */
    NSArray<NSDictionary *> *skippedEntries = @[
        @{
            @"dh_pub"         : previousPeerRatchet.publicKey.data,
            @"N"              : @(kIRStateSkippedN0),
            @"mk"             : IRVectorBytes(kIRStateMessageKey0),
            @"inserted_at_ms" : @(kIRStateSkippedInsertedAtMs0),
        },
        @{
            @"dh_pub"         : previousPeerRatchet.publicKey.data,
            @"N"              : @(kIRStateSkippedN1),
            @"mk"             : IRVectorBytes(kIRStateMessageKey1),
            @"inserted_at_ms" : @(kIRStateSkippedInsertedAtMs1),
        },
        @{
            @"dh_pub"         : peerRatchet.publicKey.data,
            @"N"              : @(kIRStateSkippedN2),
            @"mk"             : IRVectorBytes(kIRStateMessageKey2),
            @"inserted_at_ms" : @(kIRStateSkippedInsertedAtMs2),
        },
    ];

    #pragma mark STATE-INIT-SKIP0

    /* §7.5 / §11.3 — an initiator that has sent but not yet decrypted anything from B: no `DHr`, no
       `CKr`, and the prologue still held so the next message is another type 0x02. This is the ONLY
       shape in which `prologue_present` can legitimately be 0x01. */
    NSData *initSkip0Blob = IRStateBlobBytes((uint8_t)IRSessionRoleInitiator,
                                             sessionAD.bytes,
                                             handshakeId,
                                             rootKey,
                                             ownRatchetPrivate,
                                             ownRatchet.publicKey.data,
                                             nil,
                                             sendingChainKey,
                                             nil,
                                             kIRStateInitSkip0Ns,
                                             kIRStateInitSkip0Nr,
                                             kIRStateInitSkip0PN,
                                             kIRStateInitSkip0SendCounter,
                                             prologueBytes,
                                             @[]);
    IRVectorRequire(initSkip0Blob.length == 472,
                    @"the fixed prefix is 472 bytes (§18), got %lu",
                    (unsigned long)initSkip0Blob.length);

    NSDictionary *initSkip0 = IRStateVector(
        @"STATE-INIT-SKIP0",
        @"Initiator state, skipped_count 0, prologue_present 0x01 — the 472-byte fixed prefix and "
        @"nothing after it. §11.3's window: no DHr and no CKr, because A has sent but has not yet "
        @"decrypted anything from B, so the 41-byte prologue block at offset 427 is still live and "
        @"the next outbound message is another type 0x02. Parse-then-reserialize with the "
        @"inputs.now_ms of §15.5 rule 6.",
        initSkip0Blob);

    #pragma mark STATE-INIT-SKIP3

    /* The same role after B has replied: DHr and CKr present, the prologue cleared by the first
       successful decrypt (§11.3), and three keys in the skipped store. */
    NSData *initSkip3Blob = IRStateBlobBytes((uint8_t)IRSessionRoleInitiator,
                                             sessionAD.bytes,
                                             handshakeId,
                                             rootKey,
                                             ownRatchetPrivate,
                                             ownRatchet.publicKey.data,
                                             peerRatchet.publicKey.data,
                                             sendingChainKey,
                                             receivingChainKey,
                                             kIRStateInitSkip3Ns,
                                             kIRStateInitSkip3Nr,
                                             kIRStateInitSkip3PN,
                                             kIRStateInitSkip3SendCounter,
                                             nil,
                                             skippedEntries);
    IRVectorRequire(initSkip3Blob.length == 700,
                    @"472 + 76 * 3 is 700 (§12.1), got %lu", (unsigned long)initSkip3Blob.length);

    NSDictionary *initSkip3 = IRStateVector(
        @"STATE-INIT-SKIP3",
        @"Initiator state, skipped_count 3, prologue_present 0x00 — 472 + 76 * 3 = 700 bytes, "
        @"pinning §12.1's exact-length identity and the 76-byte skipped-entry layout. The prologue "
        @"has been cleared by the first successful decrypt (§11.3) and its 41 bytes are zeros, "
        @"which is what makes §12.1's rule — branch on the _present flag, never on whether the "
        @"bytes happen to be zero — testable. Two entries sit under the previous peer ratchet key "
        @"and one under the "
        @"current, so the store spans a DH ratchet turn and §7.6's dh_pub ‖ N map key is "
        @"load-bearing. inputs.now_ms places all three inside SKIPPED_TTL_MS, so §12.2 rule 9 drops "
        @"nothing.",
        initSkip3Blob);

    #pragma mark STATE-RESP-SKIP0

    /* §7.5 — a responder before its first DH ratchet has no sending chain at all, and §7.8 answers
       a send attempt in that window with ERR_NO_SENDING_CHAIN. Ns, PN and send_counter are
       therefore all zero, which also pins §15.2's "the single digit 0" spelling for a uint64. */
    NSData *respSkip0Blob = IRStateBlobBytes((uint8_t)IRSessionRoleResponder,
                                             sessionAD.bytes,
                                             handshakeId,
                                             rootKey,
                                             ownRatchetPrivate,
                                             ownRatchet.publicKey.data,
                                             peerRatchet.publicKey.data,
                                             nil,
                                             receivingChainKey,
                                             kIRStateRespSkip0Ns,
                                             kIRStateRespSkip0Nr,
                                             kIRStateRespSkip0PN,
                                             kIRStateRespSkip0SendCounter,
                                             nil,
                                             @[]);
    IRVectorRequire(respSkip0Blob.length == 472,
                    @"the fixed prefix is 472 bytes (§18), got %lu",
                    (unsigned long)respSkip0Blob.length);

    NSDictionary *respSkip0 = IRStateVector(
        @"STATE-RESP-SKIP0",
        @"Responder state, skipped_count 0, prologue_present 0x00, CKs_present 0x00 — the "
        @"before-first-ratchet shape of §7.5, where the session can receive but not yet send. The "
        @"stored SESSION_AD is byte-identical to the initiator vectors' because §6.5 orders it by "
        @"ROLE, not by (self, peer); the role byte at offset 5 is the only thing that says which "
        @"side this is. send_counter is the single-digit decimal string 0, pinning §15.2's "
        @"no-leading-zeros rule at its boundary.",
        respSkip0Blob);

    #pragma mark STATE-RESP-SKIP3

    NSData *respSkip3Blob = IRStateBlobBytes((uint8_t)IRSessionRoleResponder,
                                             sessionAD.bytes,
                                             handshakeId,
                                             rootKey,
                                             ownRatchetPrivate,
                                             ownRatchet.publicKey.data,
                                             peerRatchet.publicKey.data,
                                             sendingChainKey,
                                             receivingChainKey,
                                             kIRStateRespSkip3Ns,
                                             kIRStateRespSkip3Nr,
                                             kIRStateRespSkip3PN,
                                             kIRStateRespSkip3SendCounter,
                                             nil,
                                             skippedEntries);
    IRVectorRequire(respSkip3Blob.length == 700,
                    @"472 + 76 * 3 is 700 (§12.1), got %lu", (unsigned long)respSkip3Blob.length);

    NSDictionary *respSkip3 = IRStateVector(
        @"STATE-RESP-SKIP3",
        @"Responder state, skipped_count 3, prologue_present 0x00 — 700 bytes. Its send_counter is "
        @"9007199254740993 (2^53 + 1), carried as a decimal string: §15.2 names this exact value as "
        @"the corruption path, because a port that parses uint64 fields through a double writes "
        @"00 20 00 00 00 00 00 00 at blob offset 418 where every conformant port writes "
        @"00 20 00 00 00 00 00 01. Differs from STATE-INIT-SKIP3 only in the role byte and the four "
        @"counters, so a diff between the two frozen blobs is exactly the dimension under test.",
        respSkip3Blob);

    return @[initSkip0, initSkip3, respSkip0, respSkip3];
}

#pragma mark - Executor

/**
 THE GUARD IS NOT DEFENSIVE PROGRAMMING, IT IS §13.4.

 A nil passed for a `_Nonnull` parameter is a caller contract violation that traps through
 IRRequireArgument — it is not an error code and it is not recoverable. A vector whose blob failed
 to parse produces a nil state, and passing that on would abort the whole test binary with a trap
 instead of reporting which vector was malformed.

 `testCase` and `vectorCase` must be in scope, which they are in the executor below.
 */
#define IRStateGuard(value, ...)                                                                   \
    do {                                                                                           \
        if ((value) == nil) {                                                                      \
            IRVectorRecordFailure(testCase, __VA_ARGS__);                                          \
            [vectorCase finish];                                                                   \
            return;                                                                                \
        }                                                                                          \
    } while (0)

void IRRunStateVector(XCTestCase *testCase, NSDictionary *vector) {
    IRVectorCase *vectorCase = [IRVectorCase caseForVector:vector testCase:testCase];

    if (![vectorCase.kind isEqualToString:@"state"]) {
        IRVectorRecordFailure(testCase, @"[%@] kind is \"%@\"; state.json carries only \"state\"",
                              vectorCase.identifier, vectorCase.kind);
        return;
    }

    /* §15.5 rule 3's sibling: an unrecognised VECTOR is a suite error too. A runner that silently
       ran an unknown id through the generic path would report green on a vector nobody wrote, which
       is what §15.6 step 5's "none are skipped without an explicit, reviewed reason" forbids. */
    if (![vectorCase.identifier hasPrefix:@"STATE-"]) {
        IRVectorRecordFailure(testCase, @"[%@] state.json has no executor for this id",
                              vectorCase.identifier);
        return;
    }

    /* Every input is read FIRST, so §15.5 rule 3's consumption bookkeeping is complete even on a
       path that then bails out. There are exactly three: the blob is self-describing, and adding a
       decomposed copy of any field would put a second source of truth in the file. */
    NSString *entryPoint = [vectorCase stringInput:@"entry_point"];
    NSData *blob = [vectorCase dataInput:@"state_blob"];

    /* §15.5 rule 6 — THE injected clock for this layer. +deserializeStateFromData:atTimeMs:error:
       takes it as an argument, so nothing here reads [NSDate date] and §12.2 rule 9 is evaluated
       against the vector's own timestamp rather than the runner's. -uint64Input: rejects a JSON
       number outright, which is rule 7. */
    uint64_t nowMs = [vectorCase uint64Input:@"now_ms"];

    if (![entryPoint isEqualToString:@"parse_state"]) {
        IRVectorRecordFailure(testCase, @"[%@] entry_point is \"%@\", expected \"parse_state\"",
                              vectorCase.identifier, entryPoint);
    }

    NSError *error = nil;
    IRRatchetState *state = [IRSessionStateCodec deserializeStateFromData:blob
                                                                 atTimeMs:nowMs
                                                                    error:&error];
    IRStateGuard(state, @"[%@] §12.2 rejected a valid blob: %@", vectorCase.identifier, error);

    [vectorCase checkResultError:nil];

    #pragma mark Intermediates — §15.5 rule 2

    /* The formula, not the literal: `blobLengthForSkippedCount:` is 472 + 76 * n, and checking it
       against the frozen length is what makes §12.2 rule 6's exact-length identity an assertion
       rather than an assumption. */
    [vectorCase checkIntermediate:@"blob_len"
                           number:@([IRSessionStateCodec
                                        blobLengthForSkippedCount:(uint32_t)state.skipped.count])];
    [vectorCase checkIntermediate:@"role" number:@((uint32_t)state.role)];

    /* §6.5 — the four sub-slices, by ROLE. A port that recomputed SESSION_AD as (self, peer)
       interoperates with itself and with nothing else, and fails on IK_A_s_pub here rather than on
       141 anonymous bytes. */
    [vectorCase checkIntermediate:@"SESSION_AD" data:state.sessionAD.bytes];
    [vectorCase checkIntermediate:@"IK_A_s_pub"
                             data:state.sessionAD.initiatorIdentity.signingKey.data];
    [vectorCase checkIntermediate:@"IK_A_d_pub"
                             data:state.sessionAD.initiatorIdentity.agreementKey.data];
    [vectorCase checkIntermediate:@"IK_B_s_pub"
                             data:state.sessionAD.responderIdentity.signingKey.data];
    [vectorCase checkIntermediate:@"IK_B_d_pub"
                             data:state.sessionAD.responderIdentity.agreementKey.data];

    [vectorCase checkIntermediate:@"handshake_id" data:state.handshakeId];
    [vectorCase checkIntermediate:@"RK" data:IRStateSecretData(state.RK)];

    /* §12.2 rule 8 and §19.5 — the stored scalar is the CLAMPED form, and the parser rejects rather
       than re-clamping. A port that re-clamped on read would still match here; one that stored the
       raw CSPRNG bytes would not, which is the byte-level split §4.2 exists to prevent. */
    [vectorCase checkIntermediate:@"DHs_priv" data:IRStateSecretData(state.DHs.privateKey)];
    [vectorCase checkIntermediate:@"DHs_pub" data:state.DHs.publicKey.data];

    /* Each `_present` flag is checked as a number AND its payload is checked exactly when the flag
       is set. The two-way bookkeeping is deliberate: a vector carrying `DHr_pub` for a state with
       no DHr fails -finish's untouched-intermediates rule, and a state with a DHr whose vector has
       no `DHr_pub` fails -checkIntermediate:'s "not in the vector". */
    [vectorCase checkIntermediate:@"DHr_present" number:@(state.DHr != nil ? 1 : 0)];
    if (state.DHr != nil) {
        [vectorCase checkIntermediate:@"DHr_pub" data:state.DHr.data];
    }

    [vectorCase checkIntermediate:@"CKs_present" number:@(state.CKs != nil ? 1 : 0)];
    if (state.CKs != nil) {
        [vectorCase checkIntermediate:@"CKs" data:IRStateSecretData(state.CKs)];
    }

    [vectorCase checkIntermediate:@"CKr_present" number:@(state.CKr != nil ? 1 : 0)];
    if (state.CKr != nil) {
        [vectorCase checkIntermediate:@"CKr" data:IRStateSecretData(state.CKr)];
    }

    /* Offsets 406, 410 and 414 are three consecutive uint32s. Reading all three back separately is
       what catches a port that transposed two of them — a bug a single round-trip cannot see,
       because an encoder and a decoder that transpose the same pair agree with each other. */
    [vectorCase checkIntermediate:@"Ns" number:@(state.Ns)];
    [vectorCase checkIntermediate:@"Nr" number:@(state.Nr)];
    [vectorCase checkIntermediate:@"PN" number:@(state.PN)];
    [vectorCase checkIntermediate:@"send_counter" uint64:state.sendCounter];

    [vectorCase checkIntermediate:@"prologue_present" number:@(state.prologue != nil ? 1 : 0)];
    if (state.prologue != nil) {
        [vectorCase checkIntermediate:@"EK_A_pub" data:state.prologue.ephemeralPublic.data];
        [vectorCase checkIntermediate:@"spk_id" number:@(state.prologue.spkId)];
        [vectorCase checkIntermediate:@"opk_flag" number:@((uint32_t)state.prologue.opkFlag)];
        [vectorCase checkIntermediate:@"opk_id" number:@(state.prologue.opkId)];
    }

    /* §12.2 rule 9 has already run inside the parse. If the vector's `now_ms` had fallen outside
       SKIPPED_TTL_MS the store would be EMPTY here and `skipped_count` would read 0 against a
       frozen 3 — which is exactly the silent destruction §15.3 warns about, surfaced as a named
       mismatch instead. */
    NSArray<IRSkippedKeyEntry *> *entries = [state.skipped entriesInInsertionOrder];
    [vectorCase checkIntermediate:@"skipped_count" number:@(entries.count)];

    for (NSUInteger i = 0; i < entries.count; i++) {
        IRSkippedKeyEntry *entry = entries[i];

        [vectorCase checkIntermediate:[NSString stringWithFormat:@"skipped_%lu_dh_pub",
                                                                 (unsigned long)i]
                                 data:entry.dhPublic.data];
        [vectorCase checkIntermediate:[NSString stringWithFormat:@"skipped_%lu_N",
                                                                 (unsigned long)i]
                               number:@(entry.N)];
        [vectorCase checkIntermediate:[NSString stringWithFormat:@"skipped_%lu_mk",
                                                                 (unsigned long)i]
                                 data:IRStateSecretData(entry.messageKey)];
        [vectorCase checkIntermediate:[NSString stringWithFormat:@"skipped_%lu_inserted_at_ms",
                                                                 (unsigned long)i]
                               uint64:entry.insertedAtMs];
    }

    #pragma mark Outputs — §15.5 rule 1

    NSData *reserialized = IRStateReserialize(state, &error);
    if (reserialized == nil) {
        IRVectorRecordFailure(testCase, @"[%@] §12.1 encode failed: %@",
                              vectorCase.identifier, error);
        [vectorCase finish];
        [state zeroize];
        return;
    }

    [vectorCase checkOutput:@"reserialized_blob" data:reserialized];
    [vectorCase checkOutput:@"reserialized_blob_len" number:@(reserialized.length)];

    /* THE ROUND-TRIP ITSELF, stated against `inputs` rather than against `outputs`.
       -checkOutput: compares the encode to the frozen expectation; this compares it to the bytes
       the vector was PARSED FROM, which is the property §15.3 actually names. They differ in one
       situation that matters: a corpus regenerated from a drifted implementation would agree with
       its own `outputs` and disagree here. */
    if (![reserialized isEqualToData:blob]) {
        IRVectorRecordFailure(testCase,
                              @"[%@] parse-then-reserialize is not the identity — either §12.2 "
                              @"rule 9 dropped a skipped entry (check inputs.now_ms against "
                              @"SKIPPED_TTL_MS) or this port's §12.1 encode differs.\n  in  %@\n"
                              @"  out %@",
                              vectorCase.identifier, IRVectorHex(blob), IRVectorHex(reserialized));
    }

    /* §12.2 rule 6's exact-length identity, restated as a length assertion rather than inferred
       from the blob comparison above: a port whose encoder emitted a short blob would otherwise
       report only "MISMATCH at byte N". */
    const NSUInteger expectedLength =
        [IRSessionStateCodec blobLengthForSkippedCount:(uint32_t)entries.count];
    if (reserialized.length != expectedLength) {
        IRVectorRecordFailure(testCase,
                              @"[%@] §12.1 total length MUST be 472 + 76 * %lu = %lu, got %lu",
                              vectorCase.identifier, (unsigned long)entries.count,
                              (unsigned long)expectedLength, (unsigned long)reserialized.length);
    }

    [vectorCase finish];

    /* §13.3 teardown. This state owns its skipped store — it was built by the parser and shared
       with nothing — so the full -zeroize is the correct one of the three, not
       -zeroizeAsDiscardedSnapshot or -zeroizeAsSupersededState. */
    [state zeroize];
}
