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
#import <XCTest/XCTest.h>

/**
 THE EIGHT VECTOR MODULES — SPEC §15.2, §15.3, §15.4, §15.5.

 THIS HEADER IS COMPLETE AND FROZEN. Every module function pair the corpus will ever have is
 declared here, so no module author ever edits a shared file and no two authors ever collide in one.
 A module is exactly one `.m` file that defines its own pair and imports this header, plus
 IRVectorIO.h for the harness. Nothing else is shared.

 EACH MODULE CONTRIBUTES TWO FUNCTIONS.

   1. A GENERATOR, `IRVectorsFor<Module>()`, which returns this module's vectors as
      NSArray<NSDictionary *> * built by RUNNING THE REAL IMPLEMENTATION over fixed inputs. It takes
      no arguments and reads no clock: every value it needs is a literal in its own source or is
      derived from one.

   2. An EXECUTOR, `IRRun<Module>Vector(tc, v)`, which takes ONE vector dictionary loaded from the
      FROZEN file, runs it through the implementation, and asserts against `intermediates` and
      `outputs` — or against `error` — per §15.5's runner rules. It builds an IRVectorCase and ends
      with -finish, which is what enforces rules 1, 2 and 3 and reports the skipped intermediates.

 THE GENERATOR/EXECUTOR SPLIT IS NOT REDUNDANT. The generator proves the implementation still
 produces the frozen bytes; the executor proves the frozen bytes can be CONSUMED by an
 implementation that did not produce them, which is the only thing the Java, Kotlin and Swift ports
 will ever run. A module that implements one and stubs the other has tested half of what it claims.

 MODULE -> FILE MAPPING. Three negative modules share one file, which is why the mapping is stated
 here rather than inferred:

     IRVectorsForPrimitives      -> spec/vectors/primitives.json
     IRVectorsForX3DH            -> spec/vectors/x3dh.json
     IRVectorsForRatchet         -> spec/vectors/ratchet.json
     IRVectorsForWire            -> spec/vectors/wire.json
     IRVectorsForState           -> spec/vectors/state.json
     IRVectorsForNegativeCrypto  ┐
     IRVectorsForNegativeWire    ├─> spec/vectors/negative.json, concatenated in THIS ORDER
     IRVectorsForNegativeStore   ┘

 DISPATCH INSIDE negative.json IS BY `kind`, THEN BY `entry_point`, and the driver does it with no
 table to maintain:

     kind "primitive" / "x3dh" / "ratchet"      -> IRRunNegativeCryptoVector
     kind "wire" / "state", entry_point
         "parse_bundle" or "parse_state"        -> IRRunNegativeStoreVector
     kind "wire" / "state", anything else       -> IRRunNegativeWireVector

 The second dimension exists because `kind` CLASSIFIES a vector and `entry_point` names the API it
 calls, and §15.5 makes `entry_point` authoritative for the latter inside negative.json. The §10.3
 bundle rows are `kind: "wire"` — a §5.4 prekey bundle is a wire structure parsed by a wire gate, not
 a §12.1 state blob — while their executor lives beside the state-blob decoder in
 IRVectorNegativeStore.m, which is the other hand-written parser. `entry_point` alone would NOT do:
 NEG-SPKSIG-BAD, NEG-SPK-EXPIRED and NEG-SPK-WINDOW-TOO-LONG are `kind: "x3dh"` and legitimately
 carry `entry_point: "parse_bundle"` too, since they call the bundle parser with a whole identity and
 prekey store behind it.

 The §15.4 rows are partitioned as follows. The partition is exhaustive and DISJOINT — every row in
 §15.4 is emitted by exactly one module — and it is a partition by IMPLEMENTATION, which is not the
 same thing as the `kind` a vector carries. See the integration note below for the one place the two
 come apart.

   IRVectorsForNegativeCrypto — kinds `primitive`, `x3dh`, `ratchet`. The rejections that require
     key agreement, a ratchet, a prekey store or a session to reach:
       NEG-DH2-ALTERED, NEG-DH3-ALTERED, NEG-DH4-ALTERED, NEG-RK-ALTERED, NEG-SK-TAMPER, NEG-ATOMIC,
       NEG-SKIP-RETAIN, NEG-IKB-SWAP, NEG-IKB-RETRANS, NEG-SPKSIG-BAD, NEG-SPK-EXPIRED,
       NEG-SPK-WINDOW-TOO-LONG, NEG-SPK-SURVIVES-RATCHET, NEG-OPK-UNKNOWN, NEG-OPK-EXPIRED,
       NEG-OPK-NOFALLBACK, NEG-SMALLORDER, NEG-COUNTER, NEG-SKIP-LIMIT, NEG-REPLAY, NEG-NO-SESSION,
       NEG-DEMUX-WRONG-SESSION, NEG-DEMUX-WRONG-PEER, NEG-HANDSHAKE-TOMBSTONE,
       NEG-COLLAPSE-LOSER-REPLAY, NEG-COLLAPSE-LOSER-HANDLE

   IRVectorsForNegativeWire — kind `wire`. The message rejections a parser reaches from bytes alone.
     §15.4 groups §10.3's bundle rows with these, but they are emitted by the store module below,
     beside the other hand-written decoder — see the integration note:
       NEG-VERSION, NEG-VERSION-SHORT, NEG-TYPE, NEG-ENTRYPOINT-01-TO-02, NEG-ENTRYPOINT-02-TO-01,
       NEG-FLAGS, NEG-TRUNCATED, NEG-PUBKEY-HIGHBIT, NEG-PUBKEY-REFLECT-01,
       NEG-PUBKEY-REFLECT-02-EKA, NEG-PUBKEY-REFLECT-02-SPK, NEG-PUBKEY-REFLECT-02-DHS,
       NEG-PREKEY-PN, NEG-OPKFLAG-ID

   IRVectorsForNegativeStore — kinds `state` and `wire`. §12.2's parse rejections, plus §10.3's
     bundle structural rejections, which are the other hand-written decoder:
       NEG-STATE-TRAILING, NEG-STATE-COUNT, NEG-STATE-UNCLAMPED,
       NEG-BUNDLE-EMPTY, NEG-BUNDLE-SHORT, NEG-BUNDLE-MAGIC, NEG-BUNDLE-VERSION,
       NEG-BUNDLE-OPKCOUNT, NEG-BUNDLE-LEN

 INTEGRATION NOTE — WHICH MODULE OWNS THE §10.3 BUNDLE ROWS, AND WHAT `kind` THEY CARRY.

 §15.4 groups the bundle rows with the parser rejections, but they are IMPLEMENTED in
 IRVectorsForNegativeStore, beside the state-blob decoder. Both authors were briefed to own them;
 the store module emitted them and the wire module deleted its copies, so the corpus has each
 exactly once and every §15.4 row is covered. Nothing is missing and nothing is duplicated.

 They are frozen with `kind: "wire"`, which is what a §5.4 prekey bundle IS. An earlier draft froze
 them as `kind: "state"` purely because of which module emitted them, and that was a trap for the
 ports rather than a cosmetic mismatch: a runner that switched on `kind` to pick a parser would
 hand a 251-byte bundle to its §12.1 state-blob parser. `kind` is a property of the VECTOR, not of
 the generator module, so the classification was corrected and the code stayed put.

 THE RULE FOR EVERY PORT, and §15.5 now states it normatively: inside negative.json,
 `inputs.entry_point` is AUTHORITATIVE for selecting the API under test and `kind` is a
 classification. Switch on `entry_point`. Do not infer the parser from `kind`, and equally do not
 assume `entry_point` partitions the corpus on its own — `parse_bundle` appears on `kind: "x3dh"`
 vectors too (NEG-SPKSIG-BAD, NEG-SPK-EXPIRED, NEG-SPK-WINDOW-TOO-LONG), which call the same parser
 with an identity and a prekey store behind it.

 Two more §15.4 rows expand to two vectors each, because §15.5 makes `id` unique and a row that needs
 two artifacts cannot reuse its row id: NEG-STATE-UNCLAMPED is frozen as NEG-STATE-UNCLAMPED-LOW /
 -HIGH, and NEG-BUNDLE-LEN as NEG-BUNDLE-LEN-LONG / -SHORT.

 THE STUB CONTRACT, AND IT IS THE ONE RULE THAT MUST NOT BE MISREAD:

     A generator returns nil ONLY while the module is an unwritten stub. The driver then skips that
     file entirely — it does not freeze it, does not load it, and does not run it, and it reports
     the module as PENDING. A REAL MODULE MUST RETURN A NON-EMPTY ARRAY; returning @[] is a suite
     error, because an empty array would freeze an empty artifact and lock it in.

     The stubs live in ONE clearly-marked block at the bottom of IRVectorCorpusSpec.m. Adding a real
     module means deleting that module's two stub definitions from that block in the same commit as
     the new file: two definitions of the same C function are a DUPLICATE SYMBOL LINK ERROR, so a
     forgotten deletion cannot produce a build that quietly runs the stub.

 WHAT EVERY VECTOR MUST HONOUR (§15.2, §15.5, §15.6), restated because it is what breaks first:

   - All byte strings: lowercase hex, no `0x`, no separators, even length.
   - uint8/uint16/uint32 protocol fields: JSON numbers.
   - The uint64-typed fields — `send_counter`, `inserted_at_ms`, `not_before`, `not_after`, `now_s`,
     `now_ms` — are ALWAYS JSON strings holding the unsigned decimal value, whatever the magnitude.
   - No vector reads the host wall clock. A vector whose evaluation reads a clock supplies `now_s`
     and/or `now_ms` in `inputs` and the executor injects it through
     IRVectorEnvironmentAtUnixMilliseconds. A vector that reads a clock and supplies neither is
     MALFORMED, and the driver runs the entire corpus a second time with the ambient clock ten years
     forward to prove none does (§15.6).
   - Randomness is supplied in `inputs` and injected with IRScriptedRandomSource. That source FAILS
     on exhaustion rather than cycling. Do not work around it by scripting extra bytes: script
     exactly what the code path draws, in the order it draws it.
   - `entry_point` is REQUIRED on every vector whose evaluation calls one of the named APIs
     (`decrypt_prekey`, `decrypt_with_handle`, `decrypt_by_peer`, `encrypt`, `parse_bundle`,
     `parse_state`, `message_type`).
   - THE RFC VECTORS IN primitives.json ARE NOT GENERATED. RFC5869-A1..A3, RFC7748-X25519,
     RFC8032-ED25519 and RFC8439-AEAD carry expected outputs TRANSCRIBED FROM THE RFC TEXT. They are
     the only external check in the suite: a corpus generated entirely by the implementation under
     test proves self-consistency and nothing else. Producing one of those expected outputs by
     running our own code destroys the anchor and leaves a corpus that cannot detect a wrong
     primitive.

 IRVectorWire.m IS THE WORKED EXAMPLE. Read it before writing a module; it is deliberately complete
 rather than minimal.
 */

NS_ASSUME_NONNULL_BEGIN

#pragma mark - primitives.json — §15.3, §15.4

/// HKDF, HMAC, X25519, Ed25519 and ChaCha20-Poly1305 known-answer tests. The RFC rows carry
/// transcribed expected outputs; only the nuntius-specific rows (`HKDF-SALT-EQUIV`, `HKDF-EXPAND-64`,
/// `ED25519-SEED-EXPAND`, `KDF-CK-1`, `KDF-RK-1`, `KDF-MK-1`) are generated.
NSArray<NSDictionary *> *_Nullable IRVectorsForPrimitives(void);
void IRRunPrimitiveVector(XCTestCase *testCase, NSDictionary *vector);

#pragma mark - x3dh.json — §15.3

/// `X3DH-OPK`, `X3DH-NOOPK`, `X3DH-IKBIND`, `X3DH-SPKSIG`, `X3DH-FP`. The two handshake vectors
/// ingest a bundle and so run §5.3 rules 5–6: each carries fixed `not_before` / `not_after` literals
/// and an `inputs.now_s` inside that window.
NSArray<NSDictionary *> *_Nullable IRVectorsForX3DH(void);
void IRRunX3DHVector(XCTestCase *testCase, NSDictionary *vector);

#pragma mark - ratchet.json — §15.3

/// `RATCHET-INIT`, `RATCHET-LINEAR`, `RATCHET-BIDI`, `RATCHET-SKIP`, `RATCHET-SKIP-XCHAIN`,
/// `RATCHET-PREKEY-BURST`, `RATCHET-RETRANSMIT`, `SESSION-COLLAPSE`, `DEMUX-NO-TRIAL`.
NSArray<NSDictionary *> *_Nullable IRVectorsForRatchet(void);
void IRRunRatchetVector(XCTestCase *testCase, NSDictionary *vector);

#pragma mark - wire.json — §15.3 (THE WORKED EXAMPLE: IRVectorWire.m)

/// Byte-exact encodings of a type `0x01` message, a type `0x02` message, a bundle with `opk_count`
/// 0, a bundle with `opk_count` 1, and the `AD` byte strings for both message types.
///
/// ENCODING-ONLY. These vectors assert the byte layout of §9.1, §9.2, §5.4 and §8.5 and the
/// structural gate of §10.3. They do NOT run §5.3's signature and validity-window checks, they read
/// NO clock, and they supply no `now_s`; the `not_before` / `not_after` fields are fixed literals
/// that are part of the frozen bytes. Validity-window verification is carried by `X3DH-OPK` /
/// `X3DH-NOOPK` and the `NEG-SPK*` rows.
NSArray<NSDictionary *> *_Nullable IRVectorsForWire(void);
void IRRunWireVector(XCTestCase *testCase, NSDictionary *vector);

#pragma mark - state.json — §15.3

/// A blob with `skipped_count` 0, one with `skipped_count` 3, initiator and responder roles, and
/// `prologue_present` both set and clear.
///
/// PARSE-THEN-RESERIALIZE over the literal blob bytes in `inputs`, never "execute RATCHET-SKIP, then
/// serialize". Every vector supplies an `inputs.now_ms` placing all skipped entries INSIDE
/// `SKIPPED_TTL_MS`, so §12.2 rule 9 drops nothing and the reserialized blob is byte-identical.
NSArray<NSDictionary *> *_Nullable IRVectorsForState(void);
void IRRunStateVector(XCTestCase *testCase, NSDictionary *vector);

#pragma mark - negative.json — §15.4, three modules, concatenated in this order

/// Kinds `primitive`, `x3dh`, `ratchet`. See the partition in this file's header comment.
NSArray<NSDictionary *> *_Nullable IRVectorsForNegativeCrypto(void);
void IRRunNegativeCryptoVector(XCTestCase *testCase, NSDictionary *vector);

/// Kind `wire`. §10.0/§10.1/§10.2 message-parsing rejections. The bundle structural failures are
/// NOT here — they are emitted by the store module below. See the partition in the header comment.
NSArray<NSDictionary *> *_Nullable IRVectorsForNegativeWire(void);
void IRRunNegativeWireVector(XCTestCase *testCase, NSDictionary *vector);

/// Kinds `state` AND `wire`: §12.2's blob rejections plus §10.3's bundle structural rejections,
/// which are `kind: "wire"` because a §5.4 prekey bundle is a wire structure. The module that emits
/// a vector does not decide its classification. See the partition in the header comment.
NSArray<NSDictionary *> *_Nullable IRVectorsForNegativeStore(void);
void IRRunNegativeStoreVector(XCTestCase *testCase, NSDictionary *vector);

NS_ASSUME_NONNULL_END
