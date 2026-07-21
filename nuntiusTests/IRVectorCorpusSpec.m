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

#import <XCTest/XCTest.h>

#import "IRVectorIO.h"
#import "IRVectorModules.h"

#import "IRSodium.h"

/**
 THE CONFORMANCE CORPUS DRIVER — SPEC §15.2, §15.3, §15.4, §15.5, §15.6.

 One test class drives all six frozen files and all eight modules. There is deliberately no
 per-module XCTestCase: the freeze rule, the id-uniqueness rule and the ten-years-forward rule are
 all properties of the CORPUS, and a per-module suite cannot state any of them.

 WHAT EACH TEST IS FOR:

   test001  Builds every module's vectors, freezes or compares all six files, then loads each frozen
            file back from disk and runs every vector through its executor. Loading the artifact
            back — rather than executing the in-memory corpus — is the point: the frozen bytes are
            what the Java, Kotlin and Swift ports will run, and nothing else here proves they can be
            consumed by an implementation that did not produce them.

   test002  The harness's own encodings. If IRVectorHex or the uint64 decimal-string rules are wrong,
            every other assertion in the suite is comparing two wrong things to each other.

   test999  §15.6's mandatory clock test: the whole corpus regenerated and re-executed with the
            AMBIENT clock ten years forward. Without it a suite that is green on the day it is frozen
            goes red at most 90 days later on the bundle validity window and exactly 7 days later on
            the skipped-key TTL — and §15.6 step 4 forbids the obvious workaround of regenerating.

 THE STUB BLOCK AT THE BOTTOM OF THIS FILE IS TEMPORARY. Read the contract in IRVectorModules.h
 before touching it: a stub generator returns nil, the driver then skips that file entirely and
 reports it PENDING, and landing a real module means deleting that module's two stub definitions in
 the same commit — which the linker enforces, since two definitions of one C function do not link.
 */

#pragma mark - File table

static NSArray<NSString *> *IRCorpusFiles(void) {
    return @[
        kIRVectorFilePrimitives,
        kIRVectorFileX3DH,
        kIRVectorFileRatchet,
        kIRVectorFileWire,
        kIRVectorFileState,
        kIRVectorFileNegative,
    ];
}

static NSString *IRCorpusNotesForFile(NSString *file) {
    if ([file isEqualToString:kIRVectorFilePrimitives]) {
        return @"HKDF, HMAC, X25519, Ed25519 and ChaCha20-Poly1305 known-answer tests. The RFC rows "
               @"carry expected outputs transcribed from the RFC text and are NOT generated: they "
               @"are the only external check in the corpus.";
    }

    if ([file isEqualToString:kIRVectorFileX3DH]) {
        return @"Full X3DH handshakes from fixed keys, with and without a one-time prekey. Both "
               @"handshake vectors run SPEC 5.3 rules 5-6 and therefore carry fixed not_before / "
               @"not_after literals and an inputs.now_s inside that window.";
    }

    if ([file isEqualToString:kIRVectorFileRatchet]) {
        return @"Full conversations including ratchet turns, out-of-order delivery, a prekey burst, "
               @"a retransmit, the concurrent-initiation collapse, and the no-trial-decryption pair.";
    }

    if ([file isEqualToString:kIRVectorFileWire]) {
        return @"Byte-exact encodings of a type 0x01 message, a type 0x02 message, a bundle with "
               @"opk_count 0, a bundle with opk_count 1, and the AD byte strings for both message "
               @"types. Encoding-only: these vectors read no clock and supply no now_s, and the "
               @"bundle not_before / not_after values are fixed literals that are part of the "
               @"frozen bytes.";
    }

    if ([file isEqualToString:kIRVectorFileState]) {
        return @"State blob parse-then-reserialize round-trips over the literal blob bytes in "
               @"inputs. Every vector supplies an inputs.now_ms placing all skipped entries inside "
               @"SKIPPED_TTL_MS, so SPEC 12.2 rule 9 drops nothing.";
    }

    if ([file isEqualToString:kIRVectorFileNegative]) {
        return @"Every rejection path of SPEC 15.4, in three blocks: crypto and session rejections, "
               @"then wire and bundle structural rejections, then state-blob rejections. Each vector "
               @"names the exact error code from SPEC 10.5.";
    }

    return @"";
}

/// nil when any contributing module is still a stub — see IRVectorModules.h.
static NSArray<NSDictionary *> *IRCorpusVectorsForFile(NSString *file) {
    if ([file isEqualToString:kIRVectorFilePrimitives]) {
        return IRVectorsForPrimitives();
    }

    if ([file isEqualToString:kIRVectorFileX3DH]) {
        return IRVectorsForX3DH();
    }

    if ([file isEqualToString:kIRVectorFileRatchet]) {
        return IRVectorsForRatchet();
    }

    if ([file isEqualToString:kIRVectorFileWire]) {
        return IRVectorsForWire();
    }

    if ([file isEqualToString:kIRVectorFileState]) {
        return IRVectorsForState();
    }

    if ([file isEqualToString:kIRVectorFileNegative]) {
        /* THREE MODULES, ONE FILE, CONCATENATED IN THIS ORDER. The order is part of the frozen
           bytes: reordering the blocks reorders the array and changes the artifact. */
        NSArray<NSDictionary *> *crypto = IRVectorsForNegativeCrypto();
        NSArray<NSDictionary *> *wire = IRVectorsForNegativeWire();
        NSArray<NSDictionary *> *store = IRVectorsForNegativeStore();

        if (crypto == nil || wire == nil || store == nil) {
            return nil;
        }

        return [[crypto arrayByAddingObjectsFromArray:wire] arrayByAddingObjectsFromArray:store];
    }

    IRVectorFail(@"no generator is registered for %@.json", file);
}

static void IRCorpusRunVector(NSString *file, XCTestCase *testCase, NSDictionary *vector) {
    if ([file isEqualToString:kIRVectorFilePrimitives]) {
        IRRunPrimitiveVector(testCase, vector);
        return;
    }

    if ([file isEqualToString:kIRVectorFileX3DH]) {
        IRRunX3DHVector(testCase, vector);
        return;
    }

    if ([file isEqualToString:kIRVectorFileRatchet]) {
        IRRunRatchetVector(testCase, vector);
        return;
    }

    if ([file isEqualToString:kIRVectorFileWire]) {
        IRRunWireVector(testCase, vector);
        return;
    }

    if ([file isEqualToString:kIRVectorFileState]) {
        IRRunStateVector(testCase, vector);
        return;
    }

    if ([file isEqualToString:kIRVectorFileNegative]) {
        /* §15.5: WITHIN negative.json, `inputs.entry_point` IS AUTHORITATIVE for selecting the API
           under test and `kind` is a classification. The §10.3 bundle rows are `kind: "wire"`,
           because a §5.4 prekey bundle is a wire structure, but their executor lives in the store
           module beside the other hand-written decoder. Routing `parse_bundle` on `entry_point`
           first is what lets the classification be correct without moving code between modules —
           and it is the same rule every port's runner has to implement, so the driver implements it
           the same way rather than by an id table nobody else can see. */
        NSDictionary *inputs = vector[@"inputs"];
        id rawEntryPoint = [inputs isKindOfClass:[NSDictionary class]] ? inputs[@"entry_point"] : nil;
        NSString *entryPoint =
            [rawEntryPoint isKindOfClass:[NSString class]] ? (NSString *)rawEntryPoint : nil;

        NSString *kind = vector[@"kind"];

        if ([kind isEqualToString:@"wire"] || [kind isEqualToString:@"state"]) {
            /* `entry_point` ALONE IS NOT A ROUTER, and reaching for it as one is the mistake to
               avoid: NEG-SPKSIG-BAD, NEG-SPK-EXPIRED and NEG-SPK-WINDOW-TOO-LONG are `kind: "x3dh"`
               and ALSO carry `entry_point: "parse_bundle"`, correctly — they really do call the
               bundle parser, they just need a whole identity and prekey store behind it. So `kind`
               picks the family and `entry_point` picks the parser within it, which is exactly the
               division §15.5 states. */
            if ([entryPoint isEqualToString:@"parse_bundle"] ||
                [entryPoint isEqualToString:@"parse_state"]) {
                IRRunNegativeStoreVector(testCase, vector);
            } else {
                IRRunNegativeWireVector(testCase, vector);
            }
        } else {
            IRRunNegativeCryptoVector(testCase, vector);
        }

        return;
    }

    IRVectorFail(@"no executor is registered for %@.json", file);
}

#pragma mark - IRVectorCorpusSpec

@interface IRVectorCorpusSpec : XCTestCase
@end

@implementation IRVectorCorpusSpec

- (void)setUp {
    [super setUp];

    NSError *error = nil;
    XCTAssertTrue([IRSodium ensureInitialized:&error], @"libsodium must initialize: %@", error);

    IRVectorResetSkippedIntermediateReport();
}

- (void)tearDown {
    /* §15.5 rule 2 — "a runner MUST report which it skipped". A skip is legitimate; a silent skip is
       not, and §15.6 step 5 makes an unexplained one a conformance failure. */
    NSArray<NSString *> *skipped = IRVectorSkippedIntermediateReport();
    if (skipped.count > 0) {
        NSLog(@"[vectors] §15.5 rule 2 — %lu intermediate(s) skipped:\n  %@",
              (unsigned long)skipped.count, [skipped componentsJoinedByString:@"\n  "]);
    }

    [super tearDown];
}

#pragma mark Helpers

/// Freezes (or compares) every file whose modules are complete, and returns the pending ones.
- (NSArray<NSString *> *)freezeCorpus {
    NSMutableArray<NSString *> *pending = [NSMutableArray array];
    NSMutableSet<NSString *> *allIds = [NSMutableSet set];

    for (NSString *file in IRCorpusFiles()) {
        NSArray<NSDictionary *> *vectors = IRCorpusVectorsForFile(file);

        if (vectors == nil) {
            [pending addObject:file];
            continue;
        }

        XCTAssertGreaterThan(vectors.count, 0,
                             @"%@.json: a real module MUST return a non-empty array; only an "
                             @"unwritten stub returns nil (IRVectorModules.h)", file);

        /* §15.5 — `id` is "unique across all files. Stable forever; never renumbered." */
        for (NSDictionary *vector in vectors) {
            NSString *identifier = vector[@"id"];
            XCTAssertTrue([identifier isKindOfClass:[NSString class]] && identifier.length > 0,
                          @"%@.json: a vector has no id", file);
            XCTAssertFalse([allIds containsObject:identifier],
                           @"vector id %@ is duplicated; §15.5 requires uniqueness across ALL files",
                           identifier);
            [allIds addObject:identifier ?: @""];
        }

        IRVectorFreeze(self, file, IRCorpusNotesForFile(file), vectors);
    }

    return pending;
}

/// Loads each frozen file and runs every vector through its module executor.
- (void)runFrozenCorpusSkippingFiles:(NSArray<NSString *> *)pending {
    NSUInteger executed = 0;

    for (NSString *file in IRCorpusFiles()) {
        if ([pending containsObject:file]) {
            continue;
        }

        NSArray<NSDictionary *> *vectors = IRVectorLoadFrozen(self, file);
        XCTAssertNotNil(vectors, @"%@.json could not be loaded", file);

        for (NSDictionary *vector in vectors) {
            IRCorpusRunVector(file, self, vector);
            executed += 1;
        }
    }

    XCTAssertGreaterThan(executed, 0, @"the corpus executed no vectors at all");
    NSLog(@"[vectors] executed %lu frozen vector(s) from %@",
          (unsigned long)executed, IRVectorsDirectory());
}

#pragma mark Tests

- (void)test001CorpusIsFrozenAndEveryFrozenVectorRuns {
    NSArray<NSString *> *pending = [self freezeCorpus];

    if (pending.count > 0) {
        NSLog(@"[vectors] PENDING MODULES — no frozen file yet for: %@. Each is an unwritten stub "
              @"in IRVectorCorpusSpec.m; see IRVectorModules.h.",
              [pending componentsJoinedByString:@", "]);
    }

    [self runFrozenCorpusSkippingFiles:pending];
}

- (void)test002HarnessEncodingsAreExact {
    /* §15.2 / §15.5 rule 4 — lowercase hex, even length, no prefix, no separators. */
    XCTAssertEqualObjects(IRVectorHex([NSData data]), @"");
    XCTAssertEqualObjects(IRVectorHex(IRVectorBytes(@"00ff10ab")), @"00ff10ab");

    XCTAssertTrue(IRVectorHexIsWellFormed(@""));
    XCTAssertTrue(IRVectorHexIsWellFormed(@"deadbeef"));
    XCTAssertFalse(IRVectorHexIsWellFormed(@"DEADBEEF"), @"uppercase is a hard failure");
    XCTAssertFalse(IRVectorHexIsWellFormed(@"abc"), @"odd length is a hard failure");
    XCTAssertFalse(IRVectorHexIsWellFormed(@"0xab"), @"a 0x prefix is a hard failure");
    XCTAssertFalse(IRVectorHexIsWellFormed(@"ab:cd"), @"separators are a hard failure");
    XCTAssertFalse(IRVectorHexIsWellFormed(nil));

    /* §15.2 — uint64 as an unsigned decimal string: no sign, no separators, no leading zeros
       except the single digit "0", IRRESPECTIVE OF MAGNITUDE. */
    XCTAssertEqualObjects(IRVectorUInt64String(0), @"0");
    XCTAssertEqualObjects(IRVectorUInt64String(5), @"5");
    XCTAssertEqualObjects(IRVectorUInt64String(UINT64_MAX), @"18446744073709551615");

    XCTAssertTrue(IRVectorDecimalStringIsWellFormed(@"0"));
    XCTAssertTrue(IRVectorDecimalStringIsWellFormed(@"18446744073709551615"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"00"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"007"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"+7"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"-7"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"1_000"));
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@"18446744073709551616"), @"above 2^64-1");
    XCTAssertFalse(IRVectorDecimalStringIsWellFormed(@""));

    /* The value §15.2 names as the corruption path: exact on the JVM, rounded through a Double. */
    XCTAssertEqual(IRVectorUInt64FromString(@"9007199254740993"), 9007199254740993ULL);

    /* §10.5 — the names in `error` are the exact taxonomy names. */
    XCTAssertEqualObjects(IRVectorNameForErrorCode(IRErrorBadSignature), @"ERR_BAD_SIGNATURE");
    XCTAssertEqualObjects(IRVectorNameForErrorCode(IRErrorWrongEntryPoint), @"ERR_WRONG_ENTRY_POINT");
    XCTAssertEqual(IRVectorErrorCodeForName(@"ERR_AEAD_AUTH_FAILED"), IRErrorAEADAuthFailed);
    XCTAssertEqual(IRVectorErrorCodeForName(@"ERR_NOT_A_REAL_CODE"), (IRErrorCode)0);
}

- (void)test999TheWholeSuitePassesWithTheClockTenYearsForward {
    /* §15.6 — "CI MUST additionally run the whole suite with the system clock set arbitrarily far
       in the future — ten years is sufficient — and the suite MUST pass unchanged."

       The host clock cannot be moved from inside a test, and it does not need to be: §15.5 rule 6
       routes EVERY clock read in this protocol through one injectable source, so skewing the
       ambient environment is equivalent for anything that honours the rule and lethal for anything
       that does not. A generator that read [NSDate date] produces different bytes here and fails
       the freeze comparison; an executor that read one fails its vector. */
    static const uint64_t kTenYearsInSeconds = 315576000ULL;   /* 10 * 365.25 * 86400 */

    IRVectorSetAmbientClockSkewSeconds(kTenYearsInSeconds);

    @try {
        NSArray<NSString *> *pending = [self freezeCorpus];
        [self runFrozenCorpusSkippingFiles:pending];
    } @finally {
        IRVectorSetAmbientClockSkewSeconds(0);
    }
}

@end
