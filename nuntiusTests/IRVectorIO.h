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

#import "IRCryptoProvider.h"
#import "IREnvironment.h"
#import "IREnvironment+Testing.h"
#import "IRErrors.h"

/**
 THE CONFORMANCE VECTOR HARNESS — SPEC §15.2, §15.5, §15.6.

 Everything in this file is shared by all eight vector modules (IRVectorModules.h) and by the single
 driver (IRVectorCorpusSpec.m). A module author writes a GENERATOR and an EXECUTOR and touches
 nothing here.

 THREE THINGS THIS FILE OWNS, AND WHY EACH IS CENTRAL RATHER THAN PER-MODULE:

 1. BYTE-EXACTNESS (§15.2). Lowercase hex with no separators, uint64-typed fields as decimal
    STRINGS, JSON written with sorted keys and a trailing newline. Two runs of the generator must
    produce identical bytes or the freeze is meaningless. Eight modules spelling their own encoder
    is eight chances to emit `0x` or an uppercase digit into a file §15.6 step 4 says may never be
    regenerated without a spec version bump.

 2. THE FREEZE (§15.6). A generator and a frozen artifact coexist in one suite under exactly three
    rules, implemented once in IRVectorFreeze:

      - file missing        -> write it. Bootstrap only, and it is not a failure.
      - file present        -> build in memory, assert byte-identical to disk. A mismatch is a
                               FAILING TEST: the implementation drifted from the frozen contract.
      - `.regenerate` present -> rewrite the files AND FAIL, telling the operator to delete the
                               sentinel and review the diff. Regeneration is never silent.

 3. THE RUNNER RULES (§15.5). IRVectorCase is the whole assertion vocabulary, and it enforces the
    normative rules structurally rather than by asking eight authors to remember them:

      rule 1  every key in `outputs` is checked          -> -finish fails on an unchecked output
      rule 2  every exposable key in `intermediates` is
              checked, and the SKIPPED ONES ARE REPORTED -> -skipIntermediate:because: records to a
                                                            process-wide report the driver prints
      rule 3  an unrecognised key in `inputs` is an ERROR -> reading an input CONSUMES it; -finish
                                                            fails on anything left over
      rule 4  hex is even-length and lowercase           -> IRVectorBytes hard-fails otherwise
      rule 6  a clock-reading vector supplies `now_*`     -> IRVectorEnvironmentAtUnixMilliseconds
      rule 7  a uint64-typed field that is not a JSON
              string is REJECTED                         -> -uint64Input: fails on an NSNumber

 NO VECTOR MAY READ THE HOST WALL CLOCK (§15.6). Executors and generators MUST take their clock from
 IRVectorEnvironmentAtUnixMilliseconds (for a vector that supplies `now_s` / `now_ms`) or from
 IRVectorAmbientEnvironment (for one that must read no clock at all). The ambient environment is
 skewed by IRVectorSetAmbientClockSkewSeconds, and the driver's ten-years-forward test does exactly
 that before re-running the whole corpus — which is the only thing that proves the property. Calling
 +[IREnvironment production], [NSDate date], or time(NULL) anywhere in a module defeats it silently.
 */

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Envelope constants (§15.5)

/// `$schema` — the envelope's first field.
extern NSString * const kIRVectorSchemaURL;

/// `spec_version` — the string `"4"`. A change to any frozen vector bumps this (§15.6 step 4).
extern NSString * const kIRVectorSpecVersion;

/// `generated_by` — which implementation produced the corpus.
extern NSString * const kIRVectorGeneratedBy;

/// `generated_at` — A FIXED LITERAL, never the current date. The envelope is part of the frozen
/// bytes, so a live timestamp would make every second run of the generator a diff.
extern NSString * const kIRVectorGeneratedAt;

/// The six frozen file stems, without the `.json` suffix.
extern NSString * const kIRVectorFilePrimitives;
extern NSString * const kIRVectorFileX3DH;
extern NSString * const kIRVectorFileRatchet;
extern NSString * const kIRVectorFileWire;
extern NSString * const kIRVectorFileState;
extern NSString * const kIRVectorFileNegative;

#pragma mark - Hard failure

/**
 A GENERATOR-SIDE failure: the implementation could not produce the value the vector needs.

 This raises rather than returning nil because a generator has no XCTestCase and no error path that
 a caller could act on — a corpus that cannot be built is a suite error, not a test result. Executors
 use IRVectorCase, which records XCTest issues instead.
 */
void IRVectorFail(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2) __attribute__((noreturn));

#define IRVectorRequire(condition, ...)                                                            \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            IRVectorFail(__VA_ARGS__);                                                             \
        }                                                                                          \
    } while (0)

/// Records an XCTest failure against `testCase` without needing to be inside an XCTestCase method.
void IRVectorRecordFailure(XCTestCase *testCase, NSString *format, ...) NS_FORMAT_FUNCTION(2, 3);

#pragma mark - Hex (§15.2, §15.5 rule 4)

/// Lowercase hex, no `0x`, no separators. The only encoder in the suite.
NSString *IRVectorHex(NSData *data);

/// The inverse, with validation: odd length, a non-hex digit, or ANY uppercase digit is a hard
/// failure. Uppercase is rejected rather than accepted-and-normalized because §15.2 makes the
/// lowercase form normative, and a file that round-trips through a lenient decoder stops being a
/// byte-exact artifact.
NSData *IRVectorBytes(NSString *hex);

/// The predicate behind IRVectorBytes, for a caller that must impose its own diagnostic.
BOOL IRVectorHexIsWellFormed(NSString *_Nullable hex);

#pragma mark - uint64 as decimal string (§15.2, §15.5 rule 7)

/// The unsigned decimal form: no sign, no leading zeros except the single digit `"0"`.
NSString *IRVectorUInt64String(uint64_t value);

/// The inverse, with validation. A leading `+`, a leading zero, a sign, whitespace, a separator, or
/// an overflow past 2^64-1 is a hard failure.
uint64_t IRVectorUInt64FromString(NSString *string);

/// The predicate behind IRVectorUInt64FromString.
BOOL IRVectorDecimalStringIsWellFormed(NSString *_Nullable string);

#pragma mark - Error names (§10.5)

/// `IRErrorBadSignature` -> `@"ERR_BAD_SIGNATURE"`. Returns nil for a code outside the taxonomy.
NSString *_Nullable IRVectorNameForErrorCode(IRErrorCode code);

/// The inverse. Returns 0 for a name outside the taxonomy — which §15.5 makes a malformed vector,
/// since `error` MUST be "the exact error name from §10.5".
IRErrorCode IRVectorErrorCodeForName(NSString *_Nullable name);

#pragma mark - Locating spec/vectors/ (§15.6)

/**
 The absolute path of `spec/vectors/`, created if absent.

 DERIVED FROM __FILE__ AT COMPILE TIME — this file's path minus `/nuntiusTests/IRVectorIO.m` — with
 an `NUNTIUS_VECTORS_DIR` environment override for a CI layout that differs.

 IT IS DELIBERATELY NOT THE TEST BUNDLE'S RESOURCES. The frozen files do not exist at first build,
 so a resource reference is a chicken-and-egg problem: the bootstrap run could not write the file it
 was supposed to read, and every later run would read a stale copy from the build directory rather
 than the artifact under review.
 */
NSString *IRVectorsDirectory(void);

/// `spec/vectors/<file>.json`.
NSString *IRVectorFilePath(NSString *file);

/// YES when `spec/vectors/.regenerate` exists. See IRVectorFreeze.
BOOL IRVectorRegenerateRequested(void);

#pragma mark - Envelope and deterministic serialization (§15.5)

/// The §15.5 envelope around `vectors`, ready for IRVectorSerializeEnvelope.
NSDictionary *IRVectorEnvelope(NSString *file, NSString *notes, NSArray<NSDictionary *> *vectors);

/**
 `NSJSONWritingSortedKeys | NSJSONWritingPrettyPrinted`, plus a trailing newline.

 Two runs MUST produce identical bytes. Two details make that true rather than nearly true: the
 solidus escapes NSJSONSerialization emits (`\/`) are unescaped afterwards, and every string in the
 tree is asserted to contain no backslash — so that unescaping is a total, unambiguous operation
 rather than a substitution that could collide with real content.
 */
NSData *IRVectorSerializeEnvelope(NSDictionary *envelope);

#pragma mark - Freeze / compare / regenerate (§15.6)

/**
 The three-rule freeze, in one place. See this file's class comment.

 `vectors` MUST be non-empty. A module with nothing to contribute yet returns nil from its generator
 and the driver skips the file entirely — see IRVectorModules.h.
 */
void IRVectorFreeze(XCTestCase *testCase,
                    NSString *file,
                    NSString *notes,
                    NSArray<NSDictionary *> *vectors);

/**
 Loads the FROZEN file from disk and returns its `vectors` array, having validated the envelope.

 Executors run against these, never against the in-memory corpus: reading the artifact back is what
 makes the artifact — rather than the generator — the contract the other three ports are held to.
 */
NSArray<NSDictionary *> *_Nullable IRVectorLoadFrozen(XCTestCase *testCase, NSString *file);

#pragma mark - Clock and randomness injection (§15.5 rules 5–6, §15.6)

/// The skew applied to IRVectorAmbientEnvironment's clock. Zero in a normal run.
uint64_t IRVectorAmbientClockSkewSeconds(void);

/// Moves the ambient clock. The driver's ten-years-forward test is the only intended caller, and it
/// restores zero afterwards.
void IRVectorSetAmbientClockSkewSeconds(uint64_t seconds);

/**
 An environment for a vector that reads NO clock: system time plus the ambient skew, frozen.

 A generator or executor that secretly reads a clock produces different output when the driver moves
 the skew ten years forward, which is precisely the §15.6 property under test.
 */
IREnvironment *IRVectorAmbientEnvironment(id<IRRandomSource> _Nullable randomSource);

/// An environment pinned to a vector's `now_ms` (§15.5 rule 6). The ambient skew is NOT applied:
/// the whole point of an injected clock is that the host's is irrelevant.
IREnvironment *IRVectorEnvironmentAtUnixMilliseconds(uint64_t nowMs,
                                                     id<IRRandomSource> _Nullable randomSource);

/// A libsodium provider over `environment`. Hard-fails if libsodium is unusable.
id<IRCryptoProvider> IRVectorProviderWithEnvironment(IREnvironment *environment);

/// The common shape: no injected randomness, no injected clock.
id<IRCryptoProvider> IRVectorAmbientProvider(void);

#pragma mark - The §15.5 rule 2 skipped-intermediate report

/// Every `<vector id>.<intermediate key>: <reason>` recorded so far, in order.
NSArray<NSString *> *IRVectorSkippedIntermediateReport(void);

/// Clears the report. The driver calls this before a run and prints the result after.
void IRVectorResetSkippedIntermediateReport(void);

#pragma mark - IRVectorCase

/**
 ONE VECTOR, MID-EXECUTION — the assertion vocabulary every executor shares.

 The shape of an executor is always the same three phases, and -finish is what makes the runner
 rules structural:

     void IRRunSomethingVector(XCTestCase *tc, NSDictionary *v) {
         IRVectorCase *c = [IRVectorCase caseForVector:v testCase:tc];

         NSData *key = [c dataInput:@"some_key"];          // consumes it (rule 3)
         uint32_t n  = [c uint32Input:@"N"];

         ... run the real implementation ...

         [c checkIntermediate:@"header" data:header];      // rule 2
         [c checkOutput:@"message" data:message];          // rule 1
         [c finish];                                       // enforces 1, 2 and 3
     }

 EVERY METHOD RECORDS AN XCTEST FAILURE AND CARRIES ON where it can, rather than raising. A vector
 that mismatches in four fields should report four lines; the first one is rarely the informative
 one when two ports disagree.
 */
@interface IRVectorCase : NSObject

+ (instancetype)caseForVector:(NSDictionary *)vector testCase:(XCTestCase *)testCase;

/// `id`, `kind`, `description` — validated present at construction.
@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, copy, readonly) NSString *kind;
@property (nonatomic, copy, readonly) NSString *vectorDescription;

/// `expect == "error"`.
@property (nonatomic, readonly) BOOL expectsError;

/// The `error` field, e.g. `ERR_BAD_SIGNATURE`. Nil when `expect == "ok"`.
@property (nonatomic, copy, readonly, nullable) NSString *expectedErrorName;

/// The §10.5 code behind -expectedErrorName. Zero when `expect == "ok"`.
@property (nonatomic, readonly) IRErrorCode expectedErrorCode;

/// The raw sections, for the rare executor that must iterate rather than name keys. Reading through
/// these does NOT consume anything, so an executor that uses them MUST still call -ignoreInput:
/// or the typed accessors for rule 3.
@property (nonatomic, copy, readonly) NSDictionary *inputs;
@property (nonatomic, copy, readonly) NSDictionary *intermediates;
@property (nonatomic, copy, readonly) NSDictionary *outputs;

#pragma mark Inputs — reading one CONSUMES it (§15.5 rule 3)

/// A hex byte string. Absent, non-string, or malformed hex is a failure and returns empty data.
- (NSData *)dataInput:(NSString *)key;

/// As -dataInput:, but a missing key returns nil without a failure.
- (nullable NSData *)optionalDataInput:(NSString *)key;

/// A uint8/uint16/uint32 protocol field: a JSON NUMBER (§15.2). A string here is a failure.
- (uint32_t)uint32Input:(NSString *)key;
- (nullable NSNumber *)optionalUInt32Input:(NSString *)key;

/// A uint64-typed field: a JSON STRING holding the unsigned decimal value (§15.2). An NSNumber here
/// is REJECTED — that is rule 7, and it is the whole reason `send_counter` cannot drift between a
/// JVM `long` and a Swift `Double`.
- (uint64_t)uint64Input:(NSString *)key;
- (nullable NSNumber *)optionalUInt64Input:(NSString *)key;

- (NSString *)stringInput:(NSString *)key;
- (nullable NSString *)optionalStringInput:(NSString *)key;
- (NSArray *)arrayInput:(NSString *)key;
- (nullable NSDictionary *)optionalDictionaryInput:(NSString *)key;

/// Consumes `key` without reading it, for an input this port genuinely does not need. `reason` is
/// recorded, because rule 3 exists to stop a port quietly ignoring a field another port acts on.
- (void)ignoreInput:(NSString *)key because:(NSString *)reason;

#pragma mark Intermediates (§15.5 rule 2)

/// Checks `key` against `actual`. Passing nil means THIS IMPLEMENTATION CANNOT EXPOSE THE VALUE and
/// records a skip in the report; it is not a failure, but it is never silent.
- (void)checkIntermediate:(NSString *)key data:(nullable NSData *)actual;
- (void)checkIntermediate:(NSString *)key number:(nullable NSNumber *)actual;
- (void)checkIntermediate:(NSString *)key uint64:(uint64_t)actual;

/// Explicitly declines `key`, with a reason, when the value is not merely unexposed but meaningless
/// for this port.
- (void)skipIntermediate:(NSString *)key because:(NSString *)reason;

#pragma mark Outputs (§15.5 rule 1)

- (void)checkOutput:(NSString *)key data:(NSData *)actual;
- (void)checkOutput:(NSString *)key number:(NSNumber *)actual;
- (void)checkOutput:(NSString *)key uint64:(uint64_t)actual;
- (void)checkOutput:(NSString *)key boolean:(BOOL)actual;
- (void)checkOutput:(NSString *)key string:(NSString *)actual;

#pragma mark Errors

/// Asserts that `error` is exactly the vector's `error` code in IRErrorDomain, and that the vector
/// expected an error at all. Pass nil to assert that no error occurred on an `expect: "ok"` vector.
- (void)checkResultError:(nullable NSError *)error;

#pragma mark Finish

/// Enforces rules 1, 2 and 3, and flushes the skip report. MUST be the last statement of every
/// executor, on every path.
- (void)finish;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
