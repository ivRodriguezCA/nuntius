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

#import "IRVectorIO.h"

#import "IRSodium.h"
#import "IRSodiumCryptoProvider.h"

#pragma mark - Envelope constants

NSString * const kIRVectorSchemaURL     = @"https://nuntius.dev/schema/vectors-v1.json";
NSString * const kIRVectorSpecVersion   = @"4";
NSString * const kIRVectorGeneratedBy   = @"nuntius-objc 0.1.0";
NSString * const kIRVectorGeneratedAt   = @"2026-07-20T00:00:00Z";

NSString * const kIRVectorFilePrimitives = @"primitives";
NSString * const kIRVectorFileX3DH       = @"x3dh";
NSString * const kIRVectorFileRatchet    = @"ratchet";
NSString * const kIRVectorFileWire       = @"wire";
NSString * const kIRVectorFileState      = @"state";
NSString * const kIRVectorFileNegative   = @"negative";

#pragma mark - Hard failure

void IRVectorFail(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    [[NSException exceptionWithName:@"IRVectorCorpusError" reason:message userInfo:nil] raise];

    /* -raise does not return, but the compiler cannot prove it for a __attribute__((noreturn))
       function, and a fallthrough here would be a silently-continuing generator. */
    abort();
}

void IRVectorRecordFailure(XCTestCase *testCase, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    if (testCase == nil) {
        IRVectorFail(@"%@", message);
    }

    XCTIssue *issue = [[XCTIssue alloc] initWithType:XCTIssueTypeAssertionFailure
                                  compactDescription:message];
    [testCase recordIssue:issue];
}

#pragma mark - Hex

static const char kIRVectorHexDigits[17] = "0123456789abcdef";

NSString *IRVectorHex(NSData *data) {
    IRVectorRequire(data != nil, @"IRVectorHex: nil data");

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger count = data.length;

    NSMutableString *hex = [NSMutableString stringWithCapacity:count * 2];
    for (NSUInteger i = 0; i < count; i++) {
        char pair[3] = {kIRVectorHexDigits[bytes[i] >> 4], kIRVectorHexDigits[bytes[i] & 0x0F], 0};
        [hex appendString:[NSString stringWithUTF8String:pair]];
    }

    return [hex copy];
}

static int IRVectorHexNibble(unichar c) {
    if (c >= '0' && c <= '9') {
        return (int)(c - '0');
    }

    /* Lowercase ONLY. §15.2 makes the lowercase form normative; accepting uppercase here would let a
       hand-edited file survive the freeze comparison in one direction and fail it in the other. */
    if (c >= 'a' && c <= 'f') {
        return (int)(c - 'a') + 10;
    }

    return -1;
}

BOOL IRVectorHexIsWellFormed(NSString *hex) {
    if (![hex isKindOfClass:[NSString class]]) {
        return NO;
    }

    if ((hex.length % 2) != 0) {
        return NO;
    }

    for (NSUInteger i = 0; i < hex.length; i++) {
        if (IRVectorHexNibble([hex characterAtIndex:i]) < 0) {
            return NO;
        }
    }

    return YES;
}

NSData *IRVectorBytes(NSString *hex) {
    IRVectorRequire(IRVectorHexIsWellFormed(hex),
                    @"§15.2 / §15.5 rule 4: hex must be even-length, lowercase, unseparated and "
                    @"unprefixed — got \"%@\"", hex);

    NSMutableData *data = [NSMutableData dataWithLength:hex.length / 2];
    uint8_t *out = (uint8_t *)data.mutableBytes;

    for (NSUInteger i = 0; i < hex.length; i += 2) {
        int high = IRVectorHexNibble([hex characterAtIndex:i]);
        int low  = IRVectorHexNibble([hex characterAtIndex:i + 1]);
        out[i / 2] = (uint8_t)((high << 4) | low);
    }

    return [data copy];
}

#pragma mark - uint64 as decimal string

NSString *IRVectorUInt64String(uint64_t value) {
    return [NSString stringWithFormat:@"%llu", (unsigned long long)value];
}

BOOL IRVectorDecimalStringIsWellFormed(NSString *string) {
    if (![string isKindOfClass:[NSString class]]) {
        return NO;
    }

    if (string.length == 0) {
        return NO;
    }

    /* No sign, no separators, no whitespace, and no leading zero except the single digit "0". */
    if (string.length > 1 && [string characterAtIndex:0] == '0') {
        return NO;
    }

    for (NSUInteger i = 0; i < string.length; i++) {
        unichar c = [string characterAtIndex:i];
        if (c < '0' || c > '9') {
            return NO;
        }
    }

    /* 2^64-1 is 20 digits. Anything longer, or 20 digits above the maximum, does not fit the type
       the field is declared as. */
    if (string.length > 20) {
        return NO;
    }

    if (string.length == 20 && [string compare:@"18446744073709551615"] == NSOrderedDescending) {
        return NO;
    }

    return YES;
}

uint64_t IRVectorUInt64FromString(NSString *string) {
    IRVectorRequire(IRVectorDecimalStringIsWellFormed(string),
                    @"§15.2: a uint64-typed field is an unsigned decimal string with no sign, no "
                    @"separators and no leading zeros (except \"0\") — got \"%@\"", string);

    return strtoull(string.UTF8String, NULL, 10);
}

#pragma mark - Error names

static NSDictionary<NSNumber *, NSString *> *IRVectorErrorNames(void) {
    static NSDictionary<NSNumber *, NSString *> *names = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        names = @{
            @(IRErrorUnsupportedVersion) : @"ERR_UNSUPPORTED_VERSION",
            @(IRErrorUnknownMessageType) : @"ERR_UNKNOWN_MESSAGE_TYPE",
            @(IRErrorReservedFlagsSet)   : @"ERR_RESERVED_FLAGS_SET",
            @(IRErrorTruncatedMessage)   : @"ERR_TRUNCATED_MESSAGE",
            @(IRErrorMalformedHeader)    : @"ERR_MALFORMED_HEADER",
            @(IRErrorTrailingBytes)      : @"ERR_TRAILING_BYTES",
            @(IRErrorInvalidPublicKey)   : @"ERR_INVALID_PUBLIC_KEY",
            @(IRErrorSmallOrderKey)      : @"ERR_SMALL_ORDER_KEY",
            @(IRErrorBadSignature)       : @"ERR_BAD_SIGNATURE",
            @(IRErrorAEADAuthFailed)     : @"ERR_AEAD_AUTH_FAILED",
            @(IRErrorTooManySkipped)     : @"ERR_TOO_MANY_SKIPPED",
            @(IRErrorReplay)             : @"ERR_REPLAY",
            @(IRErrorCounterOverflow)    : @"ERR_COUNTER_OVERFLOW",
            @(IRErrorRNGFailure)         : @"ERR_RNG_FAILURE",
            @(IRErrorUnknownPreKeyId)    : @"ERR_UNKNOWN_PREKEY_ID",
            @(IRErrorOPKAlreadyConsumed) : @"ERR_OPK_ALREADY_CONSUMED",
            @(IRErrorPreKeyExpired)      : @"ERR_PREKEY_EXPIRED",
            @(IRErrorStateCorrupt)       : @"ERR_STATE_CORRUPT",
            @(IRErrorNotInitialized)     : @"ERR_NOT_INITIALIZED",
            @(IRErrorPlaintextTooLarge)  : @"ERR_PLAINTEXT_TOO_LARGE",
            @(IRErrorNoSession)          : @"ERR_NO_SESSION",
            @(IRErrorNoSendingChain)     : @"ERR_NO_SENDING_CHAIN",
            @(IRErrorBundleMalformed)    : @"ERR_BUNDLE_MALFORMED",
            @(IRErrorIdentityMismatch)   : @"ERR_IDENTITY_MISMATCH",
            @(IRErrorStateRollback)      : @"ERR_STATE_ROLLBACK",
            @(IRErrorWrongEntryPoint)    : @"ERR_WRONG_ENTRY_POINT",
        };
    });

    return names;
}

NSString *IRVectorNameForErrorCode(IRErrorCode code) {
    return IRVectorErrorNames()[@(code)];
}

IRErrorCode IRVectorErrorCodeForName(NSString *name) {
    if (![name isKindOfClass:[NSString class]]) {
        return (IRErrorCode)0;
    }

    __block IRErrorCode found = (IRErrorCode)0;
    [IRVectorErrorNames() enumerateKeysAndObjectsUsingBlock:^(NSNumber *code,
                                                              NSString *candidate,
                                                              BOOL *stop) {
        if ([candidate isEqualToString:name]) {
            found = (IRErrorCode)code.integerValue;
            *stop = YES;
        }
    }];

    return found;
}

#pragma mark - Locating spec/vectors/

NSString *IRVectorsDirectory(void) {
    static NSString *directory = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        NSString *override = NSProcessInfo.processInfo.environment[@"NUNTIUS_VECTORS_DIR"];
        if (override.length > 0) {
            directory = [override stringByStandardizingPath];
        } else {
            /* __FILE__ is this file's absolute path: <repo>/nuntiusTests/IRVectorIO.m. Two
               deletions give the repo root. Compiled in, so it survives being run from a simulator
               whose working directory is nothing like the repo. */
            NSString *thisFile = @(__FILE__);
            NSString *testsDirectory = thisFile.stringByDeletingLastPathComponent;
            NSString *repoRoot = testsDirectory.stringByDeletingLastPathComponent;

            IRVectorRequire([testsDirectory.lastPathComponent isEqualToString:@"nuntiusTests"],
                            @"__FILE__ (%@) is not inside nuntiusTests/. Set NUNTIUS_VECTORS_DIR to "
                            @"the absolute path of spec/vectors/.", thisFile);

            directory = [repoRoot stringByAppendingPathComponent:@"spec/vectors"];
        }

        NSError *error = nil;
        BOOL created = [NSFileManager.defaultManager createDirectoryAtPath:directory
                                              withIntermediateDirectories:YES
                                                               attributes:nil
                                                                    error:&error];
        IRVectorRequire(created, @"cannot create %@: %@", directory, error);
    });

    return directory;
}

NSString *IRVectorFilePath(NSString *file) {
    IRVectorRequire(file.length > 0, @"IRVectorFilePath: empty file stem");

    return [IRVectorsDirectory() stringByAppendingPathComponent:
                [file stringByAppendingPathExtension:@"json"]];
}

BOOL IRVectorRegenerateRequested(void) {
    NSString *sentinel = [IRVectorsDirectory() stringByAppendingPathComponent:@".regenerate"];

    return [NSFileManager.defaultManager fileExistsAtPath:sentinel];
}

#pragma mark - Envelope and deterministic serialization

NSDictionary *IRVectorEnvelope(NSString *file, NSString *notes, NSArray<NSDictionary *> *vectors) {
    IRVectorRequire(file.length > 0, @"IRVectorEnvelope: empty file stem");
    IRVectorRequire(vectors.count > 0, @"IRVectorEnvelope: %@ has no vectors", file);

    return @{
        @"$schema"      : kIRVectorSchemaURL,
        @"spec_version" : kIRVectorSpecVersion,
        @"file"         : file,
        @"generated_by" : kIRVectorGeneratedBy,
        @"generated_at" : kIRVectorGeneratedAt,
        @"notes"        : (notes ?: @""),
        @"vectors"      : vectors,
    };
}

/// Every string in the tree must be backslash-free, so unescaping `\/` afterwards is total.
static void IRVectorAssertNoBackslashes(id node, NSString *path) {
    if ([node isKindOfClass:[NSString class]]) {
        IRVectorRequire([node rangeOfString:@"\\"].location == NSNotFound,
                        @"%@ contains a backslash; the deterministic serializer forbids it", path);
        return;
    }

    if ([node isKindOfClass:[NSDictionary class]]) {
        [(NSDictionary *)node enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
            IRVectorAssertNoBackslashes(key, [NSString stringWithFormat:@"%@/%@", path, key]);
            IRVectorAssertNoBackslashes(value, [NSString stringWithFormat:@"%@/%@", path, key]);
        }];
        return;
    }

    if ([node isKindOfClass:[NSArray class]]) {
        [(NSArray *)node enumerateObjectsUsingBlock:^(id value, NSUInteger index, BOOL *stop) {
            IRVectorAssertNoBackslashes(value,
                                        [NSString stringWithFormat:@"%@[%lu]",
                                                                   path, (unsigned long)index]);
        }];
    }
}

NSData *IRVectorSerializeEnvelope(NSDictionary *envelope) {
    IRVectorAssertNoBackslashes(envelope, @"");

    IRVectorRequire([NSJSONSerialization isValidJSONObject:envelope],
                    @"envelope is not JSON-serializable — a non-JSON value reached a vector "
                    @"dictionary (NSData and NSNull are the usual culprits; encode bytes with "
                    @"IRVectorHex and uint64 with IRVectorUInt64String)");

    NSError *error = nil;
    NSJSONWritingOptions options = NSJSONWritingSortedKeys | NSJSONWritingPrettyPrinted;
    NSData *json = [NSJSONSerialization dataWithJSONObject:envelope options:options error:&error];
    IRVectorRequire(json != nil, @"JSON serialization failed: %@", error);

    NSString *text = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    IRVectorRequire(text != nil, @"JSON output is not UTF-8");

    /* NSJSONSerialization escapes the solidus. The escape is legal JSON and deterministic, but it
       makes `$schema` unreadable in the artifact humans review under §15.6 step 3, so it is undone
       here. IRVectorAssertNoBackslashes above is what makes this a total operation. */
    text = [text stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];

    NSMutableData *out = [[text dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [out appendBytes:"\n" length:1];

    return [out copy];
}

#pragma mark - Freeze / compare / regenerate

/// The offset of the first differing byte, or NSNotFound.
static NSUInteger IRVectorFirstDifference(NSData *lhs, NSData *rhs) {
    NSUInteger shortest = MIN(lhs.length, rhs.length);
    const uint8_t *a = (const uint8_t *)lhs.bytes;
    const uint8_t *b = (const uint8_t *)rhs.bytes;

    for (NSUInteger i = 0; i < shortest; i++) {
        if (a[i] != b[i]) {
            return i;
        }
    }

    return (lhs.length == rhs.length) ? NSNotFound : shortest;
}

static NSString *IRVectorContextAround(NSData *data, NSUInteger offset) {
    if (offset >= data.length) {
        return @"<end of file>";
    }

    NSUInteger start = (offset > 60) ? (offset - 60) : 0;
    NSUInteger length = MIN((NSUInteger)120, data.length - start);
    NSData *slice = [data subdataWithRange:NSMakeRange(start, length)];
    NSString *text = [[NSString alloc] initWithData:slice encoding:NSUTF8StringEncoding];

    return text ?: IRVectorHex(slice);
}

void IRVectorFreeze(XCTestCase *testCase,
                    NSString *file,
                    NSString *notes,
                    NSArray<NSDictionary *> *vectors) {
    NSString *path = IRVectorFilePath(file);
    NSData *built = IRVectorSerializeEnvelope(IRVectorEnvelope(file, notes, vectors));

    /* Determinism is asserted, not assumed: a dictionary that serialized differently on a second
       pass would produce a corpus that fails its own freeze comparison on the next run, at which
       point the diff would be blamed on the implementation. */
    NSData *again = IRVectorSerializeEnvelope(IRVectorEnvelope(file, notes, vectors));
    IRVectorRequire([built isEqualToData:again],
                    @"%@.json does not serialize deterministically (§15.2)", file);

    NSError *error = nil;

    if (IRVectorRegenerateRequested()) {
        BOOL written = [built writeToFile:path options:NSDataWritingAtomic error:&error];
        IRVectorRequire(written, @"cannot write %@: %@", path, error);

        IRVectorRecordFailure(testCase,
                              @"REGENERATED %@.json because spec/vectors/.regenerate is present. "
                              @"This is always a failing test (§15.6 step 4): a changed vector is a "
                              @"spec version bump, never a silent rewrite. Review `git diff "
                              @"spec/vectors/`, then delete spec/vectors/.regenerate and re-run.",
                              file);
        return;
    }

    if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
        BOOL written = [built writeToFile:path options:NSDataWritingAtomic error:&error];
        IRVectorRequire(written, @"cannot write %@: %@", path, error);

        NSLog(@"[vectors] BOOTSTRAP: wrote %@ (%lu bytes, %lu vectors). It is FROZEN from now on.",
              path, (unsigned long)built.length, (unsigned long)vectors.count);
        return;
    }

    NSData *onDisk = [NSData dataWithContentsOfFile:path options:0 error:&error];
    IRVectorRequire(onDisk != nil, @"cannot read %@: %@", path, error);

    if ([built isEqualToData:onDisk]) {
        return;
    }

    NSUInteger offset = IRVectorFirstDifference(onDisk, built);
    IRVectorRecordFailure(testCase,
                          @"%@.json DRIFTED from the frozen artifact. The implementation now "
                          @"produces different vectors from the ones committed under §15.6 step 3. "
                          @"frozen=%lu bytes, generated=%lu bytes, first difference at byte %lu.\n"
                          @"--- frozen ---\n%@\n--- generated ---\n%@\n"
                          @"If this change is intended it is a SPEC VERSION BUMP: create "
                          @"spec/vectors/.regenerate, re-run, review the diff, delete the sentinel.",
                          file,
                          (unsigned long)onDisk.length,
                          (unsigned long)built.length,
                          (unsigned long)offset,
                          IRVectorContextAround(onDisk, offset),
                          IRVectorContextAround(built, offset));
}

NSArray<NSDictionary *> *IRVectorLoadFrozen(XCTestCase *testCase, NSString *file) {
    NSString *path = IRVectorFilePath(file);
    NSError *error = nil;

    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&error];
    if (data == nil) {
        IRVectorRecordFailure(testCase, @"%@ is missing: %@", path, error);
        return nil;
    }

    id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![parsed isKindOfClass:[NSDictionary class]]) {
        IRVectorRecordFailure(testCase, @"%@ is not a JSON object: %@", path, error);
        return nil;
    }

    NSDictionary *envelope = parsed;

    if (![envelope[@"$schema"] isEqual:kIRVectorSchemaURL]) {
        IRVectorRecordFailure(testCase, @"%@: $schema is %@, expected %@",
                              path, envelope[@"$schema"], kIRVectorSchemaURL);
    }

    if (![envelope[@"spec_version"] isEqual:kIRVectorSpecVersion]) {
        IRVectorRecordFailure(testCase, @"%@: spec_version is %@, expected %@",
                              path, envelope[@"spec_version"], kIRVectorSpecVersion);
    }

    if (![envelope[@"file"] isEqual:file]) {
        IRVectorRecordFailure(testCase, @"%@: file is %@, expected %@",
                              path, envelope[@"file"], file);
    }

    for (NSString *key in @[@"generated_by", @"generated_at", @"notes"]) {
        if (![envelope[key] isKindOfClass:[NSString class]]) {
            IRVectorRecordFailure(testCase, @"%@: %@ is missing or not a string", path, key);
        }
    }

    id vectors = envelope[@"vectors"];
    if (![vectors isKindOfClass:[NSArray class]] || [vectors count] == 0) {
        IRVectorRecordFailure(testCase, @"%@: vectors is missing, not an array, or empty", path);
        return nil;
    }

    return vectors;
}

#pragma mark - Clock and randomness injection

static uint64_t gIRVectorAmbientSkewSeconds = 0;

uint64_t IRVectorAmbientClockSkewSeconds(void) {
    return gIRVectorAmbientSkewSeconds;
}

void IRVectorSetAmbientClockSkewSeconds(uint64_t seconds) {
    gIRVectorAmbientSkewSeconds = seconds;
}

IREnvironment *IRVectorAmbientEnvironment(id<IRRandomSource> randomSource) {
    uint64_t nowMs = (uint64_t)([NSDate date].timeIntervalSince1970 * 1000.0);
    uint64_t skewMs = gIRVectorAmbientSkewSeconds * 1000ULL;
    IRFixedClock *clock = [IRFixedClock clockAtUnixMilliseconds:nowMs + skewMs];

    id<IRRandomSource> source = randomSource ?: [IREnvironment production].randomSource;

    return [[IREnvironment alloc] initWithClock:clock randomSource:source];
}

IREnvironment *IRVectorEnvironmentAtUnixMilliseconds(uint64_t nowMs,
                                                     id<IRRandomSource> randomSource) {
    IRFixedClock *clock = [IRFixedClock clockAtUnixMilliseconds:nowMs];
    id<IRRandomSource> source = randomSource ?: [IREnvironment production].randomSource;

    return [[IREnvironment alloc] initWithClock:clock randomSource:source];
}

id<IRCryptoProvider> IRVectorProviderWithEnvironment(IREnvironment *environment) {
    IRVectorRequire(environment != nil, @"IRVectorProviderWithEnvironment: nil environment");

    NSError *error = nil;
    IRVectorRequire([IRSodium ensureInitialized:&error], @"libsodium: %@", error);

    IRSodiumCryptoProvider *provider = [IRSodiumCryptoProvider providerWithEnvironment:environment
                                                                                error:&error];
    IRVectorRequire(provider != nil, @"cannot build a crypto provider: %@", error);

    return provider;
}

id<IRCryptoProvider> IRVectorAmbientProvider(void) {
    return IRVectorProviderWithEnvironment(IRVectorAmbientEnvironment(nil));
}

#pragma mark - The §15.5 rule 2 skipped-intermediate report

static NSMutableArray<NSString *> *IRVectorSkipLog(void) {
    static NSMutableArray<NSString *> *log = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        log = [NSMutableArray array];
    });

    return log;
}

NSArray<NSString *> *IRVectorSkippedIntermediateReport(void) {
    @synchronized (IRVectorSkipLog()) {
        return [IRVectorSkipLog() copy];
    }
}

void IRVectorResetSkippedIntermediateReport(void) {
    @synchronized (IRVectorSkipLog()) {
        [IRVectorSkipLog() removeAllObjects];
    }
}

static void IRVectorRecordSkip(NSString *entry) {
    @synchronized (IRVectorSkipLog()) {
        [IRVectorSkipLog() addObject:entry];
    }
}

#pragma mark - IRVectorCase

@interface IRVectorCase ()

@property (nonatomic, weak) XCTestCase *testCase;
@property (nonatomic, copy) NSDictionary *vector;
@property (nonatomic, strong) NSMutableSet<NSString *> *consumedInputs;
@property (nonatomic, strong) NSMutableSet<NSString *> *checkedIntermediates;
@property (nonatomic, strong) NSMutableSet<NSString *> *checkedOutputs;
@property (nonatomic, assign) BOOL finished;

@end

@implementation IRVectorCase

+ (instancetype)caseForVector:(NSDictionary *)vector testCase:(XCTestCase *)testCase {
    return [[self alloc] initWithVector:vector testCase:testCase];
}

- (instancetype)initWithVector:(NSDictionary *)vector testCase:(XCTestCase *)testCase {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    IRVectorRequire([vector isKindOfClass:[NSDictionary class]], @"vector is not an object");

    _vector = [vector copy];
    _testCase = testCase;
    _consumedInputs = [NSMutableSet set];
    _checkedIntermediates = [NSMutableSet set];
    _checkedOutputs = [NSMutableSet set];

    _identifier = [self requiredString:@"id"];
    _kind = [self requiredString:@"kind"];
    _vectorDescription = [self requiredString:@"description"];

    NSString *expect = [self requiredString:@"expect"];
    IRVectorRequire([expect isEqualToString:@"ok"] || [expect isEqualToString:@"error"],
                    @"%@: expect is \"%@\", must be \"ok\" or \"error\" (§15.5)",
                    _identifier, expect);
    _expectsError = [expect isEqualToString:@"error"];

    if (_expectsError) {
        _expectedErrorName = [self requiredString:@"error"];
        _expectedErrorCode = IRVectorErrorCodeForName(_expectedErrorName);
        IRVectorRequire(_expectedErrorCode != 0,
                        @"%@: error \"%@\" is not a §10.5 name", _identifier, _expectedErrorName);
    } else {
        IRVectorRequire(vector[@"error"] == nil,
                        @"%@: `error` is present on an expect:\"ok\" vector", _identifier);
    }

    _inputs = [self requiredObject:@"inputs"];

    id intermediates = vector[@"intermediates"];
    IRVectorRequire(intermediates == nil || [intermediates isKindOfClass:[NSDictionary class]],
                    @"%@: intermediates is not an object", _identifier);
    _intermediates = intermediates ? [intermediates copy] : @{};

    id outputs = vector[@"outputs"];
    IRVectorRequire(outputs == nil || [outputs isKindOfClass:[NSDictionary class]],
                    @"%@: outputs is not an object", _identifier);
    _outputs = outputs ? [outputs copy] : @{};

    if (!_expectsError) {
        IRVectorRequire(_outputs.count > 0,
                        @"%@: outputs is REQUIRED when expect == \"ok\" (§15.5)", _identifier);
    }

    return self;
}

- (NSString *)requiredString:(NSString *)key {
    id value = self.vector[key];
    IRVectorRequire([value isKindOfClass:[NSString class]] && [value length] > 0,
                    @"vector is missing the required string field `%@`", key);

    return value;
}

- (NSDictionary *)requiredObject:(NSString *)key {
    id value = self.vector[key];
    IRVectorRequire([value isKindOfClass:[NSDictionary class]],
                    @"%@: missing the required object field `%@`", self.identifier, key);

    return value;
}

- (void)fail:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    IRVectorRecordFailure(self.testCase, @"[%@] %@", self.identifier, message);
}

#pragma mark Inputs

- (id)consumeInput:(NSString *)key {
    [self.consumedInputs addObject:key];

    return self.inputs[key];
}

- (NSData *)dataInput:(NSString *)key {
    NSData *value = [self optionalDataInput:key];
    if (value == nil) {
        [self fail:@"inputs.%@ is missing", key];
        return [NSData data];
    }

    return value;
}

- (NSData *)optionalDataInput:(NSString *)key {
    id value = [self consumeInput:key];
    if (value == nil) {
        return nil;
    }

    if (![value isKindOfClass:[NSString class]]) {
        [self fail:@"inputs.%@ is not a hex string", key];
        return [NSData data];
    }

    if (!IRVectorHexIsWellFormed(value)) {
        [self fail:@"inputs.%@ = \"%@\" violates §15.5 rule 4 (even-length, lowercase hex)",
                   key, value];
        return [NSData data];
    }

    return IRVectorBytes(value);
}

- (uint32_t)uint32Input:(NSString *)key {
    NSNumber *value = [self optionalUInt32Input:key];
    if (value == nil) {
        [self fail:@"inputs.%@ is missing", key];
        return 0;
    }

    return (uint32_t)value.unsignedLongLongValue;
}

- (NSNumber *)optionalUInt32Input:(NSString *)key {
    id value = [self consumeInput:key];
    if (value == nil) {
        return nil;
    }

    if ([value isKindOfClass:[NSString class]]) {
        [self fail:@"inputs.%@ is a string; uint8/uint16/uint32 protocol fields are JSON NUMBERS "
                   @"(§15.2)", key];
        return @0;
    }

    if (![value isKindOfClass:[NSNumber class]]) {
        [self fail:@"inputs.%@ is not a number", key];
        return @0;
    }

    unsigned long long raw = [value unsignedLongLongValue];
    if (raw > UINT32_MAX) {
        [self fail:@"inputs.%@ = %llu exceeds uint32", key, raw];
        return @0;
    }

    return value;
}

- (uint64_t)uint64Input:(NSString *)key {
    NSNumber *value = [self optionalUInt64Input:key];
    if (value == nil) {
        [self fail:@"inputs.%@ is missing", key];
        return 0;
    }

    return value.unsignedLongLongValue;
}

- (NSNumber *)optionalUInt64Input:(NSString *)key {
    id value = [self consumeInput:key];
    if (value == nil) {
        return nil;
    }

    /* §15.5 rule 7 — "a runner MUST reject a uint64 field that is not a JSON string". Not a
       stylistic preference: a bare JSON integer is a `long` to Jackson and a `Double` to
       JSONSerialization, so 9007199254740993 serializes to two different 8-byte fields inside a
       structure §12 declares byte-normative. */
    if (![value isKindOfClass:[NSString class]]) {
        [self fail:@"inputs.%@ is a JSON %@; every uint64-typed field is a decimal STRING "
                   @"(§15.2, §15.5 rule 7)", key, [value class]];
        return @0;
    }

    if (!IRVectorDecimalStringIsWellFormed(value)) {
        [self fail:@"inputs.%@ = \"%@\" is not an unsigned decimal string with no leading zeros",
                   key, value];
        return @0;
    }

    return @(IRVectorUInt64FromString(value));
}

- (NSString *)stringInput:(NSString *)key {
    NSString *value = [self optionalStringInput:key];
    if (value == nil) {
        [self fail:@"inputs.%@ is missing", key];
        return @"";
    }

    return value;
}

- (NSString *)optionalStringInput:(NSString *)key {
    id value = [self consumeInput:key];
    if (value == nil) {
        return nil;
    }

    if (![value isKindOfClass:[NSString class]]) {
        [self fail:@"inputs.%@ is not a string", key];
        return @"";
    }

    return value;
}

- (NSArray *)arrayInput:(NSString *)key {
    id value = [self consumeInput:key];
    if (![value isKindOfClass:[NSArray class]]) {
        [self fail:@"inputs.%@ is missing or not an array", key];
        return @[];
    }

    return value;
}

- (NSDictionary *)optionalDictionaryInput:(NSString *)key {
    id value = [self consumeInput:key];
    if (value == nil) {
        return nil;
    }

    if (![value isKindOfClass:[NSDictionary class]]) {
        [self fail:@"inputs.%@ is not an object", key];
        return @{};
    }

    return value;
}

- (void)ignoreInput:(NSString *)key because:(NSString *)reason {
    if (self.inputs[key] == nil) {
        [self fail:@"-ignoreInput:%@ names a key that is not present", key];
        return;
    }

    [self.consumedInputs addObject:key];
    NSLog(@"[vectors] %@: ignored inputs.%@ — %@", self.identifier, key, reason);
}

#pragma mark Intermediates

- (void)checkIntermediate:(NSString *)key data:(NSData *)actual {
    id expected = self.intermediates[key];
    if (expected == nil) {
        [self fail:@"intermediates.%@ is not in the vector", key];
        return;
    }

    [self.checkedIntermediates addObject:key];

    if (actual == nil) {
        [self recordSkipFor:key reason:@"this implementation cannot expose the value"];
        return;
    }

    [self compareHexValue:expected actual:actual section:@"intermediates" key:key];
}

- (void)checkIntermediate:(NSString *)key number:(NSNumber *)actual {
    id expected = self.intermediates[key];
    if (expected == nil) {
        [self fail:@"intermediates.%@ is not in the vector", key];
        return;
    }

    [self.checkedIntermediates addObject:key];

    if (actual == nil) {
        [self recordSkipFor:key reason:@"this implementation cannot expose the value"];
        return;
    }

    [self compareNumber:expected actual:actual section:@"intermediates" key:key];
}

- (void)checkIntermediate:(NSString *)key uint64:(uint64_t)actual {
    id expected = self.intermediates[key];
    if (expected == nil) {
        [self fail:@"intermediates.%@ is not in the vector", key];
        return;
    }

    [self.checkedIntermediates addObject:key];
    [self compareUInt64:expected actual:actual section:@"intermediates" key:key];
}

- (void)skipIntermediate:(NSString *)key because:(NSString *)reason {
    if (self.intermediates[key] == nil) {
        [self fail:@"-skipIntermediate:%@ names a key that is not in the vector", key];
        return;
    }

    [self.checkedIntermediates addObject:key];
    [self recordSkipFor:key reason:reason];
}

- (void)recordSkipFor:(NSString *)key reason:(NSString *)reason {
    NSString *entry = [NSString stringWithFormat:@"%@.%@: %@", self.identifier, key, reason];
    IRVectorRecordSkip(entry);
    NSLog(@"[vectors] SKIPPED INTERMEDIATE %@", entry);
}

#pragma mark Outputs

- (id)expectedOutputFor:(NSString *)key {
    id expected = self.outputs[key];
    if (expected == nil) {
        [self fail:@"outputs.%@ is not in the vector", key];
        return nil;
    }

    [self.checkedOutputs addObject:key];

    return expected;
}

- (void)checkOutput:(NSString *)key data:(NSData *)actual {
    id expected = [self expectedOutputFor:key];
    if (expected == nil) {
        return;
    }

    if (actual == nil) {
        [self fail:@"outputs.%@: the implementation produced nothing", key];
        return;
    }

    [self compareHexValue:expected actual:actual section:@"outputs" key:key];
}

- (void)checkOutput:(NSString *)key number:(NSNumber *)actual {
    id expected = [self expectedOutputFor:key];
    if (expected == nil) {
        return;
    }

    [self compareNumber:expected actual:actual section:@"outputs" key:key];
}

- (void)checkOutput:(NSString *)key uint64:(uint64_t)actual {
    id expected = [self expectedOutputFor:key];
    if (expected == nil) {
        return;
    }

    [self compareUInt64:expected actual:actual section:@"outputs" key:key];
}

- (void)checkOutput:(NSString *)key boolean:(BOOL)actual {
    id expected = [self expectedOutputFor:key];
    if (expected == nil) {
        return;
    }

    if (![expected isKindOfClass:[NSNumber class]]) {
        [self fail:@"outputs.%@ is not a JSON boolean", key];
        return;
    }

    if ([expected boolValue] != actual) {
        [self fail:@"outputs.%@: expected %@, got %@",
                   key, [expected boolValue] ? @"true" : @"false", actual ? @"true" : @"false"];
    }
}

- (void)checkOutput:(NSString *)key string:(NSString *)actual {
    id expected = [self expectedOutputFor:key];
    if (expected == nil) {
        return;
    }

    if (![expected isEqual:actual]) {
        [self fail:@"outputs.%@: expected \"%@\", got \"%@\"", key, expected, actual];
    }
}

#pragma mark Comparison

- (void)compareHexValue:(id)expected
                 actual:(NSData *)actual
                section:(NSString *)section
                    key:(NSString *)key {
    if (![expected isKindOfClass:[NSString class]]) {
        [self fail:@"%@.%@ is not a hex string", section, key];
        return;
    }

    if (!IRVectorHexIsWellFormed(expected)) {
        [self fail:@"%@.%@ = \"%@\" violates §15.5 rule 4", section, key, expected];
        return;
    }

    NSString *actualHex = IRVectorHex(actual);
    if ([actualHex isEqualToString:expected]) {
        return;
    }

    NSData *expectedBytes = IRVectorBytes(expected);
    NSUInteger offset = IRVectorFirstDifference(expectedBytes, actual);
    [self fail:@"%@.%@ MISMATCH at byte %lu (expected %lu bytes, got %lu)\n  expected %@\n  actual   %@",
               section, key, (unsigned long)offset,
               (unsigned long)expectedBytes.length, (unsigned long)actual.length,
               expected, actualHex];
}

- (void)compareNumber:(id)expected
               actual:(NSNumber *)actual
              section:(NSString *)section
                  key:(NSString *)key {
    if ([expected isKindOfClass:[NSString class]]) {
        [self fail:@"%@.%@ is a string but was checked as a number", section, key];
        return;
    }

    if (![expected isKindOfClass:[NSNumber class]]) {
        [self fail:@"%@.%@ is not a number", section, key];
        return;
    }

    if ([expected unsignedLongLongValue] != [actual unsignedLongLongValue]) {
        [self fail:@"%@.%@: expected %@, got %@", section, key, expected, actual];
    }
}

- (void)compareUInt64:(id)expected
               actual:(uint64_t)actual
              section:(NSString *)section
                  key:(NSString *)key {
    if (![expected isKindOfClass:[NSString class]]) {
        [self fail:@"%@.%@ is a JSON %@; every uint64-typed field is a decimal STRING "
                   @"(§15.2, §15.5 rule 7)", section, key, [expected class]];
        return;
    }

    if (!IRVectorDecimalStringIsWellFormed(expected)) {
        [self fail:@"%@.%@ = \"%@\" is not an unsigned decimal string", section, key, expected];
        return;
    }

    uint64_t value = IRVectorUInt64FromString(expected);
    if (value != actual) {
        [self fail:@"%@.%@: expected %llu, got %llu",
                   section, key, (unsigned long long)value, (unsigned long long)actual];
    }
}

#pragma mark Errors

- (void)checkResultError:(NSError *)error {
    if (!self.expectsError) {
        if (error != nil) {
            [self fail:@"expect is \"ok\" but the implementation returned %@ (%ld)",
                       error.domain, (long)error.code];
        }
        return;
    }

    if (error == nil) {
        [self fail:@"expect is \"error\" (%@) but the implementation SUCCEEDED",
                   self.expectedErrorName];
        return;
    }

    if (![error.domain isEqualToString:IRErrorDomain]) {
        [self fail:@"error domain is %@, expected %@", error.domain, IRErrorDomain];
        return;
    }

    if ((IRErrorCode)error.code != self.expectedErrorCode) {
        NSString *actualName = IRVectorNameForErrorCode((IRErrorCode)error.code) ?: @"<unknown>";
        [self fail:@"expected %@ (%ld), got %@ (%ld)",
                   self.expectedErrorName, (long)self.expectedErrorCode,
                   actualName, (long)error.code];
    }
}

#pragma mark Finish

- (void)finish {
    if (self.finished) {
        [self fail:@"-finish called twice"];
        return;
    }

    self.finished = YES;

    /* Rule 3 — an unrecognised key in `inputs` is an ERROR, not a forward-compatibility
       affordance. Reading an input consumes it, so anything left here is a field this port never
       looked at, which is exactly how one port silently ignores what another port acts on. */
    NSMutableSet<NSString *> *unconsumed = [NSMutableSet setWithArray:self.inputs.allKeys];
    [unconsumed minusSet:self.consumedInputs];
    if (unconsumed.count > 0) {
        NSArray *sorted = [unconsumed.allObjects sortedArrayUsingSelector:@selector(compare:)];
        [self fail:@"§15.5 rule 3: inputs keys never read: %@. Read them, or declare each with "
                   @"-ignoreInput:because:.", [sorted componentsJoinedByString:@", "]];
    }

    /* Rule 1 — a runner MUST check every key present in `outputs`. */
    NSMutableSet<NSString *> *uncheckedOutputs = [NSMutableSet setWithArray:self.outputs.allKeys];
    [uncheckedOutputs minusSet:self.checkedOutputs];
    if (uncheckedOutputs.count > 0) {
        NSArray *sorted = [uncheckedOutputs.allObjects sortedArrayUsingSelector:@selector(compare:)];
        [self fail:@"§15.5 rule 1: outputs keys never checked: %@",
                   [sorted componentsJoinedByString:@", "]];
    }

    /* Rule 2 — every intermediate this implementation can expose MUST be checked, and the skipped
       ones MUST be reported. Neither checking nor explicitly skipping is the one outcome the rule
       does not allow. */
    NSMutableSet<NSString *> *untouched = [NSMutableSet setWithArray:self.intermediates.allKeys];
    [untouched minusSet:self.checkedIntermediates];
    if (untouched.count > 0) {
        NSArray *sorted = [untouched.allObjects sortedArrayUsingSelector:@selector(compare:)];
        [self fail:@"§15.5 rule 2: intermediates neither checked nor reported as skipped: %@",
                   [sorted componentsJoinedByString:@", "]];
    }
}

@end
