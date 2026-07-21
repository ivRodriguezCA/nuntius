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
#import <nuntius/IRSecretBytes.h>

/**
 The fixed-layout structure builder — SPEC §6.2, §9, §12.

 Every structure in this protocol has a length the specification states exactly, and §6.2 makes the
 discipline normative: "A transcript builder that appends fixed-width fields and asserts the total
 is RECOMMENDED in all four languages, so that a missing field is a test failure rather than a
 silent interop break." -finishExpectingLength:error: generalizes that assertion to every fixed
 structure in the document:

     IKBIND_MSG    81      SPK_SIGN_MSG   130     TRANSCRIPT     259
     SESSION_AD    141     FP input       77      IKM            128 or 160
     0x01 header   56      0x02 header    225     bundle         251 + 36n
     state blob    472 + 76n

 A field omitted, duplicated or written at the wrong width changes the total, so it fails here
 rather than on a peer's machine in another language.

 ALL MULTI-BYTE INTEGERS ARE WRITTEN BIG-ENDIAN, byte by byte. No memcpy of a native integer
 (§3.1).

 SECRETS. Some of what this type builds is secret — IKM is F32 ‖ DH1..DH4, whose zeroization §13.3
 schedules for "immediately after SK is derived". The accumulator is therefore zeroized on -dealloc
 unconditionally, and -finishSecretExpectingLength:error: hands the result back as an IRSecretBytes
 rather than an NSData, wiping the writer's own copy as it goes. Use the NSData form only for
 material that is not secret: transcripts, headers, associated data, bundles.
 */
@interface IRByteWriter : NSObject

/// `capacity` is a hint; the accumulator grows if it is exceeded. Pass the structure's expected
/// length so the common case performs one allocation.
- (instancetype _Nonnull)initWithCapacity:(NSUInteger)capacity NS_DESIGNATED_INITIALIZER;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

/// Bytes accumulated so far.
@property (nonatomic, readonly) NSUInteger length;

- (void)appendUInt8:(uint8_t)value;
- (void)appendUInt16BE:(uint16_t)value;
- (void)appendUInt32BE:(uint32_t)value;
- (void)appendUInt64BE:(uint64_t)value;
- (void)appendBytes:(const void * _Nonnull)bytes length:(NSUInteger)length;
- (void)appendData:(NSData * _Nonnull)data;

/// Appends the secret's raw bytes. Used for IKM's DH terms; the writer's copy is wiped by
/// -finishSecretExpectingLength:error:, by -zeroize, or by -dealloc.
- (void)appendSecretBytes:(IRSecretBytes * _Nonnull)secret;

/// Appends `count` zero bytes. §12.1's fixed-size optional fields are "always present and
/// zero-filled when absent", and §6.2 encodes an absent OPK as 32 zero bytes rather than omitting
/// it, so the builder has no conditional structure in either case.
- (void)appendZeros:(NSUInteger)count;

/**
 Returns the accumulated bytes, but ONLY if the total is EXACTLY `expectedLength`.

 On a mismatch it returns nil and reports `mismatchErrorCode`, which the caller chooses because the
 right code depends on what was being built — a malformed state blob is ERR_STATE_CORRUPT, a
 malformed bundle is ERR_BUNDLE_MALFORMED, and a builder that got its own transcript wrong is a
 programming error the caller surfaces however it sees fit.
 */
- (NSData * _Nullable)finishExpectingLength:(NSUInteger)expectedLength
                          mismatchErrorCode:(IRErrorCode)mismatchErrorCode
                                      error:(NSError * _Nullable * _Nullable)error;

/// As -finishExpectingLength:mismatchErrorCode:error: with ERR_STATE_CORRUPT, which is the code for
/// every fixed-layout structure this framework builds for itself rather than parses from a peer.
- (NSData * _Nullable)finishExpectingLength:(NSUInteger)expectedLength
                                      error:(NSError * _Nullable * _Nullable)error;

/**
 As -finishExpectingLength:error:, but yields an IRSecretBytes and zeroizes the writer's own
 accumulator before returning. This is the form IKM MUST use (§13.3): an NSData result would put
 the concatenated DH outputs into a copy-on-write container with no zeroizing hook.

 On a length mismatch the accumulator is still zeroized.
 */
- (IRSecretBytes * _Nullable)finishSecretExpectingLength:(NSUInteger)expectedLength
                                                 guarded:(BOOL)guarded
                                                   error:(NSError * _Nullable * _Nullable)error;

/// Wipes and discards everything accumulated so far. -dealloc does this unconditionally; call it
/// explicitly at a §13.3 schedule point or on an abandoned build.
- (void)zeroize;

@end
