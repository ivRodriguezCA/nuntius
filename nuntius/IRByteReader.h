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

/**
 The only code in this framework that reads bytes at an offset — SPEC §3.1, §9, §10, §12, §16.2.

 EVERY read returns BOOL and refuses to read past the end. Nothing here can trap, raise, or read
 out of bounds, which is what makes §12.4's requirement — "a fuzz run is a failure if any input
 produces anything other than a specified error code" — achievable rather than aspirational.

 INTEGERS ARE ASSEMBLED WITH EXPLICIT SHIFTS AND MASKS. Never a memcpy of a native integer, never a
 pointer cast (§3.1, §3.3). v3 read a 1-byte NSData as `*(NSInteger*)data.bytes` at three sites in
 IREncryptionService — an 8-byte out-of-bounds read whose upper 7 bytes were whatever followed in
 memory — and that construct is what §3.3 bans by name. `subdataWithRange:`, which raises rather
 than returning nil when the range is out of bounds (§16.2), does not appear here either.

 TWO ACCESS MODES, both bounds-checked:

   Sequential — -readUInt32BE: and friends advance the cursor. Used by the fixed-layout builders'
   inverse: the bundle parser and the state-blob parser walk their structures front to back.

   Absolute — -readUInt32BE:atOffset: and friends do NOT move the cursor. The §10.1 and §10.2
   ordered gates read fields out of layout order (check 6 inspects msg[168] before check 10 reads
   msg[4]), so they need random access; every §9 offset is a compile-time constant from
   IRProtocolConstants, never a value carried in the message.
 */
@interface IRByteReader : NSObject

/// Copies `data`, so a caller mutating its buffer afterwards cannot change what was parsed.
- (instancetype _Nonnull)initWithData:(NSData * _Nonnull)data NS_DESIGNATED_INITIALIZER;

/**
 A reader over CALLER-OWNED bytes. Nothing is copied and nothing is retained: the caller MUST keep
 the buffer alive and unmodified for the reader's lifetime, and owns its zeroization.

 THIS EXISTS FOR ONE CALLER — the §12.2 state-blob parser. A decrypted state blob holds `RK`,
 `DHs_priv`, `CKs`, `CKr` and every stored message key, so it lives in an IRSecretBytes; feeding it
 to -initWithData: would first materialize all of that into an NSData whose backing store §13.3 has
 no way to wipe ("Serialized state buffer — after sealing, and after parsing"). Copy-on-write is
 exactly the hazard §13.3's Swift note calls out, and it applies verbatim to NSData here.

 Prefer -initWithData: everywhere else. A wire message is attacker-supplied and public; the copy is
 what guarantees it cannot change under a parser mid-gate.
 */
- (instancetype _Nonnull)initWithBytesNoCopy:(const uint8_t * _Nonnull)bytes
                                      length:(NSUInteger)length NS_DESIGNATED_INITIALIZER;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

/// Total number of bytes available, cursor-independent.
@property (nonatomic, readonly) NSUInteger count;

/// Bytes remaining after the cursor.
@property (nonatomic, readonly) NSUInteger remaining;

/// Current cursor position.
@property (nonatomic, readonly) NSUInteger offset;

/// YES when the cursor has consumed every byte. §10.3 and §12.2's exact-length rules are expressed
/// as "parse the declared extent, then require -atEnd".
- (BOOL)atEnd;

/// YES when at least `count` bytes remain after the cursor. Overflow-safe.
- (BOOL)requireRemaining:(NSUInteger)count;

/// YES when the half-open range [offset, offset + length) lies inside the buffer. Overflow-safe:
/// an `offset + length` that would wrap is rejected rather than wrapping.
- (BOOL)hasBytesAtOffset:(NSUInteger)offset length:(NSUInteger)length;

/// Direct access to the backing bytes, for the constant-time comparisons and hash inputs that need
/// a pointer. Never NULL for a non-empty buffer; valid for -count bytes.
- (const uint8_t * _Nullable)constBytes;

#pragma mark - Sequential reads

- (BOOL)readUInt8:(uint8_t * _Nonnull)outValue;
- (BOOL)readUInt16BE:(uint16_t * _Nonnull)outValue;
- (BOOL)readUInt32BE:(uint32_t * _Nonnull)outValue;
- (BOOL)readUInt64BE:(uint64_t * _Nonnull)outValue;

/// Copies `length` bytes into `outBytes`, which MUST address at least `length` writable bytes.
- (BOOL)readBytes:(void * _Nonnull)outBytes length:(NSUInteger)length;

/// Returns a copy of the next `length` bytes, or nil if fewer remain. A zero length yields empty
/// data, not nil.
- (NSData * _Nullable)readDataOfLength:(NSUInteger)length;

/// Compares the next `length` bytes against `literal` and, on a match, consumes them. On a
/// mismatch or a short buffer the cursor does not move. This is how the "NTB4" and "NTS4" magic
/// values are checked without ever calling strlen on a literal (§3.1).
- (BOOL)matchLiteral:(const uint8_t * _Nonnull)literal length:(NSUInteger)length;

- (BOOL)skip:(NSUInteger)count;

/// Moves the cursor to an absolute position. Fails, leaving the cursor untouched, if `offset`
/// exceeds -count.
- (BOOL)seekToOffset:(NSUInteger)offset;

#pragma mark - Absolute reads (cursor unchanged)

- (BOOL)readUInt8:(uint8_t * _Nonnull)outValue atOffset:(NSUInteger)offset;
- (BOOL)readUInt16BE:(uint16_t * _Nonnull)outValue atOffset:(NSUInteger)offset;
- (BOOL)readUInt32BE:(uint32_t * _Nonnull)outValue atOffset:(NSUInteger)offset;
- (BOOL)readUInt64BE:(uint64_t * _Nonnull)outValue atOffset:(NSUInteger)offset;
- (BOOL)readBytes:(void * _Nonnull)outBytes length:(NSUInteger)length atOffset:(NSUInteger)offset;

/// Returns a copy of `length` bytes at `offset`, or nil if the range is out of bounds. The
/// bounds-checked replacement for -[NSData subdataWithRange:], which raises (§16.2).
- (NSData * _Nullable)dataAtOffset:(NSUInteger)offset length:(NSUInteger)length;

/// A borrowed pointer to `length` bytes at `offset`, or NULL if the range is out of bounds. Valid
/// only while the reader lives. Use it to avoid copying a 32-byte key just to compare it.
- (const uint8_t * _Nullable)bytesAtOffset:(NSUInteger)offset length:(NSUInteger)length;

- (BOOL)matchLiteral:(const uint8_t * _Nonnull)literal
              length:(NSUInteger)length
            atOffset:(NSUInteger)offset;

@end
