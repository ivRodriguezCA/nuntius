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
#import <nuntius/IRSessionStore.h>

/**
 An IRSessionStore that keeps live IRSession objects in memory — SPEC §11.1, §11.1.1, §11.4.

 The reference implementation of §11's routing rules, and the store the §15 conformance vectors run
 against: it holds objects rather than blobs, so a vector exercising `SESSION-COLLAPSE` or
 `NEG-HANDSHAKE-TOMBSTONE` is testing the collapse rule and the tombstone window rather than the
 codec and the seal underneath them. IRSealedSessionStore implements the identical protocol over
 §12.1 blobs sealed per §12.3, and is what a production host uses.

 NOT SUFFICIENT ON ITS OWN FOR PRODUCTION, for two reasons that are worth naming rather than
 implying. Nothing here survives a process restart, so every session is lost on launch — which is
 an availability problem, not a security one. And §12.3's "the blob MUST NOT be persisted in
 plaintext" is satisfied only vacuously: this store persists nothing at all. Reaching for it
 because it is the simpler constructor, and then adding persistence around it, is precisely how a
 plaintext session blob ends up on disk.

 TOMBSTONES OUTLIVE SESSIONS BY DESIGN (§11.4). Tearing a session down leaves its `handshake_id`
 behind for `HANDSHAKE_CACHE_MS`, so the store's memory footprint is bounded by the number of peers
 plus the number of teardowns in the last seven days. -pruneAtTimeMs:error: bounds the second.
 */
@interface IRInMemorySessionStore : NSObject <IRSessionStore>

+ (instancetype _Nonnull)store;

/// Live sessions. Tombstones are not counted.
@property (nonatomic, readonly) NSUInteger sessionCount;

/// Retained tombstones, INCLUDING any that have expired but not yet been pruned. A caller asking
/// whether a specific id is live MUST use -hasTombstoneForHandshakeId:atTimeMs:, which applies the
/// window; this is for diagnostics and for the specs.
@property (nonatomic, readonly) NSUInteger tombstoneCount;

/// §13.3 teardown — zeroizes every live session and drops every index. Tombstones are dropped too,
/// which is correct only because nothing survives this object; a store that persisted would have
/// to keep them for the full `HANDSHAKE_CACHE_MS`.
- (void)zeroizeAll;

@end
