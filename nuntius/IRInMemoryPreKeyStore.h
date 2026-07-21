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
#import <nuntius/IRPreKeyStore.h>

/**
 The reference IRPreKeyStore — SPEC §5.3, §6.6, §13.3.

 Every conformance vector runs against this class, so its behaviour IS the specification's behaviour
 for the retention set, for OPK expiry, and for the zeroize-then-unlink ordering of §6.6 step 4.

 NOT SEALED, AND THEREFORE NOT FOR PRODUCTION ON ITS OWN. §5.6 requires the store holding OPK
 privates, SPK privates and the identity privates be sealed with the §12.3 construction under a
 device-bound keystore key and excluded from application backups — Keychain with
 kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly and no iCloud sync on Apple platforms. A durable
 subclass overrides -commitDurably: and layers that on; this class keeps everything in memory and
 documents its commit hook as a no-op.

 THREAD SAFETY. All mutation and all reads are serialized under a lock, because a host may plausibly
 publish a bundle on one queue while a message arrives on another, and §6.6's consumption is a
 read-modify-write that must not interleave.
 */
@interface IRInMemoryPreKeyStore : NSObject <IRPreKeyStore>

+ (instancetype _Nonnull)store;

/// Number of one-time prekeys currently held, expired ones included — a sweep only happens on a
/// method that takes a clock. For diagnostics and tests.
@property (nonatomic, readonly) NSUInteger oneTimePreKeyCount;

/**
 The durability hook of §6.6 step 4, called after a consumption has been applied in memory.

 A no-op here, which is honest: an in-memory store has nothing to commit. A durable subclass MUST
 override it and MUST NOT return until the deletion has actually reached stable storage, because
 §10.7 step 14 returns the decrypted plaintext immediately afterwards and a crash in between reopens
 the replay window that §6.6 rule 2 closes.
 */
- (BOOL)commitDurably:(NSError * _Nullable * _Nullable)error;

/// Zeroizes every retained private half — both signed prekey generations and every one-time prekey
/// — and empties the store. §13.3's application-data-erasure path.
- (void)zeroizeAll;

@end
