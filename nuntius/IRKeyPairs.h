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
#import <nuntius/IRKeyTypes.h>

/**
 Key pairs — SPEC §4.3, §5.3, §7.5, §19.1.

 §4.3: "Implementations MUST also keep KeyPair (public + private) distinct from PublicKey (public
 only), so that a public-key-only value cannot be passed where a private key is required."

 The private half of both types is NON-NULLABLE. v3's IRCurve25519KeyPair had a nullable privateKey
 and an -isEqual: that returned NO whenever one side had a private key and the other did not, so
 its header-key comparison behaved according to how a field had been populated rather than
 according to the key bytes. A non-optional private half makes that defect structurally impossible
 rather than merely fixed.

 NEITHER TYPE OVERRIDES -isEqual:. §4.3 is explicit that the header ratchet key is compared as raw
 32 bytes and nothing else, so compare `pair.publicKey` with -isEqualToX25519Public: and never
 compare pairs. Identity semantics are what these objects keep.
 */

#pragma mark - IRX25519KeyPair

@interface IRX25519KeyPair : NSObject

/// Both halves are required. Returns nil with ERR_INVALID_PUBLIC_KEY if either is missing or
/// carries the wrong width — both are class invariants of the nominal types, so this only fires on
/// a programming error.
///
/// This constructor does NOT verify that the public half corresponds to the private half: doing so
/// needs a scalar multiplication, and the crypto seam sits above these value types. The provider
/// that generates a pair is the only code that can guarantee correspondence, and it does.
+ (instancetype _Nullable)pairWithPublicKey:(IRX25519Public * _Nonnull)publicKey
                                 privateKey:(IRX25519Private * _Nonnull)privateKey
                                      error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IRX25519Public  * _Nonnull publicKey;
@property (nonatomic, strong, readonly) IRX25519Private * _Nonnull privateKey;

/**
 A fresh allocation of the private half, sharing the immutable public half.

 THIS IS THE ONLY WAY A PREKEY RECORD'S KEY PAIR MAY REACH RATCHET STATE. §7.5 has the responder's
 initial DHs be a COPY of SPK_B, and §7.4 step 4 zeroizes the session-owned copy when the ratchet
 replaces it — while §5.3 gives the prekey store exclusive ownership of SPK_B_priv, whose lifetime
 "no ratchet operation may shorten". Aliasing the store's object would let a routine ratchet step
 destroy a key that messages still in flight need, so §19.1 records copy-not-alias as the decision.

 It is named -deepCopy rather than -copy precisely so that the aliasing bug has to be written on
 purpose. Returns nil on allocation failure.
 */
- (IRX25519KeyPair * _Nullable)deepCopy;

/// Zeroizes the private half in place. §13.3's "Ratchet private keys — session-owned copies only"
/// row; NEVER call it on a pair the prekey store owns.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IREd25519KeyPair

@interface IREd25519KeyPair : NSObject

/// The private half is the 32-byte RFC 8032 SEED (§4.2), never libsodium's 64-byte expanded `sk`.
/// The expansion is an internal, single-call value that §3.4 requires be zeroized the moment
/// crypto_sign_detached returns; it MUST NOT appear here or at any other API boundary.
+ (instancetype _Nullable)pairWithPublicKey:(IREd25519Public * _Nonnull)publicKey
                                       seed:(IREd25519Private * _Nonnull)seed
                                      error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) IREd25519Public  * _Nonnull publicKey;
@property (nonatomic, strong, readonly) IREd25519Private * _Nonnull seed;

/// A fresh allocation of the seed, sharing the immutable public half.
- (IREd25519KeyPair * _Nullable)deepCopy;

/// Zeroizes the seed in place. §13.3 holds IK^s_priv for the identity's lifetime, so this is for
/// identity deletion and application data erasure only.
- (void)zeroize;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
