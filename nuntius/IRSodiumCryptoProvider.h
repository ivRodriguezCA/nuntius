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
#import <nuntius/IRCryptoProvider.h>
#import <nuntius/IREnvironment.h>
#import <nuntius/IRErrors.h>

/**
 The libsodium 1.0.22 crypto backend — SPEC §3.2–§3.5, §4.4, §8.2, §13.1, §16.2.

 REPLACES IREncryptionService, which is deleted with the rest of v3. Gone with it, and NOT
 reimplemented anywhere:

   - AES-256-CBC + PKCS7 and the separate HMAC step. CommonCrypto is not imported anywhere in this
     target (§2). The AEAD subsumes both.
   - The derived IV, and the three-values-from-one-message-key scheme that requested a 16-byte IV
     and silently hit crypto_kdf_BYTES_MIN (§8.1).
   - consistentTimeEqual:hmachToCompare: — deleted, not fixed (§8.2, §14 defect 5). Under an AEAD
     there is nothing left to compare.
   - genericKDFWithSecret:andSalt:outputLength:infoLabel: and its four labels, including the
     KDF_MesageKey_Label typo. crypto_kdf_derive_from_key is BANNED (§3.3): it reads exactly 32
     bytes of key, which is what truncated the 96–128 byte X3DH input and collapsed the protocol to
     a single DH.
   - The BLAKE2b ECDH wrapper. Raw X25519 output feeds our own HKDF.
   - Both crypto_sign_ed25519_*_to_curve25519 conversions, whose discarded return values left stack
     buffers UNINITIALIZED and used them as ECDH inputs (§4.1).
   - aeEncryptSimpleData: / aeDecryptSimpleData: — there is no second wire format (§9.3).

 THIS AND IRSodium.m ARE THE ONLY TWO FILES IN THIS FRAMEWORK THAT INCLUDE <Clibsodium/sodium.h>.
 That single property is what turns §3.3's banned-API list into a one-command grep instead of
 reviewer discipline (§3.3, §16.2).

 THREAD SAFETY. Instances are immutable and hold no cryptographic state; libsodium's primitives are
 reentrant and randombytes_buf is thread-safe after sodium_init. One provider may be shared freely.
 Ordering guarantees for ratchet state are the session layer's problem, not this layer's.
 */
@interface IRSodiumCryptoProvider : NSObject <IRCryptoProvider>

/**
 Fails with IRErrorNotInitialized if sodium_init() has not succeeded — checked here at construction
 AND again at every primitive entry point, because §13.2 forbids a silently degraded service and a
 provider can outlive the check that built it.
 */
+ (instancetype _Nullable)providerWithEnvironment:(IREnvironment * _Nonnull)environment
                                             error:(NSError * _Nullable * _Nullable)error;

/// +providerWithEnvironment: against +[IREnvironment production] — the system clock and
/// randombytes_buf. The only form a production caller needs.
+ (instancetype _Nullable)productionProvider:(NSError * _Nullable * _Nullable)error;

/// The clock and CSPRNG this provider draws on. Held rather than read globally so that §15.5
/// rules 5–6 injection reaches the primitives, and so §15.6's ten-years-forward CI run is possible.
@property (nonatomic, strong, readonly) IREnvironment * _Nonnull environment;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end
