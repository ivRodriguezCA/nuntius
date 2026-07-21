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

#import "IRSodiumCryptoProvider.h"

#import "IRProtocolConstants.h"
#import "IRSodium.h"

#include <Clibsodium/sodium.h>

/* This is the SECOND AND LAST file in the framework that includes <Clibsodium/sodium.h>; the other
   is IRSodium.m. The §3.3 lint depends on that being exactly true, because it is what makes the
   banned-API list a one-command grep rather than a code-review convention:

       grep -rl 'Clibsodium/sodium.h' nuntius/   ->  must list exactly two files

   NOT PRESENT HERE, AND BANNED BY §3.3:
     crypto_kdf_derive_from_key, crypto_kdf_blake2b_*   (32-byte truncation; root cause of defect 1)
     crypto_kx_*                                        (single DH; BLAKE2b has no JDK/CryptoKit peer)
     crypto_sign_ed25519_pk_to_curve25519, _sk_to_...   (no JDK/CryptoKit peer; uninitialized stack)
     crypto_sign_init/_update/_final_create/_final_verify: PREHASHED — see §3.4, IRSignWithSeed
     crypto_aead_chacha20poly1305_encrypt, non-IETF:      8-byte nonce; silent incompatibility
     crypto_aead_xchacha20poly1305_ietf_*:                absent from CryptoKit and the JDK
     crypto_aead_aes256gcm_*:                             hardware-gated behind an availability call
     CommonCrypto, in any form:                           §2 removed it entirely

   NOTE FOR THE §3.3 LINT SCRIPT (tools/lint_banned_apis.py): the names above are MENTIONS, not call sites. A lint that greps
   for a bare identifier will flag this comment. Match a call site — the identifier followed
   immediately by '(' with no intervening space — or strip comments first (`clang -E -P`). The
   punctuation above is deliberately ':' rather than '(' so that even the naive form stays clean. */

#pragma mark - Compile-time width agreement

/* §16.2 requires the nonce width be asserted. Doing it at compile time against libsodium's own
   macros makes a mismatch between §18's frozen table and the linked library a BUILD failure rather
   than a runtime one — and picking up the non-IETF 8-byte-nonce variant by autocomplete is exactly
   the silent incompatibility §3.3 bans it for. */
IR_STATIC_ASSERT(kIRLenNonce == crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                 "SPEC 18: AEAD nonce is 12 bytes - the IETF construction, not the 8-byte original");
IR_STATIC_ASSERT(kIRLenMessageEncKey == crypto_aead_chacha20poly1305_ietf_KEYBYTES,
                 "SPEC 8.2: AEAD key is 256 bits");
IR_STATIC_ASSERT(kIRLenAEADTag == crypto_aead_chacha20poly1305_ietf_ABYTES,
                 "SPEC 8.2: Poly1305 tag is 128 bits, appended to the ciphertext");
IR_STATIC_ASSERT(kIRLenX25519Public == crypto_scalarmult_BYTES,
                 "SPEC 4.2: X25519 public key is the raw 32-byte u-coordinate");
IR_STATIC_ASSERT(kIRLenX25519Private == crypto_scalarmult_SCALARBYTES,
                 "SPEC 4.2: X25519 private key is a 32-byte scalar");
IR_STATIC_ASSERT(kIRLenDHOutput == crypto_scalarmult_BYTES,
                 "SPEC 4.4 check 3: the DH output is the 32 bytes the all-zero test covers");
IR_STATIC_ASSERT(kIRLenEd25519Public == crypto_sign_PUBLICKEYBYTES,
                 "SPEC 4.2: Ed25519 public key is the raw 32-byte RFC 8032 5.1.2 encoding");
IR_STATIC_ASSERT(kIRLenEd25519Private == crypto_sign_SEEDBYTES,
                 "SPEC 4.2: Ed25519 private key is the 32-byte SEED, never the 64-byte expanded sk");
IR_STATIC_ASSERT(kIRLenEd25519Signature == crypto_sign_BYTES,
                 "SPEC 4.2: Ed25519 signature is the raw 64-byte RFC 8032 5.1.6 encoding");
IR_STATIC_ASSERT(kIRLenSHA256 == crypto_hash_sha256_BYTES,
                 "SPEC 3.2: SHA-256 output is 32 bytes");
IR_STATIC_ASSERT(kIRLenHMACSHA256 == crypto_auth_hmacsha256_BYTES,
                 "SPEC 3.2: HMAC-SHA256 output is 32 bytes");
IR_STATIC_ASSERT(kIRLenHKDFPRK == crypto_kdf_hkdf_sha256_KEYBYTES,
                 "SPEC 3.2: the HKDF-Extract PRK is 32 bytes");

/* §4.2 requires the 64-byte libsodium sk never appear in a nominal type, a vector file, a
   serialized structure, or at an API boundary. It exists in exactly one place — the stack of
   IRSignWithSeed / IRPublicKeyFromSeed — and this assertion pins the width that code assumes. */
IR_STATIC_ASSERT(crypto_sign_SECRETKEYBYTES == (crypto_sign_SEEDBYTES + crypto_sign_PUBLICKEYBYTES),
                 "SPEC 3.4: libsodium sk is seed || pk; crypto_sign_detached reads all 64 bytes");

/// §3.2 — HKDF-Expand's ceiling is 255 blocks. KDF_RK's L = 64 is two.
static const NSUInteger kIRHKDFMaxOutputLength = (NSUInteger)crypto_kdf_hkdf_sha256_BYTES_MAX;

#pragma mark - Pointer helpers

/**
 A valid, readable address for a zero-length input.

 -[NSData bytes] is not documented to return non-NULL for empty data, and several libsodium entry
 points are declared __attribute__((nonnull)) on pointers this code passes through. Handing a
 zero-length span a real address costs nothing and removes the whole class of "worked until the
 empty case".
 */
static const uint8_t kIREmptyByte = 0;

static const uint8_t * _Nonnull IRDataBytes(NSData * _Nullable data) {
    const void *bytes = data.bytes;
    return (bytes != NULL) ? (const uint8_t *)bytes : &kIREmptyByte;
}

#pragma mark - Ed25519 seed expansion (§3.4, §4.2, §13.3, §16.2)

/**
 Expand a 32-byte RFC 8032 seed, sign, and destroy the expansion — IN ONE LEXICAL SCOPE.

 THIS IS THE ONLY CALL TO crypto_sign_detached IN THE TREE, and the shape is the point.

 §3.4: crypto_sign_detached reads exactly crypto_sign_SECRETKEYBYTES = 64 bytes from `sk` and uses
 sk[32..64) as the public key A, which it hashes into the RFC 8032 challenge. The nominal
 IREd25519Private is the 32-BYTE SEED. Passing that seed straight through — the natural
 transcription of a vector file's `IK_A_s_priv` — is an OUT-OF-BOUNDS READ OF 32 BYTES, undefined
 behaviour rather than a wrong-key bug, and it yields a signature that fails to verify against the
 real IK^s. §1.2 defines a verification failure as an active MITM, so the bug arrives disguised as
 an attack. Keeping the expansion inside the signing function means there is no `sk` for a future
 caller to get wrong.

 §13.3: the expanded sk "MUST NOT outlive the single signing call that needed it". It is zeroized
 before this function returns, on the success path and on the failure path.

 RFC 8032 signing is fully determined by the seed, so this produces byte-identical output to the
 JDK's Ed25519PrivateKeySpec and CryptoKit's Curve25519.Signing.PrivateKey(rawRepresentation:).
 There are not two legitimate encodings to reconcile.

 The multi-part crypto_sign_init/_update/_final_create API is NOT used and MUST NOT be: crypto_sign.h
 line 23 of the vendored 1.0.22 tree reads `typedef crypto_sign_ed25519ph_state crypto_sign_state`,
 so it is Ed25519ph — PREHASHED — which neither the JDK nor CryptoKit can verify. v3 used it at
 IREncryptionService.m:431-433 and :449-450.
 */
static BOOL IRSignWithSeed(const uint8_t * _Nonnull seed,
                           const uint8_t * _Nonnull message,
                           unsigned long long messageLength,
                           uint8_t * _Nonnull signatureOut,
                           NSError * _Nullable * _Nullable error) {
    uint8_t publicKey[crypto_sign_PUBLICKEYBYTES];
    uint8_t secretKey[crypto_sign_SECRETKEYBYTES];

    if (crypto_sign_seed_keypair(publicKey, secretKey, seed) != 0) {
        IRZeroize(publicKey, sizeof(publicKey));
        IRZeroize(secretKey, sizeof(secretKey));
        IRSetError(error, IRErrorBadSignature);
        return NO;
    }

    unsigned long long signatureLength = 0;
    const int signResult = crypto_sign_detached(signatureOut, &signatureLength,
                                                message, messageLength, secretKey);

    /* Before ANY branch on the result. §13.3's row is unconditional, and an early return that
       skipped the wipe would leave a full Ed25519 secret key on the stack. */
    IRZeroize(secretKey, sizeof(secretKey));
    IRZeroize(publicKey, sizeof(publicKey));

    if (signResult != 0 || signatureLength != (unsigned long long)crypto_sign_BYTES) {
        IRZeroize(signatureOut, crypto_sign_BYTES);
        IRSetError(error, IRErrorBadSignature);
        return NO;
    }

    return YES;
}

/**
 Recover the RFC 8032 public key from a seed, destroying the expansion in the same scope.

 Split from IRSignWithSeed rather than sharing an expansion helper, so that no `sk` is ever returned
 to a caller. Both functions expand and wipe within their own frame; neither hands one out.
 */
static BOOL IRPublicKeyFromSeed(const uint8_t * _Nonnull seed,
                                uint8_t * _Nonnull publicKeyOut,
                                NSError * _Nullable * _Nullable error) {
    uint8_t secretKey[crypto_sign_SECRETKEYBYTES];

    const int result = crypto_sign_seed_keypair(publicKeyOut, secretKey, seed);

    IRZeroize(secretKey, sizeof(secretKey));

    if (result != 0) {
        IRZeroize(publicKeyOut, crypto_sign_PUBLICKEYBYTES);
        IRSetError(error, IRErrorInvalidPublicKey);
        return NO;
    }

    return YES;
}

#pragma mark - IRSodiumCryptoProvider

@interface IRSodiumCryptoProvider ()
@property (nonatomic, strong, readwrite) IREnvironment * _Nonnull environment;
- (instancetype _Nonnull)initWithEnvironment:(IREnvironment * _Nonnull)environment;
@end

@implementation IRSodiumCryptoProvider

#pragma mark Construction

+ (instancetype _Nullable)providerWithEnvironment:(IREnvironment * _Nonnull)environment
                                             error:(NSError * _Nullable * _Nullable)error {
    if (environment == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §13.2 — sodium_init() runs exactly once and its return value is checked. A negative return is
       LATCHED, so this fails here and keeps failing rather than degrading into a service that looks
       like it works. v3 wrote `__unused int result = sodium_init();`. */
    if (![IRSodium ensureInitialized:error]) {
        return nil;
    }

    return [[IRSodiumCryptoProvider alloc] initWithEnvironment:environment];
}

+ (instancetype _Nullable)productionProvider:(NSError * _Nullable * _Nullable)error {
    return [IRSodiumCryptoProvider providerWithEnvironment:[IREnvironment production] error:error];
}

- (instancetype _Nonnull)initWithEnvironment:(IREnvironment * _Nonnull)environment {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _environment = environment;

    return self;
}

#pragma mark Preconditions

/**
 §13.2 — re-checked at EVERY primitive entry point, not merely at construction.

 A provider can outlive the check that built it, and "never a silently degraded service" is only
 true if the guard sits where the primitive is. It is one predicate call, off any hot loop.
 */
- (BOOL)ensureUsable:(NSError * _Nullable * _Nullable)error {
    if (![IRSodium isInitialized]) {
        IRSetError(error, IRErrorNotInitialized);
        return NO;
    }

    return YES;
}

#pragma mark - Hash and MAC (§3.2)

- (NSData * _Nullable)sha256OfData:(NSData * _Nonnull)data
                             error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (data == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    uint8_t digest[crypto_hash_sha256_BYTES];

    if (crypto_hash_sha256(digest, IRDataBytes(data), (unsigned long long)data.length) != 0) {
        IRZeroize(digest, sizeof(digest));
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

- (IRSecretBytes * _Nullable)hmacSHA256WithKey:(IRSecretBytes * _Nonnull)key
                                       message:(NSData * _Nonnull)message
                                         error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (key == nil || key.length == 0 || message == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSecretBytes *mac = [[IRSecretBytes alloc] initWithLength:(NSUInteger)crypto_auth_hmacsha256_BYTES];
    if (mac == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* The MULTI-PART form, deliberately. The one-shot crypto_auth_hmacsha256 fixes the key at
       crypto_auth_hmacsha256_KEYBYTES = 32; init/update/final takes a length. §7.3's KDF_CK happens
       to use a 32-byte chain key, but HKDF-Extract's salt is arbitrary length and shares this
       code path, so a 32-byte-only HMAC could not express it.

       This is NOT the banned multi-part SIGNING API of §3.3 — that ban is about
       crypto_sign_init/_update/_final_create being Ed25519ph. HMAC has no such variant. */
    crypto_auth_hmacsha256_state state;

    if (crypto_auth_hmacsha256_init(&state, key.constBytes, (size_t)key.length) != 0 ||
        crypto_auth_hmacsha256_update(&state, IRDataBytes(message),
                                      (unsigned long long)message.length) != 0 ||
        crypto_auth_hmacsha256_final(&state, [mac mutableBytes]) != 0) {
        IRZeroize(&state, sizeof(state));
        [mac zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* The state holds the key-derived inner and outer SHA-256 contexts. Leaving it on the stack
       would leave a usable HMAC continuation behind. */
    IRZeroize(&state, sizeof(state));

    return mac;
}

#pragma mark - HKDF (§3.2)

- (IRSecretBytes * _Nullable)hkdfExtractWithSalt:(IRSecretBytes * _Nullable)salt
                                             ikm:(IRSecretBytes * _Nonnull)ikm
                                           error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (ikm == nil || ikm.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSecretBytes *prk = [[IRSecretBytes alloc] initWithLength:(NSUInteger)crypto_kdf_hkdf_sha256_KEYBYTES];
    if (prk == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* A nil salt means a ZERO-LENGTH salt, which §3.2 states produces an IDENTICAL PRK to Z32:
       HMAC pads any key shorter than its 64-byte block with zeros, and RFC 5869 §2.2 defines the
       default salt as HashLen zeros for exactly this reason. Everywhere this document writes
       `salt = Z32` an implementation MAY pass nil. Not a divergence point; HKDF-SALT-EQUIV records
       that it is not. */
    const uint8_t *saltBytes = (salt != nil) ? salt.constBytes : &kIREmptyByte;
    const size_t saltLength = (salt != nil) ? (size_t)salt.length : 0;

    if (crypto_kdf_hkdf_sha256_extract([prk mutableBytes], saltBytes, saltLength,
                                       ikm.constBytes, (size_t)ikm.length) != 0) {
        [prk zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return prk;
}

- (IRSecretBytes * _Nullable)hkdfExpandWithPRK:(IRSecretBytes * _Nonnull)prk
                                           info:(NSData * _Nonnull)info
                                   outputLength:(NSUInteger)outputLength
                                          error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (prk == nil || prk.length != (NSUInteger)crypto_kdf_hkdf_sha256_KEYBYTES || info == nil ||
        outputLength == 0 || outputLength > kIRHKDFMaxOutputLength) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSecretBytes *okm = [[IRSecretBytes alloc] initWithLength:outputLength];
    if (okm == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §3.5 verified that crypto_kdf_hkdf_sha256_expand's ctx/ctx_len pair IS the HKDF `info`
       parameter — it is not a crypto_kdf-style 8-byte context, and it is not truncated. The
       RFC 5869 A1–A3 vectors in IRPrimitivesSpec are what hold that claim to account, and
       HKDF-EXPAND-64 covers the two-block T(i) loop that §7.2's L = 64 needs. */
    if (crypto_kdf_hkdf_sha256_expand([okm mutableBytes], (size_t)outputLength,
                                      (const char *)IRDataBytes(info), (size_t)info.length,
                                      prk.constBytes) != 0) {
        [okm zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return okm;
}

- (IRSecretBytes * _Nullable)hkdfWithSalt:(IRSecretBytes * _Nullable)salt
                                       ikm:(IRSecretBytes * _Nonnull)ikm
                                      info:(NSData * _Nonnull)info
                              outputLength:(NSUInteger)outputLength
                                     error:(NSError * _Nullable * _Nullable)error {
    IRSecretBytes *prk = [self hkdfExtractWithSalt:salt ikm:ikm error:error];
    if (prk == nil) {
        return nil;
    }

    IRSecretBytes *okm = [self hkdfExpandWithPRK:prk
                                            info:info
                                    outputLength:outputLength
                                           error:error];

    /* The PRK is a secret with no role past this point. It is not on §13.3's table because §13.3
       enumerates secrets the PROTOCOL names; this one never escapes the function that made it. */
    [prk zeroizeNow];

    return okm;
}

#pragma mark - X25519 (§4.2, §4.4)

- (IRX25519KeyPair * _Nullable)generateX25519KeyPairWithError:(NSError * _Nullable * _Nullable)error {
    return [self generateX25519KeyPairGuarded:NO error:error];
}

- (IRX25519KeyPair * _Nullable)generateX25519KeyPairGuarded:(BOOL)guarded
                                                       error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    uint8_t scalar[crypto_scalarmult_SCALARBYTES];

    if (![self.environment.randomSource fillBytes:scalar length:sizeof(scalar) error:error]) {
        IRZeroize(scalar, sizeof(scalar));
        return nil;
    }

    /* §13.1's tripwire, AND IT MUST RUN HERE — on the RAW CSPRNG output, BEFORE the §4.2 clamp.
       The clamp sets `k[31] |= 0x40`, so a scalar that arrived all-zero from a broken RNG is
       `00..0040` by the time it is stored and would sail past an all-zero test applied afterwards.
       Ordering is the whole value of the check: run it after clamping and it can never fire. */
    if (IRIsAllZero(scalar, sizeof(scalar))) {
        IRZeroize(scalar, sizeof(scalar));
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    /* +fromBytes:guarded:error: applies -normalizeRepresentation, which is where the §4.2 clamp
       lands. Clamping at construction covers generation, state load and vector input in one place;
       it is idempotent and changes no cryptographic output, because RFC 7748 §5 clamps internally
       anyway. What it buys is that libsodium/CryptoKit (which store raw CSPRNG bytes) and
       BouncyCastle (which clamps at generation) write the SAME bytes at state-blob offsets 243
       and 274 for cryptographically identical state. */
    IRX25519Private *privateKey = [IRX25519Private fromBytes:scalar guarded:guarded error:error];
    IRZeroize(scalar, sizeof(scalar));

    if (privateKey == nil) {
        return nil;
    }

    uint8_t publicBytes[crypto_scalarmult_BYTES];

    /* Derived from the CLAMPED scalar that will actually be stored, so the pair cannot disagree
       with what a later state blob holds. */
    if (crypto_scalarmult_base(publicBytes, privateKey.constBytes) != 0) {
        IRZeroize(publicBytes, sizeof(publicBytes));
        [privateKey zeroizeNow];
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRX25519Public *publicKey = [IRX25519Public fromBytes:publicBytes error:error];
    IRZeroize(publicBytes, sizeof(publicBytes));

    if (publicKey == nil) {
        [privateKey zeroizeNow];
        return nil;
    }

    IRX25519KeyPair *pair = [IRX25519KeyPair pairWithPublicKey:publicKey
                                                    privateKey:privateKey
                                                         error:error];
    if (pair == nil) {
        [privateKey zeroizeNow];
        return nil;
    }

    return pair;
}

- (IRSecretBytes * _Nullable)x25519WithPrivateKey:(IRX25519Private * _Nonnull)privateKey
                                         publicKey:(IRX25519Public * _Nonnull)publicKey
                                             error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (privateKey == nil || privateKey.length != (NSUInteger)crypto_scalarmult_SCALARBYTES ||
        publicKey == nil || publicKey.length != (NSUInteger)crypto_scalarmult_BYTES) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRSecretBytes *shared = [[IRSecretBytes alloc] initWithLength:(NSUInteger)crypto_scalarmult_BYTES];
    if (shared == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* crypto_scalarmult carries __attribute__((warn_unused_result)), and -Werror=unused-result is
       promoted on this file, so this return CANNOT be dropped. libsodium returns -1 exactly when
       the output is all-zero. */
    const int result = crypto_scalarmult([shared mutableBytes], privateKey.constBytes,
                                         publicKey.constBytes);

    /* §4.4 CHECK 3, run unconditionally and INDEPENDENTLY of libsodium's own verdict.

       §4.4 requires this "even on platforms whose library already fails closed", so that all four
       ports behave uniformly — libsodium returns -1, BouncyCastle throws, the JDK throws, and
       CryptoKit does NOTHING, which leaves the accumulator as Swift's only defence. Testing here
       rather than trusting the return also means the two failure modes are indistinguishable to a
       caller, which is what §4.4 asks for.

       IRIsAllZero is the OR-accumulator §4.4 prescribes. A hard-coded blacklist of the twelve
       small-order points is explicitly forbidden as a sole check: mistyping one of twelve 32-byte
       constants is a silent failure. */
    const BOOL outputIsZero = IRIsAllZero(shared.constBytes, shared.length);

    if (result != 0 || outputIsZero) {
        /* "zeroize the output, abort the entire operation with ERR_SMALL_ORDER_KEY, and mutate no
           state" — §4.4 check 3, verbatim. */
        [shared zeroizeNow];
        IRSetError(error, IRErrorSmallOrderKey);
        return nil;
    }

    return shared;
}

#pragma mark - Ed25519 (§3.4, §4.2)

- (IREd25519KeyPair * _Nullable)generateEd25519KeyPairWithError:(NSError * _Nullable * _Nullable)error {
    return [self generateEd25519KeyPairGuarded:NO error:error];
}

- (IREd25519KeyPair * _Nullable)generateEd25519KeyPairGuarded:(BOOL)guarded
                                                         error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    uint8_t seedBytes[crypto_sign_SEEDBYTES];

    /* crypto_sign_keypair would generate the pair in one call, but it returns the 64-byte expanded
       sk and no seed. §4.2 makes the SEED the nominal private key, so the seed is generated here
       and the public half is derived from it. */
    if (![self.environment.randomSource fillBytes:seedBytes length:sizeof(seedBytes) error:error]) {
        IRZeroize(seedBytes, sizeof(seedBytes));
        return nil;
    }

    /* §13.1 tripwire. Ed25519 seeds are stored VERBATIM — §4.2: Ed25519 clamps the SHA-512 hash of
       the seed, not the seed itself — so there is no clamp to order this against, unlike X25519. */
    if (IRIsAllZero(seedBytes, sizeof(seedBytes))) {
        IRZeroize(seedBytes, sizeof(seedBytes));
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    uint8_t publicBytes[crypto_sign_PUBLICKEYBYTES];

    if (!IRPublicKeyFromSeed(seedBytes, publicBytes, error)) {
        IRZeroize(seedBytes, sizeof(seedBytes));
        IRZeroize(publicBytes, sizeof(publicBytes));
        return nil;
    }

    IREd25519Private *seed = [IREd25519Private fromBytes:seedBytes guarded:guarded error:error];
    IRZeroize(seedBytes, sizeof(seedBytes));

    if (seed == nil) {
        IRZeroize(publicBytes, sizeof(publicBytes));
        return nil;
    }

    IREd25519Public *publicKey = [IREd25519Public fromBytes:publicBytes error:error];
    IRZeroize(publicBytes, sizeof(publicBytes));

    if (publicKey == nil) {
        [seed zeroizeNow];
        return nil;
    }

    IREd25519KeyPair *pair = [IREd25519KeyPair pairWithPublicKey:publicKey seed:seed error:error];
    if (pair == nil) {
        [seed zeroizeNow];
        return nil;
    }

    return pair;
}

- (IREd25519Public * _Nullable)ed25519PublicKeyForSeed:(IREd25519Private * _Nonnull)seed
                                                  error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (seed == nil || seed.length != (NSUInteger)crypto_sign_SEEDBYTES) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    uint8_t publicBytes[crypto_sign_PUBLICKEYBYTES];

    if (!IRPublicKeyFromSeed(seed.constBytes, publicBytes, error)) {
        IRZeroize(publicBytes, sizeof(publicBytes));
        return nil;
    }

    IREd25519Public *publicKey = [IREd25519Public fromBytes:publicBytes error:error];
    IRZeroize(publicBytes, sizeof(publicBytes));

    return publicKey;
}

- (IREd25519Signature * _Nullable)ed25519SignMessage:(NSData * _Nonnull)message
                                             withSeed:(IREd25519Private * _Nonnull)seed
                                                error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (message == nil || seed == nil || seed.length != (NSUInteger)crypto_sign_SEEDBYTES) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    uint8_t signatureBytes[crypto_sign_BYTES];

    if (!IRSignWithSeed(seed.constBytes, IRDataBytes(message),
                        (unsigned long long)message.length, signatureBytes, error)) {
        IRZeroize(signatureBytes, sizeof(signatureBytes));
        return nil;
    }

    IREd25519Signature *signature = [IREd25519Signature fromBytes:signatureBytes error:error];
    IRZeroize(signatureBytes, sizeof(signatureBytes));

    return signature;
}

- (BOOL)ed25519VerifySignature:(IREd25519Signature * _Nonnull)signature
                     ofMessage:(NSData * _Nonnull)message
                     publicKey:(IREd25519Public * _Nonnull)publicKey {
    /* Every failure is NO, including an uninitialized library. There is no error out-parameter to
       vary, and fail-closed is the only safe reading of "the signature did not verify". */
    if (![IRSodium isInitialized]) {
        return NO;
    }

    if (signature == nil || signature.length != (NSUInteger)crypto_sign_BYTES ||
        message == nil ||
        publicKey == nil || publicKey.length != (NSUInteger)crypto_sign_PUBLICKEYBYTES) {
        return NO;
    }

    /* PURE Ed25519 (§3.4). crypto_sign_verify_detached carries warn_unused_result and this file
       promotes -Werror=unused-result, so the result cannot be discarded — §13.2 names a dropped
       Bool here "the exact Swift analogue of v3's __unused int", i.e. a silent verification
       bypass on the one path that decides whether a peer is who it claims to be. */
    return (crypto_sign_verify_detached(signature.constBytes,
                                        IRDataBytes(message),
                                        (unsigned long long)message.length,
                                        publicKey.constBytes) == 0);
}

#pragma mark - AEAD (§8.2)

- (NSData * _Nullable)aeadSealPlaintext:(NSData * _Nonnull)plaintext
                                     key:(IRMessageEncKey * _Nonnull)key
                                   nonce:(IRNonce * _Nonnull)nonce
                          associatedData:(NSData * _Nonnull)associatedData
                                   error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (plaintext == nil || associatedData == nil ||
        key == nil || key.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        nonce == nil || nonce.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §10.4 — bounds are checked BEFORE any allocation sized from input. The §10 gates remain the
       authority for what a parse returns; this is the same bound applied one layer lower, where the
       allocation actually happens. */
    if (plaintext.length > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    const NSUInteger sealedLength = plaintext.length + (NSUInteger)kIRLenAEADTag;

    NSMutableData *sealed = [NSMutableData dataWithLength:sealedLength];
    if (sealed == nil) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    unsigned long long producedLength = 0;

    /* The _ietf_ variant, and only it. The non-IETF spelling takes an 8-byte nonce and is a silent
       incompatibility with every other port (§3.3); the widths are pinned by _Static_assert above.
       The 16-byte Poly1305 tag is APPENDED by libsodium, the JDK and BouncyCastle alike (§8.2). */
    const int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        [sealed mutableBytes], &producedLength,
        IRDataBytes(plaintext), (unsigned long long)plaintext.length,
        IRDataBytes(associatedData), (unsigned long long)associatedData.length,
        NULL,
        nonce.constBytes,
        key.constBytes);

    if (result != 0 || producedLength != (unsigned long long)sealedLength) {
        IRZeroize([sealed mutableBytes], sealed.length);
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    return [sealed copy];
}

- (NSData * _Nullable)aeadOpenCiphertextAndTag:(NSData * _Nonnull)ciphertextAndTag
                                            key:(IRMessageEncKey * _Nonnull)key
                                          nonce:(IRNonce * _Nonnull)nonce
                                 associatedData:(NSData * _Nonnull)associatedData
                                          error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (ciphertextAndTag == nil || associatedData == nil ||
        key == nil || key.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        nonce == nil || nonce.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* Shorter than the tag cannot authenticate, so the honest answer is the same one a forged tag
       gets. Unreachable through the §10 gates — check 1 of each already guarantees at least
       HDR_LEN + 16 bytes — but this method is also the §12.3 at-rest primitive, which no gate
       covers. */
    if (ciphertextAndTag.length < (NSUInteger)kIRLenAEADTag) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    const NSUInteger plaintextLength = ciphertextAndTag.length - (NSUInteger)kIRLenAEADTag;

    /* §10.4 again: bound BEFORE the allocation that is sized from attacker-adjacent input. */
    if (plaintextLength > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    NSMutableData *plaintext = [NSMutableData dataWithLength:plaintextLength];
    if (plaintext == nil) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    unsigned long long producedLength = 0;

    /* An empty plaintext is LEGAL (§10.4: the type 0x01 minimum is 56 + 0 + 16), and
       -[NSMutableData mutableBytes] is not documented to be non-NULL at length 0. libsodium
       declares this entry point nonnull(4, 8, 9) — c, npub, k — so a NULL m is permitted. */
    uint8_t *plaintextBytes = (plaintextLength > 0) ? (uint8_t *)[plaintext mutableBytes] : NULL;

    const int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintextBytes, &producedLength,
        NULL,
        IRDataBytes(ciphertextAndTag), (unsigned long long)ciphertextAndTag.length,
        IRDataBytes(associatedData), (unsigned long long)associatedData.length,
        nonce.constBytes,
        key.constBytes);

    if (result != 0 || producedLength != (unsigned long long)plaintextLength) {
        /* libsodium already wipes the output buffer on a tag mismatch. Doing it again is the
           difference between relying on that and guaranteeing it — there is no second AEAD step,
           no comparison function and no padding, so this is the entire failure path (§8.2). */
        if (plaintextBytes != NULL) {
            IRZeroize(plaintextBytes, plaintextLength);
        }
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    return [plaintext copy];
}

#pragma mark - AEAD over SECRET plaintext (§12.3, §13.3)

- (NSData * _Nullable)aeadSealSecret:(IRSecretBytes * _Nonnull)plaintext
                                 key:(IRMessageEncKey * _Nonnull)key
                               nonce:(IRNonce * _Nonnull)nonce
                      associatedData:(NSData * _Nonnull)associatedData
                               error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (plaintext == nil || associatedData == nil ||
        key == nil || key.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        nonce == nil || nonce.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    if (plaintext.length > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    const NSUInteger sealedLength = plaintext.length + (NSUInteger)kIRLenAEADTag;

    NSMutableData *sealed = [NSMutableData dataWithLength:sealedLength];
    if (sealed == nil) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    unsigned long long producedLength = 0;

    /* The plaintext is read straight out of the secret's own buffer — no NSData in between, which
       is the whole reason this entry point exists (§13.3). The output is ciphertext and is not
       secret. */
    const int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        [sealed mutableBytes], &producedLength,
        (plaintext.length > 0) ? plaintext.constBytes : NULL,
        (unsigned long long)plaintext.length,
        IRDataBytes(associatedData), (unsigned long long)associatedData.length,
        NULL,
        nonce.constBytes,
        key.constBytes);

    if (result != 0 || producedLength != (unsigned long long)sealedLength) {
        IRZeroize([sealed mutableBytes], sealed.length);
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    return [sealed copy];
}

- (IRSecretBytes * _Nullable)aeadOpenCiphertextAndTagToSecret:(NSData * _Nonnull)ciphertextAndTag
                                                           key:(IRMessageEncKey * _Nonnull)key
                                                         nonce:(IRNonce * _Nonnull)nonce
                                                associatedData:(NSData * _Nonnull)associatedData
                                                       guarded:(BOOL)guarded
                                                         error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (ciphertextAndTag == nil || associatedData == nil ||
        key == nil || key.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        nonce == nil || nonce.length != (NSUInteger)crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    if (ciphertextAndTag.length < (NSUInteger)kIRLenAEADTag) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    const NSUInteger plaintextLength = ciphertextAndTag.length - (NSUInteger)kIRLenAEADTag;

    if (plaintextLength > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    /* The destination is allocated wipeable BEFORE the AEAD runs, so the plaintext never exists
       anywhere else. An IRSecretBytes of length 0 is not constructible, and a zero-length sealed
       payload is meaningless at rest, so it is refused rather than special-cased. */
    if (plaintextLength == 0) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    IRSecretBytes *plaintext = guarded
        ? [[IRSecretBytes alloc] initGuardedWithLength:plaintextLength]
        : [[IRSecretBytes alloc] initWithLength:plaintextLength];
    if (plaintext == nil) {
        IRSetError(error, IRErrorPlaintextTooLarge);
        return nil;
    }

    unsigned long long producedLength = 0;

    const int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        [plaintext mutableBytes], &producedLength,
        NULL,
        IRDataBytes(ciphertextAndTag), (unsigned long long)ciphertextAndTag.length,
        IRDataBytes(associatedData), (unsigned long long)associatedData.length,
        nonce.constBytes,
        key.constBytes);

    if (result != 0 || producedLength != (unsigned long long)plaintextLength) {
        /* libsodium already wipes on a tag mismatch; -zeroizeNow makes it a guarantee rather than
           a reliance, and -dealloc would do it again in any case. */
        [plaintext zeroizeNow];
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    return plaintext;
}

#pragma mark - Randomness (§13.1)

- (IRNonce * _Nullable)randomNonceWithError:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    uint8_t nonceBytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

    /* §8.3 — fresh from the CSPRNG for EVERY seal. Never a counter, never derived from the message
       key, never reused. A derived nonce would make (key, nonce) reuse the consequence of a state
       rollback, which discloses the keystream XOR and leaks the Poly1305 one-time key, permitting
       forgery. With a random nonce the same rollback is only a plaintext repetition. */
    if (![self.environment.randomSource fillBytes:nonceBytes length:sizeof(nonceBytes) error:error]) {
        IRZeroize(nonceBytes, sizeof(nonceBytes));
        return nil;
    }

    IRNonce *nonce = [IRNonce fromBytes:nonceBytes error:error];
    IRZeroize(nonceBytes, sizeof(nonceBytes));

    return nonce;
}

- (NSData * _Nullable)randomBytesOfLength:(NSUInteger)length
                                     error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return nil;
    }

    if (length == 0 || length > (NSUInteger)kIRMaxPlaintext) {
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    NSMutableData *buffer = [NSMutableData dataWithLength:length];
    if (buffer == nil) {
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    /* §13.1's headline rule is that a zero-filling allocation MUST NOT be handed to a possibly
       failing fill without checking. -dataWithLength: zero-fills; the check is right here, and the
       buffer is wiped and dropped rather than returned on failure. v3 discarded this status at
       IREncryptionService.m:478 and returned the all-zero buffer as a key. */
    if (![self.environment.randomSource fillBytes:[buffer mutableBytes] length:length error:error]) {
        IRZeroize([buffer mutableBytes], buffer.length);
        return nil;
    }

    return [buffer copy];
}

- (BOOL)fillSecretBytes:(IRSecretBytes * _Nonnull)secret
                   error:(NSError * _Nullable * _Nullable)error {
    if (![self ensureUsable:error]) {
        return NO;
    }

    if (secret == nil || secret.length == 0) {
        IRSetError(error, IRErrorRNGFailure);
        return NO;
    }

    if (![self.environment.randomSource fillBytes:[secret mutableBytes]
                                           length:secret.length
                                            error:error]) {
        [secret zeroizeNow];
        return NO;
    }

    return YES;
}

@end
