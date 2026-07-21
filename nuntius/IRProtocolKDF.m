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

#import "IRProtocolKDF.h"

#import "IRProtocolConstants.h"
#import "IRTranscript.h"

#pragma mark - Shared helpers

/// §3.2 / §6.3 / §8.1 — the 32-zero-byte default HKDF salt, materialized explicitly so the code
/// reads exactly as the specification writes it. §3.2 records that a nil salt produces an IDENTICAL
/// PRK and that this is NOT a divergence point; `HKDF-SALT-EQUIV` (§15.3) is the vector that says so.
static IRSecretBytes * _Nullable IRZeroSalt(NSError * _Nullable * _Nullable error) {
    IRSecretBytes *salt = [[IRSecretBytes alloc] initWithBytes:kIRZ32 length:kIRLenZ32];
    if (salt == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    return salt;
}

#pragma mark - IRRootChainStep

@interface IRRootChainStep ()

- (instancetype _Nonnull)initWithRootKey:(IRRootKey * _Nonnull)rootKey
                                chainKey:(IRChainKey * _Nonnull)chainKey;

@end

@implementation IRRootChainStep

- (instancetype _Nonnull)initWithRootKey:(IRRootKey * _Nonnull)rootKey
                                chainKey:(IRChainKey * _Nonnull)chainKey {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _rootKey = rootKey;
    _chainKey = chainKey;

    return self;
}

- (void)zeroize {
    [_rootKey zeroizeNow];
    [_chainKey zeroizeNow];
}

@end

#pragma mark - IRChainStep

@interface IRChainStep ()

- (instancetype _Nonnull)initWithMessageKey:(IRMessageKey * _Nonnull)messageKey
                               nextChainKey:(IRChainKey * _Nonnull)nextChainKey;

@end

@implementation IRChainStep

- (instancetype _Nonnull)initWithMessageKey:(IRMessageKey * _Nonnull)messageKey
                               nextChainKey:(IRChainKey * _Nonnull)nextChainKey {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _messageKey = messageKey;
    _nextChainKey = nextChainKey;

    return self;
}

- (void)zeroize {
    [_messageKey zeroizeNow];
    [_nextChainKey zeroizeNow];
}

@end

#pragma mark - IRProtocolKDF

@implementation IRProtocolKDF

+ (IRRootChainStep * _Nullable)deriveRootStepWithRootKeyAsSalt:(IRRootKey * _Nonnull)rootKey
                                                      dhOutput:(IRSecretBytes * _Nonnull)dhOutput
                                                      provider:(id<IRCryptoProvider> _Nonnull)provider
                                                         error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §7.2: the previous root key is MANDATORY. There is no code path that calls KDF_RK without
       it — which is the whole reason RK is the salt rather than part of the IKM. */
    if (rootKey == nil || rootKey.length != kIRLenRootKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (dhOutput == nil || dhOutput.length != kIRLenDHOutput) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSData *info = [NSData dataWithBytes:kIRLabelRK length:kIRLenLabelRK];

    /* THE ARGUMENT ORDER IS THE CONTRACT: salt = RK, ikm = DH_out. Reversed, this still produces a
       working ratchet that agrees with itself and with nothing else (§7.2, §16.1). */
    IRSecretBytes *okm = [provider hkdfWithSalt:rootKey
                                            ikm:dhOutput
                                           info:info
                                   outputLength:kIRLenKDFRKOutput
                                          error:error];
    if (okm == nil) {
        return nil;
    }

    if (okm.length != kIRLenKDFRKOutput) {
        [okm zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRRootKey *nextRootKey = [IRRootKey fromBytes:okm.constBytes guarded:NO error:error];
    if (nextRootKey == nil) {
        [okm zeroizeNow];
        return nil;
    }

    IRChainKey *chainKey = [IRChainKey fromBytes:(okm.constBytes + kIRLenRootKey)
                                         guarded:NO
                                           error:error];
    if (chainKey == nil) {
        [nextRootKey zeroizeNow];
        [okm zeroizeNow];
        return nil;
    }

    [okm zeroizeNow];

    return [[IRRootChainStep alloc] initWithRootKey:nextRootKey chainKey:chainKey];
}

+ (IRChainStep * _Nullable)deriveChainStepWithChainKey:(IRChainKey * _Nonnull)chainKey
                                              provider:(id<IRCryptoProvider> _Nonnull)provider
                                                 error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §7.3: "Implementations MUST assert len(CK) == 32 at the call site." */
    if (chainKey == nil || chainKey.length != kIRLenChainKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    const uint8_t messageKeyInput = (uint8_t)kIRKDFCKMessageKeyInput;
    const uint8_t chainKeyInput = (uint8_t)kIRKDFCKChainKeyInput;

    IRSecretBytes *messageKeyBytes =
        [provider hmacSHA256WithKey:chainKey
                            message:[NSData dataWithBytes:&messageKeyInput length:1]
                              error:error];
    if (messageKeyBytes == nil) {
        return nil;
    }

    IRSecretBytes *nextChainKeyBytes =
        [provider hmacSHA256WithKey:chainKey
                            message:[NSData dataWithBytes:&chainKeyInput length:1]
                              error:error];
    if (nextChainKeyBytes == nil) {
        [messageKeyBytes zeroizeNow];
        return nil;
    }

    if (messageKeyBytes.length != kIRLenMessageKey || nextChainKeyBytes.length != kIRLenChainKey) {
        [messageKeyBytes zeroizeNow];
        [nextChainKeyBytes zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRMessageKey *messageKey = [IRMessageKey fromBytes:messageKeyBytes.constBytes
                                               guarded:NO
                                                 error:error];
    IRChainKey *nextChainKey = nil;
    if (messageKey != nil) {
        nextChainKey = [IRChainKey fromBytes:nextChainKeyBytes.constBytes guarded:NO error:error];
    }

    [messageKeyBytes zeroizeNow];
    [nextChainKeyBytes zeroizeNow];

    if (messageKey == nil || nextChainKey == nil) {
        [messageKey zeroizeNow];
        [nextChainKey zeroizeNow];
        return nil;
    }

    /* `chainKey` is NOT zeroized here. See the header: SkipMessageKeys advances a §7.7 snapshot
       that is discarded on a tag failure, and wiping the input would take the live session's CKr
       with it — the desynchronisation DoS NEG-ATOMIC exists to catch. */
    return [[IRChainStep alloc] initWithMessageKey:messageKey nextChainKey:nextChainKey];
}

+ (IRMessageEncKey * _Nullable)expandMessageKey:(IRMessageKey * _Nonnull)messageKey
                                       provider:(id<IRCryptoProvider> _Nonnull)provider
                                          error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    if (messageKey == nil || messageKey.length != kIRLenMessageKey) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRSecretBytes *salt = IRZeroSalt(error);
    if (salt == nil) {
        return nil;
    }

    NSData *info = [NSData dataWithBytes:kIRLabelMK length:kIRLenLabelMK];

    IRSecretBytes *okm = [provider hkdfWithSalt:salt
                                            ikm:messageKey
                                           info:info
                                   outputLength:kIRLenKDFMKOutput
                                          error:error];
    [salt zeroizeNow];

    if (okm == nil) {
        return nil;
    }

    if (okm.length != kIRLenMessageEncKey) {
        [okm zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRMessageEncKey *encKey = [IRMessageEncKey fromBytes:okm.constBytes guarded:NO error:error];
    [okm zeroizeNow];

    /* `messageKey` is NOT zeroized here — NEG-SKIP-RETAIN requires a stored skipped key to survive
       a failed AEAD open, and this expansion runs before that AEAD. */
    return encKey;
}

+ (IRRootKey * _Nullable)deriveSharedKeyWithIKM:(IRSecretBytes * _Nonnull)ikm
                                 transcriptHash:(NSData * _Nonnull)transcriptHash
                                       provider:(id<IRCryptoProvider> _Nonnull)provider
                                          error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §6.3: "Both parties MUST assert len(IKM) ∈ {128, 160} ... That assertion alone would have
       caught defect 1 on the day it was introduced." DH4 is OMITTED, not zero-filled, when no
       one-time prekey is used; opk_flag inside TH removes the ambiguity that omission could
       otherwise create. */
    if (ikm == nil || (ikm.length != kIRLenIKMNoOPK && ikm.length != kIRLenIKMOPK)) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSData *info = [IRTranscript x3dhInfoWithTranscriptHash:transcriptHash error:error];
    if (info == nil) {
        return nil;
    }

    IRSecretBytes *salt = IRZeroSalt(error);
    if (salt == nil) {
        return nil;
    }

    IRSecretBytes *okm = [provider hkdfWithSalt:salt
                                            ikm:ikm
                                           info:info
                                   outputLength:kIRLenSK
                                          error:error];
    [salt zeroizeNow];

    if (okm == nil) {
        return nil;
    }

    /* §6.3's second assertion. */
    if (okm.length != kIRLenSK) {
        [okm zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRRootKey *sharedKey = [IRRootKey fromBytes:okm.constBytes guarded:NO error:error];
    [okm zeroizeNow];

    /* `ikm` is NOT zeroized here: §13.3 schedules it, EK_A's private half and DH1–DH4 together,
       "immediately after SK is derived", and IRX3DH — which owns all five — performs that wipe as
       one step so no subset can be forgotten. */
    return sharedKey;
}

@end
