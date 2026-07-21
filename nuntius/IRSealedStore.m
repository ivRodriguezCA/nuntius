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

#import "IRSealedStore.h"

#import "IRByteReader.h"
#import "IRByteWriter.h"

#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRSodium.h>

#import <Security/Security.h>

NSString * _Nonnull const IRSealedStoreLabelSession = @"nuntius.session";
NSString * _Nonnull const IRSealedStoreLabelPreKeys = @"nuntius.prekeys";

/* NON-NORMATIVE container constants. §12.3 places the at-rest container outside the byte-compatible
   surface — "only the plaintext layout is normative" — so these deliberately do NOT live in
   IRProtocolConstants beside the §18 table, where their presence would imply a port must reproduce
   them. Nothing here is observed by a peer. */
static const uint8_t kIRSealMagic[4] = {0x4E, 0x54, 0x53, 0x4C};   // "NTSL"
static const uint8_t kIRSealContainerFormat = 0x01;

static const NSUInteger kIRSealOffMagic = 0;
static const NSUInteger kIRSealOffFormat = 4;
static const NSUInteger kIRSealOffNonce = 5;
static const NSUInteger kIRSealOffCiphertext = 17;

/// The width the at-rest key must have. Equals the AEAD key width; a distinct name so that reading
/// this file does not suggest the seal key is a message key.
static const NSUInteger kIRSealKeyLength = 32;

#pragma mark - IRSealedStore

@interface IRSealedStore ()

- (instancetype _Nonnull)initWithKeyProvider:(id<IRSealKeyProvider> _Nonnull)keyProvider
                              cryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider;

- (IRMessageEncKey * _Nullable)aeadKeyForLabel:(NSString * _Nonnull)label
                                         error:(NSError * _Nullable * _Nullable)error;

- (NSData * _Nullable)associatedDataForLabel:(NSString * _Nonnull)label;

@end

@implementation IRSealedStore {
    id<IRSealKeyProvider> _keyProvider;
    id<IRCryptoProvider> _cryptoProvider;
}

+ (NSUInteger)containerOverhead {
    return kIRSealOffCiphertext + (NSUInteger)kIRLenAEADTag;
}

+ (instancetype _Nullable)storeWithKeyProvider:(id<IRSealKeyProvider> _Nonnull)keyProvider
                                cryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider
                                         error:(NSError * _Nullable * _Nullable)error {
    if (keyProvider == nil || cryptoProvider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[IRSealedStore alloc] initWithKeyProvider:keyProvider cryptoProvider:cryptoProvider];
}

- (instancetype _Nonnull)initWithKeyProvider:(id<IRSealKeyProvider> _Nonnull)keyProvider
                              cryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _keyProvider = keyProvider;
    _cryptoProvider = cryptoProvider;

    return self;
}

- (id<IRSealKeyProvider> _Nonnull)keyProvider {
    return _keyProvider;
}

- (id<IRCryptoProvider> _Nonnull)cryptoProvider {
    return _cryptoProvider;
}

#pragma mark - Key and AD

/**
 The device-bound key, retyped for the AEAD entry point.

 IRMessageEncKey is the type -aeadSealSecret: accepts and it is not otherwise meaningful here — the
 at-rest key is not a message key and is not derived from anything in the protocol. §12.3's "the
 at-rest key MUST NOT be derived from the state itself" is satisfied by construction: this method
 has no access to the state, only to the label.
 */
- (IRMessageEncKey * _Nullable)aeadKeyForLabel:(NSString * _Nonnull)label
                                         error:(NSError * _Nullable * _Nullable)error {
    NSError *providerError = nil;
    IRSecretBytes *keyBytes = [_keyProvider sealKeyForLabel:label error:&providerError];
    if (keyBytes == nil) {
        IRSetErrorWithUnderlying(error, IRErrorStateCorrupt, providerError);
        return nil;
    }

    if (keyBytes.length != kIRSealKeyLength) {
        [keyBytes zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* An all-zero key means an RNG that failed silently and a buffer that was zero-filled — v3's
       exact failure (§13.1), and the one tripwire cheap enough to run on every seal. */
    if ([keyBytes isAllZero]) {
        [keyBytes zeroizeNow];
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    IRMessageEncKey *aeadKey = [IRMessageEncKey fromBytes:keyBytes.constBytes
                                                  guarded:NO
                                                    error:error];
    /* The provider handed us a copy; wiping it here means only the retyped key survives, and its
        lifetime ends with this call. */
    [keyBytes zeroizeNow];

    return aeadKey;
}

- (NSData * _Nullable)associatedDataForLabel:(NSString * _Nonnull)label {
    NSData *labelBytes = [label dataUsingEncoding:NSUTF8StringEncoding];
    if (labelBytes == nil) {
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:
                            ((NSUInteger)sizeof(kIRSealMagic) + 1 + labelBytes.length)];
    [writer appendBytes:kIRSealMagic length:(NSUInteger)sizeof(kIRSealMagic)];
    [writer appendUInt8:kIRSealContainerFormat];
    [writer appendData:labelBytes];

    return [writer finishExpectingLength:((NSUInteger)sizeof(kIRSealMagic) + 1 + labelBytes.length)
                                   error:NULL];
}

#pragma mark - Seal and open

- (NSData * _Nullable)sealSecret:(IRSecretBytes * _Nonnull)plaintext
                           label:(NSString * _Nonnull)label
                           error:(NSError * _Nullable * _Nullable)error {
    if (plaintext == nil || plaintext.length == 0 || label.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSData *associatedData = [self associatedDataForLabel:label];
    if (associatedData == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRMessageEncKey *aeadKey = [self aeadKeyForLabel:label error:error];
    if (aeadKey == nil) {
        return nil;
    }

    /* Fresh for every seal, from the same CSPRNG §8.3 mandates on the message path. Never a
       counter and never derived: a session blob is rewritten after every message, so one key seals
       many containers and nonce reuse would be reachable rather than theoretical. */
    IRNonce *nonce = [_cryptoProvider randomNonceWithError:error];
    if (nonce == nil) {
        [aeadKey zeroizeNow];
        return nil;
    }

    NSData *ciphertextAndTag = [_cryptoProvider aeadSealSecret:plaintext
                                                            key:aeadKey
                                                          nonce:nonce
                                                 associatedData:associatedData
                                                          error:error];
    /* §13.3 — "immediately after the AEAD call returns, success AND failure paths". */
    [aeadKey zeroizeNow];

    if (ciphertextAndTag == nil) {
        return nil;
    }

    const NSUInteger total = kIRSealOffCiphertext + ciphertextAndTag.length;

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:total];
    [writer appendBytes:kIRSealMagic length:(NSUInteger)sizeof(kIRSealMagic)];
    [writer appendUInt8:kIRSealContainerFormat];
    [writer appendData:nonce.data];
    [writer appendData:ciphertextAndTag];

    return [writer finishExpectingLength:total error:error];
}

- (IRSecretBytes * _Nullable)openSealed:(NSData * _Nonnull)sealed
                                  label:(NSString * _Nonnull)label
                                guarded:(BOOL)guarded
                                  error:(NSError * _Nullable * _Nullable)error {
    if (sealed == nil || label.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* Structure first, and every field read is bounds-checked. This decoder is not one of §12.4's
       four — it sits below them — but it takes bytes off disk, which a local adversary may have
       rewritten, so it is written to the same standard: nothing here can trap or read out of
       bounds, and a truncated container is a specified error rather than a crash. */
    if (sealed.length < [IRSealedStore containerOverhead]) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:sealed];

    if (![reader matchLiteral:kIRSealMagic
                       length:(NSUInteger)sizeof(kIRSealMagic)
                     atOffset:kIRSealOffMagic]) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    uint8_t formatByte = 0;
    if (![reader readUInt8:&formatByte atOffset:kIRSealOffFormat] ||
        formatByte != kIRSealContainerFormat) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    NSData *nonceBytes = [reader dataAtOffset:kIRSealOffNonce length:(NSUInteger)kIRLenNonce];
    if (nonceBytes == nil) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }
    IRNonce *nonce = [IRNonce fromData:nonceBytes error:NULL];
    if (nonce == nil) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    NSData *ciphertextAndTag = [reader dataAtOffset:kIRSealOffCiphertext
                                             length:(sealed.length - kIRSealOffCiphertext)];
    if (ciphertextAndTag == nil) {
        IRSetError(error, IRErrorAEADAuthFailed);
        return nil;
    }

    NSData *associatedData = [self associatedDataForLabel:label];
    if (associatedData == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRMessageEncKey *aeadKey = [self aeadKeyForLabel:label error:error];
    if (aeadKey == nil) {
        return nil;
    }

    IRSecretBytes *plaintext = [_cryptoProvider aeadOpenCiphertextAndTagToSecret:ciphertextAndTag
                                                                             key:aeadKey
                                                                           nonce:nonce
                                                                  associatedData:associatedData
                                                                         guarded:guarded
                                                                           error:error];
    [aeadKey zeroizeNow];

    return plaintext;
}

@end

#pragma mark - IRInMemorySealKeyProvider

@interface IRInMemorySealKeyProvider ()

- (instancetype _Nonnull)initWithCryptoProvider:(id<IRCryptoProvider> _Nullable)cryptoProvider
                                       fixedKey:(IRSecretBytes * _Nullable)fixedKey;

@end

@implementation IRInMemorySealKeyProvider {
    id<IRCryptoProvider> _cryptoProvider;
    IRSecretBytes *_fixedKey;
    NSMutableDictionary<NSString *, IRSecretBytes *> *_keysByLabel;
}

+ (instancetype _Nullable)providerWithCryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider
                                               error:(NSError * _Nullable * _Nullable)error {
    if (cryptoProvider == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[IRInMemorySealKeyProvider alloc] initWithCryptoProvider:cryptoProvider fixedKey:nil];
}

+ (instancetype _Nullable)providerWithFixedKey:(IRSecretBytes * _Nonnull)key
                                         error:(NSError * _Nullable * _Nullable)error {
    if (key == nil || key.length != kIRSealKeyLength) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return [[IRInMemorySealKeyProvider alloc] initWithCryptoProvider:nil fixedKey:key];
}

- (instancetype _Nonnull)initWithCryptoProvider:(id<IRCryptoProvider> _Nullable)cryptoProvider
                                       fixedKey:(IRSecretBytes * _Nullable)fixedKey {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _cryptoProvider = cryptoProvider;
    _fixedKey = fixedKey;
    _keysByLabel = [NSMutableDictionary dictionary];

    return self;
}

- (IRSecretBytes * _Nullable)sealKeyForLabel:(NSString * _Nonnull)label
                                       error:(NSError * _Nullable * _Nullable)error {
    if (label.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    if (_fixedKey != nil) {
        IRSecretBytes *copy = [[IRSecretBytes alloc] initWithBytes:_fixedKey.constBytes
                                                             length:_fixedKey.length];
        if (copy == nil) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }
        return copy;
    }

    IRSecretBytes *stored = _keysByLabel[label];
    if (stored == nil) {
        stored = [[IRSecretBytes alloc] initWithLength:kIRSealKeyLength];
        if (stored == nil) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }

        /* -fillSecretBytes: propagates an RNG failure rather than leaving the zero-filled
           allocation in place. That distinction is v3's defect 4: NSMutableData dataWithLength:
           zero-fills, so a discarded RNG return produced an all-zero key. */
        if (![_cryptoProvider fillSecretBytes:stored error:error]) {
            [stored zeroizeNow];
            return nil;
        }

        _keysByLabel[label] = stored;
    }

    IRSecretBytes *copy = [[IRSecretBytes alloc] initWithBytes:stored.constBytes
                                                         length:stored.length];
    if (copy == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return copy;
}

- (void)zeroizeAll {
    for (IRSecretBytes *key in _keysByLabel.allValues) {
        [key zeroizeNow];
    }
    [_keysByLabel removeAllObjects];

    [_fixedKey zeroizeNow];
}

@end

#pragma mark - IRKeychainSealKeyProvider

@interface IRKeychainSealKeyProvider ()

- (instancetype _Nonnull)initWithService:(NSString * _Nonnull)service;

- (NSMutableDictionary * _Nonnull)baseQueryForLabel:(NSString * _Nonnull)label;

@end

@implementation IRKeychainSealKeyProvider {
    NSString *_service;
}

+ (instancetype _Nonnull)providerWithService:(NSString * _Nonnull)service {
    return [[IRKeychainSealKeyProvider alloc] initWithService:service];
}

- (instancetype _Nonnull)initWithService:(NSString * _Nonnull)service {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _service = [service copy];

    return self;
}

- (NSString * _Nonnull)service {
    return _service;
}

- (NSMutableDictionary * _Nonnull)baseQueryForLabel:(NSString * _Nonnull)label {
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: _service,
        (__bridge id)kSecAttrAccount: label,
        /* NO iCloud Keychain. Together with ThisDeviceOnly below this is what §5.6 means by
           "excluded from application backups": the item does not leave the device, and a restored
           backup image does not carry it. */
        (__bridge id)kSecAttrSynchronizable: (__bridge id)kCFBooleanFalse,
    } mutableCopy];
}

- (IRSecretBytes * _Nullable)sealKeyForLabel:(NSString * _Nonnull)label
                                       error:(NSError * _Nullable * _Nullable)error {
    if (label.length == 0 || _service.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSMutableDictionary *query = [self baseQueryForLabel:label];
    query[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef found = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &found);

    if (status == errSecSuccess) {
        NSData *keyData = (__bridge_transfer NSData *)found;
        if (keyData.length != kIRSealKeyLength) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }

        /* The residue documented in the header: this NSData cannot be wiped, and §13.3 forbids
           scrubbing its backing store through a const pointer. The copy below is what everything
           downstream uses, and its lifetime IS controlled. */
        IRSecretBytes *key = [[IRSecretBytes alloc] initWithData:keyData guarded:YES];
        if (key == nil) {
            IRSetError(error, IRErrorStateCorrupt);
            return nil;
        }

        return key;
    }

    if (status != errSecItemNotFound) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    // First use for this label — generate and store.
    IRSecretBytes *fresh = [[IRSecretBytes alloc] initGuardedWithLength:kIRSealKeyLength];
    if (fresh == nil) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    /* §13.1 — randombytes_buf, which cannot fail: it aborts the process on entropy failure, so
       there is no return value to forget. This is why §13.1 prefers it to SecRandomCopyBytes. */
    IRRandomBytes([fresh mutableBytes], (size_t)kIRSealKeyLength);

    if ([fresh isAllZero]) {
        [fresh zeroizeNow];
        IRSetError(error, IRErrorRNGFailure);
        return nil;
    }

    NSMutableDictionary *insert = [self baseQueryForLabel:label];
    insert[(__bridge id)kSecAttrAccessible] =
        (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    insert[(__bridge id)kSecValueData] = [NSData dataWithBytes:fresh.constBytes
                                                        length:kIRSealKeyLength];

    status = SecItemAdd((__bridge CFDictionaryRef)insert, NULL);
    if (status != errSecSuccess) {
        [fresh zeroizeNow];
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return fresh;
}

- (BOOL)deleteKeyForLabel:(NSString * _Nonnull)label
                    error:(NSError * _Nullable * _Nullable)error {
    if (label.length == 0) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)[self baseQueryForLabel:label]);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    return YES;
}

@end

#pragma mark - IRKeychainRollbackTripwire

@interface IRKeychainRollbackTripwire ()

- (instancetype _Nonnull)initWithService:(NSString * _Nonnull)service;

- (NSMutableDictionary * _Nonnull)baseQueryForHandshakeId:(NSData * _Nonnull)handshakeId;

@end

@implementation IRKeychainRollbackTripwire {
    NSString *_service;
}

+ (instancetype _Nonnull)tripwireWithService:(NSString * _Nonnull)service {
    return [[IRKeychainRollbackTripwire alloc] initWithService:service];
}

- (instancetype _Nonnull)initWithService:(NSString * _Nonnull)service {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _service = [service copy];

    return self;
}

- (NSString * _Nonnull)service {
    return _service;
}

- (NSMutableDictionary * _Nonnull)baseQueryForHandshakeId:(NSData * _Nonnull)handshakeId {
    NSMutableString *account = [NSMutableString stringWithCapacity:(handshakeId.length * 2)];
    const uint8_t *bytes = (const uint8_t *)handshakeId.bytes;
    for (NSUInteger i = 0; i < handshakeId.length; i++) {
        [account appendFormat:@"%02x", bytes[i]];
    }

    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: _service,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecAttrSynchronizable: (__bridge id)kCFBooleanFalse,
    } mutableCopy];
}

- (BOOL)lastObservedSendCounter:(uint64_t * _Nonnull)outSendCounter
                 forHandshakeId:(NSData * _Nonnull)handshakeId
                          error:(NSError * _Nullable * _Nullable)error {
    if (outSendCounter == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    *outSendCounter = 0;

    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    NSMutableDictionary *query = [self baseQueryForHandshakeId:handshakeId];
    query[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef found = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &found);

    /* THE ONLY status that means "no record". Everything else is a FAILED READ and must not be
       reported as 0 — see the protocol declaration. errSecInteractionNotAllowed (device rebooted,
       never unlocked) and errSecMissingEntitlement (keychain-group change) both land here, and
       both are states an attacker can induce or wait for. */
    if (status == errSecItemNotFound) {
        return YES;
    }

    if (status != errSecSuccess) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    NSData *stored = (__bridge_transfer NSData *)found;

    /* A record that is present but not 8 bytes is a CORRUPT record, not an absent one. Reporting
       it as 0 would disable the comparison for exactly the session whose tripwire someone has been
       editing. */
    if (stored.length != sizeof(uint64_t)) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* Explicit big-endian assembly, never a pointer cast onto an integer (§3.3, defect 6). */
    const uint8_t *raw = (const uint8_t *)stored.bytes;
    uint64_t value = 0;
    for (NSUInteger i = 0; i < sizeof(uint64_t); i++) {
        value = (value << 8) | (uint64_t)raw[i];
    }

    *outSendCounter = value;

    return YES;
}

- (BOOL)recordSendCounter:(uint64_t)sendCounter
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* MONOTONIC. A restored-then-advanced session would otherwise lower its own tripwire and
       disable the very check §12.5 asks for.

       A FAILED read fails the write, rather than falling through to a blind overwrite. Monotonicity
       cannot be established against a value that could not be read, and writing anyway is how a
       high-water mark gets LOWERED — the one outcome this check exists to prevent. */
    uint64_t recorded = 0;
    if (![self lastObservedSendCounter:&recorded forHandshakeId:handshakeId error:error]) {
        return NO;
    }

    if (sendCounter <= recorded) {
        return YES;
    }

    uint8_t encoded[sizeof(uint64_t)];
    for (NSUInteger i = 0; i < sizeof(uint64_t); i++) {
        encoded[i] = (uint8_t)((sendCounter >> (8 * (sizeof(uint64_t) - 1 - i))) & 0xFF);
    }
    NSData *value = [NSData dataWithBytes:encoded length:sizeof(encoded)];

    NSMutableDictionary *query = [self baseQueryForHandshakeId:handshakeId];
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                    (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData: value});

    if (status == errSecItemNotFound) {
        NSMutableDictionary *insert = [self baseQueryForHandshakeId:handshakeId];
        insert[(__bridge id)kSecAttrAccessible] =
            (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        insert[(__bridge id)kSecValueData] = value;
        status = SecItemAdd((__bridge CFDictionaryRef)insert, NULL);
    }

    if (status != errSecSuccess) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    return YES;
}

- (BOOL)forgetHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)
                                    [self baseQueryForHandshakeId:handshakeId]);
    if (status != errSecSuccess && status != errSecItemNotFound) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    return YES;
}

@end

#pragma mark - IRDisabledRollbackTripwire

@implementation IRDisabledRollbackTripwire

+ (instancetype _Nonnull)tripwire {
    return [[IRDisabledRollbackTripwire alloc] init];
}

- (BOOL)lastObservedSendCounter:(uint64_t * _Nonnull)outSendCounter
                 forHandshakeId:(NSData * _Nonnull)handshakeId
                          error:(NSError * _Nullable * _Nullable)error {
    (void)handshakeId;
    (void)error;

    if (outSendCounter == NULL) {
        return NO;
    }

    /* YES, not NO: declining the tripwire is a SUCCESSFUL read of "no record", not a failed one.
       0 is the "no record" value and no blob can carry a counter below it, so the §12.5 comparison
       can never fire. That is the point — see the header. Returning NO here would make an explicit
       §12.5 opt-out unload every session, since callers treat a failed read as rolled back. */
    *outSendCounter = 0;

    return YES;
}

- (BOOL)recordSendCounter:(uint64_t)sendCounter
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    (void)sendCounter;
    (void)handshakeId;
    (void)error;

    return YES;
}

- (BOOL)forgetHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    (void)handshakeId;
    (void)error;

    return YES;
}

@end

#pragma mark - IRInMemoryRollbackTripwire

@implementation IRInMemoryRollbackTripwire {
    NSMutableDictionary<NSData *, NSNumber *> *_countersByHandshakeId;
}

+ (instancetype _Nonnull)tripwire {
    return [[IRInMemoryRollbackTripwire alloc] init];
}

- (instancetype _Nonnull)init {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _countersByHandshakeId = [NSMutableDictionary dictionary];

    return self;
}

- (NSUInteger)recordCount {
    return _countersByHandshakeId.count;
}

- (BOOL)lastObservedSendCounter:(uint64_t * _Nonnull)outSendCounter
                 forHandshakeId:(NSData * _Nonnull)handshakeId
                          error:(NSError * _Nullable * _Nullable)error {
    if (outSendCounter == NULL) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    *outSendCounter = 0;

    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    /* A dictionary read cannot fail, so this implementation has no failed-read case at all: an
       absent key is genuinely "no record". That is exactly why it is unfit for §12.5 in production
       — see the header — and why the Keychain implementation is the one that has to get the
       distinction right. */
    *outSendCounter = _countersByHandshakeId[handshakeId].unsignedLongLongValue;

    return YES;
}

- (BOOL)recordSendCounter:(uint64_t)sendCounter
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    if (handshakeId.length != (NSUInteger)kIRLenHandshakeId) {
        IRSetError(error, IRErrorStateCorrupt);
        return NO;
    }

    uint64_t recorded = 0;
    if (![self lastObservedSendCounter:&recorded forHandshakeId:handshakeId error:error]) {
        return NO;
    }

    if (sendCounter > recorded) {
        _countersByHandshakeId[[handshakeId copy]] = @(sendCounter);
    }

    return YES;
}

- (BOOL)forgetHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error {
    (void)error;

    if (handshakeId.length == (NSUInteger)kIRLenHandshakeId) {
        [_countersByHandshakeId removeObjectForKey:handshakeId];
    }

    return YES;
}

@end
