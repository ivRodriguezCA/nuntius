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

#import "TripleDHService.h"
#import "EncryptionService.h"
#import "Curve25519KeyPair.h"
#import "Constants.h"

@interface TripleDHService ()

@property (nonatomic, strong) EncryptionService * _Nonnull encryptionService;

@property (nonatomic, strong) Curve25519KeyPair * _Nonnull identityKeyPair;
@property (nonatomic, strong) Curve25519KeyPair * _Nonnull signedPreKeyPair;
@property (nonatomic, strong) NSArray<Curve25519KeyPair *> * _Nonnull ephemeralKeyPairs;

@property (nonatomic, strong) Curve25519KeyPair * _Nullable currentEphemeralKeyPair;

@end

@implementation TripleDHService

#pragma mark - <NSObject>

- (instancetype)initWithIdentityKeyPair:(Curve25519KeyPair *)identityKeyPair
                       signedPreKeyPair:(Curve25519KeyPair *)signedPreKeyPair
                          ephemeralKeys:(NSArray<Curve25519KeyPair *> *)ephemeralKeys {
    if (self = [super init]) {
        _encryptionService = [EncryptionService new];

        _identityKeyPair = identityKeyPair;
        _signedPreKeyPair = signedPreKeyPair;
        _ephemeralKeyPairs = ephemeralKeys;
    }

    return self;
}

- (instancetype)initWithData:(NSDictionary<NSString *, NSObject *> *)data {
    if (self = [super init]) {
        _encryptionService = [EncryptionService new];

        NSDictionary *identityKeyData = (NSDictionary *)data[kDictionaryKeyTripleDHServiceIdentityKeyKey];
        _identityKeyPair = [Curve25519KeyPair keyPairWithSerializedData:identityKeyData];

        NSDictionary *signedPreKeyData = (NSDictionary *)data[kDictionaryKeyTripleDHServiceSignedPreKeyKey];
        _signedPreKeyPair = [Curve25519KeyPair keyPairWithSerializedData:signedPreKeyData];

        NSData *signature = [_encryptionService signData:_signedPreKeyPair.publicKey
                                             withKeyPair:_identityKeyPair];
        [_signedPreKeyPair addKeyPairSignature:signature];

        NSArray *keys = (NSArray *)data[kDictionaryKeyTripleDHServiceEphemeralKeysKey];
        NSMutableArray *eKeys = [NSMutableArray new];
        for (NSInteger i=0; i<keys.count; i++) {
            NSDictionary *keyData = keys[i];
            Curve25519KeyPair *keyPair = [Curve25519KeyPair keyPairWithSerializedData:keyData];
            if (keyPair == nil) continue;

            [eKeys addObject:keyPair];
        }
        _ephemeralKeyPairs = [eKeys copy];
    }

    return self;
}

#pragma mark - Public

- (NSData * _Nullable)sharedKeyFromReceiverIdentityKey:(Curve25519KeyPair * _Nonnull)rIdentityKey
                                  receiverSignedPreKey:(Curve25519KeyPair * _Nonnull)rSignedPreKey
                                  receiverEphemeralKey:(Curve25519KeyPair * _Nullable)rEphemeralKey {

    //TODO: Investigate `cryptographic domain separation`
    const char separation[32] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    __unused NSData *separationData = [NSData dataWithBytes:separation length:sizeof(separation)];

    self.currentEphemeralKeyPair = [self.encryptionService generateKeyPair];
    NSData *dh1 = [self.encryptionService receiverSharedKeyWithSenderPublicKey:rSignedPreKey.publicKey
                                                            andReceiverKeyPair:self.identityKeyPair];
    NSData *dh2 = [self.encryptionService receiverSharedKeyWithSenderPublicKey:rIdentityKey.publicKey
                                                            andReceiverKeyPair:self.currentEphemeralKeyPair];
    NSData *dh3 = [self.encryptionService receiverSharedKeyWithSenderPublicKey:rSignedPreKey.publicKey
                                                            andReceiverKeyPair:self.currentEphemeralKeyPair];
    NSData *dh4 = nil;
    if (rEphemeralKey != nil) {
        dh4 = [self.encryptionService receiverSharedKeyWithSenderPublicKey:rEphemeralKey.publicKey
                                                        andReceiverKeyPair:self.currentEphemeralKeyPair];
    }

    NSMutableData *kdfInput = [NSMutableData new];//[NSMutableData dataWithData:separationData];
    [kdfInput appendData:dh1];
    [kdfInput appendData:dh2];
    [kdfInput appendData:dh3];
    if (dh4 != nil) {
        [kdfInput appendData:dh4];
    }

    return [self.encryptionService sharedKeyKDFWithSecret:[kdfInput copy]
                                                  andSalt:0
                                             outputLength:32];
}

- (NSData * _Nullable)sharedKeyFromSenderIdentityKey:(Curve25519KeyPair * _Nonnull)sIdentityKey
                                  senderEphemeralKey:(Curve25519KeyPair * _Nonnull)sEphemeralKey
                              receiverEphemeralKeyID:(NSString * _Nullable)rEphemeralKeyID {

    //TODO: Investigate `cryptographic domain separation`
    const char separation[32] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    __unused NSData *separationData = [NSData dataWithBytes:separation length:sizeof(separation)];

    self.currentEphemeralKeyPair = sEphemeralKey;
    NSData *dh1 = [self.encryptionService senderSharedKeyWithRecieverPublicKey:sIdentityKey.publicKey
                                                              andSenderKeyPair:self.signedPreKeyPair];
    NSData *dh2 = [self.encryptionService senderSharedKeyWithRecieverPublicKey:sEphemeralKey.publicKey
                                                              andSenderKeyPair:self.identityKeyPair];
    NSData *dh3 = [self.encryptionService senderSharedKeyWithRecieverPublicKey:sEphemeralKey.publicKey
                                                              andSenderKeyPair:self.signedPreKeyPair];
    NSData *dh4 = nil;
    Curve25519KeyPair *receiverEphemeralKey = [self keyFromKeyID:rEphemeralKeyID];
    if (receiverEphemeralKey != nil) {
        dh4 = [self.encryptionService senderSharedKeyWithRecieverPublicKey:sEphemeralKey.publicKey
                                                          andSenderKeyPair:receiverEphemeralKey];
    }

    NSMutableData *kdfInput = [NSMutableData new];//[NSMutableData dataWithData:separationData];
    [kdfInput appendData:dh1];
    [kdfInput appendData:dh2];
    [kdfInput appendData:dh3];
    if (dh4 != nil) {
        [kdfInput appendData:dh4];
    }

    return [self.encryptionService sharedKeyKDFWithSecret:[kdfInput copy]
                                                  andSalt:0
                                             outputLength:32];

}

#pragma mark - Serialization

- (NSDictionary<NSString *, NSObject *> * _Nullable)serializedForTransport {
    if (self.identityKeyPair == nil || self.signedPreKeyPair == nil || self.ephemeralKeyPairs == nil) {
        return nil;
    }

    NSMutableArray *serializedEphemeralKeys = [NSMutableArray arrayWithCapacity:self.ephemeralKeyPairs.count];
    for (Curve25519KeyPair *keyPair in self.ephemeralKeyPairs) {
        NSDictionary *serialized = [keyPair serializedForTransport];
        if (serialized != nil) {
            [serializedEphemeralKeys addObject:serialized];
        }
    }

    if (self.currentEphemeralKeyPair == nil) {
        return @{kDictionaryKeyTripleDHServiceIdentityKeyKey:[self.identityKeyPair serializedForTransport],
                 kDictionaryKeyTripleDHServiceSignedPreKeyKey:[self.signedPreKeyPair serializedForTransport],
                 kDictionaryKeyTripleDHServiceEphemeralKeysKey:[serializedEphemeralKeys copy]};
    }

    return @{kDictionaryKeyTripleDHServiceIdentityKeyKey:[self.identityKeyPair serializedForTransport],
             kDictionaryKeyTripleDHServiceSignedPreKeyKey:[self.signedPreKeyPair serializedForTransport],
             kDictionaryKeyTripleDHServiceEphemeralKeysKey:[serializedEphemeralKeys copy],
             kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey:[self.currentEphemeralKeyPair serializedForTransport]};
}

- (NSDictionary<NSString *, NSObject *> * _Nullable)serialized {
    if (self.identityKeyPair == nil || self.signedPreKeyPair == nil || self.ephemeralKeyPairs == nil) {
        return nil;
    }

    NSMutableArray *serializedEphemeralKeys = [NSMutableArray arrayWithCapacity:self.ephemeralKeyPairs.count];
    for (Curve25519KeyPair *keyPair in self.ephemeralKeyPairs) {
        NSDictionary *serialized = [keyPair serialized];
        if (serialized != nil) {
            [serializedEphemeralKeys addObject:serialized];
        }
    }

    if (self.currentEphemeralKeyPair == nil) {
        return @{kDictionaryKeyTripleDHServiceIdentityKeyKey:[self.identityKeyPair serialized],
                 kDictionaryKeyTripleDHServiceSignedPreKeyKey:[self.signedPreKeyPair serialized],
                 kDictionaryKeyTripleDHServiceEphemeralKeysKey:[serializedEphemeralKeys copy]};
    }

    return @{kDictionaryKeyTripleDHServiceIdentityKeyKey:[self.identityKeyPair serialized],
             kDictionaryKeyTripleDHServiceSignedPreKeyKey:[self.signedPreKeyPair serialized],
             kDictionaryKeyTripleDHServiceEphemeralKeysKey:[serializedEphemeralKeys copy],
             kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey:[self.currentEphemeralKeyPair serialized]};
}

- (NSData * _Nullable)jsonSerializedForTransport {
    NSDictionary<NSString *, NSObject *> *serialized = [self serializedForTransport];
    if (serialized == nil) {
        return  nil;
    }

    return [NSJSONSerialization dataWithJSONObject:serialized options:NSJSONWritingPrettyPrinted error:nil];
}

- (NSData * _Nullable)jsonSerialized {
    NSDictionary<NSString *, NSObject *> *serialized = [self serialized];
    if (serialized == nil) {
        return  nil;
    }

    return [NSJSONSerialization dataWithJSONObject:serialized options:NSJSONWritingPrettyPrinted error:nil];
}

#pragma mark - Private

- (Curve25519KeyPair * _Nullable)keyFromKeyID:(NSString * _Nullable)keyID {
    if (keyID == nil || keyID.length == 0) {
        return nil;
    }

    for (Curve25519KeyPair *key in self.ephemeralKeyPairs) {
        if ([key.keyID isEqualToString:keyID]) {
            return key;
        }
    }

    return nil;
}

//TODO: Add Encoding/Decoding
/*
 def decodeLittleEndian(b, bits):
 return sum([b[i] << 8*i for i in range((bits+7)/8)])

 def decodeUCoordinate(u, bits):
 u_list = [ord(b) for b in u]
 # Ignore any unused bits.
 if bits % 8:
 u_list[-1] &= (1<<(bits%8))-1
 return decodeLittleEndian(u_list, bits)

 def encodeUCoordinate(u, bits):
 u = u % p
 return ''.join([chr((u >> 8*i) & 0xff)
 for i in range((bits+7)/8)])
 */

- (NSData * _Nullable)encodeUCoordinate:(NSData * _Nonnull)uCoordinate andBits:(NSUInteger)bits {
    return nil;
}

@end
