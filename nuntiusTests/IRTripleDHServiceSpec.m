/*
 The MIT License (MIT)
 Copyright (c) 2017 Ivan Rodriguez. All rights reserved.

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

#import <XCTest/XCTest.h>
#import "IRTripleDHService.h"
#import "IRCurve25519KeyPair.h"
#import "IREncryptionService.h"
#import "IRConstants.h"

@interface IRTripleDHServiceSpec : XCTestCase

@property (nonatomic, strong) IRTripleDHService *alice;
@property (nonatomic, strong) IRTripleDHService *bob;
@property (nonatomic, strong) IRTripleDHService *eve;

@end

@implementation IRTripleDHServiceSpec

- (void)setUp {
    [super setUp];

    self.alice = [self generateX3DH];
    self.bob = [self generateX3DH];
    self.eve = [self generateX3DH];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testSerialization {
    NSDictionary *serialized = [self.alice serialized];

    NSDictionary *idKey = serialized[kDictionaryKeyTripleDHServiceIdentityKeyKey];
    XCTAssertNotNil(idKey);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *signedPreKey = serialized[kDictionaryKeyTripleDHServiceSignedPreKeyKey];
    XCTAssertNotNil(signedPreKey);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *currentEphemeralKey = serialized[kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey];
    XCTAssertNil(currentEphemeralKey);

    NSArray *ephemeralKeys = serialized[kDictionaryKeyTripleDHServiceEphemeralKeysKey];
    XCTAssertEqual(ephemeralKeys.count, 50);

    NSData *jsonSerialized = [self.alice jsonSerialized];
    XCTAssertNotNil(jsonSerialized);
}

- (void)testTransportSerialization {
    NSDictionary *serialized = [self.alice serializedForTransport];

    NSDictionary *idKey = serialized[kDictionaryKeyTripleDHServiceIdentityKeyKey];
    XCTAssertNotNil(idKey);
    XCTAssertNil(idKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *signedPreKey = serialized[kDictionaryKeyTripleDHServiceSignedPreKeyKey];
    XCTAssertNotNil(signedPreKey);
    XCTAssertNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *currentEphemeralKey = serialized[kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey];
    XCTAssertNil(currentEphemeralKey);

    NSArray *ephemeralKeys = serialized[kDictionaryKeyTripleDHServiceEphemeralKeysKey];
    XCTAssertEqual(ephemeralKeys.count, 50);

    NSData *jsonSerialized = [self.alice jsonSerializedForTransport];
    XCTAssertNotNil(jsonSerialized);
}

- (void)testSharedKey {
    IRCurve25519KeyPair *bobEphemeralKey = self.bob.ephemeralKeyPairs.firstObject;
    NSData *sharedKeyAlice = [self.alice sharedKeyFromReceiverIdentityKey:self.bob.identityKeyPair
                                                     receiverSignedPreKey:self.bob.signedPreKeyPair
                                                     receiverEphemeralKey:bobEphemeralKey];

    NSData *sharedKeyBob = [self.bob sharedKeyFromSenderIdentityKey:self.alice.identityKeyPair
                                                 senderEphemeralKey:self.alice.currentEphemeralKeyPair
                                             receiverEphemeralKeyID:bobEphemeralKey.keyID];
    XCTAssertEqualObjects(sharedKeyAlice, sharedKeyBob);
    XCTAssertEqual(sharedKeyAlice.length,32);
    XCTAssertEqual(sharedKeyBob.length,32);
}

- (void)testSharedKeyWithoutBobEphemeralKey {
    NSData *sharedKeyAlice = [self.alice sharedKeyFromReceiverIdentityKey:self.bob.identityKeyPair
                                                     receiverSignedPreKey:self.bob.signedPreKeyPair
                                                     receiverEphemeralKey:nil];

    NSData *sharedKeyBob = [self.bob sharedKeyFromSenderIdentityKey:self.alice.identityKeyPair
                                                 senderEphemeralKey:self.alice.currentEphemeralKeyPair
                                             receiverEphemeralKeyID:nil];
    XCTAssertEqualObjects(sharedKeyAlice, sharedKeyBob);
    XCTAssertEqual(sharedKeyAlice.length,32);
    XCTAssertEqual(sharedKeyBob.length,32);
}


- (void)testInvalidSharedKey {
    IRCurve25519KeyPair *bobEphemeralKey = self.bob.ephemeralKeyPairs.firstObject;
    NSData *sharedKeyAlice = [self.alice sharedKeyFromReceiverIdentityKey:self.bob.identityKeyPair
                                                     receiverSignedPreKey:self.bob.signedPreKeyPair
                                                     receiverEphemeralKey:bobEphemeralKey];

    NSData *sharedKeyBob = [self.bob sharedKeyFromSenderIdentityKey:self.alice.identityKeyPair
                                                 senderEphemeralKey:self.alice.currentEphemeralKeyPair
                                             receiverEphemeralKeyID:bobEphemeralKey.keyID];

    XCTAssertEqualObjects(sharedKeyAlice, sharedKeyBob);
    XCTAssertEqual(sharedKeyAlice.length,32);
    XCTAssertEqual(sharedKeyBob.length,32);

    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *eveIdentityKeyPair = [eS generateKeyPair];
    IRCurve25519KeyPair *eveSignedPreKeyPair = [eS generateKeyPair];
    [eveSignedPreKeyPair addKeyPairSignature:[eS signData:eveSignedPreKeyPair.publicKey withKeyPair:eveIdentityKeyPair]];
    IRCurve25519KeyPair *eveEphemeralKeyPair = [eS generateKeyPair];
    NSData *sharedKeyEve = [self.eve sharedKeyFromReceiverIdentityKey:eveIdentityKeyPair
                                                 receiverSignedPreKey:eveSignedPreKeyPair
                                                 receiverEphemeralKey:eveEphemeralKeyPair];
    XCTAssertNotEqualObjects(sharedKeyAlice, sharedKeyEve);
}

- (void)testLoadFromSerializedData {
    NSDictionary *dic = [self.alice serialized];

    IRTripleDHService *savedAlice = [[IRTripleDHService alloc] initWithData:dic];

    XCTAssertNotNil(savedAlice.identityKeyPair);
    XCTAssertNotNil(savedAlice.signedPreKeyPair);
    XCTAssertEqual(savedAlice.ephemeralKeyPairs.count, 50);

    NSDictionary *serialized = [savedAlice serialized];

    NSDictionary *idKey = serialized[kDictionaryKeyTripleDHServiceIdentityKeyKey];
    XCTAssertNotNil(idKey);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNil(idKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *signedPreKey = serialized[kDictionaryKeyTripleDHServiceSignedPreKeyKey];
    XCTAssertNotNil(signedPreKey);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPrivateKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKey]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeyID]);
    XCTAssertNotNil(signedPreKey[kDictionaryKeyCurve25519KeyPairPublicKeySignature]);

    NSDictionary *currentEphemeralKey = serialized[kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey];
    XCTAssertNil(currentEphemeralKey);

    NSArray *ephemeralKeys = serialized[kDictionaryKeyTripleDHServiceEphemeralKeysKey];
    XCTAssertEqual(ephemeralKeys.count, 50);

    NSData *jsonSerialized = [self.alice jsonSerialized];
    XCTAssertNotNil(jsonSerialized);
}

- (void)testSharedSecretLoadedFromSerializedData {
    NSDictionary *dic = [self.alice serialized];
    IRTripleDHService *savedAlice = [[IRTripleDHService alloc] initWithData:dic];

    XCTAssertNotNil(savedAlice.identityKeyPair);
    XCTAssertNotNil(savedAlice.signedPreKeyPair);
    XCTAssertEqual(savedAlice.ephemeralKeyPairs.count, 50);

    IRCurve25519KeyPair *bobEphemeralKey = self.bob.ephemeralKeyPairs.firstObject;
    NSData *sharedKeyAlice = [savedAlice sharedKeyFromReceiverIdentityKey:self.bob.identityKeyPair
                                                     receiverSignedPreKey:self.bob.signedPreKeyPair
                                                     receiverEphemeralKey:bobEphemeralKey];

    NSData *sharedKeyBob = [self.bob sharedKeyFromSenderIdentityKey:savedAlice.identityKeyPair
                                                 senderEphemeralKey:savedAlice.currentEphemeralKeyPair
                                             receiverEphemeralKeyID:bobEphemeralKey.keyID];
    XCTAssertEqualObjects(sharedKeyAlice, sharedKeyBob);
    XCTAssertEqual(sharedKeyAlice.length,32);
    XCTAssertEqual(sharedKeyBob.length,32);
}

#pragma mark - Helpers

- (IRTripleDHService *)generateX3DH {
    IREncryptionService *eS = [IREncryptionService new];

    IRCurve25519KeyPair *identityKeyPair = [eS generateKeyPair];
    IRCurve25519KeyPair *signedPreKeyPair = [eS generateKeyPair];
    NSData *signature = [eS signData:signedPreKeyPair.publicKey withKeyPair:identityKeyPair];
    [signedPreKeyPair addKeyPairSignature:signature];

    NSMutableArray *eKeys = [NSMutableArray new];
    for (NSInteger i=0; i<50; i++) {
        IRCurve25519KeyPair *keyPair = [eS generateKeyPair];
        if (keyPair == nil) continue;

        [eKeys addObject:keyPair];
    }

    return [[IRTripleDHService alloc] initWithIdentityKeyPair:identityKeyPair signedPreKeyPair:signedPreKeyPair ephemeralKeys:[eKeys copy]];
}

@end
