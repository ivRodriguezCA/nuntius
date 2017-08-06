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

#import <XCTest/XCTest.h>
#import "Constants.h"
#import "EncryptionService.h"
#import "Curve25519KeyPair.h"
#import "RatchetHeader.h"
#import "AEADInfo.h"

@interface EncryptionServiceSpec : XCTestCase

@property (nonnull, strong) EncryptionService *subject;

@end

@implementation EncryptionServiceSpec

- (void)setUp {
    [super setUp];
    self.subject = [EncryptionService new];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testKeyGeneration {
    Curve25519KeyPair *keyPair = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair.publicKey);
    XCTAssertNotNil(keyPair.privateKey);
}

- (void)testSharedSecretGeneration {
    Curve25519KeyPair *keyPair1 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair1.publicKey);
    XCTAssertNotNil(keyPair1.privateKey);

    Curve25519KeyPair *keyPair2 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair2.publicKey);
    XCTAssertNotNil(keyPair2.privateKey);

    NSData *sharedSecret1 = [self.subject senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [self.subject receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];
    XCTAssertNotNil(sharedSecret1);
    XCTAssertNotNil(sharedSecret2);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqualObjects(sharedSecret1, sharedSecret2);
}

- (void)testBadSharedSecretGeneration {
    Curve25519KeyPair *keyPair1 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair1.publicKey);
    XCTAssertNotNil(keyPair1.privateKey);

    Curve25519KeyPair *keyPair2 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair2.publicKey);
    XCTAssertNotNil(keyPair2.privateKey);

    Curve25519KeyPair *keyPair3 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair3.publicKey);
    XCTAssertNotNil(keyPair3.privateKey);

    NSData *sharedSecret1 = [self.subject senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [self.subject receiverSharedKeyWithSenderPublicKey:keyPair3.publicKey andReceiverKeyPair:keyPair2];
    XCTAssertNotNil(sharedSecret1);
    XCTAssertNotNil(sharedSecret2);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertNotEqualObjects(sharedSecret1, sharedSecret2);
}

- (void)testSigningData {
    Curve25519KeyPair *keyPair = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair.publicKey);
    XCTAssertNotNil(keyPair.privateKey);

    NSData *message = [@"my-raw-message" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [self.subject signData:message withKeyPair:keyPair];
    XCTAssertNotNil(signature);
    XCTAssertEqual(signature.length, 64);
}

- (void)testVerifySignedData {
    Curve25519KeyPair *keyPair = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair.publicKey);
    XCTAssertNotNil(keyPair.privateKey);

    NSData *message = [@"my-raw-message" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [self.subject signData:message withKeyPair:keyPair];
    XCTAssertNotNil(signature);
    XCTAssertEqual(signature.length, 64);

    BOOL valid = [self.subject verifySignature:signature
                                     ofRawData:message
                                   withKeyPair:keyPair];
    XCTAssertTrue(valid);
}

- (void)testKDFKeyDerivation {
    Curve25519KeyPair *keyPair1 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair1.publicKey);
    XCTAssertNotNil(keyPair1.privateKey);

    Curve25519KeyPair *keyPair2 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair2.publicKey);
    XCTAssertNotNil(keyPair2.privateKey);

    NSData *sharedSecret1 = [self.subject senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [self.subject receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];
    XCTAssertNotNil(sharedSecret1);
    XCTAssertNotNil(sharedSecret2);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqualObjects(sharedSecret1, sharedSecret2);

    NSData *aesKey1 = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                  andSalt:0
                                             outputLength:32];
    NSData *hmacKey1 = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                   andSalt:0
                                              outputLength:32];
    NSData *iv1 = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                              andSalt:0
                                         outputLength:16];
    NSData *aesKey2 = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                  andSalt:0
                                             outputLength:32];
    NSData *hmacKey2 = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                   andSalt:0
                                              outputLength:32];
    NSData *iv2 = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                              andSalt:0
                                         outputLength:16];
    XCTAssertEqual(aesKey1.length, 32);
    XCTAssertEqual(aesKey2.length, 32);
    XCTAssertEqualObjects(aesKey1, aesKey2);

    XCTAssertEqual(hmacKey1.length, 32);
    XCTAssertEqual(hmacKey2.length, 32);
    XCTAssertEqualObjects(hmacKey1, hmacKey2);

    XCTAssertEqual(iv1.length, 16);
    XCTAssertEqual(iv2.length, 16);
    XCTAssertEqualObjects(iv1, iv2);
}

- (void)testGeneratingAEADInfo {
    Curve25519KeyPair *keyPair1 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair1.publicKey);
    XCTAssertNotNil(keyPair1.privateKey);

    Curve25519KeyPair *keyPair2 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair2.publicKey);
    XCTAssertNotNil(keyPair2.privateKey);

    NSData *sharedSecret1 = [self.subject senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [self.subject receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];
    XCTAssertNotNil(sharedSecret1);
    XCTAssertNotNil(sharedSecret2);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqualObjects(sharedSecret1, sharedSecret2);

    NSData *aesKey1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                  andSalt:0
                                             outputLength:32];
    NSData *hmacKey1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                   andSalt:0
                                              outputLength:32];
    NSData *iv1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                              andSalt:0
                                         outputLength:16];
    NSData *aesKey2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                  andSalt:0
                                             outputLength:32];
    NSData *hmacKey2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                   andSalt:0
                                              outputLength:32];
    NSData *iv2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                              andSalt:0
                                         outputLength:16];
    XCTAssertEqual(aesKey1_generated.length, 32);
    XCTAssertEqual(aesKey2_generated.length, 32);
    XCTAssertEqualObjects(aesKey1_generated, aesKey2_generated);

    XCTAssertEqual(hmacKey1_generated.length, 32);
    XCTAssertEqual(hmacKey2_generated.length, 32);
    XCTAssertEqualObjects(hmacKey1_generated, hmacKey2_generated);

    XCTAssertEqual(iv1_generated.length, 16);
    XCTAssertEqual(iv2_generated.length, 16);
    XCTAssertEqualObjects(iv1_generated, iv2_generated);

    AEADInfo *aeadInfo1 = [AEADInfo infoWithAESKey:aesKey1_generated HMACKey:hmacKey1_generated iv:iv1_generated];
    AEADInfo *aeadInfo2 = [AEADInfo infoWithAESKey:aesKey2_generated HMACKey:hmacKey2_generated iv:iv2_generated];

    NSData *aesKey1 = aeadInfo1.aesKey;
    NSData *aesKey2 = aeadInfo2.aesKey;
    XCTAssertNotNil(aesKey1);
    XCTAssertNotNil(aesKey2);
    XCTAssertEqual(aesKey1.length, 32);
    XCTAssertEqual(aesKey2.length, 32);
    XCTAssertEqualObjects(aesKey1, aesKey2);

    NSData *hmacKey1 = aeadInfo1.hmacKey;
    NSData *hmacKey2 = aeadInfo2.hmacKey;
    XCTAssertNotNil(hmacKey1);
    XCTAssertNotNil(hmacKey2);
    XCTAssertEqual(hmacKey1.length, 32);
    XCTAssertEqual(hmacKey2.length, 32);
    XCTAssertEqualObjects(hmacKey1, hmacKey2);

    NSData *iv1 = aeadInfo1.iv;
    NSData *iv2 = aeadInfo2.iv;
    XCTAssertNotNil(iv1);
    XCTAssertNotNil(iv2);
    XCTAssertEqual(iv1.length, 16);
    XCTAssertEqual(iv2.length, 16);
    XCTAssertEqualObjects(iv1, iv2);
}

- (void)testAEADEncryptionAndDecryption {
    Curve25519KeyPair *keyPair1 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair1.publicKey);
    XCTAssertNotNil(keyPair1.privateKey);

    Curve25519KeyPair *keyPair2 = [self.subject generateKeyPair];
    XCTAssertNotNil(keyPair2.publicKey);
    XCTAssertNotNil(keyPair2.privateKey);

    NSData *sharedSecret1 = [self.subject senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [self.subject receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];
    XCTAssertNotNil(sharedSecret1);
    XCTAssertNotNil(sharedSecret2);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqual(sharedSecret1.length, 32);
    XCTAssertEqualObjects(sharedSecret1, sharedSecret2);

    NSData *aesKey1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                            andSalt:0
                                                       outputLength:32];
    NSData *hmacKey1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                             andSalt:0
                                                        outputLength:32];
    NSData *iv1_generated = [self.subject chainKeyKDFWithSecret:sharedSecret1
                                                        andSalt:0
                                                   outputLength:16];
    NSData *aesKey2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                            andSalt:0
                                                       outputLength:32];
    NSData *hmacKey2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                             andSalt:0
                                                        outputLength:32];
    NSData *iv2_generated = [self.subject chainKeyKDFWithSecret:sharedSecret2
                                                        andSalt:0
                                                   outputLength:16];
    XCTAssertEqual(aesKey1_generated.length, 32);
    XCTAssertEqual(aesKey2_generated.length, 32);
    XCTAssertEqualObjects(aesKey1_generated, aesKey2_generated);

    XCTAssertEqual(hmacKey1_generated.length, 32);
    XCTAssertEqual(hmacKey2_generated.length, 32);
    XCTAssertEqualObjects(hmacKey1_generated, hmacKey2_generated);

    XCTAssertEqual(iv1_generated.length, 16);
    XCTAssertEqual(iv2_generated.length, 16);
    XCTAssertEqualObjects(iv1_generated, iv2_generated);

    AEADInfo *aeadInfo1 = [AEADInfo infoWithAESKey:aesKey1_generated HMACKey:hmacKey1_generated iv:iv1_generated];
    AEADInfo *aeadInfo2 = [AEADInfo infoWithAESKey:aesKey2_generated HMACKey:hmacKey2_generated iv:iv2_generated];

    NSData *aesKey1 = aeadInfo1.aesKey;
    NSData *aesKey2 = aeadInfo2.aesKey;
    XCTAssertNotNil(aesKey1);
    XCTAssertNotNil(aesKey2);
    XCTAssertEqual(aesKey1.length, 32);
    XCTAssertEqual(aesKey2.length, 32);
    XCTAssertEqualObjects(aesKey1, aesKey2);

    NSData *hmacKey1 = aeadInfo1.hmacKey;
    NSData *hmacKey2 = aeadInfo2.hmacKey;
    XCTAssertNotNil(hmacKey1);
    XCTAssertNotNil(hmacKey2);
    XCTAssertEqual(hmacKey1.length, 32);
    XCTAssertEqual(hmacKey2.length, 32);
    XCTAssertEqualObjects(hmacKey1, hmacKey2);

    NSData *iv1 = aeadInfo1.iv;
    NSData *iv2 = aeadInfo2.iv;
    XCTAssertNotNil(iv1);
    XCTAssertNotNil(iv2);
    XCTAssertEqual(iv1.length, 16);
    XCTAssertEqual(iv2.length, 16);
    XCTAssertEqualObjects(iv1, iv2);

    NSData *data = [@"my-secret-data" dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableData *ratchetData = [NSMutableData new];

    //Add Sender Ratchet Public Key
    [ratchetData appendData:keyPair1.publicKey];

    //Add Number of Sent Messages
    const char numberOfSentMessages[1] = {0x0};
    [ratchetData appendBytes:numberOfSentMessages length:sizeof(numberOfSentMessages)];

    //Add Number of Sent Messages in Previous Chain
    const char numberOfSentMessagesInPreviousChain[1] = {0x0};
    [ratchetData appendBytes:numberOfSentMessagesInPreviousChain length:sizeof(numberOfSentMessagesInPreviousChain)];

    NSData *ciphertext = [self.subject aeEncryptData:data
                                        symmetricKey:aesKey1
                                             hmacKey:hmacKey1
                                                  iv:iv1
                                       ratchetHeader:ratchetData
                                               error:nil];
    XCTAssertNotNil(ciphertext);

    RatchetHeader *ratchetHeader = [self.subject ratchetHeaderFromCipherData:ciphertext];
    XCTAssertNotNil(ratchetHeader);
    XCTAssertNotNil(ratchetHeader.ratchetKey);
    XCTAssertEqual(ratchetHeader.numberOfSentMessages, 0);
    XCTAssertEqual(ratchetHeader.numberOfPreviousChainSentMessages, 0);

    NSData *decryptedData = [self.subject aeDecryptData:ciphertext
                                           symmetricKey:aesKey2
                                                hmacKey:hmacKey2
                                                     iv:iv2
                                                  error:nil];
    NSString *stringDecrypted = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    XCTAssertNotNil(decryptedData);
    XCTAssertEqualObjects(stringDecrypted, @"my-secret-data");
}

- (void)testPerformanceOfKeyGeneration {
    [self measureBlock:^{
        Curve25519KeyPair *keyPair = [self.subject generateKeyPair];
        XCTAssertNotNil(keyPair.publicKey);
        XCTAssertNotNil(keyPair.privateKey);
    }];
}

@end
