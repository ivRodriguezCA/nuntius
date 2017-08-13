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
#import "IRDoubleRatchetService.h"
#import "IREncryptionService.h"
#import "IRCurve25519KeyPair.h"

@interface IRDoubleRatchetServiceSpec : XCTestCase

@property (nonatomic, strong) IRDoubleRatchetService *alice;
@property (nonatomic, strong) IRDoubleRatchetService *bob;

@end

@implementation IRDoubleRatchetServiceSpec

- (void)setUp {
    [super setUp];

    self.alice = [IRDoubleRatchetService new];
    self.bob = [IRDoubleRatchetService new];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testSendAndReceiveMessages {
    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *preKey = [eS generateKeyPair];
    IRCurve25519KeyPair *bobPublicPreKey = [IRCurve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    IRCurve25519KeyPair *keyPair1 = [eS generateKeyPair];
    IRCurve25519KeyPair *keyPair2 = [eS generateKeyPair];

    NSData *sharedSecret1 = [eS senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [eS receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];

    [self.alice setupRatchetForSendingWithSharedKey:sharedSecret1
                                   andDHReceiverKey:bobPublicPreKey];

    [self.bob setupRatchetForReceivingWithSharedKey:sharedSecret2
                                andSignedPreKeyPair:preKey];

    NSData *message = [@"hello bob" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertext = [self.alice encryptData:message error:nil];
    XCTAssertNotNil(ciphertext);

    NSData *plaintext = [self.bob decryptData:ciphertext error:nil];
    XCTAssertNotNil(plaintext);
    NSString *m = [[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(m, @"hello bob");
}

- (void)testSendAndReceiveAndSendMessages {
    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *preKey = [eS generateKeyPair];
    IRCurve25519KeyPair *bobPublicPreKey = [IRCurve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    IRCurve25519KeyPair *keyPair1 = [eS generateKeyPair];
    IRCurve25519KeyPair *keyPair2 = [eS generateKeyPair];

    NSData *sharedSecret1 = [eS senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [eS receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];

    [self.alice setupRatchetForSendingWithSharedKey:sharedSecret1
                                   andDHReceiverKey:bobPublicPreKey];

    [self.bob setupRatchetForReceivingWithSharedKey:sharedSecret2
                                andSignedPreKeyPair:preKey];

    //Alice -> Bob
    NSData *messageAlice = [@"Hello Bob!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice = [self.alice encryptData:messageAlice error:nil];
    XCTAssertNotNil(ciphertextAlice);

    NSData *plaintextAlice = [self.bob decryptData:ciphertextAlice error:nil];
    XCTAssertNotNil(plaintextAlice);
    NSString *mAlice = [[NSString alloc] initWithData:plaintextAlice encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice, @"Hello Bob!");

    //Bob -> Alice
    NSData *messageBob = [@"Hello Alice" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextBob = [self.bob encryptData:messageBob error:nil];
    XCTAssertNotNil(ciphertextBob);

    NSData *plaintextBob = [self.alice decryptData:ciphertextBob error:nil];
    XCTAssertNotNil(plaintextBob);
    NSString *mBob = [[NSString alloc] initWithData:plaintextBob encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mBob, @"Hello Alice");
}

- (void)testSendAndSendAndReceiveAndSendMessages {
    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *preKey = [eS generateKeyPair];
    IRCurve25519KeyPair *bobPublicPreKey = [IRCurve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    IRCurve25519KeyPair *keyPair1 = [eS generateKeyPair];
    IRCurve25519KeyPair *keyPair2 = [eS generateKeyPair];

    NSData *sharedSecret1 = [eS senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [eS receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];

    [self.alice setupRatchetForSendingWithSharedKey:sharedSecret1
                                   andDHReceiverKey:bobPublicPreKey];

    [self.bob setupRatchetForReceivingWithSharedKey:sharedSecret2
                                andSignedPreKeyPair:preKey];

    //Alice -> Bob
    NSData *messageAlice1 = [@"Hello Bob!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice1 = [self.alice encryptData:messageAlice1 error:nil];
    XCTAssertNotNil(ciphertextAlice1);

    NSData *plaintextAlice1 = [self.bob decryptData:ciphertextAlice1 error:nil];
    XCTAssertNotNil(plaintextAlice1);
    NSString *mAlice1 = [[NSString alloc] initWithData:plaintextAlice1 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice1, @"Hello Bob!");

    //Alice -> Bob
    NSData *messageAlice2 = [@"How you doing?" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice2 = [self.alice encryptData:messageAlice2 error:nil];
    XCTAssertNotNil(ciphertextAlice2);

    NSData *plaintextAlice2 = [self.bob decryptData:ciphertextAlice2 error:nil];
    XCTAssertNotNil(plaintextAlice2);
    NSString *mAlice2 = [[NSString alloc] initWithData:plaintextAlice2 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice2, @"How you doing?");

    //Bob -> Alice
    NSData *messageBob = [@"Hello Alice" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextBob = [self.bob encryptData:messageBob error:nil];
    XCTAssertNotNil(ciphertextBob);

    NSData *plaintextBob = [self.alice decryptData:ciphertextBob error:nil];
    XCTAssertNotNil(plaintextBob);
    NSString *mBob = [[NSString alloc] initWithData:plaintextBob encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mBob, @"Hello Alice");
}

- (void)testOutOfOrderMessages {
    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *preKey = [eS generateKeyPair];
    IRCurve25519KeyPair *bobPublicPreKey = [IRCurve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    IRCurve25519KeyPair *keyPair1 = [eS generateKeyPair];
    IRCurve25519KeyPair *keyPair2 = [eS generateKeyPair];

    NSData *sharedSecret1 = [eS senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [eS receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];

    [self.alice setupRatchetForSendingWithSharedKey:sharedSecret1
                                   andDHReceiverKey:bobPublicPreKey];

    [self.bob setupRatchetForReceivingWithSharedKey:sharedSecret2
                                andSignedPreKeyPair:preKey];

    //Alice -> Bob
    NSData *messageAlice1 = [@"Hello Bob!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice1 = [self.alice encryptData:messageAlice1 error:nil];
    XCTAssertNotNil(ciphertextAlice1);

    NSData *plaintextAlice1 = [self.bob decryptData:ciphertextAlice1 error:nil];
    XCTAssertNotNil(plaintextAlice1);
    NSString *mAlice1 = [[NSString alloc] initWithData:plaintextAlice1 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice1, @"Hello Bob!");

    //Alice -> Bob
    NSData *messageAlice2 = [@"How you doing?" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice2 = [self.alice encryptData:messageAlice2 error:nil];
    XCTAssertNotNil(ciphertextAlice2);

    //Alice -> Bob
    NSData *messageAlice3 = [@"Hows everything?" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice3 = [self.alice encryptData:messageAlice3 error:nil];
    XCTAssertNotNil(ciphertextAlice3);

    //Message 3 arrives before Message 2
    NSData *plaintextAlice2 = [self.bob decryptData:ciphertextAlice3 error:nil];
    XCTAssertNotNil(plaintextAlice2);
    NSString *mAlice2 = [[NSString alloc] initWithData:plaintextAlice2 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice2, @"Hows everything?");

    //Message 2 arrives later
    NSData *plaintextAlice3 = [self.bob decryptData:ciphertextAlice2 error:nil];
    XCTAssertNotNil(plaintextAlice3);
    NSString *mAlice3 = [[NSString alloc] initWithData:plaintextAlice3 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice3, @"How you doing?");
}

- (void)testOutOfOrderMessagesAndSend {
    IREncryptionService *eS = [IREncryptionService new];
    IRCurve25519KeyPair *preKey = [eS generateKeyPair];
    IRCurve25519KeyPair *bobPublicPreKey = [IRCurve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    IRCurve25519KeyPair *keyPair1 = [eS generateKeyPair];
    IRCurve25519KeyPair *keyPair2 = [eS generateKeyPair];

    NSData *sharedSecret1 = [eS senderSharedKeyWithRecieverPublicKey:keyPair2.publicKey andSenderKeyPair:keyPair1];
    NSData *sharedSecret2 = [eS receiverSharedKeyWithSenderPublicKey:keyPair1.publicKey andReceiverKeyPair:keyPair2];

    [self.alice setupRatchetForSendingWithSharedKey:sharedSecret1
                                   andDHReceiverKey:bobPublicPreKey];

    [self.bob setupRatchetForReceivingWithSharedKey:sharedSecret2
                                andSignedPreKeyPair:preKey];

    //Alice -> Bob
    NSData *messageAlice1 = [@"Hello Bob!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice1 = [self.alice encryptData:messageAlice1 error:nil];
    XCTAssertNotNil(ciphertextAlice1);

    NSData *plaintextAlice1 = [self.bob decryptData:ciphertextAlice1 error:nil];
    XCTAssertNotNil(plaintextAlice1);
    NSString *mAlice1 = [[NSString alloc] initWithData:plaintextAlice1 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice1, @"Hello Bob!");

    //Alice -> Bob
    NSData *messageAlice2 = [@"How you doing?" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice2 = [self.alice encryptData:messageAlice2 error:nil];
    XCTAssertNotNil(ciphertextAlice2);

    //Alice -> Bob
    NSData *messageAlice3 = [@"Hows everything?" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextAlice3 = [self.alice encryptData:messageAlice3 error:nil];
    XCTAssertNotNil(ciphertextAlice3);

    //Message 3 arrives before Message 2
    NSData *plaintextAlice2 = [self.bob decryptData:ciphertextAlice3 error:nil];
    XCTAssertNotNil(plaintextAlice2);
    NSString *mAlice2 = [[NSString alloc] initWithData:plaintextAlice2 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice2, @"Hows everything?");

    //Message 2 arrives later
    NSData *plaintextAlice3 = [self.bob decryptData:ciphertextAlice2 error:nil];
    XCTAssertNotNil(plaintextAlice3);
    NSString *mAlice3 = [[NSString alloc] initWithData:plaintextAlice3 encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mAlice3, @"How you doing?");

    //Bob -> Alice
    NSData *messageBob = [@"Hello Alice" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextBob = [self.bob encryptData:messageBob error:nil];
    XCTAssertNotNil(ciphertextBob);

    NSData *plaintextBob = [self.alice decryptData:ciphertextBob error:nil];
    XCTAssertNotNil(plaintextBob);
    NSString *mBob = [[NSString alloc] initWithData:plaintextBob encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(mBob, @"Hello Alice");
}

@end
