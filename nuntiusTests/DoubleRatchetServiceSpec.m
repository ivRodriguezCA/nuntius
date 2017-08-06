//
//  DoubleRatchetServiceSpec.m
//  Kuik
//
//  Created by Ivan E. Rodriguez on 2017-04-03.
//  Copyright © 2017 Ivan E. Rodriguez. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "DoubleRatchetService.h"
#import "EncryptionService.h"
#import "Curve25519KeyPair.h"

@interface DoubleRatchetServiceSpec : XCTestCase

@property (nonatomic, strong) DoubleRatchetService *alice;
@property (nonatomic, strong) DoubleRatchetService *bob;

@end

@implementation DoubleRatchetServiceSpec

- (void)setUp {
    [super setUp];

    self.alice = [DoubleRatchetService new];
    self.bob = [DoubleRatchetService new];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testSendAndReceiveMessages {
    EncryptionService *eS = [EncryptionService new];
    Curve25519KeyPair *preKey = [eS generateKeyPair];
    Curve25519KeyPair *bobPublicPreKey = [Curve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    Curve25519KeyPair *keyPair1 = [eS generateKeyPair];
    Curve25519KeyPair *keyPair2 = [eS generateKeyPair];

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
    EncryptionService *eS = [EncryptionService new];
    Curve25519KeyPair *preKey = [eS generateKeyPair];
    Curve25519KeyPair *bobPublicPreKey = [Curve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    Curve25519KeyPair *keyPair1 = [eS generateKeyPair];
    Curve25519KeyPair *keyPair2 = [eS generateKeyPair];

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
    EncryptionService *eS = [EncryptionService new];
    Curve25519KeyPair *preKey = [eS generateKeyPair];
    Curve25519KeyPair *bobPublicPreKey = [Curve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    Curve25519KeyPair *keyPair1 = [eS generateKeyPair];
    Curve25519KeyPair *keyPair2 = [eS generateKeyPair];

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
    EncryptionService *eS = [EncryptionService new];
    Curve25519KeyPair *preKey = [eS generateKeyPair];
    Curve25519KeyPair *bobPublicPreKey = [Curve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    Curve25519KeyPair *keyPair1 = [eS generateKeyPair];
    Curve25519KeyPair *keyPair2 = [eS generateKeyPair];

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
    EncryptionService *eS = [EncryptionService new];
    Curve25519KeyPair *preKey = [eS generateKeyPair];
    Curve25519KeyPair *bobPublicPreKey = [Curve25519KeyPair keyPairWithPublicKey:preKey.publicKey];

    Curve25519KeyPair *keyPair1 = [eS generateKeyPair];
    Curve25519KeyPair *keyPair2 = [eS generateKeyPair];

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
