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

@class Curve25519KeyPair;
@class RatchetHeader;
@class AEADInfo;

@interface EncryptionService : NSObject

#pragma mark - Key Generation

- (Curve25519KeyPair * _Nullable)generateKeyPair;
- (AEADInfo * _Nonnull)generateRandomAEADInfoData;

#pragma mark - Shared Keys

- (NSData * _Nullable)senderSharedKeyWithRecieverPublicKey:(NSData * _Nonnull)receiverPublicKey
                                          andSenderKeyPair:(Curve25519KeyPair * _Nonnull)senderKeyPair;
- (NSData * _Nullable)receiverSharedKeyWithSenderPublicKey:(NSData * _Nonnull)senderPublicKey
                                        andReceiverKeyPair:(Curve25519KeyPair * _Nonnull)receiverKeyPair;

#pragma mark - Key Derivation

- (NSData * _Nullable)rootKeyKDFWithSecret:(NSData * _Nonnull)secret
                                   andSalt:(uint64_t)salt
                              outputLength:(NSUInteger)outputLength;
- (NSData * _Nullable)chainKeyKDFWithSecret:(NSData * _Nonnull)secret
                                    andSalt:(uint64_t)salt
                               outputLength:(NSUInteger)outputLength;
- (NSData * _Nullable)messageKeyKDFWithSecret:(NSData * _Nonnull)secret
                                      andSalt:(uint64_t)salt
                                 outputLength:(NSUInteger)outputLength;
- (NSData * _Nullable)sharedKeyKDFWithSecret:(NSData * _Nonnull)secret
                                     andSalt:(uint64_t)salt
                                outputLength:(NSUInteger)outputLength;

#pragma mark - AE Crypto

- (NSData * _Nullable)aeEncryptSimpleData:(NSData * _Nonnull)plaintextData
                             symmetricKey:(NSData * _Nonnull)symmetricKey
                                  hmacKey:(NSData * _Nonnull)hmacKey
                                       iv:(NSData * _Nonnull)iv
                                    error:(NSError * _Nullable * _Nullable)error;

- (NSData * _Nullable)aeEncryptData:(NSData * _Nonnull)plaintextData
                       symmetricKey:(NSData * _Nonnull)symmetricKey
                            hmacKey:(NSData * _Nonnull)hmacKey
                                 iv:(NSData * _Nonnull)iv
                      ratchetHeader:(NSData * _Nonnull)ratchetHeader
                              error:(NSError * _Nullable * _Nullable)error;

- (NSData * _Nullable)aeDecryptSimpleData:(NSData * _Nonnull)cipherData
                             symmetricKey:(NSData * _Nonnull)symmetricKey
                                  hmacKey:(NSData * _Nonnull)hmacKey
                                       iv:(NSData * _Nonnull)iv
                                    error:(NSError * _Nullable * _Nullable)error;

- (NSData * _Nullable)aeDecryptData:(NSData * _Nonnull)cipherData
                       symmetricKey:(NSData * _Nonnull)symmetricKey
                            hmacKey:(NSData * _Nonnull)hmacKey
                                 iv:(NSData * _Nonnull)iv
                              error:(NSError * _Nullable * _Nullable)error;

#pragma mark - Signing

- (NSData * _Nullable)signData:(NSData * _Nonnull)rawData
                   withKeyPair:(Curve25519KeyPair * _Nonnull)keyPair;

- (BOOL)verifySignature:(NSData * _Nonnull)signature
              ofRawData:(NSData * _Nonnull)rawData
            withKeyPair:(Curve25519KeyPair * _Nonnull)keyPair;

#pragma mark - Hashing

- (NSData * _Nonnull)hashData:(NSData * _Nonnull)dataToHash;

#pragma mark - Random Data Generation

- (NSData * _Nonnull)randomBytesOfLength:(NSUInteger)length;
- (NSMutableData * _Nonnull)mutableRandomBytesOfLength:(NSUInteger)length;

#pragma mark - Ratchet Header

- (RatchetHeader * _Nullable)ratchetHeaderFromCipherData:(NSData * _Nonnull)cipherData;

@end
