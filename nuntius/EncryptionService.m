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

#import "EncryptionService.h"
#import "Curve25519KeyPair.h"
#import "RatchetHeader.h"
#import "Constants.h"
#import "AEADInfo.h"

#import "sodium/crypto_kdf.h"
#import "sodium/crypto_sign.h"
#import "sodium/crypto_scalarmult.h"
#import "sodium/crypto_generichash.h"

#import <CommonCrypto/CommonCrypto.h>

static char * const KDF_RootKey_Label = "KDF_RootKey_Label";
static char * const KDF_ChainKey_Label = "KDF_ChainKey_Label";
static char * const KDF_MesageKey_Label = "KDF_MesageKey_Label";
static char * const KDF_SharedKey_Label = "KDF_SharedKey_Label";

@implementation EncryptionService

#pragma mark - Key Generation

- (Curve25519KeyPair * _Nullable)generateKeyPair {
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];

    crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);

    NSData *publicKey = [NSData dataWithBytes:ed25519_pk length:crypto_sign_ed25519_PUBLICKEYBYTES];
    NSData *privateKey = [NSData dataWithBytes:ed25519_skpk length:crypto_sign_ed25519_SECRETKEYBYTES];

    return [Curve25519KeyPair keyPairWithPublicKey:publicKey privateKey:privateKey];
}

- (AEADInfo * _Nonnull)generateRandomAEADInfoData {
    NSData *randomData = [self randomBytesOfLength:80];
    return [AEADInfo infoWithRawData:randomData];
}

#pragma mark - Shared Keys

- (NSData * _Nullable)senderSharedKeyWithRecieverPublicKey:(NSData * _Nonnull)receiverPublicKey
                                          andSenderKeyPair:(Curve25519KeyPair * _Nonnull)senderKeyPair {
    NSUInteger keyLength = [Curve25519KeyPair keyLength];
    if (receiverPublicKey.length != keyLength) {
        return nil;
    }

    unsigned char curve25519_receiver_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_sender_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_sender_sk[crypto_scalarmult_curve25519_BYTES];
    unsigned char scalarmult_q[crypto_scalarmult_BYTES];
    unsigned char sharedkey[crypto_generichash_BYTES];
    crypto_generichash_state state;

    __unused int rpkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_receiver_pk, receiverPublicKey.bytes);
    __unused int pkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_sender_pk, senderKeyPair.publicKey.bytes);
    __unused int skResult = crypto_sign_ed25519_sk_to_curve25519(curve25519_sender_sk, senderKeyPair.privateKey.bytes);

    // q = ECDH(sender_secretkey, receiver_publickey)
    if (crypto_scalarmult(scalarmult_q, curve25519_sender_sk, curve25519_receiver_pk) != 0) {
        return nil;
    }

    crypto_generichash_init(&state, NULL, 0U, crypto_generichash_BYTES);
    crypto_generichash_update(&state, scalarmult_q, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, curve25519_sender_pk, crypto_scalarmult_curve25519_BYTES);
    crypto_generichash_update(&state, curve25519_receiver_pk, crypto_scalarmult_curve25519_BYTES);
    crypto_generichash_final(&state, sharedkey, crypto_generichash_BYTES);

    // sharedkey = hash(q ‖ sender_publickey ‖ receiver_publickey)
    return [NSData dataWithBytes:sharedkey length:crypto_generichash_BYTES];
}

- (NSData * _Nullable)receiverSharedKeyWithSenderPublicKey:(NSData * _Nonnull)senderPublicKey
                                        andReceiverKeyPair:(Curve25519KeyPair * _Nonnull)receiverKeyPair {
    NSUInteger keyLength = [Curve25519KeyPair keyLength];
    if (senderPublicKey.length != keyLength) {
        return nil;
    }

    unsigned char curve25519_sender_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_receiver_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_receiver_sk[crypto_scalarmult_curve25519_BYTES];
    unsigned char scalarmult_q[crypto_scalarmult_BYTES];
    unsigned char sharedkey[crypto_generichash_BYTES];
    crypto_generichash_state state;

    __unused int rpkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_sender_pk, senderPublicKey.bytes);
    __unused int pkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_receiver_pk, receiverKeyPair.publicKey.bytes);
    __unused int skResult = crypto_sign_ed25519_sk_to_curve25519(curve25519_receiver_sk, receiverKeyPair.privateKey.bytes);

    // q = ECDH(receiver_secretkey, sender_publickey)
    if (crypto_scalarmult(scalarmult_q, curve25519_receiver_sk, curve25519_sender_pk) != 0) {
        return nil;
    }

    crypto_generichash_init(&state, NULL, 0U, crypto_generichash_BYTES);
    crypto_generichash_update(&state, scalarmult_q, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, curve25519_sender_pk, crypto_scalarmult_curve25519_BYTES);
    crypto_generichash_update(&state, curve25519_receiver_pk, crypto_scalarmult_curve25519_BYTES);
    crypto_generichash_final(&state, sharedkey, crypto_generichash_BYTES);

    // sharedkey = hash(q ‖ sender_publickey ‖ receiver_publickey)
    return [NSData dataWithBytes:sharedkey length:crypto_generichash_BYTES];
}

#pragma mark - Key Derivation

- (NSData * _Nullable)rootKeyKDFWithSecret:(NSData * _Nonnull)secret
                                   andSalt:(uint64_t)salt
                              outputLength:(NSUInteger)outputLength {
    return [self genericKDFWithSecret:secret
                              andSalt:(uint64_t)salt
                         outputLength:outputLength
                            infoLabel:KDF_RootKey_Label];
}

- (NSData * _Nullable)chainKeyKDFWithSecret:(NSData * _Nonnull)secret
                                    andSalt:(uint64_t)salt
                               outputLength:(NSUInteger)outputLength {
    return [self genericKDFWithSecret:secret
                              andSalt:salt
                         outputLength:outputLength
                            infoLabel:KDF_ChainKey_Label];
}

- (NSData * _Nullable)messageKeyKDFWithSecret:(NSData * _Nonnull)secret
                                      andSalt:(uint64_t)salt
                                 outputLength:(NSUInteger)outputLength {
    return [self genericKDFWithSecret:secret
                              andSalt:salt
                         outputLength:outputLength
                            infoLabel:KDF_MesageKey_Label];
}

- (NSData * _Nullable)sharedKeyKDFWithSecret:(NSData * _Nonnull)secret
                                     andSalt:(uint64_t)salt
                                outputLength:(NSUInteger)outputLength {
    return [self genericKDFWithSecret:secret
                              andSalt:salt
                         outputLength:outputLength
                            infoLabel:KDF_SharedKey_Label];
}

- (NSData * _Nullable)genericKDFWithSecret:(NSData * _Nonnull)secret
                                   andSalt:(uint64_t)salt
                              outputLength:(NSUInteger)outputLength
                                 infoLabel:(char * _Nonnull)infoLabel {
    if (secret == nil) {
        return nil;
    }

    NSUInteger keyLength = MAX(crypto_kdf_BYTES_MIN, MIN(crypto_kdf_BYTES_MAX, outputLength));
    uint8_t subkey[keyLength];

    crypto_kdf_derive_from_key(subkey, keyLength, salt, infoLabel, secret.bytes);

    return [NSData dataWithBytes:subkey length:keyLength];
}

#pragma mark - AE Crypto

- (NSData * _Nullable)aeEncryptSimpleData:(NSData * _Nonnull)plaintextData
                             symmetricKey:(NSData * _Nonnull)symmetricKey
                                  hmacKey:(NSData * _Nonnull)hmacKey
                                       iv:(NSData * _Nonnull)iv
                                    error:(NSError * _Nullable * _Nullable)error {
    NSData *cipherData = [self encryptData:plaintextData withKey:symmetricKey iv:iv];
    if (cipherData.length == 0) {
        NSString *description = NSLocalizedString(@"Invalid Ciphertext Size", nil);
        NSError *err = [NSError errorWithDomain:@"com.ciphie.InvalidCiphertextSize" code:kInvalidCiphertextSize_ErrorCode userInfo:@{NSLocalizedDescriptionKey: description}];
        *error = err;
        return nil;
    }

    //Create Header
    NSMutableData *headerData = [NSMutableData new];

    //Add version (1 byte)
    const char version[1] = {0x03};
    [headerData appendBytes:version length:sizeof(version)];

    //Add Options (1 byte)
    const char options[1] = {0x0};
    [headerData appendBytes:options length:sizeof(options)];

    //Create HMAC Data from header + cipher
    NSMutableData *dataToHMAC = [NSMutableData new];
    [dataToHMAC appendData:headerData];
    [dataToHMAC appendData:cipherData];

    //HMAC header and cipher
    NSData *hmacData = [self hmacData:dataToHMAC withKey:hmacKey];

    //All together
    NSMutableData *aeCipherData = [NSMutableData new];
    [aeCipherData appendData:headerData];
    [aeCipherData appendData:cipherData];
    [aeCipherData appendData:hmacData];

    return [aeCipherData copy];

}

- (NSData * _Nullable)aeEncryptData:(NSData * _Nonnull)plaintextData
                       symmetricKey:(NSData * _Nonnull)symmetricKey
                            hmacKey:(NSData * _Nonnull)hmacKey
                                 iv:(NSData * _Nonnull)iv
                      ratchetHeader:(NSData * _Nonnull)ratchetHeader
                              error:(NSError * _Nullable * _Nullable)error {

    NSData *cipherData = [self encryptData:plaintextData withKey:symmetricKey iv:iv];
    if (cipherData.length == 0) {
        if (error) {
            NSString *description = NSLocalizedString(@"Invalid Ciphertext Size", nil);
            NSError *err = [NSError errorWithDomain:@"com.ciphie.InvalidCiphertextSize" code:kInvalidCiphertextSize_ErrorCode userInfo:@{NSLocalizedDescriptionKey: description}];
            *error = err;
        }
        return nil;
    }

    //Create Header
    NSMutableData *headerData = [NSMutableData new];

    //Add version (1 byte)
    const char version[1] = {0x03};
    [headerData appendBytes:version length:sizeof(version)];

    //Add Options (1 byte)
    const char options[1] = {0x0};
    [headerData appendBytes:options length:sizeof(options)];

    //Add Ratchet Header Size (1 byte)
    const char ratchetHeaderSize[1] = {sizeof(char[ratchetHeader.length])};
    [headerData appendBytes:ratchetHeaderSize length:sizeof(ratchetHeaderSize)];

    //Add Ratchet header
    [headerData appendData:ratchetHeader];

    //Create HMAC Data from header + cipher
    NSMutableData *dataToHMAC = [NSMutableData new];
    [dataToHMAC appendData:headerData];
    [dataToHMAC appendData:cipherData];

    //HMAC header and cipher
    NSData *hmacData = [self hmacData:dataToHMAC withKey:hmacKey];

    //All together
    NSMutableData *aeCipherData = [NSMutableData new];
    [aeCipherData appendData:headerData];
    [aeCipherData appendData:cipherData];
    [aeCipherData appendData:hmacData];

    return [aeCipherData copy];
}

- (NSData * _Nullable)aeDecryptSimpleData:(NSData * _Nonnull)cipherData
                             symmetricKey:(NSData * _Nonnull)symmetricKey
                                  hmacKey:(NSData * _Nonnull)hmacKey
                                       iv:(NSData * _Nonnull)iv
                                    error:(NSError * _Nullable * _Nullable)error {

    NSData *dataToHMAC = [self hmacDataFromSimpleCipherData:cipherData];
    NSData *hmacData = [self hmacData:dataToHMAC withKey:hmacKey];
    NSData *hmac = [self hmacFromSimpleCipherData:cipherData];

    if ([self consistentTimeEqual:hmacData hmachToCompare:hmac]) {
        NSData *ciphertext = [self ciphertextFromSimpleCipherData:cipherData];
        return [self decryptData:ciphertext
                         withKey:symmetricKey
                              iv:iv];
    }

    NSString *description = NSLocalizedString(@"Invalid Ciphertext", nil);
    NSError *err = [NSError errorWithDomain:@"com.ciphie.InvalidCiphertext" code:kInvalidCiphertext_ErrorCode userInfo:@{NSLocalizedDescriptionKey: description}];
    *error = err;

    return nil;
}

- (NSData * _Nullable)aeDecryptData:(NSData * _Nonnull)cipherData
                       symmetricKey:(NSData * _Nonnull)symmetricKey
                            hmacKey:(NSData * _Nonnull)hmacKey
                                 iv:(NSData * _Nonnull)iv
                              error:(NSError * _Nullable * _Nullable)error {
    if (cipherData == nil) {
        return nil;
    }

    NSData *dataToHMAC = [self hmacDataFromCipherData:cipherData];
    NSData *hmacData = [self hmacData:dataToHMAC withKey:hmacKey];
    NSData *hmac = [self hmacFromCipherData:cipherData];

    if ([self consistentTimeEqual:hmacData hmachToCompare:hmac]) {
        NSData *ciphertext = [self ciphertextFromCipherData:cipherData];
        return [self decryptData:ciphertext
                         withKey:symmetricKey
                              iv:iv];
    }

    NSString *description = NSLocalizedString(@"Invalid Ciphertext", nil);
    if (error != nil) {
        NSError *err = [NSError errorWithDomain:@"com.ciphie.InvalidCiphertext" code:kInvalidCiphertext_ErrorCode userInfo:@{NSLocalizedDescriptionKey: description}];
        *error = err;
    }

    return nil;
}

#pragma mark - Symmetric Crypto

- (NSData * _Nullable)encryptData:(NSData * _Nonnull)plainTextData
                          withKey:(NSData * _Nonnull)key
                               iv:(NSData * _Nullable)iv {
    size_t cipherLength = 0;
    NSMutableData *cipherData = [NSMutableData dataWithLength:plainTextData.length + kCCBlockSizeAES128];
    [cipherData resetBytesInRange:NSMakeRange(0, cipherData.length)];

    OSStatus status = CCCrypt(kCCEncrypt,
                              kCCAlgorithmAES128,
                              kCCOptionPKCS7Padding,
                              key.bytes,
                              key.length,
                              iv.bytes,
                              plainTextData.bytes,
                              plainTextData.length,
                              cipherData.mutableBytes,
                              cipherData.length,
                              &cipherLength);

    /*
     memset((void *)key.bytes, 0, key.length);
     *(volatile char*)key.bytes = *(volatile char*)key.bytes;
     */

    if (status == errSecSuccess) {
        return [cipherData subdataWithRange:NSMakeRange(0, cipherLength)];
    }

    return nil;
}

- (NSData *  _Nullable)decryptData:(NSData * _Nonnull)cipherData
                           withKey:(NSData * _Nonnull)key
                                iv:(NSData * _Nonnull)iv {
    size_t plainTextLength = 0;
    NSMutableData *plainTextData = [NSMutableData dataWithLength:cipherData.length];
    [plainTextData resetBytesInRange:NSMakeRange(0, plainTextData.length)];

    OSStatus status = CCCrypt(kCCDecrypt,
                              kCCAlgorithmAES128,
                              kCCOptionPKCS7Padding,
                              key.bytes,
                              key.length,
                              iv.bytes,
                              cipherData.bytes,
                              cipherData.length,
                              plainTextData.mutableBytes,
                              plainTextData.length,
                              &plainTextLength);

    /*
     memset((void *)key.bytes, 0, key.length);
     *(volatile char*)key.bytes = *(volatile char*)key.bytes;
     */

    if (status == errSecSuccess) {
        return [plainTextData subdataWithRange:NSMakeRange(0, plainTextLength)];
    }

    return nil;
}

#pragma mark - Data Integrity (HMAC)

- (NSData * _Nullable)hmacData:(NSData * _Nonnull)cipherData
                       withKey:(NSData * _Nonnull)key {
    NSMutableData *hmacData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           key.bytes,
           key.length,
           cipherData.bytes,
           cipherData.length,
           hmacData.mutableBytes);

    /*
     memset((void *)key.bytes, 0, key.length);
     *(volatile char*)key.bytes = *(volatile char*)key.bytes;
     */

    return [hmacData copy];
}

#pragma mark - Signing

- (NSData * _Nullable)signData:(NSData * _Nonnull)rawData
                   withKeyPair:(Curve25519KeyPair * _Nonnull)keyPair {
    if (rawData == nil || rawData.length == 0 || keyPair == nil) {
        return nil;
    }

    crypto_sign_state state;
    unsigned char signature[crypto_sign_BYTES];

    crypto_sign_init(&state);
    crypto_sign_update(&state, rawData.bytes, rawData.length);
    if (crypto_sign_final_create(&state, signature, NULL, keyPair.privateKey.bytes) != 0) {
        return nil;
    }

    return [NSData dataWithBytes:signature length:crypto_sign_BYTES];
}

- (BOOL)verifySignature:(NSData * _Nonnull)signature
              ofRawData:(NSData * _Nonnull)rawData
            withKeyPair:(Curve25519KeyPair * _Nonnull)keyPair {
    if (signature.length == 0) {
        return NO;
    }

    crypto_sign_state state;

    crypto_sign_init(&state);
    crypto_sign_update(&state, rawData.bytes, rawData.length);
    NSUInteger result = crypto_sign_final_verify(&state, (unsigned char *)signature.bytes, keyPair.publicKey.bytes);

    return (result == 0);
}

#pragma mark - Hashing

- (NSData * _Nonnull)hashData:(NSData * _Nonnull)dataToHash {
    uint8_t digestData[CC_SHA256_DIGEST_LENGTH];
    size_t digestLength = sizeof(digestData);

    CC_SHA256(dataToHash.bytes,
              (CC_LONG)dataToHash.length,
              digestData);

    return [NSData dataWithBytes:digestData length:digestLength];
}

#pragma mark - Random Data Generation

- (NSData * _Nonnull)randomBytesOfLength:(NSUInteger)length {
    return [[self mutableRandomBytesOfLength:length] copy];
}

- (NSMutableData * _Nonnull)mutableRandomBytesOfLength:(NSUInteger)length {
    NSMutableData *randomBytes = [NSMutableData dataWithLength:length];

    __unused uint result = SecRandomCopyBytes(kSecRandomDefault,
                                              length,
                                              randomBytes.mutableBytes);
    return randomBytes;
}

#pragma mark - Ratchet Header

- (RatchetHeader * _Nullable)ratchetHeaderFromCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 70 bytes
    if (cipherData.length < 70) {
        return nil;
    }

    //Get Ratchet Header Size
    NSRange range = NSMakeRange(2, 1);
    NSData *ratchetHeaderSizeData = [cipherData subdataWithRange:range];
    NSUInteger ratchetHeaderSize = *(NSInteger*)ratchetHeaderSizeData.bytes;

    //Get Ratchet Header
    range = NSMakeRange(3, ratchetHeaderSize);
    NSData *ratchetHeader = [cipherData subdataWithRange:range];

    //Get Ratchet Public Key
    range = NSMakeRange(0, 32);
    NSData *publicKeyData = [ratchetHeader subdataWithRange:range];

    //Get Number of Sent Messages
    range = NSMakeRange(32, 1);
    NSData *sentMessagesData = [ratchetHeader subdataWithRange:range];
    NSUInteger sentMessages = *(NSInteger*)sentMessagesData.bytes;

    //Get Number of Sent Messages in Previous Chain
    range = NSMakeRange(33, 1);
    NSData *numberOfSentMessagesInPreviousChainData = [ratchetHeader subdataWithRange:range];
    NSUInteger numberOfSentMessagesInPreviousChain = *(NSInteger*)numberOfSentMessagesInPreviousChainData.bytes;

    return [RatchetHeader headerWithKey:publicKeyData
                           sentMessages:sentMessages
              previousChainSentMessages:numberOfSentMessagesInPreviousChain];
}

#pragma mark - Helpers

- (BOOL)consistentTimeEqual:(NSData * _Nonnull)computedHMAC
             hmachToCompare:(NSData * _Nonnull)HMAC {
    uint8_t result = computedHMAC.length - HMAC.length;

    const uint8_t *hmacBytes = [HMAC bytes];
    const NSUInteger hmacLength = [HMAC length];
    const uint8_t *computedHMACBytes = [computedHMAC bytes];
    const NSUInteger computedHMACLength = [computedHMAC length];

    for (NSUInteger i = 0; i < computedHMACLength; ++i) {
        result |= hmacBytes[i % hmacLength] ^ computedHMACBytes[i];
    }

    return result == 0;
}

#pragma mark - Simple Ciphertext

- (NSData * _Nullable)hmacDataFromSimpleCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 35 bytes for simple ciphertext
    if (cipherData.length < 35) {
        return nil;
    }

    NSMutableData *dataToHMAC = [NSMutableData new];

    //Get Version
    NSRange range = NSMakeRange(0, 1);
    NSData *versionData = [cipherData subdataWithRange:range];
    //NSUInteger version = *(NSInteger*)versionData.bytes;
    [dataToHMAC appendData:versionData];

    //Get Options
    range = NSMakeRange(1, 1);
    NSData *optionsData = [cipherData subdataWithRange:range];
    //NSUInteger options = *(NSInteger*)optionsData.bytes;
    [dataToHMAC appendData:optionsData];

    //Get Ciphertext
    range = NSMakeRange(2, cipherData.length - 34);
    NSData *ciphertext = [cipherData subdataWithRange:range];
    [dataToHMAC appendData:ciphertext];

    return [dataToHMAC copy];
}

- (NSData * _Nullable)hmacFromSimpleCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 32 bytes
    if (cipherData.length < 32) {
        return nil;
    }

    NSRange range = NSMakeRange(cipherData.length - 32, 32);
    return [cipherData subdataWithRange:range];
}

- (NSData * _Nullable)ciphertextFromSimpleCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 35 bytes
    if (cipherData.length < 35) {
        return nil;
    }

    //Get Ciphertext
    NSRange range = NSMakeRange(2, cipherData.length - 34);
    return [cipherData subdataWithRange:range];
}

#pragma mark - Double Ratchet Ciphertext

- (NSData * _Nullable)hmacDataFromCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 70 bytes
    if (cipherData.length < 70) {
        return nil;
    }

    NSMutableData *dataToHMAC = [NSMutableData new];

    //Get Version
    NSRange range = NSMakeRange(0, 1);
    NSData *versionData = [cipherData subdataWithRange:range];
    //NSUInteger version = *(NSInteger*)versionData.bytes;
    [dataToHMAC appendData:versionData];

    //Get Options
    range = NSMakeRange(1, 1);
    NSData *optionsData = [cipherData subdataWithRange:range];
    //NSUInteger options = *(NSInteger*)optionsData.bytes;
    [dataToHMAC appendData:optionsData];

    //Get Ratchet Header Size
    range = NSMakeRange(2, 1);
    NSData *ratchetHeaderSizeData = [cipherData subdataWithRange:range];
    NSUInteger ratchetHeaderSize = *(NSInteger*)ratchetHeaderSizeData.bytes;
    [dataToHMAC appendData:ratchetHeaderSizeData];

    //Get Ratchet Header
    range = NSMakeRange(3, ratchetHeaderSize);
    NSData *ratchetHeader = [cipherData subdataWithRange:range];
    [dataToHMAC appendData:ratchetHeader];

    //Get Ciphertext
    range = NSMakeRange(3 + ratchetHeaderSize, cipherData.length - (3 + ratchetHeaderSize + 32));
    NSData *ciphertext = [cipherData subdataWithRange:range];
    [dataToHMAC appendData:ciphertext];

    return [dataToHMAC copy];
}

- (NSData * _Nullable)hmacFromCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 32 bytes
    if (cipherData.length < 32) {
        return nil;
    }

    NSRange range = NSMakeRange(cipherData.length - 32, 32);
    return [cipherData subdataWithRange:range];
}

- (NSData * _Nullable)ciphertextFromCipherData:(NSData * _Nonnull)cipherData {
    //Minimum size 70 bytes
    if (cipherData.length < 70) {
        return nil;
    }

    //Get Ratchet Header Size
    NSRange range = NSMakeRange(2, 1);
    NSData *ratchetHeaderSizeData = [cipherData subdataWithRange:range];
    NSUInteger ratchetHeaderSize = *(NSInteger*)ratchetHeaderSizeData.bytes;
    
    //Get Ciphertext
    range = NSMakeRange(3 + ratchetHeaderSize, cipherData.length - (3 + ratchetHeaderSize + 32));
    return [cipherData subdataWithRange:range];
}

@end
