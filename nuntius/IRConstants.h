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

@interface IRConstants : NSObject

// Double Ratchet State

extern NSString * _Nonnull const kDHSenderKey_Key;
extern NSString * _Nonnull const kDHReceiverKey_Key;
extern NSString * _Nonnull const kChainKeySender_Key;
extern NSString * _Nonnull const kChainKeyReceiver_Key;
extern NSString * _Nonnull const kSkippedMessagesKeys_Key;
extern NSString * _Nonnull const kNumberOfSentMessages_Key;
extern NSString * _Nonnull const kNumberOfReceivedMessages_Key;
extern NSString * _Nonnull const kNumberOfPreviousChainSentMessages_Key;

//Dictionary Keys

extern NSString * _Nonnull const kDictionaryKeyCurve25519KeyPairPrivateKey;
extern NSString * _Nonnull const kDictionaryKeyCurve25519KeyPairPublicKey;
extern NSString * _Nonnull const kDictionaryKeyCurve25519KeyPairPublicKeyID;
extern NSString * _Nonnull const kDictionaryKeyCurve25519KeyPairPublicKeySignature;

extern NSString * _Nonnull const kDictionaryKeyTripleDHServiceIdentityKeyKey;
extern NSString * _Nonnull const kDictionaryKeyTripleDHServiceSignedPreKeyKey;
extern NSString * _Nonnull const kDictionaryKeyTripleDHServiceEphemeralKeysKey;
extern NSString * _Nonnull const kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey;

// Error Codes

extern NSUInteger const kSkippedMessagesError_ErrorCode;
extern NSUInteger const kInvalidCiphertextSize_ErrorCode;
extern NSUInteger const kInvalidCiphertext_ErrorCode;

@end
