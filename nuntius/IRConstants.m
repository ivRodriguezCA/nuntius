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

#import "IRConstants.h"

@implementation IRConstants

// Double Ratchet State

NSString * const kDHSenderKey_Key = @"DHSenderKey_Key";
NSString * const kDHReceiverKey_Key = @"DHReceiverKey_Key";
NSString * const kChainKeySender_Key = @"ChainKeySender_Key";
NSString * const kChainKeyReceiver_Key = @"ChainKeyReceiver_Key";
NSString * const kSkippedMessagesKeys_Key = @"SkippedMessagesKeys_Key";
NSString * const kNumberOfSentMessages_Key = @"NumberOfSentMessages_Key";
NSString * const kNumberOfReceivedMessages_Key = @"NumberOfReceivedMessages_Key";
NSString * const kNumberOfPreviousChainSentMessages_Key = @"NumberOfPreviousChainSentMessages_Key";

//Dictionary Keys

NSString * const kDictionaryKeyCurve25519KeyPairPrivateKey = @"kDictionaryKeyCurve25519KeyPairPrivateKey";
NSString * const kDictionaryKeyCurve25519KeyPairPublicKey = @"kDictionaryKeyCurve25519KeyPairPublicKey";
NSString * const kDictionaryKeyCurve25519KeyPairPublicKeyID = @"kDictionaryKeyCurve25519KeyPairPublicKeyID";
NSString * const kDictionaryKeyCurve25519KeyPairPublicKeySignature = @"kDictionaryKeyCurve25519KeyPairPublicKeySignature";

NSString * const kDictionaryKeyTripleDHServiceIdentityKeyKey = @"kDictionaryKeyTripleDHServiceIdentityKeyKey";
NSString * const kDictionaryKeyTripleDHServiceSignedPreKeyKey = @"kDictionaryKeyTripleDHServiceSignedPreKeyKey";
NSString * const kDictionaryKeyTripleDHServiceEphemeralKeysKey = @"kDictionaryKeyTripleDHServiceEphemeralKeysKey";
NSString * const kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey = @"kDictionaryKeyTripleDHServiceCurrentEphemeralKeyKey";

// Error Codes

NSUInteger const kSkippedMessagesError_ErrorCode = 7001;
NSUInteger const kInvalidCiphertextSize_ErrorCode = 7002;
NSUInteger const kInvalidCiphertext_ErrorCode = 7003;

@end
