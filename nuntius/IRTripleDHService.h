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

@class IRCurve25519KeyPair;

@interface IRTripleDHService : NSObject

@property (nonatomic, strong, readonly) IRCurve25519KeyPair * _Nonnull identityKeyPair;
@property (nonatomic, strong, readonly) IRCurve25519KeyPair * _Nonnull signedPreKeyPair;
@property (nonatomic, strong, readonly) NSArray<IRCurve25519KeyPair *> * _Nonnull ephemeralKeyPairs;
@property (nonatomic, strong, readonly) IRCurve25519KeyPair * _Nullable currentEphemeralKeyPair;

- (instancetype _Nonnull)initWithIdentityKeyPair:(IRCurve25519KeyPair * _Nonnull)identityKeyPair
                       signedPreKeyPair:(IRCurve25519KeyPair * _Nonnull)signedPreKeyPair
                                    ephemeralKeys:(NSArray<IRCurve25519KeyPair *> * _Nonnull)ephemeralKeys;

- (instancetype _Nullable)initWithData:(NSDictionary<NSString *, NSObject *> * _Nonnull)data;

- (NSData * _Nullable)sharedKeyFromReceiverIdentityKey:(IRCurve25519KeyPair * _Nonnull)identityKey
                                  receiverSignedPreKey:(IRCurve25519KeyPair * _Nonnull)signedPreKey
                                  receiverEphemeralKey:(IRCurve25519KeyPair * _Nullable)ephemeralKey;
- (NSData * _Nullable)sharedKeyFromSenderIdentityKey:(IRCurve25519KeyPair * _Nonnull)sIdentityKey
                                  senderEphemeralKey:(IRCurve25519KeyPair * _Nonnull)sEphemeralKey
                              receiverEphemeralKeyID:(NSString * _Nullable)rEphemeralKeyID;
- (NSDictionary<NSString *, NSObject *> * _Nullable)serializedForTransport;
- (NSDictionary<NSString *, NSObject *> * _Nullable)serialized;
- (NSData * _Nullable)jsonSerializedForTransport;
- (NSData * _Nullable)jsonSerialized;

@end
