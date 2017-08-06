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

@interface Curve25519KeyPair : NSObject

@property (nonatomic, strong, readonly) NSData * _Nonnull publicKey;
@property (nonatomic, strong, readonly) NSData * _Nonnull privateKey;
@property (nonatomic, strong, readonly) NSData * _Nullable signature;
@property (nonatomic, copy, readonly) NSString * _Nullable keyID;

+ (NSUInteger)keyLength;
+ (NSUInteger)signatureLength;

+ (Curve25519KeyPair * _Nonnull)keyPairWithPublicKey:(NSData * _Nonnull)publicKey
                                        privateKey:(NSData * _Nonnull)privateKey;

+ (Curve25519KeyPair * _Nonnull)keyPairWithPublicKey:(NSData * _Nonnull)publicKey;

+ (Curve25519KeyPair * _Nonnull)keyPairWithSerializedData:(NSDictionary<NSString *, NSString *> * _Nonnull)serializedData;

- (void)addKeyPairSignature:(NSData * _Nonnull)signature;
- (NSDictionary<NSString *, NSString *> * _Nullable)serializedForTransport;
- (NSDictionary<NSString *, NSString *> * _Nullable)serialized;
- (NSString * _Nullable)base64PublicKey;
- (NSString * _Nullable)base64PrivateKey;

@end
