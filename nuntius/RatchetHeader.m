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

#import "RatchetHeader.h"
#import "Curve25519KeyPair.h"

@interface RatchetHeader ()

@property (nonnull, strong) Curve25519KeyPair *ratchetKey;
@property (nonatomic, assign) NSUInteger numberOfSentMessages;
@property (nonatomic, assign) NSUInteger numberOfPreviousChainSentMessages;

@end

@implementation RatchetHeader

+ (instancetype _Nonnull)headerWithKey:(NSData * _Nonnull)ratchetKey
                          sentMessages:(NSUInteger)sentMessages
             previousChainSentMessages:(NSUInteger)previousChainSentMessages {
    RatchetHeader *header = [RatchetHeader new];
    header.ratchetKey = [Curve25519KeyPair keyPairWithPublicKey:ratchetKey];
    header.numberOfSentMessages = sentMessages;
    header.numberOfPreviousChainSentMessages = previousChainSentMessages;

    return header;
}

- (NSArray<NSObject *> * _Nullable)serialized {
    if (self.ratchetKey == nil || self.ratchetKey.publicKey == nil) {
        return nil;
    }

    return @[self.ratchetKey.publicKey,@(self.numberOfSentMessages)];
}

- (NSString * _Nullable)dictionaryKey {
    if (self.ratchetKey == nil || self.ratchetKey.publicKey == nil) {
        return nil;
    }

    NSMutableString *key = [NSMutableString new];

    NSString *publicKey = [self.ratchetKey.publicKey base64EncodedStringWithOptions:0];
    [key appendString:publicKey];

    [key appendString:@"|"];

    NSString *messages = [@(self.numberOfSentMessages) stringValue];
    [key appendString:messages];

    return [key copy];
}

@end
