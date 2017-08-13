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

#import "IRAEADInfo.h"

@interface IRAEADInfo ()

@property (nonatomic, strong) NSData * _Nonnull aesKey;
@property (nonatomic, strong) NSData * _Nonnull hmacKey;
@property (nonatomic, strong) NSData * _Nonnull iv;

@end

@implementation IRAEADInfo

+ (instancetype _Nonnull)infoWithRawData:(NSData * _Nonnull)data {
    NSRange aesRange = NSMakeRange(0, 32);
    NSData *aes = [data subdataWithRange:aesRange];

    NSRange hmacRange = NSMakeRange(32, 32);
    NSData *hmac = [data subdataWithRange:hmacRange];

    NSRange ivRange = NSMakeRange(64, 16);
    NSData *iv = [data subdataWithRange:ivRange];

    return [IRAEADInfo infoWithAESKey:aes HMACKey:hmac iv:iv];
}

+ (instancetype _Nonnull)infoWithAESKey:(NSData * _Nonnull)aesKey HMACKey:(NSData * _Nonnull)hmacKey iv:(NSData * _Nonnull)iv {
    IRAEADInfo *info = [IRAEADInfo new];
    info.aesKey = aesKey;
    info.hmacKey = hmacKey;
    info.iv = iv;

    return info;
}

- (NSData * _Nonnull)serialized {
    NSMutableData *data = [NSMutableData new];
    [data appendData:self.aesKey];
    [data appendData:self.hmacKey];
    [data appendData:self.iv];

    return [data copy];
}

@end
