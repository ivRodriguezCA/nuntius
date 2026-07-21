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

#import "IRTranscript.h"

#import "IRByteWriter.h"

@implementation IRTranscript

+ (NSData * _Nullable)transcriptWithInitiator:(IRIdentityKeyPair * _Nonnull)initiator
                                    ephemeral:(IRX25519Public * _Nonnull)ephemeral
                                    responder:(IRIdentityKeyPair * _Nonnull)responder
                                 signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                                        spkId:(uint32_t)spkId
                                      opkFlag:(IROPKFlag)opkFlag
                                        opkId:(uint32_t)opkId
                                oneTimePreKey:(IRX25519Public * _Nullable)oneTimePreKey
                                        error:(NSError * _Nullable * _Nullable)error {
    if (initiator == nil || responder == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (ephemeral == nil || ephemeral.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (signedPreKey == nil || signedPreKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    if (opkFlag != IROPKFlagAbsent && opkFlag != IROPKFlagPresent) {
        IRSetError(error, IRErrorMalformedHeader);
        return nil;
    }

    /* §6.2 / §9.2: the flag, the id and the key are one three-part statement, and a transcript
       built from an inconsistent triple would agree with nothing. §10.2 checks 6 and 7 catch the
       wire-side form of this before the responder ever reaches here; the initiator's triple comes
       from its own bundle selection and is checked only here. */
    if (opkFlag == IROPKFlagPresent) {
        if (oneTimePreKey == nil || oneTimePreKey.length != kIRLenX25519Public) {
            IRSetError(error, IRErrorInvalidPublicKey);
            return nil;
        }
    } else {
        if (oneTimePreKey != nil || opkId != 0) {
            IRSetError(error, IRErrorMalformedHeader);
            return nil;
        }
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenTranscript];

    [writer appendBytes:kIRLabelTranscript length:kIRLenLabelTranscript];
    [writer appendData:initiator.signingKey.data];
    [writer appendData:initiator.agreementKey.data];
    [writer appendData:ephemeral.data];
    [writer appendData:responder.signingKey.data];
    [writer appendData:responder.agreementKey.data];
    [writer appendData:signedPreKey.data];
    [writer appendUInt32BE:spkId];
    [writer appendUInt8:(uint8_t)opkFlag];
    [writer appendUInt32BE:opkId];

    /* The one place the two cases differ, and only in WHAT is written, never in HOW MANY bytes:
       32 either way, so the field count never varies and the builder stays unconditional in extent
       (§6.2). DH4 by contrast is genuinely OMITTED from the IKM (§6.3) — the asymmetry between the
       two structures is deliberate and `opk_flag` here is what disambiguates it. */
    if (opkFlag == IROPKFlagPresent) {
        [writer appendData:oneTimePreKey.data];
    } else {
        [writer appendZeros:kIRLenX25519Public];
    }

    return [writer finishExpectingLength:kIRLenTranscript error:error];
}

+ (NSData * _Nullable)transcriptHashOf:(NSData * _Nonnull)transcript
                              provider:(id<IRCryptoProvider> _Nonnull)provider
                                 error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    /* §6.2: "Implementations MUST assert len(TRANSCRIPT) == 259 before hashing." */
    if (transcript == nil || transcript.length != kIRLenTranscript) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    NSData *hash = [provider sha256OfData:transcript error:error];
    if (hash == nil) {
        return nil;
    }

    if (hash.length != kIRLenTH) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    return hash;
}

+ (NSData * _Nullable)x3dhInfoWithTranscriptHash:(NSData * _Nonnull)transcriptHash
                                           error:(NSError * _Nullable * _Nullable)error {
    if (transcriptHash == nil || transcriptHash.length != kIRLenTH) {
        IRSetError(error, IRErrorStateCorrupt);
        return nil;
    }

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:kIRLenX3DHInfo];
    [writer appendBytes:kIRLabelX3DH length:kIRLenLabelX3DH];
    [writer appendData:transcriptHash];

    return [writer finishExpectingLength:kIRLenX3DHInfo error:error];
}

@end
