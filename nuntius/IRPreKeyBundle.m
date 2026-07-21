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

#import "IRPreKeyBundle.h"

#import "IRByteReader.h"
#import "IRByteWriter.h"
#import "IRProtocolConstants.h"

#pragma mark - IRPreKeyBundleOPKEntry

@interface IRPreKeyBundleOPKEntry ()

- (instancetype _Nonnull)initWithOpkId:(uint32_t)opkId
                             publicKey:(IRX25519Public * _Nonnull)publicKey;

@end

@implementation IRPreKeyBundleOPKEntry

+ (instancetype _Nullable)entryWithOpkId:(uint32_t)opkId
                               publicKey:(IRX25519Public * _Nonnull)publicKey
                                   error:(NSError * _Nullable * _Nullable)error {
    if (publicKey == nil || publicKey.length != kIRLenX25519Public) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    return [[self alloc] initWithOpkId:opkId publicKey:publicKey];
}

- (instancetype _Nonnull)initWithOpkId:(uint32_t)opkId
                             publicKey:(IRX25519Public * _Nonnull)publicKey {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _opkId = opkId;
    _publicKey = publicKey;

    return self;
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:@"<%@: %p; opk_id = %u; OPK = %@>",
            NSStringFromClass([self class]), (void *)self, _opkId, [_publicKey hexString]];
}

@end

#pragma mark - IRPreKeyBundle

@interface IRPreKeyBundle ()

- (instancetype _Nonnull)initWithIdentity:(IRPublicIdentity * _Nonnull)identity
                                    spkId:(uint32_t)spkId
                             signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                               notBeforeS:(uint64_t)notBeforeS
                                notAfterS:(uint64_t)notAfterS
                    signedPreKeySignature:(IREd25519Signature * _Nonnull)signedPreKeySignature
                               opkEntries:(NSArray<IRPreKeyBundleOPKEntry *> * _Nonnull)opkEntries
                              encodedData:(NSData * _Nonnull)encodedData;

@end

@implementation IRPreKeyBundle

#pragma mark - Parsing — §10.3 ordered gate, then §5.3 rules 2–4

+ (instancetype _Nullable)bundleFromData:(NSData * _Nonnull)data
                                provider:(id<IRCryptoProvider> _Nonnull)provider
                                   error:(NSError * _Nullable * _Nullable)error {
    if (provider == nil) {
        IRSetError(error, IRErrorNotInitialized);
        return nil;
    }

    if (data == nil) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    IRByteReader *reader = [[IRByteReader alloc] initWithData:data];

    /* ---- §10.3 step 1: the length floor. -------------------------------------------------------
       MUST precede step 4. `opk_count` sits at a fixed offset, but both structural rules are
       predicates OVER it, so neither can be evaluated without first loading two bytes at 249 —
       which on a short input is an out-of-bounds read that three ports fail three different ways. */
    if (reader.count < (NSUInteger)kIRMinBundleLength) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* ---- §10.3 step 2: magic. ---------------------------------------------------------------- */
    if (![reader matchLiteral:kIRBundleMagic
                       length:kIRLenMagic
                     atOffset:kIROffBundleMagic]) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* ---- §10.3 step 3: version. The ONE bundle-structure failure with its own code. ----------- */
    uint8_t version = 0;
    if (![reader readUInt8:&version atOffset:kIROffBundleVersion]) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    if (version != (uint8_t)kIRProtocolVersion) {
        IRSetError(error, IRErrorUnsupportedVersion);
        return nil;
    }

    /* ---- §10.3 step 4: the opk_count cap. ---------------------------------------------------- */
    uint16_t opkCount = 0;
    if (![reader readUInt16BE:&opkCount atOffset:kIROffBundleOPKCount]) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    if ((NSUInteger)opkCount > (NSUInteger)kIRMaxBundleOPKCount) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* ---- §10.3 step 5: the exact-length identity, in BOTH directions. -------------------------
       Step 4 has already bounded opkCount at 1000, so the product cannot overflow. Over-length is
       ERR_BUNDLE_MALFORMED and never ERR_TRAILING_BYTES — 7105 is for state blobs alone
       (§10.5, §19.4). */
    NSUInteger expectedLength =
        (NSUInteger)kIRLenBundlePrefix + ((NSUInteger)kIRLenBundleOPKEntry * (NSUInteger)opkCount);

    if (reader.count != expectedLength) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* ---- Structural decode. Every read below sits at a compile-time constant offset inside a
            length the gate has already pinned exactly, so none of them can fail; the checks are
            kept so that a future layout change cannot turn a short read into a silent zero. ---- */
    if (![reader seekToOffset:kIROffBundleIdentitySigning]) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    NSData *signingKeyBytes = [reader readDataOfLength:kIRLenEd25519Public];
    NSData *agreementKeyBytes = [reader readDataOfLength:kIRLenX25519Public];
    NSData *bindingBytes = [reader readDataOfLength:kIRLenEd25519Signature];

    uint32_t spkId = 0;
    BOOL readSpkId = [reader readUInt32BE:&spkId];

    NSData *signedPreKeyBytes = [reader readDataOfLength:kIRLenX25519Public];

    uint64_t notBeforeS = 0;
    uint64_t notAfterS = 0;
    BOOL readWindow = [reader readUInt64BE:&notBeforeS] && [reader readUInt64BE:&notAfterS];

    NSData *signedPreKeySignatureBytes = [reader readDataOfLength:kIRLenEd25519Signature];

    uint16_t sequentialOPKCount = 0;
    BOOL readOPKCount = [reader readUInt16BE:&sequentialOPKCount];

    if (signingKeyBytes == nil || agreementKeyBytes == nil || bindingBytes == nil ||
        !readSpkId || signedPreKeyBytes == nil || !readWindow ||
        signedPreKeySignatureBytes == nil || !readOPKCount ||
        sequentialOPKCount != opkCount) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* §5.3 rule 2 covers IK^d, SPK and every OPK — NOT IK^s. §4.4 checks 1–2 are RFC 7748
       u-coordinate rules, and bit 255 of an Ed25519 public key is the sign of x (RFC 8032 §5.1.2),
       set in roughly half of all valid keys. */
    IREd25519Public *signingKey = [IREd25519Public fromData:signingKeyBytes error:NULL];
    IREd25519Signature *binding = [IREd25519Signature fromData:bindingBytes error:NULL];
    IREd25519Signature *signedPreKeySignature =
        [IREd25519Signature fromData:signedPreKeySignatureBytes error:NULL];

    if (signingKey == nil || binding == nil || signedPreKeySignature == nil) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* ---- §5.3 rule 2: §4.4 checks 1–2 on IK^d, SPK, and EVERY OPK. ---------------------------
       This runs BEFORE rules 3 and 4. A parser that verifies the two signatures first, because
       they are the cheaper early exit, reports ERR_BAD_SIGNATURE where the specification requires
       ERR_INVALID_PUBLIC_KEY on a bundle that is wrong in both ways. The gate owns the code, so the
       constructors are called with a NULL error and the code is set here. */
    IRX25519Public *agreementKey = [IRX25519Public fromData:agreementKeyBytes error:NULL];
    if (agreementKey == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    IRX25519Public *signedPreKey = [IRX25519Public fromData:signedPreKeyBytes error:NULL];
    if (signedPreKey == nil) {
        IRSetError(error, IRErrorInvalidPublicKey);
        return nil;
    }

    NSMutableArray<IRPreKeyBundleOPKEntry *> *opkEntries =
        [NSMutableArray arrayWithCapacity:(NSUInteger)opkCount];

    for (NSUInteger index = 0; index < (NSUInteger)opkCount; index++) {
        uint32_t opkId = 0;
        if (![reader readUInt32BE:&opkId]) {
            IRSetError(error, IRErrorBundleMalformed);
            return nil;
        }

        NSData *opkBytes = [reader readDataOfLength:kIRLenX25519Public];
        if (opkBytes == nil) {
            IRSetError(error, IRErrorBundleMalformed);
            return nil;
        }

        IRX25519Public *opk = [IRX25519Public fromData:opkBytes error:NULL];
        if (opk == nil) {
            IRSetError(error, IRErrorInvalidPublicKey);
            return nil;
        }

        IRPreKeyBundleOPKEntry *entry = [IRPreKeyBundleOPKEntry entryWithOpkId:opkId
                                                                    publicKey:opk
                                                                        error:error];
        if (entry == nil) {
            return nil;
        }

        [opkEntries addObject:entry];
    }

    /* Step 5 pinned the length exactly, so the cursor must now sit on the final byte. */
    if (![reader atEnd]) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    IRIdentityKeyPair *identityKeyPair = [IRIdentityKeyPair pairWithSigningKey:signingKey
                                                                 agreementKey:agreementKey
                                                                        error:error];
    if (identityKeyPair == nil) {
        return nil;
    }

    /* ---- §5.3 rule 3: IKB. The verifying constructor IS the check (§5.5). -------------------- */
    IRPublicIdentity *identity = [IRPublicIdentity identityWithKeyPair:identityKeyPair
                                                              binding:binding
                                                             provider:provider
                                                                error:error];
    if (identity == nil) {
        return nil;
    }

    /* ---- §5.3 rule 4: SPK_SIG. ---------------------------------------------------------------
       v3 did not merely skip this check: IRTripleDHService.m:66-68 RE-SIGNED the peer's prekey with
       the local identity key, destroying the evidence by overwriting the peer's signature with a
       locally manufactured one that later code would find "valid". §5.3 deletes that code. */
    NSData *spkSignMessage = IRSPKSignMessage(identityKeyPair,
                                              spkId,
                                              signedPreKey,
                                              notBeforeS,
                                              notAfterS,
                                              error);
    if (spkSignMessage == nil) {
        return nil;
    }

    if (![provider ed25519VerifySignature:signedPreKeySignature
                                ofMessage:spkSignMessage
                                publicKey:signingKey]) {
        IRSetError(error, IRErrorBadSignature);
        return nil;
    }

    return [[self alloc] initWithIdentity:identity
                                    spkId:spkId
                             signedPreKey:signedPreKey
                               notBeforeS:notBeforeS
                                notAfterS:notAfterS
                    signedPreKeySignature:signedPreKeySignature
                               opkEntries:opkEntries
                              encodedData:data];
}

- (instancetype _Nonnull)initWithIdentity:(IRPublicIdentity * _Nonnull)identity
                                    spkId:(uint32_t)spkId
                             signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                               notBeforeS:(uint64_t)notBeforeS
                                notAfterS:(uint64_t)notAfterS
                    signedPreKeySignature:(IREd25519Signature * _Nonnull)signedPreKeySignature
                               opkEntries:(NSArray<IRPreKeyBundleOPKEntry *> * _Nonnull)opkEntries
                              encodedData:(NSData * _Nonnull)encodedData {
    self = [super init];
    if (self == nil) {
        return self;
    }

    _identity = identity;
    _spkId = spkId;
    _signedPreKey = signedPreKey;
    _notBeforeS = notBeforeS;
    _notAfterS = notAfterS;
    _signedPreKeySignature = signedPreKeySignature;
    _opkEntries = [opkEntries copy];
    _encodedData = [encodedData copy];

    return self;
}

#pragma mark - §5.3 rules 5–6

- (BOOL)validateValidityWindowAtUnixSeconds:(uint64_t)nowS
                                      error:(NSError * _Nullable * _Nullable)error {
    /* Rule 5 — the window is half-open: `not_before <= now < not_after`. */
    if (nowS < _notBeforeS || nowS >= _notAfterS) {
        IRSetError(error, IRErrorPreKeyExpired);
        return NO;
    }

    /* Rule 6 — the cap. Rule 5 passing implies `not_before < not_after`, so the unsigned difference
       below cannot wrap; the explicit guard states that invariant rather than relying on it. */
    if (_notAfterS < _notBeforeS ||
        (_notAfterS - _notBeforeS) > (uint64_t)kIRMaxSPKValiditySeconds) {
        IRSetError(error, IRErrorPreKeyExpired);
        return NO;
    }

    return YES;
}

#pragma mark - Encoding — §5.4

+ (NSData * _Nullable)serializeWithIdentity:(IRPublicIdentity * _Nonnull)identity
                         signedPreKeyRecord:(IRSignedPreKeyRecord * _Nonnull)signedPreKeyRecord
                       oneTimePreKeyRecords:(NSArray<IROneTimePreKeyRecord *> * _Nonnull)opks
                                      error:(NSError * _Nullable * _Nullable)error {
    if (signedPreKeyRecord == nil) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    NSMutableArray<IRPreKeyBundleOPKEntry *> *entries =
        [NSMutableArray arrayWithCapacity:opks.count];

    for (IROneTimePreKeyRecord *record in opks) {
        /* Only the id and the PUBLIC half are published. The record's creation timestamp is
           responder-local and MUST NOT reach the wire (§5.3): the entry is 36 bytes and the
           `251 + 36 * opk_count` rule depends on it. */
        IRPreKeyBundleOPKEntry *entry =
            [IRPreKeyBundleOPKEntry entryWithOpkId:record.opkId
                                         publicKey:record.keyPair.publicKey
                                             error:error];
        if (entry == nil) {
            return nil;
        }

        [entries addObject:entry];
    }

    return [self serializeWithIdentity:identity
                                 spkId:signedPreKeyRecord.spkId
                          signedPreKey:signedPreKeyRecord.keyPair.publicKey
                            notBeforeS:signedPreKeyRecord.notBeforeS
                             notAfterS:signedPreKeyRecord.notAfterS
                 signedPreKeySignature:signedPreKeyRecord.signature
                            opkEntries:entries
                                 error:error];
}

+ (NSData * _Nullable)serializeWithIdentity:(IRPublicIdentity * _Nonnull)identity
                                      spkId:(uint32_t)spkId
                               signedPreKey:(IRX25519Public * _Nonnull)signedPreKey
                                 notBeforeS:(uint64_t)notBeforeS
                                  notAfterS:(uint64_t)notAfterS
                      signedPreKeySignature:(IREd25519Signature * _Nonnull)signedPreKeySignature
                                 opkEntries:(NSArray<IRPreKeyBundleOPKEntry *> * _Nonnull)opkEntries
                                      error:(NSError * _Nullable * _Nullable)error {
    if (identity == nil || signedPreKey == nil || signedPreKeySignature == nil) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    /* A conformant encoder never emits a bundle §10.3 step 4 would reject. */
    if (opkEntries.count > (NSUInteger)kIRMaxBundleOPKCount) {
        IRSetError(error, IRErrorBundleMalformed);
        return nil;
    }

    NSUInteger expectedLength =
        (NSUInteger)kIRLenBundlePrefix + ((NSUInteger)kIRLenBundleOPKEntry * opkEntries.count);

    IRByteWriter *writer = [[IRByteWriter alloc] initWithCapacity:expectedLength];
    [writer appendBytes:kIRBundleMagic length:kIRLenMagic];
    [writer appendUInt8:(uint8_t)kIRProtocolVersion];
    [writer appendData:identity.signingKey.data];
    [writer appendData:identity.agreementKey.data];
    [writer appendData:identity.binding.data];
    [writer appendUInt32BE:spkId];
    [writer appendData:signedPreKey.data];
    [writer appendUInt64BE:notBeforeS];
    [writer appendUInt64BE:notAfterS];
    [writer appendData:signedPreKeySignature.data];
    [writer appendUInt16BE:(uint16_t)opkEntries.count];

    for (IRPreKeyBundleOPKEntry *entry in opkEntries) {
        [writer appendUInt32BE:entry.opkId];
        [writer appendData:entry.publicKey.data];
    }

    return [writer finishExpectingLength:expectedLength
                       mismatchErrorCode:IRErrorBundleMalformed
                                   error:error];
}

- (NSData * _Nullable)serializedData:(NSError * _Nullable * _Nullable)error {
    return [[self class] serializeWithIdentity:_identity
                                         spkId:_spkId
                                  signedPreKey:_signedPreKey
                                    notBeforeS:_notBeforeS
                                     notAfterS:_notAfterS
                         signedPreKeySignature:_signedPreKeySignature
                                    opkEntries:_opkEntries
                                         error:error];
}

#pragma mark - Selection

- (IRPreKeyBundleOPKEntry * _Nullable)firstUsableOPKEntry {
    return _opkEntries.firstObject;
}

- (NSString * _Nonnull)description {
    return [NSString stringWithFormat:
            @"<%@: %p; identity = %@; spk_id = %u; window = [%llu, %llu); opk_count = %lu>",
            NSStringFromClass([self class]), (void *)self, _identity.keyPair, _spkId,
            (unsigned long long)_notBeforeS, (unsigned long long)_notAfterS,
            (unsigned long)_opkEntries.count];
}

@end
