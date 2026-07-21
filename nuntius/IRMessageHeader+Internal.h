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

#import "IRMessageHeader.h"

/**
 The only constructors for IRMessageHeader — SPEC §9.1, §9.2.

 EXACTLY ONE CONSUMER: IRMessageGate.m. (IRMessageHeader.m also imports it, necessarily — it
 implements the category.) That is the whole mechanism behind "an unvalidated header value cannot
 exist". IRMessageHeader.h alone gives the rest of the framework a readable, immutable,
 already-checked value with no way to fabricate one, so the ratchet cannot be handed a header whose
 `N` was never bounded or whose `DHs_pub` was never encoding-checked.

 The grep that enforces it MUST anchor on the import line, not the bare filename — this comment
 names the file, and so does IRMessageHeader.h's, so a substring match reports four hits and the
 rule fails against its own documentation:

     grep -rn '^#import "IRMessageHeader+Internal.h"' nuntius/
         ->  IRMessageHeader.m   (the implementer)
             IRMessageGate.m     (the only consumer)

 Anything else in that list is a layering violation. The same anchoring applies to §3.3's
 `Clibsodium/sodium.h` rule for the same reason.

 Neither factory re-runs the ordered gates. They assert only the invariants a gate cannot express in
 its return type — field lengths, and the type `0x02` `opk_flag` / `opk_id` consistency — so that a
 gate which forgot a check produces a nil header rather than a plausible one. They are a backstop,
 not the gate.
 */
@interface IRMessageHeader (Internal)

/**
 §9.1 — a type `0x01` header. `headerBytes` MUST be the verbatim `message[0 .. 56)` slice (§8.5);
 it is not rebuilt from the other arguments and it is not checked against them, because the
 authority runs the other way: the fields were parsed OUT of these bytes.
 */
+ (instancetype _Nullable)type01HeaderWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                           ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                                    N:(uint32_t)N
                                                   PN:(uint32_t)PN
                                                nonce:(IRNonce * _Nonnull)nonce
                                                error:(NSError * _Nullable * _Nullable)error;

/**
 §9.2 — a type `0x02` header. `headerBytes` MUST be the verbatim `message[0 .. 225)` slice.

 THERE IS NO `PN:` PARAMETER, mirroring IRMessageBuilder. §9.2 fixes `PN` at zero for this type and
 §10.2 check 8 rejects anything else, so the value is not information the parser carries — making it
 unwritable is stronger than validating it, and -PN reads 0.

 `identityBinding` is stored UNVERIFIED (§10.7 step 3 / §11.2 own that). `handshakeId` is computed
 here via IRHandshakeIdentifier so §11.1's concatenation has one definition in the framework.
 */
+ (instancetype _Nullable)type02HeaderWithHeaderBytes:(NSData * _Nonnull)headerBytes
                                    initiatorIdentity:(IRIdentityKeyPair * _Nonnull)initiatorIdentity
                                      identityBinding:(IREd25519Signature * _Nonnull)identityBinding
                                      ephemeralPublic:(IRX25519Public * _Nonnull)ephemeralPublic
                                                spkId:(uint32_t)spkId
                                              opkFlag:(IROPKFlag)opkFlag
                                                opkId:(uint32_t)opkId
                                           ratchetKey:(IRX25519Public * _Nonnull)ratchetKey
                                                    N:(uint32_t)N
                                                nonce:(IRNonce * _Nonnull)nonce
                                                error:(NSError * _Nullable * _Nullable)error;

@end
