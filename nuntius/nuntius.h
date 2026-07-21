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

#import <UIKit/UIKit.h>

FOUNDATION_EXPORT double nuntiusVersionNumber;
FOUNDATION_EXPORT const unsigned char nuntiusVersionString[];

// ---------------------------------------------------------------------------
// v4 protocol (SPEC.md). These are the supported interfaces.
// ---------------------------------------------------------------------------

//Core
#import <nuntius/IRProtocolConstants.h>
#import <nuntius/IRErrors.h>
#import <nuntius/IRSodium.h>
#import <nuntius/IRSecretBytes.h>
#import <nuntius/IREnvironment.h>

//Keys
#import <nuntius/IRKeyTypes.h>
#import <nuntius/IRKeyPairs.h>

//Crypto — the seam. Protocol layers hold an id<IRCryptoProvider> and never call a primitive
//directly; this is where a platform backend is swapped.
#import <nuntius/IRCryptoProvider.h>
#import <nuntius/IRSodiumCryptoProvider.h>

//Identity, prekeys and the bundle. IRPublicIdentity is the INGEST type: its only constructor
//verifies IKB, so §5.5's "verified on every identity ingest" holds by construction.
#import <nuntius/IRPublicIdentity.h>
#import <nuntius/IRIdentity.h>
#import <nuntius/IRPreKeyRecords.h>
#import <nuntius/IRPreKeyBundle.h>
#import <nuntius/IRPreKeyStore.h>
#import <nuntius/IRInMemoryPreKeyStore.h>

//At-rest protection. IRSealedStore is the ONLY place §12.3's construction is performed, and the
//two protocols are the host's seams: where the device-bound key comes from, and where §12.5's
//backup-excluded counter lives.
#import <nuntius/IRSealedStore.h>

//Session lifecycle. §11.1's two indices, §11.1.1's one-live-session-per-peer collapse, and
//§11.4's tombstones. IRInMemorySessionStore is for the conformance vectors;
//IRSealedSessionStore is the production one, over §12.1 blobs sealed per §12.3.
#import <nuntius/IRSession.h>
#import <nuntius/IRSessionStore.h>
#import <nuntius/IRInMemorySessionStore.h>
#import <nuntius/IRSealedSessionStore.h>

//The consumer API. §10.7's fourteen steps and §11.2's three checks live here because they are the
//two orderings no lower layer can enforce — neither sees both the prekey store and the session
//store. The receive path is split in two, and the split IS §11.5.
#import <nuntius/IRMessenger.h>

// ---------------------------------------------------------------------------
// v3 IS GONE. IREncryptionService, IRTripleDHService, IRDoubleRatchetService,
// IRCurve25519KeyPair, IRRatchetHeader, IRAEADInfo and IRConstants were DELETED
// — not deprecated, not soft-landed — in the L11 cleanup.
//
// Deletion rather than deprecation is what SPEC §3.3 requires: "the following
// MUST NOT appear in any nuntius v4 implementation or port". A deprecated class
// still compiles crypto_kdf_derive_from_key, CCCrypt, CCHmac and the prehashed
// crypto_sign_init/_update/_final_create into the shipped binary, still links
// CommonCrypto, and still lets a consumer build a session with no security by
// autocompleting a name. §14's Mechanism column says "deleted, not fixed" for
// defects 5, 6 and 9 for the same reason: an unreachable defect beats a fixed
// one, and an absent file beats both.
//
// There is no v3 → v4 migration (§17.9) and no dual-stack mode (§10.6). A v4
// receiver rejects a message whose first byte is not 0x04 with
// ERR_UNSUPPORTED_VERSION. Existing identities must be re-registered: the
// identity key type itself changed (§4.1).
// ---------------------------------------------------------------------------
