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
#import <nuntius/IRCryptoProvider.h>
#import <nuntius/IRErrors.h>
#import <nuntius/IRSecretBytes.h>

#pragma mark - IRSealKeyProvider

/**
 The device-bound key seam — SPEC §12.3, §5.6.

 The host supplies 32 bytes and nothing else; the library performs the AEAD and owns the plaintext.
 That split is deliberate: §12.3 fixes the construction (ChaCha20-Poly1305, fresh random 12-byte
 nonce stored alongside, key never derived from the contents) and leaves only keystore selection,
 rotation and device-migration behaviour to the host, which is exactly the boundary between what
 must be identical across four ports and what cannot be.

 `label` names the store being sealed, not a key derivation input. A provider MUST return the SAME
 key for the same label across launches, and SHOULD return different keys for different labels —
 the labels in use are `IRSealedStoreLabelSession` and `IRSealedStoreLabelPreKeys`. The label is
 also bound into the AEAD's associated data, so a sealed prekey store cannot be substituted for a
 sealed session blob even under a single key.
 */
@protocol IRSealKeyProvider <NSObject>

/// Exactly 32 bytes. Returning a shorter or longer secret is IRErrorStateCorrupt at the call site.
- (IRSecretBytes * _Nullable)sealKeyForLabel:(NSString * _Nonnull)label
                                       error:(NSError * _Nullable * _Nullable)error;

@end

/// §12.3's label for the session state blob (§12.1).
extern NSString * _Nonnull const IRSealedStoreLabelSession;

/// §5.6's label for the prekey and identity store.
extern NSString * _Nonnull const IRSealedStoreLabelPreKeys;

#pragma mark - Key providers

/**
 §12.3 / §5.6 on Apple platforms — Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
 `kSecAttrSynchronizable = false`.

 Generates a 32-byte key on first use and stores it; every later lookup returns the same key.
 `ThisDeviceOnly` is what excludes it from iCloud Keychain and from encrypted device backups, which
 is the property §5.6 relies on: a backup image that yielded the at-rest key would hand over
 `SPK_B_priv` and every unconsumed OPK, and §5.6 spells out that this collapses the forward secrecy
 §1.2 claims.

 NOT EXERCISED BY THIS REPOSITORY'S TEST SUITE. Keychain access from a simulator test bundle
 without a host application fails with `errSecMissingEntitlement` (-34018) for reasons that have
 nothing to do with this code, so the specs use IRInMemorySealKeyProvider and a host integrating
 this framework SHOULD verify the Keychain path on a device before shipping.

 ONE RESIDUE IS ACKNOWLEDGED RATHER THAN HIDDEN. `SecItemCopyMatching` returns the key in a
 CFData/NSData the caller cannot wipe; the bytes are copied into an IRSecretBytes and the NSData is
 released, leaving a copy in freed heap. §13.3 forbids the alternative — scrubbing an NSData's
 backing store through a const pointer — so this is a platform-API limitation of the same kind
 §17.1 records for the JVM, not a choice.
 */
@interface IRKeychainSealKeyProvider : NSObject <IRSealKeyProvider>

/// `service` scopes the Keychain items; pass a value unique to the application. The label becomes
/// the account, so one service holds one item per label.
+ (instancetype _Nonnull)providerWithService:(NSString * _Nonnull)service;

/// The `kSecAttrService` value in use.
@property (nonatomic, copy, readonly) NSString * _Nonnull service;

/// Removes the stored key for `label`. Destroys access to everything sealed under it — the sealed
/// data becomes permanently unopenable, which is the intended effect of an application-data erase.
- (BOOL)deleteKeyForLabel:(NSString * _Nonnull)label
                    error:(NSError * _Nullable * _Nullable)error;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

/**
 A key provider that holds its keys in memory — for the conformance suite and for tests.

 NOT A PRODUCTION PROVIDER, and the reason is the whole point of §12.3: the key vanishes with the
 process, so anything sealed under it is unopenable after a restart, and while the process lives
 the key sits in ordinary memory rather than in a keystore. It exists so that a test can seal and
 open without a Keychain entitlement.
 */
@interface IRInMemorySealKeyProvider : NSObject <IRSealKeyProvider>

/// Generates keys lazily, one per label, from the provider's CSPRNG.
+ (instancetype _Nullable)providerWithCryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider
                                               error:(NSError * _Nullable * _Nullable)error;

/// A provider pinned to one key for every label. For a vector that must be reproducible.
+ (instancetype _Nullable)providerWithFixedKey:(IRSecretBytes * _Nonnull)key
                                         error:(NSError * _Nullable * _Nullable)error;

/// §13.3 — wipes every key held.
- (void)zeroizeAll;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRSealedStore

/**
 §12.3's at-rest construction, and the only place in this framework that performs it.

 "The blob MUST NOT be persisted in plaintext. Seal it with ChaCha20-Poly1305 under a device-bound
 key from the platform keystore, with a fresh random 12-byte nonce stored alongside... The at-rest
 key MUST NOT be derived from the state itself."

 THE CONTAINER LAYOUT BELOW IS NOT NORMATIVE AND MUST NOT BE TREATED AS WIRE FORMAT. §12.3 says so
 directly — "only the plaintext layout is normative", and keystore selection, rotation and
 device-migration behaviour are deliberately outside the byte-compatible surface. No peer ever
 observes these bytes and no port has to reproduce them. It is written down only so that a future
 revision of THIS implementation can change it deliberately:

     +0   4    magic  "NTSL"          non-normative, and deliberately not in §18's table
     +4   1    container format 0x01
     +5   12   nonce                  fresh from the CSPRNG for every seal (§8.3's rule, reused)
     +17  n+16 ciphertext ‖ tag

     AD = magic ‖ container format ‖ UTF-8(label)

 BINDING THE LABEL INTO THE AD is what stops a sealed prekey store being substituted for a sealed
 session blob. Without it, a host whose key provider returns one key for every label would accept
 either file in either slot, and the failure would be a confused-deputy rather than an
 authentication error.

 A FRESH NONCE PER SEAL, NEVER A COUNTER. Same reasoning as §8.3: a derived or counted nonce makes
 (key, nonce) reuse the consequence of a rollback, and reuse under ChaCha20-Poly1305 discloses the
 keystream XOR and leaks the Poly1305 one-time key, permitting forgery. Rewriting a session blob
 after every message means many seals under one long-lived key, so this matters more here than on
 the message path.
 */
@interface IRSealedStore : NSObject

+ (instancetype _Nullable)storeWithKeyProvider:(id<IRSealKeyProvider> _Nonnull)keyProvider
                                cryptoProvider:(id<IRCryptoProvider> _Nonnull)cryptoProvider
                                         error:(NSError * _Nullable * _Nullable)error;

@property (nonatomic, strong, readonly) id<IRSealKeyProvider> _Nonnull keyProvider;
@property (nonatomic, strong, readonly) id<IRCryptoProvider> _Nonnull cryptoProvider;

/**
 Seals `plaintext` under the key for `label`.

 DOES NOT ZEROIZE `plaintext`. Every layer of this framework leaves its arguments alone, and
 §13.3's "serialized state buffer — after sealing" belongs to whoever built the buffer.
 IRSealedSessionStore and IRSealedPreKeyStore both build and wipe their own; a caller doing it by
 hand MUST do the same.
 */
- (NSData * _Nullable)sealSecret:(IRSecretBytes * _Nonnull)plaintext
                           label:(NSString * _Nonnull)label
                           error:(NSError * _Nullable * _Nullable)error;

/**
 Opens a container produced by -sealSecret:label:error: under the SAME label.

 A tampered container, a wrong label, or a wrong key are all IRErrorAEADAuthFailed — one code, no
 oracle, and nothing about which of the three it was. `guarded` selects `sodium_malloc` for the
 result.
 */
- (IRSecretBytes * _Nullable)openSealed:(NSData * _Nonnull)sealed
                                  label:(NSString * _Nonnull)label
                                guarded:(BOOL)guarded
                                  error:(NSError * _Nullable * _Nullable)error;

/// Container overhead in bytes: `sealed.length - plaintext.length`. 33 = 4 + 1 + 12 + 16.
+ (NSUInteger)containerOverhead;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

#pragma mark - IRRollbackTripwire

/**
 §12.5's rollback tripwire.

 "`send_counter` is a uint64 incremented on EVERY successful RatchetEncrypt, persisted before the
 message is emitted. An implementation SHOULD additionally record the last observed `send_counter`
 in storage that is EXCLUDED FROM APPLICATION BACKUPS... On state load, if the blob's
 `send_counter` is less than the recorded value, the state has been rolled back."

 A PROTOCOL RATHER THAN A CLASS, because the storage §12.5 asks for is storage the library cannot
 verify (§17.2), and because the requirement is a SHOULD. A host that cannot provide
 backup-excluded storage should say so with IRDisabledRollbackTripwire rather than silently get a
 tripwire that a restore also rolls back.

 THIS IS DEFENCE IN DEPTH, NOT THE PRIMARY MITIGATION. §12.5 and §8.3 both say so: the random nonce
 is what makes a missed rollback survivable — a repeated plaintext rather than a keystream
 disclosure — and a sufficiently privileged local adversary can roll back the state and the
 tripwire together.
 */
@protocol IRRollbackTripwire <NSObject>

/**
 Reads the highest `send_counter` ever recorded for this session into `outSendCounter`.

 Returns YES on a successful read. `*outSendCounter == 0` then means "no record", which disables
 the comparison for that session, since no blob can carry a counter below 0.

 Returns NO when the backing store could not be READ AT ALL — which is NOT the same fact as "no
 record", and MUST NOT be reported as 0.

 WHY THIS IS A BOOL AND NOT A BARE uint64_t. It used to be a bare uint64_t, and every failing
 read returned 0. §12.5 mandates `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, and that is
 precisely the accessibility class that returns errSecInteractionNotAllowed (-25308) after a reboot
 with no unlock, and errSecMissingEntitlement (-34018) after a keychain-group or provisioning
 change. Both are transient, and the second is attacker-influenceable — a forced reboot is enough.
 With 0 as the answer, `state.sendCounter < 0` is false for every session, so an attacker who has
 restored an old backup gets that stale state indexed and encryptable while -hasRollbackForHandshakeId:
 reports NO. §12.5's entire mechanism would be silently disabled with no log, no error, and nothing
 to distinguish it from a clean load. It was the one Sec* return value in this framework whose
 failure path failed OPEN; §13.2 requires every return value be checked, and everything else here
 fails closed with IRErrorStateCorrupt.

 A FAILED READ MUST BE TREATED AS ROLLED BACK by callers, not as "no record" — see
 -[IRSealedSessionStore loadAtTimeMs:error:]. Refusing to load a session that is probably fine is
 recoverable (the peer's next handshake replaces it); loading one that was probably rolled back is
 not.

 Note that DECLINING the tripwire is a successful read, not a failure: IRDisabledRollbackTripwire
 returns YES with 0. Opting out under §12.5's SHOULD must not make every session unloadable.
 */
- (BOOL)lastObservedSendCounter:(uint64_t * _Nonnull)outSendCounter
                 forHandshakeId:(NSData * _Nonnull)handshakeId
                          error:(NSError * _Nullable * _Nullable)error;

/// Records a new high-water mark. MUST be monotonic: a lower value is ignored, not written, or a
/// restored-then-advanced session would lower its own tripwire.
- (BOOL)recordSendCounter:(uint64_t)sendCounter
           forHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error;

/// Drops the record for a torn-down session. Its `handshake_id` cannot recur — it embeds `EK_A`
/// (§11.1) — so retaining the entry would leak storage for the life of the installation.
- (BOOL)forgetHandshakeId:(NSData * _Nonnull)handshakeId
                    error:(NSError * _Nullable * _Nullable)error;

@end

/**
 §12.5 over the Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and no iCloud sync —
 which is what "excluded from application backups" means on Apple platforms.

 Carries the same simulator caveat as IRKeychainSealKeyProvider: not exercised by this repository's
 tests, and worth verifying on a device.
 */
@interface IRKeychainRollbackTripwire : NSObject <IRRollbackTripwire>

+ (instancetype _Nonnull)tripwireWithService:(NSString * _Nonnull)service;

@property (nonatomic, copy, readonly) NSString * _Nonnull service;

- (instancetype _Nonnull)init NS_UNAVAILABLE;
+ (instancetype _Nonnull)new NS_UNAVAILABLE;

@end

/**
 An explicit opt-out. Every read returns 0 and every write succeeds without storing anything, so
 §12.5's comparison never fires.

 EXPLICIT BECAUSE §12.5 IS A SHOULD. A host with no backup-excluded storage has to choose between
 no tripwire and a tripwire that a restore rolls back with the state — and the second is worse than
 the first, because it looks like protection. Naming the choice in the object graph is what keeps
 it a decision rather than an omission.
 */
@interface IRDisabledRollbackTripwire : NSObject <IRRollbackTripwire>

+ (instancetype _Nonnull)tripwire;

@end

/// §12.5 in memory — for tests. Provides no rollback protection whatsoever across a restart, since
/// it does not survive one.
@interface IRInMemoryRollbackTripwire : NSObject <IRRollbackTripwire>

+ (instancetype _Nonnull)tripwire;

/// Number of sessions with a recorded high-water mark.
@property (nonatomic, readonly) NSUInteger recordCount;

@end
