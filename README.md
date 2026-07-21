# nuntius

**nuntius** is an iOS framework for end-to-end encrypted messaging. It implements the
**Extended Triple Diffie-Hellman (X3DH)** key agreement and the **Double Ratchet** — both written
from the published specification documents — on top of a vendored
[libsodium](https://github.com/jedisct1/libsodium) 1.0.22.

The current protocol is **v4**. Its normative definition is [`SPEC.md`](SPEC.md); this README is
orientation. Where the two disagree, `SPEC.md` is right and this file is wrong.

> **Status.** v4 is implemented and unit-tested, and it has **not** been externally reviewed or
> audited. See [Security posture](#security-posture) before you ship anything on it.

---

## Table of contents

- [What it does](#what-it-does)
- [The protocol in two stages](#the-protocol-in-two-stages)
- [v4 is a hard break from v3](#v4-is-a-hard-break-from-v3)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Production wiring](#production-wiring)
- [The specification, and the ports](#the-specification-and-the-ports)
- [Security posture](#security-posture)
- [Build, test, lint](#build-test-lint)
- [Repository layout](#repository-layout)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

Two parties exchange messages that only they can read, without ever being online at the same time.
The recipient publishes a **prekey bundle** once; the sender fetches it, derives a shared secret
against it, and sends. From then on every message carries fresh keys.

The primitives are fixed by `SPEC.md` §3.2 and are the same in every port:

| Purpose | Primitive |
| --- | --- |
| Key agreement | X25519 (RFC 7748), raw output — no hash wrapper |
| Signatures | Ed25519 (RFC 8032), **pure**, one-shot detached |
| Key derivation | HKDF-SHA256 (RFC 5869), Extract + Expand, everywhere |
| Authenticated encryption | ChaCha20-Poly1305, **IETF variant** (RFC 8439), 12-byte random nonce on the wire |
| Hashing | SHA-256 |

There is no BLAKE2b, no AES, no CommonCrypto, and no hand-rolled encrypt-then-MAC. Every one of
those was in v3 and every one of them is gone.

The public entry point is a single class, [`IRMessenger`](nuntius/IRMessenger.h). Everything below
it — the ratchet, the wire gates, the KDFs, the crypto seam — is internal to the framework or
exposed only as the seams a host has to fill: `IRSessionStore`, `IRPreKeyStore`,
`IRSealKeyProvider`, `IRRollbackTripwire`.

## The protocol in two stages

### Stage 1 — X3DH (`SPEC.md` §5, §6)

Asynchronous session establishment. Roles are fixed for the lifetime of a session and never swap:
**A** is the *initiator* (fetches a bundle, sends first), **B** is the *responder* (published the
bundle).

B publishes a bundle carrying its identity `(IK^s, IK^d)`, the identity binding signature `IKB`, a
signed prekey `SPK` with a validity window and its signature, and a batch of one-time prekeys.
A fetches it, verifies **both** signatures before performing any Diffie-Hellman, generates an
ephemeral `EK_A`, and computes up to four DH values:

```
DH1 = X25519(IK_A^d_priv, SPK_B)     authenticates A to B
DH2 = X25519(EK_A_priv,   IK_B^d)    authenticates B to A
DH3 = X25519(EK_A_priv,   SPK_B)     forward secrecy
DH4 = X25519(EK_A_priv,   OPK_B)     present only when a one-time prekey is used

IKM = F32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]                  128 bytes, or 160 with an OPK
SK  = HKDF-SHA256(salt = Z32, ikm = IKM,
                  info = "nuntius:X3DH:v4" ‖ TH, L = 32)
```

The responder computes the mirror image in the identical order. Every DH output is checked: an
all-zero result aborts the whole handshake, and no session is created and no one-time prekey is
consumed. `DH4` is **omitted, not zero-filled**, when no one-time prekey is used.

`TH` is a **transcript hash** over every public value the handshake used, in a canonical order. It
is folded into the HKDF `info`, which is what binds the derived key to the exact identities, prekeys
and flags that produced it. `EK_A_priv` is zeroized the moment `SK` exists.

A one-time prekey is consumed exactly once, and consumption is a hard requirement: an unknown or
already-consumed `opk_id` is rejected outright. There is deliberately no fallback to the three-DH
derivation, because that fallback is what would turn a replay defence into a downgrade.

### Stage 2 — Double Ratchet (`SPEC.md` §7, §8)

`SK` seeds the ratchet root key. Thereafter every message derives its own key from two interlocking
ratchets:

- a **symmetric ratchet** — each message advances a chain key by HMAC-SHA256, so a compromised
  message key says nothing about earlier ones (*forward secrecy*);
- a **Diffie-Hellman ratchet** — each direction change mixes a fresh X25519 exchange into the root
  chain, so a compromised session state heals once both sides have stepped (*post-compromise
  security*).

Out-of-order and delayed messages are handled by storing skipped message keys, bounded at
1000 skips per received message and 2000 stored keys per session, each with a 7-day TTL.

**Decrypt is atomic.** The ratchet step, chain advance, counter increment and skipped-key inserts
all happen on a snapshot that is committed only after Poly1305 authenticates. A message that fails
to authenticate mutates nothing — otherwise an unauthenticated packet could permanently
desynchronise a live session (`SPEC.md` §7.7).

### The wire

Two message types, both fully covered by the AEAD associated data, both parsed at compile-time
constant offsets:

| Type | Header | Minimum total | Purpose |
| --- | --- | --- | --- |
| `0x01` normal | 56 bytes | 72 bytes | ratchet message on an established session |
| `0x02` prekey | 225 bytes | 241 bytes | carries the X3DH prologue; opens a session |

**There is no length field anywhere in the format.** Header length is a constant selected by the
one-byte type field, and the ciphertext extent is derived by subtraction from the received length.
No offset, allocation size or bound is ever computed from a received byte.

## v4 is a hard break from v3

**There is no migration path, no dual-stack mode, and no in-band upgrade.** A v4 receiver rejects
any message whose first byte is not `0x04` with `ERR_UNSUPPORTED_VERSION` (`IRErrorUnsupportedVersion`,
7100). See `SPEC.md` §2, §10.6 and §17.9.

**Existing identities must be re-registered and existing sessions torn down**, because the identity
key type itself changed. v3 held one Ed25519 key pair and converted it to X25519 on demand. v4 holds
**two independently generated key pairs**:

```
IK^s   Ed25519   signing ONLY, never used for Diffie-Hellman
IK^d   X25519    ECDH ONLY,    never used for signing
```

The conversion trick is banned, for three independent reasons (`SPEC.md` §4.1): it has no JDK
equivalent at any version and CryptoKit models the two key kinds as deliberately unbridged types, so
keeping it would put hand-rolled curve arithmetic in two of four trusted computing bases; v3
discarded the conversion return values, feeding uninitialized stack buffers to ECDH; and using one
key pair for both a signature scheme and a key-agreement scheme is a documented cross-protocol
hazard.

The split creates a new obligation — something must attest that a given `IK^s` and `IK^d` belong to
the same identity — and the **identity binding signature** `IKB` discharges it. This has a
consequence applications must honour:

> **An identity in nuntius v4 *is* the pair `(IK^s, IK^d)`, not either key alone.** Applications MUST
> key identity lookup, contact registration, trust-store entries, pinning and any displayed safety
> number on the pair — or equivalently on `FP = SHA256("nuntius:FP:v4" ‖ IK^s ‖ IK^d)`. An
> application that keys on `IK^s` alone is not conformant: an attacker presenting a victim's genuine
> `IK^s` beside its own `IK^d` would be displayed as the victim. (`SPEC.md` §5.5 — required reading.)

The v3 classes were **deleted, not deprecated**: `IREncryptionService`, `IRTripleDHService`,
`IRDoubleRatchetService`, `IRCurve25519KeyPair`, `IRRatchetHeader`, `IRAEADInfo` and `IRConstants`
no longer exist, and the build-phase lint fails the build on the v3 type names. A deprecated class
still compiles the broken primitives into the shipped binary and still lets a consumer build an
insecure session by autocompleting a name.

Wire compatibility was already lost the moment the protocol became correct: fixing the KDF and the
key-type defects changes every derived key. `SPEC.md` §14 maps the thirteen confirmed v3 defects to
the sections that fix them, and §14.1 lists nine more found while the specification was being
written.

## Requirements

- **iOS 13.0+**. The umbrella header imports UIKit and the vendored libsodium XCFramework ships
  `ios-arm64_arm64e` and `ios-arm64_arm64e_x86_64-simulator` slices only — there is no macOS,
  watchOS or tvOS slice.
- Xcode with the iOS SDK.
- **No package-manager dependency on libsodium.** It is vendored in-tree at
  `nuntius/libsodium/Clibsodium.xcframework` (1.0.22) and that binary *is* the dependency. Do not add
  a second one.

CocoaPods support has been removed. `nuntius.podspec` is gone and `pod "nuntius"` no longer
describes this library.

## Installation

### Swift Package Manager

In Xcode: **File → Add Package Dependencies…**, then enter the repository URL and pick the `nuntius`
library product.

In a `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/ivRodriguezCA/nuntius.git", from: "1.0.0")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [.product(name: "nuntius", package: "nuntius")]
    )
]
```

### Dropping the project in

Drag `nuntius.xcodeproj` into your workspace, add the `nuntius` framework to your app target's
**Frameworks, Libraries, and Embedded Content**, and embed it. This route is what the test suite and
CI use, and it needs no package resolution.

### Importing

Objective-C:

```objc
#import <nuntius/nuntius.h>
```

Swift — the framework sets `DEFINES_MODULE`, so it imports as a module. Every failable API follows
the Cocoa error convention (`nil`/`NO` plus an `NSError **` out-parameter), so each one bridges into
Swift as a `throws` method:

```swift
import nuntius
```

## Usage

Alice is the **responder**: she registers, publishes a bundle, and waits. Bob is the **initiator**:
he fetches her bundle and sends first. The roles are fixed from then on, regardless of who speaks
next.

The example runs both sides in one process for brevity. In a real deployment the bundle travels
through your distribution server and the messages through your transport.

### 1. Register an identity, once per device

```objc
#import <nuntius/nuntius.h>

NSError *error = nil;

IRIdentity *aliceIdentity = [IRIdentity generate:&error];
IRIdentity *bobIdentity   = [IRIdentity generate:&error];
```

`+generate:` produces both key pairs, computes `IKB` over them, and **verifies the freshly produced
signature before returning**. That costs one Ed25519 verification per identity and buys a self-test
at the exact place a mis-wired signing API would otherwise stay hidden for months.

Persist `signingKeyPair`, `agreementKeyPair` and `binding`, and rehydrate with
`+identityWithSigningKeyPair:agreementKeyPair:binding:provider:error:`. `IKB` **must be stored, not
recomputed** — re-signing on restore would destroy the evidence the check exists to find.

### 2. Build a messenger per identity

```objc
IRMessenger *alice = [[IRMessenger alloc] initWithIdentity:aliceIdentity
                                               preKeyStore:[IRInMemoryPreKeyStore store]
                                              sessionStore:[IRInMemorySessionStore store]
                                                     error:&error];

IRMessenger *bob = [[IRMessenger alloc] initWithIdentity:bobIdentity
                                             preKeyStore:[IRInMemoryPreKeyStore store]
                                            sessionStore:[IRInMemorySessionStore store]
                                                   error:&error];
```

This convenience initializer builds a libsodium provider over the production environment. The
in-memory stores shown here are the reference implementations the conformance vectors run against —
**they are not production stores.** See [Production wiring](#production-wiring).

### 3. Alice publishes a prekey bundle

```objc
uint64_t nowS = (uint64_t)[[NSDate date] timeIntervalSince1970];

NSData *aliceBundle = [alice publishBundleWithSPKId:0x11223344
                                         notBeforeS:nowS
                                          notAfterS:nowS + 7776000   // 90d = MAX_SPK_VALIDITY_SECONDS
                                           opkCount:100
                                              error:&error];
// Upload aliceBundle to your distribution server.
```

The private halves stay in Alice's prekey store; only public components reach the wire. The result
is exactly `251 + 36 * opk_count` bytes.

> **The server hands out one one-time prekey at a time.** A bundle fetched *for a single handshake*
> must carry `opk_count` of 0 or 1; a fetching client that receives more uses only the first entry.
> The server is responsible for never issuing the same one-time prekey twice, and — per `SPEC.md`
> §17.3 — for never serving an OPK-less bundle, which is both replayable and the case in which
> forward secrecy against a compromised prekey store offers nothing.

### 4. Bob fetches the bundle and sends the first message

```objc
// bundleForOneHandshake: Alice's bundle as served, carrying 0 or 1 one-time prekeys.
IRSession *bobSession = [bob beginSessionWithBundleData:bundleForOneHandshake error:&error];

NSData *opener = [bob encrypt:[@"hello" dataUsingEncoding:NSUTF8StringEncoding]
                    inSession:bobSession
                        error:&error];
// `opener` is a type 0x02 prekey message. Send it.
```

`-beginSessionWithBundleData:error:` parses the bundle, runs the full verification gate — structure,
version, public-key validation, `IKB`, the signed-prekey signature, and the validity window against
the injected clock — then runs X3DH and initializes the ratchet. Any failure is a hard abort with a
specific error code; there is no "verify later" path.

The caller never chooses the message type. `session.sendsPreKeyMessages` is derived from the ratchet
state, and Bob keeps sending type `0x02` — re-emitting the *identical* X3DH prologue with an
incrementing `N` — until he successfully decrypts something from Alice.

### 5. Alice receives it

```objc
IRDecryptedMessage *atAlice = [alice decryptPreKeyMessage:opener error:&error];

IRSession *aliceSession = atAlice.session;   // ALWAYS use the returned handle from here on
NSString *text = [[NSString alloc] initWithData:atAlice.plaintext encoding:NSUTF8StringEncoding];
// atAlice.establishedNewSession == YES
```

Type `0x02` is **self-routing**: the handshake identifier is computed from the header, so no session
handle is needed and none is accepted.

`atAlice.session` is always the surviving session and is the handle to use from now on. If both
parties initiated at once, establishing this session may have collapsed another one with the same
peer — at most one live session per peer is permitted. Check `atAlice.tornDownHandshakeId` against
any handle you have cached for that peer and discard on a match; every operation on a torn-down
session fails with `IRErrorNoSession`. Do not branch on "a collapse occurred" alone: it is true on
both branches of the race while your obligation is the opposite on each.

### 6. Alice replies, Bob receives

```objc
NSData *reply = [alice encrypt:[@"hi back" dataUsingEncoding:NSUTF8StringEncoding]
                     inSession:aliceSession
                         error:&error];
// `reply` is a type 0x01 normal message.

IRDecryptedMessage *atBob = [bob decryptMessage:reply inSession:bobSession error:&error];
```

Type `0x01` is **not** self-routing, and the receive API is split in two on purpose. There is
deliberately no `-decrypt:error:` taking only a message.

- `-decryptMessage:inSession:error:` — you already resolved the handle.
- `-decryptMessage:fromPeerIdentityKeyPair:error:` — resolve it through the peer index instead.

**Three rules govern the second form** (`SPEC.md` §11.5):

1. The peer identity pair MUST come from a sender identity **your transport authenticated**, never
   from any field of the message. Nothing in a type `0x01` header is authenticated before
   decryption, so routing on header bytes would let an attacker choose which session absorbs a
   forgery. The library cannot check this for you; the parameter exists to make the obligation
   explicit.
2. An unresolvable peer or an absent handle is `IRErrorNoSession` — a specified protocol condition,
   not a programming error.
3. A message that fails under the selected session returns `IRErrorAEADAuthFailed` and is **never**
   retried against another. There is no loop over candidate sessions anywhere in this library, and
   there must not be one in yours.

### Routing bytes off the transport

Select an entry point rather than calling one at random and interpreting the result:

```objc
IRMessageType type = [IRMessenger messageTypeOfMessage:incoming error:&error];
switch (type) {
    case IRMessageTypePrekey:   // 0x02
        result = [messenger decryptPreKeyMessage:incoming error:&error];
        break;
    case IRMessageTypeNormal:   // 0x01
        result = [messenger decryptMessage:incoming inSession:session error:&error];
        break;
    default:                    // 0 — the demultiplex failed; `error` says why
        result = nil;
        break;
}
```

`+messageTypeOfMessage:error:` never decrypts, never resolves a session and takes no handle. It
returns `0` on failure with `error` set.

Calling the wrong entry point is `IRErrorWrongEntryPoint` (7125) — a diagnosable bug that a
conformant host never reaches, not a protocol condition. The helper checks the global length floor
and the version byte before it reads the type, so v3 traffic is rejected here as an unsupported
version rather than misreported as a truncation.

### Fingerprints

```objc
IRFingerprint *mine  = [alice fingerprint:&error];
IRFingerprint *peers = [aliceSession peerFingerprintWithProvider:alice.provider error:&error];
```

Display these side by side for out-of-band verification. Key your contact records on the fingerprint
or on the full identity pair — never on `IK^s` alone.

### Errors

Failure is `nil`/`NO` plus an `NSError **` out-parameter in domain `IRErrorDomain`. Codes run
7100–7125 and are enumerated in [`IRErrors.h`](nuntius/IRErrors.h) alongside the `ERR_*` names
`SPEC.md` §10.5 uses. The ones a host routinely handles:

| Code | Symbol | Meaning |
| --- | --- | --- |
| 7100 | `IRErrorUnsupportedVersion` | not a v4 message — v3 traffic lands here |
| 7108 | `IRErrorBadSignature` | `IKB` or the signed-prekey signature did not verify |
| 7109 | `IRErrorAEADAuthFailed` | tampered, truncated, or wrong session — nothing mutated |
| 7114 | `IRErrorUnknownPreKeyId` | unknown or already-consumed prekey id |
| 7116 | `IRErrorPreKeyExpired` | bundle validity window failed |
| 7120 | `IRErrorNoSession` | no handle, unresolvable peer, or a stale handle |
| 7124 | `IRErrorStateRollback` | persisted state is behind the tripwire's high-water mark |
| 7125 | `IRErrorWrongEntryPoint` | message type does not match the method called |

Passing `nil` for a `_Nonnull` parameter is **not** in this taxonomy. It is a caller contract
violation and it fails fast rather than returning an error, because the alternative — silently
coercing it to empty — yields a well-formed, mutually agreed, cryptographically void session key
that no test vector can see (`SPEC.md` §13.4, §17.11).

### Threading

`IRMessenger`, `IRSession` and the session stores are **not thread-safe**, deliberately. The
atomicity guarantee above is about *failure*, not about concurrency, and a lock here would give a
false sense of the second. A host that receives on more than one queue MUST serialize access to a
session and to its store: two concurrent decrypts against one session are two snapshots of the same
state, and whichever commits second silently discards the first.

(`IRInMemoryPreKeyStore` is the exception and does serialize internally, because a host may
plausibly publish a bundle on one queue while a message arrives on another and one-time prekey
consumption is a read-modify-write. That does not make the messenger above it safe to share.)

## Production wiring

The in-memory stores are the reference implementations that the conformance vectors run against.
Neither is sufficient on its own for shipping, and both reasons are worth naming rather than
implying.

**Sessions.** `IRSealedSessionStore` is the production store: the same routing rules over
fixed-layout state blobs, sealed at rest, with the rollback tripwire on the load path.

```objc
IRSodiumCryptoProvider *provider = [IRSodiumCryptoProvider productionProvider:&error];

IRSealedStore *sealedStore =
    [IRSealedStore storeWithKeyProvider:[IRKeychainSealKeyProvider providerWithService:@"com.example.app.nuntius"]
                         cryptoProvider:provider
                                  error:&error];

IRSealedSessionStore *sessions =
    [IRSealedSessionStore storeWithSealedStore:sealedStore
                                       storage:myDurableRecordStorage      // id<IRSessionRecordStorage>
                              rollbackTripwire:[IRKeychainRollbackTripwire tripwireWithService:@"com.example.app.nuntius"]
                                         error:&error];

[sessions loadAtTimeMs:nowMs error:&error];   // required before first use
```

`id<IRSessionRecordStorage>` is your key-value store — a directory, SQLite, Core Data, a server-side
blob. Every value handed to it is **already sealed**, so it never sees a plaintext blob and needs no
zeroization schedule of its own. Only `IRInMemorySessionRecordStorage` ships, on purpose: a
filesystem implementation would bake in choices (container location, file protection class,
migration, backup exclusion) that the specification leaves to you.

The tripwire argument is required, and `IRDisabledRollbackTripwire` is how you decline it. Declining
is legitimate — the tripwire is a SHOULD — but it has to be said out loud, because the alternative
failure mode is a tripwire stored in a backup that a restore rolls back along with the state, which
looks like protection and is not.

**Prekeys.** `IRInMemoryPreKeyStore` is **not sealed**, and `SPEC.md` §5.6 makes sealing this store
normative rather than advisory. It holds every input to every future handshake: an adversary who
images the device, goes passive, and later records a handshake computes DH1, DH2 and DH3 directly
from the signed-prekey and identity privates, and needs only DH4 — whose private half is the
unconsumed one-time prekey sitting in this same store. A session blob compromises one session; this
store compromises all of them.

No sealed prekey store ships today. A production host subclasses `IRInMemoryPreKeyStore`, overrides
`-commitDurably:`, and layers durable sealed storage on it — on Apple platforms, Keychain with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, no iCloud sync, and excluded from backups. The
override MUST NOT return until the deletion has reached stable storage: the plaintext is returned to
the caller immediately afterwards, and a crash in between reopens the replay window that one-time
prekey consumption exists to close.

Also schedule maintenance. `-pruneExpiredAtUnixSeconds:error:` on the prekey store and
`-pruneAtTimeMs:error:` on the session store bound key lifetimes, tombstone retention and
skipped-key TTLs. Both bounds are also enforced at the point of use, so calling them on any schedule
is safe — including never — but a store left unpruned grows.

## The specification, and the ports

[`SPEC.md`](SPEC.md) is the normative contract, and it is normative for **four** implementations —
this Objective-C reference, plus Java, Kotlin and Swift ports being written against the document
rather than against this code, each in its own repository. All four must interoperate byte-for-byte:
a message encrypted by one has to decrypt in the others.

That is why the specification is written the way it is. Every structure with a byte-exact layout has
one; every ordered validation gate states its order and says which rule is load-bearing and why;
every KDF info string, label literal and derived length is tabulated with its hex encoding in §18.
Any change to the wire format, the header layout or a KDF info string is a cross-repo breaking
change, not a local one.

**Test vectors are the interop contract**, not per-language unit tests. `SPEC.md` §15 specifies six
JSON files to live under `spec/vectors/` — `primitives.json`, `x3dh.json`, `ratchet.json`,
`wire.json`, `state.json`, `negative.json` — holding raw key material and expected bytes, frozen
once generated, with every clock read routed through one injectable source so the corpus has no
shelf life. **That corpus has not been generated yet**; today the coverage it specifies lives in the
XCTest suite, whose negative cases are named for the `NEG-*` vector ids of §15.4.

§16 is a per-platform trap catalogue: the same hostile bundle that Objective-C reads past silently
will *trap* in Swift `Data` subscripting and throw an unchecked `IndexOutOfBoundsException` on the
JVM. Three observable behaviours for the same bytes, in the one structure every implementation has
to parse for every other. §19 records the decisions taken under adversarial review, so that a future
reader does not silently reopen them.

## Security posture

### What the protocol defends against (`SPEC.md` §1.2)

- Passive observation of ciphertext.
- Active modification, insertion, reordering and replay — the Poly1305 tag covers the **full**
  header, including the version, type and flags bytes, so a tampered version byte is an
  authentication failure rather than a silent no-op.
- Man-in-the-middle at session setup — Ed25519 verification of the identity binding and the signed
  prekey is mandatory before any DH.
- Retroactive compromise of a long-term identity private key alone: DH3 and DH4 both stay out of
  reach, because `EK_A_priv` is zeroized as soon as `SK` exists.
- Compromise of session state at time *t* — earlier messages by forward secrecy, later messages by
  post-compromise security once the DH ratchet re-randomises the root chain.
- Replay of the initial handshake — one-time prekey consume-once plus a 7-day handshake tombstone
  cache, enforced rather than left to the implementer to infer.
- Malformed or hostile ciphertext — fixed-offset parsing, no wire-derived lengths, bounded skip and
  storage, explicit maximum sizes.
- Unauthenticated denial of service by desynchronising a live session — snapshot-and-commit.

### Deliberate non-goals and open risks (`SPEC.md` §17)

These are **stated, not solved**. Read them before you build on this.

- **The transcript-hash binding has not been externally reviewed** (§17.7). The claim that folding
  `TH` into the X3DH `info` is strictly stronger than v3's ECDH hash wrapper is *informal*. The
  construction closely resembles standard practice, but the exact composition — `TH` in `info`
  rather than in the IKM or in the AEAD associated data — should be reviewed by someone who did not
  write the specification before any of the four implementations ships. **No audit of this library
  has taken place.**
- **No header encryption** (§17.4). Ratchet public keys and the counters `N` and `PN` travel in the
  clear, so an observer can count messages and detect ratchet steps. The v4 format reserves no space
  to add it without a version bump.
- **No post-quantum component** (§17.5). X25519-only agreement is harvest-now-decrypt-later
  vulnerable. Adding a KEM would change the X3DH IKM and the bundle format; the version byte is the
  intended lever.
- **State rollback is mitigated, not solved** (§17.2). The random nonce makes rollback survivable
  rather than catastrophic and the tripwire detects the common case, but the tripwire depends on
  backup-excluded storage the library cannot verify, and a sufficiently privileged local adversary
  can roll back both. **Multi-device session sync is not supported**; an application that forks a
  session across devices is outside the model.
- **JVM zeroization is best-effort** (§17.1). `Arrays.fill` is not guaranteed against JIT dead-store
  elimination and a relocating GC may already have copied a `byte[]` before the wipe runs; there is
  no JVM equivalent of `sodium_malloc`'s guard pages. The Java and Kotlin ports are therefore
  strictly weaker than this one on that point, and are required to say so in their own READMEs
  rather than paper over it.
- **Replay of a no-OPK initial message** (§17.3). With `opk_flag == 0x00` nothing is consumed, so a
  captured prekey message can be replayed once the handshake tombstone ages out at 7 days — and,
  because a new session displaces an existing one with the same peer, that replay can also cost the
  messages in flight on the live session. X3DH's documented limitation in the no-OPK case; the
  mitigation is to never serve an OPK-less bundle.
- **Forward secrecy is bounded by prekey-store hygiene, not by the ratchet** (§17.10). If the
  identity *and* signed-prekey privates fall together — which one unsealed prekey store yields at
  once — DH4 is the only surviving term. Forward secrecy then holds **only** for handshakes that
  used a one-time prekey, and only if that private was actually erased. This is memory and storage
  hygiene; no test vector can enforce it.
- **Skipped-key DoS** (§17.6). A single crafted header can force up to 1000 HMAC-SHA256 derivations
  before rejection. The bound is generous for real out-of-order delivery and cheap to abuse on an
  unauthenticated, unrate-limited transport. It holds *per received message* only because trial
  decryption across sessions is forbidden.
- **Ed25519 verifier strictness differs across platforms** (§17.8). libsodium, SunEC/SunJCE and
  BouncyCastle disagree on cofactored verification and the canonical-`S` check. The blast radius is
  reduced by keeping signature bytes out of the transcript, so a divergence causes a clean
  `ERR_BAD_SIGNATURE` on one side rather than two peers computing different session keys. Each port
  must pin a provider.
- **Metadata, traffic analysis, message sizes, and endpoint compromise at the time of use** are all
  out of scope.
- **Identity distribution is out of scope.** This library specifies how to verify that a bundle is
  self-consistent and signed by a claimed identity key. It does not specify how a user learns that
  the identity key is the right one — that remains your trust-on-first-use, directory, or
  out-of-band fingerprint problem.

## Build, test, lint

```sh
xcodebuild -project nuntius.xcodeproj -scheme nuntius -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build

xcodebuild -project nuntius.xcodeproj -scheme nuntius -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
```

A single test class or case:

```sh
xcodebuild ... test -only-testing:nuntiusTests/IRRatchetSpec
xcodebuild ... test -only-testing:nuntiusTests/IRRatchetSpec/testMethodName
```

`.travis.yml` still pins `iPhone 7 / iOS 10.3.1` on `xcode8.3`; that simulator no longer exists, so
substitute a current `-destination` locally. Deployment target is iOS 13.0.

`tools/lint_banned_apis.py` runs as a build phase **before** Sources, so a violation stops the build
rather than shipping. It enforces `SPEC.md` §3.3's banned-API list — `crypto_kdf_derive_from_key`,
the BLAKE2b and `crypto_kx` families, the Ed25519↔X25519 conversions, the prehashed multi-part
signing API, the non-IETF ChaCha20-Poly1305 variant, XChaCha20-Poly1305, AES-256-GCM,
`NSKeyedArchiver`, CommonCrypto, and the deleted v3 class names — plus multi-byte pointer-cast reads,
elidable `NSParameterAssert`/`NSAssert`, a raw `*error =` outside `IRErrors.m`, §3.4's single
`crypto_sign_detached` call site, and §13.2's per-file `-Werror=unused-result`. Comments and string
literals are stripped before matching, so prose that names a banned API in order to warn about it is
fine — and that prose is load-bearing for the ports, so do not delete it to appease a grep.

`tools/pbxproj_tool.py` is the only supported way to register files, groups and script phases in
`project.pbxproj`. A missing `PBXSourcesBuildPhase` entry is a **silent no-op** — the file simply
never compiles — so never hand-edit the pbxproj, and always run
`plutil -lint nuntius.xcodeproj/project.pbxproj` after a mutation.

## Repository layout

```
SPEC.md                     the normative contract — start here
CLAUDE.md                   orientation for contributors; SPEC.md wins where they disagree
CHANGELOG.md
Package.swift               SwiftPM manifest (there is no podspec; CocoaPods support was removed)
include/nuntius -> ../nuntius
                            a relative symlink, and it is LOAD-BEARING. SwiftPM has no header map,
                            so `#import <nuntius/Foo.h>` only resolves if the single include
                            directory it passes contains a `nuntius/` directory. Deleting this as
                            redundant breaks `Package.swift` at graph load. See the long comment in
                            Package.swift for the three simpler layouts that were tried and why
                            each fails. The Xcode build does not use it.
nuntius/
  nuntius.h                 umbrella header
  IRMessenger.h/.m          the consumer API
  IRSession*, IRPreKey*,    identity, prekeys, session lifecycle
  IRIdentity, IRPublicIdentity
  IRX3DH, IRTranscript,     X3DH
  IRSessionAD
  IRRatchet*, IRSkippedKeyStore   Double Ratchet
  IRMessageHeader/Gate/Builder    wire format and the ordered gates
  IRCryptoProvider.h        the crypto seam — the protocol layers hold this, never a primitive
  IRSodiumCryptoProvider.m  the only file that calls libsodium
  IRSealedStore, IRSessionStateCodec   state serialization and at-rest sealing
  libsodium/                vendored Clibsodium.xcframework, 1.0.22
nuntiusTests/               XCTest, one *Spec.m per layer
tools/                      lint_banned_apis.py, pbxproj_tool.py
```

The layering is load-bearing, not cosmetic. Every protocol layer holds an `id<IRCryptoProvider>` and
never calls a primitive directly — that seam is where a platform crypto backend gets swapped, and
where the ports are expected to diverge in implementation but not in behaviour. The nominal key
types are the other half of it: an `IREd25519Public` is not an `IRX25519Public` and the compiler
enforces it, so the key-confusion class of v3 defects cannot be written.

## Contributing

Pull requests are welcome. Two constraints apply to any change that touches protocol behaviour:

1. If it changes the wire format, the header layout, a KDF info string or a derived length, it is a
   cross-repo breaking change and `SPEC.md` must change first.
2. Do not hand-roll cryptographic primitives. Bind to the vendored libsodium through
   `IRCryptoProvider`.

## License

MIT. See [`LICENSE`](LICENSE). Copyright © 2017 Ivan Rodriguez.

## Disclaimer

- The X3DH and Double Ratchet implementations here were developed from scratch against the published
  specification documents for those protocols. They share no source code with any existing library.
- This library has no relation to, and is not backed or supported by, the authors of the X3DH and
  Double Ratchet specifications.
- It has not been independently audited. See [Security posture](#security-posture).
