# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

nuntius is an iOS framework (Objective-C, MIT) implementing X3DH + Double Ratchet on libsodium. It is
the reference implementation for the Java/Kotlin/Swift ports in sibling directories.

**`SPEC.md` is the contract, and it is normative.** This file is orientation; where the two disagree,
`SPEC.md` wins and this file is the thing that is wrong. Every port is written against `SPEC.md`, not
against this code, and all four must interoperate byte-for-byte.

**The library is experimental, published for research and study, and not recommended for production
environments.** v4 is complete and unaudited — no external security review of the code or of the
specification — and `SPEC.md` §17 enumerates open risks and deliberate non-goals that are stated
rather than solved. That posture is not a reason to hold work to a lower standard; it is the reason
the standard is what it is, and it constrains how the project describes itself. Do not write
documentation, comments or commit messages that read as an endorsement for deployment. The README's
*Read this first* section is the canonical statement; keep new prose consistent with it.

## Protocol version

The tree implements **v4 only**. The v3 protocol was deleted, not deprecated — sources, tests,
headers, and every pbxproj reference. See `SPEC.md` §14 for the thirteen confirmed defects that made
v3 cryptographically broken, and §2 for what v4 changed.

There is no v3 → v4 migration and no dual-stack mode (§10.6, §17.9). A v4 receiver rejects a first
byte that is not `0x04` with `ERR_UNSUPPORTED_VERSION`. Existing identities must be re-registered:
the identity key type itself changed.

If you find a reference to `IREncryptionService`, `IRTripleDHService`, `IRDoubleRatchetService`,
`IRCurve25519KeyPair`, `IRRatchetHeader`, `IRAEADInfo`, or `IRConstants` outside a comment explaining
what v3 got wrong, it is a mistake. The banned-API lint fails the build on them.

## Build, test, lint

```sh
xcodebuild -project nuntius.xcodeproj -scheme nuntius -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
xcodebuild -project nuntius.xcodeproj -scheme nuntius -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test

# Single test class / case
xcodebuild ... test -only-testing:nuntiusTests/IRRatchetSpec
xcodebuild ... test -only-testing:nuntiusTests/IRRatchetSpec/testMethodName
```

Deployment target is iOS 13.0; substitute whichever `-destination` you have installed.

CI is `.github/workflows/ci.yml` (macOS runner): `tools/lint_banned_apis.py`, then the same
`xcodebuild test` against the newest available iPhone simulator — chosen at run time via
`xcrun simctl list devices available --json`, because the pinned `iPhone 7 / iOS 10.3.1 / xcode8.3`
destination in the deleted `.travis.yml` is exactly how that configuration stopped being runnable —
then `git diff --exit-code -- spec/vectors`, which fails if a run rewrote a frozen vector file.

libsodium ships **vendored as an XCFramework** at `nuntius/libsodium/Clibsodium.xcframework`
(1.0.22, iOS device + simulator). Include it as `#include <Clibsodium/sodium.h>`. Do not add a
package-manager dependency on libsodium — the vendored binary is the dependency.

### Tooling

- `tools/lint_banned_apis.py` — enforces `SPEC.md` §3.3's banned-API list, §3.4's single
  `crypto_sign_detached` call site, and §13.2's per-file `-Werror=unused-result`. Wired into the
  `nuntius` target as a build phase that runs **before** Sources, so a violation stops the build
  rather than shipping. Comments and string literals are stripped before matching, so prose that
  names a banned API in order to warn about it is fine — and that prose is load-bearing for the
  ports, so do not delete it to appease a grep.
- `tools/pbxproj_tool.py` — idempotent registration of files, groups, and script phases in
  `project.pbxproj`. **A missing `PBXSourcesBuildPhase` entry is a silent no-op, not an error**: the
  file simply never compiles. Never hand-edit the pbxproj; always `plutil -lint` after a mutation.

## Architecture

Layered, and the seams are load-bearing — they are where a platform crypto backend gets swapped, and
where the ports are expected to diverge in implementation but not in behaviour.

| Layer | Types | Role |
| --- | --- | --- |
| Substrate | `IRProtocolConstants`, `IRErrors`, `IRSodium`, `IRSecretBytes`, `IRByteReader`, `IRByteWriter`, `IREnvironment` | Constants, error taxonomy, wipeable storage, bounds-checked byte IO, injected clock/RNG |
| Key types | `IRKeyTypes`, `IRKeyPairs` | Nominal types — an `IREd25519Public` is not an `IRX25519Public`, and the compiler enforces it (§4.3) |
| Crypto seam | `IRCryptoProvider` (protocol), `IRSodiumCryptoProvider` | **The only file that calls libsodium.** Every layer above holds an `id<IRCryptoProvider>` |
| KDFs | `IRProtocolKDF` | HKDF-SHA256 for `KDF_RK`, `KDF_CK`, `KDF_MK` (§7.2, §7.3, §8.1) |
| Identity | `IRPublicIdentity`, `IRIdentity`, `IRPreKeyRecords`, `IRPreKeyBundle`, `IRPreKeyStore`, `IRInMemoryPreKeyStore` | `IRPublicIdentity` is the **ingest type**: its only constructor verifies `IKB`, so §5.5's "verified on every identity ingest" holds by construction |
| X3DH | `IRTranscript`, `IRSessionAD`, `IRX3DH` | §6 |
| Wire | `IRMessageHeader`, `IRMessageGate`, `IRMessageBuilder` | §9 layouts and §10's ordered gates |
| Ratchet | `IRSkippedKeyStore`, `IRRatchetState`, `IRRatchet` | §7, including §7.7's snapshot-and-commit atomicity |
| State | `IRSessionStateCodec`, `IRSealedStore` | §12.1's fixed binary layout, §12.3's sealing, §12.5's rollback tripwire |
| Session | `IRSession`, `IRSessionStore`, `IRInMemorySessionStore`, `IRSealedSessionStore`, `IRSessionDispatch` | §11 lifecycle |
| Facade | `IRMessenger` | §10.7's ordering and §11.2's dispatch — the two orderings no lower layer can enforce, because neither sees both stores |

## Invariants that are easy to break and hard to notice

Each of these is a v3 defect that round-tripped correctly. A passing test suite is not evidence
against any of them.

- **HKDF-SHA256 everywhere.** `crypto_kdf_derive_from_key` reads exactly 32 bytes whatever you pass
  it; that is how v3's 96–128 byte X3DH input silently collapsed to DH1 with both parties agreeing.
- **Two identity key pairs.** `IK^s` (Ed25519, signing) and `IK^d` (X25519, ECDH) are separate. The
  Ed25519→X25519 conversion is banned: no JDK equivalent, no CryptoKit equivalent.
- **Pure Ed25519 only.** libsodium's multi-part `crypto_sign_init`/`_update`/`_final_create` is
  **prehashed** (`crypto_sign.h:23`), which no port can verify. Use `crypto_sign_detached`, and
  expand the 32-byte seed with `crypto_sign_seed_keypair` first — passing a seed straight to
  `crypto_sign_detached` is a 32-byte out-of-bounds read that surfaces as `ERR_BAD_SIGNATURE`, i.e.
  disguised as an active MITM.
- **No offset is ever derived from a received byte.** Every §9 offset is a compile-time constant
  selected by the type byte. v3 read a wire-supplied length and used it as a `subdataWithRange:`
  bound.
- **Every libsodium and `Sec*` return value is checked.** `NSMutableData dataWithLength:` zero-fills,
  so an unchecked RNG failure yields an all-zero key with no signal. Fail closed, always: the one
  place that failed open (§12.5's tripwire read) is fixed and regression-tested.
- **Decrypt is atomic.** Ratchet, chain advance, counter increment and skip-insert all happen on a
  snapshot that is committed only after the AEAD authenticates (§7.7). Otherwise an unauthenticated
  message permanently desynchronises a live session.
- **Zeroize on every exit, including failure exits**, per §13.3's schedule. ARC deallocation is not a
  schedule, and the JVM ports have no equivalent of it at all.
- **nil is never coerced to empty** (§13.4, and §13.4 clause 6 requires this file to say so). A null
  passed for a `_Nonnull` parameter is a caller contract violation, not a protocol condition: it has
  no §10.5 code and it aborts through `IRRequireArgument`. Messaging `nil` in Objective-C does not
  raise — `[nilData length]` is 0 and `[nilData bytes]` is NULL — so the banned coercion happens
  without anyone writing it, and §10.4 makes a *zero-length* plaintext legal, which is what makes it
  invisible downstream. `NSParameterAssert` and `NSAssert` are banned in `nuntius/` by the lint
  because `NS_BLOCK_ASSERTIONS` compiles them out in Release. The one exception is a **session
  handle**: its absence is specified as `ERR_NO_SESSION` with a required vector, so every handle
  parameter is `_Nullable`.
- **A length floor is a function of the message type**, so §10.0's demultiplex — global floor, global
  cap, version, type domain, entry-point match — runs before either gate. Evaluating §10.2's 241-byte
  floor against a message whose type has not been read reports a truncation that does not exist, and
  it is what made §10.6's v3-rejection guarantee silently conditional on length.
- **A collapse loser's plaintext is still delivered** (§10.7 step 14d). What varies between the two
  branches is *which handle comes back*, and a bare "a collapse occurred" boolean is true on both
  while the caller's obligation is opposite on each — hence `tornDownHandshakeId` rather than a flag.

## Conventions

- Every file opens with the full MIT license block. New files must match exactly.
- Nullability is annotated per-parameter (`_Nullable` / `_Nonnull`), not with audited regions.
- Failure is `nil` / `NO` plus an `NSError **` out-param, always assigned through `IRSetError`,
  which null-checks. A raw `*error = ...` outside `IRErrors.m` is a lint failure.
- A **caller contract violation** is not a failure and does not use that convention: it aborts
  through `IRRequireArgument` (§13.4). `IRErrors.m` is the only file that may end a call abnormally,
  for the same reason it is the only file that may write `*error`.
- Error codes and their `ERR_*` names live in `IRErrors.h` (§10.5); the domain is `IRErrorDomain`.
- Tests are XCTest, one `*Spec.m` per layer, with negative cases named for the `NEG-*` vectors in
  §15.4.

## Known spec gaps

Raised, deliberately not resolved locally, because resolving them in one port and not the others is
worse than the gap. Each is documented at the site in the code.

- **§5.3 does not say a signed-prekey rotation must assign a new `spk_id`.** It is the only
  implementable reading — `spk_id` resolves to exactly one record and §9.2's header carries nothing
  else — but until §5.3 says so, reusing an id for fresh key material silently drops the superseded
  key out of the `{current, one previous}` retention set. See `IRInMemoryPreKeyStore.m`.
- **§12.2 states no reader-side rule for non-zero bytes under a clear `_present` flag**, though
  §12.1 requires writers to zero-fill. The decoder accepts and normalizes, which is what branching
  on the flag does naturally and therefore what the other ports will most likely do — at the cost of
  parse→re-serialize byte identity on a blob no conformant writer emits. See `IRSessionStateCodec.m`
  and `testNonZeroBytesUnderAClearPresenceFlagAreAcceptedAndNormalized`.
- **§12.1's layout carries no `IKB` field**, so §5.5's "verified on every identity ingest... and
  after state restore" is structurally unmeetable on the state-restore path: there is nothing stored
  to verify against. Every other ingest path does discharge it.
- **§7.8 specifies no behaviour when `persist(state)` fails** after the ratchet has already stepped,
  and §7.7's atomicity rule is scoped to `RatchetDecrypt` only. The send path therefore has a
  committed chain-key step it cannot reproduce if persistence then fails.
