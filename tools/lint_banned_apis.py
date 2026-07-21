#!/usr/bin/env python3
"""
Enforces SPEC.md §3.3's banned-API list over the nuntius v4 tree.

§3.3: "The following MUST NOT appear in any nuntius v4 implementation or port." §3.3's own table
and §16.2 both ask for this to be a lint rule rather than a review convention, and §13.3's closing
paragraph makes the point that the memory-hygiene rules "MUST be enforced by code review and by the
§3.3 lint rules" — several of these constructions are invisible in a passing test suite. Every one
of them round-trips correctly:

  - crypto_kdf_derive_from_key truncates the 96-128 byte X3DH input to 32 bytes, collapsing the
    protocol to DH1. Both parties agree. Every round-trip test passes. (defect 1)
  - crypto_sign_init/_update/_final_create is Ed25519PH -- crypto_sign.h:23 typedefs
    crypto_sign_state to crypto_sign_ed25519ph_state -- so signatures verify against themselves and
    against nothing the JDK or CryptoKit produces. The failure surfaces only cross-port, and looks
    exactly like an active MITM. (§3.4)
  - *(NSInteger*)data.bytes reads 8 bytes from a 1-byte NSData. The upper 7 are adjacent heap, so
    it is correct exactly as often as the heap happens to be zero. (defect 6)

A grep is therefore a stronger check than the test suite for this specific class of defect, which
is why it is wired into the build rather than left to review.

COMMENTS AND STRING LITERALS ARE STRIPPED BEFORE MATCHING. This tree documents what it does not do
-- IRCryptoProvider.h names crypto_sign_init in prose precisely so a port author does not reach for
it -- and a lint that cannot tell a warning from a call would force those explanations out of the
code. That is the wrong trade: the prose is load-bearing for the ports.

Usage:
    lint_banned_apis.py [--root PATH]

Exit status is 1 if any violation is found, 0 otherwise.
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------------------- §3.3

BANNED_IDENTIFIERS = [
    # (regex, why)
    (r'\bcrypto_kdf_derive_from_key\b',
     '§3.3 / defect 1: takes const unsigned char k[32] and reads exactly 32 bytes regardless of '
     'what is passed. Silently truncated the 96-128 byte X3DH input to DH1. Use HKDF-SHA256.'),
    (r'\bcrypto_kdf_blake2b_\w+',
     '§3.3: fixed 32-byte key input, 8-byte context truncation, and BLAKE2b has no JDK or CryptoKit '
     'equivalent.'),
    (r'\bcrypto_kx_\w+',
     '§3.3: expresses only a single DH, and its BLAKE2b derivation has no JDK or CryptoKit '
     'equivalent.'),
    (r'\bcrypto_sign_ed25519_(?:pk|sk)_to_curve25519\b',
     '§3.3 / defect 4: no JDK equivalent, no CryptoKit equivalent (Curve25519.Signing and '
     '.KeyAgreement are deliberately non-interconvertible), and the source of v3\'s '
     'uninitialized-stack-buffer-as-private-key bug. §4.1 splits the identity into IK^s and IK^d '
     'so the conversion is never needed.'),
    (r'\bcrypto_sign_(?:init|update|final_create|final_verify)\b',
     '§3.3 / §3.4: crypto_sign.h:23 reads "typedef crypto_sign_ed25519ph_state crypto_sign_state", '
     'so the multi-part API is PREHASHED Ed25519, not the pure Ed25519 of RFC 8032 §5.1 that '
     'java.security.Signature and CryptoKit implement. Use crypto_sign_detached / '
     'crypto_sign_verify_detached.'),
    (r'\bcrypto_aead_chacha20poly1305_(?!ietf_)\w+',
     '§3.3: the non-IETF variant takes an 8-byte nonce and is silently incompatible with the '
     '_ietf_ variant this protocol specifies (§8.2). Use crypto_aead_chacha20poly1305_ietf_*.'),
    (r'\bcrypto_aead_xchacha20poly1305_\w+',
     '§3.3 / §8.4: absent from CryptoKit and from BouncyCastle\'s JCE provider; would force two '
     'ports to hand-roll HChaCha20.'),
    (r'\bcrypto_aead_aes256gcm_\w+',
     '§3.3: hardware-gated behind crypto_aead_aes256gcm_is_available(), requiring a runtime '
     'availability branch the other three ports do not have.'),
    (r'\bNSKeyed(?:Archiver|Unarchiver)\b',
     '§3.3 / defect 12: no two runtimes agree byte-for-byte, and unarchiveObjectWithData: without '
     'secure coding is a deserialization gadget surface. §12.1 specifies a fixed-layout binary '
     'blob.'),

    # §2 row 4 and §14 defect 5: CommonCrypto is not "avoided", it is gone. AES-CBC + PKCS7 +
    # hand-rolled encrypt-then-MAC took the padding oracle, the broken comparator, the separate
    # HMAC key and the derived IV with it.
    (r'<CommonCrypto/',
     '§2: CommonCrypto is removed ENTIRELY in v4. There is no AES-CBC, no separate HMAC, no IV '
     'derivation and no MAC comparator left to need it.'),
    (r'\bCC(?:Crypt|Hmac|HmacInit|HmacUpdate|HmacFinal)\b',
     '§2 / §14 defects 5 and 8: replaced by a single ChaCha20-Poly1305 AEAD call (§8.2).'),

    # §14 -- the v3 types are deleted, not deprecated. A deprecated class still compiles the banned
    # primitives into the shipped binary and still lets a consumer build an insecure session by
    # autocompleting a name.
    (r'\bIR(?:EncryptionService|TripleDHService|DoubleRatchetService|Curve25519KeyPair|'
     r'RatchetHeader|AEADInfo)\b',
     '§14: this v3 type was DELETED in the L11 cleanup. If you need what it did, the v4 replacement '
     'is IRSodiumCryptoProvider / IRX3DH / IRRatchet / IRKeyPairs / IRMessageHeader respectively.'),
]

# §3.3's last row, and §16.2's "lint for it". The construction is a dereference of a pointer cast to
# a MULTI-BYTE integer type: `*(NSInteger*)data.bytes` reads 8 bytes from whatever it is pointed at,
# which in v3 was a 1-byte NSData. Single-byte types are excluded -- a uint8_t read cannot over-read
# and is how the correct code spells a one-byte field read.
POINTER_CAST_READ = re.compile(
    r'\*\s*\(\s*(?:const\s+)?'
    r'(NSInteger|NSUInteger|uint(?:16|32|64)_t|int(?:16|32|64)_t|unsigned\s+\w+|long|short|int|'
    r'size_t|float|double)'
    r'\s*\*\s*\)')

# ---------------------------------------------- structural invariants, not §3.3 text

#: §3.4 + §16.2. crypto_sign_detached reads 64 bytes and Ed25519Private is the 32-byte seed, so the
#: expand -> sign -> zeroize sequence has to be one function with no other way in. A second call
#: site is how that invariant gets lost, and the resulting out-of-bounds read arrives disguised as
#: ERR_BAD_SIGNATURE, i.e. as an active MITM.
SINGLE_CALL_SITE = {
    'crypto_sign_detached': 1,
}

#: §13.2 wants -Wunused-result promoted to an error across the crypto layer. Scoped per-file in the
#: pbxproj, which is easy to lose in a later project edit, so it is asserted here.
REQUIRED_COMPILER_FLAGS = {
    'IRSodiumCryptoProvider.m': '-Werror=unused-result',
}

#: IRErrors.h: "A raw `*error = ...` anywhere outside IRErrors.m is a lint failure." Every
#: NSError out-param in this tree is set through IRSetError, which null-checks -- v3 crashed on a
#: NULL error** at two sites (§14.1).
#:
#: `NSError *error = nil;` has the same character sequence and is a DECLARATION, not a dereference.
#: Distinguished by what precedes the star: a type name (identifier character) means declarator,
#: anything else -- `;`, `{`, `)`, start of line -- means dereference.
RAW_ERROR_ASSIGN = re.compile(r'\*\s*error\s*=(?!=)')
IDENTIFIER_TAIL = re.compile(r'[A-Za-z0-9_]$')

#: §3.3's NSParameterAssert row and §13.4 clause 3. Both NSParameterAssert and NSAssert are compiled
#: out under NS_BLOCK_ASSERTIONS, which is the default in a Release build of a framework dependency,
#: so a precondition written with either does NOTHING in the configuration consumers actually ship.
#: §13.4 requires the check to survive Release; IRRequireNonNil / IRRequireArgument (IRErrors.h) is
#: the one sanctioned mechanism, and it aborts unconditionally.
#:
#: Banned in the framework only. nuntiusTests may use them: a test binary is never built with
#: NS_BLOCK_ASSERTIONS, and an assert there guards the test's own preconditions rather than a
#: caller's.
ELIDABLE_ASSERT = re.compile(r'\b(NSParameterAssert|NSCParameterAssert|NSAssert|NSCAssert)\s*\(')
ELIDABLE_ASSERT_DIR = 'nuntius'



def is_error_dereference(code, start):
    """True when the `*error =` at `start` dereferences rather than declares."""
    before = code[:start].rstrip()

    return not IDENTIFIER_TAIL.search(before)

SOURCE_DIRS = ['nuntius', 'nuntiusTests']
SOURCE_EXTENSIONS = ('.h', '.m', '.c')


def strip_comments_and_strings(text):
    """Blank out comments and string literals, preserving line structure and offsets.

    Replacing rather than deleting keeps every line number in the output equal to the line number
    in the file, which is the whole value of a lint message.
    """
    out = []
    i = 0
    length = len(text)

    while i < length:
        char = text[i]
        pair = text[i:i + 2]

        if pair == '//':
            end = text.find('\n', i)
            end = length if end == -1 else end
            out.append(' ' * (end - i))
            i = end

        elif pair == '/*':
            end = text.find('*/', i + 2)
            end = length if end == -1 else end + 2
            # Newlines survive so line numbering does not shift.
            out.append(''.join('\n' if c == '\n' else ' ' for c in text[i:end]))
            i = end

        elif char in ('"', "'"):
            quote = char
            j = i + 1
            while j < length:
                if text[j] == '\\':
                    j += 2
                    continue
                if text[j] == quote or text[j] == '\n':
                    break
                j += 1
            j = min(j + 1, length)
            out.append(''.join('\n' if c == '\n' else ' ' for c in text[i:j]))
            i = j

        else:
            out.append(char)
            i += 1

    return ''.join(out)


def source_files(root):
    for directory in SOURCE_DIRS:
        base = os.path.join(root, directory)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            # The vendored libsodium is a dependency, not our source: it legitimately DEFINES the
            # banned functions. §3.3 bans calling them, not shipping the library that has them.
            dirnames[:] = [d for d in dirnames if d not in ('libsodium', 'Clibsodium.xcframework')]
            for filename in sorted(filenames):
                if filename.endswith(SOURCE_EXTENSIONS):
                    yield os.path.join(dirpath, filename)


def check_sources(root):
    violations = []
    call_site_counts = {name: [] for name in SINGLE_CALL_SITE}

    for path in source_files(root):
        with open(path, 'r', encoding='utf-8') as handle:
            raw = handle.read()

        code = strip_comments_and_strings(raw)
        rel = os.path.relpath(path, root)

        for pattern, reason in BANNED_IDENTIFIERS:
            for match in re.finditer(pattern, code):
                line = code.count('\n', 0, match.start()) + 1
                violations.append((rel, line, match.group(0).strip(), reason))

        for match in POINTER_CAST_READ.finditer(code):
            line = code.count('\n', 0, match.start()) + 1
            violations.append((
                rel, line, ' '.join(match.group(0).split()),
                '§3.3 / defect 6: pointer-cast integer read. v3 did this to a 1-byte NSData and '
                'read 8 bytes, 7 of them adjacent heap, then used the result as a wire-derived '
                'LENGTH. Assemble multi-byte integers explicitly, big-endian, after a bounds '
                'check -- IRByteReader exists for this.'))

        if rel.split(os.sep)[0] == ELIDABLE_ASSERT_DIR:
            for match in ELIDABLE_ASSERT.finditer(code):
                line = code.count('\n', 0, match.start()) + 1
                violations.append((
                    rel, line, match.group(1),
                    '§3.3 / §13.4 clause 3 / §16.2: compiled out under NS_BLOCK_ASSERTIONS, which '
                    'is the default in a Release build of a framework dependency -- so this guard '
                    'does nothing in the configuration consumers ship. A null passed for a _Nonnull '
                    'parameter is a caller contract violation that MUST fail fast in Release and '
                    'MUST NOT be normalized to an empty or default value. Use IRRequireArgument().'))

        if os.path.basename(path) != 'IRErrors.m':
            for match in RAW_ERROR_ASSIGN.finditer(code):
                if not is_error_dereference(code, match.start()):
                    continue
                line = code.count('\n', 0, match.start()) + 1
                violations.append((
                    rel, line, ' '.join(match.group(0).split()),
                    'IRErrors.h: assign NSError out-params through IRSetError, which null-checks. '
                    'v3 dereferenced a NULL error** at two sites (§14.1).'))

        for name in SINGLE_CALL_SITE:
            for match in re.finditer(r'\b' + name + r'\s*\(', code):
                line = code.count('\n', 0, match.start()) + 1
                call_site_counts[name].append('%s:%d' % (rel, line))

    for name, limit in SINGLE_CALL_SITE.items():
        sites = call_site_counts[name]
        if len(sites) > limit:
            violations.append((
                sites[limit], 0, name,
                '§3.4 / §16.2: %s must have exactly %d call site(s), found %d (%s). It reads a '
                '64-byte secret key while Ed25519Private is the 32-byte seed, so the '
                'crypto_sign_seed_keypair -> sign -> zeroize sequence must be a single function '
                'with no other way in. Passing a seed straight through is a 32-byte '
                'out-of-bounds read that surfaces as ERR_BAD_SIGNATURE.'
                % (name, limit, len(sites), ', '.join(sites))))

    return violations


def check_project(root):
    """Per-file COMPILER_FLAGS survive project edits only if something asserts them."""
    violations = []
    path = os.path.join(root, 'nuntius.xcodeproj', 'project.pbxproj')
    if not os.path.isfile(path):
        return violations

    with open(path, 'r', encoding='utf-8') as handle:
        text = handle.read()

    for filename, flag in REQUIRED_COMPILER_FLAGS.items():
        pattern = (r'/\* ' + re.escape(filename) + r' in Sources \*/ = \{isa = PBXBuildFile;'
                   r'[^\n]*COMPILER_FLAGS = "[^"]*' + re.escape(flag))
        if not re.search(pattern, text):
            violations.append((
                'nuntius.xcodeproj/project.pbxproj', 0, filename,
                '§13.2: %s must carry COMPILER_FLAGS %s. It is the file that calls libsodium, and '
                'a discarded crypto return value is defect 4 -- an RNG failure with a zero-filled '
                'buffer yields an all-zero key with no signal.' % (filename, flag)))

    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = parser.parse_args()

    violations = check_sources(args.root) + check_project(args.root)

    if not violations:
        print('banned-API lint: clean (SPEC §3.3, §3.4, §13.2, §16.2)')
        return 0

    print('banned-API lint: %d violation(s)\n' % len(violations))
    for path, line, token, reason in violations:
        location = '%s:%d' % (path, line) if line else path
        print('%s\n    %s\n    %s\n' % (location, token, reason))

    return 1


if __name__ == '__main__':
    sys.exit(main())
