// swift-tools-version:5.9
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

/*
 The license block above is the one every source file in this tree opens with. It is second here
 rather than first only because SwiftPM reads the tools-version comment from the FIRST line of a
 manifest and fails the manifest if anything precedes it.

 swift-tools-version:5.9 — the floor is set by what the manifest uses, not by taste:
 `.iOS(.v13)` needs >= 5.1 and `.binaryTarget(path:)` for a local .xcframework needs >= 5.3.
 5.9 (Xcode 15) is the modern baseline that clears both.

 There is deliberately NO `version` field: SwiftPM takes the version from the git tag, and the
 next tag is 1.0.0.

 This manifest REPLACES the podspec that used to sit here. The podspec was deleted deliberately
 and is not coming back; SwiftPM is the only supported package manager for this framework.
*/

import PackageDescription

let package = Package(
    name: "nuntius",
    /*
     iOS only, and only because the vendored libsodium is iOS only: Clibsodium.xcframework ships
     ios-arm64_arm64e and ios-arm64_arm64e_x86_64-simulator, nothing else. A plain `swift build`
     on macOS therefore cannot succeed: the graph resolves, then no slice matches the host, so no
     libsodium header path is handed to the compiler and the build stops at IRSodium.m with
     "'Clibsodium/sodium.h' file not found". That is the expected failure, not a manifest bug —
     slice selection is the Xcode build system's job. Build and test through the Xcode project.

     Deployment target is 13.0, matching IPHONEOS_DEPLOYMENT_TARGET in nuntius.xcodeproj.
    */
    platforms: [
        .iOS(.v13)
    ],
    products: [
        /*
         The product, the target and the generated module are all named `nuntius`, so
         `import nuntius` / `@import nuntius;` means the same thing here as it does against
         nuntius.framework built by the Xcode project.
        */
        .library(
            name: "nuntius",
            targets: ["nuntius"]
        )
    ],
    targets: [
        /*
         libsodium 1.0.22, vendored as a binary. This IS the libsodium dependency: there is no
         package-manager dependency on libsodium and there must not be one. The XCFramework wraps
         a static libsodium.a per slice plus a Headers/Clibsodium directory holding sodium.h, the
         sodium subdirectory and a module.modulemap. That is what makes `#include
         <Clibsodium/sodium.h>` — the form used by the only two files in the framework allowed to
         include it — resolve identically under both build systems.

         The target name matches the artifact's basename (Clibsodium.xcframework); do not rename
         one without the other.
        */
        .binaryTarget(
            name: "Clibsodium",
            path: "nuntius/libsodium/Clibsodium.xcframework"
        ),

        .target(
            name: "nuntius",
            dependencies: ["Clibsodium"],
            /*
             LAYOUT CONSTRAINT — read this before changing `path`, `publicHeadersPath`, or the
             include/nuntius symlink. Nothing here is stylistic; three simpler shapes were tried
             and each fails, with the exact SwiftPM error quoted.

             The problem. Sources are flat in nuntius/, and the headers import each other
             framework-style — `#import <nuntius/IRErrors.h>` in IRCryptoProvider.h, IRKeyTypes.h,
             IRMessenger.h and ~30 more. Xcode resolves that through the framework header map.
             SwiftPM has no header map: it hands dependents exactly one -I, the target's
             publicHeadersPath. For `<nuntius/Foo.h>` to resolve, that one directory must CONTAIN a
             directory named `nuntius` holding the headers — which the flat layout does not offer
             anywhere, since nuntius/ is itself the header directory.

             1. `path: "nuntius", publicHeadersPath: "."` — dependents get -I <root>/nuntius, so
                `<nuntius/IRErrors.h>` resolves to <root>/nuntius/nuntius/IRErrors.h, which does
                not exist. A consumer package fails with "'nuntius/IRErrors.h' file not found /
                could not build Objective-C module 'nuntius'". It also fails earlier, at graph
                load, because the .xcframework sits next to the umbrella header: "target 'nuntius'
                has invalid header layout: umbrella header found at .../nuntius/nuntius.h, but
                directories exist next to it: .../nuntius/libsodium".
             2. `path: ".", publicHeadersPath: "."` — the -I is then the package root, so the
                imports do resolve, but SwiftPM's other umbrella rule rejects it: "umbrella header
                found at .../nuntius/nuntius.h, but more than one directory exists next to its
                parent directory: .git, nuntius.xcodeproj, nuntiusTests, tools; consider reducing
                them to one". Unfixable — .git alone breaks it.
             3. Hand-written module.modulemap at the package root, to bypass umbrella generation
                entirely — SwiftPM stops treating the package as a source package at all:
                "ignoring declared target(s) 'nuntius' in the system package". A root
                module.modulemap means "system library package".

             What works, and what include/ is. include/nuntius is a relative symlink to ../nuntius.
             It gives SwiftPM the one directory shape it accepts — an include directory containing
             exactly one subdirectory, which holds an umbrella header matching the module name —
             WITHOUT moving a single source file. The -I is <root>/include, `<nuntius/Foo.h>`
             resolves through the symlink, and the umbrella lands at include/nuntius/nuntius.h.
             Verified three ways: `swift package describe` is clean; all 33 .m files compile for
             arm64-apple-ios13.0-simulator with zero warnings through this manifest; and a separate
             consumer package resolves the module and links against it.

             The canonical fix is the SwiftPM layout — headers under
             Sources/nuntius/include/nuntius — and it is not on the table here: it would move all
             39 headers away from the .m files that `#import "Foo.h"` them, out from under the
             Xcode project's file references, and out from under tools/lint_banned_apis.py's
             flat-path scan. The symlink is the cost of keeping one tree buildable by two build
             systems.

             If include/nuntius is ever lost (a checkout on a filesystem without symlinks, an
             over-eager clean), this manifest fails at graph load, not at link time — the error
             will name the include directory.
            */
            path: ".",
            /*
             Excluded from the source set, not from the repo:
             - nuntius/libsodium — the binary target's own directory (the .xcframework and the
               libsodium LICENSE). Without this it would be scanned as part of this target's
               sources, which both duplicates the binary target and drags ~90 libsodium headers
               into the module.
             - nuntius/Info.plist — the framework bundle's plist. It belongs to the Xcode target;
               SwiftPM would otherwise report it as an unhandled resource.
            */
            exclude: [
                "nuntius/libsodium",
                "nuntius/Info.plist"
            ],
            sources: [
                "nuntius"
            ],
            /*
             PUBLIC INTERFACE — §15.5 rules 5 and 6.

             SwiftPM's publicHeadersPath is a directory, not a file list, so it cannot by itself
             reproduce the Xcode project's per-header Public/Project split — 22 headers carry
             ATTRIBUTES = (Public, ) in the Headers phase, the other 17 carry no Headers-phase
             entry at all.
             What draws the line instead is the module map SwiftPM generates: because
             include/nuntius/nuntius.h exists and matches the module name, it emits an UMBRELLA
             HEADER module map over nuntius.h rather than an umbrella DIRECTORY over everything.
             The module is therefore exactly what the umbrella imports.

             nuntius.h does not import IREnvironment+Testing.h — that is deliberate and it is what
             keeps -initWithClock:randomSource:, IRFixedClock and IRScriptedRandomSource out of the
             shipped interface, which is what §15.5 rules 5 and 6 require of a production API. The
             other 16 project-visibility headers (IRByteReader, IRByteWriter, IRProtocolKDF,
             IRTranscript, IRSessionAD, IRX3DH, IRMessageHeader, IRMessageHeader+Internal,
             IRMessageGate, IRMessageBuilder, IRSkippedKeyStore, IRRatchetState, IRRatchet,
             IRSessionStateCodec, IRSessionDispatch, IRSession+Internal) are out of the module for
             the same reason.

             Two things this does NOT do, both verified:
             1. It does not make those headers unreachable. They sit in a directory that is on the
                consumer's -I, so a determined `#import <nuntius/IREnvironment+Testing.h>` still
                finds the file textually. It is absent from the MODULE, not from the checkout —
                the same guarantee Xcode's Project visibility gives.
             2. It is not silent. clang emits one -Wincomplete-umbrella warning per header in the
                directory that the umbrella omits ("umbrella header for module 'nuntius' does not
                include header 'IREnvironment+Testing.h'") when a consumer builds the module. That
                warning is the split being enforced, not a defect. Silencing it would take a
                hand-written module.modulemap listing the 23 public headers explicitly — the fix if
                the noise ever outweighs the signal, and the only other way to encode the split
                without moving files.

             Tests are NOT declared here. nuntiusTests is Objective-C XCTest, and it imports
             project-visibility headers by design (decision D8: Xcode's project header map reaches
             them). `xcodebuild test` remains the only way to run the suite.

             Also absent, and only expressible in the Xcode project: the tools/lint_banned_apis.py
             pre-Sources build phase (§3.3's banned-API list, §3.4's single crypto_sign_detached
             call site) and the per-file -Werror=unused-result on IRSodiumCryptoProvider.m (§13.2).
             SwiftPM has no per-file flags, and reaching for .unsafeFlags would make this package
             unusable as a tagged dependency — which is the whole point of the 1.0.0 tag. A build
             through this manifest is therefore NOT lint-gated; the Xcode build is.
            */
            publicHeadersPath: "include",
            linkerSettings: [
                /*
                 IRSealedStore.m imports <Security/Security.h>. Module autolinking would usually
                 pick this up; stating it makes the link explicit and independent of that.
                */
                .linkedFramework("Security")
            ]
        )
    ]
)
