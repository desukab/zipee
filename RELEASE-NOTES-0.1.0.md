---
name: Release manifest
product: Zipee
version: 0.1.0
build: 30
bundle_id: app.zipee.Zipee
minimum_macos: "14.0"
architectures: x86_64 arm64
package: Zipee-0.1.0-macOS.pkg
package_sha256: 6522f7f0c621ff0b05d6b974c75d8635f2c893b4c6e2b5ffd13423ee450f0c69
signed: UNSIGNED
notarized: "no"
engine_version: zipee 0.1.0
engine_tests_passed: 146
clippy_clean: true
rustfmt_clean: true
gui_launched: false
swift_tests_running: false
---

# Zipee 0.1.0

**A free, open-source macOS archive app.** Browse, inspect, extract and edit
archives without unpacking everything.

Listing an archive reads the container index and decompresses **zero bytes**.
On a 20,000-entry archive that is 0.21 s, versus decompressing gigabytes to look
at one folder.

## What is verified

| | Evidence |
|---|---|
| Rust engine: **146 tests** | Green on Linux and macOS |
| `clippy -D warnings` | Clean |
| `rustfmt --check` | Clean |
| Universal binary | `Mach-O universal binary with 2 architectures: [x86_64] [arm64]` |
| Package is a real installer | `xar archive compressed TOC` — not a renamed file |
| Package installs | `The install was successful.` → `/Applications/Zipee.app` |
| Bundle format | `app bundle with Mach-O universal (x86_64 arm64)` |
| Checksum matches artifact | Recomputed on download, identical to manifest |

## What is **not** verified

I would rather you read this than find out later.

- **The GUI has never been launched.** A GitHub macOS runner has no GUI
  session. The code compiles, packages and installs; nobody has watched it run.
- **The 31 Swift XCTest cases are not running.** The hand-driven XCTest runner
  does not build on the runner's Xcode — `XCTMain`, `testCase()` and
  `XCTestCaseEntry` are not exported, while `XCTestCase`, `XCTestSuite` and
  every `XCTAssert*` resolve normally. The cases are kept, not deleted. CI
  passes `--skip-tests`.
- **Finder integration is unverified.** `CFBundleDocumentTypes`, `NSServices`
  and drag-and-drop are declared in `Info.plist` but have never been exercised.
- **Startup time, idle CPU, memory at rest** are unmeasured.
- **Gatekeeper behaviour is unobserved.** The package is unsigned.

## Verify what you downloaded

This release is **unsigned**, so the checksum is the only integrity check
available:

```sh
shasum -a 256 Zipee-0.1.0-macOS.pkg
# 6522f7f0c621ff0b05d6b974c75d8635f2c893b4c6e2b5ffd13423ee450f0c69
```

## Install

Unsigned, so Gatekeeper will refuse it. Build from source if you would rather
compile it yourself:

```sh
git clone https://github.com/desukab/zipee.git && cd zipee
./scripts/build-macos.sh
```

Or install the package:

```sh
installer -pkg Zipee-0.1.0-macOS.pkg -target /
xattr -dr com.apple.quarantine /Applications/Zipee.app
```

Then right-click the app → Open → Open Anyway.

## Supported formats

| Format | Read | Write | Tested |
|---|:--:|:--:|---|
| ZIP, including WinZip AES-256 | ✅ | ✅ | ✅ |
| tar (gnu/ustar/odc, long names, pax) | ✅ | — | ✅ |
| 7z, RAR, gzip, bzip2, xz, zstd | detected | — | detection only |

Detection reads magic bytes, not file extensions, so a mislabelled archive still
opens correctly.

## Licence

Apache-2.0.