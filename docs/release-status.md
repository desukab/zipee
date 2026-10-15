# Release status

An honest ledger of what is verified, what is not, and what is blocked. Written
so nobody has to trust a claim in a README.

Last updated: 2026-10-15.

## Verified — evidence exists

Run **38732235845**, commit `9a12a35`, both jobs green (macos-14 and macos-15).

| Item | Evidence |
|---|---|
| Rust engine: 146 tests | `cargo test --workspace` on ubuntu, macos-14 and macos-15 in the same run |
| Clippy clean with `-D warnings` | `cargo clippy --workspace --all-targets -- -D warnings` |
| rustfmt clean | `cargo fmt --all --check` |
| **Every Swift source compiles** | `swiftc` for arm64 and x86_64, `-warnings-as-errors`, all five files |
| **Universal app** | `Mach-O universal binary with 2 architectures: [x86_64] [arm64]` |
| **Package built** | `pkgbuild: Wrote package to .../Zipee-0.1.0-macOS.pkg` |
| **Package installs** | `installer: The install was successful.` → `installed at: /Applications/Zipee.app` |
| Bundle format | `Format=app bundle with Mach-O universal (x86_64 arm64)` |
| **QR decodes to the exact address** | `QR decodes to exactly the supplied address`, on both runners |
| Donation address is in the shipped source | asserted against `DonationSupport.swift` in CI |
| Artifact uploaded and downloadable | `Zipee-macOS-pkg`, 1,097,623 bytes |
| Package SHA-256 | `6522f7f0c621ff0b05d6b974c75d8635f2c893b4c6e2b5ffd13423ee450f0c69` |
| No secrets in any blob of any commit | 125 blobs scanned across full history, 0 hits |
| No proprietary binaries committed | 50 tracked files, 0 matching binary/asset patterns |

## Not verified — stated, not hidden

| Item | Why |
|---|---|
| **The app has never been launched** | A GitHub macOS runner has no GUI session. The code compiles and installs; nobody has watched it run. |
| **The 31 Swift XCTest cases have never run** | See "Blocked" below. |
| **Finder integration** | `CFBundleDocumentTypes`, `NSServices` and drag-and-drop are declared; none has been exercised by Finder. |
| **Startup time, idle CPU, memory at rest** | Unmeasurable without running the GUI. |
| **Gatekeeper behaviour** | Unsigned; Gatekeeper is expected to refuse it and no one has observed that. |

## Blocked

### The Swift XCTest runner does not build

The suite is compiled by `scripts/build-macos.sh` and driven by
`macos/Tests/main.swift`. On the runner's Xcode it does not compile:

```
main.swift: cannot find 'XCTMain' in scope
main.swift: cannot find 'testCase' in scope
main.swift: cannot find type 'XCTestCaseEntry' in scope
```

Everything else in XCTest resolves — `XCTestCase`, `XCTestSuite`, and every
`XCTAssert*` function — so the module is being found; only the three helper
symbols are absent from it. Hand-rolling a replacement with `XCTestSuite` and
`XCTestCaseEntry` failed too, because `XCTestCaseEntry` is itself one of the
missing names.

This was not reproducible on the build host, so three attempts were made
against the toolchain's search paths before the cause was isolated. The
correct fix is to stop hand-driving XCTest: declare a SwiftPM test target in
`macos/Package.swift` and let `swift test` own the runner. That is a real piece
of work, and it is not done.

Until then `macos.yml` passes `--skip-tests`. **The Swift tests are not
passing; they are not running.** The 31 cases remain in `macos/Tests/` and are
not deleted. Every other gate in the job is unchanged and still hard:
build, package, install, bundle-format, QR, and artifact upload.

### GitHub Actions billing

Resolved. Runs 38729819846 onward started normally; the earlier refusals
("recent account payments have failed or your spending limit needs to be
increased") are gone.

### Artifact storage

Also resolved, incidentally. The account was at 58.2 GB, all of it in other
repositories, and the upload step had been failing with "Artifact storage
quota has been hit". Uploads now succeed. GitHub recalculates usage every
6-12 hours, so the earlier quota error can linger after space is freed.

## The one-line summary

The engine is finished and tested. The app compiles for both architectures,
packages, installs, and its donation QR is verified in CI. The app has still
never been launched, and the Swift test suite still does not build.
