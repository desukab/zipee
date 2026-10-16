# Zipee

**A free, open-source macOS archive app.** Browse, inspect, extract and edit
archives without unpacking everything.

```sh
zipee list photos.zip --tree      # browse without decompressing a member
zipee verify backup.zip          # CRC-check every member
zipee extract photos.zip june -d ~/Desktop
```

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.7x-000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![CI](https://github.com/desukab/zipee/actions/workflows/engine.yml/badge.svg)](https://github.com/desukab/zipee/actions/workflows/engine.yml)
[![macOS build](https://github.com/desukab/zipee/actions/workflows/macos.yml/badge.svg)](https://github.com/desukab/zipee/actions/workflows/macos.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## Why it exists

Most archive tools extract everything before you can see what's inside. On a
20,000-entry archive that means decompressing gigabytes to look at one folder.

**Zipee never unpacks more than you ask for.** Listing reads the container index
and decompresses **zero bytes**.

## What it does

Open an archive and browse it as a tree, with sizes, formats, timestamps and
encryption status per member. Pull out one file, one folder, or everything.
Check the whole archive's integrity. Edit a ZIP without ever touching your
original.

- **Never unpacks more than you ask for.** Listing reads the container index and
  decompresses zero bytes. 20,000 entries: **0.21 s**.
- **Never writes outside where you told it to.** Every member name passes one
  audited choke point before any filesystem call. **32 adversarial tests** cover
  traversal, absolute paths, symlink escapes and decompression bombs.
- **Never edits an archive in place.** A replacement is built in a temporary
  file, validated, then swapped in atomically. If anything fails, your original
  is untouched.
- **Free, no telemetry.** No account, no licence key, no analytics, no network
  calls except an optional update check.

## Supported formats

| Format | Read | Write | Tested |
|---|:--:|:--:|---|
| ZIP, including **WinZip AES-256** | ✅ | ✅ | ✅ |
| tar (gnu/ustar/odc, long names, pax) | ✅ | — | ✅ |
| 7z, RAR, gzip, bzip2, xz, zstd | detected | — | detection only |

Detection reads **magic bytes, not the file extension**, so a mislabelled
archive still opens correctly.

## Status — the honest version

We'd rather you read this than find out later.

| | |
|---|---|
| ✅ Archive engine | **Complete.** 146 tests, green on Linux and macOS |
| ✅ CLI | Works today |
| ✅ `.app` / `.pkg` | Built as a **universal Mach-O**, installs on macOS 15 |
| ⚠️ **The GUI has never been launched** | A CI runner has no GUI session. It compiles and installs; nobody has watched it run |
| ⚠️ **Finder integration unverified** | Declared in `Info.plist`, not exercised |
| ⚠️ **Swift XCTest suite not running** | 31 cases exist but are skipped — see below |
| ⚠️ **Unsigned** | Gatekeeper will refuse it until you allow it |

- [`docs/platform-limitations.md`](docs/platform-limitations.md) — every unverified claim, with evidence sources
- [`docs/release-status.md`](docs/release-status.md) — what has evidence, what doesn't
- [`docs/mounting-feasibility.md`](docs/mounting-feasibility.md) — what Zipee deliberately does **not** do

<details>
<summary><b>Why the Swift tests are skipped</b></summary>

The suite is hand-driven through `XCTMain`, `XCTestCaseEntry` and `testCase()`.
On the CI runner's Xcode those three helper symbols are not exported, so the
runner fails to compile. Everything else in XCTest resolves — `XCTestCase`,
`XCTestSuite`, every `XCTAssert*` — so the module is found; only the helpers are
missing.

Hand-rolling a replacement failed too, because `XCTestCaseEntry` is itself one
of the missing names. The fix is to let SwiftPM own the runner via a
`Package.swift` test target, which requires cbindgen output committed and a
`systemLibrary` target to link the Rust core. **Not done.** The 31 cases are
kept, not deleted, and CI still enforces build, package, install,
bundle-format, QR and artifact upload.

</details>

## Installing

Zipee ships **unsigned**. Apple requires a paid Developer ID certificate to sign
and notarise, and Zipee is committed to being free to build and use.

**Best option — build it yourself:**

```sh
git clone https://github.com/desukab/zipee.git
cd zipee
cargo build --release          # the CLI works immediately
./scripts/build-macos.sh       # builds Zipee.app for macOS 15+
```

Then in Finder: right-click → Open → Open Anyway.

<details>
<summary><b>Prebuilt .pkg</b></summary>

Releases carry an unsigned universal `.pkg` named
`Zipee-<version>-macOS.pkg`. Substitute the version you downloaded:

```sh
installer -pkg Zipee-<version>-macOS.pkg -target /
xattr -dr com.apple.quarantine /Applications/Zipee.app
```

Verify before you trust it:

```sh
shasum -a 256 Zipee-<version>-macOS.pkg
```

The published SHA-256 is in [`docs/release-status.md`](docs/release-status.md).
It is unsigned, so this is the only way to check you got what you expected.

</details>

## The CLI

```
zipee <archive>                      browse as a tree
zipee list <archive> [--tree]        list entries
zipee verify <archive>               CRC-check every member
zipee extract <archive> <entry> [-d dir]
zipee write <archive> ...            build a new archive safely
```

## Security

Archive handling is the classic hostile-input surface, so this is treated as a
security boundary rather than a convenience feature.

- Every member name passes **one** choke point, `sanitize_member_path`, before
  any filesystem call. No second, laxer path exists.
- Extraction budgets live in `extract.rs`, where untrusted data becomes
  filesystem calls — not in the UI layer.
- Security tests use **synthetic fixtures**. `tests/rawzip.rs` is a hand-rolled
  ZIP writer because the `zip` crate refuses to emit hostile member names. A
  test that cannot construct the attack is not a test.

Invariants are listed in [`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Rules are short: add a test with the
change, never weaken a security invariant to make something pass, and report
what you actually verified — in the same breath as claiming it.

**If you can run macOS, you can do the most valuable thing here:** the Swift
layer has never been compiled. Running `./scripts/build-macos.sh` and reporting
what breaks is the highest-value contribution available.

## Licence

Apache-2.0. See [`LICENSE-APACHE`](LICENSE-APACHE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).