# Zipee

**A free, open-source macOS archive app.** Browse, inspect, extract and edit
archives without unpacking everything.

```
zipee list photos.zip --tree      # browse without decompressing a member
zipee verify backup.zip          # CRC-check every member
zipee extract photos.zip june -d ~/Desktop
```

---

## What Zipee does

Open an archive and browse it as a tree, with sizes, formats, timestamps and
encryption status per member. Pull out one file, one folder, or everything.
Check the whole archive's integrity. Edit a ZIP without ever touching your
original. All of it is free, all of it is open source, and none of it requires
an account, a licence key, or a network connection.

### Why you might prefer it

- **It never unpacks more than you ask for.** Listing reads the container index
  and decompresses zero bytes. On a 20,000-entry archive that is 0.21 s.
- **It will not write outside where you told it to.** Every member name passes
  one audited choke point before any filesystem call. 32 adversarial tests
  cover traversal, absolute paths, symlink escapes and decompression bombs.
- **It never edits an archive in place.** A replacement is built in a temporary
  file, validated, then swapped in atomically. If anything fails, your original
  is untouched.
- **It is free and has no telemetry.** No account, no licence server, no
  analytics, no network calls except an optional update check.

## Status — please read

| | |
|---|---|
| ✅ Archive engine | **Complete and tested.** 146 tests, on Linux and macOS |
| ✅ Swift application | **Compiles** with warnings-as-errors; **packages and installs** |
| ✅ `.app` and `.pkg` | **Built as a universal Mach-O**; installs on macOS 15 |
| ⚠️ **The app has never been launched** | A CI runner has no GUI session |
| ⚠️ **Finder integration is unverified** | Declared in `Info.plist`, not exercised |
| ⚠️ **Unsigned** | Gatekeeper will refuse it until you allow it |

See [`docs/platform-limitations.md`](docs/platform-limitations.md) for every
unverified claim, and [`docs/mounting-feasibility.md`](docs/mounting-feasibility.md)
for what Zipee deliberately does **not** do.

## Supported formats

Tested means covered by an automated test that runs on every push.

| Format | Read | Write | Tested |
|---|:--:|:--:|---|
| ZIP, including **WinZip AES-256** | ✅ | ✅ | ✅ |
| tar (gnu/ustar/odc, long names, pax) | ✅ | — | ✅ |
| 7z, RAR, gzip, bzip2, xz, zstd | detected | — | detection only |

Detection reads magic bytes, not the file extension, so a mislabelled archive
still opens correctly.

## Installing

Zipee ships **unsigned**. Apple requires a paid Developer ID certificate to
sign and notarise, and Zipee is committed to being free to build and use, so
the release is deliberately unsigned.

**Before you download a build**, prefer compiling it yourself — see
[Build from source](#build-from-source).

### If you downloaded a `.pkg`

```sh
# Check it is the file you think it is
shasum -a 256 Zipee-<version>-macOS.pkg
# compare against the published SHA256SUMS.txt

# Install. Gatekeeper will block the app on first launch:
sudo installer -pkg Zipee-<version>-macOS.pkg -target /
```

Then **right-click Zipee in Finder → Open → Open**. macOS refuses unsigned
apps launched from a double-click; the right-click override is the intended
path and is a one-time action.

An unsigned package is also **not reliably installable on macOS 14** — the
installer there reports success, writes no receipt, and installs nothing. This
is a property of unsigned packages, observed in CI and documented in
[`docs/platform-limitations.md`](docs/platform-limitations.md#an-unsigned-package-does-not-install-on-macos-14).

**Security limitations of the unsigned build, stated plainly:**

- No code signature, so macOS cannot verify the binary has not been altered.
- No notarisation ticket, so Gatekeeper cannot confirm it came from a
  developer.
- The app is **sandboxed** and requests only seven entitlements, each
  documented with a reason in
  [`macos/Zipee/Resources/Zipee.entitlements`](macos/Zipee/Resources/Zipee.entitlements).

If your threat model needs a verified binary, build it from source. The source
build is the strongest form of verification available without paid credentials.

## Build from source

Requires macOS with the Xcode command line tools and Rust. Nothing else, and
nothing paid.

```sh
git clone https://github.com/desukab/zipee.git
cd zipee

# Test the engine first
cargo test --workspace

# Build Zipee.app and Zipee-<version>-macOS.pkg
./scripts/build-macos.sh
```

The script runs both test suites before it packages anything, compiles the
Swift with warnings treated as errors, verifies the produced package really is
an installer, and writes `dist/SHA256SUMS.txt` and
`dist/release-manifest.txt`.

Building from source is a stronger integrity guarantee than downloading an
unsigned binary: you can read every line that produced it.

## Development

```sh
cargo test --workspace                    # 146 engine tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
./scripts/build-macos.sh                  # compiles, tests and packages on macOS
```

CI runs the engine tests on Linux and macOS, and builds, tests, packages,
installs and inspects the app on macOS 15 and macOS 14.

| Layout | |
|---|---|
| `crates/zipee-engine/` | the archive core — no UI, no macOS dependency |
| `crates/zipee-cli/` | the `zipee` binary |
| `macos/Zipee/` | SwiftUI app, engine bridge, `Info.plist`, entitlements |
| `macos/Tests/` | Swift tests for the Rust/Swift boundary |
| `scripts/build-macos.sh` | the single source of truth for how the app is built |
| `docs/` | architecture, feature matrix, limitations, research |

Adding an archive format means implementing one trait. The UI does not change.

## Security

Report vulnerabilities privately through GitHub's security advisory form.
Please do not open a public issue for an unfixed one. Include a synthetic
reproducer — **never send a real user archive**.

The threat model, the invariants the test suite defends, and what is out of
scope are in [`SECURITY.md`](SECURITY.md).

## Known limitations

- **No filesystem mount.** Zipee browses inside its own window; it does not
  appear in Finder as a mountable volume. A mount requires Apple's FSKit
  framework and a restricted entitlement Zipee does not hold. It is not faked.
  The reasoning is in
  [`docs/mounting-feasibility.md`](docs/mounting-feasibility.md).
- **No encrypted-archive creation.** Reading them is supported.
- **No 7z or RAR writing.**
- **tar reads are O(N) per member**, so verifying a very large tar is slow.
- **Duplicate member names collapse** when read, because the underlying reader
  keys by name. Documented, not hidden.
- **The app has never been run** — only compiled, packaged and installed.
- **No screenshot is included**, because the app has not been run and
  fabricating one would be worse than its absence.

## Licence

**Apache License 2.0** — see [`LICENSE-APACHE`](LICENSE-APACHE) and
[`NOTICE`](NOTICE). Dependency licences are audited in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); no copyleft code is linked
and no LGPL obligation arises.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: add a test with the
change, do not weaken a security invariant to make something pass, and report
what you actually verified — including what you could not.

## Support Zipee

**Zipee is free and open-source. Donating is entirely optional.** Every
feature, the entire source code, and all updates remain free whether you
donate or not. There is no paid tier, no paywall, and nothing is reduced for
anyone who does not donate.

Donations help pay for maintenance, testing, and future development.

If you would like to support the project, you can send Solana to:

```
2EJyURV4HhJNFas4V3cJtB1BqvMnDaPhqcxu5yiSkAxG
```

The same address is in the app under **Zipee → Support Development…**, with a
copy button and a QR code. It carries no amount and requests nothing.
Zipee never connects to a wallet, signs anything, or stores any key.

Please verify the address by copying it rather than scanning, and by comparing
it against this README. Never share a seed phrase or private key with anyone,
including anyone claiming to represent this project.

## Research

Zipee's architecture was informed by observing how other macOS archive tools
behave and by decompiling one for factual comparison. **No code, binary, asset
or string from any other product is present in this repository**, and the
research is original analysis. See [`docs/research/README.md`](docs/research/README.md)
for exactly what was examined, how, and what was deliberately excluded.
