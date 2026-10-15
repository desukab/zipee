# Platform limitations

What Zipee can do, what it deliberately does not do, and what remains
**unverified** until it runs on a Mac. Read this before trusting any claim in
this repository about the native app.

---

## 1. The build host is not macOS — but a macOS runner is

**This is the single most important limitation in the project.**

Interactive work happens on:

```
Linux 6.17.0-1022-azure #22-Ubuntu SMP x86_64
Ubuntu 24.04 LTS, x86_64
rustc 1.99.0, cargo 1.99.0
```

There is no macOS, Xcode or Swift toolchain there. **However**, GitHub Actions
macOS runners *are* available to this repository and *have been used*. The table
below is measured evidence, not expectation.

### What has actually been executed on macOS

GitHub Actions run **38713701004**, both jobs **green**:

| Claim | Evidence | Status |
|---|---|---|
| Engine tests pass on macOS | `121 passed; 0 failed` in the run log | **Verified** |
| Swift sources compile | `swiftc` with `-warnings-as-errors` produced a binary | **Verified** |
| App binary is a Mach-O | `Mach-O universal binary with 2 architectures: [x86_64] [arm64]` | **Verified** |
| App binary is universal | `Format=app bundle with Mach-O universal (x86_64 arm64)` after install | **Verified** |
| Package builds | `pkgbuild: Wrote package to .../dist/Zipee-0.1.0-macOS.pkg` | **Verified** |
| Package is a real installer | `xar -tf`, `pkgutil --expand-full`, executable + `Info.plist` found in the payload | **Verified** |
| Package installs | `installer: The install was successful.` on macos-15 **and** macos-14 | **Verified** |
| Bundle identifier | `app.zipee.Zipee`, read from the *installed* app's `Info.plist` | **Verified** |
| Minimum macOS | `14.0`, from the packaged `Info.plist` | **Verified** |
| CLI runs on macOS | `zipee create` / `list --tree` / `verify` executed in the run | **Verified** |
| Package SHA-256 | recorded in `dist/SHA256SUMS.txt` and `dist/release-manifest.txt` | **Verified** |

Runner matrix used:

| Runner | OS | Xcode | SDK |
|---|---|---|---|
| `macos-15` | macOS 15.7.9 (24G830) | 16.4 | MacOSX15.5.sdk |
| `macos-14` | macOS 14.8.9 (23J631) | 15.4 | MacOSX15.4.sdk |

### What is still NOT verified

| Claim | Status |
|---|---|
| **The app launches and stays running** | **NOT VERIFIED.** The package installs, but nothing starts the app. A headless runner has no window server session for a GUI app. |
| **The UI renders, navigates, or extracts** | **NOT VERIFIED** |
| **Finder integration**: Services menu, Open With, drag-and-drop | **NOT VERIFIED** |
| **Gatekeeper accepts the build** | **NOT VERIFIED**, and currently **would refuse it** — the package is unsigned. |
| **Code signature validity** | **NOT VERIFIED.** No Developer ID certificate exists here. |
| **Notarization** | **NOT VERIFIED**, and not performed. |
| **Any filesystem mount** | **NOT IMPLEMENTED and NOT VERIFIED.** |

**The honest summary:** Zipee now *compiles* on macOS and *packages* and
*installs* on macOS. It has never been *run*. Those are different claims and
this document keeps them apart.

### Why the app cannot simply be launched on a runner

`open -a Zipee` on a GitHub runner has no Aqua session to attach to. The
honest options, none of which is implemented yet:

- run the app's logic in a headless test harness (unit tests for
  `ArchiveSession` and the FFI, no `App`/`Window`);
- an XCTest UI test, which still needs a session;
- a local machine.

The first is cheap and is the natural next step: **unit-test the Swift layer
on the runner** so the FFI binding and the session model are proven even though
the window is not.

---

## 2. Defects that only running on macOS could find

Eight were found and fixed this way. Each is recorded because the pattern
matters more than the instance:

| # | Defect | Symptom |
|---|---|---|
| 1 | `rustup target add` failure swallowed | build died on a missing target |
| 2 | `uname -m` is `arm64`, Rust wants `aarch64-apple-darwin` | target "never installed" |
| 3 | `mapfile` used; macOS ships bash 3.2 | script error |
| 4 | crate had no `staticlib` crate type | `swiftc` had no `.a` to link |
| 5 | `-target ...apple-darwin13.0` does not resolve a macOS deployment target | every Foundation type rejected as "macOS 10.10 or newer" |
| 6 | `@Published private(set)` assigned from the view | 3 compile errors |
| 7 | `TableColumn.width(min:ideal:alignment:)` does not exist | compile error |
| 8 | Rust objects stamped with the SDK version, not the deployment target | linked binary would call unavailable APIs |
| 9 | `libbz2` not linked | undefined `_BZ2_bzDecompress` |
| 10 | `pkgutil --expand` does not unpack the payload | verification could never pass |
| 11 | `NSString.deletingLastPathComponent` returns non-Optional | compile error |
| 12 | `guard let x, x != nil` | always-true comparison |
| 13 | bundle `Contents` derived one level too high | verification failure |

Not one of these is visible to `bash -n`, `cargo test`, or a code review. They
were found only by compiling and running on the actual platform — which is the
argument for doing it.

---

## 3. What the Swift layer is, and what is still thin

`macos/Zipee/` contains:

- `ZipeeEngine.swift` — the Swift face of the C ABI. **Compiles clean** with
  `-warnings-as-errors` on both runners.
- `ArchiveSession.swift` — the `@MainActor` model. **Compiles clean.**
- `BrowserView.swift` — sidebar + table + toolbar. **Compiles clean.**
- `ZipeeApp.swift` — app lifecycle, menus, Services, drag-and-drop.
  **Compiles clean.**
- `Resources/Info.plist`, `Resources/Zipee.entitlements` — both validated as
  well-formed property lists, and the former was read back out of the
  *installed* bundle to confirm the version placeholders were substituted.

So the layer that was previously "written but never compiled" now compiles.

### What compiling does not prove

- **It has never run.** Nothing launches it; a runner has no GUI session.
- **No Swift unit tests exist.** The C ABI has six Rust tests that cross it,
  but the Swift wrapper around it has none. This is the largest remaining gap
  in coverage and the cheapest to close.
- **Runtime behaviour is unknown**: actor isolation, `Task.detached`
  round-trips, the `fileImporter` binding, and whether the archive session
  behaves under a large index are all untested.

The specific Swift risks previously listed here (silgen on `private`
declarations, hand-written struct layouts versus the generated header,
`@MainActor` isolation across the view boundary) **did not materialise** —
the compiler accepted all of them. That is worth recording: the speculation was
wrong in the compiler's favour, and now there is evidence instead.

One latent risk remains unaddressed: the C struct layouts in `ZipeeEngine.swift`
are hand-written to match `crates/zipee-engine/src/ffi.rs`, and the header is
generated by the build script. Nothing asserts the two agree. A layout
mismatch would corrupt memory silently. A build-time assertion, or generating
the Swift declarations from the header, is the fix.

## 4. macOS-only constraints in the engine

Two behaviours depend on the host filesystem and are untested here:

- **Case sensitivity.** On a case-insensitive volume (macOS's default APFS),
  an archive containing `A.txt` and `a.txt` cannot be extracted faithfully to
  both. Zipee reads both (there is a test), and extraction is last-one-wins.
  Zipee does **not** yet warn about this, which is a known gap.
- **Unix modes.** Extraction restores the archived mode where present. macOS's
  sandbox then applies its own rules on top, which is correct but means the
  effective permissions may differ from the archived ones.

## 5. tar is O(N) per member read

`TarArchive::read_entry` re-walks the archive from the start. A tar has no
random-access index, so this is inherent unless a second pass is made and
offsets are cached.

Consequence: verifying an N-member tar is O(N²). For a 20,000-member tar this
would be minutes.

**Not yet fixed.** The honest options are to cache member offsets on first walk
(memory cost: 16 bytes per member) or to accept it and document the limit. This
is recorded rather than hidden; ZIP, the common case, is not affected.

## 6. Duplicate member names

The underlying `zip` reader keys its central-directory index by name, so an
archive with two records called `dup.txt` collapses to one member. Zipee
inherits this and **does not** pretend otherwise: the test
`duplicate_names_are_indexed_individually_and_read_deterministically` asserts
the real count (2, not 3) and names the limitation in a comment.

Surfacing both would require re-implementing the ZIP central-directory parser.
Not done.

## 7. Formats

| Format | Read | Write | Notes |
|---|---|---|---|
| ZIP | yes | yes | Including WinZip AES-256 decryption |
| tar | yes | no | Own reader, own safety rules |
| 7z | detected only | no | Recognised, then reported unsupported |
| RAR | detected only | no | Recognised, then reported unsupported |
| gzip / bzip2 / xz / zstd | detected only | no | Recognised as stream containers |

Detection is complete for all of the above; only ZIP and tar have readers.
Detection is not a promise of support, and the error message says so.

## 8. Symlinks are never written

Zipee shows symlink members and their targets but never materialises one during
extraction. The reasoning, and the test, are in
[`extract.rs`](../crates/zipee-engine/src/extract.rs). This is a deliberate
product decision, not an omission.

## 9. Sandboxing

The app ships sandboxed with seven entitlements, each documented with a reason
in [`Zipee.entitlements`](../macos/Zipee/Resources/Zipee.entitlements).

Not requested, and therefore not used: app groups, bookmarks beyond
app-scope, `get-task-allow`, any private framework, and — notably — **no
FSKit or FileProvider entitlement**, because those are restricted and Zipee
does not have them.

## 10. Packaging and signing

`scripts/build-macos.sh`:

- refuses to run anywhere but macOS;
- runs the full test suite **before** packaging, so a failing security test
  cannot reach an artifact;
- compiles the app with `-warnings-as-errors`;
- verifies the produced package with `xar -tf`, `pkgutil --expand` and
  `pkgutil --flatten`, and asserts the expanded payload contains the expected
  executable — i.e. it proves the artifact is a real installer rather than a
  renamed file;
- signs and notarizes **only** when credentials are present, and otherwise
  produces a real unsigned package while saying so loudly.

**Unsigned packages are blocked by Gatekeeper.** Users would have to
right-click → Open. No Developer ID certificate or notarization credentials
are present in this environment, so no signed artifact can be produced here.
Secrets would live in GitHub Actions secrets (`ZIPEE_SIGN_IDENTITY`,
`ZIPEE_NOTARY_PROFILE`) and are deliberately not committed.

## 11. Performance actually measured

On the Linux host, release build, against a synthetic 20,000-entry ZIP
(5,973,304 bytes, 50 MB uncompressed, generated with Python's `zipfile`):

| Operation | Wall clock | Peak RSS |
|---|---|---|
| `zipee info` (central directory only) | 0.08 s | 16.0 MB |
| `zipee list` (all 20,000 entries) | 0.21 s | 23.7 MB |
| `zipee list --tree` | 0.17 s | 23.8 MB |
| `zipee verify` (decompress + CRC all 20,000) | 0.35 s | 18.0 MB |
| `zipee extract` (all 20,000 to disk) | 2.02 s | 23.3 MB |

Listing is ~1.3× the cost of reading the index and the same order as `info`,
which is the point: **listing never decompresses a member.**

These numbers are reproducible:

```sh
python3 - <<'PY'
import zipfile, random, string
z = zipfile.ZipFile('big.zip', 'w', zipfile.ZIP_DEFLATED)
for i in range(20000):
    d = '/'.join(f'dir{j%20}' for j in range(i % 4 + 1))
    z.writestr(f'{d}/file_{i:06}.txt',
               ''.join(random.choice(string.ascii_letters) for _ in range(200)).encode())
z.close()
PY
/usr/bin/time -f 'elapsed=%e rss=%MkB' ./target/release/zipee list big.zip >/dev/null
```

**These are Linux numbers for the engine.** They say nothing about the Swift
UI, which is unmeasured because it has never run.

### A performance bug this corpus found

The first `verify` of the same archive took **48.72 s** — `read_entry` scanned
the central directory linearly, making a full verify O(N²) (200 million string
comparisons at 20,000 members). Adding a name→index map, built once per open,
took it to **0.35 s**: a 139× improvement. `reading_every_member_of_a_large_archive_stays_linear`
guards it.

## 12. Mounting: the recommendation changed

This document and `docs/architecture.md` originally ruled out macFUSE because it
"ships a kext, requires a reboot and breaks on macOS updates". That is now
known to be outdated:

- **macFUSE 5.2.0** (2026-04-09) introduced `MFMount.framework`, an open API
  for mounting volumes through Apple's FSKit backend, explicitly to enable
  *fully sandboxed* file systems that previously were not possible.
- **macFUSE 5.4.0** (2026-09-07) supports macOS 26 that way with **no kernel
  extension**, requiring no Recovery Mode change.
- All official releases are **signed and notarized by Apple**, so Gatekeeper and
  SIP are satisfied without user exceptions.
- The legacy kext backend still exists and can still be selected, but nothing
  requires it.

**Status: unmounted-by-default is no longer forced by the technology.** Zipee can
ship a genuine mount by depending on macFUSE, or by applying for the
`com.apple.developer.fskit.fsmodule` managed capability from Apple.

Not yet done: the mount layer is not written. The engine already exposes
everything it would need (`Vfs`, `read_entry`, `ExtractionBudget`,
`sanitize_member_path`), and macFUSE requires per-operation callbacks, which map
onto `read_entry` cleanly — the write path additionally needs
`writeback::MemberEdit`.

Licensing needs checking before linking: `libfuse` itself is BSD, but
`MFMount.framework` is new and its licence is not yet confirmed. The macFUSE
kernel extension is closed source, though that is no longer the path.

## 13. The highest-priority unverified item

Run `scripts/build-macos.sh` on a Mac. Everything above the Swift layer is
verified; everything below it is not. A single `swiftc` run would convert the
largest block of unknowns in this repository into either working code or a list
of concrete errors.