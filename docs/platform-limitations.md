# Platform limitations

What Zipee can do, what it deliberately does not do, and what remains
**unverified** until it runs on a Mac. Read this before trusting any claim in
this repository about the native app.

---

## 1. The build host was not macOS

**This is the single most important limitation in the project.**

Every measurement, test result and artifact in this repository was produced on:

```
Linux 6.17.0-1022-azure #22-Ubuntu SMP x86_64
Ubuntu 24.04 LTS, x86_64
rustc 1.99.0, cargo 1.99.0
Node v24.21.0 (for REA)
```

There is no macOS, no Xcode, and no Swift toolchain on that host. Therefore:

| Claim | Status |
|---|---|
| The Rust engine compiles and its tests pass | **Verified here** |
| The `zipee` CLI works end to end | **Verified here** |
| Security properties of the engine | **Verified here** (32 adversarial tests) |
| The Swift sources **compile** | **NOT VERIFIED** |
| `Zipee.app` builds | **NOT VERIFIED** |
| `Zipee-<version>-macOS.pkg` builds | **NOT VERIFIED** |
| Finder integration, Services, drag-and-drop work | **NOT VERIFIED** |
| Gatekeeper accepts the build | **NOT VERIFIED** |
| The app runs without crashing | **NOT VERIFIED** |

**No `.pkg` artifact exists.** The packaging script
([`scripts/build-macos.sh`](../scripts/build-macos.sh)) is written and syntax
checked, but it has never been executed, because it cannot be on this host. It
is wired into a macOS CI workflow that installs the result on the runner and
launches the app; that workflow has also not run yet.

Anyone reading this should treat the Swift layer as **unvalidated source**, not
as a shipped product.

---

## 2. What the Swift layer actually is

`macos/Zipee/` contains:

- `ZipeeEngine.swift` — the Swift face of the C ABI.
- `ArchiveSession.swift` — the `@MainActor` model.
- `BrowserView.swift` — sidebar + table + toolbar.
- `ZipeeApp.swift` — app lifecycle, menus, Services, drag-and-drop.
- `Resources/Info.plist`, `Resources/Zipee.entitlements` — both validated as
  well-formed property lists.

The engine side of that boundary is solid: the C ABI is exercised by six
Rust tests that cross it for real, including null pointers, bad UTF-8, and
freeing a returned buffer. The Swift side is ordinary SwiftUI and has **not**
been type-checked.

### Specific Swift risks that a compiler would catch and a reader will not

These are the places most likely to need fixing on first compile:

1. **`@_silgen_name` on a `private` declaration.** The FFI imports are marked
   `private`, which may or may not satisfy the linker depending on how
   `swiftc` is invoked. Moving them to `internal` is the safe fix.
2. **The generated `ZipeeEngine.h` is written by the build script, not by
   hand.** The Swift struct layouts are hand-written to match
   `crates/zipee-engine/src/ffi.rs`. If either drifts, the ABI silently
   mismatches. A build-time layout assertion is the right fix and is not yet
   written.
3. **`ArchiveSession` uses `@MainActor` with `Task.detached`**, writing back
   through `await MainActor.run`. This compiles under Swift 5.9+ strict
   concurrency but may need explicit `Sendable` annotations.
4. **`BrowserView` calls `session.extract(to:)` to set `isChoosingDestination`
   indirectly** through a `fileImporter` binding; the `Button` in `welcome`
   sets the flag directly. Both paths look consistent, but only a compiler can
   confirm the `@MainActor` isolation across the view boundary.
5. **`.target(uname -m)-apple-darwin13.0` in the build script** assumes the
   runner's SDK matches. On a machine with an older SDK this fails.

None of these are design problems. They are the ordinary residue of not having
run a compiler, and they are listed so nobody mistakes unverified code for
verified code.

---

## 3. macOS-only constraints in the engine

Two behaviours depend on the host filesystem and are untested here:

- **Case sensitivity.** On a case-insensitive volume (macOS's default APFS),
  an archive containing `A.txt` and `a.txt` cannot be extracted faithfully to
  both. Zipee reads both (there is a test), and extraction is last-one-wins.
  Zipee does **not** yet warn about this, which is a known gap.
- **Unix modes.** Extraction restores the archived mode where present. macOS's
  sandbox then applies its own rules on top, which is correct but means the
  effective permissions may differ from the archived ones.

## 4. tar is O(N) per member read

`TarArchive::read_entry` re-walks the archive from the start. A tar has no
random-access index, so this is inherent unless a second pass is made and
offsets are cached.

Consequence: verifying an N-member tar is O(N²). For a 20,000-member tar this
would be minutes.

**Not yet fixed.** The honest options are to cache member offsets on first walk
(memory cost: 16 bytes per member) or to accept it and document the limit. This
is recorded rather than hidden; ZIP, the common case, is not affected.

## 5. Duplicate member names

The underlying `zip` reader keys its central-directory index by name, so an
archive with two records called `dup.txt` collapses to one member. Zipee
inherits this and **does not** pretend otherwise: the test
`duplicate_names_are_indexed_individually_and_read_deterministically` asserts
the real count (2, not 3) and names the limitation in a comment.

Surfacing both would require re-implementing the ZIP central-directory parser.
Not done.

## 6. Formats

| Format | Read | Write | Notes |
|---|---|---|---|
| ZIP | yes | yes | Including WinZip AES-256 decryption |
| tar | yes | no | Own reader, own safety rules |
| 7z | detected only | no | Recognised, then reported unsupported |
| RAR | detected only | no | Recognised, then reported unsupported |
| gzip / bzip2 / xz / zstd | detected only | no | Recognised as stream containers |

Detection is complete for all of the above; only ZIP and tar have readers.
Detection is not a promise of support, and the error message says so.

## 7. Symlinks are never written

Zipee shows symlink members and their targets but never materialises one during
extraction. The reasoning, and the test, are in
[`extract.rs`](../crates/zipee-engine/src/extract.rs). This is a deliberate
product decision, not an omission.

## 8. Sandboxing

The app ships sandboxed with seven entitlements, each documented with a reason
in [`Zipee.entitlements`](../macos/Zipee/Resources/Zipee.entitlements).

Not requested, and therefore not used: app groups, bookmarks beyond
app-scope, `get-task-allow`, any private framework, and — notably — **no
FSKit or FileProvider entitlement**, because those are restricted and Zipee
does not have them.

## 9. Packaging and signing

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

## 10. Performance actually measured

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

## 11. The highest-priority unverified item

Run `scripts/build-macos.sh` on a Mac. Everything above the Swift layer is
verified; everything below it is not. A single `swiftc` run would convert the
largest block of unknowns in this repository into either working code or a list
of concrete errors.