# Zipee

A native macOS archive utility: **browse, inspect, extract and edit archives
with the convenience of working in Finder, without unpacking everything.**

Zipee is a **security-first** archive engine with a thin macOS shell on top. The
engine is portable Rust with no UI and no macOS dependency, so every security
property is an automated test that runs on Linux on every push — not a claim in
a document.

```
zipee list photos.zip --tree        # browse without decompressing a single member
zipee verify backup.zip            # CRC-check every member
zipee extract photos.zip june -d ~/Desktop
zipee edit notes.zip -o fixed.zip --delete old.txt --rename a.txt=archive/a.txt
```

---

## Status — read this first

**The archive engine is complete and tested. The macOS app is written but has
never been compiled.**

This repository was built on an Ubuntu host with no Xcode and no macOS. That
means:

- ✅ **105 tests pass**, including 32 adversarial security tests — verified here
- ✅ **The CLI works end to end** on real archives — verified here
- ❌ **The Swift sources have not been type-checked**
- ❌ **No `.app` and no `.pkg` have been built** — this is impossible without macOS
- ❌ **Finder integration has not been exercised**

[`docs/platform-limitations.md`](docs/platform-limitations.md) lists every
unverified claim, the measured performance numbers, and the specific Swift risks
that a compiler would catch.

Nothing in this repository is described as working on macOS until it has been.

---

## What Zipee does, and does not, do

There are four things people conflate when they say "it mounts archives":

| | |
|---|---|
| 1. Browse inside the app | ✅ **Zipee does this** |
| 2. Open archives through Finder | ✅ **Zipee does this** |
| 3. Mount an archive as a real filesystem volume | ❌ Zipee does not |
| 4. Write changes back to a mounted archive | ❌ Zipee edits via `zipee edit` instead |

Layers 3 and 4 require Apple's **FSKit**, and FSKit requires the restricted
`com.apple.developer.fskit.fsmodule` entitlement, which Apple grants to approved
developers. Zipee is an independent project and does not assume it.

This is a deliberate trade, not a gap. A real mount costs a kext or a restricted
entitlement, and — as the competitor product's own strings admit — files dragged
out of a mounted archive often do not run, and large archives must be read in
full before Finder shows anything. An in-app browser has none of those failure
modes, and adds nested browsing without intermediate extraction.

The full reasoning is in [`docs/architecture.md`](docs/architecture.md#why-no-mount-and-what-replaces-it).

---

## Security

Archives are untrusted input. Zipee treats them that way.

- **One choke point.** Every member name passes `sanitize_member_path` before any
  filesystem call. Absolute paths, `..` in any position, Windows drive and UNC
  forms, NUL and control characters, and overlong names are all refused.
- **Backslashes are normalised first**, so `..\..\x` cannot slip past a
  POSIX-only check.
- **Symlinks are never written during extraction.** Their safety depends on
  every *later* member; the reasoning is in the code and the test is in the suite.
- **Expansion is bounded before decompressing**, on four independent axes:
  entry count, total bytes, per-entry bytes, and expansion ratio.
- **CRC-32 is verified on every read**, not only on `verify`.
- **Archives are never edited in place.** A replacement is built in a temporary
  file, re-opened and validated, then swapped in atomically. There is no code
  path that truncates a user's archive.
- **Nothing is dropped silently.** Unsafe members are reported to the UI with a
  reason; encrypted members are distinguished from corrupt ones.

See [`docs/feature-matrix.md`](docs/feature-matrix.md#security) for the full
threat table with a named test per row.

---

## Layout

```
crates/zipee-engine/     portable archive core — no UI, no macOS
crates/zipee-cli/        the `zipee` binary
macos/Zipee/             SwiftUI app, engine FFI, Info.plist, entitlements
scripts/build-macos.sh   builds Zipee.app and packages Zipee-<ver>-macOS.pkg
docs/                    architecture, feature matrix, platform limitations, research
```

## Build

**Engine and CLI — anywhere Rust runs:**

```sh
cargo test --workspace      # 105 tests
cargo build --release -p zipee-cli
```

**The macOS app — on macOS only:**

```sh
./scripts/build-macos.sh
```

The script runs the test suite before it packages anything, compiles the app
with `-warnings-as-errors`, verifies the result is a real XAR installer, and
writes `dist/SHA256SUMS.txt` and `dist/release-manifest.txt`. With signing
credentials it signs and notarizes; without them it produces a real unsigned
package and says so rather than pretending otherwise.

Signing secrets are GitHub Actions secrets (`ZIPEE_SIGN_IDENTITY`,
`ZIPEE_NOTARY_PROFILE`) and are never committed.

## CLI

Exit codes are part of the interface, so scripts can branch on them:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | refused (in-place write, external modification, usage) |
| 2 | I/O, unidentifiable container, no such entry |
| 3 | corrupt |
| 4 | password required or wrong |
| 5 | **refused for safety** (unsafe path in the archive) |
| 6 | unsupported container or encryption |
| 7 | **resource limit exceeded** (bomb, entry-count flood) |
| 8 | cancelled |

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how it is built and why
- [`docs/feature-matrix.md`](docs/feature-matrix.md) — what is done, partial, and not doing
- [`docs/platform-limitations.md`](docs/platform-limitations.md) — **what is unverified, and the measured numbers**
- [`docs/research/zipgeist-findings.md`](docs/research/zipgeist-findings.md) — the competitive research, with evidence and confidence per claim

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
