# Zipee architecture

## The problem, stated honestly

Zipee's promise is "browse, inspect, extract and edit archives with the
convenience of working in Finder, without unpacking everything."

The prompt that shaped this project also insists on something easy to fake:

> Do not represent a simulated folder view as a genuine mounted filesystem.

So the architecture starts by separating four things that are routinely
conflated, and being explicit about which one Zipee ships.

| Layer | What it means | Zipee status |
|---|---|---|
| **1. Browse inside the app** | Zipee lists and navigates an archive's contents in its own window | **Shipped** |
| **2. Open through Finder** | Finder's "Open With" / Services hand an archive to Zipee | **Shipped** (documented, unverified on a Mac) |
| **3. Genuine filesystem mount** | The archive appears as a real volume that Finder shows as a folder | **Not shipped** |
| **4. Write back to a mounted archive** | Edits made in Finder persist into the archive file | **Not shipped** |

Layers 1 and 2 are what Zipee does today. Layers 3 and 4 are a separate product
with a separate distribution problem, and this document explains why Zipee does
not pretend to them.

---

## Why no mount, and what replaces it

### The blocker

The research (see [research/zipgeist-findings.md](research/zipgeist-findings.md))
established that Zipgeist mounts archives using **FSKit**, Apple's filesystem
extension framework, and that doing so requires the entitlement
`com.apple.developer.fskit.fsmodule`. That is a **restricted entitlement**:
Apple grants it to approved developers, and it is not available to an
independent developer building a public utility.

The alternatives, honestly assessed:

| Approach | Verdict |
|---|---|
| **FSKit `FSModule`** | The right API. **Blocked**: needs an Apple-granted entitlement. |
| **FileProvider file-system extension** | Also an entitlement (`com.apple.developer.fileprovider.testing-mode` for the non-App-Store path), and URL-based, which is the wrong model for a seekable ZIP. |
| **macFUSE 5.2+ (`MFMount.framework`)** | **Viable.** Its FSKit backend mounts volumes entirely in user space on macOS 26+, with no kernel extension and no Recovery Mode step. Official releases are signed and notarized by Apple. It is a separate user-installed component, so Zipee must detect its absence and degrade to in-app browsing. |
| **`diskdev-helper` / Disk Arbitration** | Deprecated; Apple no longer offers it to new apps. |
| **Browse in-app (chosen)** | No entitlement, no installer, no kext, no reboot. Works on any macOS Zipee supports. |

### What in-app browsing costs, and why it is the better trade

From the observed behaviour of a real mounted-archive app, the mount buys
Finder's chrome and pays for it:

- **Files dragged out of a mounted volume do not reliably work.** The competitor
  ships a string telling the user exactly this: *"Apps dragged out of the
  archive in Finder won't open."* A file that has lost its container, its
  relative position, and often its code signature is not a working app.
- **Large archives must be read in full before Finder can show anything.**
  Confirmed by that same vendor: *"Large compressed archives are read in full
  before Finder can show them."*
- **Ownership is ignored**, so an archive containing binaries cannot restore
  them faithfully.
- **A mounted volume must handle every write path Finder can produce** —
  renames, partial writes, concurrent readers — or it corrupts the archive.

An in-app browser has none of these failure modes, and Zipee adds two things a
mount cannot easily give:

- **Nested browsing without intermediate extraction.** Opening
  `photos.zip/june/inner.zip/report.pdf` inflates only that one member.
- **A single choke point for safety.** Every member name passes through
  [`sanitize_member_path`](../crates/zipee-engine/src/security.rs) before any
  filesystem call, and that is provable by test rather than by review.

**Correction to an earlier draft of this document.** It originally dismissed
macFUSE as "ships a kext, triggers a reboot, breaks on every macOS security
update." That is outdated and wrong. As of macFUSE 5.2.0 (April 2026) the
project ships `MFMount.framework`, an open API for mounting volumes through the
FSKit backend, and 5.4.0 (September 2026) supports macOS 26 that way with no
kernel extension at all. Those releases are notarized by Apple, so Gatekeeper
is satisfied without exceptions. A third-party kext is still the *legacy*
backend and can still be selected, but nothing forces it.

That materially changes the recommendation. A genuine mount is reachable for
Zipee by two routes:

1. **Depend on macFUSE's FSKit backend.** No restricted entitlement needed.
   Costs a separate user-installed component, so Zipee must detect its absence
   and degrade to in-app browsing rather than fail.
2. **Request `com.apple.developer.fskit.fsmodule` from Apple.** It is a managed
   capability — requested through Certificates, Identifiers & Profiles → App
   ID → Capability Requests. This is the route Zipgeist evidently took (its
   profile is a `Mac Team Direct Provisioning Profile` carrying exactly that
   entitlement). Full control, but gated on Apple's approval.

Route 1 is the one Zipee should ship, because it works today without anyone's
permission. Route 2 is worth applying for in parallel.

**The honest position:** Zipee gives up "it looks exactly like a folder in
Finder" *by default*, and buys correctness, a single safety choke point, and an
installer that does nothing scary. If either mount route lands, layer 3 is an
additive feature over the same engine — the index, the readers and the safety
layer are all reusable, and they are already tested. That is why the engine is a
separate library with no macOS dependency.

---

## Shape of the system

```
┌──────────────────────────────────────────────────────────────┐
│ macOS/Zipee/                       Swift + SwiftUI          │
│   ZipeeApp.swift      app lifecycle, menus, Services, drop  │
│   ArchiveSession.swift  @MainActor model, off-thread indexing│
│   BrowserView.swift   sidebar + table + toolbar              │
│   ZipeeEngine.swift   Swift face of the C ABI               │
└───────────────────────────────┬──────────────────────────────┘
                                │ C ABI (macos/Zipee/ZipeeEngine.h)
┌───────────────────────────────▼──────────────────────────────┐
│ crates/zipee-engine/                  Rust, no UI, no macOS  │
│                                                               │
│  ffi.rs          C ABI; every entry point catch_unwind's      │
│  security.rs     path safety + expansion budgets  ◄── the    │
│                  choke point for untrusted input       rules   │
│  format.rs       magic-byte container detection               │
│  zip_archive.rs  zip read (+AES), index, CRC verification     │
│  tar_archive.rs  tar read, hand-written so it cannot be       │
│                  bypassed by a dependency                      │
│  vfs.rs          flat member list ⇄ browsable tree            │
│  extract.rs      selective extraction, progress, cancel       │
│  writeback.rs    add/replace/rename/delete, validate, swap    │
│  nested.rs       archive-inside-archive without unpacking     │
└───────────────────────────────┬──────────────────────────────┘
                                │ safe Rust API
┌───────────────────────────────▼──────────────────────────────┐
│ crates/zipee-cli/                   the `zipee` binary       │
│   info · list · stat · cat · verify · extract · create · edit │
└───────────────────────────────────────────────────────────────┘
```

### Why the engine has no macOS dependency

This is the decision that makes the rest possible.

- Every security property is a **test**, not a claim. The 32-case adversarial
  suite runs on Linux in CI on every push. A zip-slip regression is a red build,
  not a code-review miss.
- The macOS UI is a thin shell. Adding a container means implementing
  `ArchiveAccess`; no UI code changes.
- The CLI is the cheapest honest exercise of the whole engine, and its
  exit-code contract is what CI asserts against.

The cost is one hand-written tar reader, which is deliberate: the `tar` crate's
writer will happily emit absolute paths and `..`, and Zipee will not have a
code path that can emit one.

---

## Key design decisions

### 1. Detect containers from content, never from the extension

`format.rs` reads magic bytes. Extensions lie — `backup.zip` is routinely a tar,
and an attacker controls the name entirely. The extension is used only as a
fallback when the content is inconclusive, and tar is detected at offset 257
where its `ustar` marker actually lives.

### 2. Safety is one function, called at the point of writing

`security::sanitize_member_path` rejects absolute paths, `..` in any position,
Windows drive and UNC forms, NUL and control characters, and overlong names.
Backslashes are normalised to `/` *first*, so `..\..\x` cannot slip through a
POSIX-only check.

It is called in two places: when building the index (so the UI can show an
entry greyed out rather than make it vanish) and immediately before every
filesystem call during extraction. Defence in depth, with the second call being
the one that actually matters.

Symlinks are a special case worth stating plainly: **Zipee never writes a
symlink during extraction.** Not because validation is hard —
[`validate_symlink_target`] proves a target stays inside the root — but because
a link's safety depends on every *later* member, and any gap in that reasoning
is an escape. Links are shown, with their targets, and never materialised.

### 3. Bound expansion before decompressing, on four axes

A decompression bomb defeats any single check, so [`ExtractionBudget`] bounds
entry count, total bytes, per-entry bytes, and per-entry expansion ratio
independently — all **before** any decompression. The ratio check treats
`compressed == 0 && uncompressed > 0` as a bomb outright, since that is the
canonical shape.

### 4. Never edit an archive in place

[`writeback`] is a four-step contract:

1. Refuse if the destination is the source (`Error::InPlaceWriteRefused`).
2. Build a complete replacement in a temporary file beside the destination.
3. **Re-open and validate the replacement** — its index must parse.
4. `rename(2)` into place, atomically.

If steps 2 or 3 fail, the original is untouched. There is no code path that
truncates a user's archive, and the guarantee is enforced by a test that asserts
the source file's bytes are unchanged afterwards.

Two further rules fall out of this: unsafe members are **dropped** rather than
copied into a rewrite (republishing a traversal payload under a new name would
be worse), and an edit against an archive that changed on disk since it was
opened is refused (`Error::ExternalModification`), because the edits were
computed against a stale index.

### 5. Listing must not decompress

`vfs.rs` splits paths and nothing else. Opening a 200,000-entry archive reads the
central directory and decompresses zero bytes. Directories that the archive
never declared are materialised from path prefixes, because most archives omit
directory records entirely and requiring one would make `photos/june` unreachable.

### 6. The FFI must not unwind into Swift

A Rust panic unwinding across an FFI boundary is undefined behaviour, so every
exported function wraps its body in `catch_unwind` and reports failure through
its return value. Strings are stripped of interior NULs rather than silently
truncated. Buffers use `ManuallyDrop` so the Rust side never drops an allocation
the caller now owns.

---

## Testing strategy

| Layer | What runs | Where |
|---|---|---|
| Unit | path safety, budgets, VFS, tar headers, CRC handling | every push, Linux + macOS |
| Security | 32 adversarial cases, synthetic fixtures only | every push, own CI job |
| Integration | real archives through `ArchiveAccess` | every push |
| FFI | cross-boundary open/read/extract/free, null and bad input | every push |
| CLI | round-trip, exit-code contract, reproducibility | every push |
| Native | build, install, launch, Finder integration | macOS runner, manual/scheduled |

The security fixtures are built by a hand-rolled ZIP writer
(`tests/rawzip.rs`) because the `zip` crate refuses to emit hostile member names
— a test that cannot construct the attack is not a test.

The macOS job cannot run on a pull request. A fork cannot read the secrets, and
a build that could produce a signed artifact must not be steerable by an
untrusted branch.

---

## Dependencies

| Crate | Version | Licence | Why |
|---|---|---|---|
| `zip` | 2.4 | MIT | ZIP read/write **and** WinZip AES decryption. Chosen specifically because Apple's own Archive Utility cannot read AES-256 archives. |
| `crc32fast` | 1.4 | MIT | Integrity verification |
| `thiserror` | 2 | MIT OR Apache-2.0 | Error derive |
| `clap` (CLI only) | 4 | MIT OR Apache-2.0 | Argument parsing |

Deliberately **not** used:

- **`tar` crate.** Its writer will emit absolute paths and `..`. Zipee ships its
  own read-only tar instead, so the safety rules cannot be bypassed by a
  dependency upgrade.
- **`libarchive` bindings.** Heavy native dependency, LGPL/BSD licensing split,
  and it would move the security boundary into C where the test suite cannot see
  it.

Zipee is dual-licensed MIT OR Apache-2.0 to match its dependency floor.

## What is deliberately not built

- **Encrypted archive creation.** Writing AES requires a key-management story
  Zipee does not have yet.
- **7z / RAR writing.** Read support only; both formats' writers are
  non-trivial and RAR's is effectively closed.
- **Archive *creation* in the UI.** The CLI does it; the app's create flow is
  not written.
- **Background indexing daemon.** The index is built per open, which is fast
  enough for the corpus sizes measured and far simpler to reason about.
- **A license server.** Zipee is MIT/Apache-2.0 with no telemetry.