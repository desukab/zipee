# Feature matrix

Status legend:

- **Done** — implemented and covered by tests that pass on every push.
- **Partial** — implemented, with the gap named.
- **Planned** — designed, not built.
- **Not doing** — deliberately out of scope, with the reason.

"Tested" refers to the automated suite in this repository. Nothing here has
been validated on a Mac; see [platform-limitations.md](platform-limitations.md).

---

## Container support

| Container | Detect | Read index | Read data | Write | Tested |
|---|:--:|:--:|:--:|:--:|---|
| ZIP | ✅ | ✅ | ✅ | ✅ | 24 cases |
| ZIP + WinZip AES-256 | ✅ | ✅ | ✅ | ➖ rewrite refuses | 1 case |
| tar (gnu/ustar/odc, long names, pax) | ✅ | ✅ | ✅ | ➖ | 11 cases |
| 7z | ✅ | ➖ | ➖ | ➖ | detection only |
| RAR | ✅ | ➖ | ➖ | ➖ | detection only |
| gzip / bzip2 / xz / zstd | ✅ | ➖ | ➖ | ➖ | detection only |
| macOS `.pkg` (XAR) | ✅ | ➖ | ➖ | ➖ | detection only |

Detection is by magic bytes, not extension. `docs/` has a real `.pkg` whose
XAR container this engine identifies correctly.

## Core

| Feature | Status | Notes |
|---|---|---|
| Identify a file's container | **Done** | `zipee info`; magic bytes first, extension only as fallback |
| List members without decompressing | **Done** | 0.21 s for 20,000 entries; the central directory is the only I/O |
| Browse as a tree | **Done** | Directories materialised from path prefixes, because most archives declare none |
| Case-insensitive sort, folders first | **Done** | |
| Per-member metadata | **Done** | Size, compressed size, ratio, mode, mtime, CRC-32, compression, encryption |
| Whole-archive statistics | **Done** | Counts, totals, compression ratio |
| Name/path filter | **Done** | `--filter` on the CLI; live search in the app |
| Read one member to stdout or a file | **Done** | `zipee cat` |
| CRC verification on every read | **Done** | Not just on `verify` — every read checks |
| Full verification with per-member report | **Done** | `zipee verify`, and `ArchiveAccess::verify` |

## Extraction

| Feature | Status | Notes |
|---|---|---|
| Extract everything | **Done** | |
| Extract a subtree | **Done** | `Selection::Subtree` |
| Extract one member | **Done** | |
| Name a folder without a trailing `/` | **Done** | Resolved against the index; works for implicit directories |
| Implicit directories created | **Done** | |
| Atomic per-file writes | **Done** | Temp sibling + rename, so no partial file survives a failure |
| Restore stored Unix mode | **Done** | |
| Progress reporting | **Done** | Entry-level; streamed to the UI |
| Cancellation | **Done** | Cooperative token, checked between members |
| Free space check | **Planned** | The error message is planned; the check is not written |
| Resume a partial extraction | **Not doing** | Zipee can restart selectively, which is simpler than resuming |

## Editing

| Feature | Status | Notes |
|---|---|---|
| Create a ZIP | **Done** | CLI only; the app's create flow is not written |
| Replace a member | **Done** | |
| Add a member | **Done** | |
| Delete a member | **Done** | |
| Rename a member, preserving contents | **Done** | Fixed a bug where the rename lost the read-side name |
| Write to a new file, never in place | **Done** | `InPlaceWriteRefused`, with a test asserting the source bytes are unchanged |
| Validate before replacing | **Done** | The replacement is re-opened and its index parsed before the swap |
| Detect external modification | **Done** | Size + mtime fingerprint; `ExternalModification` refuses the edit |
| Drop unsafe members from a rewrite | **Done** | Never republish a traversal payload |
| Refuse to rewrite past encrypted members | **Done** | Loudly, rather than silently dropping them |
| Encrypted archive creation | **Not doing** | Needs a key-management story Zipee does not have |
| 7z / RAR writing | **Not doing** | Effectively closed or very large |

## Security

| Threat | Status | Test |
|---|---|---|
| Path traversal (`../`) | **Done** | `zip_slip_member_is_never_written`, `deep_traversal_is_never_written`, `tar_traversal_is_never_written` |
| Windows-style traversal (`..\`) | **Done** | `windows_style_traversal_is_never_written` |
| Absolute paths | **Done** | `absolute_member_is_never_written`, `tar_absolute_path_is_never_written` |
| Drive-relative / UNC paths | **Done** | unit tests in `security.rs` |
| NUL and control characters in names | **Done** | `nul_in_member_name_is_refused` |
| Overlong names | **Done** | `rejects_overlong_names` |
| Symlink escape | **Done** | `symlink_members_are_recognised_but_never_written`, `symlink_followed_on_read_does_not_escape` |
| Decompression bombs (ratio) | **Done** | `high_ratio_member_is_refused_before_decompression` |
| Decompression bombs (zero compressed size) | **Done** | `budget_rejects_decompression_bombs` |
| Entry-count flood | **Done** | `entry_count_flood_is_bounded` |
| Total-byte exhaustion | **Done** | `total_byte_ceiling_is_enforced` |
| Corrupt CRC reported, not swallowed | **Done** | `corrupt_checksum_is_reported_not_silently_accepted` |
| Truncated archives | **Done** | `truncated_archive_reports_corruption` |
| Tar header checksum | **Done** | `rejects_corrupt_header_checksum` |
| Empty archives | **Done** | `empty_archive_is_valid_not_an_error` |
| Unicode and long filenames | **Done** | `unicode_and_long_names_survive_intact` |
| Case-colliding names | **Done** | `conflicting_case_differing_names_are_both_kept` |
| Duplicate names | **Partial** | Reader collapses them; asserted honestly, not hidden |
| Nested archives | **Done** | `nested_archive_is_opened_without_touching_the_outer_archive` |
| Encrypted archives, no password | **Done** | `encrypted_member_is_flagged_and_never_written_without_a_password` |
| Encrypted archives, wrong password | **Done** | `aes_encrypted_archive_needs_a_password_and_accepts_the_right_one` |
| AES-256 archives | **Done** | Same test; a bug found here (CRC enforced on AES) is fixed |
| Cancellation leaves no debris | **Done** | `cancellation_stops_before_the_first_member`, `no_partial_file_survives_a_write_failure` |
| Write-back failure keeps the original | **Done** | `writeback_produces_a_valid_archive_and_keeps_the_original_on_failure` |
| Concurrent access / external modification | **Done** | `external_modification_is_detected` |
| Password never printed | **Done** | `secret_never_prints_its_value` |
| Panics cannot cross the FFI | **Done** | `catch_unwind` on every export; tested with null and bad input |
| Duplicate free across the FFI | **Done** | Fixed; `ManuallyDrop` |

## macOS integration

| Feature | Status | Notes |
|---|---|---|
| SwiftUI sources compile | **Done** | `swiftc -warnings-as-errors`, both runners |
| `.pkg` builds | **Done** | `pkgbuild`, verified with `xar -tf` + `pkgutil --expand-full` |
| `.pkg` installs | **Done** | `installer: The install was successful.` on macOS 14 and 15 |
| App binary is a universal Mach-O | **Done** | `Mach-O universal binary with 2 architectures` |
| Bundle identifier / deployment target | **Done** | Read back from the *installed* bundle |
| **App launches and renders** | **NOT VERIFIED** | No GUI session on a runner |
| **Finder "Open With"** | **NOT VERIFIED** | `CFBundleDocumentTypes` declared, all `LSHandlerRank = Alternate` |
| **Finder Services menu** | **NOT VERIFIED** | `NSServices` → `extractArchives` declared |
| **Drag archives onto the window** | **NOT VERIFIED** | |
| Reveal in Finder | **Planned** | Entitlement requested, code not written |
| Quick Look previews | **Planned** | |
| Sandbox entitlements applied | **NOT VERIFIED** | Seven declared; unsigned builds do not enforce them |
| Code signing | **Not doing** | No Developer ID credentials exist here |
| Notarization | **Not doing** | Requires signing first |
| Genuine filesystem mount | **Not doing** | Read-only adapter exists and is tested; no platform backend. See [mounting-feasibility.md](mounting-feasibility.md) |
| Finder Sync badges | **Planned** | |
| Touch Bar / menu bar extras | **Not doing** | No demonstrated value |

### The read-only filesystem adapter

`crates/zipee-engine/src/fs_adapter.rs` exists, is platform-agnostic, and is
tested on Linux. It is the surface a mount backend implements.

| Operation | Status | Notes |
|---|---|---|
| `lookup` | **Done** | Caller spelling normalised; root always resolves |
| `read_dir` | **Done** | Final component only, directories first |
| `read_file` | **Done** | Ranged reads clamp at EOF; CRC verified |
| `size_of` | **Done** | From the index, no decompression |
| `is_cancelled` | **Done** | Stops every operation, so an unmount never waits on a read |
| Escape refusal (`..`) | **Done** | Never resolved, always refused |
| Typed errors | **Done** | `FsError` → `io::ErrorKind` mapping |
| Platform backend (FSKit / macFUSE) | **Not doing** | Gated on a licensing answer and an Apple capability request |

## Performance

Measured on Linux, release build. Numbers and reproduction steps are in
[platform-limitations.md](platform-limitations.md#10-performance-actually-measured).

| Operation (20,000-entry ZIP, 5.97 MB) | Time | RSS |
|---|---|---|
| `info` | 0.08 s | 16.0 MB |
| `list` | 0.21 s | 23.7 MB |
| `list --tree` | 0.17 s | 23.8 MB |
| `verify` | 0.35 s | 18.0 MB |
| `extract` | 2.02 s | 23.3 MB |

Startup latency of the **app**, idle CPU, and memory at rest are **unmeasured**
— the app has never run.

## Deliberately not built

| Not doing | Why |
|---|---|
| License server, telemetry, accounts | Zipee is MIT/Apache-2.0. A license server is not a neutral choice about privacy. |
| Writing 7z / RAR | Non-trivial or effectively closed. |
| Mounting archives as real volumes | Needs an Apple-granted entitlement; the trade-off is documented in [architecture.md](architecture.md#why-no-mount-and-what-replaces-it). |
| A background indexing daemon | Per-open indexing is fast enough for measured corpora and far simpler to reason about. |
| Cloud sync, sharing, collaboration | Different product. |
| Spotlight indexing of archive contents | Needs a metadata importer; possible later, not now. |
| Bulk operations across many archives | No demonstrated need yet. |

## Test counts

| Suite | Tests | Where run |
|---|---|---|
| Unit (`zipee-engine` lib) | 88 | Linux + macOS |
| Security (`tests/security.rs`) | 32 | Linux + macOS |
| Doc-tests | 1 | Linux + macOS |
| **Total** | **121** | |

Plus two CI-only checks: a CLI end-to-end job asserting the exit-code contract
and archive reproducibility, and a macOS job that compiles the app, packages
it, installs the package on the runner, and re-inspects the installed bundle.

