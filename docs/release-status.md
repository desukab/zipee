# Release status

An honest ledger of what is verified, what is not, and what is blocked. Written
so nobody has to trust a claim in a README.

Last updated: 2026-10-15.

## Verified — evidence exists

| Item | Evidence |
|---|---|
| Rust engine builds and passes 146 tests | `cargo test --workspace`, Linux x86_64 |
| Clippy clean with `-D warnings` | `cargo clippy --workspace --all-targets -- -D warnings` |
| rustfmt clean | `cargo fmt --all --check` |
| Security properties (32 adversarial cases) | `crates/zipee-engine/tests/security.rs` |
| **The app compiles** as a universal Mach-O | macOS CI run 38724308550: `Mach-O universal binary with 2 architectures: [x86_64] [arm64]` |
| **`Zipee-0.1.0-macOS.pkg` builds** | Same run: `pkgbuild: Wrote package to .../Zipee-0.1.0-macOS.pkg` |
| **The package is a real installer** | `xar -tf` plus `pkgutil --expand-full` found the executable and `Info.plist` in the payload |
| **The package installs** | Same run: `installer: The install was successful.`, `installed at: /Applications/Zipee.app` |
| Bundle id and deployment target | Read back from the **installed** bundle: `app.zipee.Zipee`, `14.0` |
| Rust tests pass on macOS | 121 passing in the run log |
| Unsigned package does **not** install on macOS 14 | Observed: success reported, no receipt, nothing installed |
| Solana address is a valid public key | 44 chars, base58 → 32 bytes, on the ed25519 curve |
| The QR decodes to the exact address | Verified with OpenCV; repeated in CI |
| No secrets in any blob of any commit | 125 blobs scanned across full history, 0 hits |
| No proprietary binaries committed | 50 tracked files, 0 matching binary/asset patterns |

## Not verified — stated, not hidden

| Item | Why |
|---|---|
| **The app has never been launched** | A GitHub macOS runner has no GUI session. Not a code defect, but it means no one has seen the app run. |
| **Finder integration** | `CFBundleDocumentTypes`, `NSServices` and drag-and-drop are declared; none has been exercised by Finder. |
| **The Swift test suite has never been executed** | See the blocker below. |
| **Startup time, idle CPU, memory at rest** | Unmeasurable without running the GUI. |
| **Gatekeeper behaviour** | The build is unsigned; Gatekeeper is expected to refuse it and no one has observed that. |

## Blocked

### GitHub Actions spending limit

Every macOS and Linux job since 2026-10-15T10:52Z has been refused before
starting:

> The job was not started because recent account payments have failed or your
> spending limit needs to be increased.

This is an account-level billing state, not a workflow defect. The workflows
were green immediately before it.

**Consequence.** The following were added *after* the last successful run and
have therefore **never been compiled**:

- `macos/Zipee/DonationSupport.swift` (donation address validation, QR
  rendering, clipboard)
- `macos/Zipee/AboutView.swift` (the About window and donation entry point)
- `macos/Tests/` (31 Swift boundary tests)
- the `Support Development…` menu wiring in `ZipeeApp.swift`
- the Swift test runner in `scripts/build-macos.sh`

Two of those were reviewed by hand and two real defects were found and fixed
that way — a fixture writer that appended central-directory fields to the wrong
buffer, and an `async`/`@MainActor` test class that `XCTMain` cannot register.
That is not a substitute for a compiler.

**No `.pkg` binary is published**, because none can be built containing the
current source. The last green artifact did not survive GitHub's artifact
storage quota, so there is no stale binary to publish either — which is the
honest outcome.

### What to do first when the limit is lifted

```sh
gh workflow run macos.yml --ref main
```

That single command compiles the Swift with `-warnings-as-errors`, runs the 31
Swift boundary tests, builds the universal `.app` and `.pkg`, installs the
package, and verifies the installation. Nothing else is needed to produce a
release artifact.

## The one-line summary

The engine is finished and tested. The app compiles, packages and installs as
of run 38724308550. The newest Swift — tests, About window, donations — has
not been compiled, because the CI account cannot currently start a job.
