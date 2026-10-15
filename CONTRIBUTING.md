# Contributing

## Ground rules

1. **Add a test with the change.** Not instead of it.
2. **Do not weaken a security invariant** to make something pass. The
   invariants are listed in [SECURITY.md](SECURITY.md).
3. **Report what you actually verified.** If you could not run something, say
   so in the same breath as claiming it. [docs/platform-limitations.md](docs/platform-limitations.md)
   is the model: claims carry an evidence source and a confidence level.
4. **Clean `clippy` and `fmt` are required.** CI runs with `-D warnings`.

## Before you push

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Working on the engine

- `security.rs` is the choke point. New path-shaped input goes through
  `sanitize_member_path`; do not add a second, laxer path.
- `extract.rs` is where untrusted data becomes filesystem calls. Every budget
  check belongs there, not in the UI.
- Adding a container means implementing `ArchiveAccess`. No UI code changes.

## Working on the macOS app

The Swift layer has **never been compiled**. If you can run macOS, that is the
single most valuable contribution available: run `./scripts/build-macos.sh`,
report what breaks, and fix it.

## Adding fixtures

Security tests must use synthetic fixtures. `tests/rawzip.rs` is a hand-rolled
ZIP writer because the `zip` crate refuses to emit hostile member names — a test
that cannot construct the attack is not a test.

## Licensing

Contributions are accepted under MIT OR Apache-2.0, matching the project.
