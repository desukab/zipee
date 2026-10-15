## What changed

<!-- What does this do, and why? -->

## How it was verified

<!-- Which tests did you run, and what did they print? -->

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all --check`

## What is NOT verified

<!-- Be explicit. Unverified claims must be labelled as such. -->

## Checklist

- [ ] Tests added for new behaviour
- [ ] No security invariant weakened ([SECURITY.md](SECURITY.md))
- [ ] New untrusted input goes through `sanitize_member_path`
- [ ] Documentation updated if behaviour changed
- [ ] No credentials, certificates, or signing assets committed
