# Security policy

## Reporting

Report vulnerabilities privately through GitHub's security advisory form on
this repository. Please do not open a public issue for an unfixed vulnerability.

Include: what you did, what you expected, the archive or input that triggers it,
and the Zipee version or commit. A synthetic reproducer is ideal — **please do
not send a real user archive**.

## Threat model

Zipee processes archives, so an archive is untrusted input. The boundaries:

- **In scope.** Hostile or malformed archives: path traversal, absolute paths,
  symlink escapes, decompression bombs, entry-count floods, corrupt or
  truncated containers, crafted CRC values, archive-in-archive recursion,
  unicode and case-collision edge cases.
- **In scope.** The extraction and write-back paths in `crates/zipee-engine`.
- **Out of scope.** Vulnerabilities in a dependency that we do not use, and
  attacks requiring an attacker who already controls the user's account.
- **Out of scope.** Zipee does not mount archives as filesystems, so the entire
  class of mount-time attacks (kernel FS bugs, FUSE escapes) does not apply.

## Design commitments

These are the invariants the test suite defends. A change that breaks one is a
regression, not an improvement:

1. No member path reaches the filesystem without passing
   `security::sanitize_member_path`.
2. No member is decompressed before its budget is checked on all four axes.
3. An archive is never modified in place; a replacement is validated before it
   is swapped in.
4. Unsafe members are reported, never silently dropped.
5. Passwords are never formatted, logged, or included in an error message.

## Supported versions

Only `main`. There are no release tags yet.
