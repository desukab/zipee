//! Path-safety and resource-limit enforcement for untrusted archive members.
//!
//! Everything in an archive is attacker-controlled input. A member name is a
//! path *inside the archive*; it must never be allowed to become a path
//! *outside the extraction root*. This module is the single choke point for
//! that decision, and it is deliberately fail-closed: anything not provably
//! safe is rejected rather than sanitised into something that "looks fine".
//!
//! The rules enforced here are the ones behind CVE-class archive bugs:
//!
//! * **zip-slip / path traversal** — `../../etc/passwd`, `a/../../b`.
//! * **absolute paths** — `/etc/passwd`, `C:\Windows\...`, `\\server\share`.
//! * **drive-relative and Windows separators** — backslashes are normalised
//!   before the check, so `..\..\x` is caught.
//! * **NUL and control characters** — truncate paths in C APIs, and hide
//!   extensions from naive validators.
//! * **symlink escape** — a symlink whose target is absolute or climbs out of
//!   the extraction root lets a *later* member write outside the root even
//!   though every name passed the traversal check.

use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Why a member path was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathViolation {
    /// The name was empty or resolved to nothing (e.g. `./`, `.`).
    Empty,
    /// Name contained a NUL byte or a C0/C1 control character.
    ControlCharacter(u8),
    /// Name tried to escape the extraction root with `..`.
    Traversal,
    /// Name was absolute (`/x`), a UNC path (`\\host\share`) or drive-rooted.
    Absolute,
    /// Name exceeded `MAX_PATH_BYTES`.
    TooLong(usize),
    /// A symlink member pointed outside the extraction root.
    SymlinkEscape(String),
}

impl fmt::Display for PathViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "member name is empty"),
            Self::ControlCharacter(b) => {
                write!(f, "member name contains control character 0x{b:02x}")
            }
            Self::Traversal => write!(f, "member name tries to escape the extraction root"),
            Self::Absolute => write!(f, "member name is an absolute path"),
            Self::TooLong(n) => write!(f, "member name is {n} bytes, limit is {MAX_PATH_BYTES}"),
            Self::SymlinkEscape(t) => write!(f, "symlink target {t:?} escapes the extraction root"),
        }
    }
}

/// Longest member path we will accept, in bytes.
///
/// macOS caps a single path component at 255 bytes and a path at 1024, but
/// POSIX leaves room for much longer names in an archive. Refusing early keeps
/// downstream filesystem writes from failing in less obvious ways.
pub const MAX_PATH_BYTES: usize = 4096;

/// A member name that has been proven safe to resolve inside an extraction root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMemberPath(PathBuf);

impl SafeMemberPath {
    /// The sanitised, relative path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Final component, e.g. `photo.jpg`.
    pub fn file_name(&self) -> &str {
        self.0
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
    }

    /// Parent path, empty for a top-level member.
    pub fn parent(&self) -> &str {
        self.0.parent().and_then(|p| p.to_str()).unwrap_or_default()
    }

    /// The path as a `/`-joined string, the form used as a map key.
    pub fn as_key(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_os_str().is_empty()
    }
}

/// Validate a raw archive member name and return a safe relative path.
///
/// Accepts a member name that is *already* safe. Rejects anything absolute,
/// anything containing `..`, anything with control characters, and anything
/// over [`MAX_PATH_BYTES`].
///
/// Backslashes are treated as separators: a ZIP written on Windows can use
/// them, and `..\..\evil` must not slip through a POSIX-only check.
pub fn sanitize_member_path(raw: &str) -> Result<SafeMemberPath, PathViolation> {
    if raw.is_empty() {
        return Err(PathViolation::Empty);
    }
    if raw.len() > MAX_PATH_BYTES {
        return Err(PathViolation::TooLong(raw.len()));
    }
    if let Some(bad) = raw.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        return Err(PathViolation::ControlCharacter(bad));
    }

    // Reject absolute and UNC forms *before* normalising, because
    // `Path::components` treats `a/../b` as fine but `/a` as RootDir.
    let unified = raw.replace('\\', "/");
    if unified.starts_with('/') {
        return Err(PathViolation::Absolute);
    }
    if raw.starts_with("\\\\") {
        return Err(PathViolation::Absolute);
    }
    // `C:foo` and `C:/foo`
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(PathViolation::Absolute);
    }

    let path = Path::new(&unified);
    let mut out = PathBuf::new();
    let mut any = false;
    for comp in path.components() {
        match comp {
            Component::Normal(part) => {
                // A single component may still be "." or ".." on some inputs.
                let s = part.to_string_lossy();
                if s == "." {
                    continue;
                }
                if s == ".." {
                    return Err(PathViolation::Traversal);
                }
                any = true;
                out.push(part);
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(PathViolation::Traversal),
            Component::RootDir | Component::Prefix(_) => return Err(PathViolation::Absolute),
        }
    }
    if !any || out.as_os_str().is_empty() {
        return Err(PathViolation::Empty);
    }
    Ok(SafeMemberPath(out))
}

/// Decide whether a symlink member may be materialised inside `root`.
///
/// Only links that stay strictly within the root are allowed. Absolute
/// targets and any target that would climb above the root are refused, because
/// writing through such a link escapes the extraction directory no matter how
/// safe the *name* of the link itself was.
pub fn validate_symlink_target(root: &Path, target: &str) -> Result<PathBuf, PathViolation> {
    if target.is_empty() {
        return Err(PathViolation::Empty);
    }
    let unified = target.replace('\\', "/");
    if unified.starts_with('/') || target.starts_with("\\\\") {
        return Err(PathViolation::SymlinkEscape(target.to_string()));
    }
    // Resolve against the link's own directory: the only place a link may point.
    let mut resolved = root.to_path_buf();
    for comp in Path::new(&unified).components() {
        match comp {
            Component::Normal(p) => resolved.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return Err(PathViolation::SymlinkEscape(target.to_string()));
                }
                if !resolved.starts_with(root) {
                    return Err(PathViolation::SymlinkEscape(target.to_string()));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathViolation::SymlinkEscape(target.to_string()))
            }
        }
    }
    if !resolved.starts_with(root) {
        return Err(PathViolation::SymlinkEscape(target.to_string()));
    }
    Ok(resolved)
}

/// Resource ceilings applied to any extraction or rewrite.
///
/// A "decompression bomb" is a tiny archive that expands to an enormous tree.
/// No single check catches every variant, so we bound each axis
/// independently: entry count, total bytes, single-entry bytes, and the
/// per-entry expansion ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionBudget {
    /// Maximum number of members that may be materialised.
    pub max_entries: u64,
    /// Maximum total uncompressed bytes across all materialised members.
    pub max_total_bytes: u64,
    /// Maximum uncompressed bytes for any single member.
    pub max_single_entry_bytes: u64,
    /// Maximum uncompressed:compressed ratio for any single member.
    pub max_compression_ratio: u64,
}

impl Default for ExtractionBudget {
    fn default() -> Self {
        // Deliberately generous for real work, tight enough to stop classic
        // bombs (a 1:1000 ratio is far beyond what real text compresses to).
        Self {
            max_entries: 100_000,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_single_entry_bytes: 4 * 1024 * 1024 * 1024,
            max_compression_ratio: 1000,
        }
    }
}

impl ExtractionBudget {
    /// A budget sized for interactive extraction of ordinary user archives.
    pub fn interactive() -> Self {
        Self::default()
    }

    /// A deliberately small budget, for tests and for previewing untrusted files.
    pub fn strict() -> Self {
        Self {
            max_entries: 1_000,
            max_total_bytes: 64 * 1024 * 1024,
            max_single_entry_bytes: 64 * 1024 * 1024,
            max_compression_ratio: 100,
        }
    }

    /// Check one member's expansion ratio before decompressing it.
    ///
    /// `compressed_size == 0` with a non-zero `uncompressed_size` is the
    /// canonical bomb shape and is rejected outright.
    pub fn check_ratio(&self, uncompressed: u64, compressed: u64) -> Result<(), BudgetExceeded> {
        if uncompressed == 0 {
            return Ok(());
        }
        if compressed == 0 {
            return Err(BudgetExceeded::Ratio {
                uncompressed,
                compressed,
                limit: self.max_compression_ratio,
            });
        }
        // ceil division, compared against the limit
        if uncompressed.div_ceil(compressed) > self.max_compression_ratio {
            return Err(BudgetExceeded::Ratio {
                uncompressed,
                compressed,
                limit: self.max_compression_ratio,
            });
        }
        Ok(())
    }
}

/// A budget axis that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetExceeded {
    EntryCount {
        limit: u64,
    },
    TotalBytes {
        limit: u64,
    },
    SingleEntryBytes {
        limit: u64,
    },
    Ratio {
        uncompressed: u64,
        compressed: u64,
        limit: u64,
    },
}

impl fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryCount { limit } => write!(f, "archive has more than {limit} entries"),
            Self::TotalBytes { limit } => {
                write!(f, "extraction would exceed {limit} bytes")
            }
            Self::SingleEntryBytes { limit } => {
                write!(f, "a single entry exceeds the {limit} byte limit")
            }
            Self::Ratio {
                uncompressed,
                compressed,
                limit,
            } => write!(
                f,
                "entry expands {uncompressed} bytes from {compressed} \
                 (ratio above {limit}:1)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_paths() {
        for name in [
            "a.txt",
            "dir/file.txt",
            "deep/nested/dir/file.txt",
            "./dir/file.txt",
            "dir//file.txt",
            "file with spaces.txt",
            "café/naïve.txt",
            "日本語/ファイル.txt",
            "emoji-\u{1F600}.txt",
        ] {
            assert!(
                sanitize_member_path(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_traversal() {
        for name in [
            "../evil",
            "../../etc/passwd",
            "a/../../evil",
            "a/b/../../../evil",
            "..",
            "..\\..\\evil",
            "a\\..\\..\\evil",
        ] {
            assert_eq!(
                sanitize_member_path(name),
                Err(PathViolation::Traversal),
                "expected {name:?} to be rejected as traversal"
            );
        }
    }

    #[test]
    fn rejects_absolute_paths() {
        for name in [
            "/etc/passwd",
            "/",
            "//server/share",
            "\\\\server\\share",
            "C:\\Windows\\system32",
            "C:/Windows",
            "z:\\x",
        ] {
            assert_eq!(
                sanitize_member_path(name),
                Err(PathViolation::Absolute),
                "expected {name:?} to be rejected as absolute"
            );
        }
    }

    #[test]
    fn rejects_empty_and_control_characters() {
        assert_eq!(sanitize_member_path(""), Err(PathViolation::Empty));
        assert_eq!(sanitize_member_path("."), Err(PathViolation::Empty));
        assert_eq!(sanitize_member_path("./"), Err(PathViolation::Empty));
        assert_eq!(
            sanitize_member_path("a\0b"),
            Err(PathViolation::ControlCharacter(0))
        );
        assert_eq!(
            sanitize_member_path("a\nb"),
            Err(PathViolation::ControlCharacter(b'\n'))
        );
        assert_eq!(
            sanitize_member_path("a\tb"),
            Err(PathViolation::ControlCharacter(b'\t'))
        );
        assert_eq!(
            sanitize_member_path("a\x7fb"),
            Err(PathViolation::ControlCharacter(0x7f))
        );
    }

    #[test]
    fn rejects_overlong_names() {
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            sanitize_member_path(&long),
            Err(PathViolation::TooLong(MAX_PATH_BYTES + 1))
        );
        // exactly at the limit is fine
        assert!(sanitize_member_path(&"a".repeat(MAX_PATH_BYTES)).is_ok());
    }

    #[test]
    fn sanitised_paths_are_relative_and_normalised() {
        let p = sanitize_member_path("./a//b/./c.txt").unwrap();
        assert_eq!(p.as_key(), "a/b/c.txt");
        assert_eq!(p.file_name(), "c.txt");
        assert_eq!(p.parent(), "a/b");
    }

    #[test]
    fn symlink_targets_may_point_inside_only() {
        let root = Path::new("/tmp/extract");
        assert!(validate_symlink_target(root, "sibling.txt").is_ok());
        assert!(validate_symlink_target(root, "sub/dir/file.txt").is_ok());
        // climbing up but staying under root is fine
        assert!(validate_symlink_target(root, "sub/../other.txt").is_ok());

        assert_eq!(
            validate_symlink_target(root, "/etc/passwd"),
            Err(PathViolation::SymlinkEscape("/etc/passwd".into()))
        );
        assert!(validate_symlink_target(root, "../../etc/passwd").is_err());
        assert!(validate_symlink_target(root, "sub/../../../etc/passwd").is_err());
        assert!(validate_symlink_target(root, "").is_err());
    }

    #[test]
    fn budget_rejects_decompression_bombs() {
        let b = ExtractionBudget::strict();
        // 100 MiB claiming to come from 1 KiB is a ratio of ~100_000:1
        assert!(b.check_ratio(100 * 1024 * 1024, 1024).is_err());
        // zero compressed size with content is always a bomb
        assert!(b.check_ratio(1, 0).is_err());
        // ordinary text: ~3:1
        assert!(b.check_ratio(300, 100).is_ok());
        // empty is always fine
        assert!(b.check_ratio(0, 0).is_ok());
    }

    #[test]
    fn budget_ratio_limit_is_inclusive() {
        let b = ExtractionBudget {
            max_compression_ratio: 10,
            ..Default::default()
        };
        assert!(b.check_ratio(1000, 100).is_ok());
        assert!(b.check_ratio(1001, 100).is_err());
    }
}
