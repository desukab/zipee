//! The archive entry model shared by every container Zipee supports.
//!
//! The UI, the CLI and the macOS bridge all speak this one type, so adding a
//! container means implementing [`ArchiveAccess`](crate::archive::ArchiveAccess)
//! and nothing else changes for callers.

use std::fmt;
use std::time::SystemTime;

use crate::format::Format;
use crate::security::SafeMemberPath;

/// What kind of thing a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory. Carries no data of its own.
    Directory,
    /// A regular file.
    File,
    /// A symbolic link. Zipee never follows links while extracting.
    Symlink,
    /// Anything else (device nodes, FIFOs) — recorded but never materialised.
    Special,
}

impl EntryKind {
    /// True for [`EntryKind::File`].
    pub fn is_file(self) -> bool {
        matches!(self, Self::File)
    }
}

/// How a member's bytes are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    Stored,
    /// DEFLATE, the ZIP default.
    Deflate,
    /// bzip2.
    Bzip2,
    /// LZMA.
    Lzma,
    /// LZMA2.
    Lzma2,
    /// Zstandard.
    Zstd,
    /// Something Zipee recognises as compressed but does not implement.
    Unsupported(u16),
}

/// Whether a member needs a password to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// Readable without a password.
    None,
    /// Traditional PKWARE ZipCrypto. Weak, and read-only in practice.
    ZipCrypto,
    /// WinZip AES (AES-CTR with an HMAC-SHA1 authentication code).
    WinZipAes,
    /// AES as used by 7-Zip.
    SevenZipAes,
    /// Encrypted with a method Zipee does not implement.
    Unsupported(u16),
}

impl Encryption {
    /// True when the member cannot be read without a password.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One member of an archive, as reported by the container's index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// The member name exactly as stored, before safety checking.
    pub raw_name: String,
    /// The sanitised relative path. `None` when the name was rejected.
    pub path: Option<SafeMemberPath>,
    /// Why the name was rejected, when `path` is `None`.
    pub path_violation: Option<crate::security::PathViolation>,
    /// Directory, file, symlink or special.
    pub kind: EntryKind,
    /// Size once decompressed.
    pub uncompressed_size: u64,
    /// Size as stored in the container.
    pub compressed_size: u64,
    /// Which compressor was used.
    pub compression: Compression,
    /// Whether a password is required.
    pub encryption: Encryption,
    /// Last modification time, when the container records one.
    pub modified: Option<SystemTime>,
    /// Unix mode bits, when the container records them.
    pub unix_mode: Option<u32>,
    /// CRC-32 of the uncompressed data, when the container records one.
    pub crc32: Option<u32>,
}

impl ArchiveEntry {
    /// True when Zipee refused this member's path for safety reasons.
    pub fn is_unsafe(&self) -> bool {
        self.path.is_none()
    }

    /// Bytes saved compared with storing the member uncompressed.
    pub fn saved_bytes(&self) -> u64 {
        self.uncompressed_size.saturating_sub(self.compressed_size)
    }

    /// Compression ratio as a percentage in `0..=100`, or `None` when unknown.
    pub fn ratio_percent(&self) -> Option<u64> {
        if self.uncompressed_size == 0 {
            return None;
        }
        self.compressed_size
            .checked_mul(100)
            .map(|v| v / self.uncompressed_size)
    }

    /// The sanitised path as a `/`-joined string, or the raw name if unsafe.
    pub fn key(&self) -> String {
        match &self.path {
            Some(p) => p.as_key(),
            None => self.raw_name.clone(),
        }
    }
}

/// Summary statistics for a whole archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArchiveStats {
    /// Total members, including directories and unsafe entries.
    pub total_entries: u64,
    /// Members that are regular files.
    pub files: u64,
    /// Members that are directories.
    pub directories: u64,
    /// Members whose path Zipee refused to use.
    pub unsafe_entries: u64,
    /// Members that are encrypted.
    pub encrypted_entries: u64,
    /// Sum of uncompressed sizes of all members.
    pub uncompressed_bytes: u64,
    /// Sum of compressed sizes of all members.
    pub compressed_bytes: u64,
}

impl ArchiveStats {
    /// Build stats from a slice of entries.
    pub fn from_entries(entries: &[ArchiveEntry]) -> Self {
        let mut s = Self::default();
        for e in entries {
            s.total_entries += 1;
            match e.kind {
                EntryKind::File => s.files += 1,
                EntryKind::Directory => s.directories += 1,
                _ => {}
            }
            if e.is_unsafe() {
                s.unsafe_entries += 1;
            }
            if e.encryption.is_encrypted() {
                s.encrypted_entries += 1;
            }
            s.uncompressed_bytes = s.uncompressed_bytes.saturating_add(e.uncompressed_size);
            s.compressed_bytes = s.compressed_bytes.saturating_add(e.compressed_size);
        }
        s
    }

    /// Overall compression ratio as a percentage in `0..=100`.
    pub fn ratio_percent(&self) -> u64 {
        self.compressed_bytes
            .checked_mul(100)
            .and_then(|v| v.checked_div(self.uncompressed_bytes))
            .unwrap_or(0)
    }

    /// Human-readable total size, e.g. `1.4 GB`.
    pub fn human_uncompressed(&self) -> String {
        human_bytes(self.uncompressed_bytes)
    }

    /// Human-readable compressed size.
    pub fn human_compressed(&self) -> String {
        human_bytes(self.compressed_bytes)
    }
}

/// Format a byte count using decimal units, matching macOS Finder.
pub fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["bytes", "KB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return if n == 1 {
            "1 byte".to_string()
        } else {
            format!("{n} bytes")
        };
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i + 1 < UNITS.len() {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Where an entry sits inside its archive, for progress reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// Members completed so far.
    pub done: u64,
    /// Members to process in total.
    pub total: u64,
    /// Uncompressed bytes written so far.
    pub bytes_done: u64,
    /// Total uncompressed bytes expected.
    pub bytes_total: u64,
    /// Name of the member just finished, for the UI.
    pub current: String,
}

impl Progress {
    /// Fraction complete in `0.0..=1.0`, by member count.
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.done as f64 / self.total as f64).min(1.0)
        }
    }
}

impl fmt::Display for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of {} ({:.0}%)",
            self.done,
            self.total,
            self.fraction() * 100.0
        )
    }
}

/// How a password was supplied to the engine.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub String);

impl Secret {
    /// Build a secret from any string-like value.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Debug for Secret {
    /// Never print the password, not even in a panic message or a test failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A source of passwords, consulted lazily so the UI can prompt on demand.
///
/// The macOS app implements this with a `PasswordChannel` so that the
/// sandboxed engine never has to hold a password the user has not typed yet.
pub trait PasswordSource {
    /// Return the password for `entry`, or `None` if the user cancelled.
    fn password_for(&mut self, entry: &ArchiveEntry) -> Option<Secret>;
}

/// A source that always answers with the same password.
///
/// Used by the CLI (`--password`), by tests, and as the fallback when an
/// archive needs one password for every member.
#[derive(Debug, Clone, Default)]
pub struct StaticPassword(pub Option<Secret>);

impl PasswordSource for StaticPassword {
    fn password_for(&mut self, _entry: &ArchiveEntry) -> Option<Secret> {
        self.0.clone()
    }
}

/// Lets a caller hold either concrete source behind one box.
impl PasswordSource for Box<dyn PasswordSource> {
    fn password_for(&mut self, entry: &ArchiveEntry) -> Option<Secret> {
        (**self).password_for(entry)
    }
}

/// A source that has no password, so encrypted members fail cleanly.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPassword;

impl PasswordSource for NoPassword {
    fn password_for(&mut self, _entry: &ArchiveEntry) -> Option<Secret> {
        None
    }
}

/// The container kinds an [`ArchiveAccess`](crate::archive::ArchiveAccess)
/// implementation can report.
pub trait FormatInfo {
    /// The container this archive is.
    fn format(&self) -> Format;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: EntryKind, usize_: u64, csize: u64) -> ArchiveEntry {
        ArchiveEntry {
            raw_name: name.to_string(),
            path: crate::security::sanitize_member_path(name).ok(),
            path_violation: None,
            kind,
            uncompressed_size: usize_,
            compressed_size: csize,
            compression: Compression::Deflate,
            encryption: Encryption::None,
            modified: None,
            unix_mode: None,
            crc32: None,
        }
    }

    #[test]
    fn stats_count_correctly() {
        let entries = vec![
            entry("a.txt", EntryKind::File, 1000, 100),
            entry("dir", EntryKind::Directory, 0, 0),
            entry("dir/b.txt", EntryKind::File, 1000, 900),
            entry("../evil", EntryKind::File, 10, 10),
        ];
        let s = ArchiveStats::from_entries(&entries);
        assert_eq!(s.total_entries, 4);
        assert_eq!(s.files, 3);
        assert_eq!(s.directories, 1);
        assert_eq!(s.unsafe_entries, 1);
        assert_eq!(s.uncompressed_bytes, 2010);
        assert_eq!(s.compressed_bytes, 1010);
    }

    #[test]
    fn unsafe_entry_keeps_raw_name() {
        let e = entry("../evil", EntryKind::File, 1, 1);
        assert!(e.is_unsafe());
        assert_eq!(e.key(), "../evil");
    }

    #[test]
    fn safe_entry_key_is_normalised() {
        let e = entry("./a/b.txt", EntryKind::File, 1, 1);
        assert!(!e.is_unsafe());
        assert_eq!(e.key(), "a/b.txt");
    }

    #[test]
    fn secret_never_prints_its_value() {
        let s = Secret::new("hunter2");
        let shown = format!("{s:?}");
        assert_eq!(shown, "Secret(<redacted>)");
        assert!(!shown.contains("hunter2"));
        // `Secret` deliberately implements neither `Display` nor `Debug`
        // beyond the redacted form, so a password cannot reach a log line.
    }

    #[test]
    fn human_bytes_formats_readable_sizes() {
        use super::human_bytes as fmt_bytes;
        assert_eq!(fmt_bytes(0), "0 bytes");
        assert_eq!(fmt_bytes(1), "1 byte");
        assert_eq!(fmt_bytes(999), "999 bytes");
        assert_eq!(fmt_bytes(1000), "1.0 KB");
        assert_eq!(fmt_bytes(1_500_000), "1.5 MB");
        assert_eq!(fmt_bytes(1_400_000_000), "1.4 GB");
    }

    #[test]
    fn ratio_percent() {
        assert_eq!(
            entry("a", EntryKind::File, 1000, 250).ratio_percent(),
            Some(25)
        );
        assert_eq!(entry("a", EntryKind::File, 0, 0).ratio_percent(), None);
        assert_eq!(
            entry("a", EntryKind::File, 1000, 0).ratio_percent(),
            Some(0)
        );
    }

    #[test]
    fn progress_fraction() {
        let p = Progress {
            done: 0,
            total: 0,
            bytes_done: 0,
            bytes_total: 0,
            current: String::new(),
        };
        assert_eq!(p.fraction(), 1.0);
        let p = Progress {
            done: 5,
            total: 10,
            bytes_done: 0,
            bytes_total: 0,
            current: String::new(),
        };
        assert_eq!(p.fraction(), 0.5);
        let p = Progress {
            done: 10,
            total: 10,
            bytes_done: 0,
            bytes_total: 0,
            current: String::new(),
        };
        assert_eq!(p.fraction(), 1.0);
    }
}
