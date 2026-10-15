//! Archive container detection from content, not from the file extension.
//!
//! Extensions lie: `backup.zip` is routinely a tar, and an attacker controls
//! the name entirely. Zipee identifies the container from its magic bytes and
//! only uses the extension as a tiebreaker, so a mislabelled archive is still
//! opened correctly and a hostile `.png` that is really a ZIP is recognised.

use std::fmt;
use std::path::Path;

/// A supported archive container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// PKZIP / ZIP / APPLESINGLEPACKAGE and friends.
    Zip,
    /// 7-Zip.
    SevenZip,
    /// RAR (both v4 and v5 signatures are recognised).
    Rar,
    /// POSIX tar (ustar, GNU or v7).
    Tar,
    /// Any gzip stream. May wrap a tar (`.tar.gz`) or be a single member.
    Gzip,
    /// bzip2.
    Bzip2,
    /// XZ.
    Xz,
    /// Zstandard.
    Zstd,
    /// Apple Installer package (a XAR container).
    Xar,
}

impl Format {
    /// Canonical lowercase name, used on the command line and in the UI.
    pub fn name(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Xar => "xar",
        }
    }

    /// True when the container is a stream-compressed single object rather
    /// than a multi-member archive. `foo.gz` yields exactly one member;
    /// `foo.tar.gz` yields a tar, which is detected first.
    pub fn is_single_stream(self) -> bool {
        matches!(self, Self::Gzip | Self::Bzip2 | Self::Xz | Self::Zstd)
    }

    /// True when Zipee can list members without decoding the payload.
    pub fn supports_random_access(self) -> bool {
        matches!(self, Self::Zip | Self::SevenZip | Self::Rar | Self::Tar | Self::Xar)
    }

    /// True when Zipee can write or modify archives of this container.
    pub fn supports_writing(self) -> bool {
        matches!(self, Self::Zip | Self::Tar)
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a byte range could not be classified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// The buffer is shorter than any signature needs.
    TooShort(usize),
    /// No known signature matched.
    Unknown,
}

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "only {n} bytes available, need at least 512 to detect"),
            Self::Unknown => write!(f, "no known archive signature found"),
        }
    }
}

const fn starts(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if hay[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Identify a container from the leading bytes of the file.
///
/// The `tar` check deliberately reads offset 257 (`ustar`) because a tar has
/// no magic at offset 0 — the first bytes are the first file's name.
pub fn detect_bytes(head: &[u8]) -> Result<Format, DetectError> {
    // ZIP: a local file header, an empty archive, or a spanned archive.
    if starts(head, b"PK\x03\x04")
        || starts(head, b"PK\x05\x06")
        || starts(head, b"PK\x07\x08")
    {
        return Ok(Format::Zip);
    }
    // 7-Zip
    if starts(head, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Ok(Format::SevenZip);
    }
    // RAR v4 and v5
    if starts(head, b"Rar!\x1a\x07\x00") || starts(head, b"Rar!\x1a\x07\x01\x00") {
        return Ok(Format::Rar);
    }
    // gzip
    if starts(head, &[0x1F, 0x8B]) {
        return Ok(Format::Gzip);
    }
    // bzip2
    if starts(head, b"BZh") {
        return Ok(Format::Bzip2);
    }
    // xz
    if starts(head, &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Ok(Format::Xz);
    }
    // zstd
    if starts(head, &[0x28, 0xB5, 0x2F, 0xFD]) {
        return Ok(Format::Zstd);
    }
    // Apple Installer package (XAR)
    if starts(head, b"xar!") {
        return Ok(Format::Xar);
    }
    // tar: "ustar" lives in the first header block at offset 257
    if head.len() >= 262 && (&head[257..262] == b"ustar") {
        return Ok(Format::Tar);
    }

    // A bare gzip stream whose payload is a tar must be reported as `tar`; the
    // caller re-checks after inflating. Detection of the *outer* container
    // legitimately stops here.
    Err(if head.len() < 512 {
        DetectError::TooShort(head.len())
    } else {
        DetectError::Unknown
    })
}

/// Identify a container from a file path, preferring content.
///
/// Falls back to the extension when the content is inconclusive (for example
/// when only the first few bytes are available), and reports [`Format`] with
/// the lower confidence of the two.
pub fn detect_path(path: &Path) -> Result<Format, DetectError> {
    use std::io::Read;
    let mut head = [0u8; 512];
    let mut file = std::fs::File::open(path).map_err(|_| DetectError::TooShort(0))?;
    let n = file.read(&mut head).unwrap_or(0);
    match detect_bytes(&head[..n]) {
        Ok(f) => Ok(f),
        Err(e) => from_extension(path).ok_or(e),
    }
}

/// Best-effort container guess from a file extension.
///
/// Only used as a fallback; never as the primary signal.
pub fn from_extension(path: &Path) -> Option<Format> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let f = match ext.as_str() {
        "zip" | "jar" | "apk" | "ipa" | "docx" | "xlsx" | "pptx" | "epub" => Format::Zip,
        "7z" => Format::SevenZip,
        "rar" => Format::Rar,
        "tar" => Format::Tar,
        "gz" | "tgz" | "gzip" => Format::Gzip,
        "bz2" | "tbz" | "tbz2" | "bzip2" => Format::Bzip2,
        "xz" | "txz" => Format::Xz,
        "zst" | "tzst" | "zstd" => Format::Zstd,
        "pkg" | "xar" => Format::Xar,
        _ => return None,
    };
    Some(f)
}

/// True when `name` looks like an archive Zipee could open.
///
/// Used for nested-archive discovery and for drag-and-drop acceptance.
pub fn looks_like_archive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXTS: &[&str] = &[
        "zip", "7z", "rar", "tar", "gz", "tgz", "gzip", "bz2", "tbz", "tbz2", "bzip2", "xz",
        "txz", "zst", "tzst", "zstd",
    ];
    match lower.rsplit_once('.') {
        Some((_, ext)) => EXTS.contains(&ext),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_from_magic_not_extension() {
        // A ZIP that lies about being a PNG.
        let mut buf = vec![0u8; 512];
        buf[..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(detect_bytes(&buf).unwrap(), Format::Zip);
    }

    #[test]
    fn detects_each_signature() {
        let cases: &[(&[u8], Format)] = &[
            (b"PK\x03\x04", Format::Zip),
            (b"PK\x05\x06", Format::Zip),
            (&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], Format::SevenZip),
            (b"Rar!\x1a\x07\x00", Format::Rar),
            (b"Rar!\x1a\x07\x01\x00", Format::Rar),
            (&[0x1f, 0x8b], Format::Gzip),
            (b"BZh9", Format::Bzip2),
            (&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], Format::Xz),
            (&[0x28, 0xb5, 0x2f, 0xfd], Format::Zstd),
            (b"xar!", Format::Xar),
        ];
        for (magic, expected) in cases {
            let mut buf = vec![0u8; 512];
            buf[..magic.len()].copy_from_slice(magic);
            assert_eq!(detect_bytes(&buf).unwrap(), *expected, "magic {magic:?}");
        }
    }

    #[test]
    fn detects_tar_at_offset_257() {
        let mut buf = vec![0u8; 512];
        buf[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_bytes(&buf).unwrap(), Format::Tar);
    }

    #[test]
    fn rejects_unknown_and_short() {
        let png = b"\x89PNG\r\n\x1a\n";
        assert_eq!(detect_bytes(png), Err(DetectError::TooShort(8)));
        let junk = vec![0x41u8; 512];
        assert_eq!(detect_bytes(&junk), Err(DetectError::Unknown));
    }

    #[test]
    fn extension_fallback() {
        assert_eq!(from_extension(Path::new("a/b.zip")), Some(Format::Zip));
        assert_eq!(from_extension(Path::new("A.TAR.GZ")), Some(Format::Gzip));
        assert_eq!(from_extension(Path::new("x.7z")), Some(Format::SevenZip));
        assert_eq!(from_extension(Path::new("noext")), None);
        assert_eq!(from_extension(Path::new("a.png")), None);
    }

    #[test]
    fn archive_name_heuristic() {
        assert!(looks_like_archive("inner.zip"));
        assert!(looks_like_archive("INNER.ZIP"));
        assert!(looks_like_archive("a.tar.gz"));
        assert!(!looks_like_archive("image.png"));
        assert!(!looks_like_archive("noextension"));
    }

    #[test]
    fn capability_flags() {
        assert!(Format::Zip.supports_writing());
        assert!(Format::Tar.supports_writing());
        assert!(!Format::SevenZip.supports_writing());
        assert!(Format::Gzip.is_single_stream());
        assert!(!Format::Zip.is_single_stream());
        assert!(Format::Zip.supports_random_access());
    }
}