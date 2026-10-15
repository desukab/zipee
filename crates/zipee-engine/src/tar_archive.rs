//! The tar container: read-only support.
//!
//! tar is the one container where Zipee is the *reader* rather than the
//! writer, because writing tar safely means preserving ownership, device
//! nodes and sparse-file maps that a general-purpose archiver should not
//! invent. The `tar` crate is deliberately not used here: its writer would
//! happily emit members with absolute paths and `..` in them, which is
//! exactly the class of bug this project exists to avoid. Zipee ships its own
//! reader so the safety rules cannot be bypassed by a dependency.

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use crate::archive::ArchiveAccess;
use crate::entry::{
    ArchiveEntry, ArchiveStats, Compression, Encryption, EntryKind, PasswordSource,
};
use crate::error::{Error, IoContext, Result};
use crate::format::Format;
use crate::security::{sanitize_member_path, SafeMemberPath};
use crate::vfs::Vfs;

/// Size of one tar header block.
const BLOCK: usize = 512;

/// An open tar archive.
#[derive(Debug)]
pub struct TarArchive {
    inner: Reader,
    path: PathBuf,
    format: Format,
}

#[derive(Debug)]
enum Reader {
    File(BufReader<File>),
    Bytes(Cursor<Vec<u8>>),
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Bytes(c) => c.read(buf),
        }
    }
}

impl Seek for Reader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Bytes(c) => c.seek(pos),
        }
    }
}

impl TarArchive {
    /// Open a tar from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).ctx("opening tar")?;
        Ok(Self {
            inner: Reader::File(BufReader::with_capacity(64 * 1024, file)),
            path: path.to_path_buf(),
            format: Format::Tar,
        })
    }

    /// Open a tar already in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            inner: Reader::Bytes(Cursor::new(bytes)),
            path: PathBuf::from("<memory>"),
            format: Format::Tar,
        })
    }

    /// The path this archive was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Parse an octal or base-256 tar numeric field.
///
/// GNU tar writes large values in base-256 (high bit set). Truncating those to
/// i64 would turn a 8 EiB file into a small positive number, so base-256 is
/// decoded explicitly.
fn parse_numeric(field: &[u8]) -> u64 {
    if field.is_empty() {
        return 0;
    }
    if field[0] & 0x80 != 0 {
        // GNU base-256: the field is a big-endian two's-complement integer whose
        // high bit is a marker. Decoding it byte-by-byte and dropping the first
        // byte's bits would shift the value and silently shrink large sizes,
        // so mask the marker in place and accumulate the whole field in u128.
        let negative = field[0] & 0x40 != 0;
        let mut v: u128 = 0;
        for (i, b) in field.iter().enumerate() {
            let byte = if i == 0 { b & 0x7f } else { *b };
            v = (v << 8) | byte as u128;
        }
        if negative {
            // tar does not use negative sizes; clamp rather than wrap.
            return 0;
        }
        return u64::try_from(v).unwrap_or(u64::MAX);
    }
    let s: String = field
        .iter()
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect();
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

/// The typeflag of a tar member.
fn parse_typeflag(b: u8) -> EntryKind {
    match b {
        b'0' | 0 => EntryKind::File,
        b'5' => EntryKind::Directory,
        b'2' => EntryKind::Symlink,
        b'1' | b'3' | b'4' | b'6' => EntryKind::Special,
        // '7' contiguous file and 'L'/'K' long-name extensions are handled by
        // the caller; anything else is treated as a regular file.
        _ => EntryKind::File,
    }
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Build an [`ArchiveEntry`] from one 512-byte ustar header.
fn entry_from_header(header: &[u8], name: &str, prefix: &str) -> Option<ArchiveEntry> {
    let full_name = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    };
    let size = parse_numeric(&header[124..136]);
    let mtime = parse_numeric(&header[136..148]);
    let mode = parse_numeric(&header[100..108]);
    let typeflag = header[156];
    let kind = parse_typeflag(typeflag);
    let linkname = cstr(&header[157..257]);

    let raw = if kind == EntryKind::Symlink && !linkname.is_empty() {
        linkname
    } else {
        full_name
    };

    let raw_name = if kind == EntryKind::Directory {
        raw.trim_end_matches('/').to_string()
    } else {
        raw.clone()
    };

    // One validation pass; its result is what the entry carries.
    let (path, violation) = match sanitize_member_path(&raw_name) {
        Ok(p) => (Some(p), None),
        Err(v) => (None, Some(v)),
    };

    Some(ArchiveEntry {
        raw_name,
        path,
        path_violation: violation,
        kind,
        uncompressed_size: if kind == EntryKind::Directory {
            0
        } else {
            size
        },
        // tar has no per-member compression
        compressed_size: if kind == EntryKind::Directory {
            0
        } else {
            size
        },
        compression: Compression::Stored,
        encryption: Encryption::None,
        modified: std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(mtime)),
        unix_mode: Some((mode & 0o7777) as u32),
        crc32: None,
    })
}

/// Read a member's body, given the current stream position.
///
/// A member's data is padded to a multiple of [`BLOCK`]; the padding is
/// skipped so the next header lands correctly.
fn read_member_data<R: Read>(reader: &mut R, size: u64) -> Result<Vec<u8>> {
    let capped = size.min(64 * 1024 * 1024);
    let mut buf = vec![0u8; capped as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|_| Error::Corrupt("tar ends inside a member".into()))?;
    // Skip any tail we deliberately truncated plus the block padding.
    let padding = (BLOCK - (size as usize % BLOCK)) % BLOCK;
    std::io::copy(
        &mut reader.by_ref().take(size - capped + padding as u64),
        &mut std::io::sink(),
    )
    .ctx("skipping tar padding")?;
    Ok(buf)
}

/// True for the all-zero block that marks end-of-archive.
fn is_terminator(block: &[u8]) -> bool {
    block.iter().all(|b| *b == 0)
}

/// Read the raw member table of a tar.
fn walk<R: Read + Seek>(reader: &mut R) -> Result<Vec<ArchiveEntry>> {
    let mut entries = Vec::new();
    let mut header = [0u8; BLOCK];
    let mut pending_name: Option<String> = None;

    loop {
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::Corrupt("tar is truncated".into()))?;
        if is_terminator(&header) {
            break;
        }

        // Verify the header checksum: a corrupted header would otherwise make
        // every field garbage.
        let declared = parse_numeric(&header[148..156]);
        let computed: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as u64
                } else {
                    *b as u64
                }
            })
            .sum();
        if declared != 0 && declared != computed {
            return Err(Error::Corrupt(format!(
                "tar header checksum mismatch (declared {declared}, computed {computed})"
            )));
        }

        let name = cstr(&header[0..100]);
        let prefix = cstr(&header[345..500]);
        let typeflag = header[156];

        // GNU long-name extension: the *next* header's name lives in this body.
        if typeflag == b'L' {
            let size = parse_numeric(&header[124..136]);
            let long = read_member_data(reader, size)?;
            pending_name = Some(cstr(&long));
            continue;
        }
        // Long link target, for symlinks whose target exceeds 100 bytes.
        if typeflag == b'K' {
            let size = parse_numeric(&header[124..136]);
            read_member_data(reader, size)?;
            continue;
        }
        // Global extended header (pax): skip the body, keep going.
        if typeflag == b'g' || typeflag == b'x' {
            let size = parse_numeric(&header[124..136]);
            read_member_data(reader, size)?;
            continue;
        }

        let entry_name = pending_name.take().unwrap_or(name);
        if let Some(entry) = entry_from_header(&header, &entry_name, &prefix) {
            entries.push(entry);
        }

        let size = parse_numeric(&header[124..136]);
        if parse_typeflag(typeflag) != EntryKind::Directory {
            read_member_data(reader, size)?;
        } else {
            let padding = (BLOCK - (size as usize % BLOCK)) % BLOCK;
            std::io::copy(
                &mut reader.by_ref().take(padding as u64),
                &mut std::io::sink(),
            )
            .ctx("skipping directory padding")?;
        }
    }
    Ok(entries)
}

impl ArchiveAccess for TarArchive {
    fn format(&self) -> Format {
        self.format
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self) -> Result<Vec<ArchiveEntry>> {
        self.inner
            .seek(std::io::SeekFrom::Start(0))
            .ctx("rewinding tar")?;
        walk(&mut self.inner)
    }

    fn stats(&mut self) -> Result<ArchiveStats> {
        Ok(ArchiveStats::from_entries(&self.entries()?))
    }

    fn vfs(&mut self) -> Result<Vfs> {
        Ok(Vfs::from_entries(&self.entries()?))
    }

    fn read_entry(&mut self, name: &str, _passwords: &mut dyn PasswordSource) -> Result<Vec<u8>> {
        self.inner
            .seek(std::io::SeekFrom::Start(0))
            .ctx("rewinding tar")?;
        let entries = walk(&mut self.inner)?;
        let entry = entries
            .iter()
            .find(|e| e.raw_name == name)
            .ok_or_else(|| Error::NoSuchEntry(name.to_string()))?;

        // Seek directly: the index pass left us at the end, so re-walk to the
        // member. Tar has no random access index of its own.
        self.inner
            .seek(std::io::SeekFrom::Start(0))
            .ctx("rewinding tar")?;
        let mut header = [0u8; BLOCK];
        let mut pending_name: Option<String> = None;
        loop {
            self.inner
                .read_exact(&mut header)
                .map_err(|_| Error::Corrupt("tar is truncated".into()))?;
            if is_terminator(&header) {
                return Err(Error::NoSuchEntry(name.to_string()));
            }
            let typeflag = header[156];
            let size = parse_numeric(&header[124..136]);
            let this_name = cstr(&header[0..100]);
            let prefix = cstr(&header[345..500]);

            if matches!(typeflag, b'L' | b'K' | b'g' | b'x') {
                let body = read_member_data(&mut self.inner, size)?;
                if typeflag == b'L' {
                    pending_name = Some(cstr(&body));
                }
                continue;
            }
            let candidate = pending_name.take().unwrap_or(this_name);
            let effective = if prefix.is_empty() {
                candidate.clone()
            } else {
                format!("{prefix}/{candidate}")
            };
            let effective = if parse_typeflag(typeflag) == EntryKind::Directory {
                effective.trim_end_matches('/').to_string()
            } else {
                effective
            };

            if effective == entry.raw_name && parse_typeflag(typeflag) != EntryKind::Directory {
                return read_member_data(&mut self.inner, size);
            }
            if parse_typeflag(typeflag) != EntryKind::Directory {
                read_member_data(&mut self.inner, size)?;
            }
        }
    }
}

/// A tar member's sanitised path, for callers that build one on the fly.
pub fn safe_path_for(name: &str) -> Result<SafeMemberPath> {
    Ok(sanitize_member_path(name)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, size: u64, typeflag: u8, link: &str) -> Vec<u8> {
        let mut h = vec![0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let put = |h: &mut Vec<u8>, off: usize, len: usize, v: u64| {
            let s = format!("{v:0width$o}", width = len - 1);
            h[off..off + s.len()].copy_from_slice(s.as_bytes());
        };
        put(&mut h, 100, 8, 0o644);
        put(&mut h, 108, 8, 0);
        put(&mut h, 116, 8, 0);
        put(&mut h, 124, 12, size);
        put(&mut h, 136, 12, 1_700_000_000);
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        if !link.is_empty() {
            h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        }
        h[257..262].copy_from_slice(b"ustar");
        h[263..265].copy_from_slice(b"00");
        let sum: u64 = h.iter().map(|b| *b as u64).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..148 + s.len()].copy_from_slice(s.as_bytes());
        h
    }

    fn build_tar(members: &[(&str, u64, u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, _, tf, link, body) in members {
            out.extend(header(name, body.len() as u64, *tf, link));
            out.extend_from_slice(body);
            let pad = (BLOCK - (body.len() % BLOCK)) % BLOCK;
            out.extend(std::iter::repeat(0u8).take(pad));
        }
        out.extend(std::iter::repeat(0u8).take(BLOCK * 2));
        out
    }

    #[test]
    fn parses_numeric_forms() {
        assert_eq!(parse_numeric(b"00000000000\0"), 0);
        assert_eq!(parse_numeric(b"00000001234\0"), 0o1234);
        assert_eq!(parse_numeric(b""), 0);
        assert_eq!(parse_numeric(b"   "), 0);
        // base-256 value above 2^32: marker bit in byte 0, then big-endian
        let value: u64 = 5_000_000_000;
        let mut b256 = [0u8; 12];
        b256[0] = 0x80;
        b256[4..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(parse_numeric(&b256), value);
        assert!(parse_numeric(&b256) > 1 << 32);
    }

    #[test]
    fn typeflags_map_to_kinds() {
        assert_eq!(parse_typeflag(b'0'), EntryKind::File);
        assert_eq!(parse_typeflag(0), EntryKind::File);
        assert_eq!(parse_typeflag(b'5'), EntryKind::Directory);
        assert_eq!(parse_typeflag(b'2'), EntryKind::Symlink);
        assert_eq!(parse_typeflag(b'3'), EntryKind::Special);
    }

    #[test]
    fn reads_a_simple_tar() {
        let tar = build_tar(&[
            ("hello.txt", 0, b'0', "", b"hello world"),
            ("dir/", 0, b'5', "", b""),
            ("dir/inner.bin", 0, b'0', "", &[0u8, 1, 2, 3]),
        ]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        let entries = a.entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].raw_name, "hello.txt");
        assert_eq!(entries[1].kind, EntryKind::Directory);
        assert_eq!(entries[2].raw_name, "dir/inner.bin");
        assert_eq!(entries[2].uncompressed_size, 4);
    }

    #[test]
    fn reads_member_contents() {
        let tar = build_tar(&[
            ("a.txt", 0, b'0', "", b"alpha"),
            ("b.txt", 0, b'0', "", b"bravo"),
        ]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        assert_eq!(
            a.read_entry("a.txt", &mut crate::entry::NoPassword)
                .unwrap(),
            b"alpha"
        );
        assert_eq!(
            a.read_entry("b.txt", &mut crate::entry::NoPassword)
                .unwrap(),
            b"bravo"
        );
        assert!(a
            .read_entry("missing", &mut crate::entry::NoPassword)
            .is_err());
    }

    #[test]
    fn rejects_corrupt_header_checksum() {
        let mut tar = build_tar(&[("a.txt", 0, b'0', "", b"x")]);
        // Write a well-formed but wrong octal checksum. An all-NUL field is the
        // documented "unknown checksum" escape hatch and is deliberately allowed.
        let correct: u32 = {
            let sum: u32 = tar[148..156].iter().map(|b| *b as u32).sum();
            sum
        };
        let wrong = format!("{:06o}\0 ", correct.wrapping_add(1));
        tar[148..156].copy_from_slice(wrong.as_bytes());
        let mut a = TarArchive::from_bytes(tar).unwrap();
        let err = a.entries().unwrap_err();
        assert!(err.to_string().contains("checksum"), "got {err}");

        // ...and the untouched archive must still parse.
        let good = build_tar(&[("a.txt", 0, b'0', "", b"x")]);
        let mut ok = TarArchive::from_bytes(good).unwrap();
        assert_eq!(ok.entries().unwrap().len(), 1);
    }

    #[test]
    fn rejects_truncated_tar() {
        let mut tar = build_tar(&[("a.txt", 0, b'0', "", b"hello")]);
        tar.truncate(300);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        assert!(a.entries().is_err());
    }

    #[test]
    fn rejects_traversal_members() {
        let tar = build_tar(&[("../../etc/passwd", 0, b'0', "", b"x")]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        let entries = a.entries().unwrap();
        assert!(entries[0].is_unsafe());
    }

    #[test]
    fn rejects_absolute_members() {
        let tar = build_tar(&[("/etc/passwd", 0, b'0', "", b"x")]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        assert!(a.entries().unwrap()[0].is_unsafe());
    }

    #[test]
    fn symlink_members_are_not_followed() {
        let tar = build_tar(&[("link", 0, b'2', "/etc/passwd", b"")]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        let e = &a.entries().unwrap()[0];
        assert_eq!(e.kind, EntryKind::Symlink);
        assert!(e.is_unsafe(), "escaping symlink target must be rejected");
    }

    #[test]
    fn vfs_builds_a_tree() {
        let tar = build_tar(&[
            ("dir/a.txt", 0, b'0', "", b"a"),
            ("dir/b.txt", 0, b'0', "", b"bb"),
        ]);
        let mut a = TarArchive::from_bytes(tar).unwrap();
        let vfs = a.vfs().unwrap();
        assert!(vfs.is_directory("dir"));
        assert_eq!(vfs.children("dir").len(), 2);
        assert_eq!(vfs.subtree_size("dir"), 3);
    }

    #[test]
    fn empty_tar_is_valid() {
        let mut a = TarArchive::from_bytes(vec![0u8; BLOCK * 2]).unwrap();
        assert_eq!(a.entries().unwrap().len(), 0);
        assert_eq!(a.stats().unwrap().total_entries, 0);
    }
}
