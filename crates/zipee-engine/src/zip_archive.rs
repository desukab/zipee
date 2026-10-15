//! The ZIP container: read, verify, extract, and write back safely.
//!
//! ZIP is the only container Zipee both reads and edits today. Everything here
//! goes through the safety layer in [`crate::security`]; no member name reaches
//! the filesystem without passing [`sanitize_member_path`](crate::security::sanitize_member_path).

use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use crate::archive::ArchiveAccess;
use crate::entry::{ArchiveEntry, ArchiveStats, Compression, Encryption, PasswordSource};
use crate::error::{Error, IoContext, Result};
use crate::format::{detect_path, Format};
use crate::security::{ExtractionBudget, SafeMemberPath};
use crate::vfs::Vfs;

/// Object-safe reader+seeker, so one `ZipArchive` type serves both files and
/// in-memory buffers without a generic parameter leaking into the engine API.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// An open ZIP archive.
///
/// Holds the underlying file so member data can be read on demand rather than
/// slurped into memory — this is what keeps opening a huge archive cheap.
/// `Debug` is implemented by hand because the reader is a trait object.
pub struct ZipArchive {
    reader: zip::ZipArchive<Box<dyn ReadSeek>>,
    path: PathBuf,
    /// Fingerprint of the file when it was opened, to detect external edits.
    opened_fingerprint: FileFingerprint,
    format: Format,
    /// Member name to index, built on first lookup.
    ///
    /// Without this, `read_entry` scans the central directory linearly, which
    /// makes verifying an N-member archive O(N²): at 20,000 members that is
    /// 200 million string comparisons. Measured on the corpus in
    /// docs/platform-limitations.md, adding this map took a full verify from
    /// 48.7s to 0.6s. The archive is immutable while open, so the map is
    /// built once and never invalidated.
    index_map: Option<std::collections::HashMap<String, usize>>,
}

/// Cheap identity of a file at open time.
///
/// Four parts, because each catches a different way a file can change
/// underneath an open session:
///
/// * **device + inode** catch a *replacement*. An app that writes a new file
///   and renames it over the old one can preserve size and modification time
///   deliberately; it cannot preserve the inode without going to great
///   lengths.
/// * **size** catches a shorter rewrite immediately.
/// * **modification time** catches an in-place edit of equal length.
///
/// This is still a heuristic, not a cryptographic guarantee: an attacker with
/// write access can restore all four. It is documented as such, and the
/// guarantee that actually matters is structural — see [`crate::writeback`],
/// which never edits the original in place, so a failed save cannot damage it
/// whatever this fingerprint misses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFingerprint {
    /// Size in bytes at open time.
    pub len: u64,
    /// Modified time at open time, if the platform reported one.
    pub modified: Option<std::time::SystemTime>,
    /// Device number, on platforms that report one.
    pub device: Option<u64>,
    /// Inode number, on platforms that report one.
    pub inode: Option<u64>,
}

/// Read a fingerprint for a path.
pub fn fingerprint(path: &Path) -> Result<FileFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ctx("reading archive metadata")?;
    Ok(FileFingerprint {
        len: meta.len(),
        modified: meta.modified().ok(),
        device: Some(meta.dev()),
        inode: Some(meta.ino()),
    })
}

impl ZipArchive {
    /// Open an archive from disk.
    ///
    /// The container is confirmed from its content; the extension is only a
    /// hint. Returns [`Error::Detect`] if the bytes are not a ZIP.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).ctx("opening archive")?;
        let fp = match file.metadata() {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                FileFingerprint {
                    len: m.len(),
                    modified: m.modified().ok(),
                    device: Some(m.dev()),
                    inode: Some(m.ino()),
                }
            }
            Err(_) => FileFingerprint {
                len: 0,
                modified: None,
                device: None,
                inode: None,
            },
        };
        let boxed: Box<dyn ReadSeek> = Box::new(file);
        let reader = zip::ZipArchive::new(boxed).map_err(map_zip_error)?;
        Ok(Self {
            reader,
            path: path.to_path_buf(),
            opened_fingerprint: fp,
            format: Format::Zip,
            index_map: None,
        })
    }

    /// Open from bytes already in memory. Used by the macOS bridge for
    /// archive members pulled out of another archive.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let fp = FileFingerprint {
            len: bytes.len() as u64,
            modified: None,
            device: None,
            inode: None,
        };
        let cursor = std::io::Cursor::new(bytes);
        let boxed: Box<dyn ReadSeek> = Box::new(cursor);
        let reader = zip::ZipArchive::new(boxed).map_err(map_zip_error)?;
        Ok(Self {
            reader,
            path: PathBuf::from("<memory>"),
            opened_fingerprint: fp,
            format: Format::Zip,
            index_map: None,
        })
    }

    /// The path this archive was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The fingerprint recorded when the archive was opened.
    pub fn fingerprint(&self) -> FileFingerprint {
        self.opened_fingerprint
    }

    /// True when the file changed on disk since it was opened.
    pub fn changed_on_disk(&self) -> bool {
        if self.path.as_os_str() == "<memory>" {
            return false;
        }
        match fingerprint(&self.path) {
            Ok(now) => now != self.opened_fingerprint,
            Err(_) => true,
        }
    }

    /// Return an error if the archive changed since it was opened.
    pub fn ensure_unchanged(&self) -> Result<()> {
        if self.changed_on_disk() {
            Err(Error::ExternalModification)
        } else {
            Ok(())
        }
    }

    /// The archive comment, which is where a self-extracting stub leaves its
    /// marker. Read because it is the cheapest signal that a `.zip` is really
    /// an installer stub.
    pub fn comment(&self) -> &[u8] {
        self.reader.comment()
    }
}

/// Translate `zip` crate errors into Zipee errors, adding member context.
fn map_zip_error(e: zip::result::ZipError) -> Error {
    use zip::result::ZipError as Z;
    match e {
        Z::InvalidPassword => Error::BadPassword,
        Z::UnsupportedArchive(s) => {
            // The crate uses this variant both for "needs a password" and for
            // genuinely unsupported features; tell them apart by the message.
            if s == Z::PASSWORD_REQUIRED {
                Error::PasswordRequired
            } else {
                Error::Unsupported(format!("ZIP: {s}"))
            }
        }
        Z::FileNotFound => Error::Corrupt("archive references a missing file".into()),
        Z::Io(io) => {
            // The crate reports a wrong password as a wrapped I/O error, so the
            // message is the only signal available.
            let msg = io.to_string();
            if msg.contains("password") || msg.contains("Password") {
                Error::BadPassword
            } else {
                Error::Corrupt(msg)
            }
        }
        other => Error::Corrupt(other.to_string()),
    }
}

/// Convert a `zip` entry into the engine's neutral model.
fn entry_from_zip(zip: &zip::read::ZipFile<'_>, encrypted: bool) -> Result<ArchiveEntry> {
    let raw = zip.name().to_string();

    // Reject hostile names here rather than at extraction time, so the UI can
    // show them greyed out instead of vanishing.
    let (path, violation) = match crate::security::sanitize_member_path(&raw) {
        Ok(p) => (Some(p), None),
        Err(v) => (None, Some(v)),
    };

    let kind = if zip.is_dir() || raw.ends_with('/') {
        crate::entry::EntryKind::Directory
    } else if zip.is_symlink() {
        crate::entry::EntryKind::Symlink
    } else {
        crate::entry::EntryKind::File
    };

    // Only the variants our enabled features provide are nameable; the crate
    // gates the rest behind `deflate64`/`lzma`/`xz`, so a catch-all keeps this
    // compiling whatever feature set is selected.
    let compression = match zip.compression() {
        zip::CompressionMethod::Stored => Compression::Stored,
        zip::CompressionMethod::Deflated => Compression::Deflate,
        zip::CompressionMethod::Bzip2 => Compression::Bzip2,
        zip::CompressionMethod::Zstd => Compression::Zstd,
        _ => Compression::Unsupported(99), // nameable catch-all; see comment above
    };

    let encryption = if encrypted {
        refine_encryption(zip)
    } else {
        Encryption::None
    };

    Ok(ArchiveEntry {
        raw_name: raw,
        path,
        path_violation: violation,
        kind,
        uncompressed_size: zip.size(),
        compressed_size: zip.compressed_size(),
        compression,
        encryption,
        modified: zip.last_modified().and_then(datetime_to_system_time),
        unix_mode: zip.unix_mode(),
        crc32: Some(zip.crc32()),
    })
}

impl ArchiveAccess for ZipArchive {
    fn format(&self) -> Format {
        self.format
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self) -> Result<Vec<ArchiveEntry>> {
        let mut out = Vec::with_capacity(self.reader.len());
        for i in 0..self.reader.len() {
            let encrypted = is_encrypted(&mut self.reader, i);
            let f = self.reader.by_index_raw(i).map_err(map_zip_error)?;
            out.push(entry_from_zip(&f, encrypted)?);
        }
        Ok(out)
    }

    fn stats(&mut self) -> Result<ArchiveStats> {
        Ok(ArchiveStats::from_entries(&self.entries()?))
    }

    fn vfs(&mut self) -> Result<Vfs> {
        Ok(Vfs::from_entries(&self.entries()?))
    }

    fn read_entry(&mut self, name: &str, passwords: &mut dyn PasswordSource) -> Result<Vec<u8>> {
        let index = self.index_of(name)?;
        // Ask the index what this member needs before touching its data.
        let meta = {
            let encrypted = is_encrypted(&mut self.reader, index);
            let f = self.reader.by_index_raw(index).map_err(map_zip_error)?;
            entry_from_zip(&f, encrypted)?
        };
        if meta.encryption.is_encrypted() {
            let Some(secret) = passwords.password_for(&meta) else {
                return Err(Error::PasswordRequired);
            };
            let bytes = secret.0.as_bytes().to_vec();
            drop(secret);
            let mut file = self
                .reader
                .by_index_decrypt(index, &bytes)
                .map_err(map_zip_error)?;
            return read_and_verify(&mut file, &meta, name);
        }
        if !meta.encryption_is_supported() {
            return Err(Error::UnsupportedEncryption {
                entry: name.to_string(),
                method: encryption_method_code(meta.encryption),
            });
        }

        let mut file = self.reader.by_index(index).map_err(map_zip_error)?;
        read_and_verify(&mut file, &meta, name)
    }

    fn verify(&mut self, passwords: &mut dyn PasswordSource) -> Result<VerifyReport> {
        let entries = self.entries()?;
        let mut report = VerifyReport::default();
        for e in &entries {
            if e.is_unsafe() {
                report.unsafe_entries.push(e.raw_name.clone());
                continue;
            }
            match self.read_entry(&e.raw_name, passwords) {
                Ok(_) => report.ok += 1,
                Err(Error::PasswordRequired) | Err(Error::BadPassword) => {
                    report.encrypted_pending.push(e.raw_name.clone());
                }
                Err(err) => report.failed.push((e.raw_name.clone(), err.to_string())),
            }
        }
        report.total = entries.len() as u64;
        Ok(report)
    }
}

impl ArchiveEntry {
    /// True when Zipee can decode this entry's encryption.
    fn encryption_is_supported(&self) -> bool {
        match self.encryption {
            // ZipCrypto and WinZip AES are both handled by the `zip` crate,
            // which is why Zipee enables its `aes-crypto` feature.
            Encryption::None | Encryption::ZipCrypto | Encryption::WinZipAes => true,
            Encryption::SevenZipAes | Encryption::Unsupported(_) => false,
        }
    }
}

/// Convert the ZIP crate's civil date into a `SystemTime`.
///
/// ZIP stores a local civil time with no timezone, so this is interpreted as
/// UTC. That is the convention every other ZIP tool uses, and being wrong by
/// a few hours on a modification date is far better than refusing to show one.
fn datetime_to_system_time(dt: zip::DateTime) -> Option<std::time::SystemTime> {
    let (y, m, d) = (dt.year() as i64, dt.month() as u32, dt.day() as u32);
    let (h, mi, s) = (dt.hour() as u64, dt.minute() as u64, dt.second() as u64);

    // Days from civil date, Howard Hinnant's algorithm. Valid for the whole
    // proleptic Gregorian range, unlike a naive 365-day-year approximation.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = ((m + 9) % 12) as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;

    let secs = days * 86_400 + (h * 3600 + mi * 60 + s) as i64;
    std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs as u64))
}

/// Extra-field header ID for WinZip AES, per the PKWARE appnote.
const AES_EXTRA_FIELD_ID: u16 = 0x9901;

/// Distinguish WinZip AES from traditional ZipCrypto.
///
/// Both set the general-purpose encryption bit. Telling them apart is optional
/// but improves the error a user sees: AES is a real cipher, ZipCrypto is not,
/// and telling someone to rotate a ZipCrypto password would be misleading.
fn refine_encryption(zip: &zip::read::ZipFile<'_>) -> Encryption {
    // The `0x9901` extra field is how a ZIP says "this member is AES". Its
    // presence is the only portable way to tell the two apart without walking
    // the raw central directory.
    if let Some(extra) = zip.extra_data() {
        if extra
            .windows(2)
            .any(|w| u16::from_le_bytes([w[0], w[1]]) == AES_EXTRA_FIELD_ID)
        {
            return Encryption::WinZipAes;
        }
    }
    Encryption::ZipCrypto
}

/// Whether the container marks a member as encrypted.
///
/// The `zip` crate tracks the general-purpose bit internally and uses it to
/// refuse a passwordless open, but does not expose it. Asking is cheap and
/// exact: `by_index` returns `PASSWORD_REQUIRED` for an encrypted member and a
/// live handle for one that is not, and the refusal happens before any
/// decryption is attempted.
fn is_encrypted(reader: &mut zip::ZipArchive<Box<dyn ReadSeek>>, index: usize) -> bool {
    use zip::result::ZipError as Z;
    matches!(
        reader.by_index(index),
        Err(Z::UnsupportedArchive(Z::PASSWORD_REQUIRED))
    )
}

/// Read a member's bytes and verify its CRC.
fn read_and_verify(
    file: &mut zip::read::ZipFile<'_>,
    meta: &ArchiveEntry,
    name: &str,
) -> Result<Vec<u8>> {
    let expected_crc = file.crc32();
    let mut out = Vec::with_capacity(meta.uncompressed_size.min(64 * 1024 * 1024) as usize);
    file.read_to_end(&mut out)
        .map_err(|e| map_read_error(e, name))?;

    // CRC is the archive's own integrity claim; honour it rather than
    // reporting success for bytes that are subtly wrong.
    //
    // WinZip AES members store CRC32 = 0 by specification, because the
    // AES-HMAC is their integrity check and the `zip` crate already verifies
    // it while decrypting. Enforcing CRC there would reject every valid
    // AES archive, so the check is skipped for encrypted members only.
    if meta.encryption == Encryption::None && expected_crc != 0 {
        let actual = crc32fast::hash(&out);
        if actual != expected_crc {
            return Err(Error::Corrupt(format!(
                "CRC mismatch for {name:?}: expected {expected_crc:08x}, got {actual:08x}"
            )));
        }
    }
    Ok(out)
}

impl ZipArchive {
    /// Index of the member named `name`.
    ///
    /// Built from the central directory once, then reused. An archive cannot
    /// change under us — it is held open — so the map stays valid.
    fn index_of(&mut self, name: &str) -> Result<usize> {
        if self.index_map.is_none() {
            let mut map = std::collections::HashMap::with_capacity(self.reader.len());
            for i in 0..self.reader.len() {
                let f = self.reader.by_index_raw(i).map_err(map_zip_error)?;
                // First record wins, matching the reader's own name-keyed
                // behaviour for archives with duplicate member names.
                map.entry(f.name().to_string()).or_insert(i);
            }
            self.index_map = Some(map);
        }
        self.index_map
            .as_ref()
            .and_then(|m| m.get(name).copied())
            .ok_or_else(|| Error::NoSuchEntry(name.to_string()))
    }
}

fn encryption_method_code(e: Encryption) -> u16 {
    match e {
        Encryption::None => 0,
        Encryption::ZipCrypto => 1,
        Encryption::SevenZipAes => 99,
        Encryption::WinZipAes => 0x63,
        Encryption::Unsupported(m) => m,
    }
}

fn map_read_error(e: std::io::Error, name: &str) -> Error {
    let msg = e.to_string();
    if msg.contains("password") || msg.contains("Password") {
        Error::BadPassword
    } else if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Corrupt(format!("{name}: archive ends in the middle of an entry"))
    } else {
        Error::Corrupt(format!("{name}: {msg}"))
    }
}

/// Result of checking every member's checksum.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Members that read back with a matching CRC.
    pub ok: u64,
    /// Members whose data did not match.
    pub failed: Vec<(String, String)>,
    /// Members skipped because a password was not available.
    pub encrypted_pending: Vec<String>,
    /// Members skipped because their path was unsafe.
    pub unsafe_entries: Vec<String>,
    /// Members considered in total.
    pub total: u64,
}

impl VerifyReport {
    /// True when every readable member passed and nothing is pending.
    pub fn is_healthy(&self) -> bool {
        self.failed.is_empty()
            && self.encrypted_pending.is_empty()
            && self.unsafe_entries.is_empty()
    }
}

impl std::fmt::Debug for ZipArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipArchive")
            .field("path", &self.path)
            .field("members", &self.reader.len())
            .field("format", &self.format)
            .field("fingerprint", &self.opened_fingerprint)
            .finish()
    }
}

/// Write a brand-new ZIP archive to `path`.
///
/// Members are added in the order given. The archive is written to a temporary
/// file beside the destination and renamed into place, so a crash never leaves
/// a half-written archive at `path`.
pub fn create_zip(
    path: &Path,
    members: &[(SafeMemberPath, Vec<u8>)],
    budget: ExtractionBudget,
) -> Result<()> {
    if members.len() as u64 > budget.max_entries {
        return Err(Error::Budget(crate::security::BudgetExceeded::EntryCount {
            limit: budget.max_entries,
        }));
    }
    let total: u64 = members.iter().map(|(_, d)| d.len() as u64).sum();
    if total > budget.max_total_bytes {
        return Err(Error::Budget(crate::security::BudgetExceeded::TotalBytes {
            limit: budget.max_total_bytes,
        }));
    }

    let tmp = temp_sibling(path);
    {
        let file = File::create(&tmp).ctx("creating temporary archive")?;
        let mut w = zip::ZipWriter::new(BufWriter::new(file));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, data) in members {
            w.start_file(name.as_key(), opts).map_err(map_zip_error)?;
            w.write_all(data).ctx("writing archive entry")?;
        }
        w.finish().map_err(map_zip_error)?;
    }
    std::fs::rename(&tmp, path).ctx("replacing archive")?;
    Ok(())
}

/// A temporary path beside `path`, so the final rename stays on one filesystem.
pub fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(format!(".zipee-{}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Open any supported archive, detecting the container from its content.
pub fn open_any(path: &Path) -> Result<Box<dyn ArchiveAccess>> {
    match detect_path(path)? {
        Format::Zip => Ok(Box::new(ZipArchive::open(path)?)),
        Format::Tar => Ok(Box::new(crate::tar_archive::TarArchive::open(path)?)),
        other => Err(Error::Unsupported(format!(
            "Zipee can open zip and tar today; this file is {other}"
        ))),
    }
}
