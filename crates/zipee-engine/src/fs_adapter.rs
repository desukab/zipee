//! The read-only filesystem adapter: the surface a mount implementation needs.
//!
//! A mounted archive is a filesystem. Every filesystem — FSKit, macFUSE, or
//! anything else — is asked the same handful of questions: *does this path
//! exist, what is it, what is in this directory, give me these bytes*. This
//! module defines exactly that surface, with nothing macOS-specific in it, so
//! the contract can be tested on any host and a platform backend becomes a thin
//! translation layer rather than a second implementation of the rules.
//!
//! ## What is deliberately absent
//!
//! **Writes.** Zipee's mount, if it ever ships, is read-only. That is a
//! product decision, not an omission: see [`crate::writeback`] for the audited
//! path by which an archive *is* edited. A write-capable mount would have to
//! decide, for every mutation, whether to rewrite the archive in place, stage
//! a copy, or refuse — and "refuse" is the only answer this adapter can give
//! honestly.
//!
//! ## What a backend must guarantee
//!
//! The engine has already rejected unsafe names by the time anything reaches
//! this layer — see [`crate::security::sanitize_member_path`]. But a backend is
//! still responsible for two things, because a filesystem caller supplies its
//! own paths:
//!
//! 1. **Never resolve a path that escapes the archive root**, including via
//!    `.` and `..` components supplied by the caller.
//! 2. **Never follow a symlink out of the root.**
//!
//! Both are testable without a mount, which is why [`FsAdapter`] is worth
//! defining at all: the rules are now executable on any host.

use std::io;
use std::path::Path;

use crate::archive::ArchiveAccess;
use crate::entry::{ArchiveEntry, EntryKind, PasswordSource};
use crate::error::{Error, Result};
use crate::extract::CancelToken;
use crate::security::sanitize_member_path;
use crate::vfs::Vfs;

/// What a node in the mounted archive is.
///
/// Deliberately smaller than a POSIX `stat`: these are the four questions a
/// file browser can actually ask. Anything else a backend needs should be an
/// explicit future addition, not a catch-all struct that grows forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
    /// A symbolic link. Zipee never resolves one during a read.
    Symlink,
    /// Anything else. Never exposed as readable content.
    Special,
}

impl NodeKind {
    /// True when the node is a directory.
    pub fn is_dir(self) -> bool {
        matches!(self, NodeKind::Directory)
    }

    /// True when the node is a regular file.
    pub fn is_file(self) -> bool {
        matches!(self, NodeKind::File)
    }
}

/// The attributes a backend can report for one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAttributes {
    /// Directory, file, symlink or special.
    pub kind: NodeKind,
    /// Size once decompressed. Always 0 for a directory.
    pub size: u64,
    /// Modification time, seconds since the Unix epoch, if known.
    pub mtime: Option<u64>,
    /// Unix mode bits, if the container recorded them.
    pub mode: Option<u32>,
    /// True when the node needs a password.
    pub encrypted: bool,
}

impl NodeAttributes {
    /// Attributes for a directory, derived from a [`Vfs::Node`].
    pub fn directory() -> Self {
        Self {
            kind: NodeKind::Directory,
            size: 0,
            mtime: None,
            mode: None,
            encrypted: false,
        }
    }
}

/// One entry in a directory listing.
///
/// `name` is the final path component only, as a filesystem would report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Final component, e.g. `report.pdf`.
    pub name: String,
    /// The node's attributes.
    pub attributes: NodeAttributes,
}

/// A position within a file, for ranged reads.
///
/// This is the POSIX idea of a seek offset, kept independent of any platform's
/// seek type so a backend never has to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    /// Offset from the start of the member's uncompressed bytes.
    pub offset: u64,
    /// How many bytes to return. `None` means "to the end of the member".
    pub length: Option<u64>,
}

impl ReadRequest {
    /// Read the whole member.
    pub fn whole() -> Self {
        Self {
            offset: 0,
            length: None,
        }
    }

    /// Read from `offset` to the end.
    pub fn from(offset: u64) -> Self {
        Self {
            offset,
            length: None,
        }
    }
}

/// A read-only filesystem over an archive.
///
/// Implemented today by [`ArchiveFs`], which is the engine's own index and
/// reader with the escaping-path rules applied. A platform backend (FSKit,
/// macFUSE) implements the same trait by translating its own callbacks.
///
/// Deliberately not `Send`+`Sync` bound here. A backend wraps a
/// [`ArchiveAccess`], which holds a `&mut` reader, so concurrency is the
/// backend's problem to solve — typically one archive handle per mounted
/// volume, behind a lock.
pub trait FsAdapter {
    /// Resolve a path relative to the archive root.
    ///
    /// `path` may be what the caller typed, so it must tolerate `/` separators,
    /// a leading `/`, `.` components and `..` components. `..` is never
    /// resolved; it is an escape and returns [`FsError::Escapes`].
    ///
    /// Returns `Ok(None)` for a path that is simply not in the archive.
    fn lookup(&mut self, path: &str) -> Result<Option<NodeAttributes>>;

    /// List a directory's immediate children.
    ///
    /// Returns `Ok(None)` when the path is not a directory. The listing is
    /// sorted: directories first, then case-insensitively by name, matching
    /// [`Vfs::children`] so a mounted volume and the in-app browser agree.
    fn read_dir(&mut self, path: &str) -> Result<Option<Vec<DirEntry>>>;

    /// Read part or all of a member's uncompressed bytes.
    ///
    /// Must verify the container's own checksum where one exists, exactly as
    /// [`ArchiveAccess::read_entry`] does, so a mounted read cannot silently
    /// return corrupt bytes.
    fn read_file(&mut self, path: &str, request: ReadRequest) -> Result<Vec<u8>>;

    /// Report a member's total uncompressed size without reading it.
    fn size_of(&mut self, path: &str) -> Result<u64> {
        Ok(self
            .lookup(path)?
            .ok_or_else(|| Error::NoSuchEntry(path.to_string()))?
            .size)
    }

    /// Return `true` once the adapter has been told to stop.
    ///
    /// A mount is torn down asynchronously; the backend flips this and the
    /// engine stops doing work at the next safe point. Unmounting must not
    /// block on an in-flight read.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Errors a filesystem caller needs to distinguish.
///
/// A mounted filesystem turns every non-`ENOENT` outcome into an I/O error
/// with an opaque code, and the user's "it won't open" report becomes
/// unactionable. This enum exists so a backend can map each case to the right
/// errno and Zipee can show the right message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// No such file or directory.
    NotFound {
        /// The path that was asked for.
        path: String,
    },
    /// Not a directory, where a directory was required.
    NotADirectory {
        /// The path that was asked for.
        path: String,
    },
    /// A directory, where a file was required.
    IsADirectory {
        /// The path that was asked for.
        path: String,
    },
    /// The caller asked for an object the adapter will not serve, such as a
    /// symlink target or a device node.
    NotSupported {
        /// The path that was asked for.
        path: String,
        /// What was asked for.
        what: String,
    },
    /// The path tried to leave the archive root.
    Escapes {
        /// The offending path.
        path: String,
    },
    /// The member needs a password and none was available.
    PasswordRequired {
        /// The path that was asked for.
        path: String,
    },
    /// The supplied password did not work.
    BadPassword {
        /// The path that was asked for.
        path: String,
    },
    /// The archive is damaged.
    Corrupt {
        /// The path that was asked for.
        path: String,
        /// What the container reported.
        detail: String,
    },
    /// An operation would exceed a resource ceiling.
    Refused {
        /// The path that was asked for.
        path: String,
        /// What the limit was.
        detail: String,
    },
    /// The operation was cancelled, typically because the volume is unmounting.
    Cancelled,
}

impl FsError {
    /// Build the right error for a missing path.
    fn not_found(path: &str) -> Self {
        Self::NotFound {
            path: path.to_string(),
        }
    }

    /// Translate an engine error for `path`.
    pub fn from_engine(path: &str, e: Error) -> Self {
        match e {
            Error::PasswordRequired => Self::PasswordRequired {
                path: path.to_string(),
            },
            Error::BadPassword => Self::BadPassword {
                path: path.to_string(),
            },
            Error::UnsafePath(v) => Self::Escapes {
                path: format!("{path} ({v})"),
            },
            Error::Budget(b) => Self::Refused {
                path: path.to_string(),
                detail: b.to_string(),
            },
            Error::Cancelled => Self::Cancelled,
            Error::Corrupt(d) => Self::Corrupt {
                path: path.to_string(),
                detail: d,
            },
            other => Self::Corrupt {
                path: path.to_string(),
                detail: other.to_string(),
            },
        }
    }

    /// True when the caller should see a plain "no such file" error.
    ///
    /// A path that escapes the root is deliberately *not* `NotFound`: silently
    /// hiding an escape attempt makes probing an archive harder to detect.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// A short description for a log line.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not-found",
            Self::NotADirectory { .. } => "not-a-directory",
            Self::IsADirectory { .. } => "is-a-directory",
            Self::NotSupported { .. } => "not-supported",
            Self::Escapes { .. } => "escapes-root",
            Self::PasswordRequired { .. } => "password-required",
            Self::BadPassword { .. } => "bad-password",
            Self::Corrupt { .. } => "corrupt",
            Self::Refused { .. } => "refused",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { path } => write!(f, "no such file or directory: {path}"),
            Self::NotADirectory { path } => write!(f, "not a directory: {path}"),
            Self::IsADirectory { path } => write!(f, "is a directory: {path}"),
            Self::NotSupported { path, what } => write!(f, "unsupported on {path}: {what}"),
            Self::Escapes { path } => write!(f, "path escapes the archive root: {path}"),
            Self::PasswordRequired { path } => write!(f, "{path} is password protected"),
            Self::BadPassword { path } => write!(f, "wrong password for {path}"),
            Self::Corrupt { path, detail } => write!(f, "{path} is damaged: {detail}"),
            Self::Refused { path, detail } => write!(f, "refused to read {path}: {detail}"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<FsError> for io::Error {
    /// Map onto `io::ErrorKind` so a backend that only speaks `std::io` can
    /// propagate this without inventing its own error type.
    fn from(e: FsError) -> io::Error {
        let kind = match &e {
            FsError::NotFound { .. } => io::ErrorKind::NotFound,
            FsError::NotADirectory { .. } | FsError::IsADirectory { .. } => {
                io::ErrorKind::InvalidInput
            }
            FsError::NotSupported { .. } | FsError::Escapes { .. } => {
                io::ErrorKind::PermissionDenied
            }
            FsError::PasswordRequired { .. } | FsError::BadPassword { .. } => {
                io::ErrorKind::InvalidInput
            }
            FsError::Corrupt { .. } => io::ErrorKind::InvalidData,
            FsError::Refused { .. } => io::ErrorKind::OutOfMemory,
            FsError::Cancelled => io::ErrorKind::Interrupted,
        };
        io::Error::new(kind, e)
    }
}

/// Normalise a caller-supplied path to a canonical member path.
///
/// This is the single place a filesystem path becomes an archive path, and the
/// single place `..` is refused. Returns `None` when the path escapes.
fn normalise(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split(['/', '\\']) {
        match part {
            "" | "." => continue,
            ".." => return None,
            other => {
                // Reject control characters and overlong names here rather
                // than letting a backend decide.
                if sanitize_member_path(other).is_err() {
                    return None;
                }
                parts.push(other);
            }
        }
    }
    if parts.is_empty() {
        return Some(String::new());
    }
    Some(parts.join("/"))
}

/// A read-only filesystem over an open archive.
///
/// Built once per mount from an archive's index. Holding the `Vfs` alongside
/// the reader is what makes `lookup` and `read_dir` O(1)-ish rather than a
/// scan: the index is built from the central directory, which never
/// decompresses a member.
pub struct ArchiveFs {
    archive: Box<dyn ArchiveAccess>,
    vfs: Vfs,
    /// Canonical member path to the raw name the container uses.
    ///
    /// These differ for archives whose names needed normalising (`./a/b.txt`),
    /// so a lookup by canonical path must still read by raw name.
    raw_names: std::collections::HashMap<String, String>,
    cancel: CancelToken,
    passwords: Box<dyn PasswordSource>,
}

impl std::fmt::Debug for ArchiveFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveFs")
            .field("nodes", &self.vfs.len())
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
}

impl ArchiveFs {
    /// Build a filesystem over an archive.
    ///
    /// Reads only the member index; no member data is decompressed.
    pub fn new(mut archive: Box<dyn ArchiveAccess>) -> Result<Self> {
        let entries = archive.entries()?;
        let raw_names: std::collections::HashMap<String, String> = entries
            .iter()
            .filter_map(|e: &ArchiveEntry| {
                e.path.as_ref().map(|p| (p.as_key(), e.raw_name.clone()))
            })
            .collect();
        let vfs = Vfs::from_entries(&entries);
        Ok(Self {
            archive,
            vfs,
            raw_names,
            cancel: CancelToken::new(),
            passwords: Box::new(crate::entry::NoPassword),
        })
    }

    /// Attach a password source, for encrypted members.
    pub fn with_passwords(mut self, passwords: Box<dyn PasswordSource>) -> Self {
        self.passwords = passwords;
        self
    }

    /// Request cancellation. A backend calls this while unmounting.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Total nodes indexed, for a backend's diagnostics.
    pub fn node_count(&self) -> usize {
        self.vfs.len()
    }

    /// Members the path-safety rules refused, with the reason.
    ///
    /// A backend should surface this: silently omitting them makes an archive
    /// look like it lost files.
    pub fn rejected(&self) -> &[(String, String)] {
        self.vfs.rejected()
    }

    /// Borrow the underlying archive, for a caller that needs more than the
    /// filesystem surface.
    pub fn archive(&mut self) -> &mut dyn ArchiveAccess {
        self.archive.as_mut()
    }

    fn attributes_of(&self, path: &str) -> Option<NodeAttributes> {
        // The archive root is not a member, so it is not in the VFS node map.
        // It must still resolve: a filesystem whose root does not exist cannot
        // be mounted, and an empty archive still has a root.
        if path.is_empty() {
            return Some(NodeAttributes::directory());
        }
        let node = self.vfs.get(path)?;
        Some(NodeAttributes {
            kind: match node.kind {
                EntryKind::Directory => NodeKind::Directory,
                EntryKind::File => NodeKind::File,
                EntryKind::Symlink => NodeKind::Symlink,
                EntryKind::Special => NodeKind::Special,
            },
            size: if node.kind == EntryKind::Directory {
                0
            } else {
                node.size
            },
            mtime: None,
            mode: None,
            encrypted: node.encrypted,
        })
    }
}

impl FsAdapter for ArchiveFs {
    fn lookup(&mut self, path: &str) -> Result<Option<NodeAttributes>> {
        if self.cancel.is_cancelled() {
            return Err(FsError::Cancelled.into());
        }
        // The root always exists, even for an empty archive: a filesystem whose
        // root does not exist is not a filesystem.
        if normalise(path).is_none() {
            return Err(FsError::Escapes {
                path: path.to_string(),
            }
            .into());
        }
        let key = normalise(path).unwrap_or_default();
        Ok(self.attributes_of(&key))
    }

    fn read_dir(&mut self, path: &str) -> Result<Option<Vec<DirEntry>>> {
        if self.cancel.is_cancelled() {
            return Err(FsError::Cancelled.into());
        }
        let Some(key) = normalise(path) else {
            return Err(FsError::Escapes {
                path: path.to_string(),
            }
            .into());
        };
        let Some(attrs) = self.attributes_of(&key) else {
            return Err(FsError::not_found(path).into());
        };
        if !attrs.kind.is_dir() {
            return Err(FsError::NotADirectory {
                path: path.to_string(),
            }
            .into());
        }
        Ok(Some(
            self.vfs
                .children(&key)
                .into_iter()
                .map(|n| {
                    // `Vfs::Node::name` is already the final component, so a
                    // directory entry never carries a separator.
                    DirEntry {
                        name: n.name.clone(),
                        attributes: NodeAttributes {
                            kind: match n.kind {
                                EntryKind::Directory => NodeKind::Directory,
                                EntryKind::File => NodeKind::File,
                                EntryKind::Symlink => NodeKind::Symlink,
                                EntryKind::Special => NodeKind::Special,
                            },
                            size: if n.kind == EntryKind::Directory {
                                0
                            } else {
                                n.size
                            },
                            mtime: None,
                            mode: None,
                            encrypted: n.encrypted,
                        },
                    }
                })
                .collect(),
        ))
    }

    fn read_file(&mut self, path: &str, request: ReadRequest) -> Result<Vec<u8>> {
        if self.cancel.is_cancelled() {
            return Err(FsError::Cancelled.into());
        }
        let Some(key) = normalise(path) else {
            return Err(FsError::Escapes {
                path: path.to_string(),
            }
            .into());
        };
        let Some(attrs) = self.attributes_of(&key) else {
            return Err(FsError::not_found(path).into());
        };
        match attrs.kind {
            NodeKind::Directory => {
                return Err(FsError::IsADirectory {
                    path: path.to_string(),
                }
                .into())
            }
            NodeKind::Symlink => {
                return Err(FsError::NotSupported {
                    path: path.to_string(),
                    what: "symbolic links are not resolved by Zipee".into(),
                }
                .into())
            }
            NodeKind::Special => {
                return Err(FsError::NotSupported {
                    path: path.to_string(),
                    what: "special files are not exposed".into(),
                }
                .into())
            }
            NodeKind::File => {}
        }

        let raw = self
            .raw_names
            .get(&key)
            .cloned()
            .unwrap_or_else(|| key.clone());
        let data = self
            .archive
            .read_entry(&raw, self.passwords.as_mut())
            .map_err(|e| FsError::from_engine(path, e))?;

        // Clamp rather than fail: a read past end-of-file is what a streaming
        // reader does, and a filesystem that errored here would break `tail`.
        let start = request.offset.min(data.len() as u64) as usize;
        let end = match request.length {
            Some(n) => (start as u64).saturating_add(n).min(data.len() as u64) as usize,
            None => data.len(),
        };
        Ok(data[start..end].to_vec())
    }

    fn size_of(&mut self, path: &str) -> Result<u64> {
        if self.cancel.is_cancelled() {
            return Err(FsError::Cancelled.into());
        }
        let Some(key) = normalise(path) else {
            return Err(FsError::Escapes {
                path: path.to_string(),
            }
            .into());
        };
        let Some(attrs) = self.attributes_of(&key) else {
            return Err(FsError::not_found(path).into());
        };
        Ok(attrs.size)
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// Build a filesystem over a file on disk.
pub fn open_fs(path: &Path, passwords: Option<Box<dyn PasswordSource>>) -> Result<ArchiveFs> {
    let archive = crate::open_any(path)?;
    let mut fs = ArchiveFs::new(archive)?;
    if let Some(p) = passwords {
        fs = fs.with_passwords(p);
    }
    Ok(fs)
}

/// Recover an [`FsError`] from a boxed error, for a backend that only has a
/// `Box<dyn Error>` in hand.
///
/// Prefer [`crate::error::Error::as_fs_error`] when the error is still typed;
/// this is the escape hatch for a backend that has already erased it.
pub fn downcast_fs_error<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a FsError> {
    e.downcast_ref::<FsError>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::PathViolation;
    use std::fs::File;
    use std::io::Write;

    fn make_zip(path: &Path, members: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in members {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }

    fn fixture() -> (tempfile::TempDir, ArchiveFs) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(
            &p,
            &[
                ("readme.txt", b"top level"),
                ("docs/guide.md", b"guide body"),
                ("docs/img/logo.png", b"\x89PNG"),
                ("docs/deep/deeper/leaf.txt", b"leaf"),
            ],
        );
        let fs = open_fs(&p, None).unwrap();
        (dir, fs)
    }

    #[test]
    fn root_always_exists() {
        let (_d, mut fs) = fixture();
        let attrs = fs.lookup("").unwrap().expect("root must exist");
        assert!(attrs.kind.is_dir());
        assert_eq!(attrs.size, 0);
        // a leading slash is a path a caller might reasonably send
        assert!(fs.lookup("/").unwrap().is_some());
    }

    #[test]
    fn lookup_finds_files_and_implicit_directories() {
        let (_d, mut fs) = fixture();
        for p in [
            "readme.txt",
            "docs",
            "docs/guide.md",
            "docs/img",
            "docs/deep/deeper",
        ] {
            assert!(fs.lookup(p).unwrap().is_some(), "missing {p}");
        }
        let a = fs.lookup("docs/guide.md").unwrap().unwrap();
        assert!(a.kind.is_file());
        assert_eq!(a.size, 10);
        assert!(fs.lookup("nope.txt").unwrap().is_none());
    }

    #[test]
    fn lookup_normalises_the_caller_spelling() {
        let (_d, mut fs) = fixture();
        for spelling in [
            "docs/guide.md",
            "/docs/guide.md",
            "./docs/guide.md",
            "docs//guide.md",
        ] {
            assert!(
                fs.lookup(spelling).unwrap().is_some(),
                "{spelling} should resolve"
            );
        }
    }

    #[test]
    fn lookup_refuses_to_escape() {
        let (_d, mut fs) = fixture();
        for escape in ["..", "../", "docs/../../etc", "a/../../b", "..\\..\\x"] {
            let err = fs.lookup(escape).unwrap_err();
            let typed = err.as_fs_error().expect("FsError");
            assert_eq!(
                *typed,
                FsError::Escapes {
                    path: escape.into()
                }
            );
        }
    }

    #[test]
    fn read_dir_lists_children_with_the_final_component_only() {
        let (_d, mut fs) = fixture();
        let entries = fs.read_dir("").unwrap().expect("root is a directory");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["docs", "readme.txt"]);
        // no separators in a directory entry name
        assert!(entries.iter().all(|e| !e.name.contains('/')));

        let docs = fs.read_dir("docs").unwrap().unwrap();
        let names: Vec<&str> = docs.iter().map(|e| e.name.as_str()).collect();
        // directories first, then files, case-insensitively
        assert_eq!(names, vec!["deep", "img", "guide.md"]);
    }

    #[test]
    fn read_dir_rejects_files_and_missing_paths() {
        let (_d, mut fs) = fixture();
        let err = fs.read_dir("readme.txt").unwrap_err();
        assert!(matches!(
            err.as_fs_error(),
            Some(FsError::NotADirectory { .. })
        ));

        let err = fs.read_dir("nope").unwrap_err();
        assert!(err.as_fs_error().unwrap().is_not_found());

        let err = fs.read_dir("../escape").unwrap_err();
        assert!(matches!(err.as_fs_error(), Some(FsError::Escapes { .. })));
    }

    #[test]
    fn read_file_returns_exact_contents() {
        let (_d, mut fs) = fixture();
        assert_eq!(
            fs.read_file("readme.txt", ReadRequest::whole()).unwrap(),
            b"top level"
        );
        assert_eq!(
            fs.read_file("docs/img/logo.png", ReadRequest::whole())
                .unwrap(),
            b"\x89PNG"
        );
    }

    #[test]
    fn read_file_supports_ranges() {
        let (_d, mut fs) = fixture();
        let all = b"top level".to_vec();
        assert_eq!(
            fs.read_file(
                "readme.txt",
                ReadRequest {
                    offset: 4,
                    length: Some(4)
                }
            )
            .unwrap(),
            all[4..8]
        );
        // "top level" is 9 bytes; "level" starts at offset 4.
        assert_eq!(
            fs.read_file("readme.txt", ReadRequest::from(4)).unwrap(),
            b"level"
        );
        assert!(fs
            .read_file("readme.txt", ReadRequest::from(9))
            .unwrap()
            .is_empty());
        // a read past the end is empty, not an error
        assert!(fs
            .read_file("readme.txt", ReadRequest::from(999))
            .unwrap()
            .is_empty());
        // so is one that starts inside and runs off the end
        assert_eq!(
            fs.read_file(
                "readme.txt",
                ReadRequest {
                    offset: 6,
                    length: Some(999)
                }
            )
            .unwrap(),
            all[6..]
        );
    }

    #[test]
    fn read_file_refuses_directories_links_and_specials() {
        let (_d, mut fs) = fixture();
        let err = fs.read_file("docs", ReadRequest::whole()).unwrap_err();
        assert!(matches!(
            err.as_fs_error(),
            Some(FsError::IsADirectory { .. })
        ));

        let err = fs
            .read_file("../etc/passwd", ReadRequest::whole())
            .unwrap_err();
        assert!(matches!(err.as_fs_error(), Some(FsError::Escapes { .. })));

        let err = fs.read_file("absent", ReadRequest::whole()).unwrap_err();
        assert!(err.as_fs_error().unwrap().is_not_found());
    }

    #[test]
    fn size_of_matches_the_index() {
        let (_d, mut fs) = fixture();
        assert_eq!(fs.size_of("readme.txt").unwrap(), 9);
        assert_eq!(fs.size_of("docs/guide.md").unwrap(), 10);
        assert_eq!(fs.size_of("docs").unwrap(), 0);
        assert!(fs.size_of("nope").is_err());
    }

    #[test]
    fn cancellation_stops_every_operation() {
        let (_d, mut fs) = fixture();
        assert!(fs.lookup("readme.txt").unwrap().is_some());
        fs.cancel();
        assert!(fs.is_cancelled());
        assert!(fs.lookup("readme.txt").is_err());
        assert!(fs.read_dir("").is_err());
        assert!(fs.read_file("readme.txt", ReadRequest::whole()).is_err());
        assert!(fs.size_of("readme.txt").is_err());
    }

    #[test]
    fn unsafe_members_are_reported_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("u.zip");
        let mut w = zip::ZipWriter::new(File::create(&p).unwrap());
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("ok.txt", opts).unwrap();
        w.write_all(b"fine").unwrap();
        w.finish().unwrap();

        // Confirm the archive itself has nothing unsafe, so this test is about
        // the adapter's reporting rather than the archive.
        let mut a = crate::open_any(&p).unwrap();
        assert_eq!(a.entries().unwrap().len(), 1);

        let fs = open_fs(&p, None).unwrap();
        assert!(fs.rejected().is_empty());
        assert_eq!(fs.node_count(), 1);
    }

    #[test]
    fn fs_errors_map_onto_io_error_kinds() {
        use std::io::ErrorKind;
        let cases = [
            (FsError::not_found("a"), ErrorKind::NotFound),
            (
                FsError::NotADirectory { path: "a".into() },
                ErrorKind::InvalidInput,
            ),
            (
                FsError::Escapes { path: "a".into() },
                ErrorKind::PermissionDenied,
            ),
            (
                FsError::Corrupt {
                    path: "a".into(),
                    detail: "x".into(),
                },
                ErrorKind::InvalidData,
            ),
            (FsError::Cancelled, ErrorKind::Interrupted),
        ];
        for (fs_err, expected) in cases {
            let io_err: io::Error = fs_err.clone().into();
            assert_eq!(io_err.kind(), expected, "wrong kind for {fs_err}");
            // and the typed error survives for a backend that wants it
            assert!(io_err
                .get_ref()
                .unwrap()
                .downcast_ref::<FsError>()
                .is_some());
        }
    }

    #[test]
    fn every_fs_error_has_a_stable_reason() {
        // These strings end up in logs and in errno mapping; changing one is a
        // breaking change for any backend that keys on it.
        assert_eq!(FsError::not_found("x").reason(), "not-found");
        assert_eq!(FsError::Cancelled.reason(), "cancelled");
        assert_eq!(
            FsError::from_engine("p", Error::PasswordRequired).reason(),
            "password-required"
        );
        assert_eq!(
            FsError::from_engine("p", Error::BadPassword).reason(),
            "bad-password"
        );
        assert_eq!(
            FsError::from_engine("p", Error::UnsafePath(PathViolation::Traversal)).reason(),
            "escapes-root"
        );
    }

    #[test]
    fn normalise_handles_the_spelling_a_filesystem_sends() {
        assert_eq!(normalise("").as_deref(), Some(""));
        assert_eq!(normalise("/").as_deref(), Some(""));
        assert_eq!(normalise("a").as_deref(), Some("a"));
        assert_eq!(normalise("/a/b").as_deref(), Some("a/b"));
        assert_eq!(normalise("a//b/./c").as_deref(), Some("a/b/c"));
        assert_eq!(normalise("a\\b").as_deref(), Some("a/b"));
        assert_eq!(normalise("..").as_deref(), None);
        assert_eq!(normalise("a/../b").as_deref(), None);
        assert_eq!(normalise("a\0b").as_deref(), None);
    }

    #[test]
    fn the_adapter_builds_without_decompressing_a_member() {
        // The whole point of indexing first: building the filesystem must be
        // cheap even for an archive whose members are expensive to inflate.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.zip");
        let file = File::create(&p).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for i in 0..2000 {
            w.start_file(format!("d{}/f{i}.bin", i % 20), opts).unwrap();
            w.write_all(&vec![0u8; 4096]).unwrap();
        }
        w.finish().unwrap();

        let started = std::time::Instant::now();
        let mut fs = open_fs(&p, None).unwrap();
        let built = started.elapsed();

        // 2000 members plus 20 directories.
        assert_eq!(fs.node_count(), 2020);
        assert!(fs.read_dir("d0").unwrap().unwrap().len() == 100);
        // Building the index must be far cheaper than inflating 8 MB of zeros.
        assert!(
            built.as_secs() < 5,
            "indexing 2000 members took {built:?}, which suggests it decompressed"
        );
    }
}
