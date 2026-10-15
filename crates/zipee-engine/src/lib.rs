//! # zipee-engine
//!
//! The archive engine behind Zipee, a native macOS archive utility.
//!
//! ## Design
//!
//! The engine is deliberately free of any UI, macOS or Objective-C
//! dependency. It runs unchanged on Linux and in CI, which is what makes the
//! security properties below *testable* rather than merely claimed:
//!
//! * hostile member names never reach the filesystem
//!   ([`security`]);
//! * expansion is bounded before decompression, not after
//!   ([`security::ExtractionBudget`]);
//! * an archive is never edited in place ([`writeback`]);
//! * listing an archive never decompresses a member ([`vfs`]).
//!
//! The macOS app talks to this crate through the C ABI in
//! `zipee-engine/src/ffi.rs`, and the CLI through the safe Rust API.
//!
//! ## Quick start
//!
//! ```no_run
//! use zipee_engine::{open_any, vfs, ExtractionBudget, NoPassword, Selection, extract};
//! use std::path::Path;
//!
//! let mut archive = open_any(Path::new("photos.zip"))?;
//! let tree = archive.vfs()?;
//! println!("{} top-level entries", tree.children("").len());
//!
//! extract(
//!     archive.as_mut(),
//!     &Selection::parse("shoot-2026")?,
//!     Path::new("/tmp/out"),
//!     &ExtractionBudget::interactive(),
//!     &mut NoPassword,
//!     &Default::default(),
//!     &mut |_| {},
//! )?;
//! # Ok::<(), zipee_engine::Error>(())
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod archive;
pub mod entry;
pub mod error;
pub mod extract;
pub mod ffi;
pub mod format;
pub mod nested;
pub mod security;
pub mod tar_archive;
pub mod vfs;
pub mod writeback;
pub mod zip_archive;

pub use archive::{ArchiveAccess, MemberEdit};
pub use entry::{
    ArchiveEntry, ArchiveStats, Compression, Encryption, EntryKind, NoPassword, PasswordSource,
    Progress, Secret, StaticPassword,
};
pub use error::{Error, Result};
pub use extract::{extract, CancelToken, ExtractReport, MemberOutcome, Selection};
pub use format::{detect_bytes, detect_path, Format};
pub use security::{
    sanitize_member_path, BudgetExceeded, ExtractionBudget, PathViolation, SafeMemberPath,
};
pub use vfs::{Node, Vfs};
pub use writeback::{WriteReport};

/// Open any supported archive, detecting the container from its content.
pub fn open_any(path: &std::path::Path) -> Result<Box<dyn ArchiveAccess>> {
    zip_archive::open_any(path)
}

/// Identify a file's container without opening it.
pub fn identify(path: &std::path::Path) -> Result<Format> {
    Ok(detect_path(path)?)
}

#[cfg(test)]
mod integration_smoke {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn make_zip(path: &std::path::Path, members: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in members {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn opens_lists_and_reads_a_real_zip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(&p, &[("one.txt", b"one"), ("sub/two.txt", b"two")]);

        let mut a = open_any(&p).unwrap();
        assert_eq!(a.format(), Format::Zip);
        let entries = a.entries().unwrap();
        assert_eq!(entries.len(), 2);

        let tree = a.vfs().unwrap();
        assert!(tree.is_directory("sub"));
        assert_eq!(tree.children("sub").len(), 1);
        assert_eq!(tree.subtree_size(""), 6);

        assert_eq!(
            a.read_entry("sub/two.txt", &mut NoPassword).unwrap(),
            b"two"
        );
    }

    #[test]
    fn identifies_by_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mislabelled.png");
        make_zip(&p, &[("a.txt", b"x")]);
        assert_eq!(identify(&p).unwrap(), Format::Zip);
    }
}