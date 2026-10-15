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
pub mod fs_adapter;
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
pub use fs_adapter::{
    downcast_fs_error, open_fs, ArchiveFs, DirEntry, FsAdapter, FsError, NodeAttributes, NodeKind,
    ReadRequest,
};
pub use security::{
    sanitize_member_path, BudgetExceeded, ExtractionBudget, PathViolation, SafeMemberPath,
};
pub use vfs::{Node, Vfs};
pub use writeback::WriteReport;

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
    fn reading_every_member_of_a_large_archive_stays_linear() {
        // Regression test. `read_entry` used to scan the central directory
        // linearly, which made reading every member O(N^2) — on a 20,000-entry
        // archive a full verify took 48.7s before the name index and 0.35s
        // after (see docs/platform-limitations.md). This asserts correctness on
        // every member; the quadratic regression would show up as a suite that
        // crawls, which is just as visible and far less flaky than a timer.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("many.zip");
        {
            let file = File::create(&p).unwrap();
            let mut w = zip::ZipWriter::new(std::io::BufWriter::new(file));
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for i in 0..5_000u32 {
                w.start_file(format!("d{}/f{i:05}.txt", i % 50), opts)
                    .unwrap();
                w.write_all(format!("body-{i}").as_bytes()).unwrap();
            }
            w.finish().unwrap();
        }

        let mut a = open_any(&p).unwrap();
        assert_eq!(a.entries().unwrap().len(), 5_000);

        for i in 0..5_000u32 {
            let name = format!("d{}/f{i:05}.txt", i % 50);
            let data = a.read_entry(&name, &mut NoPassword).unwrap();
            assert_eq!(
                data,
                format!("body-{i}").as_bytes(),
                "wrong body for {name}"
            );
        }

        // An unknown name must be reported, not panic.
        assert!(matches!(
            a.read_entry("nope.txt", &mut NoPassword),
            Err(Error::NoSuchEntry(_))
        ));
    }

    #[test]
    fn identifies_by_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mislabelled.png");
        make_zip(&p, &[("a.txt", b"x")]);
        assert_eq!(identify(&p).unwrap(), Format::Zip);
    }
}
