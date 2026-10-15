//! The archive abstraction every container implements.
//!
//! Callers — the UI, the CLI, the macOS bridge — depend only on this trait,
//! so adding a container is a local change. Extraction, budgets, cancellation
//! and progress all live here rather than in each implementation, which is why
//! every container inherits the same security properties for free.

use std::path::Path;

use crate::entry::{ArchiveEntry, ArchiveStats, PasswordSource};
use crate::error::Result;
use crate::format::Format;
use crate::vfs::Vfs;
use crate::zip_archive::VerifyReport;

/// Read-only access to an archive container.
///
/// Implementations must not resolve member data until [`ArchiveAccess::read_entry`]
/// is called: listing a large archive has to stay cheap.
pub trait ArchiveAccess: std::any::Any + 'static {
    /// The container this archive is.
    fn format(&self) -> Format;

    /// Every member, in container order.
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>>;

    /// Aggregate statistics, computed from the member index.
    fn stats(&mut self) -> Result<ArchiveStats> {
        Ok(ArchiveStats::from_entries(&self.entries()?))
    }

    /// The archive presented as a browsable tree.
    fn vfs(&mut self) -> Result<Vfs> {
        Ok(Vfs::from_entries(&self.entries()?))
    }

    /// Read one member's bytes in full.
    ///
    /// Must verify the container's own checksum where one exists.
    fn read_entry(&mut self, name: &str, passwords: &mut dyn PasswordSource) -> Result<Vec<u8>>;

    /// Read every member, reporting per-member outcomes.
    fn verify(&mut self, _passwords: &mut dyn PasswordSource) -> Result<VerifyReport> {
        let entries = self.entries()?;
        let mut report = VerifyReport::default();
        for e in &entries {
            if e.is_unsafe() {
                report.unsafe_entries.push(e.raw_name.clone());
                continue;
            }
            match self.read_entry(&e.raw_name, &mut crate::entry::NoPassword) {
                Ok(_) => report.ok += 1,
                Err(crate::error::Error::PasswordRequired)
                | Err(crate::error::Error::BadPassword) => {
                    report.encrypted_pending.push(e.raw_name.clone());
                }
                Err(err) => report.failed.push((e.raw_name.clone(), err.to_string())),
            }
        }
        report.total = entries.len() as u64;
        Ok(report)
    }

    /// Write a member back into the archive.
    ///
    /// The default refuses, because most containers cannot be edited safely.
    /// Implementations that support editing must go through
    /// [`ArchiveAccess::write_member_to`] so the atomic-replacement rules
    /// apply.
    fn replace_entry(&mut self, _name: &str, _data: &[u8]) -> Result<()> {
        Err(crate::error::Error::Unsupported(format!(
            "{} archives cannot be edited by Zipee yet",
            self.format()
        )))
    }

    /// Default implementation of the edit path: write to a sibling temporary
    /// file, validate it, then atomically replace the source.
    ///
    /// Refuses outright if `destination` resolves to the same file as the
    /// source, because Zipee never edits an archive in place — a failure
    /// halfway through must leave the original untouched.
    fn write_member_to(
        &mut self,
        source: &Path,
        destination: &Path,
        edits: &[MemberEdit],
        budget: crate::security::ExtractionBudget,
    ) -> Result<()> {
        if same_file(source, destination) {
            return Err(crate::error::Error::InPlaceWriteRefused);
        }
        let bytes = self.rewrite_with(edits, budget)?;
        let tmp = crate::zip_archive::temp_sibling(destination);
        std::fs::write(&tmp, &bytes).ctx_err("writing replacement archive")?;
        // Validate the replacement before it replaces anything.
        let check = crate::zip_archive::ZipArchive::from_bytes(bytes).map_err(|e| {
            crate::error::Error::Corrupt(format!("replacement failed validation: {e}"))
        })?;
        drop(check);
        std::fs::rename(&tmp, destination).ctx_err("installing replacement archive")?;
        Ok(())
    }

    /// Produce the bytes of a rewritten archive. Container-specific.
    fn rewrite_with(
        &mut self,
        _edits: &[MemberEdit],
        _budget: crate::security::ExtractionBudget,
    ) -> Result<Vec<u8>> {
        Err(crate::error::Error::Unsupported(format!(
            "{} archives cannot be edited by Zipee yet",
            self.format()
        )))
    }

    /// Upcast, so callers holding a `&mut dyn ArchiveAccess` can recover the
    /// concrete container when they need container-specific behaviour.
    ///
    /// The trait requires `Any`, so every container is `'static` and this
    /// blanket implementation is enough — no per-container boilerplate.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// A change to apply when rewriting an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberEdit {
    /// Replace an existing member's contents.
    Replace {
        /// Member name as stored in the container.
        name: String,
        /// New contents.
        data: Vec<u8>,
    },
    /// Add a member that did not previously exist.
    Add {
        /// Sanitised path for the new member.
        path: crate::security::SafeMemberPath,
        /// Contents.
        data: Vec<u8>,
    },
    /// Remove a member.
    Delete {
        /// Member name as stored in the container.
        name: String,
    },
    /// Rename a member, keeping its contents.
    Rename {
        /// Existing name.
        from: String,
        /// New sanitised path.
        to: crate::security::SafeMemberPath,
    },
}

/// Lets callers pass an already-boxed archive straight through, which is what
/// `open_any` returns and what the extraction helpers want.
impl ArchiveAccess for Box<dyn ArchiveAccess> {
    fn format(&self) -> Format {
        (**self).format()
    }
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>> {
        (**self).entries()
    }
    fn stats(&mut self) -> Result<ArchiveStats> {
        (**self).stats()
    }
    fn vfs(&mut self) -> Result<Vfs> {
        (**self).vfs()
    }
    fn read_entry(&mut self, name: &str, passwords: &mut dyn PasswordSource) -> Result<Vec<u8>> {
        (**self).read_entry(name, passwords)
    }
    fn verify(
        &mut self,
        passwords: &mut dyn PasswordSource,
    ) -> Result<crate::zip_archive::VerifyReport> {
        (**self).verify(passwords)
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self.as_mut()
    }
}

/// True when two paths refer to the same file on disk.
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Extension that lets `io::Result` carry a context string.
trait CtxErr<T> {
    /// Wrap the error case with a description of the operation.
    fn ctx_err(self, context: &str) -> Result<T>;
}

impl<T> CtxErr<T> for std::result::Result<T, std::io::Error> {
    fn ctx_err(self, context: &str) -> Result<T> {
        self.map_err(|e| crate::error::Error::io(context, e))
    }
}
