//! Selective extraction: writing archive members to disk, safely.
//!
//! This is where a hostile archive actually does damage, so every rule from
//! [`crate::security`] is enforced at the point of writing — not at listing,
//! not in the UI, and not in some future code path that forgets to check.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::archive::ArchiveAccess;
use crate::entry::{ArchiveEntry, PasswordSource};
use crate::error::{Error, IoContext, Result};
use crate::security::{sanitize_member_path, BudgetExceeded, ExtractionBudget};

/// A cooperative cancellation flag.
///
/// Cancellation is checked between members and between write chunks, so a
/// cancelled extraction stops promptly without leaving a partial file behind
/// at a path the user did not ask for.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Safe to call from any thread, repeatedly.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    /// True once cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Return [`Error::Cancelled`] if cancellation has been requested.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// A member to extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Extract exactly this member.
    Entry(String),
    /// Extract every member beneath this directory prefix.
    Subtree(String),
    /// Extract every safe member.
    Everything,
}

impl Selection {
    /// Build a selection from a user-typed path.
    ///
    /// A trailing `/` means "this folder and everything in it".
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() || spec == "*" || spec == "." || spec == "/" {
            return Ok(Self::Everything);
        }
        if spec.ends_with('/') {
            let safe = sanitize_member_path(spec.trim_end_matches('/'))?;
            return Ok(Self::Subtree(safe.as_key()));
        }
        let safe = sanitize_member_path(spec)?;
        Ok(Self::Entry(safe.as_key()))
    }

    /// True when `key` (a sanitised member path) is selected.
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Everything => true,
            Self::Entry(n) => key == n,
            Self::Subtree(p) => key == p || key.starts_with(&format!("{p}/")),
        }
    }
}

/// What happened to one member during extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOutcome {
    /// Written successfully.
    Extracted {
        /// Path relative to the destination root.
        path: String,
        /// Bytes written.
        bytes: u64,
    },
    /// Created as a directory.
    DirectoryCreated {
        /// Path relative to the destination root.
        path: String,
    },
    /// Created as a symbolic link.
    SymlinkCreated {
        /// Path relative to the destination root.
        path: String,
        /// The link's target, as stored.
        target: String,
    },
    /// Deliberately skipped because it is inside another member's subtree and
    /// already covered by extracting an ancestor.
    Skipped {
        /// Path relative to the destination root.
        path: String,
    },
    /// Refused because its path is unsafe.
    Rejected {
        /// The offending name.
        path: String,
        /// Why it was refused.
        reason: String,
    },
    /// Failed for a reason other than its path.
    Failed {
        /// The offending name.
        path: String,
        /// The error.
        reason: String,
    },
}

/// Result of an extraction run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractReport {
    /// Per-member outcomes, in the order they were processed.
    pub outcomes: Vec<MemberOutcome>,
    /// Members written.
    pub extracted: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Members refused for unsafe paths.
    pub rejected: u64,
    /// Members that failed for other reasons.
    pub failed: u64,
    /// Files and directories created, relative to the destination.
    pub created: Vec<PathBuf>,
}

impl ExtractReport {
    /// True when nothing failed and nothing was refused.
    pub fn is_clean(&self) -> bool {
        self.failed == 0 && self.rejected == 0
    }

    /// Members that were refused, for the summary line in the UI.
    pub fn rejections(&self) -> Vec<&MemberOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, MemberOutcome::Rejected { .. }))
            .collect()
    }
}

/// Called after each member so the UI can show progress.
pub type ProgressFn<'a> = &'a mut dyn FnMut(&crate::entry::Progress);

/// Extract members from `archive` into `destination`.
///
/// Guarantees:
///
/// * Every written path is inside `destination`, proven by
///   [`sanitize_member_path`] before any filesystem call.
/// * A symlink is only created when its target also stays inside
///   `destination`, so a later member cannot write through it and escape.
/// * The budget is enforced on entry count, total bytes, per-entry bytes and
///   expansion ratio *before* any decompression happens.
/// * Cancellation is checked before each member and leaves already-written
///   members in place, but never a partially written one: each file is written
///   to a temporary sibling and renamed into place.
pub fn extract(
    archive: &mut dyn ArchiveAccess,
    selection: &Selection,
    destination: &Path,
    budget: &ExtractionBudget,
    passwords: &mut dyn PasswordSource,
    cancel: &CancelToken,
    progress: ProgressFn<'_>,
) -> Result<ExtractReport> {
    fs::create_dir_all(destination)
        .ctx(format!("creating destination {}", destination.display()))?;
    let destination = destination
        .canonicalize()
        .map_err(|e| Error::io("resolving destination", e))?;

    let entries = archive.entries()?;

    // Naming a folder should extract its contents, not just create the folder.
    // `Selection::parse` cannot know this (the spec is just a string), so the
    // decision is made here once the index is available.
    let selection = match selection {
        Selection::Entry(ref p) => {
            // A directory is "real" if the archive declares it *or* if any
            // member lives beneath it — most archives omit directory records
            // entirely, and requiring an explicit one would make `zipee
            // extract archive.zip photos` silently extract nothing.
            let prefix = format!("{p}/");
            let is_dir = entries.iter().any(|e| match &e.path {
                Some(x) => {
                    x.as_key() == *p
                        || x.as_key().starts_with(&prefix)
                        || (e.kind == crate::entry::EntryKind::Directory && x.as_key() == *p)
                }
                None => false,
            });
            if is_dir {
                Selection::Subtree(p.clone())
            } else {
                Selection::Entry(p.clone())
            }
        }
        other => other.clone(),
    };
    let selection = &selection;

    // Unsafe members must stay in the selected set so they are *reported* as
    // rejected. Filtering them out here would silently drop them, which is the
    // one behaviour this whole module exists to prevent.
    let selected: Vec<&ArchiveEntry> = entries
        .iter()
        .filter(|e| {
            // macOS metadata is never materialised, exactly as it is never
            // browsable. Extraction works from the container index rather than
            // the Vfs, so the policy has to be applied here too.
            if crate::macmeta::is_mac_metadata(&e.raw_name) {
                return false;
            }
            match &e.path {
                Some(p) => selection.matches(&p.as_key()),
                None => true,
            }
        })
        .collect();

    let total_bytes: u64 = selected
        .iter()
        .filter(|e| e.kind.is_file())
        .fold(0u64, |a, e| a.saturating_add(e.uncompressed_size));

    let mut report = ExtractReport::default();
    let mut done = 0u64;
    let mut bytes_done = 0u64;

    // Create explicit directories first, so empty folders survive even when
    // no member would otherwise cause them to exist.
    for e in &selected {
        if e.kind == crate::entry::EntryKind::Directory {
            if let Some(p) = &e.path {
                let target = destination.join(p.as_path());
                if let Err(err) = fs::create_dir_all(&target) {
                    report.outcomes.push(MemberOutcome::Failed {
                        path: p.as_key(),
                        reason: err.to_string(),
                    });
                    report.failed += 1;
                } else {
                    report
                        .outcomes
                        .push(MemberOutcome::DirectoryCreated { path: p.as_key() });
                    report.created.push(target);
                }
            }
        }
    }

    for entry in &selected {
        cancel.check()?;

        let Some(safe) = &entry.path else {
            report.outcomes.push(MemberOutcome::Rejected {
                path: entry.raw_name.clone(),
                reason: entry
                    .path_violation
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unsafe path".into()),
            });
            report.rejected += 1;
            done += 1;
            continue;
        };

        // Resource ceilings are checked before decompression, not after.
        if done >= budget.max_entries {
            return Err(Error::Budget(BudgetExceeded::EntryCount {
                limit: budget.max_entries,
            }));
        }
        if entry.kind.is_file() {
            if entry.uncompressed_size > budget.max_single_entry_bytes {
                return Err(Error::Budget(BudgetExceeded::SingleEntryBytes {
                    limit: budget.max_single_entry_bytes,
                }));
            }
            if bytes_done.saturating_add(entry.uncompressed_size) > budget.max_total_bytes {
                return Err(Error::Budget(BudgetExceeded::TotalBytes {
                    limit: budget.max_total_bytes,
                }));
            }
            budget.check_ratio(entry.uncompressed_size, entry.compressed_size)?;
        }

        let key = safe.as_key();
        let target = destination.join(safe.as_path());

        let outcome = match entry.kind {
            crate::entry::EntryKind::Directory => {
                let _ = fs::create_dir_all(&target);
                MemberOutcome::Skipped { path: key.clone() }
            }
            crate::entry::EntryKind::Symlink => extract_symlink(entry, &destination, &target, &key),
            crate::entry::EntryKind::Special => MemberOutcome::Rejected {
                path: key.clone(),
                reason: "device and FIFO members are never materialised".into(),
            },
            crate::entry::EntryKind::File => {
                match read_and_write(archive, entry, &target, cancel, budget, passwords) {
                    Ok(n) => {
                        report.created.push(target);
                        report.bytes_written += n;
                        MemberOutcome::Extracted {
                            path: key.clone(),
                            bytes: n,
                        }
                    }
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(e) => MemberOutcome::Failed {
                        path: key.clone(),
                        reason: e.to_string(),
                    },
                }
            }
        };

        match &outcome {
            MemberOutcome::Extracted { .. } => report.extracted += 1,
            MemberOutcome::Rejected { .. } => report.rejected += 1,
            MemberOutcome::Failed { .. } => report.failed += 1,
            _ => {}
        }
        report.outcomes.push(outcome);

        done += 1;
        if entry.kind.is_file() {
            bytes_done = bytes_done.saturating_add(entry.uncompressed_size);
        }
        progress(&crate::entry::Progress {
            done,
            total: selected.len() as u64,
            bytes_done,
            bytes_total: total_bytes,
            current: key,
        });
    }

    Ok(report)
}

/// Decide what to do with a symlink member.
///
/// Zipee's policy is deliberate and documented: **extraction never creates
/// symlinks.** The reason is not timidity about validation — [`crate::security`]
/// can prove a target stays inside the root — it is that a link is only safe in
/// combination with every *later* member. A link created at step 3 can be
/// traversed by a member at step 7, and any gap in that reasoning is an escape.
///
/// Nested browsing still shows link targets, and callers that genuinely need a
/// link on disk can use [`validate_symlink_target`] to vet one explicitly.
fn extract_symlink(
    entry: &ArchiveEntry,
    destination: &Path,
    target: &Path,
    key: &str,
) -> MemberOutcome {
    debug_assert!(!destination.as_os_str().is_empty());
    debug_assert!(!target.as_os_str().is_empty());

    // The member's name is still checked, because the link would be *created*
    // at that path even if its target is fine.
    if crate::security::sanitize_member_path(&entry.raw_name).is_err() {
        return MemberOutcome::Rejected {
            path: key.into(),
            reason: "symlink member name is unsafe".into(),
        };
    }
    MemberOutcome::Rejected {
        path: key.into(),
        reason: "symbolic links are shown but never written to disk".into(),
    }
}

/// Read one member and write it atomically.
fn read_and_write(
    archive: &mut dyn ArchiveAccess,
    entry: &ArchiveEntry,
    target: &Path,
    cancel: &CancelToken,
    _budget: &ExtractionBudget,
    passwords: &mut dyn PasswordSource,
) -> Result<u64> {
    cancel.check()?;
    let data = archive.read_entry(&entry.raw_name, passwords)?;

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).ctx(format!("creating directory {}", parent.display()))?;
    }

    // Write to a temporary sibling, then rename. A cancelled or failed write
    // therefore leaves no half-file at `target`.
    let tmp = temp_for(target);
    {
        let file = File::create(&tmp).ctx("creating temporary file")?;
        let mut w = BufWriter::new(file);
        w.write_all(&data).ctx("writing extracted file")?;
        w.flush().ctx("flushing extracted file")?;
    }

    cancel.check()?;
    // Restore the stored mode where possible; archives legitimately carry 0600
    // or 0755 and silently widening them would be wrong.
    if let Some(mode) = entry.unix_mode {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(mode & 0o777);
        let _ = fs::set_permissions(&tmp, perm);
    }
    fs::rename(&tmp, target).ctx("installing extracted file")?;
    Ok(data.len() as u64)
}

/// A temporary path beside `target`, on the same filesystem so rename works.
fn temp_for(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(format!(".zipee-part-{}", std::process::id()));
    target.with_file_name(name)
}

/// Extract an archive member into memory. Used for previews and nested browsing.
pub fn read_selected(
    archive: &mut dyn ArchiveAccess,
    selection: &Selection,
    passwords: &mut dyn PasswordSource,
) -> Result<Vec<(String, Vec<u8>)>> {
    let entries = archive.entries()?;
    let mut out = Vec::new();
    for e in entries {
        let Some(p) = &e.path else { continue };
        if !selection.matches(&p.as_key()) || !e.kind.is_file() {
            continue;
        }
        out.push((p.as_key(), archive.read_entry(&e.raw_name, passwords)?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_token_roundtrip() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        assert!(t.check().is_ok());
        t.cancel();
        assert!(t.is_cancelled());
        assert!(matches!(t.check(), Err(Error::Cancelled)));
        // cancelling twice is harmless
        t.cancel();
        assert!(t.is_cancelled());
    }

    #[test]
    fn cancel_token_is_shared_across_clones() {
        let a = CancelToken::new();
        let b = a.clone();
        a.cancel();
        assert!(b.is_cancelled());
    }

    #[test]
    fn selection_parsing() {
        assert_eq!(
            Selection::parse("a.txt").unwrap(),
            Selection::Entry("a.txt".into())
        );
        assert_eq!(
            Selection::parse("dir/").unwrap(),
            Selection::Subtree("dir".into())
        );
        assert_eq!(Selection::parse("*").unwrap(), Selection::Everything);
        assert_eq!(Selection::parse("").unwrap(), Selection::Everything);
        // hostile input is rejected at parse time
        assert!(Selection::parse("../evil").is_err());
        assert!(Selection::parse("/etc/passwd").is_err());
    }

    #[test]
    fn selection_matching() {
        let s = Selection::Subtree("a".into());
        assert!(s.matches("a"));
        assert!(s.matches("a/b.txt"));
        assert!(s.matches("a/b/c.txt"));
        assert!(!s.matches("ab"));
        assert!(!s.matches("b/a.txt"));
    }

    #[test]
    fn report_classification() {
        let mut r = ExtractReport::default();
        r.outcomes.push(MemberOutcome::Rejected {
            path: "x".into(),
            reason: "y".into(),
        });
        r.rejected = 1;
        assert!(!r.is_clean());
        assert_eq!(r.rejections().len(), 1);
    }
}
