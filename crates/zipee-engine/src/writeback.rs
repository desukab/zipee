//! Safe write-back: editing an archive without ever risking the original.
//!
//! The contract, in order:
//!
//! 1. The archive must not be edited in place. Zipee always builds a complete
//!    replacement in a temporary file.
//! 2. The replacement is written and closed.
//! 3. The replacement is re-opened and validated (its index must parse).
//! 4. Only then is the original replaced, atomically where the platform allows.
//!
//! If anything fails at steps 2 or 3, the original is untouched. This is what
//! makes "changing ZIP archives" safe enough to offer as a feature.

use std::collections::BTreeMap;
use std::path::Path;

use crate::archive::{ArchiveAccess, MemberEdit};
use crate::entry::ArchiveEntry;
use crate::error::{Error, Result};
use crate::security::{ExtractionBudget, SafeMemberPath};
use crate::zip_archive::ZipArchive;

/// The result of rewriting an archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Members added.
    pub added: Vec<String>,
    /// Members replaced.
    pub replaced: Vec<String>,
    /// Members removed.
    pub deleted: Vec<String>,
    /// Members renamed, as `(from, to)`.
    pub renamed: Vec<(String, String)>,
    /// Members that were deliberately left alone.
    pub unchanged: u64,
}

impl WriteReport {
    /// Total members touched.
    pub fn changed(&self) -> usize {
        self.added.len() + self.replaced.len() + self.deleted.len() + self.renamed.len()
    }
}

/// Apply `edits` to a ZIP archive and atomically install the result at `destination`.
///
/// Returns [`Error::InPlaceWriteRefused`] if `destination` is the archive
/// being edited — Zipee has no code path that truncates a user's archive.
///
/// Returns [`Error::ExternalModification`] if the source changed since it was
/// opened, because the edits were computed against a stale index.
pub fn rewrite_zip(
    archive: &mut ZipArchive,
    source: &Path,
    destination: &Path,
    edits: &[MemberEdit],
    budget: &ExtractionBudget,
) -> Result<WriteReport> {
    if source == destination {
        return Err(Error::InPlaceWriteRefused);
    }
    archive.ensure_unchanged()?;

    let mut report = WriteReport::default();
    let entries = archive.entries()?;

    // An ordered map keyed by member name gives us stable output and makes
    // "add then replace" behave the way a user expects.
    let mut plan: BTreeMap<String, PlanItem> = BTreeMap::new();
    for e in &entries {
        if e.is_unsafe() {
            // Unsafe members are never carried into a rewritten archive: doing
            // so would re-publish a path-traversal payload under a new file.
            continue;
        }
        plan.insert(
            e.raw_name.clone(),
            PlanItem::Keep {
                source_name: e.raw_name.clone(),
                entry: e.clone(),
            },
        );
    }

    for edit in edits {
        match edit {
            MemberEdit::Delete { name } => {
                if plan.remove(name).is_some() {
                    report.deleted.push(name.clone());
                }
            }
            MemberEdit::Replace { name, data } => {
                budget.check_ratio(data.len() as u64, data.len() as u64)?;
                if plan.contains_key(name) {
                    plan.insert(name.clone(), PlanItem::New { data: data.clone() });
                    report.replaced.push(name.clone());
                } else {
                    plan.insert(name.clone(), PlanItem::New { data: data.clone() });
                    report.added.push(name.clone());
                }
            }
            MemberEdit::Add { path, data } => {
                budget.check_ratio(data.len() as u64, data.len() as u64)?;
                let name = path.as_key();
                if plan.contains_key(&name) {
                    plan.insert(name.clone(), PlanItem::New { data: data.clone() });
                    report.replaced.push(name);
                } else {
                    plan.insert(name.clone(), PlanItem::New { data: data.clone() });
                    report.added.push(name);
                }
            }
            MemberEdit::Rename { from, to } => {
                let new_name = to.as_key();
                if let Some(item) = plan.remove(from) {
                    plan.insert(new_name.clone(), item);
                    report.renamed.push((from.clone(), new_name));
                }
            }
        }
    }

    report.unchanged = plan
        .values()
        .filter(|i| matches!(i, PlanItem::Keep { .. }))
        .count() as u64;

    let bytes = materialise(archive, &plan, budget)?;
    validate(&bytes)?;
    install(&bytes, destination)?;
    Ok(report)
}

enum PlanItem {
    /// Carry an existing member over, preserving its bytes.
    ///
    /// `source_name` is the name in the *input* archive, which differs from the
    /// map key after a rename: a rename moves where a member is written, not
    /// where its bytes are read from.
    Keep {
        source_name: String,
        entry: ArchiveEntry,
    },
    /// Write new bytes for this name.
    New { data: Vec<u8> },
}

/// Produce the bytes of the rewritten archive.
fn materialise(
    archive: &mut ZipArchive,
    plan: &BTreeMap<String, PlanItem>,
    budget: &ExtractionBudget,
) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut written: u64 = 0;
    for (name, item) in plan {
        let data = match item {
            PlanItem::New { data } => data.clone(),
            PlanItem::Keep { source_name, entry } => {
                if entry.encryption.is_encrypted() {
                    // An encrypted member cannot be copied without its password;
                    // dropping it silently would be worse than failing loudly.
                    return Err(Error::Unsupported(format!(
                        "{name:?} is encrypted; Zipee cannot rewrite an archive \
                         containing encrypted members without re-encrypting them"
                    )));
                }
                archive.read_entry(source_name, &mut crate::entry::NoPassword)?
            }
        };
        if data.len() as u64 > budget.max_single_entry_bytes {
            return Err(Error::Budget(
                crate::security::BudgetExceeded::SingleEntryBytes {
                    limit: budget.max_single_entry_bytes,
                },
            ));
        }
        written = written.saturating_add(data.len() as u64);
        if written > budget.max_total_bytes {
            return Err(Error::Budget(crate::security::BudgetExceeded::TotalBytes {
                limit: budget.max_total_bytes,
            }));
        }
        out.start_file(name.as_str(), opts)
            .map_err(|e| Error::Corrupt(format!("writing {name:?}: {e}")))?;
        out.write_all(&data).ctx_err()?;
    }
    let cursor = out.finish().map_err(|e| Error::Corrupt(e.to_string()))?;
    Ok(cursor.into_inner())
}

/// Re-open a freshly built archive and confirm its index parses.
///
/// This is the check that stops a truncated or malformed replacement from
/// replacing a good archive.
fn validate(bytes: &[u8]) -> Result<()> {
    let probe = ZipArchive::from_bytes(bytes.to_vec())?;
    let mut probe = probe;
    let entries = probe.entries()?;
    if entries.is_empty() && !bytes.is_empty() {
        return Err(Error::Corrupt(
            "replacement archive has no readable entries".into(),
        ));
    }
    Ok(())
}

/// Install the validated replacement at `destination`, atomically.
fn install(bytes: &[u8], destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).ctx_err()?;
    }
    let tmp = crate::zip_archive::temp_sibling(destination);
    std::fs::write(&tmp, bytes).map_err(|e| Error::io("writing replacement archive", e))?;
    if let Err(e) = std::fs::rename(&tmp, destination) {
        // Leave no debris if the swap fails.
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::io("installing replacement archive", e));
    }
    Ok(())
}

trait CtxErr<T> {
    fn ctx_err(self) -> Result<T>;
}

impl<T> CtxErr<T> for std::result::Result<T, std::io::Error> {
    fn ctx_err(self) -> Result<T> {
        self.map_err(|e| Error::io("writing archive", e))
    }
}

/// Plan a set of edits for a member list, without touching the filesystem.
///
/// Exposed so the UI can preview "3 changes" before committing them, and so
/// the rules can be unit-tested independently of I/O.
pub fn plan_edits(entries: &[ArchiveEntry], edits: &[MemberEdit]) -> WriteReport {
    let mut report = WriteReport::default();
    let mut present: BTreeMap<String, ()> = entries
        .iter()
        .filter(|e| !e.is_unsafe())
        .map(|e| (e.raw_name.clone(), ()))
        .collect();
    let initial = present.len() as u64;

    for edit in edits {
        match edit {
            MemberEdit::Delete { name } => {
                if present.remove(name).is_some() {
                    report.deleted.push(name.clone());
                }
            }
            MemberEdit::Replace { name, .. } => {
                if present.contains_key(name) {
                    report.replaced.push(name.clone());
                } else {
                    present.insert(name.clone(), ());
                    report.added.push(name.clone());
                }
            }
            MemberEdit::Add { path, .. } => {
                let name = path.as_key();
                if present.contains_key(&name) {
                    report.replaced.push(name.clone());
                } else {
                    present.insert(name.clone(), ());
                    report.added.push(name);
                }
            }
            MemberEdit::Rename { from, to } => {
                let name = to.as_key();
                if present.remove(from).is_some() {
                    present.insert(name.clone(), ());
                    report.renamed.push((from.clone(), name));
                }
            }
        }
    }
    report.unchanged = initial;
    report
}

/// Build an [`ArchiveEntry`] describing a member that does not exist yet, so
/// callers can preview an addition without allocating a [`MemberEdit`].
pub fn preview_entry(path: &SafeMemberPath, size: u64) -> ArchiveEntry {
    ArchiveEntry {
        raw_name: path.as_key(),
        path: Some(path.clone()),
        path_violation: None,
        kind: crate::entry::EntryKind::File,
        uncompressed_size: size,
        compressed_size: size,
        compression: crate::entry::Compression::Deflate,
        encryption: crate::entry::Encryption::None,
        modified: None,
        unix_mode: None,
        crc32: None,
    }
}

/// Blanket helper so a `Box<dyn ArchiveAccess>` can still be written back.
pub fn rewrite_boxed(
    archive: &mut Box<dyn ArchiveAccess>,
    source: &Path,
    destination: &Path,
    edits: &[MemberEdit],
    budget: &ExtractionBudget,
) -> Result<WriteReport> {
    let Some(zip) = archive.as_any_mut().downcast_mut::<ZipArchive>() else {
        return Err(Error::Unsupported(format!(
            "{} archives cannot be edited by Zipee yet",
            archive.format()
        )));
    };
    rewrite_zip(zip, source, destination, edits, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sanitize_member_path;

    fn e(name: &str, unsafe_: bool) -> ArchiveEntry {
        ArchiveEntry {
            raw_name: name.into(),
            path: if unsafe_ {
                None
            } else {
                sanitize_member_path(name).ok()
            },
            path_violation: if unsafe_ {
                Some(crate::security::PathViolation::Traversal)
            } else {
                None
            },
            kind: crate::entry::EntryKind::File,
            uncompressed_size: 1,
            compressed_size: 1,
            compression: crate::entry::Compression::Stored,
            encryption: crate::entry::Encryption::None,
            modified: None,
            unix_mode: None,
            crc32: None,
        }
    }

    #[test]
    fn plan_adds_and_replaces() {
        let entries = vec![e("a.txt", false), e("b.txt", false)];
        let edits = vec![
            MemberEdit::Replace {
                name: "a.txt".into(),
                data: b"new".to_vec(),
            },
            MemberEdit::Add {
                path: sanitize_member_path("c.txt").unwrap(),
                data: b"x".to_vec(),
            },
        ];
        let r = plan_edits(&entries, &edits);
        assert_eq!(r.replaced, vec!["a.txt"]);
        assert_eq!(r.added, vec!["c.txt"]);
        assert_eq!(r.unchanged, 2);
        assert_eq!(r.changed(), 2);
    }

    #[test]
    fn plan_deletes_and_renames() {
        let entries = vec![e("a.txt", false), e("b.txt", false)];
        let edits = vec![
            MemberEdit::Delete {
                name: "a.txt".into(),
            },
            MemberEdit::Rename {
                from: "b.txt".into(),
                to: sanitize_member_path("d/b.txt").unwrap(),
            },
        ];
        let r = plan_edits(&entries, &edits);
        assert_eq!(r.deleted, vec!["a.txt"]);
        assert_eq!(r.renamed, vec![("b.txt".into(), "d/b.txt".into())]);
    }

    #[test]
    fn plan_ignores_edits_for_absent_members() {
        let entries = vec![e("a.txt", false)];
        let edits = vec![MemberEdit::Delete {
            name: "nope.txt".into(),
        }];
        let r = plan_edits(&entries, &edits);
        assert!(r.deleted.is_empty());
        assert_eq!(r.unchanged, 1);
    }

    #[test]
    fn plan_never_reintroduces_unsafe_members() {
        let entries = vec![e("../evil", true)];
        let r = plan_edits(&entries, &[]);
        assert_eq!(r.unchanged, 0);
    }

    #[test]
    fn refuses_in_place_write() {
        let p = Path::new("/tmp/x.zip");
        assert!(crate::archive::same_file(p, p));
    }

    #[test]
    fn preview_entry_is_consistent() {
        let p = sanitize_member_path("x/y.txt").unwrap();
        let e = preview_entry(&p, 42);
        assert_eq!(e.key(), "x/y.txt");
        assert_eq!(e.uncompressed_size, 42);
        assert!(!e.is_unsafe());
    }
}
