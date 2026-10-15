//! macOS metadata inside archives: AppleDouble sidecars and `__MACOSX` trees.
//!
//! Archives created on macOS carry two kinds of non-content that other
//! platforms do not produce:
//!
//! * **`._name` sidecars** — an AppleDouble file holding resource forks,
//!   Finder info and extended attributes for the sibling `name`.
//! * **`__MACOSX/name` trees** — the same data, laid out as a parallel
//!   directory tree.
//!
//! Both are *derived* data. They are never something a user chose to put in the
//! archive, they are noise when browsing, and extracting them produces a
//! directory full of `._` files that macOS then shows as hidden junk.
//!
//! ## Why this module exists
//!
//! This is not hypothetical. While reverse-engineering the reference product,
//! its own installer payload was found to contain a stray
//! `Contents/Resources/._zipgeist-icon-source.png` — an AppleDouble file that
//! its own packager leaked. The reference implementation decompiles to
//! `ArchiveEngine.AppleDouble`, `ArchiveEngine.MacMetadata` (with
//! `maximumSidecarSize` and an allow-list) and `ArchiveEngine.MacMetadataMap`
//! (with `hidden` and `sidecars`); this module is the equivalent policy,
//! written from scratch.
//!
//! ## Policy
//!
//! Sidecars are **hidden from browsing and never extracted**. They are not
//! deleted: the archive is the user's file, and Zipee does not rewrite it
//! without being asked. They are counted so the UI can say "12 macOS metadata
//! items hidden" rather than making an archive look like it lost files.

/// The conventional directory Apple puts sidecars in.
pub const MACOSX_DIR: &str = "__MACOSX";

/// The AppleDouble prefix. `._` followed by the sibling's name.
pub const APPLEDOUBLE_PREFIX: &str = "._";

/// The upper bound on a sidecar Zipee will even look inside.
///
/// A sidecar is metadata for one file; anything large is either corruption or
/// an attempt to make Zipee allocate on demand. Matching the reference's
/// `MacMetadata.maximumSidecarSize`, this is deliberately small.
pub const MAX_SIDECAR_BYTES: u64 = 64 * 1024;

/// What kind of macOS metadata item, if any, a member name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacMetadataKind {
    /// A member inside a `__MACOSX` directory.
    SidecarTree,
    /// A `._name` AppleDouble sidecar.
    AppleDouble,
}

/// Why a member is classified as macOS metadata rather than content.
fn classify(name: &str) -> Option<MacMetadataKind> {
    // Reject anything that is not already a normalised relative path; the
    // safety layer owns that decision and this one must not second-guess it.
    let mut components = name.split('/');
    if components.clone().next() == Some(MACOSX_DIR) {
        return Some(MacMetadataKind::SidecarTree);
    }
    // A sidecar may itself sit in a directory, e.g. `docs/._readme.md`.
    if components
        .clone()
        .next_back()
        .is_some_and(|c| c.starts_with(APPLEDOUBLE_PREFIX))
    {
        let last = components.next_back().unwrap_or_default();
        // `._` alone is not a sidecar; it has no sibling to describe.
        if last.len() > APPLEDOUBLE_PREFIX.len() {
            return Some(MacMetadataKind::AppleDouble);
        }
    }
    // A directory entry that is itself the sidecar directory, e.g. `__MACOSX`.
    if name == MACOSX_DIR || name.starts_with(&format!("{MACOSX_DIR}/")) {
        return Some(MacMetadataKind::SidecarTree);
    }
    None
}

/// True when this member is macOS metadata rather than archive content.
///
/// ```ignore
/// assert!(is_mac_metadata("__MACOSX/dir/f.txt"));
/// assert!(is_mac_metadata("dir/._f.txt"));
/// assert!(!is_mac_metadata("dir/f.txt"));
/// ```
pub fn is_mac_metadata(name: &str) -> bool {
    classify(name).is_some()
}

/// True when this member is specifically a `._` AppleDouble sidecar.
pub fn is_appledouble(name: &str) -> bool {
    classify(name) == Some(MacMetadataKind::AppleDouble)
}

/// True when this member lives in the `__MACOSX` tree.
pub fn is_sidecar_tree(name: &str) -> bool {
    classify(name) == Some(MacMetadataKind::SidecarTree)
}

/// The content member a sidecar describes, when it can be determined.
///
/// `docs/._readme.md` describes `docs/readme.md`. Returns `None` when no
/// plausible sibling exists, because a sidecar with no sibling is junk.
pub fn sibling_of(name: &str) -> Option<String> {
    let kind = classify(name)?;
    match kind {
        MacMetadataKind::AppleDouble => match name.rsplit_once('/') {
            // `._top.txt` sits at the archive root and has no directory part.
            Some((dir, last)) => {
                let stem = last.strip_prefix(APPLEDOUBLE_PREFIX)?;
                (!stem.is_empty()).then(|| format!("{dir}/{stem}"))
            }
            None => {
                let stem = name.strip_prefix(APPLEDOUBLE_PREFIX)?;
                (!stem.is_empty()).then(|| stem.to_string())
            }
        },
        MacMetadataKind::SidecarTree => {
            let rest = name.strip_prefix(MACOSX_DIR)?.strip_prefix('/')?;
            (!rest.is_empty()).then(|| rest.to_string())
        }
    }
}

/// Whether a sidecar is small enough to be plausible metadata.
///
/// A `._` file larger than [`MAX_SIDECAR_BYTES`] is either corruption or a
/// deliberate attempt to make a metadata reader allocate without bound.
pub fn is_plausible_sidecar(size: u64) -> bool {
    size <= MAX_SIDECAR_BYTES
}

/// What happened to the metadata items in one archive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacMetadataSummary {
    /// Members inside a `__MACOSX` tree.
    pub sidecar_tree_members: usize,
    /// `._name` AppleDouble members.
    pub appledouble_members: usize,
    /// Sidecar members too large to be plausible metadata.
    pub oversized: usize,
    /// `__MACOSX` directory entries that carry no data of their own.
    pub directories: usize,
}

impl MacMetadataSummary {
    /// Total members held back from the user's view.
    pub fn hidden(&self) -> usize {
        self.sidecar_tree_members + self.appledouble_members
    }

    /// A sentence for the UI, or `None` when there was nothing to hide.
    ///
    /// Naming the count matters: silently omitting members makes an archive
    /// look damaged, and this project refuses to do that anywhere.
    pub fn description(&self) -> Option<String> {
        if self.hidden() == 0 {
            return None;
        }
        let n = self.hidden();
        let noun = if n == 1 { "item" } else { "items" };
        let mut s = format!("{n} macOS metadata {noun} hidden", n = self.hidden());
        if self.oversized > 0 {
            s.push_str(&format!(" ({} of them implausibly large)", self.oversized));
        }
        Some(s)
    }
}

/// Decide the policy for every member of an archive.
///
/// Returns the indices of members that are macOS metadata. `entries` is any
/// iterator of `(name, size)` pairs, so this works on the engine's own
/// [`ArchiveEntry`](crate::entry::ArchiveEntry) and on a test fixture.
pub fn classify_all<'a, I>(entries: I) -> MacMetadataSummary
where
    I: IntoIterator<Item = (&'a str, u64)>,
{
    let mut s = MacMetadataSummary::default();
    for (name, size) in entries {
        match classify(name) {
            Some(MacMetadataKind::SidecarTree) => {
                if size == 0 {
                    s.directories += 1;
                } else {
                    s.sidecar_tree_members += 1;
                    if !is_plausible_sidecar(size) {
                        s.oversized += 1;
                    }
                }
            }
            Some(MacMetadataKind::AppleDouble) => {
                s.appledouble_members += 1;
                if !is_plausible_sidecar(size) {
                    s.oversized += 1;
                }
            }
            None => {}
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_mac_metadata_layouts() {
        assert!(is_mac_metadata("__MACOSX"));
        assert!(is_mac_metadata("__MACOSX/dir/file.txt"));
        assert!(is_mac_metadata("__MACOSX/dir/._file.txt"));
        assert!(is_mac_metadata("dir/._file.txt"));
        assert!(is_mac_metadata("./dir/._file.txt"));
        assert!(is_mac_metadata("._file.txt"));
    }

    #[test]
    fn does_not_mistake_real_content_for_metadata() {
        for name in [
            "file.txt",
            "dir/file.txt",
            "dir/_.hidden.txt", // single underscore, not `._`
            "dir/..hidden",     // starts with `..`
            "dir/..",
            "my__MACOSX_dir/file", // contains, does not start
            "MACOSX/file",
            "__MACOSXish/file",
            "archive/._", // sidecar with no sibling name
        ] {
            assert!(
                !is_mac_metadata(name),
                "{name:?} is real content and must not be hidden"
            );
        }
    }

    #[test]
    fn separates_the_two_kinds() {
        assert!(is_sidecar_tree("__MACOSX/a/b"));
        assert!(!is_sidecar_tree("a/._b"));
        assert!(is_appledouble("a/._b"));
        assert!(!is_appledouble("__MACOSX/a/b"));
    }

    #[test]
    fn resolves_the_content_a_sidecar_describes() {
        assert_eq!(
            sibling_of("docs/._readme.md").as_deref(),
            Some("docs/readme.md")
        );
        assert_eq!(sibling_of("._top.txt").as_deref(), Some("top.txt"));
        assert_eq!(
            sibling_of("__MACOSX/docs/readme.md").as_deref(),
            Some("docs/readme.md")
        );
        assert_eq!(sibling_of("readme.md"), None);
    }

    #[test]
    fn bounds_sidecar_size() {
        assert!(is_plausible_sidecar(0));
        assert!(is_plausible_sidecar(MAX_SIDECAR_BYTES));
        assert!(!is_plausible_sidecar(MAX_SIDECAR_BYTES + 1));
        assert!(!is_plausible_sidecar(u64::MAX));
    }

    #[test]
    fn summarises_an_archive() {
        let s = classify_all([
            ("__MACOSX", 0),
            ("__MACOSX/a/f.txt", 120),
            ("docs/._readme.md", 4096),
            ("docs/readme.md", 5000),
            ("src/main.rs", 900),
        ]);
        assert_eq!(s.directories, 1);
        assert_eq!(s.sidecar_tree_members, 1);
        assert_eq!(s.appledouble_members, 1);
        assert_eq!(s.hidden(), 2);
        assert_eq!(s.oversized, 0);
        assert_eq!(
            s.description().as_deref(),
            Some("2 macOS metadata items hidden")
        );
    }

    #[test]
    fn flags_implausibly_large_sidecars() {
        let s = classify_all([("a/._big", MAX_SIDECAR_BYTES * 10)]);
        assert_eq!(s.hidden(), 1);
        assert_eq!(s.oversized, 1);
        assert!(s.description().unwrap().contains("implausibly large"));
    }

    #[test]
    fn description_is_absent_when_nothing_was_hidden() {
        let s = classify_all([("a.txt", 1), ("dir/b.txt", 2)]);
        assert_eq!(s.hidden(), 0);
        assert_eq!(s.description(), None);
    }

    #[test]
    fn singular_wording_is_not_pluralised() {
        assert_eq!(
            classify_all([("a/._x", 1)]).description().as_deref(),
            Some("1 macOS metadata item hidden")
        );
    }
}
