//! The virtual filesystem: how Zipee presents an archive as a browsable tree.
//!
//! Archives are flat lists of slash-separated names. Finder is not. This
//! module turns one into the other without reading any member data, so
//! opening a 200,000-entry archive costs one pass over the central directory
//! and no decompression at all.
//!
//! The index is built lazily: `Vfs::from_entries` only splits paths, and
//! `children()` only materialises the nodes a caller actually asks for.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::entry::{ArchiveEntry, EntryKind};
use crate::security::SafeMemberPath;

/// One node in the browsable tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Sanitised path, relative to the archive root. Empty string is the root.
    pub path: String,
    /// Display name; empty for the root.
    pub name: String,
    /// What kind of member this node represents.
    pub kind: EntryKind,
    /// Size once decompressed, for files.
    pub size: u64,
    /// Size as stored.
    pub compressed_size: u64,
    /// Whether the member needs a password.
    pub encrypted: bool,
    /// True when this node exists only because a descendant mentions it.
    pub implicit: bool,
}

/// An archive presented as a browsable tree.
#[derive(Debug, Clone, Default)]
pub struct Vfs {
    /// Explicit members, keyed by sanitised path.
    nodes: HashMap<String, Node>,
    /// Children of each directory path, pre-sorted.
    children: BTreeMap<String, Vec<String>>,
    /// Members rejected by the path-safety rules, for the diagnostics panel.
    rejected: Vec<(String, String)>,
}

impl Vfs {
    /// Build a tree from a container's index.
    ///
    /// Unsafe member names are *not* indexed — they are collected into
    /// `rejected()` so Zipee can tell the user "3 entries were skipped because
    /// their paths tried to escape the archive" instead of silently hiding them.
    pub fn from_entries(entries: &[ArchiveEntry]) -> Self {
        let mut vfs = Self::default();
        for e in entries {
            let Some(path) = &e.path else {
                vfs.rejected.push((
                    e.raw_name.clone(),
                    e.path_violation
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unsafe path".into()),
                ));
                continue;
            };
            let key = path.as_key();
            vfs.nodes.insert(
                key.clone(),
                Node {
                    path: key.clone(),
                    name: path.file_name().to_string(),
                    kind: e.kind,
                    size: e.uncompressed_size,
                    compressed_size: e.compressed_size,
                    encrypted: e.encryption.is_encrypted(),
                    implicit: false,
                },
            );
        }
        vfs.materialise_implicit_dirs();
        vfs.rebuild_children();
        vfs
    }

    /// Add the directory nodes that no explicit entry declared.
    ///
    /// Real archives are inconsistent: plenty of them contain `a/b/c.txt` with
    /// no `a/` or `a/b/` entry at all. Without this pass those files would be
    /// unreachable, because Finder's model requires every level to exist.
    fn materialise_implicit_dirs(&mut self) {
        let existing: HashSet<String> = self.nodes.keys().cloned().collect();
        let mut implied: Vec<String> = Vec::new();

        for key in &existing {
            let mut prefix = String::new();
            // Split on '/', taking every proper prefix as a directory.
            let parts: Vec<&str> = key.split('/').collect();
            for part in &parts[..parts.len().saturating_sub(1)] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if !existing.contains(&prefix) && !implied.contains(&prefix) {
                    implied.push(prefix.clone());
                }
            }
        }

        for dir in implied {
            if self.nodes.contains_key(&dir) {
                continue;
            }
            let name = dir.rsplit('/').next().unwrap_or(&dir).to_string();
            self.nodes.insert(
                dir.clone(),
                Node {
                    path: dir.clone(),
                    name,
                    kind: EntryKind::Directory,
                    size: 0,
                    compressed_size: 0,
                    encrypted: false,
                    implicit: true,
                },
            );
        }
    }

    /// Rebuild the parent → children map, with directories before files and
    /// each group sorted case-insensitively so browsing is stable.
    fn rebuild_children(&mut self) {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        map.insert(String::new(), Vec::new());

        let keys: Vec<String> = self.nodes.keys().cloned().collect();
        for key in keys {
            let parent = match key.rfind('/') {
                Some(i) => key[..i].to_string(),
                None => String::new(),
            };
            map.entry(parent).or_default().push(key);
        }

        for kids in map.values_mut() {
            kids.sort_by(|a, b| {
                let na = self.nodes.get(a).map(|n| n.kind);
                let nb = self.nodes.get(b).map(|n| n.kind);
                let da = matches!(na, Some(EntryKind::Directory));
                let db = matches!(nb, Some(EntryKind::Directory));
                db.cmp(&da).then_with(|| {
                    let la = self
                        .nodes
                        .get(a)
                        .map(|n| n.name.to_lowercase())
                        .unwrap_or_default();
                    let lb = self
                        .nodes
                        .get(b)
                        .map(|n| n.name.to_lowercase())
                        .unwrap_or_default();
                    la.cmp(&lb).then_with(|| a.cmp(b))
                })
            });
        }
        self.children = map;
    }

    /// The root node.
    pub fn root(&self) -> Node {
        Node {
            path: String::new(),
            name: String::new(),
            kind: EntryKind::Directory,
            size: 0,
            compressed_size: 0,
            encrypted: false,
            implicit: true,
        }
    }

    /// Immediate children of `dir`, directories first.
    pub fn children(&self, dir: &str) -> Vec<&Node> {
        self.children
            .get(dir)
            .map(|v| v.iter().filter_map(|k| self.nodes.get(k)).collect())
            .unwrap_or_default()
    }

    /// Look up one node by its sanitised path.
    pub fn get(&self, path: &str) -> Option<&Node> {
        self.nodes.get(path)
    }

    /// True when `path` names a directory in the tree.
    pub fn is_directory(&self, path: &str) -> bool {
        self.get(path)
            .map(|n| n.kind == EntryKind::Directory)
            .unwrap_or(false)
    }

    /// Resolve a user-supplied relative path, e.g. from a search box.
    ///
    /// Returns `None` if any component would climb above the archive root.
    pub fn resolve(&self, rel: &str) -> Option<&Node> {
        let mut cur = String::new();
        for part in rel.split('/') {
            match part {
                "" | "." => continue,
                ".." => return None,
                other => {
                    if !cur.is_empty() {
                        cur.push('/');
                    }
                    cur.push_str(other);
                }
            }
        }
        self.get(&cur)
    }

    /// Every node path, sorted.
    pub fn paths(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.nodes.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    /// Total number of indexed nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when the archive has nothing to browse.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Members that were rejected by the path-safety rules.
    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }

    /// Sum of the sizes of every file in the subtree rooted at `dir`.
    pub fn subtree_size(&self, dir: &str) -> u64 {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        self.nodes
            .values()
            .filter(|n| n.kind.is_file())
            .filter(|n| n.path.starts_with(&prefix))
            .fold(0u64, |acc, n| acc.saturating_add(n.size))
    }

    /// Every node in the subtree rooted at `dir`, in depth-first name order.
    ///
    /// With an empty `dir` this is the whole archive, which is what `zipee list`
    /// without a path prints.
    pub fn subtree_nodes(&self, dir: &str) -> Vec<&Node> {
        let mut out = Vec::new();
        fn walk<'a>(vfs: &'a Vfs, dir: &str, out: &mut Vec<&'a Node>) {
            for node in vfs.children(dir) {
                out.push(node);
                if node.kind == EntryKind::Directory {
                    walk(vfs, &node.path, out);
                }
            }
        }
        walk(self, dir, &mut out);
        out
    }

    /// The `ls -R` listing of one subtree, without its own header line.
    pub fn tree_lines_in(&self, dir: &str) -> Vec<String> {
        fn walk(vfs: &Vfs, dir: &str, out: &mut Vec<String>, depth: usize) {
            for node in vfs.children(dir) {
                let indent = "  ".repeat(depth);
                let tag = match node.kind {
                    EntryKind::Directory => "/",
                    EntryKind::File => "",
                    EntryKind::Symlink => " ->",
                    EntryKind::Special => " (special)",
                };
                out.push(format!("{indent}{}{tag}", node.name));
                if node.kind == EntryKind::Directory {
                    walk(vfs, &node.path, out, depth + 1);
                }
            }
        }
        let mut out = Vec::new();
        walk(self, dir, &mut out, 1);
        out
    }

    /// A recursive listing in `ls -R` style, used by the CLI and tests.
    pub fn tree_lines(&self) -> Vec<String> {
        fn walk(vfs: &Vfs, dir: &str, out: &mut Vec<String>, depth: usize) {
            for node in vfs.children(dir) {
                let indent = "  ".repeat(depth);
                let tag = match node.kind {
                    EntryKind::Directory => "/",
                    EntryKind::File => "",
                    EntryKind::Symlink => " ->",
                    EntryKind::Special => " (special)",
                };
                out.push(format!("{indent}{}{tag}", node.name));
                if node.kind == EntryKind::Directory {
                    walk(vfs, &node.path, out, depth + 1);
                }
            }
        }
        let mut out = Vec::new();
        walk(self, "", &mut out, 0);
        out
    }
}

/// Resolve `name` to a sanitised path, for callers that build paths by hand.
pub fn join(parent: &str, name: &str) -> Option<SafeMemberPath> {
    let raw = if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    };
    crate::security::sanitize_member_path(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Compression, Encryption};
    use crate::security::PathViolation;

    fn file(name: &str) -> ArchiveEntry {
        ArchiveEntry {
            raw_name: name.into(),
            path: crate::security::sanitize_member_path(name).ok(),
            path_violation: None,
            kind: EntryKind::File,
            uncompressed_size: 10,
            compressed_size: 5,
            compression: Compression::Deflate,
            encryption: Encryption::None,
            modified: None,
            unix_mode: None,
            crc32: None,
        }
    }

    fn dir(name: &str) -> ArchiveEntry {
        let mut e = file(name);
        e.kind = EntryKind::Directory;
        e.uncompressed_size = 0;
        e.compressed_size = 0;
        e
    }

    fn unsafe_entry(name: &str) -> ArchiveEntry {
        ArchiveEntry {
            raw_name: name.into(),
            path: None,
            path_violation: Some(PathViolation::Traversal),
            kind: EntryKind::File,
            uncompressed_size: 1,
            compressed_size: 1,
            compression: Compression::Stored,
            encryption: Encryption::None,
            modified: None,
            unix_mode: None,
            crc32: None,
        }
    }

    #[test]
    fn lists_top_level_entries() {
        let vfs = Vfs::from_entries(&[file("a.txt"), file("b.txt"), dir("sub")]);
        let names: Vec<&str> = vfs.children("").iter().map(|n| n.name.as_str()).collect();
        // directories sort first
        assert_eq!(names, vec!["sub", "a.txt", "b.txt"]);
    }

    #[test]
    fn creates_implicit_directories() {
        // No explicit "a" or "a/b" entries at all.
        let vfs = Vfs::from_entries(&[file("a/b/c.txt"), file("a/b/d.txt")]);
        assert!(vfs.is_directory("a"));
        assert!(vfs.is_directory("a/b"));
        let kids: Vec<&str> = vfs
            .children("a/b")
            .iter()
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(kids, vec!["c.txt", "d.txt"]);
        assert!(vfs.get("a").unwrap().implicit);
    }

    #[test]
    fn explicit_directory_is_not_marked_implicit() {
        let vfs = Vfs::from_entries(&[dir("a"), file("a/b.txt")]);
        assert!(!vfs.get("a").unwrap().implicit);
        assert!(vfs.get("a").unwrap().kind == EntryKind::Directory);
    }

    #[test]
    fn nesting_is_case_insensitive_sorted() {
        let vfs = Vfs::from_entries(&[file("Zeta.txt"), file("alpha.txt"), file("Beta.txt")]);
        let names: Vec<&str> = vfs.children("").iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["alpha.txt", "Beta.txt", "Zeta.txt"]);
    }

    #[test]
    fn unsafe_entries_are_collected_not_indexed() {
        let vfs = Vfs::from_entries(&[file("ok.txt"), unsafe_entry("../../evil")]);
        assert_eq!(vfs.len(), 1);
        assert_eq!(vfs.rejected().len(), 1);
        assert_eq!(vfs.rejected()[0].0, "../../evil");
        assert!(vfs.get("../../evil").is_none());
    }

    #[test]
    fn resolve_rejects_escapes() {
        let vfs = Vfs::from_entries(&[file("a/b.txt")]);
        assert!(vfs.resolve("a/b.txt").is_some());
        assert!(vfs.resolve("./a/b.txt").is_some());
        assert!(vfs.resolve("../etc/passwd").is_none());
        assert!(vfs.resolve("a/../..").is_none());
        assert!(vfs.resolve("nope").is_none());
    }

    #[test]
    fn subtree_size_sums_files_only() {
        let mut big = file("a/big.bin");
        big.uncompressed_size = 1000;
        let vfs = Vfs::from_entries(&[file("a/small.txt"), big, file("other.txt")]);
        // 10 (a/small.txt) + 1000 (a/big.bin) + 10 (other.txt)
        assert_eq!(vfs.subtree_size("a"), 1010);
        assert_eq!(vfs.subtree_size(""), 1020);
    }

    #[test]
    fn empty_archive_has_only_root() {
        let vfs = Vfs::from_entries(&[]);
        assert!(vfs.is_empty());
        assert!(vfs.children("").is_empty());
    }

    #[test]
    fn tree_lines_are_indented() {
        let vfs = Vfs::from_entries(&[file("a/b.txt"), file("c.txt")]);
        assert_eq!(vfs.tree_lines(), vec!["a/", "  b.txt", "c.txt"]);
    }

    #[test]
    fn join_helper_sanitises() {
        assert_eq!(join("a", "b.txt").unwrap().as_key(), "a/b.txt");
        assert_eq!(join("", "b.txt").unwrap().as_key(), "b.txt");
        assert!(join("a", "../evil").is_none());
    }

    #[test]
    fn explicit_directory_wins_over_implied() {
        // archive declares both; the explicit one must not be duplicated
        let vfs = Vfs::from_entries(&[dir("a"), file("a/b.txt")]);
        assert_eq!(vfs.len(), 2);
        assert_eq!(vfs.children("").len(), 1);
    }
}
