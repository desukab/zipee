//! Integration tests for the improvements driven by the decompiled reference.
//!
//! Each case here corresponds to a named gap in
//! `docs/research/decompiled-architecture.md`. The reference implementation
//! was *read*, never copied: what is tested is Zipee's own behaviour, chosen
//! because the reference decompiles to a symbol suggesting it is a real
//! problem.
//!
//! Fixtures are synthetic, built with the crate's own helpers.

use std::fs::File;
use std::io::Write;

use zipee_engine::macmeta::{is_mac_metadata, MacMetadataSummary};
use zipee_engine::security::{DEFAULT_DIRECTORY_MODE, DEFAULT_FILE_MODE, MAX_COMPONENT_BYTES};
use zipee_engine::{open_any, ArchiveAccess, EntryKind, Vfs};

fn make_zip(path: &std::path::Path, members: &[(&str, &[u8])]) {
    let mut w = zip::ZipWriter::new(File::create(path).unwrap());
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap();
}

/// Build an archive in a temp dir and return an open `Vfs`.
fn vfs_for(members: &[(&str, &[u8])]) -> (tempfile::TempDir, Vfs) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.zip");
    make_zip(&p, members);
    let mut a = open_any(&p).unwrap();
    (dir, a.vfs().unwrap())
}

// --- gap 1: AppleDouble and __MACOSX -------------------------------------

#[test]
fn appledouble_sidecars_are_hidden_from_browsing() {
    let (_d, vfs) = vfs_for(&[
        ("readme.md", b"content"),
        ("._readme.md", b"\x00\x05\x16\x07mdim"),
        ("__MACOSX", b""),
        ("__MACOSX/._readme.md", b"\x00\x05\x16\x07"),
        ("src/main.rs", b"fn main(){}"),
        ("src/._main.rs", b"\x00\x05\x16\x07"),
    ]);

    let visible: Vec<&str> = vfs
        .subtree_nodes("")
        .into_iter()
        .map(|n| n.path.as_str())
        .collect();
    assert!(
        visible.contains(&"readme.md"),
        "real content must survive: {visible:?}"
    );
    assert!(
        visible.contains(&"src"),
        "real directories must survive: {visible:?}"
    );

    for hidden in ["._readme.md", "__MACOSX", "src/._main.rs"] {
        assert!(
            !visible.contains(&hidden),
            "{hidden:?} is macOS metadata and must not be browsable"
        );
        assert!(
            vfs.get(hidden).is_none(),
            "{hidden:?} must not be in the tree"
        );
    }

    // And it must be *reported*, not silently dropped.
    assert_eq!(vfs.mac_metadata().hidden(), 3);
    assert!(vfs.hidden_summary().unwrap().contains("macOS metadata"));
}

#[test]
fn appledouble_members_are_never_extracted() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.zip");
    make_zip(
        &p,
        &[
            ("real.txt", b"real"),
            ("._real.txt", b"sidecar"),
            ("__MACOSX/._other.txt", b"tree sidecar"),
        ],
    );
    let out = dir.path().join("out");

    let mut a = open_any(&p).unwrap();
    let report = zipee_engine::extract(
        a.as_mut(),
        &zipee_engine::Selection::Everything,
        &out,
        &zipee_engine::ExtractionBudget::interactive(),
        &mut zipee_engine::NoPassword,
        &Default::default(),
        &mut |_| {},
    )
    .unwrap();

    assert_eq!(report.extracted, 1);
    assert!(out.join("real.txt").exists());
    assert!(
        !out.join("._real.txt").exists(),
        "sidecar must not be written"
    );
    assert!(
        !out.join("__MACOSX").exists(),
        "sidecar tree must not be written"
    );
    // The destination contains exactly one file.
    let mut files = Vec::new();
    collect_files(&out, &mut files);
    assert_eq!(files.len(), 1, "got {files:?}");
}

fn collect_files(dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else {
            out.push(p.strip_prefix(dir).unwrap().to_string_lossy().into_owned());
        }
    }
}

#[test]
fn the_reference_products_own_leak_is_the_motivation() {
    // While reverse-engineering the reference product, its own payload was
    // found to contain Contents/Resources/._zipgeist-icon-source.png — an
    // AppleDouble file its packager leaked. This asserts the detector catches
    // exactly that shape.
    assert!(is_mac_metadata(
        "Applications/Zipgeist.app/Contents/Resources/._zipgeist-icon-source.png"
    ));
    assert!(!is_mac_metadata(
        "Applications/Zipgeist.app/Contents/Resources/zipgeist-icon-source.png"
    ));
}

#[test]
fn oversized_sidecars_are_flagged_but_still_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.zip");
    let huge = vec![0u8; 200 * 1024];
    make_zip(&p, &[("real.txt", b"real"), ("._real.txt", &huge)]);
    let mut a = open_any(&p).unwrap();
    let vfs = a.vfs().unwrap();
    assert_eq!(vfs.mac_metadata().hidden(), 1);
    assert_eq!(vfs.mac_metadata().oversized, 1);
    assert!(vfs.hidden_summary().unwrap().contains("implausibly large"));
    assert!(vfs.get("real.txt").is_some());
    assert!(vfs.get("._real.txt").is_none());
}

// --- gap 2: case-insensitive collisions -----------------------------------

#[test]
fn case_collisions_are_detected_and_reported() {
    let (_d, vfs) = vfs_for(&[("Notes.txt", b"upper"), ("notes.txt", b"lower")]);

    let collisions = vfs.case_collisions();
    assert_eq!(collisions.len(), 1, "got {collisions:?}");
    let (first, second) = &collisions[0];
    assert_ne!(first, second);
    assert_eq!(first.to_lowercase(), second.to_lowercase());

    assert!(vfs.hidden_summary().unwrap().contains("case-insensitive"));

    // Both remain individually readable by their exact names.
    assert!(vfs.get("Notes.txt").is_some());
    assert!(vfs.get("notes.txt").is_some());
}

#[test]
fn case_sensitive_archives_report_nothing() {
    let (_d, vfs) = vfs_for(&[("Notes.txt", b"a"), ("notes.md", b"b"), ("readme", b"c")]);
    assert!(vfs.case_collisions().is_empty());
    assert_eq!(vfs.hidden_summary(), None);
}

#[test]
fn directories_collide_too_not_just_files() {
    let (_d, vfs) = vfs_for(&[("Src/a.txt", b"a"), ("src/b.txt", b"b")]);
    assert_eq!(vfs.case_collisions().len(), 1);
    assert!(vfs.get("Src").is_some());
    assert!(vfs.get("src").is_some());
}

// --- gap 3: external modification ----------------------------------------

#[test]
fn fingerprint_catches_a_replacement_even_at_the_same_size_and_time() {
    use zipee_engine::zip_archive::{fingerprint, ZipArchive};

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("watch.zip");
    make_zip(&p, &[("a.txt", b"aaaa")]);
    let a = ZipArchive::open(&p).unwrap();
    assert!(!a.changed_on_disk());

    let before = fingerprint(&p).unwrap();

    // Replace by rename, which is how atomic writers and editors swap a file.
    // `fs::copy` would NOT demonstrate this: it writes into the existing
    // inode. A new file of the *same length*, renamed over the old one,
    // preserves size -- and can preserve mtime -- but cannot preserve inode.
    let replacement = dir.path().join("replacement.zip");
    make_zip(&replacement, &[("a.txt", b"bbbb")]);
    std::fs::rename(&replacement, &p).unwrap();

    let after = fingerprint(&p).unwrap();
    assert_eq!(before.len, after.len, "size was deliberately preserved");
    assert_ne!(
        before.inode, after.inode,
        "a rename-over must change the inode even when size is preserved"
    );
    assert_eq!(
        before.device, after.device,
        "same directory, so the device must be stable"
    );

    // And the engine must notice the swap.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let a = ZipArchive::open(&p).unwrap();
    let replacement2 = dir.path().join("r2.zip");
    make_zip(&replacement2, &[("a.txt", b"cccc")]);
    std::fs::rename(&replacement2, &p).unwrap();
    assert!(a.changed_on_disk());
    assert!(matches!(
        a.ensure_unchanged(),
        Err(zipee_engine::Error::ExternalModification)
    ));
}

// --- gaps 4 and 5: defaults and component limits -------------------------

#[test]
fn default_modes_are_conservative_not_permissive() {
    // The reference decompiles to defaultFilePermissions /
    // defaultDirectoryPermissions; the values are its own. Zipee chose these,
    // and the assertion is that they are not wide.
    assert_eq!(DEFAULT_FILE_MODE & 0o7777, 0o644);
    assert_eq!(DEFAULT_DIRECTORY_MODE & 0o7777, 0o755);
    assert_eq!(
        DEFAULT_FILE_MODE & 0o022,
        0,
        "files must not be group/other writable"
    );
    assert_eq!(
        DEFAULT_DIRECTORY_MODE & 0o022,
        0,
        "directories must not be group/other writable"
    );
}

#[test]
fn a_long_single_component_is_refused_even_when_the_path_is_short() {
    // 300 bytes in one component is under the 4096-byte whole-path limit but
    // over the 255-byte component limit, so a naive path check would accept it
    // and the write would fail later.
    let long_component = "a".repeat(300);
    let path = format!("{long_component}.txt");
    assert!(path.len() < zipee_engine::security::MAX_PATH_BYTES);
    assert!(path.len() > MAX_COMPONENT_BYTES);
    let err = zipee_engine::sanitize_member_path(&path).unwrap_err();
    assert!(
        matches!(err, zipee_engine::PathViolation::ComponentTooLong(_)),
        "the component limit, not the whole-path limit, is what must fire: {err:?}"
    );

    // Splitting the same bytes into two components is accepted.
    let split = format!("{}/{}", "a".repeat(200), "b".repeat(200));
    assert!(zipee_engine::sanitize_member_path(&split).is_ok());
}

#[test]
fn ordinary_components_still_pass() {
    for name in ["readme.md", "a/b/c.txt", "café.txt", "日本語.txt"] {
        assert!(
            zipee_engine::sanitize_member_path(name).is_ok(),
            "{name:?} should be accepted"
        );
    }
}

// --- regression: real content must never be hidden ------------------------

#[test]
fn nothing_that_is_real_content_is_ever_hidden() {
    let tricky = [
        "dir/_.hidden",     // one underscore
        "dir/..hidden",     // leading dots, not `._`
        "my__MACOSX/file",  // contains, does not start with
        "MACOSX/file",      // no underscores
        "__MACOSXish/file", // longer name, not the directory
        "dir/_",            // bare underscore
        "dir/._",           // bare AppleDouble prefix, no sibling
        "data/file.tar.gz",
        "docs/__MACOSX.md", // a file, in a doc directory
    ];
    for name in tricky {
        assert!(!is_mac_metadata(name), "{name:?} is real content");
    }
}

#[test]
fn an_archive_of_only_sidecars_is_empty_but_not_an_error() {
    let (_d, vfs) = vfs_for(&[("._a", b"x"), ("__MACOSX/._b", b"y")]);
    assert!(vfs.subtree_nodes("").is_empty());
    assert_eq!(vfs.mac_metadata().hidden(), 2);
    assert!(vfs.hidden_summary().is_some());
}

#[test]
fn stats_still_count_hidden_members_but_the_tree_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.zip");
    make_zip(
        &p,
        &[
            ("real.txt", b"x"),
            ("._real.txt", b"y"),
            ("__MACOSX/._z", b"w"),
        ],
    );
    let mut a = open_any(&p).unwrap();
    // The container index is untouched: nothing is rewritten behind the user's
    // back, so every member is still accounted for.
    assert_eq!(a.entries().unwrap().len(), 3);
    let vfs = a.vfs().unwrap();
    // The browsable tree omits the metadata.
    assert_eq!(vfs.subtree_nodes("").len(), 1);
    assert_eq!(vfs.mac_metadata().hidden(), 2);
    assert!(vfs.get("real.txt").unwrap().kind == EntryKind::File);
}

#[test]
fn summary_is_absent_for_a_fully_ordinary_archive() {
    let (_d, vfs) = vfs_for(&[("a.txt", b"a"), ("dir/b.txt", b"b")]);
    assert_eq!(vfs.hidden_summary(), None);
    assert_eq!(vfs.mac_metadata(), &MacMetadataSummary::default());
    assert!(vfs.rejected().is_empty());
    assert!(vfs.case_collisions().is_empty());
}
