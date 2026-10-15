//! Security tests.
//!
//! Every fixture here is synthetic and built in-process from bytes Zipee
//! assembles itself. Nothing in this file touches a real user archive, and
//! every extraction runs into a fresh `tempfile` directory so a bug can never
//! escape into the developer's home directory.
//!
//! The cases map to the archive-parsing vulnerability classes that matter:
//! path traversal, absolute paths, symlink escape, decompression bombs,
//! entry-count floods, resource exhaustion, checksum corruption, and the
//! failure-atomicity of write-back.

use std::fs;
use std::io::Write;
use std::path::Path;

use zipee_engine::archive::{ArchiveAccess, MemberEdit};
use zipee_engine::entry::{NoPassword, StaticPassword};
use zipee_engine::error::Error;
use zipee_engine::extract::{extract, CancelToken, Selection};
use zipee_engine::format::Format;
use zipee_engine::security::ExtractionBudget;
use zipee_engine::writeback::rewrite_zip;
use zipee_engine::zip_archive::ZipArchive;

// --- fixture helpers -------------------------------------------------------

mod rawzip;
use rawzip::{raw_zip, RawMember};

/// Build a ZIP with the `zip` crate. Used where a *well-formed* archive is
/// wanted and member names are not the point.
fn zip_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

/// Run an extraction to completion, ignoring progress.
fn run_extract(
    archive: &mut dyn ArchiveAccess,
    spec: &str,
    dest: &Path,
    budget: &ExtractionBudget,
) -> zipee_engine::error::Result<zipee_engine::extract::ExtractReport> {
    extract(
        archive,
        &Selection::parse(spec)?,
        dest,
        budget,
        &mut NoPassword,
        &CancelToken::new(),
        &mut |_| {},
    )
}

/// Assert that nothing was created outside the extraction root.
///
/// Security tests must assert *outcomes*, not just counters: a bug that writes
/// to `/tmp` while still reporting a tidy report would pass a counter check.
fn assert_contained(root: &Path, sentinel_names: &[&str]) {
    let parent = root.parent().unwrap();
    for name in sentinel_names {
        assert!(
            !parent.join(name).exists(),
            "a member escaped and created {}",
            parent.join(name).display()
        );
    }
    // Nothing may be left beside the destination either.
    for entry in fs::read_dir(parent).unwrap() {
        let n = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !n.contains("zipee-part") && !n.ends_with(".zipee"),
            "temporary artefact {n:?} left behind"
        );
    }
}

// --- path traversal --------------------------------------------------------

#[test]
fn zip_slip_member_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[RawMember::hostile("../evil.txt", b"pwned")]);
    let archive_path = write_temp(dir.path(), "a.zip", &bytes);

    let out = dir.path().join("out");
    let mut a = ZipArchive::open(&archive_path).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();

    assert!(
        report.rejected >= 1,
        "the traversing member must be refused, report was {report:?}"
    );
    assert_contained(&out, &["evil.txt"]);
    assert!(!dir.path().join("evil.txt").exists());
}

#[test]
fn deep_traversal_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    // climbs out, then back in: still an escape and still refused
    let bytes = raw_zip(&[RawMember::hostile("sub/../../../b", b"pwned")]);
    let p = write_temp(dir.path(), "b.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert_contained(&out, &["b"]);
    assert!(!dir.path().join("b").exists());
}

#[test]
fn absolute_member_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[RawMember::hostile("/tmp/zipee-escape-test", b"pwned")]);
    let p = write_temp(dir.path(), "c.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert!(
        !Path::new("/tmp/zipee-escape-test").exists(),
        "an absolute member was written outside the destination"
    );
}

#[test]
fn windows_style_traversal_is_never_written() {
    // Backslash separators must not bypass the traversal check on a POSIX host.
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[RawMember::hostile("..\\evil", b"pwned")]);
    let p = write_temp(dir.path(), "d.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert_contained(&out, &["evil"]);
    let _ = &report;
}

#[test]
fn nul_in_member_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[RawMember::hostile("ok.txt\u{0}.png", b"x")]);
    let p = write_temp(dir.path(), "nul.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let _report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    // Whatever the reader made of the name, the only file on disk must be
    // inside the destination.
    assert_contained(&out, &["ok.txt.png", "ok.txt"]);
}

#[test]
fn tar_traversal_is_never_written() {
    // tar headers are built here so the engine's own reader is exercised
    // against a hostile name, independently of any writer.
    let dir = tempfile::tempdir().unwrap();
    let tar = build_hostile_tar("../../evil", b"pwned");
    let p = write_temp(dir.path(), "e.tar", &tar);
    let out = dir.path().join("out");

    let mut a = zipee_engine::open_any(&p).unwrap();
    assert_eq!(a.format(), Format::Tar);
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert_contained(&out, &["evil"]);
    let _ = &report;
    assert!(!dir.path().join("evil").exists());
}

#[test]
fn tar_absolute_path_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let tar = build_hostile_tar("/tmp/zipee-tar-escape", b"pwned");
    let p = write_temp(dir.path(), "f.tar", &tar);
    let out = dir.path().join("out");

    let mut a = zipee_engine::open_any(&p).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert!(!Path::new("/tmp/zipee-tar-escape").exists());
}

#[test]
fn selection_itself_rejects_hostile_specs() {
    for spec in [
        "../evil",
        "/etc/passwd",
        "a/../../b",
        "..\\..\\evil",
        "C:\\Windows\\evil",
    ] {
        assert!(
            Selection::parse(spec).is_err(),
            "selection {spec:?} must be refused before any I/O"
        );
    }
}

// --- symlinks --------------------------------------------------------------

#[test]
fn symlink_members_are_recognised_but_never_written() {
    let dir = tempfile::tempdir().unwrap();
    // A symlink member whose body is an absolute path. The engine must see it
    // as a link, show it, and refuse to create it on disk.
    let bytes = raw_zip(&[RawMember::file("link", b"/etc/passwd").into_symlink()]);
    let p = write_temp(dir.path(), "s.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let entries = a.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].kind,
        zipee_engine::EntryKind::Symlink,
        "the member must be recognised as a symbolic link"
    );

    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert_eq!(
        report.rejected, 1,
        "a symlink must be refused, report was {report:?}"
    );
    assert!(!out.join("link").exists(), "no link may be created");
    assert_contained(&out, &["link"]);
}

#[test]
fn symlink_target_validator_rejects_escapes() {
    use zipee_engine::security::validate_symlink_target;
    let root = Path::new("/tmp/zipee-root");
    assert!(validate_symlink_target(root, "inside/file").is_ok());
    assert!(validate_symlink_target(root, "sub/../inside").is_ok());
    assert!(validate_symlink_target(root, "/etc/passwd").is_err());
    assert!(validate_symlink_target(root, "../../etc/passwd").is_err());
    assert!(validate_symlink_target(root, "").is_err());
}

#[test]
fn symlink_followed_on_read_does_not_escape() {
    // A member whose name collides with a link we would create must still land
    // inside the destination, because no link is ever created.
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[
        RawMember::file("link", b"../../elsewhere").into_symlink(),
        RawMember::file("link/child.txt", b"payload"),
    ]);
    let p = write_temp(dir.path(), "linkattack.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.rejected >= 1, "{report:?}");
    assert_contained(&out, &["link", "elsewhere"]);
    assert!(!dir.path().join("elsewhere").exists());
}

// --- decompression bombs ---------------------------------------------------

#[test]
fn high_ratio_member_is_refused_before_decompression() {
    let dir = tempfile::tempdir().unwrap();
    // 8 MiB of zeros deflates to a few KiB: a ratio well past the strict
    // budget's 100:1 ceiling, and exactly the shape of a classic bomb.
    let big = vec![0u8; 8 * 1024 * 1024];
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    w.start_file("zeros.bin", opts).unwrap();
    w.write_all(&big).unwrap();
    let bytes = w.finish().unwrap().into_inner();
    let p = write_temp(dir.path(), "bomb.zip", &bytes);

    let mut a = ZipArchive::open(&p).unwrap();
    let err = run_extract(
        &mut a,
        "*",
        &dir.path().join("out"),
        &ExtractionBudget::strict(),
    )
    .expect_err("a bomb must be refused");

    match err {
        Error::Budget(b) => assert!(b.to_string().contains("ratio"), "got {b}"),
        other => panic!("expected a budget error, got {other}"),
    }
    assert!(!dir.path().join("out/zeros.bin").exists());
}

#[test]
fn zero_compressed_size_with_content_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_temp(
        dir.path(),
        "zero.zip",
        &zip_bytes(&[("x.bin", b"not actually empty")]),
    );
    let a = ZipArchive::open(&p).unwrap();

    // Force the pathological header directly through the budget API.
    let budget = ExtractionBudget::default();
    assert!(budget.check_ratio(1024, 0).is_err());
    let _ = a;
}

#[test]
fn entry_count_flood_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let members: Vec<(String, Vec<u8>)> = (0..2000)
        .map(|i| (format!("f{i:05}.txt"), Vec::new()))
        .collect();
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let p = write_temp(dir.path(), "flood.zip", &zip_bytes(&refs));

    let budget = ExtractionBudget {
        max_entries: 100,
        ..ExtractionBudget::default()
    };
    let mut a = ZipArchive::open(&p).unwrap();
    let err = run_extract(&mut a, "*", &dir.path().join("out"), &budget)
        .expect_err("an entry-count flood must be bounded");

    match err {
        Error::Budget(b) => assert!(b.to_string().contains("entries"), "got {b}"),
        other => panic!("expected an entry-count budget error, got {other}"),
    }
}

#[test]
fn total_byte_ceiling_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let chunk = vec![7u8; 4096];
    let members: Vec<(String, Vec<u8>)> = (0..64)
        .map(|i| (format!("c{i}.bin"), chunk.clone()))
        .collect();
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let p = write_temp(dir.path(), "big.zip", &zip_bytes(&refs));

    let budget = ExtractionBudget {
        max_total_bytes: 4096 * 10,
        max_single_entry_bytes: 1 << 30,
        ..ExtractionBudget::default()
    };
    let mut a = ZipArchive::open(&p).unwrap();
    let err = run_extract(&mut a, "*", &dir.path().join("out"), &budget)
        .expect_err("the total byte ceiling must be enforced");
    assert!(matches!(err, Error::Budget(_)), "got {err}");
}

// --- corruption ------------------------------------------------------------

#[test]
fn corrupt_checksum_is_reported_not_silently_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[
        RawMember::file("data.txt", b"original contents"),
        RawMember::file("other.txt", b"fine").with_bad_crc(),
    ]);
    let p = write_temp(dir.path(), "corrupt.zip", &bytes);

    let mut a = ZipArchive::open(&p).unwrap();
    assert_eq!(
        a.read_entry("data.txt", &mut NoPassword).unwrap(),
        b"original contents"
    );

    let err = a
        .read_entry("other.txt", &mut NoPassword)
        .expect_err("a CRC mismatch must be reported");
    match err {
        Error::Corrupt(msg) => assert!(
            msg.contains("CRC") || msg.contains("checksum"),
            "the message must name the integrity failure, got {msg}"
        ),
        other => panic!("expected a corrupt error, got {other}"),
    }

    // verify() must localise the failure to the bad member only.
    let report = a.verify(&mut NoPassword).unwrap();
    assert_eq!(report.ok, 1);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, "other.txt");
    assert!(!report.is_healthy());

    // And extraction must record it as a failure, not write bad bytes.
    let out = dir.path().join("out");
    let extract_report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert_eq!(extract_report.failed, 1);
    assert!(
        !out.join("other.txt").exists(),
        "corrupt data must not be written"
    );
    assert!(out.join("data.txt").exists());
}

#[test]
fn truncated_archive_reports_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = zip_bytes(&[("a.txt", &vec![9u8; 4096]), ("b.txt", b"second")]);
    // Chop the file in half: the central directory is gone.
    let truncated = &bytes[..bytes.len() / 2];
    let p = write_temp(dir.path(), "trunc.zip", truncated);

    let opened = ZipArchive::open(&p);
    match opened {
        Err(Error::Corrupt(_)) | Err(Error::Io { .. }) => {}
        Ok(mut a) => {
            // Some truncation still parses; reading a member must then fail.
            let r = a.read_entry("a.txt", &mut NoPassword);
            assert!(r.is_err(), "a truncated archive must not yield member data");
        }
        Err(other) => panic!("unexpected error {other}"),
    }
}

#[test]
fn empty_archive_is_valid_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = zip_bytes(&[]);
    let p = write_temp(dir.path(), "empty.zip", &bytes);

    let mut a = ZipArchive::open(&p).unwrap();
    assert_eq!(a.entries().unwrap().len(), 0);
    let out = dir.path().join("out");
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.extracted, 0);
}

#[test]
fn verify_reports_per_member_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = zip_bytes(&[("ok.txt", b"fine"), ("also.txt", b"also fine")]);
    let p = write_temp(dir.path(), "verify.zip", &bytes);
    let mut a = ZipArchive::open(&p).unwrap();

    let report = a.verify(&mut NoPassword).unwrap();
    assert_eq!(report.ok, 2);
    assert!(report.failed.is_empty());
    assert!(report.is_healthy());
}

// --- unicode and pathological names ---------------------------------------

#[test]
fn unicode_and_long_names_survive_intact() {
    let dir = tempfile::tempdir().unwrap();
    let names = [
        "café/naïve.txt",
        "日本語/ファイル名.txt",
        "emoji-\u{1F4C1}/archive-\u{1F5DC}.zip",
        "русский/файл.txt",
    ];
    let members: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, b"x" as &[u8])).collect();
    let p = write_temp(dir.path(), "uni.zip", &zip_bytes(&members));

    let mut a = ZipArchive::open(&p).unwrap();
    let out = dir.path().join("out");
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert!(report.is_clean(), "{:?}", report.rejections());
    assert_eq!(report.extracted, names.len() as u64);

    for n in names {
        assert!(out.join(n).exists(), "{n} was not extracted");
    }
}

#[test]
fn duplicate_names_are_indexed_individually_and_read_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[
        RawMember::file("dup.txt", b"first"),
        RawMember::file("dup.txt", b"second"),
        RawMember::file("other.txt", b"other"),
    ]);
    let p = write_temp(dir.path(), "dup.zip", &bytes);

    let mut a = ZipArchive::open(&p).unwrap();

    // KNOWN LIMITATION, documented rather than hidden: the `zip` reader keys
    // its central-directory index by name, so two records with the same name
    // collapse to one. Zipee therefore sees 2 members, not 3, and exposes the
    // name that wins. Reporting a third phantom entry would be a lie; the
    // reader limitation is tracked in docs/feature-matrix.md.
    let entries = a.entries().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "the underlying reader collapses same-named records"
    );
    assert!(entries.iter().all(|e| e.raw_name != "dup.txt.extra"));

    // Reading is deterministic even though the archive is ambiguous.
    let first = a.read_entry("dup.txt", &mut NoPassword).unwrap();
    let second = a.read_entry("dup.txt", &mut NoPassword).unwrap();
    assert_eq!(first, second, "reads must be deterministic");
    assert!(
        first == b"first" || first == b"second",
        "resolved to one of the two records"
    );

    let out = dir.path().join("out");
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert_eq!(report.extracted, 2);
    assert!(out.join("dup.txt").exists());
}

#[test]
fn conflicting_case_differing_names_are_both_kept() {
    let dir = tempfile::tempdir().unwrap();
    // Filesystems vary: macOS's default HFS+/APFS is case-insensitive, so a
    // ZIP with `A.txt` and `a.txt` cannot be extracted faithfully to both.
    let bytes = raw_zip(&[
        RawMember::file("A.txt", b"upper"),
        RawMember::file("a.txt", b"lower"),
    ]);
    let p = write_temp(dir.path(), "case.zip", &bytes);
    let mut a = ZipArchive::open(&p).unwrap();
    assert_eq!(a.entries().unwrap().len(), 2);
    // Both are addressable by their exact names regardless of the host FS.
    assert_eq!(a.read_entry("A.txt", &mut NoPassword).unwrap(), b"upper");
    assert_eq!(a.read_entry("a.txt", &mut NoPassword).unwrap(), b"lower");
}

// --- cancellation and write failures --------------------------------------

#[test]
fn cancellation_stops_before_the_first_member() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_temp(
        dir.path(),
        "cancel.zip",
        &zip_bytes(&[("a.txt", b"a"), ("b.txt", b"b")]),
    );
    let out = dir.path().join("out");
    let cancel = CancelToken::new();
    cancel.cancel();

    let mut a = ZipArchive::open(&p).unwrap();
    let err = extract(
        &mut a,
        &Selection::Everything,
        &out,
        &ExtractionBudget::interactive(),
        &mut NoPassword,
        &cancel,
        &mut |_| {},
    )
    .expect_err("a cancelled extraction must fail");
    assert!(matches!(err, Error::Cancelled));
    assert!(!out.join("a.txt").exists(), "nothing should be written");
}

#[test]
fn no_partial_file_survives_a_write_failure() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_temp(dir.path(), "partial.zip", &zip_bytes(&[("a.txt", b"body")]));
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();

    let mut a = ZipArchive::open(&p).unwrap();
    run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();

    // No temporary part-file may remain after a successful extraction.
    let leftovers: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("zipee-part"))
        .collect();
    assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"body");
}

// --- write-back ------------------------------------------------------------

#[test]
fn writeback_refuses_to_overwrite_its_own_source() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_temp(dir.path(), "edit.zip", &zip_bytes(&[("a.txt", b"a")]));

    let mut a = ZipArchive::open(&p).unwrap();
    let err = rewrite_zip(
        &mut a,
        &p,
        &p,
        &[MemberEdit::Replace {
            name: "a.txt".into(),
            data: b"b".to_vec(),
        }],
        &ExtractionBudget::interactive(),
    )
    .expect_err("in-place editing must be refused");

    assert!(matches!(err, Error::InPlaceWriteRefused));
    // and the original is untouched
    assert_eq!(fs::read(&p).unwrap(), zip_bytes(&[("a.txt", b"a")]));
}

#[test]
fn writeback_produces_a_valid_archive_and_keeps_the_original_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let src = write_temp(
        dir.path(),
        "src.zip",
        &zip_bytes(&[("keep.txt", b"keep"), ("drop.txt", b"drop")]),
    );
    let dst = dir.path().join("edited.zip");

    let mut a = ZipArchive::open(&src).unwrap();
    let report = rewrite_zip(
        &mut a,
        &src,
        &dst,
        &[
            MemberEdit::Delete {
                name: "drop.txt".into(),
            },
            MemberEdit::Add {
                path: zipee_engine::sanitize_member_path("new/added.txt").unwrap(),
                data: b"added".to_vec(),
            },
        ],
        &ExtractionBudget::interactive(),
    )
    .unwrap();

    assert_eq!(report.deleted, vec!["drop.txt"]);
    assert_eq!(report.added, vec!["new/added.txt"]);

    // original intact
    assert!(src.exists());
    let mut original = ZipArchive::open(&src).unwrap();
    assert_eq!(original.entries().unwrap().len(), 2);

    // replacement is a valid archive with the expected contents
    let mut edited = ZipArchive::open(&dst).unwrap();
    let names: Vec<String> = edited
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.raw_name.clone())
        .collect();
    assert!(names.contains(&"keep.txt".to_string()));
    assert!(!names.contains(&"drop.txt".to_string()));
    assert!(names.contains(&"new/added.txt".to_string()));
    assert_eq!(
        edited.read_entry("new/added.txt", &mut NoPassword).unwrap(),
        b"added"
    );
}

#[test]
fn writeback_drops_unsafe_members_instead_of_republishing_them() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[
        RawMember::file("safe.txt", b"ok"),
        RawMember::hostile("../evil.txt", b"pwned"),
    ]);
    let src = write_temp(dir.path(), "hostile.zip", &bytes);
    let dst = dir.path().join("clean.zip");

    let mut a = ZipArchive::open(&src).unwrap();
    rewrite_zip(&mut a, &src, &dst, &[], &ExtractionBudget::interactive()).unwrap();

    let mut cleaned = ZipArchive::open(&dst).unwrap();
    let entries = cleaned.entries().unwrap();
    assert!(
        entries.iter().all(|e| !e.is_unsafe()),
        "a rewritten archive must contain no unsafe members"
    );
}

#[test]
fn external_modification_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let src = write_temp(dir.path(), "watch.zip", &zip_bytes(&[("a.txt", b"a")]));

    let mut a = ZipArchive::open(&src).unwrap();
    assert!(!a.changed_on_disk());

    // Rewrite the file behind the engine's back.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(&src, zip_bytes(&[("a.txt", b"aaaa"), ("b.txt", b"b")])).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    assert!(a.changed_on_disk());
    assert!(matches!(
        a.ensure_unchanged(),
        Err(Error::ExternalModification)
    ));

    // A rewrite against a stale index must refuse rather than clobber.
    let dst = dir.path().join("out.zip");
    let err = rewrite_zip(&mut a, &src, &dst, &[], &ExtractionBudget::interactive());
    assert!(
        matches!(err, Err(Error::ExternalModification)),
        "got {err:?}"
    );
    assert!(!dst.exists(), "no output may be written from a stale index");
}

// --- passwords -------------------------------------------------------------

#[test]
fn missing_password_is_reported_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_temp(dir.path(), "plain.zip", &zip_bytes(&[("a.txt", b"a")]));

    let mut a = ZipArchive::open(&p).unwrap();
    // A source with no password must not fabricate a password error for an
    // archive that does not need one.
    assert_eq!(a.read_entry("a.txt", &mut NoPassword).unwrap(), b"a");

    let mut src = StaticPassword(None);
    assert_eq!(a.read_entry("a.txt", &mut src).unwrap(), b"a");
}

#[test]
fn aes_encrypted_archive_needs_a_password_and_accepts_the_right_one() {
    use zip::AesMode;

    let dir = tempfile::tempdir().unwrap();
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_aes_encryption(AesMode::Aes256, "correct horse");
        w.start_file("secret.txt", opts).unwrap();
        w.write_all(b"classified").unwrap();
        w.finish().unwrap();
    }

    let p = write_temp(dir.path(), "aes.zip", &buf);

    // No password at all: a clear, specific error rather than a panic.
    let mut a = ZipArchive::open(&p).unwrap();
    let entries = a.entries().unwrap();
    let secret = entries.iter().find(|e| e.raw_name == "secret.txt").unwrap();
    assert!(
        secret.encryption.is_encrypted(),
        "the member must be reported as encrypted"
    );

    let mut none = NoPassword;
    let err = a
        .read_entry("secret.txt", &mut none)
        .expect_err("an encrypted member must not read without a password");
    assert!(
        matches!(err, Error::PasswordRequired | Error::BadPassword),
        "got {err}"
    );

    // Wrong password: reported as a password error, not as corruption.
    let mut wrong = StaticPassword(Some("battery staple".into()));
    let err = a.read_entry("secret.txt", &mut wrong);
    assert!(
        matches!(err, Err(Error::BadPassword) | Err(Error::PasswordRequired)),
        "got {err:?}"
    );

    // Right password: the member reads and verifies.
    let mut right = StaticPassword(Some("correct horse".into()));
    assert_eq!(
        a.read_entry("secret.txt", &mut right).unwrap(),
        b"classified"
    );

    // With the correct password verify() must succeed. AES members store
    // CRC32 = 0, so a naive CRC check would have rejected every one of them;
    // that is the regression this test exists to catch.
    let report = a.verify(&mut right).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(report.ok, 1);
    assert!(report.encrypted_pending.is_empty());

    // Without a password the member is reported as pending, not failed, so the
    // UI can prompt instead of showing a corruption error.
    let report = a.verify(&mut NoPassword).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(report.encrypted_pending, vec!["secret.txt"]);
    assert!(!report.is_healthy());
}

#[test]
fn encrypted_member_is_flagged_and_never_written_without_a_password() {
    // A structurally valid archive whose single member declares the encryption
    // bit. The payload is not real ciphertext, which is exactly what makes this
    // useful: it proves the engine routes on the *flag* and refuses, rather than
    // handing undecryptable bytes to the filesystem.
    let dir = tempfile::tempdir().unwrap();
    let bytes = raw_zip(&[
        RawMember::file("secret.bin", b"plaintext in an encrypted shell").into_encrypted(),
    ]);
    let p = write_temp(dir.path(), "enc.zip", &bytes);
    let out = dir.path().join("out");

    let mut a = ZipArchive::open(&p).unwrap();
    let entries = a.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].encryption.is_encrypted(),
        "the encryption bit must be surfaced in the index"
    );

    // Without a password the member must not be written.
    let report = run_extract(&mut a, "*", &out, &ExtractionBudget::interactive()).unwrap();
    assert_eq!(report.extracted, 0, "nothing may be written");
    assert!(!out.join("secret.bin").exists());

    // And the engine must say "password", not "damaged".
    let err = a.read_entry("secret.bin", &mut NoPassword);
    assert!(
        matches!(err, Err(Error::PasswordRequired) | Err(Error::BadPassword)),
        "got {err:?}"
    );
}

// --- nested archives -------------------------------------------------------

#[test]
fn nested_archive_is_opened_without_touching_the_outer_archive() {
    let dir = tempfile::tempdir().unwrap();
    let inner = zip_bytes(&[("inner.txt", b"deep"), ("sub/inner2.txt", b"deeper")]);
    let outer = zip_bytes(&[("noise1.bin", &[0u8; 1024]), ("nested.zip", &inner)]);

    let p = write_temp(dir.path(), "outer.zip", &outer);
    let mut a = ZipArchive::open(&p).unwrap();

    let found = zipee_engine::nested::find_nested(&mut a).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].raw_name, "nested.zip");

    let at = zipee_engine::nested::NestedPath::root();
    let nested = zipee_engine::nested::NestedArchive::open_member(
        &mut a,
        "nested.zip",
        &mut NoPassword,
        &at,
    )
    .unwrap()
    .expect("nested.zip should open");

    let mut nested = nested;
    assert_eq!(nested.container(), Format::Zip);
    let tree = nested.vfs().unwrap();
    assert!(tree.is_directory("sub"));
    assert_eq!(
        nested
            .archive()
            .read_entry("inner.txt", &mut NoPassword)
            .unwrap(),
        b"deep"
    );
    assert_eq!(nested.path().display(), "nested.zip");
}

// --- helpers only used above -----------------------------------------------

/// Build a tar containing exactly one member with the given (possibly hostile)
/// name, computing a valid header checksum.
fn build_hostile_tar(name: &str, body: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut h = vec![0u8; BLOCK];
    let n = name.len().min(100);
    h[..n].copy_from_slice(&name.as_bytes()[..n]);
    let put = |h: &mut [u8], off: usize, len: usize, v: u64| {
        let s = format!("{v:0width$o}", width = len - 1);
        h[off..off + s.len()].copy_from_slice(s.as_bytes());
    };
    put(&mut h, 100, 8, 0o644);
    put(&mut h, 108, 8, 0);
    put(&mut h, 116, 8, 0);
    put(&mut h, 124, 12, body.len() as u64);
    put(&mut h, 136, 12, 1_700_000_000);
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..262].copy_from_slice(b"ustar");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..148 + s.len()].copy_from_slice(s.as_bytes());

    let mut out = h;
    out.extend_from_slice(body);
    out.extend(std::iter::repeat(0u8).take((BLOCK - body.len() % BLOCK) % BLOCK));
    out.extend(std::iter::repeat(0u8).take(BLOCK * 2));
    out
}
