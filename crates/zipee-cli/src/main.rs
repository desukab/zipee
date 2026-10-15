//! `zipee` — the command-line face of the archive engine.
//!
//! The CLI exists because it is the cheapest honest way to exercise the
//! engine: every feature the app has is reachable here, the exit codes are
//! stable, and a shell script can verify an archive without a GUI. It is also
//! what CI runs, so a regression shows up as a failing build rather than a
//! screenshot.
//!
//! Exit codes are part of the contract — see [`exit_code`].

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use zipee_engine::archive::MemberEdit;
use zipee_engine::entry::{human_bytes, NoPassword, PasswordSource, StaticPassword};
use zipee_engine::error::Error;
use zipee_engine::extract::{extract, CancelToken, MemberOutcome, Selection};
use zipee_engine::security::ExtractionBudget;
use zipee_engine::{open_any, ArchiveAccess, Node};

/// Browse, inspect, extract and edit archives without unpacking everything.
#[derive(Parser, Debug)]
#[command(name = "zipee", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Identify a file's container without opening it.
    Info {
        /// The archive to inspect.
        archive: PathBuf,
    },

    /// List members. Never decompresses anything.
    List {
        /// The archive to list.
        archive: PathBuf,

        /// Print the browsable tree instead of a flat list.
        #[arg(long)]
        tree: bool,

        /// List a subtree, e.g. `photos/june`.
        #[arg(long, default_value = "")]
        path: String,

        /// Show only entries matching this substring.
        #[arg(long)]
        filter: Option<String>,
    },

    /// Show detailed metadata for one member.
    Stat {
        /// The archive.
        archive: PathBuf,

        /// The member to describe.
        entry: String,
    },

    /// Read one member and write it to stdout or a file.
    Cat {
        /// The archive.
        archive: PathBuf,

        /// The member to read.
        entry: String,

        /// Write to this file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Verify every member's checksum.
    Verify {
        /// The archive to check.
        archive: PathBuf,

        /// Password, for encrypted members.
        #[arg(long, short)]
        password: Option<String>,
    },

    /// Extract members to a directory.
    Extract {
        /// The archive.
        archive: PathBuf,

        /// Where to extract. Defaults to the current directory.
        #[arg(long, short, default_value = ".")]
        destination: PathBuf,

        /// What to extract: a member, a folder (trailing `/`), or `*` for all.
        #[arg(default_value = "*")]
        selection: String,

        /// Refuse to expand any member beyond this ratio.
        #[arg(long, default_value_t = 1000)]
        max_ratio: u64,

        /// Refuse to write more than this many bytes in total.
        #[arg(long, default_value_t = 8_589_934_592)]
        max_bytes: u64,

        /// Show a line per member as it is written.
        #[arg(long, short)]
        verbose: bool,
    },

    /// Create a new ZIP archive from files on disk.
    Create {
        /// The archive to create. Refuses to overwrite an existing file.
        archive: PathBuf,

        /// Files and folders to add.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },

    /// Edit an existing ZIP archive, writing a new file.
    Edit {
        /// The archive to edit. It is never modified in place.
        archive: PathBuf,

        /// Where to write the edited archive.
        #[arg(long, short)]
        output: PathBuf,

        /// Replace a member's contents.
        #[arg(long, value_name = "NAME=FILE")]
        replace: Vec<String>,

        /// Delete a member.
        #[arg(long, value_name = "NAME")]
        delete: Vec<String>,

        /// Rename a member.
        #[arg(long, value_name = "OLD=NEW")]
        rename: Vec<String>,
    },
}

/// Map an error to a stable exit code.
///
/// Scripts branch on these, so they are part of the public interface:
/// `0` success, `1` usage error, `2` I/O, `3` corrupt, `4` needs a password,
/// `5` refused for safety, `6` unsupported, `7` budget exceeded, `8` cancelled.
fn exit_code(e: &Error) -> u8 {
    match e {
        Error::Cancelled => 8,
        // The filesystem adapter reuses the engine's taxonomy, so a mount-side
        // refusal gets the same exit code as an extraction-side one.
        Error::Fs(f) => match f {
            zipee_engine::FsError::Escapes { .. } => 5,
            zipee_engine::FsError::PasswordRequired { .. }
            | zipee_engine::FsError::BadPassword { .. } => 4,
            zipee_engine::FsError::Corrupt { .. } => 3,
            zipee_engine::FsError::NotFound { .. } => 2,
            zipee_engine::FsError::Cancelled => 8,
            zipee_engine::FsError::Refused { .. } => 7,
            _ => 2,
        },
        Error::Budget(_) => 7,
        Error::Unsupported(_) | Error::UnsupportedEncryption { .. } => 6,
        Error::UnsafePath(_) => 5,
        Error::PasswordRequired | Error::BadPassword => 4,
        Error::Corrupt(_) => 3,
        Error::Io { .. } | Error::Detect(_) | Error::NoSuchEntry(_) => 2,
        Error::ExternalModification | Error::InPlaceWriteRefused => 1,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zipee: {e}");
            ExitCode::from(exit_code(&e))
        }
    }
}

fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Command::Info { archive } => cmd_info(&archive),
        Command::List {
            archive,
            tree,
            path,
            filter,
        } => cmd_list(&archive, tree, &path, filter.as_deref()),
        Command::Stat { archive, entry } => cmd_stat(&archive, &entry),
        Command::Cat {
            archive,
            entry,
            output,
        } => cmd_cat(&archive, &entry, output.as_deref()),
        Command::Verify { archive, password } => cmd_verify(&archive, password.as_deref()),
        Command::Extract {
            archive,
            destination,
            selection,
            max_ratio,
            max_bytes,
            verbose,
        } => cmd_extract(
            &archive,
            &destination,
            &selection,
            max_ratio,
            max_bytes,
            verbose,
        ),
        Command::Create { archive, inputs } => cmd_create(&archive, &inputs),
        Command::Edit {
            archive,
            output,
            replace,
            delete,
            rename,
        } => cmd_edit(&archive, &output, &replace, &delete, &rename),
    }
}

fn cmd_info(archive: &Path) -> Result<(), Error> {
    let format = zipee_engine::identify(archive)?;
    println!("file:      {}", archive.display());
    println!("format:    {format}");
    println!(
        "writable:  {}",
        if format.supports_writing() {
            "yes"
        } else {
            "no"
        }
    );
    println!("size:      {}", human_bytes(fs_size(archive)));

    let mut a = open_any(archive)?;
    let s = a.stats()?;
    println!("entries:   {}", s.total_entries);
    println!("files:     {}", s.files);
    println!("folders:   {}", s.directories);
    println!(
        "encrypted: {}",
        if s.encrypted_entries > 0 { "yes" } else { "no" }
    );
    if s.unsafe_entries > 0 {
        println!(
            "unsafe:    {} member(s) were refused for unsafe paths",
            s.unsafe_entries
        );
    }
    println!(
        "unpacked:  {} ({}% of original)",
        s.human_uncompressed(),
        s.ratio_percent()
    );
    Ok(())
}

fn cmd_list(archive: &Path, tree: bool, path: &str, filter: Option<&str>) -> Result<(), Error> {
    let mut a = open_any(archive)?;
    let vfs = a.vfs()?;

    if let Some(rejected) = vfs.rejected().first() {
        eprintln!(
            "note: {} member(s) skipped for unsafe paths (e.g. {:?}: {})",
            vfs.rejected().len(),
            rejected.0,
            rejected.1
        );
    }

    if tree {
        // The tree view always starts at the archive root; `path` selects a
        // subtree to print in full.
        let lines = if path.is_empty() {
            vfs.tree_lines()
        } else {
            let Some(node) = vfs.resolve(path) else {
                return Err(Error::NoSuchEntry(path.to_string()));
            };
            if node.kind != zipee_engine::EntryKind::Directory {
                vec![format!("{}/", node.name)]
            } else {
                let mut out = vec![format!("{}/", node.name)];
                out.extend(vfs.tree_lines_in(node.path.as_str()));
                out
            }
        };
        for l in lines {
            println!("{l}");
        }
        return Ok(());
    }

    let start = if path.is_empty() { "" } else { path };
    let mut count = 0;
    for node in vfs.subtree_nodes(start) {
        if let Some(f) = filter {
            if !node.name.to_lowercase().contains(&f.to_lowercase())
                && !node.path.to_lowercase().contains(&f.to_lowercase())
            {
                continue;
            }
        }
        print_node(node);
        count += 1;
    }
    if count == 0 && filter.is_some() {
        eprintln!("zipee: no entries matched {filter:?}");
    }
    Ok(())
}

fn print_node(node: &Node) {
    let tag = match node.kind {
        zipee_engine::EntryKind::Directory => "/",
        zipee_engine::EntryKind::Symlink => " ->",
        zipee_engine::EntryKind::Special => " (special)",
        zipee_engine::EntryKind::File => "",
    };
    let lock = if node.encrypted { " [encrypted]" } else { "" };
    let imp = if node.implicit { " (implied)" } else { "" };
    println!(
        "{:>12}  {:>12}  {}{}{}{}",
        human_bytes(node.size),
        if node.kind == zipee_engine::EntryKind::Directory {
            String::new()
        } else {
            format!("{}b", node.compressed_size)
        },
        node.path,
        tag,
        lock,
        imp
    );
}

fn cmd_stat(archive: &Path, entry: &str) -> Result<(), Error> {
    let mut a = open_any(archive)?;
    let entries = a.entries()?;
    let Some(found) = entries
        .iter()
        .find(|e| e.raw_name == entry || e.key() == entry)
    else {
        return Err(Error::NoSuchEntry(entry.to_string()));
    };

    println!("name:            {}", found.raw_name);
    println!("kind:            {:?}", found.kind);
    println!("size:            {}", human_bytes(found.uncompressed_size));
    println!("compressed:      {} bytes", found.compressed_size);
    println!(
        "ratio:           {}",
        found
            .ratio_percent()
            .map(|r| format!("{r}%"))
            .unwrap_or_else(|| "n/a".into())
    );
    println!("compression:     {:?}", found.compression);
    println!("encryption:      {:?}", found.encryption);
    println!(
        "modified:        {:?}",
        found
            .modified
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
    );
    println!(
        "unix mode:       {}",
        found
            .unix_mode
            .map(|m| format!("{m:o}"))
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "crc32:           {}",
        found
            .crc32
            .map(|c| format!("{c:08x}"))
            .unwrap_or_else(|| "-".into())
    );
    match &found.path {
        Some(p) => println!("safe path:       {}", p.as_key()),
        None => println!(
            "safe path:       REFUSED ({})",
            found
                .path_violation
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unsafe".into())
        ),
    }
    Ok(())
}

fn cmd_cat(archive: &Path, entry: &str, output: Option<&Path>) -> Result<(), Error> {
    use std::io::Write;
    let mut a = open_any(archive)?;
    let data = a.read_entry(entry, &mut NoPassword)?;
    match output {
        Some(p) => {
            std::fs::write(p, &data)
                .map_err(|e| Error::io(format!("writing {}", p.display()), e))?;
            eprintln!("wrote {} ({})", p.display(), human_bytes(data.len() as u64));
        }
        None => {
            std::io::stdout()
                .write_all(&data)
                .map_err(|e| Error::io("writing to stdout", e))?;
        }
    }
    Ok(())
}

fn cmd_verify(archive: &Path, password: Option<&str>) -> Result<(), Error> {
    let mut passwords: Box<dyn PasswordSource> = match password {
        Some(p) => Box::new(StaticPassword(Some(zipee_engine::Secret::new(p)))),
        None => Box::new(NoPassword),
    };
    let mut a = open_any(archive)?;
    let report = a.verify(&mut passwords)?;

    println!("checked:  {} member(s)", report.total);
    println!("ok:       {}", report.ok);
    println!(
        "failed:   {}{}",
        report.failed.len(),
        if report.failed.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                report
                    .failed
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    println!(
        "skipped:  {} (encrypted, no password)",
        report.encrypted_pending.len()
    );
    println!("unsafe:   {}", report.unsafe_entries.len());

    if !report.failed.is_empty() || !report.unsafe_entries.is_empty() {
        return Err(Error::Corrupt(format!(
            "{} member(s) failed verification",
            report.failed.len() + report.unsafe_entries.len()
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_extract(
    archive: &Path,
    destination: &Path,
    selection: &str,
    max_ratio: u64,
    max_bytes: u64,
    verbose: bool,
) -> Result<(), Error> {
    let selection = Selection::parse(selection)?;
    let budget = ExtractionBudget {
        max_total_bytes: max_bytes,
        max_compression_ratio: max_ratio,
        ..ExtractionBudget::interactive()
    };

    let mut a = open_any(archive)?;
    let mut seen = 0usize;
    let report = extract(
        a.as_mut(),
        &selection,
        destination,
        &budget,
        &mut NoPassword,
        &CancelToken::new(),
        &mut |p| {
            seen += 1;
            if verbose {
                eprintln!("[{seen}/{}] {}", p.total, p.current);
            } else if seen % 500 == 0 {
                eprintln!("  ... {}/{} members", p.done, p.total);
            }
        },
    )?;

    println!(
        "extracted {} member(s), {}",
        report.extracted,
        human_bytes(report.bytes_written)
    );
    for o in &report.outcomes {
        if let MemberOutcome::Rejected { path, reason } = o {
            eprintln!("refused: {path} ({reason})");
        }
    }
    for o in &report.outcomes {
        if let MemberOutcome::Failed { path, reason } = o {
            eprintln!("failed:  {path} ({reason})");
        }
    }
    println!("into: {}", destination.display());

    if report.failed > 0 {
        return Err(Error::Corrupt(format!(
            "{} member(s) could not be extracted",
            report.failed
        )));
    }
    Ok(())
}

fn cmd_create(archive: &Path, inputs: &[PathBuf]) -> Result<(), Error> {
    if archive.exists() {
        return Err(Error::io(
            format!("refusing to overwrite {}", archive.display()),
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file exists"),
        ));
    }

    let mut members: Vec<(zipee_engine::SafeMemberPath, Vec<u8>)> = Vec::new();
    for input in inputs {
        collect(input, input, &mut members)?;
    }
    if members.is_empty() {
        return Err(Error::Unsupported("nothing to add".into()));
    }

    zipee_engine::zip_archive::create_zip(archive, &members, ExtractionBudget::interactive())?;

    let total: u64 = members.iter().map(|(_, d)| d.len() as u64).sum();
    println!(
        "created {} with {} member(s), {} unpacked",
        archive.display(),
        members.len(),
        human_bytes(total)
    );
    Ok(())
}

/// Walk a file or folder, appending every regular file as a member.
///
/// The member name is relative to the folder that was named on the command
/// line, so `zipee create out.zip photos` produces `photos/...` members rather
/// than an absolute path.
fn collect(
    root: &Path,
    current: &Path,
    out: &mut Vec<(zipee_engine::SafeMemberPath, Vec<u8>)>,
) -> Result<(), Error> {
    if current.is_file() {
        let rel = current.strip_prefix(root).unwrap_or(current);
        let name = if root.is_dir() {
            root.file_name()
                .map(|n| format!("{}/{}", n.to_string_lossy(), rel.to_string_lossy()))
                .unwrap_or_else(|| rel.to_string_lossy().into_owned())
        } else {
            current
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| rel.to_string_lossy().into_owned())
        };
        let safe = zipee_engine::sanitize_member_path(&name)
            .map_err(|e| Error::io("unsafe input path", std::io::Error::other(e.to_string())))?;
        let data = std::fs::read(current)
            .map_err(|e| Error::io(format!("reading {}", current.display()), e))?;
        out.push((safe, data));
        return Ok(());
    }
    if !current.is_dir() {
        return Err(Error::io(
            format!("no such file: {}", current.display()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        ));
    }
    let mut children: Vec<PathBuf> = std::fs::read_dir(current)
        .map_err(|e| Error::io(format!("listing {}", current.display()), e))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    children.sort();
    for c in children {
        collect(root, &c, out)?;
    }
    Ok(())
}

fn cmd_edit(
    archive: &Path,
    output: &Path,
    replace: &[String],
    delete: &[String],
    rename: &[String],
) -> Result<(), Error> {
    let mut edits: Vec<MemberEdit> = Vec::new();

    for spec in replace {
        let (name, file) = spec.split_once('=').ok_or_else(|| {
            Error::Unsupported(format!("--replace wants NAME=FILE, got {spec:?}"))
        })?;
        let data = std::fs::read(file).map_err(|e| Error::io(format!("reading {file}"), e))?;
        edits.push(MemberEdit::Replace {
            name: name.to_string(),
            data,
        });
    }
    for name in delete {
        edits.push(MemberEdit::Delete { name: name.clone() });
    }
    for spec in rename {
        let (from, to) = spec
            .split_once('=')
            .ok_or_else(|| Error::Unsupported(format!("--rename wants OLD=NEW, got {spec:?}")))?;
        let safe = zipee_engine::sanitize_member_path(to)?;
        edits.push(MemberEdit::Rename {
            from: from.to_string(),
            to: safe,
        });
    }

    if edits.is_empty() {
        return Err(Error::Unsupported(
            "nothing to change: pass --replace, --delete or --rename".into(),
        ));
    }

    // The engine refuses in-place writes, which is exactly what we want here:
    // `--output` is mandatory and the source is never touched.
    let mut a = open_any(archive)?;
    let Some(zip) = a
        .as_any_mut()
        .downcast_mut::<zipee_engine::zip_archive::ZipArchive>()
    else {
        return Err(Error::Unsupported(format!(
            "editing is only supported for zip archives; this is {}",
            a.format()
        )));
    };

    let report = zipee_engine::writeback::rewrite_zip(
        zip,
        archive,
        output,
        &edits,
        &ExtractionBudget::interactive(),
    )?;

    println!("wrote {}", output.display());
    println!("  added:   {}", report.added.len());
    println!("  replaced: {}", report.replaced.len());
    println!("  deleted: {}", report.deleted.len());
    println!("  renamed: {}", report.renamed.len());
    println!("  untouched: {}", report.unchanged);
    Ok(())
}

fn fs_size(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}
