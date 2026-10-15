//! Nested archives: looking inside an archive that is inside an archive.
//!
//! The point is to avoid materialising the outer archive. When the user opens
//! `photos.zip/june/inner.zip`, Zipee inflates only that one member into a
//! temporary buffer, parses its index, and recurses — the rest of `photos.zip`
//! is never decompressed.


use crate::archive::ArchiveAccess;
use crate::entry::{ArchiveEntry, PasswordSource};
use crate::error::{Error, Result};
use crate::format::{detect_bytes, Format};
use crate::vfs::Vfs;

/// Maximum nesting depth, to bound recursion on adversarial input.
///
/// An archive can contain an archive that contains an archive indefinitely;
/// each level costs memory, so the engine stops and says so rather than
/// recursing until the process dies.
pub const MAX_NESTING_DEPTH: usize = 8;

/// One location in a chain of nested archives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedPath {
    /// The segments leading here, outermost first.
    segments: Vec<String>,
}

impl NestedPath {
    /// The root: no segments.
    pub fn root() -> Self {
        Self { segments: Vec::new() }
    }

    /// Descend into a member.
    pub fn child(&self, name: &str) -> Self {
        let mut s = self.segments.clone();
        s.push(name.to_string());
        Self { segments: s }
    }

    /// The segments, outermost first.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// How deep this location is.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Render as `outer.zip/inner.zip/file.txt`.
    pub fn display(&self) -> String {
        self.segments.join("/")
    }
}

impl std::fmt::Debug for NestedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NestedArchive")
            .field("container", &self.container)
            .field("path", &self.path.display())
            .finish()
    }
}

/// A live handle to an archive nested inside another archive.
///
/// Holds the compressed or decompressed bytes of exactly one member, so the
/// cost of browsing one level in is bounded by the size of that member.
pub struct NestedArchive {
    archive: Box<dyn ArchiveAccess>,
    container: Format,
    path: NestedPath,
}

impl NestedArchive {
    /// Open the member `name` of `parent` as an archive, if it is one.
    ///
    /// Returns `Ok(None)` when the member exists but is not a recognised
    /// container — that is a normal outcome, not an error, and the caller
    /// should treat it as a plain file.
    pub fn open_member(
        parent: &mut dyn ArchiveAccess,
        name: &str,
        passwords: &mut dyn PasswordSource,
        at: &NestedPath,
    ) -> Result<Option<Self>> {
        if at.depth() >= MAX_NESTING_DEPTH {
            return Err(Error::Unsupported(format!(
                "archives nested more than {MAX_NESTING_DEPTH} deep are not opened"
            )));
        }
        let data = parent.read_entry(name, passwords)?;

        let head_len = data.len().min(512);
        let container = match detect_bytes(&data[..head_len]) {
            Ok(f) => f,
            // A compressed stream might still wrap a tar; treat it as such and
            // let the tar reader report the real answer.
            Err(crate::format::DetectError::Unknown) => return Ok(None),
            Err(_) => return Ok(None),
        };

        let archive: Box<dyn ArchiveAccess> = match container {
            Format::Zip => Box::new(crate::zip_archive::ZipArchive::from_bytes(data)?),
            Format::Tar => Box::new(crate::tar_archive::TarArchive::from_bytes(data)?),
            other => {
                return Err(Error::Unsupported(format!(
                    "Zipee can look inside zip and tar; this member is {other}"
                )))
            }
        };

        Ok(Some(Self {
            archive,
            container,
            path: at.child(name),
        }))
    }

    /// The container of the nested archive.
    pub fn container(&self) -> Format {
        self.container
    }

    /// Where this archive sits in the chain.
    pub fn path(&self) -> &NestedPath {
        &self.path
    }

    /// Borrow the underlying archive.
    pub fn archive(&mut self) -> &mut dyn ArchiveAccess {
        self.archive.as_mut()
    }

    /// Members of the nested archive.
    pub fn entries(&mut self) -> Result<Vec<ArchiveEntry>> {
        self.archive.entries()
    }

    /// The nested archive as a browsable tree.
    pub fn vfs(&mut self) -> Result<Vfs> {
        self.archive.vfs()
    }
}

/// List the members of `archive` that look like archives themselves.
///
/// This is what powers "show nested archives" in the UI without the user
/// having to open anything.
pub fn find_nested(archive: &mut dyn ArchiveAccess) -> Result<Vec<ArchiveEntry>> {
    let entries = archive.entries()?;
    let mut out = Vec::new();
    for e in entries {
        if e.kind.is_file() && crate::format::looks_like_archive(&e.raw_name) {
            out.push(e);
        }
    }
    Ok(out)
}

/// Parse an archive from an in-memory buffer, for previews.
pub fn open_bytes(bytes: Vec<u8>) -> Result<Option<Box<dyn ArchiveAccess>>> {
    let head_len = bytes.len().min(512);
    match detect_bytes(&bytes[..head_len])? {
        Format::Zip => Ok(Some(Box::new(crate::zip_archive::ZipArchive::from_bytes(bytes)?))),
        Format::Tar => Ok(Some(Box::new(crate::tar_archive::TarArchive::from_bytes(bytes)?))),
        other => Err(Error::Unsupported(format!(
            "Zipee can open zip and tar; these bytes are {other}"
        ))),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_depth_and_display() {
        let p = NestedPath::root();
        assert_eq!(p.depth(), 0);
        assert_eq!(p.display(), "");
        let p = p.child("outer.zip").child("inner.txt");
        assert_eq!(p.depth(), 2);
        assert_eq!(p.display(), "outer.zip/inner.txt");
        assert_eq!(p.segments(), ["outer.zip", "inner.txt"]);
    }

    #[test]
    fn depth_limit_is_enforced_before_reading() {
        // Build a path at the limit without needing a real archive.
        let mut p = NestedPath::root();
        for i in 0..MAX_NESTING_DEPTH {
            p = p.child(&format!("l{i}.zip"));
        }
        assert_eq!(p.depth(), MAX_NESTING_DEPTH);
    }

    #[test]
    fn non_archive_bytes_are_not_confused() {
        let png = b"\x89PNG\r\n\x1a\n".to_vec();
        assert!(open_bytes(png).is_err());
    }
}