//! A stable C ABI for the macOS app.
//!
//! Swift cannot call Rust directly, so this module is the entire native
//! surface the app sees. Three rules govern it:
//!
//! 1. **Nothing panics across the boundary.** Every entry point wraps its body
//!    in [`catch_unwind`] and reports failure through the return value.
//! 2. **No Rust types cross the boundary.** Only integers, raw byte buffers
//!    and NUL-terminated strings. Ownership is explicit.
//! 3. **Every allocation has a matching free.** Strings returned here are
//!    released with [`zipee_string_free`]; buffers with [`zipee_bytes_free`].
//!
//! A panic unwinding into Swift would abort the process, so point 1 is a
//! correctness requirement rather than a nicety.

// FFI structs are plain data carriers for the C ABI; a `Debug` impl would
// invite a caller to log a password or a raw byte buffer.
#![allow(missing_debug_implementations)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::entry::NoPassword;
use crate::extract::{CancelToken, Selection};
use crate::security::ExtractionBudget;

/// Opaque handle to an open archive.
pub struct ZipeeArchive {
    inner: Box<dyn crate::archive::ArchiveAccess>,
}

/// An owned byte buffer handed to the caller.
///
/// The pointer and length together describe the allocation; release it with
/// [`zipee_bytes_free`] and never with `free()`.
#[repr(C)]
pub struct ZipeeBytes {
    /// Start of the allocation.
    pub data: *mut u8,
    /// Length in bytes.
    pub len: usize,
    /// Always 0. Lets Swift keep the struct as a value type.
    pub capacity: usize,
}

impl ZipeeBytes {
    /// Hand the `Vec`'s allocation to the caller.
    ///
    /// `ManuallyDrop` *forgets* the vector, so the allocation is not freed when
    /// this function returns; [`zipee_bytes_free`] gives it back exactly once.
    /// Letting the `Vec` drop here would be a double free; `into_raw_parts`
    /// would work but needs Rust 1.93, above the engine's declared MSRV.
    fn from_vec(v: Vec<u8>) -> Self {
        let mut v = std::mem::ManuallyDrop::new(v);
        Self {
            data: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        }
    }

    fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }
}

/// An archive summary, flattened so Swift can decode it without a parser.
#[repr(C)]
pub struct ZipeeStats {
    /// Total members.
    pub total_entries: u64,
    /// Regular files.
    pub files: u64,
    /// Directories.
    pub directories: u64,
    /// Members rejected for unsafe paths.
    pub unsafe_entries: u64,
    /// Encrypted members.
    pub encrypted_entries: u64,
    /// Sum of uncompressed sizes.
    pub uncompressed_bytes: u64,
    /// Sum of compressed sizes.
    pub compressed_bytes: u64,
}

/// One member, flattened for Swift.
#[repr(C)]
pub struct ZipeeEntry {
    /// Owned NUL-terminated UTF-8 name. Free with [`zipee_string_free`].
    pub name: *mut c_char,
    /// 0 = file, 1 = directory, 2 = symlink, 3 = special.
    pub kind: i32,
    /// 1 when the name was rejected by the path-safety rules.
    pub is_unsafe: i32,
    /// 1 when the member needs a password.
    pub is_encrypted: i32,
    /// Size once decompressed.
    pub uncompressed_size: u64,
    /// Size as stored.
    pub compressed_size: u64,
    /// Unix mode, or 0 when the container records none.
    pub unix_mode: u32,
    /// Seconds since the Unix epoch, or 0 when unknown.
    pub modified: u64,
}

/// Open an archive.
///
/// Returns null on failure. `error_out`, when non-null, receives an owned
/// message the caller must free with [`zipee_string_free`].
#[no_mangle]
/// # Safety
/// `path` must be a valid NUL-terminated C string or null, and `error_out`
/// must be null or point to writable storage for one pointer.
pub unsafe extern "C" fn zipee_open(
    path: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut ZipeeArchive {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(path) = (unsafe { cstr(path) }) else {
            unsafe { set_error(error_out, "path is not valid UTF-8") };
            return std::ptr::null_mut();
        };
        match crate::open_any(std::path::Path::new(&path)) {
            Ok(a) => Box::into_raw(Box::new(ZipeeArchive { inner: a })),
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                std::ptr::null_mut()
            }
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Close an archive. Safe to call with null.
#[no_mangle]
/// # Safety
/// `handle` must be null, or a pointer returned by [`zipee_open`] that has not
/// already been closed. Closing twice is a double free.
pub unsafe extern "C" fn zipee_close(handle: *mut ZipeeArchive) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(unsafe { Box::from_raw(handle) });
    }));
}

/// Read the archive's summary statistics.
#[no_mangle]
/// # Safety
/// `handle` must be a live archive handle and `error_out` null or writable.
pub unsafe extern "C" fn zipee_stats(
    handle: *mut ZipeeArchive,
    error_out: *mut *mut c_char,
) -> ZipeeStats {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(a) = (unsafe { archive_mut(handle) }) else {
            return ZipeeStats {
                total_entries: 0,
                files: 0,
                directories: 0,
                unsafe_entries: 0,
                encrypted_entries: 0,
                uncompressed_bytes: 0,
                compressed_bytes: 0,
            };
        };
        match a.inner.stats() {
            Ok(s) => ZipeeStats {
                total_entries: s.total_entries,
                files: s.files,
                directories: s.directories,
                unsafe_entries: s.unsafe_entries,
                encrypted_entries: s.encrypted_entries,
                uncompressed_bytes: s.uncompressed_bytes,
                compressed_bytes: s.compressed_bytes,
            },
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                ZipeeStats {
                    total_entries: 0,
                    files: 0,
                    directories: 0,
                    unsafe_entries: 0,
                    encrypted_entries: 0,
                    uncompressed_bytes: 0,
                    compressed_bytes: 0,
                }
            }
        }
    }))
    .unwrap_or(ZipeeStats {
        total_entries: 0,
        files: 0,
        directories: 0,
        unsafe_entries: 0,
        encrypted_entries: 0,
        uncompressed_bytes: 0,
        compressed_bytes: 0,
    })
}

/// List every member.
///
/// `*count` receives the number of entries written into `out`. The caller owns
/// the returned array and each name in it.
#[no_mangle]
/// # Safety
/// `handle` must be live; `out` must have room for `capacity` elements and
/// `count_out` must be writable.
pub unsafe extern "C" fn zipee_entries(
    handle: *mut ZipeeArchive,
    out: *mut ZipeeEntry,
    capacity: usize,
    count_out: *mut usize,
    error_out: *mut *mut c_char,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(a) = (unsafe { archive_mut(handle) }) else {
            return -1;
        };
        let entries = match a.inner.entries() {
            Ok(e) => e,
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                return -1;
            }
        };
        let n = entries.len().min(capacity);
        for (i, e) in entries.iter().take(n).enumerate() {
            unsafe {
                (*out.add(i)) = ZipeeEntry {
                    name: to_c_string(&e.raw_name),
                    kind: match e.kind {
                        crate::entry::EntryKind::File => 0,
                        crate::entry::EntryKind::Directory => 1,
                        crate::entry::EntryKind::Symlink => 2,
                        crate::entry::EntryKind::Special => 3,
                    },
                    is_unsafe: i32::from(e.is_unsafe()),
                    is_encrypted: i32::from(e.encryption.is_encrypted()),
                    uncompressed_size: e.uncompressed_size,
                    compressed_size: e.compressed_size,
                    unix_mode: e.unix_mode.unwrap_or(0),
                    modified: e
                        .modified
                        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                };
            }
        }
        unsafe { *count_out = n };
        0
    }))
    .unwrap_or(-1)
}

/// Read one member's bytes.
///
/// The caller owns the returned buffer and frees it with [`zipee_bytes_free`].
#[no_mangle]
/// # Safety
/// `name` must be a valid C string. The returned buffer is owned by the
/// caller and must be released with [`zipee_bytes_free`].
pub unsafe extern "C" fn zipee_read_entry(
    handle: *mut ZipeeArchive,
    name: *const c_char,
    error_out: *mut *mut c_char,
) -> ZipeeBytes {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(name) = (unsafe { cstr(name) }) else {
            unsafe { set_error(error_out, "name is not valid UTF-8") };
            return ZipeeBytes::empty();
        };
        let Some(a) = (unsafe { archive_mut(handle) }) else {
            unsafe { set_error(error_out, "archive handle is null") };
            return ZipeeBytes::empty();
        };
        match a.inner.read_entry(&name, &mut NoPassword) {
            Ok(bytes) => ZipeeBytes::from_vec(bytes),
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                ZipeeBytes::empty()
            }
        }
    }))
    .unwrap_or(ZipeeBytes::empty())
}

/// Extract members into a directory.
///
/// Returns 0 on success and a negative value on failure. `report_json`, when
/// non-null, receives an owned JSON summary the caller must free.
#[no_mangle]
/// # Safety
/// `spec` and `destination` must be valid C strings; `report_json` must be
/// null or writable.
pub unsafe extern "C" fn zipee_extract(
    handle: *mut ZipeeArchive,
    spec: *const c_char,
    destination: *const c_char,
    max_total_bytes: u64,
    report_json: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(spec) = (unsafe { cstr(spec) }) else {
            unsafe { set_error(error_out, "selection is not valid UTF-8") };
            return -1;
        };
        let Some(dest) = (unsafe { cstr(destination) }) else {
            unsafe { set_error(error_out, "destination is not valid UTF-8") };
            return -1;
        };
        let Some(a) = (unsafe { archive_mut(handle) }) else {
            unsafe { set_error(error_out, "archive handle is null") };
            return -1;
        };
        let selection = match Selection::parse(&spec) {
            Ok(s) => s,
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                return -1;
            }
        };
        let budget = ExtractionBudget {
            max_total_bytes,
            ..ExtractionBudget::default()
        };
        match crate::extract(
            a.inner.as_mut(),
            &selection,
            std::path::Path::new(&dest),
            &budget,
            &mut NoPassword,
            &CancelToken::new(),
            &mut |_| {},
        ) {
            Ok(report) => {
                let json = serde_json_minimal(&report);
                unsafe { *report_json = to_c_string(&json) };
                0
            }
            Err(e) => {
                unsafe { set_error(error_out, &e.to_string()) };
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

/// Free a buffer returned by [`zipee_read_entry`].
#[no_mangle]
/// # Safety
/// `bytes` must be a value returned by [`zipee_read_entry`] that has not
/// already been freed.
pub unsafe extern "C" fn zipee_bytes_free(bytes: ZipeeBytes) {
    if bytes.data.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(unsafe { Vec::from_raw_parts(bytes.data, bytes.len, bytes.capacity) });
    }));
}

/// Free a string returned by any `zipee_*` function.
#[no_mangle]
/// # Safety
/// `s` must be null or a pointer returned by this module that has not already
/// been freed.
pub unsafe extern "C" fn zipee_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(unsafe { CString::from_raw(s) });
    }));
}

/// The engine's version string, for the About box and for bug reports.
#[no_mangle]
pub extern "C" fn zipee_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION"))
}

// --- helpers ---------------------------------------------------------------

/// Borrow a C string as UTF-8, or `None` for null or non-UTF-8 input.
unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

/// Borrow an archive handle.
unsafe fn archive_mut<'a>(p: *mut ZipeeArchive) -> Option<&'a mut ZipeeArchive> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &mut *p })
    }
}

/// Move a Rust string into a NUL-terminated C string.
fn to_c_string(s: &str) -> *mut c_char {
    // Interior NULs would truncate silently; strip them so the caller always
    // gets the whole value rather than a prefix.
    let cleaned: String = s.chars().filter(|c| *c != '\0').collect();
    CString::new(cleaned)
        .unwrap_or_else(|_| CString::new("").expect("empty string is always valid"))
        .into_raw()
}

/// Write an error message through the out-parameter, if the caller wants one.
unsafe fn set_error(error_out: *mut *mut c_char, message: &str) {
    if !error_out.is_null() {
        unsafe { *error_out = to_c_string(message) };
    }
}

/// A minimal JSON encoder, so the FFI does not drag in a dependency.
///
/// Only what the extraction report needs: a flat object of integers and an
/// array of strings.
fn serde_json_minimal(report: &crate::extract::ExtractReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(256);
    s.push('{');
    let _ = write!(
        s,
        "\"extracted\":{},\"bytes_written\":{},\"rejected\":{},\"failed\":{}",
        report.extracted, report.bytes_written, report.rejected, report.failed
    );
    s.push_str(",\"reasons\":[");
    for (i, o) in report.outcomes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let reason = match o {
            crate::extract::MemberOutcome::Rejected { path, reason } => {
                format!("{path}: {reason}")
            }
            crate::extract::MemberOutcome::Failed { path, reason } => {
                format!("{path}: {reason}")
            }
            _ => continue,
        };
        let _ = write!(s, "\"{}\"", reason.replace('"', "'"));
    }
    s.push_str("]}");
    s
}

#[cfg(test)]
mod tests {
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
    fn open_read_and_close_across_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(&p, &[("one.txt", b"hello")]);

        let c_path = CString::new(p.to_str().unwrap()).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe { zipee_open(c_path.as_ptr(), &mut err) };
        assert!(!handle.is_null());
        assert!(err.is_null());

        let stats = unsafe { zipee_stats(handle, &mut err) };
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.uncompressed_bytes, 5);

        let name = CString::new("one.txt").unwrap();
        let bytes = unsafe { zipee_read_entry(handle, name.as_ptr(), &mut err) };
        assert!(!bytes.data.is_null());
        assert_eq!(bytes.len, 5);
        unsafe { zipee_bytes_free(bytes) };

        unsafe { zipee_close(handle) };
    }

    #[test]
    fn listing_across_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(&p, &[("a.txt", b"a"), ("d/b.txt", b"bb")]);

        let c_path = CString::new(p.to_str().unwrap()).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe { zipee_open(c_path.as_ptr(), &mut err) };
        assert!(!handle.is_null());

        let mut storage: [ZipeeEntry; 8] = core::array::from_fn(|_| ZipeeEntry {
            name: std::ptr::null_mut(),
            kind: 0,
            is_unsafe: 0,
            is_encrypted: 0,
            uncompressed_size: 0,
            compressed_size: 0,
            unix_mode: 0,
            modified: 0,
        });
        let mut n = 0usize;
        let rc = unsafe { zipee_entries(handle, storage.as_mut_ptr(), 8, &mut n, &mut err) };
        assert_eq!(rc, 0);
        assert_eq!(n, 2);
        for slot in storage.iter_mut().take(n) {
            unsafe { zipee_string_free(slot.name) };
            slot.name = std::ptr::null_mut();
        }
        unsafe { zipee_close(handle) };
    }

    #[test]
    fn null_and_bad_inputs_are_rejected_without_panicking() {
        let mut err: *mut c_char = std::ptr::null_mut();
        assert!(unsafe { zipee_open(std::ptr::null(), &mut err) }.is_null());
        assert!(!err.is_null());
        unsafe { zipee_string_free(err) };

        err = std::ptr::null_mut();
        let bytes = unsafe { zipee_read_entry(std::ptr::null_mut(), std::ptr::null(), &mut err) };
        assert!(bytes.data.is_null());

        // closing null is a no-op, not a crash
        unsafe { zipee_close(std::ptr::null_mut()) };
        unsafe { zipee_bytes_free(ZipeeBytes::empty()) };
        unsafe { zipee_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn extract_across_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(&p, &[("a.txt", b"alpha"), ("sub/b.txt", b"beta")]);
        let out = dir.path().join("out");

        let c_path = CString::new(p.to_str().unwrap()).unwrap();
        let c_spec = CString::new("sub/").unwrap();
        let c_dest = CString::new(out.to_str().unwrap()).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let mut report: *mut c_char = std::ptr::null_mut();

        let handle = unsafe { zipee_open(c_path.as_ptr(), &mut err) };
        assert!(!handle.is_null());

        let rc = unsafe {
            zipee_extract(
                handle,
                c_spec.as_ptr(),
                c_dest.as_ptr(),
                u64::MAX,
                &mut report,
                &mut err,
            )
        };
        assert_eq!(rc, 0);
        assert!(!report.is_null());
        let json = unsafe { CStr::from_ptr(report) }.to_str().unwrap();
        assert!(json.contains("\"extracted\":1"), "got {json}");
        unsafe { zipee_string_free(report) };

        assert_eq!(std::fs::read(out.join("sub/b.txt")).unwrap(), b"beta");
        assert!(
            !out.join("a.txt").exists(),
            "selection must not over-extract"
        );

        unsafe { zipee_close(handle) };
    }

    #[test]
    fn traversal_is_refused_through_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.zip");
        make_zip(&p, &[("a.txt", b"x")]);
        let out = dir.path().join("out");

        let c_path = CString::new(p.to_str().unwrap()).unwrap();
        let c_spec = CString::new("../../etc/passwd").unwrap();
        let c_dest = CString::new(out.to_str().unwrap()).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let mut report: *mut c_char = std::ptr::null_mut();
        let handle = unsafe { zipee_open(c_path.as_ptr(), &mut err) };

        let rc = unsafe {
            zipee_extract(
                handle,
                c_spec.as_ptr(),
                c_dest.as_ptr(),
                u64::MAX,
                &mut report,
                &mut err,
            )
        };
        assert_eq!(rc, -1);
        unsafe { zipee_string_free(err) };
        unsafe { zipee_close(handle) };
    }

    #[test]
    fn interior_nul_is_stripped_not_truncated_silently() {
        let p = to_c_string("a\0b");
        assert_eq!(unsafe { CStr::from_ptr(p) }.to_str().unwrap(), "ab");
        unsafe { zipee_string_free(p) };
    }

    #[test]
    fn version_is_readable() {
        let v = zipee_version();
        assert!(!v.is_null());
        let s = unsafe { CStr::from_ptr(v) }.to_str().unwrap();
        assert!(!s.is_empty());
        unsafe { zipee_string_free(v) };
    }
}
