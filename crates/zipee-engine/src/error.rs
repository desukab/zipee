//! Error type for the Zipee engine.
//!
//! Every failure an archive can produce is named here so the UI can show a
//! specific, actionable message instead of "something went wrong", and so the
//! CLI can map errors to exit codes.

use std::fmt;
use std::io;

use crate::format::DetectError;
use crate::security::{BudgetExceeded, PathViolation};

/// Result alias used throughout the engine.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong opening, reading or editing an archive.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying file could not be read or written.
    #[error("{context}: {source}")]
    Io {
        /// What Zipee was doing when the I/O error surfaced.
        context: String,
        #[source]
        source: io::Error,
    },

    /// The bytes are not a container Zipee recognises.
    #[error("cannot identify this archive: {0}")]
    Detect(#[from] DetectError),

    /// A member name was rejected by the path-safety rules.
    #[error("unsafe path in archive: {0}")]
    UnsafePath(#[from] PathViolation),

    /// An extraction or rewrite would exceed a configured resource ceiling.
    #[error("resource limit exceeded: {0}")]
    Budget(#[from] BudgetExceeded),

    /// The archive requires a password and none was supplied.
    #[error("this archive is password protected")]
    PasswordRequired,

    /// A password was supplied but the archive did not open with it.
    #[error("that password did not unlock the archive")]
    BadPassword,

    /// The archive is encrypted with a method Zipee does not implement.
    #[error("unsupported encryption (method {method}) in {entry}")]
    UnsupportedEncryption {
        /// The member that carries the unsupported encryption.
        entry: String,
        /// The numeric encryption method from the archive header.
        method: u16,
    },

    /// The container is recognised but structurally broken.
    #[error("this archive is damaged: {0}")]
    Corrupt(String),

    /// The named member does not exist.
    #[error("no such entry: {0}")]
    NoSuchEntry(String),

    /// The container cannot be edited, or the edit is not representable.
    #[error("{0}")]
    Unsupported(String),

    /// The caller cancelled the operation.
    #[error("cancelled")]
    Cancelled,

    /// The archive changed on disk while it was open.
    #[error("the archive changed on disk since it was opened")]
    ExternalModification,

    /// A filesystem-adapter operation failed.
    ///
    /// Carrying the typed [`crate::fs_adapter::FsError`] rather than an
    /// `io::Error` is deliberate: a mount backend must be able to tell
    /// "no such file" from "you tried to escape the root" from "needs a
    /// password", because each maps to a different errno and a different
    /// sentence for the user.
    #[error("{0}")]
    Fs(#[from] crate::fs_adapter::FsError),

    /// The operation would have overwritten the source archive in place.
    ///
    /// Zipee never writes back over the original: it builds a replacement in a
    /// temporary file and swaps it in atomically.
    #[error("refusing to write an archive back over its own source")]
    InPlaceWriteRefused,
}

impl Error {
    /// Wrap an [`io::Error`] with the operation that produced it.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// The typed filesystem error, when this is one.
    ///
    /// Lets a mount backend recover the precise failure — "no such file"
    /// versus "escaped the root" versus "needs a password" — without
    /// string-matching the message.
    pub fn as_fs_error(&self) -> Option<&crate::fs_adapter::FsError> {
        match self {
            Self::Fs(e) => Some(e),
            _ => None,
        }
    }

    /// True when retrying with a different password could plausibly succeed.
    pub fn is_password_related(&self) -> bool {
        matches!(self, Self::PasswordRequired | Self::BadPassword)
    }

    /// A stable, machine-readable tag. Used by the CLI and by the macOS FFI
    /// layer to translate an error into user-facing text in one place.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::Detect(_) => "detect",
            Self::UnsafePath(_) => "unsafe-path",
            Self::Budget(_) => "budget",
            Self::PasswordRequired => "password-required",
            Self::BadPassword => "bad-password",
            Self::UnsupportedEncryption { .. } => "unsupported-encryption",
            Self::Corrupt(_) => "corrupt",
            Self::NoSuchEntry(_) => "no-such-entry",
            Self::Unsupported(_) => "unsupported",
            Self::Fs(e) => e.reason(),
            Self::Cancelled => "cancelled",
            Self::ExternalModification => "external-modification",
            Self::InPlaceWriteRefused => "in-place-write-refused",
        }
    }
}

/// Attach a context string to a [`Result`], like `anyhow` but allocation-free.
pub trait IoContext<T> {
    /// Wrap the error case with a human description of the operation.
    fn ctx(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for std::result::Result<T, io::Error> {
    fn ctx(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::io(context, e))
    }
}

impl fmt::Display for FormatTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Newtype used by tests that need a printable tag.
#[derive(Debug, Clone, Copy)]
pub struct FormatTag(pub &'static str);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(Error::Cancelled.code(), "cancelled");
        assert_eq!(Error::BadPassword.code(), "bad-password");
        assert_eq!(Error::InPlaceWriteRefused.code(), "in-place-write-refused");
    }

    #[test]
    fn password_related_is_narrow() {
        assert!(Error::PasswordRequired.is_password_related());
        assert!(Error::BadPassword.is_password_related());
        assert!(!Error::Cancelled.is_password_related());
        assert!(!Error::Corrupt("x".into()).is_password_related());
    }

    #[test]
    fn io_errors_carry_context() {
        let e = Error::io("reading central directory", io::Error::other("boom"));
        assert!(e.to_string().contains("reading central directory"));
        assert!(e.to_string().contains("boom"));
    }
}
