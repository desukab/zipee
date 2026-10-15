//===----------------------------------------------------------------------===//
//
// ZipeeEngine — the Swift face of the Zipee archive core.
//
// This is a thin, correct wrapper around the Rust engine's C ABI. It owns no
// archive logic of its own: every decision about what is safe to read, what a
// member is called, and how much of an archive may expand is made in Rust,
// where it is covered by the test suite. Anything this layer adds is concern
// with Swift's memory model, error presentation, and concurrency.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - C interop types
//
// These mirror `crates/zipee-engine/src/ffi.rs` exactly. They are declared here
// rather than generated because the ABI is frozen: changing it would break any
// app already built against a released Zipee.

/// Error slot filled in by the engine when an entry point fails.
private typealias ZipeeErrorOut = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>

/// An open archive. Opaque to Swift.
private typealias ZipeeArchiveHandle = OpaquePointer?

@_silgen_name("zipee_open")
private func zipee_open(_ path: UnsafePointer<CChar>, _ errorOut: ZipeeErrorOut) -> ZipeeArchiveHandle

@_silgen_name("zipee_close")
private func zipee_close(_ handle: ZipeeArchiveHandle)

@_silgen_name("zipee_stats")
private func zipee_stats(_ handle: ZipeeArchiveHandle, _ errorOut: ZipeeErrorOut) -> ZipeeStatsRecord

@_silgen_name("zipee_entries")
private func zipee_entries(
    _ handle: ZipeeArchiveHandle,
    _ out: UnsafeMutablePointer<ZipeeEntryRecord>,
    _ capacity: Int,
    _ countOut: UnsafeMutablePointer<Int>,
    _ errorOut: ZipeeErrorOut
) -> Int32

@_silgen_name("zipee_read_entry")
private func zipee_read_entry(
    _ handle: ZipeeArchiveHandle,
    _ name: UnsafePointer<CChar>,
    _ errorOut: ZipeeErrorOut
) -> ZipeeBytesRecord

@_silgen_name("zipee_extract")
private func zipee_extract(
    _ handle: ZipeeArchiveHandle,
    _ spec: UnsafePointer<CChar>,
    _ destination: UnsafePointer<CChar>,
    _ maxTotalBytes: UInt64,
    _ reportJSON: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    _ errorOut: ZipeeErrorOut
) -> Int32

@_silgen_name("zipee_bytes_free")
private func zipee_bytes_free(_ bytes: ZipeeBytesRecord)

@_silgen_name("zipee_string_free")
private func zipee_string_free(_ string: UnsafeMutablePointer<CChar>?)

@_silgen_name("zipee_version")
private func zipee_version() -> UnsafeMutablePointer<CChar>?

struct ZipeeBytesRecord {
    var data: UnsafeMutablePointer<UInt8>?
    var len: Int
    var capacity: Int
}

struct ZipeeStatsRecord {
    var totalEntries: UInt64
    var files: UInt64
    var directories: UInt64
    var unsafeEntries: UInt64
    var encryptedEntries: UInt64
    var uncompressedBytes: UInt64
    var compressedBytes: UInt64
}

struct ZipeeEntryRecord {
    var name: UnsafeMutablePointer<CChar>?
    var kind: Int32
    var isUnsafe: Int32
    var isEncrypted: Int32
    var uncompressedSize: UInt64
    var compressedSize: UInt64
    var unixMode: UInt32
    var modified: UInt64
}

// MARK: - Errors

/// A failure surfaced by the archive core.
///
/// `code` matches the engine's stable tags, which the UI switches on so every
/// error message the user sees lives in one place.
public struct ZipeeError: Error, LocalizedError, CustomStringConvertible {
    /// Stable machine-readable tag, e.g. `"unsafe-path"`.
    public let code: String

    /// The engine's message.
    public let detail: String

    init(code: String, detail: String) {
        self.code = code
        self.detail = detail
    }

    public var errorDescription: String? {
        switch code {
        case "password-required":
            return "This archive is password protected."
        case "bad-password":
            return "That password didn't unlock the archive."
        case "unsupported-encryption":
            return "This archive uses an encryption method Zipee can't read."
        case "unsafe-path":
            return "Some entries were skipped because their paths tried to escape the archive."
        case "budget":
            return "This archive expands further than Zipee is willing to unpack."
        case "corrupt":
            return detail
        case "cancelled":
            return "Cancelled."
        case "external-modification":
            return "The archive changed on disk since Zipee opened it."
        default:
            return detail
        }
    }

    public var description: String { "\(code): \(detail)" }
}

// MARK: - Model

/// What a member is.
public enum ZipeeEntryKind: Int32, Sendable {
    case file = 0
    case directory = 1
    case symlink = 2
    case special = 3
}

/// One member, as reported by the engine.
public struct ZipeeEntry: Identifiable, Sendable {
    public var id: String { path }
    public let path: String
    public let rawName: String
    public let kind: ZipeeEntryKind
    public let isUnsafe: Bool
    public let isEncrypted: Bool
    public let uncompressedSize: UInt64
    public let compressedSize: UInt64
    public let unixMode: UInt32?
    public let modified: Date?

    /// Bytes saved compared with storing the member uncompressed.
    public var savedBytes: UInt64 { uncompressedSize &- min(uncompressedSize, compressedSize) }
}

/// Aggregate counts for a whole archive.
public struct ZipeeArchiveStats: Sendable {
    public let totalEntries: UInt64
    public let files: UInt64
    public let directories: UInt64
    public let unsafeEntries: UInt64
    public let encryptedEntries: UInt64
    public let uncompressedBytes: UInt64
    public let compressedBytes: UInt64

    /// Compression ratio as a percentage in `0...100`.
    public var ratioPercent: Int {
        guard uncompressedBytes > 0 else { return 0 }
        return Int(compressedBytes * 100 / uncompressedBytes)
    }
}

// MARK: - Engine

/// An open archive.
///
/// The handle owns a Rust allocation and is closed in `deinit`, so a Swift
/// object going out of scope cannot leak the engine's file descriptor. The
/// class is not `Sendable`: the underlying `ZipArchive` holds a `&mut` reader
/// and two threads using it would corrupt that borrow.
public final class ZipeeArchive {
    private let handle: ZipeeArchiveHandle
    public let url: URL

    /// Open an archive, identifying the container from its contents.
    public init(url: URL) throws {
        var error: UnsafeMutablePointer<CChar>?
        let handle = url.path.withCString { path in
            zipee_open(path, &error)
        }
        guard let handle, handle != nil else {
            let detail = error.map { String(cString: $0) } ?? "unknown error"
            zipee_string_free(error)
            throw ZipeeError(code: "open-failed", detail: detail)
        }
        self.handle = handle
        self.url = url
    }

    deinit { zipee_close(handle) }

    /// The engine version string.
    public static var engineVersion: String {
        guard let p = zipee_version() else { return "unknown" }
        defer { zipee_string_free(p) }
        return String(cString: p)
    }

    /// Every member, read from the container index without decompressing.
    public func entries() throws -> [ZipeeEntry] {
        var error: UnsafeMutablePointer<CChar>?
        var stats = zipee_stats(handle, &error)
        if stats.totalEntries == 0, let e = error {
            zipee_string_free(e)
            throw ZipeeError(code: "stats-failed", detail: String(cString: e))
        }

        let count = Int(stats.totalEntries)
        guard count > 0 else { return [] }
        var raw = [ZipeeEntryRecord](
            repeating: ZipeeEntryRecord(
                name: nil, kind: 0, isUnsafe: 0, isEncrypted: 0,
                uncompressedSize: 0, compressedSize: 0, unixMode: 0, modified: 0),
            count: count
        )

        var written = 0
        let rc = raw.withUnsafeMutableBufferPointer { buffer in
            zipee_entries(
                handle,
                buffer.baseAddress!,
                count,
                &written,
                &error
            )
        }
        defer { for i in 0..<written { zipee_string_free(raw[i].name) } }

        guard rc == 0 else {
            let detail = error.map { String(cString: $0) } ?? "listing failed"
            zipee_string_free(error)
            throw ZipeeError(code: "listing-failed", detail: detail)
        }

        stats = stats  // keep the value alive for the duration of this scope
        return raw.prefix(written).compactMap { record in
            guard let namePtr = record.name else { return nil }
            let rawName = String(cString: namePtr)
            return ZipeeEntry(
                path: (rawName as NSString).lastPathComponent,
                rawName: rawName,
                kind: ZipeeEntryKind(rawValue: record.kind) ?? .special,
                isUnsafe: record.isUnsafe != 0,
                isEncrypted: record.isEncrypted != 0,
                uncompressedSize: record.uncompressedSize,
                compressedSize: record.compressedSize,
                unixMode: record.unixMode == 0 ? nil : record.unixMode,
                modified: record.modified == 0
                    ? nil
                    : Date(timeIntervalSince1970: TimeInterval(record.modified))
            )
        }
    }

    /// Summary counts for the archive.
    public func stats() -> ZipeeArchiveStats {
        var error: UnsafeMutablePointer<CChar>?
        let s = zipee_stats(handle, &error)
        zipee_string_free(error)
        return ZipeeArchiveStats(
            totalEntries: s.totalEntries,
            files: s.files,
            directories: s.directories,
            unsafeEntries: s.unsafeEntries,
            encryptedEntries: s.encryptedEntries,
            uncompressedBytes: s.uncompressedBytes,
            compressedBytes: s.compressedBytes
        )
    }

    /// Read one member's bytes.
    public func readEntry(_ name: String) throws -> Data {
        var error: UnsafeMutablePointer<CChar>?
        let bytes = name.withCString { ptr in
            zipee_read_entry(handle, ptr, &error)
        }
        guard let data = bytes.data, bytes.len > 0 else {
            let detail = error.map { String(cString: $0) } ?? "no data"
            zipee_string_free(error)
            throw ZipeeError(code: "read-failed", detail: detail)
        }
        zipee_string_free(error)
        // Copy out of the engine's buffer, then hand the buffer straight back.
        defer { zipee_bytes_free(bytes) }
        return Data(bytes: data, count: bytes.len)
    }

    /// Extract members to a directory.
    ///
    /// - Parameters:
    ///   - selection: a member path, a folder path, or `"*"` for everything.
    ///   - destination: must already exist or be creatable by the engine.
    ///   - maxTotalBytes: hard ceiling on total bytes written.
    public func extract(
        selection: String = "*",
        to destination: URL,
        maxTotalBytes: UInt64 = .max
    ) throws {
        var error: UnsafeMutablePointer<CChar>?
        var report: UnsafeMutablePointer<CChar>?
        let rc = selection.withCString { sel in
            destination.path.withCString { dest in
                zipee_extract(handle, sel, dest, maxTotalBytes, &report, &error)
            }
        }
        defer { zipee_string_free(report) }

        guard rc == 0 else {
            let detail = error.map { String(cString: $0) } ?? "extraction failed"
            zipee_string_free(error)
            throw ZipeeError(code: "extract-failed", detail: detail)
        }
        zipee_string_free(error)
    }
}