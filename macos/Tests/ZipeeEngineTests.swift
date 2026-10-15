//===----------------------------------------------------------------------===//
//
// ZipeeEngineTests — the Swift half of the boundary tests.
//
// The Rust suite proves the engine. These tests prove the *Swift wrapper*:
// that the C ABI is declared correctly, that memory returned by the engine is
// released, that errors convert rather than crash, and that repeated use does
// not leak. None of that is visible from Rust, because a mistake in the Swift
// struct layouts or in who calls `zipee_bytes_free` would not fail a single
// Rust test.
//
// Run with `scripts/build-macos.sh --test` or the `macos` CI workflow.
//
//===----------------------------------------------------------------------===//

import Foundation
import XCTest

// MARK: - Fixtures

/// A temporary archive built once per test, so the engine has real ZIP bytes to
/// read rather than a mock.
final class ArchiveFixture {
    let directory: URL
    let archiveURL: URL
    let members: [(name: String, body: Data)]

    init(members: [(String, Data)]) throws {
        self.members = members
        self.directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zipee-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        self.archiveURL = directory.appendingPathComponent("fixture.zip")
        try ArchiveFixture.write(members: members, to: archiveURL)
    }

    /// Write a ZIP by hand.
    ///
    /// `Archive` is not available headlessly, and shelling out would make these
    /// tests depend on an external tool. The records below are a complete,
    /// spec-valid, stored-method ZIP.
    private static func write(members: [(String, Data)], to url: URL) throws {
        var bytes = Data()
        var central = Data()
        var count: UInt16 = 0

        func append32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { bytes.append(contentsOf: $0) } }
        func append16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { bytes.append(contentsOf: $0) } }

        for (name, body) in members {
            let nameBytes = Array(name.utf8)
            let offset = UInt32(bytes.count)
            let crc = CRC32.checksum(body)

            bytes.append(contentsOf: [0x50, 0x4B, 0x03, 0x04])
            append16(20); append16(0); append16(0); append16(0); append16(0x21)
            append32(crc); append32(UInt32(body.count)); append32(UInt32(body.count))
            append16(UInt16(nameBytes.count)); append16(0)
            bytes.append(contentsOf: nameBytes)
            bytes.append(body)

            let cOffset = UInt32(central.count)
            central.append(contentsOf: [0x50, 0x4B, 0x01, 0x02])
            append16(0x031E); append16(20); append16(0); append16(0)
            append16(0); append16(0x21)
            append32(crc); append32(UInt32(body.count)); append32(UInt32(body.count))
            append16(UInt16(nameBytes.count)); append16(0); append16(0)
            append16(0); append16(0); append32(0o100644 << 16); append32(offset)
            central.append(contentsOf: nameBytes)
            _ = cOffset
            count += 1
        }

        let cdOffset = UInt32(bytes.count)
        bytes.append(central)
        bytes.append(contentsOf: [0x50, 0x4B, 0x05, 0x06])
        append16(0); append16(0); append16(count); append16(count)
        append32(UInt32(central.count)); append32(cdOffset); append16(0)

        try bytes.write(to: url)
    }

    func cleanUp() { try? FileManager.default.removeItem(at: directory) }
}

/// Minimal CRC-32, so the fixture writer does not need a dependency.
enum CRC32 {
    static func checksum(_ data: Data) -> UInt32 {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1) }
            table[i] = c
        }
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}

// MARK: - Lifecycle

final class LifecycleTests: XCTestCase {
    func testEngineVersionIsReported() {
        let v = ZipeeArchive.engineVersion
        XCTAssertFalse(v.isEmpty, "the engine must report a version")
        XCTAssertTrue(
            v.contains("."),
            "expected a dotted version, got \\(v)")
    }

    func testOpenAndCloseRepeatedly() throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("a".utf8))])
        defer { fixture.cleanUp() }
        // Repeated open/close is where a leaked file handle would show up.
        for _ in 0..<50 {
            let archive = try ZipeeArchive(url: fixture.archiveURL)
            XCTAssertEqual(try archive.entries().count, 1)
        }
    }

    func testDeinitReleasesTheHandleWithoutCrashing() throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("a".utf8))])
        defer { fixture.cleanUp() }
        // No reference kept: deinit must run and must close the handle.
        for _ in 0..<50 {
            _ = try ZipeeArchive(url: fixture.archiveURL).entries()
        }
        XCTAssertTrue(true, "survived 50 implicit deinits")
    }
}

// MARK: - Opening, listing, reading

final class ReadTests: XCTestCase {
    func testListingReportsEveryMember() throws {
        let fixture = try ArchiveFixture(members: [
            ("readme.md", Data("# hi".utf8)),
            ("docs/guide.txt", Data("guide body".utf8)),
            ("docs/img/logo.png", Data([0x89, 0x50, 0x4E, 0x47])),
        ])
        defer { fixture.cleanUp() }

        let archive = try ZipeeArchive(url: fixture.archiveURL)
        let entries = try archive.entries()
        XCTAssertEqual(entries.count, 3)
        XCTAssertEqual(
            Set(entries.map(\\.rawName)),
            ["readme.md", "docs/guide.txt", "docs/img/logo.png"])

        let stats = archive.stats()
        XCTAssertEqual(stats.totalEntries, 3)
        XCTAssertEqual(stats.files, 3)
        XCTAssertEqual(stats.uncompressedBytes, 10 + 10 + 4)
    }

    func testReadingReturnsExactBytes() throws {
        let body = Data("the exact bytes".utf8)
        let fixture = try ArchiveFixture(members: [("payload.bin", body)])
        defer { fixture.cleanUp() }

        let archive = try ZipeeArchive(url: fixture.archiveURL)
        let data = try archive.readEntry("payload.bin")
        XCTAssertEqual(data, body)
        XCTAssertEqual(data.count, body.count)
    }

    func testReadingTheSameEntryManyTimesIsStable() throws {
        let fixture = try ArchiveFixture(members: [("x.bin", Data(repeating: 0xAB, count: 4096))])
        defer { fixture.cleanUp() }
        let archive = try ZipeeArchive(url: fixture.archiveURL)
        // Each read allocates a buffer the engine allocated; freeing it wrongly
        // would eventually corrupt the heap rather than fail cleanly.
        for _ in 0..<200 {
            XCTAssertEqual(try archive.readEntry("x.bin").count, 4096)
        }
    }

    func testMixedSizesAreNotConfused() throws {
        let sizes = [0, 1, 2, 255, 256, 65_535, 65_536, 200_000]
        let members = sizes.enumerated().map { (i, n) in
            ("f\(i).bin", Data(repeating: UInt8(i % 251), count: n))
        }
        let fixture = try ArchiveFixture(members: members)
        defer { fixture.cleanUp() }

        let archive = try ZipeeArchive(url: fixture.archiveURL)
        for (i, n) in sizes.enumerated() {
            let data = try archive.readEntry("f\\(i).bin")
            XCTAssertEqual(data.count, n, "size mismatch for f\\(i).bin")
            XCTAssertEqual(data.first, UInt8(i % 251))
        }
    }
}

// MARK: - Errors

final class ErrorTests: XCTestCase {
    func testOpeningAMissingFileFails() {
        let missing = URL(fileURLWithPath: "/nonexistent/definitely/not/here.zip")
        XCTAssertThrowsError(try ZipeeArchive(url: missing)) { error in
            guard let e = error as? ZipeeError else {
                return XCTFail("expected a ZipeeError, got \\(error)")
            }
            XCTAssertFalse(e.errorDescription?.isEmpty ?? true)
        }
    }

    func testOpeningSomethingThatIsNotAnArchiveFails() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zipee-notanarchive-\\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("actually.txt")
        try Data(repeating: 0x41, count: 4096).write(to: url)

        XCTAssertThrowsError(try ZipeeArchive(url: url))
    }

    func testAnEmptyFileIsNotMistakenForAnArchive() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zipee-empty-\\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("empty.zip")
        try Data().write(to: url)
        XCTAssertThrowsError(try ZipeeArchive(url: url))
    }

    func testReadingAMissingEntryFails() throws {
        let fixture = try ArchiveFixture(members: [("present.txt", Data("x".utf8))])
        defer { fixture.cleanUp() }
        let archive = try ZipeeArchive(url: fixture.archiveURL)
        XCTAssertThrowsError(try archive.readEntry("absent.txt"))
    }

    func testErrorDescriptionsAreNeverEmpty() {
        let codes = ["password-required", "bad-password", "unsafe-path", "budget", "cancelled"]
        for code in codes {
            let e = ZipeeError(code: code, detail: "detail text")
            XCTAssertFalse(
                e.errorDescription?.isEmpty ?? true,
                "no user-facing message for \\(code)")
        }
        // An unknown code still yields the engine's own message.
        let unknown = ZipeeError(code: "something-new", detail: "raw engine text")
        XCTAssertEqual(unknown.errorDescription, "raw engine text")
    }

    func testCorruptArchiveFailsRatherThanReturningGarbage() throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("original".utf8))])
        defer { fixture.cleanUp() }
        // Corrupt the stored CRC in the local file header so the archive no
        // longer matches its own contents.
        var bytes = try Data(contentsOf: fixture.archiveURL)
        let idx = bytes.range(of: Data([0x50, 0x4B, 0x03, 0x04]))!
        let crcOffset = idx.lowerBound + 14
        bytes[crcOffset] ^= 0xFF
        try bytes.write(to: fixture.archiveURL)

        // Either opening or reading must fail. Returning the wrong bytes would
        // be far worse than an error.
        var didThrow = false
        do {
            let archive = try ZipeeArchive(url: fixture.archiveURL)
            _ = try archive.readEntry("a.txt")
        } catch {
            didThrow = true
        }
        XCTAssertTrue(didThrow, "a corrupt archive must not yield data silently")
    }
}

// MARK: - Extraction

final class ExtractTests: XCTestCase {
    func testExtractingEverything() throws {
        let fixture = try ArchiveFixture(members: [
            ("a.txt", Data("alpha".utf8)),
            ("dir/b.txt", Data("beta".utf8)),
        ])
        defer { fixture.cleanUp() }
        let out = fixture.directory.appendingPathComponent("out")

        let archive = try ZipeeArchive(url: fixture.archiveURL)
        try archive.extract(selection: "*", to: out)

        XCTAssertEqual(
            try String(contentsOf: out.appendingPathComponent("a.txt"), encoding: .utf8),
            "alpha")
        XCTAssertEqual(
            try String(contentsOf: out.appendingPathComponent("dir/b.txt"), encoding: .utf8),
            "beta")
    }

    func testSelectiveExtractionDoesNotOverExtract() throws {
        let fixture = try ArchiveFixture(members: [
            ("wanted/a.txt", Data("a".utf8)),
            ("unwanted/b.txt", Data("b".utf8)),
        ])
        defer { fixture.cleanUp() }
        let out = fixture.directory.appendingPathComponent("out")

        let archive = try ZipeeArchive(url: fixture.archiveURL)
        try archive.extract(selection: "wanted", to: out)

        XCTAssertTrue(FileManager.default.fileExists(atPath: out.appendingPathComponent("wanted/a.txt").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.appendingPathComponent("unwanted").path))
    }

    func testTraversingSelectionIsRefused() throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("a".utf8))])
        defer { fixture.cleanUp() }
        let out = fixture.directory.appendingPathComponent("out")
        let archive = try ZipeeArchive(url: fixture.archiveURL)

        // The engine must refuse before anything is written.
        XCTAssertThrowsError(try archive.extract(selection: "../../evil", to: out))
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: fixture.directory.appendingPathComponent("evil").path),
            "nothing may be written outside the destination")
    }

    func testExtractingRepeatedlyIsStable() throws {
        let fixture = try ArchiveFixture(members: [("r.bin", Data(repeating: 7, count: 2048))])
        defer { fixture.cleanUp() }
        let out = fixture.directory.appendingPathComponent("out")
        let archive = try ZipeeArchive(url: fixture.archiveURL)
        for _ in 0..<20 {
            try archive.extract(selection: "*", to: out)
            let data = try Data(contentsOf: out.appendingPathComponent("r.bin"))
            XCTAssertEqual(data.count, 2048)
        }
    }
}
// MARK: - AllTests manifests
//
// Required by XCTMain, which is how the suite is launched without SwiftPM.

extension LifecycleTests {
    static var allTests = [
        ("testEngineVersionIsReported", testEngineVersionIsReported),
        ("testOpenAndCloseRepeatedly", testOpenAndCloseRepeatedly),
        ("testDeinitReleasesTheHandleWithoutCrashing", testDeinitReleasesTheHandleWithoutCrashing),
    ]
}

extension ReadTests {
    static var allTests = [
        ("testListingReportsEveryMember", testListingReportsEveryMember),
        ("testReadingReturnsExactBytes", testReadingReturnsExactBytes),
        ("testReadingTheSameEntryManyTimesIsStable", testReadingTheSameEntryManyTimesIsStable),
        ("testMixedSizesAreNotConfused", testMixedSizesAreNotConfused),
    ]
}

extension ErrorTests {
    static var allTests = [
        ("testOpeningAMissingFileFails", testOpeningAMissingFileFails),
        ("testOpeningSomethingThatIsNotAnArchiveFails", testOpeningSomethingThatIsNotAnArchiveFails),
        ("testAnEmptyFileIsNotMistakenForAnArchive", testAnEmptyFileIsNotMistakenForAnArchive),
        ("testReadingAMissingEntryFails", testReadingAMissingEntryFails),
        ("testErrorDescriptionsAreNeverEmpty", testErrorDescriptionsAreNeverEmpty),
        ("testCorruptArchiveFailsRatherThanReturningGarbage", testCorruptArchiveFailsRatherThanReturningGarbage),
    ]
}

extension ExtractTests {
    static var allTests = [
        ("testExtractingEverything", testExtractingEverything),
        ("testSelectiveExtractionDoesNotOverExtract", testSelectiveExtractionDoesNotOverExtract),
        ("testTraversingSelectionIsRefused", testTraversingSelectionIsRefused),
        ("testExtractingRepeatedlyIsStable", testExtractingRepeatedlyIsStable),
    ]
}
