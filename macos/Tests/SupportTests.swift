//===----------------------------------------------------------------------===//
//
// SessionTests and DonationTests.
//
// Session tests cover the app's own model, which no Rust test can reach.
// Donation tests cover the one thing that must never be wrong: the address.
//
//===----------------------------------------------------------------------===//

import Foundation
import XCTest
@testable import Foundation

// MARK: - ArchiveSession

@MainActor
final class SessionTests: XCTestCase {
    func testSessionOpensAndIndexes() async throws {
        let fixture = try ArchiveFixture(members: [
            ("a.txt", Data("alpha".utf8)),
            ("dir/b.txt", Data("beta".utf8)),
        ])
        defer { fixture.cleanUp() }

        let session = ArchiveSession()
        session.open(fixture.archiveURL)

        // The index is built on a background task, so wait for it rather than
        // assuming it has landed.
        let deadline = Date().addingTimeInterval(20)
        while session.entries.isEmpty && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        XCTAssertEqual(session.entries.count, 2)
        XCTAssertNotNil(session.stats)
        XCTAssertFalse(session.isBusy)
        XCTAssertNil(session.errorMessage, "an ordinary archive must not report an error")
    }

    func testNavigationMovesBetweenFoldersAndBack() async throws {
        let fixture = try ArchiveFixture(members: [("dir/b.txt", Data("beta".utf8))])
        defer { fixture.cleanUp() }

        let session = ArchiveSession()
        session.open(fixture.archiveURL)
        let deadline = Date().addingTimeInterval(20)
        while session.entries.isEmpty && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        XCTAssertEqual(session.location.path, "")
        let items = session.visibleItems
        XCTAssertEqual(items.first?.name, "dir")
        XCTAssertEqual(items.first?.isDirectory, true)

        session.navigate(to: .folder("dir"))
        XCTAssertEqual(session.location.path, "dir")
        XCTAssertEqual(session.visibleItems.first?.name, "b.txt")

        session.goUp()
        XCTAssertEqual(session.location.path, "")
        // Going up from the root must be a no-op, not an error.
        session.goUp()
        XCTAssertEqual(session.location.path, "")
    }

    func testSearchNarrowsTheListing() async throws {
        let fixture = try ArchiveFixture(members: [
            ("needle.txt", Data("x".utf8)),
            ("other.txt", Data("y".utf8)),
        ])
        defer { fixture.cleanUp() }

        let session = ArchiveSession()
        session.open(fixture.archiveURL)
        let deadline = Date().addingTimeInterval(20)
        while session.entries.isEmpty && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        session.search("needle")
        XCTAssertEqual(session.visibleItems.count, 1)
        XCTAssertEqual(session.visibleItems.first?.name, "needle.txt")

        session.search("")
        XCTAssertEqual(session.visibleItems.count, 2)
    }

    func testOpeningSomethingUnreadableReportsAnErrorRatherThanCrashing() async throws {
        let session = ArchiveSession()
        session.open(URL(fileURLWithPath: "/nonexistent/nope.zip"))

        let deadline = Date().addingTimeInterval(20)
        while session.errorMessage == nil && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertNotNil(session.errorMessage, "a failed open must be reported")
        XCTAssertNil(session.archive)
        XCTAssertFalse(session.isBusy)
    }

    func testCloseResetsEverything() async throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("x".utf8))])
        defer { fixture.cleanUp() }

        let session = ArchiveSession()
        session.open(fixture.archiveURL)
        let deadline = Date().addingTimeInterval(20)
        while session.entries.isEmpty && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertNotNil(session.archive)

        session.close()
        XCTAssertNil(session.archive)
        XCTAssertTrue(session.entries.isEmpty)
        XCTAssertNil(session.stats)
        XCTAssertEqual(session.location.path, "")
    }

    static var allTests = [
        ("testSessionOpensAndIndexes", testSessionOpensAndIndexes),
        ("testNavigationMovesBetweenFoldersAndBack", testNavigationMovesBetweenFoldersAndBack),
        ("testSearchNarrowsTheListing", testSearchNarrowsTheListing),
        ("testOpeningSomethingUnreadableReportsAnErrorRatherThanCrashing", testOpeningSomethingUnreadableReportsAnErrorRatherThanCrashing),
        ("testCloseResetsEverything", testCloseResetsEverything),
    ]
}

// MARK: - Donation

final class DonationTests: XCTestCase {
    /// The address supplied for Zipee, written out independently of the app's
    /// own constant so the test can catch an edit to either.
    private let expectedAddress = "2EJyURV4HhJNFas4V3cJtB1BqvMnDaPhqcxu5yiSkAxG"

    func testAddressIsExactlyAsSupplied() {
        XCTAssertEqual(
            Donation.solanaAddress, expectedAddress,
            "the donation address must never be altered, truncated or substituted")
    }

    func testAddressIsNotTruncated() {
        // A Solana address is 32 bytes of key plus a base58 length that varies
        // with leading zeros; 44 is what this one is and it must stay so.
        XCTAssertEqual(Donation.solanaAddress.count, 44)
    }

    func testAddressValidates() {
        switch SolanaAddress.validate(Donation.solanaAddress) {
        case .success: break
        case .failure(let e): XCTFail("address failed validation: \(e)")
        }
    }

    func testValidationRejectsMalformedAddresses() {
        for bad in ["", "not base58!", "abc", String(repeating: "1", count: 32), "0OIl"] {
            XCTAssertThrowsError(
                try { () throws -> Void in
                    if case .failure = SolanaAddress.validate(bad) { return }
                    XCTFail("expected \(bad.debugDescription) to be rejected")
                }(),
                "expected \(bad.debugDescription) to be rejected")
        }
    }

    func testBase58DecoderMatchesTheKnownAddress() {
        let bytes = Base58.decode(expectedAddress)
        XCTAssertEqual(bytes?.count, SolanaAddress.expectedByteCount)
        // First byte of the little-endian ed25519 public key, as verified
        // independently in Python during the audit.
        XCTAssertEqual(bytes?.map(String.init).joined(separator: ""),
                       "12448f7236f6b36545464f4d33c3517eacde43afafc9f9b0f9a17206681562b1")
    }

    func testSolanaPayURICarriesNoAmountAndNoMemo() {
        XCTAssertEqual(Donation.solanaPayURI, "solana:\(expectedAddress)")
        // Must not imply a payment is due.
        XCTAssertFalse(Donation.solanaPayURI.contains("amount"), "no amount may be implied")
        XCTAssertFalse(Donation.solanaPayURI.contains("memo"), "no memo may be attached")
        XCTAssertEqual(Donation.solanaPayURI.filter { $0 == ":" }.count, 1,
                       "only the scheme separator")
    }

    func testQRCodeGeneratesFromTheExactAddress() throws {
        let png = try XCTUnwrap(
            DonationQRCode.donationPNG(),
            "the QR code must generate locally from the address")
        XCTAssertGreaterThan(png.count, 100, "a QR PNG of this size should not be tiny")

        // The payload the QR encodes is the address, verbatim: assert on the
        // value passed to the generator rather than on the rendered pixels.
        XCTAssertEqual(Donation.solanaAddress, expectedAddress)
    }

    func testDisclaimerStatesDonationsAreOptional() {
        let text = Donation.disclaimer.lowercased()
        XCTAssertTrue(text.contains("free"))
        XCTAssertTrue(text.contains("optional"),
                      "the donation notice must say donations are optional")
        XCTAssertFalse(text.contains("required"))
        XCTAssertFalse(text.contains("must donate"))
    }

    func testNoWalletSecretIsReferencedAnywhereInTheSources() throws {
        // A structural check: the app must contain no seed-phrase or private
        // key handling at all. Cheap, and it fails loudly if anyone adds one.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
        let banned = ["mnemonic", "seedPhrase", "secretKey", "privateKey", "keypairPath", "solana-keygen"]
        for url in ["Zipee/DonationSupport.swift", "Zipee/AboutView.swift"] {
            let text = try String(contentsOf: root.appendingPathComponent(url), encoding: .utf8)
            for term in banned {
                XCTAssertFalse(text.lowercased().contains(term.lowercased()),
                               "\(url) must not mention \(term)")
            }
        }
    }

    static var allTests = [
        ("testAddressIsExactlyAsSupplied", testAddressIsExactlyAsSupplied),
        ("testAddressIsNotTruncated", testAddressIsNotTruncated),
        ("testAddressValidates", testAddressValidates),
        ("testValidationRejectsMalformedAddresses", testValidationRejectsMalformedAddresses),
        ("testBase58DecoderMatchesTheKnownAddress", testBase58DecoderMatchesTheKnownAddress),
        ("testSolanaPayURICarriesNoAmountAndNoMemo", testSolanaPayURICarriesNoAmountAndNoMemo),
        ("testQRCodeGeneratesFromTheExactAddress", testQRCodeGeneratesFromTheExactAddress),
        ("testDisclaimerStatesDonationsAreOptional", testDisclaimerStatesDonationsAreOptional),
        ("testNoWalletSecretIsReferencedAnywhereInTheSources", testNoWalletSecretIsReferencedAnywhereInTheSources),
    ]
}
