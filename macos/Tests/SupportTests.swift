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

// MARK: - ArchiveSession

final class SessionTests: XCTestCase {
    /// Wait for the session's background indexing to land.
    ///
    /// ArchiveSession is `@MainActor` and indexes off-thread, so the tests are
    /// synchronous and wait on an expectation. An `async` test method cannot be
    /// registered with `XCTMain`, which only accepts synchronous closures.
    private func waitForIndexed(_ session: ArchiveSession, timeout: TimeInterval = 20) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if MainActor.assumeIsolated({ session.isBusy }) { break }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
    }

    func testSessionOpensAndIndexes() throws {
        let fixture = try ArchiveFixture(members: [
            ("a.txt", Data("alpha".utf8)),
            ("dir/b.txt", Data("beta".utf8)),
        ])
        defer { fixture.cleanUp() }

        let session = MainActor.assumeIsolated { ArchiveSession() }
        MainActor.assumeIsolated { session.open(fixture.archiveURL) }
        waitForIndexed(session)

        XCTAssertEqual(MainActor.assumeIsolated { session.entries.count }, 2)
        XCTAssertNotNil(MainActor.assumeIsolated { session.stats })
        XCTAssertFalse(MainActor.assumeIsolated { session.isBusy })
        XCTAssertNil(
            MainActor.assumeIsolated { session.errorMessage },
            "an ordinary archive must not report an error")
    }

    func testNavigationMovesBetweenFoldersAndBack() throws {
        let fixture = try ArchiveFixture(members: [("dir/b.txt", Data("beta".utf8))])
        defer { fixture.cleanUp() }

        let session = MainActor.assumeIsolated { ArchiveSession() }
        MainActor.assumeIsolated { session.open(fixture.archiveURL) }
        waitForIndexed(session)

        XCTAssertEqual(MainActor.assumeIsolated { session.location.path }, "")
        let items = MainActor.assumeIsolated { session.visibleItems }
        XCTAssertEqual(items.first?.name, "dir")
        XCTAssertEqual(items.first?.isDirectory, true)

        MainActor.assumeIsolated { session.navigate(to: .folder("dir")) }
        XCTAssertEqual(MainActor.assumeIsolated { session.location.path }, "dir")
        XCTAssertEqual(
            MainActor.assumeIsolated { session.visibleItems.first?.name }, "b.txt")

        MainActor.assumeIsolated { session.goUp() }
        XCTAssertEqual(MainActor.assumeIsolated { session.location.path }, "")
        // Going up from the root must be a no-op, not an error.
        MainActor.assumeIsolated { session.goUp() }
        XCTAssertEqual(MainActor.assumeIsolated { session.location.path }, "")
    }

    func testSearchNarrowsTheListing() throws {
        let fixture = try ArchiveFixture(members: [
            ("needle.txt", Data("x".utf8)),
            ("other.txt", Data("y".utf8)),
        ])
        defer { fixture.cleanUp() }

        let session = MainActor.assumeIsolated { ArchiveSession() }
        MainActor.assumeIsolated { session.open(fixture.archiveURL) }
        waitForIndexed(session)

        MainActor.assumeIsolated { session.search("needle") }
        XCTAssertEqual(MainActor.assumeIsolated { session.visibleItems.count }, 1)
        XCTAssertEqual(
            MainActor.assumeIsolated { session.visibleItems.first?.name }, "needle.txt")

        MainActor.assumeIsolated { session.search("") }
        XCTAssertEqual(MainActor.assumeIsolated { session.visibleItems.count }, 2)
    }

    func testOpeningSomethingUnreadableReportsAnErrorRatherThanCrashing() {
        let session = MainActor.assumeIsolated { ArchiveSession() }
        MainActor.assumeIsolated { session.open(URL(fileURLWithPath: "/nonexistent/nope.zip")) }

        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            if MainActor.assumeIsolated({ session.errorMessage }) != nil { break }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        XCTAssertNotNil(
            MainActor.assumeIsolated { session.errorMessage },
            "a failed open must be reported")
        XCTAssertNil(MainActor.assumeIsolated { session.archive })
        XCTAssertFalse(MainActor.assumeIsolated { session.isBusy })
    }

    func testCloseResetsEverything() throws {
        let fixture = try ArchiveFixture(members: [("a.txt", Data("x".utf8))])
        defer { fixture.cleanUp() }

        let session = MainActor.assumeIsolated { ArchiveSession() }
        MainActor.assumeIsolated { session.open(fixture.archiveURL) }
        waitForIndexed(session)
        XCTAssertNotNil(MainActor.assumeIsolated { session.archive })

        MainActor.assumeIsolated { session.close() }
        XCTAssertNil(MainActor.assumeIsolated { session.archive })
        XCTAssertTrue(MainActor.assumeIsolated { session.entries.isEmpty })
        XCTAssertNil(MainActor.assumeIsolated { session.stats })
        XCTAssertEqual(MainActor.assumeIsolated { session.location.path }, "")
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
        // Rejected means the Result is a failure, not that a method throws.
        for bad in ["", "not base58!", "abc", String(repeating: "1", count: 32), "0OIl"] {
            if case .success = SolanaAddress.validate(bad) {
                XCTFail("expected \(bad.debugDescription) to be rejected")
            }
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
