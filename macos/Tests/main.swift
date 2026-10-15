//===----------------------------------------------------------------------===//
//
// XCTMain entry point for the Zipee Swift tests.
//
// Built with `swift test`-style linking rather than SwiftPM, because the app
// is assembled with `swiftc` and a generated ObjC bridging header for the Rust
// core. Running the same tests through two build systems would mean two
// configurations to keep in step; this way the tests compile against exactly the
// headers and libraries the shipped app uses.
//
// XCTest's XCTMain() and testCase() helpers are not visible to this swiftc
// invocation, even though XCTestCase, XCTAssert* and XCTestSuite all are. The
// suite is therefore assembled by hand from XCTestCaseEntry values -- the same
// type testCase() would have produced -- and run directly.
//
//===----------------------------------------------------------------------===//

import Foundation
import XCTest

/// Convert a class's `(name, method)` table into XCTestCaseEntry values.
private func entries<T: XCTestCase>(
    _ type: T.Type,
    _ all: [(String, (T) -> () throws -> Void)]
) -> [XCTestCaseEntry] {
    all.map { XCTestCaseEntry(testCaseClass: type, allTests: [$0]) }
}

let cases: [XCTestCaseEntry] =
    entries(LifecycleTests.self, LifecycleTests.allTests)
    + entries(ReadTests.self, ReadTests.allTests)
    + entries(ErrorTests.self, ErrorTests.allTests)
    + entries(ExtractTests.self, ExtractTests.allTests)
    + entries(SessionTests.self, SessionTests.allTests)
    + entries(DonationTests.self, DonationTests.allTests)

let suite = XCTestSuite(name: "Zipee")
for entry in cases {
    suite.addTest(entry)
}

suite.run()
exit(suite.hasSucceeded ? 0 : 1)