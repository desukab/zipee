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
//===----------------------------------------------------------------------===//

import Foundation
import XCTest

XCTMain([
    testCase(LifecycleTests.allTests),
    testCase(ReadTests.allTests),
    testCase(ErrorTests.allTests),
    testCase(ExtractTests.allTests),
    testCase(SessionTests.allTests),
    testCase(DonationTests.allTests),
])