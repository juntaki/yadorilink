import XCTest
@testable import FileProviderCore

final class EagerRootsTests: XCTestCase {
    private func urls(_ paths: String...) -> Set<URL> {
        Set(paths.map { URL(fileURLWithPath: $0, isDirectory: true) })
    }

    func testNothingIsMonitoredBeforeAConfirmedSnapshot() {
        var set = EagerRootSet()
        XCTAssertFalse(set.apply(.unavailable))
        XCTAssertEqual(set.roots, [])
    }

    func testConfirmedRootsAreMonitoredExactly() {
        var set = EagerRootSet()
        XCTAssertTrue(set.apply(.confirmed(["/Users/x/Documents/Work", "/Volumes/D/Photos"])))
        XCTAssertEqual(set.roots, urls("/Users/x/Documents/Work", "/Volumes/D/Photos"))
        XCTAssertFalse(set.apply(.confirmed(["/Volumes/D/Photos", "/Users/x/Documents/Work"])))
    }

    func testConfirmedEmptyClearsTheRoots() {
        var set = EagerRootSet()
        set.apply(.confirmed(["/a"]))
        XCTAssertTrue(set.apply(.confirmed([])))
        XCTAssertEqual(set.roots, [])
    }

    func testUnavailableKeepsTheLastConfirmedSet() {
        var set = EagerRootSet()
        set.apply(.confirmed(["/a", "/b"]))
        XCTAssertFalse(set.apply(.unavailable))
        XCTAssertEqual(set.roots, urls("/a", "/b"))
    }

    func testLinkAndUnlinkReplaceTheSetWithoutDisturbingOthers() {
        var set = EagerRootSet()
        set.apply(.confirmed(["/a"]))
        XCTAssertTrue(set.apply(.confirmed(["/a", "/b"])))
        XCTAssertEqual(set.roots, urls("/a", "/b"))
        XCTAssertTrue(set.apply(.confirmed(["/b"])))
        XCTAssertEqual(set.roots, urls("/b"))
    }

    func testRestartStartsEmptyAndConvergesOnTheFirstConfirmation() {
        var first = EagerRootSet()
        first.apply(.confirmed(["/a"]))
        var restarted = EagerRootSet()
        // The daemon is still starting: nothing invented, nothing monitored.
        XCTAssertFalse(restarted.apply(.unavailable))
        XCTAssertEqual(restarted.roots, [])
        XCTAssertTrue(restarted.apply(.confirmed(["/a"])))
        XCTAssertEqual(restarted.roots, first.roots)
    }

    // MARK: monitored = eager + provider

    private func url(_ p: String) -> URL { URL(fileURLWithPath: p, isDirectory: true) }

    func testAProviderDomainGoingFromOneRootToNoneRemovesItsRoot() {
        var roots = MonitoredRoots()
        roots.applyProvider(.confirmed(["/CloudStorage/A"]))
        XCTAssertEqual(roots.monitored(), [url("/CloudStorage/A")])
        XCTAssertTrue(roots.applyProvider(.confirmed([])))
        XCTAssertEqual(roots.monitored(), [])
    }

    func testAnUnavailableProviderListingKeepsTheLastProviderRoots() {
        var roots = MonitoredRoots()
        roots.applyProvider(.confirmed(["/CloudStorage/A"]))
        XCTAssertFalse(roots.applyProvider(.unavailable))
        XCTAssertEqual(roots.monitored(), [url("/CloudStorage/A")])
    }

    func testEagerAndProviderRootsAreIndependentAndUnioned() {
        var roots = MonitoredRoots()
        roots.applyEager(.confirmed(["/a"]))
        roots.applyProvider(.confirmed(["/p"]))
        XCTAssertEqual(roots.monitored(), [url("/a"), url("/p")])
        roots.applyEager(.confirmed([]))
        XCTAssertEqual(roots.monitored(), [url("/p")])
    }
}
