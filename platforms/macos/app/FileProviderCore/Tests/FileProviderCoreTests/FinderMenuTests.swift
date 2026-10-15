import XCTest
@testable import FileProviderCore

final class FinderMenuTests: XCTestCase {
    private func facts(
        tracked: Bool = true, paused: Bool = false, inherited: Bool = false,
        current: Bool = false, transition: Bool = false, reclaim: Bool = true,
        directory: Bool? = false
    ) -> FinderItemFacts {
        FinderItemFacts(
            tracked: tracked, paused: paused, pausedByAncestor: inherited,
            reclaimSupported: reclaim, currentContentPresent: current,
            inTransition: transition, isDirectory: directory)
    }

    func testAnActivelySyncedLocalFileOffersPauseAndFreeUpSpace() {
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(current: true)]),
            [.viewStatus, .pause, .freeUpSpace])
    }

    func testAPausedItemOffersResumeAndNeverPause() {
        let actions = FinderMenu.actions(for: [facts(paused: true, current: true)])
        XCTAssertEqual(actions, [.viewStatus, .resume, .freeUpSpace])
        XCTAssertFalse(actions.contains(.pause))
    }

    func testPauseAndResumeAreNeverTogetherForAMixedSelection() {
        let actions = FinderMenu.actions(for: [facts(paused: true), facts(paused: false)])
        XCTAssertEqual(actions.filter { $0 == .pause || $0 == .resume }, [.pause])
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(paused: true), facts(paused: true)]),
            [.viewStatus, .resume])
    }

    func testAnItemPausedByAnAncestorOffersNeitherPauseNorResume() {
        let actions = FinderMenu.actions(for: [facts(inherited: true, current: true)])
        XCTAssertEqual(actions, [.viewStatus, .freeUpSpace])
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(inherited: true), facts(paused: true)]),
            [.viewStatus])
    }

    func testFreeUpSpaceIsHiddenWhenTheDaemonDoesNotSupportReclaimForTheRoot() {
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(current: true, reclaim: false)]),
            [.viewStatus, .pause])
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(current: true), facts(current: true, reclaim: false)]),
            [.viewStatus, .pause])
    }

    func testRemoteContentIsNotOfferedFreeUpSpace() {
        XCTAssertEqual(FinderMenu.actions(for: [facts(current: false)]), [.viewStatus, .pause])
    }

    func testATransitionOffersNoFreeUpSpace() {
        XCTAssertEqual(
            FinderMenu.actions(for: [facts(current: false, transition: true)]),
            [.viewStatus, .pause])
        // Even if a stale answer claimed current content during a transition.
        XCTAssertFalse(
            FinderMenu.actions(for: [facts(current: true, transition: true)]).contains(.freeUpSpace))
    }

    func testAFolderOrUnknownKindIsNotOfferedFreeUpSpace() {
        XCTAssertFalse(
            FinderMenu.actions(for: [facts(current: true, directory: true)]).contains(.freeUpSpace))
        XCTAssertFalse(
            FinderMenu.actions(for: [facts(current: true, directory: nil)]).contains(.freeUpSpace))
    }

    func testFreeUpSpaceNeedsEverySelectedItemToQualify() {
        XCTAssertFalse(
            FinderMenu.actions(for: [facts(current: true), facts(current: false)])
                .contains(.freeUpSpace))
        XCTAssertTrue(
            FinderMenu.actions(for: [facts(current: true), facts(current: true)])
                .contains(.freeUpSpace))
    }

    func testAnUntrackedItemGetsNoActionsAtAll() {
        XCTAssertEqual(FinderMenu.actions(for: [facts(tracked: false)]), [])
        XCTAssertEqual(FinderMenu.actions(for: [facts(), facts(tracked: false)]), [])
        XCTAssertEqual(FinderMenu.actions(for: []), [])
    }

    func testUserVisibleTitlesUseProductWording() {
        XCTAssertEqual(FinderMenuAction.viewStatus.title, "View YadoriLink Status")
        XCTAssertEqual(FinderMenuAction.pause.title, "Pause Syncing")
        XCTAssertEqual(FinderMenuAction.resume.title, "Resume Syncing")
        XCTAssertEqual(FinderMenuAction.freeUpSpace.title, "Free Up Space")
        for action in [FinderMenuAction.viewStatus, .pause, .resume, .freeUpSpace] {
            XCTAssertFalse(action.title.lowercased().contains("evict"))
        }
    }

    func testTheDeepLinkIsAStableEncodedItemURL() {
        XCTAssertEqual(
            FinderDeepLink.url(forItemAt: "/Users/me/Work/a b.txt")?.absoluteString,
            "yadorilink://item?path=/Users/me/Work/a%20b.txt")
    }

    func testTheDeepLinkKeepsReservedCharactersInsideThePath() throws {
        let path = "/Users/me/R&D+x=1/100%/日本語.txt"
        let url = try XCTUnwrap(FinderDeepLink.url(forItemAt: path))
        let query = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
        XCTAssertEqual(query.count, 1)
        XCTAssertEqual(query.first?.name, "path")
        XCTAssertEqual(query.first?.value, path)
    }

    func testARelativePathHasNoDeepLink() {
        XCTAssertNil(FinderDeepLink.url(forItemAt: "relative/file.txt"))
        XCTAssertNil(FinderDeepLink.url(forItemAt: ""))
    }
}
