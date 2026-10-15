import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

final class MemoryNotifiedStore: NotifiedStore {
    var saved: Set<String> = []
    init(_ initial: Set<String> = []) { saved = initial }
    func load() -> Set<String> { saved }
    func save(_ identities: Set<String>) { saved = identities }
}

@Suite("Critical notifications")
struct CriticalNotificationTests {
    static func reason(_ category: AttentionCategory, subject: String = "g1", path: String? = "/Users/me/Docs", kind: AttentionKind = .permanent, action: ProductAction = .reviewConflict) -> AttentionReason {
        AttentionReason(category: category, subject: subject, folderLocalPath: path, raw: "x", kind: kind, primaryAction: action)
    }

    static func snapshot(_ reasons: [AttentionReason]) -> StatusSnapshot {
        Fixtures.snapshot(reasons: reasons, folders: [Fixtures.folder("Docs", path: "/Users/me/Docs"), Fixtures.folder("Photos", path: "/Users/me/Photos")])
    }

    @Test func newConflictNotifiesOnceAndNotAgainWhileActive() {
        let planner = CriticalNotificationPlanner(store: MemoryNotifiedStore())
        #expect(planner.plan(for: Self.snapshot([])).isEmpty)
        let first = planner.plan(for: Self.snapshot([Self.reason(.conflict)]))
        #expect(first.count == 1)
        #expect(first[0].title == "Conflicting copies")
        #expect(first[0].body == "Docs has conflicting copies of some files.")
        #expect(first[0].action == .reviewConflict)
        #expect(first[0].folderLocalPath == "/Users/me/Docs")
        #expect(planner.plan(for: Self.snapshot([Self.reason(.conflict)])).isEmpty)
    }

    @Test func diskFullStopNotifies() {
        let planner = CriticalNotificationPlanner(store: MemoryNotifiedStore())
        let notices = planner.plan(for: Self.snapshot([Self.reason(.lowDiskCritical, subject: "/", path: nil, action: .freeUpSpace)]))
        #expect(notices.count == 1)
        #expect(notices[0].title == "Disk almost full")
        #expect(notices[0].action == .freeUpSpace)
    }

    @Test func differentScopesAreDifferentIdentities() {
        let planner = CriticalNotificationPlanner(store: MemoryNotifiedStore())
        _ = planner.plan(for: Self.snapshot([Self.reason(.conflict)]))
        let more = planner.plan(for: Self.snapshot([Self.reason(.conflict), Self.reason(.conflict, subject: "g2", path: "/Users/me/Photos")]))
        #expect(more.count == 1)
        #expect(more[0].folderLocalPath == "/Users/me/Photos")
    }

    @Test func restartDoesNotRepeatPreExistingItemsButAnnouncesUnseenOnes() {
        let store = MemoryNotifiedStore()
        let before = CriticalNotificationPlanner(store: store)
        _ = before.plan(for: Self.snapshot([Self.reason(.conflict)]))

        let after = CriticalNotificationPlanner(store: store)
        let notices = after.plan(for: Self.snapshot([Self.reason(.conflict), Self.reason(.ownershipLost, subject: "g2", path: "/Users/me/Photos", action: .viewDetails)]))
        #expect(notices.map(\.title) == ["Folder access lost"])
    }

    @Test func resolvingIsSilentAndReappearingIsNewAgain() {
        let store = MemoryNotifiedStore()
        let planner = CriticalNotificationPlanner(store: store)
        _ = planner.plan(for: Self.snapshot([Self.reason(.conflict)]))
        #expect(planner.plan(for: Self.snapshot([])).isEmpty)
        #expect(store.saved.isEmpty)
        #expect(planner.plan(for: Self.snapshot([Self.reason(.conflict)])).count == 1)
    }

    @Test func waitingAndOrdinaryKindsNeverNotify() {
        let planner = CriticalNotificationPlanner(store: MemoryNotifiedStore())
        let notices = planner.plan(for: Self.snapshot([
            Self.reason(.peerDisconnected, subject: "dev", path: nil, kind: .waiting, action: .viewDetails),
            Self.reason(.fetchUnavailable, kind: .waiting),
            Self.reason(.durabilityUnknown, kind: .waiting),
            Self.reason(.degraded, kind: .retryable, action: .retry),
            Self.reason(.recentError, subject: "", path: nil, kind: .retryable, action: .retry),
            Self.reason(.lowDisk, subject: "/", path: nil, action: .freeUpSpace),
            Self.reason(.held),
            Self.reason(.durabilityAtRisk),
            Self.reason(.unrecognized, subject: "", path: nil),
            // A critical category that is only waiting is not critical.
            Self.reason(.conflict, kind: .waiting),
        ]))
        #expect(notices.isEmpty)
    }

    @Test func manyNewItemsCollapseToOneSummary() {
        let planner = CriticalNotificationPlanner(store: MemoryNotifiedStore())
        let reasons = (0..<5).map { Self.reason(.conflict, subject: "g\($0)", path: "/p/\($0)") }
        let notices = planner.plan(for: Self.snapshot(reasons))
        #expect(notices.count == 1)
        #expect(notices[0].identity == "summary")
        #expect(notices[0].body == "5 issues need attention.")
        #expect(planner.plan(for: Self.snapshot(reasons)).isEmpty)
    }

    @Test func actionsMapToTheSameRemediationAsTheWindow() {
        #expect(NotificationRoute.route(for: .reviewConflict, folderLocalPath: "/a") == .showFolder("/a"))
        #expect(NotificationRoute.route(for: .reviewConflict, folderLocalPath: nil) == .openHome)
        #expect(NotificationRoute.route(for: .freeUpSpace, folderLocalPath: nil) == .openStorage)
        #expect(NotificationRoute.route(for: .revealPath, folderLocalPath: "/a") == .revealInFinder("/a"))
        #expect(NotificationRoute.route(for: .retry, folderLocalPath: "/a") == .refresh)
        #expect(NotificationRoute.route(for: .openSettings, folderLocalPath: nil) == .openSettings)
        #expect(ProductAction.freeUpSpace.notificationButtonTitle == "Free Up Space")
    }

    @Test func defaultsStoreRoundTrips() {
        let defaults = UserDefaults(suiteName: "critical-notifications-test")!
        defaults.removePersistentDomain(forName: "critical-notifications-test")
        let store = DefaultsNotifiedStore(defaults: defaults)
        #expect(store.load().isEmpty)
        store.save(["a", "b"])
        #expect(store.load() == ["a", "b"])
    }
}
