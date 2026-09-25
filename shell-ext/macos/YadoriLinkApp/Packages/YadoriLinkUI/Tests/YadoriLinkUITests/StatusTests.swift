import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("App status and daemon banner")
struct AppStatusTests {
    @Test func daemonDownShowsOneBannerAndNoSpinnerOrEmptyState() async throws {
        let (app, _) = try await startedApp(.daemonDown)
        let home = HomeViewModel(app: app)

        #expect(app.banner == .daemonUnavailable)
        #expect(home.showsLoading == false)
        #expect(home.showsNoFoldersMessage == false)
        #expect(home.folderRows.isEmpty)
        #expect(home.showsDevicesSection == false)
        #expect(home.showsTransfersSection == false)
    }

    @Test func daemonBannerWordingAndSingleAction() {
        #expect(AppBanner.daemonUnavailable.title == "YadoriLink isn't running.")
        #expect(AppBanner.daemonUnavailable.actionTitle == "Start YadoriLink")
        #expect(AppBanner.signedOut.title == "You're signed out.")
        #expect(AppBanner.signedOut.actionTitle == "Sign In…")
    }

    @Test func startActionBringsStatusBack() async throws {
        let (app, client) = try await startedApp(.daemonDown)
        await app.startDaemon()
        try await waitUntil("snapshot after start") { app.snapshot != nil }
        #expect(app.banner == nil)
        #expect(client.calls.contains("startDaemon"))
        #expect(HomeViewModel(app: app).folderRows.count == 3)
    }

    @Test func failedStartKeepsBannerAndSaysWhy() async throws {
        let (app, client) = try await startedApp(.daemonDown)
        client.setFailure("startDaemon", .daemonUnavailable(message: "launchctl kickstart failed", reason: .notRunning))
        await app.startDaemon()
        #expect(app.banner == .daemonUnavailable)
        #expect(app.notice?.kind == .failure)
        #expect(app.notice?.detail == "launchctl kickstart failed")
    }

    @Test func daemonGoingAwayReplacesSnapshot() async throws {
        let (app, client) = try await startedApp(.healthy)
        #expect(app.snapshot != nil)
        client.setDaemonRunning(false)
        try await waitUntil("banner") { app.banner == .daemonUnavailable }
        #expect(app.snapshot == nil)
    }

    @Test func loadingOnlyBeforeFirstResult() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let app = AppModel(client: client, pollInterval: 0.05)
        #expect(HomeViewModel(app: app).showsLoading)
        app.start()
        try await waitUntil { app.snapshot != nil }
        #expect(HomeViewModel(app: app).showsLoading == false)
    }

    @Test func signedOutBannerWhenDaemonIsUp() async throws {
        let (app, _) = try await startedApp(.signedOut)
        #expect(app.banner == .signedOut)
        #expect(HomeViewModel(app: app).showsDevicesSection == false, "devices need sign-in")
    }

    @Test func daemonBannerWinsOverSignedOut() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.setDaemonRunning(false)
        let app = AppModel(client: client, pollInterval: 0.05)
        app.start()
        try await waitUntil { app.status != .loading && app.account != nil }
        #expect(app.banner == .daemonUnavailable)
    }

    @Test func onDemandSetChangeIsReportedButNotWhileDaemonDown() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let app = AppModel(client: client, pollInterval: 0.05)
        var reported: [Set<String>] = []
        app.onDemandGroupsChanged = { reported.append($0) }
        app.start()
        try await waitUntil { reported.count == 1 }
        #expect(reported[0] == ["g-photos"])

        client.setDaemonRunning(false)
        try await waitUntil { app.banner == .daemonUnavailable }
        #expect(reported.count == 1)

        client.setDaemonRunning(true)
        try await waitUntil { app.snapshot != nil }
        #expect(reported.count == 1, "same set again is not a change")

        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        await app.setMode(.onDemand, for: docs)
        try await waitUntil { reported.count == 2 }
        #expect(reported[1] == ["g-photos", "g-documents"])
    }

    @Test func pauseAllThenResumeAll() async throws {
        let (app, _) = try await startedApp(.healthy)
        #expect(MenuBarPresentation(app: app).pauseTitle == "Pause Syncing")
        await app.setAllPaused(true)
        try await waitUntil { app.snapshot?.folders.allSatisfy(\.paused) == true }
        #expect(MenuBarPresentation(app: app).pauseTitle == "Resume Syncing")
    }
}

@MainActor
@Suite("Home")
struct HomeTests {
    @Test func headlineIsPlainSentence() async throws {
        #expect(HomeViewModel(app: try await startedApp(.healthy).0).headline == "All folders up to date")
        #expect(HomeViewModel(app: try await startedApp(.syncing).0).headline == "Syncing 1 folder")
        #expect(HomeViewModel(app: try await startedApp(.problem).0).headline == "4 issues need attention")
        #expect(HomeViewModel(app: try await startedApp(.empty).0).headline == "No folders yet")
    }

    @Test func emptyStateOnlyWhenReallyEmpty() async throws {
        let home = HomeViewModel(app: try await startedApp(.empty).0)
        #expect(home.showsNoFoldersMessage)
        #expect(home.showsLoading == false)
    }

    @Test func folderRowSummaryIsOneQuietLine() async throws {
        let home = HomeViewModel(app: try await startedApp(.healthy).0)
        let photos = try #require(home.folderRows.first { $0.name == "Photos" })
        #expect(photos.summary == "Protected · 2 devices · \(Format.bytes(182 * Fixtures.gib)) free")
        #expect(photos.detail == nil, "no detail line while protected")
        #expect(photos.pathTooltip == "/Users/me/Photos")
        let docs = try #require(home.folderRows.first { $0.name == "Documents" })
        #expect(docs.summary.contains("1 device ·"))
    }

    @Test func detailLineOnlyWhenNotProtected() async throws {
        let home = HomeViewModel(app: try await startedApp(.problem).0)
        let docs = try #require(home.folderRows.first { $0.name == "Documents" })
        #expect(docs.detail == "No other device has a complete copy yet.")
        #expect(docs.summary.hasPrefix("At risk · No devices"))
        #expect(home.folderRows.filter { $0.detail != nil }.count == 1)
    }

    @Test func diskLabelHidesOkAndFlagsLow() {
        #expect(Format.freeSpace(VolumeSummary(path: "/", state: .ok, availableBytes: 5 * Fixtures.gib, headroomBytes: 0)) == "\(Format.bytes(5 * Fixtures.gib)) free")
        #expect(Format.freeSpace(VolumeSummary(path: "/", state: .low, availableBytes: 5 * Fixtures.gib, headroomBytes: 0)) == "Only \(Format.bytes(5 * Fixtures.gib)) free")
        #expect(Format.freeSpaceIsWarning(.low))
        #expect(Format.freeSpaceIsWarning(.ok) == false)
    }

    @Test func transfersSectionOnlyWhileTransferring() async throws {
        #expect(HomeViewModel(app: try await startedApp(.healthy).0).showsTransfersSection == false)
        let syncing = HomeViewModel(app: try await startedApp(.syncing).0)
        #expect(syncing.showsTransfersSection)
        let photos = try #require(syncing.folderRows.first { $0.name == "Photos" })
        #expect(photos.progress != nil)
    }

    @Test func attentionReasonsArePlainSentencesWithRawTooltip() async throws {
        let home = HomeViewModel(app: try await startedApp(.problem).0)
        let lines = home.attentionLines
        #expect(lines.map(\.text).contains("Documents has conflicting copies of some files."))
        #expect(lines.map(\.text).contains("Office iMac is offline.") || lines.map(\.text).contains("A device is offline."))
        #expect(lines.allSatisfy { !$0.text.contains(":") })
        #expect(lines.first?.tooltip.contains(":") == true)
    }

    @Test func devicesLoadOnceAndEmptyStateNeedsASuccessfulFetch() async throws {
        let (app, client) = try await startedApp(.healthy)
        let home = HomeViewModel(app: app)
        #expect(home.showsNoDevicesMessage == false)
        await home.loadDevices()
        #expect(home.deviceRows.map(\.name) == ["Studio", "Office iMac"])
        #expect(home.deviceRows.first?.tooltip == Fixtures.studioId)

        client.setFailure("listFolderDevices", .network(message: "timeout", kind: .unreachable))
        let failing = HomeViewModel(app: app)
        await failing.loadDevices()
        #expect(failing.showsNoDevicesMessage == false)
        #expect(failing.devicesError != nil)
    }
}

@MainActor
@Suite("Menu bar")
struct MenuBarTests {
    @Test func headlineAndRowsPerState() async throws {
        let healthy = MenuBarPresentation(app: try await startedApp(.healthy).0)
        #expect(healthy.headline == "All folders up to date")
        #expect(healthy.folders.count == 3)
        #expect(healthy.canPause)

        let down = MenuBarPresentation(app: try await startedApp(.daemonDown).0)
        #expect(down.headline == "YadoriLink isn't running.")
        #expect(down.showsStartAction)
        #expect(down.canPause == false)
        #expect(down.folders.isEmpty)

        let syncing = MenuBarPresentation(app: try await startedApp(.syncing).0)
        #expect(syncing.transferLine == "Receiving 2 files · 26%")
    }

    @Test func pluralization() {
        #expect(Plural.devices(0) == "No devices")
        #expect(Plural.devices(1) == "1 device")
        #expect(Plural.devices(2) == "2 devices")
        #expect(Plural.files(1) == "1 file")
        #expect(Plural.files(1204) == "1,204 files")
        #expect(Plural.folders(1) == "1 folder")
        #expect(Plural.issues(1) == "1 issue needs attention")
        #expect(Plural.issues(3) == "3 issues need attention")
    }
}
