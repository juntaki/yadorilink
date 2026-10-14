import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Stop syncing a folder")
struct UnlinkTests {
    private func setup(_ scenario: FakeScenario = .healthy) async throws -> (UnlinkModel, AppModel, FakeYadoriLinkClient, FolderSummary) {
        let (app, client) = try await startedApp(scenario)
        let folder = try #require(app.snapshot?.folders.first)
        return (UnlinkModel(app: app), app, client, folder)
    }

    @Test func requestOnlyAsksAndCancelLeavesTheFolder() async throws {
        let (model, app, client, folder) = try await setup()
        model.request(folder)
        #expect(model.pendingConfirmation == folder)
        #expect(client.calls.contains("unlinkFolder") == false)
        model.cancel()
        #expect(model.pendingConfirmation == nil)
        #expect(client.calls.contains("unlinkFolder") == false)
        #expect(app.snapshot?.folders.contains(folder) == true)
    }

    @Test func successRefreshesStatusNotifiesOnceAndLeavesTheDetail() async throws {
        let (model, app, _, folder) = try await setup()
        var left: [String] = []
        model.onUnlinked = { left.append($0) }
        model.request(folder)
        await model.confirm()
        #expect(left == [folder.localPath])
        #expect(app.notice == Notice(kind: .success, text: UnlinkWording.success(folder)))
        try await waitUntil("folder gone from status") { app.snapshot?.folders.contains { $0.localPath == folder.localPath } == false }
    }

    @Test func contextPopsTheUnlinkedFolderRoute() async throws {
        let context = AppContext.fixture(.healthy)
        context.app.start()
        try await waitUntil("status") { context.app.snapshot != nil }
        let folder = try #require(context.app.snapshot?.folders.first)
        context.showFolder(folder.localPath)
        context.unlink.request(folder)
        await context.unlink.confirm()
        #expect(context.folderPath.isEmpty)
    }

    @Test func ordinaryFailureShowsTheNormalNoticeAndKeepsTheFolder() async throws {
        let (model, app, client, folder) = try await setup()
        client.setFailure("unlinkFolder", .network(message: "timeout", kind: .unreachable))
        var left = 0
        model.onUnlinked = { _ in left += 1 }
        model.request(folder)
        await model.confirm()
        #expect(left == 0)
        #expect(app.notice?.kind == .failure)
        #expect(model.pendingOverride == nil)
        #expect(app.snapshot?.folders.contains(folder) == true)
    }

    @Test func durabilityBlockAsksAgainAndOnlyThenForces() async throws {
        let (model, app, client, folder) = try await setup(.durabilityBlockedRevoke)
        model.request(folder)
        await model.confirm()
        #expect(model.pendingOverride == folder)
        #expect(client.calls.filter { $0 == "unlinkFolder" }.count == 1, "the first attempt is not forced and was refused")
        #expect(app.snapshot?.folders.contains(folder) == true)

        // Cancel at the override leaves the folder untouched.
        model.cancel()
        #expect(model.pendingOverride == nil)
        #expect(client.calls.filter { $0 == "unlinkFolder" }.count == 1)

        model.request(folder)
        await model.confirm()
        await model.confirmOverride()
        #expect(client.calls.filter { $0 == "unlinkFolder" }.count == 3)
        #expect(app.notice?.kind == .success)
        #expect(model.pendingOverride == nil)
    }

    @Test func wordingFollowsWhatTheFolderKindActuallyDoes() async throws {
        let (_, _, _, folder) = try await setup()
        var directory = folder
        directory.provider = false
        directory.mode = .keepAll
        let ordinary = UnlinkWording.message(directory)
        #expect(ordinary.contains("stay where they are and are not deleted"))
        #expect(ordinary.contains("not affected"))
        #expect(ordinary.contains("link it again later"))
        #expect(ordinary.contains("Finder") == false)

        var provider = folder
        provider.provider = true
        provider.localPath = "provider://root-1"
        let message = UnlinkWording.message(provider)
        #expect(message.contains("remove it from Finder"))
        #expect(message.contains("stay where they are") == false)
        #expect(message.contains(provider.localPath) == false)
        #expect(UnlinkWording.success(provider).contains("provider://") == false)
        #expect(UnlinkWording.overrideMessage(directory).contains("only on this Mac"))
    }

    @Test func providerFolderUnlinksByIdentityKeyWithoutAPath() async throws {
        let (app, client) = try await startedApp(.healthy)
        var provider = try #require(app.snapshot?.folders.first)
        provider.provider = true
        provider.localPath = "provider://root-1"
        var snapshot = try #require(app.snapshot)
        snapshot.folders.append(provider)
        client.setSnapshot(snapshot)
        try await waitUntil("provider folder visible") { app.snapshot?.folders.contains(provider) == true }
        let model = UnlinkModel(app: app)
        model.request(provider)
        await model.confirm()
        #expect(app.notice?.text.contains("asked macOS to remove it from Finder") == true)
        try await waitUntil("provider folder gone") { app.snapshot?.folders.contains(provider) == false }
    }

    @Test func providerFailureDoesNotLeakTheKeyInTheNotice() async throws {
        let (app, client) = try await startedApp(.healthy)
        var provider = try #require(app.snapshot?.folders.first)
        provider.provider = true
        provider.localPath = "provider://root-1"
        client.setFailure("unlinkFolder", .invalidInput(message: "no link at provider://root-1", field: "local_path"))
        let model = UnlinkModel(app: app)
        model.request(provider)
        await model.confirm()
        #expect(app.notice?.kind == .failure)
        #expect(app.notice?.detail == nil)
        #expect(FolderRow(provider).pathTooltip.isEmpty)
    }
}
