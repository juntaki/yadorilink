import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

private let unreachable = DesktopError.network(message: "timeout", kind: .unreachable)

@MainActor
@Suite("List loading is never a false empty state")
struct ListLoadingTests {
    private func onboarding(_ client: FakeYadoriLinkClient) -> OnboardingViewModel {
        OnboardingViewModel(client: client, mode: .addFolder, loginItem: LoginItemModel(service: FakeLoginItemService()), openURL: { _ in })
    }

    @Test func destinationFailureBlocksCreationAndRetryRecovers() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        client.setFailure("listJoinableGroups", unreachable)
        let model = onboarding(client)
        await model.prepare()
        #expect(model.destinationsError != nil)
        #expect(model.destinationsUnavailable)
        await model.chooseFolder("/Users/me/Documents")
        #expect(model.canLink == false, "no ambiguous New shared folder path while existing folders are unknown")

        client.setFailure("listJoinableGroups", nil)
        let before = client.calls.filter { $0 != "listJoinableGroups" }
        await model.retryDestinations()
        #expect(model.destinationsError == nil)
        #expect(model.destinations.map(\.title) == ["New shared folder", "Sync into: Documents", "Sync into: Photos"])
        #expect(model.canLink)
        #expect(client.calls.filter { $0 != "listJoinableGroups" } == before, "retry re-runs only the failed read")
    }

    @Test func destinationSuccessfulEmptyOffersOnlyNewSharedFolder() async throws {
        let client = FakeYadoriLinkClient(scenario: .empty)
        let model = onboarding(client)
        await model.prepare()
        #expect(model.destinationsError == nil)
        #expect(model.destinations.first?.title == "New shared folder")
    }

    @Test func transferDevicesFailureIsNotAnEmptyList() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setFailure("listFolderDevices", unreachable)
        let model = TransfersViewModel(app: app)
        await model.loadDevices()
        #expect(model.devicesError != nil)
        #expect(model.showsNoTargetDevices == false)

        client.setFailure("listFolderDevices", nil)
        await model.loadDevices()
        #expect(model.devicesError == nil)
        #expect(model.targetDevices.isEmpty == false)

        client.setFailure("listFolderDevices", unreachable)
        await model.loadDevices()
        #expect(model.targetDevices.isEmpty == false, "earlier list stays")
        #expect(model.devicesStale != nil, "but is marked as not current")
    }

    @Test func transferDevicesSuccessfulEmpty() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setDevices(Fixtures.devices.filter(\.isThisDevice))
        let model = TransfersViewModel(app: app)
        await model.loadDevices()
        #expect(model.showsNoTargetDevices)
        #expect(model.devicesError == nil)
    }

    @Test func inboxRefreshFailureKeepsRowsButFlagsThem() async throws {
        let (app, client) = try await startedApp(.healthy)
        let model = TransfersViewModel(app: app)
        await model.loadInbox()
        let rows = model.inboxRows
        #expect(rows.isEmpty == false)
        client.setFailure("listInbox", unreachable)
        await model.loadInbox()
        #expect(model.inboxRows == rows)
        #expect(model.inboxStale != nil)
        #expect(model.inboxError == nil)
        client.setFailure("listInbox", nil)
        await model.loadInbox()
        #expect(model.inboxStale == nil)
    }

    @Test func homeDevicesRefreshFailureKeepsListAndFlagsIt() async throws {
        let (app, client) = try await startedApp(.healthy)
        let home = HomeViewModel(app: app)
        await home.loadDevices()
        let rows = home.deviceRows
        client.setFailure("listFolderDevices", unreachable)
        await home.loadDevices()
        #expect(home.deviceRows == rows)
        #expect(home.devicesStale != nil)
        #expect(home.devicesError == nil)
        client.setFailure("listFolderDevices", nil)
        await home.loadDevices()
        #expect(home.devicesStale == nil)
    }

    @Test func devicesPaneFirstLoadFailureThenRetry() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setFailure("listFolderDevices", unreachable)
        let model = DevicesViewModel(app: app)
        await model.load()
        guard case .failed = model.phase else { Issue.record("expected failed"); return }
        client.setFailure("listFolderDevices", nil)
        await model.load()
        #expect(model.devices.isEmpty == false)
        client.setFailure("listFolderDevices", unreachable)
        await model.load()
        #expect(model.devices.isEmpty == false)
        #expect(model.staleNotice != nil)
    }

    @Test func accountDevicesFailureIsNotLoadingForever() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setFailure("listAccountDevices", unreachable)
        let model = AccountViewModel(app: app)
        await model.load()
        guard case .failed = model.devicesPhase else { Issue.record("expected failed"); return }
        client.setFailure("listAccountDevices", nil)
        await model.load()
        #expect(model.devices.isEmpty == false)
    }

    @Test func shareLoadFailureIsSeparateFromNotices() async throws {
        let (_, client) = try await startedApp(.healthy)
        client.setFailure("listMembers", unreachable)
        let model = ShareViewModel(client: client, groupId: "g-docs", folderName: "Documents")
        await model.load()
        #expect(model.loadFailure != nil)
        #expect(model.hasLoaded == false)
        client.setFailure("listMembers", nil)
        await model.load()
        #expect(model.loadFailure == nil)
        #expect(model.hasLoaded)
        #expect(model.members.isEmpty == false)
        client.setFailure("listPendingApprovals", unreachable)
        await model.load()
        #expect(model.loadFailure != nil)
        #expect(model.members.isEmpty == false, "earlier members stay but the load is flagged")
    }

    @Test func folderDetailFailureDoesNotClaimNoCopies() async throws {
        let (app, client) = try await startedApp(.healthy)
        let folder = try #require(app.snapshot?.folders.first)
        client.setFailure("folderDetail", unreachable)
        let model = FolderDetailViewModel(client: client, folder: folder)
        await model.load()
        #expect(model.loadFailure != nil)
        #expect(model.showsNoCopies == false)
        client.setFailure("folderDetail", nil)
        await model.load()
        #expect(model.loadFailure == nil)
    }

    @Test func emptyClaimsAreWithheldWhenARefreshFailedAfterAnEmptyRead() async throws {
        let (app, client) = try await startedApp(.empty)
        let model = TransfersViewModel(app: app)
        await model.loadInbox()
        #expect(model.showsInboxEmpty)
        client.setFailure("listInbox", unreachable)
        await model.loadInbox()
        #expect(model.showsInboxEmpty == false, "an earlier empty list is not confirmed by a failed refresh")

        let (app2, client2) = try await startedApp(.healthy)
        client2.setDevices(Fixtures.devices.filter(\.isThisDevice))
        let home = HomeViewModel(app: app2)
        await home.loadDevices()
        #expect(home.showsNoDevicesMessage)
        client2.setFailure("listFolderDevices", unreachable)
        await home.loadDevices()
        #expect(home.showsNoDevicesMessage == false)
    }

    @Test func signedOutAddFolderDoesNotOfferNewSharedFolderAsConfirmed() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        let model = onboarding(client)
        await model.prepare()
        #expect(model.destinationsUnavailable)
        #expect(model.canLink == false)
    }

    @Test func devicesPaneForgetsTheRosterWhenSignedOut() async throws {
        let (app, client) = try await startedApp(.healthy)
        let model = DevicesViewModel(app: app)
        await model.load()
        #expect(model.devices.isEmpty == false)
        client.setAccount(Fixtures.account(.signedOut, hasLinkedFolders: false))
        await app.refreshAccount()
        await model.load()
        #expect(model.devices.isEmpty)
    }

    @Test func deviceNamesFailureOffersRetryAndFileHistoryFailureIsSeparate() async throws {
        let (app, client) = try await startedApp(.healthy)
        let folder = try #require(app.snapshot?.folders.first)
        client.setFailure("listFolderDevices", unreachable)
        let model = FolderDetailViewModel(client: client, folder: folder)
        await model.load()
        #expect(model.loadFailure != nil)
        client.setFailure("listFolderDevices", nil)
        await model.load()
        #expect(model.loadFailure == nil)

        client.setFailure("listVersions", unreachable)
        await model.selectFile(folder.localPath + "/a.txt")
        #expect(model.historyFailure != nil)
        client.setFailure("listVersions", nil)
        await model.retryFileHistory()
        #expect(model.historyFailure == nil)
    }

    @Test func rostersAreDroppedOnSignOutAndNoCopiesIsWithheldAfterAFailedRetry() async throws {
        let (app, client) = try await startedApp(.healthy)
        let home = HomeViewModel(app: app)
        let transfers = TransfersViewModel(app: app)
        await home.loadDevices()
        await transfers.loadDevices()
        #expect(home.deviceRows.isEmpty == false)
        client.setAccount(Fixtures.account(.signedOut, hasLinkedFolders: false))
        await app.refreshAccount()
        await home.loadDevices()
        await transfers.loadDevices()
        #expect(home.deviceRows.isEmpty)
        #expect(transfers.targetDevices.isEmpty)

        let folder = try #require(app.snapshot?.folders.first)
        let detail = FolderDetailViewModel(client: client, folder: folder)
        await detail.load()
        client.setFailure("folderDetail", unreachable)
        await detail.load()
        #expect(detail.showsNoCopies == false)
    }
}
