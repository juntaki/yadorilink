import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Sign-in flow")
struct SignInTests {
    @Test func fullFlowOpensBothBrowserPagesInOrderAndSignsIn() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        var opened: [URL] = []
        let model = SignInModel(client: client, openURL: { opened.append($0) })
        await model.run()
        #expect(opened.map(\.absoluteString) == [
            "https://auth.example.invalid/approve?d=1",
            "https://auth.example.invalid/authorize?s=2",
        ])
        #expect(model.phase == .signedIn)
        #expect(await client.accountStatus().signIn == .signedIn)
    }

    @Test func phasesFollowEvents() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.loginScript = [
            .init(.enrolling),
            .init(.openBrowser(url: "https://auth.example.invalid/a", purpose: .approveDevice)),
            .init(.waitingForApproval(expiresIn: 600)),
        ]
        let model = SignInModel(client: client, openURL: { _ in })
        let task = Task { await model.run() }
        try await waitUntil { model.phase == .waitingForApproval }
        #expect(model.statusText == "Approve this Mac in your browser.")
        model.cancel()
        await task.value
        #expect(model.phase == .cancelled)
    }

    @Test func cancelWhileWaitingForBrowserStoresNothing() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.loginScript = Array(Fixtures.loginEvents().prefix(5)).map { .init($0) }
        var opened = 0
        let model = SignInModel(client: client, openURL: { _ in opened += 1 })
        let task = Task { await model.run() }
        try await waitUntil { model.phase == .waitingForAuthorization }
        model.cancel()
        await task.value
        #expect(model.phase == .cancelled)
        #expect(opened == 2)
        #expect(await client.accountStatus().signIn == .signedOut)
        #expect(model.canRetry)
    }

    @Test func failedEventShowsSharedErrorStyle() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.loginScript = [.init(.enrolling), .init(.failed(error: .network(message: "timed out waiting for browser sign-in", kind: .unreachable)))]
        let model = SignInModel(client: client, openURL: { _ in })
        await model.run()
        #expect(model.phase == .failed(ErrorWording.text(.network(message: "", kind: .unreachable))))
        #expect(model.errorDetail == "timed out waiting for browser sign-in")
    }

    @Test func beginErrorFailsWithoutEvents() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.loginBeginError = .permissionDenied(message: "already enrolled; sign out first", reason: .sessionRejected)
        let model = SignInModel(client: client, openURL: { _ in })
        await model.run()
        if case .failed = model.phase {} else { Issue.record("expected failed, got \(model.phase)") }
    }
}

@MainActor
@Suite("Settings")
struct SettingsTests {
    @Test func bandwidthInvalidInputShowsErrorAndDisablesSave() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = BandwidthModel(client: app.client)
        await model.load()
        #expect(model.canSave == false, "unchanged")
        model.uploadText = "abc"
        #expect(model.uploadError == "Enter a number")
        #expect(model.canSave == false)
        model.uploadText = "2.5"
        #expect(model.uploadError == nil)
        #expect(model.canSave)
        await model.save()
        #expect(await (try? app.client.bandwidthLimits())?.uploadBytesPerSec == UInt64(2.5 * 1_048_576))
        #expect(model.canSave == false, "saved value is the new baseline")
        model.uploadText = ""
        #expect(model.uploadError == nil, "empty means unlimited")
        #expect(model.canSave)
    }

    @Test func updateHeadline() async throws {
        let (upToDate, _) = try await startedApp(.healthy)
        let a = UpdatesModel(client: upToDate.client, now: { Fixtures.now })
        await a.load()
        #expect(a.headline == "YadoriLink 0.4.2 is up to date")
        #expect(a.lastChecked == "Last checked 1 hour ago")
        #expect(a.canInstall == false)

        let (available, _) = try await startedApp(.updateAvailable)
        let b = UpdatesModel(client: available.client, now: { Fixtures.now })
        await b.load()
        #expect(b.headline == "Update 0.4.3 available")
        #expect(b.canInstall)
    }

    @Test func loginItemReflectsStatusAndRoutesApprovalToSystemSettings() {
        let service = FakeLoginItemService(status: .notRegistered)
        let model = LoginItemModel(service: service)
        #expect(model.isOn == false)
        model.setOn(true)
        #expect(service.registerCalls == 1)
        #expect(model.isOn)

        let pending = FakeLoginItemService(status: .requiresApproval)
        let pendingModel = LoginItemModel(service: pending)
        #expect(pendingModel.needsApproval)
        #expect(pendingModel.isOn, "registered but waiting for approval still reads as on")
        pendingModel.openSystemSettings()
        #expect(pending.openedSystemSettings == 1)
    }

    @Test func loginItemFailureIsShown() {
        struct Nope: Error {}
        let service = FakeLoginItemService(status: .notRegistered)
        service.registerError = Nope()
        let model = LoginItemModel(service: service)
        model.setOn(true)
        #expect(model.isOn == false)
        #expect(model.errorText != nil)
    }
}

@MainActor
@Suite("Account")
struct AccountTests {
    @Test func signedOutShowsOneBannerAndDisablesSections() async throws {
        let (app, client) = try await startedApp(.signedOut)
        let model = AccountViewModel(app: app)
        await model.load()
        #expect(model.banner == .signedOut)
        #expect(model.sectionsEnabled == false)
        #expect(model.devices.isEmpty)
        #expect(model.errorText == nil, "no repeated per-section errors")
        #expect(!client.calls.contains("listAccountDevices"))
    }

    @Test func signedInLoadsDevices() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = AccountViewModel(app: app)
        await model.load()
        #expect(model.banner == nil)
        #expect(model.sectionsEnabled)
        #expect(model.devices.map(\.name) == ["MacBook Air", "Studio", "Office iMac"])
    }

    @Test func credentialStoreProblemIsItsOwnBanner() async throws {
        let (app, _) = try await startedApp(.credentialStoreUnusable)
        #expect(app.banner == .credentialStoreUnusable)
        #expect(AccountViewModel(app: app).sectionsEnabled == false)
    }
}

@MainActor
@Suite("Devices and sharing")
struct DevicesAndShareTests {
    @Test func removeDeviceBlockedOffersOverrideThenWarnsAboutDataLoss() async throws {
        let (app, _) = try await startedApp(.durabilityBlockedRevoke)
        let model = DevicesViewModel(app: app)
        await model.load()
        let studio = try #require(model.devices.first { $0.name == "Studio" })
        await model.remove(studio)
        let override = try #require(model.pendingOverride)
        #expect(override.buttonTitle == "Remove anyway and accept the risk")
        await model.confirmOverride()
        #expect(model.pendingOverride == nil)
        #expect(model.warnings.contains(MembershipWarning.forcedRemoval))
        #expect(!model.devices.contains { $0.name == "Studio" })
    }

    @Test func unknownScopeWarningIsShown() {
        let warnings = MembershipWarning.warnings(for: MembershipOutcome(handoffs: [], forcedGroupIds: [], unknownScopeOperationId: "op-9"))
        #expect(warnings == [.unknownScope(operationId: "op-9")])
        #expect(MembershipWarning.warnings(for: MembershipOutcome(handoffs: [], forcedGroupIds: [], unknownScopeOperationId: nil)).isEmpty)
    }

    @Test func thisDeviceCannotBeRemoved() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = DevicesViewModel(app: app)
        await model.load()
        #expect(model.devices.first { $0.isThisDevice }?.canRemove == false)
        #expect(model.devices.first { !$0.isThisDevice }?.canRemove == true)
    }

    @Test func mintedLinkCollapsesTheForm() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = ShareViewModel(client: app.client, groupId: "g-docs", folderName: "Documents")
        await model.load()
        #expect(model.showsCreateForm)
        await model.createInvite()
        #expect(model.invite?.url == "yadorilink://invite/K7QX-M2PA")
        #expect(model.showsCreateForm == false)
        #expect(model.showsQRCode == false, "QR is behind a disclosure")
    }

    @Test func roleChangeAppliesImmediately() async throws {
        let (app, client) = try await startedApp(.healthy)
        let model = ShareViewModel(client: client, groupId: "g-docs", folderName: "Documents")
        await model.load()
        let phone = try #require(model.members.first { $0.name == "Aki's iPhone" })
        #expect(phone.role == .viewer)
        await model.setRole(.editor, for: phone)
        #expect(client.calls.contains("changeMemberRole"))
        #expect(model.members.first { $0.name == "Aki's iPhone" }?.role == .editor)
        _ = app
    }

    /// The Mac showing the list is running, so it is never drawn offline,
    /// whatever the coordination service last observed of it.
    @Test func thisMacIsNeverShownOfflineInTheDeviceLists() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setDevices([
            DeviceSummary(deviceId: Fixtures.thisDeviceId, displayName: "MacBook Air", online: false, lastSeen: nil, isThisDevice: true),
            DeviceSummary(deviceId: Fixtures.studioId, displayName: "Studio", online: false, lastSeen: nil, isThisDevice: false),
        ])
        let model = DevicesViewModel(app: app)
        await model.load()
        #expect(model.devices.first { $0.isThisDevice }?.online == true)
        #expect(model.devices.first { !$0.isThisDevice }?.online == false)

        let rows = [DeviceSummary(deviceId: Fixtures.thisDeviceId, displayName: "MacBook Air", online: false, lastSeen: nil, isThisDevice: true)]
            .map { DeviceRow($0, now: Fixtures.now) }
        #expect(rows.first?.online == true)
    }

    @Test func thisMacIsNeverShownOfflineAmongPeopleWithAccess() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setMembers([
            MemberSummary(deviceId: Fixtures.thisDeviceId, deviceName: "MacBook Air", role: .owner, relationship: .you, storage: .fullCopy, online: false, lastSeen: nil),
            MemberSummary(deviceId: Fixtures.studioId, deviceName: "Studio", role: .editor, relationship: .yourOtherDevice, storage: .fullCopy, online: false, lastSeen: nil),
        ], groupId: "g-docs")
        let model = ShareViewModel(client: app.client, groupId: "g-docs", folderName: "Documents")
        await model.load()
        #expect(model.members.first { $0.id == Fixtures.thisDeviceId }?.online == true)
        #expect(model.members.first { $0.id == Fixtures.studioId }?.online == false)
    }

    @Test func pendingRequestsShowNamesNotIds() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = ShareViewModel(client: app.client, groupId: "g-docs", folderName: "Documents")
        await model.load()
        let request = try #require(model.requests.first)
        #expect(!request.title.contains("d-aa11bb22cc33dd44ee55ff6600778899"))
        #expect(request.tooltip == "d-aa11bb22cc33dd44ee55ff6600778899")
    }
}

@MainActor
@Suite("Transfers")
struct TransfersTests {
    @Test func inboxLoadingOnlyWhileInFlightAndEmptyOnlyAfterFetch() async throws {
        let (app, client) = try await startedApp(.empty)
        let model = TransfersViewModel(app: app)
        #expect(model.showsInboxLoading == false)
        #expect(model.showsInboxEmpty == false, "not fetched yet")
        await model.loadInbox()
        #expect(model.showsInboxLoading == false)
        #expect(model.showsInboxEmpty)

        client.setFailure("listInbox", Fixtures.daemonDownError)
        let failing = TransfersViewModel(app: app)
        await failing.loadInbox()
        #expect(failing.showsInboxLoading == false)
        #expect(failing.showsInboxEmpty == false)
    }

    @Test func inboxRowsUseWordsAndNames() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = TransfersViewModel(app: app)
        await model.loadDevices()
        await model.loadInbox()
        let row = try #require(model.inboxRows.first)
        #expect(row.title == "From Studio: 2 files, \(Format.bytes(18 * Fixtures.mib + 2_048))")
        #expect(row.status == "Waiting")
        #expect(row.tooltip == "t-81f2")
    }

    @Test func sentMessageNamesDevice() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = TransfersViewModel(app: app)
        await model.loadDevices()
        model.sourcePath = "/Users/me/Desktop/report.pdf"
        model.targetDeviceId = Fixtures.studioId
        await model.send()
        #expect(model.notice?.text == "Sent to Studio: 1 file, \(Format.bytes(3 * Fixtures.mib))")
    }

    @Test func syncTransfersComeFromStatus() async throws {
        let (app, _) = try await startedApp(.syncing)
        let model = TransfersViewModel(app: app)
        #expect(model.syncRows.count == 2)
        #expect(model.syncRows.first?.title == "IMG_4410.HEIC")
    }
}

@MainActor
@Suite("Onboarding")
struct OnboardingTests {
    @Test func firstRunStepsAndLoginItemDefaultOn() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        let loginItems = FakeLoginItemService(status: .notRegistered)
        let model = OnboardingViewModel(client: client, mode: .firstRun, loginItem: LoginItemModel(service: loginItems), openURL: { _ in })
        await model.prepare()
        #expect(model.steps == [.welcome, .signIn, .chooseFolder, .review, .done])
        #expect(model.startAtLogin, "default on")
        #expect(model.startAtLoginTitle == "Open at login", "the same words as the Settings toggle")
        #expect(model.startAtLoginTitle == SettingWording.openAtLogin)
        model.finish()
        #expect(loginItems.registerCalls == 1)
    }

    @Test func uncheckedLoginItemIsNotRegistered() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let loginItems = FakeLoginItemService(status: .notRegistered)
        let model = OnboardingViewModel(client: client, mode: .firstRun, loginItem: LoginItemModel(service: loginItems), openURL: { _ in })
        await model.prepare()
        #expect(model.steps == [.welcome, .chooseFolder, .review, .done], "already signed in skips sign-in")
        model.startAtLogin = false
        model.finish()
        #expect(loginItems.registerCalls == 0)
    }

    @Test func stepListSaysEachStepsProgressForVoiceOver() async throws {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        let model = OnboardingViewModel(client: client, mode: .firstRun, loginItem: LoginItemModel(service: FakeLoginItemService()), openURL: { _ in })
        await model.prepare()
        model.next()
        #expect(model.step == .signIn)
        #expect(model.progress(of: .welcome) == "Done")
        #expect(model.progress(of: .signIn) == "Current step")
        #expect(model.progress(of: .done) == "Not started")
    }

    @Test func addFolderModeShowsTwoSteps() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let model = OnboardingViewModel(client: client, mode: .addFolder, loginItem: LoginItemModel(service: FakeLoginItemService()), openURL: { _ in })
        await model.prepare()
        #expect(model.steps == [.chooseFolder, .review])
    }

    @Test func riskyFolderNeedsAcknowledgementBeforeLinking() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        client.preflightResults["/Users/me/Big"] = PreflightResult(resolvedPath: "/Users/me/Big", pathExists: true, isDirectory: true, entryCount: 42, ignoredEntryCount: 0, totalSizeBytes: 9 * Fixtures.gib, scanTruncated: false, freeSpace: nil, issues: [.notEmpty(entryCount: 42, scanTruncated: false)], requiresAcknowledgement: true)
        let model = OnboardingViewModel(client: client, mode: .addFolder, loginItem: LoginItemModel(service: FakeLoginItemService()), openURL: { _ in })
        await model.prepare()
        await model.chooseFolder("/Users/me/Big")
        #expect(model.step == .review)
        #expect(model.issueLines == ["This folder already has 42 items. They will be shared too."])
        #expect(model.canLink == false)
        model.acknowledgedRisks = true
        #expect(model.canLink)
        model.folderMode = .keepAll
        await model.link()
        #expect(model.linked != nil)
    }

    @Test func destinationsReadAsOptions() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let model = OnboardingViewModel(client: client, mode: .addFolder, loginItem: LoginItemModel(service: FakeLoginItemService()), openURL: { _ in })
        await model.prepare()
        #expect(model.destinations.map(\.title) == ["New shared folder", "Sync into: Documents", "Sync into: Photos"])
    }
}
