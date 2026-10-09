import Foundation
import Observation
import YadoriLinkModel

// MARK: - Sign-in

/// Drives one browser sign-in: begins the session, opens each browser page
/// it asks for, and follows its events until a terminal one.
@MainActor
@Observable
public final class SignInModel {
    public enum Phase: Equatable, Sendable {
        case idle
        case starting
        case waitingForApproval
        case waitingForAuthorization
        case deviceCode(verificationUri: String, userCode: String)
        case signedIn
        case failed(String)
        case cancelled
    }

    public private(set) var phase: Phase = .idle
    public private(set) var errorDetail: String?
    /// Called once with the new account when sign-in completes.
    @ObservationIgnored public var onSignedIn: ((AccountStatus) -> Void)?

    @ObservationIgnored private let client: any YadoriLinkClient
    @ObservationIgnored private let openURL: (URL) -> Void
    @ObservationIgnored private var session: (any LoginSessionHandle)?

    public init(client: any YadoriLinkClient, openURL: @escaping (URL) -> Void) {
        self.client = client
        self.openURL = openURL
    }

    public var isRunning: Bool {
        switch phase {
        case .starting, .waitingForApproval, .waitingForAuthorization, .deviceCode: true
        default: false
        }
    }

    public var canRetry: Bool {
        switch phase {
        case .failed, .cancelled: true
        default: false
        }
    }

    public var statusText: String {
        switch phase {
        case .idle: ""
        case .starting: "Connecting…"
        case .waitingForApproval: "Approve this Mac in your browser."
        case .waitingForAuthorization: "Finish signing in in your browser."
        case .deviceCode(let uri, let code): "Go to \(uri) and enter \(code)."
        case .signedIn: "You're signed in."
        case .failed(let text): text
        case .cancelled: "Sign-in was cancelled."
        }
    }

    /// Runs the whole flow; returns after a terminal event.
    public func run() async {
        guard !isRunning else { return }
        errorDetail = nil
        phase = .starting
        let session = client.newLoginSession(options: LoginOptions(flow: .loopback, overallTimeout: 300))
        self.session = session
        defer { self.session = nil }
        do {
            try session.begin()
        } catch {
            fail(error)
            return
        }
        while let event = await session.nextEvent() {
            handle(event)
            if event.isTerminal { break }
        }
    }

    public func cancel() {
        session?.cancel()
    }

    private func handle(_ event: LoginEvent) {
        switch event {
        case .enrolling:
            phase = .starting
        case .openBrowser(let url, _):
            if let url = URL(string: url) { openURL(url) }
        case .waitingForApproval:
            phase = .waitingForApproval
        case .waitingForAuthorization:
            phase = .waitingForAuthorization
        case .showDeviceCode(let uri, let code):
            phase = .deviceCode(verificationUri: uri, userCode: code)
        case .signedIn(let account):
            phase = .signedIn
            onSignedIn?(account)
        case .failed(let error):
            fail(error)
        case .cancelled:
            phase = .cancelled
        }
    }

    private func fail(_ error: Error) {
        let notice = Notice.failure(error)
        phase = .failed(notice.text)
        errorDetail = notice.detail
    }
}

// MARK: - Account

@MainActor
@Observable
public final class AccountViewModel {
    public let app: AppModel
    public private(set) var devices: [DeviceRow] = []
    public private(set) var deletion: AccountDeletionStatus?
    public private(set) var deletionToken: String?
    public private(set) var isWorking = false
    public var notice: Notice?
    @ObservationIgnored private let now: () -> Date

    public init(app: AppModel, now: @escaping () -> Date = Date.init) {
        self.app = app
        self.now = now
    }

    /// Only the sign-in banners; the account does not need the daemon.
    public var banner: AppBanner? {
        switch app.account?.signIn {
        case .signedOut: .signedOut
        case .credentialStoreUnusable: .credentialStoreUnusable
        default: nil
        }
    }

    /// Every section below the banner is disabled while signed out.
    public var sectionsEnabled: Bool { app.isSignedIn }

    /// One error at the top, never repeated per section.
    public var errorText: String? {
        if case .failure = notice?.kind { return notice?.text }
        return nil
    }

    public func load() async {
        guard sectionsEnabled else {
            devices = []
            return
        }
        do {
            devices = try await app.client.listAccountDevices().map { DeviceRow($0, now: now()) }
            deletion = try await app.client.accountDeletionStatus()
        } catch {
            notice = .failure(error)
        }
    }

    public func signOut() async {
        await work {
            _ = try await self.app.client.signOut()
            await self.app.refreshAccount()
            self.devices = []
            return "Signed out."
        }
    }

    public func exportData(to url: URL) async {
        await work {
            let json = try await self.app.client.exportAccountData()
            do {
                try Data(json.utf8).write(to: url)
            } catch {
                throw DesktopError.internal(message: error.localizedDescription, category: "io")
            }
            return "Saved your data to \(url.lastPathComponent)."
        }
    }

    public func requestDeletion() async {
        await work {
            let request = try await self.app.client.requestAccountDeletion()
            self.deletionToken = request.confirmationToken
            return "Check the code below, then confirm to delete your account."
        }
    }

    public func confirmDeletion() async {
        guard let token = deletionToken else { return }
        await work {
            self.deletion = try await self.app.client.confirmAccountDeletion(confirmationToken: token)
            self.deletionToken = nil
            return "Your account will be deleted at the end of the grace period."
        }
    }

    public func cancelDeletion() async {
        await work {
            self.deletion = try await self.app.client.cancelAccountDeletion()
            return "Account deletion cancelled."
        }
    }

    public var deletionLine: String? {
        guard let deletion else { return nil }
        switch deletion.state {
        case .active: return nil
        case .requested: return "Deletion requested. Confirm it to start the grace period."
        case .grace:
            if let at = deletion.graceExpiresAt { return "Your account will be deleted \(Format.relative(at, now: now()))." }
            return "Your account is scheduled for deletion."
        case .other(let raw): return "Deletion status: \(raw)"
        }
    }

    private func work(_ body: () async throws -> String) async {
        isWorking = true
        defer { isWorking = false }
        do { notice = Notice(kind: .success, text: try await body()) } catch { notice = .failure(error) }
    }
}

// MARK: - Removing devices and access

/// Warnings the UI must show after a removal.
public enum MembershipWarning: Sendable, Equatable, Hashable {
    case forcedRemoval
    case unknownScope(operationId: String)

    public static func warnings(for outcome: MembershipOutcome) -> [MembershipWarning] {
        var warnings: [MembershipWarning] = []
        if !outcome.forcedGroupIds.isEmpty { warnings.append(.forcedRemoval) }
        if let op = outcome.unknownScopeOperationId { warnings.append(.unknownScope(operationId: op)) }
        return warnings
    }

    public var text: String {
        switch self {
        case .forcedRemoval:
            "Removed before another device had a complete copy. Files that only existed there may be lost."
        case .unknownScope(let op):
            "The server couldn't confirm which shared folders were affected. Reference: \(op)"
        }
    }
}

/// Shown when a removal was refused because no other device has a complete
/// copy yet. Confirming retries with the override.
public struct OverridePrompt: Equatable, Sendable {
    public var targetId: String
    public var targetName: String
    public var message: String
    public var buttonTitle: String { "Remove anyway and accept the risk" }
}

public struct ManagedDevice: Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var detail: String
    public var online: Bool
    public var isThisDevice: Bool
    public var canRemove: Bool { !isThisDevice }
}

@MainActor
@Observable
public final class DevicesViewModel {
    public let app: AppModel
    public private(set) var phase: FetchPhase<[ManagedDevice]> = .notLoaded
    public private(set) var warnings: [MembershipWarning] = []
    public var pendingOverride: OverridePrompt?
    public var notice: Notice?
    @ObservationIgnored private let now: () -> Date

    public init(app: AppModel, now: @escaping () -> Date = Date.init) {
        self.app = app
        self.now = now
    }

    public var banner: AppBanner? {
        switch app.account?.signIn {
        case .signedOut: .signedOut
        case .credentialStoreUnusable: .credentialStoreUnusable
        default: nil
        }
    }

    public var devices: [ManagedDevice] { phase.value ?? [] }

    public func load() async {
        guard app.isSignedIn else { return }
        if phase.value == nil { phase = .loading }
        do {
            // Folder devices carry online state but need the daemon; the
            // account list works without it.
            let list = app.isDaemonUnavailable ? try await app.client.listAccountDevices() : try await app.client.listFolderDevices()
            phase = .loaded(list.map { d in
                let row = DeviceRow(d, now: now())
                return ManagedDevice(id: d.deviceId, name: d.displayName, detail: row.detail, online: row.online, isThisDevice: d.isThisDevice)
            })
        } catch {
            phase = .failed(.failure(error))
        }
    }

    public func remove(_ device: ManagedDevice) async {
        await remove(id: device.id, name: device.name, force: false)
    }

    public func confirmOverride() async {
        guard let prompt = pendingOverride else { return }
        pendingOverride = nil
        await remove(id: prompt.targetId, name: prompt.targetName, force: true)
    }

    private func remove(id: String, name: String, force: Bool) async {
        do {
            let outcome = try await app.client.removeDevice(deviceId: id, force: force)
            warnings = MembershipWarning.warnings(for: outcome)
            if case .loaded(let list) = phase { phase = .loaded(list.filter { $0.id != id }) }
            notice = Notice(kind: .success, text: "Removed \(name).")
        } catch DesktopError.durabilityBlocked(let message, _, _, true) where !force {
            pendingOverride = OverridePrompt(targetId: id, targetName: name, message: message)
        } catch {
            notice = .failure(error)
        }
    }
}
