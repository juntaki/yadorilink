import Foundation
import Observation
import YadoriLinkModel

/// App-wide state. Owns the one status watch; every scene reads from here,
/// so there is exactly one poll loop per process.
@MainActor
@Observable
public final class AppModel {
    public enum StatusPhase: Equatable {
        /// No answer yet. The only time a spinner is shown.
        case loading
        case ready(StatusSnapshot)
        /// The daemon did not answer. Replaces the snapshot entirely.
        case unavailable(DesktopError)
    }

    public let client: any YadoriLinkClient
    public private(set) var status: StatusPhase = .loading
    public private(set) var account: AccountStatus?
    public private(set) var isStartingDaemon = false
    /// The latest action result, shown once at the top of the window.
    public var notice: Notice?

    /// Called with the group ids of every On-Demand folder whenever that set
    /// changes. Never called while the daemon is down, so a caller that
    /// reconciles File Provider domains from it stays fail-closed.
    @ObservationIgnored public var onDemandGroupsChanged: ((Set<String>) -> Void)?

    @ObservationIgnored private let pollInterval: TimeInterval
    @ObservationIgnored private var watch: (any StatusWatchHandle)?
    @ObservationIgnored private var watchTask: Task<Void, Never>?
    @ObservationIgnored private var lastOnDemandGroups: Set<String>?

    public init(client: any YadoriLinkClient, pollInterval: TimeInterval = 2) {
        self.client = client
        self.pollInterval = pollInterval
    }

    /// Starts the status watch and loads the account. Idempotent.
    public func start() {
        guard watchTask == nil else { return }
        let watch = client.watchStatus(interval: pollInterval)
        self.watch = watch
        watchTask = Task { [weak self] in
            while let update = await watch.next() {
                guard let self else { return }
                self.apply(update)
            }
        }
        Task { await refreshAccount() }
    }

    public func stop() {
        watch?.cancel()
        watchTask?.cancel()
        watch = nil
        watchTask = nil
    }

    /// Polls now instead of waiting for the next tick. Call after a mutation.
    public func refresh() {
        watch?.refresh()
    }

    public func refreshAccount() async {
        account = await client.accountStatus()
    }

    private func apply(_ update: StatusUpdate) {
        let wasUnavailable: Bool
        if case .unavailable = status { wasUnavailable = true } else { wasUnavailable = false }
        switch update {
        case .snapshot(let snapshot):
            status = .ready(snapshot)
            let onDemand = Set(snapshot.folders.filter { $0.mode == .onDemand }.map(\.groupId))
            if onDemand != lastOnDemandGroups {
                lastOnDemandGroups = onDemand
                onDemandGroupsChanged?(onDemand)
            }
            if wasUnavailable { Task { await refreshAccount() } }
        case .unavailable(let error):
            status = .unavailable(error)
        }
    }

    // MARK: Derived state

    public var snapshot: StatusSnapshot? {
        if case .ready(let snapshot) = status { return snapshot }
        return nil
    }

    public var isDaemonUnavailable: Bool {
        if case .unavailable = status { return true }
        return false
    }

    public var isSignedIn: Bool { account?.signIn == .signedIn }

    /// At most one banner. The daemon comes first: nothing else works without it.
    public var banner: AppBanner? {
        if isDaemonUnavailable { return .daemonUnavailable }
        switch account?.signIn {
        case .signedOut: return .signedOut
        case .credentialStoreUnusable: return .credentialStoreUnusable
        case .signedIn, nil: return nil
        }
    }

    // MARK: Actions

    public func startDaemon() async {
        isStartingDaemon = true
        defer { isStartingDaemon = false }
        do {
            _ = try await client.startDaemon()
            notice = nil
            refresh()
            await refreshAccount()
        } catch {
            notice = .failure(error)
        }
    }

    public func setPaused(_ paused: Bool, for folder: FolderSummary) async {
        await perform {
            if paused { try await $0.pauseFolder(localPath: folder.localPath) } else { try await $0.resumeFolder(localPath: folder.localPath) }
        }
    }

    public func setAllPaused(_ paused: Bool) async {
        await perform {
            if paused { try await $0.pauseAll() } else { try await $0.resumeAll() }
        }
    }

    public func setMode(_ mode: FolderMode, for folder: FolderSummary) async {
        await perform { _ = try await $0.setStorageMode(groupId: folder.groupId, mode: mode) }
    }

    private func perform(_ body: (any YadoriLinkClient) async throws -> Void) async {
        do {
            try await body(client)
            notice = nil
        } catch {
            notice = .failure(error)
        }
        refresh()
    }

    // MARK: Status sentences shared by the menu bar and Home

    /// "All folders up to date", "Syncing 1 folder", "4 issues need attention".
    public var headline: String {
        switch status {
        case .loading: return "Checking status…"
        case .unavailable: return AppBanner.daemonUnavailable.title
        case .ready(let snapshot):
            if snapshot.folders.isEmpty { return "No folders yet" }
            if !snapshot.attentionReasons.isEmpty { return Plural.issues(snapshot.attentionReasons.count) }
            let syncing = snapshot.folders.filter { $0.state == .syncing }.count
            if syncing > 0 { return "Syncing \(Plural.folders(syncing))" }
            if snapshot.folders.allSatisfy(\.paused) { return "Syncing is paused" }
            return "All folders up to date"
        }
    }

    public var overallTone: StatusTone {
        switch status {
        case .loading: return .neutral
        case .unavailable: return .danger
        case .ready(let snapshot):
            switch snapshot.overall {
            case .healthy: return snapshot.folders.contains { $0.state == .syncing } ? .info : .ok
            case .attention: return .warning
            case .degraded: return .danger
            case .unknown: return .neutral
            }
        }
    }
}
