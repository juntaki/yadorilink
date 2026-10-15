import Foundation
import Observation
import YadoriLinkModel

// MARK: - Storage

public struct NamedLine: Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var text: String
    public var trailing: String?
    public var trailingIsWarning: Bool
}

@MainActor
@Observable
public final class StorageViewModel {
    public let app: AppModel
    public private(set) var isWorking = false
    public var notice: Notice?
    @ObservationIgnored private let now: () -> Date

    public init(app: AppModel, now: @escaping () -> Date = Date.init) {
        self.app = app
        self.now = now
    }

    public static let filesSectionTitle = "Files on this Mac"
    public static let internalSectionTitle = "YadoriLink internal storage"
    public static let diskSectionTitle = "Free disk space"
    public static let internalTotalLabel = "YadoriLink data"
    public static let cleanableLabel = "Internal space that can be cleaned up"
    public static let checkActionTitle = "Check Internal Space"
    public static let cleanUpActionTitle = "Clean Up YadoriLink Data"
    public static let filesExplanation = "Counts of synced files kept on this Mac or available online only. Sizes are not shown because they are not measured per file."
    public static let cleanUpExplanation = "Old versions and other internal data YadoriLink no longer needs. This does not change the files in your folders and does not make downloaded files online only. It never removes anything you can still restore."
    public static let diskExplanation = "Free space on the disk holding each folder. Each disk is shown on its own."

    public var localFilesTotals: String? { Format.localFilesTotals(app.snapshot?.folders ?? []) }
    public var diskSummary: String? { Format.diskSummary((app.snapshot?.folders ?? []).compactMap(\.volume)) }

    /// One row per folder that has a volume: its disk's free space, never summed with another.
    public var diskRows: [NamedLine] {
        (app.snapshot?.folders ?? []).compactMap { folder in
            guard let volume = folder.volume else { return nil }
            return NamedLine(
                id: folder.localPath,
                name: folder.name,
                text: volume.path,
                trailing: Format.freeSpace(volume),
                trailingIsWarning: Format.freeSpaceIsWarning(volume.state)
            )
        }
    }

    public var storedData: String? { app.snapshot.map { Format.bytes($0.storage.blockStoreTotalBytes) } }
    public var reclaimable: String? { app.snapshot.map { Format.bytes($0.storage.reclaimableEstimateBytes) } }
    public var blocksStored: String? { app.snapshot.map { Format.count($0.storage.blockCount) } }
    public var lastCleanup: String? {
        guard let snapshot = app.snapshot else { return nil }
        return snapshot.storage.lastGcAt.map { Format.relative($0, now: now()) } ?? "Never"
    }

    /// One line per folder: mode and what is on this Mac.
    public var folderLines: [NamedLine] {
        (app.snapshot?.folders ?? []).map { folder in
            NamedLine(
                id: folder.localPath,
                name: folder.name,
                text: Format.localCopyLine(folder),
                trailing: nil,
                trailingIsWarning: false
            )
        }
    }

    public static func message(for report: GcReport) -> String {
        if report.bytesReclaimed == 0 {
            return report.dryRun ? "Nothing to clean up right now" : "Nothing needed cleaning up"
        }
        return report.dryRun ? "About \(Format.bytes(report.bytesReclaimed)) of internal data can be cleaned up" : "Cleaned up \(Format.bytes(report.bytesReclaimed)) of internal data"
    }

    public func checkReclaimable() async { await runGc(dryRun: true) }
    public func reclaim() async { await runGc(dryRun: false) }

    private func runGc(dryRun: Bool) async {
        isWorking = true
        defer { isWorking = false }
        do {
            let report = try await app.client.runGc(dryRun: dryRun)
            notice = Notice(kind: .success, text: Self.message(for: report), detail: Plural.blocks(report.blocksDeleted))
            if !dryRun { app.refresh() }
        } catch {
            notice = .failure(error)
        }
    }
}

// MARK: - Bandwidth

@MainActor
@Observable
public final class BandwidthModel {
    public let client: any YadoriLinkClient
    public var uploadText = ""
    public var downloadText = ""
    public private(set) var isLoaded = false
    public private(set) var isSaving = false
    public var notice: Notice?
    @ObservationIgnored private var baseline = BandwidthLimits(uploadBytesPerSec: nil, downloadBytesPerSec: nil)

    public init(client: any YadoriLinkClient) { self.client = client }

    static let bytesPerMiB = 1_048_576.0

    /// Empty or 0 means unlimited; otherwise a positive number of MiB/s.
    static func parse(_ text: String) -> Result<UInt64?, ParseError> {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return .success(nil) }
        guard let value = Double(trimmed), value.isFinite, value >= 0 else { return .failure(ParseError()) }
        if value == 0 { return .success(nil) }
        return .success(UInt64(value * bytesPerMiB))
    }

    struct ParseError: Error {}

    static func text(_ bytes: UInt64?) -> String {
        guard let bytes else { return "" }
        let mib = Double(bytes) / bytesPerMiB
        return mib.formatted(.number.precision(.fractionLength(0...2)).grouping(.never).locale(Format.locale))
    }

    public var uploadError: String? { Self.error(uploadText) }
    public var downloadError: String? { Self.error(downloadText) }

    private static func error(_ text: String) -> String? {
        if case .failure = parse(text) { return "Enter a number" }
        return nil
    }

    private var parsed: BandwidthLimits? {
        guard case .success(let up) = Self.parse(uploadText), case .success(let down) = Self.parse(downloadText) else { return nil }
        return BandwidthLimits(uploadBytesPerSec: up, downloadBytesPerSec: down)
    }

    /// Only when both fields are valid and something changed.
    public var canSave: Bool {
        guard isLoaded, !isSaving, let parsed else { return false }
        return parsed != baseline
    }

    public func load() async {
        do {
            apply(try await client.bandwidthLimits())
            isLoaded = true
        } catch {
            notice = .failure(error)
        }
    }

    private func apply(_ limits: BandwidthLimits) {
        baseline = limits
        uploadText = Self.text(limits.uploadBytesPerSec)
        downloadText = Self.text(limits.downloadBytesPerSec)
    }

    public func save() async {
        guard canSave, let parsed else { return }
        isSaving = true
        defer { isSaving = false }
        do {
            apply(try await client.setBandwidthLimits(limits: parsed))
            notice = Notice(kind: .success, text: "Saved.")
        } catch {
            notice = .failure(error)
        }
    }
}

// MARK: - Updates

@MainActor
@Observable
public final class UpdatesModel {
    public let client: any YadoriLinkClient
    public private(set) var status: UpdateStatus?
    public private(set) var isWorking = false
    public var notice: Notice?
    @ObservationIgnored private let now: () -> Date
    /// Opens a page in the browser; `false` when it could not be opened.
    @ObservationIgnored private let openURL: (URL) -> Bool

    public init(client: any YadoriLinkClient, openURL: @escaping (URL) -> Bool = { _ in true }, now: @escaping () -> Date = Date.init) {
        self.client = client
        self.openURL = openURL
        self.now = now
    }

    public func load() async {
        do { status = try await client.updateStatus() } catch { notice = .failure(error) }
    }

    /// An update that can be fetched: YadoriLink only reports it. Every state
    /// that carries a version is the same to the user, because nothing is
    /// downloaded or installed on their behalf.
    public var canDownload: Bool {
        guard let s = status, s.availableVersion != nil else { return false }
        switch s.state {
        case .available, .downloading, .downloaded, .verified, .installing, .deferred: return true
        default: return false
        }
    }

    /// The last look for a newer version failed. This is not an install failure:
    /// nothing is installed here. The way out is to look again.
    /// The button that gets the new version: a package-managed install is shown
    /// its steps, everything else is sent to the download page.
    public var downloadButtonTitle: String {
        status?.packageManaged == true ? UpdateWording.showStepsButton : UpdateWording.downloadButton
    }

    public var lookupFailed: Bool { status?.state == .failed }

    public var headline: String {
        guard let s = status else { return "" }
        let next = s.availableVersion ?? ""
        if canDownload { return UpdateWording.available(next) }
        switch s.state {
        case .upToDate, .idle: return UpdateWording.upToDate(s.currentVersion)
        case .checking: return UpdateWording.checking
        case .failed: return UpdateWording.lookupFailed
        case .heldBack: return UpdateWording.heldBack(next)
        case .killSwitched: return UpdateWording.paused
        case .available, .downloading, .downloaded, .verified, .installing, .deferred:
            return UpdateWording.availableUnnamed
        case .unknown: return UpdateWording.current(s.currentVersion)
        }
    }

    /// Small notes under the headline.
    public var notes: [String] {
        guard let s = status else { return [] }
        var notes: [String] = []
        if canDownload {
            if s.mandatory { notes.append(UpdateWording.required) }
            if let reason = s.holdbackReason, !reason.isEmpty { notes.append(reason) }
        }
        if lookupFailed {
            notes.append(s.lastErrorMessage.flatMap { $0.isEmpty ? nil : $0 } ?? UpdateWording.lookupFailedHint)
        }
        return notes
    }

    public var lastChecked: String {
        guard let checked = status?.lastCheckedAt else { return "Never checked" }
        return "Last checked \(Format.relative(checked, now: now()))"
    }

    public var releaseNotesURL: URL? {
        guard let raw = status?.releaseNotesUrl, let url = URL(string: raw), url.scheme == "https" else { return nil }
        return url
    }

    public var automaticChecks: Bool { status?.config.automaticChecks ?? true }

    public func check() async {
        await work { self.status = try await self.client.checkForUpdates() }
    }

    /// Shows where to get the new version. YadoriLink downloads and installs
    /// nothing, so the result says what was actually done: a page was opened
    /// (or a command is shown), and the user installs it.
    public func download() async {
        await work {
            let guidance = try await self.client.downloadGuidance()
            if let raw = guidance.url, let url = URL(string: raw), url.scheme == "https" {
                self.notice = self.openURL(url)
                    ? Notice(kind: .success, text: UpdateWording.openedDownloadPage)
                    : Notice(kind: .failure, text: UpdateWording.couldNotOpenDownloadPage, detail: raw)
            } else {
                self.notice = Notice(kind: .success, text: UpdateWording.updateSteps(guidance.guidance))
            }
        }
    }

    public func setAutomaticChecks(_ on: Bool) async {
        await work {
            let config = try await self.client.setAutomaticUpdateChecks(on)
            self.status?.config = config
        }
    }

    private func work(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        do { try await body() } catch { notice = .failure(error) }
    }
}

// MARK: - Open at login

public enum LoginItemStatus: Sendable, Equatable {
    case notRegistered, enabled, requiresApproval, notFound
}

/// The system login-item registration for this app. The app target wraps
/// `SMAppService.mainApp`; tests use a fake.
public protocol LoginItemService: AnyObject {
    var status: LoginItemStatus { get }
    func register() throws
    func unregister() throws
    func openSystemSettingsLoginItems()
}

@MainActor
@Observable
public final class LoginItemModel {
    @ObservationIgnored private let service: any LoginItemService
    public private(set) var status: LoginItemStatus
    public private(set) var errorText: String?

    public init(service: any LoginItemService) {
        self.service = service
        status = service.status
    }

    /// Waiting for approval still counts as on: the registration exists.
    public var isOn: Bool { status == .enabled || status == .requiresApproval }
    public var needsApproval: Bool { status == .requiresApproval }

    public func refresh() { status = service.status }

    public func setOn(_ on: Bool) {
        do {
            if on { try service.register() } else { try service.unregister() }
            errorText = nil
        } catch {
            errorText = "Couldn't change the login item. \(error.localizedDescription)"
        }
        refresh()
    }

    public func openSystemSettings() { service.openSystemSettingsLoginItems() }

    /// The `UserDefaults` key recording that the default was applied.
    public static let defaultAppliedKey = "didApplyOpenAtLoginDefault"

    /// Open at login is on by default. The first launch turns it on once
    /// and records that in `defaults`, so a user who later turns it off
    /// stays off. A failed registration is not recorded and is retried on
    /// the next launch.
    public func applyDefaultOnce(defaults: UserDefaults = .standard) {
        guard !defaults.bool(forKey: Self.defaultAppliedKey) else { return }
        if !isOn { setOn(true) }
        if isOn { defaults.set(true, forKey: Self.defaultAppliedKey) }
    }
}
