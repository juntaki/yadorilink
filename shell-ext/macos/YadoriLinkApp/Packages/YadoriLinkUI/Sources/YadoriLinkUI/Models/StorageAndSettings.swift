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

    public var storedData: String? { app.snapshot.map { Format.bytes($0.storage.blockStoreTotalBytes) } }
    public var reclaimable: String? { app.snapshot.map { Format.bytes($0.storage.reclaimableEstimateBytes) } }
    public var blocksStored: String? { app.snapshot.map { Format.count($0.storage.blockCount) } }
    public var lastCleanup: String? {
        guard let snapshot = app.snapshot else { return nil }
        return snapshot.storage.lastGcAt.map { Format.relative($0, now: now()) } ?? "Never"
    }

    /// One line per folder: mode, what is on this device, free space.
    public var folderLines: [NamedLine] {
        (app.snapshot?.folders ?? []).map { folder in
            NamedLine(
                id: folder.localPath,
                name: folder.name,
                text: Format.localCopyLine(folder),
                trailing: folder.volume.map(Format.freeSpace),
                trailingIsWarning: folder.volume.map { Format.freeSpaceIsWarning($0.state) } ?? false
            )
        }
    }

    public static func message(for report: GcReport) -> String {
        if report.bytesReclaimed == 0 {
            return report.dryRun ? "Nothing to free up right now" : "Nothing needed freeing"
        }
        return report.dryRun ? "About \(Format.bytes(report.bytesReclaimed)) can be freed" : "Freed \(Format.bytes(report.bytesReclaimed))"
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

    public init(client: any YadoriLinkClient, now: @escaping () -> Date = Date.init) {
        self.client = client
        self.now = now
    }

    public func load() async {
        do { status = try await client.updateStatus() } catch { notice = .failure(error) }
    }

    public var headline: String {
        guard let s = status else { return "" }
        let next = s.availableVersion ?? ""
        switch s.state {
        case .available, .downloaded, .verified:
            return s.availableVersion.map { "Update \($0) available" } ?? "An update is available"
        case .upToDate, .idle: return "YadoriLink \(s.currentVersion) is up to date"
        case .checking: return "Checking for updates…"
        case .downloading: return "Downloading update \(next)…"
        case .installing: return "Installing update…"
        case .failed: return "The last update didn't install"
        case .heldBack: return "Update \(next) is held back for now"
        case .killSwitched: return "Updates are paused by the publisher"
        case .deferred: return "Update \(next) will install later"
        case .unknown: return "YadoriLink \(s.currentVersion)"
        }
    }

    /// Small notes shown only under an available update.
    public var notes: [String] {
        guard let s = status, canInstall else { return [] }
        var notes: [String] = []
        if s.mandatory { notes.append("This update is required.") }
        if s.waitingForSafePoint { notes.append("It will install when syncing is idle.") }
        if let reason = s.holdbackReason, !reason.isEmpty { notes.append(reason) }
        return notes
    }

    public var lastChecked: String {
        guard let checked = status?.lastCheckedAt else { return "Never checked" }
        return "Last checked \(Format.relative(checked, now: now()))"
    }

    public var canInstall: Bool {
        guard let s = status, s.availableVersion != nil else { return false }
        return s.state == .available || s.state == .downloaded || s.state == .verified
    }

    public var automaticChecks: Bool { status?.config.automaticChecks ?? true }

    public func check() async {
        await work { self.status = try await self.client.checkForUpdates() }
    }

    public func install() async {
        await work {
            switch try await self.client.installUpdate() {
            case .installing: self.notice = Notice(kind: .success, text: "Installing the update. YadoriLink will restart.")
            case .deferred: self.notice = Notice(kind: .success, text: "The update will install when syncing is idle.")
            case .storeManaged(let guidance): self.notice = Notice(kind: .success, text: guidance)
            case .other(let raw): self.notice = Notice(kind: .success, text: "Update requested.", detail: raw)
            }
        }
    }

    public func setAutomaticChecks(_ on: Bool) async {
        await work {
            let config = try await self.client.setUpdateConfig(automaticChecks: on, installMode: nil)
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
