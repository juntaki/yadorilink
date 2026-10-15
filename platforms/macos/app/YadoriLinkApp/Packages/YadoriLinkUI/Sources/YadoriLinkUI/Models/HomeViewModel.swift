import Foundation
import Observation
import YadoriLinkModel

/// One folder, in two lines: name and state, then one quiet summary.
public struct FolderRow: Identifiable, Equatable, Sendable {
    public var id: String { folder.localPath }
    public var folder: FolderSummary
    public var name: String
    public var stateTitle: String
    public var stateTone: StatusTone
    /// "Protected · 2 devices · 182 GB free"
    public var summary: String
    public var summaryIsWarning: Bool
    /// Only when the folder is not protected.
    public var detail: String?
    public var protectionTone: StatusTone
    /// The path, shown on hover over the name.
    public var pathTooltip: String
    /// 0...1 while transferring.
    public var progress: Double?
    public var progressText: String?

    init(_ folder: FolderSummary) {
        self.folder = folder
        name = folder.name
        stateTitle = folder.state.title
        stateTone = folder.state.tone
        var parts = [folder.protection.protection.sentence(copies: folder.protection.deviceIds.count).0]
        if let volume = folder.volume { parts.append(Format.freeSpace(volume)) }
        summary = parts.joined(separator: " · ")
        summaryIsWarning = folder.volume.map { Format.freeSpaceIsWarning($0.state) } ?? false
        detail = folder.protection.protection.detail
        protectionTone = folder.protection.protection.sentence(copies: folder.protection.deviceIds.count).1
        pathTooltip = folder.provider ? "" : folder.localPath
        if let t = folder.transfer, t.bytesTotal > 0 {
            progress = Double(t.bytesDone) / Double(t.bytesTotal)
            var text = "\(Format.bytes(t.bytesDone)) of \(Format.bytes(t.bytesTotal))"
            if let eta = t.eta, eta > 0 { text += " · about \(Format.duration(eta)) left" }
            progressText = text
        }
    }
}

public struct TextLine: Identifiable, Equatable, Sendable {
    public var id: String { tooltip }
    public var text: String
    /// The raw code, for a tooltip.
    public var tooltip: String
    public var folderLocalPath: String?
}

public struct DeviceRow: Identifiable, Equatable, Sendable {
    public var id: String { tooltip }
    public var name: String
    public var detail: String
    public var online: Bool
    public var isThisDevice: Bool
    /// The device id, for a tooltip.
    public var tooltip: String

    init(_ device: DeviceSummary, now: Date) {
        name = device.displayName
        // This Mac is running, so it is never drawn offline, whatever the
        // coordination service last observed of it.
        online = device.online || device.isThisDevice
        isThisDevice = device.isThisDevice
        tooltip = device.deviceId
        if device.isThisDevice {
            detail = "This Mac"
        } else if device.online {
            detail = "Online"
        } else if let seen = device.lastSeen {
            detail = "Last seen \(Format.relative(seen, now: now))"
        } else {
            detail = "Offline"
        }
    }
}

/// Where a list fetched from the coordination service stands. An empty list
/// is only claimed after a fetch has succeeded once.
public enum FetchPhase<Value: Equatable & Sendable>: Equatable, Sendable {
    case notLoaded
    case loading
    case loaded(Value)
    case failed(Notice)

    public var value: Value? {
        if case .loaded(let v) = self { return v }
        return nil
    }
}

@MainActor
@Observable
public final class HomeViewModel {
    public let app: AppModel
    public private(set) var devices: FetchPhase<[DeviceSummary]> = .notLoaded
    /// A refresh failed while an earlier list is still shown.
    public private(set) var devicesStale: Notice?
    @ObservationIgnored private let now: () -> Date

    public init(app: AppModel, now: @escaping () -> Date = Date.init) {
        self.app = app
        self.now = now
    }

    public var headline: String { app.headline }
    public var banner: AppBanner? { app.banner }

    /// Only before the first status answer. Never together with a banner.
    public var showsLoading: Bool { app.status == .loading }

    /// Only when the daemon answered and there really are no folders.
    public var showsNoFoldersMessage: Bool { app.snapshot?.folders.isEmpty == true }

    public var folderRows: [FolderRow] { app.snapshot?.folders.map(FolderRow.init) ?? [] }

    public var showsTransfersSection: Bool { app.snapshot?.transfers.isEmpty == false }
    /// Devices come from the account, so they need sign-in as well.
    public var showsDevicesSection: Bool { app.snapshot != nil && app.isSignedIn }

    /// Resolved or short-lived problems, secondary to `attentionLines`.
    public var recentProblemLines: [TextLine] {
        guard let snapshot = app.snapshot else { return [] }
        return RecentProblems.items(errors: snapshot.recentErrors, activeReasons: snapshot.attentionReasons, now: now()).map {
            TextLine(text: [$0.text, $0.age].compactMap { $0 }.joined(separator: " · "), tooltip: $0.tooltip, folderLocalPath: nil)
        }
    }

    public var summary: ProductSummary {
        ProductSummary.make(snapshot: app.snapshot, daemonUnavailable: app.isDaemonUnavailable, deviceNames: deviceNames)
    }

    private var deviceNames: [String: String] {
        Dictionary((devices.value ?? []).map { ($0.deviceId, $0.displayName) }, uniquingKeysWith: { a, _ in a })
    }

    /// Current problems, each with what to do about it. The daemon's raw code is never shown.
    public var attentionItems: [AttentionItem] {
        guard let snapshot = app.snapshot else { return [] }
        let names = deviceNames
        return RecentProblems.attentionReasons(snapshot.attentionReasons).filter { $0.kind != .waiting }.map { reason in
            func offer(_ action: ProductAction) -> ActionOffer {
                ActionOffer(action: action, title: action.title, destination: action.destination(for: reason, in: snapshot))
            }
            return AttentionItem(
                id: reason.raw,
                text: reason.category.sentence(subject: Self.subjectName(reason, snapshot: snapshot, deviceNames: names)),
                primary: offer(reason.primaryAction),
                secondary: reason.secondaryAction.map(offer),
                folderLocalPath: reason.folderLocalPath
            )
        }
    }

    /// Things the app is waiting on, as plain sentences. They need no action from the user.
    public var waitingLines: [String] {
        guard let snapshot = app.snapshot else { return [] }
        let names = deviceNames
        return RecentProblems.attentionReasons(snapshot.attentionReasons).filter { $0.kind == .waiting }.map {
            $0.category.sentence(subject: Self.subjectName($0, snapshot: snapshot, deviceNames: names))
        }
    }

    static func subjectName(_ reason: AttentionReason, snapshot: StatusSnapshot, deviceNames: [String: String]) -> String? {
        if let path = reason.folderLocalPath {
            return snapshot.folders.first { $0.localPath == path }?.name
        }
        switch reason.category {
        case .peerDisconnected:
            return deviceNames[reason.subject]
        case .lowDisk, .lowDiskCritical:
            let onVolume = snapshot.folders.filter { $0.volume?.path == reason.subject }
            return onVolume.count == 1 ? onVolume[0].name : nil
        default:
            return nil
        }
    }

    public var deviceRows: [DeviceRow] {
        (devices.value ?? []).filter { !$0.isThisDevice }.map { DeviceRow($0, now: now()) }
    }

    public var showsNoDevicesMessage: Bool {
        app.snapshot != nil && devicesStale == nil && devices.value?.contains { !$0.isThisDevice } == false
    }

    /// The first read failed: nothing to show, so the section offers Retry.
    public var devicesError: Notice? {
        if case .failed(let notice) = devices { return notice }
        return nil
    }

    public func loadDevices() async {
        // Another account may sign in next; never carry this roster over.
        if !app.isSignedIn {
            devices = .notLoaded
            devicesStale = nil
        }
        guard app.isSignedIn, !app.isDaemonUnavailable else { return }
        if devices.value == nil { devices = .loading }
        do {
            let list = try await app.client.listFolderDevices()
            // Signed out while the read was in flight: that roster belongs to the old account.
            guard app.isSignedIn else { return }
            devices = .loaded(list)
            devicesStale = nil
        } catch {
            guard app.isSignedIn else { return }
            if devices.value == nil {
                devices = .failed(.failure(error))
            } else {
                devicesStale = .failure(error)
            }
        }
    }
}

/// What the menu bar popover shows. Built from `AppModel`, no state of its own.
@MainActor
public struct MenuBarPresentation {
    public var headline: String
    public var tone: StatusTone
    public var folders: [FolderRow]
    public var transferLine: String?
    public var transferProgress: Double?
    public var canPause: Bool
    public var pauseTitle: String
    public var allPaused: Bool
    public var showsStartAction: Bool
    public var updateLine: String?
    /// "Protected · another device has a copy", "Checking protection"; nil without folders or a daemon.
    public var protectionLine: String?

    public init(app: AppModel) {
        headline = app.headline
        tone = app.overallTone
        showsStartAction = app.isDaemonUnavailable
        let snapshot = app.snapshot
        folders = snapshot?.folders.map(FolderRow.init) ?? []
        canPause = snapshot.map { !$0.folders.isEmpty } ?? false
        allPaused = snapshot.map { !$0.folders.isEmpty && $0.folders.allSatisfy(\.paused) } ?? false
        if let snapshot, !snapshot.folders.isEmpty {
            protectionLine = snapshot.protection.protection.sentence(copies: snapshot.protection.deviceIds.count).0
        }
        pauseTitle = allPaused ? "Resume Syncing" : "Pause Syncing"

        if let snapshot, !snapshot.transfers.isEmpty {
            let sources = Set(snapshot.transfers.map(\.sourceDeviceId))
            let verb: String
            if !sources.contains(snapshot.thisDeviceId ?? "") { verb = "Receiving" }
            else if sources == [snapshot.thisDeviceId ?? ""] { verb = "Sending" }
            else { verb = "Syncing" }
            let progress = snapshot.folders.compactMap(\.transfer)
            let done = progress.reduce(0) { $0 + $1.bytesDone }
            let total = progress.reduce(0) { $0 + $1.bytesTotal }
            transferLine = TransferRate.appending(
                rate: TransferRate.text(snapshot.bandwidth),
                to: "\(verb) \(Plural.files(snapshot.transfers.count)) · \(Format.percent(done: done, total: total))%"
            )
            transferProgress = total > 0 ? Double(done) / Double(total) : nil
        }

        if let update = snapshot?.update, let version = update.availableVersion,
           update.state == .available || update.state == .downloaded || update.state == .verified {
            updateLine = "Update \(version) available"
        }
    }
}
