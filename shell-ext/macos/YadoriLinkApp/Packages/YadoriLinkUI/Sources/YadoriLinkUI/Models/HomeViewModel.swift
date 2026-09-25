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
        var parts = [folder.durability.title, Plural.devices(folder.fullReplicaDeviceIds.count)]
        if let volume = folder.volume { parts.append(Format.freeSpace(volume)) }
        summary = parts.joined(separator: " · ")
        summaryIsWarning = folder.volume.map { Format.freeSpaceIsWarning($0.state) } ?? false
        detail = folder.durability.detail
        pathTooltip = folder.localPath
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

    public var attentionLines: [TextLine] {
        guard let snapshot = app.snapshot else { return [] }
        let names = Dictionary((devices.value ?? []).map { ($0.deviceId, $0.displayName) }, uniquingKeysWith: { a, _ in a })
        return snapshot.attentionReasons.map { reason in
            TextLine(
                text: reason.category.sentence(subject: Self.subjectName(reason, snapshot: snapshot, deviceNames: names)),
                tooltip: reason.raw,
                folderLocalPath: reason.folderLocalPath
            )
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
        app.snapshot != nil && devices.value?.contains { !$0.isThisDevice } == false
    }

    public var devicesError: String? {
        if case .failed(let notice) = devices { return notice.text }
        return nil
    }

    public func loadDevices() async {
        guard app.isSignedIn, !app.isDaemonUnavailable else { return }
        if devices.value == nil { devices = .loading }
        do {
            devices = .loaded(try await app.client.listFolderDevices())
        } catch {
            devices = .failed(.failure(error))
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

    public init(app: AppModel) {
        headline = app.headline
        tone = app.overallTone
        showsStartAction = app.isDaemonUnavailable
        let snapshot = app.snapshot
        folders = snapshot?.folders.map(FolderRow.init) ?? []
        canPause = snapshot.map { !$0.folders.isEmpty } ?? false
        allPaused = snapshot.map { !$0.folders.isEmpty && $0.folders.allSatisfy(\.paused) } ?? false
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
            transferLine = "\(verb) \(Plural.files(snapshot.transfers.count)) · \(Format.percent(done: done, total: total))%"
            transferProgress = total > 0 ? Double(done) / Double(total) : nil
        }

        if let update = snapshot?.update, let version = update.availableVersion,
           update.state == .available || update.state == .downloaded || update.state == .verified {
            updateLine = "Update \(version) available"
        }
    }
}
