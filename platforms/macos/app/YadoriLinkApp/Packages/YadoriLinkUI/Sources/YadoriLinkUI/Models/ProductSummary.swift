import Foundation
import YadoriLinkModel

/// One answer on Home: a short label, one sentence, and how it is coloured.
public struct SummaryLine: Equatable, Sendable {
    public var label: String
    public var text: String
    public var tone: StatusTone
    /// A second quiet line, only when it adds something.
    public var detail: String?
}

/// The five questions Home answers, in the order a person asks them:
/// is it healthy, is it syncing, is it waiting for something, do I need to
/// act, is my data protected. Built from the status snapshot alone.
public struct ProductSummary: Equatable, Sendable {
    public var health: SummaryLine
    public var syncing: SummaryLine
    public var waiting: SummaryLine
    public var action: SummaryLine
    public var protection: SummaryLine
    /// What YadoriLink keeps for itself, from the storage summary.
    public var storage: String?

    public var lines: [SummaryLine] { [health, syncing, waiting, action, protection] }

    /// `deviceNames` maps device ids to display names; an id without a name is
    /// never shown, the sentence says "another device" instead.
    public static func make(snapshot: StatusSnapshot?, daemonUnavailable: Bool, deviceNames: [String: String] = [:]) -> ProductSummary {
        guard let snapshot, !daemonUnavailable else {
            let notRunning = daemonUnavailable
            let unknown = notRunning ? SummaryWording.unavailableDetail : nil
            func line(_ label: String, _ text: String) -> SummaryLine {
                SummaryLine(label: label, text: text, tone: .neutral, detail: unknown)
            }
            return ProductSummary(
                health: SummaryLine(label: SummaryWording.healthLabel, text: notRunning ? AppBanner.daemonUnavailable.title : SummaryWording.checking, tone: notRunning ? .danger : .neutral, detail: nil),
                syncing: line(SummaryWording.syncingLabel, SummaryWording.checking),
                waiting: line(SummaryWording.waitingLabel, SummaryWording.checking),
                action: line(SummaryWording.actionLabel, SummaryWording.checking),
                protection: line(SummaryWording.protectionLabel, ProtectionWording.checking),
                storage: nil
            )
        }
        // Waiting items are answered by the Waiting line; only the rest asks something of the user.
        let reasons = RecentProblems.attentionReasons(snapshot.attentionReasons).filter { $0.kind != .waiting }
        return ProductSummary(
            health: health(snapshot),
            syncing: syncing(snapshot),
            waiting: waiting(snapshot.availability, deviceNames: deviceNames),
            action: action(reasons),
            protection: protection(snapshot, deviceNames: deviceNames),
            storage: snapshot.storage.blockStoreTotalBytes > 0
                ? SummaryWording.storage(Format.bytes(snapshot.storage.blockStoreTotalBytes)) : nil
        )
    }

    private static func health(_ snapshot: StatusSnapshot) -> SummaryLine {
        let (text, tone): (String, StatusTone) = switch snapshot.overall {
        case .healthy: (SummaryWording.healthy, .ok)
        case .attention: (SummaryWording.healthAttention, .warning)
        case .degraded: (SummaryWording.healthDegraded, .danger)
        case .unknown: (SummaryWording.checking, .neutral)
        }
        return SummaryLine(label: SummaryWording.healthLabel, text: text, tone: tone, detail: nil)
    }

    private static func syncing(_ snapshot: StatusSnapshot) -> SummaryLine {
        let label = SummaryWording.syncingLabel
        let folders = snapshot.folders
        if folders.isEmpty {
            return SummaryLine(label: label, text: SummaryWording.noFolders, tone: .neutral, detail: nil)
        }
        let syncing = folders.filter { $0.state == .syncing }.count
        if syncing > 0 || !snapshot.transfers.isEmpty {
            let files = snapshot.transfers.count
            let text = files > 0 ? "Syncing \(Plural.files(files))" : "Syncing \(Plural.folders(syncing))"
            return SummaryLine(label: label, text: text, tone: .info, detail: nil)
        }
        if folders.allSatisfy(\.paused) {
            return SummaryLine(label: label, text: SummaryWording.paused, tone: .neutral, detail: nil)
        }
        let paused = folders.filter(\.paused).count
        return SummaryLine(
            label: label, text: SummaryWording.upToDate, tone: .ok,
            detail: paused > 0 ? "\(Plural.folders(paused)) paused" : nil
        )
    }

    private static func waiting(_ availability: AvailabilitySummary, deviceNames: [String: String]) -> SummaryLine {
        let (text, tone) = availability.availability.sentence(waitingOn: availability.offlineDeviceIds.compactMap { deviceNames[$0] })
        return SummaryLine(label: SummaryWording.waitingLabel, text: text, tone: tone, detail: nil)
    }

    private static func action(_ reasons: [AttentionReason]) -> SummaryLine {
        let label = SummaryWording.actionLabel
        if reasons.isEmpty {
            return SummaryLine(label: label, text: SummaryWording.nothingToDo, tone: .ok, detail: nil)
        }
        return SummaryLine(label: label, text: Plural.issues(reasons.count), tone: .warning, detail: nil)
    }

    private static func protection(_ snapshot: StatusSnapshot, deviceNames: [String: String]) -> SummaryLine {
        let label = SummaryWording.protectionLabel
        if snapshot.folders.isEmpty {
            return SummaryLine(label: label, text: SummaryWording.noFolders, tone: .neutral, detail: nil)
        }
        let summary = snapshot.protection
        let (text, tone) = summary.protection.sentence(copies: summary.deviceIds.count)
        let waitingOn = summary.protection == .pending ? summary.deviceIds.compactMap { deviceNames[$0] } : []
        return SummaryLine(
            label: label, text: text, tone: tone,
            detail: waitingOn.isEmpty ? nil : "Copying to \(ListWording.join(waitingOn))."
        )
    }
}

// MARK: - Attention items and their actions

/// Where an action leads in the app. The view performs it.
public enum AttentionDestination: Equatable, Sendable {
    case refresh
    case folder(String)
    case sidebar(SidebarItem)
    case revealInFinder(String)
    case settings(SettingsTab)
}

extension ProductAction {
    func destination(for reason: AttentionReason, in snapshot: StatusSnapshot) -> AttentionDestination {
        let folder = reason.folderLocalPath.flatMap { path in snapshot.folders.first { $0.localPath == path } }
        switch self {
        case .retry: return .refresh
        case .reviewConflict, .viewDetails:
            return folder.map { .folder($0.localPath) } ?? .sidebar(self == .viewDetails ? .home : .folders)
        case .freeUpSpace: return .sidebar(.storage)
        case .revealPath:
            guard let folder else { return .sidebar(.folders) }
            return folder.provider ? .folder(folder.localPath) : .revealInFinder(folder.localPath)
        case .openSettings: return .settings(.general)
        case .downloadUpdate: return .settings(.updates)
        }
    }
}

/// One current problem: a sentence and what to do about it.
public struct AttentionItem: Identifiable, Equatable, Sendable {
    public var id: String
    public var text: String
    public var primary: ActionOffer
    public var secondary: ActionOffer?
    public var folderLocalPath: String?
}

public struct ActionOffer: Equatable, Sendable {
    public var action: ProductAction
    public var title: String
    public var destination: AttentionDestination
}
