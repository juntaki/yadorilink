// Every user-facing word for a product state lives here, once. The client
// returns meaning (enums, numbers, ids); this file turns it into text.
//
// Vocabulary:
// - Folder modes: "Keep all files" / "On-Demand".
// - File actions: "Download now" / "Free up space" / "Always keep on this device".
// - Sharing: "shared folder".
// - Ids never appear as primary text; they go in tooltips.

import Foundation
import YadoriLinkModel

// MARK: - Formatting

public enum Format {
    /// The app's copy is English for now, so numbers and dates use an
    /// English locale to keep sentences consistent.
    static let locale = Locale(identifier: "en_US")

    public static func bytes(_ count: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(clamping: count))
    }

    public static func count<T: BinaryInteger>(_ value: T) -> String {
        Int(clamping: value).formatted(.number.locale(locale))
    }

    public static func relative(_ date: Date, now: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        formatter.unitsStyle = .full
        if abs(date.timeIntervalSince(now)) < 60 { return "just now" }
        return formatter.localizedString(for: date, relativeTo: now)
    }

    public static func duration(_ interval: TimeInterval) -> String {
        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .abbreviated
        formatter.allowedUnits = interval >= 3600 ? [.hour, .minute] : [.minute, .second]
        formatter.maximumUnitCount = 2
        var calendar = Calendar(identifier: .gregorian)
        calendar.locale = locale
        formatter.calendar = calendar
        return formatter.string(from: interval) ?? ""
    }

    public static func percent(done: UInt64, total: UInt64) -> Int {
        guard total > 0 else { return 0 }
        return Int((Double(done) / Double(total) * 100).rounded(.down))
    }

    /// "182 GB free", "Only 7 GB free" when low. Never "(ok)".
    public static func freeSpace(_ volume: VolumeSummary) -> String {
        switch volume.state {
        case .ok, .unknown: return "\(bytes(volume.availableBytes)) free"
        case .low, .critical: return "Only \(bytes(volume.availableBytes)) free"
        }
    }

    public static func freeSpaceIsWarning(_ state: FreeSpaceState) -> Bool {
        state == .low || state == .critical
    }

    /// "On-Demand · 312 on this device · 892 online only"
    public static func localCopyLine(_ folder: FolderSummary) -> String {
        var parts = [folder.mode.title, "\(count(folder.hydratedFileCount)) on this device"]
        if folder.placeholderFileCount > 0 { parts.append("\(count(folder.placeholderFileCount)) online only") }
        return parts.joined(separator: " · ")
    }
}

public enum Plural {
    public static func devices(_ n: Int) -> String {
        n == 0 ? "No devices" : n == 1 ? "1 device" : "\(Format.count(n)) devices"
    }
    public static func files(_ n: Int) -> String {
        n == 1 ? "1 file" : "\(Format.count(n)) files"
    }
    public static func folders(_ n: Int) -> String {
        n == 1 ? "1 folder" : "\(Format.count(n)) folders"
    }
    public static func items(_ n: Int) -> String {
        n == 1 ? "1 item" : "\(Format.count(n)) items"
    }
    public static func issues(_ n: Int) -> String {
        n == 1 ? "1 issue needs attention" : "\(Format.count(n)) issues need attention"
    }
    public static func blocks(_ n: UInt64) -> String {
        n == 1 ? "1 block" : "\(Format.count(n)) blocks"
    }
}

// MARK: - Product states

extension FolderMode {
    public var title: String {
        switch self {
        case .keepAll: "Keep all files"
        case .onDemand: "On-Demand"
        }
    }
    public var hint: String {
        switch self {
        case .keepAll: "Every file is stored on this Mac."
        case .onDemand: "Files download when you open them, to save space."
        }
    }
}

/// How a badge is coloured. Views map this to a colour in one place.
public enum StatusTone: Sendable, Equatable { case ok, info, neutral, warning, danger }

extension FolderState {
    public var title: String {
        switch self {
        case .upToDate: "Up to date"
        case .syncing: "Syncing"
        case .paused: "Paused"
        case .blocked: "Can't sync"
        case .attention: "Needs attention"
        }
    }
    public var tone: StatusTone {
        switch self {
        case .upToDate: .ok
        case .syncing: .info
        case .paused: .neutral
        case .blocked: .danger
        case .attention: .warning
        }
    }
}

extension DurabilityStatus {
    public var title: String {
        switch self {
        case .protected: "Protected"
        case .protecting: "Protecting"
        case .atRisk: "At risk"
        case .unknown: "Protection unknown"
        }
    }
    /// The one explanatory line, shown only when not protected.
    public var detail: String? {
        switch self {
        case .protected: nil
        case .protecting: "Copying to another device."
        case .atRisk: "No other device has a complete copy yet."
        case .unknown: "Can't confirm a complete copy on another device right now."
        }
    }
    public var tone: StatusTone {
        switch self {
        case .protected: .ok
        case .protecting: .info
        case .atRisk: .danger
        case .unknown: .warning
        }
    }
}

extension LocalStorageState {
    public var title: String {
        switch self {
        case .fullCopy: "All files on this Mac"
        case .partiallyMaterialized: "Some files on this Mac"
        case .onDemand: "Files download when opened"
        case .unknown: "Unknown"
        }
    }
}

extension MaterializationState {
    public var title: String {
        switch self {
        case .hydrated: "On this Mac"
        case .placeholder: "Online only"
        case .hydrating: "Downloading"
        case .evicting: "Freeing up space"
        case .unknown: "Unknown"
        }
    }
}

extension PeerReachability {
    public var title: String {
        switch self {
        case .connected: "Available"
        case .unreachable: "Offline"
        case .connecting: "Connecting"
        case .unknown: "Unknown"
        }
    }
}

extension RouteKind {
    public var title: String? {
        switch self {
        case .direct: "Direct"
        case .relay: "Relayed"
        case .unknown: nil
        }
    }
}

extension ShareRole {
    public var title: String {
        switch self {
        case .owner: "Owner"
        case .editor: "Can edit"
        case .viewer: "Can view"
        case .other(let raw): raw.capitalized
        }
    }
}

extension AssignableRole {
    public var title: String {
        switch self {
        case .viewer: "Can view"
        case .editor: "Can edit"
        }
    }
}

extension AttentionCategory {
    /// A plain sentence. `subject` is a display name (folder, device) when
    /// one is known; the raw code stays in a tooltip.
    public func sentence(subject: String?) -> String {
        switch self {
        case .degraded:
            subject.map { "\($0) can't sync right now." } ?? "A folder can't sync right now."
        case .durabilityAtRisk:
            subject.map { "\($0) has no complete copy on another device yet." } ?? "A folder has no complete copy on another device yet."
        case .durabilityUnknown:
            subject.map { "Can't confirm that \($0) has a complete copy on another device." } ?? "Can't confirm that every folder has a complete copy on another device."
        case .fetchUnavailable:
            subject.map { "Some files in \($0) can't be downloaded right now." } ?? "Some files can't be downloaded right now."
        case .fetchAvailabilityUnknown:
            subject.map { "Can't tell whether files in \($0) can be downloaded right now." } ?? "Can't tell whether some files can be downloaded right now."
        case .conflict:
            subject.map { "\($0) has conflicting copies of some files." } ?? "Some files have conflicting copies."
        case .held:
            subject.map { "Some files in \($0) are on hold and haven't synced." } ?? "Some files are on hold and haven't synced."
        case .lowDiskCritical:
            subject.map { "The disk holding \($0) is almost full. Syncing has stopped." } ?? "Your disk is almost full. Syncing has stopped."
        case .lowDisk:
            subject.map { "The disk holding \($0) is running low on space." } ?? "Your disk is running low on space."
        case .peerDisconnected:
            subject.map { "\($0) is offline." } ?? "A device is offline."
        case .recentError:
            "Something went wrong recently."
        case .updateFailed:
            "The last update didn't install."
        case .unrecognized:
            "Something needs attention."
        }
    }
}

// MARK: - File actions

public enum FileAction: CaseIterable, Sendable, Equatable {
    case download, freeUpSpace, keepOnDevice, stopKeeping

    public var title: String {
        switch self {
        case .download: "Download now"
        case .freeUpSpace: "Free up space"
        case .keepOnDevice: "Always keep on this device"
        case .stopKeeping: "Stop always keeping"
        }
    }

    public var systemImage: String {
        switch self {
        case .download: "icloud.and.arrow.down"
        case .freeUpSpace: "icloud"
        case .keepOnDevice: "pin"
        case .stopKeeping: "pin.slash"
        }
    }

    /// Only the actions that make sense for the file's current state.
    public static func available(for availability: FileAvailability) -> [FileAction] {
        guard availability.tracked else { return [] }
        if availability.pinned { return [.stopKeeping] }
        switch availability.state {
        case .placeholder: return [.download, .keepOnDevice]
        case .hydrated: return [.freeUpSpace, .keepOnDevice]
        case .hydrating: return [.keepOnDevice]
        case .evicting, .unknown: return []
        }
    }
}

// MARK: - Banners, notices, errors

/// The one banner a screen shows when something below it can't work.
public enum AppBanner: Sendable, Equatable {
    case daemonUnavailable
    case signedOut
    case credentialStoreUnusable

    public var title: String {
        switch self {
        case .daemonUnavailable: "YadoriLink isn't running."
        case .signedOut: "You're signed out."
        case .credentialStoreUnusable: "YadoriLink can't read your sign-in details from the keychain."
        }
    }

    public var actionTitle: String {
        switch self {
        case .daemonUnavailable: "Start YadoriLink"
        case .signedOut: "Sign In…"
        case .credentialStoreUnusable: "Sign In Again…"
        }
    }
}

/// A result line shown once at the top of a window.
public struct Notice: Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case success, failure }
    public var kind: Kind
    public var text: String
    /// Secondary detail for a tooltip or "Details…".
    public var detail: String?

    public init(kind: Kind, text: String, detail: String? = nil) {
        self.kind = kind
        self.text = text
        self.detail = detail
    }

    public static func failure(_ error: Error) -> Notice {
        guard let error = error as? DesktopError else {
            return Notice(kind: .failure, text: "Something went wrong.", detail: String(describing: error))
        }
        return Notice(kind: .failure, text: ErrorWording.text(error), detail: error.message)
    }
}

/// Labels for settings that appear in more than one place.
public enum SettingWording {
    /// Settings > General and the last step of setup.
    public static let openAtLogin = "Open at login"
}

public enum ErrorWording {
    /// One sentence per error kind. The diagnostic `message` goes in the
    /// notice detail, never here.
    public static func text(_ error: DesktopError) -> String {
        switch error {
        case .notSignedIn:
            return "You're signed out."
        case .daemonUnavailable(_, .notRunning):
            return "YadoriLink isn't running."
        case .daemonUnavailable(_, .unresponsive):
            return "YadoriLink isn't responding. Try again in a moment."
        case .daemonUnavailable(_, .protocolMismatch):
            return "This app and the background service are different versions. Reinstall YadoriLink."
        case .network(_, .unreachable):
            return "Can't reach the YadoriLink service. Check your connection and try again."
        case .network(_, .rateLimited):
            return "Too many requests. Try again in a minute."
        case .network(_, .activationPendingReconciliation):
            return "Still finishing setup with the server. Try again shortly."
        case .permissionDenied(_, .sessionRejected):
            return "Your session has ended. Sign in again."
        case .permissionDenied(_, .forbidden):
            return "You don't have permission to do that."
        case .permissionDenied(_, .quotaExceeded):
            return "Your account has reached its limit."
        case .permissionDenied(_, .credentialStoreUnusable):
            return "YadoriLink can't read your sign-in details from the keychain."
        case .durabilityBlocked:
            return "No other device has a complete copy yet, so this could lose data."
        case .invalidInput:
            return "That can't be done with what was entered."
        case .internal:
            return "Something went wrong."
        }
    }
}
