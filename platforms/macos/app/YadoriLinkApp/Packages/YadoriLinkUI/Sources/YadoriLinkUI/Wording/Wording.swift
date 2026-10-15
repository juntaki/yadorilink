// Every user-facing word for a product state lives here, once. The client
// returns meaning (enums, numbers, ids); this file turns it into text.
//
// Vocabulary:
// - Folder modes: "Keep all files" / "On-Demand".
// - File actions: "Download Now" / "Free Up Space" / "Always Keep on This Device".
// - Action titles are Title Case everywhere, Finder menu included.
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

    /// "Sep 21, 2026 at 10:12 AM", for tooltips beside a relative time.
    public static func dateTime(_ date: Date) -> String {
        date.formatted(.dateTime.locale(locale).year().month(.abbreviated).day().hour().minute())
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

    /// Counts across all folders, never bytes: the snapshot has file counts but no materialized
    /// sizes, and a size must not be estimated from a count. `nil` when there are no folders.
    public static func localFilesTotals(_ folders: [FolderSummary]) -> String? {
        guard !folders.isEmpty else { return nil }
        let onMac = folders.reduce(0) { $0 + $1.hydratedFileCount }
        let online = folders.reduce(0) { $0 + $1.placeholderFileCount }
        let loading = folders.reduce(0) { $0 + $1.hydratingFileCount }
        var parts = ["\(count(onMac)) on this Mac"]
        if online > 0 { parts.append("\(count(online)) online only") }
        if loading > 0 { parts.append("\(count(loading)) downloading") }
        return parts.joined(separator: " · ")
    }

    /// A compact verdict over the volumes; free bytes of different disks are never added up.
    public static func diskSummary(_ volumes: [VolumeSummary]) -> String? {
        guard !volumes.isEmpty else { return nil }
        let critical = volumes.filter { $0.state == .critical }.count
        let low = volumes.filter { $0.state == .low }.count
        if critical == 0 && low == 0 { return "Every disk has enough free space" }
        func disks(_ n: Int, _ phrase: String) -> String { n == 1 ? "1 disk is \(phrase)" : "\(n) disks are \(phrase)" }
        if critical > 0 && low > 0 { return "\(disks(critical, "critically low")), \(low) \(low == 1 ? "is" : "are") running low" }
        return critical > 0 ? disks(critical, "critically low") : disks(low, "running low")
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
        case .strandedDirectory:
            subject.map { "A folder in \($0) couldn't be removed safely and was left under a temporary name. Nothing was deleted." } ?? "A folder couldn't be removed safely and was left under a temporary name. Nothing was deleted."
        case .lowDiskCritical:
            subject.map { "The disk holding \($0) is almost full. Syncing has stopped." } ?? "Your disk is almost full. Syncing has stopped."
        case .lowDisk:
            subject.map { "The disk holding \($0) is running low on space." } ?? "Your disk is running low on space."
        case .peerDisconnected:
            subject.map { "\($0) is offline." } ?? "A device is offline."
        case .recentError:
            "Something went wrong recently."
        case .updateFailed:
            "Couldn't check for updates."
        case .ambiguous:
            subject.map { "\($0) is set up in more than one place, so it isn't syncing." } ?? "A folder is set up in more than one place, so it isn't syncing."
        case .ownershipLost:
            subject.map { "\($0) can't sync because this device no longer has access to it." } ?? "A folder can't sync because this device no longer has access to it."
        case .volumeChanged:
            subject.map { "\($0) is no longer on the disk it was set up on." } ?? "A folder is no longer on the disk it was set up on."
        case .providerNotReady:
            "A folder in Finder isn't ready yet."
        case .providerStuck:
            "Some files in a Finder folder keep failing to download."
        case .keptEdits:
            "Some edits were kept beside the original files."
        case .providerOrphanDomain:
            "A Finder folder is left over from an earlier setup."
        case .unrecognized:
            "Something needs attention."
        }
    }
}

// MARK: - Home summary

public enum SummaryWording {
    public static let healthLabel = "Status"
    public static let syncingLabel = "Syncing"
    public static let waitingLabel = "Waiting"
    public static let actionLabel = "Your attention"
    public static let protectionLabel = "Protection"
    public static let checking = "Checking…"
    public static let healthy = "YadoriLink is running normally"
    public static let healthAttention = "Running, but something needs attention"
    public static let healthDegraded = "Some folders can't sync"
    public static let noFolders = "No folders yet"
    public static let paused = "Syncing is paused"
    public static let upToDate = "Everything is up to date"
    public static let nothingToDo = "Nothing needs you right now"
    public static let unavailableDetail = "Can't tell while YadoriLink isn't running."

    public static func storage(_ size: String) -> String { "YadoriLink keeps \(size) of its own data on this Mac." }
}

public enum ListWording {
    /// "A", "A and B", "A, B and C".
    public static func join(_ names: [String]) -> String {
        switch names.count {
        case 0: ""
        case 1: names[0]
        default: names.dropLast().joined(separator: ", ") + " and " + names[names.count - 1]
        }
    }
}

extension Availability {
    /// `waitingOn` are the display names of the offline devices, when known.
    func sentence(waitingOn names: [String]) -> (String, StatusTone) {
        switch self {
        case .available: ("Not waiting for anything", .ok)
        case .waitingForPeer:
            names.isEmpty
                ? ("Waiting for another device to come online", .info)
                : ("Waiting for \(ListWording.join(names)) to come online", .info)
        case .waitingForExactContent: ("Waiting for the latest version of some files to arrive", .info)
        case .unknown: (SummaryWording.checking, .neutral)
        }
    }
}

public enum ProtectionWording {
    public static let checking = "Checking protection"
    public static let pending = "Protection pending"
    public static let atRisk = "At risk · this Mac is the only confirmed copy"
}

extension Protection {
    /// The one explanatory line, shown only when not protected.
    var detail: String? {
        switch self {
        case .protected: nil
        case .pending: "Copying to another device."
        case .atRisk: "No other device has a confirmed copy yet."
        case .unknown: "Can't confirm a copy on another device right now."
        }
    }

    /// `copies` is how many other devices hold a copy; it only matters when protected.
    func sentence(copies: Int) -> (String, StatusTone) {
        switch self {
        case .protected:
            copies > 1
                ? ("Protected · \(copies) other devices have a copy", .ok)
                : ("Protected · another device has a copy", .ok)
        case .atRisk: (ProtectionWording.atRisk, .danger)
        case .pending: (ProtectionWording.pending, .info)
        case .unknown: (ProtectionWording.checking, .neutral)
        }
    }
}

extension ProductAction {
    public var title: String {
        switch self {
        case .retry: "Try Again"
        case .reviewConflict: "Review Conflict…"
        case .freeUpSpace: "Free Up Space…"
        case .revealPath: "Show in Finder"
        case .openSettings: "Open Settings…"
        case .downloadUpdate: "Update…"
        case .viewDetails: "View Details"
        }
    }
}

// MARK: - File actions

public enum FileAction: CaseIterable, Sendable, Equatable {
    case download, freeUpSpace, keepOnDevice, stopKeeping

    public var title: String {
        switch self {
        case .download: "Download Now"
        case .freeUpSpace: "Free Up Space"
        case .keepOnDevice: "Always Keep on This Device"
        case .stopKeeping: "Stop Keeping on This Device"
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
    ///
    /// A provider folder's files are downloaded by the operating system (open one, or keep it on
    /// this device), so Download now is for ordinary folders only. Free up space is the other way
    /// round: only a provider folder can give space back (an ordinary folder has no placeholder to
    /// leave in the file's place, and the daemon refuses it), and never a file that is kept (the
    /// daemon refuses that too). `retention` is what the daemon says about the file; `nil` (it could
    /// not be read) offers nothing that depends on it. A file kept only because a folder above is has
    /// neither keep action: that folder is what to release.
    public static func available(for availability: FileAvailability, providerFolder: Bool, retention: FileRetention?) -> [FileAction] {
        guard availability.tracked else { return [] }
        var keep: [FileAction] = []
        if let retention {
            switch (retention.policy, retention.inherited) {
            case (.reclaimable, _): keep = [.keepOnDevice]
            case (.pinned, false): keep = [.stopKeeping]
            case (.pinned, true): keep = []
            }
        }
        switch availability.state {
        case .placeholder: return (providerFolder ? [] : [.download]) + keep
        case .hydrated:
            let free: [FileAction] = providerFolder && retention?.policy == .reclaimable ? [.freeUpSpace] : []
            return free + keep
        case .hydrating, .evicting, .unknown: return []
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

/// What a list says when its read failed. An empty list is only ever shown
/// after a read succeeded; these lines stand in for it otherwise.
public enum LoadWording {
    public static let sharedFolders = "Couldn't load shared folders."
    public static let devices = "Couldn't load devices."
    public static let received = "Couldn't load received files."
    public static let members = "Couldn't load who has access."
    public static let folderDetails = "Couldn't load this folder's details."
    public static let fileHistory = "Couldn't load this file's history."
    public static let retry = "Retry"

    /// A refresh failed while an earlier list is still shown.
    public static func stale(_ what: String) -> String {
        "Couldn't refresh \(what). Showing what loaded earlier, which may be out of date."
    }
}

/// "Stop Syncing This Folder…": what stops, what stays, and what the risk is.
public enum UnlinkWording {
    public static let menuTitle = "Stop Syncing This Folder…"
    public static let confirmButton = "Stop Syncing"
    public static let overrideButton = "Stop syncing anyway and accept the risk"

    public static func title(_ folder: FolderSummary) -> String {
        "Stop syncing \(folder.name) on this Mac?"
    }

    public static func message(_ folder: FolderSummary) -> String {
        var lines: [String]
        if folder.provider {
            lines = [
                "YadoriLink will stop syncing \(folder.name) on this Mac and ask macOS to remove it from Finder.",
                "macOS decides what stays on this Mac, and files that were never downloaded won't be available here afterwards.",
            ]
        } else {
            lines = [
                "YadoriLink will stop syncing \(folder.name) on this Mac. The files in the folder stay where they are and are not deleted.",
            ]
            if folder.mode == .onDemand {
                lines.append("Files that were never downloaded to this Mac are not downloaded by this.")
            }
        }
        lines.append("The shared folder and the other devices that sync it are not affected. You can link it again later.")
        return lines.joined(separator: "\n\n")
    }

    public static func overrideTitle(_ folder: FolderSummary) -> String {
        "\(folder.name) may be left without a complete copy"
    }

    public static func overrideMessage(_ folder: FolderSummary) -> String {
        "YadoriLink couldn't confirm that another device can keep a complete copy of \(folder.name). If you stop syncing it here anyway, files that exist only on this Mac may never reach another device."
    }

    public static func success(_ folder: FolderSummary) -> String {
        folder.provider
            ? "Stopped syncing \(folder.name) on this Mac. YadoriLink asked macOS to remove it from Finder."
            : "Stopped syncing \(folder.name) on this Mac. Its files were left in place."
    }
}

/// Updates are checked for by YadoriLink and installed by the user: no
/// wording here may say or imply that YadoriLink installs anything.
public enum UpdateWording {
    public static let downloadButton = "Download Update…"
    public static let showStepsButton = "Show Update Steps…"
    public static let checkButton = "Check Now"
    public static let checkAgainButton = "Check Again"
    public static let releaseNotesButton = "Release Notes…"
    public static let automaticChecks = "Check for updates automatically"
    public static let checksOnlyNote = "YadoriLink only checks for updates. You download and install them yourself."
    public static let checking = "Checking for updates…"
    public static let lookupFailed = "Couldn't check for updates."
    public static let lookupFailedHint = "Check your connection and try again."
    public static let paused = "Updates are paused by the publisher"
    public static let required = "This update is required."
    public static let availableUnnamed = "An update is available"
    public static let couldNotOpenDownloadPage = "Couldn't open the download page. Open it in your browser to get the new version."
    public static let openedDownloadPage = "Opened the download page. Download the new version and install it yourself; YadoriLink doesn't install updates."

    public static func available(_ version: String) -> String { "Update \(version) available" }
    public static func upToDate(_ version: String) -> String { "YadoriLink \(version) is up to date" }
    public static func current(_ version: String) -> String { "YadoriLink \(version)" }
    public static func heldBack(_ version: String) -> String { "Update \(version) isn't offered to this Mac yet" }
    /// `steps` is the daemon's instruction for an install a package manager owns.
    public static func updateSteps(_ steps: String) -> String { steps }
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
