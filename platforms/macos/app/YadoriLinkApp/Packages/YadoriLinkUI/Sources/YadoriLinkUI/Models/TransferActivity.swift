import Foundation
import YadoriLinkModel

/// The daemon's measured aggregate transfer rate, as one short phrase.
/// The rate is global (all folders and devices), never per file, and the
/// UI never estimates its own: a direction at zero is idle and is omitted.
enum TransferRate {
    static func text(_ bandwidth: BandwidthStatus) -> String? {
        var parts: [String] = []
        if bandwidth.currentDownloadBytesPerSec > 0 { parts.append("↓ \(Format.bytes(bandwidth.currentDownloadBytesPerSec))/s") }
        if bandwidth.currentUploadBytesPerSec > 0 { parts.append("↑ \(Format.bytes(bandwidth.currentUploadBytesPerSec))/s") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    static func appending(rate: String?, to line: String) -> String {
        rate.map { "\(line) · \($0)" } ?? line
    }
}

/// What a recent daemon error means to a person. Only categories with a
/// stable plain reading map; the rest stay diagnostic (tooltip/CLI only).
enum RecentProblemKind: CaseIterable {
    case file, connection, disk, storage, conflict, protocolMismatch

    init?(category: String) {
        switch category {
        case "io", "permission": self = .file
        case "peer_unreachable", "transport", "no_route", "channel_closed": self = .connection
        case "disk_pressure": self = .disk
        case "storage", "corrupt_state", "block_integrity": self = .storage
        case "conflict": self = .conflict
        case "protocol": self = .protocolMismatch
        default: return nil
        }
    }

    var text: String {
        switch self {
        case .file: "A file couldn't sync"
        case .connection: "Connection was interrupted"
        case .disk: "Disk space stopped syncing"
        case .storage: "Local storage reported a problem"
        case .conflict: "A file changed while syncing"
        case .protocolMismatch: "A device sent data that couldn't be read"
        }
    }

    /// A still-active attention reason of this kind already says it; then no recent item.
    var activeCategories: Set<AttentionCategory> {
        switch self {
        case .connection: [.peerDisconnected]
        case .disk: [.lowDisk, .lowDiskCritical]
        case .conflict: [.conflict]
        default: []
        }
    }
}

struct RecentProblem: Equatable {
    var text: String
    var age: String?
    /// Raw daemon category, for the hover/diagnostic path only.
    var tooltip: String
}

enum RecentProblems {
    static let limit = 3

    /// Newest first, one item per meaning, at most `limit`, minus anything still active.
    static func items(errors: [RecentError], activeReasons: [AttentionReason], now: Date) -> [RecentProblem] {
        let active = Set(activeReasons.map(\.category))
        var latest: [RecentProblemKind: (at: Date?, category: String)] = [:]
        for error in errors {
            guard let kind = RecentProblemKind(category: error.category),
                  active.isDisjoint(with: kind.activeCategories) else { continue }
            if let seen = latest[kind], !isNewer(error.at, than: seen.at) { continue }
            latest[kind] = (error.at, error.category)
        }
        return latest
            .sorted { isNewer($0.value.at, than: $1.value.at) }
            .prefix(limit)
            .map { kind, entry in
                RecentProblem(text: kind.text, age: entry.at.map { Format.relative($0, now: now) }, tooltip: entry.category)
            }
    }

    /// `recent_error:*` reasons whose meaning the recent section presents are
    /// dropped from the current attention list; unmapped ones collapse to one line.
    static func attentionReasons(_ reasons: [AttentionReason]) -> [AttentionReason] {
        var seenUnmapped = false
        return reasons.filter { reason in
            guard reason.category == .recentError else { return true }
            if RecentProblemKind(category: reason.subject) != nil { return false }
            defer { seenUnmapped = true }
            return !seenUnmapped
        }
    }

    private static func isNewer(_ a: Date?, than b: Date?) -> Bool {
        switch (a, b) {
        case let (a?, b?): a > b
        case (_?, nil): true
        default: false
        }
    }
}
