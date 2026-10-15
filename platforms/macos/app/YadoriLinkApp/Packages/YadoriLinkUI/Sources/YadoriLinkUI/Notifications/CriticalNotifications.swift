import Foundation
import YadoriLinkModel

/// One system notification to post.
public struct CriticalNotice: Sendable, Equatable {
    /// Stable per (attention category, subject, folder). Reposting it replaces, never stacks.
    public var identity: String
    public var title: String
    public var body: String
    public var action: ProductAction
    public var folderLocalPath: String?
}

/// Where a tapped notification or one of its buttons leads inside the app.
public enum NotificationRoute: Sendable, Equatable {
    case showFolder(String)
    case revealInFinder(String)
    case openStorage
    case openSettings
    case openHome
    case refresh

    /// The same remediation the window offers for `action`.
    public static func route(for action: ProductAction, folderLocalPath: String?) -> NotificationRoute {
        switch action {
        case .reviewConflict, .viewDetails:
            folderLocalPath.map(NotificationRoute.showFolder) ?? .openHome
        case .freeUpSpace: .openStorage
        case .revealPath: folderLocalPath.map(NotificationRoute.revealInFinder) ?? .openHome
        case .openSettings: .openSettings
        case .downloadUpdate: .openHome
        case .retry: .refresh
        }
    }
}

/// The small set of identities already announced and still active, kept across launches.
public protocol NotifiedStore: AnyObject {
    func load() -> Set<String>
    func save(_ identities: Set<String>)
}

public final class DefaultsNotifiedStore: NotifiedStore {
    private let defaults: UserDefaults
    private let key: String
    public init(defaults: UserDefaults = .standard, key: String = "criticalNotificationsActive") {
        self.defaults = defaults
        self.key = key
    }
    public func load() -> Set<String> { Set(defaults.stringArray(forKey: key) ?? []) }
    public func save(_ identities: Set<String>) { defaults.set(identities.sorted(), forKey: key) }
}

/// Decides which newly appeared attention items deserve a system notification.
///
/// The attention list is the only source of truth: a notice is the difference between the
/// critical items now and the ones already announced. The announced set is exactly the critical
/// items that were active last time, so an item that is still active after a restart is silent,
/// one that resolved is forgotten without a notice, and one that comes back is new again.
public final class CriticalNotificationPlanner {
    /// More new items than this collapse into one summary notice, so a first launch with
    /// many open problems does not flood the screen.
    public static let summaryThreshold = 3

    private let store: NotifiedStore
    private var announced: Set<String>

    public init(store: NotifiedStore) {
        self.store = store
        self.announced = store.load()
    }

    /// Items worth interrupting for: they need the user and time will not fix them.
    static func isCritical(_ reason: AttentionReason) -> Bool {
        guard reason.kind == .permanent else { return false }
        switch reason.category {
        case .conflict, .lowDiskCritical, .ownershipLost, .volumeChanged, .ambiguous: return true
        default: return false
        }
    }

    static func identity(_ reason: AttentionReason) -> String {
        "\(reason.category)|\(reason.subject)|\(reason.folderLocalPath ?? "")"
    }

    /// Call with every snapshot, in order. A daemon that does not answer is not a snapshot.
    public func plan(for snapshot: StatusSnapshot) -> [CriticalNotice] {
        var active: [String: AttentionReason] = [:]
        for reason in snapshot.attentionReasons where Self.isCritical(reason) {
            active[Self.identity(reason)] = reason
        }
        let fresh = active.keys.filter { !announced.contains($0) }.sorted()
        if Set(active.keys) != announced {
            announced = Set(active.keys)
            store.save(announced)
        }
        let notices = fresh.compactMap { id in active[id].map { Self.notice(id, $0, snapshot) } }
        if notices.count > Self.summaryThreshold {
            return [CriticalNotice(
                identity: "summary",
                title: "YadoriLink needs your attention",
                body: Plural.issues(notices.count) + ".",
                action: .viewDetails,
                folderLocalPath: nil
            )]
        }
        return notices
    }

    private static func notice(_ id: String, _ reason: AttentionReason, _ snapshot: StatusSnapshot) -> CriticalNotice {
        CriticalNotice(
            identity: id,
            title: reason.category.notificationTitle,
            body: reason.category.sentence(subject: subjectName(reason, snapshot)),
            action: reason.primaryAction,
            folderLocalPath: reason.folderLocalPath
        )
    }

    private static func subjectName(_ reason: AttentionReason, _ snapshot: StatusSnapshot) -> String? {
        if let path = reason.folderLocalPath {
            return snapshot.folders.first { $0.localPath == path }?.name
        }
        let onVolume = snapshot.folders.filter { $0.volume?.path == reason.subject }
        return reason.category == .lowDiskCritical && onVolume.count == 1 ? onVolume[0].name : nil
    }
}

extension AttentionCategory {
    var notificationTitle: String {
        switch self {
        case .conflict: "Conflicting copies"
        case .lowDiskCritical: "Disk almost full"
        case .ownershipLost: "Folder access lost"
        case .volumeChanged: "Folder is on another disk"
        case .ambiguous: "Folder set up twice"
        default: "YadoriLink needs your attention"
        }
    }
}

extension ProductAction {
    /// The notification button label.
    public var notificationButtonTitle: String {
        switch self {
        case .retry: "Try Again"
        case .reviewConflict: "Review"
        case .freeUpSpace: "Free Up Space"
        case .revealPath: "Show in Finder"
        case .openSettings: "Open Settings"
        case .downloadUpdate: "Get Update"
        case .viewDetails: "View Details"
        }
    }
}
