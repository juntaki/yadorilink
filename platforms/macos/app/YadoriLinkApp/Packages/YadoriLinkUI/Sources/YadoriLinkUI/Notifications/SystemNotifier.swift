import Foundation
import UserNotifications
import YadoriLinkModel

/// Posts the planner's notices as system notifications and routes taps back into the app.
/// Permission is asked the first time there is something to say, not at launch.
@MainActor
public final class SystemNotifier: NSObject, UNUserNotificationCenterDelegate {
    nonisolated private static let actionKey = "action"
    nonisolated private static let pathKey = "path"
    nonisolated private static let categoryPrefix = "critical."
    nonisolated private static let buttonID = "primary"
    nonisolated private static let allActions: [ProductAction] = [.retry, .reviewConflict, .freeUpSpace, .revealPath, .openSettings, .downloadUpdate, .viewDetails]

    private let planner: CriticalNotificationPlanner
    private let route: (NotificationRoute) -> Void
    private let center = UNUserNotificationCenter.current()

    public init(planner: CriticalNotificationPlanner, route: @escaping (NotificationRoute) -> Void) {
        self.planner = planner
        self.route = route
        super.init()
        center.delegate = self
        center.setNotificationCategories(Set(Self.allActions.map { action in
            UNNotificationCategory(
                identifier: Self.categoryPrefix + String(describing: action),
                actions: [UNNotificationAction(identifier: Self.buttonID, title: action.notificationButtonTitle, options: [.foreground])],
                intentIdentifiers: []
            )
        }))
    }

    public func post(for snapshot: StatusSnapshot) {
        let notices = planner.plan(for: snapshot)
        guard !notices.isEmpty else { return }
        Task { [center] in
            guard await Self.isAllowed(center) else { return }
            for notice in notices {
                let content = UNMutableNotificationContent()
                content.title = notice.title
                content.body = notice.body
                content.categoryIdentifier = Self.categoryPrefix + String(describing: notice.action)
                content.userInfo = [Self.actionKey: String(describing: notice.action), Self.pathKey: notice.folderLocalPath ?? ""]
                // The identity is the request id, so a repeat replaces rather than stacks.
                try? await center.add(UNNotificationRequest(identifier: notice.identity, content: content, trigger: nil))
            }
        }
    }

    private static func isAllowed(_ center: UNUserNotificationCenter) async -> Bool {
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional: return true
        case .notDetermined: return (try? await center.requestAuthorization(options: [.alert])) ?? false
        default: return false
        }
    }

    nonisolated public func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let info = response.notification.request.content.userInfo
        let path = (info[Self.pathKey] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let name = info[Self.actionKey] as? String
        // A tap on the banner shows details; the button performs the notice's own action.
        let action = response.actionIdentifier == Self.buttonID
            ? Self.allActions.first { String(describing: $0) == name } ?? .viewDetails
            : .viewDetails
        await MainActor.run { route(NotificationRoute.route(for: action, folderLocalPath: path)) }
    }

    nonisolated public func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }
}
