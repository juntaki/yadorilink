import AppKit
import Observation
import SwiftUI
import YadoriLinkFixtures
import YadoriLinkModel

/// Scene identifiers shared by the app and the views that open windows.
public enum WindowID {
    public static let main = "main"
    public static let onboarding = "onboarding"
    public static let addFolder = "add-folder"
    public static let invite = "invite"
}

public enum SidebarItem: String, CaseIterable, Identifiable, Hashable, Sendable {
    case home, folders, devices, transfers, storage
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .home: "Home"
        case .folders: "Folders"
        case .devices: "Devices"
        case .transfers: "Transfers"
        case .storage: "Storage"
        }
    }
    public var systemImage: String {
        switch self {
        case .home: "house"
        case .folders: "folder"
        case .devices: "laptopcomputer.and.iphone"
        case .transfers: "arrow.up.arrow.down"
        case .storage: "internaldrive"
        }
    }
}

/// A folder the share sheet is open for.
public struct ShareTarget: Identifiable, Hashable, Sendable {
    public var id: String { groupId }
    public var groupId: String
    public var folderName: String
}

/// Everything the scenes share: the app model, the login-item model, the
/// main window's navigation, and the few AppKit hooks the views need.
@MainActor
@Observable
public final class AppContext {
    public let app: AppModel
    public let loginItem: LoginItemModel
    public var sidebar: SidebarItem? = .home
    public var folderPath: [String] = []
    public var shareTarget: ShareTarget?
    public var showsSignIn = false
    @ObservationIgnored public let openURL: (URL) -> Void

    public init(app: AppModel, loginItem: LoginItemModel, openURL: @escaping (URL) -> Void = { NSWorkspace.shared.open($0) }) {
        self.app = app
        self.loginItem = loginItem
        self.openURL = openURL
    }

    public func showFolder(_ localPath: String) {
        sidebar = .folders
        folderPath = [localPath]
    }

    /// Runs the banner's single action.
    public func perform(_ banner: AppBanner) {
        switch banner {
        case .daemonUnavailable: Task { await app.startDaemon() }
        case .signedOut, .credentialStoreUnusable: showsSignIn = true
        }
    }

    /// A sign-in flow that refreshes the account when it completes.
    public func makeSignInModel() -> SignInModel {
        let model = SignInModel(client: app.client, openURL: openURL)
        model.onSignedIn = { [weak app] _ in Task { await app?.refreshAccount() } }
        return model
    }

    /// Invite links whose QR window was opened in this run, by invite id.
    /// The Invite window is keyed by the id, not the link: window
    /// restoration saves a window's value to disk, and the link is a
    /// bearer credential that may be cancelled or expire meanwhile.
    @ObservationIgnored private var invitesForQRCode: [String: String] = [:]

    /// Remembers `invite` for its QR window and returns the window's value.
    public func showQRCode(for invite: InviteSummary) -> String {
        invitesForQRCode[invite.inviteId] = invite.url
        return invite.inviteId
    }

    /// The link for an Invite window, or `nil` when the window was restored
    /// from an earlier run.
    public func inviteURL(forQRCode inviteId: String) -> String? {
        invitesForQRCode[inviteId]
    }

    public func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}

// MARK: - Preview support

/// A login-item service that only remembers its state, for Previews.
public final class PreviewLoginItemService: LoginItemService {
    public var status: LoginItemStatus
    public init(status: LoginItemStatus = .enabled) { self.status = status }
    public func register() throws { status = .enabled }
    public func unregister() throws { status = .notRegistered }
    public func openSystemSettingsLoginItems() {}
}

extension AppContext {
    /// A started context over the fake client, for Previews and fixture runs.
    public static func fixture(_ scenario: FakeScenario, loginItem: any LoginItemService = PreviewLoginItemService()) -> AppContext {
        let app = AppModel(client: FakeYadoriLinkClient(scenario: scenario))
        app.start()
        return AppContext(app: app, loginItem: LoginItemModel(service: loginItem), openURL: { _ in })
    }
}
