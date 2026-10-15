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
    public static let join = "join-invite"
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

public enum SettingsTab: Hashable, Sendable { case general, updates, bandwidth, account, diagnostics }

/// A folder the share sheet is open for.
public struct ShareTarget: Identifiable, Hashable, Sendable {
    public var id: String { groupId }
    public var groupId: String
    public var folderName: String
}

/// A file an item link wants preselected in one folder's detail.
public struct FileSelectionRequest: Equatable, Sendable {
    public var folderLocalPath: String
    public var path: String
    fileprivate let id = UUID()
}

/// Everything the scenes share: the app model, the login-item model, the
/// main window's navigation, and the few AppKit hooks the views need.
@MainActor
@Observable
public final class AppContext {
    public let app: AppModel
    public let loginItem: LoginItemModel
    public let unlink: UnlinkModel
    public var sidebar: SidebarItem? = .home
    /// The Settings tab to show; set before opening Settings from elsewhere.
    public var settingsTab: SettingsTab = .general
    public var folderPath: [String] = []
    public var shareTarget: ShareTarget?
    public var showsSignIn = false
    /// An invite link received from the system (a clicked `yadorilink://` link),
    /// waiting for the Join window to pick it up.
    public var pendingInviteLink: String?
    /// A Finder "View YadoriLink Status" request, waiting for the first status so it can be
    /// resolved against the linked folders.
    public private(set) var pendingItemPath: String?
    /// The file a routed item link wants preselected in a folder's detail; taken once by that folder.
    public private(set) var fileSelection: FileSelectionRequest?
    /// Bumped when something outside the window (a notification) wants the main window shown.
    public private(set) var mainWindowRequests = 0
    @ObservationIgnored public let openURL: (URL) -> Void

    public init(app: AppModel, loginItem: LoginItemModel, openURL: @escaping (URL) -> Void = { NSWorkspace.shared.open($0) }) {
        self.app = app
        self.loginItem = loginItem
        self.openURL = openURL
        self.unlink = UnlinkModel(app: app)
        // Leave any folder screen that points at what was just unlinked.
        unlink.onUnlinked = { [weak self] path in self?.folderPath.removeAll { $0 == path } }
    }

    /// True when the app runs on the fake client: everything shown is made up.
    public var isFixture: Bool { app.client is FakeYadoriLinkClient }

    public func showFolder(_ localPath: String) {
        sidebar = .folders
        folderPath = [localPath]
    }

    /// Takes a link the system delivered.
    public func receive(_ link: AppLink) {
        switch link {
        case .invite(let url): pendingInviteLink = url
        case .item(let path): pendingItemPath = path
        }
    }

    /// Opens the folder an item link leads to, once the linked folders are known. Returns `false`
    /// while it must keep waiting for the first status; `true` once it is decided, whether it
    /// opened something or the path belongs to no linked folder (then nothing opens).
    @discardableResult
    public func routePendingItem() -> Bool {
        guard let path = pendingItemPath else { return true }
        guard let snapshot = app.snapshot else { return false }
        pendingItemPath = nil
        guard let destination = ItemLinkRouting.destination(for: path, linkedFolders: snapshot.folders.map(\.localPath), canonicalize: ItemLinkRouting.realPath) else {
            return true
        }
        showFolder(destination.folderLocalPath)
        fileSelection = destination.selectedPath.map {
            FileSelectionRequest(folderLocalPath: destination.folderLocalPath, path: $0)
        }
        return true
    }

    /// The file to preselect in `folderLocalPath`'s detail, if a link asked for one there.
    public func takeFileSelection(for folderLocalPath: String) -> String? {
        guard let request = fileSelection, request.folderLocalPath == folderLocalPath else { return nil }
        fileSelection = nil
        return request.path
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

    /// Carries out where a notification or its button leads.
    public func handle(_ route: NotificationRoute) {
        switch route {
        case .showFolder(let path): showFolder(path); mainWindowRequests += 1
        case .openStorage: sidebar = .storage; mainWindowRequests += 1
        case .openHome: sidebar = .home; mainWindowRequests += 1
        case .revealInFinder(let path): revealInFinder(path)
        case .openSettings: NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil); NSApp.activate()
        case .refresh: app.refresh()
        }
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

/// A small, always-visible mark that the data on screen is fixture data.
struct FixtureBadge: View {
    var body: some View {
        Label("Fixture", systemImage: "testtube.2")
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .foregroundStyle(.orange)
            .background(.orange.opacity(0.15), in: Capsule())
            .help("Fixture data: this is not your real YadoriLink state.")
            .accessibilityLabel("Fixture data, not real")
    }
}
