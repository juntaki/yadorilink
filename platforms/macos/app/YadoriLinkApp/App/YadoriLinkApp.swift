import AppKit
import SwiftUI
import YadoriLinkModel
import YadoriLinkUI

/// YadoriLink lives in the menu bar (no Dock icon). The main window,
/// Settings, onboarding and the invite QR code are separate scenes that all
/// read one shared `AppContext`.
@main
struct YadoriLinkApp: App {
    @NSApplicationDelegateAdaptor(InviteLinkDelegate.self) private var delegate
    @State private var context: AppContext

    init() {
        let app = AppModel(client: ClientFactory.makeClient())
        // The provider duties (domains, the materialized report, evict and signal answers, the Eager
        // loop) run on one persistent daemon connection; a change of the provider-folder set asks it
        // to reconcile at once.
        ProviderHostService.shared.start()
        app.onDemandGroupsChanged = { _ in ProviderHostService.shared.requestReconcile() }
        app.start()
        let loginItem = LoginItemModel(service: MainAppLoginItem())
        // Open at login is on by default, independent of whether setup is
        // completed; setup's checkbox only turns it off again.
        loginItem.applyDefaultOnce()
        let context = AppContext(app: app, loginItem: loginItem)
        InviteLinkDelegate.deliver = { context.pendingInviteLink = $0 }
        _context = State(initialValue: context)
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarContentView()
                .environment(context)
        } label: {
            MenuBarLabel(context: context)
        }
        .menuBarExtraStyle(.window)

        Window("YadoriLink", id: WindowID.main) {
            MainWindowView()
                .environment(context)
        }
        .defaultSize(width: 920, height: 660)

        Settings {
            SettingsView(extensions: FinderExtensionStatus())
                .environment(context)
        }

        Window("Set Up YadoriLink", id: WindowID.onboarding) {
            OnboardingView(model: makeOnboarding(.firstRun), extensions: FinderExtensionStatus())
        }
        .windowResizability(.contentSize)

        Window("Add Folder", id: WindowID.addFolder) {
            OnboardingView(model: makeOnboarding(.addFolder))
        }
        .windowResizability(.contentSize)

        Window("Join with Invite Link", id: WindowID.join) {
            JoinInviteView(client: context.app.client, context: context) {
                context.app.refresh()
            }
        }
        .windowResizability(.contentSize)

        // Keyed by invite id; the link stays in memory (see AppContext).
        WindowGroup("Invite", id: WindowID.invite, for: String.self) { $inviteId in
            InviteQRView(url: inviteId.flatMap { context.inviteURL(forQRCode: $0) })
        }
        .handlesExternalEvents(matching: [])
        .windowResizability(.contentSize)
    }

    @MainActor
    private func makeOnboarding(_ flow: OnboardingViewModel.Flow) -> OnboardingViewModel {
        let model = OnboardingViewModel(client: context.app.client, mode: flow, loginItem: context.loginItem, openURL: context.openURL, providerFoldersAvailable: ProviderFolders.available)
        let app = context.app
        model.onLinked = { _ in
            app.refresh()
            Task { await app.refreshAccount() }
        }
        if flow == .firstRun {
            model.onFinished = { UserDefaults.standard.set(true, forKey: MenuBarLabel.didFinishOnboardingKey) }
        }
        return model
    }
}

/// Receives `yadorilink://invite/<code>` links the system hands to the app
/// (a link clicked anywhere, or opened with `open`). A link that arrives
/// before the app has finished starting is held until it has.
final class InviteLinkDelegate: NSObject, NSApplicationDelegate {
    @MainActor static var deliver: ((String) -> Void)? {
        didSet { if let held = heldLink, let deliver { heldLink = nil; deliver(held) } }
    }
    @MainActor private static var heldLink: String?

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first(where: { $0.scheme?.lowercased() == "yadorilink" }) else { return }
        MainActor.assumeIsolated {
            if let deliver = Self.deliver { deliver(url.absoluteString) } else { Self.heldLink = url.absoluteString }
        }
    }
}

/// The menu bar icon. It also opens the launch windows (setup until it has
/// been completed, and the development arguments `LaunchPlan` describes),
/// because the label is the one view that exists from launch.
struct MenuBarLabel: View {
    static let didFinishOnboardingKey = "didFinishOnboarding"

    let context: AppContext
    private var app: AppModel { context.app }
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        // Fixture runs get a flask icon and a title so the menu bar item itself says the data is fake.
        HStack(spacing: 3) {
            Image(systemName: context.isFixture ? "testtube.2" : symbol)
            if context.isFixture { Text("Fixture") }
        }
            .accessibilityLabel("YadoriLink\(context.isFixture ? " (Fixture)" : ""): \(app.headline)")
            .task { openLaunchWindows() }
            .onChange(of: context.pendingInviteLink) { _, link in
                // A clicked yadorilink://invite/ link: the Join window picks it up.
                guard link != nil else { return }
                openWindow(id: WindowID.join)
                NSApp.activate()
            }
    }

    private func openLaunchWindows() {
        let plan = LaunchPlan(
            arguments: CommandLine.arguments,
            didFinishOnboarding: UserDefaults.standard.bool(forKey: Self.didFinishOnboardingKey)
        )
        if plan.showsOnboarding {
            openWindow(id: WindowID.onboarding)
            NSApp.activate()
        }
        if let pane = plan.pane {
            context.sidebar = pane
            openWindow(id: WindowID.main)
            NSApp.activate()
        }
        if let folder = plan.folder {
            context.showFolder(folder)
            openWindow(id: WindowID.main)
            NSApp.activate()
        }
        if plan.showsSettings {
            openSettings()
            NSApp.activate()
        }
    }

    private var symbol: String {
        switch app.overallTone {
        case .ok: "arrow.triangle.2.circlepath.circle"
        case .info: "arrow.triangle.2.circlepath.circle.fill"
        case .neutral: "pause.circle"
        case .warning: "exclamationmark.circle"
        case .danger: "xmark.circle"
        }
    }
}
