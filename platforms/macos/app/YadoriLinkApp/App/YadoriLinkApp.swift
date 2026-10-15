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
        InviteLinkDelegate.deliver = { context.receive($0) }
        if !context.isFixture {
            let notifier = SystemNotifier(planner: CriticalNotificationPlanner(store: DefaultsNotifiedStore())) { [weak context] route in
                context?.handle(route)
            }
            app.onSnapshot = { notifier.post(for: $0) }
        }
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

/// Receives `yadorilink://` links the system hands to the app (an invite clicked anywhere, the
/// Finder extension's item link, or `open`), whether the app was launched by the link or was
/// already running. A link that arrives before the app has finished starting is held until it has.
final class InviteLinkDelegate: NSObject, NSApplicationDelegate {
    @MainActor static var deliver: ((AppLink) -> Void)? {
        didSet { if let held = heldLink, let deliver { heldLink = nil; deliver(held) } }
    }
    @MainActor private static var heldLink: AppLink?

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let link = urls.lazy.compactMap({ AppLink(url: $0) }).first else { return }
        MainActor.assumeIsolated {
            if let deliver = Self.deliver { deliver(link) } else { Self.heldLink = link }
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
            .onChange(of: context.pendingItemPath) { _, path in
                // A Finder "View YadoriLink Status": open the main window, then route as soon as
                // the linked folders are known.
                guard path != nil else { return }
                openWindow(id: WindowID.main)
                NSApp.activate()
                context.routePendingItem()
            }
            .onChange(of: context.app.snapshot != nil) { _, _ in context.routePendingItem() }
            .onChange(of: context.mainWindowRequests) { _, _ in
                openWindow(id: WindowID.main)
                NSApp.activate()
            }
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
        // A Finder item link that launched the app arrived before this label existed, so
        // `onChange` never saw it.
        if context.pendingItemPath != nil {
            openWindow(id: WindowID.main)
            NSApp.activate()
            context.routePendingItem()
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
