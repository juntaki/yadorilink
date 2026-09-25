import AppKit
import SwiftUI
import YadoriLinkModel
import YadoriLinkUI

/// YadoriLink lives in the menu bar (no Dock icon). The main window,
/// Settings, onboarding and the invite QR code are separate scenes that all
/// read one shared `AppContext`.
@main
struct YadoriLinkApp: App {
    @State private var context: AppContext

    init() {
        let app = AppModel(client: ClientFactory.makeClient())
        // Keep File Provider domains in step with the daemon: once at launch
        // and whenever the On-Demand folder set changes. The reconciliation
        // asks the daemon itself and leaves domains alone when it can't.
        // Runs never overlap: a change during a run queues one more run.
        let reconciler = CoalescingRunner { done in DomainRegistration.reconcileInBackground(done: done) }
        app.onDemandGroupsChanged = { _ in reconciler.request() }
        reconciler.request()
        app.start()
        let loginItem = LoginItemModel(service: MainAppLoginItem())
        // Open at login is on by default, independent of whether setup is
        // completed; setup's checkbox only turns it off again.
        loginItem.applyDefaultOnce()
        _context = State(initialValue: AppContext(app: app, loginItem: loginItem))
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

        // Keyed by invite id; the link stays in memory (see AppContext).
        WindowGroup("Invite", id: WindowID.invite, for: String.self) { $inviteId in
            InviteQRView(url: inviteId.flatMap { context.inviteURL(forQRCode: $0) })
        }
        .windowResizability(.contentSize)
    }

    @MainActor
    private func makeOnboarding(_ flow: OnboardingViewModel.Flow) -> OnboardingViewModel {
        let model = OnboardingViewModel(client: context.app.client, mode: flow, loginItem: context.loginItem, openURL: context.openURL)
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
        Image(systemName: symbol)
            .accessibilityLabel("YadoriLink: \(app.headline)")
            .task { openLaunchWindows() }
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

extension DomainRegistration {
    /// The daemon query blocks for up to its own timeout, so it never runs
    /// on the main thread. `done` runs once the whole run has finished.
    static func reconcileInBackground(done: @escaping @Sendable () -> Void) {
        DispatchQueue.global(qos: .utility).async { registerOnDemandDomains(completion: done) }
    }
}
