import AppKit
import SwiftUI
import UniformTypeIdentifiers
import YadoriLinkFixtures
import YadoriLinkModel

/// The Settings scene (⌘,): General, Updates, Bandwidth, Account, Diagnostics.
public struct SettingsView: View {
    @Environment(AppContext.self) private var context
    /// Hooks the app supplies for the Finder extension status.
    let extensions: ExtensionStatusProvider?

    public init(extensions: ExtensionStatusProvider? = nil) {
        self.extensions = extensions
    }

    public var body: some View {
        TabView {
            GeneralSettingsView(extensions: extensions)
                .tabItem { Label("General", systemImage: "gearshape") }
            UpdatesSettingsView(client: context.app.client)
                .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
            BandwidthSettingsView(client: context.app.client)
                .tabItem { Label("Bandwidth", systemImage: "speedometer") }
            AccountSettingsView(app: context.app)
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
            DiagnosticsSettingsView(client: context.app.client)
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
        }
        .frame(width: 540)
        .frame(minHeight: 380)
    }
}

/// Whether the Finder extension is on, and how to turn it on.
@MainActor
public protocol ExtensionStatusProvider {
    var isFinderExtensionEnabled: Bool { get }
    func openExtensionSettings()
}

extension View {
    /// Keeps `enabled` in step with the Finder extension: read when the
    /// view appears and again whenever the app becomes active, which is
    /// when the user comes back from turning it on in System Settings.
    func readsFinderExtensionStatus(_ extensions: ExtensionStatusProvider?, into enabled: Binding<Bool>) -> some View {
        onAppear { if let extensions { enabled.wrappedValue = extensions.isFinderExtensionEnabled } }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                if let extensions { enabled.wrappedValue = extensions.isFinderExtensionEnabled }
            }
    }
}

struct DaemonGate<Content: View>: View {
    @Environment(AppContext.self) private var context
    @ViewBuilder var content: Content
    var body: some View {
        if context.app.isDaemonUnavailable {
            AppBannerView(.daemonUnavailable, isWorking: context.app.isStartingDaemon) { context.perform(.daemonUnavailable) }
                .padding()
            Spacer()
        } else {
            content
        }
    }
}

struct GeneralSettingsView: View {
    @Environment(AppContext.self) private var context
    @State private var finderExtensionEnabled = true
    let extensions: ExtensionStatusProvider?

    var body: some View {
        let loginItem = context.loginItem
        Form {
            Section("Startup") {
                Toggle(SettingWording.openAtLogin, isOn: Binding(get: { loginItem.isOn }, set: { loginItem.setOn($0) }))
                if loginItem.needsApproval {
                    HStack {
                        Text("Allow YadoriLink in System Settings to finish turning this on.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("Open System Settings") { loginItem.openSystemSettings() }
                    }
                }
                if let error = loginItem.errorText {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
            if let extensions {
                Section("Finder") {
                    LabeledContent("Finder integration", value: finderExtensionEnabled ? "On" : "Off")
                    if !finderExtensionEnabled {
                        Text("Turn it on to see sync status in Finder and use the YadoriLink menu on files.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("Open Extension Settings…") { extensions.openExtensionSettings() }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { loginItem.refresh() }
        .readsFinderExtensionStatus(extensions, into: $finderExtensionEnabled)
    }
}

struct UpdatesSettingsView: View {
    @State private var model: UpdatesModel
    @State private var showsVersionDetails = false

    init(client: any YadoriLinkClient) { _model = State(initialValue: UpdatesModel(client: client)) }

    var body: some View {
        DaemonGate {
            Form {
                Section {
                    HStack {
                        Text(model.headline).font(.headline)
                        Spacer()
                        if model.canInstall {
                            Button("Install") { Task { await model.install() } }.disabled(model.isWorking)
                        } else {
                            Button("Check Now") { Task { await model.check() } }.disabled(model.isWorking)
                        }
                    }
                    ForEach(model.notes, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                    Text(model.lastChecked).font(.caption).foregroundStyle(.secondary)
                    Toggle("Check for updates automatically", isOn: Binding(
                        get: { model.automaticChecks },
                        set: { on in Task { await model.setAutomaticChecks(on) } }
                    ))
                    if let status = model.status {
                        DisclosureGroup("Version details", isExpanded: $showsVersionDetails) {
                            LabeledContent("Version", value: status.currentVersion)
                            LabeledContent("Channel", value: status.channel)
                            LabeledContent("Installed from", value: status.installSource)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .noticeBar($model.notice)
            .task { await model.load() }
        }
    }
}

struct BandwidthSettingsView: View {
    @State private var model: BandwidthModel

    init(client: any YadoriLinkClient) { _model = State(initialValue: BandwidthModel(client: client)) }

    var body: some View {
        DaemonGate {
            Form {
                Section {
                    limitField("Upload limit", text: $model.uploadText, error: model.uploadError)
                    limitField("Download limit", text: $model.downloadText, error: model.downloadError)
                    Text("Leave empty for no limit.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Spacer()
                        Button("Save") { Task { await model.save() } }
                            .keyboardShortcut(.defaultAction)
                            .disabled(!model.canSave)
                    }
                }
            }
            .formStyle(.grouped)
            .noticeBar($model.notice)
            .task { await model.load() }
        }
    }

    private func limitField(_ title: String, text: Binding<String>, error: String?) -> some View {
        LabeledContent(title) {
            VStack(alignment: .trailing, spacing: 2) {
                HStack {
                    TextField(title, text: text, prompt: Text("No limit"))
                        .labelsHidden()
                        .frame(width: 90)
                        .multilineTextAlignment(.trailing)
                    Text("MiB/s").foregroundStyle(.secondary)
                }
                if let error { Text(error).font(.caption).foregroundStyle(.red) }
            }
        }
    }
}

struct DiagnosticsSettingsView: View {
    let client: any YadoriLinkClient
    @State private var notice: Notice?
    @State private var isExporting = false

    var body: some View {
        Form {
            Section {
                Text("Save a report to send when asking for help. Sensitive details are redacted before it is saved.")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Export Diagnostics…") { export() }.disabled(isExporting)
                }
            }
        }
        .formStyle(.grouped)
        .noticeBar($notice)
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "YadoriLink Diagnostics.zip"
        panel.allowedContentTypes = [.zip]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        isExporting = true
        Task {
            defer { isExporting = false }
            do {
                let result = try await client.exportDiagnostics(destinationPath: url.path)
                notice = Notice(kind: .success, text: "Saved \(url.lastPathComponent).", detail: "\(result.redactionCount) items removed")
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: result.path)])
            } catch {
                notice = .failure(error)
            }
        }
    }
}

// MARK: - Account

struct AccountSettingsView: View {
    @Environment(AppContext.self) private var context
    @State private var model: AccountViewModel
    @State private var showsDeletion = false
    @State private var confirmSignOut = false
    @State private var showsSignIn = false

    init(app: AppModel) { _model = State(initialValue: AccountViewModel(app: app)) }

    var body: some View {
        Form {
            if let banner = model.banner {
                Section {
                    AppBannerView(banner) { showsSignIn = true }
                }
            }
            Group {
                Section("Devices on your account") {
                    if model.devices.isEmpty && model.sectionsEnabled { LoadingRow() }
                    ForEach(model.devices) { device in
                        HStack {
                            Text(device.name).help(device.tooltip)
                            Spacer()
                            Text(device.detail).foregroundStyle(.secondary)
                        }
                    }
                }
                Section {
                    Button("Sign Out…") { confirmSignOut = true }
                }
                Section("Your data") {
                    HStack {
                        Text("Save a copy of your account data.")
                        Spacer()
                        Button("Export…") { exportData() }
                    }
                    DisclosureGroup("Delete account…", isExpanded: $showsDeletion) {
                        Text("Deleting your account removes your account, devices and shared folders from the YadoriLink service and stops every device from syncing. The folders on your devices are not deleted; they stay yours.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if let line = model.deletionLine { Text(line) }
                        if let token = model.deletionToken {
                            LabeledContent("Confirmation code") { Text(token).font(.body.monospaced()).textSelection(.enabled) }
                            Button("Delete My Account", role: .destructive) { Task { await model.confirmDeletion() } }
                        } else if model.deletion?.state == .grace || model.deletion?.state == .requested {
                            Button("Cancel Deletion") { Task { await model.cancelDeletion() } }
                        } else {
                            Button("Request Deletion…", role: .destructive) { Task { await model.requestDeletion() } }
                        }
                    }
                }
            }
            .disabled(!model.sectionsEnabled)
        }
        .formStyle(.grouped)
        .noticeBar($model.notice)
        .confirmationDialog("Sign out of YadoriLink?", isPresented: $confirmSignOut) {
            Button("Cancel", role: .cancel) {}
            Button("Sign Out", role: .destructive) { Task { await model.signOut() } }
        } message: {
            Text("Folders stop syncing until you sign in again. Files stay on this Mac.")
        }
        .sheet(isPresented: $showsSignIn) {
            SignInView(model: context.makeSignInModel())
        }
        .task(id: context.app.isSignedIn) { await model.load() }
    }

    private func exportData() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "YadoriLink Account.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await model.exportData(to: url) }
    }
}

#Preview("Settings") { SettingsView().environment(AppContext.fixture(.healthy)) }
#Preview("Settings – signed out") { SettingsView().environment(AppContext.fixture(.signedOut)) }
#Preview("Settings – daemon down") { SettingsView().environment(AppContext.fixture(.daemonDown)) }
