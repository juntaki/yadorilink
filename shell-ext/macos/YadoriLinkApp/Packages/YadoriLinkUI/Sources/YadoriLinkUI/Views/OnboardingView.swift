import SwiftUI
import UniformTypeIdentifiers
import YadoriLinkFixtures
import YadoriLinkModel

/// First-run setup, and the shorter "Add Folder…" flow. Back is on the
/// left, the primary action on the right, and Return triggers it.
public struct OnboardingView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: OnboardingViewModel
    @State private var picksFolder = false
    @State private var finderExtensionEnabled = true
    let extensions: ExtensionStatusProvider?

    public init(model: OnboardingViewModel, extensions: ExtensionStatusProvider? = nil) {
        _model = State(initialValue: model)
        self.extensions = extensions
    }

    public var body: some View {
        HStack(spacing: 0) {
            if model.flow == .firstRun {
                sidebar
                Divider()
            }
            VStack(alignment: .leading, spacing: 16) {
                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if let notice = model.notice {
                    NoticeView(notice) { model.notice = nil }
                }
                buttons
            }
            .padding(24)
        }
        .frame(width: model.flow == .firstRun ? 640 : 480, height: 420)
        .fileImporter(isPresented: $picksFolder, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result { Task { await model.chooseFolder(url.path) } }
        }
        .onChange(of: model.isFinished) { _, finished in if finished { dismiss() } }
        .task { await model.prepare() }
        .readsFinderExtensionStatus(extensions, into: $finderExtensionEnabled)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(model.steps, id: \.self) { step in
                let index = model.steps.firstIndex(of: step) ?? 0
                let current = model.steps.firstIndex(of: model.step) ?? 0
                HStack(spacing: 8) {
                    Image(systemName: index < current ? "checkmark.circle.fill" : index == current ? "circle.inset.filled" : "circle")
                        .foregroundStyle(index <= current ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    Text(step.title).fontWeight(index == current ? .semibold : .regular)
                }
                .accessibilityElement(children: .combine)
                .accessibilityValue(model.progress(of: step))
                .accessibilityAddTraits(index == current ? .isSelected : [])
            }
            Spacer()
        }
        .padding(20)
        .frame(width: 170, alignment: .leading)
        .background(.background.secondary)
    }

    @ViewBuilder private var content: some View {
        switch model.step {
        case .welcome:
            VStack(alignment: .leading, spacing: 12) {
                Text("Welcome to YadoriLink").font(.largeTitle.weight(.semibold))
                Text("Keep folders in sync across your devices, directly between them.")
                    .font(.title3).foregroundStyle(.secondary)
            }
        case .signIn:
            VStack(alignment: .leading, spacing: 12) {
                Text("Sign in").font(.title.weight(.semibold))
                SignInStatusView(model: model.signIn)
            }
        case .chooseFolder:
            VStack(alignment: .leading, spacing: 12) {
                Text(model.flow == .firstRun ? "Choose a folder to sync" : "Add a folder").font(.title.weight(.semibold))
                Text("Pick a folder on this Mac. You'll review it before anything is shared.")
                    .foregroundStyle(.secondary)
                Button("Choose Folder…") { picksFolder = true }
                if model.isWorking { LoadingRow("Checking the folder…") }
            }
        case .review:
            review
        case .done:
            VStack(alignment: .leading, spacing: 14) {
                Text("You're all set").font(.title.weight(.semibold))
                if let linked = model.linked {
                    Text("\((linked.localPath as NSString).lastPathComponent) now syncs as \(linked.mode.title).")
                        .foregroundStyle(.secondary)
                }
                if let extensions, !finderExtensionEnabled {
                    HStack {
                        Text("Turn on Finder integration to see sync status in Finder.")
                        Button("Open Extension Settings…") { extensions.openExtensionSettings() }
                    }
                    .font(.callout)
                }
                Toggle(model.startAtLoginTitle, isOn: $model.startAtLogin)
                if model.loginItem.needsApproval {
                    Text("Allow YadoriLink in System Settings to finish turning this on.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var review: some View {
        Form {
            Section("Before linking") {
                LabeledContent("Folder") {
                    Text(model.folderPath.map { ($0 as NSString).lastPathComponent } ?? "")
                        .help(model.folderPath ?? "")
                }
                if let summary = model.summaryLine {
                    Text(summary).foregroundStyle(.secondary)
                }
                ForEach(model.issueLines, id: \.self) { line in
                    Label(line, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                if model.needsAcknowledgement {
                    Toggle("I understand, link this folder anyway", isOn: $model.acknowledgedRisks)
                }
            }
            Section("Sync with") {
                Picker("Sync with", selection: $model.destinationId) {
                    ForEach(model.destinations) { Text($0.title).tag($0.id) }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
                if model.destinationId == "new" {
                    TextField("Shared folder name", text: $model.newFolderName)
                }
            }
            Section("Files on this Mac") {
                Picker("Files on this Mac", selection: $model.folderMode) {
                    ForEach(FolderMode.allCases, id: \.self) { mode in
                        VStack(alignment: .leading) {
                            Text(mode.title)
                            Text(mode.hint).font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(mode)
                    }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private var buttons: some View {
        HStack {
            if model.canGoBack {
                Button("Back") { model.back() }
            }
            Spacer()
            switch model.step {
            case .welcome:
                Button("Continue") { model.next() }.keyboardShortcut(.defaultAction)
            case .signIn:
                if model.signIn.phase == .signedIn {
                    Button("Continue") { model.next() }.keyboardShortcut(.defaultAction)
                } else {
                    if model.signIn.isRunning {
                        Button("Cancel") { model.signIn.cancel() }
                    }
                    Button(model.signIn.canRetry ? "Try Again" : "Sign In with Browser") {
                        Task { await model.signIn.run() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.signIn.isRunning)
                }
            case .chooseFolder:
                if model.flow == .firstRun {
                    Button("Skip for Now") { model.skipToDone() }
                }
            case .review:
                Button("Link Folder") { Task { await model.link() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canLink)
            case .done:
                Button("Done") { model.finish() }.keyboardShortcut(.defaultAction)
            }
        }
    }
}

#Preview("Onboarding – signed out") {
    OnboardingView(model: OnboardingViewModel(client: FakeYadoriLinkClient(scenario: .signedOut), mode: .firstRun, loginItem: LoginItemModel(service: PreviewLoginItemService(status: .notRegistered)), openURL: { _ in }))
}

#Preview("Add folder") {
    OnboardingView(model: OnboardingViewModel(client: FakeYadoriLinkClient(scenario: .healthy), mode: .addFolder, loginItem: LoginItemModel(service: PreviewLoginItemService()), openURL: { _ in }))
}
