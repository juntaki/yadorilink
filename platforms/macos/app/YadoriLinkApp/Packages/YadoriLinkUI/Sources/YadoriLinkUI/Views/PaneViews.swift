import AppKit
import SwiftUI
import YadoriLinkFixtures
import YadoriLinkModel

// MARK: - Devices

public struct DevicesView: View {
    @Environment(AppContext.self) private var context
    public init() {}
    public var body: some View { DevicesContent(app: context.app) }
}

struct DevicesContent: View {
    @State private var model: DevicesViewModel
    @State private var confirmRemoval: ManagedDevice?

    init(app: AppModel) { _model = State(initialValue: DevicesViewModel(app: app)) }

    private func removeButton(_ device: ManagedDevice) -> some View {
        Button("Remove Device…", role: .destructive) { confirmRemoval = device }
    }

    var body: some View {
        List {
            if !model.warnings.isEmpty {
                Section { WarningList(warnings: model.warnings) }
            }
            Section {
                switch model.phase {
                case .notLoaded:
                    if model.banner != nil { EmptyStateText("Sign in to see your devices.") }
                case .loading:
                    LoadingRow()
                case .failed(let notice):
                    RetryRow(LoadWording.devices, notice: notice) { await model.load() }
                case .loaded(let devices):
                    if let stale = model.staleNotice {
                        RetryRow(LoadWording.stale("devices"), notice: stale) { await model.load() }
                    }
                    if devices.isEmpty && model.staleNotice == nil { EmptyStateText("No devices yet.") }
                    ForEach(devices) { device in
                        HStack(spacing: 10) {
                            OnlineDot(online: device.online)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(device.name)
                                Text(device.detail).font(.caption).foregroundStyle(.secondary)
                            }
                            .help(device.id)
                            Spacer()
                            if device.canRemove {
                                RowActionsMenu(label: "Actions for \(device.name)") { removeButton(device) }
                            }
                        }
                        .contextMenu {
                            if device.canRemove { removeButton(device) }
                        }
                    }
                }
            }
        }
        .noticeBar($model.notice)
        .navigationTitle("Devices")
        .confirmationDialog(
            "Remove \(confirmRemoval?.name ?? "")?",
            isPresented: Binding(get: { confirmRemoval != nil }, set: { if !$0 { confirmRemoval = nil } }),
            presenting: confirmRemoval
        ) { device in
            Button("Cancel", role: .cancel) {}
            Button("Remove Device", role: .destructive) { Task { await model.remove(device) } }
        } message: { _ in
            Text("It will stop syncing every shared folder. You can add it again later by signing in on it.")
        }
        .overrideAlert($model.pendingOverride) { await model.confirmOverride() }
        .task(id: model.app.isSignedIn) { await model.load() }
    }
}

// MARK: - Transfers

public struct TransfersView: View {
    @Environment(AppContext.self) private var context
    public init() {}
    public var body: some View { TransfersContent(app: context.app) }
}

struct SyncRowView: View {
    let row: SyncRow
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(row.title).lineLimit(1).truncationMode(.middle).help(row.tooltip)
                Spacer()
                Text(row.subtitle).font(.caption).foregroundStyle(.secondary)
            }
            ProgressView(value: row.progress)
        }
    }
}

struct TransfersContent: View {
    @State private var model: TransfersViewModel
    @State private var picksSource = false
    @State private var expanded: Set<String> = []

    init(app: AppModel) { _model = State(initialValue: TransfersViewModel(app: app)) }

    var body: some View {
        Form {
            Section("Syncing now") {
                if model.syncRows.isEmpty {
                    EmptyStateText("Nothing is transferring.")
                }
                if let rate = model.rateLine {
                    Text(rate).font(.callout).foregroundStyle(.secondary).help("Current speed across all folders and devices")
                }
                ForEach(model.syncRows) { SyncRowView(row: $0) }
            }

            if !model.recentProblemLines.isEmpty {
                Section("Recent problems") {
                    ForEach(model.recentProblemLines) { line in
                        Label(line.text, systemImage: "clock.badge.exclamationmark")
                            .foregroundStyle(.secondary)
                            .help(line.tooltip)
                    }
                }
            }

            Section("Send to a device") {
                LabeledContent("File or folder") {
                    HStack {
                        Text(model.sourcePath.isEmpty ? "None chosen" : (model.sourcePath as NSString).lastPathComponent)
                            .foregroundStyle(model.sourcePath.isEmpty ? .secondary : .primary)
                            .help(model.sourcePath)
                        Button("Choose…") { picksSource = true }
                    }
                }
                Picker("Send to", selection: $model.targetDeviceId) {
                    Text("Choose a device").tag(String?.none)
                    ForEach(model.targetDevices) { device in
                        Text(device.online ? device.displayName : "\(device.displayName) (offline)")
                            .tag(Optional(device.deviceId))
                            .help(device.deviceId)
                    }
                }
                if let error = model.devicesError {
                    RetryRow(LoadWording.devices, notice: error) { await model.loadDevices() }
                } else if let stale = model.devicesStale {
                    RetryRow(LoadWording.stale("devices"), notice: stale) { await model.loadDevices() }
                } else if model.showsNoTargetDevices {
                    EmptyStateText("No other devices yet.")
                }
                TextField("Or paste a path", text: $model.sourcePath)
                    .font(.callout)
                HStack {
                    Spacer()
                    Button("Send") { Task { await model.send() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.canSend)
                }
            }

            Section("Received") {
                if model.showsInboxLoading { LoadingRow() }
                if let error = model.inboxError {
                    RetryRow(LoadWording.received, notice: error) { await model.loadInbox() }
                } else if let stale = model.inboxStale {
                    RetryRow(LoadWording.stale("received files"), notice: stale) { await model.loadInbox() }
                }
                if model.showsInboxEmpty { EmptyStateText("Nothing received yet.") }
                ForEach(model.inboxRows) { row in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(row.title).help(row.tooltip)
                            Spacer()
                            Text(row.status).foregroundStyle(.secondary)
                            if row.canReceive {
                                Button("Save to Downloads") { Task { await model.receive(row, into: nil) } }
                            }
                            if row.canRetry {
                                Button("Retry") { Task { await model.retry(row) } }
                            }
                            if row.canCancel {
                                Button("Cancel") { Task { await model.cancel(row) } }
                            }
                        }
                        if row.files.count > 3 {
                            DisclosureGroup(Plural.files(row.files.count), isExpanded: Binding(
                                get: { expanded.contains(row.id) },
                                set: { if $0 { expanded.insert(row.id) } else { expanded.remove(row.id) } }
                            )) {
                                ForEach(row.files, id: \.self) { Text($0).font(.caption) }
                            }
                        } else {
                            Text(row.files.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .noticeBar($model.notice)
        .navigationTitle("Transfers")
        .fileImporter(isPresented: $picksSource, allowedContentTypes: [.item, .folder]) { result in
            if case .success(let url) = result { model.sourcePath = url.path }
        }
        .task { await model.loadInbox() }
        .task(id: model.app.isSignedIn) { await model.loadDevices() }
    }
}

// MARK: - Storage

public struct StorageView: View {
    @Environment(AppContext.self) private var context
    public init() {}
    public var body: some View { StorageContent(app: context.app) }
}

struct StorageContent: View {
    @State private var model: StorageViewModel
    @State private var showsDetails = false
    @State private var confirmsCleanUp = false

    init(app: AppModel) { _model = State(initialValue: StorageViewModel(app: app)) }

    var body: some View {
        Form {
            if model.storedData != nil {
                Section(StorageViewModel.filesSectionTitle) {
                    if let totals = model.localFilesTotals { LabeledContent("Synced files", value: totals) }
                    Text(StorageViewModel.filesExplanation).font(.caption).foregroundStyle(.secondary)
                    if model.folderLines.isEmpty { EmptyStateText("No folders yet.") }
                    ForEach(model.folderLines) { line in
                        FolderStorageRow(line: line)
                    }
                }
                Section(StorageViewModel.internalSectionTitle) {
                    LabeledContent(StorageViewModel.internalTotalLabel, value: model.storedData ?? "")
                    LabeledContent(StorageViewModel.cleanableLabel, value: model.reclaimable ?? "")
                    Text(StorageViewModel.cleanUpExplanation)
                        .font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button(StorageViewModel.checkActionTitle) { Task { await model.checkReclaimable() } }
                        Button(StorageViewModel.cleanUpActionTitle) { confirmsCleanUp = true }
                        if model.isWorking { ProgressView().controlSize(.small).accessibilityLabel("Working") }
                    }
                    .disabled(model.isWorking)
                    DisclosureGroup("Details", isExpanded: $showsDetails) {
                        LabeledContent("Blocks stored", value: model.blocksStored ?? "")
                        LabeledContent("Last cleanup", value: model.lastCleanup ?? "")
                    }
                }
                Section(StorageViewModel.diskSectionTitle) {
                    if let summary = model.diskSummary { Text(summary) }
                    ForEach(model.diskRows) { row in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(row.name)
                                Text(row.text).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if let trailing = row.trailing {
                                Text(trailing).font(.caption).foregroundStyle(row.trailingIsWarning ? .orange : .secondary)
                            }
                        }
                    }
                    Text(StorageViewModel.diskExplanation).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .noticeBar($model.notice)
        .navigationTitle("Storage")
        .confirmationDialog(StorageViewModel.cleanUpActionTitle + "?", isPresented: $confirmsCleanUp) {
            Button("Cancel", role: .cancel) {}
            Button(StorageViewModel.cleanUpActionTitle) { Task { await model.reclaim() } }
        } message: {
            Text(StorageViewModel.cleanUpExplanation)
        }
    }
}

struct FolderStorageRow: View {
    @Environment(AppContext.self) private var context
    let line: NamedLine
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(line.name)
                Text(line.text).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let trailing = line.trailing {
                Text(trailing).font(.caption).foregroundStyle(line.trailingIsWarning ? .orange : .secondary)
            }
            Button("Folder Details…") { context.showFolder(line.id) }
        }
    }
}

#Preview("Devices") { DevicesView().environment(AppContext.fixture(.healthy)).frame(width: 640, height: 420) }
#Preview("Transfers – syncing") { TransfersView().environment(AppContext.fixture(.syncing)).frame(width: 640, height: 640) }
#Preview("Storage") { StorageView().environment(AppContext.fixture(.healthy)).frame(width: 640, height: 520) }
