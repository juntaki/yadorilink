import AppKit
import SwiftUI
import YadoriLinkFixtures
import YadoriLinkModel

/// The main window: a sidebar with Home, Folders, Devices, Transfers and
/// Storage. The app-wide banner sits above whichever pane is shown, once.
public struct MainWindowView: View {
    @Environment(AppContext.self) private var context
    @Environment(\.openWindow) private var openWindow

    public init() {}

    public var body: some View {
        @Bindable var context = context
        @Bindable var app = context.app
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $context.sidebar) { item in
                Label(item.title, systemImage: item.systemImage).tag(item)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            VStack(spacing: 0) {
                if context.isFixture {
                    HStack { FixtureBadge(); Spacer() }
                        .padding([.horizontal, .top], 16)
                }
                if let banner = context.app.banner {
                    AppBannerView(banner, isWorking: context.app.isStartingDaemon) { context.perform(banner) }
                        .padding([.horizontal, .top], 16)
                }
                // While the daemon is down only the banner shows; Devices
                // still works because it comes from the account.
                if !context.app.isDaemonUnavailable || context.sidebar == .devices {
                    detail
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                } else {
                    Spacer()
                }
            }
            .noticeBar($app.notice)
        }
        .frame(minWidth: 760, minHeight: 520)
        .sheet(item: $context.shareTarget) { target in
            ShareView(model: ShareViewModel(client: context.app.client, groupId: target.groupId, folderName: target.folderName)) { invite in
                openWindow(id: WindowID.invite, value: context.showQRCode(for: invite))
            }
        }
        .sheet(isPresented: $context.showsSignIn) {
            SignInView(model: context.makeSignInModel())
        }
        .alert(
            context.unlink.pendingConfirmation.map(UnlinkWording.title) ?? "",
            isPresented: Binding(get: { context.unlink.pendingConfirmation != nil }, set: { if !$0 { context.unlink.pendingConfirmation = nil } }),
            presenting: context.unlink.pendingConfirmation
        ) { _ in
            Button("Cancel", role: .cancel) { context.unlink.cancel() }
            Button(UnlinkWording.confirmButton, role: .destructive) { Task { await context.unlink.confirm() } }
        } message: { folder in
            Text(UnlinkWording.message(folder))
        }
        .alert(
            context.unlink.pendingOverride.map(UnlinkWording.overrideTitle) ?? "",
            isPresented: Binding(get: { context.unlink.pendingOverride != nil }, set: { if !$0 { context.unlink.pendingOverride = nil } }),
            presenting: context.unlink.pendingOverride
        ) { _ in
            Button("Cancel", role: .cancel) { context.unlink.cancel() }
            Button(UnlinkWording.overrideButton, role: .destructive) { Task { await context.unlink.confirmOverride() } }
        } message: { folder in
            Text(UnlinkWording.overrideMessage(folder))
        }
    }

    @ViewBuilder private var detail: some View {
        switch context.sidebar ?? .home {
        case .home: HomeView()
        case .folders: FoldersView()
        case .devices: DevicesView()
        case .transfers: TransfersView()
        case .storage: StorageView()
        }
    }
}

// MARK: - Home

public struct HomeView: View {
    @Environment(AppContext.self) private var context
    public init() {}
    public var body: some View { HomeContent(app: context.app) }
}

struct HomeContent: View {
    @Environment(AppContext.self) private var context
    @Environment(\.openWindow) private var openWindow
    @State private var model: HomeViewModel

    init(app: AppModel) { _model = State(initialValue: HomeViewModel(app: app)) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if model.showsLoading {
                    LoadingRow("Checking status…")
                } else if model.banner == .daemonUnavailable {
                    SummaryCard(summary: model.summary)
                } else {
                    SummaryCard(summary: model.summary)

                    if !model.waitingLines.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(model.waitingLines, id: \.self) { Text($0).font(.callout).foregroundStyle(.secondary) }
                        }
                    }

                    if !model.attentionItems.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionHeader("Needs your attention")
                            ForEach(model.attentionItems) { item in
                                AttentionItemRow(item: item)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        SectionHeader("Folders") {
                            Button("Add Folder…") { openAddFolder() }
                        }
                        if model.showsNoFoldersMessage {
                            EmptyStateText("Add a folder to start syncing it with your other devices.")
                        }
                        ForEach(model.folderRows) { row in
                            FolderCard(row: row)
                        }
                    }

                    if model.showsTransfersSection {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionHeader("Transfers") {
                                Button("Show All") { context.sidebar = .transfers }.buttonStyle(.link)
                            }
                            let transfers = TransfersViewModel(app: context.app)
                            if let rate = transfers.rateLine {
                                Text(rate).font(.callout).foregroundStyle(.secondary)
                            }
                            ForEach(transfers.syncRows.prefix(3)) { row in
                                SyncRowView(row: row)
                            }
                        }
                    }

                    if !model.recentProblemLines.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionHeader("Recent problems")
                            ForEach(model.recentProblemLines) { line in
                                Label(line.text, systemImage: "clock.badge.exclamationmark")
                                    .foregroundStyle(.secondary)
                                    .help(line.tooltip)
                            }
                        }
                    }

                    if model.showsDevicesSection {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionHeader("Devices")
                            if let error = model.devicesError {
                                RetryRow(LoadWording.devices, notice: error) { await model.loadDevices() }
                            } else if model.devices == .loading {
                                LoadingRow()
                            } else if model.showsNoDevicesMessage {
                                EmptyStateText("No other devices yet.")
                            }
                            if let stale = model.devicesStale {
                                RetryRow(LoadWording.stale("devices"), notice: stale) { await model.loadDevices() }
                            }
                            ForEach(model.deviceRows) { row in
                                HStack(spacing: 8) {
                                    OnlineDot(online: row.online)
                                    Text(row.name).help(row.tooltip)
                                    Text(row.detail).foregroundStyle(.secondary).font(.callout)
                                }
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .navigationTitle("Home")
        .task(id: context.app.isSignedIn) { await model.loadDevices() }
    }

    private func openAddFolder() { openWindow(id: WindowID.addFolder) }
}

/// The five answers Home gives first, one per line.
struct SummaryCard: View {
    let summary: ProductSummary

    var body: some View {
        Card {
            ForEach(summary.lines, id: \.label) { line in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(line.label).font(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(line.text).foregroundStyle(line.tone.color)
                        if let detail = line.detail {
                            Text(detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 0)
                }
                .accessibilityElement(children: .combine)
            }
            if let storage = summary.storage {
                Text(storage).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// One problem with its first action as a button and its second, if any, as a link.
struct AttentionItemRow: View {
    @Environment(AppContext.self) private var context
    @Environment(\.openSettings) private var openSettings
    let item: AttentionItem

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Label(item.text, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button(item.primary.title) { run(item.primary) }
                .accessibilityHint(item.text)
            if let secondary = item.secondary {
                Button(secondary.title) { run(secondary) }.buttonStyle(.link)
                    .accessibilityHint(item.text)
            }
        }
    }

    private func run(_ offer: ActionOffer) {
        switch offer.destination {
        case .refresh: context.app.refresh()
        case .folder(let path): context.showFolder(path)
        case .sidebar(let item): context.sidebar = item
        case .revealInFinder(let path): context.revealInFinder(path)
        case .settings(let tab):
            context.settingsTab = tab
            NSApp.activate()
            openSettings()
        }
    }
}

/// Row 1: name, state and Share…/Details…. Row 2: one quiet summary.
/// Pause and the mode sit behind the "⋯" menu.
struct FolderCard: View {
    @Environment(AppContext.self) private var context
    let row: FolderRow

    var body: some View {
        Card {
            HStack(spacing: 8) {
                Image(systemName: "folder.fill").foregroundStyle(.tint)
                Text(row.name).font(.headline).lineLimit(1).truncationMode(.middle).help(row.pathTooltip)
                StatusBadge(row.stateTitle, tone: row.stateTone)
                Spacer()
                Button("Share…") {
                    context.shareTarget = ShareTarget(groupId: row.folder.groupId, folderName: row.name)
                }
                .accessibilityLabel("Share \(row.name)")
                Button("Details…") { context.showFolder(row.folder.localPath) }
                    .accessibilityLabel("Details for \(row.name)")
                FolderOptionsMenu(folder: row.folder)
            }
            Text(row.summary)
                .font(.callout)
                .foregroundStyle(row.summaryIsWarning ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
            if let detail = row.detail {
                Text(detail).font(.callout).foregroundStyle(row.protectionTone.color)
            }
            if let progress = row.progress {
                ProgressView(value: progress) {
                    EmptyView()
                } currentValueLabel: {
                    Text(row.progressText ?? "").font(.caption)
                }
                .accessibilityLabel("\(row.name), \(row.stateTitle)")
                .accessibilityValue(row.progressText ?? "")
            }
        }
    }
}

struct FolderOptionsMenu: View {
    @Environment(AppContext.self) private var context
    let folder: FolderSummary

    var body: some View {
        Menu {
            if folder.paused {
                Text(PauseText.status(until: folder.pausedUntil, now: Date()))
                Button("Resume Syncing") {
                    Task { await context.app.setPaused(false, for: folder) }
                }
            } else {
                ForEach(PauseDuration.allCases, id: \.self) { duration in
                    Button(duration.menuTitle) {
                        Task { await context.app.setPaused(true, for: folder, duration: duration) }
                    }
                }
            }
            Divider()
            Picker("Files on this Mac", selection: Binding(
                get: { folder.mode },
                set: { mode in Task { await context.app.setMode(mode, for: folder) } }
            )) {
                ForEach(FolderMode.allCases, id: \.self) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.inline)
            if !folder.provider {
                Divider()
                Button("Show in Finder") { context.revealInFinder(folder.localPath) }
            }
            Divider()
            Button(UnlinkWording.menuTitle, role: .destructive) { context.unlink.request(folder) }
                .disabled(context.unlink.isWorking)
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("Options for \(folder.name)")
    }
}

// MARK: - Folders

public struct FoldersView: View {
    @Environment(AppContext.self) private var context
    public init() {}

    public var body: some View {
        @Bindable var context = context
        NavigationStack(path: $context.folderPath) {
            List {
                let rows = context.app.snapshot?.folders.map(FolderRow.init) ?? []
                if context.app.snapshot != nil && rows.isEmpty {
                    EmptyStateText("No folders yet.")
                }
                ForEach(rows) { row in
                    NavigationLink(value: row.folder.localPath) {
                        HStack {
                            Image(systemName: "folder").foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(row.name).lineLimit(1).truncationMode(.middle)
                                Text(row.summary).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            StatusBadge(row.stateTitle, tone: row.stateTone)
                        }
                        .padding(.vertical, 3)
                        .help(row.pathTooltip)
                    }
                }
            }
            .navigationTitle("Folders")
            .navigationDestination(for: String.self) { path in
                if let folder = context.app.snapshot?.folders.first(where: { $0.localPath == path }) {
                    FolderDetailView(model: FolderDetailViewModel(client: context.app.client, folder: folder))
                        .id(path)
                } else {
                    EmptyStateText("This folder isn't available right now.").padding()
                }
            }
        }
    }
}

#Preview("Main – healthy") { MainWindowView().environment(AppContext.fixture(.healthy)).frame(width: 900, height: 640) }
#Preview("Main – syncing") { MainWindowView().environment(AppContext.fixture(.syncing)).frame(width: 900, height: 640) }
#Preview("Main – problem") { MainWindowView().environment(AppContext.fixture(.problem)).frame(width: 900, height: 640) }
#Preview("Main – daemon down") { MainWindowView().environment(AppContext.fixture(.daemonDown)).frame(width: 900, height: 640) }
#Preview("Main – signed out") { MainWindowView().environment(AppContext.fixture(.signedOut)).frame(width: 900, height: 640) }
#Preview("Main – empty") { MainWindowView().environment(AppContext.fixture(.empty)).frame(width: 900, height: 640) }
#Preview("Main – Japanese names") { MainWindowView().environment(AppContext.fixture(.japaneseLongNames)).frame(width: 900, height: 640) }
#Preview("Main – twenty folders") { MainWindowView().environment(AppContext.fixture(.twentyFolders)).frame(width: 900, height: 640) }
