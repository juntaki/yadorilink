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
                } else if model.banner != .daemonUnavailable {
                    Text(model.headline).font(.title2.weight(.semibold))

                    if !model.attentionLines.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(model.attentionLines) { line in
                                Label(line.text, systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                    .help(line.tooltip)
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
                            ForEach(TransfersViewModel(app: context.app).syncRows.prefix(3)) { row in
                                SyncRowView(row: row)
                            }
                        }
                    }

                    if model.showsDevicesSection {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionHeader("Devices")
                            if let error = model.devicesError {
                                EmptyStateText(error)
                            } else if model.devices == .loading {
                                LoadingRow()
                            } else if model.showsNoDevicesMessage {
                                EmptyStateText("No other devices yet.")
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
                Button("Details…") { context.showFolder(row.folder.localPath) }
                FolderOptionsMenu(folder: row.folder)
            }
            Text(row.summary)
                .font(.callout)
                .foregroundStyle(row.summaryIsWarning ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
            if let detail = row.detail {
                Text(detail).font(.callout).foregroundStyle(row.folder.durability.tone.color)
            }
            if let progress = row.progress {
                ProgressView(value: progress) {
                    EmptyView()
                } currentValueLabel: {
                    Text(row.progressText ?? "").font(.caption)
                }
            }
        }
    }
}

struct FolderOptionsMenu: View {
    @Environment(AppContext.self) private var context
    let folder: FolderSummary

    var body: some View {
        Menu {
            Button(folder.paused ? "Resume Syncing" : "Pause Syncing") {
                Task { await context.app.setPaused(!folder.paused, for: folder) }
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
            Divider()
            Button("Show in Finder") { context.revealInFinder(folder.localPath) }
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
