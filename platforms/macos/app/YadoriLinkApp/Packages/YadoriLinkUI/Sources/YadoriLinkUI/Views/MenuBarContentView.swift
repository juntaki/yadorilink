import SwiftUI
import YadoriLinkFixtures
import YadoriLinkModel

/// The menu bar popover: overall state, each folder, transfer progress,
/// Pause/Resume, and the ways into the main window. Anything more complex
/// happens in the main window.
public struct MenuBarContentView: View {
    @Environment(AppContext.self) private var context
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss

    public init() {}

    public var body: some View {
        let app = context.app
        let p = MenuBarPresentation(app: app)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: p.tone.symbol).foregroundStyle(p.tone.color).font(.title3)
                Text(p.headline).font(.headline)
                Spacer()
            }

            if p.showsStartAction {
                Button {
                    Task { await app.startDaemon() }
                } label: {
                    Label(AppBanner.daemonUnavailable.actionTitle, systemImage: "play.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(app.isStartingDaemon)
                if let notice = app.notice, notice.kind == .failure {
                    Text(notice.text).font(.caption).foregroundStyle(.secondary).help(notice.detail ?? "")
                }
            }

            if !p.folders.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(p.folders.prefix(8)) { row in
                        Button {
                            open(.folders)
                            context.showFolder(row.folder.localPath)
                        } label: {
                            HStack {
                                Image(systemName: "folder").foregroundStyle(.secondary)
                                Text(row.name).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Text(row.stateTitle).font(.caption).foregroundStyle(row.stateTone.color)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help(row.pathTooltip)
                    }
                    if p.folders.count > 8 {
                        Text("and \(p.folders.count - 8) more").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if let line = p.transferLine {
                VStack(alignment: .leading, spacing: 4) {
                    Text(line).font(.caption)
                    if let progress = p.transferProgress { ProgressView(value: progress) }
                }
            }

            if let update = p.updateLine {
                Button(update) { open(.home) }
                    .buttonStyle(.link)
            }

            Divider()

            VStack(alignment: .leading, spacing: 2) {
                if p.canPause {
                    MenuRowButton(p.pauseTitle, systemImage: p.allPaused ? "play.circle" : "pause.circle") {
                        Task { await app.setAllPaused(!p.allPaused) }
                    }
                }
                MenuRowButton("Open YadoriLink…", systemImage: "macwindow") { open(.home) }
                MenuRowButton("Add Folder…", systemImage: "folder.badge.plus") {
                    openWindow(id: WindowID.addFolder)
                    NSApp.activate()
                    dismiss()
                }
                SettingsLink {
                    Label("Settings…", systemImage: "gearshape")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.vertical, 3)
                .simultaneousGesture(TapGesture().onEnded { NSApp.activate() })
                Divider().padding(.vertical, 4)
                MenuRowButton("Quit YadoriLink", systemImage: "power") { NSApp.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 300)
    }

    private func open(_ item: SidebarItem) {
        context.sidebar = item
        openWindow(id: WindowID.main)
        NSApp.activate()
        dismiss()
    }
}

struct MenuRowButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void

    init(_ title: String, systemImage: String, action: @escaping () -> Void) {
        self.title = title
        self.systemImage = systemImage
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 3)
    }
}

#Preview("Healthy") { MenuBarContentView().environment(AppContext.fixture(.healthy)) }
#Preview("Syncing") { MenuBarContentView().environment(AppContext.fixture(.syncing)) }
#Preview("Problem") { MenuBarContentView().environment(AppContext.fixture(.problem)) }
#Preview("Daemon down") { MenuBarContentView().environment(AppContext.fixture(.daemonDown)) }
#Preview("Empty") { MenuBarContentView().environment(AppContext.fixture(.empty)) }
