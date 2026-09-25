import SwiftUI
import UniformTypeIdentifiers
import YadoriLinkFixtures
import YadoriLinkModel

/// Folder details: protection and this device first; availability, devices
/// with a full copy and free space under "Details"; then conflicts, trash,
/// and file history & download options.
public struct FolderDetailView: View {
    @Environment(AppContext.self) private var context
    @State private var model: FolderDetailViewModel
    @State private var showsDetails = false
    @State private var picksFile = false

    public init(model: FolderDetailViewModel) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        Form {
            Section {
                LabeledContent("Data protection") {
                    StatusBadge(model.protectionTitle, tone: model.protectionTone)
                }
                if let detail = model.protectionDetail {
                    Text(detail).foregroundStyle(.secondary)
                }
                LabeledContent("This Mac", value: model.thisDevice)
                DisclosureGroup("Details", isExpanded: $showsDetails) {
                    LabeledContent("Availability", value: model.folder.fetchAvailability == .availableNow ? "Files can be downloaded now" : "Some files can't be downloaded right now")
                    if let free = model.freeSpace { LabeledContent("Free space", value: free) }
                    LabeledContent("Location") {
                        Text(model.folder.localPath).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Devices with a complete copy (as configured)").font(.subheadline.weight(.medium))
                        if model.copies.isEmpty {
                            Text("None yet").foregroundStyle(.secondary)
                        }
                        ForEach(model.copies) { copy in
                            HStack {
                                OnlineDot(online: copy.tone == .ok)
                                Text(copy.name).help(copy.tooltip)
                                Spacer()
                                Text(copy.status).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } header: {
                HStack {
                    Text(model.folder.name).font(.title3.weight(.semibold))
                    StatusBadge(model.folder.state.title, tone: model.folder.state.tone)
                    Spacer()
                    Button("Share…") {
                        context.shareTarget = ShareTarget(groupId: model.folder.groupId, folderName: model.folder.name)
                    }
                    Button("Show in Finder") { context.revealInFinder(model.folder.localPath) }
                }
            }

            if !model.conflicts.isEmpty {
                Section("Conflicts") {
                    if let why = model.conflictExplanation {
                        Text(why).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(model.conflicts) { conflict in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(conflict.title)
                            Text("\(conflict.subtitle) · \(conflict.relation)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .help(conflict.path)
                    }
                }
            }

            if !model.trash.isEmpty {
                Section("Recently deleted") {
                    ForEach(model.trashGroups) { group in
                        if let title = group.title {
                            HStack {
                                Text(title).font(.subheadline.weight(.medium))
                                Spacer()
                                Button("Restore Folder") { Task { await model.restoreFolder(group) } }
                                    .help("Restores everything this delete or rename removed, together.")
                                    .disabled(model.isWorking)
                            }
                        }
                        ForEach(group.rows) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title)
                                    Text(item.subtitle).font(.caption).foregroundStyle(.secondary)
                                }
                                .padding(.leading, group.title == nil ? 0 : 12)
                                Spacer()
                                Button("Restore") { Task { await model.restoreFromTrash(item) } }
                            }
                        }
                    }
                }
            }

            Section("File history & download options") {
                HStack {
                    Text(model.selectedFile.map { ($0 as NSString).lastPathComponent } ?? "No file or folder chosen")
                        .foregroundStyle(model.selectedFile == nil ? .secondary : .primary)
                        .help(model.selectedFile ?? "")
                    Spacer()
                    Button("Choose File or Folder…") { picksFile = true }
                        .help("A folder is kept, downloaded or freed up as a whole. A folder kept on this Mac also keeps what is added to it later.")
                }
                if let state = model.fileStateTitle {
                    LabeledContent("Status", value: state)
                }
                if !model.fileActions.isEmpty {
                    HStack {
                        ForEach(model.fileActions, id: \.self) { action in
                            Button {
                                Task { await model.perform(action) }
                            } label: {
                                Label(action.title, systemImage: action.systemImage)
                            }
                            .disabled(model.isWorking)
                        }
                    }
                }
                if !model.versions.isEmpty {
                    ForEach(model.versions) { version in
                        HStack {
                            Text(version.text).help(version.tooltip)
                            Spacer()
                            if !version.isCurrent {
                                Button("Restore") { Task { await model.restore(version) } }
                            }
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .noticeBar($model.notice)
        .navigationTitle(model.folder.name)
        .frame(minWidth: 560, minHeight: 640)
        .fileImporter(isPresented: $picksFile, allowedContentTypes: [.item, .folder]) { result in
            if case .success(let url) = result { Task { await model.selectFile(url.path) } }
        }
        .task { await model.load() }
    }
}

#Preview("Folder – healthy") {
    let context = AppContext.fixture(.healthy)
    FolderDetailView(model: FolderDetailViewModel(client: context.app.client, folder: Fixtures.healthyFolders[1]))
        .environment(context)
}

#Preview("Folder – conflicts") {
    let context = AppContext.fixture(.problem)
    FolderDetailView(model: FolderDetailViewModel(client: context.app.client, folder: Fixtures.problemSnapshot.folders[0]))
        .environment(context)
}
