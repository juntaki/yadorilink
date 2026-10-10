import SwiftUI
import UniformTypeIdentifiers
import YadoriLinkModel

/// The "Join with Invite Link" window.
public struct JoinInviteView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: JoinInviteModel
    @State private var picksFolder = false
    let context: AppContext

    public init(client: any YadoriLinkClient, context: AppContext, onAccepted: @escaping () -> Void = {}) {
        let model = JoinInviteModel(client: client)
        model.onAccepted = onAccepted
        _model = State(initialValue: model)
        self.context = context
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            content.frame(maxWidth: .infinity, alignment: .topLeading)
            if let notice = model.notice { NoticeView(notice) { model.notice = nil } }
            buttons
        }
        .padding(24)
        .frame(width: 460)
        .fileImporter(isPresented: $picksFolder, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result { model.chooseFolder(url.path) }
        }
        .onAppear { takePending() }
        .onChange(of: context.pendingInviteLink) { _, _ in takePending() }
    }

    private func takePending() {
        guard let link = context.pendingInviteLink else { return }
        context.pendingInviteLink = nil
        model.receive(link)
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .entering:
            VStack(alignment: .leading, spacing: 10) {
                Text("Join with an invite link").font(.title2.weight(.semibold))
                Text("Paste the link you were sent. It starts with yadorilink://invite/.")
                    .foregroundStyle(.secondary)
                TextField("yadorilink://invite/…", text: $model.input)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.review() }
            }
        case .confirming(let code):
            confirmation(code: code)
        case .accepting:
            HStack { ProgressView(); Text("Joining…") }
        case .done(let outcome):
            VStack(alignment: .leading, spacing: 10) {
                Text("Done").font(.title2.weight(.semibold))
                Text(JoinInviteModel.doneText(outcome))
                Text(outcome.localPath).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func confirmation(code: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Accept this invite?").font(.title2.weight(.semibold))
            Text("Invite code: \(code)").font(.callout.monospaced())
            Text(JoinInviteModel.confirmationText)
            HStack {
                Text(model.folderPath ?? "No folder chosen")
                    .foregroundStyle(model.folderPath == nil ? .secondary : .primary)
                    .lineLimit(1).truncationMode(.middle)
                Spacer()
                Button("Choose Folder…") { picksFolder = true }
            }
        }
    }

    @ViewBuilder private var buttons: some View {
        HStack {
            switch model.phase {
            case .entering:
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Continue") { model.review() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.input.trimmingCharacters(in: .whitespaces).isEmpty)
            case .confirming, .accepting:
                Button("Back") { model.back() }.disabled(model.phase == .accepting)
                Spacer()
                Button("Accept Invite") { Task { await model.accept() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canAccept)
            case .done:
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
    }
}
