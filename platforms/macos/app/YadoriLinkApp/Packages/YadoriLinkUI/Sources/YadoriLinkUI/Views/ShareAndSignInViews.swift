import AppKit
import CoreImage.CIFilterBuiltins
import SwiftUI
import YadoriLinkFixtures
import YadoriLinkModel

// MARK: - Share sheet

/// Sharing one folder: the invite link (once created) first, then people
/// with access, pending requests and open invites.
public struct ShareView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: ShareViewModel
    @State private var confirmRemoval: MemberRow?
    private let showQRCode: (InviteSummary) -> Void

    /// `showQRCode` opens the invite's QR window.
    public init(model: ShareViewModel, showQRCode: @escaping (InviteSummary) -> Void = { _ in }) {
        _model = State(initialValue: model)
        self.showQRCode = showQRCode
    }

    public var body: some View {
        VStack(spacing: 0) {
            Form {
                if let invite = model.invite {
                    Section("Invite link") {
                        HStack {
                            Text(invite.url).textSelection(.enabled).font(.body.monospaced())
                            Spacer()
                            Button("Copy") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(invite.url, forType: .string)
                            }
                            ShareLink(item: invite.url) { Text("Send…") }
                        }
                        Text("\(invite.role.title) · expires \(invite.expiresAt.formatted(date: .abbreviated, time: .shortened))\(invite.requiresApproval ? " · you approve each device" : "")")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("Show QR Code…") { showQRCode(invite) }
                    }
                }

                Section {
                    if model.showsCreateForm {
                        createForm
                    } else {
                        DisclosureGroup("Create another invite link", isExpanded: $model.createAnotherExpanded) { createForm }
                    }
                } header: {
                    if model.invite == nil { Text("Invite someone") }
                }

                if !model.warnings.isEmpty {
                    Section { WarningList(warnings: model.warnings) }
                }

                Section("People with access") {
                    ForEach(model.members) { member in
                        HStack {
                            OnlineDot(online: member.online)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(member.name)
                                Text("\(member.relationship) · \(member.storage)").font(.caption).foregroundStyle(.secondary)
                            }
                            .help(member.tooltip)
                            Spacer()
                            if let role = member.role {
                                Picker("Role", selection: Binding(
                                    get: { role },
                                    set: { newRole in Task { await model.setRole(newRole, for: member) } }
                                )) {
                                    ForEach(AssignableRole.allCases, id: \.self) { Text($0.title).tag($0) }
                                }
                                .labelsHidden()
                                .fixedSize()
                            } else {
                                Text(member.roleTitle).foregroundStyle(.secondary)
                            }
                        }
                        .contextMenu {
                            if member.canRemove {
                                Button("Remove Access…", role: .destructive) { confirmRemoval = member }
                            }
                        }
                    }
                }

                if !model.requests.isEmpty {
                    Section("Requests") {
                        ForEach(model.requests) { request in
                            HStack {
                                Text(request.title).help(request.tooltip)
                                Spacer()
                                Button("Decline") { Task { await model.deny(request) } }
                                Button("Approve") { Task { await model.approve(request) } }
                            }
                        }
                    }
                }

                if !model.invites.isEmpty {
                    Section("Open invite links") {
                        ForEach(model.invites) { invite in
                            HStack {
                                Text(invite.title)
                                Spacer()
                                Button("Cancel Link") { Task { await model.cancelInvite(invite) } }
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .noticeBar($model.notice)

            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 560, height: 620)
        .navigationTitle("Share \(model.folderName)")
        .confirmationDialog(
            "Remove access for \(confirmRemoval?.name ?? "")?",
            isPresented: Binding(get: { confirmRemoval != nil }, set: { if !$0 { confirmRemoval = nil } }),
            presenting: confirmRemoval
        ) { member in
            Button("Cancel", role: .cancel) {}
            Button("Remove Access", role: .destructive) { Task { await model.removeAccess(member) } }
        }
        .overrideAlert($model.pendingOverride) { await model.confirmOverride() }
        .task { await model.load() }
    }

    @ViewBuilder private var createForm: some View {
        Picker("People who join", selection: $model.inviteRole) {
            ForEach(AssignableRole.allCases, id: \.self) { Text($0.title).tag($0) }
        }
        Toggle("Approve each device before it joins", isOn: $model.inviteRequiresApproval)
        HStack {
            Spacer()
            Button("Create Invite Link") { Task { await model.createInvite() } }
                .disabled(model.isWorking)
        }
    }
}

/// The invite QR code, in its own small window. `url` is `nil` when the
/// window was restored from an earlier run: the link itself is never saved
/// with the window.
public struct InviteQRView: View {
    let url: String?
    public init(url: String?) { self.url = url }

    public var body: some View {
        if let url {
            qrCode(url)
        } else {
            Text("This invite link isn't shown anymore. Open the folder's Share window to see its invites.")
                .foregroundStyle(.secondary)
                .frame(width: 280)
                .padding(24)
                .fixedSize()
        }
    }

    private func qrCode(_ url: String) -> some View {
        VStack(spacing: 12) {
            if let image = Self.qrImage(url) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 240, height: 240)
                    .accessibilityLabel("QR code for the invite link")
            }
            Text("Scan with the device you're inviting.").foregroundStyle(.secondary)
            Text(url).font(.caption.monospaced()).textSelection(.enabled)
        }
        .padding(24)
        .fixedSize()
    }

    static func qrImage(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let rep = NSCIImageRep(ciImage: output)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}

// MARK: - Sign in

public struct SignInView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: SignInModel

    public init(model: SignInModel) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Sign in to YadoriLink").font(.title2.weight(.semibold))
            SignInStatusView(model: model)
            HStack {
                Button("Cancel") {
                    model.cancel()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                if model.phase == .signedIn {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                } else {
                    Button(model.canRetry ? "Try Again" : "Sign In with Browser") { Task { await model.run() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.isRunning)
                }
            }
        }
        .padding(24)
        .frame(width: 440)
    }
}

/// Explains the current sign-in step. Shared by the sheet and onboarding.
struct SignInStatusView: View {
    let model: SignInModel
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Sign in with Google in your browser. Your password is never shared with YadoriLink.")
                .fixedSize(horizontal: false, vertical: true)
                .help("YadoriLink opens your browser twice: once to approve this Mac, then to sign in. The result comes back to this Mac directly and is kept in your keychain.")
            if model.phase != .idle {
                HStack(spacing: 8) {
                    if model.isRunning { ProgressView().controlSize(.small) }
                    if case .failed = model.phase {
                        Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                    }
                    if model.phase == .signedIn {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    }
                    Text(model.statusText).help(model.errorDetail ?? "")
                }
            }
        }
    }
}

#Preview("Share") {
    ShareView(model: ShareViewModel(client: FakeYadoriLinkClient(scenario: .healthy), groupId: "g-docs", folderName: "Documents"))
}

#Preview("Share – link created") {
    let model = ShareViewModel(client: FakeYadoriLinkClient(scenario: .healthy), groupId: "g-docs", folderName: "Documents")
    Task { await model.createInvite() }
    return ShareView(model: model)
}

#Preview("Invite QR") { InviteQRView(url: "yadorilink://invite/K7QX-M2PA") }

#Preview("Invite QR – restored") { InviteQRView(url: nil) }

#Preview("Sign in") {
    SignInView(model: SignInModel(client: FakeYadoriLinkClient(scenario: .signedOut), openURL: { _ in }))
}
