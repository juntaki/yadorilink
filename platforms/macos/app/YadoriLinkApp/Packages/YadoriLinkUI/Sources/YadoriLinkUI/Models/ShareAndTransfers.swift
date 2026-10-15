import Foundation
import Observation
import YadoriLinkModel

// MARK: - Sharing a folder

public struct MemberRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    /// "You", "Your other device", "Owner's device", "Invited"
    public var relationship: String
    /// `nil` when the role can't be changed (the owner).
    public var role: AssignableRole?
    public var roleTitle: String
    public var online: Bool
    public var storage: String
    public var canRemove: Bool
    public var tooltip: String { id }
}

public struct RequestRow: Identifiable, Equatable, Sendable {
    public var id: String { tooltip }
    public var title: String
    public var tooltip: String
}

public struct InviteRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var title: String
}

@MainActor
@Observable
public final class ShareViewModel {
    public let client: any YadoriLinkClient
    public let groupId: String
    public let folderName: String
    public private(set) var members: [MemberRow] = []
    public private(set) var requests: [RequestRow] = []
    public private(set) var invites: [InviteRow] = []
    public private(set) var invite: InviteSummary?
    public private(set) var warnings: [MembershipWarning] = []
    public private(set) var isWorking = false
    /// The last read of members, requests and invites failed. Whatever was
    /// loaded before stays on screen, but it is not current.
    public private(set) var loadFailure: Notice?
    public private(set) var hasLoaded = false
    public var inviteRole: AssignableRole = .viewer
    public var inviteRequiresApproval = true
    /// After a link exists, the form folds into "Create another invite link".
    public var createAnotherExpanded = false
    public var showsQRCode = false
    public var pendingOverride: OverridePrompt?
    public var notice: Notice?
    @ObservationIgnored private let now: () -> Date

    public init(client: any YadoriLinkClient, groupId: String, folderName: String, now: @escaping () -> Date = Date.init) {
        self.client = client
        self.groupId = groupId
        self.folderName = folderName
        self.now = now
    }

    public var showsCreateForm: Bool { invite == nil || createAnotherExpanded }

    public func load() async {
        do {
            let members = try await client.listMembers(groupId: groupId).map(memberRow)
            let requests = try await client.listPendingApprovals().filter { $0.groupId == groupId }.map { request in
                let role = request.requestedRole.map { " as \($0.title.lowercased())" } ?? ""
                return RequestRow(title: "A new device wants to join\(role)", tooltip: request.deviceId)
            }
            let invites = try await client.listInvites().filter { $0.groupId == groupId }.map {
                InviteRow(id: $0.inviteId, title: "\($0.role.title) · expires \(Format.relative($0.expiresAt, now: now()))")
            }
            self.members = members
            self.requests = requests
            self.invites = invites
            hasLoaded = true
            loadFailure = nil
        } catch {
            loadFailure = .failure(error)
        }
    }

    private func memberRow(_ m: MemberSummary) -> MemberRow {
        let relationship: String = switch m.relationship {
        case .you: "This Mac"
        case .yourOtherDevice: "Your other device"
        case .ownersDevice: "Owner's device"
        case .invited: "Invited"
        }
        let role: AssignableRole? = switch m.role {
        case .viewer: .viewer
        case .editor: .editor
        case .owner, .other: nil
        }
        return MemberRow(
            id: m.deviceId, name: m.deviceName, relationship: relationship, role: role,
            roleTitle: m.role.title, online: m.online || m.relationship == .you,
            storage: m.storage == .fullCopy ? FolderMode.keepAll.title : FolderMode.onDemand.title,
            canRemove: m.relationship != .you && m.role != .owner
        )
    }

    public func createInvite() async {
        await work {
            self.invite = try await self.client.mintInvite(groupId: self.groupId, role: self.inviteRole, ttl: nil, requireApproval: self.inviteRequiresApproval)
            self.createAnotherExpanded = false
            self.showsQRCode = false
            return nil
        }
        await load()
    }

    /// Applies at once; there is no separate "Change role" step.
    public func setRole(_ role: AssignableRole, for member: MemberRow) async {
        guard member.role != role else { return }
        await work {
            try await self.client.changeMemberRole(groupId: self.groupId, deviceId: member.id, role: role)
            return "\(member.name) can now \(role == .editor ? "edit" : "view") \(self.folderName)."
        }
        await load()
    }

    public func removeAccess(_ member: MemberRow) async {
        await revoke(id: member.id, name: member.name, force: false)
    }

    public func confirmOverride() async {
        guard let prompt = pendingOverride else { return }
        pendingOverride = nil
        await revoke(id: prompt.targetId, name: prompt.targetName, force: true)
    }

    private func revoke(id: String, name: String, force: Bool) async {
        do {
            let outcome = try await client.revokeMember(groupId: groupId, deviceId: id, force: force)
            warnings = MembershipWarning.warnings(for: outcome)
            notice = Notice(kind: .success, text: "Removed access for \(name).")
            await load()
        } catch DesktopError.durabilityBlocked(let message, _, _, true) where !force {
            pendingOverride = OverridePrompt(targetId: id, targetName: name, message: message)
        } catch {
            notice = .failure(error)
        }
    }

    public func approve(_ request: RequestRow) async {
        await work {
            switch try await self.client.approveRequest(groupId: self.groupId, deviceId: request.tooltip) {
            case .approved: return "Approved."
            case .alreadyActive: return "That device already has access."
            case .unrecognized(let raw): return "The server answered: \(raw)"
            }
        }
        await load()
    }

    public func deny(_ request: RequestRow) async {
        await work {
            let outcome = try await self.client.denyRequest(groupId: self.groupId, deviceId: request.tooltip)
            self.warnings = MembershipWarning.warnings(for: outcome)
            return "Request declined."
        }
        await load()
    }

    public func cancelInvite(_ row: InviteRow) async {
        await work {
            try await self.client.cancelInvite(inviteId: row.id)
            return "Invite link cancelled."
        }
        await load()
    }

    private func work(_ body: () async throws -> String?) async {
        isWorking = true
        defer { isWorking = false }
        do {
            if let text = try await body() { notice = Notice(kind: .success, text: text) }
        } catch {
            notice = .failure(error)
        }
    }
}

// MARK: - Transfers

public struct SyncRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var title: String
    public var subtitle: String
    public var progress: Double
    public var tooltip: String
}

public struct InboxRow: Identifiable, Equatable, Sendable {
    public var id: String { tooltip }
    /// "From Studio: 2 files, 18 MB"
    public var title: String
    public var status: String
    public var files: [String]
    public var canReceive: Bool
    /// Still waiting, running or failed: Cancel stops it, and a canceled one stays listed.
    public var canCancel: Bool
    /// Failed or canceled: Retry checks the sender and destination again, then resumes.
    public var canRetry: Bool
    /// The transfer id.
    public var tooltip: String
}

@MainActor
@Observable
public final class TransfersViewModel {
    public let app: AppModel
    public private(set) var inbox: FetchPhase<[IncomingTransfer]> = .notLoaded
    /// Target devices. A failed read is not "no devices": the picker says so and offers Retry.
    public private(set) var devicesPhase: FetchPhase<[DeviceSummary]> = .notLoaded
    public var devices: [DeviceSummary] { devicesPhase.value ?? [] }
    public private(set) var devicesStale: Notice?
    public private(set) var inboxStale: Notice?
    public private(set) var isSending = false
    public var sourcePath = ""
    public var targetDeviceId: String?
    public var notice: Notice?

    public init(app: AppModel) { self.app = app }

    private func deviceName(_ id: String) -> String {
        devices.first { $0.deviceId == id }?.displayName ?? "another device"
    }

    /// The daemon's aggregate rate while transfers are active; nil when idle.
    public var rateLine: String? {
        guard let snapshot = app.snapshot, !snapshot.transfers.isEmpty else { return nil }
        return TransferRate.text(snapshot.bandwidth)
    }

    public var recentProblemLines: [TextLine] {
        guard let snapshot = app.snapshot else { return [] }
        return RecentProblems.items(errors: snapshot.recentErrors, activeReasons: snapshot.attentionReasons, now: Date()).map {
            TextLine(text: [$0.text, $0.age].compactMap { $0 }.joined(separator: " · "), tooltip: $0.tooltip, folderLocalPath: nil)
        }
    }

    /// Sync transfers straight from the status snapshot.
    public var syncRows: [SyncRow] {
        guard let snapshot = app.snapshot else { return [] }
        return snapshot.transfers.map { t in
            let folder = snapshot.folders.first { $0.localPath == t.folderLocalPath }?.name
            var parts: [String] = []
            if let folder { parts.append(folder) }
            parts.append("\(Format.bytes(t.bytesDone)) of \(Format.bytes(t.bytesTotal))")
            return SyncRow(
                id: "\(t.groupId)/\(t.path)",
                title: (t.path as NSString).lastPathComponent,
                subtitle: parts.joined(separator: " · "),
                progress: t.bytesTotal > 0 ? Double(t.bytesDone) / Double(t.bytesTotal) : 0,
                tooltip: t.path
            )
        }
    }

    public var showsInboxLoading: Bool { inbox == .loading }
    public var showsInboxEmpty: Bool { inbox.value?.isEmpty == true && inboxStale == nil }
    public var inboxError: Notice? {
        if case .failed(let n) = inbox { return n }
        return nil
    }
    public var devicesError: Notice? {
        if case .failed(let n) = devicesPhase { return n }
        return nil
    }
    /// "No other devices" is only said after the read succeeded.
    public var showsNoTargetDevices: Bool { devicesPhase.value != nil && targetDevices.isEmpty && devicesStale == nil }

    public var inboxRows: [InboxRow] {
        (inbox.value ?? []).map { t in
            let status: String = switch t.status {
            case .pending: "Waiting"
            case .inProgress: "Receiving"
            case .completed: "Received"
            case .failed: "Failed"
            case .canceled: "Canceled"
            case .other: "Unknown"
            }
            return InboxRow(
                title: "From \(deviceName(t.senderDeviceId)): \(Plural.files(t.files.count)), \(Format.bytes(t.totalSize))",
                status: status,
                files: t.files.map(\.relativePath),
                canReceive: t.status == .pending,
                canCancel: t.status == .pending || t.status == .inProgress || t.status == .failed,
                canRetry: t.status == .failed || t.status == .canceled,
                tooltip: t.transferId
            )
        }
    }

    public var targetDevices: [DeviceSummary] { devices.filter { !$0.isThisDevice } }

    public func loadDevices() async {
        // Another account may sign in next; never carry this roster over.
        if !app.isSignedIn {
            devicesPhase = .notLoaded
            devicesStale = nil
            targetDeviceId = nil
        }
        guard app.isSignedIn, !app.isDaemonUnavailable else { return }
        if devicesPhase.value == nil { devicesPhase = .loading }
        do {
            let list = try await app.client.listFolderDevices()
            // Signed out while the read was in flight: that roster belongs to the old account.
            guard app.isSignedIn else { return }
            devicesPhase = .loaded(list)
            devicesStale = nil
        } catch {
            guard app.isSignedIn else { return }
            if devicesPhase.value == nil {
                devicesPhase = .failed(.failure(error))
            } else {
                devicesStale = .failure(error)
            }
        }
    }

    public func loadInbox() async {
        if inbox.value == nil { inbox = .loading }
        do {
            inbox = .loaded(try await app.client.listInbox())
            inboxStale = nil
        } catch {
            if inbox.value == nil {
                inbox = .failed(.failure(error))
            } else {
                inboxStale = .failure(error)
            }
        }
    }

    public var canSend: Bool { !sourcePath.isEmpty && targetDeviceId != nil && !isSending }

    public func send() async {
        guard let target = targetDeviceId, !sourcePath.isEmpty else { return }
        isSending = true
        defer { isSending = false }
        do {
            let sent = try await app.client.sendToDevice(sourcePath: sourcePath, targetDeviceId: target)
            notice = Notice(kind: .success, text: "Sent to \(deviceName(target)): \(Plural.files(sent.filesOffered.count)), \(Format.bytes(sent.totalSize))", detail: sent.transferId)
        } catch {
            notice = .failure(error)
        }
    }

    public func receive(_ row: InboxRow, into directory: String?) async {
        do {
            let received = try await app.client.receiveTransfer(transferId: row.tooltip, destinationDir: directory)
            notice = Notice(kind: .success, text: "Received \(Plural.files(received.filesReceived.count)) in \((received.destinationDir as NSString).lastPathComponent).")
            await loadInbox()
        } catch {
            notice = .failure(error)
        }
    }

    public func cancel(_ row: InboxRow) async {
        do {
            try await app.client.cancelTransfer(transferId: row.tooltip)
            await loadInbox()
        } catch {
            notice = .failure(error)
        }
    }

    public func retry(_ row: InboxRow) async {
        do {
            let received = try await app.client.retryTransfer(transferId: row.tooltip)
            notice = Notice(kind: .success, text: "Received \(Plural.files(received.filesReceived.count)) in \((received.destinationDir as NSString).lastPathComponent).")
            await loadInbox()
        } catch {
            notice = .failure(error)
            await loadInbox()
        }
    }
}
