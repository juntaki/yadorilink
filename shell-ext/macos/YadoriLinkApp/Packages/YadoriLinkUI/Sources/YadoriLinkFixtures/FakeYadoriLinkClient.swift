// An in-memory client that behaves like the real one closely enough for view
// model tests and Previews: it follows the same error rules (only
// `DesktopError`), refuses coordination calls when signed out, answers
// nothing but `daemonUnavailable` while the daemon is down, and applies
// mutations to its own state so the status watch sees them.

import Foundation
import YadoriLinkModel

public final class FakeYadoriLinkClient: YadoriLinkClient, @unchecked Sendable {
    private let lock = NSLock()

    // State. Read and written only under `lock`.
    private var _daemonRunning: Bool
    private var _snapshot: StatusSnapshot
    private var _account: AccountStatus
    private var _devices: [DeviceSummary]
    private var _inbox: [IncomingTransfer]
    private var _limits: BandwidthLimits
    private var _update: UpdateStatus
    private var _members: [String: [MemberSummary]]
    private var _approvals: [PendingApprovalSummary]
    private var _invites: [PendingInviteSummary]
    private var _availability: [String: FileAvailability] = [:]
    private var _failures: [String: DesktopError] = [:]
    private var _calls: [String] = []
    private var _durabilityBlocksRemoval: Bool
    private var _watches: [WeakWatch] = []

    /// Events the next sign-in session replays.
    public var loginScript: [FakeLoginSession.Step] {
        get { lock.withLock { _loginScript } }
        set { lock.withLock { _loginScript = newValue } }
    }
    private var _loginScript: [FakeLoginSession.Step]
    /// What `begin()` throws, if anything.
    public var loginBeginError: DesktopError? {
        get { lock.withLock { _loginBeginError } }
        set { lock.withLock { _loginBeginError = newValue } }
    }
    private var _loginBeginError: DesktopError?
    /// Result of `runPreflight`, keyed by path; unknown paths get a clean result.
    public var preflightResults: [String: PreflightResult] {
        get { lock.withLock { _preflight } }
        set { lock.withLock { _preflight = newValue } }
    }
    private var _preflight: [String: PreflightResult] = [:]
    /// Artificial latency for every call, so Previews can show loading states.
    public let latency: TimeInterval

    public init(scenario: FakeScenario = .healthy, latency: TimeInterval = 0) {
        self.latency = latency
        _daemonRunning = scenario != .daemonDown
        _devices = Fixtures.devices
        _inbox = Fixtures.inbox
        _limits = Fixtures.noLimits
        _update = Fixtures.updateStatus()
        _members = ["g-docs": Fixtures.members, "g-documents": Fixtures.members, "g-photos": Fixtures.members]
        _approvals = Fixtures.pendingApprovals
        _invites = Fixtures.invites
        _durabilityBlocksRemoval = scenario == .durabilityBlockedRevoke
        _loginScript = Fixtures.loginEvents().map { FakeLoginSession.Step($0) }
        _account = Fixtures.account()

        switch scenario {
        case .healthy, .durabilityBlockedRevoke:
            _snapshot = Fixtures.snapshot(folders: Fixtures.healthyFolders)
        case .syncing:
            _snapshot = Fixtures.syncingSnapshot
        case .problem:
            _snapshot = Fixtures.problemSnapshot
        case .daemonDown:
            _snapshot = Fixtures.snapshot(folders: Fixtures.healthyFolders)
            _account = Fixtures.account(hasLinkedFolders: nil)
        case .signedOut:
            _snapshot = Fixtures.snapshot(folders: [])
            _account = Fixtures.account(.signedOut, hasLinkedFolders: false)
        case .empty:
            _snapshot = Fixtures.snapshot(folders: [])
            _account = Fixtures.account(hasLinkedFolders: false)
            _inbox = []
        case .credentialStoreUnusable:
            _snapshot = Fixtures.snapshot(folders: Fixtures.healthyFolders)
            _account = Fixtures.account(.credentialStoreUnusable(message: "keychain item is not readable"))
        case .twentyFolders:
            _snapshot = Fixtures.snapshot(folders: Fixtures.twentyFolders)
        case .japaneseLongNames:
            _snapshot = Fixtures.snapshot(folders: Fixtures.japaneseFolders)
            _devices = [
                DeviceSummary(deviceId: Fixtures.thisDeviceId, displayName: "山田のMacBook Pro(仕事用・2026年モデル)", online: true, lastSeen: Fixtures.now, isThisDevice: true),
                DeviceSummary(deviceId: Fixtures.studioId, displayName: "自宅のMac Studio", online: true, lastSeen: Fixtures.now, isThisDevice: false),
            ]
        case .updateAvailable:
            _snapshot = Fixtures.snapshot(folders: Fixtures.healthyFolders, update: Fixtures.updateBadge(available: "0.4.3"))
            _update = Fixtures.updateStatus(available: "0.4.3")
        }
    }

    // MARK: Test hooks

    /// Every call made so far, by method base name ("pauseFolder").
    public var calls: [String] { lock.withLock { _calls } }

    /// Make `method` (base name, e.g. "startDaemon") throw `error` until cleared with `nil`.
    public func setFailure(_ method: String, _ error: DesktopError?) {
        lock.withLock { _failures[method] = error }
    }

    /// Replace the daemon status the watch reports.
    public func setSnapshot(_ snapshot: StatusSnapshot) {
        lock.withLock { _snapshot = snapshot; _daemonRunning = true }
        notifyWatches()
    }

    /// Stop or start answering, as if the daemon went away or came back.
    public func setDaemonRunning(_ running: Bool) {
        lock.withLock { _daemonRunning = running }
        notifyWatches()
    }

    public func setAccount(_ account: AccountStatus) {
        lock.withLock { _account = account }
    }

    public func setAvailability(_ availability: FileAvailability, for path: String) {
        lock.withLock { _availability[path] = availability }
    }

    public func setInbox(_ inbox: [IncomingTransfer]) {
        lock.withLock { _inbox = inbox }
    }

    public func setDevices(_ devices: [DeviceSummary]) {
        lock.withLock { _devices = devices }
    }

    public func setMembers(_ members: [MemberSummary], groupId: String) {
        lock.withLock { _members[groupId] = members }
    }

    /// What the status watch would report right now.
    public var currentStatus: StatusUpdate {
        lock.withLock {
            _daemonRunning ? .snapshot(snapshot: _snapshot) : .unavailable(error: Fixtures.daemonDownError)
        }
    }

    // MARK: Plumbing

    private func enter(_ function: String = #function, daemon: Bool = true, signedIn: Bool = false) async throws {
        let name = String(function.prefix { $0 != "(" })
        let (failure, running, account) = lock.withLock { () -> (DesktopError?, Bool, AccountStatus) in
            _calls.append(name)
            return (_failures[name], _daemonRunning, _account)
        }
        if latency > 0 { try? await Task.sleep(for: .seconds(latency)) }
        if let failure { throw failure }
        if daemon && !running { throw Fixtures.daemonDownError }
        if signedIn && account.signIn != .signedIn { throw Fixtures.signedOutError }
    }

    private func mutate<T>(_ body: (FakeYadoriLinkClient) throws -> T) rethrows -> T {
        let result = try lock.withLock { try body(self) }
        notifyWatches()
        return result
    }

    private func notifyWatches() {
        let watches = lock.withLock { () -> [FakeStatusWatch] in
            _watches.removeAll { $0.watch == nil }
            return _watches.compactMap(\.watch)
        }
        watches.forEach { $0.sourceChanged() }
    }

    private func updateFolder(localPath: String, _ change: (inout FolderSummary) -> Void) throws {
        guard let index = _snapshot.folders.firstIndex(where: { $0.localPath == localPath }) else {
            throw DesktopError.invalidInput(message: "no linked folder at \(localPath)", field: "local_path")
        }
        change(&_snapshot.folders[index])
    }

    private func removalBlocked(force: Bool) -> DesktopError? {
        guard _durabilityBlocksRemoval, !force else { return nil }
        return .durabilityBlocked(message: "no other device has a complete copy yet", groupIds: ["g-docs"], operationId: nil, canForce: true)
    }

    // MARK: session / identity

    public func accountStatus() async -> AccountStatus {
        try? await enter(daemon: false)
        return lock.withLock {
            var account = _account
            if !_daemonRunning { account.hasLinkedFolders = nil }
            return account
        }
    }

    public func newLoginSession(options: LoginOptions) -> any LoginSessionHandle {
        let (script, beginError) = lock.withLock { () -> ([FakeLoginSession.Step], DesktopError?) in
            _calls.append("newLoginSession")
            return (_loginScript, _loginBeginError)
        }
        return FakeLoginSession(steps: script, beginError: beginError) { [weak self] account in
            self?.lock.withLock { self?._account = account }
        }
    }

    public func signOut() async throws -> SignOutOutcome {
        try await enter(daemon: false, signedIn: true)
        lock.withLock { _account = Fixtures.account(.signedOut, hasLinkedFolders: _account.hasLinkedFolders) }
        return SignOutOutcome(kind: .revoked(grantsRevoked: 1))
    }

    public func registerDevice(name: String) async throws -> DeviceRegistration {
        try await enter(daemon: false, signedIn: true)
        return DeviceRegistration(deviceId: Fixtures.thisDeviceId)
    }

    // MARK: status

    public func statusSnapshot() async throws -> StatusSnapshot {
        try await enter()
        return lock.withLock { _snapshot }
    }

    public func watchStatus(interval: TimeInterval) -> any StatusWatchHandle {
        let watch = FakeStatusWatch(source: { [weak self] in self?.currentStatus })
        lock.withLock { _watches.append(WeakWatch(watch: watch)) }
        return watch
    }

    public func folderDetail(localPath: String) async throws -> FolderDetail {
        try await enter()
        return try lock.withLock {
            guard let summary = _snapshot.folders.first(where: { $0.localPath == localPath }) else {
                throw DesktopError.invalidInput(message: "no linked folder at \(localPath)", field: "local_path")
            }
            let peers = Dictionary(_snapshot.peers.map { ($0.deviceId, $0) }, uniquingKeysWith: { a, _ in a })
            let copies = summary.fullReplicaDeviceIds.map { id in
                ReplicaCopy(deviceId: id, reachability: peers[id]?.reachability ?? .unknown, route: peers[id]?.route ?? .unknown)
            }
            return FolderDetail(summary: summary, heldFiles: [], completeCopies: copies)
        }
    }

    public func folderPeerCounts() async throws -> [String: UInt32] {
        try await enter(signedIn: true)
        return lock.withLock {
            Dictionary(_snapshot.folders.map { ($0.groupId, UInt32($0.fullReplicaDeviceIds.count)) }, uniquingKeysWith: { a, _ in a })
        }
    }

    // MARK: folder control

    public func pauseFolder(localPath: String) async throws {
        try await enter()
        try mutate { try $0.updateFolder(localPath: localPath) { $0.paused = true; $0.state = .paused } }
    }

    public func resumeFolder(localPath: String) async throws {
        try await enter()
        try mutate { try $0.updateFolder(localPath: localPath) { $0.paused = false; $0.state = .upToDate } }
    }

    public func pauseAll() async throws {
        try await enter()
        mutate { c in
            for i in c._snapshot.folders.indices { c._snapshot.folders[i].paused = true; c._snapshot.folders[i].state = .paused }
        }
    }

    public func resumeAll() async throws {
        try await enter()
        mutate { c in
            for i in c._snapshot.folders.indices { c._snapshot.folders[i].paused = false; c._snapshot.folders[i].state = .upToDate }
        }
    }

    public func unlinkFolder(localPath: String, force: Bool) async throws -> UnlinkOutcome {
        try await enter()
        return try mutate { c in
            if let blocked = c.removalBlocked(force: force) { throw blocked }
            c._snapshot.folders.removeAll { $0.localPath == localPath }
            return UnlinkOutcome(handoff: nil)
        }
    }

    public func setStorageMode(groupId: String, mode: FolderMode) async throws -> StorageModeOutcome {
        try await enter()
        return try mutate { c in
            guard let i = c._snapshot.folders.firstIndex(where: { $0.groupId == groupId }) else {
                throw DesktopError.invalidInput(message: "folder group is not linked on this device", field: "group_id")
            }
            if c._snapshot.folders[i].mode == mode { return StorageModeOutcome(changed: false, handoff: nil) }
            c._snapshot.folders[i].mode = mode
            c._snapshot.folders[i].localStorage = mode == .keepAll ? .fullCopy : .partiallyMaterialized
            return StorageModeOutcome(changed: true, handoff: nil)
        }
    }

    // MARK: files

    public func listConflicts(localPath: String?) async throws -> [ConflictSummary] {
        try await enter()
        let hasConflicts = lock.withLock { _snapshot.folders.contains { $0.conflictCount > 0 } }
        guard hasConflicts else { return [] }
        return Fixtures.conflicts.filter { localPath == nil || $0.localPath == localPath }
    }

    public func listTrash(localPath: String?) async throws -> [TrashedFile] {
        try await enter()
        return Fixtures.trash.filter { localPath == nil || $0.localPath == localPath }
    }

    public func restoreFromTrash(absolutePath: String) async throws { try await enter() }

    /// Restores every fixture entry sharing the named entry's operation.
    public func restoreTrashOperation(absolutePath: String) async throws -> FolderRestoreOutcome {
        try await enter()
        let named = Fixtures.trash.first { ($0.localPath as NSString).appendingPathComponent($0.path) == absolutePath }
        guard let operation = named?.deletedByOperation else {
            throw DesktopError.invalidInput(message: "\(absolutePath) was deleted on its own", field: "absolute_path")
        }
        let paths = Fixtures.trash.filter { $0.deletedByOperation == operation }.map(\.path).sorted()
        return FolderRestoreOutcome(restoredPaths: paths, failed: [], partial: false)
    }

    public func listVersions(absolutePath: String) async throws -> [FileVersion] {
        try await enter()
        return Fixtures.versions
    }

    public func restoreVersion(absolutePath: String, versionSeq: Int64?) async throws { try await enter() }

    public func fileAvailability(absolutePath: String) async throws -> FileAvailability {
        try await enter()
        return lock.withLock { _availability[absolutePath] ?? FileAvailability(tracked: true, state: .placeholder, pinned: false) }
    }

    private func setAvailability(_ path: String, _ change: (inout FileAvailability) -> Void) {
        lock.withLock {
            var a = _availability[path] ?? FileAvailability(tracked: true, state: .placeholder, pinned: false)
            change(&a)
            _availability[path] = a
        }
    }

    public func pinFile(absolutePath: String) async throws {
        try await enter()
        setAvailability(absolutePath) { $0.pinned = true; $0.state = .hydrated }
    }

    public func unpinFile(absolutePath: String) async throws {
        try await enter()
        setAvailability(absolutePath) { $0.pinned = false }
    }

    public func hydrateFile(absolutePath: String) async throws {
        try await enter()
        setAvailability(absolutePath) { $0.state = .hydrated }
    }

    public func evictFile(absolutePath: String) async throws -> EvictOutcome {
        try await enter()
        setAvailability(absolutePath) { $0.state = .placeholder }
        return EvictOutcome(evicted: true, blocksReclaimed: 4, bytesReclaimed: 12 * Fixtures.mib)
    }

    // MARK: devices

    public func listFolderDevices() async throws -> [DeviceSummary] {
        try await enter(signedIn: true)
        return lock.withLock { _devices }
    }

    public func listAccountDevices() async throws -> [DeviceSummary] {
        try await enter(daemon: false, signedIn: true)
        return lock.withLock { _devices.map { var d = $0; d.lastSeen = nil; return d } }
    }

    public func removeDevice(deviceId: String, force: Bool) async throws -> MembershipOutcome {
        try await enter(daemon: false, signedIn: true)
        return try lock.withLock {
            if let blocked = removalBlocked(force: force) { throw blocked }
            _devices.removeAll { $0.deviceId == deviceId }
            return MembershipOutcome(handoffs: [], forcedGroupIds: force ? ["g-docs"] : [], unknownScopeOperationId: nil)
        }
    }

    // MARK: send / receive

    public func sendToDevice(sourcePath: String, targetDeviceId: String) async throws -> SentTransfer {
        try await enter(signedIn: true)
        return SentTransfer(transferId: "t-send-1", filesOffered: [(sourcePath as NSString).lastPathComponent], totalSize: 3 * Fixtures.mib)
    }

    public func listInbox() async throws -> [IncomingTransfer] {
        try await enter()
        return lock.withLock { _inbox }
    }

    public func receiveTransfer(transferId: String, destinationDir: String?) async throws -> ReceivedTransfer {
        try await enter()
        return try lock.withLock {
            guard let i = _inbox.firstIndex(where: { $0.transferId == transferId }) else {
                throw DesktopError.invalidInput(message: "no such transfer", field: "transfer_id")
            }
            let t = _inbox[i]
            _inbox[i].status = .completed
            return ReceivedTransfer(destinationDir: destinationDir ?? "/Users/me/Downloads", filesReceived: t.files.map(\.relativePath), bytesReceived: t.totalSize)
        }
    }

    // MARK: storage / settings / daemon

    public func runGc(dryRun: Bool) async throws -> GcReport {
        try await enter()
        return mutate { c in
            let bytes = c._snapshot.storage.reclaimableEstimateBytes
            if !dryRun { c._snapshot.storage.reclaimableEstimateBytes = 0; c._snapshot.storage.lastGcAt = Fixtures.now }
            return GcReport(dryRun: dryRun, blocksDeleted: bytes / (256 * 1024), bytesReclaimed: bytes)
        }
    }

    public func bandwidthLimits() async throws -> BandwidthLimits {
        try await enter()
        return lock.withLock { _limits }
    }

    public func setBandwidthLimits(limits: BandwidthLimits) async throws -> BandwidthLimits {
        try await enter()
        return mutate { c in
            c._limits = limits
            c._snapshot.bandwidth.limits = limits
            return limits
        }
    }

    public func exportDiagnostics(destinationPath: String) async throws -> DiagnosticsExport {
        try await enter(daemon: false)
        let running = lock.withLock { _daemonRunning }
        return DiagnosticsExport(path: destinationPath, collectionMode: running ? .daemon : .offlineFallback, redactionCount: 3)
    }

    public func startDaemon() async throws -> DaemonStartOutcome {
        try await enter(daemon: false)
        let wasRunning = lock.withLock { () -> Bool in
            let was = _daemonRunning
            _daemonRunning = true
            if _account.hasLinkedFolders == nil { _account.hasLinkedFolders = !_snapshot.folders.isEmpty }
            return was
        }
        notifyWatches()
        return wasRunning ? .alreadyRunning : .started
    }

    public func stopDaemon() async throws {
        try await enter()
        setDaemonRunning(false)
    }

    // MARK: updates

    public func updateStatus() async throws -> UpdateStatus {
        try await enter()
        return lock.withLock { _update }
    }

    public func checkForUpdates() async throws -> UpdateStatus {
        try await enter()
        return lock.withLock { _update.lastCheckedAt = Fixtures.now; return _update }
    }

    public func installUpdate() async throws -> UpdateInstallOutcome {
        try await enter()
        return .installing
    }

    public func setUpdateConfig(automaticChecks: Bool?, installMode: UpdateInstallMode?) async throws -> UpdateConfig {
        try await enter()
        return lock.withLock {
            if let automaticChecks { _update.config.automaticChecks = automaticChecks }
            if let installMode { _update.config.installMode = installMode }
            return _update.config
        }
    }

    // MARK: account

    public func accountDeletionStatus() async throws -> AccountDeletionStatus {
        try await enter(daemon: false, signedIn: true)
        return AccountDeletionStatus(state: .active, graceExpiresAt: nil, remaining: nil)
    }

    public func requestAccountDeletion() async throws -> AccountDeletionRequest {
        try await enter(daemon: false, signedIn: true)
        return AccountDeletionRequest(confirmationToken: "DELETE-4F2A")
    }

    public func confirmAccountDeletion(confirmationToken: String) async throws -> AccountDeletionStatus {
        try await enter(daemon: false, signedIn: true)
        return AccountDeletionStatus(state: .grace, graceExpiresAt: Fixtures.now.addingTimeInterval(30 * 86_400), remaining: 30 * 86_400)
    }

    public func cancelAccountDeletion() async throws -> AccountDeletionStatus {
        try await enter(daemon: false, signedIn: true)
        return AccountDeletionStatus(state: .active, graceExpiresAt: nil, remaining: nil)
    }

    public func exportAccountData() async throws -> String {
        try await enter(daemon: false, signedIn: true)
        return "{\"devices\":3,\"shared_folders\":2}"
    }

    // MARK: shares

    public func listOwnedGroups() async throws -> [GroupSummary] {
        try await enter(daemon: false, signedIn: true)
        return Fixtures.ownedGroups
    }

    public func listJoinableGroups() async throws -> [GroupSummary] {
        try await enter(daemon: false, signedIn: true)
        return Fixtures.ownedGroups
    }

    public func listMembers(groupId: String) async throws -> [MemberSummary] {
        try await enter(daemon: false, signedIn: true)
        return lock.withLock { _members[groupId] ?? [] }
    }

    public func changeMemberRole(groupId: String, deviceId: String, role: AssignableRole) async throws {
        try await enter(daemon: false, signedIn: true)
        lock.withLock {
            guard let i = _members[groupId]?.firstIndex(where: { $0.deviceId == deviceId }) else { return }
            _members[groupId]?[i].role = role == .editor ? .editor : .viewer
        }
    }

    public func revokeMember(groupId: String, deviceId: String, force: Bool) async throws -> MembershipOutcome {
        try await enter(daemon: false, signedIn: true)
        return try lock.withLock {
            if let blocked = removalBlocked(force: force) { throw blocked }
            _members[groupId]?.removeAll { $0.deviceId == deviceId }
            return MembershipOutcome(handoffs: [], forcedGroupIds: force ? [groupId] : [], unknownScopeOperationId: nil)
        }
    }

    public func denyRequest(groupId: String, deviceId: String) async throws -> MembershipOutcome {
        try await enter(daemon: false, signedIn: true)
        lock.withLock { _approvals.removeAll { $0.groupId == groupId && $0.deviceId == deviceId } }
        return MembershipOutcome(handoffs: [], forcedGroupIds: [], unknownScopeOperationId: nil)
    }

    public func approveRequest(groupId: String, deviceId: String) async throws -> ApproveOutcome {
        try await enter(daemon: false, signedIn: true)
        lock.withLock { _approvals.removeAll { $0.groupId == groupId && $0.deviceId == deviceId } }
        return .approved
    }

    public func listPendingApprovals() async throws -> [PendingApprovalSummary] {
        try await enter(daemon: false, signedIn: true)
        return lock.withLock { _approvals }
    }

    public func listShares() async throws -> [ShareSummary] {
        try await enter(daemon: false, signedIn: true)
        return [ShareSummary(edgeId: "e-1", groupId: "g-docs", groupName: "Documents", deviceId: Fixtures.phoneId, state: .active, role: .viewer)]
    }

    public func revokeShareEdge(edgeId: String, force: Bool) async throws -> RevokeEdgeOutcome {
        try await enter(daemon: false, signedIn: true)
        if let blocked = lock.withLock({ removalBlocked(force: force) }) { throw blocked }
        return .revoked(outcome: MembershipOutcome(handoffs: [], forcedGroupIds: [], unknownScopeOperationId: nil))
    }

    public func mintInvite(groupId: String, role: AssignableRole?, ttl: TimeInterval?, requireApproval: Bool) async throws -> InviteSummary {
        try await enter(daemon: false, signedIn: true)
        let code = "K7QX-M2PA"
        return lock.withLock {
            let invite = InviteSummary(inviteId: "inv-\(_invites.count + 1)", code: code, url: "yadorilink://invite/\(code)", groupId: groupId, role: role == .editor ? .editor : .viewer, expiresAt: Fixtures.now.addingTimeInterval(ttl ?? 7 * 86_400), requiresApproval: requireApproval)
            _invites.append(PendingInviteSummary(inviteId: invite.inviteId, groupId: groupId, groupName: groupId, role: invite.role, expiresAt: invite.expiresAt, status: .pending))
            return invite
        }
    }

    public func listInvites() async throws -> [PendingInviteSummary] {
        try await enter(daemon: false, signedIn: true)
        return lock.withLock { _invites }
    }

    public func cancelInvite(inviteId: String) async throws {
        try await enter(daemon: false, signedIn: true)
        lock.withLock { _invites.removeAll { $0.inviteId == inviteId } }
    }

    public func acceptInvite(codeOrUrl: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> AcceptInviteOutcome {
        try await enter(signedIn: true)
        return AcceptInviteOutcome(groupId: "g-invited", localPath: localPath, awaitingApproval: true)
    }

    // MARK: linking

    public func runPreflight(localPath: String) async throws -> PreflightResult {
        try await enter(daemon: false)
        return lock.withLock {
            _preflight[localPath] ?? PreflightResult(resolvedPath: localPath, pathExists: true, isDirectory: true, entryCount: 0, ignoredEntryCount: 0, totalSizeBytes: 0, scanTruncated: false, freeSpace: FreeSpace(availableBytes: 182 * Fixtures.gib, totalBytes: 494 * Fixtures.gib, headroomBytes: 10 * Fixtures.gib, state: .ok), issues: [], requiresAcknowledgement: false)
        }
    }

    private func link(groupId: String, name: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) throws -> LinkOutcome {
        if let pre = _preflight[localPath], pre.requiresAcknowledgement, !acknowledgeRisks {
            throw DesktopError.invalidInput(message: "linking this folder needs acknowledgement", field: "acknowledge_risks")
        }
        _snapshot.folders.append(Fixtures.folder(name, path: localPath, groupId: groupId, mode: mode, replicas: []))
        _account.hasLinkedFolders = true
        return LinkOutcome(groupId: groupId, localPath: localPath, mode: mode)
    }

    public func createGroupAndLink(groupName: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome {
        try await enter(signedIn: true)
        return try mutate { try $0.link(groupId: "g-new", name: groupName, localPath: localPath, mode: mode, acknowledgeRisks: acknowledgeRisks) }
    }

    public func joinGroupAndLink(groupId: String, groupName: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome {
        try await enter(signedIn: true)
        return try mutate { try $0.link(groupId: groupId, name: groupName, localPath: localPath, mode: mode, acknowledgeRisks: acknowledgeRisks) }
    }

    public func linkFolder(localPath: String, groupId: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome {
        try await enter(signedIn: true)
        let name = (localPath as NSString).lastPathComponent
        return try mutate { try $0.link(groupId: groupId, name: name, localPath: localPath, mode: mode, acknowledgeRisks: acknowledgeRisks) }
    }
}

private struct WeakWatch {
    weak var watch: FakeStatusWatch?
}
