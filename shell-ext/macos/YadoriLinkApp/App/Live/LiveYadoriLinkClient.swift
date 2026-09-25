import Foundation
import YadoriLinkFFI
import YadoriLinkModel

/// The app's client over the Rust client core (the generated `YadoriLinkFFI`
/// binding). One forwarding line per method: every argument and result goes
/// through the field-for-field conversions in `FFIMapping.swift`, and every
/// error comes back as the mirror `DesktopError`.
final class LiveYadoriLinkClient: YadoriLinkClient {
    private let core: YadoriLinkFFI.ClientCore

    init(config: YadoriLinkModel.CoreConfig) {
        core = YadoriLinkFFI.ClientCore(config: YadoriLinkFFI.CoreConfig(config))
    }

    // MARK: session / identity

    func accountStatus() async -> YadoriLinkModel.AccountStatus {
        YadoriLinkModel.AccountStatus(await core.accountStatus())
    }

    func newLoginSession(options: YadoriLinkModel.LoginOptions) -> any LoginSessionHandle {
        var options = options
        // A deadline already past (negative) or meaningless (NaN) fails the
        // sign-in at once; only one too far off to carry means "no deadline".
        if let timeout = options.overallTimeout, !isCarriable(timeout) {
            options.overallTimeout = (timeout.isNaN || timeout < 0) ? 0 : nil
        }
        return LiveLoginSession(core.newLoginSession(options: YadoriLinkFFI.LoginOptions(options)))
    }

    func signOut() async throws -> YadoriLinkModel.SignOutOutcome {
        try await mapped { YadoriLinkModel.SignOutOutcome(try await core.signOut()) }
    }

    func registerDevice(name: String) async throws -> YadoriLinkModel.DeviceRegistration {
        try await mapped { YadoriLinkModel.DeviceRegistration(try await core.registerDevice(name: name)) }
    }

    // MARK: status

    func statusSnapshot() async throws -> YadoriLinkModel.StatusSnapshot {
        try await mapped { YadoriLinkModel.StatusSnapshot(try await core.statusSnapshot()) }
    }

    func watchStatus(interval: TimeInterval) -> any StatusWatchHandle {
        let interval = isCarriable(interval) ? max(interval, minimumPollInterval) : defaultPollInterval
        return LiveStatusWatch(core.watchStatus(interval: interval))
    }

    func folderDetail(localPath: String) async throws -> YadoriLinkModel.FolderDetail {
        try await mapped { YadoriLinkModel.FolderDetail(try await core.folderDetail(localPath: localPath)) }
    }

    func folderPeerCounts() async throws -> [String: UInt32] {
        try await mapped { try await core.folderPeerCounts() }
    }

    // MARK: folder control

    func pauseFolder(localPath: String) async throws {
        try await mapped { try await core.pauseFolder(localPath: localPath) }
    }

    func resumeFolder(localPath: String) async throws {
        try await mapped { try await core.resumeFolder(localPath: localPath) }
    }

    func pauseAll() async throws {
        try await mapped { try await core.pauseAll() }
    }

    func resumeAll() async throws {
        try await mapped { try await core.resumeAll() }
    }

    func unlinkFolder(localPath: String, force: Bool) async throws -> YadoriLinkModel.UnlinkOutcome {
        try await mapped { YadoriLinkModel.UnlinkOutcome(try await core.unlinkFolder(localPath: localPath, force: force)) }
    }

    func setStorageMode(groupId: String, mode: YadoriLinkModel.FolderMode) async throws -> YadoriLinkModel.StorageModeOutcome {
        try await mapped {
            YadoriLinkModel.StorageModeOutcome(try await core.setStorageMode(groupId: groupId, mode: YadoriLinkFFI.FolderMode(mode)))
        }
    }

    // MARK: files

    func listConflicts(localPath: String?) async throws -> [YadoriLinkModel.ConflictSummary] {
        try await mapped { try await core.listConflicts(localPath: localPath).map { YadoriLinkModel.ConflictSummary($0) } }
    }

    func listTrash(localPath: String?) async throws -> [YadoriLinkModel.TrashedFile] {
        try await mapped { try await core.listTrash(localPath: localPath).map { YadoriLinkModel.TrashedFile($0) } }
    }

    func restoreFromTrash(absolutePath: String) async throws {
        try await mapped { try await core.restoreFromTrash(absolutePath: absolutePath) }
    }

    func restoreTrashOperation(absolutePath: String) async throws -> YadoriLinkModel.FolderRestoreOutcome {
        try await mapped { YadoriLinkModel.FolderRestoreOutcome(try await core.restoreTrashOperation(absolutePath: absolutePath)) }
    }

    func listVersions(absolutePath: String) async throws -> [YadoriLinkModel.FileVersion] {
        try await mapped { try await core.listVersions(absolutePath: absolutePath).map { YadoriLinkModel.FileVersion($0) } }
    }

    func restoreVersion(absolutePath: String, versionSeq: Int64?) async throws {
        try await mapped { try await core.restoreVersion(absolutePath: absolutePath, versionSeq: versionSeq) }
    }

    func fileAvailability(absolutePath: String) async throws -> YadoriLinkModel.FileAvailability {
        try await mapped { YadoriLinkModel.FileAvailability(try await core.fileAvailability(absolutePath: absolutePath)) }
    }

    func pinFile(absolutePath: String) async throws {
        try await mapped { try await core.pinFile(absolutePath: absolutePath) }
    }

    func unpinFile(absolutePath: String) async throws {
        try await mapped { try await core.unpinFile(absolutePath: absolutePath) }
    }

    func hydrateFile(absolutePath: String) async throws {
        try await mapped { try await core.hydrateFile(absolutePath: absolutePath) }
    }

    func evictFile(absolutePath: String) async throws -> YadoriLinkModel.EvictOutcome {
        try await mapped { YadoriLinkModel.EvictOutcome(try await core.evictFile(absolutePath: absolutePath)) }
    }

    // MARK: devices

    func listFolderDevices() async throws -> [YadoriLinkModel.DeviceSummary] {
        try await mapped { try await core.listFolderDevices().map { YadoriLinkModel.DeviceSummary($0) } }
    }

    func listAccountDevices() async throws -> [YadoriLinkModel.DeviceSummary] {
        try await mapped { try await core.listAccountDevices().map { YadoriLinkModel.DeviceSummary($0) } }
    }

    func removeDevice(deviceId: String, force: Bool) async throws -> YadoriLinkModel.MembershipOutcome {
        try await mapped { YadoriLinkModel.MembershipOutcome(try await core.removeDevice(deviceId: deviceId, force: force)) }
    }

    // MARK: send / receive

    func sendToDevice(sourcePath: String, targetDeviceId: String) async throws -> YadoriLinkModel.SentTransfer {
        try await mapped {
            YadoriLinkModel.SentTransfer(try await core.sendToDevice(sourcePath: sourcePath, targetDeviceId: targetDeviceId))
        }
    }

    func listInbox() async throws -> [YadoriLinkModel.IncomingTransfer] {
        try await mapped { try await core.listInbox().map { YadoriLinkModel.IncomingTransfer($0) } }
    }

    func receiveTransfer(transferId: String, destinationDir: String?) async throws -> YadoriLinkModel.ReceivedTransfer {
        try await mapped {
            YadoriLinkModel.ReceivedTransfer(try await core.receiveTransfer(transferId: transferId, destinationDir: destinationDir))
        }
    }

    // MARK: storage / settings / daemon

    func runGc(dryRun: Bool) async throws -> YadoriLinkModel.GcReport {
        try await mapped { YadoriLinkModel.GcReport(try await core.runGc(dryRun: dryRun)) }
    }

    func bandwidthLimits() async throws -> YadoriLinkModel.BandwidthLimits {
        try await mapped { YadoriLinkModel.BandwidthLimits(try await core.bandwidthLimits()) }
    }

    func setBandwidthLimits(limits: YadoriLinkModel.BandwidthLimits) async throws -> YadoriLinkModel.BandwidthLimits {
        try await mapped {
            YadoriLinkModel.BandwidthLimits(try await core.setBandwidthLimits(limits: YadoriLinkFFI.BandwidthLimits(limits)))
        }
    }

    func exportDiagnostics(destinationPath: String) async throws -> YadoriLinkModel.DiagnosticsExport {
        try await mapped { YadoriLinkModel.DiagnosticsExport(try await core.exportDiagnostics(destinationPath: destinationPath)) }
    }

    func startDaemon() async throws -> YadoriLinkModel.DaemonStartOutcome {
        try await mapped { YadoriLinkModel.DaemonStartOutcome(try await core.startDaemon()) }
    }

    func stopDaemon() async throws {
        try await mapped { try await core.stopDaemon() }
    }

    // MARK: updates

    func updateStatus() async throws -> YadoriLinkModel.UpdateStatus {
        try await mapped { YadoriLinkModel.UpdateStatus(try await core.updateStatus()) }
    }

    func checkForUpdates() async throws -> YadoriLinkModel.UpdateStatus {
        try await mapped { YadoriLinkModel.UpdateStatus(try await core.checkForUpdates()) }
    }

    func installUpdate() async throws -> YadoriLinkModel.UpdateInstallOutcome {
        try await mapped { YadoriLinkModel.UpdateInstallOutcome(try await core.installUpdate()) }
    }

    func setUpdateConfig(automaticChecks: Bool?, installMode: YadoriLinkModel.UpdateInstallMode?) async throws -> YadoriLinkModel.UpdateConfig {
        try await mapped {
            YadoriLinkModel.UpdateConfig(try await core.setUpdateConfig(
                automaticChecks: automaticChecks,
                installMode: installMode.map { YadoriLinkFFI.UpdateInstallMode($0) }
            ))
        }
    }

    // MARK: account

    func accountDeletionStatus() async throws -> YadoriLinkModel.AccountDeletionStatus {
        try await mapped { YadoriLinkModel.AccountDeletionStatus(try await core.accountDeletionStatus()) }
    }

    func requestAccountDeletion() async throws -> YadoriLinkModel.AccountDeletionRequest {
        try await mapped { YadoriLinkModel.AccountDeletionRequest(try await core.requestAccountDeletion()) }
    }

    func confirmAccountDeletion(confirmationToken: String) async throws -> YadoriLinkModel.AccountDeletionStatus {
        try await mapped {
            YadoriLinkModel.AccountDeletionStatus(try await core.confirmAccountDeletion(confirmationToken: confirmationToken))
        }
    }

    func cancelAccountDeletion() async throws -> YadoriLinkModel.AccountDeletionStatus {
        try await mapped { YadoriLinkModel.AccountDeletionStatus(try await core.cancelAccountDeletion()) }
    }

    func exportAccountData() async throws -> String {
        try await mapped { try await core.exportAccountData() }
    }

    // MARK: shares

    func listOwnedGroups() async throws -> [YadoriLinkModel.GroupSummary] {
        try await mapped { try await core.listOwnedGroups().map { YadoriLinkModel.GroupSummary($0) } }
    }

    func listJoinableGroups() async throws -> [YadoriLinkModel.GroupSummary] {
        try await mapped { try await core.listJoinableGroups().map { YadoriLinkModel.GroupSummary($0) } }
    }

    func listMembers(groupId: String) async throws -> [YadoriLinkModel.MemberSummary] {
        try await mapped { try await core.listMembers(groupId: groupId).map { YadoriLinkModel.MemberSummary($0) } }
    }

    func changeMemberRole(groupId: String, deviceId: String, role: YadoriLinkModel.AssignableRole) async throws {
        try await mapped {
            try await core.changeMemberRole(groupId: groupId, deviceId: deviceId, role: YadoriLinkFFI.AssignableRole(role))
        }
    }

    func revokeMember(groupId: String, deviceId: String, force: Bool) async throws -> YadoriLinkModel.MembershipOutcome {
        try await mapped {
            YadoriLinkModel.MembershipOutcome(try await core.revokeMember(groupId: groupId, deviceId: deviceId, force: force))
        }
    }

    func denyRequest(groupId: String, deviceId: String) async throws -> YadoriLinkModel.MembershipOutcome {
        try await mapped { YadoriLinkModel.MembershipOutcome(try await core.denyRequest(groupId: groupId, deviceId: deviceId)) }
    }

    func approveRequest(groupId: String, deviceId: String) async throws -> YadoriLinkModel.ApproveOutcome {
        try await mapped { YadoriLinkModel.ApproveOutcome(try await core.approveRequest(groupId: groupId, deviceId: deviceId)) }
    }

    func listPendingApprovals() async throws -> [YadoriLinkModel.PendingApprovalSummary] {
        try await mapped { try await core.listPendingApprovals().map { YadoriLinkModel.PendingApprovalSummary($0) } }
    }

    func listShares() async throws -> [YadoriLinkModel.ShareSummary] {
        try await mapped { try await core.listShares().map { YadoriLinkModel.ShareSummary($0) } }
    }

    func revokeShareEdge(edgeId: String, force: Bool) async throws -> YadoriLinkModel.RevokeEdgeOutcome {
        try await mapped { YadoriLinkModel.RevokeEdgeOutcome(try await core.revokeShareEdge(edgeId: edgeId, force: force)) }
    }

    func mintInvite(groupId: String, role: YadoriLinkModel.AssignableRole?, ttl: TimeInterval?, requireApproval: Bool) async throws -> YadoriLinkModel.InviteSummary {
        if let ttl, !isCarriable(ttl) {
            throw YadoriLinkModel.DesktopError.invalidInput(message: "an invite lifetime must be a non-negative number of seconds, not \(ttl)", field: "ttl")
        }
        return try await mapped {
            YadoriLinkModel.InviteSummary(try await core.mintInvite(
                groupId: groupId,
                role: role.map { YadoriLinkFFI.AssignableRole($0) },
                ttl: ttl,
                requireApproval: requireApproval
            ))
        }
    }

    func listInvites() async throws -> [YadoriLinkModel.PendingInviteSummary] {
        try await mapped { try await core.listInvites().map { YadoriLinkModel.PendingInviteSummary($0) } }
    }

    func cancelInvite(inviteId: String) async throws {
        try await mapped { try await core.cancelInvite(inviteId: inviteId) }
    }

    func acceptInvite(codeOrUrl: String, localPath: String, mode: YadoriLinkModel.FolderMode, acknowledgeRisks: Bool) async throws -> YadoriLinkModel.AcceptInviteOutcome {
        try await mapped {
            YadoriLinkModel.AcceptInviteOutcome(try await core.acceptInvite(
                codeOrUrl: codeOrUrl,
                localPath: localPath,
                mode: YadoriLinkFFI.FolderMode(mode),
                acknowledgeRisks: acknowledgeRisks
            ))
        }
    }

    // MARK: linking

    func runPreflight(localPath: String) async throws -> YadoriLinkModel.PreflightResult {
        try await mapped { YadoriLinkModel.PreflightResult(try await core.runPreflight(localPath: localPath)) }
    }

    func createGroupAndLink(groupName: String, localPath: String, mode: YadoriLinkModel.FolderMode, acknowledgeRisks: Bool) async throws -> YadoriLinkModel.LinkOutcome {
        try await mapped {
            YadoriLinkModel.LinkOutcome(try await core.createGroupAndLink(
                groupName: groupName,
                localPath: localPath,
                mode: YadoriLinkFFI.FolderMode(mode),
                acknowledgeRisks: acknowledgeRisks
            ))
        }
    }

    func joinGroupAndLink(groupId: String, groupName: String, localPath: String, mode: YadoriLinkModel.FolderMode, acknowledgeRisks: Bool) async throws -> YadoriLinkModel.LinkOutcome {
        try await mapped {
            YadoriLinkModel.LinkOutcome(try await core.joinGroupAndLink(
                groupId: groupId,
                groupName: groupName,
                localPath: localPath,
                mode: YadoriLinkFFI.FolderMode(mode),
                acknowledgeRisks: acknowledgeRisks
            ))
        }
    }

    func linkFolder(localPath: String, groupId: String, mode: YadoriLinkModel.FolderMode, acknowledgeRisks: Bool) async throws -> YadoriLinkModel.LinkOutcome {
        try await mapped {
            YadoriLinkModel.LinkOutcome(try await core.linkFolder(
                localPath: localPath,
                groupId: groupId,
                mode: YadoriLinkFFI.FolderMode(mode),
                acknowledgeRisks: acknowledgeRisks
            ))
        }
    }
}

/// Whether the binding can carry `seconds` as a duration. Its converter traps
/// on a negative, NaN or out-of-range value, so none may reach it.
private func isCarriable(_ seconds: TimeInterval) -> Bool {
    seconds.isFinite && seconds >= 0 && seconds < Double(Int64.max)
}

/// The shortest status poll interval passed on, so a zero or negative one
/// cannot spin the poll loop.
private let minimumPollInterval: TimeInterval = 0.05

/// The status poll interval used in place of one the binding cannot carry.
private let defaultPollInterval: TimeInterval = 2

/// Runs one binding call and rethrows its error as the mirror
/// `DesktopError`, the only error a client method may throw. The binding's
/// async calls ignore Task cancellation and never throw `CancellationError`;
/// a sign-in or status watch is stopped through its own `cancel()`.
private func mapped<T>(_ call: () async throws -> T) async throws -> T {
    do {
        return try await call()
    } catch let error as YadoriLinkFFI.DesktopError {
        throw YadoriLinkModel.DesktopError(error)
    } catch {
        throw YadoriLinkModel.DesktopError.internal(message: String(describing: error), category: "binding")
    }
}

/// A sign-in session over the binding's `LoginSession`.
final class LiveLoginSession: LoginSessionHandle {
    private let session: YadoriLinkFFI.LoginSession

    init(_ session: YadoriLinkFFI.LoginSession) {
        self.session = session
    }

    func begin() throws {
        do {
            try session.begin()
        } catch let error as YadoriLinkFFI.DesktopError {
            throw YadoriLinkModel.DesktopError(error)
        } catch {
            throw YadoriLinkModel.DesktopError.internal(message: String(describing: error), category: "binding")
        }
    }

    func nextEvent() async -> YadoriLinkModel.LoginEvent? {
        await session.nextEvent().map { YadoriLinkModel.LoginEvent($0) }
    }

    func cancel() {
        session.cancel()
    }
}

/// The status poll loop over the binding's `StatusWatch`.
final class LiveStatusWatch: StatusWatchHandle {
    private let watch: YadoriLinkFFI.StatusWatch

    init(_ watch: YadoriLinkFFI.StatusWatch) {
        self.watch = watch
    }

    func next() async -> YadoriLinkModel.StatusUpdate? {
        await watch.next().map { YadoriLinkModel.StatusUpdate($0) }
    }

    func refresh() {
        watch.refresh()
    }

    func cancel() {
        watch.cancel()
    }
}
