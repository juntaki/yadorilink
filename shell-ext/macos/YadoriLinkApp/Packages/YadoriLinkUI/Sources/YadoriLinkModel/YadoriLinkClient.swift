// The client the app codes against. The live implementation wraps the
// generated binding of the Rust client core; the fake in
// YadoriLinkFixtures replays fixture states.
//
// Rules every implementation follows:
// - Every `throws` throws only `DesktopError`.
// - Methods may be called from any actor and never block the caller.
// - Cancelling a Swift task abandons the await, but a mutation that has
//   already started still completes. Callers refresh instead of assuming
//   it did not happen.

import Foundation

public protocol YadoriLinkClient: AnyObject, Sendable {
    // session / identity
    func accountStatus() async -> AccountStatus
    func newLoginSession(options: LoginOptions) -> any LoginSessionHandle
    func signOut() async throws -> SignOutOutcome
    func registerDevice(name: String) async throws -> DeviceRegistration

    // status
    func statusSnapshot() async throws -> StatusSnapshot
    func watchStatus(interval: TimeInterval) -> any StatusWatchHandle
    func folderDetail(localPath: String) async throws -> FolderDetail
    func folderPeerCounts() async throws -> [String: UInt32]

    // folder control
    func pauseFolder(localPath: String) async throws
    func resumeFolder(localPath: String) async throws
    func pauseAll() async throws
    func resumeAll() async throws
    func unlinkFolder(localPath: String, force: Bool) async throws -> UnlinkOutcome
    func setStorageMode(groupId: String, mode: FolderMode) async throws -> StorageModeOutcome

    // files
    func listConflicts(localPath: String?) async throws -> [ConflictSummary]
    func listTrash(localPath: String?) async throws -> [TrashedFile]
    func restoreFromTrash(absolutePath: String) async throws
    func restoreTrashOperation(absolutePath: String) async throws -> FolderRestoreOutcome
    func listVersions(absolutePath: String) async throws -> [FileVersion]
    func restoreVersion(absolutePath: String, versionSeq: Int64?) async throws
    func fileAvailability(absolutePath: String) async throws -> FileAvailability
    func pinFile(absolutePath: String) async throws
    func unpinFile(absolutePath: String) async throws
    func hydrateFile(absolutePath: String) async throws
    func evictFile(absolutePath: String) async throws -> EvictOutcome

    // devices
    func listFolderDevices() async throws -> [DeviceSummary]
    func listAccountDevices() async throws -> [DeviceSummary]
    func removeDevice(deviceId: String, force: Bool) async throws -> MembershipOutcome

    // send / receive
    func sendToDevice(sourcePath: String, targetDeviceId: String) async throws -> SentTransfer
    func listInbox() async throws -> [IncomingTransfer]
    func receiveTransfer(transferId: String, destinationDir: String?) async throws -> ReceivedTransfer

    // storage / settings / daemon
    func runGc(dryRun: Bool) async throws -> GcReport
    func bandwidthLimits() async throws -> BandwidthLimits
    func setBandwidthLimits(limits: BandwidthLimits) async throws -> BandwidthLimits
    func exportDiagnostics(destinationPath: String) async throws -> DiagnosticsExport
    func startDaemon() async throws -> DaemonStartOutcome
    func stopDaemon() async throws

    // updates
    func updateStatus() async throws -> UpdateStatus
    func checkForUpdates() async throws -> UpdateStatus
    func installUpdate() async throws -> UpdateInstallOutcome
    func setUpdateConfig(automaticChecks: Bool?, installMode: UpdateInstallMode?) async throws -> UpdateConfig

    // account
    func accountDeletionStatus() async throws -> AccountDeletionStatus
    func requestAccountDeletion() async throws -> AccountDeletionRequest
    func confirmAccountDeletion(confirmationToken: String) async throws -> AccountDeletionStatus
    func cancelAccountDeletion() async throws -> AccountDeletionStatus
    func exportAccountData() async throws -> String

    // shares
    func listOwnedGroups() async throws -> [GroupSummary]
    func listJoinableGroups() async throws -> [GroupSummary]
    func listMembers(groupId: String) async throws -> [MemberSummary]
    func changeMemberRole(groupId: String, deviceId: String, role: AssignableRole) async throws
    func revokeMember(groupId: String, deviceId: String, force: Bool) async throws -> MembershipOutcome
    func denyRequest(groupId: String, deviceId: String) async throws -> MembershipOutcome
    func approveRequest(groupId: String, deviceId: String) async throws -> ApproveOutcome
    func listPendingApprovals() async throws -> [PendingApprovalSummary]
    func listShares() async throws -> [ShareSummary]
    func revokeShareEdge(edgeId: String, force: Bool) async throws -> RevokeEdgeOutcome
    func mintInvite(groupId: String, role: AssignableRole?, ttl: TimeInterval?, requireApproval: Bool) async throws -> InviteSummary
    func listInvites() async throws -> [PendingInviteSummary]
    func cancelInvite(inviteId: String) async throws
    func acceptInvite(codeOrUrl: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> AcceptInviteOutcome

    // linking
    func runPreflight(localPath: String) async throws -> PreflightResult
    func createGroupAndLink(groupName: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome
    func joinGroupAndLink(groupId: String, groupName: String, localPath: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome
    func linkFolder(localPath: String, groupId: String, mode: FolderMode, acknowledgeRisks: Bool) async throws -> LinkOutcome
}

/// An explicit sign-in lifecycle. The app opens the browser itself when it
/// receives `.openBrowser`.
public protocol LoginSessionHandle: AnyObject, Sendable {
    /// Starts the flow and returns immediately. Throws `DesktopError`.
    func begin() throws
    /// The next event in order; `nil` after a terminal event was returned once.
    func nextEvent() async -> LoginEvent?
    /// Idempotent. Nothing is stored, and the next event is `.cancelled`
    /// unless a terminal event was already queued.
    func cancel()
}

/// One status poll loop per process. `next()` returns the first result at
/// once, then waits until the result changes or `refresh()` forces a poll.
public protocol StatusWatchHandle: AnyObject, Sendable {
    func next() async -> StatusUpdate?
    func refresh()
    func cancel()
}
