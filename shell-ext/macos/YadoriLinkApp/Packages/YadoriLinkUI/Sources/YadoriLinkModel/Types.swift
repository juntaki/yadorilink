// Product types the app sees. These mirror the records and enums the Rust
// client core exports. Names, field order, argument labels and cases follow
// the generated binding exactly, so the live client can map them field for
// field with no logic. Paths are plain strings; times are `Date`; durations
// are `TimeInterval`.

import Foundation

// MARK: - Construction

public enum DaemonLaunch: Sendable, Equatable, Hashable {
    case spawnBinary(path: String?)
    case launchAgent(label: String, fallbackBinary: String?)
}

public struct CoreConfig: Sendable, Equatable, Hashable {
    public var daemonLaunch: DaemonLaunch
    public init(daemonLaunch: DaemonLaunch) { self.daemonLaunch = daemonLaunch }
}

// MARK: - Errors

public enum DaemonUnavailableReason: Sendable, Equatable, Hashable {
    case notRunning
    /// Running but not answering in time: starting it again cannot help.
    case unresponsive
    case protocolMismatch(clientVersion: UInt32, daemonVersion: UInt32)
}

public enum NetworkErrorKind: Sendable, Equatable, Hashable {
    case unreachable, rateLimited, activationPendingReconciliation
}

public enum PermissionDeniedReason: Sendable, Equatable, Hashable {
    case sessionRejected, forbidden, quotaExceeded, credentialStoreUnusable
}

/// The only error any client method throws. Views branch on the case and
/// reason, never on `message` (diagnostic English for tooltips and details).
public enum DesktopError: Error, Sendable, Equatable, Hashable {
    case notSignedIn(message: String)
    case daemonUnavailable(message: String, reason: DaemonUnavailableReason)
    case network(message: String, kind: NetworkErrorKind)
    case permissionDenied(message: String, reason: PermissionDeniedReason)
    case durabilityBlocked(message: String, groupIds: [String], operationId: String?, canForce: Bool)
    case invalidInput(message: String, field: String?)
    case `internal`(message: String, category: String)
}

// MARK: - Account

public enum SignInState: Sendable, Equatable, Hashable {
    case signedOut
    case signedIn
    case credentialStoreUnusable(message: String)
}

public struct AccountStatus: Sendable, Equatable, Hashable {
    public var signIn: SignInState
    public var clientId: String?
    public var thisDeviceId: String?
    public var deviceRegistered: Bool
    public var defaultDeviceName: String
    public var hasLinkedFolders: Bool?
    public init(signIn: SignInState, clientId: String?, thisDeviceId: String?, deviceRegistered: Bool, defaultDeviceName: String, hasLinkedFolders: Bool?) {
        self.signIn = signIn; self.clientId = clientId; self.thisDeviceId = thisDeviceId
        self.deviceRegistered = deviceRegistered; self.defaultDeviceName = defaultDeviceName
        self.hasLinkedFolders = hasLinkedFolders
    }
}

public enum SignOutKind: Sendable, Equatable, Hashable {
    case revoked(grantsRevoked: UInt32)
    case alreadyRevoked
    case confirmedRevokedAfterRejection
}

public struct SignOutOutcome: Sendable, Equatable, Hashable {
    public var kind: SignOutKind
    public init(kind: SignOutKind) { self.kind = kind }
}

public struct DeviceRegistration: Sendable, Equatable, Hashable {
    public var deviceId: String
    public init(deviceId: String) { self.deviceId = deviceId }
}

public enum AccountDeletionState: Sendable, Equatable, Hashable {
    case active, requested, grace
    case other(raw: String)
}

public struct AccountDeletionStatus: Sendable, Equatable, Hashable {
    public var state: AccountDeletionState
    public var graceExpiresAt: Date?
    public var remaining: TimeInterval?
    public init(state: AccountDeletionState, graceExpiresAt: Date?, remaining: TimeInterval?) {
        self.state = state; self.graceExpiresAt = graceExpiresAt; self.remaining = remaining
    }
}

public struct AccountDeletionRequest: Sendable, Equatable, Hashable {
    public var confirmationToken: String
    public init(confirmationToken: String) { self.confirmationToken = confirmationToken }
}

// MARK: - Sign-in

public enum LoginFlow: Sendable, Equatable, Hashable { case loopback, deviceCode }

public struct LoginOptions: Sendable, Equatable, Hashable {
    public var flow: LoginFlow
    public var overallTimeout: TimeInterval?
    public init(flow: LoginFlow, overallTimeout: TimeInterval?) {
        self.flow = flow; self.overallTimeout = overallTimeout
    }
}

public enum BrowserPurpose: Sendable, Equatable, Hashable { case approveDevice, signIn }

public enum LoginEvent: Sendable, Equatable, Hashable {
    case enrolling
    case openBrowser(url: String, purpose: BrowserPurpose)
    case waitingForApproval(expiresIn: TimeInterval)
    case waitingForAuthorization
    case showDeviceCode(verificationUri: String, userCode: String)
    case signedIn(account: AccountStatus)
    case failed(error: DesktopError)
    case cancelled
}

// MARK: - Status

public enum OverallState: Sendable, Equatable, Hashable { case healthy, attention, degraded, unknown }

public enum AttentionCategory: Sendable, Equatable, Hashable, CaseIterable {
    case degraded, durabilityAtRisk, durabilityUnknown, fetchUnavailable, fetchAvailabilityUnknown,
         conflict, held, lowDiskCritical, lowDisk, peerDisconnected, recentError, updateFailed,
         unrecognized
}

public struct AttentionReason: Sendable, Equatable, Hashable {
    public var category: AttentionCategory
    public var subject: String
    public var folderLocalPath: String?
    public var raw: String
    public init(category: AttentionCategory, subject: String, folderLocalPath: String?, raw: String) {
        self.category = category; self.subject = subject; self.folderLocalPath = folderLocalPath; self.raw = raw
    }
}

public enum FolderMode: Sendable, Equatable, Hashable, CaseIterable { case keepAll, onDemand }
public enum FolderState: Sendable, Equatable, Hashable, CaseIterable { case upToDate, syncing, paused, blocked, attention }
public enum DurabilityStatus: Sendable, Equatable, Hashable, CaseIterable { case protected, protecting, atRisk, unknown }
public enum DurabilityEvidence: Sendable, Equatable, Hashable { case none, corroboratedIndex, verifiedPayload, unknown }
public enum LocalStorageState: Sendable, Equatable, Hashable, CaseIterable { case fullCopy, partiallyMaterialized, onDemand, unknown }
public enum FetchAvailability: Sendable, Equatable, Hashable { case availableNow, unavailableNow, unknown }

public struct FolderTransferProgress: Sendable, Equatable, Hashable {
    public var bytesDone: UInt64
    public var bytesTotal: UInt64
    public var blocksDone: UInt64
    public var blocksTotal: UInt64
    public var eta: TimeInterval?
    public init(bytesDone: UInt64, bytesTotal: UInt64, blocksDone: UInt64, blocksTotal: UInt64, eta: TimeInterval?) {
        self.bytesDone = bytesDone; self.bytesTotal = bytesTotal
        self.blocksDone = blocksDone; self.blocksTotal = blocksTotal; self.eta = eta
    }
}

public enum FreeSpaceState: Sendable, Equatable, Hashable { case ok, low, critical, unknown }

public struct VolumeSummary: Sendable, Equatable, Hashable {
    public var path: String
    public var state: FreeSpaceState
    public var availableBytes: UInt64
    public var headroomBytes: UInt64
    public init(path: String, state: FreeSpaceState, availableBytes: UInt64, headroomBytes: UInt64) {
        self.path = path; self.state = state; self.availableBytes = availableBytes; self.headroomBytes = headroomBytes
    }
}

public struct FolderSummary: Sendable, Equatable, Hashable {
    public var localPath: String
    public var groupId: String
    public var name: String
    public var mode: FolderMode
    public var state: FolderState
    public var paused: Bool
    public var conflictCount: UInt64
    public var hydratedFileCount: UInt64
    public var placeholderFileCount: UInt64
    public var hydratingFileCount: UInt64
    public var heldFileCount: UInt64
    public var skippedSymlinkCount: UInt64
    public var transfer: FolderTransferProgress?
    public var durability: DurabilityStatus
    public var durabilityEvidence: DurabilityEvidence
    public var localStorage: LocalStorageState
    public var fetchAvailability: FetchAvailability
    public var fullReplicaDeviceIds: [String]
    public var policyStale: Bool
    public var ambiguous: Bool
    public var ambiguousLocalPaths: [String]
    public var degraded: Bool
    public var degradedReason: String?
    public var volume: VolumeSummary?


    public init(localPath: String, groupId: String, name: String, mode: FolderMode, state: FolderState, paused: Bool, conflictCount: UInt64, hydratedFileCount: UInt64, placeholderFileCount: UInt64, hydratingFileCount: UInt64, heldFileCount: UInt64, skippedSymlinkCount: UInt64, transfer: FolderTransferProgress?, durability: DurabilityStatus, durabilityEvidence: DurabilityEvidence, localStorage: LocalStorageState, fetchAvailability: FetchAvailability, fullReplicaDeviceIds: [String], policyStale: Bool, ambiguous: Bool, ambiguousLocalPaths: [String], degraded: Bool, degradedReason: String?, volume: VolumeSummary?) {
        self.localPath = localPath; self.groupId = groupId; self.name = name; self.mode = mode
        self.state = state; self.paused = paused; self.conflictCount = conflictCount
        self.hydratedFileCount = hydratedFileCount; self.placeholderFileCount = placeholderFileCount
        self.hydratingFileCount = hydratingFileCount; self.heldFileCount = heldFileCount
        self.skippedSymlinkCount = skippedSymlinkCount; self.transfer = transfer
        self.durability = durability; self.durabilityEvidence = durabilityEvidence
        self.localStorage = localStorage; self.fetchAvailability = fetchAvailability
        self.fullReplicaDeviceIds = fullReplicaDeviceIds; self.policyStale = policyStale
        self.ambiguous = ambiguous; self.ambiguousLocalPaths = ambiguousLocalPaths
        self.degraded = degraded; self.degradedReason = degradedReason; self.volume = volume
    }
}

public enum PeerReachability: Sendable, Equatable, Hashable { case connecting, connected, unreachable, unknown }
public enum UnreachableCategory: Sendable, Equatable, Hashable { case noCandidates, noResponse, udpBlocked, handshakeRefused }
public enum RouteKind: Sendable, Equatable, Hashable { case direct, relay, unknown }

public struct PeerSummary: Sendable, Equatable, Hashable {
    public var deviceId: String
    public var reachability: PeerReachability
    public var unreachableCategory: UnreachableCategory?
    public var route: RouteKind
    public init(deviceId: String, reachability: PeerReachability, unreachableCategory: UnreachableCategory?, route: RouteKind) {
        self.deviceId = deviceId; self.reachability = reachability
        self.unreachableCategory = unreachableCategory; self.route = route
    }
}

public struct TransferSummary: Sendable, Equatable, Hashable {
    public var groupId: String
    public var folderLocalPath: String?
    public var path: String
    public var bytesDone: UInt64
    public var bytesTotal: UInt64
    public var blocksDone: UInt64
    public var blocksTotal: UInt64
    public var sourceDeviceId: String
    public var startedAt: Date?
    public init(groupId: String, folderLocalPath: String?, path: String, bytesDone: UInt64, bytesTotal: UInt64, blocksDone: UInt64, blocksTotal: UInt64, sourceDeviceId: String, startedAt: Date?) {
        self.groupId = groupId; self.folderLocalPath = folderLocalPath; self.path = path
        self.bytesDone = bytesDone; self.bytesTotal = bytesTotal; self.blocksDone = blocksDone
        self.blocksTotal = blocksTotal; self.sourceDeviceId = sourceDeviceId; self.startedAt = startedAt
    }
}

public struct BandwidthLimits: Sendable, Equatable, Hashable {
    /// `nil` means unlimited.
    public var uploadBytesPerSec: UInt64?
    public var downloadBytesPerSec: UInt64?
    public init(uploadBytesPerSec: UInt64?, downloadBytesPerSec: UInt64?) {
        self.uploadBytesPerSec = uploadBytesPerSec; self.downloadBytesPerSec = downloadBytesPerSec
    }
}

public struct BandwidthStatus: Sendable, Equatable, Hashable {
    public var limits: BandwidthLimits
    public var currentUploadBytesPerSec: UInt64
    public var currentDownloadBytesPerSec: UInt64
    public init(limits: BandwidthLimits, currentUploadBytesPerSec: UInt64, currentDownloadBytesPerSec: UInt64) {
        self.limits = limits; self.currentUploadBytesPerSec = currentUploadBytesPerSec
        self.currentDownloadBytesPerSec = currentDownloadBytesPerSec
    }
}

public struct StorageSummary: Sendable, Equatable, Hashable {
    public var blockStoreTotalBytes: UInt64
    public var blockCount: UInt64
    public var lastGcAt: Date?
    public var reclaimableEstimateBytes: UInt64
    public init(blockStoreTotalBytes: UInt64, blockCount: UInt64, lastGcAt: Date?, reclaimableEstimateBytes: UInt64) {
        self.blockStoreTotalBytes = blockStoreTotalBytes; self.blockCount = blockCount
        self.lastGcAt = lastGcAt; self.reclaimableEstimateBytes = reclaimableEstimateBytes
    }
}

public enum UpdateState: Sendable, Equatable, Hashable {
    case idle, checking, available, heldBack, killSwitched, downloading, downloaded, verified,
         installing, failed, deferred, upToDate
    case unknown(raw: String)
}

public struct UpdateBadge: Sendable, Equatable, Hashable {
    public var state: UpdateState
    public var availableVersion: String?
    public var mandatory: Bool
    public var waitingForSafePoint: Bool
    public var lastErrorCategory: String?
    public var channel: String
    public var installSource: String
    public var holdbackReason: String?
    public init(state: UpdateState, availableVersion: String?, mandatory: Bool, waitingForSafePoint: Bool, lastErrorCategory: String?, channel: String, installSource: String, holdbackReason: String?) {
        self.state = state; self.availableVersion = availableVersion; self.mandatory = mandatory
        self.waitingForSafePoint = waitingForSafePoint; self.lastErrorCategory = lastErrorCategory
        self.channel = channel; self.installSource = installSource; self.holdbackReason = holdbackReason
    }
}

public struct RecentError: Sendable, Equatable, Hashable {
    public var category: String
    public var at: Date?
    public var context: String
    public init(category: String, at: Date?, context: String) {
        self.category = category; self.at = at; self.context = context
    }
}

public struct StatusSnapshot: Sendable, Equatable, Hashable {
    public var capturedAt: Date
    public var overall: OverallState
    public var attentionReasons: [AttentionReason]
    public var thisDeviceId: String?
    public var folders: [FolderSummary]
    public var peers: [PeerSummary]
    public var transfers: [TransferSummary]
    public var bandwidth: BandwidthStatus
    public var volumes: [VolumeSummary]
    public var storage: StorageSummary
    public var update: UpdateBadge
    public var recentErrors: [RecentError]
    public init(capturedAt: Date, overall: OverallState, attentionReasons: [AttentionReason], thisDeviceId: String?, folders: [FolderSummary], peers: [PeerSummary], transfers: [TransferSummary], bandwidth: BandwidthStatus, volumes: [VolumeSummary], storage: StorageSummary, update: UpdateBadge, recentErrors: [RecentError]) {
        self.capturedAt = capturedAt; self.overall = overall; self.attentionReasons = attentionReasons
        self.thisDeviceId = thisDeviceId; self.folders = folders; self.peers = peers
        self.transfers = transfers; self.bandwidth = bandwidth; self.volumes = volumes
        self.storage = storage; self.update = update; self.recentErrors = recentErrors
    }
}

public enum StatusUpdate: Sendable, Equatable, Hashable {
    case snapshot(snapshot: StatusSnapshot)
    case unavailable(error: DesktopError)
}

// MARK: - Folder detail and files

public struct HeldFile: Sendable, Equatable, Hashable {
    public var path: String
    public var reason: String
    public var heldSince: Date?
    public init(path: String, reason: String, heldSince: Date?) {
        self.path = path; self.reason = reason; self.heldSince = heldSince
    }
}

public struct ReplicaCopy: Sendable, Equatable, Hashable {
    public var deviceId: String
    public var reachability: PeerReachability
    public var route: RouteKind
    public init(deviceId: String, reachability: PeerReachability, route: RouteKind) {
        self.deviceId = deviceId; self.reachability = reachability; self.route = route
    }
}

public struct FolderDetail: Sendable, Equatable, Hashable {
    public var summary: FolderSummary
    public var heldFiles: [HeldFile]
    public var completeCopies: [ReplicaCopy]
    public init(summary: FolderSummary, heldFiles: [HeldFile], completeCopies: [ReplicaCopy]) {
        self.summary = summary; self.heldFiles = heldFiles; self.completeCopies = completeCopies
    }
}

public struct ConflictSummary: Sendable, Equatable, Hashable {
    public var localPath: String
    public var path: String
    public var size: UInt64
    public var modifiedAt: Date?
    public var currentPath: String
    public var loserDeviceId: String?
    public var conflictTimestamp: String?
    public var kind: EntryKind
    public var reason: ConflictReason
    /// The folder's history compaction is waiting for this conflict to be
    /// resolved; sync is unaffected.
    public var holdsCompaction: Bool
    public init(localPath: String, path: String, size: UInt64, modifiedAt: Date?, currentPath: String, loserDeviceId: String?, conflictTimestamp: String?, kind: EntryKind, reason: ConflictReason, holdsCompaction: Bool = false) {
        self.localPath = localPath; self.path = path; self.size = size; self.modifiedAt = modifiedAt
        self.currentPath = currentPath; self.loserDeviceId = loserDeviceId; self.conflictTimestamp = conflictTimestamp
        self.kind = kind; self.reason = reason; self.holdsCompaction = holdsCompaction
    }
}

/// Why a conflict copy is kept under its own name: devices changed the same
/// file at the same time, or the name it came from is a folder now and the
/// file was moved aside instead of replacing the folder.
public enum ConflictReason: Sendable, Equatable, Hashable, CaseIterable { case concurrentEdit, folderAtPath }

/// What kind of filesystem entry a record is. A directory carries no size
/// or modification time of its own.
public enum EntryKind: Sendable, Equatable, Hashable, CaseIterable { case file, directory, symlink }

public struct TrashedFile: Sendable, Equatable, Hashable {
    public var localPath: String
    public var path: String
    public var versionSeq: Int64
    public var lastKnownSize: UInt64
    public var originDeviceId: String?
    public var deletedAt: Date?
    public var kind: EntryKind
    /// The recursive delete or directory rename that removed this entry;
    /// every trashed entry sharing it is restored together. `nil` for an
    /// entry deleted on its own.
    public var deletedByOperation: String?
    public init(localPath: String, path: String, versionSeq: Int64, lastKnownSize: UInt64, originDeviceId: String?, deletedAt: Date?, kind: EntryKind, deletedByOperation: String?) {
        self.localPath = localPath; self.path = path; self.versionSeq = versionSeq
        self.lastKnownSize = lastKnownSize; self.originDeviceId = originDeviceId; self.deletedAt = deletedAt
        self.kind = kind; self.deletedByOperation = deletedByOperation
    }
}

/// What restoring a folder from the trash brought back.
public struct FolderRestoreOutcome: Sendable, Equatable, Hashable {
    /// Relative to the folder root, in path order.
    public var restoredPaths: [String]
    public var failed: [FolderRestoreFailure]
    /// Not every part of the operation has reached this device, so what it
    /// removed elsewhere in the folder could not be restored here.
    public var partial: Bool
    public init(restoredPaths: [String], failed: [FolderRestoreFailure], partial: Bool) {
        self.restoredPaths = restoredPaths; self.failed = failed; self.partial = partial
    }
}

public struct FolderRestoreFailure: Sendable, Equatable, Hashable {
    public var path: String
    public var error: String
    public init(path: String, error: String) {
        self.path = path; self.error = error
    }
}

public struct FileVersion: Sendable, Equatable, Hashable {
    public var versionSeq: Int64
    public var size: UInt64
    public var modifiedAt: Date?
    public var state: String
    public var originDeviceId: String?
    public var unixMode: UInt32?
    public var isCurrent: Bool
    public var kind: EntryKind
    public init(versionSeq: Int64, size: UInt64, modifiedAt: Date?, state: String, originDeviceId: String?, unixMode: UInt32?, isCurrent: Bool, kind: EntryKind) {
        self.versionSeq = versionSeq; self.size = size; self.modifiedAt = modifiedAt; self.state = state
        self.originDeviceId = originDeviceId; self.unixMode = unixMode; self.isCurrent = isCurrent
        self.kind = kind
    }
}

public enum MaterializationState: Sendable, Equatable, Hashable, CaseIterable { case hydrated, placeholder, hydrating, evicting, unknown }

public struct FileAvailability: Sendable, Equatable, Hashable {
    public var tracked: Bool
    public var state: MaterializationState
    public var pinned: Bool
    public init(tracked: Bool, state: MaterializationState, pinned: Bool) {
        self.tracked = tracked; self.state = state; self.pinned = pinned
    }
}

public struct EvictOutcome: Sendable, Equatable, Hashable {
    public var evicted: Bool
    public var blocksReclaimed: UInt64
    public var bytesReclaimed: UInt64
    public init(evicted: Bool, blocksReclaimed: UInt64, bytesReclaimed: UInt64) {
        self.evicted = evicted; self.blocksReclaimed = blocksReclaimed; self.bytesReclaimed = bytesReclaimed
    }
}

public struct HandoffSummary: Sendable, Equatable, Hashable {
    public var targetDeviceId: String
    public var membershipGeneration: Int64
    public var leaseId: String?
    public init(targetDeviceId: String, membershipGeneration: Int64, leaseId: String?) {
        self.targetDeviceId = targetDeviceId; self.membershipGeneration = membershipGeneration; self.leaseId = leaseId
    }
}

public struct UnlinkOutcome: Sendable, Equatable, Hashable {
    public var handoff: HandoffSummary?
    public init(handoff: HandoffSummary?) { self.handoff = handoff }
}

public struct StorageModeOutcome: Sendable, Equatable, Hashable {
    public var changed: Bool
    public var handoff: HandoffSummary?
    public init(changed: Bool, handoff: HandoffSummary?) { self.changed = changed; self.handoff = handoff }
}

// MARK: - Devices and membership

public struct DeviceSummary: Sendable, Equatable, Hashable {
    public var deviceId: String
    public var displayName: String
    public var online: Bool
    public var lastSeen: Date?
    public var isThisDevice: Bool
    public init(deviceId: String, displayName: String, online: Bool, lastSeen: Date?, isThisDevice: Bool) {
        self.deviceId = deviceId; self.displayName = displayName; self.online = online
        self.lastSeen = lastSeen; self.isThisDevice = isThisDevice
    }
}

public struct MembershipHandoff: Sendable, Equatable, Hashable {
    public var groupId: String
    public var targetDeviceId: String
    public var leaseId: String
    public var membershipGeneration: UInt64
    public init(groupId: String, targetDeviceId: String, leaseId: String, membershipGeneration: UInt64) {
        self.groupId = groupId; self.targetDeviceId = targetDeviceId
        self.leaseId = leaseId; self.membershipGeneration = membershipGeneration
    }
}

public struct MembershipOutcome: Sendable, Equatable, Hashable {
    public var handoffs: [MembershipHandoff]
    /// Non-empty means the removal was forced; the UI must show the data-loss warning.
    public var forcedGroupIds: [String]
    /// Set means the scope is unknown; the UI must show the unknown-scope warning.
    public var unknownScopeOperationId: String?
    public init(handoffs: [MembershipHandoff], forcedGroupIds: [String], unknownScopeOperationId: String?) {
        self.handoffs = handoffs; self.forcedGroupIds = forcedGroupIds
        self.unknownScopeOperationId = unknownScopeOperationId
    }
}

// MARK: - Shares

public struct GroupSummary: Sendable, Equatable, Hashable {
    public var groupId: String
    public var name: String
    public init(groupId: String, name: String) { self.groupId = groupId; self.name = name }
}

public enum ShareRole: Sendable, Equatable, Hashable {
    case owner, editor, viewer
    case other(raw: String)
}

public enum AssignableRole: Sendable, Equatable, Hashable, CaseIterable { case viewer, editor }
public enum MemberRelationship: Sendable, Equatable, Hashable { case you, yourOtherDevice, ownersDevice, invited }
public enum MemberStorage: Sendable, Equatable, Hashable { case fullCopy, onDemand }

public struct MemberSummary: Sendable, Equatable, Hashable {
    public var deviceId: String
    public var deviceName: String
    public var role: ShareRole
    public var relationship: MemberRelationship
    public var storage: MemberStorage
    public var online: Bool
    public var lastSeen: Date?
    public init(deviceId: String, deviceName: String, role: ShareRole, relationship: MemberRelationship, storage: MemberStorage, online: Bool, lastSeen: Date?) {
        self.deviceId = deviceId; self.deviceName = deviceName; self.role = role
        self.relationship = relationship; self.storage = storage; self.online = online; self.lastSeen = lastSeen
    }
}

public struct PendingApprovalSummary: Sendable, Equatable, Hashable {
    public var groupId: String
    public var groupName: String
    public var deviceId: String
    public var requestedRole: ShareRole?
    public init(groupId: String, groupName: String, deviceId: String, requestedRole: ShareRole?) {
        self.groupId = groupId; self.groupName = groupName; self.deviceId = deviceId; self.requestedRole = requestedRole
    }
}

public enum ShareEdgeState: Sendable, Equatable, Hashable {
    case active, pendingApproval
    case other(raw: String)
}

public struct ShareSummary: Sendable, Equatable, Hashable {
    public var edgeId: String
    public var groupId: String
    public var groupName: String
    public var deviceId: String
    public var state: ShareEdgeState
    public var role: ShareRole?
    public init(edgeId: String, groupId: String, groupName: String, deviceId: String, state: ShareEdgeState, role: ShareRole?) {
        self.edgeId = edgeId; self.groupId = groupId; self.groupName = groupName
        self.deviceId = deviceId; self.state = state; self.role = role
    }
}

public enum ApproveOutcome: Sendable, Equatable, Hashable {
    case approved, alreadyActive
    case unrecognized(raw: String)
}

public enum RevokeEdgeOutcome: Sendable, Equatable, Hashable {
    case revoked(outcome: MembershipOutcome)
    case alreadyRevoked
}

public struct InviteSummary: Sendable, Equatable, Hashable {
    public var inviteId: String
    public var code: String
    /// Built by the core; the app never assembles invite URLs itself.
    public var url: String
    public var groupId: String
    public var role: ShareRole
    public var expiresAt: Date
    public var requiresApproval: Bool
    public init(inviteId: String, code: String, url: String, groupId: String, role: ShareRole, expiresAt: Date, requiresApproval: Bool) {
        self.inviteId = inviteId; self.code = code; self.url = url; self.groupId = groupId
        self.role = role; self.expiresAt = expiresAt; self.requiresApproval = requiresApproval
    }
}

public enum InviteStatus: Sendable, Equatable, Hashable {
    case pending
    case other(raw: String)
}

public struct PendingInviteSummary: Sendable, Equatable, Hashable {
    public var inviteId: String
    public var groupId: String
    public var groupName: String
    public var role: ShareRole
    public var expiresAt: Date
    public var status: InviteStatus
    public init(inviteId: String, groupId: String, groupName: String, role: ShareRole, expiresAt: Date, status: InviteStatus) {
        self.inviteId = inviteId; self.groupId = groupId; self.groupName = groupName
        self.role = role; self.expiresAt = expiresAt; self.status = status
    }
}

public struct AcceptInviteOutcome: Sendable, Equatable, Hashable {
    public var groupId: String
    public var localPath: String
    public var awaitingApproval: Bool
    public init(groupId: String, localPath: String, awaitingApproval: Bool) {
        self.groupId = groupId; self.localPath = localPath; self.awaitingApproval = awaitingApproval
    }
}

// MARK: - Linking

public struct FreeSpace: Sendable, Equatable, Hashable {
    public var availableBytes: UInt64
    public var totalBytes: UInt64
    public var headroomBytes: UInt64
    public var state: FreeSpaceState
    public init(availableBytes: UInt64, totalBytes: UInt64, headroomBytes: UInt64, state: FreeSpaceState) {
        self.availableBytes = availableBytes; self.totalBytes = totalBytes
        self.headroomBytes = headroomBytes; self.state = state
    }
}

public enum NestedLinkRelation: Sendable, Equatable, Hashable { case ancestor, descendant, same }

public enum PreflightIssue: Sendable, Equatable, Hashable {
    case pathMissing
    case ignoreRulesUnreadable
    case notEmpty(entryCount: UInt64, scanTruncated: Bool)
    case lowFreeSpace(availableBytes: UInt64, headroomBytes: UInt64)
    case criticalFreeSpace(availableBytes: UInt64, headroomBytes: UInt64)
    case nestedLink(otherPath: String, relation: NestedLinkRelation)
    case cloudProviderFolder(provider: String)
    case filesystemRoot
    case homeDirectory
    case reservedName(path: String)
}

public struct PreflightResult: Sendable, Equatable, Hashable {
    public var resolvedPath: String
    public var pathExists: Bool
    public var isDirectory: Bool
    public var entryCount: UInt64
    public var ignoredEntryCount: UInt64
    public var totalSizeBytes: UInt64
    public var scanTruncated: Bool
    public var freeSpace: FreeSpace?
    public var issues: [PreflightIssue]
    public var requiresAcknowledgement: Bool
    public init(resolvedPath: String, pathExists: Bool, isDirectory: Bool, entryCount: UInt64, ignoredEntryCount: UInt64, totalSizeBytes: UInt64, scanTruncated: Bool, freeSpace: FreeSpace?, issues: [PreflightIssue], requiresAcknowledgement: Bool) {
        self.resolvedPath = resolvedPath; self.pathExists = pathExists; self.isDirectory = isDirectory
        self.entryCount = entryCount; self.ignoredEntryCount = ignoredEntryCount
        self.totalSizeBytes = totalSizeBytes; self.scanTruncated = scanTruncated
        self.freeSpace = freeSpace; self.issues = issues; self.requiresAcknowledgement = requiresAcknowledgement
    }
}

public struct LinkOutcome: Sendable, Equatable, Hashable {
    public var groupId: String
    public var localPath: String
    public var mode: FolderMode
    public init(groupId: String, localPath: String, mode: FolderMode) {
        self.groupId = groupId; self.localPath = localPath; self.mode = mode
    }
}

// MARK: - Send and receive, storage, settings, updates

public struct SentTransfer: Sendable, Equatable, Hashable {
    public var transferId: String
    public var filesOffered: [String]
    public var totalSize: UInt64
    public init(transferId: String, filesOffered: [String], totalSize: UInt64) {
        self.transferId = transferId; self.filesOffered = filesOffered; self.totalSize = totalSize
    }
}

public struct IncomingFile: Sendable, Equatable, Hashable {
    public var relativePath: String
    public var size: UInt64
    public init(relativePath: String, size: UInt64) { self.relativePath = relativePath; self.size = size }
}

public enum IncomingTransferStatus: Sendable, Equatable, Hashable {
    case pending, inProgress, completed
    case other(raw: String)
}

public struct IncomingTransfer: Sendable, Equatable, Hashable {
    public var transferId: String
    public var senderDeviceId: String
    public var files: [IncomingFile]
    public var totalSize: UInt64
    public var offeredAt: Date?
    public var status: IncomingTransferStatus
    public init(transferId: String, senderDeviceId: String, files: [IncomingFile], totalSize: UInt64, offeredAt: Date?, status: IncomingTransferStatus) {
        self.transferId = transferId; self.senderDeviceId = senderDeviceId; self.files = files
        self.totalSize = totalSize; self.offeredAt = offeredAt; self.status = status
    }
}

public struct ReceivedTransfer: Sendable, Equatable, Hashable {
    public var destinationDir: String
    public var filesReceived: [String]
    public var bytesReceived: UInt64
    public init(destinationDir: String, filesReceived: [String], bytesReceived: UInt64) {
        self.destinationDir = destinationDir; self.filesReceived = filesReceived; self.bytesReceived = bytesReceived
    }
}

public struct GcReport: Sendable, Equatable, Hashable {
    public var dryRun: Bool
    public var blocksDeleted: UInt64
    public var bytesReclaimed: UInt64
    public init(dryRun: Bool, blocksDeleted: UInt64, bytesReclaimed: UInt64) {
        self.dryRun = dryRun; self.blocksDeleted = blocksDeleted; self.bytesReclaimed = bytesReclaimed
    }
}

public enum DiagnosticsCollectionMode: Sendable, Equatable, Hashable { case daemon, daemonPartial, offlineFallback }

public struct DiagnosticsExport: Sendable, Equatable, Hashable {
    public var path: String
    public var collectionMode: DiagnosticsCollectionMode
    public var redactionCount: UInt32
    public init(path: String, collectionMode: DiagnosticsCollectionMode, redactionCount: UInt32) {
        self.path = path; self.collectionMode = collectionMode; self.redactionCount = redactionCount
    }
}

public enum DaemonStartOutcome: Sendable, Equatable, Hashable { case alreadyRunning, started }

public enum UpdateInstallMode: Sendable, Equatable, Hashable {
    case automatic, manual
    case other(raw: String)
}

public struct UpdateConfig: Sendable, Equatable, Hashable {
    public var automaticChecks: Bool
    public var installMode: UpdateInstallMode
    public init(automaticChecks: Bool, installMode: UpdateInstallMode) {
        self.automaticChecks = automaticChecks; self.installMode = installMode
    }
}

public struct UpdateStatus: Sendable, Equatable, Hashable {
    public var currentVersion: String
    public var channel: String
    public var installSource: String
    public var lastCheckedAt: Date?
    public var state: UpdateState
    public var availableVersion: String?
    public var releaseNotesUrl: String?
    public var mandatory: Bool
    public var holdbackReason: String?
    public var waitingForSafePoint: Bool
    public var lastErrorCategory: String?
    public var lastErrorMessage: String?
    public var config: UpdateConfig
    public init(currentVersion: String, channel: String, installSource: String, lastCheckedAt: Date?, state: UpdateState, availableVersion: String?, releaseNotesUrl: String?, mandatory: Bool, holdbackReason: String?, waitingForSafePoint: Bool, lastErrorCategory: String?, lastErrorMessage: String?, config: UpdateConfig) {
        self.currentVersion = currentVersion; self.channel = channel; self.installSource = installSource
        self.lastCheckedAt = lastCheckedAt; self.state = state; self.availableVersion = availableVersion
        self.releaseNotesUrl = releaseNotesUrl; self.mandatory = mandatory; self.holdbackReason = holdbackReason
        self.waitingForSafePoint = waitingForSafePoint; self.lastErrorCategory = lastErrorCategory
        self.lastErrorMessage = lastErrorMessage; self.config = config
    }
}

public enum UpdateInstallOutcome: Sendable, Equatable, Hashable {
    case installing, deferred
    case storeManaged(guidance: String)
    case other(raw: String)
}
