// Fixture data for tests and Previews. Everything here is invented sample
// data; nothing is read from disk or the network.

import Foundation
import YadoriLinkModel

/// Named starting states for the fake client.
public enum FakeScenario: String, CaseIterable, Sendable {
    /// Signed in, three folders up to date, every peer connected.
    case healthy
    /// Signed in, one folder receiving files.
    case syncing
    /// Signed in, one folder with conflicts, a disconnected peer and low disk.
    case problem
    /// The background service is not answering.
    case daemonDown
    /// Nobody is signed in on this Mac.
    case signedOut
    /// Signed in, no folders yet.
    case empty
    /// The keychain entry cannot be used.
    case credentialStoreUnusable
    /// Twenty folders, for long-list layout checks.
    case twentyFolders
    /// Long Japanese folder and device names, for layout checks.
    case japaneseLongNames
    /// An update is ready to install.
    case updateAvailable
    /// Removing a device or member is refused until the data has another copy.
    case durabilityBlockedRevoke
}

public enum Fixtures {
    public static let now = Date(timeIntervalSince1970: 1_790_000_000)

    public static let thisDeviceId = "d-7f3a9c21e4b84d0f9a6e2c5b1d8f0a37"
    public static let studioId = "d-2b8e6f14c9a7403db5e1f6a2c3d9e870"
    public static let officeId = "d-91c4e7a2b6d8435f8e0a1c9b7d2f6e45"
    public static let phoneId = "d-5e0d3b9a8c1f4a72b6e4d2c8f1a9b063"

    public static let devices: [DeviceSummary] = [
        DeviceSummary(deviceId: thisDeviceId, displayName: "MacBook Air", online: true, lastSeen: now, isThisDevice: true),
        DeviceSummary(deviceId: studioId, displayName: "Studio", online: true, lastSeen: now.addingTimeInterval(-60), isThisDevice: false),
        DeviceSummary(deviceId: officeId, displayName: "Office iMac", online: false, lastSeen: now.addingTimeInterval(-3 * 3600), isThisDevice: false),
    ]

    public static func account(_ signIn: SignInState = .signedIn, hasLinkedFolders: Bool? = true) -> AccountStatus {
        AccountStatus(
            signIn: signIn,
            clientId: signIn == .signedIn ? "client-4c1d" : nil,
            thisDeviceId: signIn == .signedIn ? thisDeviceId : nil,
            deviceRegistered: signIn == .signedIn,
            defaultDeviceName: "MacBook Air",
            hasLinkedFolders: hasLinkedFolders
        )
    }

    public static func volume(_ path: String = "/", state: FreeSpaceState = .ok, available: UInt64 = 182 * gib) -> VolumeSummary {
        VolumeSummary(path: path, state: state, availableBytes: available, headroomBytes: 10 * gib)
    }

    public static let gib: UInt64 = 1 << 30
    public static let mib: UInt64 = 1 << 20

    public static func folder(
        _ name: String,
        path: String? = nil,
        groupId: String? = nil,
        mode: FolderMode = .keepAll,
        state: FolderState = .upToDate,
        paused: Bool = false,
        conflicts: UInt64 = 0,
        durability: DurabilityStatus = .protected,
        replicas: [String] = [studioId],
        transfer: FolderTransferProgress? = nil,
        volume: VolumeSummary? = Fixtures.volume()
    ) -> FolderSummary {
        let localPath = path ?? "/Users/me/\(name)"
        return FolderSummary(
            localPath: localPath,
            groupId: groupId ?? "g-" + String(name.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }.map(Character.init)),
            name: name,
            mode: mode,
            state: paused ? .paused : state,
            paused: paused,
            conflictCount: conflicts,
            hydratedFileCount: mode == .keepAll ? 1_204 : 312,
            placeholderFileCount: mode == .keepAll ? 0 : 892,
            hydratingFileCount: 0,
            heldFileCount: 0,
            skippedSymlinkCount: 0,
            transfer: transfer,
            durability: durability,
            durabilityEvidence: durability == .protected ? .verifiedPayload : .none,
            localStorage: mode == .keepAll ? .fullCopy : .partiallyMaterialized,
            fetchAvailability: .availableNow,
            fullReplicaDeviceIds: replicas,
            policyStale: false,
            ambiguous: false,
            ambiguousLocalPaths: [],
            degraded: false,
            degradedReason: nil,
            volume: volume
        )
    }

    public static let noLimits = BandwidthLimits(uploadBytesPerSec: nil, downloadBytesPerSec: nil)

    public static func updateBadge(available: String? = nil) -> UpdateBadge {
        UpdateBadge(
            state: available == nil ? .upToDate : .available,
            availableVersion: available,
            mandatory: false,
            waitingForSafePoint: false,
            lastErrorCategory: nil,
            channel: "stable",
            installSource: "pkg",
            holdbackReason: nil
        )
    }

    public static func snapshot(
        overall: OverallState = .healthy,
        reasons: [AttentionReason] = [],
        folders: [FolderSummary],
        transfers: [TransferSummary] = [],
        peers: [PeerSummary]? = nil,
        update: UpdateBadge = updateBadge(),
        volumes: [VolumeSummary] = [volume()]
    ) -> StatusSnapshot {
        StatusSnapshot(
            capturedAt: now,
            overall: overall,
            attentionReasons: reasons,
            thisDeviceId: thisDeviceId,
            folders: folders,
            peers: peers ?? [
                PeerSummary(deviceId: studioId, reachability: .connected, unreachableCategory: nil, route: .direct),
                PeerSummary(deviceId: officeId, reachability: .connected, unreachableCategory: nil, route: .relay),
            ],
            transfers: transfers,
            bandwidth: BandwidthStatus(limits: noLimits, currentUploadBytesPerSec: 0, currentDownloadBytesPerSec: 0),
            volumes: volumes,
            storage: StorageSummary(
                blockStoreTotalBytes: 38 * gib,
                blockCount: 612_004,
                lastGcAt: now.addingTimeInterval(-2 * 86_400),
                reclaimableEstimateBytes: UInt64(1.2 * Double(gib))
            ),
            update: update,
            recentErrors: []
        )
    }

    public static let healthyFolders: [FolderSummary] = [
        folder("Documents"),
        folder("Photos", mode: .onDemand, replicas: [studioId, officeId]),
        folder("Projects"),
    ]

    public static var syncingSnapshot: StatusSnapshot {
        let progress = FolderTransferProgress(bytesDone: 412 * mib, bytesTotal: 1_536 * mib, blocksDone: 103, blocksTotal: 384, eta: 95)
        var folders = healthyFolders
        folders[1].state = .syncing
        folders[1].transfer = progress
        folders[1].durability = .protecting
        return snapshot(
            folders: folders,
            transfers: [
                TransferSummary(groupId: folders[1].groupId, folderLocalPath: folders[1].localPath, path: "2026/Trip/IMG_4410.HEIC", bytesDone: 3 * mib, bytesTotal: 5 * mib, blocksDone: 3, blocksTotal: 5, sourceDeviceId: studioId, startedAt: now.addingTimeInterval(-4)),
                TransferSummary(groupId: folders[1].groupId, folderLocalPath: folders[1].localPath, path: "2026/Trip/IMG_4411.MOV", bytesDone: 120 * mib, bytesTotal: 640 * mib, blocksDone: 30, blocksTotal: 160, sourceDeviceId: studioId, startedAt: now.addingTimeInterval(-40)),
            ]
        )
    }

    public static var problemSnapshot: StatusSnapshot {
        let low = volume(state: .low, available: 7 * gib)
        var folders = healthyFolders.map { f -> FolderSummary in var f = f; f.volume = low; return f }
        folders[0].state = .attention
        folders[0].conflictCount = 2
        folders[0].durability = .atRisk
        folders[0].durabilityEvidence = .none
        folders[0].fullReplicaDeviceIds = []
        return snapshot(
            overall: .attention,
            reasons: [
                AttentionReason(category: .conflict, subject: folders[0].groupId, folderLocalPath: folders[0].localPath, raw: "conflict:\(folders[0].groupId)"),
                AttentionReason(category: .durabilityAtRisk, subject: folders[0].groupId, folderLocalPath: folders[0].localPath, raw: "durability_at_risk:\(folders[0].groupId)"),
                AttentionReason(category: .peerDisconnected, subject: officeId, folderLocalPath: nil, raw: "peer_disconnected:\(officeId)"),
                AttentionReason(category: .lowDisk, subject: "/", folderLocalPath: nil, raw: "low_disk:/"),
            ],
            folders: folders,
            peers: [
                PeerSummary(deviceId: studioId, reachability: .connected, unreachableCategory: nil, route: .direct),
                PeerSummary(deviceId: officeId, reachability: .unreachable, unreachableCategory: .noResponse, route: .unknown),
            ],
            volumes: [low]
        )
    }

    public static var twentyFolders: [FolderSummary] {
        (1...20).map { i in
            folder(String(format: "Folder %02d", i), mode: i % 3 == 0 ? .onDemand : .keepAll,
                   state: i == 7 ? .syncing : .upToDate)
        }
    }

    public static var japaneseFolders: [FolderSummary] {
        [
            folder("プロジェクト資料・2026年度第三四半期の共有フォルダー", path: "/Users/me/Documents/プロジェクト資料・2026年度第三四半期の共有フォルダー"),
            folder("写真とビデオ(家族の旅行アルバム)", mode: .onDemand),
            folder("請求書"),
        ]
    }

    public static let conflicts: [ConflictSummary] = [
        ConflictSummary(localPath: "/Users/me/Documents", path: "Budget (conflict from Studio).xlsx", size: 48_213, modifiedAt: now.addingTimeInterval(-3_600), currentPath: "Budget.xlsx", loserDeviceId: studioId, conflictTimestamp: "2026-09-21T10:12:00Z", kind: .file, reason: .concurrentEdit),
        ConflictSummary(localPath: "/Users/me/Documents", path: "Notes/Plan (conflict from Office iMac).md", size: 2_140, modifiedAt: now.addingTimeInterval(-7_200), currentPath: "Notes/Plan.md", loserDeviceId: officeId, conflictTimestamp: "2026-09-21T09:40:00Z", kind: .file, reason: .concurrentEdit),
        ConflictSummary(localPath: "/Users/me/Documents", path: "Receipts (conflict from Studio)", size: 12_004, modifiedAt: now.addingTimeInterval(-10_800), currentPath: "Receipts", loserDeviceId: studioId, conflictTimestamp: "2026-09-21T08:05:00Z", kind: .file, reason: .folderAtPath),
    ]

    public static let trash: [TrashedFile] = [
        TrashedFile(localPath: "/Users/me/Documents", path: "Old draft.pages", versionSeq: 4, lastKnownSize: 820_331, originDeviceId: thisDeviceId, deletedAt: now.addingTimeInterval(-86_400), kind: .file, deletedByOperation: nil),
        TrashedFile(localPath: "/Users/me/Documents", path: "Old drafts", versionSeq: 2, lastKnownSize: 0, originDeviceId: thisDeviceId, deletedAt: now.addingTimeInterval(-2 * 86_400), kind: .directory, deletedByOperation: "\(thisDeviceId):0a1b2c3d4e5f"),
        TrashedFile(localPath: "/Users/me/Documents", path: "Old drafts/Chapter 1.pages", versionSeq: 3, lastKnownSize: 402_118, originDeviceId: thisDeviceId, deletedAt: now.addingTimeInterval(-2 * 86_400), kind: .file, deletedByOperation: "\(thisDeviceId):0a1b2c3d4e5f"),
    ]

    public static let versions: [FileVersion] = [
        FileVersion(versionSeq: 3, size: 1_258_291, modifiedAt: now.addingTimeInterval(-7_200), state: "live", originDeviceId: studioId, unixMode: 0o644, isCurrent: true, kind: .file),
        FileVersion(versionSeq: 2, size: 1_101_004, modifiedAt: now.addingTimeInterval(-86_400), state: "retained", originDeviceId: thisDeviceId, unixMode: 0o644, isCurrent: false, kind: .file),
        FileVersion(versionSeq: 1, size: 998_120, modifiedAt: now.addingTimeInterval(-3 * 86_400), state: "retained", originDeviceId: thisDeviceId, unixMode: 0o644, isCurrent: false, kind: .file),
    ]

    public static let ownedGroups: [GroupSummary] = [
        GroupSummary(groupId: "g-docs", name: "Documents"),
        GroupSummary(groupId: "g-photos", name: "Photos"),
    ]

    public static let members: [MemberSummary] = [
        MemberSummary(deviceId: thisDeviceId, deviceName: "MacBook Air", role: .owner, relationship: .you, storage: .fullCopy, online: true, lastSeen: now),
        MemberSummary(deviceId: studioId, deviceName: "Studio", role: .editor, relationship: .yourOtherDevice, storage: .fullCopy, online: true, lastSeen: now),
        MemberSummary(deviceId: phoneId, deviceName: "Aki's iPhone", role: .viewer, relationship: .invited, storage: .onDemand, online: false, lastSeen: now.addingTimeInterval(-86_400)),
    ]

    public static let pendingApprovals: [PendingApprovalSummary] = [
        PendingApprovalSummary(groupId: "g-docs", groupName: "Documents", deviceId: "d-aa11bb22cc33dd44ee55ff6600778899", requestedRole: .viewer),
    ]

    public static let invites: [PendingInviteSummary] = [
        PendingInviteSummary(inviteId: "inv-1", groupId: "g-docs", groupName: "Documents", role: .viewer, expiresAt: now.addingTimeInterval(6 * 86_400), status: .pending),
    ]

    public static let inbox: [IncomingTransfer] = [
        IncomingTransfer(transferId: "t-81f2", senderDeviceId: studioId, files: [
            IncomingFile(relativePath: "slides.key", size: 18 * mib),
            IncomingFile(relativePath: "notes.txt", size: 2_048),
        ], totalSize: 18 * mib + 2_048, offeredAt: now.addingTimeInterval(-600), status: .pending),
    ]

    public static func updateStatus(available: String? = nil) -> UpdateStatus {
        UpdateStatus(
            currentVersion: "0.4.2",
            channel: "stable",
            installSource: "pkg",
            lastCheckedAt: now.addingTimeInterval(-3_600),
            state: available == nil ? .upToDate : .available,
            availableVersion: available,
            releaseNotesUrl: nil,
            mandatory: false,
            holdbackReason: nil,
            waitingForSafePoint: false,
            lastErrorCategory: nil,
            lastErrorMessage: nil,
            config: UpdateConfig(automaticChecks: true, installMode: .automatic)
        )
    }

    public static let daemonDownError = DesktopError.daemonUnavailable(message: "daemon is not running or not reachable", reason: .notRunning)
    public static let signedOutError = DesktopError.notSignedIn(message: "not logged in")

    /// The standard browser sign-in sequence.
    public static func loginEvents(account: AccountStatus = account()) -> [LoginEvent] {
        [
            .enrolling,
            .openBrowser(url: "https://auth.example.invalid/approve?d=1", purpose: .approveDevice),
            .waitingForApproval(expiresIn: 600),
            .openBrowser(url: "https://auth.example.invalid/authorize?s=2", purpose: .signIn),
            .waitingForAuthorization,
            .signedIn(account: account),
        ]
    }
}
