import Foundation
import Observation
import YadoriLinkModel

public struct CopyRow: Identifiable, Equatable, Sendable {
    public var id: String { tooltip }
    public var name: String
    /// "Available · Direct"
    public var status: String
    public var tone: StatusTone
    public var tooltip: String
}

public struct RetainedRow: Identifiable, Equatable, Sendable {
    public var id: String { path }
    public var path: String
    /// "12 KB", or why the size is unknown.
    public var size: String
}

public struct ConflictRow: Identifiable, Equatable, Sendable {
    public var id: String { path }
    public var path: String
    public var title: String
    /// "48 KB · 1 hour ago · from Studio"
    public var subtitle: String
    public var keptAs: String
    public var reason: ConflictReason
    /// "Sep 21, 2026 at 10:12 AM", when the copy was saved.
    public var savedAt: String?
    public var canResolve: Bool
    var conflict: ConflictSummary

    /// How the copy relates to the name it came from.
    public var relation: String {
        switch reason {
        case .concurrentEdit: "the other version is \(keptAs)"
        case .folderAtPath: "moved aside for the folder \(keptAs)"
        }
    }
}

public struct VersionRow: Identifiable, Equatable, Sendable {
    public var id: Int64 { versionSeq }
    public var versionSeq: Int64
    /// "v3 · 2 hours ago · 1.2 MB · from Studio (current)"
    public var text: String
    public var tooltip: String
    public var isCurrent: Bool
}

public struct TrashRow: Identifiable, Equatable, Sendable {
    public var id: String { absolutePath }
    public var absolutePath: String
    public var title: String
    public var subtitle: String
    /// The recursive delete or directory rename that removed the entry;
    /// `nil` for an entry deleted on its own.
    public var operation: String?
}

/// Trashed entries as "Recently deleted" shows them: what one recursive
/// delete or directory rename removed forms one group that can be restored
/// as a folder; an entry deleted on its own is a group of one.
public struct TrashGroup: Identifiable, Equatable, Sendable {
    public var id: String { operation ?? rows.first?.id ?? "" }
    public var operation: String?
    public var rows: [TrashRow]

    /// The group's outermost entry (fewest path components, then path
    /// order): the deleted folder, or a renamed folder's old name.
    public var root: TrashRow? {
        rows.min { a, b in
            let (da, db) = (a.title.split(separator: "/").count, b.title.split(separator: "/").count)
            return da != db ? da < db : a.title < b.title
        }
    }

    /// "Removed together with Old drafts (2 items)"; `nil` for an entry
    /// deleted on its own. The trash does not say whether the operation was
    /// a delete or a rename, so the title names only what both do: remove
    /// these entries from where they were.
    public var title: String? {
        guard operation != nil, let root else { return nil }
        return "Removed together with \(root.title) (\(rows.count) item\(rows.count == 1 ? "" : "s"))"
    }
}

@MainActor
@Observable
public final class FolderDetailViewModel {
    public let client: any YadoriLinkClient
    public private(set) var folder: FolderSummary
    public private(set) var detail: FolderDetail?
    public private(set) var conflicts: [ConflictRow] = []
    public private(set) var retained: [RetainedRow] = []
    public private(set) var trash: [TrashRow] = []
    public private(set) var selectedFile: String?
    public private(set) var availability: FileAvailability?
    /// What the daemon says about keeping the chosen file on this device; `nil` when not read.
    public private(set) var retention: FileRetention?
    public private(set) var versions: [VersionRow] = []
    public private(set) var isLoading = false
    /// The last read of the folder's details failed; nothing below it is known to be current.
    public private(set) var loadFailure: Notice?
    /// The chosen file's status or history could not be read; none of it is known.
    public private(set) var historyFailure: Notice?
    public private(set) var isWorking = false
    /// One result line for the whole window, whichever section acted.
    public var notice: Notice?

    @ObservationIgnored private var deviceNames: [String: String]?
    @ObservationIgnored private let now: () -> Date

    public init(client: any YadoriLinkClient, folder: FolderSummary, now: @escaping () -> Date = Date.init) {
        self.client = client
        self.folder = folder
        self.now = now
    }

    public func load() async {
        isLoading = true
        defer { isLoading = false }
        let namesFailure = await loadDeviceNames()
        do {
            let detail = try await client.folderDetail(localPath: folder.localPath)
            self.detail = detail
            folder = detail.summary
            conflicts = try await client.listConflicts(localPath: folder.localPath).map(conflictRow)
            trash = try await client.listTrash(localPath: folder.localPath).map(trashRow)
            retained = try await loadRetained()
            loadFailure = namesFailure
        } catch {
            loadFailure = .failure(error)
        }
    }

    /// Device names label copies and versions; without them they read "another
    /// device". Returns the failure so the details can offer Retry.
    private func loadDeviceNames() async -> Notice? {
        guard deviceNames == nil else { return nil }
        do {
            let devices = try await client.listFolderDevices()
            deviceNames = Dictionary(devices.map { ($0.deviceId, $0.displayName) }, uniquingKeysWith: { a, _ in a })
            return nil
        } catch {
            return .failure(error)
        }
    }

    func name(for deviceId: String?) -> String {
        guard let deviceId else { return "an unknown device" }
        return deviceNames?[deviceId] ?? "another device"
    }

    // MARK: Summary

    public var protectionTitle: String { folder.durability.title }
    public var protectionTone: StatusTone { folder.durability.tone }
    public var protectionDetail: String? { folder.durability.detail }
    /// "On-Demand · 312 on this device · 892 online only"
    public var thisDevice: String { Format.localCopyLine(folder) }
    public var freeSpace: String? { folder.volume.map(Format.freeSpace) }

    /// "None yet" is only said once the details were read.
    public var showsNoCopies: Bool { detail != nil && loadFailure == nil && copies.isEmpty }

    public var copies: [CopyRow] {
        (detail?.completeCopies ?? []).map { copy in
            let status = [copy.reachability.title, copy.route.title].compactMap { $0 }.joined(separator: " · ")
            let tone: StatusTone = copy.reachability == .connected ? .ok : copy.reachability == .unreachable ? .neutral : .info
            return CopyRow(name: name(for: copy.deviceId), status: status, tone: tone, tooltip: copy.deviceId)
        }
    }

    // MARK: Kept originals

    /// Why they are kept and when they can go; shown once above the list.
    public static let retainedExplanation = "These files were kept as they were because it could not be proved safe to remove them. Each can be released once nothing is writing to it. A file that changed meanwhile is saved first."

    private func loadRetained() async throws -> [RetainedRow] {
        try await client.listRetainedOriginals().filter { $0.groupId == folder.groupId }.map {
            RetainedRow(path: $0.path, size: $0.reachable ? Format.bytes($0.size) : "Size unknown while this folder is not watched")
        }
    }

    /// Releases what can safely be released; whatever cannot stays listed.
    public func releaseRetained() async {
        let groupId = folder.groupId
        let done = await act { client in
            Self.releaseSummary(try await client.releaseRetainedOriginals(groupId: groupId))
        }
        if done { retained = (try? await loadRetained()) ?? retained }
    }

    static func releaseSummary(_ releases: [RetainedRelease]) -> String {
        let released = releases.filter { [.removed, .savedThenRemoved, .gone].contains($0.outcome) }.count
        let kept = releases.count - released
        var parts: [String] = []
        if released > 0 { parts.append("Released \(released) file\(released == 1 ? "" : "s").") }
        if kept > 0 { parts.append("\(kept) kept: still in use, changed, or not safe to release yet. Try again later.") }
        if releases.contains(where: { $0.outcome == .savedThenRemoved || $0.outcome == .savedStillRetained }) {
            parts.append("Changed content was saved first.")
        }
        return parts.isEmpty ? "Nothing to release." : parts.joined(separator: " ")
    }

    // MARK: Conflicts and trash

    /// Shown once above the list instead of under every file.
    public var conflictExplanation: String? {
        let reasons = Set(conflicts.map(\.reason))
        guard !reasons.isEmpty else { return nil }
        var sentences: [String] = []
        if reasons.contains(.concurrentEdit) {
            sentences.append("Edited on two devices; both versions were kept. The original name holds one, and the copy holds the other.")
        }
        if reasons.contains(.folderAtPath) {
            sentences.append("One device made a folder where another had a file with the same name. The folder keeps the name, and the file was kept beside it as a copy.")
        }
        return sentences.joined(separator: " ")
    }

    /// Where a conflict copy lives on this Mac, for "Show in Finder".
    public func conflictFilePath(_ row: ConflictRow) -> String {
        (folder.localPath as NSString).appendingPathComponent(row.path)
    }

    private func conflictRow(_ c: ConflictSummary) -> ConflictRow {
        var parts = [sizeOrFolder(c.size, c.kind)]
        if let modified = c.modifiedAt { parts.append(Format.relative(modified, now: now())) }
        if c.loserDeviceId != nil { parts.append("from \(name(for: c.loserDeviceId))") }
        return ConflictRow(
            path: c.path, title: (c.path as NSString).lastPathComponent, subtitle: parts.joined(separator: " · "),
            keptAs: c.currentPath, reason: c.reason, savedAt: c.modifiedAt.map(Format.dateTime),
            canResolve: !folder.provider && Self.isResolvable(c), conflict: c
        )
    }

    /// Only a file copy of an edit made on two devices can be resolved: a copy
    /// moved aside for a folder has no single other file.
    static func isResolvable(_ c: ConflictSummary) -> Bool {
        c.kind == .file && c.reason == .concurrentEdit && c.currentPath != c.path
    }

    /// Keeps this copy as the file (`keepThis`) or both as separate files
    /// (`keepBoth`), then re-reads the list.
    public func resolve(_ row: ConflictRow, _ choice: ConflictChoice) async {
        let done = await act { client in
            _ = try await client.resolveConflict(copyPath: (row.conflict.localPath as NSString).appendingPathComponent(row.conflict.path), choice: choice)
            switch choice {
            case .keepThis: return "Kept this version of \(row.keptAs)."
            case .keepBoth: return "Kept both versions of \(row.keptAs)."
            }
        }
        if done { conflicts.removeAll { $0.id == row.id } }
    }

    /// A directory has no size of its own, so it reads "Folder" instead of
    /// "0 bytes".
    private func sizeOrFolder(_ size: UInt64, _ kind: EntryKind) -> String {
        kind == .directory ? "Folder" : Format.bytes(size)
    }

    private func trashRow(_ t: TrashedFile) -> TrashRow {
        var parts = [sizeOrFolder(t.lastKnownSize, t.kind)]
        if let deleted = t.deletedAt { parts.append("deleted \(Format.relative(deleted, now: now()))") }
        let absolute = (t.localPath as NSString).appendingPathComponent(t.path)
        return TrashRow(absolutePath: absolute, title: t.path, subtitle: parts.joined(separator: " · "), operation: t.deletedByOperation)
    }

    /// `trash`, grouped by the operation that removed each entry, in the
    /// order each group's first entry is listed.
    public var trashGroups: [TrashGroup] {
        var groups: [TrashGroup] = []
        for row in trash {
            if let operation = row.operation, let i = groups.firstIndex(where: { $0.operation == operation }) {
                groups[i].rows.append(row)
            } else {
                groups.append(TrashGroup(operation: row.operation, rows: [row]))
            }
        }
        return groups
    }

    /// Restores everything the group's operation removed, then re-reads the
    /// trash: a restore that failed for some entries still restored the
    /// rest, and a part of the operation that has not reached this device
    /// leaves its entries where they are.
    public func restoreFolder(_ group: TrashGroup) async {
        guard group.operation != nil, let root = group.root else { return }
        isWorking = true
        do {
            let outcome = try await client.restoreTrashOperation(absolutePath: root.absolutePath)
            notice = Self.folderRestoreNotice(outcome)
        } catch {
            notice = .failure(error)
        }
        isWorking = false
        do {
            trash = try await client.listTrash(localPath: folder.localPath).map(trashRow)
        } catch {
            // The rows shown may include entries that were just restored.
            loadFailure = .failure(error)
        }
    }

    static func folderRestoreNotice(_ outcome: FolderRestoreOutcome) -> Notice {
        let count = outcome.restoredPaths.count
        var text = "Restored \(count) item\(count == 1 ? "" : "s") of the folder."
        if outcome.partial {
            text += " Part of that delete hasn't reached this Mac yet, so what it removed elsewhere in the folder isn't back."
        }
        guard !outcome.failed.isEmpty else { return Notice(kind: .success, text: text) }
        let failed = outcome.failed.map { "\($0.path): \($0.error)" }.joined(separator: "\n")
        let couldNot = outcome.failed.count == 1 ? "1 item couldn't be restored." : "\(outcome.failed.count) items couldn't be restored."
        return Notice(kind: .failure, text: "\(text) \(couldNot)", detail: failed)
    }

    public func restoreFromTrash(_ row: TrashRow) async {
        let restored = await act { client in
            try await client.restoreFromTrash(absolutePath: row.absolutePath)
            return "Restored \(row.title)."
        }
        if restored { trash.removeAll { $0.id == row.id } }
    }

    // MARK: File history and download options

    public var fileActions: [FileAction] {
        availability.map { FileAction.available(for: $0, providerFolder: folder.provider, retention: retention) } ?? []
    }

    /// Said only for a kept file, so the absence of a line means "not kept".
    public var retentionLine: String? {
        guard let retention, retention.policy == .pinned else { return nil }
        return retention.inherited ? "Always kept on this device (by a folder above)" : "Always kept on this device"
    }

    public var fileStateTitle: String? {
        guard let availability else { return nil }
        guard availability.tracked else { return "Not synced" }
        return availability.state.title
    }

    /// Every result is dropped if another file was chosen while it loaded,
    /// so a slow answer for one file never shows next to another.
    public func selectFile(_ absolutePath: String) async {
        selectedFile = absolutePath
        availability = nil
        retention = nil
        versions = []
        historyFailure = nil
        let namesFailure = await loadDeviceNames()
        do {
            let availability = try await client.fileAvailability(absolutePath: absolutePath)
            guard selectedFile == absolutePath else { return }
            self.availability = availability
            let retention = try await client.fileRetention(absolutePath: absolutePath)
            guard selectedFile == absolutePath else { return }
            self.retention = retention
            let versions = try await client.listVersions(absolutePath: absolutePath).map(versionRow)
            guard selectedFile == absolutePath else { return }
            self.versions = versions
            historyFailure = namesFailure
        } catch {
            guard selectedFile == absolutePath else { return }
            historyFailure = .failure(error)
        }
    }

    /// Re-reads only the chosen file's availability and history.
    public func retryFileHistory() async {
        guard let path = selectedFile else { return }
        await selectFile(path)
    }

    private func versionRow(_ v: FileVersion) -> VersionRow {
        var parts = ["v\(v.versionSeq)"]
        if let modified = v.modifiedAt { parts.append(Format.relative(modified, now: now())) }
        parts.append(sizeOrFolder(v.size, v.kind))
        parts.append("from \(name(for: v.originDeviceId))")
        var text = parts.joined(separator: " · ")
        if v.isCurrent { text += " (current)" }
        var tooltip = "State: \(v.state)"
        if let mode = v.unixMode { tooltip += " · Permissions: \(String(mode, radix: 8))" }
        return VersionRow(versionSeq: v.versionSeq, text: text, tooltip: tooltip, isCurrent: v.isCurrent)
    }

    public func perform(_ action: FileAction) async {
        guard let path = selectedFile else { return }
        let name = (path as NSString).lastPathComponent
        await act { client in
            switch action {
            case .download:
                try await client.hydrateFile(absolutePath: path)
                return "Downloaded \(name)."
            case .freeUpSpace:
                let outcome = try await client.evictFile(absolutePath: path)
                return outcome.evicted ? "Freed up \(Format.bytes(outcome.bytesReclaimed)) from \(name)." : "\(name) is already online only."
            case .keepOnDevice:
                let outcome = try await client.pinFile(absolutePath: path)
                if let why = outcome.downloadError { return "\(name) will stay on this device, but couldn't be downloaded yet: \(why)" }
                return "\(name) will always stay on this device."
            case .stopKeeping:
                let retention = try await client.unpinFile(absolutePath: path)
                if retention.policy == .pinned { return "\(name) is still kept on this device because a folder above it is." }
                return "\(name) is no longer kept on this device. It stays here until you free up space."
            }
        }
        let availability = try? await client.fileAvailability(absolutePath: path)
        let retention = try? await client.fileRetention(absolutePath: path)
        if selectedFile == path { self.availability = availability; self.retention = retention }
    }

    public func restore(_ version: VersionRow) async {
        guard let path = selectedFile else { return }
        await act { client in
            try await client.restoreVersion(absolutePath: path, versionSeq: version.versionSeq)
            return "Restored v\(version.versionSeq) of \((path as NSString).lastPathComponent)."
        }
        if selectedFile == path { await selectFile(path) }
    }

    /// Runs one action and reports its result as the window's notice.
    /// Returns whether it succeeded.
    @discardableResult
    private func act(_ body: (any YadoriLinkClient) async throws -> String) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            notice = Notice(kind: .success, text: try await body(client))
            return true
        } catch {
            notice = .failure(error)
            return false
        }
    }
}
