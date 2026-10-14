import Foundation
import Observation
import YadoriLinkModel

/// "Stop Syncing This Folder…". The first attempt always asks the core
/// without `force`; only a force-capable durability refusal, confirmed a
/// second time in its own words, retries with `force`.
@MainActor
@Observable
public final class UnlinkModel {
    public let app: AppModel
    /// The first confirmation: what stops and what stays.
    public var pendingConfirmation: FolderSummary?
    /// The second confirmation, only after the core refused on durability grounds.
    public var pendingOverride: FolderSummary?
    public private(set) var isWorking = false
    /// Called with the folder's `localPath` after it was unlinked, so the
    /// caller can leave screens that point at it.
    @ObservationIgnored public var onUnlinked: ((String) -> Void)?

    public init(app: AppModel) { self.app = app }

    public func request(_ folder: FolderSummary) {
        guard !isWorking else { return }
        pendingConfirmation = folder
    }

    public func cancel() {
        pendingConfirmation = nil
        pendingOverride = nil
    }

    public func confirm() async {
        guard let folder = pendingConfirmation else { return }
        pendingConfirmation = nil
        await unlink(folder, force: false)
    }

    public func confirmOverride() async {
        guard let folder = pendingOverride else { return }
        pendingOverride = nil
        await unlink(folder, force: true)
    }

    private func unlink(_ folder: FolderSummary, force: Bool) async {
        isWorking = true
        defer { isWorking = false }
        do {
            _ = try await app.client.unlinkFolder(localPath: folder.localPath, force: force)
            app.notice = Notice(kind: .success, text: UnlinkWording.success(folder))
            app.refresh()
            onUnlinked?(folder.localPath)
        } catch DesktopError.durabilityBlocked(_, _, _, true) where !force {
            pendingOverride = folder
        } catch {
            var notice = Notice.failure(error)
            // The daemon's diagnostic names the link key, which for a provider folder is not a path.
            if folder.provider { notice.detail = nil }
            app.notice = notice
        }
    }
}
