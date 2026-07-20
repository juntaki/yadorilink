//
//  FileProviderEnumerator.swift —.
//
//  `NSFileProviderEnumerator` for one container (the root, or a
//  synthesized subdirectory — see FileProviderModel.swift). Only the two
//  required members (`invalidate`, `enumerateItems(for:startingAt:)`)
//  are implemented; `enumerateChanges(for:from:)`/`currentSyncAnchor` are
//  `@optional` and deliberately NOT implemented (documented gap, task
//  7.8): this extension has no incremental change-tracking / push
//  mechanism yet, so the system falls back to re-enumerating from
//  scratch (e.g. on a manual Finder refresh or the next domain
//  signal) rather than receiving live delta pushes. Given the daemon
//  already has a live push mechanism for badges (`StatusPush` over the
//  same shell-IPC connection), a real follow-up would listen for
//  that and call `NSFileProviderManager.signalEnumerator(for:)` to
//  trigger a live re-enumeration — out of scope for this task.

import FileProvider

final class FileProviderEnumerator: NSObject, NSFileProviderEnumerator {
    private let containerRelativePath: String
    private let localPath: String

    /// `containerItemIdentifier` is `.rootContainer` or a relative-path
    /// identifier minted by `FileProviderItem`/`FileProviderCatalog`
    /// (see FileProviderExtension.swift's `enumerator(for:request:)`).
    init(containerItemIdentifier: NSFileProviderItemIdentifier, localPath: String) {
        self.containerRelativePath =
            containerItemIdentifier == .rootContainer ? "" : containerItemIdentifier.rawValue
        self.localPath = localPath
    }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        // Single-page enumeration (minimal-but-correct scope
        // — shellipc.proto's `ListFolderFilesResponse` is itself
        // unpaginated, so there is nothing to page through on our end
        // either; a very large folder group would want real paging on
        // both sides as a follow-up).
        let entries = FileProviderCatalog.listFiles(localPath: localPath)
        let nodes = FileProviderCatalog.buildTree(from: entries)
        let children = FileProviderCatalog.children(of: containerRelativePath, in: nodes)
        observer.didEnumerate(children.map { FileProviderItem(node: $0) })
        observer.finishEnumerating(upTo: nil)
    }
}
