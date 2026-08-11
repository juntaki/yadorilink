//
//  FileProviderExtension.swift — on-demand-sync.
//
//  `NSFileProviderReplicatedExtension` (the modern replicated-extension
//  API — confirmed available since macOS 11.0 via this SDK's
//  `FILEPROVIDER_API_AVAILABILITY_V3_IOS` macro on the protocol itself,
//  `#define FILEPROVIDER_API_AVAILABILITY_V3_IOS API_AVAILABLE(macos(11.0),...)`
//  in NSFileProviderDefines.h — so this target keeps the same 11.0
//  deployment target as YadoriLinkFinderSync rather than needing a bump;
//  see project.yml's comment for the full verification note). All
//  required-protocol methods below satisfy `NSFileProviderReplicatedExtension`
//  and its `NSFileProviderEnumerating` refinement, per
//  `NSFileProviderReplicatedExtension.h` read directly from the local
//  SDK (no public docs access needed — the header is the source of
//  truth for exact Swift signatures).
//
//  All Rust FFI calls (`yadorilink_fp_*`) run on a background queue, never
//  the calling thread the system hands the completion handler on,
//  matching `core`'s "must never block Finder noticeably" contract —
//  here the constraint is "must never block the system's File Provider
//  XPC dispatch queue," same shape, different caller.

import FileProvider
import UniformTypeIdentifiers

// @objc(FileProviderExtension) is required: without it, Swift's runtime
// class name is mangled with the module name
// (YadoriLinkFileProvider.FileProviderExtension), which doesn't match
// Info.plist's NSExtensionPrincipalClass — confirmed via a real crash on
// a signed build: "Extension Info.plist does not define a principal
// class, or class was not found (expected class name:
// FileProviderExtension)". Same class of bug FinderSync.swift already
// documents fixing for the same reason.
@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    private let domain: NSFileProviderDomain
    private let localPath: String

    init(domain: NSFileProviderDomain) {
        self.domain = domain
        // Domains are registered by the host app with
        // `identifier.rawValue == group_id` (see
        // HostApp/DomainRegistration.swift) — recover the matching
        // `local_path` by re-querying the daemon rather than caching it
        // anywhere durable. The extension process can be relaunched by
        // the OS at any time (per this protocol's own doc comment on
        // `invalidate`) and must reconstruct all state from the daemon
        // alone; the daemon's local index is the single source of truth
        // throughout this project, and this extension is no
        // exception.
        let folders = FileProviderCatalog.listOnDemandFolders()
        self.localPath = folders.first(where: { $0.group_id == domain.identifier.rawValue })?.local_path ?? ""
        super.init()
        NSLog("yadorilink: FileProviderExtension initialized for domain \(domain.identifier.rawValue), localPath=\(self.localPath)")
    }

    func invalidate() {}

    // MARK: -: item(for:) — placeholder metadata

    func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let localPath = self.localPath
        DispatchQueue.global(qos: .userInitiated).async {
            defer { progress.completedUnitCount = 1 }
            if identifier == .rootContainer {
                completionHandler(FileProviderItem.rootItem(), nil)
                return
            }
            let entries = FileProviderCatalog.listFiles(localPath: localPath)
            let nodes = FileProviderCatalog.buildTree(from: entries)
            guard let node = FileProviderCatalog.node(at: identifier.rawValue, in: nodes) else {
                completionHandler(nil, NSFileProviderError(.noSuchItem))
                return
            }
            completionHandler(FileProviderItem(node: node), nil)
        }
        return progress
    }

    // MARK: -: fetchContents — on-open hydration

    func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let localPath = self.localPath
        DispatchQueue.global(qos: .userInitiated).async {
            defer { progress.completedUnitCount = 1 }
            guard itemIdentifier != .rootContainer else {
                completionHandler(nil, nil, NSFileProviderError(.noSuchItem))
                return
            }
            let relativePath = itemIdentifier.rawValue
            let absolutePath = (localPath as NSString).appendingPathComponent(relativePath)

            // Calls the daemon's HydrateRequest via the Rust core, bounded
            // to ~35s (see fileprovider-core's HYDRATION_TIMEOUT doc
            // comment) — synchronous from the opening application's point
            // of view, exactly the bounded timeout a synchronous OS
            // callback requires. `false` covers both "timed out" and
            // "daemon reported hydration failure (no reachable peer had
            // this block)" — either way the OS callback completes with a
            // clear error rather than hanging.
            let ok = absolutePath.withCString { yadorilink_fp_hydrate($0) }
            guard ok else {
                completionHandler(nil, nil, NSFileProviderError(.serverUnreachable))
                return
            }

            let entries = FileProviderCatalog.listFiles(localPath: localPath)
            let nodes = FileProviderCatalog.buildTree(from: entries)
            guard let node = FileProviderCatalog.node(at: relativePath, in: nodes) else {
                completionHandler(nil, nil, NSFileProviderError(.noSuchItem))
                return
            }
            completionHandler(URL(fileURLWithPath: absolutePath), FileProviderItem(node: node), nil)
        }
        return progress
    }

    // MARK: -: enumerator(for:) — placeholder tree presentation

    func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> NSFileProviderEnumerator {
        FileProviderEnumerator(containerItemIdentifier: containerItemIdentifier, localPath: localPath)
    }

    // MARK: - Write path (M1-3)
    //
    // No File-Provider-specific sync engine: each of the three methods
    // below (1) makes disk match what the OS callback asked for, using
    // ordinary `FileManager` operations exactly like any other app would,
    // then (2) notifies the daemon that *something* changed at this path
    // via `yadorilink_fp_notify_local_write` -- carrying no content or
    // metadata, only the relative path and a create/modify-vs-delete
    // signal. The daemon re-observes the live file itself and routes it
    // through the EXACT SAME `local_change::process_event` admission path
    // a filesystem watcher's own event would take (see
    // `LinkFlushHandle::capture_local_write`'s own doc comment on the Rust
    // side). This callback never trusts `itemTemplate`/`changedFields`
    // for anything beyond computing the target path and staged content
    // location -- the daemon is the sole authority on what actually
    // landed.

    /// Resolves an item's on-disk relative path from its parent identifier
    /// (which is either `.rootContainer` or another item's own relative
    /// path, per `FileProviderItem.parentItemIdentifier`'s convention) and
    /// filename.
    private func relativePath(parent: NSFileProviderItemIdentifier, filename: String) -> String {
        parent == .rootContainer ? filename : "\(parent.rawValue)/\(filename)"
    }

    func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let localPath = self.localPath
        let relPath = relativePath(parent: itemTemplate.parentItemIdentifier, filename: itemTemplate.filename)
        let absolutePath = (localPath as NSString).appendingPathComponent(relPath)
        let isDirectory = itemTemplate.contentType == .folder
        DispatchQueue.global(qos: .userInitiated).async {
            defer { progress.completedUnitCount = 1 }
            do {
                let fm = FileManager.default
                if isDirectory {
                    try fm.createDirectory(atPath: absolutePath, withIntermediateDirectories: true)
                } else if let url {
                    if fm.fileExists(atPath: absolutePath) {
                        try fm.removeItem(atPath: absolutePath)
                    }
                    try fm.moveItem(at: url, to: URL(fileURLWithPath: absolutePath))
                } else {
                    fm.createFile(atPath: absolutePath, contents: nil)
                }
            } catch {
                completionHandler(nil, [], false, error)
                return
            }
            // Directory creation (mkdir) is a real, admissible local
            // change too, but this device's daemon-side admission path
            // (`local_change::process_event`) is file-content-oriented --
            // it has no directory-creation signal to emit today. Only
            // notify for a plain file; a bare mkdir with no file inside it
            // yet is picked up by this link's own reconcile/scan passes
            // the same way an out-of-band `mkdir` on an Eager folder
            // already is.
            guard !isDirectory else {
                completionHandler(FileProviderItem(node: CatalogNode(relativePath: relPath, isDirectory: true, entry: nil)), [], false, nil)
                return
            }
            let ok = localPath.withCString { lp in
                relPath.withCString { rp in
                    yadorilink_fp_notify_local_write(lp, rp, 0)
                }
            }
            guard ok else {
                completionHandler(nil, [], false, NSFileProviderError(.serverUnreachable))
                return
            }
            let entries = FileProviderCatalog.listFiles(localPath: localPath)
            let nodes = FileProviderCatalog.buildTree(from: entries)
            guard let node = FileProviderCatalog.node(at: relPath, in: nodes) else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem))
                return
            }
            completionHandler(FileProviderItem(node: node), [], false, nil)
        }
        return progress
    }

    func modifyItem(
        _ item: NSFileProviderItem,
        baseVersion version: NSFileProviderItemVersion,
        changedFields: NSFileProviderItemFields,
        contents newContents: URL?,
        options: NSFileProviderModifyItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let localPath = self.localPath
        let relPath = item.itemIdentifier.rawValue
        let absolutePath = (localPath as NSString).appendingPathComponent(relPath)
        DispatchQueue.global(qos: .userInitiated).async {
            defer { progress.completedUnitCount = 1 }
            if let newContents {
                do {
                    let fm = FileManager.default
                    if fm.fileExists(atPath: absolutePath) {
                        try fm.removeItem(atPath: absolutePath)
                    }
                    try fm.moveItem(at: newContents, to: URL(fileURLWithPath: absolutePath))
                } catch {
                    completionHandler(nil, [], false, error)
                    return
                }
            }
            // A metadata-only modification (no `newContents`, e.g. only
            // `changedFields` touched something this extension does not
            // model, such as a Finder tag) still notifies the daemon --
            // `process_event` re-observes disk and correctly finds nothing
            // changed (a no-op), rather than this callback trying to guess
            // which metadata-only changes are worth propagating.
            let ok = localPath.withCString { lp in
                relPath.withCString { rp in
                    yadorilink_fp_notify_local_write(lp, rp, 0)
                }
            }
            guard ok else {
                completionHandler(nil, [], false, NSFileProviderError(.serverUnreachable))
                return
            }
            let entries = FileProviderCatalog.listFiles(localPath: localPath)
            let nodes = FileProviderCatalog.buildTree(from: entries)
            guard let node = FileProviderCatalog.node(at: relPath, in: nodes) else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem))
                return
            }
            completionHandler(FileProviderItem(node: node), [], false, nil)
        }
        return progress
    }

    func deleteItem(
        identifier: NSFileProviderItemIdentifier,
        baseVersion version: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let localPath = self.localPath
        let relPath = identifier.rawValue
        let absolutePath = (localPath as NSString).appendingPathComponent(relPath)
        DispatchQueue.global(qos: .userInitiated).async {
            defer { progress.completedUnitCount = 1 }
            do {
                try FileManager.default.removeItem(atPath: absolutePath)
            } catch {
                completionHandler(error)
                return
            }
            let ok = localPath.withCString { lp in
                relPath.withCString { rp in
                    yadorilink_fp_notify_local_write(lp, rp, 1)
                }
            }
            completionHandler(ok ? nil : NSFileProviderError(.serverUnreachable))
        }
        return progress
    }
}
