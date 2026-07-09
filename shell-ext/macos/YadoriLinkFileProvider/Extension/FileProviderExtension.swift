//
//  FileProviderExtension.swift — on-demand-sync tasks 7.1-7.3.
//
//  `NSFileProviderReplicatedExtension` (the modern replicated-extension
//  API — confirmed available since macOS 11.0 via this SDK's
//  `FILEPROVIDER_API_AVAILABILITY_V3_IOS` macro on the protocol itself,
//  `#define FILEPROVIDER_API_AVAILABILITY_V3_IOS API_AVAILABLE(macos(11.0), ...)`
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
        // task 7.2: domains are registered by the host app with
        // `identifier.rawValue == group_id` (see
        // HostApp/DomainRegistration.swift) — recover the matching
        // `local_path` by re-querying the daemon rather than caching it
        // anywhere durable. The extension process can be relaunched by
        // the OS at any time (per this protocol's own doc comment on
        // `invalidate`) and must reconstruct all state from the daemon
        // alone; the daemon's local index is the single source of truth
        // throughout this project (tasks 1-5), and this extension is no
        // exception.
        let folders = FileProviderCatalog.listOnDemandFolders()
        self.localPath = folders.first(where: { $0.group_id == domain.identifier.rawValue })?.local_path ?? ""
        super.init()
        NSLog("yadorilink: FileProviderExtension initialized for domain \(domain.identifier.rawValue), localPath=\(self.localPath)")
    }

    func invalidate() {}

    // MARK: - task 7.3: item(for:) — placeholder metadata

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

    // MARK: - task 7.3: fetchContents — on-open hydration

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

            // design.md D4/D5: calls the daemon's HydrateRequest via the
            // Rust core, bounded to ~35s (see fileprovider-core's
            // HYDRATION_TIMEOUT doc comment) — synchronous from the
            // opening application's point of view, exactly the
            // "bounded timeout on synchronous OS callback" this task
            // requires. `false` covers both "timed out" and "daemon
            // reported hydration failure (no reachable peer had this
            // block)" — either way the OS callback completes with a
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

    // MARK: - task 7.3: enumerator(for:) — placeholder tree presentation

    func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> NSFileProviderEnumerator {
        FileProviderEnumerator(containerItemIdentifier: containerItemIdentifier, localPath: localPath)
    }

    // MARK: - Write path: NOT IMPLEMENTED (documented, tracked gap)
    //
    // design.md's tasks 1-5 (daemon-side) only implement read-direction
    // materialization/hydration — there is no daemon IPC surface yet for
    // "a File Provider client created/modified/deleted a file, apply
    // this to the index and queue it for upload." Wiring that up is real
    // scope beyond task 7.1-7.3 (it would need a new shellipc.proto
    // request analogous to how `local_change::process_event` handles a
    // *filesystem watcher's* view of a local edit, but sourced from the
    // File Provider system's create/modify/delete calls instead of
    // `notify`). `FileProviderItem.capabilities` is deliberately
    // `.allowsReading`-only (no `.allowsWriting`/`.allowsAddingSubItems`)
    // specifically so Finder does not offer drag-and-drop-in/edit-in-place
    // UI that would dead-end here — these three methods exist only to
    // satisfy the protocol's required conformance and to fail cleanly
    // (not hang or crash) for any write attempt that reaches them anyway
    // (e.g. via a non-Finder File Provider client, or definitionally
    // over the API rather than through Finder's own affordances).

    func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        completionHandler(nil, [], false, NSFileProviderError(.notAuthenticated))
        progress.completedUnitCount = 1
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
        completionHandler(nil, [], false, NSFileProviderError(.notAuthenticated))
        progress.completedUnitCount = 1
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
        completionHandler(NSFileProviderError(.notAuthenticated))
        progress.completedUnitCount = 1
        return progress
    }
}
