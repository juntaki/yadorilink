//
//  FileProviderExtension.swift
//
//  `NSFileProviderReplicatedExtension` for a provider root. The daemon is the only authority on
//  what an item is; this extension is a transport for user intent and for bytes.
//
//  THE TOKEN RULE: every item and every materialized file carries the daemon's
//  40-byte version token. The OS stores it with the bytes it holds and hands it back as
//  `baseVersion`; the extension echoes it VERBATIM as the base of a modify or delete, and never
//  builds one, splits one, or combines a hash and a generation taken at different moments. A
//  `baseVersion` that is not exactly 40 bytes is sent as NO base (unknown): the daemon keeps an
//  edit beside the file and leaves a deleted file in place.
//
//  Nothing the OS reports about its own state (materialization, signals, evictions) is used to
//  decide a write. All FFI calls run on a background queue.

import CryptoKit
import FileProvider
import os
import FileProviderCore
import UniformTypeIdentifiers

@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    private let domain: NSFileProviderDomain
    private static let log = Logger(subsystem: "com.juntaki.yadorilink.extension", category: "modify")
    private let client: ProviderClient
    private let providerRoot: URL?

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        // The domain identifier is the root id as lowercase hex.
        let root = NSFileProviderItemIdentifier(domain.identifier.rawValue).itemID ?? Data()
        // The daemon's fixed temp root (`handoff/` for bytes out, `ingest/` for bytes in) lives in
        // the app group container. Without the container the extension fails closed: every call is
        // unreachable and nothing is staged.
        let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.juntaki.yadorilink.shared")
        switch ProviderStorage.decide(groupContainer: group, domainID: domain.identifier.rawValue) {
        case .available(let providerRoot, let operationLog):
            self.providerRoot = providerRoot
            client = ProviderClient(root: root, transport: FFITransport(), log: OperationLog(url: operationLog))
        case .unavailable:
            Self.log.error("the app group container is unavailable; the provider refuses all work")
            providerRoot = nil
            client = ProviderClient(
                root: root, transport: UnavailableTransport(),
                log: OperationLog(url: FileManager.default.temporaryDirectory.appendingPathComponent("provider-unavailable-\(UUID().uuidString).json")))
        }
        super.init()
    }

    func invalidate() {}

    // MARK: item(for:)

    func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        DispatchQueue.global(qos: .userInitiated).async { [client, domain] in
            defer { progress.completedUnitCount = 1 }
            if identifier == .rootContainer {
                completionHandler(RootItem(displayName: domain.displayName, readOnly: client.rootReadOnly), nil)
                return
            }
            guard let id = identifier.itemID else {
                completionHandler(nil, NSFileProviderError(.noSuchItem))
                return
            }
            switch client.item(id) {
            case .success(let item):
                completionHandler(ProviderItem(item), nil)
            case .failure(let failure): completionHandler(nil, osError(failure))
            }
        }
        return progress
    }

    // MARK: fetchContents

    func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        guard let providerRoot else {
            completionHandler(nil, nil, NSFileProviderError(.serverUnreachable))
            progress.completedUnitCount = 1
            return progress
        }
        let handoff = providerRoot.appendingPathComponent("handoff", isDirectory: true)
        DispatchQueue.global(qos: .userInitiated).async { [client] in
            defer { progress.completedUnitCount = 1 }
            guard let id = itemIdentifier.itemID, !id.isEmpty else {
                completionHandler(nil, nil, NSFileProviderError(.noSuchItem))
                return
            }
            client.activity(item: id, fetch: true)
            // A version the OS names is passed on: the daemon refuses bytes that are not that
            // version (old bytes are never returned), and the OS retries against the current one.
            let wanted = ItemToken.requestedContentHash(of: requestedVersion?.contentVersion)
            switch client.materialize(item: id, requestID: Data(UUID().uuidString.utf8), requestedHash: wanted) {
            case .failure(let failure):
                completionHandler(nil, nil, osError(failure))
            case .success(let bytes):
                // The item returned for these bytes names the token they are PAIRED with.
                guard case .success(let shown) = client.item(id) else {
                    completionHandler(nil, nil, NSFileProviderError(.serverUnreachable))
                    return
                }
                completionHandler(
                    handoff.appendingPathComponent(bytes.handoffName),
                    ProviderItem(shown, pairedContentVersion: bytes.token), nil)
            }
        }
        return progress
    }

    // MARK: enumerator(for:)

    func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> NSFileProviderEnumerator {
        if containerItemIdentifier == .workingSet { return WorkingSetEnumerator(client: client) }
        guard containerItemIdentifier != .trashContainer, let parent = containerItemIdentifier.itemID else {
            throw NSFileProviderError(.noSuchItem)
        }
        return FolderEnumerator(client: client, parent: parent)
    }

    // MARK: writes

    /// Copies the OS's file into the daemon's ingest directory (`.name.partial`, then an atomic
    /// rename) and describes it; the daemon verifies the bytes itself.
    private func stage(_ url: URL) throws -> (name: String, size: UInt64, sha256: Data) {
        guard let providerRoot else { throw NSFileProviderError(.serverUnreachable) }
        let ingest = providerRoot.appendingPathComponent("ingest", isDirectory: true)
        let name = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let partial = ingest.appendingPathComponent(".\(name).partial")
        try FileManager.default.copyItem(at: url, to: partial)
        let handle = try FileHandle(forReadingFrom: partial)
        defer { try? handle.close() }
        var hasher = SHA256()
        var size: UInt64 = 0
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
            size += UInt64(chunk.count)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: partial.path)
        // Durable BEFORE the upload is named to the daemon (which journals it on that name): the
        // bytes, then the rename in the directory. A crash after this point cannot leave a name
        // whose bytes are missing or short.
        try Self.sync(partial)
        try FileManager.default.moveItem(at: partial, to: ingest.appendingPathComponent(name))
        try Self.sync(ingest)
        return (name, size, Data(hasher.finalize()))
    }

    /// fsync of a file or a directory.
    private static func sync(_ url: URL) throws {
        let descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
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
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer { progress.completedUnitCount = 1 }
            guard let parent = itemTemplate.parentItemIdentifier.itemID else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem))
                return
            }
            Self.log.notice("create type=\(itemTemplate.contentType?.identifier ?? "none", privacy: .public) hasContents=\(url != nil) options=\(options.rawValue)")
            var change = Change(kind: .create)
            change.parent = parent
            change.name = itemTemplate.filename
            if itemTemplate.contentType == .folder {
                change.entryKind = .directory
            } else if itemTemplate.contentType == .symbolicLink, let target = itemTemplate.symlinkTargetPath ?? nil {
                change.entryKind = .symlink
                change.symlinkTarget = Data(target.utf8)
            } else if let url {
                do {
                    let staged = try stage(url)
                    change.ingestName = staged.name
                    change.size = staged.size
                    change.sha256 = staged.sha256
                } catch {
                    completionHandler(nil, [], false, error)
                    return
                }
            } else {
                Self.log.error("create: no contents were provided for a non-folder")
                completionHandler(nil, [], false, NSFileProviderError(.cannotSynchronize))
                return
            }
            // The destination folder is an identity (its item id): no view is named for it.
            switch client.apply(change) {
            case .success(let applied):
                completionHandler(applied.item.map { ProviderItem($0) }, [], false, nil)
            case .failure(let failure):
                Self.log.error("create failed: \(failure.logClass, privacy: .public)")
                completionHandler(nil, [], false, osError(failure))
            }
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
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer { progress.completedUnitCount = 1 }
            guard let id = item.itemIdentifier.itemID, !id.isEmpty else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem))
                return
            }
            var change = Change(kind: .modify)
            change.item = id
            // The token the OS holds for the version the user saw, verbatim (nil if malformed).
            change.base = ItemToken(raw: version.contentVersion)
            var handled: NSFileProviderItemFields = []
            if changedFields.contains(.contents), let newContents {
                do {
                    let staged = try stage(newContents)
                    change.ingestName = staged.name
                    change.size = staged.size
                    change.sha256 = staged.sha256
                    handled.insert(.contents)
                } catch {
                    completionHandler(nil, [], false, error)
                    return
                }
            }
            // A rename or move acts on the folder the user SAW the item in: its generation travels
            // with the item (inside the metadata version the OS stored with it), never read again
            // now. Without it (unknown) the daemon refuses the operation as a stale view.
            let sourceGeneration = ViewVersion.parentGeneration(fromMetadataVersion: version.metadataVersion)
            if changedFields.contains(.filename) {
                change.name = item.filename
                change.parentGeneration = sourceGeneration
                handled.insert(.filename)
            }
            if changedFields.contains(.parentItemIdentifier), let parent = item.parentItemIdentifier.itemID {
                change.parent = parent
                change.parentGeneration = sourceGeneration
                handled.insert(.parentItemIdentifier)
            }
            if changedFields.contains(.contentModificationDate), let date = item.contentModificationDate ?? nil {
                change.mtimeUnixNanos = Int64(date.timeIntervalSince1970 * 1e9)
                handled.insert(.contentModificationDate)
            }
            let sent = ItemToken(raw: version.contentVersion)?.generation
            switch client.apply(change) {
            case .success(let applied):
                Self.log.notice("modify item=\(id.hexString, privacy: .public) fields=\(changedFields.rawValue) sent_generation=\(sent.map(String.init) ?? "none", privacy: .public) returned_generation=\(applied.item?.contentVersion.map { String($0.generation) } ?? "none", privacy: .public)")
                // A concurrent edit that lost keeps the user's bytes in a file beside the item;
                // the item itself is the canonical version, whose bytes must be fetched again.
                let refetch = applied.needsRefetch
                completionHandler(applied.item.map { ProviderItem($0) }, changedFields.subtracting(handled), refetch, nil)
            case .failure(let failure):
                Self.log.notice("modify item=\(id.hexString, privacy: .public) fields=\(changedFields.rawValue) sent_generation=\(sent.map(String.init) ?? "none", privacy: .public) failed=\(failure.logClass, privacy: .public)")
                completionHandler(nil, [], false, osError(failure))
            }
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
        DispatchQueue.global(qos: .userInitiated).async { [client] in
            defer { progress.completedUnitCount = 1 }
            guard let id = identifier.itemID, !id.isEmpty else {
                completionHandler(NSFileProviderError(.noSuchItem))
                return
            }
            var change = Change(kind: .delete)
            change.item = id
            change.base = ItemToken(raw: version.contentVersion)
            change.recursive = options.contains(.recursive)
            switch client.apply(change) {
            // An ambiguous delete leaves the file: the OS has already removed its copy, and the
            // survivor comes back through enumeration as a new item.
            case .success: completionHandler(nil)
            case .failure(let failure): completionHandler(osError(failure))
            }
        }
        return progress
    }
}
