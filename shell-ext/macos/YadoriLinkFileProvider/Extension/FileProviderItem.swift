//
//  FileProviderItem.swift — .
//
//  `NSFileProviderItem` conformance for both synthesized directories and
//  real files (`CatalogNode`, see FileProviderModel.swift). Required
//  protocol members are `itemIdentifier`/`parentItemIdentifier`/
//  `filename` only; everything else below is `@optional` in the ObjC
//  protocol but implemented here for real behavior rather than Finder's
//  fallback defaults — in particular `isDownloaded`/
//  `isMostRecentVersionDownloaded` are what drives Finder's *native*
//  cloud-download-icon overlay from `MaterializationState` (the relevant behavior
//  "online-only" state doesn't need FinderSync's custom badge under
//  `~/Library/CloudStorage/yadorilink/`; that overlay is native to File
//  Provider items on macOS, unlike FinderSync's Eager-folder path where
//  there is no such native mechanism).
//
//  WRITE PATH: `capabilities` below is deliberately `.allowsReading`/
//  `.allowsContentEnumerating` only — see FileProviderExtension.swift's
//  doc comment on `createItem`/`modifyItem`/`deleteItem` for why write
//  support is a documented, tracked gap in this iteration, not
//  implemented here.

import FileProvider
import UniformTypeIdentifiers

final class FileProviderItem: NSObject, NSFileProviderItem {
    private let node: CatalogNode

    init(node: CatalogNode) {
        self.node = node
    }

    /// Synthesizes the root container's own item — the root has no
    /// `CatalogNode` of its own (it's identified by
    /// `NSFileProviderItemIdentifier.rootContainer`, not a relative
    /// path), so this is a small hand-built stand-in rather than routed
    /// through `CatalogNode`.
    static func rootItem() -> FileProviderItem {
        FileProviderItem(node: CatalogNode(relativePath: "", isDirectory: true, entry: nil))
    }

    var itemIdentifier: NSFileProviderItemIdentifier {
        node.relativePath.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(node.relativePath)
    }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        node.parentRelativePath.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(node.parentRelativePath)
    }

    var filename: String {
        node.relativePath.isEmpty ? "YadoriLink" : node.filename
    }

    var contentType: UTType {
        if node.isDirectory { return .folder }
        let ext = (node.filename as NSString).pathExtension
        return ext.isEmpty ? .data : (UTType(filenameExtension: ext) ?? .data)
    }

    var capabilities: NSFileProviderItemCapabilities {
        node.isDirectory ? [.allowsReading, .allowsContentEnumerating] : [.allowsReading]
    }

    var documentSize: NSNumber? {
        node.isDirectory ? nil : NSNumber(value: node.entry?.size ?? 0)
    }

    var childItemCount: NSNumber? { nil }

    var contentModificationDate: Date? {
        guard let nanos = node.entry?.mtime_unix_nanos else { return node.isDirectory ? Date(timeIntervalSince1970: 0) : nil }
        return Date(timeIntervalSince1970: TimeInterval(nanos) / 1_000_000_000)
    }

    var creationDate: Date? { contentModificationDate }

    /// Native File-Provider "downloaded"/"cloud" state (the relevant behavior).
    /// Directories are always considered "downloaded" (there's no
    /// separate placeholder concept for a directory itself — only its
    /// children are placeholders); a file is downloaded exactly when the
    /// daemon reports `MaterializationState::Hydrated`.
    var isDownloaded: Bool {
        node.isDirectory || node.entry?.materialization_state == "hydrated"
    }

    var isMostRecentVersionDownloaded: Bool { isDownloaded }

    var isUploaded: Bool { true }
    var isUploading: Bool { false }

    var itemVersion: NSFileProviderItemVersion {
        let nanos = node.entry?.mtime_unix_nanos ?? 0
        var value = nanos
        let contentVersion = Data(bytes: &value, count: MemoryLayout<Int64>.size)
        return NSFileProviderItemVersion(contentVersion: contentVersion, metadataVersion: Data())
    }
}
