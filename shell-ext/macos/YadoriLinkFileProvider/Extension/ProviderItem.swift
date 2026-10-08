import FileProvider
import FileProviderCore
import UniformTypeIdentifiers

extension NSFileProviderItemIdentifier {
    init(itemID: Data) {
        self = itemID.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(itemID.map { String(format: "%02x", $0) }.joined())
    }

    /// The daemon's item id for this identifier (empty for the root container).
    var itemID: Data? {
        if self == .rootContainer { return Data() }
        var data = Data()
        var index = rawValue.startIndex
        guard rawValue.count % 2 == 0 else { return nil }
        while index < rawValue.endIndex {
            let next = rawValue.index(index, offsetBy: 2)
            guard let byte = UInt8(rawValue[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}

/// An item exactly as the daemon shows it. `itemVersion` carries the daemon's 40-byte tokens
/// verbatim: the OS stores them with the bytes it holds and hands them back as `baseVersion` of
/// a later modify or delete.
final class ProviderItem: NSObject, NSFileProviderItem {
    private let shown: ShownItem
    private let pairedContentVersion: ItemToken?

    /// `pairedContentVersion` is the token the BYTES are paired with (from a materialize), which
    /// replaces the shown view's token for exactly those bytes.
    init(_ shown: ShownItem, pairedContentVersion: ItemToken? = nil) {
        self.shown = shown
        self.pairedContentVersion = pairedContentVersion
    }

    var itemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(itemID: shown.itemID) }
    var parentItemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(itemID: shown.parentItemID) }
    var filename: String { shown.name }

    var contentType: UTType {
        switch shown.kind {
        case .directory: return .folder
        case .symlink: return .symbolicLink
        default:
            let ext = (shown.name as NSString).pathExtension
            return ext.isEmpty ? .data : (UTType(filenameExtension: ext) ?? .data)
        }
    }

    var capabilities: NSFileProviderItemCapabilities {
        var result: NSFileProviderItemCapabilities = []
        for capability in itemCapabilities(isDirectory: shown.kind == .directory, readOnly: shown.readOnly) {
            switch capability {
            case .reading: result.insert(.allowsReading)
            case .writing: result.insert(.allowsWriting)
            case .renaming: result.insert(.allowsRenaming)
            case .reparenting: result.insert(.allowsReparenting)
            case .deleting: result.insert(.allowsDeleting)
            case .enumerating: result.insert(.allowsContentEnumerating)
            case .addingSubItems: result.insert(.allowsAddingSubItems)
            // Deprecated since macOS 13 but still what makes Finder offer "Remove Download".
            case .evicting: result.insert(.allowsEvicting)
            }
        }
        return result
    }

    var documentSize: NSNumber? { shown.kind == .file ? NSNumber(value: shown.size) : nil }

    var contentModificationDate: Date? {
        shown.mtimeUnixNanos == 0 ? nil : Date(timeIntervalSince1970: Double(shown.mtimeUnixNanos) / 1e9)
    }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(
            contentVersion: (pairedContentVersion ?? shown.contentVersion)?.raw ?? Data(),
            metadataVersion: ViewVersion.metadataVersion(token: shown.metadataVersion, parentGeneration: shown.parentGeneration))
    }
}

/// The root container's own item.
final class RootItem: NSObject, NSFileProviderItem {
    let displayName: String
    /// This domain's read-only state (a Reader), from ITS OWN client: no process-wide state.
    let readOnly: Bool
    init(displayName: String, readOnly: Bool) { self.displayName = displayName; self.readOnly = readOnly }
    var itemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
    var parentItemIdentifier: NSFileProviderItemIdentifier { .rootContainer }
    var filename: String { displayName }
    var contentType: UTType { .folder }
    var capabilities: NSFileProviderItemCapabilities {
        readOnly ? [.allowsReading, .allowsContentEnumerating] : [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems]
    }
    var itemVersion: NSFileProviderItemVersion { NSFileProviderItemVersion(contentVersion: Data(), metadataVersion: Data()) }
}

/// A daemon failure as the OS must see it. A transport failure is never an empty result.
func osError(_ failure: ProviderFailure) -> NSError {
    switch failure {
    case .unreachable, .notReady, .retry: return NSFileProviderError(.serverUnreachable) as NSError
    case .notFound: return NSFileProviderError(.noSuchItem) as NSError
    case .anchorExpired: return NSFileProviderError(.syncAnchorExpired) as NSError
    case .nameCollision: return NSFileProviderError(.filenameCollision) as NSError
    case .lowDisk: return NSFileProviderError(.insufficientQuota) as NSError
    // Nothing was authored (or the bytes stay with the user): the OS keeps them and retries.
    case .staleView, .keepLocal, .directoryNotEmpty, .publicationPending, .versionOutOfDate, .tokenInvalid, .other:
        return NSFileProviderError(.cannotSynchronize) as NSError
    }
}
