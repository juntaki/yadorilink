import Foundation

/// The bytes of one item as the daemon handed them over, verified.
public struct FetchedContents: Equatable, Sendable {
    public let url: URL
    public let item: ShownItem
    public let bytes: Materialized
}

extension ProviderClient {
    /// The whole `fetchContents` decision, apart from the OS: asks for the bytes, then refuses to
    /// call them a success unless the named handoff file exists and holds EXACTLY the number of
    /// bytes the daemon said the version has, and the item shown for them is that same version with
    /// that same size (the generation may have moved on; the content hash may not). A failed, dropped or short fetch is never a file the OS could take for an
    /// empty or truncated item.
    ///
    /// `fileSize` returns the on-disk size of a regular file, or nil when there is none.
    public func fetchContents(
        item: Data, requestID: Data, requestedHash: Data, handoffDirectory: URL,
        fileSize: (URL) -> UInt64?
    ) -> Result<FetchedContents, ProviderFailure> {
        switch materialize(item: item, requestID: requestID, requestedHash: requestedHash) {
        case .failure(let failure):
            return .failure(failure)
        case .success(let bytes):
            let url = handoffDirectory.appendingPathComponent(bytes.handoffName)
            guard let onDisk = fileSize(url) else {
                return .failure(.other(code: -3, message: "the handed-over file is missing"))
            }
            guard onDisk == bytes.size else {
                return .failure(.other(code: -4, message: "the handed-over file holds \(onDisk) of \(bytes.size) bytes"))
            }
            // The item returned for these bytes names the token they are PAIRED with.
            guard case .success(let shown) = self.item(item) else { return .failure(.unreachable) }
            guard let shownToken = shown.contentVersion, shownToken.raw.prefix(32) == bytes.token.raw.prefix(32) else { return .failure(.versionOutOfDate) }
            guard shown.size == bytes.size else {
                return .failure(.other(code: -5, message: "the item's size \(shown.size) is not the handed-over \(bytes.size) bytes"))
            }
            return .success(FetchedContents(url: url, item: shown, bytes: bytes))
        }
    }
}

/// The size of a regular file at `url`, or nil.
public func regularFileSize(_ url: URL) -> UInt64? {
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
        attributes[.type] as? FileAttributeType == .typeRegular,
        let size = attributes[.size] as? NSNumber
    else { return nil }
    return size.uint64Value
}
