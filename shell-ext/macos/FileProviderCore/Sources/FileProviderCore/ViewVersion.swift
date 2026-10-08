import Foundation

/// What the OS stores WITH an item and hands back as `baseVersion` of a later operation. The
/// content version is the daemon's 40-byte token verbatim. The metadata version is the daemon's
/// 40-byte metadata token followed by the generation of the folder the item was shown in (8 bytes,
/// big endian): the source folder of a rename or move is the one the user SAW, carried with the item
/// it was shown with, never read again at callback time.
public enum ViewVersion {
    public static func metadataVersion(token: ItemToken?, parentGeneration: UInt64) -> Data {
        var data = token?.raw ?? Data(count: ItemToken.length)
        withUnsafeBytes(of: parentGeneration.bigEndian) { data.append(contentsOf: $0) }
        return data
    }

    /// The generation of the folder the item was shown in, from the metadata version the OS handed
    /// back; `nil` (unknown, never guessed) for anything not exactly 48 bytes.
    public static func parentGeneration(fromMetadataVersion data: Data) -> UInt64? {
        guard data.count == ItemToken.length + 8 else { return nil }
        return data.suffix(8).reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
