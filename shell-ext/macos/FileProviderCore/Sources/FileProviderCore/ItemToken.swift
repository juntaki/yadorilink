import Foundation

/// The daemon's item version identifier: 40 bytes, the 32-byte content hash then the item
/// generation (big endian). It is issued by the daemon and OPAQUE to the extension: it is stored
/// with the bytes and view it names, and echoed verbatim as the base of a modify or delete. The
/// extension never builds one, and never combines a hash with a generation taken at another
/// moment.
public struct ItemToken: Equatable, Hashable, Sendable {
    public static let length = 40

    public let raw: Data

    /// `nil` for anything that is not exactly 40 bytes: such a value is not a token, so the
    /// operation that would carry it carries NO base (an unknown base the daemon never trusts).
    public init?(raw: Data) {
        guard raw.count == ItemToken.length else { return nil }
        self.raw = raw
    }

    public init?(hex: String) {
        guard let data = Data(hexString: hex) else { return nil }
        self.init(raw: data)
    }

    public var hex: String { raw.hexString }

    /// The generation inside the token. Read only to name the generation of a FOLDER the
    /// operation acts on (the parent of a create, the destination of a move); never to rebuild a
    /// token.
    public var generation: UInt64 {
        raw.suffix(8).reduce(0) { ($0 << 8) | UInt64($1) }
    }

    /// The content hash a fetch for this version asks the daemon for: the leading 32 bytes of the
    /// token. A version the OS hands back that is not one of our tokens (none, or foreign bytes)
    /// asks for the current version (empty).
    public static func requestedContentHash(of contentVersion: Data?) -> Data {
        guard let contentVersion, let token = ItemToken(raw: contentVersion) else { return Data() }
        return token.raw.prefix(32)
    }
}

extension Data {
    public var hexString: String { map { String(format: "%02x", $0) }.joined() }

    public init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
