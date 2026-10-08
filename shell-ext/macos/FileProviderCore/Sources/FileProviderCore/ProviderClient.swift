import Foundation

/// One request out, one response back (the Rust core's `yadorilink_fp_provider_call`). `nil` is a
/// transport failure (unreachable daemon, timeout, malformed reply), never an empty success.
public protocol ProviderTransport: Sendable {
    func call(_ request: [String: Any]) -> Data?
}

public enum ProviderFailure: Error, Equatable {
    /// The transport failed: map to `.serverUnreachable`.
    case unreachable
    case notFound
    case notReady
    case anchorExpired
    case tokenInvalid
    case retry
    /// A generation or base the daemon no longer holds: nothing was authored; refresh and retry.
    case staleView
    /// The item is retired or unknown: the bytes stay with the user (`suggestedName` is the
    /// conflict-copy name they could be re-sent under).
    case keepLocal(suggestedName: String)
    case nameCollision
    case directoryNotEmpty
    /// The publication fence is on for the item: `.cannotSynchronize`, the OS retries.
    case publicationPending
    case versionOutOfDate
    case lowDisk
    case other(code: Int, message: String)

    /// The failure's class for a log line: never a name, a path or a daemon message (those can carry
    /// the user's file names).
    public var logClass: String {
        switch self {
        case .unreachable: return "unreachable"
        case .notFound: return "notFound"
        case .notReady: return "notReady"
        case .anchorExpired: return "anchorExpired"
        case .tokenInvalid: return "tokenInvalid"
        case .retry: return "retry"
        case .staleView: return "staleView"
        case .keepLocal: return "keepLocal"
        case .nameCollision: return "nameCollision"
        case .directoryNotEmpty: return "directoryNotEmpty"
        case .publicationPending: return "publicationPending"
        case .versionOutOfDate: return "versionOutOfDate"
        case .lowDisk: return "lowDisk"
        case .other(let code, _): return "other(\(code))"
        }
    }
}

public enum EntryKind: String, Codable, Sendable { case file, directory, symlink, unspecified }

/// An item as the daemon shows it to the OS. `contentVersion` and `metadataVersion` are tokens.
public struct ShownItem: Equatable, Sendable {
    public let itemID: Data
    public let parentItemID: Data
    public let name: String
    public let kind: EntryKind
    public let size: UInt64
    public let mtimeUnixNanos: Int64
    public let unixMode: UInt32
    public let contentVersion: ItemToken?
    public let metadataVersion: ItemToken?
    public let contentPending: Bool
    /// The generation of the folder this item was shown in (0 for the root container).
    public let parentGeneration: UInt64
    /// This device is a Reader of the group: the item is shown without write, rename, delete or add.
    public var readOnly: Bool = false
}

public struct ChildrenPage: Equatable, Sendable {
    public let items: [ShownItem]
    public let nextPageToken: Data
    public let anchor: UInt64
}

public struct ChangesPage: Equatable, Sendable {
    public let upserts: [ShownItem]
    public let removed: [Data]
    public let nextAnchor: UInt64
    public let more: Bool
}

/// Bytes handed over by the daemon, with the token they are PAIRED with (one value, read together
/// by the daemon): the extension stores it with the bytes.
public struct Materialized: Equatable, Sendable {
    public let handoffName: String
    public let size: UInt64
    public let token: ItemToken
}

public struct AppliedItem: Equatable, Sendable {
    public let item: ShownItem
    public let current: Bool
}

public enum ApplyOutcome: Int, Sendable { case unspecified = 0, applied = 1, concurrent = 3, fileSurvived = 4 }

public struct Applied: Equatable, Sendable {
    public let outcome: ApplyOutcome
    /// Unset for a completed delete.
    public let item: ShownItem?
    /// This answer is the stored result of an operation applied before; `outcome` is the original.
    public let replayed: Bool

    /// The canonical item came back instead of the user's version (the user's bytes are in a
    /// conflict copy): the OS must fetch the canonical content again, replay or not, or its stale
    /// local bytes would sit under the canonical token.
    public var needsRefetch: Bool { outcome == .concurrent }
}

public struct Change: Sendable {
    public enum Kind: String, Sendable { case create, modify, delete }
    public var kind: Kind
    public var item: Data = Data()
    /// CREATE: the parent (empty = root). MODIFY: set only when moving.
    public var parent: Data?
    public var name: String?
    public var entryKind: EntryKind = .file
    /// MODIFY/DELETE: the token of the version the user saw, echoed verbatim; `nil` means
    /// UNKNOWN (an edit is kept beside the file, a delete leaves the file).
    public var base: ItemToken?
    public var ingestName: String?
    public var size: UInt64 = 0
    public var sha256: Data = Data()
    public var symlinkTarget: Data = Data()
    public var unixMode: UInt32?
    public var mtimeUnixNanos: Int64?
    public var recursive = false
    /// The place generation of the folder a rename or move LEAVES (a destination is an identity).
    public var parentGeneration: UInt64?
    public var observedRevision: UInt64?

    public init(kind: Kind) { self.kind = kind }
}

extension Change {
    /// What makes two requests the same logical operation (not the attempt, not the staging name).
    /// Every field is typed and length-prefixed, and an absent optional is distinct from an empty
    /// or any literal value, so two different operations can never share an identity.
    var identity: String {
        func text(_ value: String?) -> String { value.map { "s\($0.utf8.count):\($0)" } ?? "n" }
        func number(_ value: (some BinaryInteger)?) -> String { value.map { "i\($0)" } ?? "n" }
        return [
            text(kind.rawValue), text(item.hexString), text(parent?.hexString), text(name),
            text(entryKind.rawValue), text(base?.hex), text(sha256.hexString),
            text(symlinkTarget.hexString), number(unixMode), number(mtimeUnixNanos),
            recursive ? "t" : "f", number(parentGeneration),
            number(observedRevision),
        ].joined(separator: "|")
    }
}

public final class ProviderClient: @unchecked Sendable {
    private let root: Data
    private let transport: ProviderTransport
    private let log: OperationLog
    private let accessLock = NSLock()
    private var readOnlyRoot = false

    /// Whether THIS domain's items are read-only for this device (a Reader), as last shown by the daemon.
    /// Per client, so per domain: the root container follows the items of its own root and no other.
    public var rootReadOnly: Bool {
        accessLock.lock(); defer { accessLock.unlock() }
        return readOnlyRoot
    }

    public init(root: Data, transport: ProviderTransport, log: OperationLog) {
        self.root = root
        self.transport = transport
        self.log = log
    }

    // MARK: enumeration

    public func children(of parent: Data, pageToken: Data = Data(), limit: Int = 0) -> Result<ChildrenPage, ProviderFailure> {
        guard let r = request("children", ["parent": parent.hexString, "page_token": pageToken.hexString, "limit": limit])
        else { return .failure(.unreachable) }
        if let failure = enumerateFailure(r) { return .failure(failure) }
        return .success(ChildrenPage(items: items(r["items"]), nextPageToken: bytes(r["next_page_token"]), anchor: uint(r["anchor"])))
    }

    public func item(_ id: Data) -> Result<ShownItem, ProviderFailure> {
        guard let r = request("item", ["item": id.hexString]) else { return .failure(.unreachable) }
        if let failure = enumerateFailure(r) { return .failure(failure) }
        guard let item = shown(r["item"] as? [String: Any]) else { return .failure(.notFound) }
        return .success(item)
    }

    public func changes(scope: String, parent: Data = Data(), since: UInt64, limit: Int = 0) -> Result<ChangesPage, ProviderFailure> {
        guard let r = request("changes", ["scope": scope, "parent": parent.hexString, "since": since, "limit": limit])
        else { return .failure(.unreachable) }
        if let failure = enumerateFailure(r) { return .failure(failure) }
        let removed = (r["removed_item_ids"] as? [String] ?? []).compactMap { Data(hexString: $0) }
        return .success(ChangesPage(upserts: items(r["upserts"]), removed: removed, nextAnchor: uint(r["next_anchor"]), more: r["more"] as? Bool ?? false))
    }

    public func workingSet(pageToken: Data = Data(), limit: Int = 0) -> Result<ChildrenPage, ProviderFailure> {
        guard let r = request("working_set", ["page_token": pageToken.hexString, "limit": limit]) else { return .failure(.unreachable) }
        if let failure = enumerateFailure(r) { return .failure(failure) }
        return .success(ChildrenPage(items: items(r["items"]), nextPageToken: bytes(r["next_page_token"]), anchor: uint(r["anchor"])))
    }

    /// Tells the daemon a folder was enumerated or an item fetched (it drives prefetch); best effort.
    public func activity(item: Data, fetch: Bool) {
        _ = request("activity", ["item": item.hexString, "kind": fetch ? "fetch" : "enumerate"])
    }

    // MARK: contents

    /// Asks for the current version of the item's bytes. The answer carries the token the bytes
    /// are paired with; a reply without a well-formed token is a failure, never bytes with a
    /// guessed version.
    public func materialize(item: Data, requestID: Data, requestedHash: Data = Data()) -> Result<Materialized, ProviderFailure> {
        guard let r = request("materialize", ["item": item.hexString, "request_id": requestID.hexString, "requested_hash": requestedHash.hexString])
        else { return .failure(.unreachable) }
        guard r["ok"] as? Bool == true else {
            let code = Int(uint(r["failure"]))
            let message = r["error"] as? String ?? ""
            switch code {
            case 1: return .failure(.notFound)
            case 2: return .failure(.versionOutOfDate)
            case 4: return .failure(.lowDisk)
            case 5: return .failure(.notReady)
            case 7: return .failure(.publicationPending)
            default: return .failure(.other(code: code, message: message))
            }
        }
        guard let token = ItemToken(hex: r["content_version"] as? String ?? ""), let name = r["handoff_name"] as? String, !name.isEmpty
        else { return .failure(.other(code: -1, message: "the daemon's reply carried no paired token")) }
        return .success(Materialized(handoffName: name, size: uint(r["size"]), token: token))
    }

    // MARK: writes

    /// Sends one logical user operation. Its identity is derived from the operation itself (kind,
    /// item, parent, name, base token, the bytes' hash, the source folder it leaves), never from a staging
    /// name or an attempt: every retry of the same operation, however its bytes were restaged,
    /// reuses one `(session, seq)`, and different bytes are a different operation.
    public func apply(_ change: Change) -> Result<Applied, ProviderFailure> {
        let fingerprint = change.identity
        var body: [String: Any] = [
            "kind": change.kind.rawValue,
            "item": change.item.hexString,
            "entry_kind": change.entryKind.rawValue,
            // The base token, verbatim; absent when the OS named none.
            "base": change.base?.hex ?? "",
            "session": log.session.hexString,
            "seq": log.seq(for: fingerprint),
            "request_id": Data((0..<16).map { _ in UInt8.random(in: 0...255) }).hexString,
            "symlink_target": change.symlinkTarget.hexString,
            "recursive": change.recursive,
        ]
        if let parent = change.parent { body["parent"] = parent.hexString }
        if let name = change.name { body["name"] = name }
        if let ingest = change.ingestName {
            body["content"] = ["ingest_name": ingest, "size": change.size, "sha256": change.sha256.hexString]
        }
        var metadata: [String: Any] = [:]
        if let mode = change.unixMode { metadata["unix_mode"] = mode }
        if let mtime = change.mtimeUnixNanos { metadata["mtime_unix_nanos"] = mtime }
        if !metadata.isEmpty { body["metadata"] = metadata }
        if let g = change.parentGeneration { body["parent_generation"] = g }
        if let g = change.observedRevision { body["observed_revision"] = g }
        guard let r = request("apply", body) else { return .failure(.unreachable) }
        if r["ok"] as? Bool != true {
            let failure = applyFailure(r)
            // A refusal for good (not a retry hint) ends the logical action.
            switch failure {
            case .retry, .staleView, .notReady, .unreachable, .lowDisk: break
            default: log.complete(fingerprint)
            }
            return .failure(failure)
        }
        log.complete(fingerprint)
        let item = shown(r["item"] as? [String: Any])
        return .success(Applied(outcome: ApplyOutcome(rawValue: Int(uint(r["outcome"]))) ?? .unspecified, item: item, replayed: r["replayed"] as? Bool ?? false))
    }

    // MARK: decoding

    private func request(_ op: String, _ fields: [String: Any]) -> [String: Any]? {
        var body = fields
        body["op"] = op
        body["root"] = root.hexString
        guard let data = transport.call(body), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json
    }

    private func enumerateFailure(_ r: [String: Any]) -> ProviderFailure? {
        if r["ok"] as? Bool == true { return nil }
        switch Int(uint(r["failure"])) {
        case 1: return .notReady
        case 2, 3: return .notFound
        case 4: return .tokenInvalid
        case 5: return .anchorExpired
        case 6: return .retry
        case let other: return .other(code: other, message: r["error"] as? String ?? "")
        }
    }

    private func applyFailure(_ r: [String: Any]) -> ProviderFailure {
        switch Int(uint(r["failure"])) {
        case 1: return .notFound
        case 2: return .notReady
        case 4: return .nameCollision
        case 5: return .directoryNotEmpty
        case 9: return .lowDisk
        // 7: the staged copy changed or was not stable; the same (session, seq) retry repairs it
        // with a fresh copy, so the action is not over.
        case 7, 12: return .retry
        case 14: return .keepLocal(suggestedName: r["suggested_name"] as? String ?? "")
        case 17: return .staleView
        case let other: return .other(code: other, message: r["error"] as? String ?? "")
        }
    }

    private func items(_ value: Any?) -> [ShownItem] {
        (value as? [[String: Any]] ?? []).compactMap { shown($0) }
    }

    private func shown(_ d: [String: Any]?) -> ShownItem? {
        guard let d, let id = Data(hexString: d["item_id"] as? String ?? ""), !id.isEmpty else { return nil }
        accessLock.lock(); readOnlyRoot = d["read_only"] as? Bool ?? false; accessLock.unlock()
        return ShownItem(
            itemID: id,
            parentItemID: bytes(d["parent_item_id"]),
            name: d["name"] as? String ?? "",
            kind: EntryKind(rawValue: d["entry_kind"] as? String ?? "") ?? .unspecified,
            size: uint(d["size"]),
            mtimeUnixNanos: (d["mtime_unix_nanos"] as? NSNumber)?.int64Value ?? 0,
            unixMode: UInt32(truncatingIfNeeded: uint(d["unix_mode"])),
            contentVersion: ItemToken(hex: d["content_version"] as? String ?? ""),
            metadataVersion: ItemToken(hex: d["metadata_version"] as? String ?? ""),
            contentPending: d["content_pending"] as? Bool ?? false,
            parentGeneration: uint(d["parent_generation"]),
            readOnly: d["read_only"] as? Bool ?? false)
    }

    private func bytes(_ v: Any?) -> Data { Data(hexString: v as? String ?? "") ?? Data() }
    private func uint(_ v: Any?) -> UInt64 { (v as? NSNumber)?.uint64Value ?? 0 }
}
