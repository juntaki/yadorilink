import XCTest
@testable import FileProviderCore

/// A fake daemon: records every request and answers from a queue.
final class FakeTransport: ProviderTransport, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [[String: Any]] = []
    var replies: [[String: Any]?] = []

    func call(_ request: [String: Any]) -> Data? {
        lock.lock(); defer { lock.unlock() }
        requests.append(request)
        guard !replies.isEmpty, let reply = replies.removeFirst() else { return nil }
        return try? JSONSerialization.data(withJSONObject: reply)
    }
}

func token(_ byte: UInt8, _ generation: UInt64) -> ItemToken {
    var raw = Data(repeating: byte, count: 32)
    withUnsafeBytes(of: generation.bigEndian) { raw.append(contentsOf: $0) }
    return ItemToken(raw: raw)!
}

final class FileProviderCoreTests: XCTestCase {
    private func client(_ transport: FakeTransport) -> ProviderClient {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("oplog-\(UUID().uuidString).json")
        return ProviderClient(root: Data(repeating: 9, count: 16), transport: transport, log: OperationLog(url: url))
    }

    /// (review) Read-only is per DOMAIN (per client): a Reader root and an Editor root in one process never
    /// contaminate each other, whatever order their items arrive in.
    func testReadOnlyStateIsPerClientNotProcessWide() {
        let readerDaemon = FakeTransport(), editorDaemon = FakeTransport()
        let reader = client(readerDaemon), editor = client(editorDaemon)
        XCTAssertFalse(reader.rootReadOnly)
        readerDaemon.replies = [["ok": true, "items": [["item_id": "01", "name": "a", "read_only": true]], "anchor": 1]]
        editorDaemon.replies = [["ok": true, "items": [["item_id": "02", "name": "b", "read_only": false]], "anchor": 1]]
        _ = reader.children(of: Data())
        _ = editor.children(of: Data())
        XCTAssertTrue(reader.rootReadOnly, "the Reader root lost its state to the Editor root")
        XCTAssertFalse(editor.rootReadOnly, "the Editor root took the Reader root's state")
    }

    func testATokenIsExactlyFortyBytesAndCarriesItsGeneration() {
        XCTAssertNil(ItemToken(raw: Data(repeating: 1, count: 32)))
        XCTAssertNil(ItemToken(raw: Data(repeating: 1, count: 41)))
        XCTAssertEqual(token(3, 258).generation, 258)
        XCTAssertEqual(ItemToken(hex: token(3, 7).hex), token(3, 7))
        XCTAssertNil(ItemToken(hex: "zz"))
    }

    /// (1) A@g materialized -> edit to B -> the callback carries base A@g verbatim -> the daemon
    /// answers B@(g+1) -> the next callback carries base B@(g+1).
    func testEachCallbackEchoesTheTokenTheDaemonLastIssued() {
        let a = token(1, 5), b = token(2, 6), c = token(3, 7)
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [
            ["ok": true, "handoff_name": "h1", "size": 1, "content_version": a.hex],
            ["ok": true, "outcome": 1, "item": ["item_id": "01", "name": "f", "content_version": b.hex]],
            ["ok": true, "outcome": 1, "item": ["item_id": "01", "name": "f", "content_version": c.hex]],
        ]
        guard case .success(let m) = client.materialize(item: Data([1]), requestID: Data([7])) else { return XCTFail() }
        XCTAssertEqual(m.token, a)

        var edit = Change(kind: .modify)
        edit.item = Data([1]); edit.base = m.token; edit.ingestName = "c1"; edit.size = 1
        guard case .success(let applied) = client.apply(edit), let next = applied.item?.contentVersion
        else { return XCTFail() }
        XCTAssertEqual(next, b)
        XCTAssertEqual(daemon.requests[1]["base"] as? String, a.hex, "base is the token the bytes were paired with")

        var again = Change(kind: .modify)
        again.item = Data([1]); again.base = next; again.ingestName = "c2"; again.size = 1
        _ = client.apply(again)
        XCTAssertEqual(daemon.requests[2]["base"] as? String, b.hex)
    }

    /// (2) A LATE callback that still names A@g: the daemon says STALE_VIEW and the client reports it
    /// as a retriable stale view, never as success; the logical action stays open for the retry.
    func testALateCallbackOfTheOldTokenIsAStaleViewAndStaysOpen() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": false, "failure": 17, "error": "stale"], ["ok": false, "failure": 17, "error": "stale"]]
        var late = Change(kind: .modify)
        late.item = Data([1]); late.base = token(1, 5); late.ingestName = "c"; late.size = 1
        XCTAssertEqual(client.apply(late), .failure(.staleView))
        _ = client.apply(late)
        XCTAssertEqual(daemon.requests[0]["seq"] as? UInt64, daemon.requests[1]["seq"] as? UInt64, "a retry reused its identity")
    }

    /// No base is sent as empty (UNKNOWN), never as a substitute.
    func testAnAbsentBaseIsSentEmpty() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": true, "outcome": 4]]
        var gone = Change(kind: .delete)
        gone.item = Data([1])
        guard case .success(let r) = client.apply(gone) else { return XCTFail() }
        XCTAssertEqual(r.outcome, .fileSurvived)
        XCTAssertEqual(daemon.requests[0]["base"] as? String, "")
    }

    /// Bytes without a paired token are a failure: no version is guessed for them.
    func testMaterializedBytesWithoutAPairedTokenAreRefused() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": true, "handoff_name": "h", "size": 1, "content_version": "00"]]
        guard case .failure = client.materialize(item: Data([1]), requestID: Data([1])) else { return XCTFail() }
    }

    func testATransportFailureIsUnreachableNotEmpty() {
        let daemon = FakeTransport()
        let client = client(daemon)
        XCTAssertEqual(client.children(of: Data()), .failure(.unreachable))
        daemon.replies = [["ok": true, "items": [], "next_page_token": "", "anchor": 3]]
        XCTAssertEqual(client.children(of: Data()), .success(ChildrenPage(items: [], nextPageToken: Data(), anchor: 3)))
    }

    func testOperationIdentityIsStablePerActionAndSurvivesARestart() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("oplog-\(UUID().uuidString).json")
        let first = OperationLog(url: url)
        let a = first.seq(for: "a"), b = first.seq(for: "b")
        XCTAssertEqual([a, b], [1, 2])
        XCTAssertEqual(first.seq(for: "a"), 1)
        let reopened = OperationLog(url: url)
        XCTAssertEqual(reopened.session, first.session)
        XCTAssertEqual(reopened.seq(for: "a"), 1)
        reopened.complete("a")
        XCTAssertEqual(reopened.seq(for: "a"), 3)
    }

    /// (S2) A nested rename carries the generation of the folder the item was SHOWN in: it travels in
    /// the metadata version stored with the item and reaches the daemon as `parent_generation`;
    /// a version without it is unknown, never guessed.
    func testARenameNamesTheFolderGenerationOfTheOriginalView() {
        let meta = token(4, 9)
        let stored = ViewVersion.metadataVersion(token: meta, parentGeneration: 7)
        XCTAssertEqual(stored.count, 48)
        XCTAssertEqual(ViewVersion.parentGeneration(fromMetadataVersion: stored), 7)
        XCTAssertNil(ViewVersion.parentGeneration(fromMetadataVersion: meta.raw))
        XCTAssertNil(ViewVersion.parentGeneration(fromMetadataVersion: Data()))

        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [
            ["ok": true, "items": [["item_id": "01", "name": "f", "content_version": token(1, 3).hex,
                                      "metadata_version": meta.hex, "parent_generation": 7]],
             "next_page_token": "", "anchor": 1],
            ["ok": true, "outcome": 1],
        ]
        guard case .success(let page) = client.children(of: Data([2])), let shown = page.items.first else { return XCTFail() }
        XCTAssertEqual(shown.parentGeneration, 7)
        var rename = Change(kind: .modify)
        rename.item = shown.itemID; rename.name = "g"; rename.base = shown.contentVersion
        rename.parentGeneration = ViewVersion.parentGeneration(
            fromMetadataVersion: ViewVersion.metadataVersion(token: shown.metadataVersion, parentGeneration: shown.parentGeneration))
        _ = client.apply(rename)
        XCTAssertEqual(daemon.requests[1]["parent_generation"] as? UInt64, 7)
    }

    /// (T4) The operation's identity does not depend on the staging name: a retry after a lost reply
    /// whose bytes were restaged under another ingest name reuses the same `(session, seq)`, and
    /// other bytes are a new operation.
    func testARestagedRetryKeepsItsReplayIdentity() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [nil, ["ok": true, "outcome": 1], ["ok": true, "outcome": 1]]
        func edit(_ staged: String, _ sha: UInt8) -> Change {
            var change = Change(kind: .modify)
            change.item = Data([1]); change.base = token(1, 5); change.ingestName = staged
            change.size = 1; change.sha256 = Data(repeating: sha, count: 32)
            return change
        }
        XCTAssertEqual(client.apply(edit("stage-1", 7)), .failure(.unreachable))   // the reply was lost
        _ = client.apply(edit("stage-2", 7))                                      // restaged, same bytes
        _ = client.apply(edit("stage-3", 8))                                      // the user typed again
        let seqs = daemon.requests.map { $0["seq"] as? UInt64 }
        XCTAssertEqual(seqs[0], seqs[1], "a restaged retry lost its identity")
        XCTAssertNotEqual(seqs[1], seqs[2], "different bytes shared an identity")
    }


    /// An unstable staged copy is a retry hint, not a refusal: the operation stays in the log, so the
    /// retry keeps its (session, seq) and the daemon repairs the journal with a fresh copy.
    func testAnUnstableIngestIsRetryableAndKeepsItsIdentity() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": false, "failure": 7, "error": "unstable"], ["ok": true, "outcome": 1]]
        var change = Change(kind: .modify)
        change.item = Data([1]); change.base = token(1, 5); change.ingestName = "stage-1"
        change.size = 1; change.sha256 = Data(repeating: 7, count: 32)
        XCTAssertEqual(client.apply(change), .failure(.retry))
        _ = client.apply(change)
        let seqs = daemon.requests.map { $0["seq"] as? UInt64 }
        XCTAssertEqual(seqs[0], seqs[1], "an unstable ingest was completed in the log")
    }

    /// A requested version reaches the daemon as its content hash; none or foreign bytes ask for the
    /// current version, and the daemon's refusal is a version-out-of-date failure.
    func testARequestedVersionIsPassedToTheDaemon() {
        let hashed = token(3, 9)
        XCTAssertEqual(ItemToken.requestedContentHash(of: hashed.raw), Data(repeating: 3, count: 32))
        XCTAssertEqual(ItemToken.requestedContentHash(of: nil), Data())
        XCTAssertEqual(ItemToken.requestedContentHash(of: Data([1, 2, 3])), Data())
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": false, "failure": 2, "error": "not current"]]
        let result = client.materialize(item: Data([1]), requestID: Data([7]), requestedHash: ItemToken.requestedContentHash(of: hashed.raw))
        XCTAssertEqual(daemon.requests[0]["requested_hash"] as? String, Data(repeating: 3, count: 32).hexString)
        if case .failure(.versionOutOfDate) = result {} else { XCTFail("a stale version must fail: \(result)") }
    }

    /// Without the App Group container the extension has no storage and never substitutes a private
    /// temporary directory the daemon cannot see.
    func testStorageFailsClosedWithoutTheGroupContainer() {
        XCTAssertEqual(ProviderStorage.decide(groupContainer: nil, domainID: "ab"), .unavailable)
        let group = URL(fileURLWithPath: "/group")
        XCTAssertEqual(
            ProviderStorage.decide(groupContainer: group, domainID: "ab"),
            .available(providerRoot: group.appendingPathComponent("provider", isDirectory: true), operationLog: group.appendingPathComponent("provider-ops-ab.json")))
        let client = ProviderClient(root: Data([9]), transport: UnavailableTransport(), log: OperationLog(url: FileManager.default.temporaryDirectory.appendingPathComponent("x-\(UUID().uuidString).json")))
        if case .failure(.unreachable) = client.item(Data([1])) {} else { XCTFail("an extension without storage must be unreachable") }
    }

    /// (U5) Absent, empty and literal values never share an operation identity: a modify with no
    /// name and a rename to "-" (or to "") are different operations.
    func testOverlappingOperationsHaveDistinctIdentities() {
        var plain = Change(kind: .modify)
        plain.item = Data([1]); plain.base = token(1, 5)
        var renamedDash = plain; renamedDash.name = "-"
        var renamedEmpty = plain; renamedEmpty.name = ""
        var moved = plain; moved.parent = Data()
        var movedDash = plain; movedDash.parent = Data([0x2d])
        var mode0 = plain; mode0.unixMode = 0
        var recursive = plain; recursive.recursive = true
        let ids = [plain, renamedDash, renamedEmpty, moved, movedDash, mode0, recursive].map(\.identity)
        XCTAssertEqual(Set(ids).count, ids.count, "two different operations share an identity: \(ids)")
        XCTAssertEqual(plain.identity, plain.identity)
    }

    /// A replayed conflict keeps its conflict outcome: the extension still refetches the
    /// canonical content, so stale local bytes never sit under the canonical token.
    func testAReplayedConflictStillNeedsARefetch() {
        let daemon = FakeTransport()
        let client = client(daemon)
        daemon.replies = [["ok": true, "outcome": 3, "replayed": true,
                           "item": ["item_id": "01", "name": "f", "content_version": token(1, 3).hex]]]
        var edit = Change(kind: .modify)
        edit.item = Data([1]); edit.base = token(1, 2); edit.ingestName = "c"; edit.size = 1
        guard case .success(let applied) = client.apply(edit) else { return XCTFail() }
        XCTAssertTrue(applied.replayed)
        XCTAssertEqual(applied.outcome, .concurrent)
        XCTAssertTrue(applied.needsRefetch)
    }

    func testEveryItemCanBeEvictedAndAReaderCannotChangeAnything() {
        for readOnly in [false, true] {
            for isDirectory in [false, true] {
                XCTAssertTrue(
                    itemCapabilities(isDirectory: isDirectory, readOnly: readOnly).contains(.evicting),
                    "Finder offers Remove Download only for items that allow eviction")
            }
        }
        let reader = itemCapabilities(isDirectory: false, readOnly: true)
        XCTAssertEqual(reader, [.reading, .evicting])
        XCTAssertTrue(itemCapabilities(isDirectory: true, readOnly: true).isDisjoint(
            with: [.writing, .renaming, .reparenting, .deleting, .addingSubItems]))
        XCTAssertTrue(itemCapabilities(isDirectory: false, readOnly: false).contains(.writing))
    }

    /// Logs may carry ids, generations and error classes, never the user's file or folder names or
    /// paths: a `privacy: .public` interpolation (or a host-log line) must not name them.
    func testNoLogLineCarriesAUserNameOrPathPublicly() throws {
        let macos = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let roots = ["YadoriLinkFileProvider/Extension", "YadoriLinkApp/App", "FileProviderCore/Sources"]
        let risky = try NSRegularExpression(
            pattern: #"\\\((?:[^()]|\([^()]*\))*\b(filename|displayName|path|location|url|name|container|suggestedName)\b(?:[^()]|\([^()]*\))*(?:, privacy: \.public)\)"#)
        let hostLine = try NSRegularExpression(
            pattern: #"HostLog\.line\(.*\\\((?:[^()]|\([^()]*\))*\b(displayName|location|container|path)\b"#)
        var offences: [String] = []
        for root in roots {
            let dir = macos.appendingPathComponent(root)
            let files = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL } ?? []
            for file in files where file.pathExtension == "swift" {
                let text = try String(contentsOf: file, encoding: .utf8)
                for (number, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                    let range = NSRange(line.startIndex..., in: line)
                    if risky.firstMatch(in: String(line), range: range) != nil || hostLine.firstMatch(in: String(line), range: range) != nil {
                        offences.append("\(file.lastPathComponent):\(number + 1)")
                    }
                }
            }
        }
        XCTAssertEqual(offences, [], "a log line names a user file, folder or path")
    }
}
