import XCTest
@testable import FileProviderCore

final class FakeLink: HostLink {
    var folders: [HostFolder]? = []
    var removals: [Data] = []
    var sent: [[String: Any]] = []
    func send(_ command: [String: Any]) -> Bool { sent.append(command); return true }
    func listFolders() -> HostSnapshot? { folders.map { HostSnapshot(folders: $0, removals: removals) } }
    func commands(_ name: String) -> [[String: Any]] { sent.filter { $0["cmd"] as? String == name } }
}

final class FakeControl: DomainControl {
    var registered: Set<String>? = []
    var materialized: Set<Data>? = []
    var evictResult: EvictOutcome = .evicted
    var downloadResult: DownloadOutcome = .accepted
    var signalOK = true
    private(set) var added: [Data] = [], removed: [Data] = [], requested: [Data] = [], waited: [Data] = []
    func registeredDomains() -> Set<String>? { registered }
    func register(root: Data, displayName: String) -> Bool { added.append(root); registered?.insert(root.hexString); return true }
    func remove(root: Data) -> String? { removed.append(root); registered?.remove(root.hexString); return "/kept/\(root.hexString.prefix(4))" }
    func evict(root: Data, item: Data) -> EvictOutcome { evictResult }
    func signal(root: Data, items: [Data], parents: [Data], workingSet: Bool) -> Bool { signalOK }
    var onWait: ((TimeInterval) -> Void)?
    func waitForChanges(root: Data, parent: Data, timeout: TimeInterval) { waited.append(parent); onWait?(timeout) }
    func materializedItems(root: Data) -> Set<Data>? { materialized }
    func requestDownload(root: Data, item: Data) -> DownloadOutcome { requested.append(item); return downloadResult }
    func prefetch(root: Data, folder: Data) -> PrefetchOutcome { .done }
    var resolveOK = true
    private(set) var resolved: [Data] = []
    func signalErrorsResolved(root: Data) -> Bool { resolved.append(root); return resolveOK }
}

final class FakeStore: DriverStore {
    var epochs: UInt64 = 0
    var acked: [Data: UInt64] = [:]
    func nextEpoch() -> UInt64 { epochs += 1; return epochs }
    func lastAcked(root: Data) -> UInt64 { acked[root] ?? 0 }
    func setLastAcked(root: Data, revision: UInt64) { acked[root] = revision }
    var registeredRoots: Set<Data> = []
    var locations: [Data: String] = [:]
    func preservedLocation(root: Data) -> String? { locations[root] }
    func setPreservedLocation(root: Data, _ location: String?) { locations[root] = location }
    func removalLocationRoots() -> [Data] { Array(locations.keys) }
    var pending: Set<Data> = []
    func pendingRemoval(root: Data) -> Bool { pending.contains(root) }
    func setPendingRemoval(root: Data, _ p: Bool) { if p { pending.insert(root) } else { pending.remove(root) } }
    func pendingRemovalRoots() -> [Data] { Array(pending) }
    func wasRegistered(root: Data) -> Bool { registeredRoots.contains(root) }
    func setRegistered(root: Data, _ registered: Bool) {
        if registered { registeredRoots.insert(root) } else { registeredRoots.remove(root) }
    }
}

private func root(_ b: UInt8) -> Data { Data(repeating: b, count: 16) }
private func item(_ n: Int) -> Data { Data([UInt8(n >> 8), UInt8(n & 255)] + [UInt8](repeating: 0, count: 14)) }

final class ProviderDriverTests: XCTestCase {
    private func driver(_ link: FakeLink, _ control: FakeControl, _ store: FakeStore = FakeStore()) -> ProviderDriver {
        ProviderDriver(link: link, control: control, store: store)
    }

    /// Registration waits for a queryable namespace; an unavailable snapshot or an unreadable domain list
    /// changes nothing; a root absent from a CONFIRMED snapshot is removed, a root not ready is not.
    func testRegistrationRules() {
        let link = FakeLink(), control = FakeControl()
        let d = driver(link, control)
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: false, latestEvidenceSeq: 0)]
        d.reconcile()
        XCTAssertTrue(control.added.isEmpty, "a domain was registered before the namespace was queryable")
        link.folders![0] = HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)
        d.reconcile()
        XCTAssertEqual(control.added, [root(1)])

        control.registered = [root(1).hexString, root(2).hexString]
        link.folders = nil
        d.reconcile()
        XCTAssertTrue(control.removed.isEmpty, "a domain was removed with no snapshot")
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        control.registered = nil
        d.reconcile()
        XCTAssertTrue(control.removed.isEmpty, "a domain was removed when the domain list was unreadable")
        // A domain no root names is an ORPHAN: kept however many snapshots omit it, and reported.
        control.registered = [root(1).hexString, root(2).hexString, root(3).hexString]
        link.folders!.append(HostFolder(root: root(3), displayName: "C", eager: false, ready: false, latestEvidenceSeq: 0))
        for _ in 0..<3 { d.reconcile() }
        XCTAssertTrue(control.removed.isEmpty, "an orphan domain was removed on absence alone")
        XCTAssertEqual(link.commands("domain_state").last { $0["root"] as? String == root(2).hexString }?["evidence"] as? String, "orphan")
        // The daemon's durable removal intent is the only authority: then it goes, data preserved, and the
        // location the OS kept is reported back.
        link.removals = [root(2)]
        d.reconcile()
        XCTAssertEqual(control.removed, [root(2)])
        let done = link.commands("domain_state").last { $0["root"] as? String == root(2).hexString }
        XCTAssertEqual(done?["evidence"] as? String, "removed")
        XCTAssertEqual(done?["preserved_location"] as? String, "/kept/\(root(2).hexString.prefix(4))")
        // A requested removal whose domain is already gone is reported again, not retried.
        control.registered = [root(1).hexString, root(3).hexString]
        let before = control.removed.count
        d.reconcile()
        XCTAssertEqual(control.removed.count, before)
        XCTAssertEqual(link.commands("domain_state").last { $0["root"] as? String == root(2).hexString }?["evidence"] as? String, "removed")
    }

    /// (review) The waits below parents are bounded IN TOTAL: many parents cannot hold the queue for
    /// parents x 5 s, and the acknowledgement still goes out.
    func testStuckOSErrorsAreDeclaredResolvedOncePerConnectionForRegisteredRootsOnly() {
        let link = FakeLink(), control = FakeControl()
        let d = driver(link, control)
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: false, latestEvidenceSeq: 0)]
        d.reconcile()
        XCTAssertTrue(control.resolved.isEmpty, "nothing is registered yet, so there is no OS error to resolve")
        link.folders![0] = HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)
        d.reconcile()
        XCTAssertEqual(control.resolved, [root(1)])
        d.reconcile(); d.reconcile()
        XCTAssertEqual(control.resolved, [root(1)], "once per connection, not on every reconcile")
        // A new connection is a new driver: the OS is told again.
        let next = driver(link, control)
        next.reconcile()
        XCTAssertEqual(control.resolved, [root(1), root(1)])
    }

    func testAFailedResolveSignalIsRetriedAtTheNextReconcile() {
        let link = FakeLink(), control = FakeControl()
        control.resolveOK = false
        let d = driver(link, control)
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        d.reconcile(); d.reconcile()
        XCTAssertEqual(control.resolved.count, 2)
        control.resolveOK = true
        d.reconcile(); d.reconcile()
        XCTAssertEqual(control.resolved.count, 3)
    }

    func testTheWaitsBelowParentsHaveAnOverallDeadline() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        var clock: TimeInterval = 100
        let d = ProviderDriver(link: link, control: control, store: store, now: { clock })
        d.reconcile()
        control.onWait = { timeout in clock += timeout }   // every wait uses its whole allowance
        let parents = (0..<10).map { item($0).hexString }
        d.handle(["event": "changed", "root": root(1).hexString, "revision": 3, "items": [], "parents": parents, "request_id": "01"])
        XCTAssertEqual(control.waited.count, 3, "the waits were not bounded in total: \(control.waited.count)")
        XCTAssertEqual(link.commands("signal_done").last?["ok"] as? Bool, true)
    }

    /// (review) The location the OS kept is durable BEFORE the removal is reported: after a crash that lost the
    /// report, the restarted host (domain already gone) reports the SAME location, not an empty one, and
    /// forgets it once the daemon stops asking.
    func testAPreservedLocationSurvivesACrashBeforeTheReport() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        link.folders = []
        link.removals = [root(2)]
        control.registered = [root(2).hexString]
        driver(link, control, store).reconcile()
        let expected = "/kept/\(root(2).hexString.prefix(4))"
        XCTAssertEqual(store.locations[root(2)], expected, "the location was not durable")
        // Crash: the report was lost; a new host sees the domain already gone.
        link.sent.removeAll()
        driver(link, control, store).reconcile()
        let again = link.commands("domain_state").last { $0["root"] as? String == root(2).hexString }
        XCTAssertEqual(again?["evidence"] as? String, "removed")
        XCTAssertEqual(again?["preserved_location"] as? String, expected)
        // The daemon acknowledged: it no longer asks, the location is forgotten.
        link.removals = []
        driver(link, control, store).reconcile()
        XCTAssertNil(store.locations[root(2)])
    }

    /// The host makes an OBSERVED removal durable BEFORE it reports it: after a crash with the report
    /// lost, the restarted host never registers the old id again, and reports the removal until the daemon's
    /// snapshot stops listing the root.
    func testAnObservedRemovalSurvivesACrashBeforeItIsReported() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        let first = driver(link, control, store)
        first.reconcile()                       // registers
        XCTAssertEqual(control.added, [root(1)])
        control.registered = []                 // the user removes the domain in the OS
        first.reconcile()                       // first absence: nothing yet
        link.sent.removeAll()
        XCTAssertTrue(store.pending.isEmpty)
        // The second absence: the marker is written, then the report is attempted. Simulate a crash that
        // loses the report by dropping the driver after the marker exists.
        first.reconcile()
        XCTAssertEqual(store.pending, [root(1)], "the observation was not durable")
        // A new host process (same store), the daemon never heard of the removal.
        link.sent.removeAll()
        let second = driver(link, control, store)
        second.reconcile()
        XCTAssertEqual(control.added, [root(1)], "the old id was registered again after the crash")
        XCTAssertEqual(link.commands("domain_state").last?["evidence"] as? String, "removed", "the removal was not re-reported")
        // The daemon applied it: the old root is gone from the snapshot, the marker clears.
        link.folders = []
        second.reconcile()
        XCTAssertTrue(store.pending.isEmpty)
    }

    /// The domain state is reported with the highest acknowledged revision.
    func testDomainStateCarriesTheAcknowledgedRevision() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        store.acked[root(1)] = 42
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        driver(link, control, store).reconcile()
        let state = link.commands("domain_state").first
        XCTAssertEqual(state?["evidence"] as? String, "registered")
        XCTAssertEqual(state?["last_acked"] as? UInt64, 42)
    }

    /// A full snapshot is paged: consecutive sequence numbers from 1, one epoch, the evidence sequence
    /// read before, every page but the last `more`; later changes are deltas with the next sequence;
    /// `needs_full` starts the snapshot again.
    func testTheReporterPagesAFullSnapshotThenSendsDeltas() {
        let link = FakeLink(), control = FakeControl()
        control.materialized = Set((0..<(ProviderDriver.pageSize + 5)).map(item))
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 9)]
        let d = driver(link, control)
        d.reconcile()
        let pages = link.commands("report")
        XCTAssertEqual(pages.count, 2)
        XCTAssertEqual(pages.map { $0["seq"] as? UInt64 }, [1, 2])
        XCTAssertEqual(pages.map { $0["more"] as? Bool }, [true, false])
        XCTAssertEqual(Set(pages.map { $0["epoch"] as? UInt64 }).count, 1)
        XCTAssertEqual(pages.map { $0["observed_after"] as? UInt64 }, [9, 9])

        control.materialized!.insert(item(60_000)); control.materialized!.remove(item(0))
        d.reportTick(root: root(1))
        let delta = link.commands("report").last!
        XCTAssertEqual(delta["full"] as? Bool, false)
        XCTAssertEqual(delta["seq"] as? UInt64, 3)
        XCTAssertEqual((delta["upserts"] as? [String])?.count, 1)
        XCTAssertEqual((delta["removed"] as? [String])?.count, 1)
        d.reportTick(root: root(1))
        XCTAssertEqual(link.commands("report").count, 3, "an unchanged set sent a delta")

        let firstEpoch = pages[0]["epoch"] as? UInt64
        d.handle(["event": "report_ack", "root": root(1).hexString, "epoch": firstEpoch as Any, "needs_full": true])
        let again = link.commands("report").suffix(2)
        XCTAssertEqual(again.map { $0["seq"] as? UInt64 }, [1, 2], "needs_full did not restart the snapshot")
        XCTAssertEqual(again.first?["full"] as? Bool, true)
        XCTAssertGreaterThan(again.first?["epoch"] as? UInt64 ?? 0, firstEpoch ?? 0, "a restarted snapshot reused its epoch")
    }

    /// A periodic reconcile never resends a full report, a refusal of the CURRENT epoch restarts
    /// the snapshot with a NEW epoch at most once per backoff period, and an acknowledgement of an old
    /// epoch is ignored.
    func testReporterRecoveryMintsNewEpochsAndBacksOff() {
        let link = FakeLink(), control = FakeControl()
        control.materialized = [item(1)]
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        var clock: TimeInterval = 1000
        let d = ProviderDriver(link: link, control: control, store: FakeStore(), now: { clock })
        d.reconcile(); d.reconcile(); d.reconcile()
        XCTAssertEqual(link.commands("report").count, 1, "reconcile resent a full report")
        func refuse(_ epoch: UInt64) {
            d.handle(["event": "report_ack", "root": root(1).hexString, "epoch": epoch, "needs_full": true])
        }
        refuse(99)
        XCTAssertEqual(link.commands("report").count, 1, "an ack for another epoch was acted on")
        refuse(1)
        XCTAssertEqual(link.commands("report").count, 2)
        refuse(2); refuse(2)
        XCTAssertEqual(link.commands("report").count, 2, "a refusal storm was answered immediately")
        clock += 301
        refuse(2)
        XCTAssertEqual(link.commands("report").count, 3)
        XCTAssertEqual(link.commands("report").map { $0["epoch"] as? UInt64 }, [1, 2, 3])
    }

    /// Only a removal OBSERVED twice in a readable domain list of a domain this host saw registered is
    /// reported as removed. An unreadable list, a not-ready root and a first absence report nothing.
    func testRemovalEvidenceIsObservedNeverGuessed() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: false, latestEvidenceSeq: 0)]
        let d = driver(link, control, store)
        func last() -> String? { link.commands("domain_state").last?["evidence"] as? String }
        d.reconcile()
        XCTAssertEqual(last(), "not_registered")
        control.registered = nil
        d.reconcile()
        XCTAssertEqual(last(), "unknown", "an unreadable list was reported as something")
        link.folders![0] = HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)
        control.registered = []
        d.reconcile()
        XCTAssertEqual(last(), "registered")
        control.registered = []  // the user removed the domain in the OS
        d.reconcile()
        XCTAssertEqual(last(), "unknown", "one absence was reported as a removal")
        control.registered = nil
        d.reconcile()
        control.registered = []
        d.reconcile()
        XCTAssertEqual(last(), "unknown", "an unreadable list between the readings did not reset the count")
        d.reconcile()
        XCTAssertEqual(last(), "removed")
    }

    /// Eager: at most two outstanding, the outstanding ids as exclusions, settled ids freed, a rejection
    /// reported to the daemon; nothing is asked of a paused or non-Eager root.
    func testTheEagerLoopRespectsItsLimits() {
        let link = FakeLink(), control = FakeControl()
        link.folders = [
            HostFolder(root: root(1), displayName: "A", eager: true, ready: true, latestEvidenceSeq: 0),
            HostFolder(root: root(2), displayName: "B", eager: false, ready: true, latestEvidenceSeq: 0),
        ]
        let d = driver(link, control)
        d.reconcile()
        d.eagerTick(root: root(2))
        XCTAssertTrue(link.commands("next_downloads").isEmpty, "a non-Eager root was queried")
        d.eagerTick(root: root(1))
        d.eagerTick(root: root(1))
        XCTAssertEqual(link.commands("next_downloads").count, 1, "two queries were in flight")
        XCTAssertEqual(link.commands("next_downloads")[0]["max"] as? Int, 2)
        let wanted = (1...3).map { ["item": item($0).hexString, "version": "00"] }
        d.handle(["event": "downloads", "downloads": wanted, "settled": [], "state": 1])
        XCTAssertEqual(control.requested, [item(1), item(2)], "more than two downloads were outstanding")
        XCTAssertEqual(d.outstandingDownloads(root: root(1)), [item(1), item(2)])
        // At capacity the query still goes out, with no room: its answer settles finished ids.
        d.eagerTick(root: root(1))
        XCTAssertEqual(link.commands("next_downloads").count, 2)
        XCTAssertEqual(link.commands("next_downloads").last?["max"] as? Int, 0, "a query asked for room it did not have")
        d.handle(["event": "downloads", "downloads": [], "settled": [item(1).hexString], "state": 1])
        XCTAssertEqual(d.outstandingDownloads(root: root(1)), [item(2)], "a settled id kept its slot")
        d.eagerTick(root: root(1))
        let query = link.commands("next_downloads").last!
        XCTAssertEqual(query["max"] as? Int, 1)
        XCTAssertEqual(query["exclude"] as? [String], [item(2).hexString])
        d.handle(["event": "downloads", "downloads": [], "settled": [item(2).hexString], "state": 5])
        XCTAssertTrue(d.outstandingDownloads(root: root(1)).isEmpty)
        XCTAssertTrue(d.isEagerDone(root: root(1)))

        control.downloadResult = .rejected("no space")
        d.eagerTick(root: root(1))
        d.handle(["event": "downloads", "downloads": [["item": item(9).hexString, "version": "00"]], "settled": [], "state": 1])
        XCTAssertEqual(link.commands("download_rejected").first?["item"] as? String, item(9).hexString)
        XCTAssertTrue(d.outstandingDownloads(root: root(1)).isEmpty, "a rejected download took a slot")

        d.handle(["event": "prefetch_control", "root": root(1).hexString, "paused": true])
        let before = link.commands("next_downloads").count
        d.eagerTick(root: root(1))
        XCTAssertEqual(link.commands("next_downloads").count, before, "a paused root was queried")
    }

    /// Evict and signal requests are answered as hints with the daemon's own ids; a refused signal is
    /// not acknowledged; the acknowledged revision never goes back; a message naming an unknown root
    /// without items relists the folders.
    func testEvictAndSignalAreAnsweredAsHints() {
        let link = FakeLink(), control = FakeControl(), store = FakeStore()
        link.folders = [HostFolder(root: root(1), displayName: "A", eager: false, ready: true, latestEvidenceSeq: 0)]
        let d = driver(link, control, store)
        d.reconcile()
        control.evictResult = .busy
        d.handle(["event": "evict", "root": root(1).hexString, "item": item(1).hexString, "request_id": "0a"])
        XCTAssertEqual(link.commands("evict_done").last?["result"] as? String, "busy")
        XCTAssertEqual(link.commands("evict_done").last?["request_id"] as? String, "0a")

        d.handle(["event": "changed", "root": root(1).hexString, "revision": 7, "items": [item(1).hexString], "parents": [Data().hexString], "request_id": "0b"])
        XCTAssertEqual(link.commands("signal_done").last?["ok"] as? Bool, true)
        XCTAssertEqual(link.commands("signal_done").last?["request_id"] as? String, "0b", "the acknowledgement lost its correlation id")
        XCTAssertEqual(control.waited, [Data()], "the wait below the parent was not requested")
        XCTAssertEqual(store.acked[root(1)], 7)
        control.signalOK = false
        d.handle(["event": "changed", "root": root(1).hexString, "revision": 9, "items": [item(1).hexString], "parents": []])
        XCTAssertEqual(link.commands("signal_done").last?["ok"] as? Bool, false)
        XCTAssertEqual(store.acked[root(1)], 7, "a refused signal was acknowledged")

        let listed = link.commands("domain_state").count
        d.handle(["event": "changed", "root": root(9).hexString, "revision": 1, "items": [], "parents": []])
        XCTAssertGreaterThan(link.commands("domain_state").count, listed, "an unknown root did not relist the folders")
    }
}
