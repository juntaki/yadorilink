import Foundation

// The host app's provider logic, free of the FileProvider framework so it is unit-tested with fakes.
//
// NOTHING the OS reports about itself is evidence for the daemon's correctness decisions: evict,
// signal, wait and download results are answered as hints, and the materialized report carries
// membership only. What the driver must never do is register a domain before the namespace is
// queryable, or remove one when the daemon's snapshot is unavailable.

public struct HostFolder: Equatable, Sendable {
    public let root: Data
    public let displayName: String
    public let eager: Bool
    public let ready: Bool
    public let latestEvidenceSeq: UInt64
    public init(root: Data, displayName: String, eager: Bool, ready: Bool, latestEvidenceSeq: UInt64) {
        self.root = root; self.displayName = displayName; self.eager = eager
        self.ready = ready; self.latestEvidenceSeq = latestEvidenceSeq
    }
}

public enum EvictOutcome: Equatable, Sendable { case evicted, notMaterialized, busy, error(String) }
public enum DownloadOutcome: Equatable, Sendable { case accepted, rejected(String) }
public enum PrefetchOutcome: String, Sendable { case done, skipped, failed }

/// The daemon side: commands go out; folders are listed on demand (nil = the snapshot is unavailable).
public protocol HostLink: AnyObject {
    func send(_ command: [String: Any]) -> Bool
    func listFolders() -> HostSnapshot?
}

/// The daemon's confirmed answer: the domains it wants, and the domains it wants REMOVED (a durable
/// intent; the only authority to remove a domain).
public struct HostSnapshot: Equatable, Sendable {
    public let folders: [HostFolder]
    public let removals: [Data]
    public init(folders: [HostFolder], removals: [Data] = []) { self.folders = folders; self.removals = removals }
}

/// The OS side (an adapter over NSFileProviderManager). Every call is a HINT or an observation.
public protocol DomainControl: AnyObject {
    /// The registered domain identifiers (root ids as hex); nil when they cannot be read.
    func registeredDomains() -> Set<String>?
    func register(root: Data, displayName: String) -> Bool
    /// Removes a domain and PRESERVES downloaded user data. Returns where the OS kept the data (an
    /// empty string when it did not say), or nil when the removal failed.
    func remove(root: Data) -> String?
    func evict(root: Data, item: Data) -> EvictOutcome
    /// `signalEnumerator` for the parents/items (and the working set); the result is a hint.
    func signal(root: Data, items: [Data], parents: [Data], workingSet: Bool) -> Bool
    /// `waitForChanges` below `parent`, bounded by `timeout`: a HINT, never a release.
    func waitForChanges(root: Data, parent: Data, timeout: TimeInterval)
    /// The materialized item ids of the domain; nil when the enumeration failed.
    func materializedItems(root: Data) -> Set<Data>?
    func requestDownload(root: Data, item: Data) -> DownloadOutcome
    func prefetch(root: Data, folder: Data) -> PrefetchOutcome
    /// Tells the OS the errors it may be holding for this domain are resolved (the daemon is
    /// reachable again), so it retries the operations it gave up on (`signalErrorResolved` for the
    /// errors the extension maps: serverUnreachable, cannotSynchronize, insufficientQuota,
    /// notAuthenticated). A HINT: a failure is retried at the next connection.
    func signalErrorsResolved(root: Data) -> Bool
}

/// The two numbers the driver keeps across launches: the reporter epoch (strictly increasing) and the
/// highest acknowledged namespace revision per root (rollback detection).
public protocol DriverStore: AnyObject {
    /// A strictly increasing number, never reused: every FULL report takes a new one.
    func nextEpoch() -> UInt64
    func lastAcked(root: Data) -> UInt64
    func setLastAcked(root: Data, revision: UInt64)
    /// Whether this host ever OBSERVED the root's domain registered. Only that makes its later absence
    /// from a readable domain list a removal.
    func wasRegistered(root: Data) -> Bool
    func setRegistered(root: Data, _ registered: Bool)
    /// A removal the host OBSERVED (the user removed the domain) and has not yet seen the daemon apply:
    /// durable BEFORE the evidence is sent, cleared only when the daemon's snapshot no longer lists the
    /// root. While it is set the host never registers that root id again.
    func pendingRemoval(root: Data) -> Bool
    func setPendingRemoval(root: Data, _ pending: Bool)
    /// Every root with a pending removal marker.
    func pendingRemovalRoots() -> [Data]
    /// Where the OS kept the data of a domain this host removed, durable BEFORE the removal is reported:
    /// a crash between the OS removal and the report must not lose it. Cleared once the daemon no longer
    /// asks for the removal (it acknowledged it).
    func preservedLocation(root: Data) -> String?
    func setPreservedLocation(root: Data, _ location: String?)
    func removalLocationRoots() -> [Data]
}

public final class ProviderDriver {
    public static let pageSize = 2000
    public static let maxOutstandingDownloads = 2
    public static let waitTimeout: TimeInterval = 5
    /// The most all `waitForChanges` hints of one signal may take together.
    public static let waitTotal: TimeInterval = 15

    private let link: HostLink
    private let control: DomainControl
    private let store: DriverStore
    private let lock = NSLock()
    private var folders: [Data: HostFolder] = [:]
    private var reporters: [Data: Reporter] = [:]
    private var eager: [Data: EagerState] = [:]
    private var evidence: [Data: UInt64] = [:]
    private var paused: Set<Data> = []
    /// The roots whose download query awaits an answer, in the order asked: the daemon answers in order
    /// and the answer names no root.
    private var awaiting: [Data] = []

    private struct Reporter { var epoch: UInt64 = 0; var seq: UInt64 = 0; var snapshot: Set<Data>? = nil }
    /// Domains absent from the last readable domain list, and domains absent from the last daemon snapshot:
    /// a removal needs the absence in two CONSECUTIVE readings (a stale or racing list never removes).
    private var absentFromList: [Data: Int] = [:]
    /// A resent full report backs off (5 s doubling to 5 min) so a refusing daemon is never flooded.
    private var fullBackoff: [Data: (next: TimeInterval, delay: TimeInterval)] = [:]
    private let now: () -> TimeInterval
    private struct EagerState { var outstanding: Set<Data> = []; var awaiting = false; var done = false }

    public init(link: HostLink, control: DomainControl, store: DriverStore,
                now: @escaping () -> TimeInterval = { Date().timeIntervalSinceReferenceDate }) {
        self.link = link; self.control = control; self.store = store; self.now = now
    }

    /// The roots whose OS errors were declared resolved on this connection.
    private var resolvedRoots: Set<Data> = []

    /// The folders as of the last reconcile.
    public var knownFolders: [HostFolder] {
        lock.lock(); defer { lock.unlock() }
        return Array(folders.values)
    }

    // MARK: domains

    /// Reconciles the OS domains with the daemon's snapshot, reports each domain's state, and (re)starts
    /// the reporter of every registered root. Registration waits for `ready`; an unavailable snapshot
    /// or an unreadable domain list changes nothing.
    public func reconcile() {
        guard let snapshot = link.listFolders() else { return }
        let listed = control.registeredDomains()  // nil = UNKNOWN: it could not be read
        lock.lock()
        folders = Dictionary(uniqueKeysWithValues: snapshot.folders.map { ($0.root, $0) })
        for folder in snapshot.folders { evidence[folder.root] = max(evidence[folder.root] ?? 0, folder.latestEvidenceSeq) }
        lock.unlock()
        let desired = Set(snapshot.folders.map(\.root))
        let removals = Set(snapshot.removals)
        for folder in snapshot.folders {
            let root = folder.root, id = root.hexString
            // A removal this host observed and the daemon has not applied yet: report it again (idempotent),
            // and never register the old id meanwhile.
            if store.pendingRemoval(root: root) {
                sendState(root, "removed", preserved: "")
                continue
            }
            var state: String
            if let listed {
                if listed.contains(id) {
                    absentFromList[root] = nil
                    store.setRegistered(root: root, true)
                    state = "registered"
                } else if store.wasRegistered(root: root) {
                    // Observed registered, now absent from a readable list: the user removed it. Only once
                    // the absence is seen in two consecutive readings, and the observation is made DURABLE
                    // before it is reported, so a crash between the two cannot re-register the old id.
                    absentFromList[root, default: 0] += 1
                    if absentFromList[root]! >= 2 {
                        store.setPendingRemoval(root: root, true)
                        store.setRegistered(root: root, false)
                        absentFromList[root] = nil
                        lock.lock(); reporters[root] = nil; lock.unlock()
                        sendState(root, "removed", preserved: "")
                        continue
                    }
                    state = "unknown"
                } else if folder.ready, control.register(root: root, displayName: folder.displayName) {
                    store.setRegistered(root: root, true)
                    state = "registered"
                } else {
                    state = "not_registered"
                }
            } else {
                absentFromList[root] = nil
                state = "unknown"
            }
            sendState(root, state, preserved: "")
            // A (re)connected daemon is a healthy one: the OS may have stopped retrying operations that
            // failed while it was away (it gives up after a few attempts), so say once per connection
            // that those errors are resolved.
            if state == "registered" && !resolvedRoots.contains(root), control.signalErrorsResolved(root: root) {
                resolvedRoots.insert(root)
            }
            lock.lock(); let hasReporter = reporters[root] != nil; lock.unlock()
            if state == "registered" && !hasReporter { reportFull(root: root) }
        }
        // A marker clears when the daemon no longer lists the root: it applied the removal.
        for root in pendingRemovalRoots() where !desired.contains(root) { store.setPendingRemoval(root: root, false) }
        guard let listed else { return }
        for id in listed {
            guard let root = Data(hexString: id), !desired.contains(root) else { continue }
            if removals.contains(root) {
                // The daemon asked for this removal (durable intent): the ONLY thing that removes a
                // domain. Data is preserved; the location goes back with the evidence.
                if let location = control.remove(root: root) {
                    store.setPreservedLocation(root: root, location)
                    store.setRegistered(root: root, false)
                    lock.lock(); reporters[root] = nil; lock.unlock()
                    sendState(root, "removed", preserved: location)
                }
            } else {
                // A domain no root names (a lost or rolled-back database): KEPT, and reported.
                sendState(root, "orphan", preserved: "")
            }
        }
        // A requested removal whose domain is already gone (a crash after removing, before reporting):
        // report it so the daemon can finish.
        for root in removals where !listed.contains(root.hexString) {
            // The location recorded when this host removed the domain (empty only when it never learned
            // one: the report then says so explicitly, with an empty location).
            sendState(root, "removed", preserved: store.preservedLocation(root: root) ?? "")
        }
        // A location is kept only while the daemon still asks for the removal.
        for root in store.removalLocationRoots() where !removals.contains(root) {
            store.setPreservedLocation(root: root, nil)
        }
    }

    private func sendState(_ root: Data, _ evidence: String, preserved: String) {
        _ = link.send([
            "cmd": "domain_state", "root": root.hexString, "evidence": evidence,
            "last_acked": store.lastAcked(root: root), "preserved_location": preserved,
        ])
    }

    /// Roots this host has an unacknowledged observed removal for.
    private func pendingRemovalRoots() -> [Data] { store.pendingRemovalRoots() }

    // MARK: the materialized reporter

    /// A FULL snapshot in pages: one epoch per reporter start, consecutive sequence numbers from 1, the
    /// evidence sequence read BEFORE the enumeration, every page but the last marked `more`.
    public func reportFull(root: Data) {
        lock.lock()
        let observed = evidence[root] ?? 0
        lock.unlock()
        guard let items = control.materializedItems(root: root) else { return }
        // EVERY full snapshot is a new epoch (the daemon refuses a reused one).
        let epoch = store.nextEpoch()
        let sorted = items.sorted { $0.lexicographicallyPrecedes($1) }
        let pages = stride(from: 0, to: max(sorted.count, 1), by: Self.pageSize).map {
            Array(sorted[$0..<min($0 + Self.pageSize, sorted.count)])
        }
        var seq: UInt64 = 0
        for (index, page) in pages.enumerated() {
            seq += 1
            _ = link.send([
                "cmd": "report", "root": root.hexString, "epoch": epoch, "seq": seq, "full": true,
                "observed_after": observed, "upserts": page.map(\.hexString),
                "more": index < pages.count - 1,
            ])
        }
        lock.lock()
        reporters[root] = Reporter(epoch: epoch, seq: seq, snapshot: items)
        eager[root]?.outstanding.subtract(items)
        lock.unlock()
    }

    /// One reporter poll: a delta when the set changed (never before a full snapshot went out).
    public func reportTick(root: Data) {
        lock.lock()
        guard var reporter = reporters[root], let previous = reporter.snapshot else {
            lock.unlock(); return
        }
        let observed = evidence[root] ?? 0
        lock.unlock()
        guard let current = control.materializedItems(root: root) else { return }
        let added = current.subtracting(previous), removed = previous.subtracting(current)
        if added.isEmpty && removed.isEmpty { return }
        reporter.seq += 1
        reporter.snapshot = current
        lock.lock()
        reporters[root] = reporter
        // Content the OS now holds frees its Eager slot.
        eager[root]?.outstanding.subtract(added)
        lock.unlock()
        _ = link.send([
            "cmd": "report", "root": root.hexString, "epoch": reporter.epoch, "seq": reporter.seq, "full": false,
            "observed_after": observed, "upserts": added.map(\.hexString), "removed": removed.map(\.hexString),
            "more": false,
        ])
    }

    // MARK: the Eager driver

    /// Asks the daemon for the next downloads (a QUERY): at most two outstanding, the outstanding ids
    /// sent as exclusions. One query per root at a time; the answer arrives as a `downloads` event.
    public func eagerTick(root: Data) {
        lock.lock()
        guard folders[root]?.eager == true, !paused.contains(root) else { lock.unlock(); return }
        var state = eager[root] ?? EagerState()
        // At capacity the query still goes out with room 0: its answer carries the SETTLED ids, the
        // only way a slot is freed when no other evidence arrives.
        let room = max(0, Self.maxOutstandingDownloads - state.outstanding.count)
        if state.awaiting { lock.unlock(); return }
        state.awaiting = true
        eager[root] = state
        awaiting.append(root)
        let exclusions = state.outstanding
        lock.unlock()
        _ = link.send([
            "cmd": "next_downloads", "root": root.hexString, "exclude": exclusions.map(\.hexString), "max": room,
        ])
    }

    /// A download the OS finished (or abandoned): its slot is free again.
    public func downloadFinished(root: Data, item: Data) {
        lock.lock(); eager[root]?.outstanding.remove(item); lock.unlock()
    }

    public func outstandingDownloads(root: Data) -> Set<Data> {
        lock.lock(); defer { lock.unlock() }
        return eager[root]?.outstanding ?? []
    }

    // MARK: daemon events

    public func handle(_ event: [String: Any]) {
        guard let kind = event["event"] as? String else { return }
        let root = Data(hexString: event["root"] as? String ?? "")
        switch kind {
        case "evict": if let root { evict(root, event) }
        case "changed": changed(root, event)
        case "evidence_tick":
            if let root {
                lock.lock(); evidence[root] = max(evidence[root] ?? 0, (event["seq"] as? NSNumber)?.uint64Value ?? 0); lock.unlock()
            }
        case "report_ack": if let root { acknowledged(root, event) }
        case "prefetch_control":
            if let root {
                lock.lock()
                if event["paused"] as? Bool == true { paused.insert(root) } else { paused.remove(root) }
                lock.unlock()
            }
        case "prefetch_hint": if let root { prefetch(root, event) }
        case "downloads": downloads(event)
        default: break
        }
    }

    /// An acknowledgement counts only for the reporter's CURRENT epoch; `needs_full` restarts the snapshot
    /// with a new epoch, at most once per backoff period (5 s doubling to 5 min).
    private func acknowledged(_ root: Data, _ event: [String: Any]) {
        let epoch = (event["epoch"] as? NSNumber)?.uint64Value ?? 0
        lock.lock()
        let current = reporters[root]?.epoch
        lock.unlock()
        guard epoch == current else { return }
        guard event["needs_full"] as? Bool == true else {
            lock.lock(); fullBackoff[root] = nil; lock.unlock()
            return
        }
        let t = now()
        lock.lock()
        let gate = fullBackoff[root]
        if let gate, t < gate.next { lock.unlock(); return }
        let delay = min((gate?.delay ?? 2.5) * 2, 300)
        fullBackoff[root] = (next: t + delay, delay: delay)
        lock.unlock()
        reportFull(root: root)
    }

    private func evict(_ root: Data, _ event: [String: Any]) {
        guard let item = Data(hexString: event["item"] as? String ?? "") else { return }
        var done: [String: Any] = ["cmd": "evict_done", "root": root.hexString, "request_id": event["request_id"] as? String ?? ""]
        switch control.evict(root: root, item: item) {
        case .evicted: done["result"] = "evicted"
        case .notMaterialized: done["result"] = "not_materialized"
        case .busy: done["result"] = "busy"
        case .error(let message): done["result"] = "error"; done["error"] = message
        }
        _ = link.send(done)
    }

    private func changed(_ root: Data?, _ event: [String: Any]) {
        let items = (event["items"] as? [String] ?? []).compactMap { Data(hexString: $0) }
        let parents = (event["parents"] as? [String] ?? []).compactMap { Data(hexString: $0) }
        // A message naming a root we do not know, and no items: the set of folders changed.
        lock.lock(); let known = root.map { folders[$0] != nil } ?? false; lock.unlock()
        guard let root, known else {
            if items.isEmpty { reconcile() }
            return
        }
        let revision = (event["revision"] as? NSNumber)?.uint64Value ?? 0
        let ok = control.signal(root: root, items: items, parents: parents, workingSet: event["working_set"] as? Bool ?? false)
        // `waitForChanges` is only a hint, bounded in total (parents x 5 s must not hold the queue);
        // its completion releases nothing.
        let deadline = now() + Self.waitTotal
        for parent in parents {
            let remaining = deadline - now()
            if remaining <= 0 { break }
            control.waitForChanges(root: root, parent: parent, timeout: min(Self.waitTimeout, remaining))
        }
        // A signal that timed out or failed is NOT acknowledged: the anchor only advances on success.
        if ok { store.setLastAcked(root: root, revision: max(revision, store.lastAcked(root: root))) }
        _ = link.send([
            "cmd": "signal_done", "root": root.hexString, "revision": revision, "ok": ok,
            "request_id": event["request_id"] as? String ?? "",
        ])
    }

    private func prefetch(_ root: Data, _ event: [String: Any]) {
        let hint = (event["hint_id"] as? NSNumber)?.uint64Value ?? 0
        lock.lock(); let isPaused = paused.contains(root); lock.unlock()
        for folder in (event["folders"] as? [String] ?? []).compactMap({ Data(hexString: $0) }) {
            let result: PrefetchOutcome = isPaused ? .skipped : control.prefetch(root: root, folder: folder)
            _ = link.send(["cmd": "prefetch_done", "root": root.hexString, "hint_id": hint,
                           "folder": folder.hexString, "result": result.rawValue])
        }
    }

    private func downloads(_ event: [String: Any]) {
        // The answer names no root: it belongs to the root whose query is awaiting.
        lock.lock()
        guard !awaiting.isEmpty else { lock.unlock(); return }
        let target = awaiting.removeFirst()
        var state = eager[target] ?? EagerState()
        state.awaiting = false
        for settled in (event["settled"] as? [String] ?? []).compactMap({ Data(hexString: $0) }) {
            state.outstanding.remove(settled)
        }
        state.done = (event["state"] as? NSNumber)?.intValue == 5
        eager[target] = state
        lock.unlock()
        for download in event["downloads"] as? [[String: Any]] ?? [] {
            guard let item = Data(hexString: download["item"] as? String ?? "") else { continue }
            lock.lock()
            let room = (eager[target]?.outstanding.count ?? 0) < Self.maxOutstandingDownloads
            lock.unlock()
            guard room else { break }
            switch control.requestDownload(root: target, item: item) {
            case .accepted:
                lock.lock(); eager[target]?.outstanding.insert(item); lock.unlock()
            case .rejected(let error):
                _ = link.send(["cmd": "download_rejected", "root": target.hexString, "item": item.hexString, "error": error])
            }
        }
    }

    public func isEagerDone(root: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return eager[root]?.done ?? false
    }
}


/// What the OS may do with an item. The mapping onto `NSFileProviderItemCapabilities` lives in the
/// extension; this is the decision, so it is testable without the framework.
public enum ItemCapability: Hashable {
    case reading, writing, renaming, reparenting, deleting, enumerating, addingSubItems
    /// "Remove Download" in Finder and system eviction. Without it the item is never evicted (the
    /// menu entry is absent). An eviction is only ever a request: the daemon never takes its success
    /// as evidence that the bytes are gone or present.
    case evicting
}

/// A Reader sees the namespace and may free local space, but cannot change anything.
public func itemCapabilities(isDirectory: Bool, readOnly: Bool) -> Set<ItemCapability> {
    if readOnly {
        return isDirectory ? [.reading, .enumerating, .evicting] : [.reading, .evicting]
    }
    if isDirectory {
        return [.reading, .enumerating, .addingSubItems, .renaming, .reparenting, .deleting, .evicting]
    }
    return [.reading, .writing, .renaming, .reparenting, .deleting, .evicting]
}
