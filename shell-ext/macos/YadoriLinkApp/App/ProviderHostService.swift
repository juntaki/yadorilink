//
//  ProviderHostService.swift — the menu-bar app's provider duties.
//
//  One persistent connection to the daemon (the daemon's ATTACHED HOST) carries: the domain state, the
//  materialized-items report, evict and signal answers, the Eager download query and prefetch relays.
//  The logic lives in `ProviderDriver` (FileProviderCore, unit-tested with fakes); this file only adapts
//  it to the real world: the Rust host connection, `NSFileProviderManager`, UserDefaults and timers.
//
//  Everything the OS says about itself here is a HINT or an observation for the daemon, never a
//  correctness input. UNVERIFIED (no signed build or Finder here): every `NSFileProviderManager` call
//  below, the materialized-set enumeration, `waitForChanges`, `requestDownloadForItem` and the
//  user-visible-URL prefetch behave as the SDK headers describe.

import FileProvider
import FileProviderCore
import Foundation
import os

/// What the host did and why it failed, once per attempt: to os_log and to
/// `~/Library/Logs/YadoriLink/provider-host.log` (the first place to look when a domain does not
/// appear; a failed add is otherwise silent). Not the App Group container: the host holds no group
/// entitlement and the OS refuses its writes there.
enum HostLog {
    /// An error as a log line may carry it: its domain and code, never its description (which can
    /// quote a file or folder name and a path).
    static func errorClass(_ error: Error?) -> String {
        guard let error else { return "none" }
        let ns = error as NSError
        return "\(ns.domain) \(ns.code)"
    }

    private static let logger = Logger(subsystem: "com.juntaki.yadorilink.host", category: "provider")
    private static let lock = NSLock()

    static func line(_ text: String) {
        logger.notice("\(text, privacy: .public)")
        let stamp = ISO8601DateFormatter().string(from: Date())
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/YadoriLink", isDirectory: true)
        let url = directory.appendingPathComponent("provider-host.log")
        lock.lock()
        defer { lock.unlock() }
        let data = Data("\(stamp) \(text)\n".utf8)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            do { try data.write(to: url) } catch {
                logger.error("cannot write the host log: \(HostLog.errorClass(error), privacy: .public)")
            }
        }
    }
}

/// The daemon's item id as the OS identifier (empty = the root container).
private func identifier(_ id: Data) -> NSFileProviderItemIdentifier {
    id.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(id.hexString)
}

/// The Rust host connection as the driver's `HostLink`.
final class FFIHostLink: HostLink {
    private var host: OpaquePointer?
    private let onEvent: ([String: Any]) -> Void

    init(onEvent: @escaping ([String: Any]) -> Void) { self.onEvent = onEvent }

    /// Opens the connection; false while the daemon is unreachable.
    func connect() -> Bool {
        let context = Unmanaged.passUnretained(self).toOpaque()
        host = yadorilink_fp_host_open({ event, context in
            guard let event, let context else { return }
            let link = Unmanaged<FFIHostLink>.fromOpaque(context).takeUnretainedValue()
            if let data = String(cString: event).data(using: .utf8),
                let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            {
                link.onEvent(json)
            }
        }, context)
        return host != nil
    }

    func close() {
        if let host { yadorilink_fp_host_close(host) }
        host = nil
    }

    func send(_ command: [String: Any]) -> Bool {
        guard let host, let data = try? JSONSerialization.data(withJSONObject: command),
            let text = String(data: data, encoding: .utf8)
        else { return false }
        return text.withCString { yadorilink_fp_host_send(host, $0) }
    }

    /// `nil` = the snapshot is unavailable (distinct from a confirmed empty list).
    func listFolders() -> HostSnapshot? {
        // The container the OS gave THIS process: the daemon adopts it rather than guessing a path.
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: ProviderHostService.groupIdentifier)?.path ?? ""
        guard let json = container.withCString({ yadorilink_fp_list_provider_folders($0) }) else {
            HostLog.line("list provider folders: no answer from the daemon")
            return nil
        }
        defer { yadorilink_fp_free_string(json) }
        struct Folder: Decodable {
            let root_id: String, display_name: String, hydration_policy: String
            let registration_ready: Bool, latest_evidence_seq: UInt64
        }
        struct Removal: Decodable { let root_id: String, display_name: String }
        struct Snapshot: Decodable { let folders: [Folder], removals: [Removal] }
        guard let data = String(cString: json).data(using: .utf8),
            let snapshot = try? JSONDecoder().decode(Snapshot.self, from: data)
        else {
            HostLog.line("list provider folders: unreadable answer")
            return nil
        }
        let folders: [HostFolder] = snapshot.folders.compactMap { folder in
            Data(hexString: folder.root_id).map {
                HostFolder(root: $0, displayName: folder.display_name, eager: folder.hydration_policy == "eager",
                           ready: folder.registration_ready, latestEvidenceSeq: folder.latest_evidence_seq)
            }
        }
        let removals: [Data] = snapshot.removals.compactMap { Data(hexString: $0.root_id) }
        HostLog.line("daemon lists \(folders.count) provider folder(s), \(removals.count) removal(s)")
        return HostSnapshot(folders: folders, removals: removals)
    }
}

/// The OS side. Calls block (a semaphore) and so run on the service's own queue, never the main thread.
final class OSDomainControl: DomainControl {
    /// Runs `body` and waits for its completion at most `timeout`. `true` only when it COMPLETED in time: a
    /// timeout is `false`, so a caller never reads "no answer" as success.
    @discardableResult
    private func wait(_ timeout: TimeInterval = 30, _ body: (@escaping () -> Void) -> Void) -> Bool {
        let done = DispatchSemaphore(value: 0)
        body { done.signal() }
        return done.wait(timeout: .now() + timeout) == .success
    }

    private func manager(_ root: Data) -> NSFileProviderManager? {
        NSFileProviderManager(for: NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(root.hexString), displayName: ""))
    }

    func registeredDomains() -> Set<String>? {
        var result: Set<String>?
        let completed = wait { finish in
            NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
                if error == nil { result = Set(domains.map { $0.identifier.rawValue }) }
                else { HostLog.line("list domains failed: \(HostLog.errorClass(error))") }
                finish()
            }
        }
        if !completed { HostLog.line("list domains: no answer in time") }
        return result
    }

    func register(root: Data, displayName: String) -> Bool {
        var ok = false
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(root.hexString), displayName: displayName)
        var failure: Error?
        let completed = wait { finish in
            NSFileProviderManager.add(domain) { error in ok = error == nil; failure = error; finish() }
        }
        if ok { HostLog.line("add domain \(root.hexString): ok") }
        else if !completed { HostLog.line("add domain \(root.hexString): no answer in time") }
        else { HostLog.line("add domain \(root.hexString): failed: \(HostLog.errorClass(failure))") }
        return ok
    }

    /// `.preserveDownloadedUserData`: the plain removal deletes the managed location and the user's
    /// hydrated and locally written content with it. The location the OS kept the data at is
    /// returned (empty when it did not say); nil when the removal failed.
    func remove(root: Data) -> String? {
        var location: String?
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(root.hexString), displayName: "")
        var failure: Error?
        let completed = wait { finish in
            NSFileProviderManager.remove(domain, mode: .preserveDownloadedUserData) { url, error in
                if error == nil { location = url?.path ?? "" }
                failure = error
                finish()
            }
        }
        if location != nil { HostLog.line("remove domain \(root.hexString): ok") }
        else if !completed { HostLog.line("remove domain \(root.hexString): no answer in time") }
        else { HostLog.line("remove domain \(root.hexString): failed: \(HostLog.errorClass(failure))") }
        return location
    }

    func evict(root: Data, item: Data) -> EvictOutcome {
        guard let manager = manager(root) else { return .error("no manager") }
        var outcome: EvictOutcome = .error("timeout")
        wait { finish in
            manager.evictItem(identifier: identifier(item)) { error in
                switch error {
                case nil: outcome = .evicted
                case let error as NSFileProviderError where error.code == .noSuchItem: outcome = .notMaterialized
                case let error as NSError where error.domain == NSPOSIXErrorDomain && error.code == Int(EBUSY): outcome = .busy
                case let error?: outcome = .error(String(describing: error))
                }
                finish()
            }
        }
        return outcome
    }

    func signal(root: Data, items: [Data], parents: [Data], workingSet: Bool) -> Bool {
        guard let manager = manager(root) else { return false }
        var targets = parents.map { identifier($0) }
        targets += items.map { identifier($0) }
        if workingSet { targets.append(.workingSet) }
        if targets.isEmpty { targets = [.rootContainer, .workingSet] }
        // One overall deadline for the whole serial walk (not per target): a stuck domain cannot hold the
        // reconcile queue for targets x 10 s. A target that does not answer in time fails the signal.
        let deadline = Date().addingTimeInterval(Self.signalDeadline)
        var ok = true
        for target in targets {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { return false }
            var failed = false
            let completed = wait(min(10, remaining)) { finish in
                manager.signalEnumerator(for: target) { error in
                    if error != nil { failed = true }
                    finish()
                }
            }
            if !completed || failed { ok = false }
        }
        return ok
    }

    /// The most a whole signal (all targets) may take.
    static let signalDeadline: TimeInterval = 30

    /// The OS gives up on an operation after a few failures and then never retries it by itself
    /// (`next: never` in `fileproviderctl dump`); this is what makes it try again.
    func signalErrorsResolved(root: Data) -> Bool {
        guard let manager = manager(root) else { return false }
        var ok = true
        for code in [NSFileProviderError.Code.serverUnreachable, .cannotSynchronize, .insufficientQuota, .notAuthenticated] {
            var failure: Error?
            let completed = wait(10) { finish in
                manager.signalErrorResolved(NSFileProviderError(code)) { error in failure = error; finish() }
            }
            if !completed || failure != nil {
                ok = false
                HostLog.line("signalErrorResolved \(root.hexString) \(code.rawValue): \(completed ? HostLog.errorClass(failure) : "no answer in time")")
            }
        }
        if ok { HostLog.line("signalErrorResolved \(root.hexString): done") }
        return ok
    }

    func waitForChanges(root: Data, parent: Data, timeout: TimeInterval) {
        guard let manager = manager(root) else { return }
        wait(timeout) { finish in
            manager.waitForChanges(below: identifier(parent)) { _ in finish() }
        }
    }

    /// Every materialized item id, following the enumerator's page tokens to the END. A failure or a
    /// timeout anywhere means the set is UNAVAILABLE (nil): a partial set is never reported.
    func materializedItems(root: Data) -> Set<Data>? {
        guard let manager = manager(root) else { return nil }
        let enumerator = manager.enumeratorForMaterializedItems()
        defer { enumerator.invalidate() }
        var items: Set<Data> = []
        var page: NSFileProviderPage = NSFileProviderPage.initialPageSortedByName as NSFileProviderPage
        let deadline = Date().addingTimeInterval(120)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { return nil }
            let collector = MaterializedCollector()
            let done = DispatchSemaphore(value: 0)
            collector.finish = { done.signal() }
            enumerator.enumerateItems(for: collector, startingAt: page)
            if done.wait(timeout: .now() + remaining) == .timedOut { collector.abandon(); return nil }
            guard let result = collector.result() else { return nil }
            items.formUnion(result.items)
            guard let next = result.next else { return items }
            page = next
        }
    }

    func requestDownload(root: Data, item: Data) -> DownloadOutcome {
        guard let manager = manager(root) else { return .rejected("no manager") }
        var outcome: DownloadOutcome = .rejected("timeout")
        wait { finish in
            // An EMPTY range is the whole file as the API documents it; UNVERIFIED against a real Finder
            // (confirm on a real device that the whole file is fetched).
            manager.requestDownloadForItem(withIdentifier: identifier(item), requestedRange: NSRange(location: 0, length: 0)) { error in
                outcome = error.map { .rejected(String(describing: $0)) } ?? .accepted
                finish()
            }
        }
        return outcome
    }

    /// Listing the folder under its user-visible URL makes the OS enumerate it (a hint to warm it).
    func prefetch(root: Data, folder: Data) -> PrefetchOutcome {
        guard let manager = manager(root) else { return .failed }
        var url: URL?
        wait(10) { finish in
            manager.getUserVisibleURL(for: identifier(folder)) { found, _ in url = found; finish() }
        }
        guard let url else { return .skipped }
        return (try? FileManager.default.contentsOfDirectory(atPath: url.path)) != nil ? .done : .failed
    }
}

private final class MaterializedCollector: NSObject, NSFileProviderEnumerationObserver {
    private let lock = NSLock()
    private var items: Set<Data> = []
    private var next: NSFileProviderPage?
    private var failed = false
    private var abandoned = false
    var finish: (() -> Void)?

    func didEnumerate(_ updatedItems: [any NSFileProviderItemProtocol]) {
        lock.lock(); defer { lock.unlock() }
        if abandoned { return }
        for item in updatedItems where item.itemIdentifier != .rootContainer {
            if let id = Data(hexString: item.itemIdentifier.rawValue) { items.insert(id) }
        }
    }
    func finishEnumerating(upTo nextPage: NSFileProviderPage?) {
        lock.lock(); next = nextPage; lock.unlock(); finish?()
    }
    func finishEnumeratingWithError(_ error: any Error) {
        lock.lock(); failed = true; lock.unlock(); finish?()
    }
    /// The page's items and the next page token (nil = the last page); nil when the page failed.
    func result() -> (items: Set<Data>, next: NSFileProviderPage?)? {
        lock.lock(); defer { lock.unlock() }
        return failed ? nil : (items, next)
    }
    func abandon() { lock.lock(); abandoned = true; lock.unlock() }
}

/// The reporter epoch and the highest acknowledged revision, kept across launches.
final class DefaultsDriverStore: DriverStore {
    private let defaults = UserDefaults.standard
    func nextEpoch() -> UInt64 {
        let next = UInt64(defaults.integer(forKey: "provider.reporterEpoch")) + 1
        defaults.set(Int(next), forKey: "provider.reporterEpoch")
        return next
    }
    func lastAcked(root: Data) -> UInt64 { UInt64(defaults.integer(forKey: "provider.acked.\(root.hexString)")) }
    func setLastAcked(root: Data, revision: UInt64) { defaults.set(Int(revision), forKey: "provider.acked.\(root.hexString)") }
    func wasRegistered(root: Data) -> Bool { defaults.bool(forKey: "provider.registered.\(root.hexString)") }
    func setRegistered(root: Data, _ registered: Bool) { defaults.set(registered, forKey: "provider.registered.\(root.hexString)") }

    // The pending-removal markers are durable BEFORE the host reports a removal: written and flushed.
    private static let pendingKey = "provider.pendingRemovals"
    func pendingRemoval(root: Data) -> Bool { pending().contains(root.hexString) }
    func setPendingRemoval(root: Data, _ pending: Bool) {
        var ids = Set(self.pending())
        if pending { ids.insert(root.hexString) } else { ids.remove(root.hexString) }
        defaults.set(Array(ids).sorted(), forKey: Self.pendingKey)
        defaults.synchronize()
    }
    func pendingRemovalRoots() -> [Data] { pending().compactMap { Data(hexString: $0) } }

    // Where the OS kept a removed domain's data: durable before the removal is reported.
    private static let locationPrefix = "provider.preservedLocation."
    func preservedLocation(root: Data) -> String? { defaults.string(forKey: Self.locationPrefix + root.hexString) }
    func setPreservedLocation(root: Data, _ location: String?) {
        defaults.set(location, forKey: Self.locationPrefix + root.hexString)
        defaults.synchronize()
    }
    func removalLocationRoots() -> [Data] {
        defaults.dictionaryRepresentation().keys
            .filter { $0.hasPrefix(Self.locationPrefix) }
            .compactMap { Data(hexString: String($0.dropFirst(Self.locationPrefix.count))) }
    }
    private func pending() -> [String] { defaults.stringArray(forKey: Self.pendingKey) ?? [] }
}

/// Starts the provider duties: connects (retrying while the daemon is away), reconciles domains at
/// connect and whenever asked, polls the reporter and the Eager loop, and reconnects with a fresh
/// reporter epoch when the connection ends. All work runs on one serial queue.
final class ProviderHostService: @unchecked Sendable {
    static let shared = ProviderHostService()
    static let groupIdentifier = "group.com.juntaki.yadorilink.shared"

    private let queue = DispatchQueue(label: "yadorilink.provider-host", qos: .utility)
    private var link: FFIHostLink?
    private var driver: ProviderDriver?
    private var timer: DispatchSourceTimer?
    private var ticks = 0

    func start() {
        // Asking for the app group container creates it: the daemon opens its provider temp root there as
        // soon as it exists (it re-checks on demand), so provider folders work on a fresh install
        // without restarting it.
        _ = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.groupIdentifier)
        HostLog.line("provider host starting")
        queue.async { [self] in
            guard timer == nil else { return }
            let source = DispatchSource.makeTimerSource(queue: queue)
            source.schedule(deadline: .now(), repeating: .seconds(2))
            source.setEventHandler { [self] in tick() }
            source.resume()
            timer = source
        }
    }

    /// The folder set changed: reconcile now (coalesced onto the service queue).
    func requestReconcile() { queue.async { [self] in driver?.reconcile() } }

    private func tick() {
        ticks += 1
        if link == nil { connect() }
        guard let driver else { return }
        for folder in driver.knownFolders {
            driver.reportTick(root: folder.root)
            if folder.eager && ticks % 3 == 0 { driver.eagerTick(root: folder.root) }
        }
        if ticks % 15 == 0 { driver.reconcile() }
    }

    /// A new connection gets a NEW driver: a new reporter epoch (minted from the persisted counter)
    /// and a full snapshot first; nothing of the old connection's queries is awaited.
    private func connect() {
        let link = FFIHostLink { [weak self] event in
            self?.queue.async {
                if event["event"] as? String == "closed" {
                    self?.link?.close()
                    self?.link = nil
                    self?.driver = nil
                } else {
                    self?.driver?.handle(event)
                }
            }
        }
        guard link.connect() else {
            if ticks % 15 == 1 { HostLog.line("daemon not reachable") }
            return
        }
        HostLog.line("connected to the daemon")
        let driver = ProviderDriver(link: link, control: OSDomainControl(), store: DefaultsDriverStore())
        self.link = link
        self.driver = driver
        driver.reconcile()
    }
}
