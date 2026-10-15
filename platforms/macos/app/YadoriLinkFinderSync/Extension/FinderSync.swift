//
//  FinderSync.swift
//
//  The thin Swift `FIFinderSync` shell: all sync status/context-action
//  *logic* lives in the Rust FFI core
//  (`yadorilink_shell_core`, platforms/macos/app/core/src/lib.rs), which speaks
//  the daemon's shell-integration IPC protocol (shellipc.proto) with a
//  bounded 200ms timeout and fails soft to "no badge" per the
//  `shell-integration` spec's "Graceful Degradation When Daemon Is Not
//  Running" requirement. This file only does Finder-facing plumbing:
//  which directories to instrument, badge identifier
//  registration/assignment, and building the context menu — it never
//  touches the network or on-disk storage directly (spec "Shell Extension
//  to Sync Daemon Communication": "without requiring the shell extension
//  to access the network or storage directly").
//
//  NOTE on directory discovery:
//  `FIFinderSyncController.directoryURLs` is how Finder learns which
//  folders this extension instruments. The eager (ordinary) roots come
//  from the daemon's shell IPC `ListLinkedRootsRequest` (the same live link
//  table the product status reads), fetched through the Rust core and
//  re-read periodically so a link/unlink converges without a restart.
//  `EagerRootSet` (FileProviderCore/EagerRoots.swift) holds the last
//  confirmed set: an unreachable daemon keeps it, a confirmed empty
//  snapshot clears it, and nothing is guessed before the first
//  confirmation. On-Demand provider roots are re-listed on every poll via
//  `NSFileProviderManager` and unioned in. Debug builds may set
//  `YADORILINK_FINDER_SYNC_FOLDERS` (colon-separated absolute paths) as a
//  test-only fixture that replaces the daemon read; release builds ignore it.

import Cocoa
import FinderSync
import FileProvider

@objc(FinderSync)
class FinderSync: FIFinderSync {

    /// One badge identifier per `YadoriLinkBadgeStatus` value from the Rust
    /// core's C header (platforms/macos/app/core/include/yadorilink_shell_core.h).
    /// SF Symbols are used for the glyphs so this builds without an asset
    /// catalog — real product artwork is a follow-up, matching the
    /// Windows spike's own placeholder-icon note (platforms/windows/shell's
    /// overlay.rs doc comment).
    private enum Badge: String, CaseIterable {
        case synced = "com.yadorilink.badge.synced"
        case syncing = "com.yadorilink.badge.syncing"
        case pending = "com.yadorilink.badge.pending"
        case error = "com.yadorilink.badge.error"
        case onlineOnly = "com.yadorilink.badge.onlineOnly"

        var symbolName: String {
            switch self {
            case .synced: return "checkmark.circle.fill"
            case .syncing: return "arrow.triangle.2.circlepath"
            case .pending: return "clock"
            case .error: return "exclamationmark.triangle.fill"
            case .onlineOnly: return "icloud.and.arrow.down"
            }
        }

        var label: String {
            switch self {
            case .synced: return "YadoriLink: Synced"
            case .syncing: return "YadoriLink: Syncing"
            case .pending: return "YadoriLink: Pending"
            case .error: return "YadoriLink: Sync Error"
            case .onlineOnly: return "YadoriLink: Online Only"
            }
        }

        var image: NSImage {
            NSImage(systemSymbolName: symbolName, accessibilityDescription: label)
                ?? NSImage(named: NSImage.cautionName)!
        }
    }

    /// Eager roots confirmed by the daemon and File Provider roots; both only touched on `rootsQueue`.
    private var monitoredRoots = MonitoredRoots()
    private var lastPublished: Set<URL>?
    /// Provider listings are async, so at most one runs at a time: overlapping ones could finish
    /// out of order and let an older listing restore a root a newer one removed. One that has not
    /// completed after `providerListingTimeout` is abandoned (its late completion is ignored by
    /// generation), so a callback that never arrives cannot stop polling for good; until a
    /// newer listing confirms, the last confirmed provider roots stay. Only touched on `rootsQueue`.
    private var providerListingStarted: Date?
    private var providerListingGeneration: UInt64 = 0
    private static let providerListingTimeout: TimeInterval = 30
    private let rootsQueue = DispatchQueue(label: "com.juntaki.yadorilink.finder-roots")
    private var rootsTimer: DispatchSourceTimer?

    override init() {
        super.init()
        let controller = FIFinderSyncController.default()
        startEagerRootPolling()
        for badge in Badge.allCases {
            controller.setBadgeImage(badge.image, label: badge.label, forBadgeIdentifier: badge.rawValue)
        }
        NSLog("yadorilink: FinderSync extension launched, watching \(String(describing: controller.directoryURLs))")

        // OnDemand folders live under a
        // File-Provider-managed location this extension does not choose
        // — created/populated by the YadoriLinkFileProvider
        // extension via NSFileProviderManager domain registration (task
        // 7.2). Apple documents FinderSync as able to observe a
        // File-Provider-managed directory concurrently with the File
        // Provider extension that owns it (`beginObservingDirectory` is
        // the same API either way), which is how a single Finder-visible
        // custom badge (online-only/open-elsewhere) and context menu
        // (free up space) mechanism covers both Eager and OnDemand folders
        // without a second, File-Provider-native decoration API.
        //
        // BUG FOUND AND FIXED (real VM verification): the
        // originally-shipped approach guessed the mount path as a fixed
        // `~/Library/CloudStorage/yadorilink` (`cloud_storage_root` in
        // core/src/ipc_client.rs) — this is WRONG. A real registered
        // domain (identifier "ondemand-group", displayName
        // "OnDemandSource") mounted at
        // `~/Library/CloudStorage/YadoriLinkFinderSyncHost-OnDemandSource`
        // instead — macOS derives the top-level CloudStorage entry name
        // from the extension's own bundle name, not anything this code
        // controls or can predict. Fixed by asking
        // NSFileProviderManager for the real, live list of registered
        // domains and resolving each one's actual mount URL via
        // `getUserVisibleURL(for:.rootContainer)`, rather than
        // constructing a guessed path.
    }

    /// Re-reads the linked-root snapshot now and then, so a folder linked or unlinked while the
    /// extension runs (or a daemon that was not up yet) converges without a restart. The read
    /// blocks on the daemon for a bounded time, so it runs off the main thread.
    private func startEagerRootPolling() {
        let timer = DispatchSource.makeTimerSource(queue: rootsQueue)
        timer.schedule(deadline: .now(), repeating: 3)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.monitoredRoots.applyEager(Self.readEagerRootSnapshot())
            self.refreshProviderRoots()
            self.publishDirectoryURLs()
        }
        rootsTimer = timer
        timer.resume()
    }

    /// Lists the registered File Provider domains and resolves each mount root. Any failure (the
    /// listing, or one domain's URL) is `unavailable`, so the last confirmed provider roots stay;
    /// zero domains listed without error is a confirmed empty set. Applies on `rootsQueue`.
    private func refreshProviderRoots() {
        if let started = providerListingStarted,
           Date().timeIntervalSince(started) < Self.providerListingTimeout {
            return
        }
        providerListingGeneration &+= 1
        let generation = providerListingGeneration
        providerListingStarted = Date()
        NSFileProviderManager.getDomainsWithCompletionHandler { [weak self] domains, error in
            guard let self else { return }
            if let error {
                NSLog("yadorilink: FinderSync failed to list File Provider domains: \(error)")
                self.rootsQueue.async { self.finishProviderListing(.unavailable, generation: generation) }
                return
            }
            let group = DispatchGroup()
            var paths: [String] = []
            var complete = true
            let lock = NSLock()
            for domain in domains {
                guard let manager = NSFileProviderManager(for: domain) else {
                    lock.lock(); complete = false; lock.unlock()
                    continue
                }
                group.enter()
                manager.getUserVisibleURL(for: .rootContainer) { url, error in
                    defer { group.leave() }
                    lock.lock(); defer { lock.unlock() }
                    if let url {
                        paths.append(url.path)
                    } else {
                        if let error {
                            NSLog("yadorilink: FinderSync failed to resolve URL for domain \(domain.identifier.rawValue): \(error)")
                        }
                        complete = false
                    }
                }
            }
            group.notify(queue: self.rootsQueue) { [weak self] in
                self?.finishProviderListing(complete ? .confirmed(paths) : .unavailable, generation: generation)
            }
        }
    }

    /// Must run on `rootsQueue`.
    private func finishProviderListing(_ snapshot: EagerRootSnapshot, generation: UInt64) {
        // A listing abandoned after the timeout must not apply (or end) a newer one.
        guard generation == providerListingGeneration else { return }
        providerListingStarted = nil
        if monitoredRoots.applyProvider(snapshot) {
            publishDirectoryURLs()
        }
    }

    /// Must run on `rootsQueue`. Publishes only when the monitored set changed.
    private func publishDirectoryURLs() {
        let urls = monitoredRoots.monitored()
        guard urls != lastPublished else { return }
        lastPublished = urls
        DispatchQueue.main.async {
            FIFinderSyncController.default().directoryURLs = urls
            NSLog("yadorilink: FinderSync watching \(urls.map(\.path))")
        }
    }

    private static func readEagerRootSnapshot() -> EagerRootSnapshot {
        #if DEBUG
        // Test-only fixture: replaces the daemon read, never used in release builds.
        if let raw = ProcessInfo.processInfo.environment["YADORILINK_FINDER_SYNC_FOLDERS"], !raw.isEmpty {
            return .confirmed(raw.split(separator: ":").map(String.init))
        }
        #endif
        guard let roots = yadorilink_linked_roots_open() else { return .unavailable }
        defer { yadorilink_linked_roots_free(roots) }
        var paths: [String] = []
        for index in 0..<yadorilink_linked_roots_count(roots) {
            if let path = yadorilink_linked_roots_path(roots, index) {
                paths.append(String(cString: path))
            }
        }
        return .confirmed(paths)
    }

    // MARK: -: directory lifecycle

    override func beginObservingDirectory(at url: URL) {
        NSLog("yadorilink: beginObservingDirectory \(url.path)")
    }

    override func endObservingDirectory(at url: URL) {
        NSLog("yadorilink: endObservingDirectory \(url.path)")
    }

    // MARK: -: badge rendering via the Rust FFI core

    override func requestBadgeIdentifier(for url: URL) {
        let controller = FIFinderSyncController.default()
        let status = url.path.withCString { yadorilink_query_status($0) }
        // The C header's plain `typedef enum` imports into Swift with a
        // `UInt32` rawValue (the Clang importer's default for an
        // explicit-underlying-type-less C enum), while
        // `yadorilink_query_status` returns a plain C `int` (`Int32`) — cast
        // each case to `Int32` to compare like-for-like rather than
        // changing the hand-written header's C-side type (which mirrors
        // the Rust core's `#[repr(C)] c_int` return exactly).
        let identifier: String
        switch status {
        case Int32(YadoriLinkBadgeStatusSynced.rawValue): identifier = Badge.synced.rawValue
        case Int32(YadoriLinkBadgeStatusSyncing.rawValue): identifier = Badge.syncing.rawValue
        case Int32(YadoriLinkBadgeStatusPending.rawValue): identifier = Badge.pending.rawValue
        case Int32(YadoriLinkBadgeStatusError.rawValue): identifier = Badge.error.rawValue
        case Int32(YadoriLinkBadgeStatusOnlineOnly.rawValue): identifier = Badge.onlineOnly.rawValue
        default: identifier = "" // YadoriLinkBadgeStatusUnspecified, or the daemon isn't
                                  // reachable — fail soft to "no badge" per spec.
        }
        controller.setBadgeIdentifier(identifier, for: url)
    }

    // MARK: -: context menu wired to daemon actions

    /// The daemon's answer for one selected item, plus the kind Finder reports. Anything that
    /// cannot be read is "not tracked" / "not a file" so the menu offers less, never more.
    private static func facts(for url: URL) -> FinderItemFacts {
        let raw = url.path.withCString { yadorilink_query_item($0) }
        let isDirectory = (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory
        return FinderItemFacts(
            tracked: raw.tracked, paused: raw.paused,
            pausedByAncestor: raw.paused_by_ancestor, reclaimSupported: raw.reclaim_supported,
            currentContentPresent: raw.current_content_present,
            inTransition: raw.in_transition, isDirectory: isDirectory)
    }

    /// A selection this large is not worth one daemon round trip per item on Finder's menu
    /// callback; it gets no actions.
    private static let maxMenuSelection = 20

    override func menu(for menuKind: FIMenuKind) -> NSMenu {
        let menu = NSMenu(title: "")
        guard menuKind == .contextualMenuForItems else { return menu }
        guard let urls = FIFinderSyncController.default().selectedItemURLs(), !urls.isEmpty,
              urls.count <= Self.maxMenuSelection else {
            return menu
        }

        let actions = FinderMenu.actions(for: urls.map(Self.facts(for:)))
        guard !actions.isEmpty else { return menu }

        let submenu = NSMenu(title: "YadoriLink")
        for action in actions {
            let selector: Selector
            switch action {
            case .viewStatus: selector = #selector(viewStatus(_:))
            case .pause: selector = #selector(pauseItem(_:))
            case .resume: selector = #selector(resumeItem(_:))
            case .freeUpSpace: selector = #selector(freeUpSpace(_:))
            }
            let item = NSMenuItem(title: action.title, action: selector, keyEquivalent: "")
            item.target = self
            submenu.addItem(item)
        }

        let yadorilink = NSMenuItem(title: "YadoriLink", action: nil, keyEquivalent: "")
        yadorilink.submenu = submenu
        menu.addItem(yadorilink)
        return menu
    }

    /// Fire-and-forget, same as the Windows `IContextMenu::InvokeCommand`
    /// handler (platforms/windows/shell/src/context_menu.rs): a failed action
    /// just silently doesn't apply rather than showing an error dialog,
    /// matching the badge's own fail-soft contract. The daemon revalidates
    /// the path against its linked folders; this only relays.
    private func sendAction(_ action: Int32) {
        guard let urls = FIFinderSyncController.default().selectedItemURLs() else { return }
        for url in urls {
            _ = url.path.withCString { path in
                yadorilink_send_context_action(path, action)
            }
        }
    }

    @objc func pauseItem(_ sender: NSMenuItem) {
        sendAction(Int32(YadoriLinkContextActionPauseItem.rawValue))
    }

    @objc func resumeItem(_ sender: NSMenuItem) {
        sendAction(Int32(YadoriLinkContextActionResumeItem.rawValue))
    }

    /// The daemon's evict operation; "Free Up Space" is its only user-facing name.
    @objc func freeUpSpace(_ sender: NSMenuItem) {
        sendAction(Int32(YadoriLinkContextActionEvictItem.rawValue))
    }

    /// Opens the YadoriLink app at the selected item through its `yadorilink://item` URL, the
    /// same way for a cold launch and for an app that is already running (the system delivers
    /// the URL to the running instance, or starts the app with it). The app re-resolves the path
    /// against its linked folders. Fails soft: no URL or no app means nothing happens.
    @objc func viewStatus(_ sender: NSMenuItem) {
        guard let url = FIFinderSyncController.default().selectedItemURLs()?.first,
              let link = FinderDeepLink.url(forItemAt: url.path) else { return }
        NSWorkspace.shared.open(link)
    }
}
