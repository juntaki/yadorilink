//
//  FinderSync.swift
//
//  The thin Swift `FIFinderSync` shell: all sync status/context-action
//  *logic* lives in the Rust FFI core
//  (`yadorilink_shell_core`, shell-ext/macos/core/src/lib.rs), which speaks
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
//  NOTE on directory discovery (documented gap, not blocking 10.1-10.3):
//  `FIFinderSyncController.directoryURLs` is how Finder learns which
//  folders this extension instruments (driving
//  beginObservingDirectory/endObservingDirectory below). The daemon's
//  shell-integration protocol (shellipc.proto, bridges to
//  per the task brief) only exposes per-path StatusQuery/ContextAction —
//  there is no "list linked folders" message on that protocol. (A
//  `ListLinksRequest`/`ListLinksResponse` pair does exist, but on the
//  separate daemon *control* socket used by the CLI — a different
//  protocol, out of this task's scope.) Wiring real linked-folder
//  discovery is a follow-up: either add a shellipc.proto message, or have
//  the host app relay the control socket's ListLinks response into a
//  shared App Group default this extension reads. Debug builds may set
//  `YADORILINK_FINDER_SYNC_FOLDERS` (colon-separated absolute paths) for
//  local testing; release builds ignore environment overrides.

import Cocoa
import FinderSync
import FileProvider

@objc(FinderSync)
class FinderSync: FIFinderSync {

    /// One badge identifier per `YadoriLinkBadgeStatus` value from the Rust
    /// core's C header (shell-ext/macos/core/include/yadorilink_shell_core.h).
    /// SF Symbols are used for the glyphs so this builds without an asset
    /// catalog — real product artwork is a follow-up, matching the
    /// Windows spike's own placeholder-icon note (shell-ext/windows's
    /// overlay.rs doc comment).
    private enum Badge: String, CaseIterable {
        case synced = "com.yadorilink.badge.synced"
        case syncing = "com.yadorilink.badge.syncing"
        case pending = "com.yadorilink.badge.pending"
        case error = "com.yadorilink.badge.error"
        case onlineOnly = "com.yadorilink.badge.onlineOnly"
        // on-demand-sync's advisory "open elsewhere" signal (an
        // Office-style `~$*` lock file seen on a
        // peer, relayed over PeerChannel) — a sixth badge identifier
        // following the exact pattern of the five above.
        case openElsewhere = "com.yadorilink.badge.openElsewhere"

        var symbolName: String {
            switch self {
            case .synced: return "checkmark.circle.fill"
            case .syncing: return "arrow.triangle.2.circlepath"
            case .pending: return "clock"
            case .error: return "exclamationmark.triangle.fill"
            case .onlineOnly: return "icloud.and.arrow.down"
            case .openElsewhere: return "person.crop.circle.badge.exclamationmark"
            }
        }

        var label: String {
            switch self {
            case .synced: return "YadoriLink: Synced"
            case .syncing: return "YadoriLink: Syncing"
            case .pending: return "YadoriLink: Pending"
            case .error: return "YadoriLink: Sync Error"
            case .onlineOnly: return "YadoriLink: Online Only"
            case .openElsewhere: return "YadoriLink: Open on Another Device"
            }
        }

        var image: NSImage {
            NSImage(systemSymbolName: symbolName, accessibilityDescription: label)
                ?? NSImage(named: NSImage.cautionName)!
        }
    }

    override init() {
        super.init()
        let controller = FIFinderSyncController.default()
        let eagerFolders = Self.configuredEagerFolders()
        controller.directoryURLs = eagerFolders
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
        // (pin/evict) mechanism covers both Eager and OnDemand folders
        // without a second, File-Provider-native decoration API.
        //
        // BUG FOUND AND FIXED (the relevant behavior, real VM verification): the
        // originally-shipped approach guessed the mount path as a fixed
        // `~/Library/CloudStorage/yadorilink` (`cloud_storage_root()` in
        // core/src/ipc_client.rs) — this is WRONG. A real registered
        // domain (identifier "ondemand-group", displayName
        // "OnDemandSource") mounted at
        // `~/Library/CloudStorage/YadoriLinkFinderSyncHost-OnDemandSource`
        // instead — macOS derives the top-level CloudStorage entry name
        // from the extension's own bundle name, not anything this code
        // controls or can predict. Fixed by asking
        // NSFileProviderManager for the real, live list of registered
        // domains and resolving each one's actual mount URL via
        // `getUserVisibleURL(for: .rootContainer)`, rather than
        // constructing a guessed path.
        NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
            if let error {
                NSLog("yadorilink: FinderSync failed to list File Provider domains: \(error)")
                return
            }
            let group = DispatchGroup()
            var onDemandFolders: [URL] = []
            let lock = NSLock()
            for domain in domains {
                guard let manager = NSFileProviderManager(for: domain) else { continue }
                group.enter()
                manager.getUserVisibleURL(for: .rootContainer) { url, error in
                    defer { group.leave() }
                    if let error {
                        NSLog("yadorilink: FinderSync failed to resolve URL for domain \(domain.identifier.rawValue): \(error)")
                        return
                    }
                    if let url {
                        lock.lock()
                        onDemandFolders.append(url)
                        lock.unlock()
                    }
                }
            }
            group.notify(queue: .main) {
                guard !onDemandFolders.isEmpty else { return }
                controller.directoryURLs = eagerFolders.union(onDemandFolders)
                NSLog("yadorilink: FinderSync now also watching OnDemand domains: \(onDemandFolders)")
            }
        }
    }

    private static func configuredEagerFolders() -> Set<URL> {
        #if DEBUG
        if let raw = ProcessInfo.processInfo.environment["YADORILINK_FINDER_SYNC_FOLDERS"], !raw.isEmpty {
            let paths = raw.split(separator: ":").map(String.init)
            return Set(paths.map { URL(fileURLWithPath: $0, isDirectory: true) })
        }
        #endif
        let home = FileManager.default.homeDirectoryForCurrentUser
        let fallback = home.appendingPathComponent("YadoriLinkSync", isDirectory: true)
        try? FileManager.default.createDirectory(at: fallback, withIntermediateDirectories: true)
        return [fallback]
    }

    // MARK: - the relevant behavior: directory lifecycle

    override func beginObservingDirectory(at url: URL) {
        NSLog("yadorilink: beginObservingDirectory \(url.path)")
    }

    override func endObservingDirectory(at url: URL) {
        NSLog("yadorilink: endObservingDirectory \(url.path)")
    }

    // MARK: - the relevant behavior: badge rendering via the Rust FFI core

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
        case Int32(YadoriLinkBadgeStatusOpenElsewhere.rawValue): identifier = Badge.openElsewhere.rawValue
        default: identifier = "" // YadoriLinkBadgeStatusUnspecified, or the daemon isn't
                                  // reachable — fail soft to "no badge" per spec.
        }
        controller.setBadgeIdentifier(identifier, for: url)
    }

    // MARK: - the relevant behavior: context menu wired to daemon actions

    override func menu(for menuKind: FIMenuKind) -> NSMenu {
        let menu = NSMenu(title: "")
        guard menuKind == .contextualMenuForItems else { return menu }
        guard let urls = FIFinderSyncController.default().selectedItemURLs(), !urls.isEmpty else {
            return menu
        }

        let submenu = NSMenu(title: "YadoriLink")
        let actions: [(String, Int32, Selector)] = [
            ("View sync status", Int32(YadoriLinkContextActionViewStatus.rawValue), #selector(viewStatus(_:))),
            ("Pause sync for this item", Int32(YadoriLinkContextActionPauseItem.rawValue), #selector(pauseItem(_:))),
            ("Resume sync for this item", Int32(YadoriLinkContextActionResumeItem.rawValue), #selector(resumeItem(_:))),
            ("Pin (keep hydrated)", Int32(YadoriLinkContextActionPinItem.rawValue), #selector(pinItem(_:))),
            ("Evict (free disk space)", Int32(YadoriLinkContextActionEvictItem.rawValue), #selector(evictItem(_:))),
        ]
        for (title, action, selector) in actions {
            let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
            item.target = self
            item.tag = Int(action)
            submenu.addItem(item)
        }

        // Per the shell-integration spec's "Shell Actions Can Open
        // Desktop Status App": unlike the actions above,
        // this is a pure UI action -- it launches a separate companion
        // process (the menu-bar status app), it does not round-trip
        // through `yadorilink_send_context_action`/the daemon's shell IPC
        // at all, so it gets no `YadoriLinkContextAction*` tag from the
        // Rust core's C header.
        submenu.addItem(NSMenuItem.separator())
        let openStatusItem = NSMenuItem(
            title: "Open YadoriLink Status",
            action: #selector(openStatusApp(_:)),
            keyEquivalent: ""
        )
        openStatusItem.target = self
        submenu.addItem(openStatusItem)

        let yadorilink = NSMenuItem(title: "YadoriLink", action: nil, keyEquivalent: "")
        yadorilink.submenu = submenu
        menu.addItem(yadorilink)
        return menu
    }

    /// Fire-and-forget, same as the Windows `IContextMenu::InvokeCommand`
    /// handler (shell-ext/windows/src/context_menu.rs): a failed action
    /// just silently doesn't apply rather than showing an error dialog,
    /// matching the badge's own fail-soft contract.
    private func sendAction(_ tag: Int) {
        guard let urls = FIFinderSyncController.default().selectedItemURLs() else { return }
        for url in urls {
            _ = url.path.withCString { path in
                yadorilink_send_context_action(path, Int32(tag))
            }
        }
    }

    @objc func viewStatus(_ sender: NSMenuItem) { sendAction(sender.tag) }
    @objc func pauseItem(_ sender: NSMenuItem) { sendAction(sender.tag) }
    @objc func resumeItem(_ sender: NSMenuItem) { sendAction(sender.tag) }
    @objc func pinItem(_ sender: NSMenuItem) { sendAction(sender.tag) }
    @objc func evictItem(_ sender: NSMenuItem) { sendAction(sender.tag) }

    /// Launches the menu-bar status app
    /// (`yadorilink-status-app`, installed by `installer/macos/build-pkg.sh`
    /// alongside `yadorilink`/`yadorilink-daemon`), passing the selected
    /// item's path as an argument so the app *could* focus on it -- the
    /// status app doesn't parse an argv path yet (tracked as a documented
    /// follow-up, since the app is normally already running as a login
    /// item and a second invocation's argv
    /// isn't otherwise delivered to it), so today this only guarantees the
    /// app is running/visible, not that it's focused on this specific
    /// item. Uses `Process` rather than `NSWorkspace.shared.open`/
    /// `launchApplication(at:)` because the status app ships as a plain
    /// signed executable, not an `.app` bundle (see build-pkg.sh's own
    /// notes on why). Fails soft -- a missing/unlaunchable status app
    /// never throws or blocks Finder (shell-integration spec's "App is
    /// unavailable" scenario), matching `sendAction`'s own fire-and-forget
    /// discipline just above.
    @objc func openStatusApp(_ sender: NSMenuItem) {
        let path = "/usr/local/bin/yadorilink-status-app"
        guard FileManager.default.isExecutableFile(atPath: path) else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        if let url = FIFinderSyncController.default().selectedItemURLs()?.first {
            process.arguments = [url.path]
        }
        do {
            try process.run()
        } catch {
            // Fail soft, per this method's doc comment above.
        }
    }
}
