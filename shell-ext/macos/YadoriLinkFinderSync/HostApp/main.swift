//
//  main.swift — .
//
//  A FIFinderSync extension cannot run standalone; it must be embedded in
//  a host application bundle's PlugIns/ directory (build.sh assembles
//  YadoriLinkFinderSync.appex under YadoriLinkFinderSyncHost.app/Contents/
//  PlugIns/). This host app's only real job is to exist so the extension
//  has somewhere to live and so a user can find it in System Settings ->
//  General -> Login Items & Extensions -> Finder Extensions to enable it
//  (Apple does not provide a programmatic "enable my extension" API).
//  Following Nextcloud/Dropbox's own convention, it shows a short
//  instructional window rather than a blank app.
//
//  `main.swift` (this exact filename) is `swiftc`'s top-level-code entry
//  point convention — no `@main` attribute or Xcode project needed for
//  this to be a valid app main, matching this target's swiftc-direct
//  build (see ../build.sh's rationale comment for why no .xcodeproj is
//  used).

import Cocoa

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // register a File Provider domain for
        // every OnDemand-linked folder group the daemon currently knows
        // about, every launch (see DomainRegistration.swift's doc
        // comment for why this runs from the host app rather than the
        // extension, and why "every launch" rather than a persistent
        // background watch — this app has no persistent presence of its
        // own by design).
        DomainRegistration.registerOnDemandDomains()

        let text = """
        YadoriLink FinderSync

        To enable YadoriLink's Finder integration (sync-status badges and \
        the right-click "YadoriLink" menu), open:

          System Settings > General > Login Items & Extensions > \
        Extensions > Added Extensions > Finder

        and turn on "YadoriLink FinderSync".

        This host app has no other UI of its own — it exists only to \
        carry the Finder Sync extension bundle (build-yadorilink-mvp task \
        10.5). You can quit it once the extension is enabled.
        """

        let contentRect = NSRect(x: 0, y: 0, width: 480, height: 260)
        let win = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        win.title = "YadoriLink"
        win.center()

        let label = NSTextField(wrappingLabelWithString: text)
        label.frame = contentRect.insetBy(dx: 20, dy: 20)
        label.isEditable = false
        label.isBezeled = false
        label.drawsBackground = false

        let contentView = NSView(frame: contentRect)
        contentView.addSubview(label)
        win.contentView = contentView

        win.makeKeyAndOrderFront(nil)
        window = win

        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
