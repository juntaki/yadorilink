import Foundation

/// Which windows to open when the app launches.
///
/// `--onboarding` (used by the installer) forces setup, and setup also
/// opens on every launch until the user has completed it, so closing the
/// window early offers it again next time. For development and
/// screenshots: `--show <pane>` opens the main window on a pane (home,
/// folders, devices, transfers, storage), `--show-folder <path>` opens a
/// folder's details, and `--settings` opens Settings.
public struct LaunchPlan: Equatable, Sendable {
    public var showsOnboarding = false
    public var pane: SidebarItem?
    public var folder: String?
    public var showsSettings = false

    public init(showsOnboarding: Bool = false, pane: SidebarItem? = nil, folder: String? = nil, showsSettings: Bool = false) {
        self.showsOnboarding = showsOnboarding
        self.pane = pane
        self.folder = folder
        self.showsSettings = showsSettings
    }

    public init(arguments: [String], didFinishOnboarding: Bool) {
        func value(after flag: String) -> String? {
            guard let i = arguments.firstIndex(of: flag), i + 1 < arguments.count else { return nil }
            return arguments[i + 1]
        }
        showsOnboarding = arguments.contains("--onboarding") || !didFinishOnboarding
        pane = value(after: "--show").flatMap(SidebarItem.init(rawValue:))
        folder = value(after: "--show-folder")
        showsSettings = arguments.contains("--settings")
    }
}
