import AppKit
import FinderSync
import ServiceManagement
import YadoriLinkUI

/// Open-at-login through `SMAppService.mainApp`, so it shows up by name in
/// System Settings > General > Login Items.
final class MainAppLoginItem: LoginItemService {
    var status: LoginItemStatus {
        switch SMAppService.mainApp.status {
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .notFound
        case .notRegistered: .notRegistered
        @unknown default: .notRegistered
        }
    }

    func register() throws { try SMAppService.mainApp.register() }
    func unregister() throws { try SMAppService.mainApp.unregister() }
    func openSystemSettingsLoginItems() { SMAppService.openSystemSettingsLoginItems() }
}

/// Finder extension state. There is no API to turn an extension on, only to
/// open the place where the user does it.
@MainActor
struct FinderExtensionStatus: ExtensionStatusProvider {
    var isFinderExtensionEnabled: Bool { FIFinderSyncController.isExtensionEnabled }
    func openExtensionSettings() { FIFinderSyncController.showExtensionManagementInterface() }
}
