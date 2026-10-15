import Foundation

/// What the daemon said about one selected Finder item, plus what Finder says its kind is.
/// `isDirectory == nil` is "could not tell", which is never eligible for Free Up Space.
struct FinderItemFacts: Equatable {
    var tracked: Bool
    /// This exact item is paused: Resume applies to it.
    var paused: Bool
    /// An item above it is paused: neither Pause nor Resume would change anything for it.
    var pausedByAncestor: Bool
    /// The daemon's own eviction gate accepts this item's root.
    var reclaimSupported: Bool
    var currentContentPresent: Bool
    var inTransition: Bool
    var isDirectory: Bool?
}

enum FinderMenuAction: Equatable {
    case viewStatus, pause, resume, freeUpSpace

    /// The product wording the desktop app uses; internal names (evict, hydrate) never show here.
    var title: String {
        switch self {
        case .viewStatus: "View YadoriLink Status"
        case .pause: "Pause Syncing"
        case .resume: "Resume Syncing"
        case .freeUpSpace: "Free Up Space"
        }
    }
}

/// The context menu as a pure function of the daemon's answers for the selection. Fail closed:
/// an item the daemon does not know, or any doubt about reclaimability, offers nothing rather
/// than a promise the daemon would refuse.
enum FinderMenu {
    static func actions(for selection: [FinderItemFacts]) -> [FinderMenuAction] {
        guard !selection.isEmpty, selection.allSatisfy(\.tracked) else { return [] }
        var actions: [FinderMenuAction] = [.viewStatus]
        // One of the two, never both: Resume only when everything selected is paused itself. An
        // item under a paused folder is resumed by resuming the folder, so it gets neither.
        if !selection.contains(where: \.pausedByAncestor) {
            actions.append(selection.allSatisfy(\.paused) ? .resume : .pause)
        }
        // The same rule the app uses for its Free up space button: the current content is on
        // this device, nothing is moving, and the daemon's own gate accepts the root (today only
        // a provider folder can give space back, and Finder acts on a provider item itself with
        // Remove Download, so this menu offers it on no item). Files only.
        let reclaimable = selection.allSatisfy {
            $0.reclaimSupported && $0.currentContentPresent && !$0.inTransition
                && $0.isDirectory == false
        }
        if reclaimable { actions.append(.freeUpSpace) }
        return actions
    }
}

/// `yadorilink://item?path=<absolute path>`: how Finder asks the app to open the selected item.
/// The app re-resolves the path against its linked folders; the link grants nothing by itself.
enum FinderDeepLink {
    static let scheme = "yadorilink"
    static let host = "item"

    static func url(forItemAt path: String) -> URL? {
        guard path.hasPrefix("/") else { return nil }
        // Slash stays readable; everything else that could end a value (& = + % #) is encoded.
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~/")
        guard let encoded = path.addingPercentEncoding(withAllowedCharacters: allowed) else {
            return nil
        }
        return URL(string: "\(scheme)://\(host)?path=\(encoded)")
    }
}
