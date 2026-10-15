import Foundation

/// A `yadorilink://` link the system hands to the app.
///
/// - `yadorilink://invite/<code>`: an invitation to join a folder.
/// - `yadorilink://item?path=<absolute path>`: the Finder extension's "View YadoriLink Status"
///   for the selected item. The path is only a request: the app resolves it against the folders
///   it has linked (`ItemLinkRouting`) before anything opens.
public enum AppLink: Equatable, Sendable {
    case invite(String)
    case item(path: String)

    public init?(url: URL) {
        guard url.scheme?.lowercased() == "yadorilink" else { return nil }
        switch url.host?.lowercased() {
        case "invite":
            self = .invite(url.absoluteString)
        case "item":
            guard let path = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "path" })?.value,
                path.hasPrefix("/") else { return nil }
            self = .item(path: path)
        default:
            return nil
        }
    }
}

/// Where an item link leads: a linked folder's detail, and the item inside it to preselect
/// (`nil` for the folder itself).
public struct ItemDestination: Equatable, Sendable {
    public var folderLocalPath: String
    public var selectedPath: String?
}

public enum ItemLinkRouting {
    /// The linked folder that owns `itemPath` (the innermost, when folders nest), or `nil` when
    /// none does. Refuses relative paths and `.`/`..` segments outright: a link is an untrusted
    /// request and must not reach outside a linked folder by spelling. Ownership is decided on
    /// `canonicalize`d paths (symlinks resolved), as the daemon does, so a Finder spelling such as
    /// `/private/var/...` still finds its `/var/...` folder.
    public static func destination(
        for itemPath: String,
        linkedFolders: [String],
        canonicalize: (String) -> String = { $0 }
    ) -> ItemDestination? {
        guard itemPath.hasPrefix("/") else { return nil }
        let components = itemPath.split(separator: "/", omittingEmptySubsequences: true)
        guard !components.contains(".") && !components.contains("..") else { return nil }
        func normal(_ path: String) -> String {
            "/" + canonicalize(path).split(separator: "/", omittingEmptySubsequences: true).joined(separator: "/")
        }
        let item = normal(itemPath)
        let owner = linkedFolders
            .map(normal)
            .enumerated()
            .filter { item == $0.element || item.hasPrefix($0.element == "/" ? "/" : $0.element + "/") }
            .max { $0.element.count < $1.element.count }
        guard let owner else { return nil }
        return ItemDestination(
            folderLocalPath: linkedFolders[owner.offset],
            selectedPath: item == owner.element ? nil : "/" + components.joined(separator: "/"))
    }
}

extension ItemLinkRouting {
    /// Resolves symlinks the way the filesystem does, for the app's real routing.
    static func realPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }
}
