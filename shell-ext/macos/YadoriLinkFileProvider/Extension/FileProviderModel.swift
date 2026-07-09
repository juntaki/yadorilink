//
//  FileProviderModel.swift — on-demand-sync task 7.3.
//
//  Decodes the JSON the Rust FFI core (`yadorilink_fileprovider_core`)
//  returns and builds the directory tree `NSFileProviderEnumerator` needs
//  from shellipc.proto's flat `ListFolderFilesResponse` (see
//  `fileprovider-core/src/ipc_client.rs`'s doc comment on
//  `list_folder_files`: "not paginated, not directory-scoped" — the
//  daemon returns every file in the group in one response, and it is
//  this extension's job to bucket that into directory levels for
//  `enumerateItems(for:startingAt:)`).
//
//  KNOWN PERFORMANCE GAP (documented honestly, task 7.8): every call
//  here re-fetches the *entire* folder's file list from the daemon —
//  there is no per-path "look up just this one item" RPC on the
//  shell-IPC protocol (only `StatusQuery`, which reports sync/
//  materialization state but not size/mtime/filename), and no
//  in-process caching layer. For a folder group with many files this
//  means `item(for:)` (called once per identifier) does the same O(n)
//  fetch+scan `enumerator(for:)` does. Acceptable for the folder sizes
//  exercised in manual testing; a real product would want either a
//  dedicated single-item lookup RPC or a short-lived in-memory cache
//  invalidated by `NSFileProviderManager.signalEnumerator`.

import Foundation

struct RemoteOnDemandFolder: Decodable {
    let local_path: String
    let group_id: String
}

struct RemoteFileEntry: Decodable {
    let relative_path: String
    let size: UInt64
    let mtime_unix_nanos: Int64
    /// One of "hydrated" | "placeholder" | "hydrating" | "unspecified" —
    /// see `fileprovider-core/src/ipc_client.rs::materialization_state_str`.
    let materialization_state: String
}

/// One node in the directory tree synthesized from the flat file list —
/// either a real file (`entry` set) or a directory inferred purely from
/// being a path-component prefix of some file's `relative_path` (`entry`
/// nil; directories don't carry their own materialization/size/mtime,
/// since shellipc.proto's `FolderFileEntry` only describes files).
struct CatalogNode {
    /// Forward-slash-separated path relative to the folder's local_path;
    /// "" for the root container itself.
    let relativePath: String
    let isDirectory: Bool
    let entry: RemoteFileEntry?

    var filename: String {
        relativePath.isEmpty ? "" : (relativePath as NSString).lastPathComponent
    }

    var parentRelativePath: String {
        guard !relativePath.isEmpty else { return "" }
        let parent = (relativePath as NSString).deletingLastPathComponent
        return parent
    }
}

enum FileProviderCatalog {
    /// Fetches and decodes `yadorilink_fp_list_on_demand_folders()`. Empty
    /// on any decode failure — the daemon side already fails soft to
    /// `"[]"` on its own errors (see fileprovider-core/src/lib.rs), so a
    /// decode failure here would only indicate a schema mismatch, which
    /// should never crash a synchronous OS-facing call.
    static func listOnDemandFolders() -> [RemoteOnDemandFolder] {
        guard let json = yadorilink_fp_list_on_demand_folders() else { return [] }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([RemoteOnDemandFolder].self, from: data)) ?? []
    }

    /// Fetches and decodes `yadorilink_fp_list_folder_files(local_path)`.
    /// Empty on a failure, matching the Rust side's own fail-soft "[]"
    /// fallback.
    static func listFiles(localPath: String) -> [RemoteFileEntry] {
        guard let json = localPath.withCString({ yadorilink_fp_list_folder_files($0) }) else { return [] }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([RemoteFileEntry].self, from: data)) ?? []
    }

    /// Builds every directory node implied by `entries`' relative paths
    /// (e.g. "a/b/c.txt" implies directory nodes "a" and "a/b"), plus one
    /// file node per entry. Order is not significant — callers filter by
    /// `parentRelativePath` afterward.
    static func buildTree(from entries: [RemoteFileEntry]) -> [CatalogNode] {
        var directoryPaths = Set<String>()
        var nodes: [CatalogNode] = []
        for entry in entries {
            nodes.append(CatalogNode(relativePath: entry.relative_path, isDirectory: false, entry: entry))
            var component = (entry.relative_path as NSString).deletingLastPathComponent
            while !component.isEmpty {
                directoryPaths.insert(component)
                let next = (component as NSString).deletingLastPathComponent
                if next == component { break }
                component = next
            }
        }
        for dir in directoryPaths {
            nodes.append(CatalogNode(relativePath: dir, isDirectory: true, entry: nil))
        }
        return nodes
    }

    /// Direct children of `containerRelativePath` ("" for the root).
    static func children(of containerRelativePath: String, in nodes: [CatalogNode]) -> [CatalogNode] {
        nodes.filter { $0.parentRelativePath == containerRelativePath }
    }

    /// Looks up a single node by its relative path ("" for the root
    /// container itself, represented by the caller separately — this
    /// only resolves non-root nodes).
    static func node(at relativePath: String, in nodes: [CatalogNode]) -> CatalogNode? {
        nodes.first { $0.relativePath == relativePath }
    }
}
