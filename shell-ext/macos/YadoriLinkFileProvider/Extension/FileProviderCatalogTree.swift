//
//  FileProviderCatalogTree.swift
//
//  The pure part of the File Provider catalog: the entries the daemon lists
//  for a folder and the directory tree built from them. Foundation only, so
//  the app's unit tests compile it directly without the extension or the
//  Rust FFI core (`FileProviderModel.swift` holds the calls into that).
//

import Foundation

struct RemoteFileEntry: Decodable {
    let relative_path: String
    let size: UInt64
    let mtime_unix_nanos: Int64
    /// One of "hydrated" | "placeholder" | "hydrating" | "unspecified" —
    /// see `fileprovider-core/src/ipc_client.rs::materialization_state_str`.
    let materialization_state: String
    /// One of "file" | "directory" | "symlink" — see
    /// `fileprovider-core/src/ipc_client.rs::entry_kind_str`.
    let kind: String
}

/// One node in the directory tree built from the flat entry list — either
/// a file (`entry` set) or a directory (`entry` nil). A directory is either
/// listed by the daemon as its own entry (an explicit directory) or inferred
/// from being a path-component prefix of some entry's `relative_path`;
/// either way it carries no materialization state, size or mtime of its own.
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
    /// Builds one directory node per explicit directory entry and per
    /// directory implied by `entries`' relative paths (e.g. "a/b/c.txt"
    /// implies directory nodes "a" and "a/b"), with a directory listed both
    /// ways appearing once, plus one file node per other entry. Order is not
    /// significant — callers filter by `parentRelativePath` afterward.
    static func buildTree(from entries: [RemoteFileEntry]) -> [CatalogNode] {
        var directoryPaths = Set<String>()
        var nodes: [CatalogNode] = []
        for entry in entries {
            if entry.kind == "directory" {
                directoryPaths.insert(entry.relative_path)
            } else {
                nodes.append(CatalogNode(relativePath: entry.relative_path, isDirectory: false, entry: entry))
            }
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
