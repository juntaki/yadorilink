import Foundation
import XCTest

/// The File Provider extension's catalog tree, built from the daemon's flat
/// folder listing. Compiled into this bundle from the extension's sources.
final class FileProviderCatalogTreeTests: XCTestCase {
    private func entry(_ path: String, kind: String) -> RemoteFileEntry {
        RemoteFileEntry(relative_path: path, size: 0, mtime_unix_nanos: 0, materialization_state: "hydrated", kind: kind)
    }

    /// An explicit directory is listed as its own entry. It must become the
    /// one directory node at its path, not a file node next to the directory
    /// node its children's paths imply, and an empty one must still be a
    /// directory.
    func testBuildTreeDoesNotDuplicateExplicitDirectoryNode() {
        let nodes = FileProviderCatalog.buildTree(from: [
            entry("album", kind: "directory"),
            entry("album/cover.jpg", kind: "file"),
            entry("empty", kind: "directory"),
        ])

        let album = nodes.filter { $0.relativePath == "album" }
        XCTAssertEqual(album.count, 1)
        XCTAssertEqual(album.first?.isDirectory, true)
        let empty = nodes.filter { $0.relativePath == "empty" }
        XCTAssertEqual(empty.count, 1)
        XCTAssertEqual(empty.first?.isDirectory, true)
        XCTAssertEqual(
            FileProviderCatalog.children(of: "album", in: nodes).map(\.relativePath),
            ["album/cover.jpg"]
        )
        XCTAssertEqual(nodes.filter { !$0.isDirectory }.map(\.relativePath), ["album/cover.jpg"])
    }

    /// The daemon lists explicit directories as entries and nothing for a
    /// directory that only holds synced files (a structural directory, or
    /// an explicit one deleted while a file below it lives). Both are
    /// enumerated as folder items at their own place in the tree, each
    /// exactly once, and an empty explicit directory is a folder too.
    func testBuildTreeEnumeratesExplicitAndStructuralDirectories() {
        let nodes = FileProviderCatalog.buildTree(from: [
            entry("docs", kind: "directory"),
            entry("docs/empty", kind: "directory"),
            entry("trips/2026/beach.jpg", kind: "file"),
            entry("trips/2026/notes (conflicted copy, 2026-01-01-000000, device-b).txt", kind: "file"),
        ])

        let directories = nodes.filter(\.isDirectory).map(\.relativePath).sorted()
        XCTAssertEqual(directories, ["docs", "docs/empty", "trips", "trips/2026"])
        XCTAssertEqual(FileProviderCatalog.children(of: "", in: nodes).map(\.relativePath).sorted(), ["docs", "trips"])
        XCTAssertEqual(FileProviderCatalog.children(of: "docs", in: nodes).map(\.relativePath), ["docs/empty"])
        XCTAssertTrue(FileProviderCatalog.children(of: "docs/empty", in: nodes).isEmpty)
        XCTAssertEqual(
            FileProviderCatalog.children(of: "trips/2026", in: nodes).map(\.relativePath).sorted(),
            ["trips/2026/beach.jpg", "trips/2026/notes (conflicted copy, 2026-01-01-000000, device-b).txt"]
        )
    }
}
