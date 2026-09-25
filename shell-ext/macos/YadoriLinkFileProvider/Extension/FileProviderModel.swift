//
//  FileProviderModel.swift —.
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
//  KNOWN PERFORMANCE GAP (documented honestly): every call
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

extension FileProviderCatalog {
    /// Fetches and decodes `yadorilink_fp_list_on_demand_folders`. Empty
    /// on a NULL return (the daemon side returns NULL, not `"[]"`, when it
    /// can't confirm the desired state — see fileprovider-core/src/lib.rs)
    /// or a decode failure. This call site only needs its own folder's
    /// entry to re-derive `localPath`, not a reconciliation snapshot, so
    /// collapsing "can't confirm" and "confirmed empty" back to `[]` here
    /// is fine — unlike `DomainRegistration.swift`'s add/remove
    /// reconciliation, which must keep them distinct.
    static func listOnDemandFolders() -> [RemoteOnDemandFolder] {
        guard let json = yadorilink_fp_list_on_demand_folders() else { return [] }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([RemoteOnDemandFolder].self, from: data)) ?? []
    }

    /// Fetches and decodes `yadorilink_fp_list_folder_files(local_path)`.
    /// `nil` when the listing could not be confirmed: the Rust side
    /// returns NULL (not `"[]"`) for an unreachable daemon, a timeout or
    /// the daemon's own `snapshot_available == false`, and a decode
    /// failure is the same. `[]` is only ever a confirmed empty folder.
    /// Callers must fail the OS callback (`.serverUnreachable`) on `nil`;
    /// the File Provider treats a successful enumeration as authoritative.
    static func listFiles(localPath: String) -> [RemoteFileEntry]? {
        guard let json = localPath.withCString({ yadorilink_fp_list_folder_files($0) }) else { return nil }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode([RemoteFileEntry].self, from: data)
    }
}
