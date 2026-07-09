//
//  DomainRegistration.swift
//
//  Registers one NSFileProviderDomain per OnDemand-linked folder group
//  (the managed location, `~/Library/CloudStorage/yadorilink/
//  <group-name>`) so the YadoriLinkFileProvider extension gets a domain to
//  serve. Runs from the host app (not the extension itself — an
//  extension process can't register its own domain; only a containing
//  app or an XPC-privileged caller can, per NSFileProviderManager.h) on
//  every launch, since this app has no persistent background presence
//  of its own (matching its existing "exists only to carry the
//  extension bundle, quit it once enabled" design from main.swift) and
//  is the natural place to answer "how does the extension learn which
//  OnDemand folder groups exist": ask
//  the daemon directly via `yadorilink_fp_list_on_demand_folders`, same as
//  the extension itself does when re-deriving its own `localPath` (see
//  YadoriLinkFileProvider/Extension/FileProviderExtension.swift).
//
//  ARCHITECTURE DECISION (not fully pinned down by the spec):
//  domain *identifier* = the folder group's group_id (stable, daemon-
//  assigned, matches what shellipc.proto's `OnDemandFolder.group_id`
//  already reports); domain *displayName* = the local folder's own last
//  path component. `NSFileProviderDomain(identifier:displayName:)` (the
//  2-argument replicated-domain initializer, confirmed via this SDK's
//  NSFileProviderDomain.h to mount automatically under
//  `~/Library/CloudStorage/<vendor>/<displayName>` — no
//  `pathRelativeToDocumentStorage` needed, that overload is for the
//  older non-replicated extension type) is used rather than any
//  path-based constructor, matching the "macOS mounts at a fixed
//  managed location" constraint exactly.
//
//  UNVERIFIED (flagged honestly): which exact vendor-level folder name
//  macOS uses under `~/Library/CloudStorage/` (i.e. whether it is
//  literally "yadorilink" as the managed-location convention specifies,
//  or derived from some other piece of this bundle's metadata) was not
//  independently confirmed against Apple's non-header documentation in
//  this session — the SDK headers read directly (NSFileProviderDomain.h)
//  don't name the exact source of that path component. This needs a real
//  VM screenshot of `~/Library/CloudStorage/` after domain registration
//  to confirm.

import FileProvider

enum DomainRegistration {
    static func registerOnDemandDomains() {
        let folders = fetchOnDemandFolders()
        guard !folders.isEmpty else {
            NSLog("yadorilink: DomainRegistration found no OnDemand folders to register (daemon unreachable or none linked)")
            return
        }
        NSFileProviderManager.getDomainsWithCompletionHandler { existingDomains, error in
            if let error {
                NSLog("yadorilink: DomainRegistration failed to list existing domains: \(error)")
            }
            let existingIdentifiers = Set(existingDomains.map { $0.identifier.rawValue })
            for folder in folders {
                guard !existingIdentifiers.contains(folder.group_id) else {
                    NSLog("yadorilink: domain \(folder.group_id) already registered, skipping")
                    continue
                }
                let displayName = (folder.local_path as NSString).lastPathComponent
                let identifier = NSFileProviderDomainIdentifier(folder.group_id)
                let domain = NSFileProviderDomain(identifier: identifier, displayName: displayName)
                NSFileProviderManager.add(domain) { error in
                    if let error {
                        NSLog("yadorilink: failed to register domain \(folder.group_id) (\(displayName)): \(error)")
                    } else {
                        NSLog("yadorilink: registered File Provider domain \(folder.group_id) (\(displayName))")
                    }
                }
            }
        }
    }

    private struct Folder: Decodable { let local_path: String; let group_id: String }

    private static func fetchOnDemandFolders() -> [Folder] {
        guard let json = yadorilink_fp_list_on_demand_folders() else { return [] }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([Folder].self, from: data)) ?? []
    }
}
