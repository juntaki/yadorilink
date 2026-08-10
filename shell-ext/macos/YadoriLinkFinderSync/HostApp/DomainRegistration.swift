//
//  DomainRegistration.swift
//
//  Reconciles registered NSFileProviderDomains against the daemon's
//  persisted link state — one domain per OnDemand-linked folder group
//  (the managed location, `~/Library/CloudStorage/yadorilink/
//  <group-name>`) — so the YadoriLinkFileProvider extension always has
//  exactly the domains it should, no more and no fewer. Runs from the
//  host app (not the extension itself — an extension process can't
//  register or remove its own domain; only a containing app or an
//  XPC-privileged caller can, per NSFileProviderManager.h) on every
//  launch, since this app has no persistent background presence of its
//  own (matching its existing "exists only to carry the extension
//  bundle, quit it once enabled" design from main.swift).
//
//  DESIRED-STATE SOURCE OF TRUTH: the daemon's own persisted link table
//  (`shell_ipc.rs`'s `ListOnDemandFoldersRequest` handler reads straight
//  from `link_repository().list_links()`, filtered to `OnDemand` and not
//  orphaned) — not a separate flag or cache this file maintains. Every
//  call to `yadorilink_fp_list_on_demand_folders` returns that live
//  snapshot directly.
//
//  FAIL-CLOSED RECONCILIATION: a snapshot-based reconciliation that adds
//  missing domains AND removes stale ones is only as safe as its
//  behavior when the snapshot itself is unavailable. `fetchOnDemandFolders`
//  returns `nil` (not `[]`) when the daemon call failed for any reason —
//  unreachable daemon, timeout, malformed response — and `registerOnDemandDomains`
//  treats `nil` as "cannot currently confirm the desired state, leave
//  every existing registration untouched," never as "the desired state
//  is empty, remove everything." The same applies to
//  `getDomainsWithCompletionHandler` failing: if the CURRENT registration
//  set can't be read, this run only attempts additions (idempotent; the
//  OS harmlessly no-ops or errors on an already-registered domain) and
//  skips removal entirely, since removal requires trusting what's
//  currently there.
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
//
//  DOMAIN REMOVAL DATA-PRESERVATION MODE: the plain
//  `removeDomain:completionHandler:` (no mode) DELETES the on-disk
//  managed-location directory outright, per NSFileProviderManager.h's own
//  doc comment. That is not an acceptable default here — File Provider
//  write support does not exist yet (M1-3), but the READ path already
//  hydrates real file content into the managed location today, and this
//  reconciliation has no way to know, from `group_id` absence alone,
//  whether a user has anything open or otherwise depends on that content
//  still being present at the moment removal fires. This code therefore
//  uses `removeDomain:mode:completionHandler:` with
//  `.preserveDownloadedUserData` (API_AVAILABLE(macos(12.0)) per
//  FileProvider.framework's own NSFileProviderDefines.h -- this target's
//  own MACOSX_DEPLOYMENT_TARGET is bumped to 12.0 in project.yml
//  specifically for this call; YadoriLinkFileProvider itself correctly
//  stays at the project-wide 11.0 base, verified directly against this
//  SDK's headers, not the "macOS 13+" figure an earlier version of this
//  comment repeated from elsewhere in this codebase) rather than the
//  mode-less overload —
//  removal still only ever fires for a domain whose group_id is CONFIRMED
//  absent from the daemon's own live snapshot (never one this run simply
//  failed to hear about, per the FAIL-CLOSED RECONCILIATION note above),
//  but "confirmed absent from the desired-state snapshot" is a claim about
//  the daemon's *link* state, not a claim that no local content matters
//  anymore.
//
//  NOT YET DECIDED (left for M1-3, not resolved here): `OnDemand → Eager`
//  (content should end up materialized as a normal Eager copy, not merely
//  "preserved" wherever the OS puts it) and `unlink` (content disposition
//  is a user decision, possibly "discard entirely") likely need DIFFERENT
//  preservation semantics from each other and from this default. Do not
//  read `.preserveDownloadedUserData` as a final answer for either case —
//  it is only the conservative choice for what this PR's scope handles
//  (a group_id that dropped out of the OnDemand set, of either kind,
//  through today's blunt reconciliation).

import FileProvider

enum DomainRegistration {
    static func registerOnDemandDomains() {
        guard let folders = fetchOnDemandFolders() else {
            NSLog("yadorilink: DomainRegistration could not confirm desired state (daemon unreachable); leaving existing domains untouched")
            return
        }
        let desiredIdentifiers = Set(folders.map { $0.group_id })

        NSFileProviderManager.getDomainsWithCompletionHandler { existingDomains, error in
            let existingIdentifiers = Set(existingDomains.map { $0.identifier.rawValue })

            for folder in folders {
                guard !existingIdentifiers.contains(folder.group_id) else {
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

            guard error == nil else {
                NSLog("yadorilink: DomainRegistration failed to list existing domains (\(error!)); skipping removal this run")
                return
            }
            for existingDomain in existingDomains where !desiredIdentifiers.contains(existingDomain.identifier.rawValue) {
                // `.preserveDownloadedUserData`, not the mode-less
                // overload -- see this file's own DOMAIN REMOVAL
                // DATA-PRESERVATION MODE doc comment for why.
                NSFileProviderManager.remove(existingDomain, mode: .preserveDownloadedUserData) { preservedLocation, error in
                    if let error {
                        NSLog("yadorilink: failed to remove stale domain \(existingDomain.identifier.rawValue): \(error)")
                    } else {
                        NSLog("yadorilink: removed stale File Provider domain \(existingDomain.identifier.rawValue) (no longer OnDemand-linked); preserved data at \(preservedLocation?.path ?? "<none>")")
                    }
                }
            }
        }
    }

    private struct Folder: Decodable { let local_path: String; let group_id: String }

    /// `nil` means the desired state could not be confirmed this run
    /// (daemon unreachable, timeout, malformed response) — distinct from
    /// `[]`, a confirmed "no OnDemand folders exist right now." See this
    /// file's own FAIL-CLOSED RECONCILIATION doc comment for why that
    /// distinction is load-bearing.
    private static func fetchOnDemandFolders() -> [Folder]? {
        guard let json = yadorilink_fp_list_on_demand_folders() else { return nil }
        defer { yadorilink_fp_free_string(json) }
        guard let str = String(cString: json, encoding: .utf8), let data = str.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode([Folder].self, from: data)
    }
}
