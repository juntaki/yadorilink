import FileProvider
import FileProviderCore

/// Sync anchors are the daemon's event sequence as 8 big-endian bytes; anything else is expired.
func anchorData(_ value: UInt64) -> NSFileProviderSyncAnchor {
    NSFileProviderSyncAnchor(withUnsafeBytes(of: value.bigEndian) { Data($0) })
}

func anchorValue(_ anchor: NSFileProviderSyncAnchor) -> UInt64? {
    anchor.rawValue.count == 8 ? anchor.rawValue.reduce(0) { ($0 << 8) | UInt64($1) } : nil
}

/// The daemon's page token for an OS page: empty for either initial page, else the bytes we issued.
func pageToken(_ page: NSFileProviderPage) -> Data {
    let initial = [NSFileProviderPage.initialPageSortedByName as Data, NSFileProviderPage.initialPageSortedByDate as Data]
    return initial.contains(page.rawValue) ? Data() : page.rawValue
}

/// Lists one folder (or the root) page by page, and reports its changes since an anchor.
final class FolderEnumerator: NSObject, NSFileProviderEnumerator {
    private let client: ProviderClient
    private let parent: Data

    init(client: ProviderClient, parent: Data) {
        self.client = client
        self.parent = parent
    }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        DispatchQueue.global(qos: .userInitiated).async { [client, parent] in
            let token = pageToken(page)
            // A first page of a folder is activity the daemon may prefetch from.
            if token.isEmpty { client.activity(item: parent, fetch: false) }
            switch client.children(of: parent, pageToken: token) {
            case .success(let result):
                observer.didEnumerate(result.items.map { ProviderItem($0) })
                observer.finishEnumerating(upTo: result.nextPageToken.isEmpty ? nil : NSFileProviderPage(result.nextPageToken))
            case .failure(let failure):
                observer.finishEnumeratingWithError(osError(failure))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        DispatchQueue.global(qos: .userInitiated).async { [client, parent] in
            guard let since = anchorValue(anchor) else {
                observer.finishEnumeratingWithError(osError(.anchorExpired))
                return
            }
            switch client.changes(scope: "container", parent: parent, since: since) {
            case .success(let page):
                if !page.upserts.isEmpty { observer.didUpdate(page.upserts.map { ProviderItem($0) }) }
                if !page.removed.isEmpty { observer.didDeleteItems(withIdentifiers: page.removed.map { NSFileProviderItemIdentifier(itemID: $0) }) }
                observer.finishEnumeratingChanges(upTo: anchorData(page.nextAnchor), moreComing: page.more)
            case .failure(let failure):
                observer.finishEnumeratingWithError(osError(failure))
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [client, parent] in
            if case .success(let page) = client.children(of: parent, limit: 1) {
                completionHandler(anchorData(page.anchor))
            } else {
                completionHandler(nil)
            }
        }
    }
}

/// The working set: what the daemon reports as known to the OS, and every event since an anchor.
final class WorkingSetEnumerator: NSObject, NSFileProviderEnumerator {
    private let client: ProviderClient

    init(client: ProviderClient) { self.client = client }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        DispatchQueue.global(qos: .userInitiated).async { [client] in
            let token = pageToken(page)
            switch client.workingSet(pageToken: token) {
            case .success(let result):
                observer.didEnumerate(result.items.map { ProviderItem($0) })
                observer.finishEnumerating(upTo: result.nextPageToken.isEmpty ? nil : NSFileProviderPage(result.nextPageToken))
            case .failure(let failure):
                observer.finishEnumeratingWithError(osError(failure))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        DispatchQueue.global(qos: .userInitiated).async { [client] in
            guard let since = anchorValue(anchor) else {
                observer.finishEnumeratingWithError(osError(.anchorExpired))
                return
            }
            switch client.changes(scope: "working_set", since: since) {
            case .success(let page):
                if !page.upserts.isEmpty { observer.didUpdate(page.upserts.map { ProviderItem($0) }) }
                if !page.removed.isEmpty { observer.didDeleteItems(withIdentifiers: page.removed.map { NSFileProviderItemIdentifier(itemID: $0) }) }
                observer.finishEnumeratingChanges(upTo: anchorData(page.nextAnchor), moreComing: page.more)
            case .failure(let failure):
                observer.finishEnumeratingWithError(osError(failure))
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [client] in
            if case .success(let page) = client.workingSet(limit: 1) {
                completionHandler(anchorData(page.anchor))
            } else {
                completionHandler(nil)
            }
        }
    }
}
