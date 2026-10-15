import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@Suite("Finder item links")
struct ItemLinkParsingTests {
    // The same literal the Finder extension's FinderDeepLink test pins, so the two sides of the
    // contract cannot drift apart unnoticed.
    @Test func theItemLinkTheExtensionBuildsIsParsed() throws {
        let url = try #require(URL(string: "yadorilink://item?path=/Users/me/Work/a%20b.txt"))
        #expect(AppLink(url: url) == .item(path: "/Users/me/Work/a b.txt"))
    }

    @Test func reservedCharactersSurviveTheRoundTrip() throws {
        let path = "/Users/me/R&D+x=1/100%/日本語.txt"
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~/")
        let url = try #require(URL(string: "yadorilink://item?path=" + path.addingPercentEncoding(withAllowedCharacters: allowed)!))
        #expect(AppLink(url: url) == .item(path: path))
    }

    @Test func inviteLinksAreStillInvites() throws {
        let url = try #require(URL(string: "yadorilink://invite/K7QX-M2PA"))
        #expect(AppLink(url: url) == .invite("yadorilink://invite/K7QX-M2PA"))
    }

    @Test func malformedOrForeignLinksAreRejected() throws {
        for raw in ["yadorilink://item", "yadorilink://item?path=", "yadorilink://item?path=relative/x",
                    "yadorilink://item?other=/x", "yadorilink://elsewhere/x", "https://item?path=/x"] {
            #expect(AppLink(url: try #require(URL(string: raw))) == nil, "\(raw)")
        }
    }
}

@Suite("Finder item routing")
struct ItemRoutingTests {
    let folders = ["/Users/me/Work", "/Users/me/Work/Nested", "/Users/me/Photos"]

    @Test func aFolderRootOpensThatFolderWithNothingSelected() {
        #expect(ItemLinkRouting.destination(for: "/Users/me/Photos", linkedFolders: folders)
                == ItemDestination(folderLocalPath: "/Users/me/Photos", selectedPath: nil))
        #expect(ItemLinkRouting.destination(for: "/Users/me/Photos/", linkedFolders: folders)
                == ItemDestination(folderLocalPath: "/Users/me/Photos", selectedPath: nil))
    }

    @Test func aChildSelectsItInTheOwningFolder() {
        #expect(ItemLinkRouting.destination(for: "/Users/me/Photos/2026/a.jpg", linkedFolders: folders)
                == ItemDestination(folderLocalPath: "/Users/me/Photos", selectedPath: "/Users/me/Photos/2026/a.jpg"))
    }

    @Test func theInnermostLinkedFolderOwnsTheItem() {
        #expect(ItemLinkRouting.destination(for: "/Users/me/Work/Nested/x.txt", linkedFolders: folders)?.folderLocalPath
                == "/Users/me/Work/Nested")
    }

    @Test func aSiblingWithTheSamePrefixIsNotOwned() {
        #expect(ItemLinkRouting.destination(for: "/Users/me/PhotosOld/a.jpg", linkedFolders: folders) == nil)
    }

    @Test func aSymlinkedSpellingOfTheRootOrItemStillMatchesByItsRealPath() {
        // The daemon canonicalizes both sides (/var is /private/var); the app must agree.
        let real: (String) -> String = { $0.hasPrefix("/private") ? String($0.dropFirst("/private".count)) : $0 }
        #expect(ItemLinkRouting.destination(for: "/private/var/Work/a.txt", linkedFolders: ["/var/Work"], canonicalize: real)
                == ItemDestination(folderLocalPath: "/var/Work", selectedPath: "/private/var/Work/a.txt"))
        #expect(ItemLinkRouting.destination(for: "/private/var/Work", linkedFolders: ["/var/Work"], canonicalize: real)
                == ItemDestination(folderLocalPath: "/var/Work", selectedPath: nil))
        #expect(ItemLinkRouting.destination(for: "/private/var/Work/a.txt", linkedFolders: ["/var/Work"]) == nil,
                "without canonicalization the spellings differ")
    }

    @Test func pathsOutsideEveryLinkedFolderOrWithDotSegmentsAreRefused() {
        #expect(ItemLinkRouting.destination(for: "/etc/passwd", linkedFolders: folders) == nil)
        #expect(ItemLinkRouting.destination(for: "/Users/me/Photos/../../../etc/passwd", linkedFolders: folders) == nil)
        #expect(ItemLinkRouting.destination(for: "/Users/me/Photos/./a.jpg", linkedFolders: folders) == nil)
        #expect(ItemLinkRouting.destination(for: "relative/a.jpg", linkedFolders: folders) == nil)
    }
}

@MainActor
@Suite("Finder item links in the app")
struct ItemLinkContextTests {
    private func started(_ scenario: FakeScenario = .healthy) async throws -> AppContext {
        let (app, _) = try await startedApp(scenario)
        return AppContext(app: app, loginItem: LoginItemModel(service: FakeLoginItemService(status: .enabled)), openURL: { _ in })
    }

    @Test func aChildOfALinkedFolderOpensTheFolderWithTheFileSelected() async throws {
        let context = try await started()
        let folder = try #require(context.app.snapshot?.folders.first)
        let file = folder.localPath + "/sub/a.jpg"
        context.receive(.item(path: file))
        #expect(context.routePendingItem())
        #expect(context.sidebar == .folders)
        #expect(context.folderPath == [folder.localPath])
        #expect(context.takeFileSelection(for: folder.localPath) == file)
        #expect(context.takeFileSelection(for: folder.localPath) == nil, "taken once")
        #expect(context.pendingItemPath == nil)
    }

    @Test func aFolderRootOpensItsDetailWithoutASelection() async throws {
        let context = try await started()
        let folder = try #require(context.app.snapshot?.folders.first)
        context.receive(.item(path: folder.localPath))
        #expect(context.routePendingItem())
        #expect(context.folderPath == [folder.localPath])
        #expect(context.takeFileSelection(for: folder.localPath) == nil)
    }

    @Test func aSelectionIsOnlyTakenByItsOwnFolder() async throws {
        let context = try await started()
        let folder = try #require(context.app.snapshot?.folders.first)
        context.receive(.item(path: folder.localPath + "/a.jpg"))
        _ = context.routePendingItem()
        #expect(context.takeFileSelection(for: "/somewhere/else") == nil)
        #expect(context.takeFileSelection(for: folder.localPath) != nil)
    }

    @Test func aLinkBeforeTheFirstStatusWaitsAndThenRoutes() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy)
        let app = AppModel(client: client, pollInterval: 0.05)
        let context = AppContext(app: app, loginItem: LoginItemModel(service: FakeLoginItemService(status: .enabled)), openURL: { _ in })
        context.receive(.item(path: "/Users/me/Documents/Budget.xlsx"))
        #expect(!context.routePendingItem(), "no status yet: keep waiting")
        #expect(context.pendingItemPath != nil)
        app.start()
        try await waitUntil("first status") { app.snapshot != nil }
        #expect(context.routePendingItem())
        #expect(context.folderPath == ["/Users/me/Documents"])
        #expect(context.takeFileSelection(for: "/Users/me/Documents") == "/Users/me/Documents/Budget.xlsx")
    }

    @Test func aPathOutsideEveryLinkedFolderIsDroppedWithoutNavigating() async throws {
        let context = try await started()
        context.receive(.item(path: "/etc/passwd"))
        #expect(context.routePendingItem(), "decided: nothing to open")
        #expect(context.pendingItemPath == nil)
        #expect(context.folderPath.isEmpty)
    }

    @Test func anInviteLinkStillGoesToTheJoinWindow() async throws {
        let context = try await started()
        context.receive(.invite("yadorilink://invite/K7QX-M2PA"))
        #expect(context.pendingInviteLink == "yadorilink://invite/K7QX-M2PA")
        #expect(context.pendingItemPath == nil)
    }
}
