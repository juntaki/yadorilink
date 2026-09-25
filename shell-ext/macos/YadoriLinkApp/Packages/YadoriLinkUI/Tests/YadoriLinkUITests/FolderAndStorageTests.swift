import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@Suite("Wording")
struct WordingTests {
    @Test func oneVocabularyForModesAndFileActions() {
        #expect(FolderMode.keepAll.title == "Keep all files")
        #expect(FolderMode.onDemand.title == "On-Demand")
        #expect(FileAction.download.title == "Download now")
        #expect(FileAction.freeUpSpace.title == "Free up space")
        #expect(FileAction.keepOnDevice.title == "Always keep on this device")
    }

    @Test func everyCaseHasWords() {
        for c in FolderMode.allCases { #expect(!c.title.isEmpty); #expect(!c.hint.isEmpty) }
        for c in FolderState.allCases { #expect(!c.title.isEmpty) }
        for c in DurabilityStatus.allCases { #expect(!c.title.isEmpty) }
        for c in LocalStorageState.allCases { #expect(!c.title.isEmpty) }
        for c in MaterializationState.allCases { #expect(!c.title.isEmpty) }
        for c in AttentionCategory.allCases {
            let text = c.sentence(subject: "X")
            #expect(!text.isEmpty)
            #expect(!text.contains("_"), "no raw codes in \(text)")
        }
        for c in FileAction.allCases { #expect(!c.title.isEmpty) }
    }

    @Test func noOldVocabularyLeaks() {
        let banned = ["hydrate", "hydrated", "evict", "pin", "pinned", "selective", "group", "placeholder", "daemon"]
        var texts = FolderMode.allCases.flatMap { [$0.title, $0.hint] }
        texts += FileAction.allCases.map(\.title)
        texts += MaterializationState.allCases.map(\.title)
        texts += LocalStorageState.allCases.map(\.title)
        texts += AttentionCategory.allCases.map { $0.sentence(subject: "X") }
        texts += [AppBanner.daemonUnavailable.title, AppBanner.signedOut.title]
        for text in texts {
            let words = Set(text.lowercased().split { !$0.isLetter }.map(String.init))
            for word in banned {
                #expect(!words.contains(word.lowercased()), "\"\(text)\" uses \"\(word)\"")
            }
        }
    }

    @Test func errorsMapToOneStyle() {
        #expect(ErrorWording.text(Fixtures.daemonDownError) == "YadoriLink isn't running.")
        #expect(ErrorWording.text(.daemonUnavailable(message: "", reason: .unresponsive)) == "YadoriLink isn't responding. Try again in a moment.")
        #expect(ErrorWording.text(.permissionDenied(message: "401", reason: .sessionRejected)) == "Your session has ended. Sign in again.")
        #expect(ErrorWording.text(.internal(message: "boom", category: "other")) == "Something went wrong.")
    }
}

@Suite("File actions")
struct FileActionTests {
    @Test func onlyApplicableActionsPerState() {
        func actions(_ state: MaterializationState, pinned: Bool = false, tracked: Bool = true) -> [FileAction] {
            FileAction.available(for: FileAvailability(tracked: tracked, state: state, pinned: pinned))
        }
        #expect(actions(.placeholder) == [.download, .keepOnDevice])
        #expect(actions(.hydrated) == [.freeUpSpace, .keepOnDevice])
        #expect(actions(.hydrated, pinned: true) == [.stopKeeping])
        #expect(actions(.hydrating) == [.keepOnDevice])
        #expect(actions(.evicting) == [])
        #expect(actions(.unknown) == [])
        #expect(actions(.hydrated, tracked: false) == [])
    }
}

@MainActor
@Suite("Folder detail")
struct FolderDetailTests {
    @Test func copiesAreOneListWithNamesAndIdTooltips() async throws {
        let (app, client) = try await startedApp(.healthy)
        let photos = app.snapshot!.folders.first { $0.name == "Photos" }!
        let model = FolderDetailViewModel(client: client, folder: photos)
        await model.load()
        #expect(model.copies.map(\.name) == ["Studio", "Office iMac"])
        #expect(model.copies.map(\.status) == ["Available · Direct", "Available · Relayed"])
        #expect(model.copies.first?.tooltip == Fixtures.studioId)
        #expect(model.thisDevice == "On-Demand · 312 on this device · 892 online only")
    }

    @Test func conflictExplanationOnceNotPerFile() async throws {
        let (app, client) = try await startedApp(.problem)
        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        let model = FolderDetailViewModel(client: client, folder: docs)
        await model.load()
        #expect(model.conflicts.count == 3)
        let why = try #require(model.conflictExplanation)
        #expect(why.contains("at the same time"))
        #expect(why.contains("made a folder"), "a copy moved aside for a folder says so")
        let movedAside = try #require(model.conflicts.first { $0.reason == .folderAtPath })
        #expect(movedAside.relation == "moved aside for the folder Receipts")
        let edited = try #require(model.conflicts.first { $0.reason == .concurrentEdit })
        #expect(edited.relation.hasPrefix("the other version is "))
        #expect(model.conflicts.allSatisfy { !$0.subtitle.contains("Why") })
    }

    @Test func fileToolsShowOnlyApplicableActionsAndResultAtWindowLevel() async throws {
        let (app, client) = try await startedApp(.healthy)
        let photos = app.snapshot!.folders.first { $0.name == "Photos" }!
        let path = "/Users/me/Photos/a.jpg"
        client.setAvailability(FileAvailability(tracked: true, state: .placeholder, pinned: false), for: path)
        let model = FolderDetailViewModel(client: client, folder: photos)
        await model.selectFile(path)
        #expect(model.fileActions == [.download, .keepOnDevice])
        await model.perform(.download)
        #expect(model.fileActions == [.freeUpSpace, .keepOnDevice])
        #expect(model.notice == Notice(kind: .success, text: "Downloaded a.jpg."))
    }

    @Test func failedTrashRestoreKeepsTheRow() async throws {
        let (app, client) = try await startedApp(.healthy)
        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        let model = FolderDetailViewModel(client: client, folder: docs)
        await model.load()
        let row = try #require(model.trash.first)

        client.setFailure("restoreFromTrash", Fixtures.daemonDownError)
        await model.restoreFromTrash(row)
        #expect(model.trash.contains(row), "the user can retry")
        #expect(model.notice?.kind == .failure)

        client.setFailure("restoreFromTrash", nil)
        await model.restoreFromTrash(row)
        #expect(!model.trash.contains(row))
        #expect(model.notice?.kind == .success)
    }

    @Test func aTrashedFolderReadsFolderNotItsSize() async throws {
        let (app, client) = try await startedApp(.healthy)
        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        let model = FolderDetailViewModel(client: client, folder: docs)
        await model.load()
        let folder = try #require(model.trash.first { $0.title == "Old drafts" })
        #expect(folder.subtitle.hasPrefix("Folder · "))
        let file = try #require(model.trash.first { $0.title == "Old draft.pages" })
        #expect(!file.subtitle.contains("Folder"))
    }

    @Test func entriesRemovedByOneDeleteAreRestoredAsAFolder() async throws {
        let (app, client) = try await startedApp(.healthy)
        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        let model = FolderDetailViewModel(client: client, folder: docs)
        await model.load()
        let groups = model.trashGroups
        #expect(groups.count == 2)
        let loose = try #require(groups.first { $0.operation == nil })
        #expect(loose.title == nil, "an entry deleted on its own is not a folder")
        let folder = try #require(groups.first { $0.operation != nil })
        #expect(folder.rows.map(\.title) == ["Old drafts", "Old drafts/Chapter 1.pages"])
        #expect(folder.root?.title == "Old drafts")
        #expect(folder.title == "Removed together with Old drafts (2 items)")

        await model.restoreFolder(folder)
        #expect(client.calls.contains("restoreTrashOperation"))
        #expect(model.notice == Notice(kind: .success, text: "Restored 2 items of the folder."))
    }

    @Test func aFolderRestoreNamesWhatDidNotComeBack() {
        let partial = FolderDetailViewModel.folderRestoreNotice(FolderRestoreOutcome(restoredPaths: ["a"], failed: [], partial: true))
        #expect(partial.kind == .success)
        #expect(partial.text.hasPrefix("Restored 1 item of the folder. Part of that delete"))
        let failed = FolderDetailViewModel.folderRestoreNotice(FolderRestoreOutcome(
            restoredPaths: ["a"], failed: [FolderRestoreFailure(path: "a/b", error: "content unavailable")], partial: false))
        #expect(failed.kind == .failure)
        #expect(failed.text == "Restored 1 item of the folder. 1 item couldn't be restored.")
        #expect(failed.detail == "a/b: content unavailable")
    }

    @Test func aSlowActionOnOneFileDoesNotOverwriteTheNextSelection() async throws {
        let client = FakeYadoriLinkClient(scenario: .healthy, latency: 0.05)
        let photos = Fixtures.healthyFolders.first { $0.name == "Photos" }!
        let a = "/Users/me/Photos/a.jpg", b = "/Users/me/Photos/b.jpg"
        client.setAvailability(FileAvailability(tracked: true, state: .placeholder, pinned: false), for: a)
        client.setAvailability(FileAvailability(tracked: true, state: .hydrated, pinned: true), for: b)
        let model = FolderDetailViewModel(client: client, folder: photos)
        await model.selectFile(a)

        async let download: Void = model.perform(.download)
        try await Task.sleep(for: .milliseconds(10))
        await model.selectFile(b)
        await download

        #expect(model.selectedFile == b)
        #expect(model.availability == FileAvailability(tracked: true, state: .hydrated, pinned: true))
    }

    @Test func versionLinesAreReadable() async throws {
        let (app, client) = try await startedApp(.healthy)
        let docs = app.snapshot!.folders.first { $0.name == "Documents" }!
        let model = FolderDetailViewModel(client: client, folder: docs, now: { Fixtures.now })
        await model.selectFile("/Users/me/Documents/Budget.xlsx")
        let first = try #require(model.versions.first)
        #expect(first.text.hasPrefix("v3 · "))
        #expect(first.text.contains("from Studio"))
        #expect(first.text.hasSuffix("(current)"))
        #expect(!first.text.contains("0o644"))
        #expect(first.tooltip.contains("live"))
    }
}

@MainActor
@Suite("Storage")
struct StorageTests {
    @Test func gcMessagesUseBytesNotBlocks() {
        #expect(StorageViewModel.message(for: GcReport(dryRun: true, blocksDeleted: 40, bytesReclaimed: Fixtures.gib)) == "About \(Format.bytes(Fixtures.gib)) can be freed")
        #expect(StorageViewModel.message(for: GcReport(dryRun: false, blocksDeleted: 40, bytesReclaimed: Fixtures.gib)) == "Freed \(Format.bytes(Fixtures.gib))")
        #expect(StorageViewModel.message(for: GcReport(dryRun: true, blocksDeleted: 0, bytesReclaimed: 0)) == "Nothing to free up right now")
    }

    @Test func folderLinesUseModeWording() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        #expect(model.folderLines.first { $0.name == "Documents" }?.text == "Keep all files · 1,204 on this device")
        #expect(model.folderLines.first { $0.name == "Photos" }?.text == "On-Demand · 312 on this device · 892 online only")
    }

    @Test func checkThenReclaim() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        await model.checkReclaimable()
        #expect(model.notice?.text.hasPrefix("About ") == true)
        #expect(model.notice?.detail?.contains("blocks") == true)
        await model.reclaim()
        #expect(model.notice?.text.hasPrefix("Freed ") == true)
    }
}
