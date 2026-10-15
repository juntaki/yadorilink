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
        #expect(FileAction.download.title == "Download Now")
        #expect(FileAction.freeUpSpace.title == "Free Up Space")
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
        func actions(_ state: MaterializationState, tracked: Bool = true, provider: Bool = false,
                     retention: FileRetention? = FileRetention(policy: .reclaimable, inherited: false)) -> [FileAction] {
            FileAction.available(for: FileAvailability(tracked: tracked, state: state), providerFolder: provider, retention: retention)
        }
        #expect(actions(.placeholder) == [.download, .keepOnDevice])
        #expect(actions(.hydrated) == [.keepOnDevice])
        #expect(actions(.hydrated, provider: true) == [.freeUpSpace, .keepOnDevice])
        // The operating system downloads a provider folder's files: no Download now there.
        #expect(actions(.placeholder, provider: true) == [.keepOnDevice])
        #expect(actions(.hydrating) == [])
        #expect(actions(.evicting) == [])
        #expect(actions(.unknown) == [])
        #expect(actions(.hydrated, tracked: false) == [])
        // An ordinary folder cannot give space back (the daemon refuses it): the action is not offered.
        // A kept file is not freed (the daemon refuses it) and can be released; one kept only by a
        // folder above is released by releasing that folder, so it offers neither.
        #expect(actions(.hydrated, provider: true, retention: FileRetention(policy: .pinned, inherited: false)) == [.stopKeeping])
        #expect(actions(.hydrated, retention: FileRetention(policy: .pinned, inherited: true)) == [])
        #expect(actions(.placeholder, retention: FileRetention(policy: .pinned, inherited: false)) == [.download, .stopKeeping])
        // A policy that could not be read offers nothing that depends on it.
        #expect(actions(.hydrated, provider: true, retention: nil) == [])
        #expect(actions(.placeholder, retention: nil) == [.download])
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
        #expect(why.hasPrefix("Edited on two devices; both versions were kept."))
        #expect(why.contains("made a folder"), "a copy moved aside for a folder says so")
        let movedAside = try #require(model.conflicts.first { $0.reason == .folderAtPath })
        #expect(movedAside.relation == "moved aside for the folder Receipts")
        let edited = try #require(model.conflicts.first { $0.reason == .concurrentEdit })
        #expect(edited.relation.hasPrefix("the other version is "))
        #expect(model.conflicts.allSatisfy { !$0.subtitle.contains("Why") })
        #expect(edited.canResolve && !movedAside.canResolve, "only a concurrent-edit file offers keep actions")
        #expect(edited.savedAt != nil)
        await model.resolve(edited, .keepBoth)
        #expect(client.resolvedConflicts.map(\.choice) == [.keepBoth])
        #expect(model.conflicts.count == 2)
        #expect(model.conflictFilePath(edited) == (docs.localPath as NSString).appendingPathComponent(edited.path))
    }

    @Test func keptOriginalsShowForTheirFolderAndReleaseThroughTheFacade() async throws {
        let (app, client) = try await startedApp(.healthy)
        let docs = app.snapshot!.folders.first!
        client.setRetainedOriginals([
            RetainedOriginal(groupId: docs.groupId, path: "old/report.txt", size: 2_048, reachable: true, groupRemoved: false),
            RetainedOriginal(groupId: "other-group", path: "elsewhere.txt", size: 1, reachable: true, groupRemoved: false),
        ])
        let model = FolderDetailViewModel(client: client, folder: docs)
        await model.load()
        #expect(model.retained.map(\.path) == ["old/report.txt"])
        #expect(FolderDetailViewModel.retainedExplanation.contains("could not be proved safe"))
        await model.releaseRetained()
        #expect(model.retained.isEmpty)
        #expect(model.notice?.text == "Released 1 file.")
    }

    @Test func fileToolsShowOnlyApplicableActionsAndResultAtWindowLevel() async throws {
        let (app, client) = try await startedApp(.healthy)
        let photos = app.snapshot!.folders.first { $0.name == "Photos" }!
        let path = "/Users/me/Photos/a.jpg"
        client.setAvailability(FileAvailability(tracked: true, state: .placeholder), for: path)
        let model = FolderDetailViewModel(client: client, folder: photos)
        await model.selectFile(path)
        #expect(model.fileActions == [.download, .keepOnDevice])
        await model.perform(.download)
        #expect(model.fileActions == [.keepOnDevice], "Photos is an ordinary folder: its files cannot be freed")
        #expect(model.notice == Notice(kind: .success, text: "Downloaded a.jpg."))
    }

    @Test func keepingAFileOnThisDeviceIsOneActionAndAKeptFileIsNotFreed() async throws {
        let (app, client) = try await startedApp(.healthy)
        var folder = app.snapshot!.folders.first { $0.name == "Photos" }!
        folder.provider = true
        let path = "/Users/me/Photos/a.jpg"
        client.setAvailability(FileAvailability(tracked: true, state: .hydrated), for: path)
        let model = FolderDetailViewModel(client: client, folder: folder)
        await model.selectFile(path)
        #expect(model.fileActions == [.freeUpSpace, .keepOnDevice])
        await model.perform(.keepOnDevice)
        #expect(model.notice == Notice(kind: .success, text: "a.jpg will always stay on this device."))
        #expect(model.fileActions == [.stopKeeping], "a kept file offers no Free up space")
        #expect(model.retentionLine == "Always kept on this device")
        await model.perform(.stopKeeping)
        #expect(model.notice == Notice(kind: .success, text: "a.jpg is no longer kept on this device. It stays here until you free up space."))
        #expect(model.fileActions == [.freeUpSpace, .keepOnDevice])
        #expect(model.retentionLine == nil)
    }

    @Test func freeUpSpaceIsOfferedOnlyInAProviderFolder() async throws {
        let (app, client) = try await startedApp(.healthy)
        var folder = app.snapshot!.folders.first { $0.name == "Photos" }!
        folder.provider = true
        let path = "/Users/me/Photos/a.jpg"
        client.setAvailability(FileAvailability(tracked: true, state: .hydrated), for: path)
        let model = FolderDetailViewModel(client: client, folder: folder)
        await model.selectFile(path)
        #expect(model.fileActions == [.freeUpSpace, .keepOnDevice])
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
        client.setAvailability(FileAvailability(tracked: true, state: .placeholder), for: a)
        client.setAvailability(FileAvailability(tracked: true, state: .hydrated), for: b)
        let model = FolderDetailViewModel(client: client, folder: photos)
        await model.selectFile(a)

        async let download: Void = model.perform(.download)
        try await Task.sleep(for: .milliseconds(10))
        await model.selectFile(b)
        await download

        #expect(model.selectedFile == b)
        #expect(model.availability == FileAvailability(tracked: true, state: .hydrated))
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
        #expect(StorageViewModel.message(for: GcReport(dryRun: true, blocksDeleted: 40, bytesReclaimed: Fixtures.gib)) == "About \(Format.bytes(Fixtures.gib)) of internal data can be cleaned up")
        #expect(StorageViewModel.message(for: GcReport(dryRun: false, blocksDeleted: 40, bytesReclaimed: Fixtures.gib)) == "Cleaned up \(Format.bytes(Fixtures.gib)) of internal data")
        #expect(StorageViewModel.message(for: GcReport(dryRun: true, blocksDeleted: 0, bytesReclaimed: 0)) == "Nothing to clean up right now")
    }

    @Test func folderLinesUseModeWording() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        #expect(model.folderLines.first { $0.name == "Documents" }?.text == "Keep all files · 1,204 on this device")
        #expect(model.folderLines.first { $0.name == "Photos" }?.text == "On-Demand · 312 on this device · 892 online only")
    }

    @Test func sectionsAreNamedByWhatTheyOwn() {
        #expect(StorageViewModel.filesSectionTitle == "Files on this Mac")
        #expect(StorageViewModel.internalSectionTitle == "YadoriLink internal storage")
        #expect(StorageViewModel.diskSectionTitle == "Free disk space")
        #expect(StorageViewModel.cleanUpActionTitle == "Clean Up YadoriLink Data")
        #expect(StorageViewModel.cleanUpExplanation.contains("does not change the files in your folders"))
        #expect(StorageViewModel.cleanUpExplanation.contains("online only"))
    }

    @Test func internalFiguresAreQualifiedAndNotFolderUsage() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        #expect(StorageViewModel.internalTotalLabel == "YadoriLink data")
        #expect(StorageViewModel.cleanableLabel == "Internal space that can be cleaned up")
        #expect(model.storedData == Format.bytes(app.snapshot!.storage.blockStoreTotalBytes))
        #expect(model.reclaimable == Format.bytes(app.snapshot!.storage.reclaimableEstimateBytes))
    }

    @Test func localFilesTotalsAreCountsOnlyNeverBytes() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        // Sum over the three fixture folders; only Photos has online-only files.
        #expect(model.localFilesTotals == "2,720 on this Mac · 892 online only")
        #expect(model.localFilesTotals?.contains("B") == false)
    }

    @Test func localFilesTotalsMentionDownloadingOnlyWhenAny() {
        var a = Fixtures.folder("A"); a.hydratedFileCount = 5; a.placeholderFileCount = 0; a.hydratingFileCount = 2
        #expect(Format.localFilesTotals([a]) == "5 on this Mac · 2 downloading")
        #expect(Format.localFilesTotals([]) == nil)
    }

    @Test func diskRowsStayPerVolumeAndNeverSum() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        #expect(model.diskRows.count == 3)
        #expect(model.diskRows.allSatisfy { $0.trailing == Format.freeSpace(Fixtures.volume()) })
        #expect(model.diskSummary == "Every disk has enough free space")
    }

    @Test func lowAndCriticalDisksAreCountedNotSummed() {
        let ok = Fixtures.volume("/Volumes/A")
        let low = Fixtures.volume("/Volumes/B", state: .low, available: 7 * Fixtures.gib)
        let crit = Fixtures.volume("/Volumes/C", state: .critical, available: Fixtures.gib)
        #expect(Format.diskSummary([ok, low]) == "1 disk is running low")
        #expect(Format.diskSummary([ok, low, crit]) == "1 disk is critically low, 1 is running low")
        #expect(Format.diskSummary([low, Fixtures.volume("/Volumes/D", state: .low)]) == "2 disks are running low")
        #expect(Format.diskSummary([]) == nil)
    }

    @Test func checkThenReclaim() async throws {
        let (app, _) = try await startedApp(.healthy)
        let model = StorageViewModel(app: app)
        await model.checkReclaimable()
        #expect(model.notice?.text.hasPrefix("About ") == true)
        #expect(model.notice?.detail?.contains("blocks") == true)
        await model.reclaim()
        #expect(model.notice?.text.hasPrefix("Cleaned up ") == true)
    }
}
