import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Home summary")
struct ProductSummaryTests {
    private func summary(_ snapshot: StatusSnapshot?, down: Bool = false, names: [String: String] = [:]) -> ProductSummary {
        ProductSummary.make(snapshot: snapshot, daemonUnavailable: down, deviceNames: names)
    }

    @Test func answersInTheOrderAPersonAsks() {
        let s = summary(Fixtures.snapshot(folders: Fixtures.healthyFolders))
        #expect(s.lines.map(\.label) == ["Status", "Syncing", "Waiting", "Your attention", "Protection"])
        #expect(s.health.text == "YadoriLink is running normally")
        #expect(s.syncing.text == "Everything is up to date")
        #expect(s.waiting.text == "Not waiting for anything")
        #expect(s.action.text == "Nothing needs you right now")
        #expect(s.protection.text == "Protected · another device has a copy")
        #expect(s.storage?.contains("GB") == true)
    }

    @Test func daemonDownClaimsNothing() {
        let s = summary(nil, down: true)
        #expect(s.health.text == "YadoriLink isn't running.")
        #expect(s.health.tone == .danger)
        #expect(s.lines.dropFirst().allSatisfy { $0.tone == .neutral })
        #expect(s.protection.text == "Checking protection")
        #expect(s.waiting.text != "Not waiting for anything")
        #expect(s.storage == nil)
    }

    @Test func protectionWordingNeverClaimsProtectedForUnknown() {
        func line(_ p: Protection, _ ids: [String] = []) -> SummaryLine {
            summary(Fixtures.snapshot(folders: Fixtures.healthyFolders, protection: ProtectionSummary(protection: p, deviceIds: ids))).protection
        }
        #expect(line(.protected, ["a", "b"]).text == "Protected · 2 other devices have a copy")
        #expect(line(.atRisk).text == "At risk · this Mac is the only confirmed copy")
        #expect(line(.atRisk).tone == .danger)
        #expect(line(.pending).text == "Protection pending")
        #expect(line(.unknown).text == "Checking protection")
        #expect(line(.unknown).tone == .neutral)
        #expect(line(.unknown).text.contains("Protected") == false)
    }

    @Test func waitingNamesTheOfflineDeviceOrSaysAnotherDevice() {
        let waiting = AvailabilitySummary(availability: .waitingForPeer, reachableDeviceIds: [], offlineDeviceIds: [Fixtures.officeId])
        let snap = Fixtures.snapshot(folders: Fixtures.healthyFolders, availability: waiting)
        #expect(summary(snap, names: [Fixtures.officeId: "Office iMac"]).waiting.text == "Waiting for Office iMac to come online")
        #expect(summary(snap).waiting.text == "Waiting for another device to come online")

        let unknown = Fixtures.snapshot(folders: Fixtures.healthyFolders, availability: .unknown)
        #expect(summary(unknown).waiting.text == "Checking…")
        let exact = AvailabilitySummary(availability: .waitingForExactContent, reachableDeviceIds: [], offlineDeviceIds: [])
        #expect(summary(Fixtures.snapshot(folders: Fixtures.healthyFolders, availability: exact)).waiting.text.hasPrefix("Waiting for the latest version"))
    }

    @Test func syncingPausedAndEmpty() {
        #expect(summary(Fixtures.syncingSnapshot).syncing.text == "Syncing 2 files")
        let paused = Fixtures.healthyFolders.map { f -> FolderSummary in var f = f; f.paused = true; return f }
        #expect(summary(Fixtures.snapshot(folders: paused)).syncing.text == "Syncing is paused")
        let empty = summary(Fixtures.snapshot(folders: []))
        #expect(empty.syncing.text == "No folders yet")
        #expect(empty.protection.text == "No folders yet")
    }

    @Test func problemCountsIssuesAndNoInternalTerms() {
        let s = summary(Fixtures.problemSnapshot)
        #expect(s.health.tone == .warning)
        #expect(s.action.text == "3 issues need attention")
        #expect(s.protection.text.hasPrefix("At risk"))
        let jargon = ["DAG", "hydrat", "custody", "durab", "replica", "block"]
        for line in s.lines {
            for word in jargon { #expect(line.text.lowercased().contains(word.lowercased()) == false) }
        }
    }

    @Test func attentionActionsLeadToExistingScreens() async throws {
        let home = HomeViewModel(app: try await startedApp(.problem).0)
        let disk = try #require(home.attentionItems.first { $0.text.contains("running low") })
        #expect(disk.primary.action == .freeUpSpace)
        #expect(disk.primary.destination == .sidebar(.storage))
        let details = try #require(home.attentionItems.first { $0.text.contains("no complete copy") })
        #expect(details.primary.action == .viewDetails)
        #expect(details.primary.destination == .folder(try #require(details.folderLocalPath)))
        #expect(ProductAction.retry.title == "Try Again")
    }

    @Test func waitingItemsAreNotCountedAsNeedingTheUser() async throws {
        let home = HomeViewModel(app: try await startedApp(.problem).0)
        #expect(home.attentionItems.count == 3)
        #expect(home.waitingLines.count == 1)
        #expect(home.attentionItems.allSatisfy { !$0.text.contains("offline") })
        #expect(home.summary.protection.text == "At risk · this Mac is the only confirmed copy")
        #expect(MenuBarPresentation(app: home.app).protectionLine == "At risk · this Mac is the only confirmed copy")
    }

    @Test func updateActionOpensTheUpdatesTab() {
        let reason = AttentionReason(category: .updateFailed, subject: "", folderLocalPath: nil, raw: "x", kind: .permanent, primaryAction: .downloadUpdate)
        let snap = Fixtures.snapshot(folders: Fixtures.healthyFolders)
        #expect(reason.primaryAction.destination(for: reason, in: snap) == .settings(.updates))
    }

    @Test func listJoin() {
        #expect(ListWording.join(["A"]) == "A")
        #expect(ListWording.join(["A", "B"]) == "A and B")
        #expect(ListWording.join(["A", "B", "C"]) == "A, B and C")
    }
}
