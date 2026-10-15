import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@Suite("Transfer rate and recent problems")
struct TransferActivityTests {
    private func bandwidth(up: UInt64, down: UInt64) -> BandwidthStatus {
        BandwidthStatus(limits: Fixtures.noLimits, currentUploadBytesPerSec: up, currentDownloadBytesPerSec: down)
    }

    // MARK: rate

    @Test func idleShowsNoRate() {
        #expect(TransferRate.text(bandwidth(up: 0, down: 0)) == nil)
    }

    @Test func downloadOnlyHidesUpload() {
        #expect(TransferRate.text(bandwidth(up: 0, down: 7_400_000)) == "↓ 7.4 MB/s")
    }

    @Test func uploadOnlyHidesDownload() {
        #expect(TransferRate.text(bandwidth(up: 1_200_000, down: 0)) == "↑ 1.2 MB/s")
    }

    @Test func bidirectionalShowsDownloadFirst() {
        #expect(TransferRate.text(bandwidth(up: 1_200_000, down: 18_000_000)) == "↓ 18 MB/s · ↑ 1.2 MB/s")
    }

    @Test func tinyRateIsStillHumane() {
        #expect(TransferRate.text(bandwidth(up: 0, down: 900)) == "↓ 900 bytes/s")
    }

    // MARK: recent problems

    private let now = Date(timeIntervalSince1970: 1_000_000)
    private func err(_ category: String, ago: TimeInterval?) -> RecentError {
        RecentError(category: category, at: ago.map { now.addingTimeInterval(-$0) }, context: "hydration")
    }

    @Test func newestFirstDedupedByMeaningCappedAtThree() {
        let items = RecentProblems.items(
            errors: [
                err("io", ago: 600), err("peer_unreachable", ago: 480), err("io", ago: 240),
                err("transport", ago: 900), err("disk_pressure", ago: 720), err("storage", ago: 1200),
            ],
            activeReasons: [], now: now
        )
        #expect(items.map(\.text) == [
            "A file couldn't sync", "Connection was interrupted", "Disk space stopped syncing",
        ])
        #expect(items.map(\.age) == ["4 minutes ago", "8 minutes ago", "12 minutes ago"])
    }

    @Test func unmappedCategoriesStayDiagnosticOnly() {
        let items = RecentProblems.items(errors: [err("config", ago: 10), err("policy", ago: 20)], activeReasons: [], now: now)
        #expect(items.isEmpty)
    }

    @Test func undatedErrorHasNoAge() {
        let items = RecentProblems.items(errors: [err("io", ago: nil)], activeReasons: [], now: now)
        #expect(items.count == 1)
        #expect(items[0].age == nil)
    }

    @Test func rawCategoryOnlyInTooltip() {
        let items = RecentProblems.items(errors: [err("io", ago: 120)], activeReasons: [], now: now)
        #expect(!items[0].text.contains("io"))
        #expect(items[0].tooltip == "io")
    }

    @Test func activeProblemIsNotRepeatedAsRecent() {
        let disk = AttentionReason(category: .lowDiskCritical, subject: "/", folderLocalPath: nil, raw: "low_disk_critical:/")
        let peer = AttentionReason(category: .peerDisconnected, subject: "d", folderLocalPath: nil, raw: "peer_disconnected:d")
        let items = RecentProblems.items(
            errors: [err("disk_pressure", ago: 60), err("peer_unreachable", ago: 90), err("io", ago: 120)],
            activeReasons: [disk, peer], now: now
        )
        #expect(items.map(\.text) == ["A file couldn't sync"])
    }

    @Test func recentErrorReasonsAreNotRepeatedAsAttentionLines() async throws {
        let reasons = [
            AttentionReason(category: .recentError, subject: "io", folderLocalPath: nil, raw: "recent_error:io"),
            AttentionReason(category: .recentError, subject: "io", folderLocalPath: nil, raw: "recent_error:io"),
            AttentionReason(category: .recentError, subject: "config", folderLocalPath: nil, raw: "recent_error:config"),
            AttentionReason(category: .recentError, subject: "policy", folderLocalPath: nil, raw: "recent_error:policy"),
            AttentionReason(category: .lowDisk, subject: "/", folderLocalPath: nil, raw: "low_disk:/"),
        ]
        let kept = RecentProblems.attentionReasons(reasons)
        // Mapped recent errors move to the recent section; unmapped ones collapse to one diagnostic line.
        #expect(kept.map(\.raw) == ["recent_error:config", "low_disk:/"])
    }

    // MARK: summary line

    @Test func menuLineAddsRate() {
        #expect(TransferRate.appending(rate: "↓ 7.4 MB/s", to: "Receiving 3 files · 42%") == "Receiving 3 files · 42% · ↓ 7.4 MB/s")
        #expect(TransferRate.appending(rate: nil, to: "Receiving 3 files · 42%") == "Receiving 3 files · 42%")
    }
}
