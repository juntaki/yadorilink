import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Timed pause and transfer controls")
struct DailyControlsTests {
    private func transfer(_ id: String, _ status: IncomingTransferStatus) -> IncomingTransfer {
        IncomingTransfer(transferId: id, senderDeviceId: "x", files: [IncomingFile(relativePath: "a.txt", size: 10)], totalSize: 10, offeredAt: nil, status: status)
    }

    @Test func everyPauseLengthHasItsOwnMenuItem() {
        #expect(PauseDuration.allCases.map(\.menuTitle) == [
            "Pause Until I Resume", "Pause for 30 Minutes", "Pause for 1 Hour", "Pause Until Tomorrow",
        ])
    }

    @Test func aTimedPauseNamesItsEndAndAnOpenPauseDoesNot() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let now = calendar.date(from: DateComponents(year: 2026, month: 10, day: 15, hour: 10, minute: 0))!
        #expect(PauseText.status(until: nil, now: now, calendar: calendar) == "Paused")
        #expect(PauseText.status(until: now.addingTimeInterval(1800), now: now, calendar: calendar) == "Paused until 10:30 AM")
        let midnight = calendar.date(from: DateComponents(year: 2026, month: 10, day: 16))!
        #expect(PauseText.status(until: midnight, now: now, calendar: calendar) == "Paused until tomorrow")
    }

    @Test func aTimedPauseShowsItsDeadlineAndResumeClearsIt() async throws {
        let (app, _) = try await startedApp(.healthy)
        await app.setAllPaused(true, duration: .oneHour)
        try await waitUntil { app.snapshot?.folders.allSatisfy { $0.paused && $0.pausedUntil != nil } == true }
        await app.setAllPaused(false)
        try await waitUntil { app.snapshot?.folders.allSatisfy { !$0.paused && $0.pausedUntil == nil } == true }
    }

    @Test func cancelAndRetryAreOfferedOnlyWhereTheyApply() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setInbox([
            transfer("pending", .pending), transfer("running", .inProgress), transfer("done", .completed),
            transfer("failed", .failed), transfer("canceled", .canceled),
        ])
        let model = TransfersViewModel(app: app)
        await model.loadInbox()
        let rows = Dictionary(uniqueKeysWithValues: model.inboxRows.map { ($0.tooltip, $0) })
        #expect(rows["pending"]!.canCancel && !rows["pending"]!.canRetry)
        #expect(rows["running"]!.canCancel && !rows["running"]!.canRetry)
        #expect(!rows["done"]!.canCancel && !rows["done"]!.canRetry)
        #expect(rows["failed"]!.canCancel && rows["failed"]!.canRetry)
        #expect(!rows["canceled"]!.canCancel && rows["canceled"]!.canRetry)
    }

    @Test func cancelThenRetryRoundTrips() async throws {
        let (app, client) = try await startedApp(.healthy)
        client.setInbox([transfer("t1", .inProgress)])
        let model = TransfersViewModel(app: app)
        await model.loadInbox()
        await model.cancel(model.inboxRows[0])
        #expect(model.inboxRows[0].status == "Canceled")
        await model.retry(model.inboxRows[0])
        #expect(model.inboxRows[0].status == "Received")
        #expect(model.notice?.kind == .success)
    }
}
