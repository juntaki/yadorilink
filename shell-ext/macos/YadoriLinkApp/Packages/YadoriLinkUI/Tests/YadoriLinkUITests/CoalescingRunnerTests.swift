import Testing
@testable import YadoriLinkUI

@MainActor
@Suite("Coalescing runner")
struct CoalescingRunnerTests {
    /// Records each started run and lets the test finish it.
    final class Jobs {
        var finishers: [@Sendable () -> Void] = []
        var started: Int { finishers.count }
    }

    @Test func requestsDuringARunCoalesceIntoOneFollowUpRun() async throws {
        let jobs = Jobs()
        let runner = CoalescingRunner { done in jobs.finishers.append(done) }

        runner.request()
        runner.request()
        runner.request()
        #expect(jobs.started == 1)

        jobs.finishers[0]()
        try await waitUntil("follow-up run") { jobs.started == 2 }

        jobs.finishers[1]()
        try await Task.sleep(for: .milliseconds(50))
        #expect(jobs.started == 2)
    }

    @Test func aRequestAfterARunFinishesStartsANewRun() async throws {
        let jobs = Jobs()
        let runner = CoalescingRunner { done in jobs.finishers.append(done) }

        runner.request()
        jobs.finishers[0]()
        try await Task.sleep(for: .milliseconds(20))
        runner.request()
        #expect(jobs.started == 2)
    }
}
