import Foundation

/// Runs an asynchronous job one run at a time.
///
/// A request made while a run is in progress does not start a second,
/// overlapping run; it is remembered, and any number of such requests
/// cause exactly one more run after the current one finishes. The app
/// uses it for File Provider domain reconciliation, where two overlapping
/// runs can each act on a different snapshot of the desired set and undo
/// each other's work.
@MainActor
public final class CoalescingRunner {
    /// Starts one run and calls `done` (from any thread) when it has fully
    /// finished, including any asynchronous work it started.
    public typealias Job = (_ done: @escaping @Sendable () -> Void) -> Void

    private let job: Job
    private var isRunning = false
    private var isPending = false

    public init(job: @escaping Job) {
        self.job = job
    }

    public func request() {
        guard !isRunning else {
            isPending = true
            return
        }
        isRunning = true
        job { [weak self] in
            Task { @MainActor in self?.finished() }
        }
    }

    private func finished() {
        isRunning = false
        if isPending {
            isPending = false
            request()
        }
    }
}
