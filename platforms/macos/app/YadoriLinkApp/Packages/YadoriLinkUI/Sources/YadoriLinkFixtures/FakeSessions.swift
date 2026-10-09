// Fakes for the two long-lived handles: the status watch and the sign-in
// session. Both follow the same `next` contract as the real ones.

import Foundation
import YadoriLinkModel

/// Reports the fake client's status. The first `next()` returns at once;
/// later calls wait until the status changes or `refresh()` is called.
/// Latest wins: a slow consumer never sees a backlog.
public final class FakeStatusWatch: StatusWatchHandle, @unchecked Sendable {
    private let lock = NSLock()
    private let source: @Sendable () -> StatusUpdate?
    private var lastDelivered: StatusUpdate?
    private var forced = false
    private var cancelled = false
    private var waiter: CheckedContinuation<StatusUpdate?, Never>?

    init(source: @escaping @Sendable () -> StatusUpdate?) {
        self.source = source
    }

    public func next() async -> StatusUpdate? {
        await withCheckedContinuation { continuation in
            let ready: StatusUpdate?? = lock.withLock {
                if cancelled { return .some(nil) }
                guard let current = source() else { return .some(nil) }
                if lastDelivered == nil || forced || current != lastDelivered {
                    forced = false
                    lastDelivered = current
                    return .some(current)
                }
                waiter = continuation
                return .none
            }
            if case .some(let value) = ready { continuation.resume(returning: value) }
        }
    }

    public func refresh() {
        let resume: (CheckedContinuation<StatusUpdate?, Never>, StatusUpdate?)? = lock.withLock {
            guard let waiter else { forced = true; return nil }
            self.waiter = nil
            let current = source()
            lastDelivered = current
            return (waiter, current)
        }
        if let (continuation, value) = resume { continuation.resume(returning: value) }
    }

    public func cancel() {
        let pending = lock.withLock { () -> CheckedContinuation<StatusUpdate?, Never>? in
            cancelled = true
            defer { waiter = nil }
            return waiter
        }
        pending?.resume(returning: nil)
    }

    func sourceChanged() {
        let resume: (CheckedContinuation<StatusUpdate?, Never>, StatusUpdate)? = lock.withLock {
            guard let waiter, let current = source(), current != lastDelivered else { return nil }
            self.waiter = nil
            lastDelivered = current
            return (waiter, current)
        }
        if let (continuation, value) = resume { continuation.resume(returning: value) }
    }
}

/// Replays a scripted list of sign-in events. If the script runs out before
/// a terminal event, `nextEvent()` waits until `cancel()` is called, like a
/// browser the user never finishes with.
public final class FakeLoginSession: LoginSessionHandle, @unchecked Sendable {
    public struct Step: Sendable {
        public var event: LoginEvent
        public var delay: TimeInterval
        public init(_ event: LoginEvent, delay: TimeInterval = 0) {
            self.event = event
            self.delay = delay
        }
    }

    private let lock = NSLock()
    private var steps: [Step]
    private let beginError: DesktopError?
    private let onSignedIn: @Sendable (AccountStatus) -> Void
    private var begun = false
    private var cancelled = false
    private var finished = false
    private var waiter: CheckedContinuation<Void, Never>?

    public init(steps: [Step], beginError: DesktopError? = nil, onSignedIn: @escaping @Sendable (AccountStatus) -> Void = { _ in }) {
        self.steps = steps
        self.beginError = beginError
        self.onSignedIn = onSignedIn
    }

    public func begin() throws {
        try lock.withLock {
            if let beginError { throw beginError }
            if begun { throw DesktopError.invalidInput(message: "sign-in already started", field: nil) }
            begun = true
        }
    }

    public func nextEvent() async -> LoginEvent? {
        let step: Step?? = lock.withLock {
            if finished { return .some(nil) }
            if cancelled { finished = true; return .some(Step(.cancelled)) }
            if steps.isEmpty { return .none }
            return .some(steps.removeFirst())
        }
        switch step {
        case .some(nil):
            return nil
        case .some(let s?):
            if s.delay > 0 { try? await Task.sleep(for: .seconds(s.delay)) }
            let wasCancelled = lock.withLock { () -> Bool in
                if cancelled && !s.event.isTerminal { finished = true; return true }
                if s.event.isTerminal { finished = true }
                return false
            }
            if wasCancelled { return .cancelled }
            if case .signedIn(let account) = s.event { onSignedIn(account) }
            return s.event
        case .none:
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                let resumeNow = lock.withLock { () -> Bool in
                    if cancelled { return true }
                    waiter = c
                    return false
                }
                if resumeNow { c.resume() }
            }
            return await nextEvent()
        }
    }

    public func cancel() {
        let pending = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            cancelled = true
            defer { waiter = nil }
            return waiter
        }
        pending?.resume()
    }
}
