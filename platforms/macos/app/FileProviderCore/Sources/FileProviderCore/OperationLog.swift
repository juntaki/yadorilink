import Foundation

/// The logical identity of user operations: one `(session, seq)` pair per logical OS action, kept
/// with the action so every retry of the same action carries the same pair (the daemon answers a
/// replay from its record instead of applying twice). The session is 16 random bytes per domain
/// installation; sequence numbers strictly increase from 1. State is a small JSON file so a
/// relaunched extension continues the same sequence.
public final class OperationLog: @unchecked Sendable {
    private struct State: Codable {
        var session: Data
        var next: UInt64
        var pending: [String: UInt64]
    }

    private let url: URL
    private let lock = NSLock()
    private var state: State

    public init(url: URL) {
        self.url = url
        if let data = try? Data(contentsOf: url), let saved = try? JSONDecoder().decode(State.self, from: data),
            saved.session.count == 16
        {
            state = saved
        } else {
            var bytes = [UInt8](repeating: 0, count: 16)
            for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
            state = State(session: Data(bytes), next: 1, pending: [:])
        }
    }

    public var session: Data {
        lock.lock(); defer { lock.unlock() }
        return state.session
    }

    /// The sequence number of the logical action `fingerprint` names: the one it was given
    /// before if it has not completed, else the next one.
    public func seq(for fingerprint: String) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        if let known = state.pending[fingerprint] { return known }
        let seq = state.next
        state.next += 1
        state.pending[fingerprint] = seq
        persist()
        return seq
    }

    /// The action finished (applied or refused for good): a later identical action is a new one.
    public func complete(_ fingerprint: String) {
        lock.lock(); defer { lock.unlock() }
        if state.pending.removeValue(forKey: fingerprint) != nil { persist() }
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
