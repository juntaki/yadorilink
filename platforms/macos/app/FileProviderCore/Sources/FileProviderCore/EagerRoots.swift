import Foundation

/// What the daemon said about the ordinary linked folders. `unavailable` (daemon down, timeout,
/// no confirmation) is deliberately not `confirmed([])`: a confirmed empty set means "no linked
/// folders", an unavailable one means "do not know".
enum EagerRootSnapshot: Equatable {
    case confirmed([String])
    case unavailable
}

/// The Finder extension's eager (ordinary folder) roots. Holds the last CONFIRMED set for this
/// process: an unavailable snapshot never replaces it, a confirmed one replaces it exactly. Before
/// the first confirmation nothing is monitored (no guessed fallback root).
struct EagerRootSet: Equatable {
    private(set) var roots: Set<URL> = []

    /// Applies one snapshot; true when the monitored set changed.
    @discardableResult
    mutating func apply(_ snapshot: EagerRootSnapshot) -> Bool {
        guard case .confirmed(let paths) = snapshot else { return false }
        let next = Set(paths.map { URL(fileURLWithPath: $0, isDirectory: true) })
        guard next != roots else { return false }
        roots = next
        return true
    }
}

/// Everything the Finder extension monitors: the daemon's linked folders plus the File Provider
/// domains' mount roots, each with its own last-confirmed set (a failed listing of one never
/// disturbs the other). No existence check: the sandboxed extension often cannot stat a linked
/// folder, and Finder simply observes nothing at a path that is not there (yet).
struct MonitoredRoots: Equatable {
    private var eager = EagerRootSet()
    private var provider = EagerRootSet()

    @discardableResult
    mutating func applyEager(_ snapshot: EagerRootSnapshot) -> Bool { eager.apply(snapshot) }

    @discardableResult
    mutating func applyProvider(_ snapshot: EagerRootSnapshot) -> Bool { provider.apply(snapshot) }

    func monitored() -> Set<URL> {
        eager.roots.union(provider.roots)
    }
}
