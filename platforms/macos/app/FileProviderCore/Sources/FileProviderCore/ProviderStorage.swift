import Foundation

/// Where the extension keeps its files. They live in the shared App Group container, where the
/// daemon reads staged bytes and writes handed-over ones. When the container cannot be found
/// there is no safe substitute: a private temporary directory is not shared with the daemon, so
/// the extension refuses to work instead of staging bytes the daemon will never see.
public enum ProviderStorage: Equatable {
    case available(providerRoot: URL, operationLog: URL)
    case unavailable

    public static func decide(groupContainer: URL?, domainID: String) -> ProviderStorage {
        guard let groupContainer else { return .unavailable }
        return .available(
            providerRoot: groupContainer.appendingPathComponent("provider", isDirectory: true),
            operationLog: groupContainer.appendingPathComponent("provider-ops-\(domainID).json"))
    }
}

/// The transport of an extension without storage: every call fails as unreachable, which the OS
/// retries later.
public struct UnavailableTransport: ProviderTransport {
    public init() {}
    public func call(_ request: [String: Any]) -> Data? { nil }
}
