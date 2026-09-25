import Foundation
import YadoriLinkModel

/// The one place the app chooses its client.
///
/// Release builds always use the live client over the Rust client core.
/// Debug builds use the fake client with fixture states by default, for
/// development and screenshots; pass `-live` (or set `YADORILINK_CLIENT=live`)
/// to run a Debug build against the real daemon instead. The fake shows
/// made-up folders and only pretends to act, so it is never compiled into a
/// Release build. Every view and view model only sees `YadoriLinkClient`.
///
/// In Debug, pick a fixture with `-fixture <name>` on the command line or
/// the `YADORILINK_FIXTURE` environment variable, for example
/// `open YadoriLink.app --args -fixture daemonDown`.
enum ClientFactory {
    /// How the app brings the daemon up: through its LaunchAgent, falling
    /// back to the installed binary by absolute path.
    static let coreConfig = CoreConfig(
        daemonLaunch: .launchAgent(label: "com.yadorilink.daemon", fallbackBinary: "/usr/local/bin/yadorilink-daemon")
    )

    static func makeLiveClient() -> any YadoriLinkClient {
        LiveYadoriLinkClient(config: coreConfig)
    }
}

#if DEBUG
import YadoriLinkFixtures

extension ClientFactory {
    static func makeClient(arguments: [String] = CommandLine.arguments, environment: [String: String] = ProcessInfo.processInfo.environment) -> any YadoriLinkClient {
        if arguments.contains("-live") || environment["YADORILINK_CLIENT"] == "live" {
            return makeLiveClient()
        }
        return FakeYadoriLinkClient(scenario: fixture(arguments: arguments, environment: environment))
    }

    static func fixture(arguments: [String], environment: [String: String]) -> FakeScenario {
        if let i = arguments.firstIndex(of: "-fixture"), i + 1 < arguments.count,
           let scenario = FakeScenario(rawValue: arguments[i + 1]) {
            return scenario
        }
        if let name = environment["YADORILINK_FIXTURE"], let scenario = FakeScenario(rawValue: name) {
            return scenario
        }
        return .healthy
    }
}
#else
extension ClientFactory {
    static func makeClient() -> any YadoriLinkClient {
        makeLiveClient()
    }
}
#endif
