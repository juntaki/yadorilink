import Foundation
import YadoriLinkModel

/// The one place the app chooses its client.
///
/// Every build, Debug included, uses the live client over the Rust client
/// core by default. The fake client (made-up folders, pretend operations)
/// exists only in Debug builds and is chosen only explicitly: set
/// `YADORILINK_CLIENT=fake` in the environment, or run the
/// `YadoriLink Fixtures` scheme, which sets it. The UI then shows a
/// "Fixture" badge so fake data is never mistaken for real data. Previews
/// and the package tests build the fake client themselves. Every view and
/// view model only sees `YadoriLinkClient`.
///
/// With the fake client, pick a scenario with `-fixture <name>` or the
/// `YADORILINK_FIXTURE` environment variable.
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
    /// Live unless `YADORILINK_CLIENT=fake` is set. No other input (a build
    /// configuration, a `-fixture` argument alone) selects the fixture client.
    static func makeClient(arguments: [String] = CommandLine.arguments, environment: [String: String] = ProcessInfo.processInfo.environment) -> any YadoriLinkClient {
        if environment["YADORILINK_CLIENT"] == "fake" {
            return FakeYadoriLinkClient(scenario: fixture(arguments: arguments, environment: environment))
        }
        return makeLiveClient()
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

/// Whether the Add Folder flow offers a File Provider folder. The daemon refuses the request
/// on platforms without a provider adapter.
enum ProviderFolders {
    static let available = true
}
