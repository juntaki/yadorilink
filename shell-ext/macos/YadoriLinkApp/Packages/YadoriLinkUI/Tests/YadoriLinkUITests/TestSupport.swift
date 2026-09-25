import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

struct TimedOut: Error, CustomStringConvertible {
    let what: String
    var description: String { "timed out waiting for \(what)" }
}

/// Polls `condition` on the main actor until it holds or the timeout passes.
@MainActor
func waitUntil(_ what: String = "condition", timeout: Duration = .seconds(3), _ condition: @MainActor () -> Bool) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    while !condition() {
        if clock.now >= deadline { throw TimedOut(what: what) }
        try await Task.sleep(for: .milliseconds(5))
    }
}

/// An app model running against a fake client, with its first status and
/// account already loaded.
@MainActor
func startedApp(_ scenario: FakeScenario) async throws -> (AppModel, FakeYadoriLinkClient) {
    let client = FakeYadoriLinkClient(scenario: scenario)
    let app = AppModel(client: client, pollInterval: 0.05)
    app.start()
    try await waitUntil("first status") { app.status != .loading && app.account != nil }
    return (app, client)
}

/// Records which login-item calls were made.
final class FakeLoginItemService: LoginItemService, @unchecked Sendable {
    var status: LoginItemStatus
    var registerError: Error?
    private(set) var registerCalls = 0
    private(set) var unregisterCalls = 0
    private(set) var openedSystemSettings = 0

    init(status: LoginItemStatus = .notRegistered) { self.status = status }

    func register() throws {
        registerCalls += 1
        if let registerError { throw registerError }
        status = .enabled
    }

    func unregister() throws {
        unregisterCalls += 1
        status = .notRegistered
    }

    func openSystemSettingsLoginItems() { openedSystemSettings += 1 }
}
