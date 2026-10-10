import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Join with invite link")
struct JoinInviteTests {
    @Test func aReceivedLinkGoesToConfirmationAndThenAccepts() async throws {
        let model = JoinInviteModel(client: FakeYadoriLinkClient(scenario: .healthy))
        model.receive("yadorilink://invite/K7QX-M2PA")
        #expect(model.phase == .confirming(code: "K7QX-M2PA"))
        #expect(!model.canAccept)
        model.chooseFolder("/tmp/shared")
        await model.accept()
        guard case .done(let outcome) = model.phase else { Issue.record("not done: \(model.phase)"); return }
        #expect(outcome.localPath == "/tmp/shared")
    }

    @Test func aMalformedLinkStaysOnEntryWithAPlainMessage() {
        let model = JoinInviteModel(client: FakeYadoriLinkClient(scenario: .healthy))
        model.receive("https://example.com/x")
        #expect(model.phase == .entering)
        #expect(model.notice?.text.contains("invite") == true)
    }
}
