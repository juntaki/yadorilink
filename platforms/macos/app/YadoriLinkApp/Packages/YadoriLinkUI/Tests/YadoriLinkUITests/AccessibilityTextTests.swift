import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

struct AccessibilityTextTests {
    @Test func failureNoticeIsMarkedInWordsNotOnlyByColor() {
        let failure = Notice(kind: .failure, text: "Couldn't save.")
        #expect(failure.spokenText == "Error: Couldn't save.")
    }

    @Test func successNoticeReadsAsItsText() {
        let success = Notice(kind: .success, text: "Saved.")
        #expect(success.spokenText == "Saved.")
    }

    @MainActor
    @Test func failedSignInIsMarkedInWords() async {
        let client = FakeYadoriLinkClient(scenario: .signedOut)
        client.loginScript = [.init(.enrolling), .init(.failed(error: .network(message: "x", kind: .unreachable)))]
        let model = SignInModel(client: client, openURL: { _ in })
        await model.run()
        #expect(model.spokenStatusText == "Error: \(model.statusText)")
    }
}
