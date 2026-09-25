import Foundation
import Testing
import YadoriLinkFixtures
import YadoriLinkModel
@testable import YadoriLinkUI

@MainActor
@Suite("Invite QR window")
struct InviteQRTests {
    @Test func windowValueIsTheInviteIdAndTheLinkStaysInMemory() {
        let context = AppContext.fixture(.healthy)
        let invite = InviteSummary(inviteId: "inv-1", code: "K7QX-M2PA", url: "yadorilink://invite/K7QX-M2PA", groupId: "g-docs", role: .editor, expiresAt: Fixtures.now, requiresApproval: true)

        let value = context.showQRCode(for: invite)
        #expect(value == "inv-1")
        #expect(!value.contains(invite.code))
        #expect(context.inviteURL(forQRCode: value) == invite.url)
    }

    @Test func aRestoredWindowHasNoLink() {
        let context = AppContext.fixture(.healthy)
        #expect(context.inviteURL(forQRCode: "inv-from-last-run") == nil)
    }
}
