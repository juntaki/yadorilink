import Foundation
import Observation
import YadoriLinkModel

/// "Join with Invite Link…": paste (or receive) a link, read what accepting
/// does, pick a folder, accept. The link is validated by the client core, the
/// one parser shared with every other front end.
@MainActor
@Observable
public final class JoinInviteModel {
    public enum Phase: Equatable, Sendable {
        case entering
        case confirming(code: String)
        case accepting
        case done(AcceptInviteOutcome)
    }

    public let client: any YadoriLinkClient
    public var input = ""
    public private(set) var phase: Phase = .entering
    public private(set) var folderPath: String?
    public var notice: Notice?
    @ObservationIgnored public var onAccepted: () -> Void = {}

    public init(client: any YadoriLinkClient) {
        self.client = client
    }

    /// Takes a link received from the system and goes straight to the confirmation.
    public func receive(_ link: String) {
        guard phase != .accepting else { return }
        folderPath = nil
        input = link
        review()
    }

    /// Validates the input and shows the confirmation.
    public func review() {
        do {
            phase = .confirming(code: try client.parseInviteLink(input))
            notice = nil
        } catch let error as DesktopError {
            phase = .entering
            if case .invalidInput(let message, _) = error {
                notice = Notice(kind: .failure, text: message)
            } else {
                notice = .failure(error)
            }
        } catch {
            phase = .entering
            notice = .failure(error)
        }
    }

    public func chooseFolder(_ path: String) { folderPath = path }

    public func back() {
        phase = .entering
        notice = nil
    }

    public var canAccept: Bool { folderPath != nil && phase != .accepting }

    /// What the confirmation tells the person before anything happens.
    public static let confirmationText = "Someone has shared a folder with you. If you accept, YadoriLink links the folder you choose on this Mac to it, and files start syncing with the sender's devices. The sender may need to approve you first."

    public func accept() async {
        guard case .confirming(let code) = phase, let folderPath else { return }
        phase = .accepting
        do {
            let outcome = try await client.acceptInvite(codeOrUrl: code, localPath: folderPath, mode: .keepAll, acknowledgeRisks: false)
            phase = .done(outcome)
            notice = nil
            onAccepted()
        } catch {
            phase = .confirming(code: code)
            notice = .failure(error)
        }
    }

    public static func doneText(_ outcome: AcceptInviteOutcome) -> String {
        outcome.awaitingApproval
            ? "You've joined. The folder will start syncing once the sender approves you; you won't get a notification when they do."
            : "You've joined. The folder is now syncing."
    }
}
