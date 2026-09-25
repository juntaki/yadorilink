// App-side conveniences on the mirror types. They are kept out of
// Types.swift so that file stays a one-to-one mirror of the binding.

import Foundation

extension DesktopError {
    /// Diagnostic text for tooltips and "Details…"; never primary copy.
    public var message: String {
        switch self {
        case .notSignedIn(let m), .daemonUnavailable(let m, _), .network(let m, _),
             .permissionDenied(let m, _), .durabilityBlocked(let m, _, _, _),
             .invalidInput(let m, _), .internal(let m, _):
            return m
        }
    }
}

extension LoginEvent {
    public var isTerminal: Bool {
        switch self {
        case .signedIn, .failed, .cancelled: return true
        default: return false
        }
    }
}

extension FolderSummary: Identifiable { public var id: String { localPath } }
extension DeviceSummary: Identifiable { public var id: String { deviceId } }
extension GroupSummary: Identifiable { public var id: String { groupId } }
extension MemberSummary: Identifiable { public var id: String { deviceId } }
extension IncomingTransfer: Identifiable { public var id: String { transferId } }
extension PendingInviteSummary: Identifiable { public var id: String { inviteId } }
extension TransferSummary: Identifiable { public var id: String { "\(groupId)/\(path)" } }
