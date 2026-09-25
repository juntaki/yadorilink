import Foundation
import XCTest
import YadoriLinkFFI
import YadoriLinkFixtures
import YadoriLinkModel

/// The live client's glue: every mirror value survives a trip through the
/// generated binding's types, and calls reach the Rust client core and come
/// back as mirror values and mirror errors.
final class LiveClientTests: XCTestCase {
    func testStatusSnapshotsRoundTrip() {
        for snapshot in [Fixtures.syncingSnapshot, Fixtures.problemSnapshot] {
            XCTAssertEqual(YadoriLinkModel.StatusSnapshot(YadoriLinkFFI.StatusSnapshot(snapshot)), snapshot)
            let update = YadoriLinkModel.StatusUpdate.snapshot(snapshot: snapshot)
            XCTAssertEqual(YadoriLinkModel.StatusUpdate(YadoriLinkFFI.StatusUpdate(update)), update)
        }
        let down = YadoriLinkModel.StatusUpdate.unavailable(error: Fixtures.daemonDownError)
        XCTAssertEqual(YadoriLinkModel.StatusUpdate(YadoriLinkFFI.StatusUpdate(down)), down)
    }

    func testAccountAndSignInValuesRoundTrip() {
        for signIn in [YadoriLinkModel.SignInState.signedIn, .signedOut, .credentialStoreUnusable(message: "locked")] {
            let account = Fixtures.account(signIn, hasLinkedFolders: nil)
            XCTAssertEqual(YadoriLinkModel.AccountStatus(YadoriLinkFFI.AccountStatus(account)), account)
        }
        for event in Fixtures.loginEvents() + [.failed(error: Fixtures.signedOutError), .cancelled, .showDeviceCode(verificationUri: "https://example.invalid/device", userCode: "ABCD-EFGH")] {
            XCTAssertEqual(YadoriLinkModel.LoginEvent(YadoriLinkFFI.LoginEvent(event)), event)
        }
        let options = YadoriLinkModel.LoginOptions(flow: .deviceCode, overallTimeout: 300)
        XCTAssertEqual(YadoriLinkModel.LoginOptions(YadoriLinkFFI.LoginOptions(options)), options)
        let config = YadoriLinkModel.CoreConfig(daemonLaunch: .launchAgent(label: "com.yadorilink.daemon", fallbackBinary: "/usr/local/bin/yadorilink-daemon"))
        XCTAssertEqual(YadoriLinkModel.CoreConfig(YadoriLinkFFI.CoreConfig(config)), config)
    }

    func testEveryErrorCaseRoundTrips() {
        let errors: [YadoriLinkModel.DesktopError] = [
            .notSignedIn(message: "m"),
            .daemonUnavailable(message: "m", reason: .notRunning),
            .daemonUnavailable(message: "m", reason: .unresponsive),
            .daemonUnavailable(message: "m", reason: .protocolMismatch(clientVersion: 3, daemonVersion: 4)),
            .network(message: "m", kind: .activationPendingReconciliation),
            .permissionDenied(message: "m", reason: .credentialStoreUnusable),
            .durabilityBlocked(message: "m", groupIds: ["g"], operationId: "op", canForce: true),
            .invalidInput(message: "m", field: "local_path"),
            .internal(message: "m", category: "c"),
        ]
        for error in errors {
            XCTAssertEqual(YadoriLinkModel.DesktopError(YadoriLinkFFI.DesktopError(error)), error)
        }
    }

    func testFilesSharesAndSettingsRoundTrip() {
        for value in Fixtures.conflicts { XCTAssertEqual(YadoriLinkModel.ConflictSummary(YadoriLinkFFI.ConflictSummary(value)), value) }
        for value in Fixtures.trash { XCTAssertEqual(YadoriLinkModel.TrashedFile(YadoriLinkFFI.TrashedFile(value)), value) }
        for value in Fixtures.versions { XCTAssertEqual(YadoriLinkModel.FileVersion(YadoriLinkFFI.FileVersion(value)), value) }
        for value in Fixtures.members { XCTAssertEqual(YadoriLinkModel.MemberSummary(YadoriLinkFFI.MemberSummary(value)), value) }
        for value in Fixtures.pendingApprovals { XCTAssertEqual(YadoriLinkModel.PendingApprovalSummary(YadoriLinkFFI.PendingApprovalSummary(value)), value) }
        for value in Fixtures.invites { XCTAssertEqual(YadoriLinkModel.PendingInviteSummary(YadoriLinkFFI.PendingInviteSummary(value)), value) }
        for value in Fixtures.inbox { XCTAssertEqual(YadoriLinkModel.IncomingTransfer(YadoriLinkFFI.IncomingTransfer(value)), value) }
        let status = Fixtures.updateStatus(available: "0.5.0")
        XCTAssertEqual(YadoriLinkModel.UpdateStatus(YadoriLinkFFI.UpdateStatus(status)), status)

        let preflight = YadoriLinkModel.PreflightResult(
            resolvedPath: "/Users/me/Documents", pathExists: true, isDirectory: true, entryCount: 12,
            ignoredEntryCount: 2, totalSizeBytes: 4_096, scanTruncated: false,
            freeSpace: YadoriLinkModel.FreeSpace(availableBytes: 1, totalBytes: 2, headroomBytes: 3, state: .critical),
            issues: [
                .pathMissing, .ignoreRulesUnreadable, .notEmpty(entryCount: 12, scanTruncated: false),
                .lowFreeSpace(availableBytes: 1, headroomBytes: 2), .criticalFreeSpace(availableBytes: 1, headroomBytes: 2),
                .nestedLink(otherPath: "/Users/me", relation: .ancestor), .cloudProviderFolder(provider: "Dropbox"),
                .filesystemRoot, .homeDirectory, .reservedName(path: ".yadorilink"),
            ],
            requiresAcknowledgement: true
        )
        XCTAssertEqual(YadoriLinkModel.PreflightResult(YadoriLinkFFI.PreflightResult(preflight)), preflight)

        let outcome = YadoriLinkModel.MembershipOutcome(
            handoffs: [YadoriLinkModel.MembershipHandoff(groupId: "g", targetDeviceId: "d", leaseId: "l", membershipGeneration: 7)],
            forcedGroupIds: ["g2"], unknownScopeOperationId: "op"
        )
        for edge in [YadoriLinkModel.RevokeEdgeOutcome.revoked(outcome: outcome), .alreadyRevoked] {
            XCTAssertEqual(YadoriLinkModel.RevokeEdgeOutcome(YadoriLinkFFI.RevokeEdgeOutcome(edge)), edge)
        }
        for install in [YadoriLinkModel.UpdateInstallOutcome.installing, .deferred, .storeManaged(guidance: "App Store"), .other(raw: "x")] {
            XCTAssertEqual(YadoriLinkModel.UpdateInstallOutcome(YadoriLinkFFI.UpdateInstallOutcome(install)), install)
        }
        for mode in YadoriLinkModel.FolderMode.allCases { XCTAssertEqual(YadoriLinkModel.FolderMode(YadoriLinkFFI.FolderMode(mode)), mode) }
        for role in YadoriLinkModel.AssignableRole.allCases { XCTAssertEqual(YadoriLinkModel.AssignableRole(YadoriLinkFFI.AssignableRole(role)), role) }
        let limits = YadoriLinkModel.BandwidthLimits(uploadBytesPerSec: nil, downloadBytesPerSec: 1_000)
        XCTAssertEqual(YadoriLinkModel.BandwidthLimits(YadoriLinkFFI.BandwidthLimits(limits)), limits)
    }

    // MARK: through the Rust client core

    private func clientWithoutDaemon() -> LiveYadoriLinkClient {
        let socket = FileManager.default.temporaryDirectory.appendingPathComponent("yadorilink-no-daemon-\(UUID().uuidString).sock")
        setenv("YADORILINK_CONTROL_SOCKET", socket.path, 1)
        return LiveYadoriLinkClient(config: YadoriLinkModel.CoreConfig(daemonLaunch: .spawnBinary(path: nil)))
    }

    func testAnAbsentDaemonIsDaemonUnavailable() async {
        let client = clientWithoutDaemon()
        do {
            _ = try await client.statusSnapshot()
            XCTFail("expected daemonUnavailable")
        } catch let error as YadoriLinkModel.DesktopError {
            guard case .daemonUnavailable(_, reason: .notRunning) = error else {
                return XCTFail("expected daemonUnavailable(.notRunning), got \(error)")
            }
        } catch {
            XCTFail("the live client threw a non-DesktopError: \(error)")
        }
        let watch = client.watchStatus(interval: 0.05)
        let update = await watch.next()
        guard case .unavailable(error: .daemonUnavailable) = update else {
            return XCTFail("expected an unavailable update, got \(String(describing: update))")
        }
        watch.cancel()
        let afterCancel = await watch.next()
        XCTAssertNil(afterCancel)
    }

    func testAnInvalidPathIsInvalidInputAboutThePath() async {
        do {
            _ = try await clientWithoutDaemon().runPreflight(localPath: "/no/such/place/for/yadorilink")
            XCTFail("expected invalidInput")
        } catch let error as YadoriLinkModel.DesktopError {
            XCTAssertEqual(error, .invalidInput(message: "no such directory: /no/such/place/for/yadorilink", field: "local_path"))
        } catch {
            XCTFail("the live client threw a non-DesktopError: \(error)")
        }
    }

    func testASignInCancelledBeforeItBeginsEndsCancelled() async {
        let session = clientWithoutDaemon().newLoginSession(options: YadoriLinkModel.LoginOptions(flow: .loopback, overallTimeout: 5))
        session.cancel()
        let first = await session.nextEvent()
        XCTAssertEqual(first, .cancelled)
        let second = await session.nextEvent()
        XCTAssertNil(second)
        XCTAssertThrowsError(try session.begin()) { error in
            guard case .invalidInput? = error as? YadoriLinkModel.DesktopError else {
                return XCTFail("expected invalidInput, got \(error)")
            }
        }
    }
    /// A duration the binding cannot carry (negative, NaN, infinite) is
    /// refused as invalid input instead of trapping in the binding.
    func testAnInviteLifetimeOutOfRangeIsInvalidInputAboutTheTtl() async {
        let client = clientWithoutDaemon()
        for ttl in [-1, TimeInterval.nan, TimeInterval.infinity] {
            do {
                _ = try await client.mintInvite(groupId: "group", role: nil, ttl: ttl, requireApproval: false)
                XCTFail("expected invalidInput for ttl \(ttl)")
            } catch let error as YadoriLinkModel.DesktopError {
                guard case .invalidInput(_, field: "ttl") = error else {
                    return XCTFail("expected invalidInput about the ttl for \(ttl), got \(error)")
                }
            } catch {
                XCTFail("the live client threw a non-DesktopError: \(error)")
            }
        }
    }

    /// A poll interval or sign-in deadline the binding cannot carry falls
    /// back to one it can, so the call still works instead of trapping.
    func testAPollIntervalOrSignInDeadlineOutOfRangeStillWorks() async {
        let client = clientWithoutDaemon()
        for interval in [-1, TimeInterval.nan, TimeInterval.infinity] {
            let watch = client.watchStatus(interval: interval)
            let update = await watch.next()
            guard case .unavailable(error: .daemonUnavailable) = update else {
                return XCTFail("expected an unavailable update for interval \(interval), got \(String(describing: update))")
            }
            watch.cancel()
        }
        for timeout in [-1, TimeInterval.nan, TimeInterval.infinity] {
            let session = client.newLoginSession(options: YadoriLinkModel.LoginOptions(flow: .loopback, overallTimeout: timeout))
            session.cancel()
            let first = await session.nextEvent()
            XCTAssertEqual(first, .cancelled, "sign-in deadline \(timeout)")
        }
    }

    /// A deadline already past (negative) or meaningless (NaN) ends the
    /// sign-in at once with the timeout failure, rather than dropping the
    /// deadline and leaving a sign-in that waits forever.
    func testASignInDeadlineAlreadyPastEndsTheSignIn() async throws {
        let client = clientWithoutDaemon()
        let credentials = FileManager.default.temporaryDirectory.appendingPathComponent("yadorilink-credentials-\(UUID().uuidString).json")
        setenv("YADORILINK_CREDENTIAL_FILE", credentials.path, 1)
        // A server that never answers: a sign-in that reaches the network
        // waits on it.
        let silent = try silentLoopbackListener()
        setenv("YADORILINK_COORDINATION_HTTP_ADDR", "http://127.0.0.1:\(silent.port)", 1)
        defer {
            unsetenv("YADORILINK_CREDENTIAL_FILE")
            unsetenv("YADORILINK_COORDINATION_HTTP_ADDR")
            close(silent.fd)
        }
        for timeout in [-1, TimeInterval.nan] {
            let session = client.newLoginSession(options: YadoriLinkModel.LoginOptions(flow: .loopback, overallTimeout: timeout))
            try session.begin()
            var terminal: YadoriLinkModel.LoginEvent?
            for _ in 0..<10 {
                guard let event = await session.nextEvent() else { break }
                if case .signedIn = event { terminal = event }
                if case .failed = event { terminal = event }
                if case .cancelled = event { terminal = event }
                if terminal != nil { break }
            }
            guard case .failed(error: .network(message: "timed out waiting for browser sign-in", kind: .unreachable)) = terminal else {
                session.cancel()
                return XCTFail("sign-in deadline \(timeout): expected the timeout failure, got \(String(describing: terminal))")
            }
        }
    }

    /// A loopback TCP socket that listens and never accepts: connections
    /// complete through the kernel backlog, and nothing ever answers.
    private func silentLoopbackListener() throws -> (fd: Int32, port: UInt16) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, length) == 0 && Darwin.listen(fd, 16) == 0 && Darwin.getsockname(fd, $0, &length) == 0
            }
        }
        guard bound else {
            close(fd)
            throw POSIXError(.EIO)
        }
        return (fd, UInt16(bigEndian: address.sin_port))
    }
}
