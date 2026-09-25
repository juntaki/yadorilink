import Foundation
import Observation
import YadoriLinkModel

public struct Destination: Identifiable, Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case newSharedFolder
        case existing(GroupSummary)
    }
    public var kind: Kind
    public var id: String {
        switch kind {
        case .newSharedFolder: "new"
        case .existing(let g): g.groupId
        }
    }
    /// "New shared folder", "Sync into: Documents"
    public var title: String {
        switch kind {
        case .newSharedFolder: "New shared folder"
        case .existing(let g): "Sync into: \(g.name)"
        }
    }
}

/// First-run setup and "Add Folder…". First run walks welcome → sign in →
/// choose folder → review → done; adding a folder shows only choose → review.
@MainActor
@Observable
public final class OnboardingViewModel {
    public enum Flow: Sendable, Equatable { case firstRun, addFolder }
    public enum Step: Sendable, Equatable {
        case welcome, signIn, chooseFolder, review, done

        public var title: String {
            switch self {
            case .welcome: "Welcome"
            case .signIn: "Sign in"
            case .chooseFolder: "Choose folder"
            case .review: "Review"
            case .done: "Done"
            }
        }
    }

    public let flow: Flow
    public let client: any YadoriLinkClient
    public let loginItem: LoginItemModel
    public let signIn: SignInModel
    public private(set) var steps: [Step] = []
    public private(set) var step: Step
    public private(set) var destinations: [Destination] = [Destination(kind: .newSharedFolder)]
    public var destinationId = "new"
    public var newFolderName = ""
    public private(set) var folderPath: String?
    public private(set) var preflight: PreflightResult?
    public var acknowledgedRisks = false
    public var folderMode: FolderMode = .keepAll
    public private(set) var isWorking = false
    public private(set) var linked: LinkOutcome?
    public private(set) var isFinished = false
    /// Default on. Registers the app as a login item when setup finishes.
    public var startAtLogin = true
    public let startAtLoginTitle = SettingWording.openAtLogin
    public var notice: Notice?
    /// Called after a folder was linked, so the caller can refresh status.
    @ObservationIgnored public var onLinked: ((LinkOutcome) -> Void)?
    /// Called when the user completes setup with Done.
    @ObservationIgnored public var onFinished: (() -> Void)?

    public init(client: any YadoriLinkClient, mode: Flow, loginItem: LoginItemModel, openURL: @escaping (URL) -> Void) {
        self.flow = mode
        self.client = client
        self.loginItem = loginItem
        self.signIn = SignInModel(client: client, openURL: openURL)
        self.step = mode == .firstRun ? .welcome : .chooseFolder
        self.signIn.onSignedIn = { [weak self] _ in
            guard let self else { return }
            Task { await self.loadDestinations(); self.next() }
        }
    }

    public func prepare() async {
        let account = await client.accountStatus()
        let signedIn = account.signIn == .signedIn
        switch flow {
        case .firstRun:
            steps = [.welcome] + (signedIn ? [] : [.signIn]) + [.chooseFolder, .review, .done]
        case .addFolder:
            steps = [.chooseFolder, .review]
        }
        if !steps.contains(step) { step = steps[0] }
        if signedIn { await loadDestinations() }
    }

    private func loadDestinations() async {
        let groups = (try? await client.listJoinableGroups()) ?? []
        destinations = [Destination(kind: .newSharedFolder)] + groups.map { Destination(kind: .existing($0)) }
    }

    // MARK: Navigation

    public var canGoBack: Bool {
        guard let i = steps.firstIndex(of: step) else { return false }
        return i > 0 && step != .done && !isWorking
    }

    public func back() {
        guard canGoBack, let i = steps.firstIndex(of: step) else { return }
        step = steps[i - 1]
    }

    public func next() {
        guard let i = steps.firstIndex(of: step), i + 1 < steps.count else { return }
        step = steps[i + 1]
    }

    /// First run only: go straight to the last step without linking a folder.
    public func skipToDone() {
        if steps.contains(.done) { step = .done }
    }

    // MARK: Choosing and reviewing

    public func chooseFolder(_ path: String) async {
        isWorking = true
        defer { isWorking = false }
        folderPath = path
        acknowledgedRisks = false
        if newFolderName.isEmpty { newFolderName = (path as NSString).lastPathComponent }
        do {
            preflight = try await client.runPreflight(localPath: path)
            step = .review
        } catch {
            notice = .failure(error)
        }
    }

    /// Plain sentences for each preflight finding, in the order given.
    public var issueLines: [String] {
        (preflight?.issues ?? []).map(Self.sentence)
    }

    static func sentence(_ issue: PreflightIssue) -> String {
        switch issue {
        case .pathMissing:
            "This folder doesn't exist."
        case .ignoreRulesUnreadable:
            "The ignore rules for this folder can't be read, so every file will be shared."
        case .notEmpty(let count, let truncated):
            "This folder already has \(truncated ? "more than " : "")\(Plural.items(Int(clamping: count))). They will be shared too."
        case .lowFreeSpace(let available, _):
            "Only \(Format.bytes(available)) free on this disk."
        case .criticalFreeSpace(let available, _):
            "This disk is almost full (\(Format.bytes(available)) free)."
        case .nestedLink(let other, .ancestor):
            "This folder is inside \(other), which already syncs."
        case .nestedLink(let other, .descendant):
            "This folder contains \(other), which already syncs."
        case .nestedLink(_, .same):
            "This folder already syncs."
        case .cloudProviderFolder(let provider):
            "\(provider) manages this folder. Syncing it with two services can cause conflicts."
        case .filesystemRoot:
            "This is the whole disk. Choose a folder instead."
        case .homeDirectory:
            "This is your whole home folder. Choose a folder inside it instead."
        case .reservedName(let path):
            "\(path) has a name that can't sync."
        }
    }

    public var summaryLine: String? {
        guard let p = preflight else { return nil }
        var parts = ["\(Plural.items(Int(clamping: p.entryCount)))", Format.bytes(p.totalSizeBytes)]
        if let free = p.freeSpace { parts.append("\(Format.bytes(free.availableBytes)) free on this disk") }
        return parts.joined(separator: " · ")
    }

    public var needsAcknowledgement: Bool { preflight?.requiresAcknowledgement == true }

    private var destination: Destination? { destinations.first { $0.id == destinationId } }

    public var canLink: Bool {
        guard preflight != nil, folderPath != nil, !isWorking, let destination else { return false }
        if needsAcknowledgement && !acknowledgedRisks { return false }
        if destination.kind == .newSharedFolder && newFolderName.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    public func link() async {
        guard canLink, let path = folderPath, let destination else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            let outcome: LinkOutcome
            switch destination.kind {
            case .newSharedFolder:
                outcome = try await client.createGroupAndLink(groupName: newFolderName.trimmingCharacters(in: .whitespaces), localPath: path, mode: folderMode, acknowledgeRisks: acknowledgedRisks)
            case .existing(let group):
                outcome = try await client.joinGroupAndLink(groupId: group.groupId, groupName: group.name, localPath: path, mode: folderMode, acknowledgeRisks: acknowledgedRisks)
            }
            linked = outcome
            notice = nil
            onLinked?(outcome)
            if flow == .firstRun { next() } else { isFinished = true }
        } catch {
            notice = .failure(error)
        }
    }

    /// A step's progress in words, for the step list's accessibility value.
    public func progress(of step: Step) -> String {
        let index = steps.firstIndex(of: step) ?? 0
        let current = steps.firstIndex(of: self.step) ?? 0
        return index < current ? "Done" : index == current ? "Current step" : "Not started"
    }

    /// Ends setup and applies the open-at-login box either way. The app
    /// already turned open-at-login on at first launch (it is on by
    /// default), so an unchecked box turns it off.
    public func finish() {
        if startAtLogin != loginItem.isOn { loginItem.setOn(startAtLogin) }
        isFinished = true
        onFinished?()
    }
}
