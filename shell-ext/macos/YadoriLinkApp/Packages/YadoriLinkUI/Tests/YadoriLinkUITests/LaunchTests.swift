import Foundation
import Testing
import YadoriLinkFixtures
@testable import YadoriLinkUI

@Suite("Launch windows")
struct LaunchPlanTests {
    @Test func setupOpensUntilCompleted() {
        #expect(LaunchPlan(arguments: ["YadoriLink"], didFinishOnboarding: false) == LaunchPlan(showsOnboarding: true))
        #expect(LaunchPlan(arguments: ["YadoriLink"], didFinishOnboarding: true) == LaunchPlan())
    }

    @Test func installerForcesSetup() {
        #expect(LaunchPlan(arguments: ["YadoriLink", "--onboarding"], didFinishOnboarding: true).showsOnboarding)
    }

    @Test func developmentArguments() {
        let plan = LaunchPlan(arguments: ["YadoriLink", "--show", "storage", "--show-folder", "/Users/me/Photos", "--settings"], didFinishOnboarding: true)
        #expect(plan == LaunchPlan(pane: .storage, folder: "/Users/me/Photos", showsSettings: true))
        #expect(LaunchPlan(arguments: ["YadoriLink", "--show", "nonsense"], didFinishOnboarding: true).pane == nil)
        #expect(LaunchPlan(arguments: ["YadoriLink", "--show"], didFinishOnboarding: true).pane == nil)
    }
}

@MainActor
@Suite("Open at login default")
struct LoginItemDefaultTests {
    func freshDefaults() -> UserDefaults {
        let name = "yadorilink-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    @Test func firstLaunchTurnsItOnOnce() {
        let defaults = freshDefaults()
        let service = FakeLoginItemService(status: .notRegistered)
        let model = LoginItemModel(service: service)

        model.applyDefaultOnce(defaults: defaults)
        #expect(service.registerCalls == 1)
        #expect(model.isOn)

        model.setOn(false)
        LoginItemModel(service: service).applyDefaultOnce(defaults: defaults)
        #expect(service.registerCalls == 1, "a user who turned it off stays off")
    }

    @Test func alreadyOnIsRecordedWithoutRegisteringAgain() {
        let defaults = freshDefaults()
        let service = FakeLoginItemService(status: .enabled)
        LoginItemModel(service: service).applyDefaultOnce(defaults: defaults)
        #expect(service.registerCalls == 0)
        #expect(defaults.bool(forKey: LoginItemModel.defaultAppliedKey))
    }

    @Test func failedRegistrationIsRetriedNextLaunch() {
        let defaults = freshDefaults()
        let service = FakeLoginItemService(status: .notRegistered)
        service.registerError = CocoaError(.featureUnsupported)
        LoginItemModel(service: service).applyDefaultOnce(defaults: defaults)
        #expect(!defaults.bool(forKey: LoginItemModel.defaultAppliedKey))

        service.registerError = nil
        LoginItemModel(service: service).applyDefaultOnce(defaults: defaults)
        #expect(service.registerCalls == 2)
        #expect(service.status == .enabled)
    }

    @Test func turningItOffInSetupUnregisters() async {
        let service = FakeLoginItemService(status: .enabled)
        let model = OnboardingViewModel(client: FakeYadoriLinkClient(scenario: .healthy), mode: .firstRun, loginItem: LoginItemModel(service: service), openURL: { _ in })
        var finished = false
        model.onFinished = { finished = true }
        model.startAtLogin = false
        model.finish()
        #expect(service.unregisterCalls == 1)
        #expect(finished)
    }
}
