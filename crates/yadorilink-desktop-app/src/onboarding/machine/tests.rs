#![cfg(test)]

use super::*;

fn advance(state: State, event: Event) -> State {
    step(state, event).0
}

// ---- start-step derivation --------------------------------------

#[test]
fn fresh_install_derives_welcome_first_run() {
    let s = derive_initial(Probe { default_device_name: "mac".into(), ..Default::default() });
    assert_eq!(s.phase, Phase::Welcome);
    assert_eq!(s.mode, Mode::FirstRun);
    assert_eq!(s.device_name, "mac");
}

#[test]
fn signed_in_only_resumes_at_device_register() {
    let s = derive_initial(Probe {
        signed_in: true,
        account: Some("me@example.com".into()),
        ..Default::default()
    });
    assert_eq!(s.phase, Phase::DeviceRegister);
    assert_eq!(s.account.as_deref(), Some("me@example.com"));
}

#[test]
fn signed_in_and_device_registered_resumes_at_share() {
    let s =
        derive_initial(Probe { signed_in: true, device_registered: true, ..Default::default() });
    assert_eq!(s.phase, Phase::ShareChoose);
}

#[test]
fn existing_links_open_in_add_another_folder_mode() {
    let s = derive_initial(Probe {
        signed_in: true,
        device_registered: true,
        has_links: true,
        ..Default::default()
    });
    assert_eq!(s.phase, Phase::LinkFolder);
    assert_eq!(s.mode, Mode::AddFolder);
    assert_eq!(s.link_stage, LinkStage::ChooseGroup);
    assert!(s.group_id.is_none());
}

// ---- happy path through the whole flow -------------------------------

#[test]
fn full_first_run_flow_reaches_done() {
    let mut s = derive_initial(Probe { default_device_name: "mac".into(), ..Default::default() });

    let (s2, fx) = step(s, Event::Start);
    s = s2;
    assert_eq!(s.phase, Phase::SignIn);
    assert!(fx.is_empty());

    let (s2, fx) = step(s, Event::SignInRequested);
    s = s2;
    assert_eq!(fx, vec![Effect::StartLogin]);
    assert_eq!(s.status, OpStatus::Working);

    s = advance(s, Event::SignInSucceeded { account: "me@example.com".into() });
    assert_eq!(s.phase, Phase::DeviceRegister);
    assert_eq!(s.status, OpStatus::Idle);

    let (s2, fx) = step(s, Event::DeviceRegisterRequested);
    s = s2;
    assert_eq!(fx, vec![Effect::RegisterDevice { name: "mac".into() }]);

    s = advance(s, Event::DeviceRegistered);
    assert_eq!(s.phase, Phase::ShareChoose);

    s = advance(s, Event::ShareNameChanged("Photos".into()));
    // Submitting the name no longer creates the group — it just advances to
    // the folder step. The group is created atomically at link confirm, so
    // an abandoned wizard leaves no phantom full replica.
    let (s2, fx) = step(s, Event::ShareSubmitRequested);
    s = s2;
    assert!(fx.is_empty(), "group creation is deferred to link confirm");
    assert_eq!(s.phase, Phase::LinkFolder);
    assert_eq!(s.link_stage, LinkStage::ChooseFolder);
    assert_eq!(s.group_id, None);
    assert_eq!(s.share_name, "Photos");

    let (s2, fx) = step(s, Event::FolderPicked("/tmp/photos".into()));
    s = s2;
    assert_eq!(fx, vec![Effect::RunPreflight { path: "/tmp/photos".into() }]);
    assert_eq!(s.link_stage, LinkStage::Previewing);

    // A clean (non-risky) preflight — no warnings, confirm allowed at once.
    s = advance(
        s,
        Event::PreflightCompleted(PreflightView {
            resolved_path: "/private/tmp/photos".into(),
            summary: vec!["empty folder".into()],
            warnings: vec![],
            is_risky: false,
        }),
    );
    assert_eq!(s.link_stage, LinkStage::Review);
    assert!(s.can_confirm_link());

    // First-run confirm creates the group and links it in one atomic effect.
    let (s2, fx) = step(s, Event::LinkConfirmRequested);
    s = s2;
    assert_eq!(
        fx,
        vec![Effect::CreateAndLink {
            name: "Photos".into(),
            path: "/private/tmp/photos".into(),
            acknowledge_risks: false,
            // Defaults to eager when the user made no storage-mode choice.
            on_demand: false,
        }]
    );

    s = advance(s, Event::CreateAndLinkSucceeded { group_id: "g1".into() });
    assert_eq!(s.phase, Phase::Done);
    assert_eq!(s.group_id.as_deref(), Some("g1"));
    assert_eq!(s.linked_path.as_deref(), Some("/private/tmp/photos"));
}

// ---- per-warning acknowledgement gating (spec) -------------------

fn risky_review_state() -> State {
    let mut s = State {
        phase: Phase::LinkFolder,
        link_stage: LinkStage::Previewing,
        group_id: Some("g1".into()),
        available_groups: vec![GroupOption { group_id: "g1".into(), name: "Photos".into() }],
        ..State::default()
    };
    s = advance(
        s,
        Event::PreflightCompleted(PreflightView {
            resolved_path: "/data/x".into(),
            summary: vec!["non-empty folder".into()],
            warnings: vec!["folder is not empty".into(), "low free space".into()],
            is_risky: true,
        }),
    );
    s
}

#[test]
fn confirm_is_refused_until_every_warning_is_acknowledged() {
    let mut s = risky_review_state();
    assert_eq!(s.acks, vec![false, false]);
    assert!(!s.can_confirm_link());

    // Requesting confirm with unacked warnings emits no effect.
    let (s2, fx) = step(s, Event::LinkConfirmRequested);
    s = s2;
    assert!(fx.is_empty(), "confirm must not link while warnings are unacked");
    assert_eq!(s.status, OpStatus::Idle);

    s = advance(s, Event::WarningAckToggled(0));
    assert!(!s.can_confirm_link(), "one of two warnings acked is still insufficient");
    let (s2, fx) = step(s, Event::LinkConfirmRequested);
    s = s2;
    assert!(fx.is_empty());

    s = advance(s, Event::WarningAckToggled(1));
    assert!(s.can_confirm_link());
    let (_final, fx) = step(s, Event::LinkConfirmRequested);
    assert_eq!(
        fx,
        vec![Effect::JoinAndLink {
            path: "/data/x".into(),
            group_id: "g1".into(),
            group_name: "Photos".into(),
            acknowledge_risks: true,
            on_demand: false,
        }]
    );
}

#[test]
fn chosen_storage_mode_flows_into_the_link_effect() {
    // Eager is the default; choosing on-demand must reach the link effect
    // so the daemon stores only needed files instead of everything.
    let mut s = State {
        phase: Phase::LinkFolder,
        link_stage: LinkStage::Previewing,
        group_id: Some("g1".into()),
        ..State::default()
    };
    s = advance(
        s,
        Event::PreflightCompleted(PreflightView {
            resolved_path: "/data/x".into(),
            summary: vec!["empty folder".into()],
            warnings: vec![],
            is_risky: false,
        }),
    );
    assert_eq!(s.storage_mode, StorageMode::Eager);

    s = advance(s, Event::StorageModeChosen(StorageMode::OnDemand));
    assert_eq!(s.storage_mode, StorageMode::OnDemand);
    assert!(s.can_confirm_link());

    let (_final, fx) = step(s, Event::LinkConfirmRequested);
    assert_eq!(
        fx,
        vec![Effect::JoinAndLink {
            path: "/data/x".into(),
            group_id: "g1".into(),
            group_name: "g1".into(),
            acknowledge_risks: false,
            on_demand: true,
        }]
    );
}

#[test]
fn toggling_a_warning_off_again_re_gates_confirm() {
    let mut s = risky_review_state();
    s = advance(s, Event::WarningAckToggled(0));
    s = advance(s, Event::WarningAckToggled(1));
    assert!(s.can_confirm_link());
    s = advance(s, Event::WarningAckToggled(1));
    assert!(!s.can_confirm_link());
}

// ---- error / retry / back --------------------------------------------

#[test]
fn sign_in_failure_is_retryable_in_place() {
    let mut s = State { phase: Phase::SignIn, ..State::default() };
    let (s2, _) = step(s, Event::SignInRequested);
    s = s2;
    s = advance(s, Event::SignInFailed("network down".into()));
    assert_eq!(s.status, OpStatus::Failed("network down".into()));
    assert_eq!(s.phase, Phase::SignIn, "failure must not leave the step");

    let (s2, fx) = step(s, Event::Retry);
    s = s2;
    assert_eq!(fx, vec![Effect::StartLogin]);
    assert_eq!(s.status, OpStatus::Working);
}

#[test]
fn back_from_device_register_returns_to_sign_in() {
    let s = State { phase: Phase::DeviceRegister, ..State::default() };
    let s = advance(s, Event::Back);
    assert_eq!(s.phase, Phase::SignIn);
}

#[test]
fn back_in_add_folder_mode_returns_to_group_picker_not_share() {
    let mut s = State {
        phase: Phase::LinkFolder,
        mode: Mode::AddFolder,
        link_stage: LinkStage::ChooseFolder,
        ..State::default()
    };
    s = advance(s, Event::Back);
    assert_eq!(s.phase, Phase::LinkFolder);
    assert_eq!(s.link_stage, LinkStage::ChooseGroup);
}

#[test]
fn add_folder_requests_groups_then_selection_advances_to_folder_pick() {
    let mut s = derive_initial(Probe {
        signed_in: true,
        device_registered: true,
        has_links: true,
        ..Default::default()
    });
    // The window fires GroupsRequested on entering the group stage.
    let (s2, fx) = step(s, Event::GroupsRequested);
    s = s2;
    assert_eq!(fx, vec![Effect::ListGroups]);
    assert_eq!(s.status, OpStatus::Working);
    s = advance(
        s,
        Event::GroupsListed(vec![
            GroupOption { group_id: "g1".into(), name: "Photos".into() },
            GroupOption { group_id: "g2".into(), name: "Docs".into() },
        ]),
    );
    assert_eq!(s.available_groups.len(), 2);
    s = advance(s, Event::GroupSelected("g2".into()));
    assert_eq!(s.group_id.as_deref(), Some("g2"));
    assert_eq!(s.link_stage, LinkStage::ChooseFolder);
}

#[test]
fn events_out_of_phase_are_ignored() {
    // A DeviceRegistered event while still on SignIn changes nothing.
    let s = State { phase: Phase::SignIn, ..State::default() };
    let before = s.clone();
    let (after, fx) = step(s, Event::DeviceRegistered);
    assert_eq!(after, before);
    assert!(fx.is_empty());
}

#[test]
fn input_is_ignored_while_an_operation_is_working() {
    // Typing a device name mid-registration must not mutate state.
    let mut s =
        State { phase: Phase::DeviceRegister, device_name: "mac".into(), ..State::default() };
    let (s2, _) = step(s, Event::DeviceRegisterRequested);
    s = s2;
    assert_eq!(s.status, OpStatus::Working);
    let after = advance(s.clone(), Event::DeviceNameChanged("other".into()));
    assert_eq!(after.device_name, "mac");
}

#[test]
fn re_picking_a_folder_from_review_reruns_preflight() {
    let mut s = risky_review_state();
    assert_eq!(s.link_stage, LinkStage::Review);
    let (s2, fx) = step(s, Event::FolderPicked("/data/y".into()));
    s = s2;
    assert_eq!(fx, vec![Effect::RunPreflight { path: "/data/y".into() }]);
    assert_eq!(s.link_stage, LinkStage::Previewing);
    assert!(s.preflight.is_none());
    assert!(s.acks.is_empty());
}
