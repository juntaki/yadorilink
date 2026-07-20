//! The onboarding wizard as a pure state
//! machine. `step(state, event) -> (state, effects)` is the single place every
//! flow-control decision lives — the eframe window (`window.rs`) is a thin
//! renderer over this, and the effect executor (`executor.rs`) turns the
//! emitted [`Effect`]s into `yadorilink_cli` calls and feeds their results
//! back as [`Event`]s. Nothing here touches egui, tokio, the keychain, or the
//! network, so every transition — including error/retry/back, resume
//! derivation, and per-warning acknowledgement gating — is exercised by the
//! unit tests at the bottom of this file without a display server (spec's
//! "Testable Onboarding State Machine").
//!
//! Kept in the same "pure model, thin shell" discipline as this crate's
//! `status_model.rs`.
/// The wizard's linear phases. `Welcome` is the fresh-install intro; `Done` is
/// terminal. Resume drops the user directly onto the first incomplete
/// phase, and adding another folder opens straight on [`Phase::LinkFolder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Welcome,
    SignIn,
    DeviceRegister,
    ShareChoose,
    LinkFolder,
    Done,
}

impl Phase {
    /// Position of this phase in the linear flow, for the window's step-list
    /// sidebar (a phase with a lower ordinal than the current one renders as
    /// complete). `Welcome`/`Done` bracket the numbered steps.
    pub fn ordinal(self) -> usize {
        match self {
            Phase::Welcome => 0,
            Phase::SignIn => 1,
            Phase::DeviceRegister => 2,
            Phase::ShareChoose => 3,
            Phase::LinkFolder => 4,
            Phase::Done => 5,
        }
    }
}

/// First-run onboarding versus reopening on an already-configured machine to
/// link another folder (/ spec "Wizard reopened on a fully configured
/// system").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    FirstRun,
    AddFolder,
}

/// How much of the folder's content this device keeps locally, chosen on the
/// link step. `Eager` stores everything (a fully-hydrated folder); `OnDemand`
/// stores only needed files as placeholders fetched on first access. The
/// wizard defaults to `Eager`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageMode {
    Eager,
    OnDemand,
}

impl StorageMode {
    /// The daemon's `on_demand` link flag for this mode: `Eager` stores
    /// everything (`false`); `OnDemand` stores only needed files (`true`).
    pub fn on_demand(self) -> bool {
        matches!(self, StorageMode::OnDemand)
    }
}

/// Sub-stage within [`Phase::LinkFolder`]. `ChooseGroup` only appears in
/// when adding another folder (first-run carries the group from the share step);
/// `Review` is where preflight warnings are acknowledged before confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkStage {
    ChooseGroup,
    ChooseFolder,
    Previewing,
    Review,
}

/// Status of the in-flight async operation for the current phase. Rendering
/// reads this to show a spinner or an error card; it makes no flow decision of
/// its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpStatus {
    Idle,
    Working,
    Failed(String),
}

/// A folder group the account owns, offered in the add-folder group
/// picker (populated from `share::list_groups`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupOption {
    pub group_id: String,
    pub name: String,
}

/// The machine's view of a link preflight result — deliberately independent of
/// `yadorilink_sync_core::link_preflight::LinkPreflightReport` so the machine
/// stays free of sync-core types. The executor converts the report into this
/// (its `warnings` is exactly `LinkPreflightReport::warnings`), and the
/// window renders one acknowledgement card per warning.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PreflightView {
    /// Canonicalized path the preflight ran against — carried into
    /// [`Effect::JoinAndLink`] so the daemon stores the same absolute path.
    pub resolved_path: String,
    /// Factual, non-warning summary lines (empty/non-empty, free space).
    pub summary: Vec<String>,
    /// One human-readable warning per risky condition; acknowledged
    /// individually before confirm is allowed.
    pub warnings: Vec<String>,
    pub is_risky: bool,
}

/// The complete wizard state. Cloneable so `step` can be a pure
/// `(state, event) -> (state, effects)` transform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    pub mode: Mode,
    pub status: OpStatus,
    /// Label for the signed-in account shown once sign-in completes.
    pub account: Option<String>,
    pub device_name: String,
    pub share_name: String,
    /// Set once a group is created, joined, or (add-folder mode) selected.
    pub group_id: Option<String>,
    pub link_stage: LinkStage,
    pub available_groups: Vec<GroupOption>,
    pub folder_path: Option<String>,
    /// The storage mode the user picked for this link (defaults to `Eager`).
    pub storage_mode: StorageMode,
    pub preflight: Option<PreflightView>,
    /// Parallel to `preflight.warnings`; every entry must be `true` before the
    /// confirm transition is allowed.
    pub acks: Vec<bool>,
    pub linked_path: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            phase: Phase::Welcome,
            mode: Mode::FirstRun,
            status: OpStatus::Idle,
            account: None,
            device_name: String::new(),
            share_name: String::new(),
            group_id: None,
            link_stage: LinkStage::ChooseFolder,
            available_groups: Vec::new(),
            folder_path: None,
            storage_mode: StorageMode::Eager,
            preflight: None,
            acks: Vec::new(),
            linked_path: None,
        }
    }
}

/// The observed system state the start phase is derived from — gathered
/// by the window before the machine starts (keychain session, `device.json`,
/// daemon `ListLinks`). Kept as plain data so the derivation is pure and
/// unit-testable.
#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub signed_in: bool,
    pub account: Option<String>,
    pub device_registered: bool,
    pub has_links: bool,
    pub default_device_name: String,
}

/// Derive the starting state from actual system state rather than a stored
/// progress marker. Any already-completed prefix of the flow is skipped, and a
/// machine that already has links opens directly in the add-folder step.
pub fn derive_initial(probe: Probe) -> State {
    let mut state = State {
        account: probe.account.clone(),
        device_name: probe.default_device_name,
        ..State::default()
    };

    if probe.has_links {
        state.mode = Mode::AddFolder;
        state.phase = Phase::LinkFolder;
        state.link_stage = LinkStage::ChooseGroup;
    } else if probe.device_registered {
        state.phase = Phase::ShareChoose;
    } else if probe.signed_in {
        state.phase = Phase::DeviceRegister;
    } else {
        state.phase = Phase::Welcome;
    }
    state
}

/// Events driving the machine: user input from the window and results of the
/// async effects the executor ran.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Leave the welcome screen for the first real step.
    Start,
    /// Return to the previous phase/stage, clearing any error.
    Back,
    /// Re-attempt the current phase's primary action after a failure.
    Retry,

    // Sign-in
    SignInRequested,
    SignInSucceeded {
        account: String,
    },
    SignInFailed(String),

    // Device registration
    DeviceNameChanged(String),
    DeviceRegisterRequested,
    DeviceRegistered,
    DeviceRegisterFailed(String),

    // Share
    ShareNameChanged(String),
    ShareSubmitRequested,

    // Link — group selection (add-folder mode only)
    /// Ask the executor to fetch the account's groups (add-folder mode's
    /// picker); the window fires this once on entering the group stage.
    GroupsRequested,
    GroupsListed(Vec<GroupOption>),
    GroupsListFailed(String),
    GroupSelected(String),

    // Link — folder + preflight + confirm
    FolderPicked(String),
    /// The user picked how much content this device keeps locally.
    StorageModeChosen(StorageMode),
    PreflightCompleted(PreflightView),
    PreflightFailed(String),
    WarningAckToggled(usize),
    LinkConfirmRequested,
    LinkSucceeded,
    LinkFailed(String),
    /// First-run: the deferred group creation and its local link both
    /// succeeded; carries the newly created group id. Failure of either step
    /// reuses `LinkFailed` — the group is deleted before the failure surfaces,
    /// so no phantom full replica is left behind.
    CreateAndLinkSucceeded {
        group_id: String,
    },
}

/// Side effects the executor runs off the UI thread (/), each mapping to a
/// `yadorilink_cli` library call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    StartLogin,
    RegisterDevice {
        name: String,
    },
    ListGroups,
    RunPreflight {
        path: String,
    },
    JoinAndLink {
        path: String,
        group_id: String,
        group_name: String,
        acknowledge_risks: bool,
        on_demand: bool,
    },
    /// First-run: create the group and link the (already-preflighted) path to it
    /// atomically, deleting the group if the link fails. Replaces a separate
    /// create-then-link so an abandoned or failed wizard never leaves a group
    /// advertised with no local copy.
    CreateAndLink {
        name: String,
        path: String,
        acknowledge_risks: bool,
        on_demand: bool,
    },
}

impl State {
    /// the confirm transition is allowed only when a preflight has run for
    /// the current folder, a target group is known, and every warning it
    /// raised has been acknowledged. A non-risky preflight has no warnings, so
    /// this is trivially satisfied. Independent of any UI rendering — the
    /// window merely disables the button to match.
    pub fn can_confirm_link(&self) -> bool {
        let Some(preflight) = &self.preflight else {
            return false;
        };
        if self.folder_path.is_none() {
            return false;
        }
        // A target must be known: an existing group to link into (add-folder
        // mode), or a non-empty new share name to create (first-run mode, where
        // the group is created only now, at confirm, and deleted if linking
        // fails).
        if self.group_id.is_none() && self.share_name.trim().is_empty() {
            return false;
        }
        self.acks.len() == preflight.warnings.len() && self.acks.iter().all(|&a| a)
    }
}

/// The one transition function. Pure: given the current state and an event, it
/// returns the next state and any effects to run. Events that don't apply to
/// the current phase/status are ignored (returning the state unchanged), which
/// keeps the window free of "is this legal right now" checks.
pub fn step(mut state: State, event: Event) -> (State, Vec<Effect>) {
    match (&state.phase, event) {
        // ---- Welcome ------------------------------------------------------
        (Phase::Welcome, Event::Start) => {
            state.phase = Phase::SignIn;
            state.status = OpStatus::Idle;
        }

        // ---- Sign-in ------------------------------------------------------
        (Phase::SignIn, Event::SignInRequested | Event::Retry)
            if state.status != OpStatus::Working =>
        {
            state.status = OpStatus::Working;
            return (state, vec![Effect::StartLogin]);
        }
        (Phase::SignIn, Event::SignInSucceeded { account }) => {
            state.account = Some(account);
            state.status = OpStatus::Idle;
            state.phase = Phase::DeviceRegister;
        }
        (Phase::SignIn, Event::SignInFailed(msg)) => {
            state.status = OpStatus::Failed(msg);
        }
        (Phase::SignIn, Event::Back) => {
            state.phase = Phase::Welcome;
            state.status = OpStatus::Idle;
        }

        // ---- Device registration -----------------------------------------
        (Phase::DeviceRegister, Event::DeviceNameChanged(name))
            if state.status != OpStatus::Working =>
        {
            state.device_name = name;
        }
        (Phase::DeviceRegister, Event::DeviceRegisterRequested | Event::Retry)
            if state.status != OpStatus::Working && !state.device_name.trim().is_empty() =>
        {
            state.status = OpStatus::Working;
            let name = state.device_name.trim().to_string();
            return (state, vec![Effect::RegisterDevice { name }]);
        }
        (Phase::DeviceRegister, Event::DeviceRegistered) => {
            state.status = OpStatus::Idle;
            state.phase = Phase::ShareChoose;
        }
        (Phase::DeviceRegister, Event::DeviceRegisterFailed(msg)) => {
            state.status = OpStatus::Failed(msg);
        }
        (Phase::DeviceRegister, Event::Back) => {
            state.phase = Phase::SignIn;
            state.status = OpStatus::Idle;
        }

        // ---- Share choose -------------------------------------------------
        (Phase::ShareChoose, Event::ShareNameChanged(name))
            if state.status != OpStatus::Working =>
        {
            state.share_name = name;
        }
        (Phase::ShareChoose, Event::ShareSubmitRequested | Event::Retry)
            if state.status != OpStatus::Working && !state.share_name.trim().is_empty() =>
        {
            // Defer group creation: the group is created only when the local
            // link is confirmed (see the LinkConfirm arm), so an abandoned or
            // failed wizard never leaves a group advertised with no local copy.
            // Just carry the trimmed name forward and advance to folder pick.
            state.share_name = state.share_name.trim().to_string();
            state.status = OpStatus::Idle;
            state.phase = Phase::LinkFolder;
            state.link_stage = LinkStage::ChooseFolder;
        }
        (Phase::ShareChoose, Event::Back) => {
            state.phase = Phase::DeviceRegister;
            state.status = OpStatus::Idle;
        }

        // ---- Link: group selection (add-folder mode) ----------------------
        (Phase::LinkFolder, Event::GroupsRequested)
            if state.link_stage == LinkStage::ChooseGroup && state.status != OpStatus::Working =>
        {
            state.status = OpStatus::Working;
            return (state, vec![Effect::ListGroups]);
        }
        (Phase::LinkFolder, Event::GroupsListed(groups))
            if state.link_stage == LinkStage::ChooseGroup =>
        {
            state.available_groups = groups;
            state.status = OpStatus::Idle;
        }
        (Phase::LinkFolder, Event::GroupsListFailed(msg))
            if state.link_stage == LinkStage::ChooseGroup =>
        {
            state.status = OpStatus::Failed(msg);
        }
        (Phase::LinkFolder, Event::GroupSelected(group_id))
            if state.link_stage == LinkStage::ChooseGroup =>
        {
            state.group_id = Some(group_id);
            state.link_stage = LinkStage::ChooseFolder;
            state.status = OpStatus::Idle;
        }

        // ---- Link: folder pick + preflight --------------------------------
        (Phase::LinkFolder, Event::FolderPicked(path))
            if matches!(state.link_stage, LinkStage::ChooseFolder | LinkStage::Review)
                && state.status != OpStatus::Working =>
        {
            state.folder_path = Some(path.clone());
            state.preflight = None;
            state.acks.clear();
            state.link_stage = LinkStage::Previewing;
            state.status = OpStatus::Working;
            return (state, vec![Effect::RunPreflight { path }]);
        }
        (Phase::LinkFolder, Event::StorageModeChosen(mode))
            if matches!(state.link_stage, LinkStage::ChooseFolder | LinkStage::Review)
                && state.status != OpStatus::Working =>
        {
            state.storage_mode = mode;
        }
        (Phase::LinkFolder, Event::PreflightCompleted(view))
            if state.link_stage == LinkStage::Previewing =>
        {
            state.acks = vec![false; view.warnings.len()];
            state.folder_path = Some(view.resolved_path.clone());
            state.preflight = Some(view);
            state.link_stage = LinkStage::Review;
            state.status = OpStatus::Idle;
        }
        (Phase::LinkFolder, Event::PreflightFailed(msg))
            if state.link_stage == LinkStage::Previewing =>
        {
            state.status = OpStatus::Failed(msg);
            state.link_stage = LinkStage::ChooseFolder;
        }
        (Phase::LinkFolder, Event::WarningAckToggled(index))
            if state.link_stage == LinkStage::Review && state.status != OpStatus::Working =>
        {
            if let Some(ack) = state.acks.get_mut(index) {
                *ack = !*ack;
            }
        }
        (Phase::LinkFolder, Event::LinkConfirmRequested | Event::Retry)
            if state.link_stage == LinkStage::Review
                && state.status != OpStatus::Working
                && state.can_confirm_link() =>
        {
            state.status = OpStatus::Working;
            let preflight = state.preflight.as_ref().expect("can_confirm_link checked presence");
            let path = preflight.resolved_path.clone();
            let acknowledge_risks = preflight.is_risky;
            let on_demand = state.storage_mode.on_demand();
            let effect = match &state.group_id {
                // Add-folder mode: join the selected group and link it using
                // the crash-safe Pending -> Active enrollment protocol.
                Some(group_id) => Effect::JoinAndLink {
                    path,
                    group_id: group_id.clone(),
                    group_name: state
                        .available_groups
                        .iter()
                        .find(|group| group.group_id == *group_id)
                        .map(|group| group.name.clone())
                        .unwrap_or_else(|| group_id.clone()),
                    acknowledge_risks,
                    on_demand,
                },
                // First-run mode: create the group and link it atomically,
                // deleting the group if the link fails — no phantom full replica.
                None => Effect::CreateAndLink {
                    name: state.share_name.clone(),
                    path,
                    acknowledge_risks,
                    on_demand,
                },
            };
            return (state, vec![effect]);
        }
        (Phase::LinkFolder, Event::LinkSucceeded) => {
            state.linked_path = state.folder_path.clone();
            state.status = OpStatus::Idle;
            state.phase = Phase::Done;
        }
        (Phase::LinkFolder, Event::CreateAndLinkSucceeded { group_id }) => {
            // First-run: the group was created and linked atomically.
            state.group_id = Some(group_id);
            state.linked_path = state.folder_path.clone();
            state.status = OpStatus::Idle;
            state.phase = Phase::Done;
        }
        (Phase::LinkFolder, Event::LinkFailed(msg)) => {
            state.status = OpStatus::Failed(msg);
        }
        (Phase::LinkFolder, Event::Back) => {
            // First-run: back to the share step. Add-folder mode: back to the
            // group picker (there is no earlier wizard step to return to).
            match state.mode {
                Mode::FirstRun => {
                    state.phase = Phase::ShareChoose;
                }
                Mode::AddFolder => {
                    state.link_stage = LinkStage::ChooseGroup;
                }
            }
            state.status = OpStatus::Idle;
        }

        // Any event that doesn't apply to the current phase/status is a no-op.
        _ => {}
    }
    (state, Vec::new())
}

#[cfg(test)]
mod tests {
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
        let s = derive_initial(Probe {
            signed_in: true,
            device_registered: true,
            ..Default::default()
        });
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
        let mut s =
            derive_initial(Probe { default_device_name: "mac".into(), ..Default::default() });

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
}
