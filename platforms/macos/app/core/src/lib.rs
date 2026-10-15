//! The "thin Rust core" behind the Swift `FIFinderSync` extension — a
//! C-ABI FFI surface over `ipc_client`'s IPC logic, callable from Swift
//! via a bridging header (`include/yadorilink_shell_core.h`).
//!
//! Contract mirrored from the Windows shell extension and the daemon's
//! own reference client (`yadorilink_daemon::shell_ipc::client`): every
//! exported function is bounded-timeout and fail-soft — it must never
//! block Finder noticeably or crash the host process (a panic unwinding
//! across the FFI boundary is undefined behavior in a `staticlib`, so
//! every entry point is wrapped in `catch_unwind`).

mod ipc_client;

use std::ffi::{c_char, c_int, CStr};
use std::panic::catch_unwind;

use yadorilink_ipc_proto::shellipc::{ContextAction, LocalTransition, SyncState};

/// Mirrors the four spec'd overlay states plus on-demand-sync's
/// "online-only" placeholder overlay, as a flat C enum Swift can switch
/// on directly. A known local state with no current content and no transition
/// under way (the "online-only" state) takes priority over the
/// raw `SyncState`, since "online-only" is the visually distinct badge the
/// spec calls for on an unhydrated file regardless of its underlying
/// convergence state; `Hydrating` is folded into `Syncing` (content
/// actively moving), matching the spirit of the existing
/// `SyncState::Syncing` badge rather than adding a sixth visual state not
/// called for by the spec.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YadoriLinkBadgeStatus {
    Unspecified = 0,
    Synced = 1,
    Syncing = 2,
    Pending = 3,
    Error = 4,
    OnlineOnly = 5,
}

/// Mirrors `shellipc.proto`'s `ContextAction` enum, as the small stable
/// integer contract Swift's `menu(for:)` handler passes across the FFI
/// boundary (kept independent of `prost`'s generated numbering so the
/// Swift side has no build-time dependency on the `.proto` file).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YadoriLinkContextAction {
    ViewStatus = 0,
    PauseItem = 1,
    ResumeItem = 2,
    EvictItem = 4,
}

impl TryFrom<c_int> for YadoriLinkContextAction {
    type Error = ();

    fn try_from(value: c_int) -> Result<Self, ()> {
        match value {
            0 => Ok(YadoriLinkContextAction::ViewStatus),
            1 => Ok(YadoriLinkContextAction::PauseItem),
            2 => Ok(YadoriLinkContextAction::ResumeItem),
            4 => Ok(YadoriLinkContextAction::EvictItem),
            _ => Err(()),
        }
    }
}

impl From<YadoriLinkContextAction> for ContextAction {
    fn from(a: YadoriLinkContextAction) -> Self {
        match a {
            YadoriLinkContextAction::ViewStatus => ContextAction::ViewStatus,
            YadoriLinkContextAction::PauseItem => ContextAction::PauseItem,
            YadoriLinkContextAction::ResumeItem => ContextAction::ResumeItem,
            YadoriLinkContextAction::EvictItem => ContextAction::EvictItem,
        }
    }
}

/// # Safety
/// `path` must be a valid, null-terminated C string for the duration of
/// this call (standard C-string FFI contract). Returns `None` (rather
/// than panicking) for a null pointer or non-UTF-8 bytes — Finder-supplied
/// paths are always valid UTF-8 in practice, but this must fail soft, not
/// crash, on anything unexpected.
unsafe fn path_from_c_str(path: *const c_char) -> Option<String> {
    if path.is_null() {
        return None;
    }
    CStr::from_ptr(path).to_str().ok().map(str::to_owned)
}

fn combine_status(info: ipc_client::StatusInfo) -> YadoriLinkBadgeStatus {
    let in_transition = info.local_state.as_ref().is_some_and(|s| {
        s.transition() == LocalTransition::Hydrating || s.transition() == LocalTransition::Evicting
    });
    if info
        .local_state
        .as_ref()
        .is_some_and(|s| !s.current_content_present && s.transition() == LocalTransition::None)
    {
        return YadoriLinkBadgeStatus::OnlineOnly;
    }
    match info.sync_state {
        SyncState::Synced => YadoriLinkBadgeStatus::Synced,
        SyncState::Syncing => YadoriLinkBadgeStatus::Syncing,
        SyncState::Pending => YadoriLinkBadgeStatus::Pending,
        SyncState::Error => YadoriLinkBadgeStatus::Error,
        SyncState::Unspecified => {
            if in_transition {
                YadoriLinkBadgeStatus::Syncing
            } else {
                YadoriLinkBadgeStatus::Unspecified
            }
        }
    }
}

/// What the Finder context menu needs to know about one path, as plain facts. The menu decision
/// itself is Swift (`FinderMenu`); nothing here invents state: every field is the daemon's own
/// answer, and an unreachable daemon or an unknown path is `tracked == false`, which the menu
/// treats as "no YadoriLink actions".
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct YadoriLinkItemFacts {
    /// The daemon knows the path (a sync state or a local state came back).
    pub tracked: bool,
    /// The user paused this path, or an item above it.
    pub paused: bool,
    /// An item above it is paused and it is not itself: neither Pause nor Resume applies.
    pub paused_by_ancestor: bool,
    /// The daemon's eviction gate accepts this path's root (Free Up Space is not a promise the
    /// daemon would refuse).
    pub reclaim_supported: bool,
    /// A usable proof names the current version and its bytes are on this device. Never true
    /// during a hydrate or evict transition.
    pub current_content_present: bool,
    /// A hydrate or evict is under way.
    pub in_transition: bool,
}

fn item_facts(info: &ipc_client::StatusInfo) -> YadoriLinkItemFacts {
    let transition = info.local_state.as_ref().map(|s| s.transition());
    let in_transition =
        matches!(transition, Some(LocalTransition::Hydrating | LocalTransition::Evicting));
    YadoriLinkItemFacts {
        // A file row has a local state. A directory has none of its own and takes the aggregate
        // sync state. `Pending` without a local state is a file the daemon has not indexed yet.
        tracked: info.local_state.is_some()
            || matches!(info.sync_state, SyncState::Synced | SyncState::Syncing | SyncState::Error),
        paused: info.item_paused,
        paused_by_ancestor: info.paused_by_ancestor,
        reclaim_supported: info.reclaim_supported,
        current_content_present: !in_transition
            && info.local_state.as_ref().is_some_and(|s| s.current_content_present),
        in_transition,
    }
}

/// Queries the daemon for the facts behind `path`'s context menu. Fails soft to all-false
/// (untracked) on a null/invalid path or an unreachable daemon, within the bounded timeout.
///
/// # Safety
/// See `path_from_c_str`.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_query_item(path: *const c_char) -> YadoriLinkItemFacts {
    let Some(path) = path_from_c_str(path) else { return YadoriLinkItemFacts::default() };
    catch_unwind(|| item_facts(&ipc_client::query_status(&path))).unwrap_or_default()
}

/// Queries the daemon for `path`'s combined badge status.
/// Fails soft to `YadoriLinkBadgeStatus::Unspecified` (Finder shows no
/// overlay) on a null/invalid path, an unreachable daemon, or any other
/// error — never blocks longer than the bounded timeout in `ipc_client`.
///
/// # Safety
/// See `path_from_c_str`.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_query_status(path: *const c_char) -> c_int {
    let path = match path_from_c_str(path) {
        Some(p) => p,
        None => return YadoriLinkBadgeStatus::Unspecified as c_int,
    };
    let result = catch_unwind(|| combine_status(ipc_client::query_status(&path)));
    result.unwrap_or(YadoriLinkBadgeStatus::Unspecified) as c_int
}

/// Sends a context-menu action for `path` to the daemon.
/// `action` is a `YadoriLinkContextAction` discriminant; passed as a
/// plain `c_int` rather than the enum type itself so the C/Swift ABI
/// doesn't depend on how Rust happens to lay out a `#[repr(C)]`
/// fieldless enum on a given target — a bare `int` is unambiguous on
/// both sides of the bridging header.
///
/// Returns `1` (true) on a confirmed success response, `0` (false) for
/// any failure, timeout, unreachable daemon, invalid path, or
/// out-of-range `action` — the Swift side is expected to silently no-op
/// the menu item rather than show an error dialog on `false`, matching
/// the badge's own fail-soft contract.
///
/// # Safety
/// See `path_from_c_str`.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_send_context_action(
    path: *const c_char,
    action: c_int,
) -> bool {
    let path = match path_from_c_str(path) {
        Some(p) => p,
        None => return false,
    };
    let Ok(action) = YadoriLinkContextAction::try_from(action) else { return false };
    catch_unwind(|| ipc_client::send_context_action(&path, action.into())).unwrap_or(false)
}

/// One confirmed snapshot of the ordinary linked folders. Opaque to C; read with
/// `yadorilink_linked_roots_count` / `_path` and released with `_free`.
pub struct YadoriLinkRoots(Vec<std::ffi::CString>);

/// Asks the daemon for the ordinary linked folders. Returns NULL when the daemon could not
/// confirm them (unreachable, timeout, `snapshot_available == false`): the caller keeps the set
/// it last confirmed. A non-NULL handle is authoritative, even with zero paths.
#[no_mangle]
pub extern "C" fn yadorilink_linked_roots_open() -> *mut YadoriLinkRoots {
    let Ok(Some(paths)) = catch_unwind(ipc_client::list_linked_roots) else {
        return std::ptr::null_mut();
    };
    // A path with an interior NUL cannot cross the C boundary; drop it rather than the snapshot.
    let paths = paths.into_iter().filter_map(|p| std::ffi::CString::new(p).ok()).collect();
    Box::into_raw(Box::new(YadoriLinkRoots(paths)))
}

/// # Safety
/// `roots` must be a live handle from `yadorilink_linked_roots_open` (or NULL).
#[no_mangle]
pub unsafe extern "C" fn yadorilink_linked_roots_count(roots: *const YadoriLinkRoots) -> usize {
    roots.as_ref().map_or(0, |r| r.0.len())
}

/// The i-th path (valid until `yadorilink_linked_roots_free`), or NULL if out of range.
///
/// # Safety
/// `roots` must be a live handle from `yadorilink_linked_roots_open` (or NULL).
#[no_mangle]
pub unsafe extern "C" fn yadorilink_linked_roots_path(
    roots: *const YadoriLinkRoots,
    index: usize,
) -> *const c_char {
    roots.as_ref().and_then(|r| r.0.get(index)).map_or(std::ptr::null(), |p| p.as_ptr())
}

/// # Safety
/// `roots` must be a handle from `yadorilink_linked_roots_open` not yet freed (or NULL).
#[no_mangle]
pub unsafe extern "C" fn yadorilink_linked_roots_free(roots: *mut YadoriLinkRoots) {
    if !roots.is_null() {
        drop(Box::from_raw(roots));
    }
}

#[cfg(test)]
mod combine_status_tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::LocalState;

    fn info(
        local: Option<(bool, bool, LocalTransition)>,
        sync: SyncState,
    ) -> ipc_client::StatusInfo {
        ipc_client::StatusInfo {
            item_paused: false,
            paused_by_ancestor: false,
            reclaim_supported: false,
            sync_state: sync,
            local_state: local.map(|(object, current, transition)| LocalState {
                local_object_present: object,
                current_content_present: current,
                transition: transition as i32,
            }),
        }
    }

    #[test]
    fn only_a_known_state_without_current_content_is_online_only() {
        let none = LocalTransition::None;
        assert_eq!(
            combine_status(info(Some((false, false, none)), SyncState::Synced)),
            YadoriLinkBadgeStatus::OnlineOnly
        );
        // An older object that stands is not current content either.
        assert_eq!(
            combine_status(info(Some((true, false, none)), SyncState::Synced)),
            YadoriLinkBadgeStatus::OnlineOnly
        );
        assert_eq!(
            combine_status(info(Some((true, true, none)), SyncState::Synced)),
            YadoriLinkBadgeStatus::Synced
        );
        // Unknown is no badge, never online-only.
        assert_eq!(
            combine_status(info(None, SyncState::Unspecified)),
            YadoriLinkBadgeStatus::Unspecified
        );
        assert_eq!(
            combine_status(info(
                Some((false, false, LocalTransition::Hydrating)),
                SyncState::Unspecified
            )),
            YadoriLinkBadgeStatus::Syncing
        );
    }
}

#[cfg(test)]
mod item_facts_tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::LocalState;

    fn info(
        sync: SyncState,
        local: Option<(bool, bool, LocalTransition)>,
    ) -> ipc_client::StatusInfo {
        ipc_client::StatusInfo {
            sync_state: sync,
            item_paused: false,
            paused_by_ancestor: false,
            reclaim_supported: true,
            local_state: local.map(|(object, current, transition)| LocalState {
                local_object_present: object,
                current_content_present: current,
                transition: transition as i32,
            }),
        }
    }

    #[test]
    fn a_path_the_daemon_knows_nothing_about_is_untracked() {
        let facts = item_facts(&info(SyncState::Unspecified, None));
        assert!(!facts.tracked);
        assert!(!facts.paused && !facts.current_content_present && !facts.in_transition);
    }

    #[test]
    fn a_new_unindexed_file_is_untracked() {
        // The daemon answers Pending, with no local state, for a file under a linked folder that
        // has no index row yet; it gets no actions until it is indexed.
        assert!(!item_facts(&info(SyncState::Pending, None)).tracked);
    }

    #[test]
    fn an_indexed_folder_without_a_row_of_its_own_is_tracked() {
        // A directory (or the link root) takes the aggregate sync state and has no local state.
        for sync in [SyncState::Synced, SyncState::Syncing, SyncState::Error] {
            assert!(item_facts(&info(sync, None)).tracked, "{sync:?}");
        }
    }

    #[test]
    fn a_synced_local_file_is_tracked_with_current_content() {
        let facts = item_facts(&info(SyncState::Synced, Some((true, true, LocalTransition::None))));
        assert!(facts.tracked && facts.current_content_present && facts.reclaim_supported);
        assert!(!facts.paused && !facts.in_transition);
    }

    #[test]
    fn a_remote_file_is_tracked_without_current_content() {
        let facts =
            item_facts(&info(SyncState::Synced, Some((false, false, LocalTransition::None))));
        assert!(facts.tracked);
        assert!(!facts.current_content_present);
    }

    #[test]
    fn a_transition_is_reported_and_never_current_content() {
        for transition in [LocalTransition::Hydrating, LocalTransition::Evicting] {
            let facts = item_facts(&info(SyncState::Syncing, Some((true, true, transition))));
            assert!(facts.tracked && facts.in_transition);
            assert!(!facts.current_content_present, "{transition:?}");
        }
    }

    #[test]
    fn pause_and_reclaim_facts_are_carried_as_the_daemon_said_them() {
        let mut i = info(SyncState::Synced, Some((true, true, LocalTransition::None)));
        i.item_paused = true;
        i.reclaim_supported = false;
        let facts = item_facts(&i);
        assert!(facts.paused && !facts.paused_by_ancestor && !facts.reclaim_supported);
        let mut i = info(SyncState::Synced, Some((true, true, LocalTransition::None)));
        i.paused_by_ancestor = true;
        let facts = item_facts(&i);
        assert!(!facts.paused && facts.paused_by_ancestor);
    }
}
