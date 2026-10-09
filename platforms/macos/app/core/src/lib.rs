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

#[cfg(test)]
mod combine_status_tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::LocalState;

    fn info(local: Option<(bool, bool, LocalTransition)>, sync: SyncState) -> ipc_client::StatusInfo {
        ipc_client::StatusInfo {
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
            combine_status(info(Some((false, false, LocalTransition::Hydrating)), SyncState::Unspecified)),
            YadoriLinkBadgeStatus::Syncing
        );
    }
}
