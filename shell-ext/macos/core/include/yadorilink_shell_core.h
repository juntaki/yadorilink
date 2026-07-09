/*
 * build-yadorilink-mvp task 10.1: hand-written C ABI header for
 * `yadorilink_shell_ext_macos_core` (crate name `yadorilink_shell_core`),
 * mirroring `src/lib.rs`'s `#[no_mangle] extern "C"` surface exactly.
 *
 * Hand-written rather than `cbindgen`-generated: `cbindgen` was not
 * available in this build environment (no Homebrew/cargo-install network
 * access budgeted for a one-off tool), and the FFI surface here is small
 * (two functions) and intentionally kept small going forward, so keeping
 * this header in sync by hand is a reasonable trade-off. If the FFI
 * surface grows meaningfully, switching to `cbindgen` (added as a
 * build-dependency with a `cbindgen.toml`) would be the natural next step
 * to keep this header from drifting out of sync with `src/lib.rs`.
 *
 * Included via the Swift extension target's bridging header
 * (YadoriLinkFinderSync-Bridging-Header.h) so Swift can call
 * `yadorilink_query_status` / `yadorilink_send_context_action` directly.
 */

#ifndef YADORILINK_SHELL_CORE_H
#define YADORILINK_SHELL_CORE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Mirrors `YadoriLinkBadgeStatus` in src/lib.rs. Priority order (highest
 * first): a non-empty `open_elsewhere_device_id` always wins as
 * `OpenElsewhere`; then `MaterializationState::Placeholder`
 * (the "online-only" state) takes priority over the raw
 * sync state; `Hydrating` folds into `Syncing`.
 */
typedef enum {
    YadoriLinkBadgeStatusUnspecified = 0,
    YadoriLinkBadgeStatusSynced = 1,
    YadoriLinkBadgeStatusSyncing = 2,
    YadoriLinkBadgeStatusPending = 3,
    YadoriLinkBadgeStatusError = 4,
    YadoriLinkBadgeStatusOnlineOnly = 5,
    YadoriLinkBadgeStatusOpenElsewhere = 6,
} YadoriLinkBadgeStatus;

/*
 * Mirrors `YadoriLinkContextAction` in src/lib.rs / `ContextAction` in
 * shellipc.proto. Pass the raw integer value to
 * yadorilink_send_context_action; values outside 0-4 are rejected
 * (fail-soft, returns false).
 */
typedef enum {
    YadoriLinkContextActionViewStatus = 0,
    YadoriLinkContextActionPauseItem = 1,
    YadoriLinkContextActionResumeItem = 2,
    YadoriLinkContextActionPinItem = 3,
    YadoriLinkContextActionEvictItem = 4,
} YadoriLinkContextAction;

/*
 * Queries the daemon (over the local shell-integration IPC socket) for
 * `path`'s combined badge status. Bounded to a short timeout internally;
 * always returns promptly, even if the daemon is not running (returns
 * YadoriLinkBadgeStatusUnspecified in that case — never blocks or crashes).
 *
 * `path` must be a null-terminated UTF-8 C string; must not be NULL.
 */
int yadorilink_query_status(const char *path);

/*
 * Sends a context-menu action (`action`, a YadoriLinkContextAction value)
 * for `path` to the daemon. Returns true only on a confirmed success
 * response; false for any failure, timeout, unreachable daemon, invalid
 * path, or out-of-range action value.
 *
 * `path` must be a null-terminated UTF-8 C string; must not be NULL.
 */
bool yadorilink_send_context_action(const char *path, int action);

#ifdef __cplusplus
}
#endif

#endif /* YADORILINK_SHELL_CORE_H */
