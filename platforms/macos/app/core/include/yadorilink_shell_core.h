/*
 * hand-written C ABI header for
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
 * first): a known local state without current content and without a transition
 * (the "online-only" state) takes priority over the raw sync state; a
 * hydrating or evicting transition folds into `Syncing`.
 */
typedef enum {
    YadoriLinkBadgeStatusUnspecified = 0,
    YadoriLinkBadgeStatusSynced = 1,
    YadoriLinkBadgeStatusSyncing = 2,
    YadoriLinkBadgeStatusPending = 3,
    YadoriLinkBadgeStatusError = 4,
    YadoriLinkBadgeStatusOnlineOnly = 5,
} YadoriLinkBadgeStatus;

/*
 * Mirrors `YadoriLinkContextAction` in src/lib.rs / `ContextAction` in
 * shellipc.proto. Pass the raw integer value to
 * yadorilink_send_context_action; any other value is rejected
 * (fail-soft, returns false).
 */
typedef enum {
    YadoriLinkContextActionViewStatus = 0,
    YadoriLinkContextActionPauseItem = 1,
    YadoriLinkContextActionResumeItem = 2,
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
 * The facts behind one path's context menu, from the daemon's own answer. All false means
 * "no YadoriLink actions": an unknown path, or a daemon that is not reachable. Mirrors
 * `YadoriLinkItemFacts` in src/lib.rs.
 */
typedef struct {
    bool tracked;
    bool paused;
    bool paused_by_ancestor;
    bool reclaim_supported;
    bool current_content_present;
    bool in_transition;
} YadoriLinkItemFacts;

/* Bounded by the same short timeout as `yadorilink_query_status`; never blocks or crashes. */
YadoriLinkItemFacts yadorilink_query_item(const char *path);

/*
 * Sends a context-menu action (`action`, a YadoriLinkContextAction value)
 * for `path` to the daemon. Returns true only on a confirmed success
 * response; false for any failure, timeout, unreachable daemon, invalid
 * path, or out-of-range action value.
 *
 * `path` must be a null-terminated UTF-8 C string; must not be NULL.
 */
bool yadorilink_send_context_action(const char *path, int action);

/*
 * The ordinary linked folders, as one confirmed snapshot.
 * `yadorilink_linked_roots_open` returns NULL when the daemon could not
 * confirm the set (unreachable, timeout, unavailable): keep what you last
 * confirmed. A non-NULL handle is authoritative even with zero paths (a
 * confirmed empty set). Paths stay valid until `yadorilink_linked_roots_free`.
 */
typedef struct YadoriLinkRoots YadoriLinkRoots;

YadoriLinkRoots *yadorilink_linked_roots_open(void);
unsigned long yadorilink_linked_roots_count(const YadoriLinkRoots *roots);
const char *yadorilink_linked_roots_path(const YadoriLinkRoots *roots, unsigned long index);
void yadorilink_linked_roots_free(YadoriLinkRoots *roots);

#ifdef __cplusplus
}
#endif

#endif /* YADORILINK_SHELL_CORE_H */
