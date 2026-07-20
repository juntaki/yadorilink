/*
 * hand-written C ABI header for
 * `yadorilink_fileprovider_core`, mirroring `src/lib.rs`'s
 * `#[no_mangle] extern "C"` surface exactly. Hand-written for the same
 * reason `shell-ext/macos/core/include/yadorilink_shell_core.h` is
 * (cbindgen not available in this build environment; small, intentionally
 * stable FFI surface).
 *
 * Included via the FileProvider extension target's bridging header
 * (YadoriLinkFileProvider/Extension/YadoriLinkFileProvider-Bridging-Header.h)
 * and the host app's bridging header (HostApp needs
 * yadorilink_fp_list_on_demand_folders / yadorilink_fp_real_home_dir for
 * domain registration).
 */

#ifndef YADORILINK_FILEPROVIDER_CORE_H
#define YADORILINK_FILEPROVIDER_CORE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Frees a C string returned by any yadorilink_fp_* function below. NULL is
 * a no-op. Never call on a pointer not returned by this library, and
 * never call twice on the same pointer.
 */
void yadorilink_fp_free_string(char *ptr);

/*
 * Returns the real user home directory (via getpwuid(3), immune to App
 * Sandbox's HOME/NSHomeDirectory redirection). Caller must free with
 * yadorilink_fp_free_string. Never returns NULL (falls back to an empty
 * string on internal failure).
 */
char *yadorilink_fp_real_home_dir(void);

/*
 * Returns a JSON array of {"local_path": string, "group_id": string}
 * for every OnDemand-linked folder group the daemon currently knows
 * about. "[]" on any failure (unreachable daemon, timeout). Caller must
 * free with yadorilink_fp_free_string.
 */
char *yadorilink_fp_list_on_demand_folders(void);

/*
 * Returns a JSON array of {"relative_path": string, "size": uint64,
 * "mtime_unix_nanos": int64, "materialization_state": string} for every
 * non-deleted file in the folder group rooted at `local_path` (must
 * match a local_path from yadorilink_fp_list_on_demand_folders).
 * `materialization_state` is one of "hydrated" | "placeholder" |
 * "hydrating" | "unspecified". "[]" on a NULL path or any failure.
 * Caller must free with yadorilink_fp_free_string.
 *
 * `local_path` must be a null-terminated UTF-8 C string, or NULL.
 */
char *yadorilink_fp_list_folder_files(const char *local_path);

/*
 * Returns a JSON object {"sync_state": string, "materialization_state":
 * string, "open_elsewhere_device_id": string} for `path`.
 * `open_elsewhere_device_id` is empty if the file is not currently
 * reported open elsewhere (an advisory-only signal). Falls back to
 * an all-"unspecified"/empty-string object on a NULL path or any
 * failure. Caller must free with yadorilink_fp_free_string.
 *
 * `path` must be a null-terminated UTF-8 C string, or NULL.
 */
char *yadorilink_fp_query_status(const char *path);

/*
 * Requests hydration of `path` from the daemon, blocking the calling
 * thread up to ~35s (a bounded-timeout decision — long enough to cover
 * the daemon-side 30s hydration deadline plus IPC overhead). Returns
 * true only on a confirmed successful hydration;
 * false for a NULL path, timeout, unreachable daemon, or a
 * daemon-reported failure. Callers with a synchronous OS callback to
 * satisfy (fetchContents(for:...)) must complete that callback with a
 * clear error on false, never hang.
 *
 * `path` must be a null-terminated UTF-8 C string, or NULL.
 */
bool yadorilink_fp_hydrate(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* YADORILINK_FILEPROVIDER_CORE_H */
