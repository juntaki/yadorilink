/*
 * hand-written C ABI header for
 * `yadorilink_fileprovider_core`, mirroring `src/lib.rs`'s
 * `#[no_mangle] extern "C"` surface exactly. Hand-written for the same
 * reason `platforms/macos/app/core/include/yadorilink_shell_core.h` is
 * (cbindgen not available in this build environment; small, intentionally
 * stable FFI surface).
 *
 * Included via the FileProvider extension target's bridging header
 * (YadoriLinkFileProvider/Extension/YadoriLinkFileProvider-Bridging-Header.h)
 * and the host app's bridging header (the host connection, the folder
 * list and the home directory).
 */

#ifndef YADORILINK_FILEPROVIDER_CORE_H
#define YADORILINK_FILEPROVIDER_CORE_H

#include <stdbool.h>
#include <stdint.h>

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
 * Returns a JSON array of {"root_id": string (hex), "group_id": string,
 * "display_name": string, "hydration_policy": "on_demand"|"eager"|"unspecified",
 * "registration_ready": bool} for every provider-backed root the daemon
 * currently knows about (root_id is the File Provider domain identifier; there is no
 * local path). registration_ready == false: the host must NOT register a new
 * domain and must NOT delete an existing one (the OS caches an empty root
 * listing registered before the namespace is queryable). The authoritative desired-registration-state snapshot domain
 * reconciliation (ProviderDriver) reconciles against. Returns
 * NULL, deliberately distinct from a valid "[]" string, on any failure
 * (unreachable daemon, timeout, malformed response): the caller MUST
 * treat NULL as "cannot currently confirm the desired state, do not
 * reconcile," never as "the desired state is empty, remove everything
 * registered." Caller must free a non-NULL result with
 * yadorilink_fp_free_string.
 */
char *yadorilink_fp_list_provider_folders(const char *app_group_container);

/* One request of the provider-root protocol (JSON in, JSON out). NULL on any transport failure
   (map to .serverUnreachable, never to an empty result). Free a non-NULL result with
   yadorilink_fp_free_string. */
char *yadorilink_fp_provider_call(const char *request_json);

/* The host app's persistent connection (see host_client.rs). Events arrive as JSON text through
   `callback` on the connection's own thread; the text is valid only during the call. */
typedef struct YadoriLinkHost YadoriLinkHost;
typedef void (*YadoriLinkHostCallback)(const char *event_json, void *context);
YadoriLinkHost *yadorilink_fp_host_open(YadoriLinkHostCallback callback, void *context);
bool yadorilink_fp_host_send(YadoriLinkHost *host, const char *command_json);
void yadorilink_fp_host_close(YadoriLinkHost *host);

#ifdef __cplusplus
}
#endif

#endif /* YADORILINK_FILEPROVIDER_CORE_H */
