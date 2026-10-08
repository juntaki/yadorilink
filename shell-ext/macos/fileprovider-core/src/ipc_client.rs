//! Shell-integration IPC client for the File Provider extension point
//! (7.3). A close copy of
//! `shell-ext/macos/core/src/ipc_client.rs`'s connect/timeout/fail-soft
//! pattern (see this crate's Cargo.toml doc comment for why it's a copy
//! rather than a shared dependency), extended with the three calls
//! `NSFileProviderReplicatedExtension` needs that FinderSync's badge/menu
//! callbacks never did: folder discovery (for domain registration),
//! per-folder file enumeration (for `NSFileProviderEnumerator`), and
//! hydration (for `fetchContents(for:version:request:completionHandler:)`).

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    HydrationPolicy, ListProviderFoldersRequest, ShellIpcMessage,
};

/// Folder discovery is a local, in-memory read on the daemon side, but it is still bounded: the host
/// must never wait on a daemon that does not answer.
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the File Provider extension's background IPC runtime")
    })
}

/// See `core::ipc_client::real_home_dir`'s doc comment: under App
/// Sandbox, `$HOME`/`NSHomeDirectory`/`homeDirectoryForCurrentUser` are
/// all redirected to the extension's own container home, not the real
/// user home. `getpwuid(3)` reads Directory Services directly and is not
/// affected.
fn real_home_dir() -> PathBuf {
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir);
        PathBuf::from(dir.to_string_lossy().into_owned())
    }
}

/// Same App Group ID as `core::ipc_client::APP_GROUP_CONTAINER` — see
/// `YadoriLinkFileProvider/Extension/Extension.entitlements`'s doc comment
/// (copied from `YadoriLinkFinderSync/Extension/Extension.entitlements`,
/// which documents the App-Groups-not-temporary-exception root cause
/// this crate also depends on). Both extensions and the host app must
/// agree on this constant for the daemon's socket to be reachable.
const APP_GROUP_CONTAINER: &str = "group.com.juntaki.yadorilink.shared";

fn socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("YADORILINK_SHELL_IPC_SOCKET") {
        return PathBuf::from(path);
    }
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir).join("shell.sock");
    }
    let group_container =
        real_home_dir().join("Library").join("Group Containers").join(APP_GROUP_CONTAINER);
    if group_container.is_dir() {
        return group_container.join("shell.sock");
    }
    real_home_dir()
        .join("Library")
        .join("Application Support")
        .join("yadorilink")
        .join("shell.sock")
}

pub(crate) async fn connect() -> std::io::Result<UnixStream> {
    UnixStream::connect(socket_path()).await
}

/// The real, real-user-visible home directory, exposed to Swift so the
/// host app can compute `~/Library/CloudStorage/yadorilink` (the
/// managed location) without hitting the same sandbox-redirection trap
/// `real_home_dir`'s doc comment describes — the host app itself is
/// currently unsandboxed (see `YadoriLinkFinderSyncHost`'s lack of an
/// entitlements file), so `FileManager.default.homeDirectoryForCurrentUser`
/// would actually be accurate there today, but routing this through the
/// same `getpwuid`-based helper keeps the host app and both extensions
/// agreeing on one implementation rather than three independent (and
/// potentially divergent) ones.
pub fn real_home_dir_string() -> String {
    real_home_dir().to_string_lossy().into_owned()
}

/// One provider-backed root, as plain JSON for the Swift side (no build-time dependency
/// on the proto's generated numbering). `root_id` is the lowercase hex of the daemon's
/// 16-byte root id and is the File Provider domain identifier; there is no local path.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ProviderFolderInfo {
    pub root_id: String,
    pub group_id: String,
    pub display_name: String,
    /// `"on_demand" | "eager" | "unspecified"`.
    pub hydration_policy: String,
    /// false => the host must NOT register a new domain and must NOT delete an existing
    /// one: the OS caches an empty root listing registered before the namespace is
    /// queryable.
    pub registration_ready: bool,
    /// The latest handoff sequence the daemon issued (the host reads it before it enumerates the
    /// materialized set).
    pub latest_evidence_seq: u64,
}

/// A domain the daemon wants removed (a durable intent): the ONLY authority to remove one.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ProviderRemovalInfo {
    pub root_id: String,
    pub display_name: String,
}

/// The daemon's confirmed answer: the desired domains and the domains to remove.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderSnapshot {
    pub folders: Vec<ProviderFolderInfo>,
    pub removals: Vec<ProviderRemovalInfo>,
}

fn hydration_policy_str(policy: HydrationPolicy) -> &'static str {
    match policy {
        HydrationPolicy::OnDemand => "on_demand",
        HydrationPolicy::Eager => "eager",
        HydrationPolicy::Unspecified => "unspecified",
    }
}

/// Discovers every provider-backed root via `ListProviderFoldersRequest`/`Response`. The
/// daemon's answer is the authoritative desired-registration-state snapshot.
///
/// `None` on any failure (unreachable daemon, timeout, malformed response, or an explicit
/// `snapshot_available: false`), deliberately distinct from `Some(vec![])`, a *confirmed*
/// "no provider roots exist". The caller (the host's `ProviderDriver`, which both registers
/// missing domains AND removes stale ones) must treat `None` as "cannot reconcile, leave
/// existing registrations untouched".
pub fn list_provider_folders(app_group_container: &str) -> Option<ProviderSnapshot> {
    runtime().block_on(async {
        tokio::time::timeout(ENUMERATION_TIMEOUT, list_provider_folders_inner(app_group_container))
            .await
            .ok()?
    })
}

async fn list_provider_folders_inner(app_group_container: &str) -> Option<ProviderSnapshot> {
    let mut stream = connect().await.ok()?;
    list_provider_folders_over(&mut stream, app_group_container).await
}

/// The stream-generic core of `list_provider_folders_inner`, split out so the load-bearing
/// None-vs-Some distinction is testable against an in-memory duplex stream.
async fn list_provider_folders_over<S>(
    stream: &mut S,
    app_group_container: &str,
) -> Option<ProviderSnapshot>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListProviderFoldersRequest(ListProviderFoldersRequest {
            app_group_container: app_group_container.to_string(),
        })),
    };
    write_message(stream, &msg).await.ok()?;
    match read_message::<ShellIpcMessage>(stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListProviderFoldersResponse(r)) }))
            if r.snapshot_available =>
        {
            let removals = r
                .removals
                .iter()
                .map(|removal| ProviderRemovalInfo {
                    root_id: hex_lower(&removal.root_id),
                    display_name: removal.display_name.clone(),
                })
                .collect();
            let folders = {
                r.folders
                    .into_iter()
                    .map(|f| ProviderFolderInfo {
                        hydration_policy: hydration_policy_str(
                            HydrationPolicy::try_from(f.hydration_policy)
                                .unwrap_or(HydrationPolicy::Unspecified),
                        )
                        .to_string(),
                        root_id: hex_lower(&f.root_id),
                        group_id: String::from_utf8_lossy(&f.group_id).into_owned(),
                        display_name: f.display_name,
                        registration_ready: f.registration_ready,
                        latest_evidence_seq: f.latest_evidence_seq,
                    })
                    .collect()
            };
            Some(ProviderSnapshot { folders, removals })
        }
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A duplex "server" half that writes `response` (if any) back after
    /// reading whatever request arrives, then closes -- enough to drive
    /// `list_provider_folders_over` through each branch without a real
    /// daemon.
    async fn respond_with(response: Option<ShellIpcMessage>) -> Option<ProviderSnapshot> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
            if let Some(response) = response {
                let _ = write_message(&mut server, &response).await;
            }
            // Dropping `server` here closes the duplex from this end,
            // so a caller expecting a response after a `None` (simulating
            // "server closed the connection without answering") sees EOF
            // rather than hanging.
        });
        let result = list_provider_folders_over(&mut client, "/group").await;
        server_task.await.unwrap();
        result
    }

    fn wire(f: &ProviderFolderInfo) -> yadorilink_ipc_proto::shellipc::ProviderFolder {
        yadorilink_ipc_proto::shellipc::ProviderFolder {
            root_id: vec![0xab; 16],
            group_id: f.group_id.clone().into_bytes(),
            display_name: f.display_name.clone(),
            hydration_policy: HydrationPolicy::OnDemand as i32,
            registration_ready: f.registration_ready,
            latest_evidence_seq: f.latest_evidence_seq,
        }
    }

    fn response(folders: Vec<ProviderFolderInfo>, snapshot_available: bool) -> ShellIpcMessage {
        ShellIpcMessage {
            payload: Some(Payload::ListProviderFoldersResponse(
                yadorilink_ipc_proto::shellipc::ListProviderFoldersResponse {
                    folders: folders.iter().map(wire).collect(),
                    snapshot_available,
                    removals: vec![yadorilink_ipc_proto::shellipc::ProviderRemoval {
                        root_id: vec![0xcd; 16],
                        display_name: "Gone".to_string(),
                    }],
                },
            )),
        }
    }

    fn folder(ready: bool) -> ProviderFolderInfo {
        ProviderFolderInfo {
            root_id: "ab".repeat(16),
            group_id: "group-a".to_string(),
            display_name: "A".to_string(),
            hydration_policy: "on_demand".to_string(),
            registration_ready: ready,
            latest_evidence_seq: 3,
        }
    }

    #[tokio::test]
    async fn confirmed_nonempty_snapshot_is_some() {
        let folders = vec![folder(true), folder(false)];
        let result = respond_with(Some(response(folders.clone(), true))).await;
        let snapshot = result.expect("a confirmed snapshot");
        assert_eq!(snapshot.folders, folders);
        // The removal intents ride along: they are the only authority to remove a domain.
        assert_eq!(
            snapshot.removals,
            [ProviderRemovalInfo { root_id: "cd".repeat(16), display_name: "Gone".to_string() }]
        );
    }

    /// `registration_ready` crosses the JSON contract as-is: false must reach the host so
    /// it neither registers nor deletes the domain.
    #[test]
    fn the_json_contract_carries_root_id_and_registration_ready() {
        let json = serde_json::to_value(folder(false)).unwrap();
        assert_eq!(json["root_id"], "ab".repeat(16));
        assert_eq!(json["registration_ready"], false);
        assert_eq!(json["latest_evidence_seq"], 3);
        assert!(json.get("local_path").is_none());
    }

    #[tokio::test]
    async fn confirmed_empty_snapshot_is_some_empty() {
        let result = respond_with(Some(response(vec![], true))).await;
        assert_eq!(result.map(|s| s.folders), Some(vec![]));
    }

    /// The exact daemon-side bug this whole change closes: a response
    /// whose `snapshot_available` is `false` (the daemon could not
    /// confirm the desired state, e.g. a DB read error) must be treated
    /// identically to a transport failure, never as "confirmed empty."
    #[tokio::test]
    async fn unconfirmed_snapshot_with_folders_flag_false_is_none() {
        let result = respond_with(Some(response(vec![], false))).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn connection_closed_without_a_response_is_none() {
        let result = respond_with(None).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn wrong_payload_type_is_none() {
        let wrong = ShellIpcMessage {
            payload: Some(Payload::HydrateResponse(
                yadorilink_ipc_proto::shellipc::HydrateResponse { ok: false, error: String::new() },
            )),
        };
        let result = respond_with(Some(wrong)).await;
        assert_eq!(result, None);
    }
}
