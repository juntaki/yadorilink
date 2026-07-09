//! `versions`/`restore`/`trash list`/`trash restore`/`link retention` —
//! the CLI surface for `yadorilink-daemon/src/control_socket.rs`'s
//! `ListVersions`/`RestoreVersion`/`ListTrash`/`RestoreTrash`/
//! `SetRetentionPolicy` handlers. Mirrors `commands/materialization.rs`'s
//! by-absolute-path resolution pattern (pin/unpin/evict), since these
//! commands resolve the same way over the same control socket.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    FileVersionInfo, ListTrashRequest, ListVersionsRequest, RestoreTrashRequest,
    RestoreVersionRequest, SetRetentionPolicyRequest, TrashedFileInfo,
};

use crate::control_client;
use crate::error::CliError;

/// Same "best-effort canonicalize, fall back to the given string"
/// resolution `materialization.rs`'s own `absolute_path` helper uses — a
/// trashed file's path doesn't exist on disk to canonicalize, so the
/// fallback is load-bearing here, not just cosmetic.
fn absolute_path(local_path: &str) -> Result<String, CliError> {
    std::fs::canonicalize(local_path)
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|_| Ok(local_path.to_string()))
}

/// `yadorilink versions <path>` — every retained version,
/// newest first, including the current one (spec "List versions of a
/// file").
pub async fn versions(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let resp =
        control_client::send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path }))
            .await?;
    let Some(RespPayload::ListVersions(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.versions.is_empty() {
        println!("No retained versions for {local_path}.");
        return Ok(());
    }
    for version in &list.versions {
        println!("{}", version_line(version));
    }
    Ok(())
}

fn version_line(v: &FileVersionInfo) -> String {
    format!(
        "v{}  {}  size={}  origin={}  state={}",
        v.version_seq,
        v.mtime_unix_nanos,
        v.size,
        if v.origin_device_id.is_empty() { "unknown" } else { &v.origin_device_id },
        v.state,
    )
}

/// `yadorilink restore <path> [--version <id>]` — an omitted
/// `--version` resolves daemon-side to the most recent superseded version
/// (spec "Restore without a version defaults to the most recent superseded
/// version"). A missing-blocks failure (`SyncError::VersionContentUnavailable`)
/// arrives here as an ordinary `CliError::Other` (`control_client::send`
/// maps every `RespPayload::Error` the same way) carrying that error's own
/// specific message text — already distinguishable from a generic failure
/// (see `error.rs`'s `VersionContentUnavailable` doc comment), so no
/// special-casing is needed here: the message is printed as-is by
/// `main.rs`'s existing `error: {e}` handler, and the non-zero exit code
/// comes from `CliError::Other`'s existing `exit_code()` mapping, the same
/// path every other daemon-reported failure already takes.
pub async fn restore(local_path: String, version: Option<i64>) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    control_client::send(ReqPayload::RestoreVersion(RestoreVersionRequest {
        absolute_path,
        version_seq: version,
    }))
    .await?;
    println!(
        "Restored {local_path}{}",
        version.map(|v| format!(" to version {v}")).unwrap_or_default()
    );
    Ok(())
}

/// `yadorilink trash list` — every deleted file still within its
/// link's retention window.
pub async fn trash_list() -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ListTrash(ListTrashRequest {})).await?;
    let Some(RespPayload::ListTrash(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.files.is_empty() {
        println!("Trash is empty.");
        return Ok(());
    }
    for file in &list.files {
        println!("{}", trashed_file_line(file));
    }
    Ok(())
}

fn trashed_file_line(f: &TrashedFileInfo) -> String {
    format!(
        "{}/{}  deleted_at={}  last_known_size={}  origin={}",
        f.local_path,
        f.path,
        f.deleted_at_unix_nanos,
        f.last_known_size,
        if f.origin_device_id.is_empty() { "unknown" } else { &f.origin_device_id },
    )
}

/// `yadorilink trash restore <path>` — recovers a deleted file's
/// last version before deletion as a new current version; the file becomes
/// live again.
pub async fn trash_restore(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    control_client::send(ReqPayload::RestoreTrash(RestoreTrashRequest { absolute_path })).await?;
    println!("Restored {local_path} from trash");
    Ok(())
}

/// `yadorilink link retention <path> --keep-versions <n>
/// --keep-days <t>` — adjusts an already-linked folder's retention policy
/// in place, effective on the next retention-expiry sweep without
/// unlinking (spec "Adjust retention policy on an existing link"). See
/// `main.rs`'s `Command::LinkRetention` doc comment for why this is a flat
/// top-level command (`link-retention`) rather than truly nested under
/// `link`.
pub async fn link_retention(
    local_path: String,
    keep_versions: i64,
    keep_days: i64,
) -> Result<(), CliError> {
    control_client::send(ReqPayload::SetRetentionPolicy(SetRetentionPolicyRequest {
        local_path: local_path.clone(),
        keep_versions,
        keep_days,
    }))
    .await?;
    println!(
        "Set retention policy for {local_path}: keep_versions={keep_versions} keep_days={keep_days}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `versions` output shape — one line per version, newest
    /// first is the daemon's own ordering contract (`SyncState::list_versions`'s
    /// doc comment), this just checks the per-line rendering.
    #[test]
    fn version_line_renders_every_field() {
        let v = FileVersionInfo {
            version_seq: 3,
            size: 42,
            mtime_unix_nanos: 12345,
            state: "superseded".into(),
            origin_device_id: "device-a".into(),
        };
        assert_eq!(version_line(&v), "v3  12345  size=42  origin=device-a  state=superseded");
    }

    /// An unknown origin (empty string, see `FileVersionInfo.origin_device_id`'s
    /// own doc comment) renders as `unknown`, not a blank field a user
    /// could mistake for a rendering bug.
    #[test]
    fn version_line_renders_unknown_origin() {
        let v = FileVersionInfo {
            version_seq: 1,
            size: 0,
            mtime_unix_nanos: 0,
            state: "current".into(),
            origin_device_id: String::new(),
        };
        assert!(version_line(&v).contains("origin=unknown"));
    }

    #[test]
    fn trashed_file_line_renders_every_field() {
        let f = TrashedFileInfo {
            local_path: "/tmp/photos".into(),
            path: "vacation.jpg".into(),
            version_seq: 2,
            last_known_size: 1000,
            origin_device_id: "device-b".into(),
            deleted_at_unix_nanos: 999,
        };
        assert_eq!(
            trashed_file_line(&f),
            "/tmp/photos/vacation.jpg  deleted_at=999  last_known_size=1000  origin=device-b"
        );
    }
}
