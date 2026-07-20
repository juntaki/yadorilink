//! Self-service account management.
//!
//! The self-service account-deletion lifecycle and data export talk to the
//! coordination plane's `/account/*` routes. Both operate only on
//! server-side coordination records; neither ever touches the folders synced
//! on the user's machines. A lost or replaced device re-establishes its
//! identity by signing in with Google and registering as a new device --
//! there is no exported identity artifact to import.

// The self-service
// account-deletion lifecycle (request/confirm/cancel/status) and data
// export, talking to coordination-worker's /account/* routes. Typed
// library fns (the desktop app drives the same ones -- see
// crates/yadorilink-desktop-app/src/account.rs) with thin printing
// wrappers, mirroring commands/device.rs's split.
mod deletion_http {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    use crate::error::CliError;
    use crate::http_client::{get_json, post_json, require_access_token};

    /// The local-first boundary every deletion surface must state (
    /// / account-lifecycle "Local-first semantics are communicated to the
    /// user"): deletion removes server-side records and access; local
    /// folders remain the user's own data on their machines. Exposed so the
    /// desktop app renders the identical text.
    pub const LOCAL_FIRST_NOTICE: &str = "Account deletion removes your server-side coordination records \
(account, devices, folder groups, shares) and revokes every device's coordination access. \
It does NOT delete the folders synced on your machines -- those remain your own local data on your own \
devices. Removing them, if you ever want to, is a separate manual step.";

    #[derive(Debug, Clone, Deserialize)]
    pub struct DeletionRequested {
        #[serde(rename = "confirmationToken")]
        pub confirmation_token: String,
    }

    /// Mirrors coordination-worker's `DeletionStatus` JSON. `state` is one of
    /// `active` | `requested` | `grace`; the grace fields are present only in
    /// the `grace` state.
    #[derive(Debug, Clone, Deserialize)]
    pub struct DeletionStatus {
        pub state: String,
        #[serde(rename = "graceExpiresAtUnix")]
        pub grace_expires_at_unix: Option<i64>,
        #[serde(rename = "remainingSecs")]
        pub remaining_secs: Option<i64>,
    }

    #[derive(Serialize)]
    struct ConfirmRequest<'a> {
        #[serde(rename = "confirmationToken")]
        confirmation_token: &'a str,
    }

    // ---- typed library fns (also called by the desktop app) --------------

    // Deliberately no durability handoff gate here, unlike `device remove`
    // (see `commands::durability_force`): account deletion destroys every
    // folder group this account owns, not just one device's role in a group
    // some other device keeps, so there is no other replica to hand off to
    // -- and it already goes through its own grace period plus an explicit
    // confirmation token before anything is destroyed.
    pub async fn request_deletion() -> Result<DeletionRequested, CliError> {
        let access_token = require_access_token()?;
        post_json("/account/deletion/request", &(), Some(&access_token)).await
    }

    pub async fn confirm_deletion(confirmation_token: String) -> Result<DeletionStatus, CliError> {
        let access_token = require_access_token()?;
        post_json(
            "/account/deletion/confirm",
            &ConfirmRequest { confirmation_token: &confirmation_token },
            Some(&access_token),
        )
        .await
    }

    pub async fn cancel_deletion() -> Result<DeletionStatus, CliError> {
        let access_token = require_access_token()?;
        post_json("/account/deletion/cancel", &(), Some(&access_token)).await
    }

    pub async fn deletion_status() -> Result<DeletionStatus, CliError> {
        let access_token = require_access_token()?;
        get_json("/account/deletion/status", Some(&access_token)).await
    }

    /// Returns the raw versioned export document. The server built it from an
    /// allowlist and it is content-blind by construction; the CLI/desktop
    /// only ever presents or saves it, never parses file data out of it
    /// (there is none).
    pub async fn export_account() -> Result<serde_json::Value, CliError> {
        let access_token = require_access_token()?;
        get_json("/account/export", Some(&access_token)).await
    }

    /// The export document pretty-printed as JSON. The desktop app writes this
    /// directly, so it needs no JSON dependency of its own.
    pub async fn export_account_json() -> Result<String, CliError> {
        let document = export_account().await?;
        serde_json::to_string_pretty(&document).map_err(CliError::from)
    }

    // ---- thin printing wrappers (the CLI subcommands) --------------------

    pub async fn delete_request() -> Result<(), CliError> {
        let requested = request_deletion().await?;
        println!("{LOCAL_FIRST_NOTICE}\n");
        println!("Account deletion requested. Nothing is deleted yet. To confirm, run:\n");
        println!("    yadorilink account delete confirm {}\n", requested.confirmation_token);
        println!(
            "This confirmation token is shown only once. After you confirm, a grace period \
starts during which you can still cancel with `yadorilink account delete cancel`."
        );
        Ok(())
    }

    pub async fn delete_confirm(confirmation_token: String) -> Result<(), CliError> {
        let status = confirm_deletion(confirmation_token).await?;
        println!("{LOCAL_FIRST_NOTICE}\n");
        print_status(&status);
        println!(
            "You can still cancel with `yadorilink account delete cancel` until the grace period ends; \
only finalization is irreversible."
        );
        Ok(())
    }

    pub async fn delete_cancel() -> Result<(), CliError> {
        let status = cancel_deletion().await?;
        println!("Account deletion cancelled. Your account is {}.", status.state);
        Ok(())
    }

    pub async fn delete_status() -> Result<(), CliError> {
        print_status(&deletion_status().await?);
        Ok(())
    }

    /// Generates the export and either writes it to `output_path` or prints
    /// it. Writing the export is a create/write of the user's own data --
    /// there is no deletion of any local folder anywhere in this path
    /// .
    pub async fn export(output_path: Option<PathBuf>) -> Result<(), CliError> {
        let pretty = export_account_json().await?;
        match output_path {
            Some(path) => {
                std::fs::write(&path, pretty)?;
                println!("Wrote your account data export to {}.", path.display());
            }
            None => println!("{pretty}"),
        }
        println!(
            "\nThis export contains only your coordination-plane records -- never your file \
contents, file or folder names, or paths, which the server never holds."
        );
        Ok(())
    }

    fn print_status(status: &DeletionStatus) {
        match status.state.as_str() {
            "grace" => println!(
                "Account deletion is scheduled: the grace period ends in about {} (unix time {}). \
Finalization is irreversible.",
                format_remaining(status.remaining_secs.unwrap_or(0)),
                status.grace_expires_at_unix.unwrap_or(0),
            ),
            "requested" => {
                println!("Account deletion has been requested but not yet confirmed.")
            }
            "active" => println!("Your account is active. No deletion is in progress."),
            other => println!("Account deletion state: {other}."),
        }
    }

    /// Coarse, human-readable rendering of a remaining-grace duration.
    fn format_remaining(secs: i64) -> String {
        let secs = secs.max(0);
        let days = secs / 86_400;
        let hours = (secs % 86_400) / 3_600;
        let mins = (secs % 3_600) / 60;
        if days > 0 {
            format!("{days}d {hours}h")
        } else if hours > 0 {
            format!("{hours}h {mins}m")
        } else {
            format!("{mins}m")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn local_first_notice_states_local_folders_are_not_deleted() {
            assert!(LOCAL_FIRST_NOTICE.contains("does NOT delete"));
            assert!(LOCAL_FIRST_NOTICE.to_lowercase().contains("local data"));
        }

        #[test]
        fn format_remaining_renders_coarse_buckets() {
            assert_eq!(format_remaining(-5), "0m");
            assert_eq!(format_remaining(90), "1m");
            assert_eq!(format_remaining(3 * 3600 + 600), "3h 10m");
            assert_eq!(format_remaining(2 * 86_400 + 5 * 3600), "2d 5h");
        }
    }
}

pub use deletion_http::{
    cancel_deletion, confirm_deletion, delete_cancel, delete_confirm, delete_request,
    delete_status, deletion_status, export, export_account, export_account_json, request_deletion,
    DeletionRequested, DeletionStatus, LOCAL_FIRST_NOTICE,
};
