//! The exported `ClientCore`: one forwarding method per facade method, each
//! run on the client runtime through [`crate::bridge`]. Errors and docs are
//! those of `yadorilink_client_core::ClientCore`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_client_core as core;
use yadorilink_client_core::dto::*;
use yadorilink_client_core::DesktopError;

use crate::{bridge, guarded, runtime, LoginSession, StatusWatch};

/// The client facade. Every async method runs on the client runtime.
#[derive(uniffi::Object)]
pub struct ClientCore {
    inner: Arc<core::ClientCore>,
}

#[uniffi::export]
impl ClientCore {
    /// Performs no I/O.
    #[uniffi::constructor]
    pub fn new(config: CoreConfig) -> Arc<Self> {
        Arc::new(ClientCore { inner: core::ClientCore::new(config) })
    }

    /// Sign-in, registration and linked-folder state; never fails. Should
    /// the call itself fail unexpectedly, it reads as signed out with the
    /// daemon's answer unknown.
    pub async fn account_status(&self) -> AccountStatus {
        let core = self.inner.clone();
        bridge(async move { Ok(core.account_status().await) }).await.unwrap_or_else(|_| {
            AccountStatus {
                sign_in: SignInState::SignedOut,
                client_id: None,
                this_device_id: None,
                device_registered: false,
                default_device_name: String::new(),
                has_linked_folders: None,
            }
        })
    }

    /// A sign-in that has not started yet.
    pub fn new_login_session(&self, options: LoginOptions) -> Arc<LoginSession> {
        LoginSession::wrap(self.inner.new_login_session(options))
    }

    /// Starts the status poll loop on the client runtime. If the runtime
    /// cannot start, the watch ends at once.
    pub fn watch_status(&self, interval: Duration) -> Arc<StatusWatch> {
        let core = self.inner.clone();
        let start = move || match runtime() {
            Ok(runtime) => {
                let _entered = runtime.enter();
                core.watch_status(interval)
            }
            Err(_) => core.watch_status(interval),
        };
        let inner = guarded(
            || {
                Arc::new(core::session::StatusWatch::start(
                    Arc::new(|| Box::pin(async { unreachable_update() })),
                    interval,
                ))
            },
            start,
        );
        Arc::new(StatusWatch { inner })
    }

    // ---- session and identity ----
    /// Revokes this installation, then removes its credential.
    pub async fn sign_out(&self) -> Result<SignOutOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.sign_out().await }).await
    }
    pub async fn register_device(&self, name: String) -> Result<DeviceRegistration, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.register_device(name).await }).await
    }

    // ---- status ----
    pub async fn status_snapshot(&self) -> Result<StatusSnapshot, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.status_snapshot().await }).await
    }
    pub async fn folder_detail(&self, local_path: String) -> Result<FolderDetail, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.folder_detail(local_path).await }).await
    }
    /// Other devices with access to each linked folder's group, by group id.
    pub async fn folder_peer_counts(&self) -> Result<HashMap<String, u32>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.folder_peer_counts().await }).await
    }

    // ---- folder control ----
    pub async fn pause_folder(&self, local_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pause_folder(local_path).await }).await
    }
    pub async fn resume_folder(&self, local_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.resume_folder(local_path).await }).await
    }
    pub async fn pause_all(&self) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pause_all().await }).await
    }
    pub async fn resume_all(&self) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.resume_all().await }).await
    }
    pub async fn unlink_folder(
        &self,
        local_path: String,
        force: bool,
    ) -> Result<UnlinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.unlink_folder(local_path, force).await }).await
    }
    pub async fn set_storage_mode(
        &self,
        group_id: String,
        mode: FolderMode,
    ) -> Result<StorageModeOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_storage_mode(group_id, mode).await }).await
    }

    // ---- files ----
    pub async fn list_conflicts(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<ConflictSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_conflicts(local_path).await }).await
    }
    pub async fn list_trash(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<TrashedFile>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_trash(local_path).await }).await
    }
    pub async fn restore_from_trash(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_from_trash(absolute_path).await }).await
    }
    pub async fn restore_trash_operation(
        &self,
        absolute_path: String,
    ) -> Result<FolderRestoreOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_trash_operation(absolute_path).await }).await
    }
    pub async fn list_versions(
        &self,
        absolute_path: String,
    ) -> Result<Vec<FileVersion>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_versions(absolute_path).await }).await
    }
    pub async fn restore_version(
        &self,
        absolute_path: String,
        version_seq: Option<i64>,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_version(absolute_path, version_seq).await }).await
    }
    pub async fn file_availability(
        &self,
        absolute_path: String,
    ) -> Result<FileAvailability, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.file_availability(absolute_path).await }).await
    }
    pub async fn pin_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pin_file(absolute_path).await }).await
    }
    pub async fn unpin_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.unpin_file(absolute_path).await }).await
    }
    pub async fn hydrate_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.hydrate_file(absolute_path).await }).await
    }
    pub async fn evict_file(&self, absolute_path: String) -> Result<EvictOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.evict_file(absolute_path).await }).await
    }

    // ---- devices ----
    pub async fn list_folder_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_folder_devices().await }).await
    }
    pub async fn list_account_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_account_devices().await }).await
    }
    pub async fn remove_device(
        &self,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.remove_device(device_id, force).await }).await
    }

    // ---- send and receive ----
    pub async fn send_to_device(
        &self,
        source_path: String,
        target_device_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.send_to_device(source_path, target_device_id).await }).await
    }
    pub async fn list_inbox(&self) -> Result<Vec<IncomingTransfer>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_inbox().await }).await
    }
    pub async fn receive_transfer(
        &self,
        transfer_id: String,
        destination_dir: Option<String>,
    ) -> Result<ReceivedTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.receive_transfer(transfer_id, destination_dir).await }).await
    }

    // ---- storage, settings and the daemon ----
    pub async fn run_gc(&self, dry_run: bool) -> Result<GcReport, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.run_gc(dry_run).await }).await
    }
    pub async fn bandwidth_limits(&self) -> Result<BandwidthLimits, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.bandwidth_limits().await }).await
    }
    pub async fn set_bandwidth_limits(
        &self,
        limits: BandwidthLimits,
    ) -> Result<BandwidthLimits, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_bandwidth_limits(limits).await }).await
    }
    pub async fn export_diagnostics(
        &self,
        destination_path: String,
    ) -> Result<DiagnosticsExport, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.export_diagnostics(destination_path).await }).await
    }
    pub async fn start_daemon(&self) -> Result<DaemonStartOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.start_daemon().await }).await
    }
    pub async fn stop_daemon(&self) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.stop_daemon().await }).await
    }

    // ---- updates ----
    pub async fn update_status(&self) -> Result<UpdateStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.update_status().await }).await
    }
    pub async fn check_for_updates(&self) -> Result<UpdateStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.check_for_updates().await }).await
    }
    pub async fn install_update(&self) -> Result<UpdateInstallOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.install_update().await }).await
    }
    pub async fn set_update_config(
        &self,
        automatic_checks: Option<bool>,
        install_mode: Option<UpdateInstallMode>,
    ) -> Result<UpdateConfig, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_update_config(automatic_checks, install_mode).await }).await
    }

    // ---- account ----
    pub async fn account_deletion_status(&self) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.account_deletion_status().await }).await
    }
    pub async fn request_account_deletion(&self) -> Result<AccountDeletionRequest, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.request_account_deletion().await }).await
    }
    pub async fn confirm_account_deletion(
        &self,
        confirmation_token: String,
    ) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.confirm_account_deletion(confirmation_token).await }).await
    }
    pub async fn cancel_account_deletion(&self) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.cancel_account_deletion().await }).await
    }
    pub async fn export_account_data(&self) -> Result<String, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.export_account_data().await }).await
    }

    // ---- shares ----
    pub async fn list_owned_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_owned_groups().await }).await
    }
    pub async fn list_joinable_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_joinable_groups().await }).await
    }
    pub async fn list_members(&self, group_id: String) -> Result<Vec<MemberSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_members(group_id).await }).await
    }
    pub async fn change_member_role(
        &self,
        group_id: String,
        device_id: String,
        role: AssignableRole,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.change_member_role(group_id, device_id, role).await }).await
    }
    pub async fn revoke_member(
        &self,
        group_id: String,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.revoke_member(group_id, device_id, force).await }).await
    }
    pub async fn deny_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.deny_request(group_id, device_id).await }).await
    }
    pub async fn approve_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<ApproveOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.approve_request(group_id, device_id).await }).await
    }
    pub async fn list_pending_approvals(
        &self,
    ) -> Result<Vec<PendingApprovalSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_pending_approvals().await }).await
    }
    pub async fn list_shares(&self) -> Result<Vec<ShareSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_shares().await }).await
    }
    pub async fn revoke_share_edge(
        &self,
        edge_id: String,
        force: bool,
    ) -> Result<RevokeEdgeOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.revoke_share_edge(edge_id, force).await }).await
    }
    pub async fn mint_invite(
        &self,
        group_id: String,
        role: Option<AssignableRole>,
        ttl: Option<Duration>,
        require_approval: bool,
    ) -> Result<InviteSummary, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.mint_invite(group_id, role, ttl, require_approval).await }).await
    }
    pub async fn list_invites(&self) -> Result<Vec<PendingInviteSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_invites().await }).await
    }
    pub async fn cancel_invite(&self, invite_id: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.cancel_invite(invite_id).await }).await
    }
    pub async fn accept_invite(
        &self,
        code_or_url: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<AcceptInviteOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.accept_invite(code_or_url, local_path, mode, acknowledge_risks).await }).await
    }

    // ---- linking ----
    pub async fn run_preflight(&self, local_path: String) -> Result<PreflightResult, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.run_preflight(local_path).await }).await
    }
    pub async fn create_group_and_link(
        &self,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.create_group_and_link(group_name, local_path, mode, acknowledge_risks).await
        })
        .await
    }
    pub async fn join_group_and_link(
        &self,
        group_id: String,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.join_group_and_link(group_id, group_name, local_path, mode, acknowledge_risks)
                .await
        })
        .await
    }
    pub async fn link_folder(
        &self,
        local_path: String,
        group_id: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.link_folder(local_path, group_id, mode, acknowledge_risks).await })
            .await
    }
}

/// Never polled: a watch that could not start has no runtime to poll on.
fn unreachable_update() -> StatusUpdate {
    StatusUpdate::Unavailable {
        error: DesktopError::Internal {
            message: "the status watch could not start".into(),
            category: "runtime_unavailable".into(),
        },
    }
}
