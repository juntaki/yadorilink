//! The provider roots' lines of `status`: why a root is not ready, its Eager progress, the files
//! that keep failing and the edits kept beside a file. Computed on demand from the daemon's own
//! state; the control socket reads it through a [`ProviderStatusSource`] that the shell side fills
//! in (the control context deliberately holds no daemon state).

use std::sync::{Arc, RwLock};

use yadorilink_ipc_proto::daemonctl::{
    PendingPublication, ProviderRemovalStatus, ProviderRootStatus, StuckFile,
};
use yadorilink_ipc_proto::shellipc::DriverState;
use yadorilink_replica_domain::session_state::{NotReady, Readiness};
use yadorilink_sync_sqlite::provider::ProviderRoot;

use crate::provider_eager::{EagerDriver, EagerInputs, EagerStatus};
use crate::replica_coordinator::ReplicaCoordinator;

type Builder = Arc<dyn Fn() -> Vec<ProviderRootStatus> + Send + Sync>;
type ExtrasBuilder = Arc<dyn Fn() -> (Vec<ProviderRemovalStatus>, Vec<String>) + Send + Sync>;
type PendingBuilder = Arc<dyn Fn(u32) -> Vec<PendingPublication> + Send + Sync>;

/// Where the control socket gets the provider lines; empty until the shell side installs a builder.
#[derive(Default)]
pub struct ProviderStatusSource {
    builder: RwLock<Option<Builder>>,
    pending: RwLock<Option<PendingBuilder>>,
    extras: RwLock<Option<ExtrasBuilder>>,
}

impl ProviderStatusSource {
    pub(crate) fn install(&self, builder: Builder) {
        *self.builder.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    pub(crate) fn install_extras(&self, builder: ExtrasBuilder) {
        *self.extras.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    /// The removals in progress or done, and the orphan domains the host reported.
    pub(crate) fn extras(&self) -> (Vec<ProviderRemovalStatus>, Vec<String>) {
        let builder = self.extras.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(Default::default, |build| build())
    }

    pub(crate) fn install_pending(&self, builder: PendingBuilder) {
        *self.pending.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    /// Up to `limit` waiting publications per root, oldest first.
    pub(crate) fn pending_items(&self, limit: u32) -> Vec<PendingPublication> {
        let builder = self.pending.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(Vec::new, |build| build(limit))
    }

    pub(crate) fn snapshot(&self) -> Vec<ProviderRootStatus> {
        let builder = self.builder.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(Vec::new, |build| build())
    }
}

/// Why the root is not ready, in words the user can act on.
pub(crate) fn readiness_text(root: &ProviderRoot) -> String {
    match root.readiness() {
        Readiness::Ready if root.namespace_ready => "ready".into(),
        Readiness::Ready => "preparing the folder".into(),
        Readiness::NotReady(NotReady::DomainNotRegistered) => {
            "waiting for the app to register the folder".into()
        }
        Readiness::NotReady(NotReady::ExtensionNotEnabled) => "enable File Provider".into(),
        Readiness::NotReady(NotReady::ProviderError(error)) => {
            format!("File Provider error: {error}")
        }
    }
}

fn eager_state_text(state: DriverState) -> &'static str {
    match state {
        DriverState::Running | DriverState::Unspecified => "running",
        DriverState::PausedLowDisk => "paused (low disk)",
        DriverState::WaitingPeers => "waiting for peers",
        DriverState::WaitingProvider => "waiting for File Provider",
        DriverState::Done => "done",
    }
}

fn encode_eager(status: &EagerStatus, line: &mut ProviderRootStatus) {
    line.eager = true;
    line.eager_state = eager_state_text(status.state).to_owned();
    line.eager_remote = status.remote;
    line.eager_hydrating = status.hydrating;
    line.eager_current = status.current;
    line.stuck = status
        .stuck
        .iter()
        .map(|(path, failures)| StuckFile { path: path.clone(), failures: *failures })
        .collect();
}

/// One line per declared provider root.
pub(crate) fn provider_root_lines(
    coordinator: &ReplicaCoordinator,
    eager: &EagerDriver,
    inputs: &EagerInputs<'_>,
    now_ms: i64,
) -> Vec<ProviderRootStatus> {
    let repo = coordinator.provider_repository();
    let Ok(roots) = repo.list_declared_roots() else { return Vec::new() };
    roots
        .iter()
        .map(|root| {
            let (kept, first) = repo.kept_edits(&root.root_id).unwrap_or((0, None));
            let (pending, _) =
                repo.pending_publications(&root.root_id, now_ms, 0).unwrap_or_default();
            let unconfirmed =
                repo.unresolved_publications(&root.root_id, now_ms).unwrap_or_default();
            let mut line = ProviderRootStatus {
                pending_publications: pending.count,
                pending_oldest_ms: pending.oldest_age_ms,
                unconfirmed_publications: unconfirmed.count,
                unconfirmed_oldest_ms: unconfirmed.oldest_age_ms,
                root_id: root.root_id.chars().take(8).collect(),
                display_name: root.display_name.clone(),
                readiness: readiness_text(root),
                kept_edits: kept,
                kept_edits_oldest_ms: first.map_or(0, |at| (now_ms - at).max(0) as u64),
                ..Default::default()
            };
            if let Some(status) = eager.status(inputs, &root.root_id) {
                encode_eager(&status, &mut line);
            }
            line
        })
        .collect()
}

/// Up to `limit` publications waiting on the OS per declared root, oldest first.
pub(crate) fn pending_items(
    coordinator: &ReplicaCoordinator,
    limit: u32,
    now_ms: i64,
) -> Vec<PendingPublication> {
    let repo = coordinator.provider_repository();
    let Ok(roots) = repo.list_declared_roots() else { return Vec::new() };
    roots
        .iter()
        .flat_map(|root| {
            let items = repo
                .pending_publications(&root.root_id, now_ms, limit)
                .map(|(_, items)| items)
                .unwrap_or_default();
            let id: String = root.root_id.chars().take(8).collect();
            items.into_iter().map(move |(path, age_ms)| PendingPublication {
                root_id: id.clone(),
                path,
                age_ms,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
