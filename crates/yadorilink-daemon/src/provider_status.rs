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
use yadorilink_sync_sqlite::provider::{ProviderRepository, ProviderRoot};

use crate::provider_eager::{EagerDriver, EagerInputs, EagerStatus};
use crate::replica_coordinator::ReplicaCoordinator;

type Builder = Arc<dyn Fn() -> Vec<ProviderRootStatus> + Send + Sync>;
type ExtrasBuilder = Arc<dyn Fn() -> (Vec<ProviderRemovalStatus>, Vec<String>) + Send + Sync>;
type PendingBuilder = Arc<dyn Fn(u32) -> Result<Vec<PendingPublication>, String> + Send + Sync>;

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
    pub(crate) fn pending_items(&self, limit: u32) -> Result<Vec<PendingPublication>, String> {
        let builder = self.pending.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(|| Ok(Vec::new()), |build| build(limit))
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

/// The line for a read that failed. The status must not look emptier or healthier precisely when
/// the provider state cannot be read, so it is never a zero line: the readiness is not "ready",
/// which also makes the rollup ask for attention.
fn unreadable_line(
    root_id: &str,
    display_name: &str,
    what: &str,
    error: &dyn std::fmt::Display,
) -> ProviderRootStatus {
    ProviderRootStatus {
        root_id: root_id.chars().take(8).collect(),
        display_name: display_name.to_owned(),
        readiness: format!("{what} unreadable: {error}"),
        ..Default::default()
    }
}

/// One line per declared provider root, with the root's full id (the line carries only a prefix).
/// Only the repository half of the line; the Eager progress is added by the caller.
fn repository_lines(repo: &ProviderRepository, now_ms: i64) -> Vec<(String, ProviderRootStatus)> {
    let roots = match repo.list_declared_roots() {
        Ok(roots) => roots,
        Err(error) => {
            return vec![(
                String::new(),
                unreadable_line("", "provider roots", "the provider roots", &error),
            )];
        }
    };
    roots
        .iter()
        .map(|root| {
            let counters = repo.kept_edits(&root.root_id).map_err(|e| format!("{e:?}")).and_then(
                |kept| {
                    let (pending, _) = repo
                        .pending_publications(&root.root_id, now_ms, 0)
                        .map_err(|e| e.to_string())?;
                    let unconfirmed = repo
                        .unresolved_publications(&root.root_id, now_ms)
                        .map_err(|e| e.to_string())?;
                    Ok((kept, pending, unconfirmed))
                },
            );
            let line = match counters {
                Ok(((kept, first), pending, unconfirmed)) => ProviderRootStatus {
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
                },
                Err(error) => {
                    tracing::warn!(root = %root.root_id, %error, "could not read the provider root's state for status");
                    unreadable_line(&root.root_id, &root.display_name, "the provider state", &error)
                }
            };
            (root.root_id.clone(), line)
        })
        .collect()
}

/// One line per declared provider root.
pub(crate) fn provider_root_lines(
    coordinator: &ReplicaCoordinator,
    eager: &EagerDriver,
    inputs: &EagerInputs<'_>,
    now_ms: i64,
) -> Vec<ProviderRootStatus> {
    repository_lines(coordinator.provider_repository(), now_ms)
        .into_iter()
        .map(|(root_id, mut line)| {
            if let Some(status) = eager.status(inputs, &root_id) {
                encode_eager(&status, &mut line);
                if status.unreadable {
                    // Partial counters are not progress: the line is not "ready".
                    line.readiness = "the Eager progress unreadable: see the daemon log".into();
                }
            }
            line
        })
        .collect()
}

/// Up to `limit` publications waiting on the OS per declared root, oldest first. A read that fails
/// is an error, never an empty list: an empty list says nothing is waiting.
pub(crate) fn pending_items(
    coordinator: &ReplicaCoordinator,
    limit: u32,
    now_ms: i64,
) -> Result<Vec<PendingPublication>, String> {
    let repo = coordinator.provider_repository();
    let mut all = Vec::new();
    for root in repo.list_declared_roots().map_err(|e| e.to_string())? {
        let (_, items) = repo
            .pending_publications(&root.root_id, now_ms, limit)
            .map_err(|e| format!("the pending publications of {}: {e}", root.root_id))?;
        let id: String = root.root_id.chars().take(8).collect();
        all.extend(items.into_iter().map(|(path, age_ms)| PendingPublication {
            root_id: id.clone(),
            path,
            age_ms,
        }));
    }
    Ok(all)
}

#[cfg(test)]
mod tests;
