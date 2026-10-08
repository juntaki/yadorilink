//! The Eager driver, daemon side (design section 4): which items of an Eager provider root the
//! host app should ask the OS to download next.
//!
//! It is a QUERY, not a cursor and not a stored queue. The app keeps at most two downloads
//! outstanding and sends their item ids as exclusions; every call recomputes the best candidates
//! from the durable rows and the host's membership report:
//!
//! * wanted = a live regular file (a real current row) that is not held, not paused, and whose
//!   current content is not present on the OS (`provider_local_presence`), ordered by size and
//!   then path;
//! * an item is not offered while its failure backoff runs; a failure belongs to ONE version, so
//!   a newer version is offered at once; the failure counters are the only persistent driver
//!   state, and everything else is rebuilt from the rows after a restart;
//! * an exclusion is answered as SETTLED when its item is gone, no longer a file, present, or in
//!   backoff, so the app stops counting it as outstanding.
//!
//! A user's own fetch (an "Open") is never starved by Eager work: at most `EAGER_ASSEMBLIES` of
//! the daemon-wide `ASSEMBLIES` MaterializeToTemp assemblies may be Eager ones, and an assembly
//! counts as Eager when its item was handed out by this driver recently.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use yadorilink_ipc_proto::shellipc::{
    DriverState, NextProviderDownloadsRequest, NextProviderDownloadsResponse, ProviderDownload,
};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, Readiness};
use yadorilink_sync_sqlite::provider::{ItemId, ProviderRoot};

use crate::provider_evidence::{provider_local_presence, ProviderMembership};
use crate::replica_coordinator::ReplicaCoordinator;

/// Daemon-wide limit on concurrent MaterializeToTemp assemblies (the OS runs about six fetches).
pub(crate) const ASSEMBLIES: usize = 6;
/// How many of them Eager downloads may hold; the rest are for the user's own fetches.
pub(crate) const EAGER_ASSEMBLIES: usize = 4;

/// What the driver needs to know about the machine.
pub(crate) trait EagerEnvironment: Send + Sync {
    /// Whether writing `bytes` into the volume of `dir` would go below the disk headroom.
    fn low_disk(&self, dir: &Path, bytes: u64) -> bool;
    /// Whether any peer of the group is reachable now.
    fn peers_available(&self, group_id: &str) -> bool;
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EagerConfig {
    pub(crate) base_backoff_ms: i64,
    pub(crate) cap_backoff_ms: i64,
    /// Failures after which an item is reported stuck (still retried at the capped interval).
    pub(crate) stuck_after: u32,
    /// How old the host's membership snapshot may be for "done" and for offering downloads.
    pub(crate) snapshot_max_age: Duration,
    /// How long an item handed out stays "requested" (the Eager class of its assembly).
    pub(crate) request_ttl: Duration,
    pub(crate) page: usize,
    /// At most this many exclusions are looked at.
    pub(crate) max_exclusions: usize,
}

impl Default for EagerConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 30_000,
            cap_backoff_ms: 3_600_000,
            stuck_after: 8,
            snapshot_max_age: Duration::from_secs(60),
            request_ttl: Duration::from_secs(600),
            page: 256,
            max_exclusions: 8,
        }
    }
}

/// What a root's Eager download state is, for the status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EagerStatus {
    pub(crate) state: DriverState,
    /// Wanted files with no current content on the OS (stuck ones included).
    pub(crate) remote: u64,
    /// Items handed out and not yet settled.
    pub(crate) hydrating: u64,
    /// Files whose current content is on the OS.
    pub(crate) current: u64,
    /// Items past `stuck_after` failures: (path, failures).
    pub(crate) stuck: Vec<(String, u32)>,
}

/// The daemon-wide assembly limiter: `ASSEMBLIES` in all, `EAGER_ASSEMBLIES` for Eager.
pub(crate) struct AssemblyLimiter {
    total: Arc<Semaphore>,
    eager: Arc<Semaphore>,
}

/// Held while an assembly runs.
pub(crate) struct AssemblyPermits {
    _total: OwnedSemaphorePermit,
    _eager: Option<OwnedSemaphorePermit>,
}

impl AssemblyLimiter {
    pub(crate) fn new(total: usize, eager: usize) -> Self {
        Self { total: Arc::new(Semaphore::new(total)), eager: Arc::new(Semaphore::new(eager)) }
    }

    /// Waits for a slot. Eager takes its own class first and then a total slot (always in that
    /// order, so the two cannot deadlock); an Open takes only a total slot, and the Eager class
    /// being full never blocks it.
    pub(crate) async fn acquire(&self, eager: bool) -> AssemblyPermits {
        let class = if eager {
            Some(self.eager.clone().acquire_owned().await.expect("the limiter is never closed"))
        } else {
            None
        };
        let total = self.total.clone().acquire_owned().await.expect("the limiter is never closed");
        AssemblyPermits { _total: total, _eager: class }
    }
}

pub(crate) struct EagerDriver {
    config: EagerConfig,
    environment: Arc<dyn EagerEnvironment>,
    /// Items handed out by a query, with when: the Eager class of their assemblies, and the
    /// "hydrating" count. In memory only: after a restart the app asks again.
    requested: Mutex<HashMap<(String, ItemId), Instant>>,
    pub(crate) limiter: AssemblyLimiter,
}

/// Everything a query reads.
pub(crate) struct EagerInputs<'a> {
    pub(crate) coordinator: &'a ReplicaCoordinator,
    pub(crate) membership: &'a ProviderMembership,
    /// The fixed temp root's staging directory; `None` when none is configured.
    pub(crate) staging_dir: Option<&'a Path>,
    /// Whether the host app is attached.
    pub(crate) host_attached: bool,
}

impl EagerDriver {
    pub(crate) fn new(environment: Arc<dyn EagerEnvironment>, config: EagerConfig) -> Self {
        Self {
            config,
            environment,
            requested: Mutex::default(),
            limiter: AssemblyLimiter::new(ASSEMBLIES, EAGER_ASSEMBLIES),
        }
    }

    /// Whether `item` was handed out by this driver and not yet settled (its assembly is an
    /// Eager one). The classification does not expire by itself: a fetch the OS delays stays
    /// Eager for as long as the app still lists the item as outstanding.
    pub(crate) fn was_requested(&self, root_id: &str, item: &ItemId) -> bool {
        self.requested
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&(root_id.to_owned(), *item))
    }

    pub(crate) fn finished(&self, root_id: &str, item: &ItemId) {
        self.requested
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(root_id.to_owned(), *item));
    }

    fn backoff_ms(&self, failures: u32) -> i64 {
        let doublings = failures.saturating_sub(1).min(20);
        self.config
            .base_backoff_ms
            .saturating_mul(1i64 << doublings)
            .min(self.config.cap_backoff_ms)
    }

    /// An assembly of `version` of `item` failed for want of content: one more failure of THAT
    /// version, recorded only if it is still the current one (the check is transactional).
    pub(crate) fn record_failure(
        &self,
        coordinator: &ReplicaCoordinator,
        root_id: &str,
        item: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
    ) {
        let repo = coordinator.provider_repository();
        let now = self.environment.now_ms();
        if let Err(error) =
            repo.record_download_failure(root_id, item, version, now, |n| self.backoff_ms(n))
        {
            tracing::warn!(%error, "could not record a provider download failure");
        }
    }

    pub(crate) fn record_success(
        &self,
        coordinator: &ReplicaCoordinator,
        root_id: &str,
        item: &ItemId,
    ) {
        if let Err(error) = coordinator.provider_repository().clear_download_failure(root_id, item)
        {
            tracing::warn!(%error, "could not clear a provider download failure");
        }
    }

    /// The OS refused a download request before any fetch.
    pub(crate) fn record_rejection(
        &self,
        coordinator: &ReplicaCoordinator,
        root_id: &str,
        item: &ItemId,
    ) {
        let repo = coordinator.provider_repository();
        let Ok(Some(version)) = repo.current_version_hash(root_id, item) else { return };
        let next = self.environment.now_ms().saturating_add(self.config.base_backoff_ms);
        if let Err(error) = repo.record_download_rejection(root_id, item, version, next) {
            tracing::warn!(%error, "could not record a rejected provider download");
        }
        self.finished(root_id, item);
    }

    /// Whether the item's failure (of its CURRENT version) still holds it back, and whether it
    /// counts as stuck.
    fn failure_state(
        &self,
        coordinator: &ReplicaCoordinator,
        root_id: &str,
        item: &ItemId,
        now_ms: i64,
    ) -> (bool, bool) {
        let repo = coordinator.provider_repository();
        let Ok(Some(failure)) = repo.download_failure(root_id, item) else { return (false, false) };
        match repo.current_version_hash(root_id, item) {
            Ok(Some(current)) if current == failure.version_hash => {
                (failure.next_attempt_ms > now_ms, failure.failures >= self.config.stuck_after)
            }
            // A newer version, or the item is gone: the failure is about something else.
            _ => (false, false),
        }
    }

    fn declared_eager_root(
        &self,
        coordinator: &ReplicaCoordinator,
        root_id: &str,
    ) -> Option<ProviderRoot> {
        let root = coordinator
            .provider_repository()
            .list_declared_roots()
            .ok()?
            .into_iter()
            .find(|r| r.root_id == root_id)?;
        // The link's own policy: the coordinator's reader answers OnDemand for every provider
        // root, because no provider root ever writes eagerly to a directory.
        let eager = matches!(
            coordinator.link_repository().materialization_policy_for_group(&root.group_id),
            Ok(Some(MaterializationPolicy::Eager))
        );
        eager.then_some(root)
    }

    /// Answers one `NextProviderDownloads` query.
    pub(crate) fn next_downloads(
        &self,
        inputs: &EagerInputs<'_>,
        request: &NextProviderDownloadsRequest,
    ) -> NextProviderDownloadsResponse {
        let root_id = hex::encode(&request.root_id);
        let coordinator = inputs.coordinator;
        let mut response = NextProviderDownloadsResponse {
            downloads: Vec::new(),
            settled_item_ids: Vec::new(),
            state: DriverState::Unspecified as i32,
        };
        let Some(root) = self.declared_eager_root(coordinator, &root_id) else { return response };
        let now = self.environment.now_ms();
        let repo = coordinator.provider_repository();

        // Which exclusions no longer need a download.
        let exclusions: Vec<ItemId> = request
            .exclude_item_ids
            .iter()
            .take(self.config.max_exclusions)
            .filter_map(|bytes| ItemId::try_from(bytes.as_slice()).ok())
            .collect();
        for (item, raw) in exclusions.iter().zip(request.exclude_item_ids.iter()) {
            let live_file = matches!(repo.path_for_item(&root_id, item), Ok(Some((_, true))))
                && repo.current_version_hash(&root_id, item).ok().flatten().is_some();
            let present = live_file
                && provider_local_presence(coordinator, inputs.membership, &root_id, item)
                    .current_content_present;
            let (in_backoff, _) = self.failure_state(coordinator, &root_id, item, now);
            if !live_file || present || in_backoff {
                response.settled_item_ids.push(raw.clone());
                self.finished(&root_id, item);
            }
        }
        let outstanding: HashSet<ItemId> = exclusions
            .iter()
            .filter(|item| {
                !response.settled_item_ids.iter().any(|raw| raw.as_slice() == item.as_slice())
            })
            .copied()
            .collect();

        // What the app lists as outstanding stays Eager; what it no longer lists and was handed
        // out long ago is forgotten (the map stays bounded by what the app has in flight).
        {
            let ttl = self.config.request_ttl;
            let mut requested = self.requested.lock().unwrap_or_else(|p| p.into_inner());
            requested.retain(|(root, item), at| {
                *root != root_id || outstanding.contains(item) || at.elapsed() <= ttl
            });
        }
        let state = self.provider_state(&root, inputs);
        if state != DriverState::Running {
            response.state = state as i32;
            return response;
        }

        // The best candidates, smallest first, skipping what is outstanding or held back.
        let want = (request.max as usize).min(2);
        // A settlement-only query (no room): the settled ids above are the whole answer. It never
        // concludes "done", because nothing was looked for.
        if want == 0 {
            response.state = DriverState::Running as i32;
            return response;
        }
        let mut chosen: Vec<(String, u64, Option<ItemId>)> = Vec::new();
        let mut after: Option<(u64, String)> = None;
        'scan: while chosen.len() < want {
            let page = match repo.eager_page(
                &root_id,
                after.as_ref().map(|(size, path)| (*size, path.as_str())),
                self.config.page,
            ) {
                Ok(page) if !page.is_empty() => page,
                _ => break,
            };
            after = page.last().map(|c| (c.size, c.path.clone()));
            for candidate in page {
                if self.skipped(coordinator, inputs, &root, &candidate, &outstanding, now) {
                    continue;
                }
                chosen.push((candidate.path, candidate.size, candidate.item_id));
                if chosen.len() == want {
                    break 'scan;
                }
            }
        }
        if chosen.is_empty() {
            response.state = if outstanding.is_empty() {
                // Nothing wanted that is not held back: done, if the scan really found nothing
                // left that is merely waiting out a backoff.
                self.idle_state(coordinator, inputs, &root, now) as i32
            } else {
                DriverState::Running as i32
            };
            return response;
        }

        // Low disk: pause rather than hand out work the volume cannot take.
        if let Some(dir) = inputs.staging_dir {
            if self.environment.low_disk(dir, chosen[0].1) {
                response.state = DriverState::PausedLowDisk as i32;
                return response;
            }
        }
        if !self.environment.peers_available(&root.group_id) {
            response.state = DriverState::WaitingPeers as i32;
            return response;
        }
        for (path, _, item) in chosen {
            let item = match item {
                Some(item) => item,
                None => match repo.mint_item(&root_id, &path) {
                    Ok(item) => item,
                    Err(_) => continue,
                },
            };
            let Ok(Some(version)) = repo.current_version_hash(&root_id, &item) else { continue };
            self.requested
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((root_id.clone(), item), Instant::now());
            response.downloads.push(ProviderDownload {
                item_id: item.to_vec(),
                version_hash: version.0.to_vec(),
            });
        }
        response.state = DriverState::Running as i32;
        response
    }

    /// The reasons nothing can be offered at all, independent of what is wanted.
    fn provider_state(&self, root: &ProviderRoot, inputs: &EagerInputs<'_>) -> DriverState {
        if root.readiness() != Readiness::Ready
            || inputs.staging_dir.is_none()
            || !inputs.host_attached
            || !inputs.membership.snapshot_is_fresh(&root.root_id, self.config.snapshot_max_age)
        {
            return DriverState::WaitingProvider;
        }
        DriverState::Running
    }

    /// Whether the candidate is not to be offered now: held, paused, present, outstanding or in
    /// backoff.
    fn skipped(
        &self,
        coordinator: &ReplicaCoordinator,
        inputs: &EagerInputs<'_>,
        root: &ProviderRoot,
        candidate: &yadorilink_sync_sqlite::provider::FileCandidate,
        outstanding: &HashSet<ItemId>,
        now_ms: i64,
    ) -> bool {
        if let Some(item) = candidate.item_id {
            if outstanding.contains(&item) {
                return true;
            }
            // A newer version still being published refuses every fetch (the fence): offering
            // the item now would only fail; it is reconsidered once the publication completes.
            if !matches!(
                crate::provider_publication::fetch_gate(coordinator, &root.root_id, &item),
                Ok(crate::provider_publication::FetchGate::Allowed)
            ) {
                return true;
            }
            if provider_local_presence(coordinator, inputs.membership, &root.root_id, &item)
                .current_content_present
            {
                return true;
            }
            if self.failure_state(coordinator, &root.root_id, &item, now_ms).0 {
                return true;
            }
        }
        self.held_or_paused(coordinator, &root.group_id, &candidate.path)
    }

    fn held_or_paused(&self, coordinator: &ReplicaCoordinator, group_id: &str, path: &str) -> bool {
        if coordinator.held_path_repository().is_held(group_id, path).unwrap_or(true) {
            return true;
        }
        coordinator
            .paused_item_repository()
            .list(group_id)
            .map(|paused| yadorilink_sync_sqlite::paused_items::path_is_covered(&paused, path))
            .unwrap_or(true)
    }

    /// The state when nothing can be offered right now and nothing is outstanding: DONE when
    /// every wanted file is present or stuck; otherwise something is only waiting out a backoff
    /// (RUNNING) or no peer is reachable.
    fn idle_state(
        &self,
        coordinator: &ReplicaCoordinator,
        inputs: &EagerInputs<'_>,
        root: &ProviderRoot,
        now_ms: i64,
    ) -> DriverState {
        let status = self.scan(coordinator, inputs, root, now_ms);
        status.state
    }

    /// The root's full status: one pass over its files.
    pub(crate) fn status(&self, inputs: &EagerInputs<'_>, root_id: &str) -> Option<EagerStatus> {
        let root = self.declared_eager_root(inputs.coordinator, root_id)?;
        let now = self.environment.now_ms();
        let mut status = self.scan(inputs.coordinator, inputs, &root, now);
        let outstanding = self
            .requested
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .filter(|(root, _)| root == root_id)
            .count() as u64;
        status.hydrating = outstanding;
        if status.state == DriverState::Running {
            if let Some(dir) = inputs.staging_dir {
                if self.environment.low_disk(dir, 0) {
                    status.state = DriverState::PausedLowDisk;
                }
            }
        }
        Some(status)
    }

    fn scan(
        &self,
        coordinator: &ReplicaCoordinator,
        inputs: &EagerInputs<'_>,
        root: &ProviderRoot,
        now_ms: i64,
    ) -> EagerStatus {
        let repo = coordinator.provider_repository();
        let mut status = EagerStatus {
            state: DriverState::Done,
            remote: 0,
            hydrating: 0,
            current: 0,
            stuck: Vec::new(),
        };
        let provider_state = self.provider_state(root, inputs);
        let mut waiting_on_backoff = false;
        let mut open_work = false;
        let mut after: Option<(u64, String)> = None;
        loop {
            let page = match repo.eager_page(
                &root.root_id,
                after.as_ref().map(|(size, path)| (*size, path.as_str())),
                self.config.page,
            ) {
                Ok(page) if !page.is_empty() => page,
                _ => break,
            };
            after = page.last().map(|c| (c.size, c.path.clone()));
            for candidate in page {
                if self.held_or_paused(coordinator, &root.group_id, &candidate.path) {
                    continue;
                }
                let present = candidate.item_id.is_some_and(|item| {
                    provider_local_presence(coordinator, inputs.membership, &root.root_id, &item)
                        .current_content_present
                });
                if present {
                    status.current += 1;
                    continue;
                }
                status.remote += 1;
                let (in_backoff, stuck) = candidate
                    .item_id
                    .map(|item| self.failure_state(coordinator, &root.root_id, &item, now_ms))
                    .unwrap_or((false, false));
                if stuck {
                    let failures = candidate
                        .item_id
                        .and_then(|item| repo.download_failure(&root.root_id, &item).ok().flatten())
                        .map_or(0, |f| f.failures);
                    status.stuck.push((candidate.path, failures));
                } else if in_backoff {
                    waiting_on_backoff = true;
                } else {
                    open_work = true;
                }
            }
        }
        status.state = if provider_state != DriverState::Running {
            provider_state
        } else if !open_work && !waiting_on_backoff {
            DriverState::Done
        } else if open_work && !self.environment.peers_available(&root.group_id) {
            DriverState::WaitingPeers
        } else {
            DriverState::Running
        };
        status
    }
}

#[cfg(test)]
mod tests;
