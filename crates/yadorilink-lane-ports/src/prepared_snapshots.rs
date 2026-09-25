//! Re-bootstrap snapshots that have been built and had a manifest signed
//! against them, waiting to be collected.
//!
//! # Not a durable obligation
//!
//! Nothing here survives a restart, on purpose. Issuing a manifest does not
//! create a promise to serve its snapshot forever; it creates a chance to
//! collect one, and a lost chance costs a round trip:
//!
//! ```text
//!   manifest issued  →  daemon restarts  →  fetch finds nothing
//!                    →  requester asks again from the top
//! ```
//!
//! That is not a correctness failure, and treating it as one is how a
//! `Pending`/`Retry`/`Backoff` table gets born. There is no such table here,
//! and there should not be one: the requester already knows how to start over,
//! because starting over is the ordinary path.
//!
//! # Why a manifest is not a capability
//!
//! A `snapshot_hash` is not a secret — it is in a signed manifest the peer
//! was handed. So holding one proves nothing, and every lookup is keyed by
//! `(group_id, snapshot_hash)` rather than by hash alone: a peer whose hello
//! named a different group cannot reach a snapshot prepared for this one,
//! even if it somehow knows the hash. Authorization for the group is checked
//! again at collection, because a peer authorized when the manifest was
//! issued may not be authorized by the time it collects.
//!
//! # Bounded, because preparing is free for the asker
//!
//! A peer can ask for a manifest and never collect the snapshot, repeatedly.
//! Every entry therefore counts against a byte budget, a count budget and a
//! deadline, and the oldest are evicted first. Uncollected work expires.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How much prepared-but-uncollected snapshot data one daemon will hold.
const MAX_PREPARED_BYTES: usize = 256 << 20;

/// How many prepared snapshots one daemon will hold, regardless of size.
const MAX_PREPARED_SNAPSHOTS: usize = 16;

/// How long a prepared snapshot stays collectable. Long enough for a
/// requester to come straight back for it, short enough that abandoned work
/// does not accumulate.
const PREPARED_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    group_id: String,
    snapshot_hash: [u8; 32],
}

struct Entry {
    bytes: std::sync::Arc<Vec<u8>>,
    prepared_at: Instant,
}

/// The prepared snapshots this daemon is currently willing to serve.
pub struct PreparedSnapshots {
    entries: Mutex<HashMap<Key, Entry>>,
    ttl: Duration,
    max_bytes: usize,
    max_entries: usize,
}

impl Default for PreparedSnapshots {
    fn default() -> Self {
        Self::new()
    }
}

impl PreparedSnapshots {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: PREPARED_TTL,
            max_bytes: MAX_PREPARED_BYTES,
            max_entries: MAX_PREPARED_SNAPSHOTS,
        }
    }

    #[cfg(test)]
    pub fn with_bounds(ttl: Duration, max_bytes: usize, max_entries: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), ttl, max_bytes, max_entries }
    }

    /// Hold `bytes` so the peer that was just handed a manifest for it can
    /// collect it.
    ///
    /// Deduplicates on `(group_id, snapshot_hash)`: preparing the same
    /// snapshot twice refreshes its deadline rather than storing it twice,
    /// which is what stops a peer asking repeatedly from multiplying the
    /// cost of one snapshot.
    pub fn prepare(&self, group_id: &str, snapshot_hash: [u8; 32], bytes: std::sync::Arc<Vec<u8>>) {
        let key = Key { group_id: group_id.to_string(), snapshot_hash };
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.insert(key, Entry { bytes, prepared_at: Instant::now() });
        self.evict(&mut entries);
    }

    /// The snapshot prepared for this group under this hash, if it is still
    /// collectable.
    ///
    /// Keyed by both, so a hello for another group cannot reach it. Says
    /// nothing about whether the asking peer is *authorized* for the group —
    /// that is checked live at the call site, because a manifest issued
    /// earlier is not a capability.
    pub fn take_for(
        &self,
        group_id: &str,
        snapshot_hash: &[u8; 32],
    ) -> Option<std::sync::Arc<Vec<u8>>> {
        let key = Key { group_id: group_id.to_string(), snapshot_hash: *snapshot_hash };
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        self.evict(&mut entries);
        entries.get(&key).map(|entry| entry.bytes.clone())
    }

    /// Bytes currently held. For tests and diagnostics.
    pub fn held_bytes(&self) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        self.evict(&mut entries);
        entries.values().map(|entry| entry.bytes.len()).sum()
    }

    pub fn held_count(&self) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        self.evict(&mut entries);
        entries.len()
    }

    /// Drop what has expired, then the oldest, until both budgets hold.
    ///
    /// Oldest-first rather than least-recently-used: an entry's value is the
    /// chance that the peer it was prepared for comes back promptly, and that
    /// chance only decays.
    fn evict(&self, entries: &mut HashMap<Key, Entry>) {
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.prepared_at) < self.ttl);

        while entries.len() > self.max_entries
            || entries.values().map(|entry| entry.bytes.len()).sum::<usize>() > self.max_bytes
        {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.prepared_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests;
